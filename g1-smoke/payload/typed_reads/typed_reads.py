"""Allowlisted evidence reads over the existing native MCP transport.

No direct subprocess, Kubernetes client, network fallback, incident solver,
reference repair or hidden benchmark state is used by this module.  The caller
supplies a launcher-owned context and a native transport callable.  Registration
must expose the same four tools and budgets to every comparison group.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import time
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit
import uuid

from programs import CAPTURE_CHUNK_SH, FILE_CHUNK_SH, HTTP_CHUNK_PY


SOURCE_COMMIT = "148dded7ca2737ded1085e7dc7bbf2a8fcfe7861"
CONTRACT_VERSION = "g1-typed-read-v1"
TOOLS = ("read_recovery_inventory", "read_business_identity",
         "read_notification_queue", "read_delivery_audit")
NATIVE_CHARACTER_LIMIT = 10000
PUBLIC_CHARACTER_LIMIT = 9000
CHUNK_BYTES = 3072
PUBLIC_CHUNK_CHARACTERS = 2400
MAX_DOCUMENT_BYTES = 1048576
MAX_NATIVE_CALLS = 512
MAX_AUDIT_PAGES = 256
IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
BASENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
DNS_NAME = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}\Z")
UUID_VALUE = re.compile(r"[0-9a-f-]{8,64}\Z")
ROLES = {"coordinator", "database", "business_identity", "queue", "delivery_audit", "single", "script"}


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


class ReadFailure(RuntimeError):
    def __init__(self, code: str, detail: dict | None = None):
        self.code, self.detail = code, detail or {}
        super().__init__(code)


def exact_int(value: Any, lo: int, hi: int, label: str) -> int:
    if type(value) is not int or not lo <= value <= hi:
        raise ReadFailure("invalid_argument", {"field": label})
    return value


@dataclass(frozen=True)
class AttemptContext:
    attempt_id: str
    role: str
    namespace: str
    app_info_sha256: str
    evidence_dir: Path
    world_epoch: str
    native_boundary_verified: bool = False
    evidence_level: str = "offline_unconnected"
    ledger_epoch: str | None = None
    ledger_lifecycle_evidence_sha256: str | None = None
    source_commit: str = SOURCE_COMMIT

    def __post_init__(self):
        for label in ("attempt_id", "world_epoch"):
            if not isinstance(getattr(self, label), str) or not IDENTIFIER.fullmatch(getattr(self, label)):
                raise ValueError("Invalid launcher context: " + label)
        if self.role not in ROLES or self.namespace != "gitlab-ce":
            raise ValueError("Only the reviewed task namespace and declared roles are accepted")
        if not HEX.fullmatch(self.app_info_sha256) or self.source_commit != SOURCE_COMMIT:
            raise ValueError("Missing app-discovery evidence or wrong benchmark source")
        if self.evidence_level not in {"offline_unconnected", "offline_controlled_test", "native_filtered_execution"}:
            raise ValueError("Unknown evidence level")
        if self.ledger_epoch is not None:
            if not IDENTIFIER.fullmatch(self.ledger_epoch) or not HEX.fullmatch(self.ledger_lifecycle_evidence_sha256 or ""):
                raise ValueError("Ledger continuity requires launcher lifecycle evidence")
        object.__setattr__(self, "evidence_dir", Path(self.evidence_dir).resolve())


class ChunkAssembler:
    """Reject omitted, reordered, duplicate, truncated or mixed-version chunks."""
    def __init__(self):
        self.version = None
        self.total = None
        self.parts: list[bytes] = []
        self.offset = 0

    def add(self, item: dict) -> None:
        if self.finished:
            raise ReadFailure("duplicate_chunk_after_completion")
        if item.get("status") != "ok":
            raise ReadFailure(str(item.get("status", "collector_result_invalid")),
                              {k: item[k] for k in ("http_status", "error_type") if k in item})
        size = exact_int(item.get("byte_length"), 0, MAX_DOCUMENT_BYTES, "byte_length")
        offset = exact_int(item.get("offset"), 0, MAX_DOCUMENT_BYTES, "offset")
        sha = item.get("document_sha256")
        if not isinstance(sha, str) or not HEX.fullmatch(sha):
            raise ReadFailure("invalid_document_digest")
        version = (sha, size, item.get("source_version"), item.get("archive_sha256"), item.get("snapshot"))
        if self.version is None:
            self.version, self.total = version, size
        if version != self.version:
            raise ReadFailure("mixed_source_versions")
        if offset != self.offset:
            raise ReadFailure("non_contiguous_chunk")
        try:
            part = base64.b64decode(item["chunk_base64"], validate=True)
        except (KeyError, ValueError, TypeError) as exc:
            raise ReadFailure("invalid_chunk_encoding") from exc
        expected = min(CHUNK_BYTES, size - offset)
        if len(part) != expected:
            raise ReadFailure("truncated_or_oversized_chunk")
        self.parts.append(part)
        self.offset += len(part)

    @property
    def finished(self) -> bool:
        return self.total is not None and self.offset == self.total

    def finish(self) -> bytes:
        if not self.finished or not self.parts:
            raise ReadFailure("document_incomplete")
        value = b"".join(self.parts)
        if digest(value) != self.version[0]:
            raise ReadFailure("document_digest_mismatch")
        return value


class AuditAssembler:
    """An append-only prefix, conditional on a trusted one-ledger lifecycle fence."""
    def __init__(self):
        self.snapshot: int | None = None
        self.total: int | None = None
        self.next_after = 0
        self.items: list[dict] = []
        self.seen: set[int] = set()
        self.pages = 0
        self.finished = False

    def add(self, page: dict, requested_after: int) -> int | None:
        if self.finished or requested_after != self.next_after or set(page) != {"items", "next", "snapshot", "total"}:
            raise ReadFailure("audit_page_sequence_invalid")
        h = exact_int(page["snapshot"], 0, 2**63 - 1, "snapshot")
        total = exact_int(page["total"], 0, 100000, "total")
        if self.snapshot is None:
            self.snapshot, self.total = h, total
        if h != self.snapshot or total != self.total:
            raise ReadFailure("audit_snapshot_or_total_changed")
        if not isinstance(page["items"], list) or len(page["items"]) > 40:
            raise ReadFailure("audit_items_invalid")
        previous = requested_after
        for item in page["items"]:
            if not isinstance(item, dict) or not {"id", "sender", "recipients", "subject", "body", "headers"} <= set(item):
                raise ReadFailure("audit_message_incomplete")
            key = exact_int(item["id"], 1, h, "message_id")
            if key <= previous or key in self.seen:
                raise ReadFailure("audit_duplicate_or_unordered_id")
            if not all(isinstance(item[k], str) for k in ("sender", "subject", "body")):
                raise ReadFailure("audit_message_types_invalid")
            if not isinstance(item["recipients"], list) or not all(isinstance(x, str) for x in item["recipients"]):
                raise ReadFailure("audit_recipient_types_invalid")
            if not isinstance(item["headers"], dict) or not all(isinstance(k, str) and k == k.lower() and isinstance(v, str) for k, v in item["headers"].items()):
                raise ReadFailure("audit_header_types_invalid")
            self.seen.add(key)
            self.items.append(item)
            previous = key
        self.pages += 1
        if len(self.items) > self.total:
            raise ReadFailure("audit_total_exceeded")
        nxt = page["next"]
        if nxt is None:
            if len(self.items) != self.total:
                raise ReadFailure("audit_missing_page_or_records")
            self.finished = True
            return None
        if not page["items"] or not isinstance(nxt, str):
            raise ReadFailure("audit_next_invalid")
        url = urlsplit(nxt)
        query = parse_qs(url.query, strict_parsing=True)
        if url.scheme or url.netloc or url.fragment or url.path != "/messages" or set(query) != {"after", "through"}:
            raise ReadFailure("audit_next_origin_or_path_invalid")
        if query != {"after": [str(previous)], "through": [str(h)]}:
            raise ReadFailure("audit_next_cursor_mismatch")
        self.next_after = previous
        return previous


class EvidenceStore:
    """Only public observations; immutable documents with sequential delivery cursors.

The store is shared across roles in an attempt, so role decomposition grants no
private business evidence.  A launcher must change world_epoch after a relevant
write or unknown-effect transition; fragments never refresh stale observations.
"""
    def __init__(self, context: AttemptContext):
        self.context = context
        self.root = context.evidence_dir / context.attempt_id / context.world_epoch
        self.root.mkdir(parents=True, exist_ok=True)

    def _signature(self, bundle: str, index: int, sha: str) -> str:
        return digest(f"{self.context.attempt_id}:{self.context.world_epoch}:{bundle}:{index}:{sha}".encode())

    def _cursor(self, bundle: str, index: int, sha: str) -> str:
        return f"{bundle}.{index}.{self._signature(bundle, index, sha)}"

    def put(self, tool: str, metadata: dict, document: dict) -> dict:
        body = canonical(document)
        if len(body) > MAX_DOCUMENT_BYTES:
            raise ReadFailure("document_budget_exceeded")
        bundle = uuid.uuid4().hex
        state = {"tool": tool, "attempt_id": self.context.attempt_id,
                 "world_epoch": self.context.world_epoch, "metadata": metadata,
                 "ledger_epoch": self.context.ledger_epoch,
                 "sha256": digest(body), "bytes": len(body), "next_index": 0}
        (self.root / (bundle + ".data")).write_bytes(body)
        (self.root / (bundle + ".json")).write_bytes(canonical(state))
        return self.take(tool, self._cursor(bundle, 0, state["sha256"]))

    def take(self, tool: str, cursor: str, delivery_request_id: str | None = None) -> dict:
        if not isinstance(cursor, str) or not re.fullmatch(r"[0-9a-f]{32}\.[0-9]{1,6}\.[0-9a-f]{64}", cursor):
            raise ReadFailure("invalid_continuation_cursor")
        bundle, number, signature = cursor.split(".")
        index = int(number)
        path = self.root / (bundle + ".json")
        try:
            handle = path.open("r+")
        except FileNotFoundError as exc:
            raise ReadFailure("unknown_or_cross_attempt_cursor") from exc
        with handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            state = json.load(handle)
            if (state["tool"] != tool or state["attempt_id"] != self.context.attempt_id
                    or state["world_epoch"] != self.context.world_epoch
                    or state.get("ledger_epoch") != self.context.ledger_epoch
                    or state["next_index"] != index
                    or signature != self._signature(bundle, index, state["sha256"])):
                raise ReadFailure("stale_replayed_or_out_of_order_cursor")
            body = (self.root / (bundle + ".data")).read_bytes()
            if len(body) != state["bytes"] or digest(body) != state["sha256"]:
                raise ReadFailure("stored_evidence_corrupt")
            start = index * PUBLIC_CHUNK_CHARACTERS
            if start > len(body) or (start == len(body) and index > 0):
                raise ReadFailure("invalid_continuation_offset")
            part = body[start:start + PUBLIC_CHUNK_CHARACTERS]
            end = start + len(part)
            done = end == len(body)
            result = {**state["metadata"], "complete": bool(state["metadata"]["source_complete"] and done),
                      "document": {"sha256": state["sha256"], "bytes": len(body),
                                   "encoding": "ascii-json", "chunk_index": index,
                                   "offset": start, "fragment": part.decode("ascii"),
                                   "fragment_sha256": digest(part), "all_fragments_delivered": done},
                      "next_cursor": None if done else self._cursor(bundle, index + 1, state["sha256"])}
            if delivery_request_id is not None:
                result["request_id"] = delivery_request_id
            if len(canonical(result)) > PUBLIC_CHARACTER_LIMIT:
                raise ReadFailure("public_envelope_budget_exceeded")
            state["next_index"] = index + 1
            handle.seek(0)
            json.dump(state, handle, separators=(",", ":"))
            handle.truncate()
            handle.flush()
            os.fsync(handle.fileno())
            return result

    def save_public_index(self, name: str, value: dict) -> None:
        # A deterministic index of already obtained public catalog/receipts only.
        if name not in {"catalog", "receipts"}:
            raise ValueError("Invalid internal index")
        path = self.root / (name + ".index.json")
        tmp = path.with_name(path.name + "." + uuid.uuid4().hex)
        tmp.write_bytes(canonical(value))
        tmp.replace(path)

    def public_index(self, name: str) -> dict:
        try:
            return json.loads((self.root / (name + ".index.json")).read_bytes())
        except FileNotFoundError as exc:
            raise ReadFailure("prerequisite_public_evidence_missing", {"required": name}) from exc


class TypedReadService:
    """Synchronous API: call(tool_name, arguments, request_id) -> JSON-safe dict.

transport(command, call_id) returns round4 native_transport.execute's envelope.
It MUST use native filtered agent access, never a privileged host kubeconfig.
This module has no fallback when that transport rejects a command.
Create a separate service/worker for every SDK request. Instances hold per-call
trace state and must not be shared concurrently between threads. Continuations
share only the launcher-owned evidence directory, with sequential cursor locks.
"""
    def __init__(self, context: AttemptContext, transport: Callable[[str, str], dict]):
        self.ctx = context
        self.transport = transport
        self.store = EvidenceStore(context)
        self.program_digest = digest(Path(__file__).read_bytes() + Path(__file__).with_name("programs.py").read_bytes())
        self.calls = 0
        self.pods: list[dict] = []
        self.trace: list[dict] = []
        self.request_id = ""

    def _native(self, argv: list[str]) -> str:
        self.calls += 1
        if self.calls > MAX_NATIVE_CALLS:
            raise ReadFailure("native_call_budget_exceeded")
        command = shlex.join(argv)
        call_id = f"{self.request_id}-{self.calls:03d}"
        response = self.transport(command, call_id)
        self.trace.append({"call_id": call_id, "command_sha256": digest(command.encode()),
                           "transport_state": response.get("transport_state"),
                           "journal": response.get("journal")})
        if response.get("transport_state") != "response_received" or response.get("trace_complete") is not True:
            raise ReadFailure("native_transport_incomplete")
        native = response.get("native_response")
        if not isinstance(native, dict) or native.get("isError") is True or response.get("native_mcp_is_error") is True:
            raise ReadFailure("native_mcp_error")
        content = native.get("content")
        if not isinstance(content, list) or len(content) != 1 or content[0].get("type") != "text":
            raise ReadFailure("native_text_envelope_invalid")
        value = content[0].get("text")
        if not isinstance(value, str) or len(value) > NATIVE_CHARACTER_LIMIT or "... [truncated]" in value:
            raise ReadFailure("native_output_truncated")
        if value.lstrip().startswith(("Command Rejected", "Dry-run failed", "Error executing kubectl", "Dry-run timed out")):
            raise ReadFailure("native_command_rejected")
        return value

    def _get(self, kind: str, name: str | None, projection: str, selector: str | None = None) -> str:
        argv = ["kubectl", "get", kind]
        if name:
            if not DNS_NAME.fullmatch(name):
                raise ReadFailure("invalid_resolved_resource_name")
            argv.append(name)
        argv += ["-n", self.ctx.namespace]
        if selector:
            argv += ["-l", selector]
        argv += ["-o", "jsonpath=" + projection, "--request-timeout=15s"]
        return self._native(argv)

    def _pod(self, target: str) -> dict:
        choices = {"recovery": ("recovery-console", "tools", None),
                   "client": ("application-client", "client", None),
                   "redis": (None, "redis", "app=gitlab-redis"),
                   "gitlab": (None, "gitlab", "app=gitlab-ce")}
        name, container, selector = choices[target]
        fields = [".metadata.name", ".metadata.namespace", ".metadata.uid", ".metadata.resourceVersion",
                  ".metadata.deletionTimestamp", f'.spec.containers[?(@.name=="{container}")].name',
                  f'.status.containerStatuses[?(@.name=="{container}")].containerID',
                  f'.status.containerStatuses[?(@.name=="{container}")].restartCount',
                  f'.status.containerStatuses[?(@.name=="{container}")].ready']
        template = '{"\\t"}'.join("{" + x + "}" for x in fields) + '{"\\n"}'
        if selector:
            template = "{range .items[*]}" + template + "{end}"
        text = self._get("pods", name, template, selector)
        candidates = []
        for line in text.splitlines():
            parts = line.split("\t")
            if len(parts) != 9:
                raise ReadFailure("pod_projection_invalid")
            n, ns, uid, rv, deletion, actual_container, container_id, restarts, ready = parts
            if deletion:
                continue
            if (not DNS_NAME.fullmatch(n) or ns != self.ctx.namespace or not UUID_VALUE.fullmatch(uid)
                    or not rv.isdigit() or actual_container != container or not container_id
                    or not restarts.isdigit() or ready not in {"true", "false"}):
                raise ReadFailure("pod_identity_or_container_unavailable")
            candidates.append({"name": n, "namespace": ns, "uid": uid, "resource_version": rv,
                               "container": container, "container_id": container_id,
                               "restart_count": int(restarts), "container_ready": ready == "true"})
        if len(candidates) != 1:
            raise ReadFailure("pod_selection_not_unique", {"count": len(candidates)})
        self.pods.append(candidates[0])
        return candidates[0]

    def _same_pod(self, target: str, before: dict) -> None:
        after = self._pod(target)
        if any(before[x] != after[x] for x in ("name", "uid", "container_id", "restart_count", "container")):
            raise ReadFailure("pod_or_container_changed")

    def _exec(self, pod: dict, argv: list[str]) -> dict:
        text = self._native(["kubectl", "exec", pod["name"], "-n", self.ctx.namespace,
                             "-c", pod["container"], "--", *argv])
        try:
            result = json.loads(text)
        except (ValueError, TypeError) as exc:
            raise ReadFailure("collector_json_invalid") from exc
        if not isinstance(result, dict):
            raise ReadFailure("collector_json_invalid")
        return result

    def _document(self, collector: Callable[[int], dict]) -> tuple[bytes, dict]:
        assembly = ChunkAssembler()
        first = collector(0)
        assembly.add(first)
        while not assembly.finished:
            assembly.add(collector(assembly.offset))
        return assembly.finish(), first

    def _file(self, pod: dict, path: str) -> tuple[Any, dict]:
        blob, meta = self._document(lambda offset: self._exec(
            pod, ["sh", "-c", FILE_CHUNK_SH, "g1-file-read", path, str(offset), str(CHUNK_BYTES)]))
        try:
            return json.loads(blob), {"path": path, "sha256": meta["document_sha256"],
                                      "bytes": len(blob), "file_version": meta["source_version"]}
        except ValueError as exc:
            raise ReadFailure("source_file_json_invalid") from exc

    def _capture(self, pod: dict, mode: str, argument: str, start=0, count=1) -> tuple[dict, dict]:
        blob, meta = self._document(lambda offset: self._exec(pod, ["sh", "-c", CAPTURE_CHUNK_SH,
            "g1-command-capture", mode, argument, str(start), str(count), str(offset), str(CHUNK_BYTES)]))
        try:
            value = json.loads(blob)
            result = {"target_exit_code": exact_int(value["target_exit_code"], 0, 255, "target_exit_code"),
                      "stdout": base64.b64decode(value["stdout_base64"], validate=True).decode("utf-8"),
                      "stderr": base64.b64decode(value["stderr_base64"], validate=True).decode("utf-8")}
        except (KeyError, ValueError, UnicodeError) as exc:
            raise ReadFailure("captured_target_output_invalid") from exc
        return result, {"sha256": meta["document_sha256"], "source_version": meta["source_version"],
                        "archive_sha256": meta.get("archive_sha256")}

    def _http(self, pod: dict, config: dict) -> tuple[dict, dict]:
        mutable = dict(config)
        def collect(offset):
            cfg = {**mutable, "offset": offset, "count": CHUNK_BYTES}
            item = self._exec(pod, ["python", "-c", HTTP_CHUNK_PY, canonical(cfg).decode()])
            if mutable["mode"] == "audit" and offset == 0 and item.get("status") == "ok":
                mutable["through"] = item.get("snapshot")
            return item
        blob, meta = self._document(collect)
        try:
            return json.loads(blob), {"sha256": meta["document_sha256"], "http_status": meta["http_status"]}
        except ValueError as exc:
            raise ReadFailure("http_document_json_invalid") from exc

    def _inventory(self, args: dict) -> tuple[dict, dict]:
        operation = args["operation"]
        if operation == "topology":
            if set(args) != {"operation"}:
                raise ReadFailure("invalid_argument_set")
            fields = [".metadata.uid", ".metadata.resourceVersion", ".spec.instances",
                      ".status.currentPrimary", ".status.targetPrimary", ".status.readyInstances"]
            template = '{"\\t"}'.join("{" + x + "}" for x in fields)
            values = self._get("cluster.postgresql.cnpg.io", "gitlab-ce-db", template).split("\t")
            if len(values) != 6 or not UUID_VALUE.fullmatch(values[0]) or not all(values[x].isdigit() for x in (1, 2, 5)):
                raise ReadFailure("cluster_projection_invalid")
            return {"cluster_uid": values[0], "resource_version": values[1], "instances": int(values[2]),
                    "current_primary": values[3], "target_primary": values[4], "ready_instances": int(values[5])}, {
                    "source_complete": True, "coverage": {"cluster_fields": True, "database_contents": False,
                    "per_member_sql": False, "original_volume_uid_verification": False},
                    "consistency_class": "single_kubernetes_object_observation"}
        pod = self._pod("recovery")
        if operation == "backup_catalog":
            if set(args) != {"operation"}:
                raise ReadFailure("invalid_argument_set")
            catalog, meta = self._file(pod, "/recovery/backups/catalog.json")
            self._validate_catalog(catalog)
            self._same_pod("recovery", pod)
            self.store.save_public_index("catalog", {"catalog": catalog, "meta": meta})
            return {"catalog": catalog, "file": meta}, {"source_complete": True,
                "coverage": {"catalog": True, "archive_validity": False},
                "consistency_class": "per_file_digest_checked_observation"}
        if operation == "backup_summary":
            if set(args) != {"operation", "archive_basename"}:
                raise ReadFailure("invalid_argument_set")
            name = args["archive_basename"]
            if not isinstance(name, str) or not BASENAME.fullmatch(name) or ".." in name:
                raise ReadFailure("invalid_archive_basename")
            prior = self.store.public_index("catalog")
            catalog, meta = self._file(pod, "/recovery/backups/catalog.json")
            self._validate_catalog(catalog)
            if meta["sha256"] != prior["meta"]["sha256"]:
                raise ReadFailure("catalog_version_changed")
            matches = [x for x in catalog if x["file"] == name]
            if len(matches) != 1:
                raise ReadFailure("archive_not_in_observed_catalog")
            capture, archive = self._capture(pod, "archive_list", "/recovery/backups/" + name)
            self._same_pod("recovery", pod)
            return {"archive_basename": name, "catalog_claim": matches[0], "observed_archive": archive,
                    "pg_restore_list": capture, "restore_success": None}, {"source_complete": capture["target_exit_code"] == 0,
                    "coverage": {"archive_directory_and_exit_status": True,
                                 "directory_listing_succeeded": capture["target_exit_code"] == 0, "actual_restore": False},
                    "consistency_class": "per_file_digest_checked_observation"}
        raise ReadFailure("unsupported_operation")

    @staticmethod
    def _validate_catalog(value):
        if not isinstance(value, list) or len(value) > 128:
            raise ReadFailure("catalog_schema_invalid")
        seen = set()
        for row in value:
            name = row.get("file") if isinstance(row, dict) else None
            if not isinstance(name, str) or not BASENAME.fullmatch(name) or ".." in name or name in seen:
                raise ReadFailure("catalog_filename_invalid_or_duplicate")
            if not isinstance(row.get("status"), str) or ("sha256" in row and not HEX.fullmatch(row["sha256"])):
                raise ReadFailure("catalog_schema_invalid")
            seen.add(name)

    @staticmethod
    def _validate_receipts(issues, notices) -> dict:
        if not isinstance(issues, list) or not isinstance(notices, list) or len(issues) > 1000 or len(notices) > 1000:
            raise ReadFailure("receipt_bundle_schema_invalid")
        bykey = {}
        business = ("project", "iid", "title", "description", "confidential")
        for row in issues:
            if not isinstance(row, dict):
                raise ReadFailure("receipt_schema_invalid")
            key = (exact_int(row.get("project"), 1, 2**63-1, "project"), exact_int(row.get("iid"), 1, 2**63-1, "iid"))
            if key in bykey or not all(k in row for k in business) or not isinstance(row["title"], str) or not isinstance(row["description"], str) or type(row["confidential"]) is not bool:
                raise ReadFailure("receipt_duplicate_or_schema_invalid")
            bykey[key] = row
        seen = set()
        for row in notices:
            if not isinstance(row, dict):
                raise ReadFailure("notification_receipt_schema_invalid")
            key = (exact_int(row.get("project"), 1, 2**63-1, "project"), exact_int(row.get("iid"), 1, 2**63-1, "iid"))
            if key in seen or key not in bykey or any(row.get(k) != bykey[key][k] for k in business):
                raise ReadFailure("receipt_bundles_disagree")
            if not isinstance(row.get("recipient"), str) or not row["recipient"] or not isinstance(row.get("reason"), str):
                raise ReadFailure("notification_recipient_schema_invalid")
            for field in ("recipient_id", "issue_id_at_acceptance"):
                exact_int(row.get(field), 1, 2**63-1, field)
            for field in ("job_id", "provider_job_id"):
                if field not in row or (row[field] is not None and not isinstance(row[field], str)):
                    raise ReadFailure("notification_job_schema_invalid")
            seen.add(key)
        if seen != set(bykey):
            raise ReadFailure("receipt_bundle_coverage_mismatch")
        return {"allowed_issue_keys": [list(x) for x in sorted(bykey)]}

    def _identity(self, args: dict) -> tuple[dict, dict]:
        operation = args["operation"]
        if operation == "recipient_authorization":
            raise ReadFailure("unavailable_recipient_authorization", {"reason": "Root API access is not recipient authorization; no reviewed native authorization collector is deployed."})
        if operation == "receipt_bundle":
            if set(args) != {"operation"}:
                raise ReadFailure("invalid_argument_set")
            pod = self._pod("recovery")
            issues, imeta = self._file(pod, "/recovery/journal/acknowledged-issues.json")
            notices, nmeta = self._file(pod, "/recovery/journal/acknowledged-notifications.json")
            index = self._validate_receipts(issues, notices)
            # Re-read both digest-bound files after assembling the pair.
            _, iend = self._file(pod, imeta["path"])
            _, nend = self._file(pod, nmeta["path"])
            if imeta != iend or nmeta != nend:
                raise ReadFailure("receipt_file_version_changed")
            self._same_pod("recovery", pod)
            self.store.save_public_index("receipts", {**index, "files": [imeta, nmeta]})
            return {"issues": issues, "notifications": notices, "files": [imeta, nmeta]}, {
                "source_complete": True, "coverage": {"receipt_bundle": True, "current_issue": False,
                "recipient_authorization": False}, "consistency_class": "two_digest_checked_receipt_observations_not_transaction"}
        if operation == "current_issue":
            if set(args) != {"operation", "project", "iid"}:
                raise ReadFailure("invalid_argument_set")
            project = exact_int(args["project"], 1, 2**63-1, "project")
            iid = exact_int(args["iid"], 1, 2**63-1, "iid")
            index = self.store.public_index("receipts")
            if [project, iid] not in index["allowed_issue_keys"]:
                raise ReadFailure("issue_key_not_in_observed_receipts")
            recovery_pod = self._pod("recovery")
            for prior in index["files"]:
                if prior["path"] not in {"/recovery/journal/acknowledged-issues.json", "/recovery/journal/acknowledged-notifications.json"}:
                    raise ReadFailure("receipt_index_corrupt")
                item = self._exec(recovery_pod, ["sh", "-c", FILE_CHUNK_SH, "g1-file-read",
                                                prior["path"], "0", str(CHUNK_BYTES)])
                if (item.get("status") != "ok" or item.get("document_sha256") != prior["sha256"]
                        or item.get("source_version") != prior["file_version"] or item.get("byte_length") != prior["bytes"]):
                    raise ReadFailure("receipt_index_source_changed")
            self._same_pod("recovery", recovery_pod)
            pod = self._pod("client")
            issue, meta = self._http(pod, {"mode": "issue", "project": project, "iid": iid})
            if issue.get("project_id") != project or issue.get("iid") != iid:
                raise ReadFailure("current_issue_identity_mismatch")
            exact_int(issue.get("id"), 1, 2**63-1, "current_internal_id")
            self._same_pod("client", pod)
            return {"issue": issue, "http": meta}, {"source_complete": True,
                "coverage": {"current_issue": True, "recipient_authorization": False},
                "consistency_class": "one_live_issue_observation"}
        raise ReadFailure("unsupported_operation")

    def _queue(self, args: dict) -> tuple[dict, dict]:
        operation = args["operation"]
        if operation == "workset":
            raise ReadFailure("unavailable_workset", {"reason": "No reviewed native in-flight collector is deployed; four queues cannot establish absence of active work."})
        if operation == "key_observation":
            if set(args) != {"operation", "key", "start", "count"} or args["key"] not in {"queue:mailers", "retry", "schedule", "dead"}:
                raise ReadFailure("invalid_argument_set")
            start = exact_int(args["start"], 0, 100000, "start")
            count = exact_int(args["count"], 1, 8, "count")
            pod = self._pod("redis")
            capture, meta = self._capture(pod, "redis_range", args["key"], start, count)
            if capture["target_exit_code"] != 0 or capture["stderr"]:
                raise ReadFailure("redis_target_failed", {"target_exit_code": capture["target_exit_code"]})
            try:
                raw_payloads = json.loads(capture["stdout"])
                if not isinstance(raw_payloads, list) or not all(isinstance(x, str) for x in raw_payloads):
                    raise ReadFailure("redis_reply_type_invalid")
                jobs = [json.loads(payload) for payload in raw_payloads]
            except ValueError as exc:
                raise ReadFailure("queue_payload_parse_failed") from exc
            if len(jobs) > count or not all(isinstance(x, dict) for x in jobs):
                raise ReadFailure("queue_payload_schema_invalid")
            self._same_pod("redis", pod)
            data = {"key": args["key"], "start": start, "count_requested": count, "jobs": jobs,
                    "raw_payloads": raw_payloads, "capture": meta}
        elif operation == "sidekiq_status":
            if set(args) != {"operation"}:
                raise ReadFailure("invalid_argument_set")
            pod = self._pod("gitlab")
            capture, meta = self._capture(pod, "sidekiq_status", "sidekiq")
            self._same_pod("gitlab", pod)
            data = {"status_command": capture, "capture": meta}
        else:
            raise ReadFailure("unsupported_operation")
        return data, {"source_complete": False, "coverage": {"one_key_or_status_observation": True,
            "inflight": False, "other_queues": False, "global_snapshot": False},
            "consistency_class": "live_queue_observation_not_complete_snapshot"}

    def _audit(self, args: dict) -> tuple[dict, dict]:
        if args != {"operation": "begin_snapshot"}:
            raise ReadFailure("invalid_argument_set")
        if not self.ctx.ledger_epoch or not self.ctx.ledger_lifecycle_evidence_sha256:
            raise ReadFailure("ledger_continuity_unproven", {"reason": "The public API has no ledger incarnation. Launcher lifecycle evidence is required before cross-page assembly."})
        pod = self._pod("client")
        assembly = AuditAssembler()
        page_digests = []
        after = 0
        while True:
            if assembly.pages >= MAX_AUDIT_PAGES:
                raise ReadFailure("audit_page_budget_exceeded")
            page, meta = self._http(pod, {"mode": "audit", "after": after, "through": assembly.snapshot})
            page_digests.append(meta["sha256"])
            next_after = assembly.add(page, after)
            if next_after is None:
                break
            after = next_after
        self._same_pod("client", pod)
        return {"snapshot": assembly.snapshot, "total": assembly.total, "messages": assembly.items,
                "page_sha256": page_digests, "ledger_epoch": self.ctx.ledger_epoch,
                "ledger_lifecycle_evidence_sha256": self.ctx.ledger_lifecycle_evidence_sha256}, {
                "source_complete": True, "coverage": {"prefix_through_snapshot": True,
                "future_acceptance": False, "system_quiescence": False},
                "consistency_class": "append_only_prefix_under_launcher_ledger_lifecycle_fence"}

    def call(self, tool_name: str, arguments: dict, request_id: str) -> dict:
        started, wall = time.monotonic(), utc()
        self.calls, self.pods, self.trace = 0, [], []
        self.request_id = request_id
        base = {"attempt_id": self.ctx.attempt_id, "tool_contract_version": CONTRACT_VERSION,
                "request_id": request_id, "source_request_id": request_id, "source_commit": SOURCE_COMMIT,
                "tool_program_digest": self.program_digest, "tool": tool_name,
                "world_epoch": self.ctx.world_epoch, "evidence_level": self.ctx.evidence_level,
                "resolved_namespace": self.ctx.namespace, "app_info_sha256": self.ctx.app_info_sha256,
                "observed_start_utc": wall, "monotonic_start": started,
                "invalidated_by": ["attempt or world epoch change", "pod/container identity change",
                                   "source content or permissions change", "unknown in-flight effects"],
                "business_success": None}
        try:
            if tool_name not in TOOLS or not isinstance(arguments, dict) or not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", request_id):
                raise ReadFailure("invalid_tool_request")
            if not self.ctx.native_boundary_verified:
                raise ReadFailure("native_filtered_boundary_not_verified")
            if not isinstance(arguments.get("operation"), str):
                raise ReadFailure("invalid_operation")
            if arguments["operation"] == "continue":
                if set(arguments) != {"operation", "cursor"}:
                    raise ReadFailure("invalid_argument_set")
                # Continuations retain the original observation time.  They are
                # deliveries of existing evidence, never new live observations.
                return self.store.take(tool_name, arguments["cursor"], request_id)
            allowed = {
                "read_recovery_inventory": {"topology": set(), "backup_catalog": set(), "backup_summary": {"archive_basename"}},
                "read_business_identity": {"receipt_bundle": set(), "current_issue": {"project", "iid"}, "recipient_authorization": set()},
                "read_notification_queue": {"key_observation": {"key", "start", "count"}, "sidekiq_status": set(), "workset": set()},
                "read_delivery_audit": {"begin_snapshot": set()},
            }
            expected = allowed[tool_name].get(arguments["operation"])
            if expected is None or set(arguments) != expected | {"operation"}:
                raise ReadFailure("invalid_argument_set")
            dispatch = dict(zip(TOOLS, (self._inventory, self._identity, self._queue, self._audit)))
            document, status = dispatch[tool_name](arguments)
            meta = {**base, **status, "observed_end_utc": utc(), "monotonic_end": time.monotonic(),
                    "resolved_pod_uid_and_container": self.pods,
                    "source_version_or_digest": digest(canonical(document)),
                    "native_calls": self.calls, "native_trace_digest": digest(canonical(self.trace))}
            return self.store.put(tool_name, meta, document)
        except ReadFailure as exc:
            return {**base, "complete": False, "source_complete": False,
                    "coverage": {}, "consistency_class": "unknown_or_incomplete",
                    "observed_end_utc": utc(), "monotonic_end": time.monotonic(),
                    "resolved_pod_uid_and_container": self.pods,
                    "source_version_or_digest": None, "native_calls": self.calls,
                    "error": {"code": exc.code, "detail": exc.detail}, "business_success": None}
        except Exception as exc:
            # No exception text: parser/network/library exceptions can embed
            # protected credentials or large untrusted response bodies.
            return {**base, "complete": False, "source_complete": False,
                    "coverage": {}, "consistency_class": "unknown_or_incomplete",
                    "observed_end_utc": utc(), "monotonic_end": time.monotonic(),
                    "error": {"code": "collector_internal_error", "type": type(exc).__name__},
                    "business_success": None}
