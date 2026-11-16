"""Launcher-owned limits and evidence validation for the G1 read-path probe.

This is not an incident solver or a write/submission barrier.  The writable
boundary-proof copy is an integrity record; the host retains authoritative
container inspection and native rejection evidence independently.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

SOURCE_COMMIT = "148dded7ca2737ded1085e7dc7bbf2a8fcfe7861"
MODEL_SHA256 = "d98cdcbd03e17ce47681435b5150e34c1417f50b5c0019dd560e4882c5745785"
TYPED_PROGRAM_DIGEST = "5b0e8414c821c26ea522008cd03cbbd9af88e617fac2bb0c0b9b0d219508a2ee"
MODEL_NAME = "local-qwen3-8b-q4km"
MODEL_PORT, KERNEL_PORT = 19080, 19082
AUTHOR = "g1_native_reads"
TOOLS = ("read_recovery_inventory", "read_business_identity",
         "read_notification_queue", "read_delivery_audit")
INITIAL_CHOICES = {
    ("read_recovery_inventory", "backup_catalog"),
    ("read_business_identity", "receipt_bundle"),
}
OPERATIONS = {
    TOOLS[0]: {"topology": set(), "backup_catalog": set(), "backup_summary": {"archive_basename"}},
    TOOLS[1]: {"receipt_bundle": set(), "current_issue": {"project", "iid"}, "recipient_authorization": set()},
    TOOLS[2]: {"key_observation": {"key", "start", "count"}, "sidekiq_status": set(), "workset": set()},
    TOOLS[3]: {"begin_snapshot": set()},
}
IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode()


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".partial")
    temporary.write_text(json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2) + "\n")
    temporary.replace(path)


def endpoint(value: str) -> str:
    p = urlsplit(value)
    if (p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password
            or p.path not in {"", "/"} or p.query or p.fragment):
        raise ValueError("launcher_origin_invalid")
    return value.rstrip("/")


def validate_arguments(tool: str, params: dict):
    if tool not in TOOLS or not isinstance(params, dict):
        raise ValueError("typed_tool_not_registered")
    operation = params.get("operation")
    if not isinstance(operation, str):
        raise ValueError("typed_operation_invalid")
    expected = {"cursor"} if operation == "continue" else OPERATIONS[tool].get(operation)
    if expected is None or set(params) != expected | {"operation"}:
        raise ValueError("typed_argument_set_invalid")
    if len(canonical(params)) > 4096:
        raise ValueError("typed_arguments_exceed_budget")
    if operation == "continue" and (not isinstance(params["cursor"], str) or not re.fullmatch(
            r"[0-9a-f]{32}\.[0-9]{1,6}\.[0-9a-f]{64}", params["cursor"])):
        raise ValueError("typed_cursor_invalid")


def validate_selection(value: dict) -> tuple[str, dict]:
    if not isinstance(value, dict) or set(value) != {"tool", "operation"}:
        raise ValueError("model_selection_shape_invalid")
    if (not isinstance(value.get("tool"), str) or not isinstance(value.get("operation"), str)
            or (value["tool"], value["operation"]) not in INITIAL_CHOICES):
        raise ValueError("model_selection_not_allowed")
    return value["tool"], {"operation": value["operation"]}


def nonempty_public_rows(selection, document):
    """Require observed rows, without assuming a hidden workload count."""
    if not isinstance(document, dict):
        raise ValueError("public_document_not_object")
    fields = ("catalog",) if selection == {"tool": TOOLS[0], "operation": "backup_catalog"} else ("issues", "notifications")
    counts = {}
    for key in fields:
        rows = document.get(key)
        if not isinstance(rows, list) or not rows or not all(isinstance(row, dict) for row in rows):
            raise ValueError("public_document_has_no_business_rows")
        counts[key] = len(rows)
    return counts


def validate_boundary(raw: bytes, expected_digest: str, attempt_id: str, namespace: str) -> dict:
    if not HEX.fullmatch(expected_digest) or sha(raw) != expected_digest:
        raise ValueError("boundary_proof_digest_mismatch")
    proof = json.loads(raw)
    if (proof.get("attempt_id") != attempt_id or proof.get("namespace") != namespace
            or proof.get("source_commit") != SOURCE_COMMIT
            or proof.get("native_filtered_boundary_verified") is not True):
        raise ValueError("boundary_proof_context_mismatch")
    for name in ("probe_result_sha256", "container_inspection_sha256"):
        if not isinstance(proof.get(name), str) or not HEX.fullmatch(proof[name]):
            raise ValueError("boundary_proof_evidence_missing")
    return proof


class PublicDocumentAssembler:
    """Consume exactly one immutable public document through SDK continuations."""
    def __init__(self, attempt_id, world_epoch, tool, expected_app_info_sha256, expected_program_digest):
        self.attempt_id, self.world_epoch, self.tool = attempt_id, world_epoch, tool
        self.expected_app_info_sha256 = expected_app_info_sha256
        self.expected_program_digest = expected_program_digest
        self.binding = None
        self.parts = []
        self.offset = 0
        self.finished = False

    def add(self, response: dict):
        if self.finished or response.get("error"):
            raise ValueError("typed_read_failed_or_duplicate_completion")
        if (response.get("attempt_id") != self.attempt_id or response.get("world_epoch") != self.world_epoch
                or response.get("tool") != self.tool or response.get("source_commit") != SOURCE_COMMIT
                or response.get("evidence_level") != "native_filtered_execution"
                or response.get("source_complete") is not True):
            raise ValueError("public_document_context_or_completeness_invalid")
        d = response.get("document", {})
        binding = (d.get("sha256"), d.get("bytes"), response.get("source_version_or_digest"),
                   response.get("app_info_sha256"), response.get("tool_program_digest"))
        if (not isinstance(binding[0], str) or not HEX.fullmatch(binding[0])
                or type(binding[1]) is not int or not 0 <= binding[1] <= 1048576):
            raise ValueError("public_document_identity_invalid")
        if (binding[2] != binding[0] or binding[3] != self.expected_app_info_sha256
                or binding[4] != self.expected_program_digest):
            raise ValueError("public_document_discovery_or_program_binding_invalid")
        if self.binding is None:
            self.binding = binding
        if binding != self.binding or d.get("encoding") != "ascii-json":
            raise ValueError("public_document_version_changed")
        if (type(d.get("chunk_index")) is not int or d["chunk_index"] != len(self.parts)
                or type(d.get("offset")) is not int or d["offset"] != self.offset):
            raise ValueError("public_document_fragment_order_invalid")
        part = d["fragment"].encode("ascii")
        if sha(part) != d.get("fragment_sha256") or len(part) > 2400 or not part:
            raise ValueError("public_document_fragment_invalid")
        self.parts.append(part)
        self.offset += len(part)
        if self.offset > binding[1]:
            raise ValueError("public_document_length_exceeded")
        done = d.get("all_fragments_delivered") is True
        cursor = response.get("next_cursor")
        if done:
            if cursor is not None or response.get("complete") is not True or self.offset != binding[1]:
                raise ValueError("public_document_completion_invalid")
            body = b"".join(self.parts)
            if sha(body) != binding[0]:
                raise ValueError("public_document_digest_mismatch")
            json.loads(body)
            self.finished = True
        elif response.get("complete") is not False or not isinstance(cursor, str) or self.offset >= binding[1]:
            raise ValueError("public_document_continuation_invalid")
        return cursor
