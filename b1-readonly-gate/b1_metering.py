"""Bounded accounting for the real, local SDK -> AIOS -> model path.

This module never supplies model answers. The OpenAI-compatible client remains
the frozen AIOS backend; HTTP hooks retain its actual request/response bodies.
Reservations are permanent, including on disconnect. Missing usage stays null.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time

MODEL_ORIGIN = "http://127.0.0.1:19080/v1"
KERNEL_ORIGIN = "http://127.0.0.1:19082"
MODEL_NAME = "local-qwen3-8b-q4km"
LIMITS = {"model_requests": 3, "reserved_output_tokens": 576,
          "output_tokens_per_request": 192, "sdk_requests": 1027,
          "client_seconds": 900, "model_request_seconds": 180,
          "input_bytes_per_request": 16000}
REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")
LOCAL = threading.local()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_once(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())
    return digest(raw)


def query_identity(query):
    value = query if isinstance(query, dict) else query.model_dump()
    keys = ("request_id", "messages", "temperature", "max_new_tokens",
            "message_return_type", "response_format", "action_type", "tools")
    return {key: value.get(key) for key in keys}


def normalize_usage(raw):
    """Preserve the provider object; never estimate an absent token count."""
    fields = ("prompt_tokens", "completion_tokens", "total_tokens")
    values = {name: None for name in fields}
    if isinstance(raw, dict):
        for name in fields:
            value = raw.get(name)
            if type(value) is int and value >= 0:
                values[name] = value
    complete = all(value is not None for value in values.values())
    if complete and values["total_tokens"] != values["prompt_tokens"] + values["completion_tokens"]:
        status = "inconsistent_provider_usage"
    else:
        status = "complete" if complete else "partial_or_missing"
    return {"raw": raw if isinstance(raw, dict) else None,
            "counts": values, "status": status}


class Ledger:
    def __init__(self, root):
        self.root = Path(root)
        self.path = self.root / "requests.sqlite"

    @classmethod
    def create(cls, root, attempt_id):
        ledger = cls(root)
        ledger.root.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(ledger.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        with ledger.connect() as db:
            db.executescript("""
              CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
              CREATE TABLE model_requests(
                request_id TEXT PRIMARY KEY, query_json TEXT NOT NULL,
                reservation_ns INTEGER NOT NULL, max_output_tokens INTEGER NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('reserved','in_flight','response_received','unknown')),
                dispatch_ns INTEGER, end_ns INTEGER, request_sha256 TEXT,
                response_sha256 TEXT, http_status INTEGER, usage_json TEXT,
                metadata_json TEXT, error_type TEXT);
              CREATE TABLE sdk_requests(
                request_id TEXT PRIMARY KEY, query_type TEXT NOT NULL,
                start_ns INTEGER NOT NULL, end_ns INTEGER,
                request_sha256 TEXT NOT NULL, response_sha256 TEXT,
                http_status INTEGER, error_type TEXT);
            """)
            meta = {"attempt_id": attempt_id, "limits": LIMITS,
                    "deadline_ns": time.monotonic_ns() + LIMITS["client_seconds"] * 10**9,
                    "scope": "b1_readonly_engineering_gate_not_recovery_score"}
            db.executemany("INSERT INTO meta VALUES (?,?)",
                           [(key, canonical(value).decode()) for key, value in meta.items()])
        return ledger

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        try:
            with db:
                yield db
        finally:
            db.close()

    def metadata(self):
        if not self.path.is_file():
            raise ValueError("model_budget_not_initialized")
        with self.connect() as db:
            values = {row["key"]: json.loads(row["value"]) for row in db.execute("SELECT * FROM meta")}
        if values.get("limits") != LIMITS:
            raise ValueError("model_budget_profile_changed")
        return values

    def remaining_seconds(self):
        remaining = (self.metadata()["deadline_ns"] - time.monotonic_ns()) / 1e9
        if remaining <= 0:
            raise TimeoutError("readonly_client_deadline_exhausted")
        return remaining

    def reserve(self, query):
        value = query_identity(query)
        rid, maximum = value["request_id"], value["max_new_tokens"]
        self.remaining_seconds()
        if not isinstance(rid, str) or not REQUEST_ID.fullmatch(rid):
            raise ValueError("model_request_id_invalid")
        if type(maximum) is not int or not 1 <= maximum <= LIMITS["output_tokens_per_request"]:
            raise ValueError("model_output_reservation_invalid")
        if len(canonical(value)) > LIMITS["input_bytes_per_request"]:
            raise ValueError("model_input_byte_limit_exceeded")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT COUNT(*) FROM model_requests WHERE state IN ('reserved','in_flight','unknown')").fetchone()[0]:
                raise ValueError("prior_model_execution_unresolved")
            count, used = db.execute("SELECT COUNT(*), COALESCE(SUM(max_output_tokens),0) FROM model_requests").fetchone()
            if count >= LIMITS["model_requests"] or used + maximum > LIMITS["reserved_output_tokens"]:
                raise ValueError("aggregate_model_budget_exhausted")
            db.execute("INSERT INTO model_requests(request_id,query_json,reservation_ns,max_output_tokens,state) VALUES (?,?,?,?,?)",
                       (rid, canonical(value).decode(), time.monotonic_ns(), maximum, "reserved"))
        return rid

    def begin_dispatch(self, query):
        value = query_identity(query)
        rid = value["request_id"]
        self.remaining_seconds()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM model_requests WHERE request_id=?", (rid,)).fetchone()
            if row is None or row["state"] != "reserved" or json.loads(row["query_json"]) != value:
                raise ValueError("model_reservation_missing_changed_or_consumed")
            if db.execute("SELECT COUNT(*) FROM model_requests WHERE state IN ('in_flight','unknown')").fetchone()[0]:
                raise ValueError("prior_model_execution_unresolved")
            sdk = db.execute("SELECT * FROM sdk_requests WHERE request_id=? AND query_type='llm'", (rid,)).fetchone()
            if sdk is None:
                raise ValueError("model_sdk_request_not_recorded")
            db.execute("UPDATE model_requests SET state='in_flight',dispatch_ns=? WHERE request_id=?",
                       (time.monotonic_ns(), rid))
        return rid

    def wire_request(self, rid, raw):
        path = self.root / "model" / rid / "request.json"
        value = json.loads(raw)
        with self.connect() as db:
            row = db.execute("SELECT * FROM model_requests WHERE request_id=?", (rid,)).fetchone()
            if row is None or row["state"] != "in_flight" or row["request_sha256"] is not None:
                raise ValueError("model_wire_request_unbound_or_repeated")
            expected = json.loads(row["query_json"])
            if (value.get("model") != MODEL_NAME or value.get("messages") != expected["messages"]
                    or value.get("max_tokens") != expected["max_new_tokens"]
                    or value.get("temperature") != expected["temperature"]
                    or value.get("response_format") != expected["response_format"]
                    or value.get("stream", False) is not False
                    or value.get("tools", []) != (expected["tools"] or [])):
                raise ValueError("model_wire_request_differs_from_reservation")
            sha = write_once(path, raw)
            db.execute("UPDATE model_requests SET request_sha256=? WHERE request_id=?", (sha, rid))

    def wire_response(self, rid, raw, status):
        sha = write_once(self.root / "model" / rid / "response.json", raw)
        try:
            body = json.loads(raw)
        except (UnicodeError, ValueError):
            body = None
        usage = normalize_usage(body.get("usage") if isinstance(body, dict) else None)
        metadata = {"request_id": rid, "wire_response_sha256": sha,
                    "http_status": status, "usage_status": usage["status"]}
        if isinstance(body, dict):
            metadata["provider_fields"] = {key: body.get(key) for key in (
                "id", "model", "created", "object", "system_fingerprint", "service_tier")}
            metadata["finish_reasons"] = [item.get("finish_reason") for item in body.get("choices", []) if isinstance(item, dict)]
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM model_requests WHERE request_id=?", (rid,)).fetchone()
            if row is None or row["state"] != "in_flight" or row["request_sha256"] is None:
                raise ValueError("model_wire_response_unbound_or_repeated")
            metadata["wire_request_sha256"] = row["request_sha256"]
            db.execute("UPDATE model_requests SET state='response_received',end_ns=?,response_sha256=?,http_status=?,usage_json=?,metadata_json=? WHERE request_id=?",
                       (time.monotonic_ns(), sha, status, canonical(usage).decode(), canonical(metadata).decode(), rid))

    def uncertain(self, rid, error):
        with self.connect() as db:
            # A completed backend response is retained even if the SDK client disconnects.
            db.execute("UPDATE model_requests SET state='unknown',end_ns=?,error_type=? WHERE request_id=? AND state IN ('reserved','in_flight')",
                       (time.monotonic_ns(), type(error).__name__, rid))

    def record_sdk_start(self, rid, query_type, raw):
        if not isinstance(rid, str) or not REQUEST_ID.fullmatch(rid) or query_type not in {"llm", "tool"}:
            raise ValueError("sdk_request_identity_invalid")
        self.remaining_seconds()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT COUNT(*) FROM sdk_requests").fetchone()[0] >= LIMITS["sdk_requests"]:
                raise ValueError("sdk_request_budget_exhausted")
            if query_type == "llm" and db.execute("SELECT COUNT(*) FROM model_requests WHERE request_id=? AND state='reserved'", (rid,)).fetchone()[0] != 1:
                raise ValueError("sdk_model_request_not_reserved")
            sha = write_once(self.root / "sdk" / rid / "request.json", raw)
            db.execute("INSERT INTO sdk_requests(request_id,query_type,start_ns,request_sha256) VALUES (?,?,?,?)",
                       (rid, query_type, time.monotonic_ns(), sha))

    def record_sdk_end(self, rid, raw=None, status=None, error=None):
        sha = write_once(self.root / "sdk" / rid / "response.json", raw) if raw is not None else None
        with self.connect() as db:
            db.execute("UPDATE sdk_requests SET end_ns=?,response_sha256=?,http_status=?,error_type=? WHERE request_id=?",
                       (time.monotonic_ns(), sha, status, type(error).__name__ if error else None, rid))

    def receipt(self, rid):
        with self.connect() as db:
            row = db.execute("SELECT * FROM model_requests WHERE request_id=?", (rid,)).fetchone()
        if row is None:
            raise ValueError("model_receipt_missing")
        return dict(row)

    def summary(self):
        self.metadata()
        with self.connect() as db:
            rows = [dict(row) for row in db.execute("SELECT * FROM model_requests ORDER BY reservation_ns")]
            sdk = [dict(row) for row in db.execute("SELECT * FROM sdk_requests ORDER BY start_ns")]
        errors = []
        for collection, kind in ((rows, "model"), (sdk, "sdk")):
            for row in collection:
                for part in ("request", "response"):
                    sha = row.get(part + "_sha256")
                    path = self.root / kind / row["request_id"] / (part + ".json")
                    if sha is None or not path.is_file() or digest(path.read_bytes()) != sha:
                        errors.append({"request_id": row["request_id"], "kind": kind, "part": part})
        usage = [json.loads(row["usage_json"]) if row["usage_json"] else normalize_usage(None) for row in rows]
        usage_violations = [{"request_id": row["request_id"], "kind": "output_exceeds_reservation"}
            for row, item in zip(rows, usage)
            if item["counts"]["completion_tokens"] is not None
            and item["counts"]["completion_tokens"] > row["max_output_tokens"]]
        totals = {}
        for field in ("prompt_tokens", "completion_tokens", "total_tokens"):
            known = [item["counts"][field] for item in usage if item["counts"][field] is not None]
            totals[field] = {"known_sum": sum(known), "unknown_requests": len(rows) - len(known),
                             "complete_total": sum(known) if rows and len(known) == len(rows) else None}
        return {"scope": "local_model_accounting_not_recovery_or_speed_result",
                "reserved_model_requests": len(rows),
                "reserved_output_tokens": sum(row["max_output_tokens"] for row in rows),
                "reservations_ever_refunded": 0, "sdk_requests": len(sdk),
                "request_ids": [row["request_id"] for row in rows],
                "states": {name: sum(row["state"] == name for row in rows)
                           for name in ("reserved", "in_flight", "response_received", "unknown")},
                "raw_model_io_complete": bool(rows) and not errors and all(row["state"] == "response_received" for row in rows),
                "usage_budget_violations": usage_violations,
                "usage_complete": bool(rows) and all(item["status"] == "complete" for item in usage),
                "usage_totals": totals, "evidence_errors": errors}


def current_ledger():
    ledger = Ledger(Path(os.environ["G1_LOG_DIR"]) / "b1-metering")
    if ledger.metadata()["attempt_id"] != os.environ["G1_ATTEMPT_ID"]:
        raise ValueError("model_ledger_attempt_mismatch")
    return ledger


def _wire_request(request):
    rid = getattr(LOCAL, "request_id", None)
    if (not rid or request.headers.get("X-B1-Request-ID") != rid
            or str(request.url) != MODEL_ORIGIN + "/chat/completions" or request.method != "POST"):
        raise ValueError("model_wire_destination_or_request_id_invalid")
    current_ledger().wire_request(rid, request.content)


def _wire_response(response):
    rid = getattr(LOCAL, "request_id", None)
    if not rid or response.request.headers.get("X-B1-Request-ID") != rid:
        raise ValueError("model_wire_response_request_id_invalid")
    raw = response.read()
    current_ledger().wire_response(rid, raw, response.status_code)


def build_local_client(base_url, api_key):
    if base_url != MODEL_ORIGIN or api_key != "local-only":
        raise ValueError("readonly_gate_permits_only_pinned_local_model")
    import httpx
    from openai import OpenAI
    timeout = httpx.Timeout(LIMITS["model_request_seconds"], connect=5)
    client = httpx.Client(trust_env=False, timeout=timeout,
                          event_hooks={"request": [_wire_request], "response": [_wire_response]})
    return OpenAI(base_url=base_url, api_key=api_key, max_retries=0,
                  timeout=timeout, http_client=client)


def metered_create(model, query, model_name, completion_kwargs):
    if model_name != MODEL_NAME or getattr(model, "max_retries", None) != 0:
        raise ValueError("unexpected_model_or_automatic_retries")
    ledger = current_ledger()
    rid = ledger.begin_dispatch(query)
    LOCAL.request_id = rid
    try:
        response = model.chat.completions.create(model=model_name,
            extra_headers={"X-B1-Request-ID": rid}, **completion_kwargs)
        if ledger.receipt(rid)["state"] != "response_received":
            raise ValueError("model_backend_return_without_raw_response")
        return response
    except BaseException as error:
        ledger.uncertain(rid, error)
        raise
    finally:
        LOCAL.request_id = None


def attach_metering(response, query):
    rid = getattr(query, "request_id", None)
    record = current_ledger().receipt(rid)
    usage = json.loads(record["usage_json"]) if record["usage_json"] else normalize_usage(None)
    response.request_id = rid
    response.usage = usage["raw"]
    response.model_metadata = (json.loads(record["metadata_json"]) if record["metadata_json"] else
        {"request_id": rid, "state": record["state"], "usage_status": usage["status"]})
    return response


def sdk_post(base_url, endpoint, data):
    """Keep the SDK's exact request shape while adding a bound and wire capture."""
    if base_url != KERNEL_ORIGIN or endpoint != "/query":
        raise ValueError("readonly_sdk_destination_invalid")
    import requests
    query_type, query = data["query_type"], data["query_data"]
    if query_type == "llm":
        rid = query.get("request_id")
    elif query_type == "tool" and len(query.get("tool_calls", [])) == 1:
        rid = query["tool_calls"][0]["id"]
    else:
        raise ValueError("readonly_sdk_query_type_invalid")
    ledger = current_ledger()
    session = requests.Session()
    session.trust_env = False
    session.mount("http://", requests.adapters.HTTPAdapter(max_retries=0))
    prepared = session.prepare_request(requests.Request("POST", base_url + endpoint, json=data))
    raw = prepared.body.encode() if isinstance(prepared.body, str) else prepared.body
    ledger.record_sdk_start(rid, query_type, raw)
    try:
        with session.send(prepared, timeout=(5, min(360, ledger.remaining_seconds())), allow_redirects=False) as reply:
            ledger.record_sdk_end(rid, reply.content, reply.status_code)
            reply.raise_for_status()
            if 300 <= reply.status_code < 400:
                raise ValueError("readonly_sdk_redirect_rejected")
            return reply.json()
    except BaseException as error:
        # Do not overwrite a response already stored before JSON/HTTP validation.
        with ledger.connect() as db:
            db.execute("UPDATE sdk_requests SET end_ns=COALESCE(end_ns,?),error_type=? WHERE request_id=?",
                       (time.monotonic_ns(), type(error).__name__, rid))
        if query_type == "llm":
            ledger.uncertain(rid, error)
        raise
    finally:
        session.close()


def read_summary(log):
    try:
        return Ledger(Path(log) / "b1-metering").summary()
    except Exception as error:
        return {"raw_model_io_complete": False, "usage_complete": False,
                "error_type": type(error).__name__}
