"""Single-dispatch transport for the pinned, real SREGym endpoints.

This file contains no incident solver, simulated business service, or oracle.
Run under the separate Python 3.11 interpreter from requirements-native.txt.
Configuration and role identity are injected by the launcher, not model arguments.
"""
from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import timedelta
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


CLIENT_PINS = {"mcp": "1.9.4", "httpx": "0.28.1", "anyio": "4.9.0", "pydantic": "2.11.5"}
MCP_OPERATIONS = {
    "kubectl": "exec_kubectl_cmd_safely",
    "rollback": "rollback_command",
    "rollback_history": "get_previous_rollbackable_cmd",
}
READ_OPERATIONS = {"app_info", "status", "describe_tools", "rollback_history"}
OPERATIONS = READ_OPERATIONS | {"kubectl", "rollback", "submit"}
IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")


def origin(value: str) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in {"", "/"}):
        raise ValueError("Endpoint must be a launcher-owned HTTP(S) origin without path, credentials or query")
    return value.rstrip("/")


@dataclass(frozen=True)
class Config:
    api_origin: str
    mcp_origin: str
    attempt_id: str
    role: str
    log_dir: Path
    timeout_seconds: float = 330.0

    def __post_init__(self):
        object.__setattr__(self, "api_origin", origin(self.api_origin))
        object.__setattr__(self, "mcp_origin", origin(self.mcp_origin))
        for value in (self.attempt_id, self.role):
            if not IDENTIFIER.fullmatch(value):
                raise ValueError("Invalid launcher-owned attempt or role identifier")
        if not (0 < self.timeout_seconds <= 3600):
            raise ValueError("Invalid explicit transport timeout")

    @property
    def session_id(self) -> str:
        # Native rollback stacks are indexed by sregym_ssid, not MCP connection id.
        return hashlib.sha256(f"{self.attempt_id}:{self.role}".encode()).hexdigest()

    @classmethod
    def from_environment(cls) -> "Config":
        return cls(
            api_origin=os.environ["SRE_NATIVE_API_URL"],
            mcp_origin=os.environ["SRE_NATIVE_MCP_URL"],
            attempt_id=os.environ["SRE_NATIVE_ATTEMPT_ID"],
            role=os.environ["SRE_NATIVE_ROLE"],
            log_dir=Path(os.environ["SRE_NATIVE_LOG_DIR"]),
            timeout_seconds=float(os.environ.get("SRE_NATIVE_TIMEOUT_SECONDS", "330")),
        )


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # A redirect must never create an unrecorded second submission.
        return None


def validate_request(request: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    if not isinstance(request, dict) or set(request) != {"call_id", "operation", "arguments"}:
        raise ValueError("Only call_id, operation and arguments are accepted")
    if not isinstance(request["call_id"], str) or not IDENTIFIER.fullmatch(request["call_id"]):
        raise ValueError("Invalid driver-generated call identifier")
    operation, args = request["operation"], request["arguments"]
    if not isinstance(operation, str) or operation not in OPERATIONS or not isinstance(args, dict):
        raise ValueError("Unsupported operation or malformed arguments")
    expected = {"cmd"} if operation == "kubectl" else {"solution"} if operation == "submit" else set()
    if set(args) != expected:
        raise ValueError(f"{operation} requires exactly {sorted(expected)}")
    if operation == "kubectl" and (not isinstance(args["cmd"], str) or not args["cmd"].startswith("kubectl ")):
        raise ValueError("kubectl operation requires a native kubectl command")
    if operation == "submit" and not isinstance(args["solution"], str):
        raise ValueError("Submission must be a string; its text is not the native recovery verdict")
    return operation, args


def _http_once(config: Config, operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
    path = {"app_info": "/get_app", "status": "/status", "submit": "/submit"}[operation]
    body = {"solution": arguments["solution"], "stage": "mitigation"} if operation == "submit" else None
    request = Request(config.api_origin + path,
                      data=json.dumps(body).encode() if body is not None else None,
                      headers={"Content-Type": "application/json"},
                      method="POST" if body is not None else "GET")
    # Keep native filtered-network proxy settings; do not bypass environment proxies.
    opener = build_opener(NoRedirect())
    try:
        with opener.open(request, timeout=config.timeout_seconds) as response:
            status, raw = response.status, response.read().decode("utf-8", errors="replace")
    except HTTPError as error:
        status, raw = error.code, error.read().decode("utf-8", errors="replace")
    try:
        payload: Any = json.loads(raw)
    except json.JSONDecodeError:
        payload = {"unparsed_body": raw}
    accepted = (operation == "submit" and status == 200 and isinstance(payload, dict)
                and payload.get("stage") == "mitigation" and str(payload.get("status")) == "200")
    # Native submit_solution catches unexpected grading exceptions as HTTP400.
    # Without a typed pre-dispatch rejection proof, even 4xx cannot establish
    # that this attempt did not enter evaluation.
    unknown_submission = operation == "submit" and not accepted
    return {
        "transport_state": "response_received",
        "http_status": status,
        "native_response": payload,
        "submission_state": "accepted_for_evaluation" if accepted else
                            "outcome_unknown" if unknown_submission else
                            "rejected" if operation == "submit" else "not_submitted",
        "side_effect_state": "evaluation_requested" if accepted else
                             "unknown" if unknown_submission else
                             "not_executed" if operation == "submit" else "read_only",
        "business_success": None,
    }


def check_client_versions() -> dict[str, str]:
    actual = {package: version(package) for package in CLIENT_PINS}
    if actual != CLIENT_PINS:
        raise RuntimeError(f"Native MCP worker dependency mismatch: expected {CLIENT_PINS}, actual {actual}")
    return actual


async def _mcp_once(config: Config, operation: str, arguments: dict[str, Any], state: dict) -> dict:
    check_client_versions()
    from mcp import ClientSession
    from mcp.client.sse import sse_client

    stack = AsyncExitStack()
    result = None
    teardown_error = None
    try:
        streams = await stack.enter_async_context(sse_client(
            config.mcp_origin + "/kubectl/sse",
            headers={"sregym_ssid": config.session_id},
            timeout=10.0,
            sse_read_timeout=config.timeout_seconds,
        ))
        session = await stack.enter_async_context(ClientSession(
            *streams, read_timeout_seconds=timedelta(seconds=config.timeout_seconds)))
        await session.initialize()
        state["dispatch_started"] = True
        response = (await session.list_tools() if operation == "describe_tools" else
                    await session.call_tool(MCP_OPERATIONS[operation], arguments=arguments))
        # Retain native typed content and isError. A returned string can contain
        # a shell error or partial effect even if MCP isError is false.
        native = response.model_dump(mode="json")
        result = {
            "transport_state": "response_received",
            "native_response": native,
            "native_mcp_is_error": native.get("isError"),
            "side_effect_state": "read_only" if operation in READ_OPERATIONS else "not_certified",
            "business_success": None,
        }
    finally:
        try:
            await stack.aclose()
        except BaseException as error:
            teardown_error = f"{type(error).__name__}: {error}"
            if result is None:
                raise
    if teardown_error:
        # A completed tool response survives transport teardown failure.
        result["teardown_warning"] = teardown_error
    return result


def _append_record(path: Path, record: dict) -> None:
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
        output.flush()
        os.fsync(output.fileno())


def execute(config: Config, request: dict[str, Any]) -> dict[str, Any]:
    operation, arguments = validate_request(request)
    call_id = request["call_id"]
    directory = config.log_dir / config.attempt_id / config.role
    directory.mkdir(parents=True, exist_ok=True)
    journal = directory / f"{call_id}.jsonl"
    # Each call id can be dispatched once, including after an interrupted worker.
    # This is not business idempotency: a new call id still needs explicit audit.
    with journal.open("x", encoding="utf-8"):
        pass
    started = time.monotonic()
    common = {"schema_version": 1, "attempt_id": config.attempt_id, "role": config.role,
              "call_id": call_id, "operation": operation, "session_id": config.session_id,
              "automatic_retries": 0}
    _append_record(journal, {**common, "event": "start", "wall": time.time(), "mono": started,
                            "arguments": arguments,
                            "arguments_sha256": hashlib.sha256(json.dumps(arguments, sort_keys=True).encode()).hexdigest()})
    state = {"dispatch_started": False}
    try:
        if operation in {"app_info", "status", "submit"}:
            # From this boundary on, a transport exception cannot prove that
            # the peer did not accept the request.
            state["dispatch_started"] = True
            result = _http_once(config, operation, arguments)
        else:
            result = asyncio.run(_mcp_once(config, operation, arguments, state))
    except Exception as error:
        sent = state["dispatch_started"]
        result = {
            "transport_state": "outcome_unknown" if sent else "not_dispatched",
            "side_effect_state": "read_only" if operation in READ_OPERATIONS else
                                 "unknown" if sent else "not_executed",
            "business_success": None,
            "error": {"type": type(error).__name__, "message": str(error)},
        }
    result = {**common, **result, "elapsed_seconds": time.monotonic() - started,
              "journal": str(journal), "dispatch_started": state["dispatch_started"]}
    try:
        _append_record(journal, {**result, "event": "end", "wall": time.time(), "mono": time.monotonic()})
    except OSError as error:
        # Never relabel an already dispatched operation as not executed just
        # because its final journal write failed.
        result["audit_write_error"] = f"{type(error).__name__}: {error}"
        result["trace_complete"] = False
    else:
        result["trace_complete"] = True
    return result


def main() -> None:
    # Stdout is a single machine-readable envelope. No host-oracle import.
    try:
        result = execute(Config.from_environment(), json.load(sys.stdin))
    except Exception as error:
        # Bootstrap/validation failures happen before dispatch. A duplicate
        # call id may refer to an earlier dispatched worker, so it is unknown.
        duplicate = isinstance(error, FileExistsError)
        result = {"transport_state": "duplicate_call_id" if duplicate else "bootstrap_error",
                  "side_effect_state": "unknown" if duplicate else "not_executed",
                  "business_success": None, "automatic_retries": 0,
                  "error": {"type": type(error).__name__, "message": str(error)}}
    print(json.dumps(result, ensure_ascii=False, allow_nan=False))


if __name__ == "__main__":
    main()
