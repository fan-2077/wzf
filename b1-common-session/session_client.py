"""A bounded client of the host-owned full-macro session; no business runner."""
from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import time
import uuid

REQUEST_SCHEMA = "b1-public-full-helper-request-v1"
RESPONSE_SCHEMA = "b1-public-full-helper-response-v1"
IDENTITY_SCHEMA = "b1-public-full-helper-identity-v1"
REQUEST_LIMIT = 16384
RESPONSE_LIMIT = 65536
REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")
HELPER_ID = re.compile(r"full-[0-9a-f]{64}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
IDENTITY_FIELDS = {"attempt_id", "physical_scope_id", "ledger_epoch", "namespace_uid",
                   "role", "launch_context_sha256", "derived_payload_binding_sha256"}


class ClientError(ValueError):
    """Fixed public diagnostic, without filesystem paths or exception text."""


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ClientError("duplicate_json_field")
            value[key] = item
        return value

    def invalid_constant(_value):
        raise ClientError("nonfinite_json_value")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                      parse_constant=invalid_constant)


def read_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ClientError("owned_record_not_bounded_regular_file")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if len(raw) > limit or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ClientError("owned_record_changed_or_exceeded_limit")
    return raw


def write_once(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


@dataclass(frozen=True)
class HostConfiguration:
    identity_path: Path = Path("/logs/b1-common-session/session_identity.json")
    socket_path: Path = Path("/logs/b1-common-session/owner.sock")
    receipts_directory: Path = Path("/logs/b1-common-session/sdk-receipts")
    timeout_seconds: float = 5.0

    @classmethod
    def from_environment(cls):
        # These are launcher settings, never Tool.run arguments.
        return cls(
            Path(os.environ.get("B1_COMMON_SESSION_IDENTITY_PATH", str(cls.identity_path))),
            Path(os.environ.get("B1_COMMON_SESSION_SOCKET_PATH", str(cls.socket_path))),
            Path(os.environ.get("B1_COMMON_SESSION_RECEIPTS_DIR", str(cls.receipts_directory))),
        )


class SessionClient:
    def __init__(self, configuration):
        self.configuration = configuration
        if not all(isinstance(path, Path) and path.is_absolute() for path in (
                configuration.identity_path, configuration.socket_path, configuration.receipts_directory)):
            raise ClientError("host_configuration_requires_absolute_paths")
        if type(configuration.timeout_seconds) not in (int, float) or not 0 < configuration.timeout_seconds <= 30:
            raise ClientError("host_timeout_out_of_range")

    def identity(self):
        raw = read_regular(self.configuration.identity_path, REQUEST_LIMIT)
        value = decode(raw)
        if not isinstance(value, dict) or set(value) != {"schema", "helper_id", "identity_binding", "socket_path"}:
            raise ClientError("host_identity_shape_invalid")
        binding = value["identity_binding"]
        if value["schema"] != IDENTITY_SCHEMA or not isinstance(binding, dict) or set(binding) != IDENTITY_FIELDS:
            raise ClientError("host_identity_schema_invalid")
        if not all(isinstance(item, str) and item for item in binding.values()) or binding["role"] != "single":
            raise ClientError("host_identity_role_or_binding_invalid")
        if not all(SHA256.fullmatch(binding[key]) for key in ("launch_context_sha256", "derived_payload_binding_sha256")):
            raise ClientError("host_identity_digest_invalid")
        if value["helper_id"] != "full-" + digest(canonical(binding)):
            raise ClientError("host_helper_identity_mismatch")
        if value["socket_path"] != str(self.configuration.socket_path):
            raise ClientError("host_socket_identity_mismatch")
        return value, digest(raw)

    def invoke(self, parameters):
        if (not isinstance(parameters, dict) or not isinstance(parameters.get("operation"), str)
                or parameters["operation"] not in {"start", "poll"}):
            raise ClientError("sdk_operation_not_allowed")
        operation = parameters["operation"]
        expected = ({"operation", "request_id", "parent_model_request_id"} if operation == "start"
                    else {"operation", "request_id", "helper_id"})
        if set(parameters) != expected:
            raise ClientError("sdk_argument_fields_invalid")
        rid = parameters["request_id"]
        if not isinstance(rid, str) or not REQUEST_ID.fullmatch(rid):
            raise ClientError("sdk_request_id_invalid")
        parent = parameters.get("parent_model_request_id")
        if parent is not None and (not isinstance(parent, str) or not REQUEST_ID.fullmatch(parent)):
            raise ClientError("parent_model_request_id_invalid")
        identity, identity_sha = self.identity()
        helper_id = identity["helper_id"]
        if operation == "poll" and parameters["helper_id"] != helper_id:
            raise ClientError("poll_helper_identity_mismatch")
        root = self.configuration.receipts_directory
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        claims, exchanges = root / "dispatch-claims", root / "exchanges"
        for directory in (root, claims, exchanges):
            directory.mkdir(mode=0o700, exist_ok=True)
            if directory.is_symlink() or not directory.is_dir():
                raise ClientError("receipt_directory_invalid")
        lock = os.open(claims / (rid + ".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(lock).st_mode):
                raise ClientError("request_lock_not_regular")
            lock_deadline = time.monotonic() + self.configuration.timeout_seconds
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= lock_deadline:
                        raise ClientError("request_exchange_busy_poll_only")
                    time.sleep(0.01)
            claim_path = claims / (rid + ".json")
            prior = read_regular(claim_path, REQUEST_LIMIT) if claim_path.exists() else None
            request = {"schema": REQUEST_SCHEMA, "operation": operation, "request_id": rid, "helper_id": helper_id}
            claim_created = False
            if operation == "start":
                request.update(parameters={}, parent_model_request_id=parent)
                raw_claim = canonical(request) + b"\n"
                if prior is None:
                    # Persist the complete identity before the first socket connection.
                    # Once this claim exists, even a connection failure is poll-only.
                    write_once(claim_path, raw_claim)
                    claim_created = True
                elif prior != raw_claim:
                    raise ClientError("request_id_conflict")
                else:
                    request = {"schema": REQUEST_SCHEMA, "operation": "poll", "request_id": rid, "helper_id": helper_id}
            elif prior is not None:
                original = decode(prior)
                if original.get("helper_id") != helper_id or original.get("request_id") != rid:
                    raise ClientError("poll_original_request_binding_mismatch")
                parent = original.get("parent_model_request_id")
            return self._exchange(request, operation, parent, identity_sha, exchanges, claim_created)
        except OSError as error:
            # A receipt failure can occur after dispatch. Keep the original
            # handle even when no additional local evidence can be written.
            return {
                "scope": "local_full_macro_sdk_adapter_not_remote_qualified",
                "helper_id": helper_id, "request_id": rid, "operation": operation,
                "transport_state": "unknown", "next_allowed_operation": "poll",
                "parent_model_request_id": parent, "parent_attribution": "caller_declaration_only",
                "model_causality_verified": False, "automatic_retries": 0, "budget_refund": False,
                "business_success": None, "original_host_evaluation_result": None,
                "owner_response": None, "capture_complete": False,
                "error": {"code": "client_receipt_unavailable", "type": type(error).__name__},
            }
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
            os.close(lock)

    def _validate_response(self, raw, request):
        if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
            raise ClientError("owner_response_frame_incomplete_or_multiple")
        value = decode(raw)
        expected = {"schema", "ok", "operation", "request_id", "helper_id", "disposition", "session", "error"}
        if not isinstance(value, dict) or set(value) != expected:
            raise ClientError("owner_response_shape_invalid")
        if value["schema"] != RESPONSE_SCHEMA or type(value["ok"]) is not bool:
            raise ClientError("owner_response_schema_invalid")
        if any(value[key] != request[key] for key in ("operation", "request_id", "helper_id")):
            raise ClientError("owner_response_identity_mismatch")
        if (not isinstance(value["disposition"], str) or value["disposition"] not in {
                "accepted", "same_request", "already_reserved_other_request", "status", "rejected"}):
            raise ClientError("owner_response_disposition_invalid")
        session = value["session"]
        if (not isinstance(session, dict) or not isinstance(session.get("state"), str)
                or session["state"] not in {"ready", "launch_reserved", "running", "process_exited", "unknown"}):
            raise ClientError("owner_session_state_invalid")
        if type(session.get("launch_reservations")) is not int or session["launch_reservations"] not in (0, 1):
            raise ClientError("owner_reservation_shape_invalid")
        if (not isinstance(session.get("request_binding"), str)
                or session["request_binding"] not in {"not_registered", "original", "other_request"}):
            raise ClientError("owner_request_binding_invalid")
        original = session.get("original_request_id")
        if original is not None and (not isinstance(original, str) or not REQUEST_ID.fullmatch(original)):
            raise ClientError("owner_original_request_id_invalid")
        if any(type(session.get(key)) is not int or session[key] != 0
               for key in ("automatic_retries", "helper_model_calls")):
            raise ClientError("owner_unexpected_retry_or_model_call")
        if session.get("business_success") is not None or session.get("original_host_evaluation_result") is not None:
            raise ClientError("owner_promoted_process_to_business_result")
        if value["ok"] is True and value["error"] is not None:
            raise ClientError("owner_response_error_conflict")
        if value["ok"] is False and (not isinstance(value["error"], dict)
                or set(value["error"]) != {"code"} or not isinstance(value["error"]["code"], str)):
            raise ClientError("owner_rejection_shape_invalid")
        return value

    def _exchange(self, request, requested_operation, parent, identity_sha, exchanges, claim_created):
        exchange_id = uuid.uuid4().hex
        directory = exchanges / exchange_id
        directory.mkdir(mode=0o700)
        raw_request = canonical(request) + b"\n"
        if len(raw_request) > REQUEST_LIMIT:
            raise ClientError("owner_request_size_limit")
        write_once(directory / "request.bin", raw_request)
        started = time.monotonic_ns()
        raw_response, response, error, phase = bytearray(), None, None, "connect"
        evidence_errors = []
        deadline = time.monotonic() + self.configuration.timeout_seconds
        try:
            # Closing this connection never cancels or signals the persistent helper.
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
                def set_remaining():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("owner_exchange_deadline")
                    channel.settimeout(remaining)

                set_remaining()
                channel.connect(str(self.configuration.socket_path))
                phase = "send"
                set_remaining()
                channel.sendall(raw_request)
                phase = "receive"
                while b"\n" not in raw_response:
                    set_remaining()
                    part = channel.recv(min(4096, RESPONSE_LIMIT + 1 - len(raw_response)))
                    if not part:
                        raise ClientError("owner_response_eof_before_frame")
                    raw_response.extend(part)
                    if len(raw_response) > RESPONSE_LIMIT:
                        raise ClientError("owner_response_size_limit")
                response = self._validate_response(bytes(raw_response), request)
        except (OSError, ValueError, UnicodeError, RecursionError) as exc:
            error = {"code": str(exc) if isinstance(exc, ClientError) else "owner_exchange_unresolved",
                     "type": type(exc).__name__, "phase": phase}
        finally:
            # Retain partial bytes on timeout, EOF, invalid JSON and oversize frames.
            try:
                write_once(directory / "response.bin", bytes(raw_response))
            except OSError as exc:
                evidence_errors.append({"stage": "response", "type": type(exc).__name__})
            metadata = {
                "schema": "b1-session-sdk-owner-exchange-v1", "exchange_id": exchange_id,
                "helper_id": request["helper_id"], "request_id": request["request_id"],
                "owner_original_request_id": response["session"]["original_request_id"] if response else None,
                "requested_operation": requested_operation, "wire_operation": request["operation"],
                "start_dispatch_claim_created": claim_created, "identity_record_sha256": identity_sha,
                "parent_model_request_id": parent, "parent_attribution": "caller_declaration_only",
                "model_causality_verified": False, "captured_layer": "unix_owner_application_frames_including_lf",
                "request_bytes": len(raw_request), "request_sha256": digest(raw_request),
                "response_bytes": len(raw_response), "response_sha256": digest(bytes(raw_response)),
                "response_frame_validated": response is not None, "error": error,
                "evidence_errors": list(evidence_errors),
                "automatic_retries": 0, "budget_refund": False,
                "elapsed_seconds": (time.monotonic_ns() - started) / 1e9,
            }
            try:
                write_once(directory / "metadata.json", canonical(metadata) + b"\n")
            except OSError as exc:
                evidence_errors.append({"stage": "metadata", "type": type(exc).__name__})
        return {
            "scope": "local_full_macro_sdk_adapter_not_remote_qualified",
            "helper_id": request["helper_id"], "request_id": request["request_id"],
            "exchange_id": exchange_id, "operation": requested_operation, "wire_operation": request["operation"],
            "transport_state": "response_received" if response is not None else "unknown",
            "parent_model_request_id": parent, "parent_attribution": "caller_declaration_only",
            "model_causality_verified": False, "automatic_retries": 0, "budget_refund": False,
            "business_success": None, "original_host_evaluation_result": None,
            "owner_response": response, "error": error, "next_allowed_operation": "poll",
            "capture_complete": not evidence_errors, "evidence_errors": evidence_errors,
            "capture": {"request_sha256": metadata["request_sha256"], "response_sha256": metadata["response_sha256"],
                        "response_frame_validated": metadata["response_frame_validated"],
                        "layer": metadata["captured_layer"]},
        }
