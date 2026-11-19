"""One durable full-public-helper reservation, with a local Unix socket.

This owner starts the real frozen B0 entry once. It never offers native shell,
reset, retry, submit, or lower-level business operations. A caller losing a
reply can only inspect the preallocated helper identity. OS process state is
kept separate from the public controller report and the host's original score.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import socket
import sqlite3
import stat
import subprocess
import threading
import time

from controller_adapter import (HERE, LOG_ROOT, NATIVE_PYTHON, canonical,
    clean_entry_environment, digest, helper_id, read_regular, trusted_launch, write_once)

REQUEST_SCHEMA = "b1-public-full-helper-request-v1"
RESPONSE_SCHEMA = "b1-public-full-helper-response-v1"
IDENTITY_SCHEMA = "b1-public-full-helper-identity-v1"
REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")
PRODUCTION_ROOT = Path("/logs/b1-common-session")
MAX_REQUEST = 16384
MAX_RESPONSE = 65536
MAX_RESULT = 16 * 1024 * 1024
IDENTITY_FIELDS = {"attempt_id", "physical_scope_id", "ledger_epoch", "namespace_uid",
                   "role", "launch_context_sha256", "derived_payload_binding_sha256"}


class ProtocolError(ValueError):
    pass


def parse_object(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ProtocolError("duplicate_json_key")
            value[key] = item
        return value
    def bad_constant(_):
        raise ProtocolError("nonfinite_json_value")
    text = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
    value = json.loads(text, object_pairs_hook=pairs, parse_constant=bad_constant)
    if not isinstance(value, dict):
        raise ProtocolError("request_object_required")
    return value


def process_identity(pid):
    # starttime belongs to the original process, not a recyclable PID alone.
    raw = Path(f"/proc/{pid}/stat").read_text()
    tail = raw[raw.rfind(")") + 2:].split()
    return {"pid": pid, "starttime_ticks": int(tail[19]),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}


class ControllerLauncher:
    """Production launcher; no command or environment comes from the socket."""
    def __init__(self, session_root, binding_path, identity_binding):
        self.session_root = Path(session_root)
        self.binding_path = Path(binding_path).absolute()
        self.identity_binding = identity_binding

    def __call__(self, reservation_path, stdout, stderr):
        current = trusted_launch(self.binding_path, require_active=True)
        if current["identity_binding"] != self.identity_binding:
            raise ValueError("trusted_launch_identity_changed_before_spawn")
        if Path(reservation_path) != self.session_root / "controller_launch.json":
            raise ValueError("unexpected_launch_reservation_path")
        return subprocess.Popen(
            [NATIVE_PYTHON, "-B", str(HERE / "controller_adapter.py"), "exec-controller",
             "--session-root", str(self.session_root), "--binding", str(self.binding_path)],
            stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, close_fds=True,
            start_new_session=True, cwd=LOG_ROOT, env=clean_entry_environment(os.environ))


class SessionOwner:
    """State core. Only production() is exposed by the command-line server.

    The constructor's launcher seam permits controlled *real subprocesses* in
    local state-machine tests; the IPC protocol has no fixture/command option.
    """
    def __init__(self, root, identity_binding, launcher, *, result_path):
        self.root = Path(root).absolute()
        if (set(identity_binding) != IDENTITY_FIELDS or identity_binding.get("role") != "single"
                or any(not isinstance(value, str) or not value for value in identity_binding.values())):
            raise ValueError("fixed_trusted_identity_required")
        self.identity_binding = json.loads(canonical(identity_binding))
        self.helper_id = helper_id(self.identity_binding)
        self.socket_path = self.root / "owner.sock"
        if len(os.fsencode(self.socket_path)) >= 108:
            raise ValueError("unix_socket_path_too_long")
        self.result_path = Path(result_path).absolute()
        self.launcher = launcher
        self.database = self.root / "owner.sqlite"
        self._operation_lock = threading.RLock()
        self._process = None
        self._output_files = []
        self._socket = None
        self._socket_identity = None
        self._stopping = False
        self._closed = False
        self._owner_lock = None
        if self.root.is_symlink():
            raise ValueError("session_root_symlink_forbidden")
        self.root.mkdir(mode=0o700, parents=False, exist_ok=True)
        if not self.root.is_dir():
            raise ValueError("session_root_directory_required")
        os.chmod(self.root, 0o700)
        try:
            self._owner_lock = os.open(self.root / "owner.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            if not stat.S_ISREG(os.fstat(self._owner_lock).st_mode):
                raise ValueError("owner_lock_regular_file_required")
            fcntl.flock(self._owner_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._initialize()
            identity = {"schema": IDENTITY_SCHEMA, "helper_id": self.helper_id,
                        "identity_binding": self.identity_binding, "socket_path": str(self.socket_path)}
            path = self.root / "session_identity.json"
            if path.exists() or path.is_symlink():
                if read_regular(path) != canonical(identity) + b"\n":
                    raise ValueError("public_session_identity_changed")
            else:
                write_once(path, identity)
        except BaseException:
            if self._owner_lock is not None:
                os.close(self._owner_lock)
                self._owner_lock = None
            raise

    @classmethod
    def production(cls, root, binding_path):
        if Path(root).absolute() != PRODUCTION_ROOT:
            raise ValueError("fixed_production_session_root_required")
        launch = trusted_launch(binding_path)
        launcher = ControllerLauncher(root, binding_path, launch["identity_binding"])
        return cls(root, launch["identity_binding"], launcher,
                   result_path=LOG_ROOT / "b0-agent-result.json")

    def _connect(self):
        if self.database.is_symlink():
            raise ValueError("session_database_symlink_forbidden")
        db = sqlite3.connect(self.database, isolation_level=None, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        return db

    @staticmethod
    def _event(db, kind, details):
        db.execute("INSERT INTO events(kind,monotonic_ns,details_json) VALUES(?,?,?)",
                   (kind, time.monotonic_ns(), canonical(details).decode()))

    def _initialize(self):
        with closing(self._connect()) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
              CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS helper(
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),helper_id TEXT NOT NULL,
                state TEXT NOT NULL,request_id TEXT,request_json TEXT,raw_start BLOB,
                launch_reservations INTEGER NOT NULL CHECK(launch_reservations IN (0,1)),
                reserved_ns INTEGER,process_json TEXT,uncertainty TEXT,returncode INTEGER,
                exit_ns INTEGER,result_json TEXT);
              CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,monotonic_ns INTEGER NOT NULL,details_json TEXT NOT NULL);
            """)
            db.execute("BEGIN IMMEDIATE")
            original = db.execute("SELECT value FROM metadata WHERE key='identity'").fetchone()
            if original is None:
                if db.execute("SELECT count(*) FROM helper").fetchone()[0]:
                    raise ValueError("orphan_helper_without_identity")
                db.execute("INSERT INTO metadata VALUES('identity',?)", (canonical(self.identity_binding).decode(),))
                db.execute("INSERT INTO metadata VALUES('schema','b1-public-full-helper-owner-v1')")
                db.execute("INSERT INTO helper(singleton,helper_id,state,launch_reservations) VALUES(1,?,'ready',0)",
                           (self.helper_id,))
                self._event(db, "session_created", {"helper_id": self.helper_id})
            elif original["value"] != canonical(self.identity_binding).decode():
                raise ValueError("session_cannot_rebind_attempt_clock_budget_or_source")
            row = db.execute("SELECT * FROM helper WHERE singleton=1").fetchone()
            if row is None or row["helper_id"] != self.helper_id:
                raise ValueError("helper_identity_missing_or_changed")
            if row["state"] in {"launch_reserved", "running"}:
                db.execute("UPDATE helper SET state='unknown',uncertainty='owner_restarted_after_reservation' WHERE singleton=1")
                self._event(db, "unknown_latched", {"reason": "owner_restarted_after_reservation"})
            self._event(db, "owner_opened", {"owner": process_identity(os.getpid()),
                                           "automatic_recovery_or_respawn": False})
            db.execute("COMMIT")

    def _row(self):
        with closing(self._connect()) as db:
            return dict(db.execute("SELECT * FROM helper WHERE singleton=1").fetchone())

    def _unknown(self, reason):
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE helper SET state='unknown',uncertainty=COALESCE(uncertainty,?) WHERE singleton=1 AND launch_reservations=1",
                       (reason,))
            self._event(db, "unknown_latched", {"reason": reason, "automatic_retries": 0})
            db.execute("COMMIT")

    def _reserve(self, request, raw):
        binding = {key: request[key] for key in ("helper_id", "parameters", "parent_model_request_id")}
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM helper WHERE singleton=1").fetchone()
            if row["request_id"] == request["request_id"]:
                if row["request_json"] != canonical(binding).decode():
                    raise ProtocolError("request_id_conflict")
                db.execute("COMMIT")
                return "same_request"
            if request["parameters"] != {}:
                raise ProtocolError("full_helper_parameters_must_be_empty")
            if row["launch_reservations"]:
                db.execute("COMMIT")
                return "already_reserved_other_request"
            if row["state"] != "ready":
                raise ProtocolError("helper_not_ready_for_first_reservation")
            db.execute("UPDATE helper SET state='launch_reserved',request_id=?,request_json=?,raw_start=?,"
                       "launch_reservations=1,reserved_ns=? WHERE singleton=1",
                       (request["request_id"], canonical(binding).decode(), raw, time.monotonic_ns()))
            self._event(db, "launch_reserved", {"request_id": request["request_id"],
                        "request_sha256": digest(raw), "parent_model_request_id_claim": request["parent_model_request_id"]})
            db.execute("COMMIT")  # This durable commitment precedes every possible Popen.
        return "accepted"

    def _launch_once(self):
        row = self._row()
        if row["state"] != "launch_reserved" or row["launch_reservations"] != 1:
            raise RuntimeError("launch_requires_just_committed_reservation")
        try:
            launch = {"schema": "b1-public-full-helper-launch-v1", "helper_id": self.helper_id,
                      "identity_binding": self.identity_binding, "request_id": row["request_id"],
                      "request_sha256": digest(row["raw_start"]), "launch_reservations": 1}
            reservation = self.root / "controller_launch.json"
            write_once(reservation, launch)
            stdout = (self.root / "controller.stdout").open("xb")
            self._output_files.append(stdout)
            stderr = (self.root / "controller.stderr").open("xb")
            self._output_files.append(stderr)
            self._process = self.launcher(reservation, stdout, stderr)
            identity = process_identity(self._process.pid)
            with closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("UPDATE helper SET state='running',process_json=? WHERE singleton=1 AND state='launch_reserved'",
                           (canonical(identity).decode(),))
                self._event(db, "spawn_observed", {"process": identity, "business_success": None})
                db.execute("COMMIT")
        except BaseException as error:
            self._unknown("spawn_or_identity_record_unresolved:" + type(error).__name__)
            # A child may exist even when identity/persistence failed. Never retry.

    def _retain_result(self, row):
        raw = read_regular(self.result_path, MAX_RESULT)
        value = parse_object(raw)
        if value.get("attempt_id") != self.identity_binding["attempt_id"]:
            raise ValueError("controller_result_attempt_mismatch")
        path = self.root / "controller_result.json"
        write_once(path, raw)
        status_value = value.get("status")
        return {"handle": {"schema": "b1-public-controller-result-handle-v1",
                  "relative_path": path.name, "sha256": digest(raw), "bytes": len(raw),
                  "helper_id": self.helper_id, "original_request_id": row["request_id"],
                  "attempt_id": self.identity_binding["attempt_id"],
                  "derived_payload_binding_sha256": self.identity_binding["derived_payload_binding_sha256"],
                  "source": "original_public_b0_agent_result_only"},
                "reported_status": status_value if isinstance(status_value, str) and len(status_value) <= 128 else None}

    def refresh(self):
        """Observe our original child only; this function has no start path."""
        with self._operation_lock:
            if self._process is None:
                return
            row = self._row()
            if row["returncode"] is not None:
                return
            returncode = self._process.poll()
            if returncode is None:
                if row["state"] == "running":
                    try:
                        if process_identity(self._process.pid) != json.loads(row["process_json"]):
                            self._unknown("original_process_identity_changed")
                    except (OSError, ValueError, TypeError, IndexError):
                        self._unknown("original_process_identity_unavailable")
                # Original write_result is non-atomic. Never inspect it while live.
                return
            for stream in self._output_files:
                stream.close()
            self._output_files.clear()
            result = None
            reason = row["uncertainty"]
            if row["state"] != "unknown":
                try:
                    result = self._retain_result(row)
                except (OSError, ValueError, TypeError, UnicodeError) as error:
                    reason = "process_exited_without_complete_bound_result:" + type(error).__name__
            final_state = "unknown" if reason or result is None else "process_exited"
            with closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("UPDATE helper SET state=?,uncertainty=?,returncode=?,exit_ns=?,result_json=? WHERE singleton=1",
                           (final_state, reason, returncode, time.monotonic_ns(),
                            canonical(result).decode() if result is not None else None))
                self._event(db, "process_exit_observed", {"returncode": returncode, "state": final_state,
                            "controller_result_retained": result is not None, "business_success": None})
                db.execute("COMMIT")

    def _snapshot(self, request_id):
        row = self._row()
        result = json.loads(row["result_json"]) if row["result_json"] else None
        process = json.loads(row["process_json"]) if row["process_json"] else None
        if process is not None:
            process = {**process, "returncode": row["returncode"]}
        return {"state": row["state"], "original_request_id": row["request_id"],
                "request_binding": "not_registered" if row["request_id"] is None else
                    "original" if row["request_id"] == request_id else "other_request",
                "launch_reservations": row["launch_reservations"], "process": process,
                "uncertainty": row["uncertainty"],
                "controller_result_handle": result["handle"] if result else None,
                "controller_reported_status": result["reported_status"] if result else None,
                "business_success": None, "original_host_evaluation_result": None,
                "helper_model_calls": 0,
                "helper_model_calls_scope": "deterministic helper only; outer B1 model accounting is separate",
                "automatic_retries": 0}

    def handle(self, request, *, raw=None):
        with self._operation_lock:
            if self._closed:
                raise RuntimeError("owner_closed")
            raw = canonical(request) + b"\n" if raw is None else raw
            operation = request.get("operation") if isinstance(request, dict) else None
            rid = request.get("request_id") if isinstance(request, dict) else None
            try:
                if len(raw) > MAX_REQUEST:
                    raise ProtocolError("request_size_exceeded")
                parsed = parse_object(raw)
                if parsed != request:
                    raise ProtocolError("raw_request_mismatch")
                if (not isinstance(operation, str) or operation not in {"start", "poll"}
                        or request.get("schema") != REQUEST_SCHEMA):
                    raise ProtocolError("request_schema_or_operation_invalid")
                fields = {"schema", "operation", "request_id", "helper_id"}
                if operation == "start":
                    fields |= {"parameters", "parent_model_request_id"}
                if set(request) != fields:
                    raise ProtocolError("unexpected_request_fields")
                if not isinstance(rid, str) or not REQUEST_ID.fullmatch(rid):
                    raise ProtocolError("request_id_invalid")
                if request["helper_id"] != self.helper_id:
                    raise ProtocolError("helper_identity_mismatch")
                if operation == "start":
                    parent = request["parent_model_request_id"]
                    if not isinstance(request["parameters"], dict) or (parent is not None and (
                            not isinstance(parent, str) or not REQUEST_ID.fullmatch(parent))):
                        raise ProtocolError("start_parameters_or_parent_claim_invalid")
                    disposition = self._reserve(request, raw)
                    if disposition == "accepted":
                        self._launch_once()
                else:
                    disposition = "status"
                self.refresh()
                return {"schema": RESPONSE_SCHEMA, "ok": True, "operation": operation,
                        "request_id": rid, "helper_id": self.helper_id, "disposition": disposition,
                        "session": self._snapshot(rid), "error": None}
            except (ProtocolError, ValueError, UnicodeError) as error:
                return {"schema": RESPONSE_SCHEMA, "ok": False, "operation": operation,
                        "request_id": rid, "helper_id": self.helper_id, "disposition": "rejected",
                        "session": self._snapshot(rid), "error": {"code": str(error)}}

    def _read_frame(self, connection):
        raw = b""
        while b"\n" not in raw:
            fragment = connection.recv(min(4096, MAX_REQUEST + 1 - len(raw)))
            if not fragment:
                raise ProtocolError("request_frame_incomplete")
            raw += fragment
            if len(raw) > MAX_REQUEST:
                raise ProtocolError("request_size_exceeded")
        if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
            raise ProtocolError("one_json_line_per_connection_required")
        return raw

    def serve_forever(self):
        if self.socket_path.exists() or self.socket_path.is_symlink():
            if not stat.S_ISSOCK(self.socket_path.lstat().st_mode):
                raise ValueError("stale_endpoint_is_not_socket")
            self.socket_path.unlink()  # Exclusive owner lock has already been acquired.
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        info = self.socket_path.stat()
        self._socket_identity = (info.st_dev, info.st_ino)
        self._socket.listen(8)
        self._socket.settimeout(0.2)
        while not self._stopping:
            self.refresh()
            try:
                connection, _ = self._socket.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(2)
                try:
                    raw = self._read_frame(connection)
                    request = parse_object(raw)
                    response = self.handle(request, raw=raw)
                    reply = canonical(response) + b"\n"
                    if len(reply) > MAX_RESPONSE:
                        raise ProtocolError("bounded_response_invariant_failed")
                    connection.sendall(reply)
                except (OSError, ValueError, UnicodeError):
                    # A lost client never signals, retries, or recreates the helper.
                    continue

    def stop(self):
        self._stopping = True

    def close(self):
        with self._operation_lock:
            if self._closed:
                return
            self._stopping = True
            self.refresh()
            if self._row()["state"] in {"launch_reserved", "running"}:
                self._unknown("owner_closed_with_reserved_or_running_helper")
            for stream in self._output_files:
                stream.close()
            self._output_files.clear()
            if self._socket is not None:
                self._socket.close()
            if self._socket_identity and self.socket_path.exists():
                info = self.socket_path.lstat()
                if stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino) == self._socket_identity:
                    self.socket_path.unlink()
            if self._owner_lock is not None:
                os.close(self._owner_lock)
                self._owner_lock = None
            self._closed = True
            # Deliberately no terminate()/kill()/automatic restart of the child.
            # Real orphan/resource cleanup remains the combined host's obligation.


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-root", default=str(PRODUCTION_ROOT))
    parser.add_argument("--binding", required=True, help="host-installed derived payload manifest")
    args = parser.parse_args()
    owner = SessionOwner.production(args.session_root, args.binding)
    signal.signal(signal.SIGTERM, lambda *_: owner.stop())
    signal.signal(signal.SIGINT, lambda *_: owner.stop())
    try:
        owner.serve_forever()
    finally:
        owner.close()


if __name__ == "__main__":
    main()
