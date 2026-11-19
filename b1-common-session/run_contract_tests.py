"""Strict isolated-Linux contract runner; no original recovery or model call.

The host supplies the reviewed source read-only and the pinned B0 image. Passing
this runner qualifies these controlled contract tests, not AIOS or business use.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import socket
import sqlite3
import stat
import sys
import time
import traceback
import unittest


HERE = Path(__file__).resolve().parent
EXPECTED_EXECUTABLE = "/opt/native/bin/python"
EXPECTED_PYTHON = (3, 11, 17)
EXPECTED_SQLITE = "3.54.1"
EXPECTED_SQLITE_SOURCE_ID = "2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76"
OWNER_REAL_IPC_METHODS = {
    "test_lost_start_reply_keeps_original_helper_queryable_over_real_socket",
    "test_invalid_operation_over_real_socket_preserves_running_helper_and_owner",
}
GROUP_DESCRIPTIONS = {
    "actual_unix_ipc": "Actual AF_UNIX sockets and original owner server; controlled child only.",
    "connection_double": "Scripted connection double; real owner/SQLite/controlled child; not real IPC.",
    "direct_owner_fixture": "Direct owner methods, real SQLite and controlled subprocess faults; no IPC claim.",
    "source_derivation_fixture": "Actual frozen source derivation and file-binding fixtures; no controller execution.",
    "unclassified": "Not reviewed as belonging to a known test scope; cannot pass this gate.",
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def exception_record(error):
    return {"type": type(error).__name__, "message": str(error),
            "errno": getattr(error, "errno", None)}


def resource_snapshot():
    values = {}
    for name, who in (("self", resource.RUSAGE_SELF), ("reaped_children", resource.RUSAGE_CHILDREN)):
        current = resource.getrusage(who)
        values[name] = {"user_cpu_seconds": current.ru_utime,
                        "system_cpu_seconds": current.ru_stime,
                        "max_rss_kib": current.ru_maxrss,
                        "minor_page_faults": current.ru_minflt,
                        "major_page_faults": current.ru_majflt,
                        "voluntary_context_switches": current.ru_nvcsw,
                        "involuntary_context_switches": current.ru_nivcsw}
    return values


def resource_report(before, after):
    return {"before": before, "after": after,
            "cpu_delta_seconds": {name: {
                key: after[name][key] - before[name][key]
                for key in ("user_cpu_seconds", "system_cpu_seconds")} for name in before},
            "scope": "Linux getrusage; child CPU covers reaped children. RSS is a high-water mark, not a delta; self and child RSS must not be summed as a simultaneous total."}


def preserve_image_build_records(output):
    source = Path("/opt/b0/build-record")
    destination = output / "image-build-record"
    record = {"source_directory": str(source), "output_directory": destination.name,
              "copied_raw_bytes": False, "files": {}, "sqlite_binary": None,
              "sqlite_binary_matches_build_record": False, "errors": []}
    try:
        if source.is_symlink() or not source.is_dir():
            raise ValueError("fixed_image_build_record_directory_missing_or_symlink")
        destination.mkdir(exist_ok=True)
        for path in sorted(source.rglob("*")):
            if path.is_symlink():
                raise ValueError("image_build_record_symlink_rejected")
            relative = path.relative_to(source)
            if path.is_dir():
                (destination / relative).mkdir(exist_ok=True)
            elif path.is_file():
                raw = path.read_bytes()
                (destination / relative).write_bytes(raw)
                record["files"][str(relative)] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            else:
                raise ValueError("image_build_record_nonregular_node")
        if not record["files"]:
            raise ValueError("image_build_record_directory_empty")
        record["copied_raw_bytes"] = True
        binary = Path("/opt/b0/sqlite/libsqlite3.so.0")
        if binary.is_symlink() or not binary.is_file():
            raise ValueError("fixed_sqlite_binary_missing_or_symlink")
        bound_raw = (destination / "sqlite-binary.sha256").read_bytes()
        bound = re.fullmatch(rb"([0-9a-f]{64})  /opt/b0/sqlite/libsqlite3\.so\.0\n", bound_raw)
        if bound is None:
            raise ValueError("fixed_sqlite_binary_build_record_format_invalid")
        binary_sha = sha256_file(binary)
        record["sqlite_binary"] = {"path": str(binary), "bytes": binary.stat().st_size,
                                   "sha256": binary_sha, "recorded_sha256": bound[1].decode("ascii"),
                                   "binding_record_sha256": hashlib.sha256(bound_raw).hexdigest()}
        record["sqlite_binary_matches_build_record"] = binary_sha == bound[1].decode("ascii")
    except (OSError, ValueError) as error:
        record["errors"].append(exception_record(error))
    return record


def probe_runtime():
    previous_ipc_gate = os.environ.get("B1_REQUIRE_REAL_IPC")
    os.environ["B1_REQUIRE_REAL_IPC"] = "1"
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    sys.dont_write_bytecode = True
    actual = {"python_version": list(sys.version_info[:3]), "sys_version": sys.version,
              "implementation": platform.python_implementation(), "executable": sys.executable,
              "platform": sys.platform, "kernel": platform.release(), "machine": platform.machine(),
              "pid": os.getpid(), "uid": os.getuid(), "euid": os.geteuid(),
              "gid": os.getgid(), "egid": os.getegid(), "groups": os.getgroups(),
              "sqlite_module_version": sqlite3.sqlite_version,
              "sqlite_module_path": sqlite3.__file__, "sqlite_query_version": None,
              "sqlite_source_id": None}
    errors = []
    try:
        actual["executable_resolved"] = str(Path(sys.executable).resolve(strict=True))
        actual["process_executable_resolved"] = str(Path("/proc/self/exe").resolve(strict=True))
        actual["executable_sha256"] = sha256_file(actual["executable_resolved"])
        executable_matches = (sys.executable == EXPECTED_EXECUTABLE
                              and os.path.samefile(sys.executable, "/proc/self/exe"))
    except (OSError, ValueError) as error:
        executable_matches = False
        errors.append({"stage": "actual_executable", **exception_record(error)})
    try:
        connection = sqlite3.connect(":memory:")
        try:
            version, source_id = connection.execute("select sqlite_version(), sqlite_source_id()").fetchone()
            actual["sqlite_query_version"], actual["sqlite_source_id"] = version, source_id
        finally:
            connection.close()
    except sqlite3.Error as error:
        errors.append({"stage": "actual_sqlite_query", **exception_record(error)})
    checks = {"linux": sys.platform == "linux",
              "cpython": actual["implementation"] == "CPython",
              "exact_executable_and_process_identity": executable_matches,
              "python_version": tuple(actual["python_version"]) == EXPECTED_PYTHON,
              "sqlite_module_version": actual["sqlite_module_version"] == EXPECTED_SQLITE,
              "sqlite_query_version": actual["sqlite_query_version"] == EXPECTED_SQLITE,
              "sqlite_source_id": actual["sqlite_source_id"] == EXPECTED_SQLITE_SOURCE_ID}
    ipc_started = time.monotonic()
    capability = {"operation": "actual socket(AF_UNIX, SOCK_STREAM), then close",
                  "available": False, "created": False, "closed": False, "error": None,
                  "scope": "Creation/close capability only; test IDs in actual_unix_ipc must prove communication."}
    try:
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        capability["created"] = True
        probe.close()
        capability["closed"] = True
        capability["available"] = True
    except (OSError, AttributeError) as error:
        capability["error"] = exception_record(error)
    capability["elapsed_seconds"] = time.monotonic() - ipc_started
    return {"schema": "b1-common-session-contract-runtime-v1",
            "expected": {"executable": EXPECTED_EXECUTABLE, "python_version": list(EXPECTED_PYTHON),
                         "sqlite_version": EXPECTED_SQLITE, "sqlite_source_id": EXPECTED_SQLITE_SOURCE_ID},
            "actual": actual, "checks": checks, "runtime_exact": all(checks.values()),
            "runtime_errors": errors, "actual_unix_socket_capability": capability,
            "ipc_gate": {"previous_environment_value": previous_ipc_gate,
                         "effective_environment_value": os.environ["B1_REQUIRE_REAL_IPC"],
                         "unavailable_must_fail": True},
            "preflight_passed": all(checks.values()) and not errors and capability["available"]}


def test_leaves(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from test_leaves(item)
        else:
            yield item


def classify(test_id):
    parts = test_id.split(".")
    if len(parts) < 3:
        return "unclassified"
    module, case, method = parts[-3:]
    if module == "test_sdk_session":
        if case == "RealUnixSDKSessionTests":
            return "actual_unix_ipc"
        if case == "SDKConnectionDoubleTests":
            return "connection_double"
    if module == "test_session_owner":
        if case == "ActualSourceDerivationTests":
            return "source_derivation_fixture"
        if case == "SessionOwnerTests":
            return "actual_unix_ipc" if method in OWNER_REAL_IPC_METHODS else "direct_owner_fixture"
    return "unclassified"


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, text):
        for stream in self.streams:
            stream.write(text)
            stream.flush()
        return len(text)

    def flush(self):
        for stream in self.streams:
            stream.flush()


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started_test_ids = []
        self.outcomes = {}
        self.started_at = {}

    def _record(self, test, status):
        record = self.outcomes.setdefault(test.id(), {"test_id": test.id(), "group": classify(test.id())})
        record["status"] = status
        return record

    def startTest(self, test):
        self.started_test_ids.append(test.id())
        self.started_at[test.id()] = time.monotonic()
        self._record(test, "running")["started_utc"] = utc_now()
        super().startTest(test)

    def stopTest(self, test):
        record = self.outcomes[test.id()]
        record["elapsed_seconds"] = time.monotonic() - self.started_at[test.id()]
        record["finished_utc"] = utc_now()
        super().stopTest(test)

    def addSuccess(self, test):
        self._record(test, "success")
        super().addSuccess(test)

    def addError(self, test, err):
        self._record(test, "error")
        super().addError(test, err)

    def addFailure(self, test, err):
        self._record(test, "failure")
        super().addFailure(test, err)

    def addSkip(self, test, reason):
        self._record(test, "skipped")["reason"] = reason
        super().addSkip(test, reason)

    def addExpectedFailure(self, test, err):
        self._record(test, "expected_failure")
        super().addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test):
        self._record(test, "unexpected_success")
        super().addUnexpectedSuccess(test)

    def addSubTest(self, test, subtest, err):
        if err is not None:
            self._record(test, "failure" if issubclass(err[0], test.failureException) else "error")
        self.outcomes[test.id()].setdefault("subtests", []).append({
            "test_id": subtest.id(), "status": "success" if err is None else "failure_or_error"})
        super().addSubTest(test, subtest, err)


def write_json(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    started_utc, started, resources_before = utc_now(), time.monotonic(), resource_snapshot()
    runtime = probe_runtime()
    output_info = output.lstat()
    expected_uid = os.environ.get("B1_EXPECTED_UID", "")
    expected_gid = os.environ.get("B1_EXPECTED_GID", "")
    runtime["output_identity"] = {
        "path": str(output), "uid": output_info.st_uid, "gid": output_info.st_gid,
        "mode": stat.S_IMODE(output_info.st_mode),
        "expected_uid_from_host": expected_uid, "expected_gid_from_host": expected_gid,
        "is_directory": stat.S_ISDIR(output_info.st_mode)}
    runtime["checks"]["unprivileged_host_bound_identity"] = (
        os.getuid() == os.geteuid() and os.getgid() == os.getegid()
        and os.geteuid() > 0 and os.getegid() > 0
        and expected_uid == str(os.geteuid()) and expected_gid == str(os.getegid()))
    runtime["checks"]["private_output_directory_owned"] = (
        stat.S_ISDIR(output_info.st_mode) and stat.S_IMODE(output_info.st_mode) == 0o700
        and output_info.st_uid == os.geteuid() and output_info.st_gid == os.getegid())
    runtime["image_build_records"] = preserve_image_build_records(output)
    runtime["checks"]["original_image_build_records_copied"] = (
        runtime["image_build_records"]["copied_raw_bytes"] and not runtime["image_build_records"]["errors"])
    runtime["checks"]["sqlite_binary_matches_original_build_record"] = (
        runtime["image_build_records"]["sqlite_binary_matches_build_record"])
    runtime["runtime_exact"] = all(runtime["checks"].values())
    runtime["preflight_passed"] = (runtime["runtime_exact"] and not runtime["runtime_errors"]
                                    and runtime["actual_unix_socket_capability"]["available"])
    test_ids, result, runner_errors, discovery_errors = [], None, [], []
    log_path = output / "contract-tests.log"
    test_sources = {str(path.relative_to(HERE)): {"sha256": sha256_file(path), "bytes": path.stat().st_size}
                    for path in sorted((HERE / "tests").glob("test_*.py"))}
    with log_path.open("w", encoding="utf-8") as logfile:
        log_stream = Tee(sys.stderr, logfile)
        try:
            loader = unittest.TestLoader()
            suite = loader.discover(str(HERE / "tests"), pattern="test_*.py")
            test_ids = [test.id() for test in test_leaves(suite)]
            discovery_errors = list(loader.errors)
            grouped = {group: [tid for tid in test_ids if classify(tid) == group] for group in GROUP_DESCRIPTIONS}
            log_stream.write("Strict runtime: " + json.dumps(runtime["checks"], sort_keys=True) + "\n")
            log_stream.write("Actual AF_UNIX preflight: " + json.dumps(runtime["actual_unix_socket_capability"], sort_keys=True) + "\n")
            log_stream.write("Discovered test scopes: " + json.dumps({k: len(v) for k, v in grouped.items()}, sort_keys=True) + "\n")
            if (runtime["preflight_passed"] and not discovery_errors and test_ids
                    and not grouped["unclassified"] and grouped["actual_unix_ipc"]
                    and len(test_ids) == len(set(test_ids))):
                with redirect_stdout(Tee(sys.stdout, logfile)), redirect_stderr(log_stream):
                    result = unittest.TextTestRunner(stream=log_stream, verbosity=2, failfast=False,
                                                     resultclass=RecordedResult).run(suite)
            else:
                log_stream.write("PRECONDITION FAILED: no contract test was executed; see RUNTIME.json and the complete discovered test ID list.\n")
        except Exception as error:
            runner_errors.append({**exception_record(error), "traceback": traceback.format_exc()})
            log_stream.write(runner_errors[-1]["traceback"])
    finished_utc, elapsed = utc_now(), time.monotonic() - started
    resources = resource_report(resources_before, resource_snapshot())
    grouped = {group: {"description": description, "test_ids": [tid for tid in test_ids if classify(tid) == group]}
               for group, description in GROUP_DESCRIPTIONS.items()}
    started_ids = result.started_test_ids if result else []
    entries = lambda name: [{"test_id": test.id(), "detail": detail}
                            for test, detail in getattr(result, name, [])]
    counts = {"discovered": len(test_ids), "run": result.testsRun if result else 0,
              "failures": len(result.failures) if result else 0, "errors": len(result.errors) if result else 0,
              "skipped": len(result.skipped) if result else 0,
              "expected_failures": len(result.expectedFailures) if result else 0,
              "unexpected_successes": len(result.unexpectedSuccesses) if result else 0}
    success_ids = sorted(tid for tid, value in (result.outcomes.items() if result else []) if value["status"] == "success")
    counts["successes"] = len(success_ids)
    all_tests_ran = bool(test_ids) and Counter(started_ids) == Counter(test_ids)
    passed = bool(runtime["preflight_passed"] and result is not None and not runner_errors
                  and not discovery_errors and all_tests_ran and counts["run"] == len(test_ids)
                  and counts["successes"] == len(test_ids) and not grouped["unclassified"]["test_ids"]
                  and grouped["actual_unix_ipc"]["test_ids"]
                  and not any(counts[key] for key in ("failures", "errors", "skipped", "expected_failures", "unexpected_successes")))
    runtime.update({"started_utc": started_utc, "finished_utc": finished_utc,
                    "elapsed_seconds": elapsed, "resources": resources})
    write_json(output / "RUNTIME.json", runtime)
    report = {"schema": "b1-common-session-contract-test-result-v1",
              "passed": passed, "status": "passed" if passed else "failed", "exit_code": 0 if passed else 1,
              "qualification_scope": "Isolated Linux controlled subprocess/SQLite/owner/SDK contract only; no Controller, model, original task or AIOS execution.",
              "not_remote_qualified": True, "full_business_qualified": False, "aios_integration_qualified": False,
              "runtime_exact": runtime["runtime_exact"], "preflight_passed": runtime["preflight_passed"],
              "all_discovered_tests_ran": all_tests_ran, "counts": counts,
              "test_ids": test_ids, "started_test_ids": started_ids,
              "not_run_test_ids": list((Counter(test_ids) - Counter(started_ids)).elements()),
              "duplicate_discovered_test_ids": sorted(tid for tid, n in Counter(test_ids).items() if n > 1),
              "groups": grouped, "success_test_ids": success_ids,
              "failures": entries("failures"), "errors": entries("errors"), "skipped": entries("skipped"),
              "expected_failures": entries("expectedFailures"),
              "unexpected_successes": [test.id() for test in result.unexpectedSuccesses] if result else [],
              "outcomes": list(result.outcomes.values()) if result else [],
              "discovery_errors": discovery_errors, "runner_errors": runner_errors,
              "test_source_files": test_sources, "entrypoint_sha256": sha256_file(__file__),
              "runtime_report_sha256": sha256_file(output / "RUNTIME.json"),
              "detailed_log": {"path": log_path.name, "sha256": sha256_file(log_path), "bytes": log_path.stat().st_size},
              "started_utc": started_utc, "finished_utc": finished_utc,
              "elapsed_seconds": elapsed, "resources": resources}
    write_json(output / "CONTRACT_TEST_RESULT.json", report)
    print(json.dumps({"status": report["status"], "counts": counts,
                      "preflight_passed": runtime["preflight_passed"], "output": str(output)}, sort_keys=True))
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
