"""Run only the unchanged 19 pagination tests in the actual fixed interpreter."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import platform
import resource
import stat
import subprocess
import sys
import time

from gate_common import (PYTHON_VERSION, TEST_COUNT, expected_test_ids, info, read_bytes,
                         read_json, require, save_json, sha, verify_tree)


SOURCE = Path("/contract-src/b1-evidence-pages")
GATE = Path("/contract-src/b1-evidence-pages-gate")
EXECUTION = Path("/tmp/b1-evidence-pages-contract-execution")
OUTPUT = Path("/results")
TEST_TIMEOUT_SECONDS = 60

# runpy executes the original test bytes with their original __main__ behavior.
# The finally record observes the module actually imported by that child.
LAUNCHER = r'''
import hashlib, json, pathlib, runpy, sys
test_path = pathlib.Path(sys.argv[1])
record_path = pathlib.Path(sys.argv[2])
try:
    runpy.run_path(str(test_path), run_name="__main__")
finally:
    module = sys.modules.get("public_evidence")
    module_path = pathlib.Path(module.__file__).resolve() if module is not None else None
    value = {"test_path": str(test_path.resolve()),
        "test_sha256": hashlib.sha256(test_path.read_bytes()).hexdigest(),
        "module_loaded": module is not None,
        "module_path": str(module_path) if module_path is not None else None,
        "module_sha256": hashlib.sha256(module_path.read_bytes()).hexdigest() if module_path is not None else None,
        "python": sys.version, "executable": sys.executable,
        "dont_write_bytecode": sys.dont_write_bytecode}
    with record_path.open("x") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
'''


def resources():
    usage = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    result = {"self": {"user_seconds": usage.ru_utime, "system_seconds": usage.ru_stime,
        "maxrss_kib": usage.ru_maxrss}, "children": {"user_seconds": children.ru_utime,
        "system_seconds": children.ru_stime, "maxrss_kib": children.ru_maxrss}, "cgroup": {},
        "proc_self_cgroup": Path("/proc/self/cgroup").read_text(),
        "memory_peak_scope": "current private container cgroup lifetime; not a sum of child RSS peaks"}
    for name in ("cpu.stat", "memory.current", "memory.peak", "memory.max", "memory.events", "pids.current", "pids.peak"):
        path = Path("/sys/fs/cgroup") / name
        try:
            result["cgroup"][name] = path.read_text()
        except OSError as error:
            result["cgroup"][name] = {"unavailable": type(error).__name__}
    return result


def prepare_execution_copy(expected):
    EXECUTION.mkdir(mode=0o700, exist_ok=False)
    for relative, entry in expected.items():
        raw = read_bytes(SOURCE / relative)
        require(info(raw) == entry, "source_changed_before_copy")
        target = EXECUTION / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(raw)
        target.chmod(0o400)
    temporary = EXECUTION / "validation/tmp"
    temporary.mkdir(mode=0o700, exist_ok=False)
    directories = [path for path in EXECUTION.rglob("*") if path.is_dir()]
    for path in sorted(directories, key=lambda value: len(value.parts), reverse=True):
        if path != temporary:
            path.chmod(0o500)
    EXECUTION.chmod(0o500)
    copied = verify_tree(EXECUTION, expected["SOURCE_MANIFEST.json"]["sha256"], component=True, ignore_test_tmp=True)
    require(copied == expected, "execution_copy_changed")
    return copied


def run():
    os.umask(0o077)
    started = time.monotonic()
    result = {"schema": "b1-evidence-pages-fixed-runtime-result-v1", "passed": False,
        "qualification_scope": "fixed_python_and_19_local_pagination_contracts_only",
        "tests_run": None, "failures": None, "errors": None, "skipped": None, "tests": [],
        "model_calls": 0, "native_business_calls": 0, "controller_calls": 0,
        "actor_integrated": False, "aios_qualified": False, "original_task_runs": 0,
        "solver_security_boundary_qualified": False, "business_result": None}
    runtime = {"schema": "b1-evidence-pages-fixed-runtime-v1", "python": sys.version,
        "version_info": list(sys.version_info[:3]), "executable": sys.executable,
        "resolved_executable": str(Path(sys.executable).resolve()), "implementation": platform.python_implementation(),
        "uid": os.getuid(), "gid": os.getgid(), "dont_write_bytecode": sys.dont_write_bytecode,
        "started_at_utc": datetime.now(timezone.utc).isoformat(), "resources_before": resources()}
    original = gate_original = None
    try:
        status = OUTPUT.lstat()
        require(stat.S_ISDIR(status.st_mode) and not OUTPUT.is_symlink()
                and stat.S_IMODE(status.st_mode) == 0o700 and status.st_uid == os.getuid()
                and status.st_gid == os.getgid(), "private_owned_results_directory_required")
        require(os.getuid() != 0 and os.getuid() == int(os.environ["B1_EXPECTED_UID"])
                and os.getgid() == int(os.environ["B1_EXPECTED_GID"]), "actual_nonroot_host_identity_required")
        result["expected_test_ids"] = expected_test_ids(SOURCE)
        require(tuple(sys.version_info[:3]) == PYTHON_VERSION and platform.python_implementation() == "CPython",
                "exact_python_3_11_17_required")
        require(sys.dont_write_bytecode and os.environ.get("PYTHONDONTWRITEBYTECODE") == "1", "bytecode_writes_forbidden")
        original = verify_tree(SOURCE, os.environ["B1_COMPONENT_MANIFEST_SHA256"], component=True)
        require(len(original) == 33, "exact_33_component_files_required")
        gate_original = verify_tree(GATE, os.environ["B1_GATE_MANIFEST_SHA256"])
        save_json(OUTPUT / "SOURCE_BEFORE.json", {"component": original, "gate": gate_original})
        copied = prepare_execution_copy(original)
        save_json(OUTPUT / "EXECUTION_COPY_BEFORE.json", {"files": copied, "root": str(EXECUTION),
            "source_files_mode": "0400", "source_directories_mode": "0500", "temporary_directory": str(EXECUTION / "validation/tmp"),
            "temporary_mode": "0700", "temporary_directory_excluded_from_source_manifest": True,
            "same_uid_hostile_isolation_claimed": False})
        identifiers = expected_test_ids(EXECUTION)
        result["expected_test_ids"] = identifiers
        command = [sys.executable, "-B", "-c", LAUNCHER, str(EXECUTION / "tests/test_public_evidence.py"), str(OUTPUT / "LOADED_MODULES.json")]
        command_record = {"argv": command, "cwd": str(EXECUTION), "timeout_seconds": TEST_TIMEOUT_SECONDS,
            "stdin": "DEVNULL", "source_test_sha256": original["tests/test_public_evidence.py"]["sha256"]}
        save_json(OUTPUT / "TEST_COMMAND.json", command_record)
        test_started = time.monotonic()
        with (OUTPUT / "tests.stdout.raw").open("xb") as stdout, (OUTPUT / "tests.stderr.raw").open("xb") as stderr:
            process = subprocess.run(command, cwd=EXECUTION, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1"), timeout=TEST_TIMEOUT_SECONDS, check=False)
        result["test_process"] = {"exit_code": process.returncode, "elapsed_seconds": time.monotonic() - test_started,
            "stdout": info(read_bytes(OUTPUT / "tests.stdout.raw")), "stderr": info(read_bytes(OUTPUT / "tests.stderr.raw"))}
        original_result = read_json(OUTPUT / "tests.stdout.raw")
        save_json(OUTPUT / "ORIGINAL_TEST_RESULT.json", original_result)
        records = original_result.get("tests", [])
        result["tests"] = records
        for key in ("tests_run", "failures", "errors", "skipped"):
            result[key] = original_result.get(key)
        require(process.returncode == 0 and original_result.get("passed") is True
                and original_result.get("tests_run") == TEST_COUNT
                and original_result.get("failures") == original_result.get("errors") == original_result.get("skipped") == 0,
                "original_19_contract_tests_not_all_passed")
        require(len(records) == TEST_COUNT and sorted(row.get("test", "") for row in records) == identifiers
                and all(row.get("status") == "passed" for row in records), "complete_test_id_set_mismatch")
        require(original_result.get("model_calls") == original_result.get("native_business_calls") == 0
                and original_result.get("actor_integrated") is False and original_result.get("aios_qualified") is False
                and original_result.get("business_result") is None, "original_test_scope_changed")
        loaded = read_json(OUTPUT / "LOADED_MODULES.json")
        require(loaded["module_loaded"] is True and loaded["module_path"] == str(EXECUTION / "public_evidence.py")
                and loaded["module_sha256"] == original["public_evidence.py"]["sha256"]
                and loaded["test_path"] == str(EXECUTION / "tests/test_public_evidence.py")
                and loaded["test_sha256"] == original["tests/test_public_evidence.py"]["sha256"]
                and loaded["python"] == sys.version and loaded["executable"] == sys.executable
                and loaded["dont_write_bytecode"] is True, "actual_loaded_source_or_interpreter_mismatch")
        result["runtime_and_tests_passed"] = True
        result["original_hardcoded_qualification_flags_preserved"] = True
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        try:
            after = verify_tree(SOURCE, os.environ.get("B1_COMPONENT_MANIFEST_SHA256"), component=True)
            gate_after = verify_tree(GATE, os.environ.get("B1_GATE_MANIFEST_SHA256"))
            save_json(OUTPUT / "SOURCE_AFTER.json", {"component": after, "gate": gate_after})
            result["source_inputs_unchanged"] = original is not None and after == original and gate_after == gate_original
            if EXECUTION.exists() and original is not None:
                copy_after = verify_tree(EXECUTION, original["SOURCE_MANIFEST.json"]["sha256"], component=True, ignore_test_tmp=True)
                save_json(OUTPUT / "EXECUTION_COPY_AFTER.json", {"files": copy_after,
                    "temporary_directory_excluded_from_source_manifest": "validation/tmp"})
                result["execution_copy_unchanged"] = copy_after == original
        except BaseException as error:
            result["source_check_error"] = {"type": type(error).__name__, "message": str(error)}
        runtime["elapsed_seconds"] = time.monotonic() - started
        runtime["resources_after"] = resources()
        runtime["actual_python_version_matches"] = tuple(sys.version_info[:3]) == PYTHON_VERSION
        result["passed"] = bool(result.get("runtime_and_tests_passed") and result.get("source_inputs_unchanged")
            and result.get("execution_copy_unchanged") and not result.get("error") and not result.get("source_check_error"))
        save_json(OUTPUT / "RUNTIME.json", runtime)
        save_json(OUTPUT / "CONTRACT_TEST_RESULT.json", result)
    print("fixed_interpreter_pagination_contract_passed=" + str(result["passed"]), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, choices=(str(OUTPUT),))
    parser.parse_args()
    raise SystemExit(run())
