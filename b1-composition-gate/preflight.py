"""Offline installation/linkage preflight for the combined B0/B1 image.

This invokes the original offline preflights, never Controller, a model server,
an inference request, AIOS registration, or the session contract test suite.
All installed sources must match a host-bound installation manifest first.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import signal
import sqlite3
import stat
import subprocess
import sys
import time
import traceback


ROOT = Path("/opt/b1-composition")
MANIFEST = ROOT / "INSTALLATION_MANIFEST.json"
INPUT_BINDING = ROOT / "SOURCE_INPUT_BINDING.json"
RUNTIME_INVENTORY = ROOT / "build-record/runtime-artifacts.json"
SESSION = Path("/opt/b1-common-session")
DERIVED = SESSION / "derived/DERIVED_PAYLOAD_BINDING.json"
BASE_MANIFEST = SESSION / "derived/BASE_PACKAGE_MANIFEST.json"
B0 = Path("/opt/b0")
G1 = Path("/opt/g1")
SQLITE_BINARY = B0 / "sqlite/libsqlite3.so.0"
LLAMA = Path("/opt/llama/bin/llama-server")
MODEL = Path("/opt/models/Qwen3-8B-Q4_K_M.gguf")
NATIVE = "/opt/native/bin/python"
AIOS = "/opt/aios/bin/python"
LD_PATH = "/opt/b0/sqlite:/opt/llama/bin"
PYTHON_VERSION = [3, 11, 17]
SQLITE_VERSION = "3.54.1"
SQLITE_SOURCE_ID = "2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76"
B0_COMMIT = "22fa7c12ea5274f86a2ecca17e6cc2e16ab7a4ad"
B0_PACKAGE_SHA = "8e1f713246630961977d407a8d51d4bfe9d077a11f0c04949ff48904301d843e"
B1_COMMIT = "43b15ea58de5d33603ac6ef60e2add74c3ea514d"
B1_PACKAGE_SHA = "812707dfc9e3dd1d31744b058b4e1c3ed4dd78b279b2d760422b6c911eabb67a"
SESSION_COMMIT = "5008fe991a60efbff6d365218f1feb9aee999e97"
INPUT_BINDING_SHA = "7665841dc89ecbaa5f0bb710099eff2f02bcb12380161956e2fde2a962907584"
LLAMA_COMMIT = "f7591a6a01f9273de03331732bdc0b39721168be"
MODEL_SHA = "d98cdcbd03e17ce47681435b5150e34c1417f50b5c0019dd560e4882c5745785"
MODEL_BYTES = 5027783488
HEX = re.compile(r"[0-9a-f]{64}\Z")
GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
SOURCE_ROOTS = (B0, G1, SESSION, ROOT)
BUILD_ROOTS = {"b0": B0 / "build-record", "g1": G1 / "build-record",
               "composition": ROOT / "build-record"}
RUNTIME_ROOTS = (B0 / "sqlite", Path("/opt/llama/bin"))
RESULT_NAME = "COMPOSITION_PREFLIGHT_RESULT.json"
PREFLIGHT_SECONDS = 240
USER_DIRECTORY = Path("/tmp/b1-composition-user-home")
DEADLINE = None


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def error_record(error):
    return {"type": type(error).__name__, "message": str(error),
            "errno": getattr(error, "errno", None)}


def check_deadline():
    if DEADLINE is not None and time.monotonic() >= DEADLINE:
        raise TimeoutError("installation_preflight_shared_deadline_exhausted")


def read_regular(path, maximum=16 * 1024 * 1024):
    check_deadline()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum,
                "bounded_regular_file_required:" + str(path))
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    require(len(raw) <= maximum and
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "file_changed_during_read:" + str(path))
    return raw


def hash_file(path):
    check_deadline()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), "regular_artifact_required:" + str(path))
        digest, total = hashlib.sha256(), 0
        while True:
            check_deadline()
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            total += len(block)
        after = os.fstat(stream.fileno())
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and total == before.st_size,
            "artifact_changed_during_hash:" + str(path))
    return {"bytes": total, "sha256": digest.hexdigest()}


def write_once(path, raw):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not path.parent.is_symlink(), "output_parent_symlink")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"bytes": len(raw), "sha256": sha(raw)}


def read_json(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "duplicate_json_key")
            value[key] = item
        return value
    def bad_constant(_):
        raise ValueError("nonfinite_json_number")
    return json.loads(read_regular(path), object_pairs_hook=unique, parse_constant=bad_constant)


def below(path, root):
    return path == root or path.is_relative_to(root)


def source_path(value):
    require(isinstance(value, str), "installation_path_not_string")
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts and str(path) == value
            and any(below(path, root) for root in SOURCE_ROOTS), "installation_path_outside_fixed_roots")
    for parent in path.parents:
        require(not parent.is_symlink(), "installation_parent_symlink:" + str(parent))
    return path


def resource_snapshot():
    result = {"monotonic_ns": time.monotonic_ns(), "processes": {}, "cgroup": {}}
    for name, who in (("self", resource.RUSAGE_SELF), ("reaped_children", resource.RUSAGE_CHILDREN)):
        value = resource.getrusage(who)
        result["processes"][name] = {"user_cpu_seconds": value.ru_utime,
            "system_cpu_seconds": value.ru_stime, "max_rss_kib": value.ru_maxrss,
            "minor_page_faults": value.ru_minflt, "major_page_faults": value.ru_majflt}
    for name in ("memory.peak", "memory.current", "memory.max", "memory.events", "cpu.max", "cpu.stat"):
        path = Path("/sys/fs/cgroup") / name
        try:
            if path.is_file():
                result["cgroup"][name] = path.read_text().strip()
        except OSError as error:
            result["cgroup"][name] = {"error": error_record(error)}
    return result


def identity():
    return {"pid": os.getpid(), "uid": os.getuid(), "euid": os.geteuid(),
            "gid": os.getgid(), "egid": os.getegid(), "groups": os.getgroups(),
            "sys_executable": sys.executable, "sys_prefix": sys.prefix,
            "sys_base_prefix": sys.base_prefix, "python_version": list(sys.version_info[:3]),
            "executable_resolved": str(Path(sys.executable).resolve(strict=True)),
            "process_executable_resolved": str(Path("/proc/self/exe").resolve(strict=True)),
            "platform": sys.platform, "machine": platform.machine(), "kernel": platform.release(),
            "ld_library_path": os.environ.get("LD_LIBRARY_PATH")}


def runtime_probe():
    import _sqlite3
    value = identity()
    with sqlite3.connect(":memory:") as db:
        version, source_id = db.execute("select sqlite_version(),sqlite_source_id()").fetchone()
    maps = Path("/proc/self/maps").read_bytes()
    libraries = sorted({line.split()[-1].decode() for line in maps.splitlines()
                        if b"libsqlite3.so" in line})
    value.update(schema="b1-composition-runtime-probe-v1", implementation=platform.python_implementation(),
                 sqlite_module_version=sqlite3.sqlite_version, sqlite_query_version=version,
                 sqlite_source_id=source_id, sqlite_module_path=sqlite3.__file__,
                 sqlite_extension_path=_sqlite3.__file__, loaded_sqlite_libraries=libraries,
                 proc_maps_sha256=sha(maps), proc_maps=maps.decode(),
                 executable_matches_process=os.path.samefile(sys.executable, "/proc/self/exe"),
                 executable_sha256=hash_file(Path(sys.executable).resolve(strict=True))["sha256"])
    value["user_directory"] = child_user_directory_identity()
    return value


def prepare_user_directory():
    # This is the isolated numeric user's actual private home, on the existing
    # /tmp tmpfs. Do not change the host or parent process environment.
    USER_DIRECTORY.mkdir(mode=0o700)
    info = USER_DIRECTORY.lstat()
    require(stat.S_ISDIR(info.st_mode) and not USER_DIRECTORY.is_symlink()
            and info.st_uid == os.geteuid() and info.st_gid == os.getegid()
            and stat.S_IMODE(info.st_mode) == 0o700,
            "private_user_directory_identity_mismatch")
    return {"path": str(USER_DIRECTORY), "uid": info.st_uid, "gid": info.st_gid,
            "mode": "0700", "created_in_existing_tmpfs": True,
            "parent_environment_modified": False}


def child_user_directory_identity():
    require(os.environ.get("HOME") == str(USER_DIRECTORY),
            "child_user_home_environment_mismatch")
    directory = Path.home()
    info = directory.lstat()
    require(directory == USER_DIRECTORY and directory.resolve(strict=True) == USER_DIRECTORY
            and stat.S_ISDIR(info.st_mode) and not directory.is_symlink()
            and info.st_uid == os.geteuid() and info.st_gid == os.getegid()
            and stat.S_IMODE(info.st_mode) == 0o700,
            "child_user_home_resolution_or_identity_mismatch")
    return {"environment_value": os.environ["HOME"], "pathlib_home": str(directory),
            "uid": info.st_uid, "gid": info.st_gid, "mode": "0700",
            "source": "isolated_user_private_directory_on_existing_tmpfs"}


def deny_active_operations(event, _args):
    if event in {"socket.connect", "socket.getaddrinfo", "socket.bind", "socket.__new__",
                 "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}:
        raise PermissionError("offline_session_import_forbids_active_operation:" + event)


def session_import_probe():
    sys.addaudithook(deny_active_operations)
    modules = {}
    for name in ("controller_adapter", "session_owner", "session_client", "sdk_tool"):
        module = importlib.import_module(name)
        path = Path(module.__file__).absolute()
        require(path == SESSION / (name + ".py"), "session_module_loaded_from_unexpected_source")
        modules[name] = {"path": str(path), **hash_file(path)}
    require("controller" not in sys.modules, "controller_was_imported_by_session_import_check")
    return {"schema": "b1-composition-session-import-v1", "passed": True,
            "modules": modules, "runtime": identity(), "constructors_invoked": False,
            "controller_executed": False, "owner_started": False, "tool_run_invoked": False,
            "contract_tests_run": 0, "model_requests": 0, "business_calls": 0}


def b0_source_probe():
    sys.addaudithook(deny_active_operations)
    adapter = importlib.import_module("controller_adapter")
    require(Path(adapter.__file__).absolute() == SESSION / "controller_adapter.py",
            "source_verifier_import_path_changed")
    value = adapter.verify_payload(B0, DERIVED, require_runtime=True)
    return {"schema": "b1-composition-b0-source-verification-v1", "passed": True,
            "verification": value, "controller_executed": False}


def llama_library_probe():
    import ctypes
    inventory = read_json(RUNTIME_INVENTORY)
    libraries = sorted({str(Path(name).resolve(strict=True)) for name in inventory["entries"]
                        if below(Path(name), Path("/opt/llama/bin"))
                        and (Path(name).name.endswith(".so") or ".so." in Path(name).name)})
    require(libraries, "no_llama_shared_library_in_fixed_inventory")
    loaded = []
    handles = []
    for name in libraries:
        check_deadline()
        handles.append(ctypes.CDLL(name, mode=os.RTLD_NOW | os.RTLD_LOCAL))
        loaded.append({"path": name, **hash_file(Path(name))})
    maps = Path("/proc/self/maps").read_bytes()
    mapped = {line.split()[-1].decode() for line in maps.splitlines() if b"/opt/llama/bin/" in line}
    require(set(libraries) <= mapped, "loaded_llama_library_not_visible_in_process_maps")
    return {"schema": "b1-composition-llama-libraries-v1", "passed": True,
            "libraries": loaded, "proc_maps": maps.decode(), "proc_maps_sha256": sha(maps),
            "load_mode": "RTLD_NOW|RTLD_LOCAL", "model_loaded": False, "inference_calls": 0}


def child_environment(kind):
    # Preserve the image's actual dynamic-library setting; never repair it for a probe.
    env = {name: os.environ[name] for name in ("PATH", "LANG", "LC_ALL", "LD_LIBRARY_PATH")
           if name in os.environ}
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1", PYTHONNOUSERSITE="1",
        XDG_CACHE_HOME="/tmp/b1-composition-cache", HF_HOME="/tmp/b1-composition-cache/huggingface",
        NLTK_DATA="/tmp/b1-composition-cache/nltk", TMPDIR="/tmp", OMP_NUM_THREADS="1",
        TOKENIZERS_PARALLELISM="false", LITELLM_LOCAL_MODEL_COST_MAP="True",
        ORT_DISABLE_TELEMETRY="1", DO_NOT_TRACK="1", ANONYMIZED_TELEMETRY="False",
        OTEL_SDK_DISABLED="true", OTEL_TRACES_EXPORTER="none", OTEL_METRICS_EXPORTER="none",
        OTEL_LOGS_EXPORTER="none", HF_HUB_DISABLE_TELEMETRY="1", HF_HUB_OFFLINE="1",
        HF_DATASETS_OFFLINE="1", TRANSFORMERS_OFFLINE="1")
    # HOME retains its standard POSIX meaning for this child user. Numeric
    # container users need not have an entry in the image's password database.
    env["HOME"] = str(USER_DIRECTORY)
    if kind == "b0":
        env["PYTHONPATH"] = ":".join(str(B0 / part) for part in
            ("common_bridge", "strategy", "native_adapter", "integration")) + ":" + str(SESSION)
    elif kind == "g1":
        env["PYTHONPATH"] = ":".join(str(path) for path in (G1 / "integration",
            G1 / "integration/source_terminal", G1 / "sdk", G1 / "typed_reads",
            G1 / "native_adapter", SESSION))
    else:
        env["PYTHONPATH"] = str(SESSION)
    if DEADLINE is not None:
        env["B1_COMPOSITION_DEADLINE_MONOTONIC"] = str(DEADLINE)
    return env


class Recorder:
    def __init__(self, output):
        self.output = output
        self.commands = []
        self.checks = {}
        self.errors = []

    def check(self, name, function):
        started = time.monotonic()
        try:
            value = function()
            record = {"passed": True, "value": value}
        except BaseException as error:
            record = {"passed": False, "error": error_record(error), "traceback": traceback.format_exc()}
            self.errors.append({"stage": name, **error_record(error)})
        record["elapsed_seconds"] = time.monotonic() - started
        self.checks[name] = record
        write_once(self.output / "checks" / (name + ".json"), canonical(record) + b"\n")
        return record.get("value") if record["passed"] else None

    def command(self, name, argv, environment, timeout):
        started = time.monotonic()
        stdout = stderr = b""
        process, returncode, error, timeout_hit = None, None, None, False
        effective_timeout = min(timeout, max(0, DEADLINE - started)) if DEADLINE is not None else timeout
        try:
            require(effective_timeout > 0, "installation_deadline_exhausted_command_not_dispatched")
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, cwd="/logs", env=environment, start_new_session=True)
            try:
                stdout, stderr = process.communicate(timeout=effective_timeout)
            except subprocess.TimeoutExpired as caught:
                timeout_hit = True
                stdout, stderr = caught.output or b"", caught.stderr or b""
                error = error_record(caught)
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                final_out, final_err = process.communicate(timeout=5)
                # communicate after a timeout returns the full retained streams.
                stdout = final_out if final_out is not None else stdout
                stderr = final_err if final_err is not None else stderr
            returncode = process.returncode
        except BaseException as caught:
            error = error_record(caught)
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    final_out, final_err = process.communicate(timeout=5)
                    stdout = final_out if final_out is not None else stdout
                    stderr = final_err if final_err is not None else stderr
                    returncode = process.returncode
                except BaseException as cleanup_error:
                    error["cleanup_error"] = error_record(cleanup_error)
        record = {"name": name, "argv": argv, "cwd": "/logs", "environment": environment,
            "pid": process.pid if process is not None else None, "returncode": returncode,
            "requested_timeout_seconds": timeout, "effective_timeout_seconds": effective_timeout,
            "shared_deadline_monotonic": DEADLINE, "dispatched": process is not None,
            "timeout_hit": timeout_hit, "error": error,
            "elapsed_seconds": time.monotonic() - started,
            "stdout": {"path": "commands/" + name + ".stdout", **write_once(self.output / "commands" / (name + ".stdout"), stdout)},
            "stderr": {"path": "commands/" + name + ".stderr", **write_once(self.output / "commands" / (name + ".stderr"), stderr)},
            "passed": returncode == 0 and error is None and not timeout_hit}
        self.commands.append(record)
        write_once(self.output / "commands" / (name + ".json"), canonical(record) + b"\n")
        require(record["passed"], "offline_command_failed:" + name)
        return stdout, stderr


def copy_tree(source, destination):
    require(source.is_dir() and not source.is_symlink(), "record_directory_missing:" + str(source))
    files = {}
    for path in sorted(source.rglob("*")):
        check_deadline()
        require(not path.is_symlink(), "record_symlink_rejected:" + str(path))
        if path.is_dir():
            continue
        require(path.is_file(), "record_nonregular_node:" + str(path))
        relative = path.relative_to(source)
        files[str(relative)] = write_once(destination / relative, read_regular(path))
    require(files, "record_directory_empty:" + str(source))
    return {"source": str(source), "files": files, "raw_bytes_preserved": True}


def validate_installation(output):
    raw = read_regular(MANIFEST)
    expected_installation_sha = os.environ.get("B1_EXPECTED_INSTALLATION_MANIFEST_SHA256", "")
    require(HEX.fullmatch(expected_installation_sha) and sha(raw) == expected_installation_sha,
            "host_installation_manifest_binding_mismatch")
    manifest = read_json(MANIFEST)
    require(manifest.get("schema") == "b1-composition-installation-manifest-v1"
            and manifest.get("qualification") == "not_remote_qualified", "installation_manifest_profile_invalid")
    require(manifest.get("runtime_inventory_path") == str(RUNTIME_INVENTORY), "runtime_inventory_path_changed")
    require(hash_file(INPUT_BINDING)["sha256"] == INPUT_BINDING_SHA,
            "reviewed_source_input_binding_changed")
    inputs = read_json(INPUT_BINDING)
    require(inputs.get("schema") == "b1-composition-source-input-binding-v1", "source_input_binding_schema_changed")
    files = manifest.get("files")
    require(isinstance(files, dict) and files, "installation_file_set_missing")
    checked, uncommitted = {}, []
    for name, record in files.items():
        check_deadline()
        path = source_path(name)
        require(path != MANIFEST and isinstance(record, dict), "installation_file_record_invalid")
        require(type(record.get("bytes")) is int and record["bytes"] >= 0
                and isinstance(record.get("sha256"), str) and HEX.fullmatch(record["sha256"]),
                "installation_digest_shape_invalid")
        source = record.get("source")
        require(isinstance(source, dict) and all(isinstance(source.get(key), str) and source[key]
            for key in ("component", "path", "sha256")) and HEX.fullmatch(source["sha256"]),
            "installation_source_binding_missing")
        require(source["component"] in {"b0_public_payload", "b1_fixed_overlay_payload",
            "session_production", "session_derived_binding", "composition_gate"},
            "installation_source_component_invalid")
        commit = source.get("commit")
        require(commit is None or (isinstance(commit, str) and GIT_SHA.fullmatch(commit)),
                "installation_source_commit_invalid")
        if commit is None:
            require(source.get("binding_status") == "uncommitted_worktree_bytes",
                    "null_commit_without_explicit_source_limit")
            uncommitted.append(name)
        actual = hash_file(path)
        require(actual == {"bytes": record["bytes"], "sha256": record["sha256"]},
                "installed_source_bytes_differ:" + name)
        checked[name] = actual
    base_files = read_json(BASE_MANIFEST)["files"]
    require({name for name in files if below(Path(name), B0)} ==
            {str(B0 / name.removeprefix("payload/")) for name in base_files
             if name.startswith("payload/")}, "b0_installed_source_set_not_original_payload")
    for name, record in files.items():
        installed_path = Path(name)
        source = record["source"]
        if below(installed_path, B0):
            relative = str(installed_path.relative_to(B0))
            require(source["component"] == "b0_public_payload" and source["commit"] == B0_COMMIT
                and source["path"] == "b0-run/payload/" + relative
                and source["sha256"] == base_files["payload/" + relative],
                "b0_installation_origin_mismatch")
        elif below(installed_path, G1):
            relative = str(installed_path.relative_to(G1))
            original = {"integration/b1_metering.py": "b1-readonly-gate/b1_metering.py",
                        "integration/g1_sdk_client.py": "b1-readonly-gate/b1_sdk_client.py"}.get(
                            relative, "g1-smoke/payload/" + relative)
            require(source["component"] == "b1_fixed_overlay_payload" and source["commit"] == B1_COMMIT
                and source["path"] == original and record.get("derivation") == {
                    "kind": "exact_fixed_43b_generator", "generator_sha256": inputs["b1"]["generator"]["sha256"],
                    "generated_package_manifest_sha256": B1_PACKAGE_SHA, "generated_path": "payload/" + relative},
                "b1_installation_origin_mismatch")
        elif below(installed_path, SESSION):
            relative = str(installed_path.relative_to(SESSION))
            require(source["commit"] == SESSION_COMMIT, "session_installation_commit_changed")
            if relative.startswith("derived/"):
                require(relative in {"derived/DERIVED_PAYLOAD_BINDING.json", "derived/BASE_PACKAGE_MANIFEST.json"}
                    and source["component"] == "session_derived_binding"
                    and source["path"] == inputs["session"]["derivation_generator"]["path"]
                    and source["sha256"] == inputs["session"]["derivation_generator"]["sha256"],
                    "session_derived_binding_origin_changed")
            else:
                expected = inputs["session"]["production_files"].get(relative)
                require(expected is not None and source["component"] == "session_production"
                    and source["path"] == expected["path"] and source["sha256"] == expected["sha256"]
                    and {key: record[key] for key in ("bytes", "sha256")} ==
                        {key: expected[key] for key in ("bytes", "sha256")},
                    "session_production_origin_changed")
        else:
            require(installed_path.name in {"preflight.py", "SOURCE_INPUT_BINDING.json"}
                and installed_path.parent == ROOT and source["component"] == "composition_gate"
                and source["path"] == "b1-composition-gate/" + installed_path.name
                and source["sha256"] == record["sha256"]
                and source.get("binding_status") == ("uncommitted_worktree_bytes"
                    if source["commit"] is None else "exact_current_git_blob"), "composition_source_origin_changed")
    actual_sources = set()
    excluded_roots = tuple(BUILD_ROOTS.values()) + (B0 / "sqlite",)
    for root in SOURCE_ROOTS:
        require(root.is_dir() and not root.is_symlink(), "source_root_invalid:" + str(root))
        for path in root.rglob("*"):
            check_deadline()
            if any(below(path, excluded) for excluded in excluded_roots):
                continue
            require(not path.is_symlink(), "source_tree_symlink:" + str(path))
            if path.is_dir() or path == MANIFEST:
                continue
            require(path.is_file(), "source_tree_nonregular:" + str(path))
            actual_sources.add(str(path))
    require(actual_sources == set(files), "installation_source_set_not_exact")
    bindings = manifest.get("source_bindings", {})
    require(set(bindings) == {"input_binding", "b0", "b1", "session"}, "source_binding_components_invalid")
    require(bindings["input_binding"] == {"path": str(INPUT_BINDING), "sha256": hash_file(INPUT_BINDING)["sha256"]},
            "source_input_binding_not_exact")
    b0, b1, session = (bindings[key] for key in ("b0", "b1", "session"))
    require(b0.get("commit") == B0_COMMIT and b0.get("package_manifest_sha256") == B0_PACKAGE_SHA
        and b0.get("verified_file_count") == 60 and b0.get("payload_file_count") == 37
        and b0.get("derived_binding_path") == str(DERIVED)
        and b0.get("derived_binding_sha256") == hash_file(DERIVED)["sha256"]
        and b0.get("base_manifest_path") == str(BASE_MANIFEST)
        and hash_file(BASE_MANIFEST)["sha256"] == B0_PACKAGE_SHA, "b0_source_basis_mismatch")
    require(b1.get("commit") == B1_COMMIT and b1.get("generated_package_manifest_sha256") == B1_PACKAGE_SHA
        and b1.get("verified_file_count") == 264 and b1.get("payload_file_count") == 254
        and sum(below(Path(name), G1) for name in files) == 254
        and b1.get("original_g1_manifest_sha256") == inputs["b1"]["original_manifest"]["sha256"]
        and b1.get("overlay_source_manifest_sha256") == inputs["b1"]["overlay_source_manifest"]["sha256"]
        and b1.get("generation_branch") == inputs["b1"]["generation_branch"],
        "b1_source_basis_mismatch")
    require(session.get("commit") == SESSION_COMMIT
        and session.get("source_manifest_sha256") == inputs["session"]["source_manifest"]["sha256"]
        and session.get("verified_file_count") == inputs["session"]["declared_source_files"]
        and session.get("installed_files") == sorted(str(SESSION / name)
            for name in inputs["session"]["production_files"])
        and all(name in files for name in session["installed_files"]),
        "session_source_basis_mismatch")
    build = manifest.get("build_inputs")
    require(isinstance(build, dict) and set(build) == {"composition_dockerfile", "python", "sqlite", "llama", "model"}
        and all(build[name] == inputs[name] for name in ("python", "sqlite", "llama", "model")),
        "build_input_binding_mismatch")
    docker = build["composition_dockerfile"]
    docker_source = docker.get("source", {})
    docker_commit = docker_source.get("commit")
    require(type(docker.get("bytes")) is int and docker["bytes"] > 0
        and isinstance(docker.get("sha256"), str) and HEX.fullmatch(docker["sha256"])
        and docker.get("context_path") == "Dockerfile"
        and docker_source.get("component") == "composition_gate"
        and docker_source.get("path") == "b1-composition-gate/Dockerfile"
        and docker_source.get("sha256") == docker["sha256"]
        and (docker_commit is None or (isinstance(docker_commit, str) and GIT_SHA.fullmatch(docker_commit)))
        and docker_source.get("binding_status") == ("uncommitted_worktree_bytes"
            if docker_commit is None else "exact_current_git_blob"), "docker_recipe_binding_invalid")
    require(read_regular(B0 / "native_adapter/requirements-native.txt") ==
            read_regular(G1 / "native_adapter/requirements-native.txt"), "combined_native_requirements_differ")
    for name, path in (("INSTALLATION_MANIFEST.json", MANIFEST), ("SOURCE_INPUT_BINDING.json", INPUT_BINDING),
                       ("DERIVED_PAYLOAD_BINDING.json", DERIVED), ("BASE_PACKAGE_MANIFEST.json", BASE_MANIFEST)):
        write_once(output / "installed-bindings" / name, read_regular(path))
    return manifest, {"host_expected_manifest_sha256": expected_installation_sha, "actual_manifest_sha256": sha(raw),
                      "files": checked, "uncommitted_source_files": uncommitted,
                      "source_commit_claim_scope": "manifest metadata and host-bound bytes; no Git objects read inside image"}


def validate_runtime_artifacts(manifest):
    declared = manifest.get("runtime_artifacts")
    require(isinstance(declared, dict) and set(declared) == {str(SQLITE_BINARY), str(LLAMA), str(MODEL)},
            "runtime_artifact_set_changed")
    sqlite_record, llama_record, model_record = (declared[str(path)] for path in (SQLITE_BINARY, LLAMA, MODEL))
    require(sqlite_record.get("component") == "sqlite" and sqlite_record.get("version") == SQLITE_VERSION
        and sqlite_record.get("source_id") == SQLITE_SOURCE_ID
        and sqlite_record.get("binary_sha256_record") == str(B0 / "build-record/sqlite-binary.sha256")
        and sqlite_record.get("build_source_binding") == str(B0 / "build-record/sqlite-source-binding.json"),
        "sqlite_artifact_profile_changed")
    require(llama_record.get("component") == "llama" and llama_record.get("commit") == LLAMA_COMMIT
        and llama_record.get("binary_sha256_record") == str(G1 / "build-record/llama-binary.sha256")
        and llama_record.get("execution_scope") == "version_only", "llama_artifact_profile_changed")
    require(model_record.get("component") == "model" and model_record.get("bytes") == MODEL_BYTES
        and model_record.get("sha256") == MODEL_SHA and model_record.get("inference_permitted") is False
        and model_record.get("source_url") == manifest["build_inputs"]["model"]["source_url"],
        "model_artifact_profile_changed")
    sqlite_source = read_json(Path(sqlite_record["build_source_binding"]))
    require(sqlite_source == {"url": manifest["build_inputs"]["sqlite"]["amalgamation_url"],
        "archive_sha3_256": manifest["build_inputs"]["sqlite"]["archive_sha3_256"], "version": SQLITE_VERSION},
        "sqlite_build_source_binding_changed")
    inventory = read_json(RUNTIME_INVENTORY)
    require(inventory.get("schema") == "b1-composition-runtime-artifacts-v1"
            and inventory.get("roots") == list(map(str, RUNTIME_ROOTS))
            and isinstance(inventory.get("entries"), dict), "runtime_inventory_shape_invalid")
    actual, links = {}, {}
    for root in RUNTIME_ROOTS:
        require(root.is_dir() and not root.is_symlink(), "runtime_root_invalid")
        for path in sorted(root.rglob("*")):
            check_deadline()
            if path.is_symlink():
                target = path.resolve(strict=True)
                require(below(target, root) and target.is_file() and not target.is_symlink(),
                        "runtime_link_escaped_own_root")
                actual[str(path)] = {"type": "symlink", "target": os.readlink(path),
                    "resolved_path": str(target), **hash_file(target)}
                links[str(path)] = str(target)
            elif path.is_dir():
                continue
            else:
                actual[str(path)] = {"type": "file", **hash_file(path)}
    require(actual == inventory["entries"] and actual, "runtime_inventory_not_exact")
    binary_records = {}
    for binary, item in ((SQLITE_BINARY, sqlite_record), (LLAMA, llama_record)):
        raw = read_regular(Path(item["binary_sha256_record"]))
        expected = re.fullmatch(rb"([0-9a-f]{64})  " + re.escape(str(binary).encode()) + rb"\n", raw)
        require(expected is not None, "binary_build_record_format_changed")
        observed = hash_file(binary)
        require(observed["sha256"] == expected[1].decode(), "binary_build_record_digest_mismatch")
        binary_records[str(binary)] = {**observed, "record_sha256": sha(raw)}
    return {"inventory_sha256": hash_file(RUNTIME_INVENTORY)["sha256"],
            "entries": actual, "internal_links": links, "binary_build_records": binary_records}


def parse_printed_object(raw, key, value):
    matches = []
    for line in raw.splitlines():
        try:
            item = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if isinstance(item, dict) and item.get(key) == value:
            matches.append(item)
    require(len(matches) == 1, "expected_one_complete_probe_result")
    return matches[0]


def validate_runtime(value, interpreter):
    expected_prefix = "/opt/native" if interpreter == NATIVE else "/opt/aios"
    require(value["sys_executable"] == interpreter and value["sys_prefix"] == expected_prefix
        and value["sys_base_prefix"] != expected_prefix and value["executable_matches_process"] is True
        and value["python_version"] == PYTHON_VERSION and value["implementation"] == "CPython"
        and value["platform"] == "linux" and value["sqlite_module_version"] == SQLITE_VERSION
        and value["sqlite_query_version"] == SQLITE_VERSION and value["sqlite_source_id"] == SQLITE_SOURCE_ID
        and value["loaded_sqlite_libraries"] == [str(SQLITE_BINARY)]
        and value["ld_library_path"] == LD_PATH, "actual_venv_or_sqlite_linkage_mismatch")
    directory = value.get("user_directory", {})
    require(directory.get("environment_value") == directory.get("pathlib_home") == str(USER_DIRECTORY)
            and directory.get("uid") == value["uid"] == value["euid"]
            and directory.get("gid") == value["gid"] == value["egid"]
            and directory.get("mode") == "0700", "actual_runtime_user_directory_mismatch")
    return value


def run_main(output):
    global DEADLINE
    output = Path(output).absolute()
    started = time.monotonic()
    DEADLINE = started + PREFLIGHT_SECONDS
    state = {"schema": "b1-composition-preflight-result-v1", "passed": False,
        "qualification_scope": "installation-only", "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "model_requests": 0, "inference_calls": 0, "controller_executions": 0,
        "original_task_runs": 0, "business_calls": 0, "aios_registrations": 0,
        "contract_tests_run": 0, "aios_end_to_end_qualified": False, "business_recovery_qualified": False,
        "comparison_budget_selected": False, "original_task_success": None,
        "preflight_deadline_seconds": PREFLIGHT_SECONDS,
        "deadline_scope": "offline installation gate only; not a model or incident comparison budget",
        "output_directory": str(output), "fatal_error": None}
    recorder = None
    try:
        require(output.is_dir() and not output.is_symlink(), "host_output_directory_missing")
        info = output.stat()
        require(stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid()
                and info.st_gid == os.getegid(), "host_output_identity_or_mode_mismatch")
        require(not (output / RESULT_NAME).exists(), "preflight_result_already_exists")
        os.umask(0o077)
        recorder = Recorder(output)
        state["identity"] = identity()
        state["resources_before"] = resource_snapshot()
        for name in ("status", "maps", "mountinfo"):
            write_once(output / "process" / (name + ".raw"), Path("/proc/self", name).read_bytes())
        def environment_check():
            expected_uid = int(os.environ["B1_EXPECTED_UID"])
            expected_gid = int(os.environ["B1_EXPECTED_GID"])
            require(expected_uid > 0 and expected_gid > 0
                and os.getuid() == os.geteuid() == expected_uid
                and os.getgid() == os.getegid() == expected_gid,
                "nonroot_host_identity_mismatch")
            require(sys.executable == NATIVE and list(sys.version_info[:3]) == PYTHON_VERSION,
                    "preflight_not_invoked_by_exact_native_runtime")
            require(os.environ.get("LD_LIBRARY_PATH") == LD_PATH, "image_dynamic_library_environment_changed")
            require(Path("/logs").is_dir() and not Path("/logs").is_symlink()
                and not any(Path("/logs").iterdir()), "preflight_requires_own_initially_empty_logs")
            user_directory = prepare_user_directory()
            return {"expected_uid": expected_uid, "expected_gid": expected_gid,
                    "logs_initially_empty": True, "ld_library_path": LD_PATH,
                    "child_user_directory": user_directory}
        recorder.check("environment", environment_check)
        installed = recorder.check("installation", lambda: validate_installation(output))
        if installed is not None:
            manifest, source_result = installed
            state["installation"] = source_result
            recorder.check("runtime_artifacts", lambda: validate_runtime_artifacts(manifest))
        for label, directory in BUILD_ROOTS.items():
            recorder.check("build_records_" + label, lambda directory=directory, label=label:
                           copy_tree(directory, output / "build-records" / label))
        source_ready = installed is not None and all(value["passed"] for value in recorder.checks.values())
        state["source_and_environment_ready_before_execution"] = source_ready
        if source_ready:
            for label, interpreter, environment in (("native", NATIVE, "b0"), ("aios", AIOS, "g1")):
                def runtime_check(label=label, interpreter=interpreter, environment=environment):
                    stdout, _ = recorder.command(label + "_runtime",
                        [interpreter, "-B", str(ROOT / "preflight.py"), "--probe", "runtime"],
                        child_environment(environment), 45)
                    value = parse_printed_object(stdout, "schema", "b1-composition-runtime-probe-v1")
                    return validate_runtime(value, interpreter)
                recorder.check(label + "_runtime", runtime_check)
            def b0_source_check():
                stdout, _ = recorder.command("b0_source", [NATIVE, "-B", str(ROOT / "preflight.py"),
                    "--probe", "b0-source"], child_environment("session"), 90)
                value = parse_printed_object(stdout, "schema", "b1-composition-b0-source-verification-v1")
                require(value.get("passed") is True, "b0_source_verifier_did_not_pass")
                return value
            recorder.check("b0_derived_source", b0_source_check)
            def b0_preflight():
                stdout, _ = recorder.command("original_b0_preflight", [NATIVE, "-B",
                    str(B0 / "integration/agent_entry.py"), "--preflight"], child_environment("b0"), 180)
                value = read_json(Path("/logs/image-preflight.json"))
                printed = parse_printed_object(stdout, "scope", "real_image_local_runtime_only")
                require(value == printed and value.get("passed") is True and all(type(value.get(key)) is int and value[key] == 0
                    for key in ("native_mcp_calls", "business_operations", "model_calls")),
                    "original_b0_preflight_not_complete_offline_pass")
                return value
            recorder.check("original_b0_preflight", b0_preflight)
            recorder.check("original_b0_log_artifacts", lambda: copy_tree(Path("/logs"), output / "b0-preflight-logs"))
            def b1_preflight():
                stdout, _ = recorder.command("original_g1_preflight", [AIOS, "-B",
                    str(G1 / "integration/g1_preflight.py")], child_environment("g1"), 180)
                value = parse_printed_object(stdout, "passed", True)
                require(value.get("loaded") == ["cerebrum.llm.apis", "cerebrum.tool.apis", "cerebrum.interface",
                    "aios.scheduler.competition_llm_extension", "aios.llm_core.adapter", "g1_tool_manager", "typed_reads"]
                    and value.get("model_requests") == 0 and value.get("business_calls") == 0,
                    "original_g1_import_preflight_result_changed")
                return value
            recorder.check("original_g1_preflight", b1_preflight)
            for label, interpreter in (("native", NATIVE), ("aios", AIOS)):
                def session_check(label=label, interpreter=interpreter):
                    stdout, _ = recorder.command(label + "_session_imports", [interpreter, "-B",
                        str(ROOT / "preflight.py"), "--probe", "session-imports"], child_environment("session"), 45)
                    value = parse_printed_object(stdout, "schema", "b1-composition-session-import-v1")
                    require(value.get("passed") is True and all(item["sha256"] == manifest["files"][item["path"]]["sha256"]
                        for item in value["modules"].values()), "session_import_source_mismatch")
                    return value
                recorder.check(label + "_session_imports", session_check)
            def binary_check():
                stdout, stderr = recorder.command("llama_version", [str(LLAMA), "--version"],
                                                   child_environment("session"), 30)
                require(LLAMA_COMMIT[:7].encode() in stdout + stderr, "llama_version_does_not_name_fixed_commit")
                ldd_out, ldd_err = recorder.command("llama_ldd", ["/usr/bin/ldd", str(LLAMA)],
                                                   child_environment("session"), 30)
                require(b"not found" not in ldd_out + ldd_err, "llama_dynamic_dependency_missing")
                return {"version_only": True, "inference_performed": False,
                        "fixed_commit_prefix_seen": True, "ldd_missing_dependencies": False}
            recorder.check("llama_dynamic_linkage", binary_check)
            def library_check():
                stdout, _ = recorder.command("llama_libraries", [NATIVE, "-B", str(ROOT / "preflight.py"),
                    "--probe", "llama-libraries"], child_environment("session"), 45)
                value = parse_printed_object(stdout, "schema", "b1-composition-llama-libraries-v1")
                require(value.get("passed") is True and value.get("model_loaded") is False
                        and value.get("inference_calls") == 0, "llama_library_probe_not_offline_pass")
                return value
            recorder.check("llama_shared_libraries", library_check)
            def model_check():
                value = hash_file(MODEL)
                require(value == {"bytes": MODEL_BYTES, "sha256": MODEL_SHA}, "fixed_gguf_bytes_mismatch")
                with MODEL.open("rb") as stream:
                    prefix = stream.read(24)
                require(prefix.startswith(b"GGUF"), "model_not_gguf")
                return {"path": str(MODEL), **value, "first_24_bytes_hex": prefix.hex(),
                        "whole_file_hashed": True, "loaded_for_inference": False}
            recorder.check("fixed_model_file", model_check)
            def sources_unchanged():
                for name, record in manifest["files"].items():
                    require(hash_file(Path(name)) == {"bytes": record["bytes"], "sha256": record["sha256"]},
                            "installed_source_changed_during_preflight:" + name)
                return {"checked_files": len(manifest["files"]), "changed_files": []}
            recorder.check("installed_sources_unchanged", sources_unchanged)
        state["passed"] = bool(source_ready and len(recorder.commands) == 10
            and all(value["passed"] for value in recorder.checks.values()) and not recorder.errors)
    except BaseException as error:
        state["fatal_error"] = {**error_record(error), "traceback": traceback.format_exc()}
        state["passed"] = False
    finally:
        state["elapsed_seconds"] = time.monotonic() - started
        state["ended_at_utc"] = datetime.now(timezone.utc).isoformat()
        try:
            state["resources_after"] = resource_snapshot()
        except BaseException as error:
            state["resources_after"] = {"error": error_record(error)}
            state["passed"] = False
        state["resource_scope"] = "getrusage CPU includes reaped children; RSS is a high-water mark, not additive concurrent memory. Container cgroup values are retained separately."
        state["checks"] = recorder.checks if recorder is not None else {}
        state["commands"] = recorder.commands if recorder is not None else []
        state["errors"] = recorder.errors if recorder is not None else []
        try:
            write_once(output / RESULT_NAME, canonical(state) + b"\n")
        except BaseException as error:
            state["passed"] = False
            state["result_write_error"] = error_record(error)
        print(json.dumps(state, ensure_ascii=False, allow_nan=False), flush=True)
    return 0 if state["passed"] is True else 1


def main():
    global DEADLINE
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    parser.add_argument("--probe", choices=("runtime", "b0-source", "session-imports", "llama-libraries"))
    args = parser.parse_args()
    if args.probe:
        require(args.output is None, "probe_cannot_write_result_directory")
        deadline = os.environ.get("B1_COMPOSITION_DEADLINE_MONOTONIC")
        if deadline is not None:
            DEADLINE = float(deadline)
            require(0 < DEADLINE < float("inf"), "invalid_shared_preflight_deadline")
        probes = {"runtime": runtime_probe, "b0-source": b0_source_probe,
                  "session-imports": session_import_probe, "llama-libraries": llama_library_probe}
        print(json.dumps(probes[args.probe](), ensure_ascii=False, allow_nan=False))
        return 0
    require(args.output is not None, "output_directory_required")
    return run_main(args.output)


if __name__ == "__main__":
    raise SystemExit(main())
