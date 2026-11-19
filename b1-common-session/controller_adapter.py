"""Reviewed B0 payload derivation and the real, unchanged B0 process entry.

No model/tool request supplies a command, path, role, budget, or clock.  The
generated public payload is installed at /opt/b0; its original entry records
the actual loaded payload before it reaches the original Controller.main().
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import sys
import time

HERE = Path(__file__).resolve().parent
BASE_COMMIT = "22fa7c12ea5274f86a2ecca17e6cc2e16ab7a4ad"
BASE_PACKAGE_SHA256 = "8e1f713246630961977d407a8d51d4bfe9d077a11f0c04949ff48904301d843e"
PAYLOAD_ROOT = Path("/opt/b0")
LOG_ROOT = Path("/logs")
NATIVE_PYTHON = "/opt/native/bin/python"
ROLE_ANCHOR = b"catalog=catalog,role='script',**extra)"
ROLE_REPLACEMENT = b"catalog=catalog,role='single',**extra)"
ENTRY_RELATIVE = "integration/agent_entry.py"
SQLITE_SOURCE_ID = "2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_regular(path, maximum=16 * 1024 * 1024):
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise ValueError("bounded_regular_file_required")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(descriptor)
        if len(raw) > maximum or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("evidence_changed_during_read")
        return raw
    finally:
        os.close(descriptor)


def write_once(path, value):
    path = Path(path)
    raw = value if isinstance(value, bytes) else canonical(value) + b"\n"
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return digest(raw)


def basis(path=None):
    value = json.loads(read_regular(path or HERE / "BASE_BINDING.json"))
    if (value.get("schema") != "b1-common-session-fixed-basis-v1"
            or value.get("base_commit") != BASE_COMMIT
            or value.get("b0_package_manifest_sha256") != BASE_PACKAGE_SHA256):
        raise ValueError("unrecognized_fixed_B0_basis")
    return value


def payload_files(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("payload_root_must_be_real_directory")
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("payload_symlink_forbidden")
        if path.is_file():
            files[str(path.relative_to(root))] = read_regular(path)
        elif not path.is_dir():
            raise ValueError("unexpected_payload_node")
    return files


def package_payload(raw):
    if digest(raw) != BASE_PACKAGE_SHA256:
        raise ValueError("base_package_manifest_changed")
    manifest = json.loads(raw)
    return {name.removeprefix("payload/"): sha for name, sha in manifest["files"].items()
            if name.startswith("payload/")}


def build_payload_overlay(base_b0, destination, *, basis_path=None):
    """Offline generation only: one literal role amendment in a new payload."""
    base_b0, destination = Path(base_b0).resolve(), Path(destination).resolve()
    fixed = basis(basis_path)
    if destination.exists() or destination.is_relative_to(base_b0) or base_b0.is_relative_to(destination):
        raise ValueError("new_external_derivation_directory_required")
    for item in fixed["b0_sources"]:
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts or relative.parts[0] != "b0-run":
            raise ValueError("invalid_fixed_source_locator")
        raw = read_regular(base_b0.parent / relative)
        if len(raw) != item["bytes"] or digest(raw) != item["sha256"]:
            raise ValueError("fixed_B0_source_changed:" + str(relative))
    package_raw = read_regular(base_b0 / "PACKAGE_MANIFEST.json")
    expected = package_payload(package_raw)
    actual = payload_files(base_b0 / "payload")
    if set(actual) != set(expected) or any(digest(raw) != expected[name] for name, raw in actual.items()):
        raise ValueError("fixed_public_payload_changed")
    original = actual["strategy/common_io.py"]
    if original.count(ROLE_ANCHOR) != 1 or ROLE_REPLACEMENT in original:
        raise ValueError("unique_original_role_anchor_required")
    destination.mkdir(mode=0o700)
    shutil.copytree(base_b0 / "payload", destination / "payload")
    (destination / "payload/strategy/common_io.py").write_bytes(original.replace(ROLE_ANCHOR, ROLE_REPLACEMENT, 1))
    derived = payload_files(destination / "payload")
    differences = [name for name in actual if actual[name] != derived[name]]
    if differences != ["strategy/common_io.py"]:
        raise ValueError("only_reviewed_role_amendment_permitted")
    binding = {
        "schema": "b1-common-session-derived-payload-v1", "base_commit": BASE_COMMIT,
        "base_package_manifest_sha256": BASE_PACKAGE_SHA256,
        "actual_install_root": str(PAYLOAD_ROOT), "trusted_role": "single",
        "entry_relative": ENTRY_RELATIVE, "entry_original_sha256": expected[ENTRY_RELATIVE],
        "amendment": {"path": "strategy/common_io.py", "before": ROLE_ANCHOR.decode(),
                      "after": ROLE_REPLACEMENT.decode(), "occurrences": 1},
        "files": {name: {"base_sha256": expected[name], "derived_sha256": digest(raw),
                         "bytes": len(raw), "actual_load_path": str(PAYLOAD_ROOT / name)}
                  for name, raw in derived.items()},
        "runtime_artifacts": {"sqlite/libsqlite3.so.0": {
            "digest_record": "build-record/sqlite-binary.sha256",
            "recorded_absolute_path": "/opt/b0/sqlite/libsqlite3.so.0",
            "source_and_version_check": "3.54.1 and original sqlite_source_id before entry"}},
        "helper_model_calls_scope": "deterministic helper only; outer B1 accounting is independent",
        "combined_image_qualification": "pending",
    }
    write_once(destination / "BASE_PACKAGE_MANIFEST.json", package_raw)
    write_once(destination / "DERIVED_PAYLOAD_BINDING.json", binding)
    verify_payload(destination / "payload", destination / "DERIVED_PAYLOAD_BINDING.json", basis_path=basis_path)
    return binding


def verify_payload(root, binding_path, *, basis_path=None, require_runtime=False):
    """Re-derive allowed hashes from the pinned original, not caller claims."""
    basis(basis_path)
    root, binding_path = Path(root), Path(binding_path)
    binding_raw = read_regular(binding_path)
    binding = json.loads(binding_raw)
    expected = package_payload(read_regular(binding_path.parent / "BASE_PACKAGE_MANIFEST.json"))
    if (binding.get("schema") != "b1-common-session-derived-payload-v1"
            or binding.get("base_commit") != BASE_COMMIT
            or binding.get("base_package_manifest_sha256") != BASE_PACKAGE_SHA256
            or binding.get("actual_install_root") != str(PAYLOAD_ROOT)
            or binding.get("trusted_role") != "single"
            or binding.get("entry_relative") != ENTRY_RELATIVE
            or binding.get("entry_original_sha256") != expected[ENTRY_RELATIVE]
            or set(binding.get("files", {})) != set(expected)):
        raise ValueError("derived_payload_binding_invalid")
    files = payload_files(root)
    # Build records are produced by the reviewed image assembly, not imports.
    runtime_artifacts = {}
    library = "sqlite/libsqlite3.so.0"
    if library in files:
        record = files.get("build-record/sqlite-binary.sha256", b"")
        match = re.fullmatch(rb"([0-9a-f]{64})  /opt/b0/sqlite/libsqlite3\.so\.0\n", record)
        if match is None or digest(files[library]) != match[1].decode():
            raise ValueError("fixed_SQLite_binary_build_record_mismatch")
        runtime_artifacts[library] = {"sha256": digest(files[library]),
                                      "build_record_sha256": digest(record)}
    elif require_runtime:
        raise ValueError("fixed_SQLite_runtime_library_missing")
    sources = {name: raw for name, raw in files.items()
               if not name.startswith("build-record/") and name != library}
    if set(sources) != set(expected):
        raise ValueError("actual_payload_source_set_changed")
    for name, raw in sources.items():
        original = raw
        if name == "strategy/common_io.py":
            if raw.count(ROLE_REPLACEMENT) != 1 or ROLE_ANCHOR in raw:
                raise ValueError("single_role_derivation_missing_or_ambiguous")
            original = raw.replace(ROLE_REPLACEMENT, ROLE_ANCHOR, 1)
        if digest(original) != expected[name]:
            raise ValueError("payload_contains_unreviewed_change:" + name)
        wanted = {"base_sha256": expected[name], "derived_sha256": digest(raw),
                  "bytes": len(raw), "actual_load_path": str(PAYLOAD_ROOT / name)}
        if binding["files"][name] != wanted:
            raise ValueError("actual_payload_does_not_match_derived_manifest:" + name)
    return {"binding_sha256": digest(binding_raw), "binding": binding,
            "runtime_artifacts": runtime_artifacts,
            "actual_source_hashes": {name: digest(raw) for name, raw in sources.items()}}


def trusted_launch(binding_path, *, environment=None, require_active=False):
    """Production paths and role are fixed; no request body reaches this code."""
    env = dict(os.environ if environment is None else environment)
    if env.get("SRE_NATIVE_ROLE") != "single" or env.get("SRE_NATIVE_PYTHON") != NATIVE_PYTHON:
        raise ValueError("trusted_single_native_environment_required")
    context_path = LOG_ROOT / "b0-launch-context.json"
    context_raw = read_regular(context_path)
    context = json.loads(context_raw)
    if (context.get("mode") != "public_b0" or context.get("protocol_id") != "public_result_v1"
            or context.get("namespace") != "gitlab-ce"
            or context.get("attempt_id") != env.get("SRE_NATIVE_ATTEMPT_ID")
            or context.get("attempt_id") != env.get("B0_ATTEMPT_ID")):
        raise ValueError("original_public_launch_context_required")
    for field in ("attempt_id", "physical_scope_id", "ledger_epoch", "namespace_uid"):
        if not isinstance(context.get(field), str) or not context[field]:
            raise ValueError("missing_trusted_physical_identity")
    before = context.get("incident_visible_mono")
    limit = context.get("budgets", {}).get("agent_timeout_seconds")
    if (type(before) not in (int, float) or not math.isfinite(before)
            or type(limit) not in (int, float) or not math.isfinite(limit) or limit <= 0
            or not 0 <= before <= time.monotonic()):
        raise ValueError("original_incident_clock_or_budget_invalid")
    if require_active and time.monotonic() >= before + limit:
        raise ValueError("original_incident_budget_not_active")
    proof = read_regular(LOG_ROOT / "b0-native-boundary.json")
    if digest(proof) != context.get("boundary_proof_sha256"):
        raise ValueError("original_boundary_proof_changed")
    verified = verify_payload(PAYLOAD_ROOT, binding_path, require_runtime=True)
    identity = {name: context[name] for name in ("attempt_id", "physical_scope_id", "ledger_epoch", "namespace_uid")}
    identity.update(role="single", launch_context_sha256=digest(context_raw),
                    derived_payload_binding_sha256=verified["binding_sha256"])
    return {"identity_binding": identity, "context": context, "verified_payload": verified}


def helper_id(identity_binding):
    return "full-" + digest(canonical(identity_binding))


def clean_entry_environment(environment):
    env = dict(environment)
    for name in ("PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", "PYTHONINSPECT"):
        env.pop(name, None)
    env.update(PYTHONPATH=":".join(str(PAYLOAD_ROOT / part) for part in
               ("common_bridge", "strategy", "native_adapter", "integration")),
               PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1")
    return env


def exec_original_entry(session_root, binding_path):
    session_root = Path(session_root)
    launch = trusted_launch(binding_path, require_active=True)
    reservation = json.loads(read_regular(session_root / "controller_launch.json"))
    identity = launch["identity_binding"]
    if (reservation.get("schema") != "b1-public-full-helper-launch-v1"
            or reservation.get("helper_id") != helper_id(identity)
            or reservation.get("identity_binding") != identity
            or reservation.get("launch_reservations") != 1):
        raise ValueError("controller_launch_not_bound_to_reserved_helper")
    if sys.version_info[:3] != (3, 11, 17) or sqlite3.sqlite_version != "3.54.1":
        raise ValueError("combined_native_python_and_SQLite_not_qualified")
    with sqlite3.connect(":memory:") as db:
        if db.execute("select sqlite_source_id()").fetchone()[0] != SQLITE_SOURCE_ID:
            raise ValueError("combined_SQLite_source_changed")
    if (LOG_ROOT / "b0-agent-result.json").exists():
        raise ValueError("preexisting_controller_result_forbids_new_execution")
    environment = clean_entry_environment(os.environ)
    argv = [NATIVE_PYTHON, "-B", str(PAYLOAD_ROOT / ENTRY_RELATIVE)]
    write_once(session_root / "controller_source_validation.json", {
        "schema": "b1-public-full-helper-actual-entry-v1", "helper_id": helper_id(identity),
        "identity_binding": identity, "argv": argv, "pythonpath": environment["PYTHONPATH"],
        "actual_source_hashes": launch["verified_payload"]["actual_source_hashes"],
        "runtime_artifacts": launch["verified_payload"]["runtime_artifacts"],
        "source_qualification_scope": "exact public sources and local runtime before original entry",
        "business_recovery_qualified": False, "combined_host_cleanup_qualified": False,
    })
    os.chdir(LOG_ROOT)
    os.execve(NATIVE_PYTHON, argv, environment)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="operation", required=True)
    build = sub.add_parser("build")
    build.add_argument("--base-b0", required=True)
    build.add_argument("--destination", required=True)
    run = sub.add_parser("exec-controller")
    run.add_argument("--session-root", required=True)
    run.add_argument("--binding", required=True)
    args = parser.parse_args()
    if args.operation == "build":
        result = build_payload_overlay(args.base_b0, args.destination)
        print(json.dumps({"files": len(result["files"]), "amended_files": ["strategy/common_io.py"]}))
    else:
        exec_original_entry(args.session_root, args.binding)


if __name__ == "__main__":
    main()
