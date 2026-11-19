"""Generate an offline-only image context from exact fixed public sources.

No download, Docker, model, owner, Controller, native endpoint or business call
is made here. The two original source generators only derive reviewed files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
MAIN_ROOT = HERE.parent
INPUT_BINDING_SHA256 = "7665841dc89ecbaa5f0bb710099eff2f02bcb12380161956e2fde2a962907584"
INPUT_SCHEMA = "b1-composition-source-input-binding-v1"
INSTALLATION_SCHEMA = "b1-composition-installation-manifest-v1"
CONTEXT_SCHEMA = "b1-composition-build-context-v1"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_regular(path, maximum=32 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise ValueError("bounded_single_link_source_required:" + str(path))
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        if len(raw) != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("source_changed_during_read:" + str(path))
        return raw
    finally:
        os.close(fd)


def file_record(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("single_link_regular_context_file_required:" + str(path))
        sha, size = hashlib.sha256(), 0
        with os.fdopen(fd, "rb", closefd=False) as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                sha.update(block)
                size += len(block)
        after = os.fstat(fd)
        if size != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("context_changed_during_read:" + str(path))
        return {"bytes": size, "sha256": sha.hexdigest()}
    finally:
        os.close(fd)


def json_write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as target:
        target.write((json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode())


def relative_name(value):
    if not isinstance(value, str):
        raise ValueError("invalid_manifest_relative_path")
    path = PurePosixPath(value)
    if (path.is_absolute() or str(path) != value
            or any(part in {".", ".."} for part in path.parts) or not path.parts):
        raise ValueError("invalid_manifest_relative_path")
    return value


def tree_files(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("real_source_directory_required:" + str(root))
    files, directories = set(), set()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISREG(mode):
            files.add(relative)
        elif stat.S_ISDIR(mode):
            directories.add(relative)
        else:
            raise ValueError("source_link_or_special_node_forbidden:" + str(path))
    return files, directories


def input_binding():
    raw = read_regular(HERE / "SOURCE_INPUT_BINDING.json")
    if digest(raw) != INPUT_BINDING_SHA256:
        raise ValueError("reviewed_input_binding_changed")
    value = json.loads(raw)
    if value.get("schema") != INPUT_SCHEMA:
        raise ValueError("input_binding_schema_invalid")
    return value, raw


def verify_manifest_tree(root, manifest_name, expected, *, strip_prefix=""):
    raw = read_regular(root / manifest_name)
    if {"bytes": len(raw), "sha256": digest(raw)} != {k: expected[k] for k in ("bytes", "sha256")}:
        raise ValueError("fixed_source_manifest_changed:" + str(root / manifest_name))
    manifest = json.loads(raw)
    expected_files = {}
    for name, item in manifest["files"].items():
        if strip_prefix:
            if not name.startswith(strip_prefix):
                raise ValueError("fixed_source_prefix_changed")
            name = name[len(strip_prefix):]
        relative_name(name)
        expected_files[name] = item if isinstance(item, dict) else {"sha256": item}
    actual_files, _ = tree_files(root)
    if actual_files != set(expected_files) | {manifest_name}:
        raise ValueError("fixed_source_file_set_changed:" + str(root))
    for name, expected_file in expected_files.items():
        actual = file_record(root / name)
        if any(actual[key] != value for key, value in expected_file.items() if key in {"sha256", "bytes"}):
            raise ValueError("fixed_source_file_changed:" + str(root / name))
    return {"manifest_sha256": digest(raw), "verified_file_count": len(expected_files),
            "files": expected_files}


def verify_inputs(reference, binding):
    b0, b1, session = binding["b0"], binding["b1"], binding["session"]
    result = {
        "b0": verify_manifest_tree(MAIN_ROOT / b0["root"], "PACKAGE_MANIFEST.json", b0["package_manifest"]),
        "g1_original": verify_manifest_tree(reference / b1["original_root"], "PACKAGE_MANIFEST.json", b1["original_manifest"]),
        "b1_overlay": verify_manifest_tree(reference / b1["overlay_root"], "SOURCE_MANIFEST.json", b1["overlay_source_manifest"]),
        "session": verify_manifest_tree(MAIN_ROOT / session["root"], "SESSION_SOURCE_MANIFEST.json",
            session["source_manifest"], strip_prefix="b1-common-session/")}
    for name, count in (("b0", b0["package_files"]), ("g1_original", b1["original_files"]),
                        ("b1_overlay", b1["overlay_declared_files"]), ("session", session["declared_source_files"])):
        if result[name]["verified_file_count"] != count:
            raise ValueError("fixed_source_file_count_changed:" + name)
    for name, expected in session["production_files"].items():
        if file_record(MAIN_ROOT / session["root"] / name) != {k: expected[k] for k in ("bytes", "sha256")}:
            raise ValueError("fixed_session_production_source_changed:" + name)
    for root, item in ((reference, b1["generator"]), (MAIN_ROOT, session["derivation_generator"])):
        if file_record(root / item["path"]) != {k: item[k] for k in ("bytes", "sha256")}:
            raise ValueError("fixed_generator_source_changed")
    return result


def candidate_source(path):
    """Never label uncommitted new source bytes as the old parent commit."""
    relative = path.relative_to(MAIN_ROOT).as_posix()
    raw = read_regular(path)
    commit, status = None, "uncommitted_worktree_bytes"
    try:
        head = subprocess.run(["git", "-C", str(MAIN_ROOT), "rev-parse", "HEAD"],
                              capture_output=True, check=True, timeout=10).stdout.decode().strip()
        recorded = subprocess.run(["git", "-C", str(MAIN_ROOT), "show", head + ":" + relative],
                                  capture_output=True, check=False, timeout=10)
        if recorded.returncode == 0 and recorded.stdout == raw:
            commit, status = head, "exact_current_git_blob"
    except (OSError, subprocess.SubprocessError):
        pass
    return {"component": "composition_gate", "commit": commit, "path": relative,
            "sha256": digest(raw), "binding_status": status}


def run_generator(path, arguments):
    environment = dict(os.environ)
    environment.update(PYTHONPATH="", PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1")
    completed = subprocess.run([sys.executable, "-B", str(path), *map(str, arguments)],
                               env=environment, capture_output=True, check=False, timeout=120)
    if completed.returncode:
        raise ValueError("fixed_source_generator_failed:" + path.name + ":" + completed.stderr.decode(errors="replace")[:4000])
    return json.loads(completed.stdout)


def fixed_build_stage(raw, name):
    start = b"FROM ${PYTHON_IMAGE} AS " + name.encode("ascii") + b"\n"
    if raw.count(start) != 1:
        raise ValueError("one_fixed_build_stage_required:" + name)
    body = raw.split(start, 1)[1].split(b"\nFROM ", 1)[0]
    return start + body.rstrip(b"\n") + b"\n"


def install_source(output, files, context_path, install_path, raw, source, derivation=None):
    relative_name(context_path)
    if install_path in files or not install_path.startswith("/opt/"):
        raise ValueError("duplicate_or_invalid_installation_path")
    destination = output / context_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as target:
        target.write(raw)
    item = {"bytes": len(raw), "sha256": digest(raw), "context_path": context_path, "source": source}
    if derivation is not None:
        item["derivation"] = derivation
    files[install_path] = item


def verify_context(output, *, require_model):
    binding, _ = input_binding()
    actual_files, actual_dirs = tree_files(output)
    context = json.loads(read_regular(output / "BUILD_CONTEXT_MANIFEST.json"))
    if context.get("schema") != CONTEXT_SCHEMA or context.get("input_binding_sha256") != INPUT_BINDING_SHA256:
        raise ValueError("composition_context_manifest_invalid")
    model = binding["model"]
    model_record = {k: model[k] for k in ("bytes", "sha256")}
    if context.get("external_required_files") != {model["context_path"]: model_record}:
        raise ValueError("fixed_external_model_slot_changed")
    required = set(context["files"]) | {"BUILD_CONTEXT_MANIFEST.json"}
    model_present = model["context_path"] in actual_files
    if require_model and not model_present:
        raise ValueError("fixed_model_artifact_missing")
    if model_present:
        required.add(model["context_path"])
    if actual_files != required:
        raise ValueError("unexpected_or_missing_build_context_file")
    expected_dirs = {"models"}
    for name in required:
        relative_name(name)
        expected_dirs.update(str(parent) for parent in PurePosixPath(name).parents if str(parent) != ".")
    if actual_dirs != expected_dirs:
        raise ValueError("unexpected_or_missing_build_context_directory")
    for name, expected in context["files"].items():
        if file_record(output / name) != expected:
            raise ValueError("build_context_file_changed:" + name)
    if model_present and file_record(output / model["context_path"]) != model_record:
        raise ValueError("fixed_model_size_or_sha256_mismatch")
    installation = json.loads(read_regular(output / "INSTALLATION_MANIFEST.json"))
    if installation.get("schema") != INSTALLATION_SCHEMA:
        raise ValueError("installation_manifest_schema_invalid")
    for path, item in installation["files"].items():
        if not path.startswith("/opt/") or file_record(output / relative_name(item["context_path"])) != {
                key: item[key] for key in ("bytes", "sha256")}:
            raise ValueError("installation_source_binding_mismatch:" + path)
    return {"schema": "b1-composition-context-verification-v1", "passed": True,
            "model_present_and_verified": model_present,
            "source_files_verified": len(context["files"]), "installed_source_files": len(installation["files"]),
            "installation_manifest_sha256": digest(read_regular(output / "INSTALLATION_MANIFEST.json")),
            "build_context_manifest_sha256": digest(read_regular(output / "BUILD_CONTEXT_MANIFEST.json")),
            "qualification": "source_context_only_not_image_or_model_qualification"}


def build(reference, output):
    binding, binding_raw = input_binding()
    if output.exists() or output.is_symlink():
        raise ValueError("new_output_directory_required")
    reference, output = reference.resolve(strict=True), output.resolve(strict=False)
    if output.exists() or output.is_symlink():
        raise ValueError("new_output_directory_required")
    for protected in (MAIN_ROOT / "b0-run", MAIN_ROOT / "b1-common-session", HERE, reference):
        if output.is_relative_to(protected) or protected.is_relative_to(output):
            raise ValueError("output_overlaps_fixed_sources")
    source_before = verify_inputs(reference, binding)
    preflight = read_regular(HERE / "preflight.py")
    dockerfile = read_regular(HERE / "Dockerfile")
    production = binding["session"]["production_files"]
    files = {}
    # Only the temporary tree contains original host wrappers; only public
    # payloads and nonexecutable binding JSON enter the final image context.
    with tempfile.TemporaryDirectory(prefix="b1-composition-derive-") as temporary:
        temporary = Path(temporary)
        b1_derived, b0_derived = temporary / "b1", temporary / "b0"
        b1_result = run_generator(reference / binding["b1"]["generator"]["path"], [
            "--base", reference / "g1-smoke", "--dest", b1_derived,
            "--branch", binding["b1"]["generation_branch"]])
        b1_manifest_raw = read_regular(b1_derived / "PACKAGE_MANIFEST.json")
        if digest(b1_manifest_raw) != binding["b1"]["generated_package_manifest_sha256"]:
            raise ValueError("generated_B1_not_exact_fixed_43b_package")
        b1_verified = verify_manifest_tree(b1_derived, "PACKAGE_MANIFEST.json",
            {"bytes": len(b1_manifest_raw), "sha256": digest(b1_manifest_raw)})
        if b1_verified["verified_file_count"] != binding["b1"]["generated_files"]:
            raise ValueError("generated_B1_file_count_changed")
        b1_dockerfile = read_regular(b1_derived / "Dockerfile")
        if digest(b1_dockerfile) != binding["llama"]["fixed_b1_generated_dockerfile_sha256"]:
            raise ValueError("fixed_B1_Docker_build_recipe_changed")
        for name, original in (("sqlite-build", read_regular(MAIN_ROOT / "b0-run/Dockerfile")),
                               ("llama-build", b1_dockerfile)):
            if fixed_build_stage(dockerfile, name) != fixed_build_stage(original, name):
                raise ValueError("fixed_build_stage_changed:" + name)
        b0_result = run_generator(MAIN_ROOT / binding["session"]["derivation_generator"]["path"], [
            "build", "--base-b0", MAIN_ROOT / "b0-run", "--destination", b0_derived])
        derived_raw = read_regular(b0_derived / "DERIVED_PAYLOAD_BINDING.json")
        b0_derived_binding = json.loads(derived_raw)
        original_b0 = source_before["b0"]["files"]
        b0_payload, _ = tree_files(b0_derived / "payload")
        b1_payload, _ = tree_files(b1_derived / "payload")
        if (len(b0_payload) != binding["b0"]["payload_files"] or set(b0_derived_binding["files"]) != b0_payload
                or len(b1_payload) != binding["b1"]["payload_files"]):
            raise ValueError("derived_payload_file_set_or_count_changed")
        if read_regular(b0_derived / "payload/native_adapter/requirements-native.txt") != read_regular(
                b1_derived / "payload/native_adapter/requirements-native.txt"):
            raise ValueError("one_native_venv_requires_identical_fixed_requirements")
        output.mkdir(mode=0o755)
        (output / "models").mkdir()
        for name in sorted(b0_payload):
            raw = read_regular(b0_derived / "payload" / name)
            expected = b0_derived_binding["files"][name]
            original = read_regular(MAIN_ROOT / "b0-run/payload" / name)
            if (digest(raw) != expected["derived_sha256"] or len(raw) != expected["bytes"]
                    or expected["base_sha256"] != original_b0["payload/" + name]["sha256"]):
                raise ValueError("derived_B0_file_binding_changed:" + name)
            amendment = binding["b0"]["allowed_payload_amendment"]
            if name == amendment["path"]:
                if raw != original.replace(amendment["from"].encode(), amendment["to"].encode(), 1):
                    raise ValueError("B0_role_amendment_not_exact")
            elif raw != original:
                raise ValueError("unexpected_B0_public_source_amendment")
            source = {"component": "b0_public_payload", "commit": binding["b0"]["commit"],
                      "path": "b0-run/payload/" + name, "sha256": digest(original)}
            install_source(output, files, "b0-payload/" + name, "/opt/b0/" + name, raw, source,
                {"kind": "only_fixed_role_amendment", **amendment} if raw != original else None)
        for name in sorted(b1_payload):
            raw = read_regular(b1_derived / "payload" / name)
            original_path = {"integration/b1_metering.py": "b1-readonly-gate/b1_metering.py",
                             "integration/g1_sdk_client.py": "b1-readonly-gate/b1_sdk_client.py"}.get(
                                 name, "g1-smoke/payload/" + name)
            source = {"component": "b1_fixed_overlay_payload", "commit": binding["b1"]["commit"],
                      "path": original_path, "sha256": digest(read_regular(reference / original_path))}
            install_source(output, files, "g1-payload/" + name, "/opt/g1/" + name, raw, source,
                {"kind": "exact_fixed_43b_generator", "generator_sha256": binding["b1"]["generator"]["sha256"],
                 "generated_package_manifest_sha256": digest(b1_manifest_raw), "generated_path": "payload/" + name})
        for name, item in production.items():
            install_source(output, files, "session/" + name, "/opt/b1-common-session/" + name,
                read_regular(MAIN_ROOT / item["path"]), {"component": "session_production",
                    "commit": binding["session"]["commit"], "path": item["path"], "sha256": item["sha256"]})
        for name in ("DERIVED_PAYLOAD_BINDING.json", "BASE_PACKAGE_MANIFEST.json"):
            generator = binding["session"]["derivation_generator"]
            install_source(output, files, "session/derived/" + name, "/opt/b1-common-session/derived/" + name,
                read_regular(b0_derived / name), {"component": "session_derived_binding", "commit": binding["session"]["commit"],
                    "path": generator["path"], "sha256": generator["sha256"]},
                {"kind": "fixed_controller_adapter_output", "output_name": name,
                 "b0_package_manifest_sha256": binding["b0"]["package_manifest"]["sha256"]})
        for name, raw in (("preflight.py", preflight), ("SOURCE_INPUT_BINDING.json", binding_raw)):
            install_source(output, files, "composition/" + name, "/opt/b1-composition/" + name,
                           raw, candidate_source(HERE / name))
        (output / "bindings").mkdir()
        for old, new in (("PACKAGE_MANIFEST.json", "B1_PACKAGE_MANIFEST.json"),
                         ("OVERLAY_MANIFEST.json", "B1_OVERLAY_MANIFEST.json")):
            (output / "bindings" / new).write_bytes(read_regular(b1_derived / old))
        (output / "Dockerfile").write_bytes(dockerfile)
        source_after = verify_inputs(reference, binding)
        if source_before != source_after or preflight != read_regular(HERE / "preflight.py") or dockerfile != read_regular(HERE / "Dockerfile"):
            raise ValueError("source_changed_during_composition")
        source_bindings = {
            "input_binding": {"path": "/opt/b1-composition/SOURCE_INPUT_BINDING.json", "sha256": digest(binding_raw)},
            "b0": {"commit": binding["b0"]["commit"], "package_manifest_sha256": source_before["b0"]["manifest_sha256"],
                "verified_file_count": source_before["b0"]["verified_file_count"], "payload_file_count": len(b0_payload),
                "derived_binding_path": "/opt/b1-common-session/derived/DERIVED_PAYLOAD_BINDING.json",
                "derived_binding_sha256": digest(derived_raw),
                "base_manifest_path": "/opt/b1-common-session/derived/BASE_PACKAGE_MANIFEST.json"},
            "b1": {"commit": binding["b1"]["commit"], "original_g1_manifest_sha256": source_before["g1_original"]["manifest_sha256"],
                "overlay_source_manifest_sha256": source_before["b1_overlay"]["manifest_sha256"],
                "generated_package_manifest_sha256": digest(b1_manifest_raw), "verified_file_count": b1_verified["verified_file_count"],
                "payload_file_count": len(b1_payload), "generation_branch": binding["b1"]["generation_branch"]},
            "session": {"commit": binding["session"]["commit"], "source_manifest_sha256": source_before["session"]["manifest_sha256"],
                "verified_file_count": source_before["session"]["verified_file_count"],
                "installed_files": sorted("/opt/b1-common-session/" + name for name in production)}}
        model = binding["model"]
        installation = {"schema": INSTALLATION_SCHEMA, "qualification": "not_remote_qualified",
            "scope": "offline combined-image materials only", "files": files, "source_bindings": source_bindings,
            "build_inputs": {"composition_dockerfile": {**file_record(output / "Dockerfile"), "context_path": "Dockerfile", "source": candidate_source(HERE / "Dockerfile")},
                             "python": binding["python"], "sqlite": binding["sqlite"], "llama": binding["llama"], "model": model},
            "runtime_inventory_path": binding["installation"]["runtime_inventory_path"],
            "runtime_artifacts": {
                "/opt/b0/sqlite/libsqlite3.so.0": {"component": "sqlite", "version": binding["sqlite"]["version"],
                    "source_id": binding["sqlite"]["source_id"], "binary_sha256_record": "/opt/b0/build-record/sqlite-binary.sha256",
                    "build_source_binding": "/opt/b0/build-record/sqlite-source-binding.json"},
                "/opt/llama/bin/llama-server": {"component": "llama", "commit": binding["llama"]["commit"],
                    "binary_sha256_record": "/opt/g1/build-record/llama-binary.sha256", "execution_scope": "version_only"},
                model["installed_path"]: {"component": "model", "bytes": model["bytes"], "sha256": model["sha256"],
                    "source_url": model["source_url"], "inference_permitted": False}},
            "not_performed": {"model_inference": True, "owner_start": True, "controller_execution": True,
                              "original_task": True, "comparison_budget_selection": True}}
        json_write(output / "INSTALLATION_MANIFEST.json", installation)
        report = {"schema": "b1-composition-generation-report-v1", "source_generation_passed": True,
            "qualification": "not_remote_qualified", "source_bindings": source_bindings,
            "source_inputs_unchanged": True, "fixed_B1_generator_executed": True,
            "fixed_session_derivation_generator_executed": True,
            "fixed_sqlite_and_llama_build_stages_byte_identical": True,
            "generator_receipts": {"b1": {k: v for k, v in b1_result.items() if k != "destination"}, "b0": b0_result},
            "installed_source_file_count": len(files), "image_built": False,
            "model_downloaded": False, "model_inference": False, "controller_executed": False,
            "original_task_started": False, "new_comparison_budget_selected": False,
            "builder_source": candidate_source(Path(__file__).resolve()),
            "installation_manifest_sha256": digest(read_regular(output / "INSTALLATION_MANIFEST.json"))}
        json_write(output / "GENERATION_REPORT.json", report)
        context_files, _ = tree_files(output)
        json_write(output / "BUILD_CONTEXT_MANIFEST.json", {"schema": CONTEXT_SCHEMA,
            "input_binding_sha256": digest(binding_raw),
            "files": {name: file_record(output / name) for name in sorted(context_files)},
            "external_required_files": {model["context_path"]: {k: model[k] for k in ("bytes", "sha256")}},
            "scope": "exact source context; host may add only the fixed model artifact before strict verification"})
        verified = verify_context(output, require_model=False)
        return {**verified, "output": str(output), "source_generation_passed": True,
                "model_inference": False, "controller_executed": False, "original_task_started": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--b1-source-root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-output", type=Path)
    args = parser.parse_args()
    if args.verify_output is not None:
        if args.b1_source_root is not None or args.output is not None:
            parser.error("--verify-output is exclusive")
        value = verify_context(args.verify_output.resolve(strict=True), require_model=True)
    else:
        if args.b1_source_root is None or args.output is None:
            parser.error("--b1-source-root and --output are required for generation")
        value = build(args.b1_source_root, args.output)
    print(json.dumps(value, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
