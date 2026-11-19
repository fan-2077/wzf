"""Owned combined-image installation checks; no inference or original incident."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import shutil
import sys
import subprocess
import tarfile
import time

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "b1-composition-results"
REF = "refs/heads/sre-b1-composition-preflight-20261119"
LABEL = "sre.b1.composition"
REFERENCE = ROOT / "b1-composition-pinned-reference"
GENERATED = ROOT / "b1-composition-generated"
REFERENCE_COMMIT = "43b15ea58de5d33603ac6ef60e2add74c3ea514d"
MODEL_NAME = "Qwen3-8B-Q4_K_M.gguf"
MODEL_SHA256 = "d98cdcbd03e17ce47681435b5150e34c1417f50b5c0019dd560e4882c5745785"
MODEL_BYTES = 5027783488
MODEL_URL = "https://huggingface.co/Qwen/Qwen3-8B-GGUF/resolve/7c41481f57cb95916b40956ab2f0b139b296d974/" + MODEL_NAME
COMMAND_DEADLINE = None


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"


def save(path, value):
    temporary = path.with_name(path.name + ".pending")
    temporary.write_text(canonical(value))
    temporary.replace(path)


def read(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("regular_owned_record_required")
    return json.loads(path.read_bytes())


def identity():
    if os.environ.get("GITHUB_REPOSITORY") != "fan-2077/wzf" or os.environ.get("GITHUB_REF") != REF:
        raise ValueError("dedicated_contract_branch_required")
    run, attempt, commit = (os.environ.get(name, "") for name in
                            ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA"))
    if not re.fullmatch(r"[0-9]+", run) or not re.fullmatch(r"[0-9]+", attempt) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("fixed_platform_identity_required")
    if attempt != "1":
        raise ValueError("one_initial_composition_run_only")
    owner = run + "-" + attempt
    return {"repository": "fan-2077/wzf", "ref": REF, "commit": commit,
            "run_id": run, "run_attempt": attempt, "owner": owner,
            "container_name": "b1-composition-" + owner,
            "image_tag": "sre-b1-composition:" + owner,
            "labels": {LABEL: owner, LABEL + ".commit": commit}}


def sources():
    result = {}
    directories = (ROOT / "b0-run", ROOT / "b1-common-session", ROOT / "b1-composition-gate",
                   REFERENCE / "g1-smoke", REFERENCE / "b1-readonly-gate")
    for directory in directories:
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("required_source_directory_missing")
        for path in sorted(directory.rglob("*")):
            if path.is_symlink():
                raise ValueError("source_symlink_forbidden")
            if path.is_file():
                raw = path.read_bytes()
                result[str(path.relative_to(ROOT))] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            elif not path.is_dir():
                raise ValueError("unexpected_source_node")
    return result


def file_hash(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def retain_generated_bindings():
    destination = OUTPUT / "generated-bindings"
    destination.mkdir(exist_ok=False)
    names = ("INSTALLATION_MANIFEST.json", "BUILD_CONTEXT_MANIFEST.json", "GENERATION_REPORT.json",
             "composition/SOURCE_INPUT_BINDING.json", "session/derived/DERIVED_PAYLOAD_BINDING.json",
             "session/derived/BASE_PACKAGE_MANIFEST.json", "bindings/B1_PACKAGE_MANIFEST.json",
             "bindings/B1_OVERLAY_MANIFEST.json", "Dockerfile")
    records = {}
    for relative in names:
        source = GENERATED / relative
        if source.is_symlink() or not source.is_file():
            raise RuntimeError("generated_binding_missing_or_nonregular:" + relative)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = source.read_bytes()
        target.write_bytes(raw)
        records[relative] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    save(OUTPUT / "GENERATED_BINDING_RECORDS.json", records)
    return records


def command(argv, name, timeout=30, *, check=True):
    records_path = OUTPUT / "commands.json"
    records = read(records_path) if records_path.exists() else []
    log = OUTPUT / ("%03d-%s.log" % (len(records) + 1, name))
    item = {"argv": list(argv), "log": log.name, "started_at_utc": datetime.now(timezone.utc).isoformat(),
            "started_monotonic": time.monotonic(), "timeout_seconds": timeout}
    error = None
    with log.open("xb") as stream:
        try:
            effective_timeout = timeout
            if COMMAND_DEADLINE is not None:
                remaining = COMMAND_DEADLINE - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("shared_setup_or_cleanup_deadline_exhausted")
                effective_timeout = min(timeout, remaining)
            item["effective_timeout_seconds"] = effective_timeout
            process = subprocess.run(argv, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
                                     timeout=effective_timeout, check=False)
            item["returncode"] = process.returncode
        except BaseException as exc:
            item["returncode"] = None
            item["exception"] = {"type": type(exc).__name__, "message": str(exc)}
            error = exc
    item["elapsed_seconds"] = time.monotonic() - item["started_monotonic"]
    item["log_sha256"] = hashlib.sha256(log.read_bytes()).hexdigest()
    records.append(item)
    save(records_path, records)
    if error is not None:
        raise error
    if check and item["returncode"] != 0:
        raise RuntimeError(name + "_failed")
    return item, log.read_bytes()


def inspect_owned(kind, target, own, name):
    item, raw = command(["docker", kind, "inspect", target], name, check=False)
    if item["returncode"] != 0:
        if b"No such" in raw:
            return None
        raise RuntimeError("owned_" + kind + "_inspection_failed")
    rows = json.loads(raw)
    if len(rows) != 1 or any(rows[0].get("Config", {}).get("Labels", {}).get(k) != v for k, v in own["labels"].items()):
        raise RuntimeError("owned_" + kind + "_labels_differ")
    return rows[0]


def cleanup():
    own = identity()
    if not (OUTPUT / "OWNERSHIP.json").exists():
        return {"passed": True, "scope": "no_owned_resource_creation_record"}
    if read(OUTPUT / "OWNERSHIP.json") != own:
        raise RuntimeError("ownership_record_does_not_match_current_run")
    resource_ids = read(OUTPUT / "RESOURCE_IDS.json") if (OUTPUT / "RESOURCE_IDS.json").exists() else {}
    if resource_ids and (resource_ids.get("owner") != own["owner"] or resource_ids.get("source_commit") != own["commit"]):
        raise RuntimeError("immutable_resource_record_identity_differs")
    findings = []
    container_target = resource_ids.get("container_id", own["container_name"])
    image_target = resource_ids.get("image_id", own["image_tag"])
    container = inspect_owned("container", container_target, own, "inspect-container-for-cleanup")
    if container is not None:
        command(["docker", "container", "rm", "--force", container["Id"]], "remove-owned-container", timeout=45)
    if inspect_owned("container", own["container_name"], own, "verify-container-absent") is not None:
        findings.append("owned_container_remains")
    image = inspect_owned("image", image_target, own, "inspect-image-for-cleanup")
    if image is not None:
        command(["docker", "image", "rm", "--force", image["Id"]], "remove-owned-image", timeout=45)
    if inspect_owned("image", own["image_tag"], own, "verify-image-absent") is not None:
        findings.append("owned_image_remains")
    result = {"passed": not findings, "findings": findings, "scope": "exact_owned_labels_and_names_only",
              "container_absent": "owned_container_remains" not in findings,
              "image_absent": "owned_image_remains" not in findings}
    save(OUTPUT / "CLEANUP.json", result)
    return result


def run():
    global COMMAND_DEADLINE
    own = identity()
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    OUTPUT.mkdir(mode=0o700, exist_ok=False)
    save(OUTPUT / "OWNERSHIP.json", own)
    host_uid, host_gid = os.geteuid(), os.getegid()
    output_info = OUTPUT.lstat()
    output_identity = {"host_uid": os.getuid(), "host_euid": host_uid,
                       "host_gid": os.getgid(), "host_egid": host_gid,
                       "output_uid": output_info.st_uid, "output_gid": output_info.st_gid,
                       "output_mode": stat.S_IMODE(output_info.st_mode),
                       "container_user": str(host_uid) + ":" + str(host_gid),
                       "policy": "unprivileged same owner; private 0700 output; no added capabilities"}
    save(OUTPUT / "OUTPUT_IDENTITY.json", output_identity)
    started = time.monotonic()
    COMMAND_DEADLINE = started + 33 * 60
    result = {"schema": "b1-composition-installation-run-v1", "scope": "combined fixed image installation checks only",
              "original_task_started": False, "model_inference_called": False, "controller_started": False,
              "aios_service_started": False, "business_recovery_qualification": None,
              "full_aios_integration_qualified": False, "new_comparison_budget_selected": False,
              "source_commit": own["commit"], "passed": False,
              "setup_deadline_seconds": 33 * 60}
    before = None
    context_verified_before = False
    try:
        if (host_uid <= 0 or host_gid <= 0 or os.getuid() != host_uid or os.getgid() != host_gid
                or not stat.S_ISDIR(output_info.st_mode) or output_info.st_uid != host_uid
                or output_info.st_gid != host_gid or stat.S_IMODE(output_info.st_mode) != 0o700):
            raise RuntimeError("private_output_must_match_unprivileged_host_identity")
        before = sources()
        save(OUTPUT / "SOURCE_BEFORE.json", before)
        _, reference_raw = command(["git", "-C", str(REFERENCE), "rev-parse", "HEAD"], "verify-pinned-B1-reference")
        if reference_raw.decode().strip() != REFERENCE_COMMIT:
            raise RuntimeError("B1_reference_commit_differs")
        _, reference_status = command(["git", "-C", str(REFERENCE), "status", "--porcelain", "--untracked-files=all"],
                                      "verify-clean-B1-reference")
        if reference_status.strip():
            raise RuntimeError("B1_reference_not_clean")
        save(OUTPUT / "REFERENCE_IDENTITY.json", {"commit": REFERENCE_COMMIT, "path": str(REFERENCE), "clean": True})
        command([sys.executable, "-B", str(ROOT / "b1-composition-gate/build_composition.py"),
                 "--b1-source-root", str(REFERENCE), "--output", str(GENERATED)], "generate-fixed-composition", timeout=120)
        command(["curl", "--fail", "--location", "--max-time", "600", "--output", str(GENERATED / "models" / MODEL_NAME),
                 MODEL_URL], "download-fixed-model-bytes-only", timeout=630)
        model = GENERATED / "models" / MODEL_NAME
        if model.is_symlink() or not model.is_file() or model.stat().st_size != MODEL_BYTES or file_hash(model) != MODEL_SHA256:
            raise RuntimeError("fixed_model_bytes_differ")
        save(OUTPUT / "MODEL_SOURCE.json", {"url": MODEL_URL, "bytes": MODEL_BYTES, "sha256": MODEL_SHA256,
                                           "inference_called": False, "scope": "artifact identity only"})
        command([sys.executable, "-B", str(ROOT / "b1-composition-gate/build_composition.py"),
                 "--verify-output", str(GENERATED)], "verify-complete-generated-context-before-build", timeout=120)
        context_verified_before = True
        result["generated_bindings"] = retain_generated_bindings()
        installation_sha = file_hash(GENERATED / "INSTALLATION_MANIFEST.json")
        result["installation_manifest_sha256"] = installation_sha
        command(["docker", "version"], "docker-version")
        command(["docker", "pull", "python:3.11.17-slim-trixie"], "resolve-official-Python-base", timeout=240)
        _, base_raw = command(["docker", "image", "inspect", "python:3.11.17-slim-trixie"], "inspect-official-Python-base")
        base_rows = json.loads(base_raw)
        if len(base_rows) != 1:
            raise RuntimeError("ambiguous_Python_base")
        base = next((v for v in base_rows[0].get("RepoDigests", [])
                     if re.fullmatch(r"(?:docker.io/library/)?python@sha256:[0-9a-f]{64}", v)), None)
        if base is None:
            raise RuntimeError("immutable_Python_base_digest_unavailable")
        save(OUTPUT / "PYTHON_BASE_IMAGE.json", base_rows[0])
        result["resolved_python_base_image"] = base
        label_args = [arg for k, v in own["labels"].items() for arg in ("--label", k + "=" + v)]
        command(["docker", "build", "--progress=plain", "--build-arg", "PYTHON_IMAGE=" + base,
                 *label_args, "-t", own["image_tag"], str(GENERATED)], "build-combined-fixed-image", timeout=1200)
        image = inspect_owned("image", own["image_tag"], own, "inspect-built-image")
        if image is None:
            raise RuntimeError("built_image_missing")
        save(OUTPUT / "IMAGE_INSPECTION.json", image)
        save(OUTPUT / "RESOURCE_IDS.json", {"image_id": image["Id"], "owner": own["owner"], "source_commit": own["commit"]})
        log_options = "rw,nosuid,nodev,mode=0700,size=134217728,uid=" + str(host_uid) + ",gid=" + str(host_gid)
        argv = ["docker", "create", "--name", own["container_name"], *label_args,
                "--user", output_identity["container_user"], "--network", "none", "--ipc", "private", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128",
                "--cpus", "4", "--memory", "8g", "--memory-swap", "8g",
                "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777,size=536870912", "--tmpfs", "/logs:" + log_options,
                "--mount", "type=bind,src=" + str(OUTPUT) + ",dst=/contract-results",
                "--workdir", "/logs", "--env", "PYTHONDONTWRITEBYTECODE=1",
                "--env", "B1_EXPECTED_UID=" + str(host_uid), "--env", "B1_EXPECTED_GID=" + str(host_gid),
                "--env", "B1_EXPECTED_INSTALLATION_MANIFEST_SHA256=" + installation_sha,
                "--entrypoint", "/opt/native/bin/python", image["Id"], "-B",
                "/opt/b1-composition/preflight.py", "--output", "/contract-results"]
        command(argv, "create-networkless-preflight-container")
        container = inspect_owned("container", own["container_name"], own, "inspect-before-preflight")
        if container is None:
            raise RuntimeError("preflight_container_missing")
        save(OUTPUT / "RESOURCE_IDS.json", {"image_id": image["Id"], "container_id": container["Id"],
                                           "owner": own["owner"], "source_commit": own["commit"]})
        host = container["HostConfig"]
        mounts = {x["Destination"]: x for x in container["Mounts"] if x["Type"] == "bind"}
        unexpected_mounts = [x for x in container["Mounts"] if x["Type"] != "bind"
                             and not (x["Type"] == "tmpfs" and x["Destination"] in {"/tmp", "/logs"})]
        if (container.get("Image") != image["Id"]
                or container.get("Config", {}).get("User") != output_identity["container_user"]
                or host.get("UsernsMode", "") != "" or host.get("NetworkMode") != "none"
                or host.get("Privileged") is not False or host.get("PidMode", "") != "" or host.get("IpcMode") != "private"
                or host.get("CapAdd") not in (None, []) or set(host.get("CapDrop") or []) != {"ALL"}
                or "no-new-privileges" not in (host.get("SecurityOpt") or []) or host.get("ReadonlyRootfs") is not True
                or unexpected_mounts or set(host.get("Tmpfs", {})) != {"/tmp", "/logs"}
                or host["Tmpfs"]["/logs"] != log_options
                or set(mounts) != {"/contract-results"} or mounts["/contract-results"]["Source"] != str(OUTPUT)
                or mounts["/contract-results"]["RW"] is not True
                or host.get("NanoCpus") != 4_000_000_000 or host.get("Memory") != 8_589_934_592
                or host.get("MemorySwap") != 8_589_934_592 or host.get("PidsLimit") != 128):
            raise RuntimeError("preflight_container_boundary_mismatch")
        save(OUTPUT / "CONTAINER_BEFORE.json", container)
        execution, _ = command(["docker", "start", "--attach", container["Id"]], "run-combined-installation-preflight", timeout=300, check=False)
        container = inspect_owned("container", container["Id"], own, "inspect-after-preflight")
        if container is None:
            raise RuntimeError("preflight_container_disappeared")
        save(OUTPUT / "CONTAINER_AFTER.json", container)
        if execution["returncode"] != 0 or container["State"].get("Running") or container["State"].get("ExitCode") != 0:
            raise RuntimeError("preflight_process_did_not_exit_zero")
        preflight = read(OUTPUT / "COMPOSITION_PREFLIGHT_RESULT.json")
        result["preflight_result"] = preflight
        if preflight.get("passed") is not True:
            raise RuntimeError("composition_preflight_did_not_pass")
        result["installation_preflight_passed"] = True
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        try:
            after = sources()
            save(OUTPUT / "SOURCE_AFTER.json", after)
            result["source_inputs_unchanged"] = before is not None and before == after
        except BaseException as error:
            result["source_inputs_unchanged"] = False
            result["source_check_error"] = {"type": type(error).__name__, "message": str(error)}
        try:
            if context_verified_before:
                command([sys.executable, "-B", str(ROOT / "b1-composition-gate/build_composition.py"),
                         "--verify-output", str(GENERATED)], "verify-complete-generated-context-after-run", timeout=120)
                result["generated_context_verified_after"] = True
            else:
                result["generated_context_verified_after"] = False
        except BaseException as error:
            result["generated_context_verified_after"] = False
            result["generated_context_check_error"] = {"type": type(error).__name__, "message": str(error)}
        COMMAND_DEADLINE = time.monotonic() + 90
        try:
            result["cleanup"] = cleanup()
        except BaseException as error:
            result["cleanup"] = {"passed": False, "error": {"type": type(error).__name__, "message": str(error)}}
        result["elapsed_seconds_including_cleanup"] = time.monotonic() - started
        result["passed"] = bool(result.get("installation_preflight_passed") and result.get("source_inputs_unchanged")
                                and result.get("generated_context_verified_after")
                                and result.get("cleanup", {}).get("passed") and not result.get("error"))
        save(OUTPUT / "RUN_RESULT.json", result)
    print(canonical({"passed": result["passed"], "error": result.get("error"), "scope": result["scope"]}), end="")
    return 0 if result["passed"] else 1


def seal():
    own = identity()
    OUTPUT.mkdir(mode=0o700, exist_ok=True)
    status = {"scope": "combined image installation evidence only; never a business result", "export_passed": False,
              "composition_installation_qualified": False,
              "run_id": own["run_id"], "run_attempt": own["run_attempt"]}
    try:
        run_result = read(OUTPUT / "RUN_RESULT.json") if (OUTPUT / "RUN_RESULT.json").exists() else None
        cleanup_result = read(OUTPUT / "WORKFLOW_CLEANUP.json") if (OUTPUT / "WORKFLOW_CLEANUP.json").exists() else None
        verdict = {"schema": "b1-composition-final-verdict-v1",
                   "scope": "combined image installation only; no AIOS service, model inference or business recovery qualification",
                   "run_preflight_passed": run_result.get("passed") if run_result else None,
                   "workflow_cleanup_passed": cleanup_result.get("passed") if cleanup_result else None,
                   "original_business_result": None, "full_strong_B1_qualified": False,
                   "composition_installation_qualified": bool(run_result and run_result.get("passed") is True
                                              and cleanup_result and cleanup_result.get("passed") is True)}
        save(OUTPUT / "FINAL_VERDICT.json", verdict)
        entries = {}
        excluded = {"EVIDENCE_MANIFEST.json", "EVIDENCE.tar.gz", "EXPORT_STATUS.json"}
        for path in sorted(OUTPUT.rglob("*")):
            relative = str(path.relative_to(OUTPUT))
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise RuntimeError("nonregular_evidence_node:" + relative)
            if relative in excluded:
                continue
            raw = path.read_bytes()
            entries[relative] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        save(OUTPUT / "EVIDENCE_MANIFEST.json", {"schema": "b1-composition-evidence-v1", "files": entries,
                                               "source_commit": own["commit"]})
        with tarfile.open(OUTPUT / "EVIDENCE.tar.gz", "w:gz") as archive:
            for name in [*sorted(entries), "EVIDENCE_MANIFEST.json"]:
                archive.add(OUTPUT / name, arcname=name, recursive=False)
        with tarfile.open(OUTPUT / "EVIDENCE.tar.gz", "r:gz") as archive:
            members = archive.getmembers()
            if len(members) != len(entries) + 1 or {m.name for m in members} != set(entries) | {"EVIDENCE_MANIFEST.json"}:
                raise RuntimeError("sealed_member_set_changed")
            for member in members:
                if not member.isfile():
                    raise RuntimeError("sealed_member_not_regular")
                raw = archive.extractfile(member).read()
                if member.name == "EVIDENCE_MANIFEST.json":
                    if raw != (OUTPUT / member.name).read_bytes():
                        raise RuntimeError("sealed_manifest_changed")
                elif {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} != entries[member.name]:
                    raise RuntimeError("sealed_member_digest_changed")
        status.update(export_passed=True, composition_installation_qualified=verdict["composition_installation_qualified"], members=len(entries) + 1,
                      sha256=hashlib.sha256((OUTPUT / "EVIDENCE.tar.gz").read_bytes()).hexdigest())
    except BaseException as error:
        status["error"] = {"type": type(error).__name__, "message": str(error)}
    save(OUTPUT / "EXPORT_STATUS.json", status)
    print(canonical(status), end="")
    return 0 if status["export_passed"] and status["composition_installation_qualified"] else 1


def main():
    global COMMAND_DEADLINE
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("run", "cleanup", "seal"), nargs="?", default="run")
    operation = parser.parse_args().operation
    if operation == "run":
        return run()
    if operation == "seal":
        return seal()
    if not OUTPUT.exists():
        return 0
    COMMAND_DEADLINE = time.monotonic() + 90
    result = cleanup()
    save(OUTPUT / "WORKFLOW_CLEANUP.json", result)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
