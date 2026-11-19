"""Owned, networkless contract validation; never starts an SREGym incident."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import time

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "b1-session-contract-results"
REF = "refs/heads/sre-b1-session-contract-20261119"
LABEL = "sre.b1.session.contract"


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
    owner = run + "-" + attempt
    return {"repository": "fan-2077/wzf", "ref": REF, "commit": commit,
            "run_id": run, "run_attempt": attempt, "owner": owner,
            "container_name": "b1-session-contract-" + owner,
            "image_tag": "sre-b1-session-contract:" + owner,
            "labels": {LABEL: owner, LABEL + ".commit": commit}}


def sources():
    result = {}
    for directory in (ROOT / "b0-run", ROOT / "b1-common-session"):
        for path in sorted(directory.rglob("*")):
            if path.is_symlink():
                raise ValueError("source_symlink_forbidden")
            if path.is_file():
                raw = path.read_bytes()
                result[str(path.relative_to(ROOT))] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            elif not path.is_dir():
                raise ValueError("unexpected_source_node")
    fixed = read(ROOT / "b1-common-session/BASE_BINDING.json")
    for item in fixed["b0_sources"]:
        if result.get(item["path"]) != {"bytes": item["bytes"], "sha256": item["sha256"]}:
            raise ValueError("fixed_B0_source_binding_changed")
    return result


def command(argv, name, timeout=30, *, check=True):
    records_path = OUTPUT / "commands.json"
    records = read(records_path) if records_path.exists() else []
    log = OUTPUT / ("%03d-%s.log" % (len(records) + 1, name))
    item = {"argv": list(argv), "log": log.name, "started_at_utc": datetime.now(timezone.utc).isoformat(),
            "started_monotonic": time.monotonic(), "timeout_seconds": timeout}
    error = None
    with log.open("xb") as stream:
        try:
            process = subprocess.run(argv, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
                                     timeout=timeout, check=False)
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
    own = identity()
    OUTPUT.mkdir(mode=0o700, exist_ok=False)
    save(OUTPUT / "OWNERSHIP.json", own)
    started = time.monotonic()
    result = {"schema": "b1-session-networkless-contract-run-v1", "scope": "fixed Linux runtime and controlled IPC contracts only",
              "original_task_started": False, "model_called": False, "business_recovery_qualification": None,
              "full_aios_integration_qualified": False, "source_commit": own["commit"], "passed": False}
    before = None
    try:
        before = sources()
        save(OUTPUT / "SOURCE_BEFORE.json", before)
        command(["docker", "version"], "docker-version")
        label_args = [arg for k, v in own["labels"].items() for arg in ("--label", k + "=" + v)]
        command(["docker", "build", "--progress=plain", *label_args, "-t", own["image_tag"],
                 "-f", "b0-run/Dockerfile", "b0-run"], "build-fixed-B0-runtime", timeout=900)
        image = inspect_owned("image", own["image_tag"], own, "inspect-built-image")
        if image is None:
            raise RuntimeError("built_image_missing")
        save(OUTPUT / "IMAGE_INSPECTION.json", image)
        save(OUTPUT / "RESOURCE_IDS.json", {"image_id": image["Id"], "owner": own["owner"],
                                           "source_commit": own["commit"]})
        argv = ["docker", "create", "--name", own["container_name"], *label_args,
                "--network", "none", "--ipc", "private", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--pids-limit", "128",
                "--cpus", "4", "--memory", "8g", "--memory-swap", "8g",
                "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777,size=536870912",
                "--tmpfs", "/logs:rw,nosuid,nodev,mode=0700,size=33554432",
                "--mount", "type=bind,src=" + str(ROOT / "b0-run") + ",dst=/contract-src/b0-run,readonly",
                "--mount", "type=bind,src=" + str(ROOT / "b1-common-session") + ",dst=/contract-src/b1-common-session,readonly",
                "--mount", "type=bind,src=" + str(OUTPUT) + ",dst=/contract-results",
                "--workdir", "/contract-src", "--env", "B1_REQUIRE_REAL_IPC=1",
                "--env", "PYTHONDONTWRITEBYTECODE=1", "--entrypoint", "/opt/native/bin/python",
                image["Id"], "-B", "/contract-src/b1-common-session/run_contract_tests.py",
                "--output", "/contract-results"]
        command(argv, "create-networkless-contract-container")
        container = inspect_owned("container", own["container_name"], own, "inspect-before-tests")
        if container is None:
            raise RuntimeError("contract_container_missing")
        host = container["HostConfig"]
        save(OUTPUT / "RESOURCE_IDS.json", {"image_id": image["Id"], "container_id": container["Id"],
                                           "owner": own["owner"], "source_commit": own["commit"]})
        mounts = {row["Destination"]: row for row in container["Mounts"] if row["Type"] == "bind"}
        unexpected_mounts = [row for row in container["Mounts"] if row["Type"] != "bind"
                             and not (row["Type"] == "tmpfs" and row["Destination"] in {"/tmp", "/logs"})]
        expected_sources = {"/contract-src/b0-run": str(ROOT / "b0-run"),
                            "/contract-src/b1-common-session": str(ROOT / "b1-common-session"),
                            "/contract-results": str(OUTPUT)}
        if (container.get("Image") != image["Id"]
                or host["NetworkMode"] != "none" or host.get("Privileged") is not False
                or host.get("PidMode", "") != "" or host.get("IpcMode") != "private"
                or host.get("CapAdd") not in (None, []) or set(host.get("CapDrop") or []) != {"ALL"}
                or "no-new-privileges" not in (host.get("SecurityOpt") or [])
                or host.get("ReadonlyRootfs") is not True
                or unexpected_mounts or set(host.get("Tmpfs", {})) != {"/tmp", "/logs"}
                or set(mounts) != {"/contract-src/b0-run", "/contract-src/b1-common-session", "/contract-results"}
                or any(mounts[destination]["Source"] != source for destination, source in expected_sources.items())
                or mounts["/contract-src/b0-run"]["RW"] or mounts["/contract-src/b1-common-session"]["RW"]
                or not mounts["/contract-results"]["RW"]
                or host.get("NanoCpus") != 4_000_000_000 or host.get("Memory") != 8_589_934_592):
            raise RuntimeError("contract_container_boundary_mismatch")
        save(OUTPUT / "CONTAINER_BEFORE.json", container)
        command(["docker", "start", "--attach", own["container_name"]], "run-real-runtime-contracts", timeout=240)
        container = inspect_owned("container", own["container_name"], own, "inspect-after-tests")
        if container is None or container["State"].get("Running") or container["State"].get("ExitCode") != 0:
            raise RuntimeError("contract_container_did_not_exit_zero")
        save(OUTPUT / "CONTAINER_AFTER.json", container)
        contract = read(OUTPUT / "CONTRACT_TEST_RESULT.json")
        result["test_result"] = contract
        if contract.get("passed") is not True:
            raise RuntimeError("actual_contract_test_gate_failed")
        result["contract_tests_passed"] = True
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
            result["cleanup"] = cleanup()
        except BaseException as error:
            result["cleanup"] = {"passed": False, "error": {"type": type(error).__name__, "message": str(error)}}
        result["elapsed_seconds_including_cleanup"] = time.monotonic() - started
        result["passed"] = bool(result.get("contract_tests_passed") and result.get("source_inputs_unchanged")
                                and result.get("cleanup", {}).get("passed") and not result.get("error"))
        save(OUTPUT / "RUN_RESULT.json", result)
    print(canonical({"passed": result["passed"], "error": result.get("error"), "scope": result["scope"]}), end="")
    return 0 if result["passed"] else 1


def seal():
    own = identity()
    OUTPUT.mkdir(mode=0o700, exist_ok=True)
    status = {"scope": "contract evidence only; never a business result", "export_passed": False,
              "contract_qualified": False,
              "run_id": own["run_id"], "run_attempt": own["run_attempt"]}
    try:
        run_result = read(OUTPUT / "RUN_RESULT.json") if (OUTPUT / "RUN_RESULT.json").exists() else None
        cleanup_result = read(OUTPUT / "WORKFLOW_CLEANUP.json") if (OUTPUT / "WORKFLOW_CLEANUP.json").exists() else None
        verdict = {"schema": "b1-session-contract-final-verdict-v1",
                   "scope": "fixed runtime and controlled IPC only; no AIOS or business recovery qualification",
                   "run_contract_passed": run_result.get("passed") if run_result else None,
                   "workflow_cleanup_passed": cleanup_result.get("passed") if cleanup_result else None,
                   "original_business_result": None, "full_strong_B1_qualified": False,
                   "contract_qualified": bool(run_result and run_result.get("passed") is True
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
        save(OUTPUT / "EVIDENCE_MANIFEST.json", {"schema": "b1-session-contract-evidence-v1", "files": entries,
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
        status.update(export_passed=True, contract_qualified=verdict["contract_qualified"], members=len(entries) + 1,
                      sha256=hashlib.sha256((OUTPUT / "EVIDENCE.tar.gz").read_bytes()).hexdigest())
    except BaseException as error:
        status["error"] = {"type": type(error).__name__, "message": str(error)}
    save(OUTPUT / "EXPORT_STATUS.json", status)
    print(canonical(status), end="")
    return 0 if status["export_passed"] and status["contract_qualified"] else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("run", "cleanup", "seal"), nargs="?", default="run")
    operation = parser.parse_args().operation
    if operation == "run":
        return run()
    if operation == "seal":
        return seal()
    if not OUTPUT.exists():
        return 0
    result = cleanup()
    save(OUTPUT / "WORKFLOW_CLEANUP.json", result)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
