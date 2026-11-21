"""Bounded, exactly owned Docker gate; no incident, model, actor, or AIOS."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tarfile
import time

from gate_common import (PYTHON_IMAGE, REF, REPOSITORY, WORKFLOW, info, platform_identity,
                         read_bytes, read_json, require, save_json, sha, verify_tree)


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "b1-evidence-pages-gate"
COMPONENT = ROOT / "b1-evidence-pages"
OUTPUT = ROOT / "b1-evidence-pages-results"
LABEL = "sre.b1.evidence-pages"
DEADLINE = 0.0


def command(argv, name, *, timeout=20, check=True):
    remaining = DEADLINE - time.monotonic()
    require(remaining > 0, "host_phase_deadline_exhausted")
    timeout = min(float(timeout), remaining)
    records_path = OUTPUT / "commands.json"
    records = read_json(records_path) if records_path.exists() else []
    prefix = "%03d-%s" % (len(records) + 1, name)
    stdout_path, stderr_path = OUTPUT / (prefix + ".stdout.raw"), OUTPUT / (prefix + ".stderr.raw")
    record = {"argv": list(argv), "cwd": str(ROOT), "state": "started", "stdin": "DEVNULL",
        "started_at_utc": datetime.now(timezone.utc).isoformat(), "timeout_seconds": timeout,
        "stdout_path": stdout_path.name, "stderr_path": stderr_path.name}
    records.append(record)
    save_json(records_path, records, replace=records_path.exists())
    started, failure = time.monotonic(), None
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        try:
            process = subprocess.run(argv, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                     timeout=timeout, check=False)
            record["returncode"] = process.returncode
        except BaseException as error:
            record["returncode"] = None
            record["error"] = {"type": type(error).__name__, "message": str(error)}
            failure = error
    record.update(state="finished", elapsed_seconds=time.monotonic() - started,
                  stdout=info(read_bytes(stdout_path)), stderr=info(read_bytes(stderr_path)))
    save_json(records_path, records, replace=True)
    if failure is not None:
        raise failure
    if check:
        require(record["returncode"] == 0, name + "_failed")
    return record, read_bytes(stdout_path), read_bytes(stderr_path)


def ownership():
    expected = platform_identity(os.environ)
    own = read_json(OUTPUT / "OWNERSHIP.json")
    require(all(own.get(key) == value for key, value in expected.items()), "ownership_platform_identity_changed")
    require(type(own.get("nonce")) is str and re.fullmatch(r"[0-9a-f]{32}", own["nonce"]), "ownership_nonce_invalid")
    labels = {LABEL: expected["run_id"] + "-1", LABEL + ".commit": expected["commit"], LABEL + ".nonce": own["nonce"]}
    require(own.get("labels") == labels, "ownership_labels_changed")
    return own


def inspect_container(target, name):
    record, raw, error = command(["docker", "container", "inspect", target], name, check=False)
    if record["returncode"] != 0:
        require(b"No such container" in error or b"No such object" in error, "container_inspection_failed")
        return None
    rows = json.loads(raw)
    require(type(rows) is list and len(rows) == 1, "single_container_inspection_required")
    return rows[0]


def require_owned(container, own):
    require(container["Name"] == "/" + own["container_name"]
            and all(container.get("Config", {}).get("Labels", {}).get(key) == value for key, value in own["labels"].items()),
            "container_not_owned_by_exact_attempt")
    require(re.fullmatch(r"[0-9a-f]{64}", container.get("Id", "")), "full_container_id_required")


def source_snapshot(own):
    binding = read_json(GATE / "SOURCE_INPUT_BINDING.json")
    require(binding["repository"] == REPOSITORY and binding["ref"] == REF
            and binding["python_image"]["tag"] == PYTHON_IMAGE, "gate_input_profile_changed")
    component = verify_tree(COMPONENT, binding["component"]["manifest"]["sha256"], component=True)
    require(len(component) == binding["component"]["total_files"] == 33, "component_file_count_changed")
    gate = verify_tree(GATE)
    files = {"b1-evidence-pages/" + key: value for key, value in component.items()}
    files.update({"b1-evidence-pages-gate/" + key: value for key, value in gate.items()})
    files[WORKFLOW] = info(read_bytes(ROOT / WORKFLOW))
    _, head, _ = command(["git", "rev-parse", "HEAD"], "source-head")
    require(head.decode().strip() == own["commit"], "actual_checkout_commit_mismatch")
    _, raw, _ = command(["git", "ls-tree", "-r", "-z", "HEAD", "--", "b1-evidence-pages", "b1-evidence-pages-gate", WORKFLOW], "source-git-tree")
    git_entries = {}
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        require(kind == "blob" and mode in {"100644", "100755"}, "regular_source_git_blob_required")
        git_entries[name.decode()] = oid
    require(set(files) == set(git_entries), "complete_source_git_member_set_mismatch")
    for relative in files:
        raw = read_bytes(ROOT / relative)
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        require(blob == git_entries[relative], "checkout_bytes_differ_from_git_blob:" + relative)
        files[relative] = dict(files[relative], git_blob_oid=blob)
    return {"commit": own["commit"], "files": files,
            "component_manifest_sha256": component["SOURCE_MANIFEST.json"]["sha256"],
            "gate_manifest_sha256": gate["SOURCE_MANIFEST.json"]["sha256"]}


def cleanup():
    own = ownership()
    if not (OUTPUT / "CREATION_RESERVED.json").exists():
        return {"passed": True, "scope": "no_container_creation_reserved_no_resource_removed"}
    reserved = read_json(OUTPUT / "CREATION_RESERVED.json")
    require(reserved == {"container_name": own["container_name"], "nonce": own["nonce"]}, "creation_reservation_changed")
    container = inspect_container(own["container_name"], "owned-cleanup-inspect")
    removed = None
    if container is not None:
        require_owned(container, own)
        removed = container["Id"]
        command(["docker", "container", "rm", "--force", removed], "owned-container-remove", timeout=25)
    require(inspect_container(own["container_name"], "owned-cleanup-confirm-absent") is None, "owned_container_remains")
    return {"passed": True, "container_absent": True, "removed_container_id": removed,
        "scope": "exact_attempt_nonce_labels_and_container_name_only", "global_prune": False,
        "base_image_removed": False, "base_image_reason": "Official pulled base is not an exclusively owned build artifact."}


def verify_isolation(container, own, image_id, uid, gid):
    require_owned(container, own)
    config, host = container["Config"], container["HostConfig"]
    require(container["Image"] == image_id and config["User"] == "%d:%d" % (uid, gid), "container_image_or_uid_changed")
    require(host["ReadonlyRootfs"] is True and host["NetworkMode"] == "none" and "ALL" in host.get("CapDrop", [])
            and any(item in {"no-new-privileges", "no-new-privileges=true"} for item in host.get("SecurityOpt", [])),
            "container_isolation_flags_changed")
    require(host["Memory"] == host["MemorySwap"] == 256 * 1024 * 1024 and host["NanoCpus"] == 1000000000
            and host["PidsLimit"] == 128 and host["CgroupnsMode"] == "private"
            and set(host["Tmpfs"]) == {"/tmp"}, "bounded_container_resources_changed")
    expected = {"/contract-src/b1-evidence-pages": (str(COMPONENT), False),
        "/contract-src/b1-evidence-pages-gate": (str(GATE), False), "/results": (str(OUTPUT / "inner"), True)}
    actual = {}
    for mount in container["Mounts"]:
        if mount["Type"] == "bind":
            actual[mount["Destination"]] = (mount["Source"], mount["RW"])
        else:
            require(mount["Type"] == "tmpfs" and mount["Destination"] == "/tmp", "unexpected_container_mount")
    require(actual == expected, "fixed_mount_set_changed")


def run():
    global DEADLINE
    own = platform_identity(os.environ)
    os.umask(0o077)
    OUTPUT.mkdir(mode=0o700, exist_ok=False)
    own["nonce"] = secrets.token_hex(16)
    own["labels"] = {LABEL: own["run_id"] + "-1", LABEL + ".commit": own["commit"], LABEL + ".nonce": own["nonce"]}
    save_json(OUTPUT / "OWNERSHIP.json", own)
    started = time.monotonic()
    DEADLINE = started + 300
    result = {"schema": "b1-evidence-pages-host-run-v1", "passed": False,
        "scope": "fixed_interpreter_contracts_only_no_model_aios_actor_controller_or_incident",
        "model_calls": 0, "native_business_calls": 0, "original_task_runs": 0, "business_result": None,
        "main_phase_limit_seconds": 300, "total_host_limit_seconds_including_cleanup": 360}
    before = container = None
    try:
        uid, gid = os.geteuid(), os.getegid()
        require(uid != 0 and os.getuid() == uid and os.getgid() == gid, "actual_unprivileged_host_identity_required")
        status = OUTPUT.lstat()
        require(stat.S_IMODE(status.st_mode) == 0o700 and status.st_uid == uid and status.st_gid == gid, "host_private_output_identity")
        require("," not in str(ROOT) and "\n" not in str(ROOT), "unsupported_mount_path")
        (OUTPUT / "inner").mkdir(mode=0o700)
        save_json(OUTPUT / "HOST_IDENTITY.json", {"uid": uid, "gid": gid, "output_mode": "0700",
            "output_path": str(OUTPUT), "docker_boundary": "Host Docker CLI only; no daemon socket or credentials mounted into test container."})
        before = source_snapshot(own)
        save_json(OUTPUT / "SOURCE_BEFORE.json", before)
        for relative, entry in before["files"].items():
            destination = OUTPUT / "source" / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            raw = read_bytes(ROOT / relative)
            require(info(raw) == {key: entry[key] for key in ("bytes", "sha256")}, "source_changed_during_archive_copy")
            destination.write_bytes(raw)
        command(["docker", "version", "--format", "{{json .}}"], "actual-docker-version")
        occupied = inspect_container(own["container_name"], "initial-exact-name-check")
        save_json(OUTPUT / "NAME_CHECK.json", {"name": own["container_name"], "unoccupied": occupied is None,
            "existing_container_id": occupied.get("Id") if occupied else None})
        require(occupied is None, "candidate_container_name_already_occupied")
        command(["docker", "pull", PYTHON_IMAGE], "pull-official-python-tag", timeout=120)
        _, raw, _ = command(["docker", "image", "inspect", PYTHON_IMAGE], "inspect-pulled-python")
        rows = json.loads(raw)
        require(len(rows) == 1, "single_official_python_image_required")
        image = rows[0]
        digests = sorted(set(value for value in image.get("RepoDigests", [])
            if re.fullmatch(r"(?:docker\.io/library/)?python@sha256:[0-9a-f]{64}", value)))
        require(len({value.split("@", 1)[1] for value in digests}) == 1 and image["Os"] == "linux",
                "actual_official_python_repo_digest_required")
        digest_reference = digests[0]
        _, raw, _ = command(["docker", "image", "inspect", digest_reference], "verify-resolved-python-digest")
        require(json.loads(raw)[0]["Id"] == image["Id"], "resolved_image_id_differs")
        save_json(OUTPUT / "IMAGE_BINDING.json", {"requested_tag": PYTHON_IMAGE, "actual_repo_digest": digest_reference,
            "actual_image_id": image["Id"], "os": image["Os"], "architecture": image["Architecture"],
            "actual_repo_digests": image["RepoDigests"], "docker_build_performed": False})
        create = ["docker", "create", "--name", own["container_name"], "--network", "none", "--read-only",
            "--user", "%d:%d" % (uid, gid), "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--cpus", "1", "--memory", "256m", "--memory-swap", "256m", "--pids-limit", "128", "--cgroupns", "private",
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777"]
        for key, value in own["labels"].items():
            create += ["--label", key + "=" + value]
        for source, destination, readonly in ((COMPONENT, "/contract-src/b1-evidence-pages", True),
                (GATE, "/contract-src/b1-evidence-pages-gate", True), (OUTPUT / "inner", "/results", False)):
            create += ["--mount", "type=bind,source=" + str(source) + ",target=" + destination + (",readonly" if readonly else "")]
        for key, value in {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1", "B1_EXPECTED_UID": str(uid),
                "B1_EXPECTED_GID": str(gid), "B1_COMPONENT_MANIFEST_SHA256": before["component_manifest_sha256"],
                "B1_GATE_MANIFEST_SHA256": before["gate_manifest_sha256"]}.items():
            create += ["--env", key + "=" + value]
        create += [digest_reference, "python", "-B", "/contract-src/b1-evidence-pages-gate/run_contract_tests.py", "--output", "/results"]
        save_json(OUTPUT / "CREATION_RESERVED.json", {"container_name": own["container_name"], "nonce": own["nonce"]})
        _, raw, _ = command(create, "create-isolated-contract-container")
        container_id = raw.decode().strip()
        require(re.fullmatch(r"[0-9a-f]{64}", container_id), "full_created_container_id_required")
        save_json(OUTPUT / "RESOURCE_IDS.json", {"container_id": container_id, "image_id": image["Id"], "name": own["container_name"]})
        container = inspect_container(container_id, "inspect-container-before")
        require(container is not None, "created_container_missing")
        verify_isolation(container, own, image["Id"], uid, gid)
        save_json(OUTPUT / "CONTAINER_BEFORE.json", container)
        started_record, _, _ = command(["docker", "start", "--attach", container_id], "run-original-19-tests", timeout=90, check=False)
        container = inspect_container(container_id, "inspect-container-after")
        require(container is not None, "completed_container_missing")
        verify_isolation(container, own, image["Id"], uid, gid)
        save_json(OUTPUT / "CONTAINER_AFTER.json", container)
        inner = read_json(OUTPUT / "inner/CONTRACT_TEST_RESULT.json")
        result["inner_contract_passed"] = inner.get("passed") is True
        result["container_terminal"] = not container["State"]["Running"]
        result["container_exit_code"] = container["State"]["ExitCode"]
        result["container_oom_killed"] = container["State"]["OOMKilled"]
        require(started_record["returncode"] == 0 and result["container_terminal"] and result["container_exit_code"] == 0
                and not result["container_oom_killed"] and result["inner_contract_passed"], "actual_fixed_runtime_contract_gate_failed")
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        DEADLINE = min(started + 360, time.monotonic() + 60)
        if (OUTPUT / "CREATION_RESERVED.json").exists():
            try:
                observed = inspect_container(own["container_name"], "final-owned-resource-inspect")
                if observed is not None:
                    require_owned(observed, own)
                    save_json(OUTPUT / "CONTAINER_FINAL_OBSERVATION.json", observed)
                    command(["docker", "logs", observed["Id"]], "complete-container-logs", timeout=10, check=False)
                    command(["docker", "stats", "--no-stream", "--format", "{{json .}}", observed["Id"]],
                            "final-container-stats", timeout=10, check=False)
            except BaseException as error:
                result["final_resource_observation_error"] = {"type": type(error).__name__, "message": str(error)}
        try:
            after = source_snapshot(own)
            save_json(OUTPUT / "SOURCE_AFTER.json", after)
            result["source_inputs_unchanged"] = before is not None and after == before
        except BaseException as error:
            result["source_inputs_unchanged"] = False
            result["source_check_error"] = {"type": type(error).__name__, "message": str(error)}
        try:
            cleaned = cleanup()
        except BaseException as error:
            cleaned = {"passed": False, "error": {"type": type(error).__name__, "message": str(error)}}
        save_json(OUTPUT / "CLEANUP.json", cleaned)
        result["cleanup_passed"] = cleaned["passed"] is True
        result["elapsed_seconds_including_cleanup"] = time.monotonic() - started
        result["passed"] = bool(result.get("inner_contract_passed") and result.get("container_terminal")
            and result.get("container_exit_code") == 0 and not result.get("container_oom_killed")
            and result.get("source_inputs_unchanged") and result.get("cleanup_passed") and not result.get("error"))
        save_json(OUTPUT / "RUN_RESULT.json", result)
    print(json.dumps({"passed": result["passed"], "error": result.get("error"), "scope": result["scope"]}), flush=True)
    return 0 if result["passed"] else 1


def seal():
    own = ownership()
    status = {"schema": "b1-evidence-pages-export-v1", "export_passed": False, "fixed_runtime_contract_qualified": False,
        "run_id": own["run_id"], "run_attempt": own["run_attempt"], "original_business_result": None}
    try:
        run_result = read_json(OUTPUT / "RUN_RESULT.json") if (OUTPUT / "RUN_RESULT.json").exists() else None
        cleanup_result = read_json(OUTPUT / "WORKFLOW_CLEANUP.json") if (OUTPUT / "WORKFLOW_CLEANUP.json").exists() else None
        verdict = {"schema": "b1-evidence-pages-final-verdict-v1", "scope": "fixed_python_3_11_17_and_19_pagination_contracts_only",
            "fixed_runtime_contract_qualified": bool(run_result and run_result.get("passed") is True
                and cleanup_result and cleanup_result.get("passed") is True), "actor_qualified": False,
            "aios_qualified": False, "model_delivery_qualified": False, "solver_security_boundary_qualified": False,
            "business_result": None, "full_strong_B1_qualified": False}
        save_json(OUTPUT / "FINAL_VERDICT.json", verdict)
        entries = {}
        excluded = {"EVIDENCE_MANIFEST.json", "EVIDENCE.tar.gz", "EXPORT_STATUS.json"}
        for path in sorted(OUTPUT.rglob("*")):
            require(time.monotonic() < DEADLINE, "evidence_seal_deadline_exhausted")
            relative = path.relative_to(OUTPUT).as_posix()
            state = path.lstat()
            if stat.S_ISDIR(state.st_mode):
                continue
            if relative not in excluded:
                entries[relative] = info(read_bytes(path))
        save_json(OUTPUT / "EVIDENCE_MANIFEST.json", {"schema": "b1-evidence-pages-gate-evidence-v1",
            "source_commit": own["commit"], "files": entries})
        with tarfile.open(OUTPUT / "EVIDENCE.tar.gz", "w:gz") as archive:
            for relative in [*sorted(entries), "EVIDENCE_MANIFEST.json"]:
                archive.add(OUTPUT / relative, arcname=relative, recursive=False)
        with tarfile.open(OUTPUT / "EVIDENCE.tar.gz", "r:gz") as archive:
            members = archive.getmembers()
            require(len(members) == len(entries) + 1 and {member.name for member in members} == set(entries) | {"EVIDENCE_MANIFEST.json"},
                    "sealed_archive_member_set_mismatch")
            for member in members:
                require(time.monotonic() < DEADLINE, "evidence_seal_deadline_exhausted")
                require(member.isfile(), "sealed_archive_nonregular_member")
                raw = archive.extractfile(member).read()
                expected = info(read_bytes(OUTPUT / member.name)) if member.name == "EVIDENCE_MANIFEST.json" else entries[member.name]
                require(info(raw) == expected, "sealed_archive_member_digest_mismatch")
        status.update(export_passed=True, fixed_runtime_contract_qualified=verdict["fixed_runtime_contract_qualified"],
            archive=info(read_bytes(OUTPUT / "EVIDENCE.tar.gz")), members=len(entries) + 1)
    except BaseException as error:
        status["error"] = {"type": type(error).__name__, "message": str(error)}
    save_json(OUTPUT / "EXPORT_STATUS.json", status)
    print(json.dumps(status), flush=True)
    return 0 if status["export_passed"] and status["fixed_runtime_contract_qualified"] else 1


def main():
    global DEADLINE
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("run", "cleanup", "seal"))
    operation = parser.parse_args().operation
    platform_identity(os.environ)
    if operation == "run":
        return run()
    DEADLINE = time.monotonic() + (60 if operation == "cleanup" else 30)
    if operation == "seal":
        return seal()
    if not OUTPUT.exists():
        return 1
    try:
        result = cleanup()
    except BaseException as error:
        result = {"passed": False, "error": {"type": type(error).__name__, "message": str(error)}}
    save_json(OUTPUT / "WORKFLOW_CLEANUP.json", result)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
