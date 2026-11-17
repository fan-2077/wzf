"""Two isolated Docker capability-spelling probes; no model or native business."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time


IMAGE = "python@sha256:b7a9e5f6a93d6d4a31f129bbd4bdee69efccb6ded0fb230d78aafaf37af98377"
OWNER_LABEL = "org.sre.g1.capability-diagnostic-owner"
SPELLINGS = ("DAC_OVERRIDE", "CAP_DAC_OVERRIDE")
WORKLOAD = """import json,os,pathlib,time
keep={'CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs'}
status={}
for line in pathlib.Path('/proc/self/status').read_text().splitlines():
    key,sep,value=line.partition(':')
    if key in keep: status[key]=value.strip()
print(json.dumps({'probe':'capability-representation-only','uid':os.getuid(),'status':status}),flush=True)
time.sleep(5)
"""


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def normalize_capadd(raw):
    """Recognize at most one explicit CAP_ prefix; never strip unknown values."""
    if not isinstance(raw, list) or not raw or any(not isinstance(x, str) for x in raw):
        return {"well_typed": False, "normalized": None, "only_dac_override": False}
    values = [x[4:] if x.startswith("CAP_") else x for x in raw]
    return {"well_typed": True, "normalized": sorted(set(values)),
            "only_dac_override": set(values) == {"DAC_OVERRIDE"}}


class Docker:
    def __init__(self, output, stage, seconds):
        self.output, self.stage = output, stage
        self.deadline, self.counter = time.monotonic() + seconds, 0
        self.binary = shutil.which("docker")
        if not self.binary:
            raise RuntimeError("Docker CLI is unavailable")
        # Do not load the runner's Docker credentials or alternate contexts.
        config = output / "empty-docker-config"
        config.mkdir(parents=True, exist_ok=True)
        self.env = {"PATH": os.environ.get("PATH", os.defpath), "DOCKER_CONFIG": str(config)}

    def call(self, label, arguments, timeout=15, required=True):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Diagnostic stage deadline reached")
        command = [self.binary, "--host", "unix:///var/run/docker.sock", *arguments]
        begin = time.monotonic()
        self.counter += 1
        try:
            p = subprocess.run(command, capture_output=True, text=True, env=self.env,
                               timeout=min(timeout, remaining), check=False)
            result = {"returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr, "timed_out": False}
        except subprocess.TimeoutExpired as error:
            text = lambda value: value.decode(errors="replace") if isinstance(value, bytes) else value or ""
            result = {"returncode": 124, "stdout": text(error.stdout), "stderr": text(error.stderr), "timed_out": True}
        result.update({"argv": command, "elapsed_seconds": time.monotonic()-begin})
        save(self.output / "commands" / self.stage / f"{self.counter:03d}-{label}.json", result)
        if required and result["returncode"] != 0:
            raise RuntimeError(f"{label} failed with exit {result['returncode']}")
        return result


def inspect(docker, container, label):
    result = docker.call(label, ["inspect", container])
    values = json.loads(result["stdout"])
    if not isinstance(values, list) or len(values) != 1:
        raise ValueError("Unexpected inspect envelope")
    save(docker.output / (label + ".json"), values)
    return values[0]


def cleanup(output, owner, stage):
    result = {"owner": owner, "stage": stage, "operations": [], "errors": [], "verified_empty": False}
    try:
        docker = Docker(output, stage, 45)
        found = docker.call("owned-list", ["ps", "-aq", "--filter", f"label={OWNER_LABEL}={owner}"])
        for container in found["stdout"].split():
            if not re.fullmatch(r"[a-f0-9]{12,64}", container):
                raise ValueError("Invalid owned container id")
            data = inspect(docker, container, "cleanup-inspect-" + container[:12])
            if data.get("Config", {}).get("Labels", {}).get(OWNER_LABEL) != owner:
                raise RuntimeError("Refusing cleanup of a container with a different owner")
            removed = docker.call("remove-" + container[:12], ["rm", "--force", container], required=False)
            result["operations"].append({"container": container, "exit_code": removed["returncode"]})
            if removed["returncode"] != 0:
                result["errors"].append("container removal failed: " + container)
        final = docker.call("owned-final", ["ps", "-aq", "--filter", f"label={OWNER_LABEL}={owner}"])
        result["remaining"] = final["stdout"].split()
        result["verified_empty"] = not result["remaining"] and not result["errors"]
    except Exception as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
    save(output / (stage + ".json"), result)
    return result


def one_case(docker, owner, index, spelling, expected_image_id):
    name = f"g1-capdiag-{owner}-{index}"
    result = {"cli_spelling": spelling, "container_name": name, "completed": False}
    try:
        created = docker.call(f"case-{index}-create", [
            "create", "--name", name, "--label", f"{OWNER_LABEL}={owner}",
            "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", spelling,
            "--security-opt", "no-new-privileges:true", "--cpus", "4", "--memory", "8g",
            "--memory-swap", "8g", "--pids-limit", "64", "--restart", "no", "--user", "0:0",
            "--entrypoint", "python3", IMAGE, "-I", "-S", "-B", "-c", WORKLOAD,
        ], timeout=25)
        container = created["stdout"].strip()
        if not re.fullmatch(r"[a-f0-9]{64}", container):
            raise ValueError("Unexpected docker create container id")
        result["container_id"] = container
        before = inspect(docker, container, f"case-{index}-created-inspect")
        docker.call(f"case-{index}-start", ["start", container], timeout=20)
        running = inspect(docker, container, f"case-{index}-started-inspect")
        waited = docker.call(f"case-{index}-wait", ["wait", container], timeout=15)
        after = inspect(docker, container, f"case-{index}-exited-inspect")
        logs = docker.call(f"case-{index}-logs", ["logs", container])
        workload_record = json.loads(logs["stdout"].strip())
        host = running["HostConfig"]
        raw = host.get("CapAdd")
        normalized = normalize_capadd(raw)
        checks = {
            "owner_matches": running.get("Config", {}).get("Labels", {}).get(OWNER_LABEL) == owner,
            "fixed_image_id": running.get("Image") == expected_image_id,
            "capadd_unchanged_through_lifecycle": before["HostConfig"].get("CapAdd") == raw == after["HostConfig"].get("CapAdd"),
            "strict_normalized_only_dac_override": normalized["only_dac_override"],
            "drop_all": set(host.get("CapDrop") or []) == {"ALL"},
            "no_new_privileges": any(x in {"no-new-privileges", "no-new-privileges:true"} for x in host.get("SecurityOpt", [])),
            "network_none": host.get("NetworkMode") == "none",
            "no_host_mounts": not running.get("Mounts") and not host.get("Binds"),
            "no_published_ports": not host.get("PortBindings") and host.get("PublishAllPorts") is False,
            "unprivileged": host.get("Privileged") is False,
            "readonly_rootfs": host.get("ReadonlyRootfs") is True,
            "cpu_limit": host.get("NanoCpus") == 4_000_000_000,
            "memory_limit": host.get("Memory") == 8 * 1024**3,
            "finite_exit_zero": waited["stdout"].strip() == "0" and after["State"]["ExitCode"] == 0 and after["State"]["Running"] is False,
            "expected_workload_record": workload_record.get("probe") == "capability-representation-only",
        }
        result.update({"raw_CapAdd": raw, "raw_CapDrop": host.get("CapDrop"), "raw_SecurityOpt": host.get("SecurityOpt"),
                       "legacy_exact_predicate": set(raw or []) == {"DAC_OVERRIDE"}, "normalization": normalized,
                       "started_state": running["State"], "workload_record": workload_record,
                       "checks": checks, "completed": all(checks.values())})
    except Exception as error:
        result["error"] = type(error).__name__ + ": " + str(error)
    save(docker.output / f"case-{index}-result.json", result)
    return result


def run(output, owner, commit):
    result = {"owner": owner, "source_commit": commit, "image": IMAGE, "started_utc": datetime.now(timezone.utc).isoformat(),
              "scope": "Docker capability field representation only; not the original failed container and not G1 qualification",
              "cases": [], "errors": [], "completed": False}
    save(output / "diagnostic-plan.json", {**result, "spellings": SPELLINGS, "container_network": "none", "host_mounts": []})
    try:
        docker = Docker(output, "run", 300)
        version = json.loads(docker.call("version", ["version", "--format", "{{json .}}"])["stdout"])
        result["docker_versions"] = {"client": version.get("Client", {}).get("Version"),
            "server": version.get("Server", {}).get("Version"), "prior_G1_server_version": "28.0.4",
            "server_matches_prior_G1": version.get("Server", {}).get("Version") == "28.0.4",
            "client_matches_prior_G1": version.get("Client", {}).get("Version") == "28.0.4",
            "client_and_server_match_prior_G1": all(version.get(side, {}).get("Version") == "28.0.4"
                                                    for side in ("Client", "Server"))}
        docker.call("pull-fixed-base", ["pull", IMAGE], timeout=180)
        data = json.loads(docker.call("image-inspect", ["image", "inspect", IMAGE])["stdout"])
        save(output / "image-inspect.json", data)
        if len(data) != 1 or IMAGE not in data[0].get("RepoDigests", []):
            raise ValueError("Resolved image does not report the pinned digest")
        result["resolved_image_id"] = data[0]["Id"]
        for index, spelling in enumerate(SPELLINGS, 1):
            result["cases"].append(one_case(docker, owner, index, spelling, data[0]["Id"]))
        if len(result["cases"]) == 2:
            result["same_raw_CapAdd"] = result["cases"][0].get("raw_CapAdd") == result["cases"][1].get("raw_CapAdd")
            result["legacy_predicates"] = [case.get("legacy_exact_predicate") for case in result["cases"]]
            result["strict_normalized_predicates"] = [case.get("normalization", {}).get("only_dac_override") for case in result["cases"]]
            result["completed"] = all(case["completed"] for case in result["cases"])
    except Exception as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
    finally:
        clean = cleanup(output, owner, "cleanup-internal")
        result["internal_cleanup_verified"] = clean["verified_empty"]
        result["completed"] = result["completed"] and clean["verified_empty"]
        save(output / "diagnostic-result.json", result)
    return result["completed"]


def seal(output, owner):
    result_path, clean_path = output / "diagnostic-result.json", output / "cleanup-workflow.json"
    result = json.loads(result_path.read_text()) if result_path.exists() else {"completed": False, "missing": True}
    clean = json.loads(clean_path.read_text()) if clean_path.exists() else {"verified_empty": False, "missing": True}
    passed = result.get("owner") == owner and clean.get("owner") == owner and result.get("completed") is True and clean.get("verified_empty") is True
    save(output / "FINAL_DIAGNOSTIC_VERDICT.json", {"passed": passed, "diagnostic_completed": result.get("completed") is True,
         "workflow_cleanup_verified": clean.get("verified_empty") is True,
         "original_failed_container_raw_value_recovered": False, "full_G1_pass_claimed": False})
    files = [p for p in output.rglob("*") if p.is_file() and p.name != "MANIFEST.json" and "empty-docker-config" not in p.parts]
    save(output / "MANIFEST.json", {"files": [{"path": str(p.relative_to(output)), "bytes": p.stat().st_size,
         "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(files)]})
    return passed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["run", "cleanup", "seal"], required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", default="unrecorded")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]{1,30}-[0-9]{1,6}", args.owner):
        parser.error("Owner must be the numeric GitHub run id and attempt")
    args.output = args.output.absolute()
    args.output.mkdir(parents=True, exist_ok=True)
    if args.mode == "run":
        passed = run(args.output, args.owner, args.commit)
    elif args.mode == "cleanup":
        passed = cleanup(args.output, args.owner, "cleanup-workflow")["verified_empty"]
    else:
        passed = seal(args.output, args.owner)
    print(json.dumps({"stage": args.mode, "passed": passed, "output": str(args.output)}))
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
