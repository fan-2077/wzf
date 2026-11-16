"""Bounded fallback for the extra G1 resources, including killed host drivers.

Only works with a persisted, empty-prefix ownership receipt from this exact
disposable Actions run. It never performs a global Docker prune or changes a
global firewall policy. Used both by the runner finally and workflow always.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from host_ingress import HostIngressGuard

PREFIXES = {"container": ("evaluation-egress-proxy-", "sregym-aios-g1-public-read-run-", "g1-image-preflight-"),
            "network": ("evaluation-egress-",), "volume": ("evaluation-egress-certs-",)}


def names(kind):
    command = {"container": ["docker", "ps", "-a", "--format", "{{.Names}}"],
               "network": ["docker", "network", "ls", "--format", "{{.Name}}"],
               "volume": ["docker", "volume", "ls", "--format", "{{.Name}}"]}[kind]
    p = subprocess.run(command, capture_output=True, text=True, timeout=15, check=True)
    return [x for x in p.stdout.splitlines() if x.startswith(PREFIXES[kind])]


def claim(path: Path, *, work: Path, cluster: str):
    identity = {k: os.environ.get(k) for k in ("GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or identity["GITHUB_REPOSITORY"] != "fan-2077/wzf"
            or identity["GITHUB_REF"] != "refs/heads/sre-g1-connection-20261116"):
        raise RuntimeError("Cannot claim resources outside reviewed hosted run")
    preexisting = {kind: names(kind) for kind in PREFIXES}
    if any(preexisting.values()) or HostIngressGuard.active_listeners():
        raise RuntimeError("G1 resource prefixes or native ports are already in use")
    if path.exists():
        raise RuntimeError("Ownership receipt already exists")
    value = {"identity": identity, "dedicated_host": True, "empty_prefixes_before_g1": preexisting,
             "native_ports_unused_before_g1": True, "work": str(work), "cluster": cluster,
             "kind_ownership_preflight_passed": False}
    path.write_text(json.dumps(value, indent=2) + "\n")
    return value


def cleanup(path: Path, *, full=False):
    value = json.loads(path.read_text())
    expected_identity = {k: os.environ.get(k) for k in value["identity"]}
    if (expected_identity != value["identity"] or not value.get("dedicated_host")
            or value.get("native_ports_unused_before_g1") is not True
            or any(value["empty_prefixes_before_g1"].values())
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise RuntimeError("Ownership receipt does not authorize this cleanup context")
    steps = []
    def action(label, command, timeout=30):
        try:
            p = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
            steps.append({"operation": label, "passed": p.returncode == 0,
                          "exit_code": p.returncode, "stderr": p.stderr[-2000:]})
        except Exception as exc:
            steps.append({"operation": label, "passed": False, "error": str(exc)})
    # Check both PID and Linux process-start ticks; never kill a reused PID.
    # Only leaders of newly-created groups were recorded by our host runner.
    process_receipt = path.parent / "process-ownership.jsonl"
    if process_receipt.is_file():
        for line in process_receipt.read_text().splitlines():
            item = json.loads(line)
            if item.get("identity") != value["identity"]:
                raise RuntimeError("Process receipt belongs to a different run")
            pid, pgid = item["pid"], item["pgid"]
            if type(pid) is not int or pid != pgid or pid <= 1 or pgid == os.getpgrp():
                raise RuntimeError("Invalid owned process-group identity")
            stat = Path(f"/proc/{pid}/stat")
            if not stat.exists():
                continue
            try:
                observed = stat.read_text().rsplit(")", 1)[1].split()[19]
            except FileNotFoundError:
                continue
            if observed != item.get("start_ticks"):
                continue
            try:
                os.killpg(pgid, signal.SIGTERM)
                until = time.monotonic() + 2
                while stat.exists() and time.monotonic() < until:
                    time.sleep(0.05)
                if stat.exists() and stat.read_text().rsplit(")", 1)[1].split()[19] == observed:
                    os.killpg(pgid, signal.SIGKILL)
                steps.append({"operation": "stop_owned_process_group", "pid": pid, "passed": True})
            except ProcessLookupError:
                pass
            except Exception as exc:
                steps.append({"operation": "stop_owned_process_group", "pid": pid, "passed": False, "error": str(exc)})
    for kind in ("container", "network", "volume"):
        try:
            current = names(kind)
            for name in current:
                command = ["docker", "rm", "-f", name] if kind == "container" else ["docker", kind, "rm", name]
                action("remove_" + kind + ":" + name, command)
            steps.append({"operation": "verify_no_owned_" + kind, "passed": not names(kind)})
        except Exception as exc:
            steps.append({"operation": "verify_no_owned_" + kind, "passed": False, "error": str(exc)})
    run_id = value["identity"]["GITHUB_RUN_ID"] + "-" + value["identity"]["GITHUB_RUN_ATTEMPT"]
    guard = HostIngressGuard(run_id, path.parent)
    try:
        listeners = guard.active_listeners()
        steps.append({"operation": "verify_native_listeners_stopped", "passed": not listeners,
                      "remaining": listeners})
        if not listeners:
            exists = guard._run(["-S", guard.chain], check=False).returncode == 0
            guard.created = exists
            if exists:
                rule = ["-C", "INPUT", "-p", "tcp", "-m", "multiport", "--dports", "8000,9954,16443", "-j", guard.chain]
                guard.attached = guard._run(rule, check=False).returncode == 0
                guard.remove_after_listeners_stop()
            steps.append({"operation": "verify_owned_ingress_removed", "passed": guard._run(["-S", guard.chain], check=False).returncode != 0})
    except Exception as exc:
        steps.append({"operation": "owned_ingress_cleanup", "passed": False, "error": str(exc)})
    if full:
        work = Path(value["work"]).resolve()
        expected = (Path(os.environ["RUNNER_TEMP"]) / ("sre-native-" + run_id)).resolve()
        if work != expected or value["cluster"] != "sre-native-" + run_id:
            raise RuntimeError("KIND cleanup ownership mismatch")
        original_receipt = path.parent / "summary.json"
        if original_receipt.is_file():
            original = json.loads(original_receipt.read_text())
            owned = (original.get("ownership_initialized") is True
                     and original.get("cluster") == value["cluster"]
                     and Path(original.get("work_directory", "")).resolve() == work
                     and all(original.get("identity", {}).get(k) == v for k, v in value["identity"].items()))
        else:
            owned = False
        if not owned:
            steps.append({"operation": "kind_not_claimed_no_mutation", "passed": True})
            return {"scope": "owned G1 fallback; KIND not claimed", "full": full,
                    "passed": all(x["passed"] for x in steps), "steps": steps}
        kind = work / "bin/kind"
        if kind.is_file():
            action("delete_owned_kind_cluster", [str(kind), "delete", "cluster", "--name", value["cluster"]], 90)
        p = subprocess.run(["docker", "ps", "-aq", "--filter", "label=io.x-k8s.kind.cluster=" + value["cluster"]],
                           capture_output=True, text=True, timeout=15, check=True)
        if p.stdout.strip():
            action("remove_owned_kind_nodes", ["docker", "rm", "-f", *p.stdout.split()])
        p = subprocess.run(["docker", "network", "ls", "--filter", "name=^kind$", "--format", "{{.Name}}"],
                           capture_output=True, text=True, timeout=15, check=True)
        if p.stdout.strip():
            action("remove_owned_kind_network", ["docker", "network", "rm", "kind"])
        (work / "kubeconfig").unlink(missing_ok=True)
        p = subprocess.run(["docker", "ps", "-aq", "--filter", "label=io.x-k8s.kind.cluster=" + value["cluster"]],
                           capture_output=True, text=True, timeout=15, check=True)
        steps.append({"operation": "verify_owned_kind_nodes_absent", "passed": not p.stdout.strip()})
        p = subprocess.run(["docker", "network", "ls", "--filter", "name=^kind$", "--format", "{{.Name}}"],
                           capture_output=True, text=True, timeout=15, check=True)
        steps.append({"operation": "verify_owned_kind_network_absent", "passed": not p.stdout.strip()})
    return {"scope": "owned G1 container/network/volume/listener/ingress fallback", "full": full,
            "passed": all(x["passed"] for x in steps), "steps": steps}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope", type=Path, required=True)
    parser.add_argument("--full", action="store_true")
    args = parser.parse_args()
    if not args.scope.exists():
        print("No persisted G1 ownership receipt; no extra G1 resource mutation authorized.")
        raise SystemExit(0)
    result = cleanup(args.scope, full=args.full)
    (args.scope.parent / "workflow-fallback-cleanup.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"owned_fallback_cleanup_passed": result["passed"]}))
    raise SystemExit(0 if result["passed"] else 1)
