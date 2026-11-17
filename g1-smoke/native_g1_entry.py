#!/usr/bin/env python3
"""One unscored read-only integration attempt with the original lifecycle.

Requires the separately reviewed disposable-host runner. This module belongs
on the host only. It is never copied into the model/agent image.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import traceback
from urllib.request import ProxyHandler, build_opener

from host_ingress import HostIngressGuard

TASK = "gitlab_notification_intermittent_replicated"
AGENT = "aios-g1-public-read"


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".partial")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    temporary.replace(path)


def sha_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stop_owned_container(name):
    if not name:
        return True
    p = subprocess.run(["docker", "ps", "-aq", "--filter", "name=^/" + name + "$"],
                       capture_output=True, text=True, timeout=10, check=True)
    if p.stdout.strip():
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True,
                       timeout=30, check=True)
    p = subprocess.run(["docker", "ps", "-aq", "--filter", "name=^/" + name + "$"],
                       capture_output=True, text=True, timeout=10, check=True)
    if p.stdout.strip():
        raise RuntimeError("Owned agent container still exists")
    return True


def verify_native_boundary(container, out, agent_logs, inspection, attempt):
    # A hidden-resource 404 must be backed by privileged proof of existence.
    existence = {}
    for kind, name in (("deployment", "notification-mailbox"),
                       ("configmap", "notification-provider-runtime")):
        p = subprocess.run(["kubectl", "get", kind, name, "-n", "gitlab-ce",
                            "-o", "jsonpath={.metadata.uid}", "--request-timeout=10s"],
                           capture_output=True, text=True, timeout=15, check=True)
        existence[kind + "/" + name] = bool(p.stdout.strip())
    if not all(existence.values()):
        raise RuntimeError("Cannot establish protected native objects exist")
    p = subprocess.run(["kubectl", "get", "pods", "-n", "sregym", "-o", "json",
                        "--request-timeout=10s"], capture_output=True, text=True,
                       timeout=15, check=True)
    identities = []
    for pod in json.loads(p.stdout).get("items", []):
        for c in pod.get("status", {}).get("containerStatuses", []):
            identities.append({"pod": pod["metadata"]["name"], "container": c["name"],
                               "image": c.get("image"), "imageID": c.get("imageID")})
    if not identities or not all(x["imageID"] for x in identities):
        raise RuntimeError("Actual native MCP image identities unavailable")
    save(out / "actual-native-mcp-image-identities.json", identities)
    p = subprocess.run(["docker", "exec", container, "/opt/native/bin/python", "-B",
                        "/opt/g1/probes/native_boundary_probe.py"],
                       capture_output=True, text=True, timeout=75)
    (out / "native-boundary-probe-stderr.log").write_text(p.stderr)
    probe = json.loads(p.stdout)
    probe["host_protected_objects_exist"] = existence
    save(out / "native-boundary-probe.json", probe)
    if p.returncode != 0 or probe.get("passed") is not True:
        raise RuntimeError("Actual original MCP boundary probe failed")
    # API and proxy are explicitly IPv4 bridge-bound; original MCP also must
    # not acquire an uncovered wildcard IPv6 listener.
    listeners = HostIngressGuard.active_listeners()
    if any(":::" in x or "[::]:" in x for x in listeners):
        raise RuntimeError("Uncovered wildcard IPv6 native listener")
    proof = {"attempt_id": attempt, "namespace": "gitlab-ce",
             "source_commit": "148dded7ca2737ded1085e7dc7bbf2a8fcfe7861",
             "native_filtered_boundary_verified": True,
             "probe_result_sha256": sha_file(out / "native-boundary-probe.json"),
             "container_inspection_sha256": sha_file(out / "container-inspection.json"),
             "native_mcp_image_identity_sha256": sha_file(out / "actual-native-mcp-image-identities.json"),
             "ingress_scope": "loopback and all Docker bridge interfaces on this disposable host",
             "ingress_active_non_bridge_probe": False}
    save(out / "host-retained-boundary-proof.json", proof)
    # Model is still waiting. Keep a host-only original; the agent copy is a
    # consistency record, not a credential or a security boundary.
    target = agent_logs / "g1-native-boundary.json"
    save(target, proof)
    digest_target = agent_logs / "g1-native-boundary.sha256"
    digest_temporary = digest_target.with_suffix(".sha256.partial")
    digest_temporary.write_text(sha_file(target) + "\n")
    digest_temporary.replace(digest_target)
    return proof


def read_http(origin, path):
    with build_opener(ProxyHandler({})).open(origin + path, timeout=3) as r:
        return json.load(r)


def inspect_agent_container(name, expected_image_id, agent_logs, expected_cert_volume):
    p = subprocess.run(["docker", "inspect", name], capture_output=True,
                       text=True, timeout=10, check=True)
    raw = json.loads(p.stdout)[0]
    mounts = [{k: m.get(k) for k in ("Type", "Name", "Source", "Destination", "RW")}
              for m in raw.get("Mounts", [])]
    host = raw["HostConfig"]
    config = raw["Config"]
    network_name = host.get("NetworkMode")
    n = subprocess.run(["docker", "network", "inspect", network_name],
                       capture_output=True, text=True, timeout=10, check=True)
    network = json.loads(n.stdout)[0]
    env_names = [x.partition("=")[0] for x in config.get("Env", [])]
    # Values are deliberately not copied into public evidence.
    forbidden = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GH_TOKEN", "GITHUB_TOKEN",
                 "JUDGE_MODEL_ID", "JUDGE_API_KEY", "JUDGE_API_BASE", "ANTHROPIC_API_KEY",
                 "CLAUDE_CODE_OAUTH_TOKEN", "HF_TOKEN", "GOOGLE_API_KEY", "OPENAI_API_KEY",
                 "AGENT_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY", "DEEPSEEK_API_KEY"}
    forbidden.update(x for x in env_names if x.endswith(("_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD")))
    allowed_destinations = {"/logs", "/root/.kube/config", "/etc/evaluation-egress"}
    checks = {
        "expected_image": raw["Image"] == expected_image_id,
        "private_container_network": network_name not in {"host", "bridge", "default"}
                                     and network.get("Internal") is True,
        "no_published_ports": not host.get("PortBindings"),
        "not_privileged": host.get("Privileged") is False,
        "no_new_privileges": any(x.startswith("no-new-privileges") for x in host.get("SecurityOpt", [])),
        "capabilities_dropped": "ALL" in (host.get("CapDrop") or []),
        "only_reviewed_added_capability": set(host.get("CapAdd") or []) == {"DAC_OVERRIDE"},
        "exact_memory_limit": host.get("Memory") == 8 * 1024**3,
        "exact_cpu_limit": host.get("NanoCpus") == 4_000_000_000,
        "only_reviewed_mounts": all(m["Destination"] in allowed_destinations for m in mounts),
        "agent_logs_only": any(m["Destination"] == "/logs" and Path(m["Source"]).resolve() == agent_logs.resolve() for m in mounts),
        "readonly_filtered_kubeconfig": any(m["Destination"] == "/root/.kube/config" and m["RW"] is False for m in mounts),
        "readonly_owned_proxy_certificates": any(m["Destination"] == "/etc/evaluation-egress"
                                                  and m["Name"] == expected_cert_volume and m["RW"] is False for m in mounts),
        "no_forwarded_secret_names": not (set(env_names) & forbidden),
    }
    return {"checks": checks, "passed": all(checks.values()), "image_id": raw["Image"],
            "mounts": mounts, "environment_names_only": sorted(env_names),
            "network_mode": host.get("NetworkMode"), "memory_limit": host.get("Memory"),
            "nano_cpus": host.get("NanoCpus"),
            "network": {k: network.get(k) for k in ("Id", "Name", "Internal", "Driver", "EnableIPv6")}}


async def main():
    required = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                "GITHUB_REPOSITORY": "fan-2077/wzf", "GITHUB_REF": "refs/heads/sre-g1-connection-20261116"}
    for key, expected in required.items():
        if os.environ.get(key) != expected:
            raise RuntimeError("Refusing unreviewed host context: " + key)
    out = Path(os.environ["G1_RESULTS"]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    agent_logs = out / "agent"
    agent_logs.mkdir(exist_ok=False)
    run_id = os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    state = {"scope": "unscored_read_only_native_integration", "task": TASK,
             "smoke_pass": False, "agent_recovery_success": None,
             "agent_submit_planned": False, "attempt_id": run_id, "cleanup": []}
    guard = HostIngressGuard(run_id, out)
    conductor = launcher = process = api_thread = None
    started = time.monotonic()
    try:
        if guard.active_listeners():
            raise RuntimeError("Native ports already in use; refusing shared host")
        guard.install()
        from logger import init_logger
        from sregym.agent_launcher import AgentLauncher
        from sregym.agent_registry import AgentRegistration
        from sregym.conductor.conductor import Conductor, ConductorConfig
        from sregym.conductor.conductor_api import run_api
        from sregym.profile import set_profile
        from sregym.service.container_runner import get_container_host_bind_address
        from sregym.service.internet_policy import InternetPolicy
        init_logger()
        set_profile("full")
        bridge = get_container_host_bind_address()
        os.environ.update(API_BIND_HOST=bridge, API_PORT="8000", MCP_SERVER_PORT="9954",
                          AGENT_LOGS_DIR=str(agent_logs))
        policy = InternetPolicy.from_mode("filtered", agent_name=None, model_id=None,
                                         additional_allowed_endpoints=())
        config = ConductorConfig(deploy_loki=False, internet_policy=policy,
                                 k8s_proxy_listen_host=bridge, k8s_proxy_listen_port=16443,
                                 block_workload_creation=True, stages=("mitigation",))
        conductor = Conductor(config=config)
        conductor.problem_id = TASK
        conductor.register_agent(AGENT)
        conductor.bind_phase_ledger(out / "native-phases.jsonl", attempt_id=run_id,
                                    problem_id=TASK, agent=AGENT)
        launcher = AgentLauncher()
        launcher.set_internet_policy(policy)
        launcher.set_container_hardening(True)
        launcher.enable_container_isolation(image=os.environ["G1_AGENT_IMAGE"], k8s_proxy_port=16443)
        runner_config = launcher._container_runner.config
        runner_config.forward_host_credentials = False
        runner_config.codex_auth = "none"
        runner_config.published_ports = []
        runner_config.sregym_apps_path = None
        runner_config.sregym_app_subdirs = []
        runner_config.cpus, runner_config.memory = 4.0, "8g"
        # start_problem owns the full original ordering, baseline, and injection.
        await conductor.start_problem()
        if conductor.submission_stage != "mitigation" or not conductor.fault_injected:
            raise RuntimeError("Original mitigation incident is not ready")
        conductor.start_k8s_proxy()
        launcher.set_agent_kubeconfig(conductor.get_agent_kubeconfig_path())
        api_thread = threading.Thread(target=run_api, args=(conductor,), daemon=True)
        api_thread.start()
        api_origin = "http://" + bridge + ":8000"
        api_deadline = time.monotonic() + 45
        while True:
            try:
                public_status = read_http(api_origin, "/status")
                if public_status.get("stage") == "mitigation":
                    break
            except OSError:
                pass
            if time.monotonic() > api_deadline:
                raise TimeoutError("Original API did not become ready")
            await asyncio.sleep(0.25)
        save(out / "public-get-app.json", read_http(api_origin, "/get_app"))
        save(out / "public-status-before-agent.json", public_status)
        registration = AgentRegistration(
            name=AGENT, container_isolation=True, cluster_access=True,
            kickoff_command="/opt/aios/bin/python -B /opt/g1/integration/agent_entry.py",
            kickoff_env={
                "API_PORT": "8000", "MCP_SERVER_PORT": "9954",
                "G1_ATTEMPT_ID": run_id, "G1_WORLD_EPOCH": "g1_" + run_id, "G1_LOG_ROOT": "/logs",
                "SRE_NATIVE_API_URL": "http://host.docker.internal:8000",
                "SRE_NATIVE_MCP_URL": "http://host.docker.internal:9954",
                "SRE_NATIVE_ATTEMPT_ID": run_id,
                "SRE_NATIVE_LOG_DIR": "/logs/native-transport",
                "SRE_NATIVE_PYTHON": "/opt/native/bin/python",
                "G1_READ_ONLY_SMOKE": "1",
            })
        conductor.agent_timeout_seconds = 1200
        conductor.agent_deadline_monotonic = time.monotonic() + 1200
        process = await launcher.ensure_started(registration)
        if process is None or not process.container_name:
            raise RuntimeError("Original launcher did not create an isolated agent")
        inspect_deadline = time.monotonic() + 30
        while True:
            try:
                inspection = inspect_agent_container(process.container_name,
                                                    os.environ["G1_AGENT_IMAGE_ID"], agent_logs,
                                                    launcher._container_runner._egress._cert_volume)
                break
            except subprocess.CalledProcessError:
                if process.proc.poll() is not None or time.monotonic() > inspect_deadline:
                    raise
                await asyncio.sleep(0.2)
        save(out / "container-inspection.json", inspection)
        if not inspection["passed"]:
            raise RuntimeError("Agent container boundary inspection failed")
        state["boundary_proof"] = verify_native_boundary(process.container_name, out, agent_logs,
                                                          inspection, run_id)
        while process.proc.poll() is None:
            if time.monotonic() > conductor.agent_deadline_monotonic:
                raise TimeoutError("Read-only smoke agent deadline exceeded")
            await asyncio.sleep(0.5)
        state["agent_process_exit_code"] = process.proc.returncode
        state["internet_policy_result"] = launcher.internet_policy_result(process)
        result_path = agent_logs / "g1-agent-result.json"
        agent_result = json.loads(result_path.read_text())
        state["agent_result"] = agent_result
        ledger = [json.loads(line) for line in (out / "native-phases.jsonl").read_text().splitlines() if line]
        state["native_no_submission_checks"] = {
            "no_mitigation_result": "Mitigation" not in conductor.results,
            "no_evaluation_phase": not any(str(x.get("phase", "")).startswith("evaluate:") for x in ledger),
            "no_pending_submissions": not conductor._pending_submission_stages,
            "no_evaluation_future": conductor._submit_future is None,
        }
        # A model/driver assertion is only one component of host acceptance.
        state["smoke_pass"] = bool(inspection["passed"] and process.proc.returncode == 0
                                    and agent_result.get("passed") is True
                                    and agent_result.get("model_requests_observed") == 1
                                    and agent_result.get("complete_public_snapshot") is True
                                    and agent_result.get("native_business_called") is True
                                    and agent_result.get("submit_calls") == 0
                                    and all(state["native_no_submission_checks"].values()))
    except BaseException as exc:
        state["smoke_pass"] = False
        state["error"] = {"type": type(exc).__name__, "message": str(exc)}
        traceback.print_exc()
    finally:
        # Freeze results before privileged reference cleanup. No /submit is added.
        def cleanup_step(name, operation):
            try:
                operation()
                state["cleanup"].append({"operation": name, "passed": True})
                return True
            except BaseException as exc:
                state["cleanup"].append({"operation": name, "passed": False, "error": str(exc)})
                return False

        cleanup_step("freeze_pre_cleanup_evidence", lambda: save(out / "g1-before-reference-cleanup.json", state))
        if conductor:
            cleanup_step("close_submissions", conductor.close_submissions)
            cleanup_step("record_incomplete_attempt", lambda: conductor.record_incomplete_attempt("read_only_integration_smoke_no_submission"))
            cleanup_step("save_native_pre_cleanup_result", lambda: save(out / "native-result-before-cleanup.json", conductor.results))
        if launcher:
            try:
                launcher.cleanup_all(timeout=30)
                state["cleanup"].append({"operation": "stop_agent_and_egress", "passed": True})
            except Exception as exc:
                state["cleanup"].append({"operation": "stop_agent_and_egress", "passed": False, "error": str(exc)})
        stopped = cleanup_step("verify_owned_agent_container_removed", lambda: stop_owned_container(process.container_name if process else None))
        if conductor and conductor.problem is not None and stopped:
            try:
                fut = conductor.finish_problem_in_background()
                await asyncio.wait_for(asyncio.wrap_future(fut), timeout=max(900, float(getattr(conductor.problem, "cleanup_timeout_seconds", 900))))
                state["cleanup"].append({"operation": "original_reference_lifecycle_cleanup", "passed": not conductor.results.get("cleanup_failed", False)})
            except Exception as exc:
                conductor.abandon_submission_work()
                state["cleanup"].append({"operation": "original_reference_lifecycle_cleanup", "passed": False, "error": str(exc)})
        if api_thread:
            from sregym.conductor.conductor_api import request_shutdown
            cleanup_step("request_api_shutdown", request_shutdown)
            cleanup_step("join_api_thread", lambda: api_thread.join(timeout=15))
        if conductor:
            for name, operation in (("stop_mcp_forward", conductor.mcp_server.stop_port_forward),
                                    ("stop_k8s_proxy", conductor.stop_k8s_proxy)):
                try:
                    operation()
                    state["cleanup"].append({"operation": name, "passed": True})
                except Exception as exc:
                    state["cleanup"].append({"operation": name, "passed": False, "error": str(exc)})
        try:
            guard.remove_after_listeners_stop()
            state["cleanup"].append({"operation": "remove_owned_ingress_after_listeners", "passed": True})
        except Exception as exc:
            state["cleanup"].append({"operation": "remove_owned_ingress_after_listeners", "passed": False, "error": str(exc)})
        state["elapsed_seconds"] = time.monotonic() - started
        state["cleanup_passed"] = bool(state["cleanup"]) and all(x["passed"] for x in state["cleanup"])
        state["passed"] = state["smoke_pass"] and state["cleanup_passed"] and not state.get("error")
        save(out / "g1-native-result.json", state)
    return 0 if state.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
