#!/usr/bin/env python3
"""Container and filtered-native boundary checks inherited from verified G1.

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
AGENT = "b0-public-baseline"


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
                        "/opt/b0/probes/native_boundary_probe.py"],
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
    target = agent_logs / "b0-native-boundary.json"
    save(target, proof)
    digest_target = agent_logs / "b0-native-boundary.sha256"
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
    cap_add_raw = host.get("CapAdd")
    # Docker accepts both spellings. Remove at most one exact prefix; malformed
    # values and every additional capability must continue to fail closed.
    cap_add_normalized = (
        {cap.removeprefix("CAP_") for cap in cap_add_raw}
        if isinstance(cap_add_raw, list) and all(isinstance(cap, str) for cap in cap_add_raw)
        else None
    )
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
        "only_reviewed_added_capability": cap_add_normalized == {"DAC_OVERRIDE"},
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
            "capabilities": {"CapAdd": cap_add_raw, "CapDrop": host.get("CapDrop"),
                             "CapAdd_present": "CapAdd" in host, "CapDrop_present": "CapDrop" in host,
                             "CapAdd_normalized": sorted(cap_add_normalized) if cap_add_normalized is not None else None},
            "network": {k: network.get(k) for k in ("Id", "Name", "Internal", "Driver", "EnableIPv6")}}


