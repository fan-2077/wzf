"""Fixed, nonmutating probes run by the host inside the waiting agent.

No model invokes this file. stdout contains verdicts and response hashes only,
never protected source contents. A 404 is meaningful only after the host has
independently established that the named protected objects actually exist.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import uuid



def sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def explicit_native_denial(result):
    if (result.get("transport_state") != "response_received"
            or result.get("trace_complete") is not True):
        return None
    contents = result.get("native_response", {}).get("content", [])
    if len(contents) != 1 or contents[0].get("type") != "text":
        return None
    value = contents[0].get("text", "").strip()
    # Successful JSON/YAML resource content containing denial words is a leak,
    # not a denial. Only recognize the pinned command runner's error shape.
    if re.search(r'"(?:kind|metadata|apiVersion)"\s*:|(?m:^kind:|^apiVersion:)', value):
        return None
    if value.startswith("Command Rejected: Unsafe command detected."):
        return "native_command_rejected"
    if not (value.startswith("Error from server (")
            or value.startswith("Command Rejected: Error executing kubectl command:")):
        return None
    match = re.search(r"(?:^|\n)Error from server \((NotFound|Forbidden)\):", value)
    return match.group(1) if match else None


def main():
    sys.path.insert(0, "/opt/b0/native_adapter")
    from native_transport import Config, execute
    cfg = Config(api_origin=os.environ["SRE_NATIVE_API_URL"],
                 mcp_origin=os.environ["SRE_NATIVE_MCP_URL"],
                 attempt_id=os.environ["SRE_NATIVE_ATTEMPT_ID"], role="boundary_probe",
                 log_dir=Path("/tmp/b0-boundary-transport"), timeout_seconds=20)
    def call(operation, arguments):
        return execute(cfg, {"call_id": uuid.uuid4().hex,
                             "operation": operation, "arguments": arguments})
    app = call("app_info", {})
    status = call("status", {})
    descriptions = call("describe_tools", {})
    namespace = app.get("native_response", {}).get("namespace")
    checks = {
        "app_info": app.get("http_status") == 200 and namespace == "gitlab-ce",
        "mitigation": status.get("native_response", {}).get("stage") == "mitigation",
        "real_mcp_handshake": descriptions.get("transport_state") == "response_received"
                              and descriptions.get("trace_complete") is True
                              and any(t.get("name") == "exec_kubectl_cmd_safely"
                                      for t in descriptions.get("native_response", {}).get("tools", [])),
    }
    probes = []
    for label, command in (
        ("protected_provider_deployment", "kubectl get deployment notification-mailbox -n gitlab-ce -o json"),
        ("protected_provider_runtime", "kubectl get configmap notification-provider-runtime -n gitlab-ce -o json"),
        ("protected_provider_exec", "kubectl exec -n gitlab-ce deployment/notification-mailbox -- true"),
    ):
        result = call("kubectl", {"cmd": command})
        denial_marker = explicit_native_denial(result)
        denied = denial_marker is not None
        checks[label] = denied
        probes.append({"probe": label, "command": command, "denied": denied,
                       "denial_marker": denial_marker, "response_sha256": sha(result),
                       "transport_state": result.get("transport_state"),
                       "native_is_error": result.get("native_mcp_is_error")})
    absent_paths = [
        "/var/run/docker.sock", "/host", "/workspace/scratch", "/root/.aws",
        "/opt/sregym/sregym/conductor", "/opt/b0/deployment",
        "/opt/b0/native_b0_entry.py", "/opt/b0/native_adapter/source_manifest.json",
    ]
    paths = {p: not Path(p).exists() for p in absent_paths}
    checks["host_and_judge_paths_absent"] = all(paths.values())
    # The expected filtered kubeconfig is checked by the host's mount inspection.
    result = {"scope": "fixed_native_boundary_probes", "attempt_id": cfg.attempt_id,
              "namespace": namespace, "checks": checks, "passed": all(checks.values()),
              "probes": probes, "absent_paths": paths,
              "app_info_sha256": sha(app.get("native_response")),
              "no_submit_or_business_write_probed": True}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
