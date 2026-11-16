"""Native-worker interpreter entry. No simulated endpoint or command fallback."""
import json
import os
from pathlib import Path
import sys
import uuid
from g1_common import canonical, sha, validate_arguments, write_json


def configured_transport():
    sys.path.insert(0, os.environ["G1_NATIVE_ADAPTER_ROOT"])
    from native_transport import Config, execute, check_client_versions
    check_client_versions()
    config = Config(api_origin=os.environ["SRE_NATIVE_API_URL"],
                    mcp_origin=os.environ["SRE_NATIVE_MCP_URL"],
                    attempt_id=os.environ["G1_ATTEMPT_ID"], role=os.environ["G1_ROLE"],
                    log_dir=Path(os.environ["G1_LOG_DIR"]) / "native_trace", timeout_seconds=60)
    return config, execute


def discover():
    config, execute = configured_transport()
    results = {}
    for operation in ("app_info", "status", "describe_tools"):
        response = execute(config, {"call_id": "discover_" + uuid.uuid4().hex,
                                   "operation": operation, "arguments": {}})
        results[operation] = response
        if response.get("transport_state") != "response_received" or response.get("trace_complete") is not True:
            raise ValueError("native_discovery_transport_incomplete")
        if operation != "describe_tools" and response.get("http_status") != 200:
            raise ValueError("native_discovery_http_failed")
    app = results["app_info"]["native_response"]
    status = results["status"]["native_response"]
    catalog = results["describe_tools"]["native_response"]
    if (not isinstance(app, dict) or app.get("namespace") != "gitlab-ce"
            or "gitlab-ce" not in app.get("namespaces", []) or status.get("stage") != "mitigation"
            or not any(t.get("name") == "exec_kubectl_cmd_safely" for t in catalog.get("tools", []))):
        raise ValueError("native_discovery_context_invalid")
    record = {"passed": True, "responses": results, "app_info": app,
              "app_info_sha256": sha(canonical(app)), "stage": status["stage"]}
    write_json(Path(os.environ["G1_LOG_DIR"]) / "g1-native-discovery.json", record)
    return record


def read():
    config, execute = configured_transport()
    request = json.load(sys.stdin)
    if not isinstance(request, dict) or set(request) != {"tool", "arguments", "request_id"}:
        raise ValueError("typed_worker_request_invalid")
    validate_arguments(request["tool"], request["arguments"])
    sys.path.insert(0, os.environ["G1_TYPED_READS_ROOT"])
    from typed_reads import AttemptContext, TypedReadService
    raw = json.loads(Path(os.environ["G1_CONTEXT_FILE"]).read_text())
    if raw["attempt_id"] != config.attempt_id or raw["role"] != config.role:
        raise ValueError("typed_worker_context_mismatch")
    context = AttemptContext(**raw)
    def transport(command, call_id):
        return execute(config, {"call_id": call_id, "operation": "kubectl", "arguments": {"cmd": command}})
    return TypedReadService(context, transport).call(request["tool"], request["arguments"], request["request_id"])


def main():
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in {"discover", "read"}:
            raise ValueError("worker_mode_invalid")
        value = discover() if sys.argv[1] == "discover" else read()
        print(json.dumps(value, ensure_ascii=False, allow_nan=False))
        return 0
    except Exception as error:
        print(json.dumps({"passed": False, "complete": False, "source_complete": False,
                          "business_success": None, "automatic_retries": 0,
                          "error": {"code": "native_worker_bootstrap_failed", "type": type(error).__name__}}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
