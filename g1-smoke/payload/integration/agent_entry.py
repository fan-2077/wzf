"""Portable G1 prerequisite: real model + SDK/AIOS + one public native read.

Run under /opt/aios/bin/python. --preflight imports and checks artifacts only.
Normal runs wait for host-owned boundary verification before any model request
or business read. No repair, evaluation submission or baseline timing claim.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from g1_common import (IDENTIFIER, KERNEL_PORT, MODEL_NAME, MODEL_PORT, MODEL_SHA256, TYPED_PROGRAM_DIGEST,
                       endpoint, file_sha, sha, validate_boundary, write_json)

ROOT = Path(__file__).resolve().parent


def paths():
    values = {
        "G1_LOG_DIR": "/logs", "G1_SOURCE_ROOT": str(ROOT / "source_terminal"),
        "G1_SDK_ROOT": "/opt/g1/sdk", "G1_TYPED_READS_ROOT": "/opt/g1/typed_reads",
        "G1_NATIVE_ADAPTER_ROOT": "/opt/g1/native_adapter", "G1_AIOS_PYTHON": "/opt/aios/bin/python",
        "G1_NATIVE_PYTHON": "/opt/native/bin/python", "G1_MODEL_SERVER": "/opt/llama/bin/llama-server",
        "G1_MODEL_PATH": "/opt/models/Qwen3-8B-Q4_K_M.gguf",
    }
    return {key: Path(os.environ.get(key, default)).resolve() for key, default in values.items()}


def base_environment(p):
    # Do not forward arbitrary provider keys. Native proxy policy is preserved.
    keep = {"PATH", "LANG", "LC_ALL", "LD_LIBRARY_PATH", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
            "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"}
    env = {key: value for key, value in os.environ.items() if key in keep}
    env.update({key: str(value) for key, value in p.items()})
    log = p["G1_LOG_DIR"]
    env.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1",
        "PYTHONPATH": ":".join(map(str, (ROOT, p["G1_SOURCE_ROOT"], p["G1_SDK_ROOT"], p["G1_TYPED_READS_ROOT"]))),
        "XDG_CACHE_HOME": str(log / "tool_cache"), "HF_HOME": str(log / "cache/huggingface"),
        "NLTK_DATA": str(log / "cache/nltk"), "TMPDIR": str(log / "tmp"),
        "G1_NATIVE_WORKER": str(ROOT / "g1_native_worker.py"),
        "OMP_NUM_THREADS": "1", "TOKENIZERS_PARALLELISM": "false", "LITELLM_LOCAL_MODEL_COST_MAP": "True",
        "ORT_DISABLE_TELEMETRY": "1", "DO_NOT_TRACK": "1", "ANONYMIZED_TELEMETRY": "False",
        "OTEL_SDK_DISABLED": "true", "OTEL_TRACES_EXPORTER": "none", "OTEL_METRICS_EXPORTER": "none",
        "OTEL_LOGS_EXPORTER": "none", "HF_HUB_DISABLE_TELEMETRY": "1", "HF_HUB_OFFLINE": "1",
        "HF_DATASETS_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"})
    # Loopback is constructed here, after the original container launcher rewrites *_URL variables.
    for key in ("NO_PROXY", "no_proxy"):
        existing = env.get(key, "")
        env[key] = ",".join(x for x in (existing, "127.0.0.1", "localhost", "::1") if x)
    for rel in ("tool_cache", "cache", "cache/nltk", "tmp", "storage"):
        (log / rel).mkdir(parents=True, exist_ok=True)
    return env


def launcher_context():
    required = ("G1_ATTEMPT_ID", "G1_WORLD_EPOCH", "SRE_NATIVE_API_URL", "SRE_NATIVE_MCP_URL")
    if any(not os.environ.get(key) for key in required):
        raise ValueError("missing_trusted_launcher_context_or_native_endpoint")
    ctx = {key: os.environ[key] for key in required}
    for key in ("G1_ATTEMPT_ID", "G1_WORLD_EPOCH"):
        if not IDENTIFIER.fullmatch(ctx[key]):
            raise ValueError("invalid_launcher_identifier")
    ctx["G1_ROLE"] = os.environ.get("G1_ROLE", "single")
    ctx["G1_NAMESPACE"] = os.environ.get("G1_NAMESPACE", "gitlab-ce")
    if ctx["G1_ROLE"] != "single" or ctx["G1_NAMESPACE"] != "gitlab-ce":
        raise ValueError("this_prerequisite_entry_is_one_single_role_in_gitlab_ce")
    for key in ("SRE_NATIVE_API_URL", "SRE_NATIVE_MCP_URL"):
        ctx[key] = endpoint(ctx[key])
    return ctx


def wait_boundary(log, ctx, timeout=90.0):
    deadline = time.monotonic() + timeout
    ready = threading.Event()
    proof, digest_file = log / "g1-native-boundary.json", log / "g1-native-boundary.sha256"
    while time.monotonic() < deadline:
        if proof.is_file() and digest_file.is_file():
            digest = digest_file.read_text().strip().split()[0]
            value = validate_boundary(proof.read_bytes(), digest, ctx["G1_ATTEMPT_ID"], ctx["G1_NAMESPACE"])
            return {"proof_sha256": digest, "proof": value,
                    "authority": "Host retained original inspection/probe; this writable copy is only an integrity record"}
        ready.wait(min(0.25, max(0, deadline - time.monotonic())))
    raise TimeoutError("host_native_boundary_evidence_not_received")


def check_materials(p):
    required = [p["G1_SOURCE_ROOT"] / "runtime/launch.py", p["G1_SOURCE_ROOT"] / "aios/llm_core/adapter.py",
                p["G1_SDK_ROOT"] / "cerebrum/llm/apis.py", p["G1_SDK_ROOT"] / "cerebrum/tool/apis.py",
                p["G1_TYPED_READS_ROOT"] / "typed_reads.py", p["G1_TYPED_READS_ROOT"] / "programs.py",
                p["G1_NATIVE_ADAPTER_ROOT"] / "native_transport.py", p["G1_MODEL_SERVER"], p["G1_MODEL_PATH"]]
    if not all(path.is_file() for path in required):
        raise ValueError("required_runtime_material_missing")
    if not all(os.access(p[key], os.X_OK) for key in ("G1_AIOS_PYTHON", "G1_NATIVE_PYTHON", "G1_MODEL_SERVER")):
        raise ValueError("required_interpreter_or_binary_not_executable")
    model_digest = file_sha(p["G1_MODEL_PATH"])
    if model_digest != MODEL_SHA256:
        raise ValueError("model_digest_mismatch")
    typed = p["G1_TYPED_READS_ROOT"]
    if sha((typed / "typed_reads.py").read_bytes() + (typed / "programs.py").read_bytes()) != TYPED_PROGRAM_DIGEST:
        raise ValueError("reviewed_typed_program_digest_mismatch")
    return {"files": [{"path": str(path), "sha256": model_digest if path == p["G1_MODEL_PATH"] else file_sha(path),
                       "bytes": path.stat().st_size} for path in required], "model_digest_verified": True}


def prepare_source(p, env):
    import yaml
    dest = p["G1_LOG_DIR"] / "runtime-source"
    if dest.exists():
        raise ValueError("runtime_source_already_exists")
    before = {}
    for folder in ("aios", "runtime"):
        shutil.copytree(p["G1_SOURCE_ROOT"] / folder, dest / folder,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for path in dest.rglob("*"):
        if path.is_file():
            before[str(path.relative_to(dest))] = file_sha(path)
    config_path = dest / "aios/config/config.yaml"
    config = yaml.safe_load(config_path.read_text())
    config["llms"]["models"] = [{"name": MODEL_NAME, "backend": "vllm",
        "hostname": f"http://127.0.0.1:{MODEL_PORT}/v1", "api_key": "local-only"}]
    config["storage"]["root_dir"] = str(p["G1_LOG_DIR"] / "storage")
    config["tool"]["mcp_server_script_path"] = str(p["G1_LOG_DIR"] / "optional_desktop_mcp_disabled.py")
    config["server"] = {"host": "127.0.0.1", "port": KERNEL_PORT}
    config_path.write_text(yaml.safe_dump(config, sort_keys=False))
    hook = dest / "aios/hooks/modules/tool.py"
    original = hook.read_text()
    marker = "from aios.tool.competition_manager import CompetitionToolManager as ToolManager"
    if original.count(marker) != 1:
        raise ValueError("pinned_aios_tool_hook_changed")
    hook.write_text(original.replace(marker, "from g1_tool_manager import G1ToolManager as ToolManager"))
    changes = [{"path": name, "before_sha256": digest, "after_sha256": file_sha(dest / name)}
               for name, digest in before.items() if file_sha(dest / name) != digest]
    if {item["path"] for item in changes} != {"aios/config/config.yaml", "aios/hooks/modules/tool.py"}:
        raise ValueError("unexpected_runtime_source_change")
    write_json(p["G1_LOG_DIR"] / "g1-runtime-source-diff.json",
               {"copied_files": len(before), "changes": changes, "frozen_source_modified": False})
    env["G1_RUNTIME_SOURCE"] = str(dest)
    env["PYTHONPATH"] = ":".join(map(str, (ROOT, dest, p["G1_SDK_ROOT"], p["G1_TYPED_READS_ROOT"])))
    return dest


def listening(port):
    with socket.socket() as probe:
        probe.settimeout(0.2)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def cgroup_observation():
    result = {}
    for key in ("memory.current", "memory.peak", "memory.max", "memory.events", "memory.pressure", "cpu.pressure"):
        try:
            raw = (Path("/sys/fs/cgroup") / key).read_text().strip()
            result[key] = int(raw) if raw.isdigit() else raw
        except OSError:
            result[key] = None
    return result


def process_observation(groups):
    items = []
    for folder in Path("/proc").iterdir():
        if not folder.name.isdigit():
            continue
        try:
            raw = (folder / "stat").read_text()
            fields = raw[raw.rfind(")") + 2:].split()
            pgid, process_state = int(fields[2]), fields[0]
            if pgid not in groups and int(folder.name) != os.getpid():
                continue
            memory = {}
            for line in (folder / "status").read_text().splitlines():
                fields = line.split()
                if fields and fields[0] in {"VmRSS:", "VmHWM:"}:
                    memory[fields[0].rstrip(":")] = int(fields[1]) * 1024
            items.append({"pid": int(folder.name), "pgid": pgid, "state": process_state, **memory})
        except (OSError, ValueError, IndexError):
            continue
    return items


class OwnedProcesses:
    def __init__(self, log, env):
        self.log, self.env = log, env
        self.children, self.handles = [], []
        self.stop = threading.Event()
        self.samples = []
        self.watcher = threading.Thread(target=self.monitor, daemon=True)
        self.watcher.start()

    def launch(self, name, argv, cwd=ROOT):
        handle = (self.log / ("g1-" + name + ".log")).open("w")
        self.handles.append(handle)
        child = subprocess.Popen(list(map(str, argv)), cwd=cwd, env=self.env,
            stdout=handle, stderr=subprocess.STDOUT, start_new_session=True)
        self.children.append((name, child))
        return child

    def run(self, name, argv, seconds):
        child = self.launch(name, argv)
        child.wait(timeout=seconds)
        if child.returncode:
            raise RuntimeError(name + "_failed")

    def monitor(self):
        while not self.stop.is_set():
            sample = {"monotonic_ns": time.monotonic_ns(), "cgroup": cgroup_observation(),
                      "processes": process_observation({p.pid for _, p in self.children})}
            self.samples.append(sample)
            with (self.log / "g1-resource-samples.jsonl").open("a") as output:
                output.write(json.dumps(sample) + "\n")
            self.stop.wait(1)

    def ready(self, url, child, seconds):
        deadline = time.monotonic() + seconds
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeError("owned_service_exited_before_readiness")
            try:
                with opener.open(url, timeout=2) as response:
                    value = json.load(response)
                if value.get("status") == "ok":
                    return value
            except Exception:
                pass
            self.stop.wait(0.25)
        raise TimeoutError("owned_service_readiness_deadline")

    def close(self):
        forced, errors = [], []
        for name, child in reversed(self.children):
            try:
                # A departed group leader may have left a native worker alive.
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError as error:
                errors.append({"name": name, "stage": "term", "error_type": type(error).__name__})
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError as error:
                    errors.append({"name": name, "stage": "kill", "error_type": type(error).__name__})
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    errors.append({"name": name, "stage": "reap", "error_type": "TimeoutExpired"})
                forced.append(name)
        groups = {p.pid for _, p in self.children}
        deadline = time.monotonic() + 2
        wait = threading.Event()
        remaining = []
        while True:
            remaining = [x for x in process_observation(groups) if x["pgid"] in groups]
            active = [x for x in remaining if x["state"] not in {"Z", "X"}]
            if not active or time.monotonic() >= deadline:
                break
            for group in {x["pgid"] for x in active}:
                try:
                    os.killpg(group, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError as error:
                    errors.append({"pgid": group, "stage": "descendant_kill", "error_type": type(error).__name__})
            wait.wait(0.05)
        self.stop.set()
        self.watcher.join(timeout=3)
        for handle in self.handles:
            handle.close()
        rss = [sum(p.get("VmRSS", 0) for p in sample["processes"])
               for sample in self.samples if any("VmRSS" in p for p in sample["processes"])]
        return {"all_owned_processes_reaped": all(p.poll() is not None for _, p in self.children) and not remaining,
                "all_owned_direct_children_reaped": all(p.poll() is not None for _, p in self.children),
                "owned_descendant_activity_stopped": not active,
                "remaining_owned_processes": remaining, "cleanup_errors": errors,
                "owned_ports_closed": not any(listening(port) for port in (MODEL_PORT, KERNEL_PORT)),
                "forced_kill": forced, "processes": [{"name": n, "exit_code": p.returncode} for n, p in self.children],
                "sampled_sum_rss_peak_bytes": max(rss) if rss else None,
                "rss_note": "Sampled sum includes shared pages more than once; not cgroup usage",
                "container_memory": cgroup_observation(),
                "memory_peak_scope": "Container lifetime peak, when exposed; null means not measured"}


def preflight(p):
    log = p["G1_LOG_DIR"]
    env = base_environment(p)
    result = {"scope": "container_materials_and_imports_only", "passed": False,
              "model_requests": 0, "native_business_called": False}
    owner = OwnedProcesses(log, env)
    try:
        result["materials"] = check_materials(p)
        owner.run("preflight-imports", [p["G1_AIOS_PYTHON"], "-B", ROOT / "g1_preflight.py"], 180)
        native_code = "import sys;sys.path.insert(0,sys.argv[1]);from native_transport import check_client_versions;print(check_client_versions())"
        owner.run("preflight-native", [p["G1_NATIVE_PYTHON"], "-c", native_code, p["G1_NATIVE_ADAPTER_ROOT"]], 30)
        owner.run("preflight-binary", [p["G1_MODEL_SERVER"], "--version"], 30)
        result["passed"] = True
    except Exception as error:
        result["error"] = {"type": type(error).__name__, "code": str(error) if isinstance(error, ValueError) else "preflight_failed"}
    finally:
        result["cleanup"] = owner.close()
        write_json(log / "g1-preflight.json", result)
    return 0 if result["passed"] else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args()
    p = paths()
    log = p["G1_LOG_DIR"]
    log.mkdir(parents=True, exist_ok=True)
    if args.preflight:
        return preflight(p)
    result_path = log / "g1-agent-result.json"
    if result_path.exists():
        print("g1_result_already_exists", file=sys.stderr)
        return 2
    started = time.monotonic()
    state = {"scope": "G1 real SDK-AIOS-model and filtered native read prerequisite",
             "passed": False, "model_requests_observed": 0, "native_business_called": False,
             "complete_public_snapshot": False, "submit_calls": 0, "business_recovery_success": None,
             "performance_comparison": False, "automatic_driver_retries": 0}
    owner = None
    try:
        ctx = launcher_context()
        state["attempt_id"] = ctx["G1_ATTEMPT_ID"]
        state["boundary"] = wait_boundary(log, ctx)
        state["materials"] = check_materials(p)
        env = base_environment(p)
        env.update(ctx)
        owner = OwnedProcesses(log, env)
        # Discovery uses the independent pinned native worker, never a host kubeconfig.
        owner.run("native-discovery", [p["G1_NATIVE_PYTHON"], "-B", ROOT / "g1_native_worker.py", "discover"], 210)
        discovery = json.loads((log / "g1-native-discovery.json").read_text())
        context = {"attempt_id": ctx["G1_ATTEMPT_ID"], "role": ctx["G1_ROLE"], "namespace": ctx["G1_NAMESPACE"],
                   "world_epoch": ctx["G1_WORLD_EPOCH"], "app_info_sha256": discovery["app_info_sha256"],
                   "evidence_dir": str(log / "public-evidence"), "native_boundary_verified": True,
                   "evidence_level": "native_filtered_execution"}
        write_json(log / "g1-attempt-context.json", context)
        env["G1_CONTEXT_FILE"] = str(log / "g1-attempt-context.json")
        runtime = prepare_source(p, env)
        owner.run("sdk-registration", [p["G1_AIOS_PYTHON"], "-B", ROOT / "g1_register_tools.py"], 90)
        if any(listening(port) for port in (MODEL_PORT, KERNEL_PORT)):
            raise ValueError("reserved_loopback_port_already_used")
        model = owner.launch("model", [p["G1_MODEL_SERVER"], "--model", p["G1_MODEL_PATH"], "--alias", MODEL_NAME,
            "--host", "127.0.0.1", "--port", MODEL_PORT, "--ctx-size", 2048, "--parallel", 1,
            "--threads", 4, "--threads-batch", 4, "--batch-size", 256, "--ubatch-size", 128,
            "--n-gpu-layers", 0, "--no-repack", "--fit", "off", "--jinja", "--reasoning", "off",
            "--chat-template-kwargs", '{"enable_thinking":false}', "--cache-ram", 0, "--no-warmup", "--no-webui"])
        owner.ready(f"http://127.0.0.1:{MODEL_PORT}/health", model, 180)
        kernel = owner.launch("kernel", [p["G1_AIOS_PYTHON"], "-B", ROOT / "g1_kernel.py"], runtime)
        owner.ready(f"http://127.0.0.1:{KERNEL_PORT}/status", kernel, 180)
        owner.run("sdk-client", [p["G1_AIOS_PYTHON"], "-B", ROOT / "g1_sdk_client.py"], 900)
        client = json.loads((log / "g1-sdk-client-result.json").read_text())
        state["client"] = client
        state["complete_public_snapshot"] = client.get("complete_public_snapshot") is True
        state["completeness_scope"] = client.get("completeness_scope")
        state["passed"] = client.get("passed") is True
    except Exception as error:
        state["error"] = {"type": type(error).__name__, "code": str(error) if isinstance(error, (ValueError, RuntimeError, TimeoutError)) else "entry_failed"}
    finally:
        state["cleanup"] = owner.close() if owner else {
            "all_owned_processes_reaped": True, "owned_ports_closed": None,
            "processes_started": 0, "sampled_sum_rss_peak_bytes": None, "container_memory": cgroup_observation()}
        audit_errors = []
        def read_journal(path):
            records = []
            try:
                for number, line in enumerate(path.read_text().splitlines(), 1):
                    try:
                        record = json.loads(line)
                        if not isinstance(record, dict):
                            raise ValueError("journal_record_not_object")
                        records.append(record)
                    except ValueError:
                        audit_errors.append({"path": str(path), "line": number, "error": "invalid_json_record"})
            except OSError:
                audit_errors.append({"path": str(path), "error": "journal_unreadable"})
            return records
        if (log / "g1-kernel-events.jsonl").exists():
            events = read_journal(log / "g1-kernel-events.jsonl")
            state["aios_model_adapter_calls"] = sum(e["event"] == "call" and e["function"] == "LLMAdapter._get_model_response" for e in events)
            state["aios_tool_manager_calls"] = sum(e["event"] == "call" and e["function"] == "SafeToolManager.address_request" for e in events)
        else:
            state["aios_model_adapter_calls"] = state["aios_tool_manager_calls"] = 0
        if (log / "g1-model.log").exists():
            state["model_requests_observed"] = (log / "g1-model.log").read_text().count("| processing task, is_child = 0")
        dispatches, returned = 0, 0
        for journal in (log / "native_trace").rglob("*.jsonl"):
            records = read_journal(journal)
            if sum(r.get("event") == "start" for r in records) != 1 or sum(r.get("event") == "end" for r in records) != 1:
                audit_errors.append({"path": str(journal), "error": "native_call_journal_not_terminal"})
            for record in records:
                if record.get("event") == "end" and record.get("operation") == "kubectl":
                    dispatches += record.get("dispatch_started") is True
                    returned += record.get("transport_state") == "response_received"
                if record.get("event") == "start" and record.get("operation") == "submit":
                    state["submit_calls"] += 1
        state["native_business_calls_dispatched"] = dispatches
        state["native_business_calls_returned"] = returned
        state["native_business_called"] = dispatches > 0
        state["evidence_audit_errors"] = audit_errors
        cleanup = state["cleanup"]
        state["passed"] = bool(state["passed"] and state["model_requests_observed"] == 1
            and state["aios_model_adapter_calls"] == 1 and state["aios_tool_manager_calls"] > 0
            and dispatches > 0 and returned == dispatches and state["submit_calls"] == 0
            and cleanup["all_owned_processes_reaped"] and cleanup["owned_ports_closed"] is True
            and not cleanup.get("cleanup_errors") and not audit_errors)
        state["elapsed_seconds_including_boundary_wait_startup_cleanup"] = time.monotonic() - started
        write_json(result_path, state)
        print(json.dumps({key: state[key] for key in ("scope", "passed", "model_requests_observed", "native_business_called", "complete_public_snapshot", "submit_calls")}))
    return 0 if state["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
