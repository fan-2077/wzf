"""Observe, but do not replace, native AIOS scheduler/model/tool execution."""
import json
import logging
import os
from pathlib import Path
import runpy
import sys
import threading
import time
from g1_common import MODEL_PORT, KERNEL_PORT

LOG = Path(os.environ["G1_LOG_DIR"])
SOURCE = Path(os.environ["G1_RUNTIME_SOURCE"])
LOCK = threading.Lock()
WATCH = {"handle_query", "execute_request", "_execute_syscall", "_run_llm",
         "execute_llm_syscalls", "execute_llm_syscall", "_get_model_response",
         "address_request", "_run_one", "load_tool_instance", "run"}


def append(name, item):
    with LOCK:
        with (LOG / name).open("a") as target:
            target.write(json.dumps(item, ensure_ascii=True) + "\n")


def audit(event, args):
    if event == "socket.getaddrinfo":
        host = args[0]
        if isinstance(host, bytes):
            host = host.decode("ascii", "replace")
        if host is not None and host not in {"127.0.0.1", "localhost", "::1"}:
            append("g1-kernel-network.jsonl", {"event": event, "allowed": False, "host": str(host)})
            raise PermissionError("AIOS kernel only uses the container loopback model service")
    elif event == "socket.connect":
        address = args[1]
        if isinstance(address, tuple) and len(address) >= 2:
            allowed = address[0] in {"127.0.0.1", "localhost", "::1"} and address[1] in {MODEL_PORT, KERNEL_PORT}
            append("g1-kernel-network.jsonl", {"event": event, "allowed": allowed,
                   "host": address[0], "port": address[1], "monotonic_ns": time.monotonic_ns()})
            if not allowed:
                raise PermissionError("AIOS kernel destination not allowed")


def observe(frame, event, arg):
    if event not in {"call", "return"} or frame.f_code.co_name not in WATCH:
        return
    source = frame.f_code.co_filename
    if not (source.startswith(str(SOURCE)) or source.startswith(os.environ["XDG_CACHE_HOME"])):
        return
    append("g1-kernel-events.jsonl", {"event": event, "module": frame.f_globals.get("__name__"),
        "function": frame.f_code.co_qualname, "source_file": source,
        "source_line": frame.f_code.co_firstlineno, "thread": threading.current_thread().name,
        "monotonic_ns": time.monotonic_ns()})


sys.addaudithook(audit)
import onnxruntime
onnxruntime.disable_telemetry_events()
logging.basicConfig(level=logging.INFO, force=True)
sys.setprofile(observe)
threading.setprofile(observe)
runpy.run_module("runtime.launch", run_name="__main__")
