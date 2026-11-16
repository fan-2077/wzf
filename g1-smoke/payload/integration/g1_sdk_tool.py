"""Actual Cerebrum package entry, with a separate pinned native MCP worker."""
import json
import os
from pathlib import Path
import subprocess
import time
import uuid
from g1_common import validate_arguments

TOOL_NAME = "read_recovery_inventory"


class Tool:
    def run(self, params):
        validate_arguments(TOOL_NAME, params)
        request_id = uuid.uuid4().hex
        request = {"tool": TOOL_NAME, "arguments": params, "request_id": request_id}
        interpreter, worker = Path(os.environ["G1_NATIVE_PYTHON"]), Path(os.environ["G1_NATIVE_WORKER"])
        if not interpreter.is_absolute() or not worker.is_absolute():
            raise ValueError("launcher_worker_paths_not_absolute")
        started = time.monotonic()
        try:
            result = subprocess.run([str(interpreter), "-B", str(worker), "read"],
                input=json.dumps(request), text=True, capture_output=True, timeout=360, check=False)
            if result.returncode != 0:
                raise RuntimeError("native_worker_nonzero_exit")
            payload = json.loads(result.stdout)
            if not isinstance(payload, dict):
                raise ValueError("native_worker_invalid_envelope")
        except Exception as error:
            # No retry and no stderr/exception text, which may contain secrets.
            payload = {"complete": False, "source_complete": False, "business_success": None,
                       "automatic_retries": 0, "error": {"code": "native_worker_failed",
                       "type": type(error).__name__}, "request_id": request_id}
        payload["driver_request_id"] = request_id
        payload["worker_inclusive_seconds"] = time.monotonic() - started
        return json.dumps(payload, ensure_ascii=False, allow_nan=False)
