"""No-endpoint, no-model inference import check executed in the AIOS venv."""
import importlib
import json
import sys


def no_network(event, args):
    if event in {"socket.connect", "socket.getaddrinfo"}:
        raise PermissionError("Preflight does not connect to model or business services")


sys.addaudithook(no_network)
loaded = []
for name in ("cerebrum.llm.apis", "cerebrum.tool.apis", "cerebrum.interface",
             "aios.scheduler.competition_llm_extension", "aios.llm_core.adapter",
             "g1_tool_manager", "typed_reads"):
    importlib.import_module(name)
    loaded.append(name)
print(json.dumps({"passed": True, "loaded": loaded, "model_requests": 0, "business_calls": 0}))
