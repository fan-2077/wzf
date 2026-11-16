"""Register reviewed reads with the existing AIOS SafeToolManager only."""
import os
from aios.scheduler.competition_extension import SafeToolManager, ToolPolicyRegistry, ToolAccess
from g1_common import AUTHOR, TOOLS, validate_arguments


class RestrictedRegistry(ToolPolicyRegistry):
    def resolve(self, name, parameters):
        if name not in {AUTHOR + "/" + tool for tool in TOOLS}:
            raise ValueError("G1 probe permits only its four registered typed reads")
        tool = name.split("/", 1)[1]
        validate_arguments(tool, parameters)
        return ToolAccess(reads=("sregym:attempt:" + os.environ["G1_ATTEMPT_ID"],))


class G1ToolManager(SafeToolManager):
    def __init__(self, log_mode="console"):
        super().__init__(log_mode=log_mode, policy_registry=RestrictedRegistry())
