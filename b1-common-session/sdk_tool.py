"""Cerebrum Tool.run entry for a write-capable full macro and read-only polling.

This is a package entry only. Registration with AIOS and a write-capable policy
is deliberately not supplied by this local candidate.
"""
import json

from session_client import ClientError, HostConfiguration, SessionClient

TOOL_NAME = "full_recovery_session_start_poll"
TOOL_OPERATIONS = {"start": "business_write_full_macro", "poll": "read_only_session_status"}
TOOL_PARAMETER_SCHEMA = {
    "oneOf": [
        {"type": "object", "additionalProperties": False,
         "required": ["operation", "request_id", "parent_model_request_id"],
         "properties": {"operation": {"const": "start"},
                        "request_id": {"type": "string", "pattern": "^[0-9a-f]{32}$"},
                        "parent_model_request_id": {"type": ["string", "null"],
                                                    "pattern": "^[0-9a-f]{32}$"}}},
        {"type": "object", "additionalProperties": False,
         "required": ["operation", "request_id", "helper_id"],
         "properties": {"operation": {"const": "poll"},
                        "request_id": {"type": "string", "pattern": "^[0-9a-f]{32}$"},
                        "helper_id": {"type": "string", "pattern": "^full-[0-9a-f]{64}$"}}},
    ]
}


class Tool:
    def run(self, params):
        try:
            result = SessionClient(HostConfiguration.from_environment()).invoke(params)
        except (ClientError, OSError, ValueError) as error:
            result = {
                "scope": "local_full_macro_sdk_adapter_not_remote_qualified",
                "transport_state": "not_dispatched_or_receipt_unavailable",
                "automatic_retries": 0, "budget_refund": False,
                "business_success": None, "original_host_evaluation_result": None,
                "model_causality_verified": False,
                "error": {"code": str(error) if isinstance(error, ClientError) else "sdk_adapter_unavailable",
                          "type": type(error).__name__},
            }
        return json.dumps(result, ensure_ascii=False, allow_nan=False)
