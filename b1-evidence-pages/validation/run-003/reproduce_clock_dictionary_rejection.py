"""Preserved old rejection; only a public clock projection has real provenance."""
import hashlib
import importlib.util
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
source = HERE / "PUBLIC_EVIDENCE_PREIMAGE.py"
spec = importlib.util.spec_from_file_location("pages_before_clock_fix", source)
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)
clock_file = ROOT / "tests" / "fixtures" / "b0-public-clock-identity.json"
clock = json.loads(clock_file.read_bytes())
identity = {
    "attempt_id": "controlled-local-attempt-a",
    "physical_scope_id": "controlled-local-scope",
    "ledger_epoch": "controlled-local-ledger",
    "namespace_uid": "controlled-local-namespace",
    "role": "single",
    "launch_context_sha256": evidence.digest(b"local fixture launch identity"),
    "derived_payload_binding_sha256": evidence.digest(b"local fixture source identity"),
    "clock_identity": clock,
    "incident_visible_mono": 0.0,
    "original_budgets": {"fixture_only": "no_incident_or_model_budget_selected"},
}
print(json.dumps({
    "scope": "old_validator_real_public_clock_projection_only",
    "original_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    "clock_projection_sha256": hashlib.sha256(clock_file.read_bytes()).hexdigest(),
    "clock_identity": clock,
    "other_identity_fields": "controlled_fixture_not_original_launch_context",
    "role_single_is_synthetic": True,
    "model_calls": 0,
    "native_business_calls": 0,
}, sort_keys=True), flush=True)
# Deliberately preserve the original exception and non-zero process exit.
evidence.validate_identity(identity)
raise RuntimeError("the preserved old clock dictionary rejection was not reproduced")
