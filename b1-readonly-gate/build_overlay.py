#!/usr/bin/env python3
"""Build a reviewable derivative package; never edit or execute the frozen base."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import shutil

HERE = Path(__file__).resolve().parent
BASE_MANIFEST_SHA256 = "948a410a3ecc63954ad505df14dd0c9845742119c7f98a96da808d273a7bbfce"
BASE_REPOSITORY_COMMIT = "6592f1c4cfd4e73c7350047a49264b9e5c3182db"
BASE_BENCHMARK_COMMIT = "148dded7ca2737ded1085e7dc7bbf2a8fcfe7861"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def verified_base(base):
    manifest_path = base / "PACKAGE_MANIFEST.json"
    if sha(manifest_path) != BASE_MANIFEST_SHA256:
        raise ValueError("frozen_g1_manifest_changed")
    manifest = json.loads(manifest_path.read_text())
    if any(path.is_symlink() for path in base.rglob("*")):
        raise ValueError("frozen_g1_contains_symlink")
    actual = {str(path.relative_to(base)) for path in base.rglob("*") if path.is_file() and path != manifest_path}
    if actual != set(manifest["files"]):
        raise ValueError("frozen_g1_file_set_changed")
    for name, expected in manifest["files"].items():
        path = base / name
        if not path.resolve().is_relative_to(base) or sha(path) != expected:
            raise ValueError("frozen_g1_file_changed: " + name)
    return manifest


class Overlay:
    def __init__(self, destination):
        self.destination = destination
        self.changes = []

    def replace(self, relative, before, after, label):
        path = self.destination / relative
        raw = path.read_text()
        if raw.count(before) != 1:
            raise ValueError("overlay_anchor_not_unique: " + label)
        old_sha = sha(path)
        path.write_text(raw.replace(before, after, 1))
        self.changes.append({"path": relative, "purpose": label,
                             "before_sha256": old_sha, "after_sha256": sha(path)})

    def install(self, source_name, relative):
        target = self.destination / relative
        old_sha = sha(target) if target.exists() else None
        shutil.copyfile(HERE / source_name, target)
        self.changes.append({"path": relative, "purpose": "install_" + source_name,
                             "before_sha256": old_sha, "after_sha256": sha(target)})


def build(base, destination, branch):
    base, destination = Path(base).resolve(), Path(destination).resolve()
    if destination.exists() or destination.is_relative_to(base) or base.is_relative_to(destination):
        raise ValueError("overlay_destination_must_be_new_and_outside_frozen_base")
    if (not re.fullmatch(r"sre-b1-readonly-[a-z0-9][a-z0-9-]{0,70}", branch)
            or branch.endswith("-")):
        raise ValueError("explicit_dedicated_b1_readonly_branch_required")
    original = verified_base(base)
    shutil.copytree(base, destination)
    overlay = Overlay(destination)
    sdk_api = "payload/sdk/cerebrum/llm/apis.py"
    runtime = "payload/integration/source_terminal/runtime/launch.py"
    adapter = "payload/integration/source_terminal/aios/llm_core/adapter.py"
    entry = "payload/integration/agent_entry.py"

    overlay.install("b1_metering.py", "payload/integration/b1_metering.py")
    overlay.install("b1_sdk_client.py", "payload/integration/g1_sdk_client.py")
    overlay.replace(sdk_api, '    query_class: str = "llm"\n',
        '    query_class: str = "llm"\n    request_id: Optional[str] = Field(default=None)\n',
        "preserve_client_request_identity")
    overlay.replace(sdk_api, '    response_class: str = "llm"\n',
        '    response_class: str = "llm"\n    request_id: Optional[str] = None\n'
        '    usage: Optional[Dict[str, Any]] = None\n'
        '    model_metadata: Optional[Dict[str, Any]] = None\n',
        "preserve_provider_usage_and_response_binding")
    overlay.replace("payload/sdk/cerebrum/utils/communication.py",
        '    response = requests.post(f"{base_url}{endpoint}", json=data)\n'
        '    response.raise_for_status()\n    return response.json()\n',
        '    from b1_metering import sdk_post\n    return sdk_post(base_url, endpoint, data)\n',
        "bound_and_record_real_sdk_http_without_retries")
    overlay.replace(runtime, '            query = LLMQuery(\n                llms=query_required_llms,',
        '            query = LLMQuery(\n                request_id=request.query_data.request_id,\n'
        '                llms=query_required_llms,', "retain_request_identity_through_kernel_reconstruction")
    overlay.replace(adapter, 'from cerebrum.llm.apis import LLMQuery, LLMResponse\n',
        'from cerebrum.llm.apis import LLMQuery, LLMResponse\n'
        'from b1_metering import build_local_client, metered_create, attach_metering\n',
        "import_real_backend_metering")
    overlay.replace(adapter,
        '                    return OpenAI(\n                        base_url=config.hostname,\n'
        '                        api_key=config.api_key or "sk-placeholder" # Use provided key or a placeholder\n'
        '                    )',
        '                    return build_local_client(\n                        base_url=config.hostname,\n'
        '                        api_key=config.api_key\n                    )',
        "same_openai_compatible_backend_local_only_zero_retries")
    overlay.replace(adapter,
        '                    response = model.chat.completions.create(\n'
        '                        model=model_name, # Pass the specific model name if needed by the endpoint\n'
        '                        **completion_kwargs\n                    )',
        '                    response = metered_create(model, llm_syscall.query, model_name, completion_kwargs)',
        "record_actual_backend_request_and_response_body")
    overlay.replace(adapter,
        '                return (llm_syscall, self._handle_completion_error(e, model_name))',
        '                return (llm_syscall, attach_metering(self._handle_completion_error(e, model_name), llm_syscall.query))',
        "return_available_usage_even_on_backend_error")
    overlay.replace(adapter, '                return (llm_syscall, processed_response)',
        '                return (llm_syscall, attach_metering(processed_response, llm_syscall.query))',
        "return_raw_usage_through_real_sdk_response")

    overlay.replace(entry, 'import urllib.request\n',
        'import urllib.request\nfrom b1_metering import read_summary\n', "independent_parent_accounting_check")
    overlay.replace(entry, '"scope": "G1 real SDK-AIOS-model and filtered native read prerequisite"',
        '"scope": "B1 readonly three-turn SDK-AIOS feedback qualification; not a recovery baseline"',
        "label_engineering_scope")
    overlay.replace(entry, '"--ctx-size", 2048,', '"--ctx-size", 4096,',
        "explicit_b1_feedback_context_profile_not_comparable_timing")
    overlay.replace(entry, '        cleanup = state["cleanup"]\n',
        '        cleanup = state["cleanup"]\n'
        '        state["model_request_accounting"] = read_summary(log)\n',
        "reopen_budget_and_hash_raw_bodies_after_owned_process_cleanup")
    overlay.replace(entry,
        '        state["passed"] = bool(state["passed"] and state["model_requests_observed"] == 1\n'
        '            and state["aios_model_adapter_calls"] == 1 and state["aios_tool_manager_calls"] > 0',
        '        state["passed"] = bool(state["passed"] and state["model_requests_observed"] == 3\n'
        '            and state["aios_model_adapter_calls"] == 3 and state["aios_tool_manager_calls"] > 0\n'
        '            and state.get("client", {}).get("feedback_binding_verified") is True\n'
        '            and state["model_request_accounting"].get("raw_model_io_complete") is True\n'
        '            and state["model_request_accounting"].get("reserved_model_requests") == 3\n'
        '            and not state["model_request_accounting"].get("usage_budget_violations", [])',
        "require_three_real_requests_and_bound_feedback_and_complete_raw_evidence")
    overlay.replace("native_g1_entry.py", '"scope": "unscored_read_only_native_integration"',
        '"scope": "b1_readonly_feedback_engineering_qualification"', "host_scope_label")
    overlay.replace("native_g1_entry.py", '"GITHUB_REF": "refs/heads/sre-g1-connection-20261116"',
        '"GITHUB_REF": "refs/heads/' + branch + '"', "native_host_exact_branch_binding")
    overlay.replace("native_g1_entry.py", 'and agent_result.get("model_requests_observed") == 1',
        'and agent_result.get("model_requests_observed") == 3\n'
        '                                    and agent_result.get("model_request_accounting", {}).get("raw_model_io_complete") is True\n'
        '                                    and agent_result.get("client", {}).get("feedback_binding_verified") is True',
        "host_requires_new_three_request_acceptance")
    overlay.replace("run_remote_smoke.py", 'infra.REF = "refs/heads/sre-g1-connection-20261116"',
        'infra.REF = "refs/heads/' + branch + '"', "explicit_future_branch_binding")
    overlay.replace("cleanup_owned.py", 'identity["GITHUB_REF"] != "refs/heads/sre-g1-connection-20261116"',
        'identity["GITHUB_REF"] != "refs/heads/' + branch + '"', "ownership_claim_exact_branch_binding")
    overlay.replace("export_owned_evidence.py", "G1_REF = 'refs/heads/sre-g1-connection-20261116'",
        "G1_REF = 'refs/heads/" + branch + "'", "evidence_export_exact_branch_binding")
    overlay.replace("seal_remote_evidence.py", "'scope': 'unscored original G1 read connection'",
        "'scope': 'unscored B1 readonly multi-turn feedback engineering qualification'",
        "formal_verdict_b1_engineering_scope")
    overlay.replace("run_remote_smoke.py", '"scope": "unscored_read_only_native_integration"',
        '"scope": "b1_readonly_feedback_engineering_qualification"', "runner_scope_label")
    overlay.replace("run_remote_smoke.py", '"checkout_scope": "only reviewed g1-smoke directory at triggering commit"',
        '"checkout_scope": "reviewed generated B1 readonly overlay at triggering commit"', "runner_package_label")
    overlay.replace("run_remote_smoke.py", 'data.get("agent_result", {}).get("model_requests_observed") == 1',
        'data.get("agent_result", {}).get("model_requests_observed") == 3', "runner_model_observation_count")

    plan_path = destination / "execution_plan.json"
    plan = json.loads(plan_path.read_text())
    plan.update({"prepared_date": "2026-11-19", "status": "local_overlay_prepared_remote_not_executed",
        "next_experiment": "B1 readonly multi-turn feedback and exact provider-usage plumbing qualification",
        "proposed_branch": branch, "proposed_workflow": None,
        "proposed_package_directory": "generated-b1-readonly-package",
        "publication_status": "not_published_by_overlay_builder",
        "remote_authorization_status": "no_remote_action_taken_by_overlay_builder",
        "whole_workflow_timeout_minutes": 96,
        "maximum_model_requests": 3, "maximum_generated_tokens": 576,
        "maximum_generated_tokens_per_request": 192, "maximum_sdk_requests": 1027,
        "sdk_client_deadline_seconds": 900, "backend_request_timeout_seconds": 180,
        "maximum_serialized_input_bytes_per_request": 16000,
        "automatic_model_and_sdk_retries": 0, "reservation_refunds": False,
        "model_feedback": "Actual public-document digest, row counts and declared coverage projection; full document retained but not sent to model",
        "usage_policy": "Provider original JSON retained and transmitted; absent fields remain null/unknown; no token estimation",
        "acceptance": ["all original native boundary and no-submission protections remain active",
            "exactly three real SDK LLMQuery calls reach original AIOS adapter and pinned local model",
            "two complete original public documents arrive via real SDK ToolQuery and original filtered native worker",
            "next actual model requests contain declared projections of those documents",
            "second and third model responses reproduce the immediately preceding digest and row counts",
            "every attempted SDK/backend request retains actual HTTP application body; missing responses make qualification fail",
            "raw provider usage, including null when absent, survives SDK response",
            "budget reservations are durable before dispatch; unknown or disconnected calls retain their slots",
            "host observes zero submits and completes original owned cleanup"],
        "baseline_warning": "Engineering gate only; neither a strong B1 solver nor a recovery or efficiency score. The 4096 context profile differs from original G1."})
    plan["model"]["context_tokens"] = 4096
    old_plan_sha = sha(plan_path)
    write_json(plan_path, plan)
    overlay.changes.append({"path": "execution_plan.json", "purpose": "declare_exact_new_qualification_profile",
                            "before_sha256": old_plan_sha, "after_sha256": sha(plan_path)})

    parsed = 0
    syntax_paths = sorted({item["path"] for item in overlay.changes if item["path"].endswith(".py")})
    for relative in syntax_paths:
        path = destination / relative
        ast.parse(path.read_bytes(), filename=str(path))
        parsed += 1
    provenance = {"scope": "generated_source_only_not_executed", "base_repository_commit": BASE_REPOSITORY_COMMIT,
        "base_benchmark_commit": BASE_BENCHMARK_COMMIT, "base_manifest_sha256": BASE_MANIFEST_SHA256,
        "base_file_count": len(original["files"]), "parsed_python_files": parsed,
        "python_syntax_scope": "only added or modified Python files; not full dependency import qualification",
        "python_syntax_paths": syntax_paths,
        "changes": overlay.changes,
        "overlay_source_sha256": {name: sha(HERE / name) for name in (
            "build_overlay.py", "b1_metering.py", "b1_sdk_client.py")},
        "unmodified_original_paths": [name for name in original["files"] if sha(destination / name) == original["files"][name]],
        "base_unchanged_after_build": verified_base(base) == original,
        "model_api_called": False, "remote_executed": False}
    write_json(destination / "OVERLAY_MANIFEST.json", provenance)
    write_json(destination / "PACKAGE_MANIFEST.json", {
        "scope": "B1 readonly overlay source package; local preparation is not model qualification",
        "excluded": original["excluded"],
        "files": {str(path.relative_to(destination)): sha(path) for path in sorted(destination.rglob("*"))
                  if path.is_file() and path != destination / "PACKAGE_MANIFEST.json"}})
    return {"destination": str(destination), "base_manifest_sha256": BASE_MANIFEST_SHA256,
            "generated_manifest_sha256": sha(destination / "PACKAGE_MANIFEST.json"),
            "changed_original_files": len({item["path"] for item in overlay.changes if item["before_sha256"]}),
            "python_files_parsed": parsed, "model_api_called": False, "remote_executed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=HERE.parent / "g1-smoke")
    parser.add_argument("--dest", type=Path, required=True)
    parser.add_argument("--branch", required=True, help="Future dedicated branch, beginning sre-b1-readonly-; builder never publishes it")
    args = parser.parse_args()
    print(json.dumps(build(args.base, args.dest, args.branch), indent=2))


if __name__ == "__main__":
    main()
