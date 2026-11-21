"""Finite authoring checks; does not execute Docker or the 19 contract tests."""
import ast
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import sys
import tempfile

GATE = Path(__file__).resolve().parents[2]
ROOT = GATE.parent
sys.path.insert(0, str(GATE))
import gate_common as common
import run_contract_tests as inner
import yaml


checks = []


def record(name, **detail):
    checks.append(dict(name=name, passed=True, **detail))


for relative in ("gate_common.py", "run_contract_tests.py", "run_ci_gate.py"):
    ast.parse(common.read_bytes(GATE / relative), filename=relative)
ast.parse(inner.LAUNCHER, filename="controlled_runpy_launcher")
record("python_ast_and_child_launcher_parse", production_modules=3)

binding = common.read_json(GATE / "SOURCE_INPUT_BINDING.json")
source = ROOT / "b1-evidence-pages"
before = common.verify_tree(source, binding["component"]["manifest"]["sha256"], component=True)
assert len(before) == 33
record("fixed_component_manifest_and_33_files", component_manifest_sha256=before["SOURCE_MANIFEST.json"]["sha256"])

identifiers = common.expected_test_ids(source)
previous = common.read_json(source / "validation/run-004/TEST_RESULT.json")
assert identifiers == sorted(item["test"] for item in previous["tests"])
record("exact_19_test_ids_without_executing_tests", test_count=len(identifiers), test_ids=identifiers)

environment = {"GITHUB_REPOSITORY": common.REPOSITORY, "GITHUB_REF": common.REF,
    "GITHUB_RUN_ID": "123456789", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "a" * 40}
assert common.platform_identity(environment)["container_name"] == "b1-evidence-pages-123456789-1"
rejections = []
for field, value in (("GITHUB_REPOSITORY", "other/repository"), ("GITHUB_REF", "refs/heads/main"),
        ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_RUN_ATTEMPT", "0"), ("GITHUB_RUN_ATTEMPT", ""),
        ("GITHUB_RUN_ID", "0"), ("GITHUB_RUN_ID", "../1"), ("GITHUB_SHA", "x" * 40)):
    invalid = dict(environment)
    invalid[field] = value
    try:
        common.platform_identity(invalid)
    except ValueError as error:
        rejections.append({"field": field, "value": value, "error": str(error)})
    else:
        raise AssertionError("invalid platform identity accepted")
record("fixed_repo_branch_attempt1_validation", rejected_cases=rejections, docker_calls=0)

with tempfile.TemporaryDirectory(prefix="b1-pages-gate-authoring-") as temporary:
    inner.SOURCE = source
    inner.EXECUTION = Path(temporary) / "execution"
    copied = inner.prepare_execution_copy(before)
    assert copied == before
    for relative in before:
        assert stat.S_IMODE((inner.EXECUTION / relative).stat().st_mode) == 0o400
    for path in [inner.EXECUTION, *inner.EXECUTION.rglob("*")]:
        if path.is_dir():
            expected_mode = 0o700 if path == inner.EXECUTION / "validation/tmp" else 0o500
            assert stat.S_IMODE(path.stat().st_mode) == expected_mode
    record("execution_copy_bytes_and_permissions", files=len(copied), source_files_mode="0400",
        source_directories_mode="0500", test_tmp_mode="0700", tests_executed=0)
    target = inner.EXECUTION / "public_evidence.py"
    raw = target.read_bytes()
    target.chmod(0o600)
    target.write_bytes(raw + b"\n")
    try:
        common.verify_tree(inner.EXECUTION, before["SOURCE_MANIFEST.json"]["sha256"], component=True, ignore_test_tmp=True)
    except ValueError as error:
        assert str(error) == "full_source_tree_mismatch"
    else:
        raise AssertionError("changed execution source accepted")
    target.write_bytes(raw)
    target.chmod(0o400)
    assert common.verify_tree(inner.EXECUTION, before["SOURCE_MANIFEST.json"]["sha256"], component=True, ignore_test_tmp=True) == before
    record("modified_execution_copy_rejected", only_disposable_copy_changed=True, original_source_modified=False)

assert common.verify_tree(source, before["SOURCE_MANIFEST.json"]["sha256"], component=True) == before
record("original_component_stays_unchanged", files=33)

workflow = yaml.load(common.read_bytes(ROOT / common.WORKFLOW), Loader=yaml.BaseLoader)
assert set(workflow["on"]) == {"push"}
assert workflow["on"]["push"]["branches"] == [common.REF.removeprefix("refs/heads/")]
assert workflow["permissions"] == {"contents": "read"}
assert workflow["concurrency"]["cancel-in-progress"] == "false"
job = workflow["jobs"]["pagination-contracts"]
assert job["runs-on"] == "ubuntu-24.04" and job["timeout-minutes"] == "15"
assert [step["run"] for step in job["steps"] if "run" in step] == [
    "python3 -B b1-evidence-pages-gate/run_ci_gate.py " + operation for operation in ("run", "cleanup", "seal")]
record("workflow_yaml_and_fixed_scope", yaml_parser="PyYAML BaseLoader; syntax and fixed public fields only")

result = {"schema": "b1-evidence-pages-gate-local-authoring-checks-v1", "passed": True, "checks": checks,
    "checks_run": len(checks), "runtime": {"python": sys.version, "executable": sys.executable,
        "implementation": platform.python_implementation(), "uid": os.getuid(), "gid": os.getgid()},
    "docker_executable_found": shutil.which("docker"), "docker_executed": False, "original_19_tests_executed": 0,
    "fixed_python_3_11_17_qualified": False, "container_or_image_qualified": False,
    "model_calls": 0, "native_business_calls": 0, "actor_calls": 0, "original_task_runs": 0,
    "qualification_scope": "local_source_copy_permissions_identity_rejections_and_syntax_only"}
print(json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
