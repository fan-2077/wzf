"""Seal evidence after the independent workflow cleanup step, including failure."""
import hashlib
import json
import os
from pathlib import Path


def main():
    root = Path(os.environ["GITHUB_WORKSPACE"]) / "g1-results"
    root.mkdir(exist_ok=True)
    def read(name):
        p = root / name
        return json.loads(p.read_text()) if p.is_file() else {}
    run = read("g1-execution-summary.json")
    cleanup = read("workflow-fallback-cleanup.json")
    verdict = {"scope": "unscored original G1 read connection",
               "remote_smoke_pass": run.get("smoke_pass") is True,
               "runner_cleanup_verified": run.get("cleanup_verified") is True,
               "extra_cleanup_verified": run.get("extra_cleanup_verified") is True,
               "workflow_fallback_cleanup_verified": cleanup.get("passed") is True,
               "source_inputs_unchanged": run.get("source_inputs_unchanged") is True,
               "no_execution_or_cleanup_error": not run.get("error") and not run.get("cleanup_error")
                                                and not run.get("extra_cleanup_error"),
               "agent_recovery_success": None,
               "formal_competition_result": False,
               "timing_comparison": False}
    verdict["passed"] = all(verdict[k] for k in (
        "remote_smoke_pass", "runner_cleanup_verified", "extra_cleanup_verified",
        "workflow_fallback_cleanup_verified", "source_inputs_unchanged", "no_execution_or_cleanup_error"))
    (root / "FINAL_REMOTE_VERDICT.json").write_text(json.dumps(verdict, indent=2) + "\n")
    files = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and p != root / "ARTIFACT_MANIFEST.json":
            files[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    (root / "ARTIFACT_MANIFEST.json").write_text(json.dumps({"files": files,
        "scope": "all final execution evidence after workflow fallback cleanup"}, indent=2) + "\n")
    print(json.dumps(verdict))
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
