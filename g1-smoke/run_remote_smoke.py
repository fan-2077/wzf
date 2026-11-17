#!/usr/bin/env python3
"""Bounded original G1 read-only integration on a dedicated hosted runner.

This file is prepared locally, not an authorization to publish or execute it.
The reused host module only provisions and cleans this run's original cluster.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sys
import time
import traceback

import native_host_runtime as infra
import cleanup_owned

HERE = Path(__file__).resolve().parent
MODEL = "Qwen3-8B-Q4_K_M.gguf"
MODEL_SHA = "d98cdcbd03e17ce47681435b5150e34c1417f50b5c0019dd560e4882c5745785"
MODEL_BYTES = 5027783488
MODEL_URL = "https://huggingface.co/Qwen/Qwen3-8B-GGUF/resolve/7c41481f57cb95916b40956ab2f0b139b296d974/" + MODEL


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def verify_package():
    manifest = json.loads((HERE / "PACKAGE_MANIFEST.json").read_text())
    actual = {str(p.relative_to(HERE)) for p in HERE.rglob("*") if p.is_file() and p != HERE / "PACKAGE_MANIFEST.json"}
    if actual != set(manifest["files"]):
        raise RuntimeError("Reviewed package file set differs from manifest")
    if any(p.is_symlink() for p in HERE.rglob("*")):
        raise RuntimeError("Symlinks are not admitted in the reviewed package")
    for name, expected in manifest["files"].items():
        raw = HERE / name
        p = raw.resolve()
        if raw.is_symlink() or not p.is_relative_to(HERE) or not p.is_file() or sha(p) != expected:
            raise RuntimeError("Reviewed package file mismatch: " + name)
    return sha(HERE / "PACKAGE_MANIFEST.json")


def configure():
    infra.REF = "refs/heads/sre-g1-connection-20261116"
    infra.RESULTS = Path(os.environ["GITHUB_WORKSPACE"]) / "g1-results"
    infra.START = time.monotonic()
    infra.DEADLINE = infra.START + 78 * 60
    infra.STATE.clear()
    infra.STATE.update({"scope": "unscored_read_only_native_integration", "source_commit": infra.COMMIT,
                        "task": infra.TASK, "profile": "full", "deploy_loki": False,
                        "agent_executed": False, "model_executed": False,
                        "user_repository_checked_out": True,
                        "checkout_scope": "only reviewed g1-smoke directory at triggering commit",
                        "cluster_creation_attempted": False, "ownership_initialized": False,
                        "cleanup_verified": False, "commands": [], "smoke_pass": False,
                        "agent_recovery_success": None})
    infra.guard()
    if os.environ.get("GITHUB_RUN_ATTEMPT") != "1":
        raise RuntimeError("This package admits one initial run only; no automatic rerun")
    infra.STATE["reviewed_package_manifest_sha256"] = verify_package()
    infra.RESULTS.mkdir(exist_ok=False)


def build_image():
    context = infra.WORK / "image-context"
    context.mkdir()
    shutil.copytree(HERE / "payload", context / "payload")
    shutil.copyfile(HERE / "Dockerfile", context / "Dockerfile")
    models = context / "models"
    models.mkdir()
    weight = models / MODEL
    infra.command("download_fixed_public_model", ["curl", "--fail", "--location", "--max-time", "600",
                                                  "--output", str(weight), MODEL_URL], timeout=630)
    if weight.stat().st_size != MODEL_BYTES or sha(weight) != MODEL_SHA:
        raise RuntimeError("Exact model weight verification failed")
    infra.STATE["model_weights"] = {"url": MODEL_URL, "bytes": MODEL_BYTES, "sha256": MODEL_SHA}
    image = "sre-g1-connection:" + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    base_tag = "python:3.11.17-slim-trixie"
    infra.command("resolve_official_python_base", ["docker", "pull", base_tag], timeout=240)
    _, digests = infra.command("python_base_digests", ["docker", "image", "inspect", base_tag,
                                                       "--format", "{{json .RepoDigests}}"])
    candidates = json.loads(digests)
    base = next((x for x in candidates if re.fullmatch(r"(?:docker.io/library/)?python@sha256:[0-9a-f]{64}", x)), None)
    if base is None:
        raise RuntimeError("Cannot freeze the official Python base image identity")
    infra.STATE["resolved_python_base_image"] = base
    infra.command("build_isolated_agent_image", ["docker", "build", "--progress=plain", "--build-arg", "PYTHON_IMAGE=" + base,
                                                  "--tag", image, str(context)],
                  timeout=1800)
    _, identity = infra.command("agent_image_identity", ["docker", "image", "inspect", image, "--format", "{{.Id}}"])
    infra.STATE["agent_image"], infra.STATE["agent_image_id"] = image, identity.strip()
    infra.command("agent_image_metadata", ["docker", "image", "inspect", image])
    # No model inference, incident observation, or external runtime request here.
    preflight_dir = infra.RESULTS / "image-preflight"
    preflight_dir.mkdir()
    preflight_name = "g1-image-preflight-" + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    infra.command("image_import_preflight", ["docker", "run", "--rm", "--name", preflight_name, "--network=none", "--cpus=4", "--memory=8g",
                                             "--cap-drop=ALL", "--cap-add=DAC_OVERRIDE", "--security-opt=no-new-privileges",
                                             "-v", str(preflight_dir) + ":/logs", image,
                                             "/opt/aios/bin/python -B /opt/g1/integration/agent_entry.py --preflight"], timeout=180)
    infra.ENV.update(G1_AGENT_IMAGE=image, G1_AGENT_IMAGE_ID=identity.strip(),
                     G1_RESULTS=str(infra.RESULTS / "native"), PYTHONPATH=str(infra.REPO))


def execute_smoke():
    if infra.DEADLINE - time.monotonic() < 25 * 60:
        raise RuntimeError("Insufficient budget remains for fresh native incident and cleanup")
    rc, _ = infra.command("original_native_g1_lifecycle", [str(infra.REPO / ".venv/bin/python"), str(HERE / "native_g1_entry.py")],
                           timeout=2400, required=False, cwd=infra.REPO)
    result = infra.RESULTS / "native/g1-native-result.json"
    data = json.loads(result.read_text()) if result.exists() else {}
    infra.STATE["native_command_exit_code"] = rc
    infra.STATE["native_g1_result"] = data
    infra.STATE["agent_executed"] = "agent_result" in data
    infra.STATE["model_executed"] = data.get("agent_result", {}).get("model_requests_observed") == 1
    infra.STATE["source_hashes_after"] = {name: sha(infra.REPO / name) for name in infra.STATE["source_hashes_before"]}
    diff, _ = infra.command("tracked_source_unchanged", ["git", "-C", str(infra.REPO), "diff", "--exit-code",
                                                        "--ignore-submodules=untracked", "HEAD", "--"], required=False)
    unchanged = diff == 0 and infra.STATE["source_hashes_before"] == infra.STATE["source_hashes_after"]
    infra.STATE["source_inputs_unchanged"] = unchanged
    infra.STATE["smoke_pass"] = rc == 0 and data.get("passed") is True and unchanged


def main():
    def interrupted(signum, frame):
        raise RuntimeError("Hosted runner interrupted by signal " + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        configure()
        run_id = os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
        cleanup_owned.claim(infra.RESULTS / "ownership.json",
                            work=Path(os.environ["RUNNER_TEMP"]) / ("sre-native-" + run_id),
                            cluster="sre-native-" + run_id)
        infra.prepare()
        build_image()
        execute_smoke()
    except BaseException as exc:
        infra.STATE["smoke_pass"] = False
        infra.STATE["error"] = {"type": type(exc).__name__, "message": str(exc)}
        traceback.print_exc()
    finally:
        scope = infra.RESULTS / "ownership.json"
        if scope.is_file():
            try:
                extra = cleanup_owned.cleanup(scope)
                infra.save("g1-extra-cleanup.json", extra)
                infra.STATE["extra_cleanup_verified"] = extra["passed"]
            except BaseException as exc:
                infra.STATE["extra_cleanup_error"] = str(exc)
                infra.STATE["extra_cleanup_verified"] = False
        else:
            infra.STATE["extra_cleanup_verified"] = not infra.STATE.get("agent_executed")
        try:
            infra.cleanup()
        except BaseException as exc:
            infra.STATE["cleanup_error"] = {"type": type(exc).__name__, "message": str(exc)}
            infra.STATE["cleanup_verified"] = False
        infra.STATE["elapsed_seconds_including_cleanup"] = time.monotonic() - infra.START
        infra.STATE["passed"] = bool(infra.STATE.get("smoke_pass") and infra.STATE.get("cleanup_verified")
                                    and infra.STATE.get("extra_cleanup_verified")
                                    and infra.STATE.get("source_inputs_unchanged") is True
                                    and not infra.STATE.get("error") and not infra.STATE.get("cleanup_error"))
        infra.save("g1-execution-summary.json", infra.STATE)
        # Private agent evidence is inventoried only by the reviewed post-cleanup
        # exporter. Never follow links or silently skip unreadable folders here.
        infra.save("evidence-inventory-pending.json", {"complete": False,
                   "scope": "final strict evidence inventory is deferred to the post-cleanup exporter"})
    return 0 if infra.STATE.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
