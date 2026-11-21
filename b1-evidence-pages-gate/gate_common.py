"""Small source/record helpers for a fixed-interpreter contract gate only."""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat


REPOSITORY = "fan-2077/wzf"
REF = "refs/heads/sre-b1-evidence-pages-clock-v2-20261119"
WORKFLOW = ".github/workflows/sre-b1-evidence-pages-clock-v2-20261119.yml"
PYTHON_IMAGE = "python:3.11.17-slim-trixie"
PYTHON_VERSION = (3, 11, 17)
TEST_COUNT = 19
COMPONENT_MANIFEST = "SOURCE_MANIFEST.json"
MAX_SOURCE_BYTES = 32 * 1024 * 1024


def require(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def info(raw):
    return {"bytes": len(raw), "sha256": sha(raw)}


def read_bytes(path):
    status = path.lstat()
    require(stat.S_ISREG(status.st_mode) and status.st_nlink == 1
            and status.st_size <= MAX_SOURCE_BYTES, "bounded_regular_file_required:" + str(path))
    raw = path.read_bytes()
    require(len(raw) == status.st_size, "file_changed_during_read:" + str(path))
    return raw


def read_json(path):
    return json.loads(read_bytes(path))


def save_json(path, value, *, replace=False):
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    require(replace or not path.exists(), "record_already_exists:" + str(path))
    temporary = path.with_name(path.name + ".pending")
    with temporary.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def safe_relative(name):
    require(type(name) is str and name and "\\" not in name, "invalid_source_name")
    path = PurePosixPath(name)
    require(not path.is_absolute() and str(path) == name and all(x not in {"", ".", ".."} for x in path.parts),
            "source_path_escape")
    return name


def inventory(root, *, ignore_test_tmp=False):
    require(root.is_dir() and not root.is_symlink(), "source_root_must_be_directory")
    result = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if ignore_test_tmp and (relative == "validation/tmp" or relative.startswith("validation/tmp/")):
            continue
        status = path.lstat()
        require(not stat.S_ISLNK(status.st_mode), "source_symlink_forbidden:" + relative)
        if stat.S_ISDIR(status.st_mode):
            continue
        result[relative] = info(read_bytes(path))
    return result


def verify_tree(root, expected_manifest_sha=None, *, component=False, ignore_test_tmp=False):
    manifest_raw = read_bytes(root / COMPONENT_MANIFEST)
    if expected_manifest_sha is not None:
        require(sha(manifest_raw) == expected_manifest_sha, "externally_bound_manifest_digest_mismatch")
    manifest = json.loads(manifest_raw)
    if component:
        require(manifest["schema"] == "b1-evidence-pages-source-manifest-v1", "component_manifest_schema")
        require(not set(manifest["source_files"]) & set(manifest["validation_artifacts"]), "manifest_duplicate_path")
        entries = {**manifest["source_files"], **manifest["validation_artifacts"]}
        require(len(manifest["source_files"]) == manifest["source_file_count"]
                and len(manifest["validation_artifacts"]) == manifest["validation_artifact_count"], "manifest_count")
    else:
        require(manifest["schema"] == "b1-evidence-pages-gate-source-manifest-v1", "gate_manifest_schema")
        entries = manifest["files"]
        require(len(entries) == manifest["file_count"], "gate_manifest_count")
    require(COMPONENT_MANIFEST not in entries and manifest.get("self_excluded") is True, "manifest_self_exclusion")
    for name, entry in entries.items():
        safe_relative(name)
        require(set(entry) == {"bytes", "sha256"} and type(entry["bytes"]) is int
                and 0 <= entry["bytes"] <= MAX_SOURCE_BYTES
                and type(entry["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]),
                "source_record_invalid")
    expected = {**entries, COMPONENT_MANIFEST: info(manifest_raw)}
    require(inventory(root, ignore_test_tmp=ignore_test_tmp) == expected, "full_source_tree_mismatch")
    return expected


def expected_test_ids(component_root):
    tree = ast.parse(read_bytes(component_root / "tests/test_public_evidence.py"))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "EvidencePagesTests"]
    require(len(classes) == 1, "fixed_test_class_required")
    methods = [node.name for node in classes[0].body if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")]
    require(len(methods) == len(set(methods)) == TEST_COUNT, "exact_19_tests_required")
    return sorted("__main__.EvidencePagesTests." + name for name in methods)


def platform_identity(environment):
    require(environment.get("GITHUB_REPOSITORY") == REPOSITORY and environment.get("GITHUB_REF") == REF,
            "fixed_repository_and_branch_required")
    run, attempt, commit = (environment.get(name, "") for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA"))
    require(re.fullmatch(r"[1-9][0-9]{0,19}", run) is not None and attempt == "1"
            and re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "attempt_one_fixed_platform_identity_required")
    return {"repository": REPOSITORY, "ref": REF, "run_id": run, "run_attempt": attempt,
            "commit": commit, "container_name": "b1-evidence-pages-" + run + "-1"}
