"""GitHub-only qualification of the real G1 exporter on synthetic evidence.

No Docker, Kubernetes, SDK, model, native business request, or original G1 run.
Only this job's newly created g1-results tree can be created/removed. The same
reviewed seal_remote_evidence.py wrapper and sudo worker perform the export.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile


HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parent
SOURCE = WORKSPACE / "g1-results"
FIXTURE_MARKER = "DIAGNOSTIC_FIXTURE.json"
SCHEMA = "g1-export-synthetic-diagnostic-v1"
REPOSITORY = "fan-2077/wzf"
REF = "refs/heads/sre-g1-export-diagnostic-20261117"
CASES = {"private-tree", "unsafe-link"}
HELPERS = {"g1-smoke/seal_remote_evidence.py", "g1-smoke/export_owned_evidence.py"}
IDENTITY_KEYS = ("GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
VIRTUAL_FILES = {"FINAL_REMOTE_VERDICT.json", "ARTIFACT_MANIFEST.json", "EVIDENCE_EXPORT_METADATA.json"}
PRIVATE_FILES = {
    "tmp/root-private/proof.txt": b"Synthetic private evidence; no business run.\n",
    "tmp/root-private/.hidden-proof": b"Hidden synthetic file must survive complete export.\n",
    "tmp/root-private/.hidden-tree/nested.bin": b"\x00synthetic-root-owned-binary\xff\n",
}
CANARY_BYTES = b"Synthetic external canary: exporter must not follow this link.\n"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        # fdopen owns fd; do not truncate/replace any preexisting evidence.
        raise


def regular(path, *, max_bytes=4 * 1024 * 1024):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "Output is not an ordinary singly linked file")
    require(info.st_size <= max_bytes, "Diagnostic output exceeds its fixed size bound")
    return info


def context(case):
    require(case in CASES, "Unsupported fixed diagnostic case")
    require(os.geteuid() != 0, "Main diagnostic must run as the real unprivileged runner")
    require(os.environ.get("GITHUB_ACTIONS") == "true", "Real GitHub Actions context required")
    require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "Hosted GitHub runner required")
    identity = {key: os.environ[key] for key in IDENTITY_KEYS}
    require(identity["GITHUB_REPOSITORY"] == REPOSITORY and identity["GITHUB_REF"] == REF,
            "Only the separate diagnostic repository/ref is authorized")
    require(all(re.fullmatch(r"[1-9][0-9]*", identity[key]) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")),
            "Invalid actual workflow run identity")
    require(identity["GITHUB_RUN_ATTEMPT"] == "1", "Only the shared exporter's first hosted attempt is qualified")
    require(re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", "")) is not None,
            "Actual checkout commit identity required")
    require(Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True) == WORKSPACE,
            "Diagnostic must use the actual checkout workspace")
    require(not WORKSPACE.is_symlink(), "Workspace must not be a symlink")
    runner_temp = Path(os.environ["RUNNER_TEMP"])
    require(runner_temp.is_absolute() and runner_temp.resolve(strict=True) == runner_temp,
            "Runner temporary directory must be an existing canonical path")
    owner = identity["GITHUB_RUN_ID"] + "-" + identity["GITHUB_RUN_ATTEMPT"]
    report_dir = runner_temp / ("sre-g1-export-diagnostic-" + case + "-" + owner)
    export_dir = runner_temp / ("sre-g1-export-" + owner)
    return identity, runner_temp, report_dir, export_dir


def bound_helpers():
    binding_file = HERE / "EXPORTER_BINDING.json"
    regular(binding_file, max_bytes=16000)
    binding = json.loads(binding_file.read_text())
    require(binding.get("schema") == "g1-exporter-binding-v1" and set(binding.get("files", {})) == HELPERS,
            "Diagnostic exporter binding is incomplete")
    actual = {}
    for relative, expected in binding["files"].items():
        path = WORKSPACE / relative
        regular(path, max_bytes=1024 * 1024)
        actual[relative] = sha(path.read_bytes())
        require(actual[relative] == expected, "Reviewed exporter bytes changed: " + relative)
    return actual


def source_payloads(identity, runner_temp, marker):
    owner = identity["GITHUB_RUN_ID"] + "-" + identity["GITHUB_RUN_ATTEMPT"]
    return {
        FIXTURE_MARKER: canonical(marker),
        "ownership.json": canonical({"identity": identity, "dedicated_host": True,
            "native_ports_unused_before_g1": True,
            "empty_prefixes_before_g1": {"container": [], "network": [], "volume": []},
            "work": str(runner_temp / ("sre-native-" + owner)), "cluster": "sre-native-" + owner,
            "kind_ownership_preflight_passed": False, "diagnostic_fixture": True}),
        "workflow-fallback-cleanup.json": canonical({"passed": True, "full": True,
            "steps": [{"operation": "synthetic_no_business_resources", "passed": True}],
            "diagnostic_fixture": True}),
        "g1-execution-summary.json": canonical({"smoke_pass": True, "cleanup_verified": True,
            "extra_cleanup_verified": True, "source_inputs_unchanged": True,
            "native_g1_result": {"cleanup_passed": True, "agent_result": {"cleanup": {"cleanup_errors": []}}},
            "diagnostic_fixture": True}),
        "public-synthetic-evidence.json": canonical({"scope": "synthetic export only",
            "original_g1_executed": False, "model_executed": False, "business_requests": 0}),
    }


def read_marker(case):
    require(case in CASES and SOURCE.parent == WORKSPACE and SOURCE.name == "g1-results",
            "Unrecognized fixture scope")
    info = SOURCE.lstat()
    require(stat.S_ISDIR(info.st_mode) and not SOURCE.is_symlink(), "Fixture source is not a real directory")
    marker_path = SOURCE / FIXTURE_MARKER
    regular(marker_path, max_bytes=16000)
    marker = json.loads(marker_path.read_text())
    require(marker.get("schema") == SCHEMA and marker.get("case") == case
            and marker.get("workspace") == str(WORKSPACE) and marker.get("synthetic_only") is True,
            "Fixture ownership marker mismatch")
    identity = marker["identity"]
    require(identity["GITHUB_REPOSITORY"] == REPOSITORY and identity["GITHUB_REF"] == REF,
            "Fixture is not bound to the separate diagnostic ref")
    require(type(marker["runner_uid"]) is int and marker["runner_uid"] > 0
            and info.st_uid == marker["runner_uid"], "Fixture owner is not the original runner")
    return marker


def snapshot_source():
    """Root-only metadata+hash of this synthetic tree; never follows a link."""
    result = {}

    def visit(path):
        info = path.lstat()
        relative = str(path.relative_to(SOURCE))
        entry = {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
                 "device": info.st_dev, "inode": info.st_ino, "nlink": info.st_nlink,
                 "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}
        if stat.S_ISDIR(info.st_mode):
            entry["kind"] = "directory"
            result[relative] = entry
            for child in sorted(path.iterdir()):
                visit(child)
        elif stat.S_ISREG(info.st_mode):
            entry.update(kind="file", bytes=info.st_size, sha256=sha(path.read_bytes()))
            result[relative] = entry
        elif stat.S_ISLNK(info.st_mode):
            entry.update(kind="symlink", target=os.readlink(path))
            result[relative] = entry
        else:
            raise RuntimeError("Unexpected synthetic source type")

    visit(SOURCE)
    return result


def internal(case, mode):
    require(os.geteuid() == 0, "Internal fixture setup/check requires actual root")
    marker = read_marker(case)
    require(os.environ.get("SUDO_UID") == str(marker["runner_uid"]), "Root helper caller differs from fixture owner")
    if mode == "create-private":
        (SOURCE / "tmp").mkdir(mode=0o700, exist_ok=False)
        (SOURCE / "tmp/root-private").mkdir(mode=0o700, exist_ok=False)
        (SOURCE / "tmp/root-private/.hidden-tree").mkdir(mode=0o700, exist_ok=False)
        for relative, data in PRIVATE_FILES.items():
            write_new(SOURCE / relative, data)
        if case == "unsafe-link":
            os.symlink(marker["external_canary"], SOURCE / "tmp/root-private/unsafe-link")
        result = snapshot_source()
        require(all(result[name]["uid"] == 0 and result[name]["mode"] == 0o600 for name in PRIVATE_FILES),
                "Private files were not created as root 0600")
        require(result["tmp/root-private"]["uid"] == 0 and result["tmp/root-private"]["mode"] == 0o700,
                "Private directory was not created as root 0700")
        print(json.dumps(result, sort_keys=True), flush=True)
    elif mode == "snapshot":
        print(json.dumps(snapshot_source(), sort_keys=True), flush=True)
    elif mode == "cleanup":
        # shutil.rmtree unlinks the deliberately unsafe symlink, not its target.
        shutil.rmtree(SOURCE)
        print(json.dumps({"removed_own_synthetic_source": not SOURCE.exists()}), flush=True)
    else:
        raise RuntimeError("Unknown root fixture operation")


def root_fixture_call(case, mode):
    command = ["sudo", "-n", "--", sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
               "--case", case, "--internal", mode]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                            shell=False, timeout=25, check=False)
    require(result.returncode == 0, "Root synthetic-fixture operation failed: " + mode)
    require(len(result.stdout) <= 200000, "Synthetic fixture report too large")
    return json.loads(result.stdout)


def append_output(name, value):
    require("\n" not in value and "\r" not in value, "Invalid workflow output path")
    output = os.environ.get("GITHUB_OUTPUT")
    require(bool(output), "Workflow output file unavailable")
    with open(output, "a", encoding="utf-8") as stream:
        stream.write(name + "=" + value + "\n")


def check_archive(path, expected_payloads, source_snapshot, identity):
    regular(path)
    # Runner actually opens the completed gzip archive; os.access is insufficient.
    with path.open("rb") as stream:
        archive_sha = sha(stream.read())
    extracted = {}
    with tarfile.open(path, "r:gz") as archive:
        seen = set()
        members = archive.getmembers()
        require(len(members) <= 128, "Synthetic archive member count unexpectedly large")
        for member in members:
            name = member.name.rstrip("/") if member.isdir() else member.name
            require(name not in seen, "Archive contains duplicate member names")
            seen.add(name)
            require(name == "g1-results" or name.startswith("g1-results/"),
                    "Archive member is outside the fixed evidence root")
            require(not any(part in {"..", ""} for part in name.split("/")), "Unsafe archive member path")
            require(member.isfile() or member.isdir(), "Archive contains a link or special file")
            if member.isfile():
                require(member.size <= 1024 * 1024, "Synthetic archive member unexpectedly large")
                extracted[name.removeprefix("g1-results/")] = archive.extractfile(member).read()
    require(set(extracted) == set(expected_payloads) | VIRTUAL_FILES, "Archive file set is incomplete or contains unplanned files")
    for relative, expected in expected_payloads.items():
        require(extracted[relative] == expected, "Original synthetic evidence bytes changed: " + relative)
    verdict = json.loads(extracted["FINAL_REMOTE_VERDICT.json"])
    require(verdict.get("scope") == "synthetic export diagnostic only"
            and verdict.get("original_g1_qualified") is False, "Synthetic verdict falsely claims original G1 qualification")
    manifest = json.loads(extracted["ARTIFACT_MANIFEST.json"])
    hashes = {name: sha(data) for name, data in extracted.items() if name != "ARTIFACT_MANIFEST.json"}
    require(isinstance(manifest, dict) and manifest.get("complete") is True
            and manifest.get("files") == hashes, "Archive manifest does not cover the exact sealed file set")
    directories = sorted(name for name, item in source_snapshot.items() if item["kind"] == "directory")
    require(manifest.get("directories") == directories, "Archive manifest directory set differs from the fixture")
    metadata = json.loads(extracted["EVIDENCE_EXPORT_METADATA.json"])
    require(metadata.get("identity") == identity and metadata.get("complete_strict_inventory") is True
            and metadata.get("original_permissions_or_ownership_changed") is False,
            "Sealed export metadata does not bind a complete unchanged source")
    sealed_source = metadata.get("source_entries", {})
    require(set(sealed_source) == set(source_snapshot), "Sealed source inventory omits an entry")
    for name, expected in source_snapshot.items():
        for key, value in expected.items():
            reported_key = "size" if key == "bytes" else key
            require(sealed_source[name].get(reported_key) == value,
                    "Sealed source inventory differs from independent root snapshot: " + name)
    return {"sha256": archive_sha, "bytes": path.stat().st_size,
            "source_files_verified": len(expected_payloads), "virtual_files_verified": sorted(VIRTUAL_FILES),
            "private_and_hidden_files_verified": sorted(PRIVATE_FILES), "runner_opened_archive": True,
            "exact_manifest_file_set_and_hashes_verified": True,
            "source_metadata_matches_independent_root_snapshot": True}


def run(case):
    identity, runner_temp, report_dir, export_dir = context(case)
    report_dir.mkdir(mode=0o700, exist_ok=False)
    upload_dir = report_dir / "upload"
    upload_dir.mkdir(mode=0o700, exist_ok=False)
    report_path = upload_dir / "DIAGNOSTIC_RESULT.json"
    report = {"schema": SCHEMA, "case": case, "identity": identity,
              "checkout_commit": os.environ["GITHUB_SHA"],
              "diagnostic_source_sha256": sha(Path(__file__).read_bytes()),
              "scope": "synthetic export diagnostic only", "original_g1_executed": False,
              "original_g1_qualified": False, "business_requests": 0, "model_calls": 0,
              "passed": False, "cross_uid_qualification": "pending"}
    error = None
    try:
        require(not SOURCE.exists() and not SOURCE.is_symlink(), "Existing g1-results must not be reused or overwritten")
        require(not export_dir.exists() and not export_dir.is_symlink(), "Existing exporter output must not be reused")
        helpers_before = bound_helpers()
        report["exporter_source_sha256"] = helpers_before
        canary = report_dir / "EXTERNAL_CANARY.bin"
        write_new(canary, CANARY_BYTES)
        canary_before = (canary.stat().st_uid, canary.stat().st_gid, stat.S_IMODE(canary.stat().st_mode),
                         canary.stat().st_ino, sha(canary.read_bytes()))
        marker = {"schema": SCHEMA, "case": case, "workspace": str(WORKSPACE), "identity": identity,
                  "runner_uid": os.getuid(), "runner_gid": os.getgid(), "synthetic_only": True,
                  "external_canary": str(canary)}
        SOURCE.mkdir(mode=0o700)
        expected_payloads = source_payloads(identity, runner_temp, marker)
        for relative, data in expected_payloads.items():
            write_new(SOURCE / relative, data)
        before = root_fixture_call(case, "create-private")
        expected_payloads.update(PRIVATE_FILES)
        failures = []
        for operation, path in (("scandir", SOURCE / "tmp/root-private"),
                                ("read", SOURCE / "tmp/root-private/proof.txt")):
            try:
                if operation == "scandir":
                    with os.scandir(path) as stream:
                        list(stream)
                else:
                    path.read_bytes()
            except PermissionError as denied:
                failures.append({"operation": operation, "errno": denied.errno, "permission_denied": True})
            else:
                raise RuntimeError("Unprivileged runner unexpectedly accessed root-private source")
        report["runner_uid"] = os.getuid()
        report["root_private_source_before"] = before
        report["unprivileged_access_checks"] = failures
        # Match the actual G1 wrapper entry; the wrapper loads its sibling helper
        # and then invokes the root worker using its own fixed -I -S command.
        command = [sys.executable, "-B", str(WORKSPACE / "g1-smoke/seal_remote_evidence.py")]
        completed = subprocess.run(command, cwd=WORKSPACE, stdin=subprocess.DEVNULL, capture_output=True,
                                   text=True, shell=False, timeout=120, check=False)
        report["actual_sealer_invocation"] = {"argv": command, "returncode": completed.returncode,
                                              "stdout_sha256": sha(completed.stdout.encode()),
                                              "stderr_sha256": sha(completed.stderr.encode())}
        require(bound_helpers() == helpers_before, "Exporter bytes changed during diagnostic")
        after = root_fixture_call(case, "snapshot")
        require(before == after, "Exporter changed source content, ownership, permission, or identity")
        report["source_metadata_and_content_unchanged"] = True
        canary_after = (canary.stat().st_uid, canary.stat().st_gid, stat.S_IMODE(canary.stat().st_mode),
                        canary.stat().st_ino, sha(canary.read_bytes()))
        require(canary_before == canary_after, "Unsafe-link target changed")
        report["external_canary_unchanged"] = True
        status_path = export_dir / "EXPORT_STATUS.json"
        regular(status_path, max_bytes=100000)
        status = json.loads(status_path.read_text())
        require(status.get("identity") == identity, "Export receipt identity does not match actual job")
        require(status.get("diagnostic_only") is True and status.get("raw_tree_upload_allowed") is False
                and status.get("original_permissions_or_ownership_changed") is False,
                "Export status does not preserve the diagnostic and unchanged-source boundary")
        report["export_status"] = status
        archive_path = export_dir / "evidence.tar.gz"
        archive_copy = None
        if case == "private-tree":
            require(completed.returncode == 0 and status.get("export_passed") is True
                    and status.get("final_verdict_passed") is True, "Private-tree export did not qualify")
            archive_report = check_archive(archive_path, expected_payloads, before, identity)
            receipt = status.get("archive") or {}
            require(receipt.get("name") == "evidence.tar.gz" and receipt.get("sha256") == archive_report["sha256"]
                    and receipt.get("bytes") == archive_report["bytes"], "Published archive differs from export receipt")
            report["archive_verification"] = archive_report
            report["cross_uid_qualification"] = "real_root_source_unprivileged_runner_archive_read"
            archive_copy = upload_dir / "evidence.tar.gz"
            write_new(archive_copy, archive_path.read_bytes())
            require(sha(archive_copy.read_bytes()) == archive_report["sha256"], "Staged archive differs from verified archive")
        else:
            require(completed.returncode != 0 and status.get("export_passed") is False
                    and status.get("archive") is None, "Unsafe link was not rejected")
            rejection = status.get("error") or {}
            require(rejection.get("type") == "ExportError" and "unsafe-link" in rejection.get("message", "")
                    and "forbidden" in rejection.get("message", ""),
                    "Negative case failed for a different reason than unsafe-link rejection")
            require(not archive_path.exists() and not archive_path.is_symlink(), "Rejected source still published a final archive")
            require({path.name for path in export_dir.iterdir()} == {"EXPORT_STATUS.json"},
                    "Rejected source retained an archive, pending output, or unvalidated fallback")
            report["unsafe_link_rejected"] = True
            report["final_or_fallback_archive_exists"] = False
            report["cross_uid_qualification"] = "real_root_private_unsafe_link_rejection"
        status_copy = upload_dir / "EXPORT_STATUS.json"
        write_new(status_copy, status_path.read_bytes())
        require(json.loads(status_copy.read_text()) == status, "Staged status differs from verified status")
        require({p.name for p in upload_dir.iterdir()} ==
                ({"EXPORT_STATUS.json", "evidence.tar.gz"} if case == "private-tree" else {"EXPORT_STATUS.json"}),
                "Diagnostic upload staging contains an unplanned file")
        if archive_copy is not None:
            append_output("validated_archive_path", str(archive_copy))
        append_output("validated_status_path", str(status_copy))
        report["passed"] = True
    except Exception as exc:
        error = type(exc).__name__ + ": " + str(exc)
        report["error"] = error
    finally:
        write_new(report_path, json.dumps(report, indent=2, ensure_ascii=False).encode() + b"\n")
    print(json.dumps({"case": case, "passed": report["passed"], "scope": report["scope"],
                      "report": str(report_path), "error": error}), flush=True)
    return 0 if report["passed"] else 1


def cleanup(case):
    identity, _, report_dir, _ = context(case)
    if not SOURCE.exists() and not SOURCE.is_symlink():
        print("No synthetic source directory remains.")
        return 0
    marker = read_marker(case)
    require(marker["identity"] == identity, "Cleanup fixture identity differs from actual job")
    require(marker["external_canary"] == str(report_dir / "EXTERNAL_CANARY.bin"), "Cleanup fixture is outside this job")
    result = root_fixture_call(case, "cleanup")
    require(result.get("removed_own_synthetic_source") is True, "Synthetic source cleanup incomplete")
    print(json.dumps(result), flush=True)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", required=True, choices=sorted(CASES))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--cleanup", action="store_true")
    mode.add_argument("--internal", choices=("create-private", "snapshot", "cleanup"))
    arguments = parser.parse_args()
    if arguments.internal:
        internal(arguments.case, arguments.internal)
    else:
        raise SystemExit(cleanup(arguments.case) if arguments.cleanup else run(arguments.case))
