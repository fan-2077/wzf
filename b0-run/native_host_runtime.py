from __future__ import annotations


import hashlib


import json


import os


from pathlib import Path


import re


import shutil


import signal


import subprocess


import tarfile


import threading


import time


REPOSITORY = "fan-2077/wzf"


REF = "refs/heads/sre-native-reference-20261116"


SOURCE = "https://github.com/SREGym/SREGym.git"


COMMIT = "148dded7ca2737ded1085e7dc7bbf2a8fcfe7861"


TASK = "gitlab_notification_intermittent_replicated"


RESULTS = Path("results").resolve()


START = time.monotonic()


DEADLINE = START + 78 * 60


STOP_MONITOR = threading.Event()


STATE = {
    "scope": "reference_recovery_only", "source_commit": COMMIT, "task": TASK,
    "profile": "full", "deploy_loki": False, "agent_executed": False, "model_executed": False,
    "user_repository_checked_out": False, "cluster_creation_attempted": False,
    "ownership_initialized": False, "native_command_exit_code": None,
    "native_admission_passed": False, "cleanup_verified": False, "commands": [],
}


WORK = None


CLUSTER = None


ENV = None


BIN = None


REPO = None


MONITOR = None


class RunFailure(RuntimeError):
    pass


def save(name, value):
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / name).write_text(json.dumps(value, indent=2) + "\n")


def command(name, argv, timeout=30, *, required=True, cwd=None, cleanup=False):
    if not cleanup:
        timeout = min(timeout, max(0, int(DEADLINE - time.monotonic())))
    if timeout < 1:
        raise RunFailure("execution budget exhausted before " + name)
    log_path = RESULTS / (name + ".log")
    began = time.monotonic()
    record = {"name": name, "argv": [str(x) for x in argv], "timeout_seconds": timeout,
              "started_seconds": began - START, "log": log_path.name}
    STATE["active_command"] = name
    print(json.dumps({"starting": name, "timeout_seconds": timeout}), flush=True)
    proc = None
    try:
        with log_path.open("wb") as log:
            proc = subprocess.Popen(argv, cwd=cwd, env=ENV, stdout=log, stderr=subprocess.STDOUT,
                                    start_new_session=True)
            try:
                # G1 derivative: persist exact child identity so an independent
                # workflow cleanup can stop it if the outer runner is killed.
                try:
                    stat = Path(f"/proc/{proc.pid}/stat").read_text()
                    start_ticks = stat.rsplit(")", 1)[1].split()[19]
                    child = {"pid": proc.pid, "pgid": os.getpgid(proc.pid),
                             "start_ticks": start_ticks, "command": name,
                             "identity": {k: os.environ.get(k) for k in
                                 ("GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}}
                    with (RESULTS / "process-ownership.jsonl").open("a") as receipt:
                        receipt.write(json.dumps(child) + "\n")
                        receipt.flush()
                        os.fsync(receipt.fileno())
                except ProcessLookupError:
                    pass
                except FileNotFoundError:
                    pass
                rc = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                record["timed_out"] = True
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
                rc = 124
            except BaseException:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=3)
                raise
    except FileNotFoundError as exc:
        rc = 127
        log_path.write_text(str(exc) + "\n")
    record.update(exit_code=rc, elapsed_seconds=time.monotonic() - began)
    STATE["commands"].append(record)
    save("summary.json", STATE)
    print(json.dumps({k: record[k] for k in ("name", "exit_code", "elapsed_seconds")}), flush=True)
    if required and rc != 0:
        raise RunFailure(name + " failed; see " + log_path.name)
    return rc, log_path.read_text(errors="replace")


def guard():
    expected = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
                "RUNNER_ARCH": "X64", "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_REF": REF}
    for key, value in expected.items():
        if os.environ.get(key) != value:
            raise RunFailure("refusing non-reviewed execution context: " + key)
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        if not os.environ.get(key, "").isdigit():
            raise RunFailure("invalid " + key)


def meminfo():
    return {p[0].rstrip(":"): int(p[1]) * 1024 for line in Path("/proc/meminfo").read_text().splitlines()
            if (p := line.split())[0] in {"MemTotal:", "MemAvailable:", "SwapTotal:", "SwapFree:"}}


def sample_resources():
    """Sample host totals and non-secret status in this run's dedicated cluster."""
    samples = RESULTS / "resource-samples.jsonl"
    statuses = RESULTS / "pod-status-samples.jsonl"
    peak_used, min_available, index = 0, None, 0
    while not STOP_MONITOR.is_set():
        try:
            mem = meminfo()
            used = mem["MemTotal"] - mem["MemAvailable"]
            peak_used = max(peak_used, used)
            min_available = min(mem["MemAvailable"], min_available or mem["MemAvailable"])
            item = {"elapsed_seconds": time.monotonic() - START, "memory_bytes": mem,
                    "host_used_including_other_processes_bytes": used,
                    "disk_free_bytes": shutil.disk_usage(WORK).free,
                    "loadavg": Path("/proc/loadavg").read_text().split()[:3]}
            with samples.open("a") as handle:
                handle.write(json.dumps(item) + "\n")
            if index % 6 == 0:
                print(json.dumps({"heartbeat_seconds": item["elapsed_seconds"],
                                  "active_command": STATE.get("active_command"),
                                  "available_memory_bytes": mem["MemAvailable"],
                                  "disk_free_bytes": item["disk_free_bytes"]}), flush=True)
            if index % 3 == 0 and STATE["cluster_creation_attempted"]:
                query = subprocess.run(["kubectl", "get", "pods", "-A", "-o", "json", "--request-timeout=8s"],
                                       env=ENV, capture_output=True, text=True, timeout=10)
                if query.returncode == 0:
                    rows = []
                    for p in json.loads(query.stdout).get("items", []):
                        rows.append({"namespace": p["metadata"]["namespace"], "name": p["metadata"]["name"],
                                     "node": p["spec"].get("nodeName"), "phase": p["status"].get("phase"),
                                     "container_statuses": p["status"].get("containerStatuses", []),
                                     "images": [c["image"] for c in p["spec"].get("containers", [])],
                                     "pvc_names": [v["persistentVolumeClaim"]["claimName"] for v in p["spec"].get("volumes", [])
                                                   if "persistentVolumeClaim" in v]})
                    with statuses.open("a") as handle:
                        handle.write(json.dumps({"elapsed_seconds": time.monotonic()-START, "pods": rows}) + "\n")
        except Exception as exc:
            with samples.open("a") as handle:
                handle.write(json.dumps({"sample_error": type(exc).__name__}) + "\n")
        index += 1
        STOP_MONITOR.wait(5)
    save("resource-peaks.json", {"sampled_host_peak_used_bytes": peak_used, "sampled_min_available_bytes": min_available,
                                 "scope": "Sampled whole hosted VM, including OS and all cluster nodes; not exact per-container high water mark.",
                                 "sample_interval_seconds": 5})


def download(name, url, destination):
    command(name, ["curl", "--fail", "--location", "--retry", "2", "--retry-delay", "2",
                   "--max-time", "180", "--output", str(destination), url], timeout=200)


def checked_download(name, url, checksum_url, destination):
    checksum = destination.with_name(destination.name + ".checksum")
    download(name, url, destination)
    download(name + "_checksum", checksum_url, checksum)
    matches = re.findall(r"\b[0-9a-fA-F]{64}\b", checksum.read_text())
    actual = hashlib.sha256(destination.read_bytes()).hexdigest()
    if len(matches) != 1 or actual != matches[0].lower():
        raise RunFailure("published checksum mismatch for " + name)
    STATE.setdefault("binary_downloads", []).append({"name": name, "url": url, "sha256": actual})
    return actual


def prepare():
    global WORK, CLUSTER, ENV, BIN, REPO, MONITOR
    guard()
    run = "sre-native-" + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    CLUSTER = run
    WORK = Path(os.environ["RUNNER_TEMP"]) / run
    WORK.mkdir(exist_ok=False)
    BIN = WORK / "bin"
    BIN.mkdir()
    REPO = WORK / "SREGym"
    ENV = os.environ.copy()
    for key in list(ENV):
        if key.endswith(("_API_KEY", "_SECRET", "_TOKEN")) or key.startswith("ACTIONS_"):
            ENV.pop(key, None)
    for key in ("KIND_NODE_IMAGE", "KIND_EXPERIMENTAL_DOCKER_NETWORK", "KIND_RETAIN_ON_FAILURE"):
        ENV.pop(key, None)
    ENV.update(PATH=str(BIN) + os.pathsep + ENV["PATH"], KUBECONFIG=str(WORK / "kubeconfig"),
               KIND_CLUSTER_NAME=CLUSTER, SREGYM_CACHE_DIR=str(WORK / "sregym-cache"),
               KIND_CONFIG=str(REPO / "kind/kind-config.yaml"), KIND_EXPERIMENTAL_PROVIDER="docker",
               SREGYM_PROFILE="full", SRE_REFERENCE_EVIDENCE=str(RESULTS),
               WAIT_FOR_POD_READY_TIMEOUT="900", PYTHONUNBUFFERED="1", PYTHONOPTIMIZE="0",
               GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
               UV_CACHE_DIR=str(WORK / "uv-cache"), UV_PYTHON_INSTALL_DIR=str(WORK / "python"))
    STATE["identity"] = {k: os.environ.get(k) for k in ("GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_SHA", "GITHUB_RUN_ID",
                         "GITHUB_RUN_ATTEMPT", "RUNNER_OS", "RUNNER_ARCH", "RUNNER_ENVIRONMENT", "ImageOS", "ImageVersion")}
    STATE["work_directory"], STATE["cluster"] = str(WORK), CLUSTER
    STATE["initial_memory_bytes"] = meminfo()
    STATE["initial_disk_free_bytes"] = shutil.disk_usage(WORK).free
    STATE["cpu_count"] = os.cpu_count()
    STATE["attempt_resource_guard"] = {"cpu": 4, "available_memory_gib": 12, "free_disk_gib": 35,
                                        "scope": "Budget guard for this attempt, not an official SREGym minimum."}
    if os.cpu_count() < 4 or meminfo()["MemAvailable"] < 12 * 1024**3 or shutil.disk_usage(WORK).free < 35 * 1024**3:
        raise RunFailure("runner below this attempt's budget guard: 4 CPU, 12 GiB available RAM, 35 GiB free disk")
    command("docker_version", ["docker", "version"])
    command("host_memory", ["free", "-b"])
    command("host_disk", ["df", "-B1", "/", "/var/lib/docker"])
    command("sudo_available", ["sudo", "-n", "true"])
    _, existing = command("check_existing_kind_nodes", ["docker", "ps", "-aq", "--filter", "label=io.x-k8s.kind.cluster"])
    if existing.strip():
        raise RunFailure("preexisting KIND nodes; refusing host mutation")
    _, existing = command("check_existing_kind_network", ["docker", "network", "ls", "--filter", "name=^kind$", "--format", "{{.ID}}"])
    if existing.strip():
        raise RunFailure("preexisting kind network; refusing host mutation")
    STATE["ownership_initialized"] = True
    save("summary.json", STATE)
    MONITOR = threading.Thread(target=sample_resources, daemon=True)
    MONITOR.start()
    # Only the fixed, public benchmark is fetched. No actions/checkout or user code.
    command("git_init", ["git", "init", str(REPO)])
    command("git_remote", ["git", "-C", str(REPO), "remote", "add", "origin", SOURCE])
    command("git_fetch", ["git", "-C", str(REPO), "fetch", "--depth=1", "origin", COMMIT], timeout=240)
    command("git_checkout", ["git", "-C", str(REPO), "checkout", "--detach", "FETCH_HEAD"])
    _, revision = command("source_revision", ["git", "-C", str(REPO), "rev-parse", "HEAD"])
    if revision.strip() != COMMIT:
        raise RunFailure("source commit mismatch")
    command("public_pinned_submodule", ["git", "-C", str(REPO), "submodule", "update", "--init", "--depth=1", "SREGym-applications"], timeout=300)
    command("submodule_revision", ["git", "-C", str(REPO), "submodule", "status"])
    manifests = ["kind/kind-config.yaml", "kind/setup_kind_cluster.sh", "pyproject.toml", "uv.lock",
                 "tests/integration/apps/gitlab/validate_gitlab_notification_intermittent.py",
                 "tests/integration/apps/gitlab/validate_gitlab_notifications.py",
                 "sregym/conductor/oracles/apps/gitlab/notification_recovery.py",
                 "sregym/conductor/oracles/apps/gitlab/database_recovery.py",
                 "sregym/conductor/oracles/postgres_application.py",
                 "sregym/conductor/conductor.py", "sregym/profile.py",
                 "sregym/conductor/problems/registry.py",
                 "sregym/conductor/problems/apps/gitlab/notification_intermittent.py",
                 "sregym/conductor/problems/apps/gitlab/notification_recovery.py",
                 "sregym/conductor/problems/apps/gitlab/notification_ambiguity.py",
                 "sregym/conductor/problems/apps/gitlab/database_deletion.py",
                 "sregym/service/apps/gitlab/application.py", "sregym/service/apps/gitlab/recovery.py",
                 "sregym/service/apps/gitlab/notifications.py", "sregym/service/apps/gitlab/reconciliation.py",
                 "sregym/service/apps/gitlab/runtime/intermittent_mail_sink.py",
                 "sregym/service/apps/postgres.py", "sregym/service/apps/components/cnpg.py"]
    STATE["source_hashes_before"] = {x: hashlib.sha256((REPO / x).read_bytes()).hexdigest() for x in manifests}
    shutil.copyfile(REPO / "kind/kind-config.yaml", RESULTS / "official-kind-config.yaml")
    checked_download("kind_binary", "https://github.com/kubernetes-sigs/kind/releases/download/v0.28.0/kind-linux-amd64",
                     "https://github.com/kubernetes-sigs/kind/releases/download/v0.28.0/kind-linux-amd64.sha256sum", BIN / "kind")
    (BIN / "kind").chmod(0o755)
    checked_download("kubectl_binary", "https://dl.k8s.io/release/v1.32.5/bin/linux/amd64/kubectl",
                     "https://dl.k8s.io/release/v1.32.5/bin/linux/amd64/kubectl.sha256", BIN / "kubectl")
    (BIN / "kubectl").chmod(0o755)
    archive = WORK / "helm.tar.gz"
    checked_download("helm_binary", "https://get.helm.sh/helm-v4.0.0-linux-amd64.tar.gz",
                     "https://get.helm.sh/helm-v4.0.0-linux-amd64.tar.gz.sha256sum", archive)
    with tarfile.open(archive) as tar:
        member = tar.getmember("linux-amd64/helm")
        if not member.isfile():
            raise RunFailure("unexpected Helm archive member")
        (BIN / "helm").write_bytes(tar.extractfile(member).read())
    (BIN / "helm").chmod(0o755)
    command("bootstrap_venv", ["python3", "-m", "venv", str(WORK / "bootstrap")])
    command("install_uv", [str(WORK / "bootstrap/bin/python"), "-m", "pip", "install", "--disable-pip-version-check", "uv==0.11.8"], timeout=180)
    (BIN / "uv").symlink_to(WORK / "bootstrap/bin/uv")
    for label, argv in (("kind", ["kind", "version"]), ("kubectl", ["kubectl", "version", "--client", "-o", "json"]),
                        ("helm", ["helm", "version"]), ("uv", ["uv", "--version"])):
        command(label + "_version", argv)
    command("frozen_python_dependencies", ["uv", "sync", "--frozen", "--no-dev", "--python", "3.12.13"], timeout=600, cwd=REPO)
    command("python_version", [str(REPO / ".venv/bin/python"), "--version"])
    command("before_inotify_limits", ["sysctl", "fs.inotify.max_user_instances", "fs.inotify.max_user_watches"])
    command("official_udev_directory", ["sudo", "mkdir", "-p", "/run/udev"])
    command("official_temporary_inotify_limits", ["sudo", "sysctl", "-w", "fs.inotify.max_user_instances=1024", "fs.inotify.max_user_watches=1048576"])
    STATE["host_tuning"] = "Only official KIND inotify guidance on this disposable VM; no persistent sysctl file."
    STATE["cluster_creation_attempted"] = True
    save("summary.json", STATE)
    command("official_kind_setup", ["bash", "kind/setup_kind_cluster.sh", "x86"], timeout=1200, cwd=REPO)
    _, nodes_text = command("four_ready_nodes", ["kubectl", "get", "nodes", "-o", "json", "--request-timeout=15s"])
    nodes = json.loads(nodes_text)["items"]
    if len(nodes) != 4 or not all(any(c["type"] == "Ready" and c["status"] == "True" for c in n["status"]["conditions"]) for n in nodes):
        raise RunFailure("official four-node topology not ready")
    command("calico_tiers", ["kubectl", "get", "tiers.crd.projectcalico.org", "--request-timeout=15s"])
    command("cni_rollout", ["kubectl", "-n", "kube-system", "rollout", "status", "daemonset/calico-node", "--timeout=60s"], timeout=70)


def cleanup():
    STOP_MONITOR.set()
    if MONITOR:
        MONITOR.join(timeout=15)
    if not STATE["ownership_initialized"]:
        STATE["cleanup_verified"] = True
        STATE["cleanup_scope"] = "No cluster/network ownership initialized; no mutation attempted."
        return
    STATE["cleanup_scope"] = "This run's KIND node containers, newly-created default kind network and dedicated kubeconfig."
    if STATE["cluster_creation_attempted"]:
        for name, argv in (
            ("final_nodes", ["kubectl", "get", "nodes", "-o", "wide", "--request-timeout=10s"]),
            ("final_pods", ["kubectl", "get", "pods", "-A", "-o", "wide", "--request-timeout=10s"]),
            ("final_events", ["kubectl", "get", "events", "-A", "--sort-by=.lastTimestamp", "--request-timeout=10s"]),
            ("final_persistent_volumes", ["kubectl", "get", "pv", "-o", "wide", "--request-timeout=10s"]),
        ):
            command(name, argv, timeout=15, required=False, cleanup=True)
        command("export_kind_logs", ["kind", "export", "logs", str(RESULTS / "kind-logs"), "--name", CLUSTER],
                timeout=60, required=False, cleanup=True)
        command("delete_own_cluster", ["kind", "delete", "cluster", "--name", CLUSTER], timeout=90, required=False, cleanup=True)
        rc, nodes = command("remaining_own_nodes", ["docker", "ps", "-aq", "--filter", "label=io.x-k8s.kind.cluster=" + CLUSTER], required=False, cleanup=True)
        if rc == 0 and nodes.strip():
            command("remove_remaining_own_nodes", ["docker", "rm", "-f", *nodes.split()], timeout=30, required=False, cleanup=True)
        command("remove_created_kind_network", ["docker", "network", "rm", "kind"], timeout=15, required=False, cleanup=True)
    rc1, nodes = command("verify_no_nodes", ["docker", "ps", "-aq", "--filter", "label=io.x-k8s.kind.cluster=" + CLUSTER], required=False, cleanup=True)
    rc2, network = command("verify_no_kind_network", ["docker", "network", "ls", "--filter", "name=^kind$", "--format", "{{.ID}}"], required=False, cleanup=True)
    (WORK / "kubeconfig").unlink(missing_ok=True)
    STATE["cleanup_verified"] = rc1 == 0 and not nodes.strip() and rc2 == 0 and not network.strip() and not (WORK / "kubeconfig").exists()

