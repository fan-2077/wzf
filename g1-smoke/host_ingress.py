"""Owned inbound rule for one disposable G1 host; never imported by the agent.

The pinned native MCP binds 0.0.0.0. This rule preserves upstream code while
restricting its three host ports to loopback and Docker bridges. No global
FORWARD policy or unrelated INPUT rule is changed. Actual enforcement is a
remote acceptance requirement, not something established by static review.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

PORTS = (8000, 9954, 16443)


class HostIngressGuard:
    def __init__(self, run_id: str, evidence: Path):
        if not re.fullmatch(r"[0-9]{1,16}-[0-9]{1,4}", run_id):
            raise ValueError("Expected numeric Actions run and attempt identifiers")
        self.chain = "G1_" + run_id.replace("-", "_")
        self.evidence = evidence
        self.created = False
        self.attached = False

    def _run(self, args, *, check=True):
        p = subprocess.run(["sudo", "-n", "iptables", "-w", "5", *args],
                           capture_output=True, text=True, timeout=15)
        self.evidence.mkdir(parents=True, exist_ok=True)
        with (self.evidence / "owned-ingress.log").open("a") as f:
            f.write(repr(args) + "\n" + p.stdout + p.stderr)
        if check and p.returncode:
            raise RuntimeError("Owned ingress operation failed: " + repr(args))
        return p

    def install(self):
        if (os.environ.get("GITHUB_ACTIONS") != "true"
                or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
            raise RuntimeError("Refusing host rule changes outside disposable hosted runner")
        if self._run(["-S", self.chain], check=False).returncode == 0:
            raise RuntimeError("Refusing an existing chain; ownership is not established")
        self._run(["-N", self.chain])
        self.created = True
        for interface in ("lo", "docker0", "br+"):
            self._run(["-A", self.chain, "-i", interface, "-j", "ACCEPT"])
        self._run(["-A", self.chain, "-j", "DROP"])
        self._run(["-I", "INPUT", "1", "-p", "tcp", "-m", "multiport",
                   "--dports", ",".join(map(str, PORTS)), "-j", self.chain])
        self.attached = True
        self._run(["-S", self.chain])

    @staticmethod
    def active_listeners() -> list[str]:
        # ss is required by the host preflight; inability to inspect fails closed.
        p = subprocess.run(["ss", "-H", "-ltn"], capture_output=True, text=True,
                           timeout=10, check=True)
        result = []
        for line in p.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[3].rsplit(":", 1)[-1] in set(map(str, PORTS)):
                result.append(line)
        return result

    def remove_after_listeners_stop(self):
        listeners = self.active_listeners()
        if listeners:
            raise RuntimeError("Owned ingress rule retained: native listeners still active")
        if self.attached:
            self._run(["-D", "INPUT", "-p", "tcp", "-m", "multiport",
                       "--dports", ",".join(map(str, PORTS)), "-j", self.chain])
            self.attached = False
        if self.created:
            self._run(["-F", self.chain])
            self._run(["-X", self.chain])
            self.created = False
