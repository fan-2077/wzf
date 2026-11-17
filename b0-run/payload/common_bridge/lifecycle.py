"""Common launcher-owned ledger lifecycle guard; no provider content access."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


class LifecycleError(RuntimeError):
    pass


class LedgerGuard:
    def __init__(self, launch_context: dict, logs: str | Path, timeout_seconds: float = 180.0):
        self.context = json.loads(canonical(launch_context))
        for key in ('attempt_id', 'physical_scope_id', 'ledger_epoch', 'namespace_uid'):
            value = self.context.get(key)
            if not isinstance(value, str) or not value or len(value) > 200:
                raise ValueError('Missing launcher identity: ' + key)
        if self.context.get('namespace') != 'gitlab-ce':
            raise ValueError('Fixed task namespace required')
        if not re.fullmatch(r'[a-f0-9]{64}', self.context.get('boundary_proof_sha256', '')):
            raise ValueError('Missing launcher boundary-proof digest')
        self.logs = Path(logs).absolute()
        self.request_directory = self.logs / 'lifecycle-requests'
        self.response_directory = self.logs / 'lifecycle-responses'
        for path in (self.request_directory, self.response_directory):
            if not path.is_dir() or path.is_symlink():
                raise LifecycleError('Launcher-owned guard directories are unavailable')
        self.timeout_seconds = timeout_seconds
        if not 0 < timeout_seconds <= 180:
            raise ValueError('Invalid bounded guard timeout')
        self.sequence = -1
        self.invalid = False
        self.receipts = []

    def check(self, reason: str = 'public_audit_before') -> dict:
        if self.invalid:
            raise LifecycleError('Ledger lifecycle was previously invalidated')
        if reason not in {'bootstrap', 'public_audit_before', 'public_audit_after', 'final_submit'}:
            raise ValueError('Guard reason is a fixed local accounting label')
        nonce = secrets.token_hex(16)
        request = {'schema': 'b0-ledger-guard-request-v1', 'attempt_id': self.context['attempt_id'], 'nonce': nonce}
        request_path = self.request_directory / (nonce + '.json')
        pending = self.request_directory / ('.' + nonce + '.pending')
        raw = canonical(request)
        with pending.open('xb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        if request_path.exists():
            pending.unlink()
            raise LifecycleError('Lifecycle request nonce collision')
        # Publish only the final one-link regular file. A link-then-unlink
        # window could make the host correctly reject st_nlink == 2.
        os.rename(pending, request_path)
        started = time.monotonic()
        response_path = self.response_directory / (nonce + '.json')
        try:
            while not response_path.exists():
                if time.monotonic() - started > self.timeout_seconds:
                    raise LifecycleError('Ledger guard response timed out')
                time.sleep(0.1)
            if response_path.is_symlink():
                raise LifecycleError('Ledger guard response cannot be a symbolic link')
            raw_response = response_path.read_bytes()
            if len(raw_response) > 16384:
                raise LifecycleError('Ledger guard response is oversized')
            response = json.loads(raw_response)
            required = {'schema', 'attempt_id', 'nonce', 'sequence', 'ledger_epoch', 'valid', 'reason_code'}
            if not isinstance(response, dict) or set(response) != required:
                raise LifecycleError('Ledger guard response schema differs')
            if (response['schema'] != 'b0-ledger-guard-response-v1' or response['attempt_id'] != self.context['attempt_id']
                    or response['nonce'] != nonce or type(response['sequence']) is not int or response['sequence'] <= self.sequence
                    or response['ledger_epoch'] != self.context['ledger_epoch'] or response['valid'] is not True
                    or not isinstance(response['reason_code'], str)):
                raise LifecycleError('Ledger lifecycle or causal guard sequence is invalid')
            self.sequence = response['sequence']
            receipt = {**response, 'reason': reason, 'request_sha256': hashlib.sha256(raw).hexdigest(),
                       'response_sha256': hashlib.sha256(raw_response).hexdigest(),
                       'elapsed_seconds': time.monotonic() - started}
            self.receipts.append(receipt)
            return receipt
        except BaseException:
            self.invalid = True
            raise
