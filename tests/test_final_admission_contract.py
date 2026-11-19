"""Exercise the actual final-admission caller, SQLite registry and IPC guard.

Only the external target probe and lifecycle responder are local fixtures.
No service or business recovery is executed by these regression checks.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'b0-run/payload/strategy'),
                str(ROOT / 'b0-run/payload/common_bridge')]
from common_facade import CommonFacade
from lifecycle import LedgerGuard, LifecycleError
from proofs import EvidenceGap
from registry_v2 import ActionRegistry, OPERATIONS


class AdmissionContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        for name in ('lifecycle-requests', 'lifecycle-responses'):
            (self.path / name).mkdir()
        self.context = {
            'attempt_id': 'fixture-attempt', 'physical_scope_id': 'fixture-scope',
            'ledger_epoch': 'fixture-ledger', 'namespace_uid': 'fixture-namespace',
            'namespace': 'gitlab-ce', 'boundary_proof_sha256': 'a' * 64,
            'protocol_id': 'public_result_v1',
        }
        self.guard = LedgerGuard(self.context, self.path, timeout_seconds=2)
        self.registry = ActionRegistry.create(self.path / 'actions.sqlite', 'fixture-secret-' * 3)
        self.adapter = self.registry.adapter('fixture-secret-' * 3)
        self.adapter.create_attempt(
            'fixture-attempt', scope_id='fixture-scope', ledger_lifecycle='fixture-ledger',
            databases={'business': {'database_key': 'db', 'target_identity': {'pod_uid': 'pod-1'}}},
            programs={name: 'b' * 64 for name in OPERATIONS})
        self.bridge = SimpleNamespace(
            context=self.context, attempt_id='fixture-attempt', registry=self.registry,
            qualification={'actual_native_mcp_qualified': True, 'action_id': 'qualified-native'},
            targets={'gitlab': {'pod_uid': 'pod-1'}}, guard=self.guard,
            _current_target=lambda name: {'pod_uid': 'pod-1'},
            state=lambda: {'database_valid': True, 'database': 0, 'queue': 0, 'services': 0})
        self.facade = CommonFacade()
        self.responder_errors = []

    def responder(self, *, ledger=None):
        def run():
            try:
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    requests = list((self.path / 'lifecycle-requests').glob('*.json'))
                    if requests:
                        request = json.loads(requests[0].read_text())
                        response = {
                            'schema': 'b0-ledger-guard-response-v1',
                            'attempt_id': request['attempt_id'], 'nonce': request['nonce'],
                            'sequence': 1, 'ledger_epoch': ledger or 'fixture-ledger',
                            'valid': True, 'reason_code': 'identity_unchanged',
                        }
                        target = self.path / 'lifecycle-responses' / requests[0].name
                        pending = target.with_suffix('.pending')
                        pending.write_text(json.dumps(response))
                        pending.rename(target)
                        return
                    time.sleep(.01)
                raise AssertionError('caller did not publish a lifecycle request')
            except BaseException as error:
                self.responder_errors.append(error)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread

    def test_real_caller_reaches_guard_and_preserves_incomplete_business_result(self):
        thread = self.responder()
        result = self.facade.final_preconditions(self.bridge)
        thread.join(2)
        self.assertEqual(self.responder_errors, [])
        self.assertFalse(thread.is_alive())
        self.assertTrue(result['execution_ready_for_original_evaluation'])
        self.assertEqual(result['ledger_guard']['reason'], 'final_submit')
        self.assertEqual(len(self.guard.receipts), 1)
        self.assertEqual(result['public_snapshot_status'], 'incomplete')
        self.assertIsNone(result['public_checks_passed'])
        self.assertEqual(result['historical_terminal_proof']['status'], 'not_evaluated')
        self.assertFalse(result['historical_terminal_required'])

    def test_original_incompatible_label_is_rejected_before_ipc(self):
        with self.assertRaisesRegex(ValueError, 'fixed local accounting label'):
            self.guard.check('public_result_final_admission')
        self.assertEqual(list((self.path / 'lifecycle-requests').iterdir()), [])

    def test_unknown_owned_action_and_lock_still_prevent_final_evaluation(self):
        self.registry.reserve(attempt_id='fixture-attempt', action_id='unresolved',
                              role='fixture', operation='observe', database_ref='business',
                              expected_epoch=0)
        self.adapter.dispatch('fixture-attempt', 'unresolved')
        self.adapter.mark_unknown('fixture-attempt', 'unresolved', 'transport disconnected')
        with self.assertRaisesRegex(EvidenceGap, 'owned_actions_or_locks_unresolved'):
            self.facade.final_preconditions(self.bridge)
        self.assertEqual(list((self.path / 'lifecycle-requests').iterdir()), [])
        self.assertIsNone(self.facade.final_admission)

    def test_ledger_epoch_change_still_invalidates_guard(self):
        thread = self.responder(ledger='different-ledger')
        with self.assertRaisesRegex(LifecycleError, 'lifecycle or causal guard sequence'):
            self.facade.final_preconditions(self.bridge)
        thread.join(2)
        self.assertTrue(self.guard.invalid)
        self.assertIsNone(self.facade.final_admission)

    def test_known_business_failure_keeps_original_evaluation_available(self):
        self.facade.public_business_snapshot = lambda: {
            'status': 'known_fail', 'evidence_handles': ['fixture-complete-audit'],
            'incomplete_reasons': [], 'known_failure_reasons': ['duplicate_observed'],
        }
        thread = self.responder()
        result = self.facade.final_preconditions(self.bridge)
        thread.join(2)
        self.assertTrue(result['execution_ready_for_original_evaluation'])
        self.assertFalse(result['public_checks_passed'])
        self.assertEqual(result['public_snapshot_status'], 'known_fail')


if __name__ == '__main__':
    unittest.main(verbosity=2)
