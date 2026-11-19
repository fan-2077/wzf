"""Local transport fixtures only: no kubectl, remote target or business action.

Exercise the real POSIX decoder, unchanged action envelope, admission order,
and URI accounting. These checks do not qualify any real SREGym target.
"""
from __future__ import annotations

import base64
from contextlib import closing
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'b0-run/payload/strategy'),
                str(ROOT / 'b0-run/payload/common_bridge')]
import catalog
from native_bridge import NativeActionBridge
from registry_v2 import ActionRegistry, OPERATIONS, canonical
import target_shell


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def run_decoder(argv):
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate(timeout=10)
    return process.pid, process.returncode, stdout, stderr


def fixture_target():
    return {'pod': {'name': 'gitlab-ce-fixture', 'container': 'gitlab'},
            'root': '/tmp/sregym-fixed-action-v2-' + 'a' * 64,
            'root_identity': '3145929:12583660',
            'linux_lifecycle': 'ed67923e-547f-4f2c-993b-7ffba6e3eced|pid:[4026534502]|mnt:[4026534501]|61835'}


def notice(title='a'):
    return {'project': 1, 'iid': 1, 'title': title, 'description': '',
            'confidential': False, 'recipient': 'a@example.test', 'reason': 'issue-update'}


class SourceTransport(unittest.TestCase):
    def test_all_seventeen_bodies_and_original_base_stay_exact(self):
        manifest = json.loads((ROOT / 'b0-run/STRATEGY_SOURCE_MANIFEST.json').read_text())
        self.assertEqual(set(catalog.PROGRAMS), set(manifest['programs']))
        self.assertEqual(len(catalog.PROGRAMS), 17)
        self.assertEqual(sha(target_shell.BASE.encode()),
                         '74442e1da44c8383bc38ae8303229c2cae9d79ff601f7f92436c090916c08d5b')
        for name, item in catalog.PROGRAMS.items():
            with self.subTest(program=name):
                self.assertEqual(sha(item['body_shell'].encode()),
                                 manifest['programs'][name]['body_shell_sha256'])
                raw = target_shell.source(item['body_shell']).encode()
                argv = target_shell.encoded_source_argv(raw.decode(), 'zero', ['data'])
                self.assertEqual(argv, target_shell.encoded_source_argv(raw.decode(), 'zero', ['data']))
                compressed = base64.b64decode(argv[4], validate=True)
                self.assertEqual(compressed[4:8], bytes(4))
                self.assertEqual(compressed[9], 255)
                self.assertEqual(gzip.decompress(compressed), raw)
                self.assertEqual(argv[5], target_shell.program_sha256(item['body_shell']))
                self.assertEqual(int(argv[6]), len(raw))
                self.assertEqual(argv[7:], ['data'])

    def test_real_posix_decoder_preserves_pid_argv_and_trailing_newlines(self):
        source = 'printf "%s\\000" "$$" "$0" "$@"\n\n\n'
        arguments = ['', 'literal $(printf NOT_EXECUTED >&2)', "'\";|&<>", 'line1\nline2', '中文']
        argv = target_shell.encoded_source_argv(source, 'original-zero', arguments)
        pid, rc, out, err = run_decoder(argv)
        self.assertEqual((rc, err), (0, b''))
        self.assertEqual(out.split(b'\0'), [str(pid).encode(), b'original-zero',
                                          *(value.encode() for value in arguments), b''])

    def test_bad_base64_exit_is_not_hidden_by_valid_gzip_output(self):
        source = 'printf BODY_MUST_NOT_RUN\n'
        argv = target_shell.encoded_source_argv(source, 'zero', [])
        argv[4] += '!'
        _, rc, out, _ = run_decoder(argv)
        self.assertNotEqual(rc, 0)
        self.assertEqual(out, b'')

    def test_bad_gzip_crc_exit_is_not_hidden_by_complete_plaintext(self):
        argv = target_shell.encoded_source_argv('printf BODY_MUST_NOT_RUN\n', 'zero', [])
        compressed = bytearray(base64.b64decode(argv[4]))
        compressed[-8] ^= 1
        argv[4] = base64.b64encode(compressed).decode()
        _, rc, out, _ = run_decoder(argv)
        self.assertNotEqual(rc, 0)
        self.assertEqual(out, b'')

    def test_nul_insertion_rejected_before_or_after_shell_capture(self):
        original = b'printf BODY_MUST_NOT_RUN\n'
        corrupted = b'\0' + original
        for bind_corrupted_stream in (False, True):
            with self.subTest(bind_corrupted_stream=bind_corrupted_stream):
                argv = target_shell.encoded_source_argv(original.decode(), 'zero', [])
                argv[4] = base64.b64encode(gzip.compress(corrupted, mtime=0)).decode()
                if bind_corrupted_stream:
                    argv[5], argv[6] = sha(corrupted), str(len(corrupted))
                _, rc, out, _ = run_decoder(argv)
                self.assertNotEqual(rc, 0)
                self.assertEqual(out, b'')

    def test_empty_or_mismatched_source_metadata_never_executes(self):
        for mutation in ('hash', 'length', 'empty'):
            with self.subTest(mutation=mutation):
                argv = target_shell.encoded_source_argv('printf BODY_MUST_NOT_RUN\n', 'zero', [])
                if mutation == 'hash':
                    argv[5] = '0' * 64
                elif mutation == 'length':
                    argv[6] = str(int(argv[6]) + 1)
                else:
                    argv[4] = base64.b64encode(gzip.compress(b'', mtime=0)).decode()
                    argv[5], argv[6] = sha(b''), '0'
                _, rc, out, _ = run_decoder(argv)
                self.assertNotEqual(rc, 0)
                self.assertEqual(out, b'')

    def test_actual_envelope_init_start_query_and_duplicate_keep_one_body(self):
        root = Path('/tmp/sregym-fixed-action-v2-' + sha(os.urandom(32)))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        action, binding = 'b' * 64, 'c' * 64
        body = 'printf "%s" "$1"'
        data = canonical({'literal': '$(false)\n中文'})
        common = {'root': str(root), 'action': action, 'binding': root.name.split('-')[-1],
                  'parameters_json': '{}'}
        _, rc, out, err = run_decoder(target_shell.argv(body, mode='init', **common))
        self.assertEqual((rc, err), (0, b''))
        initialized = json.loads(out)
        self.assertEqual(initialized['state'], 'initialized')
        common.update(binding=binding, parameters_json=data,
                      expected_root_identity=initialized['root_identity'],
                      expected_lifecycle=initialized['lifecycle'])
        pid, rc, out, err = run_decoder(target_shell.argv(body, mode='start', **common))
        self.assertEqual((rc, err), (0, b''))
        started = json.loads(out)
        self.assertEqual(started['process_pid'], pid)
        self.assertEqual(started['state'], 'body_completed')
        for mode in ('query', 'start'):
            _, rc, out, err = run_decoder(target_shell.argv(body, mode=mode, **common))
            self.assertEqual((rc, err), (0, b''))
            result = json.loads(out)
            self.assertEqual(result['state'], 'target_terminal')
            self.assertFalse(result['target_claim_won'])
            self.assertEqual(result['process_pid'], pid)
        self.assertEqual((root / action / 'stdout').read_bytes(), data.encode())
        self.assertEqual({path.name for path in root.iterdir()}, {'lifecycle', 'owner', 'probe', action})
        self.assertEqual({path.name for path in (root / action).iterdir()},
                         {'binding', 'parameters', 'process', 'lifecycle', 'body_started',
                          'stdout', 'stderr', 'manifest', 'completion'})


class BeforeGrantBudget(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.registry = ActionRegistry.create(Path(self.temp.name) / 'actions.sqlite', 'fixture-secret-' * 3)
        self.adapter = self.registry.adapter('fixture-secret-' * 3)
        self.programs = {name: 'b' * 64 for name in OPERATIONS}
        self.identity = {'fixture': 'public-target'}
        self.adapter.create_attempt('fixture', scope_id='fixture-scope', ledger_lifecycle='fixture-ledger',
            databases={'application': {'database_key': 'fixture-db', 'target_identity': self.identity}},
            programs=self.programs)
        self.bridge = NativeActionBridge.__new__(NativeActionBridge)
        self.bridge.catalog = catalog
        self.bridge.programs = dict(catalog.PROGRAMS)
        self.bridge.program_bindings = self.programs
        self.bridge.allowed_operations = set(OPERATIONS)
        self.bridge.target_identity = self.identity
        self.bridge.namespace = 'gitlab-ce'
        self.bridge.targets = {name: fixture_target() for name in
                               ('gitlab', 'application_client', 'recovery_console')}
        self.bridge.registry = self.registry
        self.bridge.adapter = self.adapter
        self.bridge.attempt_id = 'fixture'
        self.bridge.role = 'fixture'
        self.bridge.qualification = {'actual_native_mcp_qualified': True}
        self.bridge._current_target = Mock(side_effect=AssertionError('no native target read expected'))
        self.bridge._native = Mock(side_effect=AssertionError('no native request expected'))
        self.bridge._business_preconditions = Mock(side_effect=AssertionError('no business receipt expected'))
        self.adapter.dispatch = Mock(wraps=self.adapter.dispatch)
        self.adapter.mark_unknown = Mock(wraps=self.adapter.mark_unknown)

    def test_url_encoding_has_go_query_escape_shape(self):
        # Fixed vector independently checkable with Go net/url.Values.Encode.
        command = ['sh', '-c', 'a~ /+&%?\n中文', 'zero', 'x=y']
        query = ('command=sh&command=-c&command=a~+%2F%2B%26%25%3F%0A%E4%B8%AD%E6%96%87'
                 '&command=zero&command=x%3Dy&container=gitlab&stderr=true&stdout=true')
        expected = 'POST /api/v1/namespaces/gitlab-ce/pods/pod-a/exec?' + query + ' HTTP/1.1\r\n'
        self.assertEqual(target_shell.exec_request_line_bytes('gitlab-ce', 'pod-a', 'gitlab', command),
                         len(expected.encode()))

    def test_oversized_reservation_has_no_action_lock_or_permission(self):
        arguments = {'intent': notice('@' * 15500)}
        catalog.validate_arguments('notification_send', arguments)
        params = {'fixed_program': 'notification_send', 'arguments': arguments,
                  'precondition_sha256': '0' * 64}
        self.assertLessEqual(len(canonical(params).encode()), 16384)
        with self.assertRaisesRegex(ValueError, 'conservative transport budget'):
            self.bridge.reserve('oversize', 'notification_send', arguments, intent_ref='not-reached')
        with closing(self.registry._connect(readonly=True)) as db:
            self.assertEqual(db.execute('select count(*) from actions').fetchone()[0], 0)
            self.assertEqual(db.execute('select count(*) from locks').fetchone()[0], 0)
        self.adapter.dispatch.assert_not_called()
        self.adapter.mark_unknown.assert_not_called()
        self.bridge._current_target.assert_not_called()
        self.bridge._business_preconditions.assert_not_called()

    def test_pre_dispatch_recheck_leaves_reserved_action_unlaunched(self):
        arguments = {'intents': [notice('@' * 15500)]}
        self.registry.reserve(attempt_id='fixture', action_id='pre-reserved', role='fixture',
            operation='observe', database_ref='application', expected_epoch=0,
            parameters={'fixed_program': 'identity_authorization', 'arguments': arguments})
        with self.assertRaisesRegex(ValueError, 'conservative transport budget'):
            self.bridge.execute_once('pre-reserved')
        action = self.registry.poll('fixture', 'pre-reserved')
        self.assertEqual(action['execution'], 'reserved')
        self.assertIsNone(action['dispatch_epoch'])
        self.adapter.dispatch.assert_not_called()
        self.adapter.mark_unknown.assert_not_called()
        self.bridge._current_target.assert_not_called()

    def test_exec_defense_rejects_without_native_dispatch(self):
        with self.assertRaisesRegex(ValueError, 'conservative transport budget'):
            self.bridge._exec(fixture_target(), catalog.PROGRAMS['notification_send']['body_shell'],
                mode='query', action_digest='c' * 64, binding_digest='d' * 64,
                parameters={'intent': notice('@' * 15500)})
        self.bridge._native.assert_not_called()

    def test_largest_legal_chunk_offset_is_checked_before_grant(self):
        target = fixture_target()
        body = catalog.PROGRAMS['notification_send']['body_shell']
        def start_size(count):
            arguments = {'intent': notice('@' * count)}
            command = target_shell.argv(body, mode='start', root=target['root'], action='0' * 64,
                binding='0' * 64, parameters_json=canonical(arguments),
                expected_root_identity=target['root_identity'], expected_lifecycle=target['linux_lifecycle'])
            return target_shell.exec_request_line_bytes('gitlab-ce', target['pod']['name'],
                                                       target['pod']['container'], command)
        lo, hi = 1, 15500
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if start_size(mid) <= target_shell.MAX_EXEC_REQUEST_LINE_BYTES:
                lo = mid
            else:
                hi = mid - 1
        self.assertLessEqual(start_size(lo), target_shell.MAX_EXEC_REQUEST_LINE_BYTES)
        self.assertGreater(start_size(lo) + 7, target_shell.MAX_EXEC_REQUEST_LINE_BYTES)
        with self.assertRaisesRegex(ValueError, 'conservative transport budget'):
            self.bridge._preflight_exec_budget(target, body, {'intent': notice('@' * lo)})


if __name__ == '__main__':
    unittest.main(verbosity=2)
