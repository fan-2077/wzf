"""Local subprocess/SQLite fault fixtures; no B0 recovery or model execution."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1]
REPOSITORY = SOURCE.parent
sys.path.insert(0, str(SOURCE))
from controller_adapter import (build_payload_overlay, canonical, clean_entry_environment,
                                digest, helper_id, verify_payload)
from session_owner import REQUEST_SCHEMA, SessionOwner


FIXTURE_CHILD = r'''
import json, pathlib, sys, time
result, marker, release, attempt, mode = sys.argv[1:]
result, marker, release = map(pathlib.Path, (result, marker, release))
with marker.open('a') as f: f.write('controlled-fixture-start\n'); f.flush()
print('controlled subprocess only; not original B0', flush=True)
if mode == 'no_result': raise SystemExit(0)
value = json.dumps({'attempt_id': attempt, 'status': 'fixture_completed',
                    'business_success': True, 'fixture_only': True})
output = result.open('w')
if mode == 'partial':
    output.write(value[:10]); output.flush()
    marker.with_suffix('.partial').write_text('partial-result-open')
deadline = time.monotonic() + 4
while not release.exists() and time.monotonic() < deadline: time.sleep(.01)
if not release.exists(): raise SystemExit(9)
output.write(value[10:] if mode == 'partial' else value); output.flush(); output.close()
'''


def fixture_identity():
    return {'attempt_id': 'local-controlled-session', 'physical_scope_id': 'scope-fixture',
            'ledger_epoch': 'ledger-fixture', 'namespace_uid': 'namespace-fixture',
            'role': 'single', 'launch_context_sha256': '1' * 64,
            'derived_payload_binding_sha256': '2' * 64}


class ControlledLauncher:
    def __init__(self, directory, identity, mode='normal', fail_after_spawn=False):
        self.directory = directory
        self.identity = identity
        self.mode = mode
        self.fail_after_spawn = fail_after_spawn
        self.calls = 0
        self.children = []
        self.observed_reserved_before_spawn = False
        self.result = directory / 'fixture_result.json'
        self.marker = directory / 'fixture_starts'
        self.release = directory / 'fixture_release'

    def __call__(self, reservation, stdout, stderr):
        self.calls += 1
        # This is a different real SQLite connection, before the real Popen.
        db = sqlite3.connect(Path(reservation).parent / 'owner.sqlite')
        row = db.execute('select state,launch_reservations from helper').fetchone()
        db.close()
        self.observed_reserved_before_spawn = row == ('launch_reserved', 1)
        if not self.observed_reserved_before_spawn:
            raise AssertionError('reservation was not durable before subprocess')
        child = subprocess.Popen([sys.executable, '-B', '-c', FIXTURE_CHILD,
            str(self.result), str(self.marker), str(self.release), self.identity['attempt_id'], self.mode],
            stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL, close_fds=True)
        self.children.append(child)
        if self.fail_after_spawn:
            raise OSError('controlled failure after actual Popen before owner identity record')
        return child

    def cleanup(self):
        self.release.write_text('release controlled child')
        for child in self.children:
            child.wait(timeout=5)


class SessionOwnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='b1-owner-')
        self.directory = Path(self.temporary.name)
        self.identity = fixture_identity()
        self.launchers = []
        self.owners = []
        self.threads = []

    def tearDown(self):
        for launcher in self.launchers:
            launcher.cleanup()
        for owner in self.owners:
            owner.stop()
        for thread in self.threads:
            thread.join(timeout=3)
        for owner in self.owners:
            owner.close()
        self.temporary.cleanup()

    def make_owner(self, *, mode='normal', fail_after_spawn=False, identity=None):
        identity = identity or self.identity
        launcher = ControlledLauncher(self.directory, identity, mode, fail_after_spawn)
        self.launchers.append(launcher)
        owner = SessionOwner(self.directory / 'session', identity, launcher, result_path=launcher.result)
        self.owners.append(owner)
        return owner, launcher

    def request(self, owner, operation='start', rid='a' * 32, parent=None):
        value = {'schema': REQUEST_SCHEMA, 'operation': operation,
                 'request_id': rid, 'helper_id': owner.helper_id}
        if operation == 'start':
            value.update(parameters={}, parent_model_request_id=parent)
        return value

    def until(self, predicate):
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(.01)
        self.fail('bounded fixture did not reach expected state')

    def finished(self, owner):
        def observed():
            reply = owner.handle(self.request(owner, 'poll'))
            return reply if reply['session']['state'] in {'process_exited', 'unknown'} else None
        return self.until(observed)

    def require_real_ipc(self):
        try:
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        except PermissionError as error:
            if os.environ.get('B1_REQUIRE_REAL_IPC') == '1':
                self.fail('B1_REQUIRE_REAL_IPC=1 but actual AF_UNIX is unavailable: ' + str(error))
            self.skipTest('actual AF_UNIX creation is denied by this local environment; IPC qualification pending: ' + str(error))
        else:
            probe.close()

    def test_poll_never_reserves_and_second_owner_is_excluded(self):
        owner, launcher = self.make_owner()
        identity = json.loads((owner.root / 'session_identity.json').read_bytes())
        self.assertEqual(identity['helper_id'], helper_id(self.identity))
        for _ in range(3):
            reply = owner.handle(self.request(owner, 'poll'))
            self.assertEqual(reply['session']['state'], 'ready')
            self.assertEqual(reply['session']['launch_reservations'], 0)
            self.assertEqual(reply['session']['request_binding'], 'not_registered')
        self.assertEqual(launcher.calls, 0)
        with self.assertRaises(BlockingIOError):
            SessionOwner(owner.root, self.identity, launcher, result_path=launcher.result)

    def test_same_request_is_idempotent_and_new_id_never_starts_second_macro(self):
        owner, launcher = self.make_owner()
        first = owner.handle(self.request(owner, parent='c' * 32))
        self.assertEqual(first['disposition'], 'accepted')
        self.assertTrue(launcher.observed_reserved_before_spawn)
        duplicate = owner.handle(self.request(owner, parent='c' * 32))
        self.assertEqual(duplicate['disposition'], 'same_request')
        other = owner.handle(self.request(owner, rid='b' * 32))
        self.assertEqual(other['disposition'], 'already_reserved_other_request')
        self.assertEqual(other['session']['original_request_id'], 'a' * 32)
        changed = self.request(owner, parent='c' * 32)
        changed['parameters'] = {'unapproved': True}
        self.assertEqual(owner.handle(changed)['error']['code'], 'request_id_conflict')
        changed_parent = owner.handle(self.request(owner, parent='d' * 32))
        self.assertEqual(changed_parent['error']['code'], 'request_id_conflict')
        self.assertEqual(launcher.calls, 1)
        self.assertEqual(first['session']['launch_reservations'], 1)

    def test_caller_cannot_supply_role_or_command(self):
        owner, launcher = self.make_owner()
        for key in ('role', 'command', 'budget', 'clock'):
            request = self.request(owner)
            request[key] = 'caller-controlled'
            self.assertFalse(owner.handle(request)['ok'])
        for operation in ([], {}):
            request = self.request(owner, 'poll')
            request['operation'] = operation
            rejected = owner.handle(request)
            self.assertFalse(rejected['ok'])
            self.assertEqual(rejected['error']['code'], 'request_schema_or_operation_invalid')
            self.assertEqual(rejected['session']['state'], 'ready')
            self.assertEqual(rejected['session']['launch_reservations'], 0)
        self.assertEqual(launcher.calls, 0)
        self.assertEqual(owner.handle(self.request(owner, 'poll'))['session']['state'], 'ready')

    def test_partial_result_is_ignored_until_original_process_exits(self):
        owner, launcher = self.make_owner(mode='partial')
        owner.handle(self.request(owner))
        self.until(lambda: launcher.marker.with_suffix('.partial').exists())
        reply = owner.handle(self.request(owner, 'poll'))
        self.assertEqual(reply['session']['state'], 'running')
        self.assertIsNone(reply['session']['controller_result_handle'])
        self.assertIsNone(reply['session']['uncertainty'])
        launcher.release.write_text('finish fixture JSON')
        terminal = self.finished(owner)['session']
        self.assertEqual(terminal['state'], 'process_exited')
        handle = terminal['controller_result_handle']
        self.assertEqual(handle['sha256'], digest(launcher.result.read_bytes()))
        self.assertEqual((owner.root / handle['relative_path']).read_bytes(), launcher.result.read_bytes())
        # The controlled child intentionally reports True; owner never turns it into a native score.
        self.assertIsNone(terminal['business_success'])
        self.assertIsNone(terminal['original_host_evaluation_result'])
        self.assertEqual(terminal['helper_model_calls'], 0)
        self.assertIn('outer B1', terminal['helper_model_calls_scope'])

    def test_exit_zero_without_controller_result_is_unknown_and_not_retryable(self):
        owner, launcher = self.make_owner(mode='no_result')
        owner.handle(self.request(owner))
        terminal = self.finished(owner)['session']
        self.assertEqual(terminal['state'], 'unknown')
        self.assertEqual(terminal['process']['returncode'], 0)
        self.assertIsNone(terminal['controller_result_handle'])
        self.assertEqual(owner.handle(self.request(owner, rid='b' * 32))['disposition'], 'already_reserved_other_request')
        self.assertEqual(launcher.calls, 1)

    def test_actual_spawn_then_identity_record_failure_preserves_unknown(self):
        owner, launcher = self.make_owner(fail_after_spawn=True)
        reply = owner.handle(self.request(owner))
        self.assertEqual(reply['session']['state'], 'unknown')
        self.until(launcher.marker.exists)
        self.assertEqual(len(launcher.children), 1)
        self.assertIsNone(reply['session']['process'])
        owner.handle(self.request(owner))
        owner.handle(self.request(owner, rid='b' * 32))
        self.assertEqual(launcher.calls, 1)

    def test_owner_close_and_reopen_never_respawns_running_original(self):
        owner, launcher = self.make_owner()
        owner.handle(self.request(owner))
        self.until(launcher.marker.exists)
        pid = launcher.children[0].pid
        owner.close()
        self.assertIsNone(launcher.children[0].poll())
        replacement, new_launcher = self.make_owner()
        reply = replacement.handle(self.request(replacement))
        self.assertEqual(reply['session']['state'], 'unknown')
        self.assertEqual(reply['session']['process']['pid'], pid)
        self.assertEqual(reply['session']['launch_reservations'], 1)
        self.assertEqual(new_launcher.calls, 0)

    def test_real_owner_crash_after_sql_commit_before_Popen_leaves_unknown(self):
        root = self.directory / 'session'
        code = r'''
import json,os,pathlib,sys
sys.path.insert(0,sys.argv[1])
from session_owner import SessionOwner,REQUEST_SCHEMA
identity=json.loads(sys.argv[3])
def never_spawn(reservation,stdout,stderr): os._exit(73)
owner=SessionOwner(sys.argv[2],identity,never_spawn,result_path=pathlib.Path(sys.argv[2]).parent/'fixture_result.json')
owner.handle({'schema':REQUEST_SCHEMA,'operation':'start','request_id':'a'*32,'helper_id':owner.helper_id,'parameters':{},'parent_model_request_id':None})
'''
        result = subprocess.run([sys.executable, '-B', '-c', code, str(SOURCE), str(root), json.dumps(self.identity)],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 73, result.stderr)
        owner, launcher = self.make_owner()
        reply = owner.handle(self.request(owner))
        self.assertEqual(reply['session']['state'], 'unknown')
        self.assertEqual(reply['session']['uncertainty'], 'owner_restarted_after_reservation')
        self.assertEqual(reply['session']['launch_reservations'], 1)
        self.assertIsNone(reply['session']['process'])
        self.assertEqual(launcher.calls, 0)

    def test_different_trusted_identity_cannot_rebind_durable_session(self):
        owner, launcher = self.make_owner()
        owner.close()
        changed = {**self.identity, 'launch_context_sha256': '3' * 64}
        with self.assertRaisesRegex(ValueError, 'cannot_rebind'):
            SessionOwner(owner.root, changed, launcher, result_path=launcher.result)

    def test_lost_start_reply_keeps_original_helper_queryable_over_real_socket(self):
        self.require_real_ipc()
        owner, launcher = self.make_owner()
        thread = threading.Thread(target=owner.serve_forever)
        self.threads.append(thread)
        thread.start()
        self.until(owner.socket_path.exists)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(str(owner.socket_path))
            connection.sendall(canonical(self.request(owner)) + b'\n')
            # Intentionally close without receiving the accepted reply.
        self.until(launcher.marker.exists)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(str(owner.socket_path))
            connection.sendall(canonical(self.request(owner, 'poll')) + b'\n')
            raw = b''
            while not raw.endswith(b'\n'):
                raw += connection.recv(65536)
        reply = json.loads(raw)
        self.assertEqual(reply['helper_id'], owner.helper_id)
        self.assertEqual(reply['session']['original_request_id'], 'a' * 32)
        self.assertEqual(launcher.calls, 1)
        self.assertIsNone(launcher.children[0].poll())

    def test_invalid_operation_over_real_socket_preserves_running_helper_and_owner(self):
        self.require_real_ipc()
        owner, launcher = self.make_owner()
        thread = threading.Thread(target=owner.serve_forever)
        self.threads.append(thread)
        thread.start()
        self.until(owner.socket_path.exists)

        def exchange(request):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(2)
                connection.connect(str(owner.socket_path))
                connection.sendall(canonical(request) + b'\n')
                raw = b''
                while not raw.endswith(b'\n'):
                    fragment = connection.recv(65536)
                    self.assertTrue(fragment, 'owner closed without a fixed protocol response')
                    raw += fragment
            return json.loads(raw)

        accepted = exchange(self.request(owner))
        self.assertTrue(accepted['ok'])
        self.until(launcher.marker.exists)
        process = accepted['session']['process']
        for operation in ([], {}):
            request = self.request(owner, 'poll')
            request['operation'] = operation
            rejected = exchange(request)
            self.assertFalse(rejected['ok'])
            self.assertEqual(rejected['error']['code'], 'request_schema_or_operation_invalid')
            self.assertEqual(rejected['session']['state'], 'running')
            self.assertEqual(rejected['session']['process'], process)
            self.assertEqual(rejected['session']['original_request_id'], 'a' * 32)
            self.assertEqual(rejected['session']['launch_reservations'], 1)
            self.assertIsNone(rejected['session']['uncertainty'])
            self.assertTrue(thread.is_alive())
            self.assertIsNone(launcher.children[0].poll())
            self.assertEqual(launcher.calls, 1)

        launcher.release.write_text('finish original controlled subprocess')
        def terminal_reply():
            reply = exchange(self.request(owner, 'poll'))
            return reply if reply['session']['state'] in {'process_exited', 'unknown'} else None
        completed = self.until(terminal_reply)
        self.assertEqual(completed['session']['state'], 'process_exited')
        self.assertEqual(completed['session']['process']['pid'], process['pid'])
        self.assertEqual(completed['session']['launch_reservations'], 1)
        self.assertIsNotNone(completed['session']['controller_result_handle'])
        self.assertEqual(launcher.calls, 1)
        self.assertEqual(launcher.marker.read_text().count('controlled-fixture-start'), 1)
        self.assertTrue(thread.is_alive())


class ActualSourceDerivationTests(unittest.TestCase):
    def test_actual_frozen_payload_has_only_reviewed_role_change(self):
        with tempfile.TemporaryDirectory(prefix='b1-payload-') as directory:
            destination = Path(directory) / 'derived'
            binding = build_payload_overlay(REPOSITORY / 'b0-run', destination)
            verified = verify_payload(destination / 'payload', destination / 'DERIVED_PAYLOAD_BINDING.json')
            self.assertEqual(set(verified['actual_source_hashes']), set(binding['files']))
            changed = [name for name, item in binding['files'].items() if item['base_sha256'] != item['derived_sha256']]
            self.assertEqual(changed, ['strategy/common_io.py'])
            for name in ('integration/agent_entry.py', 'strategy/controller.py'):
                self.assertEqual((destination / 'payload' / name).read_bytes(),
                                 (REPOSITORY / 'b0-run/payload' / name).read_bytes())
            env = clean_entry_environment({'PYTHONPATH': '/unapproved', 'PYTHONHOME': '/unapproved', 'PATH': '/usr/bin'})
            self.assertNotIn('/unapproved', env['PYTHONPATH'])
            self.assertNotIn('PYTHONHOME', env)
            self.assertEqual(env['PYTHONPATH'], '/opt/b0/common_bridge:/opt/b0/strategy:/opt/b0/native_adapter:/opt/b0/integration')
            # A source change after generation must fail actual-byte verification.
            with (destination / 'payload/strategy/controller.py').open('ab') as stream:
                stream.write(b'\n# unreviewed fixture modification\n')
            with self.assertRaisesRegex(ValueError, 'unreviewed_change'):
                verify_payload(destination / 'payload', destination / 'DERIVED_PAYLOAD_BINDING.json')

    def test_only_fixed_SQLite_binary_is_allowed_and_it_must_match_build_record(self):
        with tempfile.TemporaryDirectory(prefix='b1-runtime-') as directory:
            destination = Path(directory) / 'derived'
            build_payload_overlay(REPOSITORY / 'b0-run', destination)
            payload = destination / 'payload'
            binding_path = destination / 'DERIVED_PAYLOAD_BINDING.json'
            with self.assertRaisesRegex(ValueError, 'runtime_library_missing'):
                verify_payload(payload, binding_path, require_runtime=True)
            (payload / 'sqlite').mkdir()
            (payload / 'build-record').mkdir()
            library = payload / 'sqlite/libsqlite3.so.0'
            library.write_bytes(b'not a runtime; controlled file-binding fixture only')
            record = payload / 'build-record/sqlite-binary.sha256'
            record.write_text(digest(library.read_bytes()) + '  /opt/b0/sqlite/libsqlite3.so.0\n')
            verified = verify_payload(payload, binding_path, require_runtime=True)
            self.assertIn('sqlite/libsqlite3.so.0', verified['runtime_artifacts'])
            library.write_bytes(b'corrupted fixture')
            with self.assertRaisesRegex(ValueError, 'build_record_mismatch'):
                verify_payload(payload, binding_path, require_runtime=True)


if __name__ == '__main__':
    unittest.main()
