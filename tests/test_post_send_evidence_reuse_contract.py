"""Local contracts for one post-terminal queue/audit pair.

The Controller scheduling methods, Driver.run/guarded_audit, CommonFacade,
NativeActionBridge capture binder, SQLite registry and file-IPC LedgerGuard are
real. The target command responder, initial public service certificates and
SMTP terminal verifier are explicitly controlled fixtures. No rendered target
body is executed, no network/model/original task is used, and this does not
qualify an actual SMTP or application runtime.
"""
from __future__ import annotations

import base64
from collections import defaultdict
from contextlib import closing
from copy import deepcopy
import gzip
import json
from pathlib import Path
import shlex
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'b0-run/payload/strategy'), str(ROOT / 'b0-run/payload/common_bridge')]
import catalog
from common_facade import CommonFacade
from common_io import Driver, canonical, digest, parse_capture
from controller import Controller
from native_bridge import NativeActionBridge, BridgeError
import proofs
from proofs import EvidenceGap, notice_key, normalized_receipt
from registry_v2 import ActionRegistry
import target_shell


def encoded(raw):
    return base64.b64encode(raw).decode()


def queue_document():
    snapshot = {'source_complete': True, 'jobs': [], 'work': [], 'processes': [],
        'patterns': {name: {'scan': [{'cursor': '0'}], 'keys': []} for name in
            ('queue:*', 'working:queue:*', '*:work', 'reliable-fetcher-heartbeat-*')},
        'registered_queues': [], 'sets': [{'key': name, 'length': 0} for name in
            ('retry', 'schedule', 'dead', 'interrupted')],
        'inventory_token': digest({'jobs': [], 'work': []})}
    return {'kind': 'queue_inventory', 'source_complete': True, 'stable_payloads': True,
        'redis_role': 'master', 'redis_run_id': 'a' * 40, 'redis_db': 0,
        'before': deepcopy(snapshot), 'after': deepcopy(snapshot)}


def audit_document(items):
    page = {'snapshot': len(items), 'total': len(items), 'items': deepcopy(items), 'next': None}
    raw = canonical(page).encode()
    response = {'method': 'GET', 'path': '/messages', 'status': 200,
        'response_complete': True, 'automatic_retries': 0, 'body': page,
        'body_base64': encoded(raw), 'body_bytes': len(raw), 'body_sha256': digest(raw)}
    return {'kind': 'public_audit', 'source_complete': True, 'fresh_begin': True,
        'snapshot': len(items), 'total': len(items), 'items': deepcopy(items), 'pages': [response]}


def process(pid, *, service=None, session=1):
    return {'pid': pid, 'ppid': 1, 'pgrp': session, 'session': session,
        'starttime': str(pid + 100), 'state': 'S', 'service': service}


def process_snapshot(rows, start, end):
    return {'source_complete': True, 'errors': [], 'unread_live_pids': [],
        'processes': deepcopy(rows), 'listed_before': [row['pid'] for row in rows],
        'listed_after': [row['pid'] for row in rows], 'started_monotonic': start,
        'completed_monotonic': end}


def service_fixture(name, supervisor_pid, main_pid):
    """Complete synthetic certificate shapes, never observed real services."""
    supervisor = {**process(supervisor_pid), 'is_runsv': True,
        'supervisor_cwd_identity': name, 'supervisor_exe_identity': 'fixture-runsv'}
    main = process(main_pid, service=name, session=main_pid)
    source = {'schema': 'b0-fixed-service-source-contract-v1', 'qualified': True,
        'runit_version': '2.1.2', 'actual_manifest_format': 2,
        'actual_runit_manifest_version_fields': {key: '2.1.2' for key in
            ('locked_version', 'described_version', 'display_version')},
        'runit_locked_source_sha256': '6fd0160cb0cf1207de4e66754b6d39750cff14bb0aa66ab49490992c0c47ba18',
        'source_files': ['controlled-source'] * 7, 'binaries': ['controlled-binary'] * 3,
        'template': {}, 'generated_run': {'data_base64': '', 'bytes': 0, 'sha256': digest(b'')}}

    def status(running):
        raw = bytearray(20)
        raw[12:16] = (main_pid if running else 0).to_bytes(4, 'little')
        raw[17], raw[19] = (117, 1) if running else (100, 0)
        return {'service': name, 'qualified': True, 'status_stable_during_snapshot': True,
            'raw_status_base64': encoded(raw), 'raw_status_sha256': digest(bytes(raw)),
            'pid': main_pid if running else 0, 'desired_byte': raw[17], 'state_code': raw[19],
            'state': 'run' if running else 'down', 'desired_not_up': not running,
            'supervisor': deepcopy(supervisor), 'directory': {'identity': name},
            'main_process': deepcopy(main) if running else None}

    before, after = status(True), status(False)
    initial = process_snapshot([supervisor, main], .3, .4)
    final = {'status': after, 'process_snapshot': process_snapshot([supervisor], .7, .8),
        'same_supervisor': True, 'same_clock_identity': True, 'postcondition_satisfied': True,
        'same_owned_live': [], 'service_live': [], 'session_live': [],
        'started_monotonic': .7, 'completed_monotonic': .8}
    command = {'dispatch_count': 1, 'wait_reaped': True, 'exit_code': 0, 'termsig': None,
        'started_monotonic': .5, 'completed_monotonic': .6}
    for stream in ('stdout', 'stderr'):
        command.update({stream + '_base64': '', stream + '_bytes': 0, stream + '_sha256': digest(b'')})
    stop = {'kind': 'service_control', 'service': name, 'verb': 'stop',
        'service_effect_verified': True, 'historical_smtp_terminal_claimed': False,
        'command': command, 'command_exit': 0, 'source_contract_unchanged': True,
        'sticky_gaps': [], 'source_contract': source, 'before_status': before,
        'after_status': after, 'session_scope': main_pid, 'initial_process_snapshot': initial,
        'session_scope_qualified': True, 'pre_control_observations': [
            {'running_session_scope_qualified': True, 'started_monotonic': start,
             'completed_monotonic': end,
             'supervision': {'status': before, 'process_snapshot': initial}}
            for start, end in ((.1, .2), (.3, .4))],
        'observations': [final], 'tracked_processes': [main], 'owned_processes_before': [main],
        'same_owned_live_after': [], 'service_live_after': [], 'session_live_after': [],
        'deadline_monotonic': 120, 'fixed_observation_budget_seconds': 120,
        'action_started_monotonic': 0}
    proofs.service_stop_document(stop)
    return stop, after, source, supervisor


class PairFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        for name in ('lifecycle-requests', 'lifecycle-responses', 'common', 'strategy'):
            (self.path / name).mkdir()
        for name in ('calls', 'actions', 'captures'):
            (self.path / 'common' / name).mkdir()
        (self.path / 'common/call_counter').write_text('0')
        self.context = {'attempt_id': 'controlled-attempt', 'physical_scope_id': 'controlled-scope',
            'ledger_epoch': 'controlled-ledger', 'namespace_uid': 'controlled-namespace',
            'namespace': 'gitlab-ce', 'boundary_proof_sha256': 'f' * 64, 'protocol_id': 'public_result_v1',
            'budgets': {'max_send_attempts_per_intent': 8, 'max_native_calls': 30000},
            'transport_evidence_level': 'local_controlled_transport'}
        self.facade = CommonFacade()
        self.bridge = NativeActionBridge(launch_context=self.context, evidence_directory=self.path / 'common',
            logs_directory=self.path, transport=self.target_responder, submit_transport=None,
            catalog=catalog, trusted_precondition_verifier=self.facade)
        self.bridge.guard.timeout_seconds = 2
        self.target_documents = {}
        self.native_requests = []
        self.accept_on_send = True
        self.queue_override = None
        self.fail_next_start = False
        self.mailbox = []
        self.bridge.targets = {name: {'pod': {'name': 'controlled-' + name.replace('_', '-'), 'container': 'fixture'},
            'root': '/tmp/sregym-fixed-action-v2-' + digest(name.encode()),
            'root_identity': '1:100', 'linux_lifecycle': 'fixture-boot|pid:[1]|mnt:[1]|42'}
            for name in ('gitlab', 'application_client', 'recovery_console')}
        # Only the external target identity probe is a fixture. The real
        # capture binder still compares every journal/argv/query byte.
        self.bridge._current_target = lambda name: self.bridge.targets[name]['pod']
        self.bridge.target_identity = {'pod_uid': 'controlled-gitlab'}
        self.bridge.registry = ActionRegistry.create(self.path / 'common/actions.sqlite', self.bridge.secret)
        self.bridge.adapter = self.bridge.registry.adapter(self.bridge.secret)
        self.bridge.adapter.create_attempt(self.bridge.attempt_id, scope_id=self.context['physical_scope_id'],
            ledger_lifecycle=self.context['ledger_epoch'],
            databases={'application': {'database_key': self.context['physical_scope_id'],
                'target_identity': self.bridge.target_identity}}, programs=self.bridge.program_bindings)
        self.bridge.qualification = {'actual_native_mcp_qualified': True, 'fixture_only': True}
        self.facade.bind(self.bridge)
        self.driver = Driver.__new__(Driver)
        self.driver.context, self.driver.bridge, self.driver.catalog = self.context, self.bridge, catalog
        self.driver.output = self.path / 'strategy'
        self.driver.actions, self.driver.calls, self.driver.failures = 0, 0, []
        self.driver.started, self.driver.wall_limit = time.monotonic(), 60
        self.driver.settle_failed_observers = True
        self.controller = Controller.__new__(Controller)
        self.controller.facade, self.controller.bridge, self.controller.driver = self.facade, self.bridge, self.driver
        self.controller.redis_db = 0
        self.controller.post_send_evidence_pair = None
        self.controller.send_attempts = defaultdict(int)
        self.controller.accepted_intent_skips, self.controller.known_missing = [], []
        self.guard_stop = threading.Event()
        self.guard_errors = []
        self.guard_thread = threading.Thread(target=self.lifecycle_responder, daemon=True)
        self.guard_thread.start()
        self.addCleanup(self.close_guard)
        self.install_public_prerequisites()

    def close_guard(self):
        self.guard_stop.set()
        self.guard_thread.join(2)
        self.assertFalse(self.guard_thread.is_alive())
        self.assertEqual(self.guard_errors, [])

    def lifecycle_responder(self):
        sequence = 0
        try:
            while not self.guard_stop.wait(.002):
                for path in (self.path / 'lifecycle-requests').glob('*.json'):
                    destination = self.path / 'lifecycle-responses' / path.name
                    if destination.exists():
                        continue
                    request = json.loads(path.read_bytes())
                    sequence += 1
                    response = {'schema': 'b0-ledger-guard-response-v1', 'attempt_id': request['attempt_id'],
                        'nonce': request['nonce'], 'sequence': sequence, 'ledger_epoch': self.context['ledger_epoch'],
                        'valid': True, 'reason_code': 'controlled_identity_unchanged'}
                    pending = destination.with_suffix('.pending')
                    pending.write_text(canonical(response))
                    pending.rename(destination)
        except BaseException as error:
            self.guard_errors.append(error)

    def target_responder(self, command, call_id):
        argv = shlex.split(command)
        encoded_argv = argv[argv.index('--') + 1:]
        raw_source = gzip.decompress(base64.b64decode(encoded_argv[4], validate=True))
        self.assertEqual(digest(raw_source), encoded_argv[5])
        self.assertEqual(len(raw_source), int(encoded_argv[6]))
        mode, root, action_hash, binding, arguments, offset, count, stream, root_id, lifecycle = encoded_argv[7:]
        self.native_requests.append({'call_id': call_id, 'mode': mode, 'action_hash': action_hash,
            'arguments': json.loads(arguments), 'command': command})
        journals = [json.loads(path.read_bytes()) for path in (self.path / 'common/actions').glob('*.json')
            if not any(part in path.name for part in ('.start.', '-preconditions.', '.qualified.', '.snapshot-', '.terminal-'))]
        journal = next(row for row in journals if row.get('action_digest') == action_hash)
        action_id = journal['binding']['action_id']
        name = journal['program_name']
        self.assertEqual(raw_source, target_shell.source(catalog.PROGRAMS[name]['body_shell']).encode())
        if mode == 'start':
            if self.fail_next_start:
                self.fail_next_start = False
                raise TimeoutError('controlled lost start reply')
            document = self.document_for(name, json.loads(arguments))
            self.target_documents[action_id] = b'B0_RESULT:' + canonical(document).encode() + b'\n'
        raw = self.target_documents.get(action_id, b'')
        result = {'schema': target_shell.SCHEMA, 'state': 'body_completed' if mode == 'start' else 'target_terminal',
            'binding': binding, 'lifecycle': lifecycle, 'root_identity': root_id,
            'target_process_terminal': True, 'process_pid': 100, 'process_starttime': '42',
            'process_observation': 'controlled_original_identity_absent', 'exit_code': 0,
            'stdout_bytes': len(raw), 'stdout_sha256': digest(raw),
            'stderr_bytes': 0, 'stderr_sha256': digest(b'')}
        if mode == 'chunk':
            data = raw if stream == 'stdout' else b''
            result.update(stream=stream, offset=int(offset),
                chunk_base64=encoded(data[int(offset):int(offset) + int(count)]))
        return {'transport_state': 'response_received', 'trace_complete': True,
            'native_response': {'content': [{'type': 'text', 'text': canonical(result)}], 'isError': False},
            'native_mcp_is_error': False}

    def document_for(self, name, args):
        if name == 'queue_inventory':
            return deepcopy(self.queue_override) if self.queue_override is not None else queue_document()
        if name == 'public_audit':
            return audit_document(self.mailbox)
        if name == 'notification_send':
            if self.accept_on_send:
                receipt = args['intent']
                self.mailbox.append({'id': len(self.mailbox) + 1, 'sender': 'fixture@example.test',
                    'headers': {'X-GitLab-NotificationReason': receipt['reason'],
                        'X-GitLab-Project-Id': str(receipt['project']), 'X-GitLab-Issue-Iid': str(receipt['iid'])},
                    'recipients': [receipt['recipient']], 'subject': receipt['title'], 'body': receipt['description']})
            return {'kind': name, 'intent': args['intent'], 'controlled_target_only': True}
        return deepcopy(self.public_documents[name if name != 'recovery_files' else args['kind']])

    def install_public_prerequisites(self):
        issues = [{'project': 1, 'iid': index, 'title': 'fixture-' + str(index),
            'description': 'controlled-content-' + str(index), 'confidential': False} for index in (1, 2)]
        notices = [{**row, 'recipient': 'user@example.test', 'reason': 'issue-update',
            'recipient_id': 1, 'issue_id_at_acceptance': row['iid'], 'job_id': None, 'provider_job_id': None}
            for row in issues]
        self.public_documents = {'runtime_contract': {'kind': 'runtime_contract', 'approved_runtime': True},
            'background_contract': {'kind': 'background_contract', 'qualified': True,
                'actual_queue_configuration': {'schema': 'b0-actual-Rails-queue-configuration-v1',
                    'source': 'Gitlab::Redis::Queues.params_after_Rails_initialization', 'qualified': True,
                    'host': 'gitlab-redis', 'port': 6379, 'database': 0, 'database_present': True,
                    'database_basis': 'actual_params_db', 'shards': ['main'],
                    'connections_created_by_observer': False,
                    **{name: False for name in ('authentication_present', 'tls_present', 'cluster_present',
                        'sentinels_present', 'unix_socket_present', 'namespace_present')}}},
            'identity_authorization': {'kind': 'identity_authorization', 'source_complete': True,
                'identities': [{'project': row['project'], 'iid': row['iid'], 'recipient': row['recipient'],
                    'matches': True, 'issue_id': row['iid']} for row in notices]}}
        for name, rows in (('issues', issues), ('notifications', notices),
                ('catalog', [{'file': 'fixture.dump', 'status': 'completed', 'sha256': 'a' * 64}])):
            raw = canonical(rows).encode()
            self.public_documents[name] = {'kind': name, 'source_complete': True,
                'data_base64': encoded(raw), 'bytes': len(raw), 'sha256': digest(raw)}
            self.controller.observe('recovery_files', {'kind': name})
        self.facade.declare_public_intents()
        self.controller.observe('runtime_contract', {})
        self.controller.observe('background_contract', {})
        self.controller.observe('identity_authorization', {'intents': [normalized_receipt(row, True) for row in notices]})
        stops = {name: service_fixture(name, supervisor, main) for name, supervisor, main in
            (('puma', 10, 101), ('sidekiq', 20, 102))}
        current_processes = [row[3] for row in stops.values()]
        service_document = {'kind': 'service_inventory', 'source_complete': True,
            'writers_stopped': True, 'processes': current_processes,
            'process_snapshot': process_snapshot(current_processes, 2, 3),
            'statuses': [row[1] for row in stops.values()],
            'source_contracts': {name: row[2] for name, row in stops.items()}}
        # Seed complete, explicitly synthetic pre-existing stop certificates.
        # They pass the unchanged writer_barrier parser but are not real stops.
        for name, row in stops.items():
            handle = 'controlled-stop-' + name
            self.facade.records[handle] = {'handle': handle, 'program': 'service_control',
                'arguments': {'service': name, 'verb': 'stop'}, 'document': row[0],
                'stamp': {'sequence': 0, 'database': 0, 'queue': 0, 'services': 0}}
        self.public_documents['service_inventory'] = service_document
        self.controller.observe('service_inventory', {})
        self.facade._barrier()
        self.controller.refresh_queue()
        self.controller.audit()

    @staticmethod
    def smtp_terminal_fixture(action, capture, bridge):
        value = parse_capture(capture)
        if value.get('controlled_target_only') is not True or value['intent'] != action['request']['parameters']['arguments']['intent']:
            raise AssertionError('not the controlled original notification capture')
        return {'execution_terminal_qualified': True, 'delivery_acceptance_claimed': False,
            'fixture_only_not_SMTP_runtime_qualification': True}

    def begin_send(self, index=0, *, terminal=True):
        receipt = self.facade.notifications[index]
        capture, _ = self.driver.run('notification_send', {'intent': normalized_receipt(receipt, True)},
            settle=False, intent_ref=self.facade.notice_refs[notice_key(receipt)])
        if terminal:
            self.bridge.notification_terminal_verified(capture['action_id'], capture, verifier=self.smtp_terminal_fixture)
        return capture

    def finish_pair(self, capture, *, queue_capture=None, retain=True):
        if queue_capture is None:
            queue_capture, _ = self.controller.refresh_queue()
        ticket = self.bridge.begin_notification_audit(capture['action_id'])
        before = self.bridge.notification_audits[ticket]['before_guard']
        audit_capture, _ = self.driver.run('public_audit', {})
        settled = self.bridge.finish_notification_snapshot(capture['action_id'], ticket, audit_capture,
            verifier=self.facade.notification_snapshot_proof)
        audit_capture['ledger_guards'] = {'before': before, 'after': self.bridge.guard.receipts[-1]}
        self.facade.ingest(audit_capture)
        self.facade.latch_acceptances(reject_conflicts=False)
        self.facade.ingest(capture)
        if retain:
            self.controller.retain_post_send_pair(capture['action_id'], queue_capture, audit_capture, ticket)
        return queue_capture, audit_capture, ticket, settled

    def ready_pair(self):
        capture = self.begin_send()
        self.finish_pair(capture)
        return deepcopy(self.controller.post_send_evidence_pair)

    def ledger_counts(self):
        with closing(self.bridge.registry._connect(readonly=True)) as db:
            return {'send_actions': db.execute("SELECT count(*) FROM actions WHERE operation='send_notification'").fetchone()[0],
                'send_permits': db.execute("SELECT count(*) FROM events e JOIN actions a ON a.attempt=e.attempt AND a.id=e.action "
                    "WHERE e.kind='dispatch_permit_issued' AND a.operation='send_notification'").fetchone()[0],
                'locks': [dict(row) for row in db.execute('SELECT * FROM locks ORDER BY resource')],
                'native_requests': len(self.native_requests),
                'raw_native_request_files': len(list((self.path / 'common/calls').glob('*.request.json')))}

    def assert_rejected_without_new_permission(self, callback, exception=(EvidenceGap, BridgeError), pattern=None):
        before = self.ledger_counts()
        if pattern is None:
            with self.assertRaises(exception):
                callback()
        else:
            with self.assertRaisesRegex(exception, pattern):
                callback()
        self.assertEqual(self.ledger_counts(), before)


class PostSendPairContract(PairFixture):
    def test_real_controller_uses_same_bound_pair_in_both_original_write_guards(self):
        with patch.object(proofs, 'smtp_terminal', self.smtp_terminal_fixture):
            self.controller.send()
        with closing(self.bridge.registry._connect(readonly=True)) as db:
            sends = [dict(row) for row in db.execute("SELECT * FROM actions WHERE operation='send_notification' ORDER BY rowid")]
        self.assertEqual(len(sends), 2)
        first = self.bridge.read_notification_snapshot(sends[0]['id'])
        self.assertEqual(first['causal_attribution_to_this_action'], 'unknown')
        self.assertTrue(all(row['effect'] == 'snapshot_closed' for row in sends))
        retained = json.loads((self.driver.output / ('POST_SEND_EVIDENCE_PAIR_' + sends[0]['id'] + '.json')).read_bytes())
        consumed = json.loads((self.driver.output / ('POST_SEND_EVIDENCE_PAIR_CONSUMED_' + sends[0]['id'] + '.json')).read_bytes())
        self.assertEqual(retained, consumed)
        for phase in ('reserve', 'dispatch'):
            original = json.loads((self.path / 'common/actions' / (sends[1]['id'] + '.' + phase + '-preconditions.json')).read_bytes())
            self.assertIn(retained['queue_handle'], original['qualified_evidence']['evidence_handles'])
            self.assertIn(retained['audit_handle'], original['qualified_evidence']['evidence_handles'])
            self.assertEqual(original['verifier_source_sha256'], self.bridge.precondition_source_sha256)
        self.assertEqual(self.facade.audit_report()['by_intent'][notice_key(self.facade.notifications[1])]['state'], 'accepted')
        self.assertTrue(self.facade.owned_execution_state()['all_owned_actions_closed'])
        self.assertEqual(self.ledger_counts()['send_permits'], 2)

    def test_missing_snapshot_pair_can_feed_only_a_new_post_terminal_attempt(self):
        self.accept_on_send = False
        first = self.begin_send()
        self.finish_pair(first)
        pair = deepcopy(self.controller.post_send_evidence_pair)
        self.assertEqual(self.bridge.read_notification_snapshot(first['action_id'])['intent_snapshot_state'], 'missing')
        self.controller.prepare_notification_evidence()
        self.assertIsNone(self.controller.post_send_evidence_pair)
        self.accept_on_send = True
        second = self.begin_send()
        self.assertNotEqual(first['action_id'], second['action_id'])
        self.finish_pair(second)
        self.assertEqual(self.bridge.read_notification_snapshot(second['action_id'])['intent_snapshot_state'], 'accepted')
        self.assertFalse(self.controller.post_send_pair_is_current(pair))
        with self.assertRaises(Exception):
            self.bridge.reserve('third-send', 'notification_send',
                {'intent': normalized_receipt(self.facade.notifications[0], True)},
                intent_ref=self.facade.notice_refs[notice_key(self.facade.notifications[0])])
        self.assertEqual(self.ledger_counts()['send_permits'], 2)

    def test_first_preparation_with_no_pair_executes_full_fresh_queue_and_guarded_audit(self):
        old_queue, old_audit = self.facade.latest['queue_inventory']['handle'], self.facade.audit['handle']
        before = self.ledger_counts()
        self.controller.prepare_notification_evidence()
        self.assertNotEqual(self.facade.latest['queue_inventory']['handle'], old_queue)
        self.assertNotEqual(self.facade.audit['handle'], old_audit)
        self.assertEqual(self.ledger_counts()['send_permits'], before['send_permits'])
        self.facade._queue()
        self.facade._fresh(self.facade.audit, ('database', 'queue', 'services'))

    def test_queue_from_before_verified_terminal_is_rejected_despite_same_generations(self):
        capture = self.begin_send(terminal=False)
        old_queue, _ = self.controller.refresh_queue()
        self.bridge.notification_terminal_verified(capture['action_id'], capture, verifier=self.smtp_terminal_fixture)
        queue, audit, ticket, _ = self.finish_pair(capture, queue_capture=old_queue, retain=False)
        self.assertEqual(self.facade.latest['queue_inventory']['stamp']['queue'], self.bridge.state()['queue'])
        self.assert_rejected_without_new_permission(lambda: self.controller.retain_post_send_pair(
            capture['action_id'], queue, audit, ticket), pattern='not_after_original_terminal')
        self.assertIsNone(self.controller.post_send_evidence_pair)

    def test_original_ticket_rejects_audit_dispatched_before_ticket(self):
        capture = self.begin_send()
        self.controller.refresh_queue()
        old_audit, _ = self.controller.audit()
        ticket = self.bridge.begin_notification_audit(capture['action_id'])
        self.assert_rejected_without_new_permission(lambda: self.bridge.finish_notification_snapshot(
            capture['action_id'], ticket, old_audit, verifier=self.facade.notification_snapshot_proof),
            pattern='before the original terminal ticket')
        self.assertEqual(len(self.ledger_counts()['locks']), 5)

    def test_pair_cross_attempt_scope_ledger_and_ticket_are_rejected(self):
        original = self.ready_pair()
        for key, value in (('attempt_id', 'other-attempt'), ('physical_scope_id', 'other-scope'),
                ('ledger_epoch', 'other-ledger'), ('capture_ticket', '0' * 48),
                ('snapshot_record_sha256', '0' * 64), ('audit_evidence_id', 'other-evidence')):
            with self.subTest(field=key):
                bad = {**original, key: value}
                self.assert_rejected_without_new_permission(lambda: self.controller.post_send_pair_is_current(bad))

    def test_changed_capture_document_stamp_and_target_do_not_become_refresh_fallback(self):
        pair = self.ready_pair()
        entry = self.facade.records[pair['queue_handle']]
        for field in ('capture', 'document', 'stamp'):
            with self.subTest(field=field):
                original = deepcopy(entry[field])
                if field == 'capture':
                    entry[field]['stdout'] += b'changed'
                elif field == 'document':
                    entry[field]['stable_payloads'] = False
                else:
                    entry[field]['queue'] += 1
                self.assert_rejected_without_new_permission(lambda: self.controller.post_send_pair_is_current(pair))
                entry[field] = original
        self.bridge.targets['application_client']['root_identity'] = '2:999'
        self.assert_rejected_without_new_permission(lambda: self.controller.post_send_pair_is_current(pair))

    def test_incomplete_and_unstable_original_queue_captures_cannot_become_pairs(self):
        for field in ('source_complete', 'stable_payloads'):
            with self.subTest(field=field):
                # Keep a separate fixture for every real incomplete capture so
                # a previous accepted intent cannot affect the counterexample.
                fixture = PairFixture(methodName='runTest')
                fixture.setUp()
                try:
                    capture = fixture.begin_send()
                    fixture.queue_override = queue_document()
                    fixture.queue_override[field] = False
                    queue, audit, ticket, _ = fixture.finish_pair(capture, retain=False)
                    self.assertEqual(fixture.bridge.registry.poll(fixture.bridge.attempt_id, queue['action_id'])['effect'], 'read_only')
                    fixture.assert_rejected_without_new_permission(lambda: fixture.controller.retain_post_send_pair(
                        capture['action_id'], queue, audit, ticket))
                    self.assertIsNone(fixture.controller.post_send_evidence_pair)
                finally:
                    fixture.doCleanups()

    def test_latest_replaced_read_falls_back_to_full_pair_without_reusing_old_permission(self):
        pair = self.ready_pair()
        self.controller.audit()
        replaced = self.facade.audit['handle']
        self.assertFalse(self.controller.post_send_pair_is_current(pair))
        count = self.ledger_counts()['send_permits']
        self.controller.prepare_notification_evidence()
        self.assertNotEqual(self.facade.audit['handle'], replaced)
        self.assertNotEqual(self.facade.latest['queue_inventory']['handle'], pair['queue_handle'])
        self.assertEqual(self.ledger_counts()['send_permits'], count)

    def test_real_completed_mutation_stales_pair_and_requires_original_full_reads(self):
        pair = self.ready_pair()
        self.bridge.registry.reserve(attempt_id=self.bridge.attempt_id, action_id='controlled-mutation',
            role='script', operation='queue_prune', database_ref='application', expected_epoch=0)
        self.bridge.adapter.dispatch(self.bridge.attempt_id, 'controlled-mutation')
        proof = {'evidence_id': 'mutation-terminal', 'target_identity': self.bridge.target_identity, 'details': {}}
        self.bridge.adapter.terminal(self.bridge.attempt_id, 'controlled-mutation', proof)
        eid = self.bridge.adapter.postcondition(self.bridge.attempt_id, 'controlled-mutation',
            {**proof, 'evidence_id': 'mutation-post', 'details': {'settled_effect': 'settled_applied'}})
        self.bridge.adapter.settle(self.bridge.attempt_id, 'controlled-mutation', eid)
        self.assertTrue(self.facade.owned_execution_state()['all_owned_actions_closed'])
        self.assertFalse(self.controller.post_send_pair_is_current(pair))
        self.controller.prepare_notification_evidence()
        self.assertNotEqual(self.facade.latest['queue_inventory']['handle'], pair['queue_handle'])
        self.assertEqual(self.facade.latest['queue_inventory']['stamp']['queue'], self.bridge.state()['queue'])

    def test_unknown_send_and_its_five_locks_prevent_even_fallback_reads(self):
        receipt = self.facade.notifications[0]
        self.bridge.reserve('unknown-send', 'notification_send', {'intent': normalized_receipt(receipt, True)},
            intent_ref=self.facade.notice_refs[notice_key(receipt)])
        self.fail_next_start = True
        original = self.bridge.execute_once('unknown-send')
        self.assertEqual(original['state'], 'unknown')
        self.assertEqual(len(self.ledger_counts()['locks']), 5)
        self.assert_rejected_without_new_permission(self.controller.prepare_notification_evidence,
            pattern='owned_actions_or_locks_unresolved')
        self.assertEqual(self.bridge.registry.poll(self.bridge.attempt_id, 'unknown-send')['effect'], 'unknown')

    def test_unknown_read_after_pair_preserves_lock_and_prevents_reuse_or_fallback(self):
        self.ready_pair()
        self.bridge.registry.reserve(attempt_id=self.bridge.attempt_id, action_id='unknown-observer',
            role='script', operation='observe', database_ref='application', expected_epoch=0)
        self.bridge.adapter.dispatch(self.bridge.attempt_id, 'unknown-observer')
        self.bridge.adapter.mark_unknown(self.bridge.attempt_id, 'unknown-observer', 'controlled-lost-read')
        self.assert_rejected_without_new_permission(self.controller.prepare_notification_evidence,
            pattern='owned_actions_or_locks_unresolved')
        self.assertIsNone(self.controller.post_send_evidence_pair)

    def test_consumption_note_loss_does_not_reinstall_pair_or_issue_write_permission(self):
        self.ready_pair()
        with patch.object(self.controller, 'note', side_effect=OSError('controlled note loss')):
            self.assert_rejected_without_new_permission(self.controller.prepare_notification_evidence, OSError)
        self.assertIsNone(self.controller.post_send_evidence_pair)

    def test_pair_creation_note_loss_stops_real_controller_before_a_second_send(self):
        original_note = self.controller.note

        def lose_pair_note(name, value):
            if name.startswith('POST_SEND_EVIDENCE_PAIR_'):
                raise OSError('controlled pair note loss')
            return original_note(name, value)

        with patch.object(proofs, 'smtp_terminal', self.smtp_terminal_fixture), patch.object(self.controller, 'note', lose_pair_note):
            with self.assertRaisesRegex(OSError, 'pair note loss'):
                self.controller.send()
        self.assertIsNone(self.controller.post_send_evidence_pair)
        self.assertEqual(self.ledger_counts()['send_permits'], 1)
        self.assertTrue(self.facade.owned_execution_state()['all_owned_actions_closed'])

    def test_snapshot_export_loss_keeps_sqlite_closed_but_stops_before_pair_or_second_send(self):
        original_record = self.bridge._new_record

        def lose_export(path, value):
            if path.endswith('.snapshot-closed.json'):
                raise OSError('controlled snapshot export loss')
            return original_record(path, value)

        with patch.object(proofs, 'smtp_terminal', self.smtp_terminal_fixture), patch.object(self.bridge, '_new_record', lose_export):
            with self.assertRaisesRegex(OSError, 'snapshot export loss'):
                self.controller.send()
        self.assertIsNone(self.controller.post_send_evidence_pair)
        self.assertEqual(self.ledger_counts()['send_permits'], 1)
        self.assertTrue(self.facade.owned_execution_state()['all_owned_actions_closed'])
        with closing(self.bridge.registry._connect(readonly=True)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM notification_snapshot_settlements').fetchone()[0], 1)

    def test_original_dispatch_guard_rechecks_queue_after_successful_reuse_and_reservation(self):
        self.ready_pair()
        self.controller.prepare_notification_evidence()
        receipt = self.facade.notifications[1]
        self.bridge.reserve('next-reserved-send', 'notification_send', {'intent': normalized_receipt(receipt, True)},
            intent_ref=self.facade.notice_refs[notice_key(receipt)])
        before = self.ledger_counts()
        self.facade.latest['queue_inventory']['document']['source_complete'] = False
        with self.assertRaisesRegex(EvidenceGap, 'queue_capture_incomplete'):
            self.bridge.execute_once('next-reserved-send')
        self.assertEqual(self.ledger_counts(), before)
        self.assertIsNone(self.bridge.registry.poll(self.bridge.attempt_id, 'next-reserved-send')['dispatch_epoch'])

    def test_invalid_guard_or_changed_finished_ticket_is_never_refreshed(self):
        pair = self.ready_pair()
        self.bridge.guard.invalid = True
        self.assert_rejected_without_new_permission(lambda: self.controller.post_send_pair_is_current(pair), pattern='guard_invalid')
        self.bridge.guard.invalid = False
        with self.bridge.registry._tx() as db:
            db.execute('UPDATE audit_tickets SET finished=0 WHERE token=?', (pair['capture_ticket'],))
        self.assert_rejected_without_new_permission(lambda: self.controller.post_send_pair_is_current(pair), pattern='ticket_changed')


if __name__ == '__main__':
    unittest.main(verbosity=2)
