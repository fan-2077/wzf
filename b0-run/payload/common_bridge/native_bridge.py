"""Trusted common fixed-action adapter over the unchanged native MCP transport.

This layer has no business recovery policy. Program sources and validators are
trusted deployment inputs, never tool parameters. Every ordinary read/write is
bound to the same registry, fixed target envelope and native call journal.
"""
from __future__ import annotations
from contextlib import closing
import base64
import fcntl
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import sqlite3
import time
from typing import Callable

import registry_v2 as registry
import target_shell
from lifecycle import LedgerGuard

HEX = re.compile(r'[0-9a-f]{64}\Z')
ID = re.compile(r'[A-Za-z0-9_-]{1,80}\Z')
DNS = re.compile(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z')
TARGETS = {'recovery_console': ('recovery-console', 'tools', None),
           'application_client': ('application-client', 'client', None),
           'gitlab': (None, 'gitlab', 'app=gitlab-ce')}
READ_CONTRACT_BODY = '''printf '{"kind":"fixed_runtime_observation","shell":"posix","uid":%s,"process_pid":%s,"site_hooks":"not_applicable","chunk_probe":"' "$(id -u)" "$$"
probe_index=0
while [ "$probe_index" -lt 416 ]; do
  printf '0123456789abcdef'
  probe_index=$((probe_index + 1))
done
printf '"}\\n'
'''
READ_CONTRACT_PROBE = '0123456789abcdef' * 416
NATIVE_MAX_CHARACTERS = 10000


def canonical(value):
    return registry.canonical(value).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class BridgeError(RuntimeError):
    pass


def sqlite_runtime() -> dict:
    version = tuple(map(int, sqlite3.sqlite_version.split('.')))
    # Official fixed primary release or fixed maintenance release. The launcher
    # separately pins actual source and artifact; this is a runtime safety floor.
    fixed = version >= (3, 51, 3) or ((3, 50, 7) <= version < (3, 51, 0)) or ((3, 44, 6) <= version < (3, 45, 0))
    if not fixed:
        raise BridgeError('SQLite runtime lacks the qualified WAL-reset fix')
    with closing(sqlite3.connect(':memory:')) as db:
        source_id = db.execute('SELECT sqlite_source_id()').fetchone()[0]
    return {'sqlite_version': sqlite3.sqlite_version, 'sqlite_source_id': source_id, 'wal_reset_fix_floor': fixed}


def native_text(response: dict) -> str:
    if response.get('transport_state') != 'response_received' or response.get('trace_complete') is not True:
        raise BridgeError('Native transport outcome or audit is incomplete')
    value = response.get('native_response')
    if not isinstance(value, dict) or value.get('isError') is True or response.get('native_mcp_is_error') is True:
        raise BridgeError('Native MCP error')
    content = value.get('content')
    if not isinstance(content, list) or len(content) != 1 or content[0].get('type') != 'text':
        raise BridgeError('Native text envelope is malformed')
    text = content[0].get('text')
    if not isinstance(text, str) or len(text) > NATIVE_MAX_CHARACTERS or '... [truncated]' in text:
        raise BridgeError('Native output is truncated or oversized')
    if text.lstrip().startswith(('Command Rejected', 'Dry-run failed', 'Error executing kubectl', 'Dry-run timed out')):
        raise BridgeError('Native filter or executor rejected the fixed command')
    return text


class NativeActionBridge:
    """Privileged adapter object: expose only reviewed public facade to agents.

    transport(command, call_id) is exactly the original filtered MCP path.
    submit_transport(solution, call_id) is exactly the original /submit path.
    Callback validators must verify actual immutable evidence. They are not
    caller booleans or arbitrary model-supplied code.
    """
    def __init__(self, *, launch_context: dict, evidence_directory: str | Path,
                 logs_directory: str | Path, transport: Callable,
                 submit_transport: Callable | None, catalog, role: str = 'script', api_read_transport: Callable | None = None,
                 trusted_precondition_verifier: Callable | None = None):
        if role not in {'script', 'single', 'coordinator', 'database', 'business_identity', 'queue', 'delivery_audit'}:
            raise ValueError('Unknown declared comparison role')
        self.context = json.loads(canonical(launch_context))
        if self.context.get('protocol_id') != registry.NOTIFICATION_SETTLEMENT_PROTOCOL:
            raise ValueError('Fixed public_result_v1 launch protocol is required')
        if (type(self.context.get('budgets', {}).get('max_send_attempts_per_intent')) is not int
                or self.context['budgets']['max_send_attempts_per_intent'] != registry.MAX_SEND_ATTEMPTS_PER_INTENT):
            raise ValueError('Public-result profile requires the fixed eight-attempt budget')
        self.attempt_id = self.context['attempt_id']
        if not ID.fullmatch(self.attempt_id):
            raise ValueError('Invalid native attempt id')
        self.role = role
        self.transport_evidence_level = self.context.get('transport_evidence_level', 'unqualified_transport')
        if self.transport_evidence_level not in {'native_filtered_execution', 'local_controlled_transport', 'unqualified_transport'}:
            raise ValueError('Unknown launcher-declared transport evidence level')
        self.mode = self.context.get('mode', 'public_b0')
        declared_operations = self.context.get('allowed_operations', sorted(registry.OPERATIONS))
        if (self.mode not in {'native_readonly_qualification', 'public_b0'}
                or not isinstance(declared_operations, list) or not declared_operations
                or len(set(declared_operations)) != len(declared_operations)
                or not set(declared_operations) <= registry.OPERATIONS):
            raise ValueError('Invalid fixed execution mode or enabled operation catalog')
        self.allowed_operations = set(declared_operations)
        if self.mode == 'native_readonly_qualification' and self.allowed_operations != {'observe'}:
            raise ValueError('Read-only qualification must explicitly enable observe only')
        self.namespace = self.context['namespace']
        if self.namespace != 'gitlab-ce':
            raise ValueError('Only the fixed task namespace is supported')
        self.directory = Path(evidence_directory).absolute()
        self.transport = transport
        self.submit_transport = submit_transport
        self.api_read_transport = api_read_transport
        self.catalog = catalog
        self.precondition_verifier = trusted_precondition_verifier
        self.precondition_source = None
        self.precondition_source_sha256 = None
        if trusted_precondition_verifier is not None:
            if not callable(trusted_precondition_verifier):
                raise ValueError('Trusted deployment precondition verifier must be callable')
            source = inspect.getsourcefile(trusted_precondition_verifier if inspect.isfunction(trusted_precondition_verifier)
                                          else type(trusted_precondition_verifier))
            if not source or not Path(source).is_file():
                raise ValueError('Fixed precondition verifier source must be available')
            self.precondition_source = Path(source).absolute()
            self.precondition_source_sha256 = digest(self.precondition_source.read_bytes())
        self.guard = LedgerGuard(self.context, logs_directory)
        self.runtime = sqlite_runtime()
        self.targets = {}
        self.registry = None
        self.adapter = None
        self.target_identity = None
        self.call_trace = []
        self.qualification = {}
        self.notification_audits = {}
        self.secret = secrets.token_hex(32)
        self.programs = json.loads(canonical(catalog.PROGRAMS))
        catalog_path = Path(catalog.__file__)
        if not catalog_path.is_file():
            raise ValueError('Fixed catalog source file is required')
        self.catalog_source_sha256 = digest(catalog_path.read_bytes())
        if '__fixed_runtime_observer' in self.programs:
            raise ValueError('Reserved common observer name')
        self.programs['__fixed_runtime_observer'] = {'operation': 'observe', 'target': 'application_client',
                                                   'body_shell': READ_CONTRACT_BODY}
        self.program_bindings = {}
        self.program_enablement = {}
        for operation in registry.OPERATIONS:
            selected = {name: {'target': item['target'], 'wrapper_sha256': target_shell.program_sha256(item['body_shell'])}
                        for name, item in self.programs.items() if item['operation'] == operation}
            if operation == 'final_submit':
                selected = {'native_original_submit': {'contract': 'unique-original-evaluation-v2'}}
            if not selected and operation in self.allowed_operations:
                raise ValueError('No deployed fixed program for operation: ' + operation)
            if operation not in self.allowed_operations:
                selected = {'disabled': {'operation': operation, 'executable_binding': False}}
            self.program_bindings[operation] = digest(canonical({'programs': selected,
                                                                'catalog_source_sha256': self.catalog_source_sha256,
                                                                'protocol_id': registry.NOTIFICATION_SETTLEMENT_PROTOCOL,
                                                                'precondition_source_sha256': self.precondition_source_sha256 if operation != 'observe' else None}))
            self.program_enablement[operation] = {'enabled': operation in self.allowed_operations,
                                                  'binding_sha256': self.program_bindings[operation],
                                                  'binding_kind': 'fixed_program_catalog' if operation in self.allowed_operations else 'explicit_disabled_marker'}
        for name, item in self.programs.items():
            if not ID.fullmatch(name) or item['operation'] not in registry.OPERATIONS or item['target'] not in TARGETS:
                raise ValueError('Invalid fixed program catalog')

    def _new_record(self, relative: str, value):
        path = self.directory / relative
        if path.parent.is_symlink() or path.is_symlink():
            raise BridgeError('Own evidence path is a symlink')
        raw = canonical(value)
        with path.open('xb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        return {'path': str(path.relative_to(self.directory)), 'sha256': digest(raw), 'bytes': len(raw)}

    def _next_call(self, purpose: str):
        path = self.directory / 'call_counter'
        with path.open('r+') as output:
            fcntl.flock(output.fileno(), fcntl.LOCK_EX)
            count = int(output.read()) + 1
            maximum = self.context.get('budgets', {}).get('max_native_calls', 4096)
            if type(maximum) is not int or maximum < 1 or count > maximum:
                raise BridgeError('Common aggregate native call budget exceeded')
            output.seek(0)
            output.write(str(count))
            output.truncate()
            output.flush()
            os.fsync(output.fileno())
        return f'b0-{count:06d}-{secrets.token_hex(6)}'

    def _native(self, argv: list[str], purpose: str):
        command = shlex.join(argv)
        if shlex.split(command) != argv:
            raise BridgeError('Fixed native argv round trip failed')
        call_id = self._next_call(purpose)
        before = {'call_id': call_id, 'purpose': purpose, 'operation': 'kubectl',
                  'command_sha256': digest(command.encode()), 'command': command,
                  'monotonic': time.monotonic()}
        self._new_record('calls/' + call_id + '.request.json', before)
        result = self.transport(command, call_id)
        record = self._new_record('calls/' + call_id + '.response.json', result)
        text = native_text(result)
        self.call_trace.append({'call_id': call_id, 'purpose': purpose, 'response': record,
                                'output_characters': len(text), 'output_bytes': len(text.encode()),
                                'native_truncation_detected': False})
        return text, call_id

    def _pod(self, name: str):
        pod_name, container, selector = TARGETS[name]
        fields = ['.metadata.name', '.metadata.namespace', '.metadata.uid', '.metadata.resourceVersion',
                  '.metadata.deletionTimestamp', f'.spec.containers[?(@.name=="{container}")].name',
                  f'.status.containerStatuses[?(@.name=="{container}")].containerID',
                  f'.status.containerStatuses[?(@.name=="{container}")].restartCount',
                  f'.status.containerStatuses[?(@.name=="{container}")].ready']
        template = '{"\\t"}'.join('{' + item + '}' for item in fields) + '{"\\n"}'
        argv = ['kubectl', 'get', 'pods']
        if pod_name:
            argv.append(pod_name)
        argv += ['-n', self.namespace]
        if selector:
            argv += ['-l', selector]
            template = '{range .items[*]}' + template + '{end}'
        argv += ['-o', 'jsonpath=' + template, '--request-timeout=15s']
        text, call_id = self._native(argv, 'target_identity_' + name)
        candidates = []
        for line in text.splitlines():
            parts = line.split('\t')
            if len(parts) != 9:
                raise BridgeError('Actual native target identity projection is malformed')
            n, ns, uid, resource_version, deletion, actual_container, container_id, restarts, ready = parts
            if deletion:
                continue
            if (not DNS.fullmatch(n) or ns != self.namespace or not re.fullmatch(r'[a-f0-9-]{8,64}', uid)
                    or not resource_version.isdigit() or actual_container != container or not container_id
                    or not restarts.isdigit() or ready not in {'true', 'false'}):
                raise BridgeError('Actual Pod/container identity is unavailable')
            candidates.append({'name': n, 'namespace': ns, 'uid': uid, 'container': container,
                               'container_id': container_id, 'restart_count': int(restarts)})
        if len(candidates) != 1:
            raise BridgeError('Actual target selection is not unique')
        return {**candidates[0], 'identity_call_id': call_id}

    @staticmethod
    def _pod_binding(pod):
        return {key: value for key, value in pod.items() if key != 'identity_call_id'}

    def _current_target(self, name):
        actual = self._pod(name)
        target = self.targets[name]
        if self._pod_binding(actual) != target['pod']:
            raise BridgeError('Actual Pod/container changed; original action remains unknown')
        return actual

    def _exec(self, target: dict, body: str, *, mode: str, action_digest: str,
              binding_digest: str, parameters: dict, offset=0, count=target_shell.CHUNK_BYTES, stream='stdout'):
        argv = ['kubectl', 'exec', target['pod']['name'], '-n', self.namespace, '-c', target['pod']['container'], '--']
        argv += target_shell.argv(body, mode=mode, root=target['root'], action=action_digest,
                                  binding=binding_digest, parameters_json=canonical(parameters).decode(),
                                  offset=offset, count=count, stream=stream,
                                  expected_root_identity=target.get('root_identity') if mode != 'init' else None,
                                  expected_lifecycle=target.get('linux_lifecycle') if mode != 'init' else None)
        text, call_id = self._native(argv, 'fixed_' + mode)
        try:
            result = json.loads(text)
        except json.JSONDecodeError as error:
            raise BridgeError('Fixed target envelope is malformed') from error
        if not isinstance(result, dict) or result.get('schema') != target_shell.SCHEMA:
            raise BridgeError('Fixed target envelope schema differs')
        return {**result, 'native_call_id': call_id}

    def bootstrap(self):
        """Single setup; no reopening or automatic recreation of missing records."""
        self.directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        for name in ('calls', 'actions', 'captures'):
            (self.directory / name).mkdir(mode=0o700)
        with (self.directory / 'call_counter').open('x') as output:
            output.write('0')
        guard = self.guard.check('bootstrap')
        self._new_record('launcher_context.json', self.context)
        self._new_record('runtime.json', self.runtime)
        for name in TARGETS:
            before = self._pod(name)
            root_digest = digest(canonical({'attempt_id': self.attempt_id, 'scope': self.context['physical_scope_id'],
                                             'target': self._pod_binding(before)}))
            target = {'pod': self._pod_binding(before), 'root': '/tmp/sregym-fixed-action-v2-' + root_digest}
            result = self._exec(target, ':', mode='init', action_digest='0' * 64,
                                binding_digest=root_digest, parameters={})
            if result.get('state') != 'initialized' or not isinstance(result.get('lifecycle'), str) or not isinstance(result.get('root_identity'), str):
                raise BridgeError('Actual target root could not be initialized: ' + name)
            if result.get('probe_sha256') != digest(b'fixed-capture-probe') or result.get('probe_bytes') != 19:
                raise BridgeError('Actual target runtime contract failed')
            target.update({'linux_lifecycle': result['lifecycle'], 'root_identity': result['root_identity'],
                           'uid': result['uid'], 'initialization_evidence': result,
                           'before_identity_call_id': before['identity_call_id']})
            self.targets[name] = target
            self._current_target(name)
        self.target_identity = {'qualification': self.transport_evidence_level, 'namespace': self.namespace,
                                'namespace_uid': self.context['namespace_uid'],
                                'physical_scope_id': self.context['physical_scope_id'],
                                'targets': {name: {'pod': value['pod'], 'linux_lifecycle': value['linux_lifecycle'],
                                                   'root_identity': value['root_identity']} for name, value in self.targets.items()}}
        self.registry = registry.ActionRegistry.create(self.directory / 'actions.sqlite', self.secret)
        self.adapter = self.registry.adapter(self.secret)
        self.adapter.create_attempt(self.attempt_id, scope_id=self.context['physical_scope_id'],
                                    ledger_lifecycle=self.context['ledger_epoch'],
                                    databases={'application': {'database_key': self.context['physical_scope_id'],
                                                               'target_identity': self.target_identity}},
                                    programs=self.program_bindings, enabled_operations=self.allowed_operations)
        self._new_record('bootstrap.json', {'targets': self.targets, 'guard': guard, 'program_bindings': self.program_bindings,
                                            'program_enablement': self.program_enablement, 'mode': self.mode})
        return {'target_identity': self.target_identity, 'runtime': self.runtime, 'guard': guard,
                'native_chain_qualified': False}

    def state(self):
        return self.registry.generations(self.attempt_id, 'application')

    def _validate(self, name, arguments):
        if name not in self.programs:
            raise ValueError('Unknown fixed program')
        if name == '__fixed_runtime_observer':
            if arguments != {}:
                raise ValueError('The fixed runtime observer has no parameters')
        else:
            self.catalog.validate_arguments(name, arguments)
        if len(canonical(arguments)) > 16384:
            raise ValueError('Bounded fixed-program arguments exceeded')
        return self.programs[name]

    def reserve(self, action_id: str, name: str, arguments: dict, *, intent_ref=None):
        if not ID.fullmatch(action_id):
            raise ValueError('Invalid action identifier')
        item = self._validate(name, arguments)
        if item['operation'] not in self.allowed_operations:
            raise BridgeError('Operation is explicitly disabled for this original attempt')
        if item['operation'] != 'observe' and not self.qualification.get('actual_native_mcp_qualified'):
            raise BridgeError('Actual common native path qualification is required before a business write')
        prior = None
        try:
            prior = self.registry.poll(self.attempt_id, action_id)
        except registry.InvalidState:
            pass
        if prior is not None:
            parameters = {'fixed_program': name, 'arguments': arguments}
            if item['operation'] != 'observe':
                parameters['precondition_sha256'] = prior['request']['parameters'].get('precondition_sha256')
            return self.registry.reserve(attempt_id=self.attempt_id, action_id=action_id, role=self.role,
                                         operation=item['operation'], database_ref='application',
                                         expected_epoch=prior['expected_epoch'], intent_ref=intent_ref,
                                         parameters=parameters)
        parameters = {'fixed_program': name, 'arguments': arguments}
        proof = None
        if item['operation'] != 'observe':
            proof = self._business_preconditions('reserve', item['operation'],
                       {'action_id': action_id, 'program_name': name, 'arguments': arguments, 'intent_ref': intent_ref,
                        'expected_generations': self.state(), 'original_action_on_dispatch': None})
            parameters['precondition_sha256'] = digest(canonical(proof))
        reserved = self.registry.reserve(attempt_id=self.attempt_id, action_id=action_id, role=self.role,
                                     operation=item['operation'], database_ref='application',
                                     expected_epoch=self.state()['database'], intent_ref=intent_ref,
                                     parameters=parameters)
        if proof is not None:
            self._new_record('actions/' + action_id + '.reserve-preconditions.json', proof)
        return reserved

    def _business_preconditions(self, phase, operation, proposal):
        if self.precondition_verifier is None or self.precondition_source is None:
            raise BridgeError('Business operations need the fixed common precondition verifier')
        if digest(self.precondition_source.read_bytes()) != self.precondition_source_sha256:
            raise BridgeError('Fixed common precondition verifier source changed')
        proof = self.precondition_verifier(phase, operation, json.loads(canonical(proposal)), self)
        if (not isinstance(proof, dict) or proof.get('qualified') is not True
                or not isinstance(proof.get('evidence_handles'), list) or not proof['evidence_handles']
                or proof.get('generations') != self.state() or len(canonical(proof)) > 65536):
            raise BridgeError('Common operation preconditions are absent, stale or unqualified')
        return {'phase': phase, 'operation': operation, 'proposal': proposal, 'qualified_evidence': proof,
                'verifier_source_sha256': self.precondition_source_sha256}

    def _journal(self, action_id):
        if not isinstance(action_id, str) or not ID.fullmatch(action_id):
            raise ValueError('Invalid original action identifier')
        path = self.directory / 'actions' / (action_id + '.json')
        if not path.is_file() or path.is_symlink():
            raise BridgeError('Original dispatch journal is missing; no automatic recreation')
        value = json.loads(path.read_bytes())
        action = self.registry.poll(self.attempt_id, action_id)
        item = self._validate(value['program_name'], value['arguments'])
        if (action['operation'] != item['operation'] or action['request']['operation'] != item['operation']
                or action['request']['program_sha256'] != self.program_bindings[item['operation']]
                or action['request']['target'] != self.target_identity):
            raise BridgeError('Registered operation/program/target differs from fixed execution catalog')
        if (value['semantic_sha256'] != action['semantic_sha'] or value['dispatch_epoch'] != action['dispatch_epoch']
                or value['program_sha256'] != target_shell.program_sha256(item['body_shell'])
                or value['operation_catalog_sha256'] != self.program_bindings[item['operation']]
                or action['request']['parameters'] != {'fixed_program': value['program_name'], 'arguments': value['arguments'],
                    **({'precondition_sha256': value['reserve_precondition_sha256']} if item['operation'] != 'observe' else {})}
                or value['target'] != self.targets[item['target']]
                or digest(canonical(value['binding'])) != value['binding_sha256']):
            raise BridgeError('Original dispatch binding changed')
        expected_binding = {'schema': target_shell.SCHEMA, 'attempt_id': self.attempt_id,
                            'action_id': action_id, 'semantic_sha256': action['semantic_sha'],
                            'dispatch_epoch': action['dispatch_epoch'],
                            'grant_sha256': value['binding'].get('grant_sha256'),
                            'program_sha256': value['program_sha256'], 'target': value['target']}
        if value['binding'] != expected_binding or not HEX.fullmatch(expected_binding['grant_sha256'] or ''):
            raise BridgeError('Original grant/target binding fields differ')
        if item['operation'] != 'observe':
            for phase, expected_sha in (('reserve', value['reserve_precondition_sha256']),
                                        ('dispatch', value['dispatch_precondition_sha256'])):
                proof_path = self.directory / 'actions' / (action_id + '.' + phase + '-preconditions.json')
                if not proof_path.is_file() or proof_path.is_symlink():
                    raise BridgeError('Original business guard receipt is missing')
                proof = json.loads(proof_path.read_bytes())
                if (digest(canonical(proof)) != expected_sha or proof.get('phase') != phase
                        or proof.get('operation') != item['operation']
                        or proof.get('verifier_source_sha256') != self.precondition_source_sha256
                        or proof.get('proposal', {}).get('action_id') != action_id
                        or proof.get('proposal', {}).get('program_name') != value['program_name']
                        or proof.get('proposal', {}).get('arguments') != value['arguments']):
                    raise BridgeError('Original business guard receipt binding differs')
        return value, action, item

    def execute_once(self, action_id: str):
        action = self.registry.poll(self.attempt_id, action_id)
        if action['operation'] == 'final_submit':
            return {'dispatch_granted': False, 'target_start_attempted': False,
                    'query': self.read_final_submission(action_id)}
        item = self._validate(action['request']['parameters']['fixed_program'], action['request']['parameters']['arguments'])
        if (action['operation'] != item['operation'] or action['request']['operation'] != item['operation']
                or action['request']['program_sha256'] != self.program_bindings[item['operation']]
                or action['request']['target'] != self.target_identity):
            raise BridgeError('Registered operation/program/target differs from fixed execution catalog')
        if item['operation'] not in self.allowed_operations:
            raise BridgeError('Operation is explicitly disabled for this original attempt')
        if item['operation'] != 'observe' and not self.qualification.get('actual_native_mcp_qualified'):
            raise BridgeError('Actual common native path qualification is required before a business dispatch')
        if action['execution'] != 'reserved':
            return {'dispatch_granted': False, 'target_start_attempted': False, 'query': self.query(action_id)}
        self._current_target(item['target'])
        dispatch_precondition = None
        if item['operation'] != 'observe':
            reserve_path = self.directory / 'actions' / (action_id + '.reserve-preconditions.json')
            if not reserve_path.is_file() or reserve_path.is_symlink():
                raise BridgeError('Original business precondition receipt is missing')
            reserve_proof = json.loads(reserve_path.read_bytes())
            if digest(canonical(reserve_proof)) != action['request']['parameters'].get('precondition_sha256'):
                raise BridgeError('Original business precondition receipt changed')
            dispatch_precondition = self._business_preconditions('dispatch', item['operation'],
                {'action_id': action_id, 'program_name': action['request']['parameters']['fixed_program'],
                 'arguments': action['request']['parameters']['arguments'],
                 'intent_ref': reserve_proof.get('proposal', {}).get('intent_ref'),
                 'expected_generations': self.state(), 'original_action_on_dispatch': action})
            self._new_record('actions/' + action_id + '.dispatch-preconditions.json', dispatch_precondition)
        decision = self.adapter.dispatch(self.attempt_id, action_id)
        if not decision.granted:
            return {'dispatch_granted': False, 'target_start_attempted': False, 'query': self.query(action_id)}
        action = decision.action
        binding = {'schema': target_shell.SCHEMA, 'attempt_id': self.attempt_id, 'action_id': action_id,
                   'semantic_sha256': action['semantic_sha'], 'dispatch_epoch': action['dispatch_epoch'],
                   'grant_sha256': digest(decision.launch_token.encode()),
                   'program_sha256': target_shell.program_sha256(item['body_shell']),
                   'target': self.targets[item['target']]}
        journal = {'program_name': action['request']['parameters']['fixed_program'],
                   'arguments': action['request']['parameters']['arguments'], 'semantic_sha256': action['semantic_sha'],
                   'dispatch_epoch': action['dispatch_epoch'], 'program_sha256': binding['program_sha256'],
                   'operation_catalog_sha256': self.program_bindings[item['operation']],
                   'target': self.targets[item['target']], 'binding': binding, 'binding_sha256': digest(canonical(binding)),
                   'action_digest': digest(canonical({'attempt_id': self.attempt_id, 'action_id': action_id}))}
        if item['operation'] != 'observe':
            journal['reserve_precondition_sha256'] = action['request']['parameters']['precondition_sha256']
            journal['dispatch_precondition_sha256'] = digest(canonical(dispatch_precondition))
        start_attempted = False
        try:
            self._new_record('actions/' + action_id + '.json', journal)
            start_attempted = True
            result = self._exec(journal['target'], item['body_shell'], mode='start', action_digest=journal['action_digest'],
                                binding_digest=journal['binding_sha256'], parameters=journal['arguments'])
            self._current_target(item['target'])
            if result.get('state') not in {'body_completed', 'running', 'target_terminal'}:
                raise BridgeError('Target claim/start state is unknown')
            if result.get('binding') != journal['binding_sha256'] or result.get('lifecycle') != journal['target']['linux_lifecycle']:
                raise BridgeError('Target start binding or lifecycle differs')
            self._new_record('actions/' + action_id + '.start.json', result)
            return {'dispatch_granted': True, 'target_start_attempted': True, 'start': result,
                    'business_terminal': False, 'effect_settled': False}
        except BaseException as error:
            self.adapter.mark_unknown(self.attempt_id, action_id, 'target_start_or_result_unknown')
            return {'dispatch_granted': True, 'target_start_attempted': start_attempted,
                    'state': 'unknown', 'error': type(error).__name__ + ': ' + str(error)}

    def query(self, action_id: str):
        existing = self.registry.poll(self.attempt_id, action_id)
        if existing['operation'] == 'final_submit':
            return self.read_final_submission(action_id)
        journal, action, item = self._journal(action_id)
        self._current_target(item['target'])
        result = self._exec(journal['target'], item['body_shell'], mode='query', action_digest=journal['action_digest'],
                            binding_digest=journal['binding_sha256'], parameters=journal['arguments'])
        self._current_target(item['target'])
        if result.get('state') == 'unknown':
            return result
        if result.get('binding') != journal['binding_sha256'] or result.get('lifecycle') != journal['target']['linux_lifecycle']:
            raise BridgeError('Query is not bound to the original target execution')
        if result.get('state') == 'target_terminal' and (result.get('root_identity') != journal['target']['root_identity']
                                                       or result.get('target_process_terminal') is not True):
            raise BridgeError('Target terminal proof lacks original root/process identity')
        return result

    def read_capture(self, action_id: str, *, stream: str, expected_sha256: str, offset: int, count=target_shell.CHUNK_BYTES):
        if not HEX.fullmatch(expected_sha256):
            raise ValueError('Expected immutable capture digest required')
        journal, action, item = self._journal(action_id)
        self._current_target(item['target'])
        result = self._exec(journal['target'], item['body_shell'], mode='chunk', action_digest=journal['action_digest'],
                            binding_digest=journal['binding_sha256'], parameters=journal['arguments'],
                            stream=stream, offset=offset, count=count)
        self._current_target(item['target'])
        if result.get('state') != 'target_terminal' or result.get('binding') != journal['binding_sha256']:
            raise BridgeError('Capture lacks qualified original target terminal')
        if result.get('lifecycle') != journal['target']['linux_lifecycle'] or result.get('root_identity') != journal['target']['root_identity']:
            raise BridgeError('Capture target lifecycle differs')
        if result.get(stream + '_sha256') != expected_sha256 or result.get('offset') != offset or result.get('stream') != stream:
            raise BridgeError('Capture version or position differs')
        raw = base64.b64decode(result['chunk_base64'], validate=True)
        total = result.get(stream + '_bytes')
        if type(total) is not int or len(raw) != min(count, total - offset):
            raise BridgeError('Capture chunk is incomplete')
        return {**result, 'decoded_bytes': raw}

    def capture_all(self, action_id: str, query: dict | None = None):
        query = self.query(action_id) if query is None else query
        if query.get('state') != 'target_terminal' or query.get('target_process_terminal') is not True:
            raise BridgeError('Original target has not reached a qualified terminal')
        captures = {}
        for stream in ('stdout', 'stderr'):
            total, sha = query[stream + '_bytes'], query[stream + '_sha256']
            parts = []
            offset = 0
            while offset < total or not parts:
                chunk = self.read_capture(action_id, stream=stream, expected_sha256=sha, offset=offset)
                parts.append(chunk['decoded_bytes'])
                offset += len(parts[-1])
                if total == 0:
                    break
            raw = b''.join(parts)
            if len(raw) != total or digest(raw) != sha:
                raise BridgeError('Reassembled immutable capture differs')
            captures[stream] = raw
            path = self.directory / 'captures' / (action_id + '.' + stream)
            if path.exists():
                if path.read_bytes() != raw:
                    raise BridgeError('Original local evidence cannot be overwritten')
            else:
                with path.open('xb') as output:
                    output.write(raw); output.flush(); os.fsync(output.fileno())
        return {'action_id': action_id, 'query': query, 'exit_code': query['exit_code'], **captures}

    def _verified_capture_binding(self, action_id: str, capture: dict):
        """Bind a classification to the original raw query, without new reads."""
        journal, action, item = self._journal(action_id)
        if not isinstance(capture, dict) or capture.get('action_id') != action_id:
            raise BridgeError('Capture belongs to a different original action')
        query = capture.get('query')
        if (not isinstance(query, dict) or query.get('state') != 'target_terminal'
                or query.get('target_process_terminal') is not True
                or query.get('binding') != journal['binding_sha256']
                or query.get('root_identity') != journal['target']['root_identity']
                or query.get('lifecycle') != journal['target']['linux_lifecycle']
                or capture.get('exit_code') != query.get('exit_code')):
            raise BridgeError('Capture lacks this original target terminal binding')
        for stream in ('stdout', 'stderr'):
            raw = capture.get(stream)
            if (not isinstance(raw, bytes) or digest(raw) != query.get(stream + '_sha256')
                    or len(raw) != query.get(stream + '_bytes')):
                raise BridgeError('Capture bytes differ from original terminal receipt')
        call_id = query.get('native_call_id')
        if not isinstance(call_id, str) or not ID.fullmatch(call_id):
            raise BridgeError('Original native query call identity is missing')
        paths = [self.directory / 'calls' / (call_id + suffix) for suffix in ('.request.json', '.response.json')]
        if any(not path.is_file() or path.is_symlink() for path in paths):
            raise BridgeError('Original native query request/response is missing')
        request, response = [json.loads(path.read_bytes()) for path in paths]
        expected_argv = ['kubectl', 'exec', journal['target']['pod']['name'], '-n', self.namespace,
                         '-c', journal['target']['pod']['container'], '--']
        expected_argv += target_shell.argv(item['body_shell'], mode='query', root=journal['target']['root'],
                     action=journal['action_digest'], binding=journal['binding_sha256'],
                     parameters_json=canonical(journal['arguments']).decode(),
                     expected_root_identity=journal['target']['root_identity'],
                     expected_lifecycle=journal['target']['linux_lifecycle'])
        expected_command = shlex.join(expected_argv)
        if (request.get('call_id') != call_id or request.get('purpose') != 'fixed_query'
                or request.get('operation') != 'kubectl' or request.get('command') != expected_command
                or request.get('command_sha256') != digest(expected_command.encode())):
            raise BridgeError('Original native query command does not bind this action')
        original = json.loads(native_text(response))
        if original != {key: value for key, value in query.items() if key != 'native_call_id'}:
            raise BridgeError('Query object differs from its original raw native response')
        return action

    def settle_verified(self, action_id: str, capture: dict, *, verifier: Callable):
        """Trusted catalog verifier only. NEVER expose callback to model callers."""
        action = self._verified_capture_binding(action_id, capture)
        if action['operation'] == 'send_notification':
            raise BridgeError('Notification requires causal post-terminal audit settlement')
        qualified = verifier(action, capture, self)
        if not isinstance(qualified, dict) or qualified.get('execution_terminal_qualified') is not True:
            raise BridgeError('Operation-specific server terminal is not qualified')
        effect = qualified.get('settled_effect')
        if effect not in registry.SETTLED or (effect == 'read_only') != (action['operation'] == 'observe'):
            raise BridgeError('Operation-specific effect classification is invalid')
        record = {'action_id': action_id, 'target_query': capture['query'], 'qualified': qualified,
                  'stdout_sha256': digest(capture['stdout']), 'stderr_sha256': digest(capture['stderr'])}
        proof_ref = self._new_record('actions/' + action_id + '.qualified.json', record)
        terminal_id = 'term-' + digest(canonical(record))
        self.adapter.terminal(self.attempt_id, action_id,
                              {'evidence_id': terminal_id, 'target_identity': self.target_identity, 'details': record})
        post_id = self.adapter.postcondition(self.attempt_id, action_id,
                        {'evidence_id': 'post-' + digest(canonical({'action_id': action_id, 'qualified': qualified})), 'target_identity': self.target_identity,
                         'details': {**qualified, 'source_evidence': proof_ref}})
        self.adapter.settle(self.attempt_id, action_id, post_id)
        return self.registry.poll(self.attempt_id, action_id)

    def declare_intent(self, intent_ref: str, *, kind: str, public_business_key: dict,
                       receipt_sha256: str, serialization_key: str | None = None):
        """Trusted public receipt parser calls this; a model cannot invent proof."""
        self.adapter.declare_intent(self.attempt_id, intent_ref, database_ref='application', kind=kind,
                                    public_business_key=public_business_key, receipt_sha256=receipt_sha256,
                                    serialization_key=serialization_key)

    def latch_verified_public_acceptance(self, intent_ref: str, audit_capture: dict, *, verifier: Callable):
        """Common pre-existing acceptance latch, not only a B0 skip decision."""
        if not isinstance(audit_capture, dict):
            raise BridgeError('Actual original public audit capture is required')
        audit_action = self._verified_capture_binding(audit_capture.get('action_id'), audit_capture)
        if audit_action['operation'] != 'observe' or audit_action['request']['parameters']['fixed_program'] != 'public_audit':
            raise BridgeError('Public acceptance needs the fixed public-audit action')
        proof = verifier(intent_ref, audit_capture, self)
        if (not isinstance(proof, dict) or proof.get('complete') is not True
                or proof.get('ledger_lifecycle') != self.context['ledger_epoch']
                or proof.get('capture_sha256') != digest(audit_capture['stdout'])):
            raise BridgeError('Acceptance validator did not prove complete same-ledger evidence')
        self.adapter.latch_public_acceptance(self.attempt_id, intent_ref, proof)

    def notification_terminal_verified(self, action_id: str, capture: dict, *, verifier: Callable):
        action = self._verified_capture_binding(action_id, capture)
        if action['operation'] != 'send_notification':
            raise BridgeError('Notification terminal method requires a notification action')
        qualified = verifier(action, capture, self)
        if not isinstance(qualified, dict) or qualified.get('execution_terminal_qualified') is not True:
            raise BridgeError('All application/SMTP server terminals are not qualified')
        if qualified.get('delivery_acceptance_claimed') is not False:
            raise BridgeError('Owned terminal proof must not claim delivery acceptance')
        record = {'protocol_id': registry.NOTIFICATION_SETTLEMENT_PROTOCOL,
                  'owned_action_terminal': True, 'terminal_scope': 'original_registered_action_only',
                  'action_id': action_id, 'target_query': capture['query'], 'qualified': qualified,
                  'stdout_sha256': digest(capture['stdout']), 'stderr_sha256': digest(capture['stderr'])}
        proof_ref = self._new_record('actions/' + action_id + '.terminal-qualified.json', record)
        terminal_id = 'term-' + digest(canonical(record))
        self.adapter.terminal(self.attempt_id, action_id,
                              {'evidence_id': terminal_id, 'target_identity': self.target_identity,
                               'details': {**record, 'source_evidence': proof_ref}})
        return {'terminal_evidence_id': terminal_id, 'qualified': qualified}

    def begin_notification_audit(self, action_id: str):
        action = self.registry.poll(self.attempt_id, action_id)
        if action['operation'] != 'send_notification':
            raise BridgeError('Only a notification uses a causal delivery audit')
        token = self.adapter.begin_audit(self.attempt_id, action_id, action['terminal_evidence'], self.context['ledger_epoch'])
        before = self.guard.check('public_audit_before')
        # A trusted controller receives this token. The public/model facade
        # exposes only an opaque action-specific audit handle, never the adapter.
        self.notification_audits[token] = {'action_id': action_id, 'before_guard': before}
        return token

    def finish_notification_audit(self, action_id: str, ticket: str, audit_capture: dict, *, verifier: Callable):
        raise BridgeError('Strict notification effect settlement is unavailable; use the fixed snapshot profile API')

    def finish_notification_snapshot(self, action_id: str, ticket: str, audit_capture: dict, *, verifier: Callable):
        own = self.notification_audits.get(ticket)
        if own is None or own['action_id'] != action_id:
            raise BridgeError('Unknown original causal audit ticket')
        after = self.guard.check('public_audit_after')
        audit_action_id = audit_capture['action_id']
        audit_action = self._verified_capture_binding(audit_action_id, audit_capture)
        if audit_action['operation'] != 'observe' or audit_action['request']['parameters']['fixed_program'] != 'public_audit':
            raise BridgeError('Snapshot evidence must be the fixed public-audit capture')
        if audit_action['execution'] != 'terminal' or audit_action['effect'] != 'read_only':
            raise BridgeError('Causal public-audit observation has not completed its own read-only settlement')
        with closing(self.registry._connect(readonly=True)) as db:
            t = db.execute('SELECT * FROM audit_tickets WHERE token=?', (ticket,)).fetchone()
            e = db.execute("SELECT seq FROM events WHERE attempt=? AND action=? AND kind='dispatch_permit_issued'",
                           (self.attempt_id, audit_action_id)).fetchone()
        if t is None or e is None or e['seq'] <= t['begin_seq']:
            raise BridgeError('Audit capture was dispatched before the original terminal ticket')
        qualified = verifier(self.registry.poll(self.attempt_id, action_id), audit_capture, self)
        expected = {'protocol_id', 'complete', 'owned_action_terminal', 'intent_snapshot_state',
                    'causal_attribution_to_this_action', 'historical_terminal_proof', 'delivery_ids',
                    'wrong_delivery_ids', 'unattributed_issue_update_delivery_ids', 'ledger_lifecycle',
                    'snapshot_id', 'snapshot_total'}
        if (not isinstance(qualified, dict) or set(qualified) != expected
                or qualified.get('protocol_id') != registry.NOTIFICATION_SETTLEMENT_PROTOCOL
                or qualified.get('complete') is not True or qualified.get('owned_action_terminal') is not True
                or qualified.get('causal_attribution_to_this_action') != 'unknown'):
            raise BridgeError('Post-terminal snapshot must retain all four scoped facts without causal effect claims')
        record = {**qualified, 'capture_ticket': ticket, 'capture_sha256': digest(audit_capture['stdout']),
                  'audit_action_id': audit_action_id, 'before_guard': own['before_guard'], 'after_guard': after}
        self.adapter.finish_notification_snapshot(ticket,
            {'evidence_id': 'snapshot-' + digest(canonical({'action_id': action_id, 'record': record})),
             'target_identity': self.target_identity, 'details': record})
        # The committed SQLite record is authoritative if this redundant export
        # is interrupted; neither failure path authorizes a repeat dispatch.
        settled = self.registry.poll(self.attempt_id, action_id)
        self._new_record('actions/' + action_id + '.snapshot-closed.json', settled['notification_snapshot'])
        del self.notification_audits[ticket]
        return settled

    def read_notification_snapshot(self, action_id: str):
        action = self.registry.poll(self.attempt_id, action_id)
        if (action['operation'] != 'send_notification' or action['execution'] != 'terminal'
                or action['effect'] != 'snapshot_closed' or 'notification_snapshot' not in action):
            raise BridgeError('Original action has no immutable notification snapshot closure')
        return action['notification_snapshot']

    def read_native_api(self, operation: str):
        if operation not in {'app_info', 'status', 'describe_tools'} or self.api_read_transport is None:
            raise BridgeError('Fixed native API read is unavailable')
        call_id = self._next_call('native_api_' + operation)
        self._new_record('calls/' + call_id + '.request.json', {'call_id': call_id, 'operation': operation, 'arguments': {}})
        response = self.api_read_transport(operation, call_id)
        self._new_record('calls/' + call_id + '.response.json', response)
        if response.get('transport_state') != 'response_received' or response.get('trace_complete') is not True:
            raise BridgeError('Native API read is incomplete')
        return {'call_id': call_id, 'response': response}

    @staticmethod
    def _is_original_submission_acknowledgement(response):
        if not isinstance(response, dict):
            return False
        payload = response.get('native_response')
        return (response.get('transport_state') == 'response_received'
                and response.get('trace_complete') is True and response.get('http_status') == 200
                and isinstance(payload, dict) and payload.get('stage') == 'mitigation'
                and str(payload.get('status')) == '200'
                and response.get('submission_state') == 'accepted_for_evaluation'
                and response.get('business_success') is None)

    def read_final_submission(self, action_id='original-final-evaluation'):
        """Read the original acceptance evidence only; never query/resubmit HTTP."""
        if not isinstance(action_id, str) or not ID.fullmatch(action_id):
            raise ValueError('Invalid original final action identity')
        action = self.registry.poll(self.attempt_id, action_id)
        if action['operation'] != 'final_submit':
            raise BridgeError('This action is not the original final submission')
        with closing(self.registry._connect(readonly=True)) as db:
            accepted = db.execute("SELECT * FROM evidence WHERE attempt=? AND action=? AND kind='original_evaluation_accepted'",
                                  (self.attempt_id, action_id)).fetchall()
        if not accepted:
            return {'state': 'not_dispatched' if action['execution'] == 'reserved' else 'outcome_unknown',
                    'submission_state': 'not_submitted' if action['execution'] == 'reserved' else 'outcome_unknown',
                    'business_success': None, 'original_evaluation_terminal': False, 'original_action': action}
        if len(accepted) != 1:
            raise BridgeError('Original acceptance evidence is not unique')
        payload = json.loads(accepted[0]['payload']);record = payload['details']
        call_id = record['native_call_id']
        if not ID.fullmatch(call_id) or record['action_id'] != action_id or record['attempt_id'] != self.attempt_id:
            raise BridgeError('Original acceptance identity differs')
        if payload['semantic_sha'] != action['semantic_sha'] or payload['target_identity'] != self.target_identity:
            raise BridgeError('Original acceptance is not bound to this final action')
        request = json.loads((self.directory / 'calls' / (call_id + '.request.json')).read_bytes())
        response = json.loads((self.directory / 'calls' / (call_id + '.response.json')).read_bytes())
        if (request.get('operation') != 'submit' or request.get('action_id') != action_id
                or request.get('semantic_sha256') != action['semantic_sha']
                or digest(canonical(response)) != record['response_sha256']
                or not self._is_original_submission_acknowledgement(response)):
            raise BridgeError('Original acceptance raw request/response is unavailable or changed')
        return {**record, 'original_action': action}

    def submit_final_once(self, *, action_id='original-final-evaluation', solution: str,
                          precondition_verifier: Callable, result_verifier: Callable | None = None):
        """One permit and one original HTTP request; acceptance remains pending.

        The frozen native endpoint starts its evaluator asynchronously. A 200
        response acknowledges acceptance only. The original host Conductor later
        records its final result separately, linked to this exact action/call;
        this agent never invents or imports an oracle boolean from acceptance.
        result_verifier is retained as a compatibility argument but is never
        called or allowed to turn an acknowledgement into business success.
        """
        if ('final_submit' not in self.allowed_operations or self.submit_transport is None
                or not self.qualification.get('actual_native_mcp_qualified')):
            raise BridgeError('Original native final submission path is unavailable')
        if not ID.fullmatch(action_id) or not isinstance(solution, str) or len(solution.encode()) > 16384:
            raise ValueError('Invalid bounded final submission')
        prior = None
        try:
            prior = self.registry.poll(self.attempt_id, action_id)
        except registry.InvalidState:
            pass
        if prior is not None and prior['execution'] != 'reserved':
            if prior['operation'] != 'final_submit' or prior['request']['parameters'].get('solution_sha256') != digest(solution.encode()):
                raise registry.Conflict('Original final action cannot be rebound')
            return {'dispatch_granted': False, 'final_submit_requested': False,
                    **self.read_final_submission(action_id)}
        preconditions = precondition_verifier(self)
        if not isinstance(preconditions, dict) or preconditions.get('qualified') is not True:
            raise BridgeError('Actual final-submission preconditions are not qualified')
        guard = self.guard.check('final_submit')
        self.registry.reserve(attempt_id=self.attempt_id, action_id=action_id, role=self.role,
                              operation='final_submit', database_ref='application', expected_epoch=self.state()['database'],
                              parameters={'solution_sha256': digest(solution.encode()),
                                          'precondition_sha256': digest(canonical(preconditions))})
        decision = self.adapter.dispatch(self.attempt_id, action_id)
        if not decision.granted:
            return {'dispatch_granted': False, 'final_submit_requested': False,
                    'original_action': self.registry.poll(self.attempt_id, action_id)}
        requested = False
        acceptance_observed = False
        try:
            call_id = self._next_call('original_final_submission')
            request = {'call_id': call_id, 'operation': 'submit', 'arguments': {'solution': solution},
                       'action_id': action_id, 'grant_sha256': digest(decision.launch_token.encode()),
                       'semantic_sha256': decision.action['semantic_sha'], 'guard': guard, 'preconditions': preconditions}
            self._new_record('calls/' + call_id + '.request.json', request)
            requested = True
            response = self.submit_transport(solution, call_id)
            self._new_record('calls/' + call_id + '.response.json', response)
            acceptance_observed = self._is_original_submission_acknowledgement(response)
            if not acceptance_observed:
                raise BridgeError('Original submission acceptance is incomplete or unknown')
            record = {'schema': 'b0-original-submission-acceptance-v1', 'attempt_id': self.attempt_id,
                      'action_id': action_id, 'native_call_id': call_id,
                      'response_sha256': digest(canonical(response)),
                      'state': 'accepted_pending_evaluation', 'submission_state': 'accepted_for_evaluation',
                      'business_success': None, 'original_evaluation_terminal': False,
                      'requires_host_original_evaluation': True, 'agent_has_seen_original_oracle_result': False}
            self._new_record('FINAL_SUBMISSION_ACCEPTED.json', record)
            self.adapter.final_evaluation_accepted(self.attempt_id, action_id,
                        {'evidence_id': 'final-accepted-' + digest(canonical(record)),
                         'target_identity': self.target_identity, 'details': record})
            return {'dispatch_granted': True, 'final_submit_requested': True, **record,
                    'original_action': self.registry.poll(self.attempt_id, action_id)}
        except BaseException as error:
            current = self.registry.poll(self.attempt_id, action_id)
            if current['execution'] in {'dispatching', 'running', 'unknown'}:
                self.adapter.mark_unknown(self.attempt_id, action_id, 'original_final_evaluation_unknown')
            return {'dispatch_granted': True, 'final_submit_requested': requested, 'state': 'unknown',
                    'submission_state': 'accepted_for_evaluation' if acceptance_observed else 'outcome_unknown',
                    'acceptance_observed_but_local_record_incomplete': acceptance_observed,
                    'business_success': None, 'original_evaluation_terminal': False,
                    'error': type(error).__name__ + ': ' + str(error),
                    'original_action': self.registry.poll(self.attempt_id, action_id)}

    def qualify_native_chain(self):
        """One actual fixed observer in initial read stage; all costs counted."""
        action_id = 'native-read-qualification'
        self.reserve(action_id, '__fixed_runtime_observer', {})
        start = self.execute_once(action_id)
        if start.get('dispatch_granted') is not True or start.get('state') == 'unknown':
            raise BridgeError('Initial actual native observer could not start')
        query = self.query(action_id)
        capture = self.capture_all(action_id, query)
        document = json.loads(capture['stdout'])
        if (capture['exit_code'] != 0 or document.get('kind') != 'fixed_runtime_observation' or capture['stderr']
                or type(document.get('uid')) is not int or document['uid'] < 0
                or type(document.get('process_pid')) is not int or document['process_pid'] != query['process_pid']):
            raise BridgeError('Initial actual native observer evidence is malformed')
        expected_stdout = ('{"kind":"fixed_runtime_observation","shell":"posix","uid":%s,"process_pid":%s,'
                           '"site_hooks":"not_applicable","chunk_probe":"%s"}\n'
                           % (document['uid'], document['process_pid'], READ_CONTRACT_PROBE)).encode()
        if (capture['stdout'] != expected_stdout
                or not target_shell.CHUNK_BYTES < len(expected_stdout) < 2 * target_shell.CHUNK_BYTES):
            raise BridgeError('Initial known-content capture did not cross the qualified chunk boundary')
        # An intentional physical duplicate of the same claim proves the remote
        # atomic claim, not only the host's single-grant guard. It is a read-only
        # qualification action and does not create another registry dispatch.
        journal, action, item = self._journal(action_id)
        duplicate = self._exec(journal['target'], item['body_shell'], mode='start', action_digest=journal['action_digest'],
                               binding_digest=journal['binding_sha256'], parameters=journal['arguments'])
        self._current_target(item['target'])
        if (duplicate.get('state') != 'target_terminal' or duplicate.get('target_claim_won') is not False
                or duplicate.get('stdout_sha256') != query['stdout_sha256']):
            raise BridgeError('Actual duplicate remote entry did not preserve the first immutable capture')
        def verifier(action, cap, bridge):
            return {'execution_terminal_qualified': True, 'settled_effect': 'read_only',
                    'contract': 'fixed_shell_self_observation_no_remote_request',
                    'native_duplicate_entry_preserved': True, 'capture_sha256': digest(cap['stdout'])}
        state = self.settle_verified(action_id, capture, verifier=verifier)
        actual_native = self.transport_evidence_level == 'native_filtered_execution'
        self.qualification = {'qualified': True, 'actual_native_mcp_qualified': actual_native,
                              'transport_evidence_level': self.transport_evidence_level,
                              'action_id': action_id, 'start': start, 'query': query,
                              'duplicate_entry': duplicate, 'registry_state': state,
                              'observer_document': document, 'qualified_mechanisms': [
                                  'provided_transport_path', 'provided_target_identity_observations',
                                  'single_host_grant', 'atomic_target_claim', 'immutable_query_and_chunk',
                                  'known_content_complete_chunk_and_tail'],
                              'native_claim_conditional_on_launcher_boundary_evidence': actual_native,
                              'business_server_terminals_qualified': False,
                              'all_initial_read_costs_part_of_attempt': True}
        self._new_record('NATIVE_PATH_QUALIFICATION.json', self.qualification)
        return self.qualification

    def accounting(self):
        with closing(self.registry._connect(readonly=True)) as db:
            actions = [self.registry._public(row) for row in db.execute('SELECT * FROM actions WHERE attempt=? ORDER BY rowid', (self.attempt_id,))]
            events = [dict(row) for row in db.execute('SELECT * FROM events WHERE attempt=? ORDER BY seq', (self.attempt_id,))]
            snapshots = [json.loads(row['record']) for row in db.execute(
                'SELECT record FROM notification_snapshot_settlements WHERE attempt=? ORDER BY rowid', (self.attempt_id,))]
        return {'attempt_id': self.attempt_id, 'role': self.role, 'runtime': self.runtime,
                'reserved_actions': len(actions),
                'committed_dispatch_permits': sum(event['kind'] == 'dispatch_permit_issued' for event in events),
                'native_transport_requests': int((self.directory / 'call_counter').read_text()),
                'qualified_execution_terminals': sum(action['execution'] == 'terminal' for action in actions),
                'effects_settled_by_class': {effect: sum(action['effect'] == effect for action in actions) for effect in sorted(registry.SETTLED)},
                'notification_snapshot_closures': len(snapshots),
                'notification_snapshot_records': snapshots,
                'actions': actions, 'events': events, 'native_chain': self.qualification,
                'ledger_guard_receipts': self.guard.receipts,
                'notes': ['Permits, transport entries, target bodies, server terminals and business effects are distinct denominators.']}
