"""Host-only B0-P evidence interpretation; never performs an original evaluation.

Business truth is read only from the retained pre-reference-cleanup snapshot.
Public self-checks and additional historical assurance remain separate facts.
"""
from __future__ import annotations
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

PROTOCOL = 'public_result_v1'
ID = re.compile(r'[A-Za-z0-9_-]{1,80}\Z')
HEX = re.compile(r'[0-9a-f]{64}\Z')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def load_json(path, maximum=32*1024*1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        metadata = os.fstat(source.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_size > maximum):
            raise RuntimeError('Invalid owned host evidence file')
        raw = source.read(maximum + 1)
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def original_snapshot(before, rows, attempt):
    """Interpret actual retained data, including exceptions after evaluation."""
    starts = [r for r in rows if r.get('phase') == 'stage:mitigation' and r.get('event') == 'start']
    evaluations = [r for r in rows if r.get('phase') == 'evaluate:mitigation' and r.get('event') == 'start']
    ends = [r for r in rows if r.get('phase') == 'evaluate:mitigation' and r.get('event') == 'end']
    cleanup = [r for r in rows if r.get('phase') == 'cleanup' and r.get('event') == 'start']
    same_attempt = bool(rows) and all(r.get('attempt_id') == attempt for r in rows)
    finite = lambda value: type(value) in (int, float) and math.isfinite(value)
    ordered = (len(starts) == len(evaluations) == len(ends) == 1 and same_attempt
               and all(finite(r.get('mono')) for r in starts + evaluations + ends)
               and starts[0]['mono'] <= evaluations[0]['mono'] <= ends[0]['mono'])
    suspension_valid = all(finite(r.get('suspended_s', 0)) and r.get('suspended_s', 0) >= 0 for r in rows)
    suspended = any(finite(r.get('suspended_s', 0)) and r.get('suspended_s', 0) > 0 for r in rows)
    retained = (isinstance(before, dict) and before.get('attempt_id') == attempt
                and before.get('reference_cleanup_has_started_business_repair') is False
                and isinstance(before.get('native_result'), dict))
    raw = before['native_result'].get('Mitigation') if retained else None
    value = raw.get('success') if isinstance(raw, dict) else None
    valid_value = value is None or type(value) is bool
    # Source identity and position are separate from whether the original
    # evaluator has produced a Boolean. No after-cleanup fallback exists.
    snapshot_ordered = (retained and finite(before.get('monotonic'))
                        and (not ends or (len(ends) == 1 and finite(ends[0].get('mono'))
                                             and ends[0]['mono'] <= before['monotonic']))
                        and len(cleanup) == 1 and finite(cleanup[0].get('mono'))
                        and cleanup[0]['mono'] <= before['monotonic']
                        and (not ends or ends[0]['mono'] <= cleanup[0]['mono']))
    return {
        'original_mitigation_success': value if valid_value else None,
        'raw_result_value': value,
        'original_result_type_valid': valid_value,
        'pre_cleanup_source_identity_valid': retained,
        'pre_cleanup_snapshot_order_valid': bool(snapshot_ordered),
        'original_evaluation_start_count': len(evaluations),
        'original_evaluation_end_count': len(ends),
        'phase_attempt_identity_valid': same_attempt,
        'timing': {'start_count': len(starts), 'evaluation_start_count': len(evaluations),
                   'evaluation_end_count': len(ends),
                   'valid': bool(ordered and suspension_valid and not suspended),
                   'suspended_record_present': suspended,
                   'seconds': ends[0]['mono'] - starts[0]['mono'] if ordered and suspension_valid and not suspended else None,
                   'scope': 'first incident visibility through unique original evaluation end, same native monotonic clock',
                   'success_speed_comparison': False},
    }


def retain_original(out, attempt):
    path = Path(out) / 'native-result-before-reference-cleanup.json'
    phase = Path(out) / 'native-phases.jsonl'
    before, source_sha = load_json(path) if path.exists() else ({}, None)
    errors = []
    phase_sha = None
    try:
        phase_raw = phase.read_bytes() if phase.exists() else b''
        phase_sha = hashlib.sha256(phase_raw).hexdigest() if phase.exists() else None
        rows = [json.loads(line) for line in phase_raw.decode().splitlines() if line]
        if not all(isinstance(row, dict) for row in rows):
            raise ValueError('Phase evidence contains a non-object row')
    except Exception as error:
        rows = []
        errors.append('phase_evidence:' + type(error).__name__ + ': ' + str(error))
    return {**original_snapshot(before, rows, attempt),
            'original_result_source': path.name if source_sha else None,
            'original_result_source_sha256': source_sha,
            'original_phases_source_sha256': phase_sha,
            'ledger_continuous_before_reference_cleanup':
                before.get('ledger_guard_final_before_reference_cleanup', {}).get('valid') is True,
            'source_errors': errors + [key for key in ('guard_error',) if before.get(key)]}


def receipt_valid(receipt, attempt):
    return (isinstance(receipt, dict)
            and receipt.get('schema') == 'b0-original-submission-acceptance-v1'
            and receipt.get('attempt_id') == attempt
            and all(isinstance(receipt.get(k), str) and ID.fullmatch(receipt[k])
                    for k in ('action_id', 'native_call_id'))
            and isinstance(receipt.get('response_sha256'), str) and HEX.fullmatch(receipt['response_sha256'])
            and receipt.get('state') == 'accepted_pending_evaluation'
            and receipt.get('submission_state') == 'accepted_for_evaluation'
            and 'business_success' in receipt and receipt['business_success'] is None
            and receipt.get('original_evaluation_terminal') is False
            and receipt.get('agent_has_seen_original_oracle_result') is False
            and receipt.get('requires_host_original_evaluation') is True)


def readiness_valid(preconditions):
    if not isinstance(preconditions, dict):
        return False
    owned = preconditions.get('owned_execution_before_submit')
    return (preconditions.get('qualified') is True
            and preconditions.get('protocol_id') == PROTOCOL
            and preconditions.get('execution_ready_for_original_evaluation') is True
            and preconditions.get('original_oracle_only') is True
            and type(preconditions.get('prior_final_submission_count')) is int
            and preconditions['prior_final_submission_count'] == 0
            and preconditions.get('historical_terminal_required') is False
            and isinstance(preconditions.get('evidence_handles'), list) and bool(preconditions['evidence_handles'])
            and isinstance(owned, dict) and owned.get('point') == 'before_original_submission'
            and owned.get('all_owned_actions_closed') is True
            and all(owned.get(key) == [] for key in
                    ('owned_unresolved_action_ids', 'unresolved_actions', 'resource_locks', 'final_submission_actions'))
            and isinstance(preconditions.get('target_identities'), dict) and bool(preconditions['target_identities'])
            and isinstance(preconditions.get('ledger_guard'), dict)
            and preconditions['ledger_guard'].get('valid') is True)


def bind_submission(agent, logs, attempt, launch):
    """Bind summary readiness to the exact original request and acceptance.

    SQLite action/evidence and native transport verification remain explicit
    independent archive-review obligations; an agent summary alone is not proof.
    """
    receipt = agent.get('submission_receipt') or {}
    result = {'receipt_structure_valid': bool(receipt_valid(receipt, attempt)),
              'receipt_raw_binding_valid': False, 'readiness_bound_to_original_request': False,
              'profile_binding_valid': (agent.get('protocol_id') == launch.get('protocol_id') == PROTOCOL
                                        and agent.get('schema') == 'b0-public-result-controller-v1'
                                        and agent.get('mode') == launch.get('mode') == 'public_b0'),
              'independent_registry_and_native_transport_review': 'pending',
              'errors': []}
    if not result['receipt_structure_valid']:
        return result
    try:
        common = Path(logs) / 'b0-common'
        record, record_sha = load_json(common / 'FINAL_SUBMISSION_ACCEPTED.json')
        request, request_sha = load_json(common / 'calls' / (receipt['native_call_id'] + '.request.json'))
        response, response_file_sha = load_json(common / 'calls' / (receipt['native_call_id'] + '.response.json'))
        action = receipt.get('original_action') or {}
        payload = response.get('native_response') or {}
        action_request = action.get('request') or {}
        preconditions = request.get('preconditions')
        binding = (receipt_valid(record, attempt) and all(receipt.get(k) == v for k, v in record.items())
                   and record_sha == digest(record) and request_sha == digest(request)
                   and receipt['response_sha256'] == digest(response) == response_file_sha
                   and request.get('operation') == 'submit'
                   and request.get('action_id') == receipt['action_id']
                   and request.get('call_id') == receipt['native_call_id']
                   and response.get('transport_state') == 'response_received'
                   and response.get('trace_complete') is True and response.get('http_status') == 200
                   and isinstance(payload, dict) and payload.get('stage') == 'mitigation'
                   and str(payload.get('status')) == '200'
                   and response.get('submission_state') == 'accepted_for_evaluation'
                   and response.get('business_success') is None
                   and action.get('attempt') == attempt and action.get('id') == receipt['action_id']
                   and action.get('operation') == 'final_submit'
                   and action.get('execution') == 'running' and action.get('effect') == 'unknown'
                   and action.get('terminal_evidence') is None and action.get('settlement_evidence') is None
                   and action.get('dispatch_epoch') is not None
                   and action.get('semantic_sha') == request.get('semantic_sha256') == digest(action_request)
                   and action_request.get('parameters', {}).get('precondition_sha256') == digest(preconditions)
                   and action_request.get('parameters', {}).get('solution_sha256') ==
                       hashlib.sha256(request['arguments']['solution'].encode()).hexdigest())
        result['receipt_raw_binding_valid'] = bool(binding)
        readiness = (readiness_valid(preconditions)
                     and preconditions.get('ledger_guard', {}).get('attempt_id') == attempt
                     and preconditions.get('ledger_guard', {}).get('ledger_epoch') == launch.get('ledger_epoch')
                     and agent.get('execution_ready_for_original_evaluation') is True
                     and canonical(agent.get('evaluation_readiness')) == canonical(preconditions))
        result['readiness_bound_to_original_request'] = bool(binding and readiness)
        result.update(action_id=receipt['action_id'], native_call_id=receipt['native_call_id'],
                      accepted_response_sha256=receipt['response_sha256'], receipt_file_sha256=record_sha,
                      request_file_sha256=request_sha, response_file_sha256=response_file_sha,
                      preconditions_sha256=digest(preconditions), evaluation_readiness=preconditions)
    except Exception as error:
        result['errors'].append(type(error).__name__ + ': ' + str(error))
    return result


def classification(raw, complete):
    if complete and raw is True:
        return 'COMPLETED_NATIVE_SUCCESS_PENDING_INDEPENDENT_REVIEW'
    if complete and raw is False:
        return 'COMPLETED_VALID_POLICY_FAILURE'
    if type(raw) is bool:
        return 'ORIGINAL_RESULT_RETAINED_EXECUTION_INCOMPLETE'
    return 'ORIGINAL_RESULT_NOT_OBTAINED'
