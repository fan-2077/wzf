"""Fixed evidence validators shared by every controller arm.

These functions consume complete public captures, never provider state, fault
counters, private oracle inputs, caller-supplied terminal flags, or elapsed-time
guesses. A target wrapper's exit qualifies byte capture only; each business
operation below additionally establishes its own finite server-side boundary.
"""
from __future__ import annotations

import base64
from collections import Counter, defaultdict
import hashlib
import json
import re

from common_io import canonical, digest, parse_capture


class EvidenceGap(RuntimeError):
    """The available evidence cannot authorize a new business effect."""


class KnownBusinessFailure(RuntimeError):
    """A complete public observation establishes a business-policy failure."""


def require(condition, reason):
    if not condition:
        raise EvidenceGap(reason)


def original_arguments(action):
    return action['request']['parameters']['arguments']


def public_key(receipt):
    return (receipt['project'], receipt['iid'])


def notice_key(receipt):
    return (*public_key(receipt), receipt['recipient'], receipt['reason'])


def normalized_receipt(receipt, notification=False):
    fields=('project','iid','title','description','confidential')
    if notification:
        fields+=('recipient','reason')
    return {key:receipt[key] for key in fields}


def complete_http(row, *, method=None, path=None, status=None):
    require(isinstance(row,dict) and row.get('response_complete') is True,
            'http_response_not_complete')
    raw=base64.b64decode(row['body_base64'],validate=True)
    require(len(raw)==row['body_bytes'] and hashlib.sha256(raw).hexdigest()==row['body_sha256']
            and json.loads(raw)==row['body'], 'http_original_body_binding_failed')
    require(row.get('automatic_retries')==0, 'http_unqualified_automatic_retry')
    if method is not None:
        require(row.get('method')==method, 'http_method_mismatch')
    if path is not None:
        require(row.get('path')==path, 'http_path_mismatch')
    if status is not None:
        require(row.get('status')==status, 'http_status_mismatch')
    return row['body']


def audit_document(document):
    require(document.get('kind')=='public_audit' and document.get('source_complete') is True,
            'public_audit_incomplete')
    pages=document.get('pages')
    require(isinstance(pages,list) and bool(pages), 'public_audit_has_no_pages')
    expected_path='/messages'; items=[]; snapshot=None; total=None
    for response in pages:
        require(expected_path is not None, 'public_audit_extra_page')
        page=complete_http(response,method='GET',path=expected_path,status=200)
        require(type(page.get('snapshot')) is int and type(page.get('total')) is int
                and page['snapshot']>=0 and page['total']>=0, 'public_audit_header_schema')
        if snapshot is None:
            snapshot,total=page['snapshot'],page['total']
        require((page['snapshot'],page['total'])==(snapshot,total), 'public_audit_snapshot_differs')
        require(isinstance(page.get('items'),list),'public_audit_items_schema')
        items.extend(page['items']); expected_path=page.get('next')
        if expected_path is not None:
            require(bool(items) and expected_path=='/messages?after=%s&through=%s'%(items[-1]['id'],snapshot),
                    'public_audit_cursor_not_exact_next')
    require(expected_path is None and items==document['items'] and total==document['total']
            and snapshot==document['snapshot'] and len(items)==total,'public_audit_not_exhaustive')
    ids=[row.get('id') for row in items]
    require(all(type(value) is int and 1<=value<=snapshot for value in ids)
            and ids==sorted(ids) and len(set(ids))==len(ids), 'public_audit_delivery_id_ambiguity')
    for row in items:
        require(isinstance(row.get('headers'),dict) and isinstance(row.get('recipients'),list)
                and all(isinstance(x,str) for x in row['recipients'])
                and isinstance(row.get('subject'),str) and isinstance(row.get('body'),str),
                'public_audit_delivery_schema')
    return items


def classify_audit(document, receipts):
    """Compare incident effects to public business content, not mutable SQL IDs."""
    items=audit_document(document)
    expected={notice_key(row):row for row in receipts}
    require(len(expected)==len(receipts),'duplicate_public_notification_intent')
    good={key:[] for key in expected}; wrong={key:[] for key in expected}; unknown=[]
    for row in items:
        headers={key.lower():value for key,value in row['headers'].items()}
        if headers.get('x-gitlab-notificationreason')!='issue-update':
            continue
        strings=(headers.get('x-gitlab-project-id'),headers.get('x-gitlab-issue-iid'))
        candidates=[key for key in expected if tuple(map(str,key[:2]))==strings]
        match=next((key for key in candidates if row['recipients']==[key[2]]),None)
        if match is None:
            unknown.append(row['id']); continue
        receipt=expected[match]
        target=good if (row['recipients']==[receipt['recipient']]
                        and receipt['title'] in row['subject']
                        and receipt['description'] in row['body']) else wrong
        target[match].append(row['id'])
    return {'by_intent':{key:{'delivery_ids':good[key],'wrong_delivery_ids':wrong[key],
                'state':'conflict' if wrong[key] or len(good[key])>1 else 'accepted' if good[key] else 'missing'}
                for key in expected},
            'unattributed_issue_update_delivery_ids':unknown,
            'complete':True,'total':len(items),'snapshot':document['snapshot']}


def queue_document(document, *, stable=True):
    require(document.get('kind')=='queue_inventory' and document.get('source_complete') is True,
            'queue_capture_incomplete')
    require(document.get('redis_role')=='master' and isinstance(document.get('redis_run_id'),str)
            and bool(re.fullmatch(r'[0-9a-f]{40}',document['redis_run_id'])),
            'queue_redis_role_or_instance_unqualified')
    for snap in (document['before'],document['after']):
        require(snap.get('source_complete') is True,'queue_snapshot_incomplete')
        for pattern in ('queue:*','working:queue:*','*:work','reliable-fetcher-heartbeat-*'):
            pages=snap['patterns'][pattern]['scan']
            require(bool(pages) and pages[-1]['cursor']=='0', 'queue_scan_not_exhausted')
        for row in snap['jobs']:
            raw=base64.b64decode(row['raw_base64'],validate=True)
            require(hashlib.sha256(raw).hexdigest()==row['raw_sha256'] and json.loads(raw)==row['item']
                    and row['jid']==row['item'].get('jid'), 'queue_raw_payload_binding_failed')
        for row in snap['work']:
            raw=base64.b64decode(row['raw_base64'],validate=True)
            require(hashlib.sha256(raw).hexdigest()==row['raw_sha256'] and json.loads(raw)==row['value'],
                    'workset_raw_payload_binding_failed')
        keys=[row['key'] for row in snap['sets']]
        require(len(set(keys))==len(keys),'queue_set_key_repeated')
        required_keys=(set(snap['patterns']['queue:*']['keys'])|set(snap['patterns']['working:queue:*']['keys'])
                       |{'queue:'+name for name in snap['registered_queues']}|{'retry','schedule','dead','interrupted'})
        require(set(keys)==required_keys,'full_queue_set_enumeration_missing_keys')
        for source in snap['sets']:
            rows=[row for row in snap['jobs'] if row['key']==source['key']]
            require(len(rows)==source['length'] and [row['index'] for row in rows]==list(range(source['length'])),
                    'queue_set_length_or_order_not_preserved')
        token={'jobs':[{key:row[key] for key in ('key','type','index','score','jid','raw_sha256')}
                        for row in snap['jobs']],
               'work':[{key:row[key] for key in ('key','thread_id','raw_sha256')} for row in snap['work']]}
        require(digest(token)==snap['inventory_token'],'queue_token_binding_failed')
    if stable:
        require(document.get('stable_payloads') is True
                and document['before']['inventory_token']==document['after']['inventory_token'],
                'queue_payloads_not_stable')
    return document['after']


def old_job_receipt(item, receipts):
    """Require exact public job identity AND structured original mail arguments.

    Public receipt fields describe the old row/recipient IDs. They are used
    solely to identify stale queued jobs; they never authorize sending to those
    IDs after restore. Actual sending always resolves current public identity.
    """
    require(isinstance(item,dict),'old_job_payload_not_object')
    active=item.get('args',[None])[0] if isinstance(item.get('args'),list) and item['args'] else None
    require(isinstance(active,dict),'old_mail_job_missing_active_job')
    arguments=active.get('arguments')
    require(isinstance(arguments,list) and len(arguments)==4
            and arguments[:3]==['Notify','new_issue_email','deliver_now']
            and isinstance(arguments[3],dict),'old_mail_job_shape_not_qualified')
    mail_args=arguments[3].get('args')
    require(isinstance(mail_args,list) and len(mail_args)==3 and mail_args[2]=='issue-update',
            'old_mail_job_arguments_not_qualified')
    candidates=[]
    for receipt in receipts:
        ids={receipt.get('provider_job_id'),receipt.get('job_id')}-{None,''}
        if item.get('jid') in ids or active.get('job_id') in ids:
            require(mail_args[:2]==[receipt.get('recipient_id'),receipt.get('issue_id_at_acceptance')],
                    'old_job_public_id_matches_but_payload_disagrees')
            candidates.append(receipt)
    require(len(candidates)==1,'old_job_not_uniquely_bound_to_public_receipt')
    return candidates[0]


def is_possible_incident_job(item, receipts, identities=()):
    """Conservative detection only; a match never by itself authorizes deletion."""
    ids={r.get(k) for r in receipts for k in ('job_id','provider_job_id')}-{None,''}
    if item.get('jid') in ids:
        return True
    first=item.get('args',[None])[0] if isinstance(item.get('args'),list) and item['args'] else None
    if not isinstance(first,dict):
        return False
    if first.get('job_id') in ids:
        return True
    arguments=first.get('arguments',[])
    if not isinstance(arguments,list) or len(arguments)<4 or arguments[:2]!=['Notify','new_issue_email']:
        return False
    args=arguments[3].get('args',[]) if isinstance(arguments[3],dict) else []
    old_ids={r.get('issue_id_at_acceptance') for r in receipts}
    current_ids={r.get('issue_id') for r in identities}
    return len(args)>=3 and args[2]=='issue-update' and args[1] in old_ids|current_ids


def process_snapshot_document(snapshot):
    require(isinstance(snapshot,dict) and snapshot.get('source_complete') is True
            and snapshot.get('errors')==[] and snapshot.get('unread_live_pids')==[],
            'complete_process_snapshot_unavailable')
    rows=snapshot.get('processes')
    require(isinstance(rows,list) and all(isinstance(row,dict) for row in rows),'process_rows_missing')
    pids=[row.get('pid') for row in rows]
    require(all(type(pid)is int and pid>0 for pid in pids) and len(pids)==len(set(pids)),
            'process_PID_set_invalid')
    for row in rows:
        require(all(type(row.get(key))is int and row[key]>=0 for key in ('ppid','pgrp','session'))
                and isinstance(row.get('starttime'),str) and row['starttime'].isdigit()
                and isinstance(row.get('state'),str) and row.get('service') in {None,'puma','sidekiq'},
                'process_identity_fields_incomplete')
    require(isinstance(snapshot.get('listed_before'),list) and isinstance(snapshot.get('listed_after'),list)
            and set(pids)<=set(snapshot['listed_before']) and set(snapshot['listed_after'])<=set(pids),
            'process_enumeration_not_closed')
    require(type(snapshot.get('started_monotonic'))in (int,float)
            and type(snapshot.get('completed_monotonic'))in (int,float)
            and snapshot['started_monotonic']<=snapshot['completed_monotonic'],
            'process_enumeration_time_invalid')
    return rows


def supervision_status_document(row):
    require(isinstance(row,dict) and row.get('qualified') is True
            and row.get('status_stable_during_snapshot') is True,'service_supervision_unqualified')
    raw=base64.b64decode(row['raw_status_base64'],validate=True)
    require(len(raw)==20 and digest(raw)==row.get('raw_status_sha256'),'runit_raw_status_not_bound')
    pid=int.from_bytes(raw[12:16],'little');desired=raw[17];code=raw[19]
    require(desired in (100,117) and code in (0,1,2)
            and (row.get('pid'),row.get('desired_byte'),row.get('state_code'))==(pid,desired,code)
            and row.get('state')=={0:'down',1:'run',2:'finish'}[code]
            and row.get('desired_not_up') is (desired==100),'runit_status_fields_mismatch')
    supervisor=row.get('supervisor')
    require(isinstance(supervisor,dict) and supervisor.get('is_runsv') is True
            and type(supervisor.get('pid'))is int and supervisor['pid']>0
            and isinstance(supervisor.get('starttime'),str) and supervisor['starttime'].isdigit()
            and supervisor.get('state')!='Z'
            and supervisor.get('supervisor_cwd_identity')==row.get('directory',{}).get('identity'),
            'actual_same_service_supervisor_not_identified')
    return row


def same_supervision_identity(before,after):
    left=before.get('supervisor') or {};right=after.get('supervisor') or {}
    return (before.get('directory')==after.get('directory')
            and all(left.get(key)==right.get(key) for key in ('pid','starttime','supervisor_exe_identity')))


def service_source_document(document):
    require(isinstance(document,dict) and document.get('schema')=='b0-fixed-service-source-contract-v1'
            and document.get('qualified') is True and document.get('runit_version')=='2.1.2'
            and document.get('actual_manifest_format')==2
            and document.get('actual_runit_manifest_version_fields')=={
                'locked_version':'2.1.2','described_version':'2.1.2','display_version':'2.1.2'}
            and document.get('runit_locked_source_sha256')=='6fd0160cb0cf1207de4e66754b6d39750cff14bb0aa66ab49490992c0c47ba18'
            and len(document.get('source_files',[]))==7,'service_fixed_source_contract_missing')
    run=document.get('generated_run',{});raw=base64.b64decode(run['data_base64'],validate=True)
    require(len(raw)==run.get('bytes') and digest(raw)==run.get('sha256'),'service_generated_run_bytes_unbound')
    require(len(document.get('binaries',[]))==3 and isinstance(document.get('template'),dict),
            'service_binary_or_template_binding_missing')
    return document


def service_stop_document(doc,arguments=None):
    require(doc.get('kind')=='service_control' and doc.get('verb')=='stop'
            and doc.get('service_effect_verified') is True
            and doc.get('historical_smtp_terminal_claimed') is False,'service_stop_effect_unknown')
    command=doc.get('command',{})
    require(command.get('dispatch_count')==1 and command.get('wait_reaped') is True
            and type(command.get('exit_code'))is int and 0<=command['exit_code']<=255
            and command.get('termsig') is None and doc.get('command_exit')==command['exit_code'],
            'original_stop_control_not_once_completed_and_reaped')
    for stream in ('stdout','stderr'):
        raw=base64.b64decode(command[stream+'_base64'],validate=True)
        require(len(raw)==command.get(stream+'_bytes') and digest(raw)==command.get(stream+'_sha256'),
                'stop_original_command_output_not_bound')
    require(doc.get('source_contract_unchanged') is True and doc.get('sticky_gaps')==[],
            'service_stop_scope_changed_during_observation')
    service_source_document(doc['source_contract'])
    before=supervision_status_document(doc['before_status'])
    root=before.get('main_process') or {};session=doc.get('session_scope')
    initial=process_snapshot_document(doc['initial_process_snapshot'])
    require(doc.get('session_scope_qualified') is True and type(session)is int and session>0
            and before['state']=='run' and root.get('pid')==before['pid']==session==root.get('session')
            and before['supervisor'].get('session')!=session
            and any(row['pid']==root['pid'] and row['starttime']==root.get('starttime') for row in initial),
            'actual_independent_service_session_not_established')
    preparation=doc.get('pre_control_observations')
    require(isinstance(preparation,list) and len(preparation)>=2
            and all(row.get('running_session_scope_qualified') is True for row in preparation[-2:])
            and preparation[-1]['supervision']['status']==before
            and preparation[-1]['supervision']['process_snapshot']==doc['initial_process_snapshot']
            and same_supervision_identity(preparation[-2]['supervision']['status'],before)
            and preparation[-2]['supervision']['status']['main_process']['pid']==root['pid']
            and preparation[-2]['supervision']['status']['main_process']['starttime']==root['starttime'],
            'unique_stop_lacks_bound_running_session_preparation')
    observations=doc.get('observations')
    require(isinstance(observations,list) and bool(observations),'stop_readonly_observation_missing')
    final=observations[-1];after=supervision_status_document(final['status'])
    require(after==doc.get('after_status') and same_supervision_identity(before,after)
            and final.get('same_supervisor') is True and final.get('same_clock_identity') is True,
            'stop_final_supervisor_or_clock_changed')
    rows=process_snapshot_document(final['process_snapshot'])
    require(after['pid']==0 and after['state_code']==0 and after['desired_byte']==100
            and after['state']=='down','actual_service_not_down_without_want_up')
    tracked=doc.get('tracked_processes');owned=doc.get('owned_processes_before')
    require(isinstance(tracked,list) and isinstance(owned,list) and bool(owned)
            and {(row['pid'],row['starttime']) for row in owned}<={(row['pid'],row['starttime']) for row in tracked},
            'original_process_scope_not_retained')
    tracked_ids={(row['pid'],row['starttime']) for row in tracked}
    require(not any(row['state']!='Z' and (row['session']==session or row.get('service')==doc['service']
                or (row['pid'],row['starttime']) in tracked_ids) for row in rows),
            'service_session_or_tracked_descendant_still_live')
    require(final.get('postcondition_satisfied') is True and all(doc.get(key)==[] for key in
            ('same_owned_live_after','service_live_after','session_live_after'))
            and all(final.get(key)==[] for key in ('same_owned_live','service_live','session_live')),
            'stop_live_process_lists_not_empty')
    deadline=doc.get('deadline_monotonic')
    require(type(deadline)in (int,float) and doc.get('fixed_observation_budget_seconds')==120
            and doc['action_started_monotonic']<deadline<=doc['action_started_monotonic']+120
            and doc['action_started_monotonic']<=command['started_monotonic']<=command['completed_monotonic'],
            'stop_fixed_deadline_or_control_timeline_invalid')
    previous=command['completed_monotonic']
    prepared_after=doc['action_started_monotonic']
    for observed in preparation:
        require(prepared_after<=observed['started_monotonic']<=observed['completed_monotonic']<=command['started_monotonic'],
                'pre_control_observation_timeline_invalid')
        prepared_after=observed['completed_monotonic']
    for observed in observations:
        require(previous<=observed['started_monotonic']<=observed['completed_monotonic']<=deadline,
                'stop_observation_outside_registered_budget')
        previous=observed['completed_monotonic']
    if arguments is not None:
        require(doc['service']==arguments['service'] and doc['clock_identity']==arguments['clock_identity']
                and deadline==arguments['deadline_monotonic'],'stop_clock_or_deadline_argument_mismatch')
    return {'service':doc['service'],'session':session,'tracked_process_ids':tracked_ids,'final_status':after,
            'final_observation':final,'command_exit':command['exit_code']}


def services_document(document):
    require(document.get('kind')=='service_inventory' and document.get('source_complete') is True,
            'service_capture_incomplete')
    processes=process_snapshot_document(document['process_snapshot'])
    require(document.get('processes')==processes,'service_inventory_process_snapshot_mismatch')
    rows={row['service']:row for row in document['statuses']}
    require(len(document['statuses'])==2 and set(rows)=={'puma','sidekiq'},'service_set_incomplete')
    for name,row in rows.items():
        supervision_status_document(row);service_source_document(document['source_contracts'][name])
        require(row['state'] in {'run','down'},'service_state_unqualified')
        supervisor=row['supervisor']
        require(any(p['pid']==supervisor['pid'] and p['starttime']==supervisor['starttime'] and p['state']!='Z'
                    for p in processes),'service_supervisor_process_not_current')
        if row['state']=='run':
            require(any(p['pid']==row['pid'] and p['state']!='Z' for p in processes),
                    'service_main_pid_not_live')
    return rows


def writer_barrier(document,stop_documents):
    rows=services_document(document)
    require(set(stop_documents)=={'puma','sidekiq'},'same_service_stop_certificates_missing')
    require(document.get('writers_stopped') is True,'actual_writer_barrier_not_established')
    for name,row in rows.items():
        stop=stop_documents[name];certificate=service_stop_document(stop)
        require(certificate['service']==name and same_supervision_identity(certificate['final_status'],row)
                and document['source_contracts'][name]==stop['source_contract'],
                'writer_barrier_service_or_source_generation_changed')
        require(row['pid']==0 and row['state_code']==0 and row['desired_byte']==100,
                'writer_barrier_supervisor_may_restart')
        require(document['process_snapshot']['started_monotonic']>=certificate['final_observation']['completed_monotonic'],
                'writer_barrier_snapshot_predates_original_stop')
        require(not any(p['state']!='Z' and (p['session']==certificate['session'] or p.get('service')
                    or (p['pid'],p['starttime']) in certificate['tracked_process_ids']) for p in document['processes']),
                'writer_barrier_prior_session_or_descendant_live')
    return {'services':['puma','sidekiq'],'actual_service_processes_absent':True,
            'same_supervision_and_stop_session_certificates':True,'historical_smtp_terminal_claimed':False}


def service_effect(action,capture,bridge):
    doc=parse_capture(capture); args=original_arguments(action)
    require(doc.get('kind')=='service_control' and (doc.get('service'),doc.get('verb'))==(args['service'],args['verb']),
            'service_action_capture_mismatch')
    if args['verb']=='stop':
        certificate=service_stop_document(doc,args)
        claim='one_stop_control_completed_then_complete_same_supervision_and_finite_process_postcondition'
    else:
        require(doc.get('service_effect_verified') is True and doc.get('command_exit')==0,
                'service_start_effect_unknown')
        after=supervision_status_document(doc['after_status'])
        require(after['state']=='run' and after['pid']>0 and after['desired_byte']==117,
                'service_start_supervisor_not_running')
        claim='successful_start_command_and_actual_supervised_running_process'
    return {'execution_terminal_qualified':True,'settled_effect':'settled_applied','claim':claim,
            'service':args['service'],'verb':args['verb'],'historical_smtp_terminal_claimed':False,
            'original_command_exit':doc['command_exit'],'capture_sha256':digest(capture['stdout'])}


def json_lines_from_base64(value):
    text=base64.b64decode(value,validate=True).decode('utf-8')
    return [json.loads(line) for line in text.splitlines() if line.startswith(('{','['))]


def restore_effect(action,capture,bridge):
    doc=parse_capture(capture); args=original_arguments(action)
    require(doc.get('file')==args['file'] and doc.get('archive_sha_before')==args['expected_sha256']
            and doc.get('archive_sha_after')==args['expected_sha256'], 'restore_archive_binding_changed')
    require(doc.get('confirmation_exit')==0,'restore_database_confirmation_incomplete')
    reset=json_lines_from_base64(doc['reset_stdout_base64'])
    confirms=json_lines_from_base64(doc['confirmation_base64'])
    require(len(reset)==1 and len(confirms)==1,'restore_server_identity_records_missing')
    before,after=reset[0],confirms[0]
    require(before['application_name']=='b0-reset-'+args['action_tag'] and type(before['pid']) is int
            and bool(before['backend_start']) and bool(before['xid']), 'reset_session_not_bound')
    require(before['server_address']==after['server_address']
            and before['postmaster_start']==after['postmaster_start']
            and after['matching_sessions']==[],'restore_server_changed_or_owned_backend_not_terminal')
    samples=json_lines_from_base64(doc['backend_samples_base64'])
    seen=[row for batch in samples for row in batch]
    require(doc['restore_exit']==125 or (type(doc['restore_child_pid']) is int and doc['restore_child_pid']>0
            and bool(base64.b64decode(doc['restore_child_stat_base64'],validate=True))
            and bool(seen)), 'actual_restore_backend_identity_not_captured')
    require(all(row['application_name']=='b0-restore-'+args['action_tag'] and type(row['pid']) is int
                and bool(row['backend_start']) for row in seen),'restore_backend_binding_failed')
    valid=doc['reset_exit']==0 and doc['restore_exit']==0 and after['issues_present'] is True
    return {'execution_terminal_qualified':True,'settled_effect':'settled_applied' if valid else 'partial_or_conflict',
            'database_valid':valid,'reset_exit':doc['reset_exit'],'restore_exit':doc['restore_exit'],
            'server_identity':{'address':after['server_address'],'postmaster_start':after['postmaster_start']},
            'backend_identities':sorted({(row['pid'],row['backend_start']) for row in seen}),
            'claim':'fixed_synchronous_SQL_responses_owned_restore_exit_and_no_bound_backend_remaining',
            'capture_sha256':digest(capture['stdout'])}


def issue_matches(issue,receipt):
    return issue.get('project_id')==receipt['project'] and all(issue.get(key)==receipt[key]
                     for key in ('iid','title','description','confidential'))


def issue_response_request_id(action,capture):
    """Use the original POST response ID, never assume client ID propagation."""
    doc=parse_capture(capture); receipt=original_arguments(action)['receipt']
    require(doc.get('kind')=='issue_replay' and doc.get('dispatched_post') is True,
            'replay_original_POST_capture_required_for_server_request_id')
    complete_http(doc['response'],method='POST',
                  path='/api/v4/projects/%d/issues'%receipt['project'],status=201)
    request_id=doc['response'].get('headers',{}).get('x-request-id')
    require(isinstance(request_id,str) and bool(re.fullmatch(r'[A-Za-z0-9_-]{1,128}',request_id)),
            'replay_actual_POST_response_request_id_missing_or_invalid')
    return request_id


def issue_effect(action,capture,completion_document):
    doc=parse_capture(capture); args=original_arguments(action); receipt=args['receipt']
    require(doc.get('kind')=='issue_replay' and doc.get('user',{}).get('is_admin') is True,
            'replay_current_admin_not_qualified')
    path='/api/v4/projects/%d/issues/%d'%public_key(receipt)
    if doc.get('dispatched_post') is False:
        row=complete_http(doc['before'],method='GET',path=path)
        require(doc['before']['status']==200 and issue_matches(row,receipt)
                and doc.get('classification')=='already_matches','replay_no_post_conflict_or_unavailable')
        return {'execution_terminal_qualified':True,'settled_effect':'settled_applied',
                'claim':'existing_public_issue_matches_and_no_POST_was_dispatched',
                'capture_sha256':digest(capture['stdout'])}
    require(doc.get('dispatched_post') is True and doc.get('mode')=='explicit_public_iid',
            'replay_creation_mode_unqualified')
    complete_http(doc['before'],method='GET',path=path,status=404)
    response=complete_http(doc['response'],method='POST',path='/api/v4/projects/%d/issues'%receipt['project'],status=201)
    current=complete_http(doc['post'],method='GET',path=path,status=200)
    require(issue_matches(response,receipt) and issue_matches(current,receipt)
            and current.get('id')==response.get('id'),'replay_actual_public_identity_differs')
    server_request_id=issue_response_request_id(action,capture)
    require(isinstance(completion_document,dict) and completion_document.get('kind')=='http_completion'
            and completion_document.get('source_complete') is True
            and completion_document.get('request_id')==server_request_id,'replay_server_completion_capture_missing')
    rows=completion_document.get('records')
    require(isinstance(rows,list) and len(rows)==1,'replay_server_completion_not_one_original_record')
    matched=rows[0]
    require(matched.get('correlation_id')==server_request_id and matched.get('method')=='POST'
            and matched.get('path')=='/api/v4/projects/%d/issues'%receipt['project']
            and type(matched.get('status')) is int and matched['status']==201
            and matched.get('file') in {'/var/log/gitlab/gitlab-rails/api_json.log',
                                       '/var/log/gitlab/gitlab-rails/api_json.log.1'}
            and isinstance(matched.get('line_sha256'),str)
            and bool(re.fullmatch(r'[0-9a-f]{64}',matched['line_sha256'])),
            'replay_HTTP_server_request_identity_not_closed')
    return {'execution_terminal_qualified':True,'settled_effect':'settled_applied',
            'claim':'fixed_synchronous_API_contract_completed_201_public_log_and_fresh_exact_GET',
            'client_requested_correlation_id':args['correlation_id'],
            'actual_POST_response_request_id':server_request_id,
            'completion_record_line_sha256':matched['line_sha256'],
            'client_ID_propagation_assumed':False,
            'public_identity':list(public_key(receipt)),'current_issue_id':current['id'],
            'capture_sha256':digest(capture['stdout'])}


def prune_effect(action,capture,bridge):
    doc=parse_capture(capture); args=original_arguments(action)
    require(doc.get('kind')=='queue_prune' and doc.get('source_complete') is True,
            'prune_capture_incomplete')
    require(doc['redis_db']==args['redis_db'] and doc['redis_run_id']==args['redis_run_id']
            and doc['before']['inventory_token']==args['before_token'],'prune_original_selection_binding_failed')
    commands=doc.get('commands',[])
    evals=[row for row in commands if row.get('command')=='EVAL']
    require(len(evals)==1 and evals[0].get('response_received') is True,
            'prune_Redis_atomic_command_terminal_unknown')
    require(doc.get('instance_unchanged') is True,'prune_Redis_instance_changed')
    if doc['classification']=='applied':
        require(doc['removed_counts']==[row['delete_count'] for row in args['selected']]
                and doc['unselected_sequence_and_multiplicity_preserved'] is True,
                'prune_preservation_or_multiplicity_failed')
        effect='settled_applied'
    elif doc['classification']=='not_applied':
        require(doc['redis_reply'][0]=='precondition_failed'
                and doc['before']['inventory_token']==doc['after']['inventory_token'],
                'prune_nonapplication_not_proven')
        effect='settled_not_applied'
    else:
        effect='partial_or_conflict'
    return {'execution_terminal_qualified':True,'settled_effect':effect,
            'claim':'one_atomic_Redis_reply_after_validation_and_complete_before_after_preservation',
            'capture_sha256':digest(capture['stdout'])}


def smtp_terminal(action,capture,bridge):
    doc=parse_capture(capture); intent=original_arguments(action)['intent']
    require(doc.get('kind')=='notification_send' and doc.get('intent')==intent,
            'notification_original_intent_binding_failed')
    require(doc.get('identity',{}).get('matches') is True
            and doc.get('smtp_internal_retries_counted') is True and doc.get('automatic_outer_retries')==0,
            'notification_application_identity_or_retry_contract_failed')
    require(doc.get('real_application')=='Notify.new_issue_email(...).deliver_now',
            'notification_not_real_GitLab_mail_path')
    require(doc.get('installed_observers')=={'smtp_first_ancestor':'B0SMTPObserver',
               'message_io_first_ancestor':'B0MessageIOObserver'},'SMTP_observer_not_actual_first_method_owner')
    expected={key:('Net::SMTP','30eb817bda9db0aaa4eee10a0a90d40db6593221b004332a8dbd0f935f907517')
              for key in ('smtp_tcp_socket','smtp_message_io','smtp_start','smtp_get_response',
                          'smtp_data','smtp_recv','smtp_sendmail','smtp_finish')}
    expected.update({
        'message_writer':('Net::InternetMessageIO','3d011dfa382fa5cc90e3619f2dc56c47e2a29e25081d90515bfc1da80771ba88'),
        'wire_writer':('Net::BufferedIO','3d011dfa382fa5cc90e3619f2dc56c47e2a29e25081d90515bfc1da80771ba88'),
        'smtp_delivery':('Mail::SMTP','14596f84aee964e30fb262caf65730cdb5f926956a3612c78f7cff28484f7459'),
        'smtp_connection':('Mail::SMTPConnection','26a2ea105b2f3c00f05d31d8848e94346f8d2a963d22326d3a74e5dfbc2d61a5'),
        'mail_deliver':('Mail::Message','62aec80d17112b198cd3cc9f7820e95e043c41fb279ce3edd3d6fb15da721dba'),
        'action_mailer_deliver_now':('ActionMailer::MessageDelivery','599657ce3dddf8fd22665aea50ee299d4df5e2c566b22566ae114ac2806131af'),
        'actual_notify_new_issue_email':('Emails::Issues','22960e4879f28927011fa01784be95cdafde16658fe9dbdb14d88434a27b591e')})
    require(all(doc.get('runtime_bindings',{}).get(key,{}).get('owner')==value[0]
                and doc['runtime_bindings'][key].get('sha256')==value[1] for key,value in expected.items()),
            'actual_Rails_SMTP_source_and_method_owners_unqualified')
    events=doc.get('smtp_events'); sessions=doc.get('smtp_sessions')
    require(isinstance(events,list) and events and isinstance(sessions,list),'SMTP_trace_missing')
    require([e['sequence'] for e in events]==list(range(1,len(events)+1)),'SMTP_trace_not_contiguous')
    require(sum(e['event']=='application_deliver_now_start' for e in events)==1
            and sum(e['event'] in {'application_deliver_now_return','application_deliver_now_error'} for e in events)==1,
            'SMTP_application_invocation_not_bounded')
    ids=[row['session_id'] for row in sessions]
    require(ids==list(range(1,len(ids)+1)) and all(row.get('all_sockets_closed') is True for row in sessions),
            'SMTP_owned_client_sessions_not_closed')
    require(all(e.get('session_id') in ids for e in events if 'session_id' in e),
            'SMTP_event_session_missing')
    entries=[e for e in events if e['event']=='data_method_entry']
    allowed=[e for e in events if e['event']=='data_allowed']
    writers=[e for e in events if e['event']=='message_writer_start']
    require(doc['data_method_entries']==len(entries) and doc['allowed_data_entries']==len(allowed)
            and len(allowed)<=1 and len(writers)<=1,'SMTP_implicit_body_retry_or_trace_gap')
    for permitted in allowed:
        matches=[e for e in events if e['event']=='qualified_data_io' and e.get('session_id')==permitted['session_id']
                 and e['sequence']<permitted['sequence']]
        require(len(matches)==1 and matches[0].get('io_class')=='Net::InternetMessageIO'
                and matches[0].get('write_message_owner')=='B0MessageIOObserver'
                and matches[0].get('writeline_owner')=='B0MessageIOObserver',
                'actual_DATA_io_not_closed_under_instrumented_stack')
        require(any(e['event']=='message_io_bound' and e.get('session_id')==permitted['session_id']
                    and e.get('io_object_id')==matches[0]['io_object_id'] and e['sequence']<matches[0]['sequence'] for e in events),
                'actual_DATA_io_not_bound_to_original_SMTP_session')
    for event in events:
        if event['event']=='tcp_connect_start':
            require((event.get('address'),event.get('port'))==('notification-mailbox',1025),
                    'SMTP_destination_unqualified')
    results=[]
    for session in sessions:
        own=[e for e in events if e.get('session_id')==session['session_id']]
        connected=[e for e in own if e['event']=='tcp_connected']
        require(len(connected)==session['socket_count'],'SMTP_socket_accounting_incomplete')
        for event in connected:
            require(isinstance(event.get('peer'),list) and event['peer'][1]==1025
                    and isinstance(event.get('socket_inode'),str),'SMTP_peer_identity_incomplete')
        starts=[e for e in own if e['event']=='message_writer_start']
        if not starts:
            # In this fixed provider protocol acceptance can only run after the
            # body terminator. Handshake-only server threads need not physically
            # disappear to prove no request remains that could append mail.
            results.append({'session_id':session['session_id'],
                'terminal_basis':'no_DATA_body_writer_invoked_in_complete_actual_stack_trace'})
            continue
        require(len(starts)==1 and bool(connected),'SMTP_body_without_single_bound_connection')
        start=starts[0]['sequence']
        data_commands=[e for e in own if e['event']=='wire_command_start' and e.get('command')=='DATA']
        data_returns=[e for e in own if e['event']=='wire_command_return' and e.get('command')=='DATA']
        continued=[e for e in own if e['event']=='response_read_complete' and e.get('phase')=='data_continue'
                   and e.get('status')=='354']
        require(len(data_commands)==len(data_returns)==len(continued)==1
                and data_commands[0]['sequence']<data_returns[0]['sequence']<continued[0]['sequence']<start,
                'SMTP_body_without_actual_DATA_wire_and_continue_reply')
        returns=[e for e in own if e['event']=='message_writer_return' and e['sequence']>start]
        require(len(returns)==1 and returns[0].get('qualified_source_includes_end_of_data_marker') is True,
                'SMTP_body_write_or_flush_may_still_be_ambiguous')
        final=[e for e in own if e.get('phase')=='data_final' and e['sequence']>returns[0]['sequence']]
        require(len([e for e in final if e['event']=='response_read_start'])==1,
                'SMTP_final_response_read_not_reached_after_flush')
        terminals=[e for e in final if e['event'] in {'response_read_complete','response_read_error'}]
        require(len(terminals)==1,'SMTP_final_response_terminal_missing')
        terminal=terminals[0]
        if terminal['event']=='response_read_complete':
            require(bool(re.fullmatch(r'[245][0-9]{2}',str(terminal.get('status','')))),
                    'SMTP_final_reply_not_terminal_reply')
            basis='actual_final_DATA_reply_after_body_and_flush'
        else:
            require(terminal.get('error_type')=='EOFError'
                    and terminal.get('client_socket_already_closed') is False
                    and terminal.get('message_writer_returned') is True
                    and terminal.get('data_continue_received') is True,
                    'SMTP_timeout_reset_or_nonfinal_EOF_is_unknown')
            basis='peer_EOF_in_exact_final_DATA_response_read_under_commit_or_reject_before_close_contract'
        results.append({'session_id':session['session_id'],'terminal_basis':basis,
                        'final_event_sequence':terminal['sequence']})
    return {'execution_terminal_qualified':True,'claim':'all_actual_SMTP_subtransactions_terminal_for_append_only_effect',
            'sessions':results,'data_method_entries':len(entries),'actual_body_submissions':len(writers),
            'actual_DATA_command_starts':sum(e['event']=='wire_command_start' and e.get('command')=='DATA' for e in events),
            'actual_DATA_command_returns':sum(e['event']=='wire_command_return' and e.get('command')=='DATA' for e in events),
            'actual_connections':sum(e['event']=='tcp_connected' for e in events),
            'implicit_body_retry_refusals':sum(e['event']=='implicit_data_retry_refused' for e in events),
            'delivery_acceptance_claimed':False,'requires_new_causal_complete_public_audit':True,
            'capture_sha256':digest(capture['stdout'])}
