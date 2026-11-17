"""Finite historical-send qualification from original public log bytes.

This deliberately exposes coverage gaps. It never turns a vanished PID, empty
WorkSet, retry payload, equal audit snapshots, or a waiting interval into a
provider terminal. Only the fresh controlled task's acknowledged operations and
their publicly identified Sidekiq jobs are in scope.
"""
from __future__ import annotations
import base64
from collections import defaultdict
from datetime import datetime
import gzip
import hashlib
import json
import re
import zlib

from proofs import EvidenceGap, notice_key, require


def _decode_files(document):
    require(document.get('kind')=='history_logs' and document.get('source_complete') is True,
            'historical_log_sources_not_complete_or_stable')
    files=document.get('files')
    require(isinstance(files,list) and bool(files),'historical_log_files_absent')
    require(document.get('names_before')==document.get('names_after')==[row['name'] for row in files],
            'historical_log_filename_set_changed')
    rows=[]; unparsed=[]
    for file in files:
        require(file.get('unchanged_during_read') is True and file.get('capture_encoding')=='zlib+base64',
                'historical_log_file_not_bound')
        compressed=base64.b64decode(file['capture_zlib_base64'],validate=True)
        inflater=zlib.decompressobj()
        original=inflater.decompress(compressed,32*1024*1024+1)
        require(inflater.eof and not inflater.unconsumed_tail and not inflater.unused_data,
                'historical_log_capture_truncated_or_extra_compressed_stream')
        require(len(original)==file['bytes'] and hashlib.sha256(original).hexdigest()==file['sha256'],
                'historical_log_original_bytes_changed')
        content=gzip.decompress(original) if file['name'].endswith('.gz') else original
        require(len(content)<=64*1024*1024,'historical_log_expansion_bound')
        for number,line in enumerate(content.splitlines(keepends=True),1):
            item={'file':file['name'],'line':number,'line_sha256':hashlib.sha256(line).hexdigest()}
            pos=line.find(b'{')
            try:
                row=json.loads(line[pos:]) if pos>=0 else None
            except (ValueError,UnicodeDecodeError):
                row=None
            if isinstance(row,dict):
                rows.append({**item,'row':row})
            else:
                unparsed.append({**item,'raw':line})
    return rows,unparsed


def _timestamp(row):
    value=row.get('time')
    require(isinstance(value,str),'historical_job_timestamp_missing')
    try:
        return datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()
    except (ValueError,TypeError) as error:
        raise EvidenceGap('historical_job_timestamp_unparseable') from error


def _failure_boundary(row):
    """Narrow source-line rules; unexpected actual failures remain unknown.

    Net::SMTP 0.5.1 data's final recv_response call is line 979, AFTER
    write_message and flush. The trace must bind this exact source frame rather
    than merely mention EOF, smtp, a retry entry, or a connection reset.

    More pre-mail DB failure rules may be reviewed after real public logs arrive;
    broad 'any PG error means no mail' classification is intentionally absent.
    """
    error=row.get('exception.class')
    trace=row.get('exception.backtrace')
    if not isinstance(trace,list) or not trace or not all(isinstance(line,str) for line in trace):
        return None
    # The exact line number is tied to the pinned complete source SHA below.
    final_data=any(re.search(r'/net-smtp-0\.5\.1/lib/net/smtp\.rb:979:in [\x27`]block in data[\x27`]',line)
                   for line in trace)
    response_read=any(re.search(r'/net-smtp-0\.5\.1/lib/net/smtp\.rb:101[4-9]:in [\x27`]recv_response[\x27`]',line)
                      for line in trace)
    protocol_eof=any('/net-protocol-0.2.2/lib/net/protocol.rb:' in line
                     and any(name in line for name in ('rbuf_fill','readuntil','readline')) for line in trace)
    if error=='EOFError' and final_data and response_read and protocol_eof:
        return {'basis':'exact_pinned_SMTP_final_DATA_read_EOF',
                'smtp_source_sha256':'30eb817bda9db0aaa4eee10a0a90d40db6593221b004332a8dbd0f935f907517',
                'protocol_source_sha256':'3d011dfa382fa5cc90e3619f2dc56c47e2a29e25081d90515bfc1da80771ba88'}
    # Actual Issue.find is the first statement in setup_issue_mail. The fixed
    # ActionMailer construction invokes it before delivery; this is narrower
    # than inferring the stage from a PostgreSQL exception class alone.
    setup_find=any(re.search(r'/app/mailers/emails/issues\.rb:184:in [\x27`]setup_issue_mail[\x27`]',line)
                   for line in trace)
    new_issue=any(re.search(r'/app/mailers/emails/issues\.rb:[0-9]+:in [\x27`]new_issue_email[\x27`]',line)
                  for line in trace)
    no_smtp=not any('/net/smtp.rb:' in line or '/network/delivery_methods/smtp' in line for line in trace)
    if error in {'ActiveRecord::StatementInvalid','PG::UndefinedTable','ActiveRecord::RecordNotFound'} and setup_find and new_issue and no_smtp:
        return {'basis':'exact_Issue_find_failed_before_message_construction_and_SMTP',
                'application_source_sha256':'22960e4879f28927011fa01784be95cdafde16658fe9dbdb14d88434a27b591e'}
    return None


def qualify_history(document, receipts, *, runtime_approved, writers_stopped, queue_snapshot):
    require(runtime_approved is True,'historical_actual_runtime_source_contract_unqualified')
    require(writers_stopped is True,'historical_writer_barrier_missing')
    rows,unparsed=_decode_files(document)
    expected={notice_key(r):r for r in receipts}
    ids={r[k] for r in receipts for k in ('provider_job_id','job_id') if isinstance(r.get(k),str) and r[k]}
    require(ids<=set(document.get('requested_job_ids',[])),'historical_public_job_id_capture_set_incomplete')
    bad_lines=[row for row in unparsed if b'job_status' in row['raw']
               or any(value.encode() in row['raw'] for value in ids)]
    require(not bad_lines,'historical_relevant_or_job_lifecycle_line_unparseable')
    selected=[]; seen=set()
    for source in rows:
        row=source['row']
        if row.get('jid') not in ids:
            continue
        if row.get('job_status') is None:
            continue
        # Runit and application log files can mirror exactly one structured
        # event. Deduplication is only of the complete JSON object, not JID or
        # start/fail counts. All original copies remain in immutable capture.
        key=json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=True)
        if key in seen:
            continue
        seen.add(key); selected.append(source)
    selected.sort(key=lambda source:(_timestamp(source['row']),source['row'].get('jid',''),
                                    source['row'].get('sidekiq_tid',''),source['file'],source['line']))
    pending={}; attempts=defaultdict(list); gaps=[]
    for source in selected:
        row=source['row']; jid=row['jid']; tid=row.get('sidekiq_tid')
        if not isinstance(tid,str) or not tid:
            gaps.append({'jid':jid,'reason':'thread_identity_missing','source':{k:source[k] for k in ('file','line')}});continue
        key=(jid,tid); status=row['job_status']
        if status=='start':
            if key in pending:
                gaps.append({'jid':jid,'reason':'second_start_without_previous_terminal'})
            pending[key]=source
            continue
        start=pending.pop(key,None)
        if start is None:
            gaps.append({'jid':jid,'reason':'terminal_without_captured_start','status':status});continue
        terminal={'jid':jid,'thread_id':tid,'start':{k:start[k] for k in ('file','line','line_sha256')},
                  'terminal':{k:source[k] for k in ('file','line','line_sha256')},'job_status':status}
        if status=='done':
            # Mail#do_delivery can swallow transport exceptions when runtime
            # raise_delivery_errors is false; ActionMailer rescue handlers can
            # also change propagation. Standalone gem/source hashes do not bind
            # those actual Rails values. This branch remains disabled until an
            # actual read-only Rails contract is explicitly implemented/reviewed.
            terminal['qualification']=None
            terminal['qualification_gap']='done_without_actual_error_propagation_contract'
        elif status=='fail':
            terminal['qualification']=_failure_boundary(row)
        else:
            terminal['qualification']=None
        if terminal['qualification'] is None:
            gaps.append({'jid':jid,'reason':'historical_terminal_cannot_bound_provider_effect',
                         'status':status,'exception_class':row.get('exception.class'),
                         'source':terminal['terminal']})
        attempts[jid].append(terminal)
    gaps.extend({'jid':jid,'thread_id':tid,'reason':'start_without_public_terminal'} for jid,tid in pending)
    queued_ids={row['jid'] for row in queue_snapshot['jobs']}
    coverage=[]
    for key,receipt in expected.items():
        provider=receipt.get('provider_job_id'); active=receipt.get('job_id')
        own_ids={x for x in (provider,active) if isinstance(x,str) and x}
        records=[record for jid in own_ids for record in attempts.get(jid,[])]
        if not own_ids:
            coverage.append({'intent':list(key),'basis':'public_acknowledged_synchronous_send_returned_before_journal_write',
                             'old_attempts':[]})
        elif records and all(record['qualification'] is not None for record in records):
            coverage.append({'intent':list(key),'basis':'all_publicly_logged_old_attempts_have_qualified_terminals',
                             'old_attempts':records})
        elif not records and provider in queued_ids:
            # A never-started job cannot be inferred from its mere queue entry.
            # Complete fresh-instance logs can establish no start, but actual
            # event coverage must first be independently qualified in the run.
            gaps.append({'intent':list(key),'reason':'queued_job_without_start_requires_fresh_log_coverage_proof'})
        else:
            gaps.append({'intent':list(key),'reason':'acknowledged_job_has_no_qualified_attempt_coverage'})
    return {'schema':'b0-historical-SMTP-qualification-v1','qualified':not gaps,
            'scope':'only_public_acknowledged_notification_jobs_in_controlled_fresh_instance',
            'coverage':coverage,'gaps':gaps,'job_lifecycle_records':len(selected),
            'done_branch_enabled':False,
            'done_branch_gap':'actual_Rails_error_propagation_and_rescue_handler_contract_not_bound',
            'provider_private_state_read':False,'arbitrary_wait_used_as_evidence':False,
            'workset_or_PID_disappearance_used_as_terminal':False}
