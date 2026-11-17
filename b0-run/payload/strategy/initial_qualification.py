"""Collect real public runtime evidence; perform zero business writes or submits.

This is an engineering qualification attempt, never a scored B0 recovery.
Unavailable or unqualified application evidence is retained as a specific gap.
"""
from __future__ import annotations
import json
import time
import traceback
import catalog_readonly as catalog
from common_io import Driver, canonical, decode_recovery_document, write_result

def main():
    driver=None
    try:
        driver=Driver(catalog)
        if driver.context.get('mode')!='native_readonly_qualification' or driver.context.get('allowed_operations')!=['observe']:
            raise RuntimeError('read_only_launch_mode_not_explicit')
        qualification=driver.initialize()
        collected={}
        for operation in ('app_info','status','describe_tools'):
            collected['native_'+operation]=driver.bridge.read_native_api(operation)
        collected['runtime_contract']=driver.collect('runtime_contract',{})
        for kind in ('catalog','issues','notifications'):
            collected[kind]=driver.collect('recovery_files',{'kind':kind})
        collected['database_state']=driver.collect('database_state',{'action_tag':'initial_qualification'})
        catalog_doc=None
        try:
            catalog_doc=decode_recovery_document(collected['catalog'])
            if not isinstance(catalog_doc,list):raise RuntimeError('catalog_expected_list')
            for index,row in enumerate(catalog_doc):
                if index>=32:raise RuntimeError('catalog_entry_budget')
                if row.get('status')=='completed' and isinstance(row.get('sha256'),str):
                    collected['archive_%02d'%index]=driver.collect('archive_check',{'file':row['file'],'expected_sha256':row['sha256']})
        except Exception as exc:
            collected['catalog_parse_gap']={'type':type(exc).__name__,'message':str(exc)}
        try:
            capture,audit=driver.guarded_audit()
            collected['audit']={'action_id':capture['action_id'],'summary':{'total':audit['total'],'snapshot':audit['snapshot'],'pages':len(audit['pages'])},'ledger_guards':capture['ledger_guards']}
        except Exception as exc:
            collected['audit_gap']={'type':type(exc).__name__,'message':str(exc)}
        runtime=collected['runtime_contract'].get('document',{})
        configs=[r for r in runtime.get('redis_configs',[]) if r.get('host')=='gitlab-redis' and r.get('port')==6379 and r.get('database') is not None and r.get('authentication_present') is False]
        queue_configs=[r for r in configs if 'queues' in r['path']]
        selected=queue_configs[0] if len(queue_configs)==1 else configs[0] if configs and len({r['database'] for r in configs})==1 else None
        # A diagnostic fallback is explicitly unqualified and never used to
        # permit a write. Runtime collection is the purpose of this attempt.
        redis_db=selected['database'] if selected else 0
        collected['redis_connection_basis']={'selected':selected,'qualified_configuration':selected is not None,'diagnostic_default_db_used':selected is None,'redis_db':redis_db}
        collected['queue_inventory']=driver.collect('queue_inventory',{'redis_db':redis_db})
        try:
            notices=decode_recovery_document(collected['notifications'])
            if not isinstance(notices,list):raise RuntimeError('notification_journal_expected_list')
            ids=sorted({r[k] for r in notices for k in ('job_id','provider_job_id') if isinstance(r.get(k),str) and r[k]})
            collected['history_logs']=driver.collect('history_logs',{'job_ids':ids})
        except Exception as exc:
            collected['history_gap']={'type':type(exc).__name__,'message':str(exc)}
        collection_gaps=[]
        qualification_gaps=[]
        for key in ('runtime_contract','catalog','issues','notifications','database_state','queue_inventory','history_logs'):
            item=collected.get(key)
            if not isinstance(item,dict) or 'document' not in item:
                collection_gaps.append({'material':key,'reason':'capture_or_parse_unavailable'})
        for kind in ('catalog','issues','notifications'):
            try:
                parsed=decode_recovery_document(collected[kind])
                if not isinstance(parsed,list):raise RuntimeError('expected_public_list')
            except Exception as exc:
                collection_gaps.append({'material':kind,'reason':'public_document_incomplete_or_unparseable','error_type':type(exc).__name__})
        if 'audit' not in collected:
            collection_gaps.append({'material':'audit','reason':'complete_guarded_public_audit_unavailable'})
        if 'history_logs' in collected and 'document' in collected['history_logs']:
            if collected['history_logs']['document'].get('source_complete') is not True:
                collection_gaps.append({'material':'history_logs','reason':'empty_rotated_or_changed_log_sources'})
        if catalog_doc is not None:
            for index,row in enumerate(catalog_doc):
                if row.get('status')=='completed' and isinstance(row.get('sha256'),str):
                    if 'document' not in collected.get('archive_%02d'%index,{}):
                        collection_gaps.append({'material':'archive_%02d'%index,'reason':'completed_catalog_entry_check_unavailable'})
        if runtime.get('approved_runtime') is not True:
            qualification_gaps.append({'material':'runtime_contract','reason':'standalone_runtime_sources_not_approved'})
        if selected is None:
            collection_gaps.append({'material':'queue_inventory','reason':'actual_queues_redis_database_not_established','diagnostic_db':redis_db})
        qualification_gaps.append({'material':'historical_smtp','reason':'requires_independent_actual_log_and_source_review'})
        accounting=driver.bridge.accounting()
        (driver.output/'COMMON_ACCOUNTING.json').write_text(canonical(accounting)+'\n')
        (driver.output/'INITIAL_PUBLIC_QUALIFICATION.json').write_text(canonical(collected)+'\n')
        result={'schema':'b0-initial-public-qualification-v1','attempt_id':driver.context['attempt_id'],
            'mode':'native_readonly_qualification','status':'qualification_completed',
            'qualified_read_chain':qualification.get('qualified') is True and qualification.get('actual_native_mcp_qualified') is True,
            'business_operations':0,'submit_calls':0,'business_success':None,
            'historical_smtp_qualification':None,'full_business_actions_qualified':False,
            'collection_complete':not collection_gaps,'collection_gaps':collection_gaps,'qualification_gaps':qualification_gaps,
            'collection_failures':driver.failures,'counts':{'driver_native_calls':driver.calls,
                'driver_public_actions_excluding_common_observer':driver.actions,
                'common_native_transport_requests':accounting['native_transport_requests'],
                'common_registered_actions_including_observer':accounting['reserved_actions'],
                'common_dispatch_permits':accounting['committed_dispatch_permits']},
            'elapsed_seconds':time.monotonic()-driver.started,
            'stopping_reason':'initial_public_evidence_collected_for_independent_review',
            'completed_pre_submission_checks':False,'submission_state':'not_submitted',
            'result_path':'b0-strategy/INITIAL_PUBLIC_QUALIFICATION.json'}
        write_result(result)
        return result
    except BaseException as exc:
        result={'schema':'b0-initial-public-qualification-v1','attempt_id':driver.context['attempt_id'] if driver else None,
            'mode':'native_readonly_qualification','status':'engineering_failure','qualified_read_chain':False,
            'business_operations':0,'submit_calls':0,'collection_complete':False,
            'collection_gaps':[{'material':'initial_qualification','reason':'fatal_driver_failure'}],
            'completed_pre_submission_checks':False,'submission_state':'not_submitted',
            'stopping_reason':'initial_public_qualification_incomplete','error_type':type(exc).__name__,'error':str(exc),'traceback':traceback.format_exc()}
        write_result(result)
        raise
    finally:
        if driver is not None and driver.bridge.registry is not None:
            account_path=driver.output/'COMMON_ACCOUNTING.json'
            if not account_path.exists():
                try:
                    account_path.write_text(canonical(driver.bridge.accounting())+'\n')
                except Exception as error:
                    (driver.output/'ACCOUNTING_ERROR.json').write_text(canonical({'type':type(error).__name__,'message':str(error)})+'\n')

if __name__=='__main__':
    main()
