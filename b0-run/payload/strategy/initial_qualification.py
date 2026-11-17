"""Second public read-only collection with full-history transfer prioritized.

All callable programs in catalog_readonly_v4 are observe-only. This entry never
stops a service, restores a DB, changes a queue, sends mail, or submits an oracle.
"""
from __future__ import annotations
import json
import time
import traceback
import catalog_readonly_v4 as catalog
from common_io import Driver,canonical,decode_recovery_document,write_result


def diagnostic_redis(runtime):
    rows=runtime.get('redis_configs',[])
    candidates=[row for row in rows if row.get('selected_by_fixed_main_queue_precedence') is True]
    selected=candidates[0] if len(candidates)==1 else None
    usable=(selected is not None and selected.get('unchanged_during_read') is True
        and selected.get('rails_link_matches') is True and selected.get('host')=='gitlab-redis'
        and selected.get('port')==6379 and type(selected.get('database'))is int
        and 0<=selected['database']<=15 and selected.get('database_explicit') is True
        and all(selected.get(key) is False for key in ('authentication_present','tls_present',
            'cluster_present','sentinels_present','config_command_present','secret_file_configured'))
        and not any(row.get('error_type') or row.get('queue_shards_present') is True for row in rows))
    return {'selected_public_file':selected,'public_file_diagnostic_usable':usable,
        'qualified_configuration':False,'actual_Rails_params_observed':False,
        'diagnostic_default_db_used':not usable,'redis_db':selected['database'] if usable else 0,
        'scope':'diagnostic_queue_capture_only_no_business_permission'}


def main():
    driver=None
    try:
        driver=Driver(catalog,settle_failed_observers=True)
        if driver.context.get('mode')!='native_readonly_qualification' or driver.context.get('allowed_operations')!=['observe']:
            raise RuntimeError('read_only_launch_mode_not_explicit')
        qualification=driver.initialize();collected={}
        for operation in ('app_info','status','describe_tools'):
            collected['native_'+operation]=driver.bridge.read_native_api(operation)
        collected['runtime_contract']=driver.collect('runtime_contract',{})
        for kind in ('catalog','issues','notifications'):
            collected[kind]=driver.collect('recovery_files',{'kind':kind})
        collected['database_state']=driver.collect('database_state',{'action_tag':'initial_qualification_v2'})
        catalog_rows=None
        try:
            catalog_rows=decode_recovery_document(collected['catalog'])
            if not isinstance(catalog_rows,list) or len(catalog_rows)>32:
                raise RuntimeError('public_catalog_list_bound')
            for index,row in enumerate(catalog_rows):
                if row.get('status')=='completed' and isinstance(row.get('sha256'),str):
                    collected['archive_%02d'%index]=driver.collect('archive_check',
                        {'file':row['file'],'expected_sha256':row['sha256']})
        except Exception as error:
            collected['catalog_parse_gap']={'type':type(error).__name__,'message':str(error)}

        # Obtain the complete original historical log capture before the larger
        # audit and queue diagnostics. No terminal claim is made by collection.
        try:
            notices=decode_recovery_document(collected['notifications'])
            if not isinstance(notices,list):raise RuntimeError('public_notification_journal_not_list')
            ids=sorted({row[key] for row in notices for key in ('job_id','provider_job_id')
                if isinstance(row.get(key),str) and row[key]})
            collected['history_logs']=driver.collect('history_logs',{'job_ids':ids})
        except Exception as error:
            collected['history_gap']={'type':type(error).__name__,'message':str(error)}
        (driver.output/'INITIAL_PUBLIC_QUALIFICATION_PROGRESS.json').write_text(canonical(collected)+'\n')

        try:
            capture,audit=driver.guarded_audit()
            collected['audit']={'action_id':capture['action_id'],
                'summary':{'total':audit['total'],'snapshot':audit['snapshot'],'pages':len(audit['pages'])},
                'ledger_guards':capture['ledger_guards']}
        except Exception as error:
            collected['audit_gap']={'type':type(error).__name__,'message':str(error)}
        runtime=collected['runtime_contract'].get('document',{})
        connection=diagnostic_redis(runtime)
        collected['redis_connection_basis']=connection
        collected['queue_inventory']=driver.collect('queue_inventory',{'redis_db':connection['redis_db']})

        gaps=[];qualification_gaps=[]
        for key in ('runtime_contract','catalog','issues','notifications','database_state','history_logs','queue_inventory'):
            item=collected.get(key)
            if not isinstance(item,dict) or 'document' not in item:
                gaps.append({'material':key,'reason':'capture_or_parse_unavailable'})
        for key in ('catalog','issues','notifications'):
            try:
                if not isinstance(decode_recovery_document(collected[key]),list):
                    raise RuntimeError('public_document_expected_list')
            except Exception as error:
                gaps.append({'material':key,'reason':'original_public_document_not_complete','error_type':type(error).__name__})
        if 'audit' not in collected:
            gaps.append({'material':'audit','reason':'complete_guarded_public_audit_unavailable'})
        history=collected.get('history_logs',{}).get('document',{})
        if history and history.get('source_complete') is not True:
            gaps.append({'material':'history_logs','reason':'empty_rotated_or_changed_original_logs'})
        if catalog_rows is not None:
            for index,row in enumerate(catalog_rows):
                if row.get('status')=='completed' and isinstance(row.get('sha256'),str):
                    if 'document' not in collected.get('archive_%02d'%index,{}):
                        gaps.append({'material':'archive_%02d'%index,'reason':'original_completed_archive_check_unavailable'})
        if runtime.get('approved_runtime') is not True:
            qualification_gaps.append({'material':'runtime_contract','reason':'standalone_runtime_sources_not_approved'})
        qualification_gaps.extend([
            {'material':'actual_queue_configuration','reason':'actual_Rails_params_not_collected_in_readonly_mode',
             'diagnostic_db':connection['redis_db'],'diagnostic_default_db_used':connection['diagnostic_default_db_used']},
            {'material':'historical_SMTP','reason':'complete_capture_still_requires_independent_terminal_and_coverage_review'}])
        accounting=driver.bridge.accounting()
        (driver.output/'COMMON_ACCOUNTING.json').write_text(canonical(accounting)+'\n')
        (driver.output/'INITIAL_PUBLIC_QUALIFICATION.json').write_text(canonical(collected)+'\n')
        result={'schema':'b0-initial-public-qualification-v2','attempt_id':driver.context['attempt_id'],
            'mode':'native_readonly_qualification','status':'qualification_completed',
            'qualified_read_chain':qualification.get('actual_native_mcp_qualified') is True,
            'business_operations':0,'submit_calls':0,'business_success':None,
            'completed_pre_submission_checks':False,'submission_state':'not_submitted',
            'full_business_actions_qualified':False,'historical_smtp_qualification':None,
            'actual_queue_configuration_qualified':False,
            'queue_inventory_scope':'explicit_public_configuration_diagnostic_or_labelled_diagnostic_default',
            'collection_complete':not gaps,'collection_gaps':gaps,'qualification_gaps':qualification_gaps,
            'collection_failures':driver.failures,
            'complete_original_history_collected':history.get('source_complete') is True,
            'counts':{'driver_native_calls':driver.calls,'driver_public_actions_excluding_common_observer':driver.actions,
                'common_native_transport_requests':accounting['native_transport_requests'],
                'common_registered_actions_including_observer':accounting['reserved_actions'],
                'common_dispatch_permits':accounting['committed_dispatch_permits']},
            'elapsed_seconds':time.monotonic()-driver.started,'incident_visible_mono':driver.started,
            'driver_initialized_mono':driver.initialized,
            'stopping_reason':'public_readonly_material_collection_finished_for_independent_review',
            'result_path':'b0-strategy/INITIAL_PUBLIC_QUALIFICATION.json'}
        write_result(result);return result
    except BaseException as error:
        result={'schema':'b0-initial-public-qualification-v2',
            'attempt_id':driver.context['attempt_id'] if driver else None,
            'mode':'native_readonly_qualification','status':'engineering_failure','qualified_read_chain':False,
            'business_operations':0,'submit_calls':0,'business_success':None,
            'collection_complete':False,'collection_gaps':[{'material':'initial_qualification','reason':'fatal_driver_failure'}],
            'completed_pre_submission_checks':False,'submission_state':'not_submitted',
            'stopping_reason':'initial_public_qualification_incomplete','error_type':type(error).__name__,
            'error':str(error),'traceback':traceback.format_exc()}
        write_result(result);raise
    finally:
        if driver is not None and driver.bridge.registry is not None:
            path=driver.output/'COMMON_ACCOUNTING.json'
            if not path.exists():
                try:path.write_text(canonical(driver.bridge.accounting())+'\n')
                except Exception as error:
                    (driver.output/'ACCOUNTING_ERROR.json').write_text(canonical({'type':type(error).__name__,'message':str(error)})+'\n')


if __name__=='__main__':
    main()
