"""Reference-informed deterministic public B0 controller.

Runtime decisions use public captures and receipts only. This is a policy
client of the same finite common action catalog offered to every future arm;
it has no provider control, private oracle import, hidden periodicity, reference
recovery macro, privileged shortcut, or prior successful incident transcript.
"""
from __future__ import annotations
from collections import defaultdict
from contextlib import closing
import json
import time
import traceback

import catalog
from common_facade import CommonFacade
from common_io import Driver, ObservationUnavailable, canonical, digest, write_result
import proofs
from proofs import EvidenceGap, KnownBusinessFailure, require, notice_key, public_key, normalized_receipt


class StrategyFailure(KnownBusinessFailure):
    pass


def execution_integrity_status(admitted, owned, pending, error):
    if error is not None:
        return 'unqualified'
    return 'verified' if (admitted.get('qualified') is True and
        owned['all_owned_actions_closed'] and pending
        and owned['accepted_original_submission_raw_verified']) else 'unknown'


def batches(rows,field,budget=10000):
    batch=[]
    for row in rows:
        candidate=batch+[row]
        if len(canonical({field:candidate}).encode())>budget:
            require(bool(batch),'one_public_receipt_exceeds_fixed_action_parameter_budget')
            yield batch; batch=[row]
            require(len(canonical({field:batch}).encode())<=budget,
                    'one_public_receipt_exceeds_fixed_action_parameter_budget')
        else:
            batch=candidate
    if batch:yield batch


class Controller:
    def __init__(self):
        self.facade=CommonFacade()
        self.driver=Driver(catalog,trusted_precondition_verifier=self.facade,settle_failed_observers=True)
        self.facade.bind(self.driver.bridge)
        self.bridge=self.driver.bridge
        self.phase='initial_public_qualification';self.submit_calls=0;self.pre_submission_complete=False
        self.selection=None;self.send_attempts=defaultdict(int);self.pruned=0;self.created=0
        self.submission=None;self.public_counts=None
        self.known_missing=[];self.policy_disposition="completed";self.stop_error=None
        self.known_failure_reason=None
        self.admission_error=None
        self.accepted_intent_skips=[]

    def note(self,name,value):
        path=self.driver.output/(name+'.json')
        with path.open('x') as output:
            output.write(canonical(value)+'\n');output.flush()

    def observe(self,name,arguments):
        capture,document=self.driver.run(name,arguments)
        self.facade.ingest(capture)
        return capture,document

    def audit(self):
        capture,document=self.driver.guarded_audit()
        self.facade.ingest(capture)
        if self.facade.notifications:self.facade.latch_acceptances(reject_conflicts=False)
        return capture,document

    def refresh_services(self):
        return self.observe('service_inventory',{})

    def service(self,name,verb):
        arguments={'service':name,'verb':verb}
        if verb=='stop':
            arguments.update(clock_identity=self.driver.context['clock_identity'],
                deadline_monotonic=min(self.driver.started+self.driver.wall_limit,time.monotonic()+120))
        capture,document=self.driver.run('service_control',arguments,settle=False)
        self.bridge.settle_verified(capture['action_id'],capture,verifier=proofs.service_effect)
        self.facade.ingest(capture)
        self.refresh_services()
        return document

    def refresh_queue(self):
        return self.observe('queue_inventory',{'redis_db':self.redis_db})

    def check_issues(self,rows=None,*,wait_for_api=False):
        receipts=[normalized_receipt(row) for row in (self.facade.issues if rows is None else rows)]
        for batch in batches(receipts,'receipts'):
            deadline=min(self.driver.started+self.driver.wall_limit,time.monotonic()+(240 if wait_for_api else 0))
            while True:
                try:
                    _,document=self.observe('issue_inventory',{'receipts':batch})
                    if all(row['classification'] in {'matches','absent','conflict'} for row in document['results']):
                        break
                except ObservationUnavailable:
                    if not wait_for_api:raise
                if not wait_for_api or time.monotonic()>=deadline:
                    raise EvidenceGap('actual_public_API_readiness_not_established')
                # This only schedules a new read. Elapsed time itself never
                # proves request termination, notification absence, or success.
                time.sleep(1)

    def current_authorization(self):
        notices=[normalized_receipt(row,True) for row in self.facade.notifications]
        for batch in batches(notices,'intents'):
            self.observe('identity_authorization',{'intents':batch})
        require(all(value['row'].get('matches') is True for value in self.facade.identities.values()),
                'restored_public_identity_or_current_recipient_authorization_failed')

    def choose_redis(self):
        entry,selected=self.facade.queue_configuration()
        self.redis_db=selected['database']
        self.note('REDIS_PUBLIC_CONFIGURATION',{'actual_configuration':selected,'evidence_handle':entry['handle']})

    def select_archive(self):
        # Deterministic public catalog order, never the reference filename.
        for row in self.facade.catalog_rows:
            if row.get('status')!='completed' or not isinstance(row.get('sha256'),str):continue
            args={'file':row['file'],'expected_sha256':row['sha256']}
            _,document=self.observe('archive_check',args)
            if document.get('valid') is True:
                self.selection=args
                self.note('PUBLIC_ARCHIVE_SELECTION',{'policy':'first_actual_valid_completed_public_catalog_entry',
                    'selected':args,'public_catalog_handle':self.facade.documents['catalog']['handle']})
                return
        raise StrategyFailure('no_public_completed_archive_passed_actual_digest_and_pg_restore_listing')

    def restore(self):
        self.phase='stop_writers_and_database_backend_barrier'
        self.refresh_services()
        self.service('sidekiq','stop')
        self.service('puma','stop')
        deadline=min(self.driver.started+self.driver.wall_limit,time.monotonic()+180)
        while True:
            _,database=self.observe('database_state',{'action_tag':'before_restore'})
            if not database.get('sessions'):break
            if time.monotonic()>=deadline:raise EvidenceGap('actual_database_backends_remain_after_writer_stop')
            time.sleep(1)
        self.phase='restore_database'
        args={**self.selection,'action_tag':'restore_'+digest(self.driver.context['attempt_id'])[:24]}
        capture,document=self.driver.run('archive_restore',args,settle=False)
        settled=self.bridge.settle_verified(capture['action_id'],capture,verifier=proofs.restore_effect)
        self.facade.ingest(capture)
        if settled['effect']!='settled_applied' or not self.bridge.state()['database_valid']:
            raise StrategyFailure('selected_archive_restore_settled_partial_or_invalid')
        self.observe('database_state',{'action_tag':'after_restore'})

    def replay(self):
        self.phase='public_issue_replay'
        self.service('puma','start')
        self.check_issues(wait_for_api=True)
        for receipt in sorted(self.facade.issues,key=public_key):
            key=public_key(receipt); classification=self.facade.issue_status[key]['row']['classification']
            if classification=='matches':continue
            if classification!='absent':raise StrategyFailure('public_issue_identity_conflict_before_replay')
            correlation=digest({'attempt':self.driver.context['attempt_id'],'public_issue':list(key)})[:32]
            args={'receipt':normalized_receipt(receipt),'correlation_id':correlation}
            capture,document=self.driver.run('issue_replay',args,settle=False,intent_ref=self.facade.issue_refs[key])
            completion=None
            if document.get('dispatched_post'):
                original_action=self.bridge.registry.poll(self.bridge.attempt_id,capture['action_id'])
                server_request_id=proofs.issue_response_request_id(original_action,capture)
                self.note('HTTP_REQUEST_ID_BINDING_'+capture['action_id'],{
                    'original_action_id':capture['action_id'],'original_capture_sha256':digest(capture['stdout']),
                    'client_requested_correlation_id':correlation,'actual_POST_response_request_id':server_request_id,
                    'lookup_basis':'complete_original_POST_response_header_not_assumed_client_echo'})
                deadline=min(self.driver.started+self.driver.wall_limit,time.monotonic()+30)
                while True:
                    _,completion=self.observe('http_completion',{'request_id':server_request_id})
                    if completion.get('records'):break
                    if time.monotonic()>=deadline:raise EvidenceGap('actual_API_request_completion_log_unavailable')
                    time.sleep(0.5)
            settled=self.bridge.settle_verified(capture['action_id'],capture,
                verifier=lambda action,cap,bridge:proofs.issue_effect(action,cap,completion))
            self.facade.ingest(capture)
            if settled['effect']!='settled_applied':raise StrategyFailure('public_issue_replay_settled_conflict')
            self.created+=int(document.get('dispatched_post') is True)
            self.check_issues([receipt])
        # Complete public content reads happen while the normal API is running.
        # Subsequent fixed helpers do not mutate issue content or authorization.
        self.check_issues()
        self.service('puma','stop')
        self.phase='current_authorization_and_normal_background_contract'
        self.current_authorization()
        _,background=self.observe('background_contract',{})
        require(background.get('qualified') is True,'actual_normal_background_notification_reason_contract_unqualified')
        self.choose_redis()
        self.phase='historical_related_SMTP_diagnostic'
        self.refresh_queue()
        ids=sorted({row[key] for row in self.facade.notifications for key in ('job_id','provider_job_id')
                    if isinstance(row.get(key),str) and row[key]})
        try:
            self.observe('history_logs',{'job_ids':ids})
            historical=self.facade.qualify_history()
        except Exception as error:
            historical=self.facade.history_diagnostic_failed(error)
        self.note('HISTORICAL_SMTP_DIAGNOSTIC',historical)
        # Optional proof insufficiency does not authorize any action. A real
        # unresolved observer/transport still blocks subsequent conflicting work.
        require(self.facade.owned_execution_state()['all_owned_actions_closed'],
                'historical_diagnostic_left_owned_execution_unresolved')

    def prune(self):
        self.phase='precise_public_job_prune'
        while True:
            _,queue=self.refresh_queue();self.audit()
            snapshot=proofs.queue_document(queue); groups={}
            identities=[value['row'] for value in self.facade.identities.values()]
            for row in snapshot['jobs']:
                if not proofs.is_possible_incident_job(row['item'],self.facade.notifications,identities):continue
                receipt=proofs.old_job_receipt(row['item'],self.facade.notifications)
                key=(row['key'],row['jid'],row['raw_sha256'],row['score'])
                if key not in groups:
                    groups[key]={'key':row['key'],'jid':row['jid'],'raw_sha256':row['raw_sha256'],
                        'score':row['score'],'expected_occurrences':0,'delete_count':0,
                        'public_intent_key':{name:receipt[name] for name in ('project','iid','recipient')}}
                groups[key]['expected_occurrences']+=1;groups[key]['delete_count']+=1
            if not groups:
                self.facade._no_incident_jobs(snapshot)
                return
            selections=[]
            for row in groups.values():
                candidate={'redis_db':self.redis_db,'redis_run_id':queue['redis_run_id'],
                           'before_token':snapshot['inventory_token'],'selected':selections+[row]}
                if selections and (len(selections)>=128 or len(canonical(candidate).encode())>10000):break
                selections.append(row)
            args={'redis_db':self.redis_db,'redis_run_id':queue['redis_run_id'],
                  'before_token':snapshot['inventory_token'],'selected':selections}
            capture,_=self.driver.run('queue_prune',args,settle=False)
            settled=self.bridge.settle_verified(capture['action_id'],capture,verifier=proofs.prune_effect)
            self.facade.ingest(capture)
            if settled['effect']!='settled_applied':raise StrategyFailure('precise_prune_did_not_apply_as_selected')
            self.pruned+=sum(row['delete_count'] for row in selections)

    def send(self):
        self.phase='real_application_notification_snapshot_reconciliation'
        maximum=int(self.driver.context.get('budgets',{}).get('max_send_attempts_per_intent',8))
        require(1<=maximum<=8,'uniform_send_attempt_budget_not_qualified')
        for receipt in sorted(self.facade.notifications,key=notice_key):
            key=notice_key(receipt)
            skip=self.facade.accepted_intent_skip(receipt)
            if skip is not None:
                self.accepted_intent_skips.append(skip)
                self.note('ACCEPTED_INTENT_SKIP_'+digest(list(key))[:32],skip)
                continue
            for attempt in range(maximum):
                # Every admission uses a fresh complete audit, including after
                # a different intent's action or a prior failed attempt.
                self.refresh_queue();self.audit()
                report=self.facade.latch_acceptances();state=report['by_intent'][key]['state']
                if state=='accepted':break
                if state!='missing':raise StrategyFailure('notification_public_delivery_conflict')
                self.facade._fresh(self.facade.audit,('database','queue','services'))
                capture,_=self.driver.run('notification_send',{'intent':normalized_receipt(receipt,True)},
                    settle=False,intent_ref=self.facade.notice_refs[key])
                self.send_attempts[key]+=1
                self.bridge.notification_terminal_verified(capture['action_id'],capture,verifier=proofs.smtp_terminal)
                ticket=self.bridge.begin_notification_audit(capture['action_id'])
                before=self.bridge.notification_audits[ticket]['before_guard']
                audit_capture,_=self.driver.run('public_audit',{})
                settled=self.bridge.finish_notification_snapshot(capture['action_id'],ticket,audit_capture,
                    verifier=self.facade.notification_snapshot_proof)
                after=self.bridge.guard.receipts[-1]
                require(after['reason']=='public_audit_after','snapshot_audit_after_guard_binding_missing')
                audit_capture['ledger_guards']={'before':before,'after':after}
                self.facade.ingest(audit_capture)
                self.facade.latch_acceptances(reject_conflicts=False)
                self.facade.ingest(capture)
                require(settled['effect']=='snapshot_closed','notification_snapshot_not_atomically_closed')
                snapshot=settled.get('notification_snapshot')
                require(isinstance(snapshot,dict) and snapshot.get('protocol_id')=='public_result_v1'
                        and snapshot.get('owned_action_terminal') is True
                        and snapshot.get('causal_attribution_to_this_action')=='unknown',
                        'notification_scoped_snapshot_record_missing')
                state=snapshot['intent_snapshot_state']
                if state=='accepted':break
                if state!='missing':raise StrategyFailure('notification_snapshot_delivery_conflict')
                # This is only a new post-terminal snapshot with no acceptance.
                # Historical requests may still be unqualified; no global
                # absence or current-action causal attribution is claimed.
            else:
                self.known_missing.append(list(key))

    def evaluate_original_once(self):
        self.phase='single_original_evaluation'
        snapshot=self.facade.public_business_snapshot()
        self.submission=self.bridge.submit_final_once(
            solution='Public-result B0-P ended its fixed public recovery policy. '
                     'Observed public business snapshot: '+snapshot['status']+'. '
                     'Only the original host evaluator determines native task success. '
                     'Historical SMTP proof is an independent diagnostic and is not claimed complete. '
                     'Policy disposition: '+self.policy_disposition+'.',
            precondition_verifier=self.facade.final_preconditions)
        self.pre_submission_complete=bool(self.facade.final_admission and
            self.facade.final_admission.get('execution_ready_for_original_evaluation') is True)
        self.submit_calls=int(self.submission.get('final_submit_requested') is True)
        self.note('SINGLE_ORIGINAL_SUBMISSION',self.submission)
        if (self.submission.get('submission_state')=='accepted_for_evaluation'
                and self.submission.get('state')=='accepted_pending_evaluation'):
            return 'awaiting_original_host_evaluation','one_original_evaluation_accepted_result_owned_by_original_host'
        self.policy_disposition='abstained_from_submission'
        return 'unknown','original_submission_transport_or_acceptance_unknown_no_resubmission'

    def finish(self):
        self.phase='normal_background_and_public_final_checks'
        self.refresh_queue();self.audit()
        ready=self.facade.mark_ready_for_normal_services();self.note('RECONCILIATION_BEFORE_NORMAL_SERVICES',ready)
        self.service('puma','start');self.service('sidekiq','start')
        self.check_issues(wait_for_api=True)
        self.refresh_queue();self.audit()
        snapshot=self.facade.public_business_snapshot()
        self.note('PUBLIC_BUSINESS_SNAPSHOT_BEFORE_SUBMIT',snapshot)
        if snapshot['status']=='known_fail':self.policy_disposition='stopped_known_failure'
        elif snapshot['status']=='incomplete':self.policy_disposition='abstained_from_mutation'
        return self.evaluate_original_once()

    def evaluate_after_policy_stop(self,error,*,known_business_failure=False):
        self.stop_error=None if known_business_failure else error
        if known_business_failure:
            self.known_failure_reason={'type':error['type'],'message':error['message'],
                                       'scope':'explicit_observed_business_failure'}
        snapshot=self.facade.public_business_snapshot()
        self.policy_disposition='stopped_known_failure' if known_business_failure else 'abstained_from_mutation'
        # No repair, resumed action or new business mutation is attempted here.
        # Admission independently rejects every unresolved read/write or lock.
        self.note('POLICY_STOP_BEFORE_ORIGINAL_EVALUATION',{'policy_stop_reason':error,
            'known_business_failure':known_business_failure,'public_snapshot':snapshot})
        return self.evaluate_original_once()

    def run(self):
        require(self.driver.context.get('mode')=='public_b0'
                and self.driver.context.get('protocol_id')=='public_result_v1',
                'B0_P_requires_explicit_public_result_launch_profile')
        policy_raw=(catalog.HERE/'RUN_POLICY.json').read_bytes()
        self.note('PREWRITE_POLICY_DECLARATION',{'policy_sha256':digest(policy_raw),
            'policy':json.loads(policy_raw),'actual_launcher_budgets':self.driver.context.get('budgets',{})})
        qualification=self.driver.initialize()
        require(qualification.get('actual_native_mcp_qualified') is True,'actual_common_native_chain_not_qualified')
        for operation in ('app_info','status','describe_tools'):
            self.note('NATIVE_'+operation.upper(),self.bridge.read_native_api(operation))
        _,runtime=self.observe('runtime_contract',{})
        for kind in ('catalog','issues','notifications'):self.observe('recovery_files',{'kind':kind})
        self.public_counts=self.facade.declare_public_intents();self.note('PUBLIC_INTENT_DECLARATIONS',self.public_counts)
        require(runtime.get('approved_runtime') is True,'standalone_actual_source_contract_unqualified')
        self.select_archive();self.audit()
        self.restore();self.replay();self.prune();self.send()
        return self.finish()

    def result(self,status,reason,error=None):
        accounting=self.bridge.accounting() if self.bridge.registry is not None else {}
        if accounting:self.note('COMMON_ACCOUNTING',accounting)
        admitted=self.facade.final_admission or {}
        snapshot=self.facade.final_snapshot or self.facade.public_business_snapshot()
        accepted=self.submission if (self.submission and
            self.submission.get('state')=='accepted_pending_evaluation') else None
        owned=self.facade.owned_execution_state(accepted_submission=accepted)
        snapshots=accounting.get('notification_snapshot_records',[])
        historical=self.facade.historical_assurance()
        history_detail=self.facade.history or {}
        unknown_intents=[]
        if historical['status']!='qualified':
            for receipt in self.facade.notifications:
                unknown_intents.append({'intent':list(notice_key(receipt)),
                    'public_job_ids':[receipt[key] for key in ('job_id','provider_job_id') if receipt.get(key)],
                    'status':historical['status'],'scope':'historical_third_party_requests_not_proven_terminal'})
        pending=bool(self.submission and self.submission.get('state')=='accepted_pending_evaluation')
        integrity_status=execution_integrity_status(admitted,owned,pending,error or self.stop_error)
        public_pass=True if snapshot['status']=='pass' else False if snapshot['status']=='known_fail' else None
        return {'schema':'b0-public-result-controller-v1','protocol_id':'public_result_v1',
            'attempt_id':self.driver.context['attempt_id'],'mode':'public_b0','status':status,
            'phase':self.phase,'stopping_reason':reason,'policy_disposition':self.policy_disposition,
            'completed_pre_submission_checks':admitted.get('execution_ready_for_original_evaluation') is True,
            'execution_ready_for_original_evaluation':admitted.get('execution_ready_for_original_evaluation') is True,
            'evaluation_readiness':self.facade.final_admission,
            'submit_calls':self.submit_calls,'public_checks_complete':not snapshot['incomplete_reasons'],
            'public_checks_passed':public_pass,'public_business_snapshot':snapshot,
            'execution_integrity':{'status':integrity_status,
                'scope':'controller_pre_submission_execution_checks_independent_artifact_review_pending',
                'native_chain_qualified':self.bridge.qualification.get('actual_native_mcp_qualified') is True,
                'execution_ready_for_original_evaluation':admitted.get('execution_ready_for_original_evaluation') is True,
                'owned_unresolved_action_ids_before_submit':admitted.get('owned_execution_before_submit',{}).get('owned_unresolved_action_ids'),
                'owned_unresolved_action_ids_at_exit':owned['owned_unresolved_action_ids'],
                'resource_locks_at_exit_excluding_original_evaluation':owned['resource_locks'],
                'original_submission_actions':owned['final_submission_actions'],
                'pending_original_evaluation':pending,'source_and_target_bindings':admitted or None,
                'accepted_original_submission_raw_verified':owned['accepted_original_submission_raw_verified'],
                'accepted_original_submission_binding_error':owned['accepted_original_submission_binding_error'],
                'artifact_complete':None,'protocol_conformance':None,'independent_review_pending':True},
            'additional_assurance':{'historical_terminal_required':False,
                'historical_terminal_status':historical['status'],'historical_terminal_proof':historical,
                'historical_unknown_intents':unknown_intents,'historical_diagnostic_error':self.facade.history_error,
                'historical_diagnostic_proof':history_detail.get('proof'),
                'all_historical_effects_settled_claimed':False,
                'owned_action_terminal_and_snapshot_records':snapshots,
                'causal_attribution_policy':'unknown_not_inferred_from_same_intent_acceptance'},
            'original_evaluation':{'status':'accepted_pending_evaluation' if pending else 'not_requested' if not self.submit_calls else 'incomplete',
                'request_count':self.submit_calls,'raw_mitigation_success':None,'host_resolution_required':bool(self.submit_calls)},
            'known_missing_after_retry_budget':self.known_missing,
            'known_failure_reason':self.known_failure_reason,
            'submission_state':self.submission.get('submission_state','unknown') if self.submission else 'not_submitted',
            'submission_receipt':self.submission,'business_success':None,'original_oracle_success':None,
            'host_original_evaluation_required':self.submit_calls==1,'public_intent_counts':self.public_counts,
            'archive_selected':self.selection,'created_public_issues':self.created,'pruned_exact_job_occurrences':self.pruned,
            'already_accepted_intent_skip_count':len(self.accepted_intent_skips),
            'already_accepted_intent_skips':self.accepted_intent_skips,
            'notification_attempts':[{'intent':list(key),'count':value} for key,value in sorted(self.send_attempts.items())],
            'counts':{'driver_native_calls':self.driver.calls,'driver_public_actions':self.driver.actions,
                'common_native_transport_requests':accounting.get('native_transport_requests'),
                'common_registered_actions':accounting.get('reserved_actions'),
                'common_dispatch_permits':accounting.get('committed_dispatch_permits')},
            'elapsed_seconds':time.monotonic()-self.driver.started,
            'driver_initialized_mono':self.driver.initialized,'incident_visible_mono':self.driver.started,
            'driver_elapsed_seconds':time.monotonic()-self.driver.initialized,'error':error or self.stop_error,
            'final_admission_error':self.admission_error,
            'claim_boundary':'original_host_business_result_execution_integrity_and_historical_assurance_are_distinct'}


def main():
    controller=None
    try:
        controller=Controller();status,reason=controller.run()
        result=controller.result(status,reason)
    except BaseException as exc:
        error={'type':type(exc).__name__,'message':str(exc),'traceback':traceback.format_exc()}
        status='strategy_failure' if isinstance(exc,KnownBusinessFailure) else 'engineering_failure'
        reason='stopped_without_new_business_dispatch'
        if controller is not None and controller.bridge.registry is not None:
            try:
                owned=controller.facade.owned_execution_state()
                if owned['owned_unresolved_action_ids'] or owned['resource_locks']:
                    status='unknown';controller.policy_disposition='abstained_from_submission'
                    error['unresolved_original_actions']=owned['owned_unresolved_action_ids']
                elif (controller.phase!='single_original_evaluation' and not owned['final_submission_actions']
                      and controller.bridge.qualification.get('actual_native_mcp_qualified') is True):
                    known_business_failure=isinstance(exc,KnownBusinessFailure)
                    status,reason=controller.evaluate_after_policy_stop(error,
                        known_business_failure=known_business_failure)
                    if known_business_failure:error=None
                else:
                    controller.policy_disposition='abstained_from_submission'
            except BaseException as admission_error:
                controller.admission_error={'type':type(admission_error).__name__,'message':str(admission_error)}
                controller.policy_disposition='abstained_from_submission'
            result=controller.result(status,reason,error)
        else:
            result={'schema':'b0-public-result-controller-v1','protocol_id':'public_result_v1',
                    'mode':'public_b0','status':'engineering_failure','policy_disposition':'execution_failure',
                    'completed_pre_submission_checks':False,'execution_ready_for_original_evaluation':False,
                    'evaluation_readiness':None,
                    'submit_calls':0,'submission_state':'not_submitted','business_success':None,
                    'stopping_reason':'controller_bootstrap_incomplete','error':error,
                    'original_evaluation':{'status':'not_requested','request_count':0,'raw_mitigation_success':None},
                    'execution_integrity':{'status':'failed','execution_ready_for_original_evaluation':False,
                        'owned_unresolved_action_ids_before_submit':None,'owned_unresolved_action_ids_at_exit':None},
                    'public_business_snapshot':{'status':'incomplete'},
                    'additional_assurance':{'historical_terminal_required':False,'historical_terminal_status':'not_evaluated',
                        'all_historical_effects_settled_claimed':False}}
    write_result(result)
    return result


if __name__=='__main__':
    main()
