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
from proofs import EvidenceGap, require, notice_key, public_key, normalized_receipt


class StrategyFailure(RuntimeError):
    pass


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
        self.known_missing=[]

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
        if self.facade.notifications:self.facade.latch_acceptances()
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
                deadline=min(self.driver.started+self.driver.wall_limit,time.monotonic()+30)
                while True:
                    _,completion=self.observe('http_completion',{'request_id':correlation})
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
        self.phase='historical_related_SMTP_qualification'
        self.refresh_queue()
        ids=sorted({row[key] for row in self.facade.notifications for key in ('job_id','provider_job_id')
                    if isinstance(row.get(key),str) and row[key]})
        self.observe('history_logs',{'job_ids':ids})
        historical=self.facade.qualify_history();self.note('HISTORICAL_SMTP_QUALIFICATION',historical)
        require(historical['proof']['qualified'] is True,'historical_SMTP_qualification_has_explicit_gaps')

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
        self.phase='real_application_notification_reconciliation'
        maximum=int(self.driver.context.get('budgets',{}).get('max_send_attempts_per_intent',8))
        require(1<=maximum<=8,'uniform_send_attempt_budget_not_qualified')
        for receipt in sorted(self.facade.notifications,key=notice_key):
            key=notice_key(receipt)
            for attempt in range(maximum):
                report=self.facade.audit_report(); state=report['by_intent'][key]['state']
                if state=='accepted':break
                if state!='missing':raise StrategyFailure('notification_public_delivery_conflict')
                # A preceding send invalidates the queue generation. The full
                # queue is recaptured even though this fixed sender is direct.
                self.refresh_queue()
                self.facade._fresh(self.facade.audit,('database','queue','services'))
                capture,_=self.driver.run('notification_send',{'intent':normalized_receipt(receipt,True)},
                    settle=False,intent_ref=self.facade.notice_refs[key])
                self.send_attempts[key]+=1
                self.bridge.notification_terminal_verified(capture['action_id'],capture,verifier=proofs.smtp_terminal)
                ticket=self.bridge.begin_notification_audit(capture['action_id'])
                before=self.bridge.notification_audits[ticket]['before_guard']
                audit_capture,_=self.driver.run('public_audit',{})
                settled=self.bridge.finish_notification_audit(capture['action_id'],ticket,audit_capture,
                    verifier=self.facade.notification_audit_proof)
                after=self.bridge.guard.receipts[-1]
                require(after['reason']=='public_audit_after','causal_audit_after_guard_binding_missing')
                audit_capture['ledger_guards']={'before':before,'after':after}
                self.facade.ingest(audit_capture);self.facade.latch_acceptances()
                self.facade.ingest(capture)
                if settled['effect']=='settled_applied':break
                if settled['effect']!='settled_not_applied':raise StrategyFailure('notification_settled_delivery_conflict')
                # Only this proven no-recipient-visible-effect branch permits a
                # fresh ID. Ordinary SentNotification application records may
                # already exist and are not erased or called nonexistent.
            else:
                self.known_missing.append(list(key))

    def finish(self):
        self.phase='normal_background_and_public_final_checks'
        self.refresh_queue();self.audit()
        ready=self.facade.mark_ready_for_normal_services();self.note('RECONCILIATION_BEFORE_NORMAL_SERVICES',ready)
        self.service('puma','start');self.service('sidekiq','start')
        self.check_issues(wait_for_api=True)
        self.audit()
        self.facade.final_preconditions(self.bridge)
        self.pre_submission_complete=True;self.phase='single_original_evaluation'
        self.submission=self.bridge.submit_final_once(
            solution='Deterministic public B0 completed registered archive recovery, exact public-IID issue replay, '
                     'authorized queue reconciliation and recipient-visible notification checks; normal GitLab services restored. '
                     'Public check outcome: '+ready['policy_outcome']+'.',
            precondition_verifier=self.facade.final_preconditions)
        self.submit_calls=int(self.submission.get('final_submit_requested') is True)
        self.note('SINGLE_ORIGINAL_SUBMISSION',self.submission)
        if (self.submission.get('submission_state')=='accepted_for_evaluation'
                and self.submission.get('state')=='accepted_pending_evaluation'):
            return 'awaiting_original_host_evaluation','one_original_evaluation_accepted_result_owned_by_original_host'
        return 'unknown','original_submission_transport_or_acceptance_unknown_no_resubmission'

    def run(self):
        require(self.driver.context.get('mode')=='public_b0','complete_B0_requires_explicit_public_b0_launch_mode')
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
        return {'schema':'b0-deterministic-public-controller-v1','attempt_id':self.driver.context['attempt_id'],
            'mode':'public_b0','status':status,'phase':self.phase,'stopping_reason':reason,
            'completed_pre_submission_checks':self.pre_submission_complete,'submit_calls':self.submit_calls,
            'public_checks_complete':self.pre_submission_complete,
            'public_checks_passed':self.facade.ready['public_checks_passed'] if self.facade.ready else None,
            'policy_outcome':self.facade.ready['policy_outcome'] if self.facade.ready else None,
            'known_missing_after_retry_budget':self.known_missing,
            'submission_state':self.submission.get('submission_state','unknown') if self.submission else 'not_submitted',
            'submission_receipt':self.submission,'business_success':None,'original_oracle_success':None,
            'host_original_evaluation_required':self.submit_calls==1,'public_intent_counts':self.public_counts,
            'archive_selected':self.selection,'created_public_issues':self.created,'pruned_exact_job_occurrences':self.pruned,
            'notification_attempts':[{'intent':list(key),'count':value} for key,value in sorted(self.send_attempts.items())],
            'counts':{'driver_native_calls':self.driver.calls,'driver_public_actions':self.driver.actions,
                'common_native_transport_requests':accounting.get('native_transport_requests'),
                'common_registered_actions':accounting.get('reserved_actions'),
                'common_dispatch_permits':accounting.get('committed_dispatch_permits')},
            'elapsed_seconds':time.monotonic()-self.driver.started,
            'driver_initialized_mono':self.driver.initialized,
            'incident_visible_mono':self.driver.started,
            'driver_elapsed_seconds':time.monotonic()-self.driver.initialized,'error':error,
            'claim_boundary':'agent_public_checks_are_not_original_oracle_success'}


def main():
    controller=None
    try:
        controller=Controller();status,reason=controller.run()
        result=controller.result(status,reason)
    except BaseException as exc:
        error={'type':type(exc).__name__,'message':str(exc),'traceback':traceback.format_exc()}
        status='strategy_failure' if isinstance(exc,StrategyFailure) else 'engineering_failure'
        if controller is not None:
            if controller.bridge.registry is not None:
                with closing(controller.bridge.registry._connect(readonly=True)) as db:
                    unresolved=db.execute("SELECT id FROM actions WHERE attempt=? AND operation<>'observe' "
                        "AND dispatch_epoch IS NOT NULL AND effect NOT IN ('settled_applied','settled_not_applied','partial_or_conflict')",
                        (controller.bridge.attempt_id,)).fetchall()
                if unresolved:status='unknown';error['unresolved_original_actions']=[row['id'] for row in unresolved]
            result=controller.result(status,'stopped_without_new_business_dispatch',error)
        else:
            result={'schema':'b0-deterministic-public-controller-v1','mode':'public_b0','status':'engineering_failure',
                    'completed_pre_submission_checks':False,'submit_calls':0,'submission_state':'not_submitted',
                    'stopping_reason':'controller_bootstrap_incomplete','error':error,'business_success':None}
    write_result(result)
    return result


if __name__=='__main__':
    main()
