"""Trusted common public-action boundary, independent of B0 planning choices.

Deploy this callable with the bridge. Models may choose finite catalog arguments
and opaque evidence handles; they never receive this object's mutable internals,
the registry adapter, callbacks, or an ability to manufacture a proof. Both
reservation and actual dispatch recheck the same public evidence conditions.
"""
from __future__ import annotations

from contextlib import closing
import base64
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import time

import catalog
import history_qualification
import proofs
from common_io import canonical, digest, parse_capture
from proofs import (EvidenceGap, require, notice_key, public_key, normalized_receipt,
                    audit_document, classify_audit, queue_document, old_job_receipt,
                    is_possible_incident_job, services_document, writer_barrier)


class CommonFacade:
    def __init__(self):
        self.bridge=None; self.records={}; self.latest={}; self.documents={}
        self.issues=[]; self.notifications=[]; self.catalog_rows=[]
        self.issue_refs={}; self.notice_refs={}; self.identities={}; self.issue_status={}
        self.history=None; self.audit=None; self.ready=None
        self.code_hashes={str(Path(module.__file__).resolve()):digest(Path(module.__file__).read_bytes())
                          for module in (proofs,history_qualification,catalog)}
        self.code_hashes[str(Path(__file__).resolve())]=digest(Path(__file__).read_bytes())

    def bind(self,bridge):
        require(self.bridge is None or self.bridge is bridge,'common_facade_bridge_rebinding_forbidden')
        self.bridge=bridge

    def _unchanged_code(self):
        for path,sha in self.code_hashes.items():
            require(digest(Path(path).read_bytes())==sha,'trusted_common_validator_source_changed')

    def _events(self):
        with closing(self.bridge.registry._connect(readonly=True)) as db:
            return [dict(row) for row in db.execute(
                'SELECT e.seq,e.action,e.kind,e.data,a.operation FROM events e LEFT JOIN actions a '
                'ON a.attempt=e.attempt AND a.id=e.action WHERE e.attempt=? ORDER BY e.seq',
                (self.bridge.attempt_id,))]

    def _dispatch_stamp(self,action):
        events=self._events(); selected=[row for row in events if row['action']==action['id']
                                       and row['kind']=='dispatch_permit_issued']
        require(len(selected)==1,'evidence_original_dispatch_not_unique')
        seq=selected[0]['seq']
        dispatches=[row for row in events if row['seq']<=seq and row['kind']=='dispatch_permit_issued']
        return {'sequence':seq,'database':action['dispatch_epoch'],
                'queue':sum(row['operation'] in {'restore_database','service_control','replay_issue',
                    'queue_prune','send_notification','final_submit'} for row in dispatches),
                'services':sum(row['operation']=='service_control' for row in dispatches)}

    def ingest(self,capture):
        self._unchanged_code()
        action=self.bridge._verified_capture_binding(capture['action_id'],capture)
        require(action['execution']=='terminal' and action['effect'] in
                {'read_only','settled_applied','settled_not_applied','partial_or_conflict'},
                'common_evidence_action_not_settled')
        name=action['request']['parameters']['fixed_program']; doc=parse_capture(capture)
        handle='capture:'+action['id']+':'+digest(capture['stdout'])
        entry={'handle':handle,'action_id':action['id'],'program':name,'document':doc,
               'arguments':action['request']['parameters']['arguments'],
               'stamp':self._dispatch_stamp(action),'capture':capture}
        old=self.records.get(handle)
        require(old is None or old['document']==doc,'immutable_public_capture_changed')
        self.records[handle]=entry; self.latest[name]=entry
        if name=='recovery_files':
            args=entry['arguments']; raw=base64.b64decode(doc['data_base64'],validate=True)
            require(doc.get('source_complete') is True and len(raw)==doc['bytes']
                    and hashlib.sha256(raw).hexdigest()==doc['sha256'],'public_recovery_document_incomplete')
            parsed=json.loads(raw)
            require(isinstance(parsed,list),'public_recovery_document_must_be_list')
            self.documents[args['kind']]={**entry,'parsed':parsed}
        elif name=='identity_authorization':
            require(doc.get('source_complete') is True,'identity_authorization_incomplete')
            wanted=entry['arguments']['intents']
            require(len(doc['identities'])==len(wanted),'identity_authorization_row_count')
            for request,row in zip(wanted,doc['identities']):
                require((row.get('project'),row.get('iid'),row.get('recipient'))==notice_key(request)[:3],
                        'identity_authorization_request_binding')
                self.identities[notice_key(request)]={'row':row,'evidence':entry}
        elif name=='issue_inventory':
            require(doc.get('source_complete') is True,'issue_inventory_incomplete')
            require(len(doc['results'])==len(entry['arguments']['receipts']),'issue_inventory_count')
            for receipt,row in zip(entry['arguments']['receipts'],doc['results']):
                require(row['key']=={'project':receipt['project'],'iid':receipt['iid']},'issue_inventory_request_binding')
                response=proofs.complete_http(row['response'],method='GET',
                     path='/api/v4/projects/%d/issues/%d'%public_key(receipt))
                if row['classification']=='matches':
                    require(row['response']['status']==200 and proofs.issue_matches(response,receipt),
                            'issue_inventory_match_not_actual')
                self.issue_status[public_key(receipt)]={'row':row,'evidence':entry}
        elif name=='public_audit':
            audit_document(doc)
            guards=capture.get('ledger_guards')
            # Causal send audits are supplied with the bridge's own recorded
            # ticket guards after finish_notification_audit. General audits
            # must arrive from the fixed driver guarded-audit wrapper.
            require(isinstance(guards,dict) and set(guards)=={'before','after'},
                    'public_audit_lifecycle_guards_missing')
            for guard in guards.values():
                require(guard.get('valid') is True and guard.get('ledger_epoch')==self.bridge.context['ledger_epoch']
                        and guard.get('attempt_id')==self.bridge.attempt_id,'public_audit_lifecycle_not_current')
            require(guards['after']['sequence']>guards['before']['sequence'],'public_audit_guards_not_ordered')
            self.audit=entry
        return handle

    def _fresh(self,entry,dimensions):
        require(entry is not None,'required_public_evidence_missing')
        current=self.bridge.state()
        require(all(entry['stamp'][key]==current[key] for key in dimensions),
                'public_evidence_stale_'+','.join(dimensions))
        return entry

    def _get(self,name,dimensions=()):
        return self._fresh(self.latest.get(name),dimensions)

    def _barrier(self):
        entry=self._get('service_inventory',('services',))
        controls={}
        for record in sorted(self.records.values(),key=lambda row:row['stamp']['sequence']):
            if record['program']=='service_control':controls[record['arguments']['service']]=record
        require(set(controls)=={'puma','sidekiq'} and all(row['arguments']['verb']=='stop' for row in controls.values()),
                'writer_barrier_latest_controls_are_not_proven_stops')
        writer_barrier(entry['document'],{name:row['document'] for name,row in controls.items()})
        return entry

    def queue_configuration(self):
        entry=self._get('background_contract',('database',))
        selected=entry['document'].get('actual_queue_configuration')
        require(isinstance(selected,dict) and entry['document'].get('qualified') is True
                and selected.get('schema')=='b0-actual-Rails-queue-configuration-v1'
                and selected.get('source')=='Gitlab::Redis::Queues.params_after_Rails_initialization'
                and selected.get('qualified') is True and selected.get('host')=='gitlab-redis'
                and selected.get('port')==6379 and type(selected.get('database'))is int
                and 0<=selected['database']<=15 and selected.get('database_present') is True
                and selected.get('database_basis') in {'actual_params_db','actual_params_URL_path','actual_client_config_normalization'}
                and selected.get('shards')==['main']
                and selected.get('connections_created_by_observer') is False
                and all(selected.get(key) is False for key in ('authentication_present','tls_present',
                    'cluster_present','sentinels_present','unix_socket_present','namespace_present')),
                'common_actual_Sidekiq_queues_Redis_configuration_unqualified')
        if selected['database_basis']=='actual_client_config_normalization':
            normalization=selected.get('client_configuration_normalization',{})
            require(normalization.get('qualified') is True
                    and normalization.get('scope')=='actual_client_configuration_only_no_client_or_pool'
                    and normalization.get('version')=='0.26.4'
                    and normalization.get('configuration_constructor_owner')=='Class'
                    and normalization.get('new_client_called') is False and normalization.get('new_pool_called') is False
                    and normalization.get('redis_commands_issued')==0
                    and (normalization.get('host'),normalization.get('port'),normalization.get('database'))==
                        (selected['host'],selected['port'],selected['database'])
                    and isinstance(normalization.get('actual_method_bindings'),list)
                    and len(normalization['actual_method_bindings'])==14
                    and all(row.get('qualified') is True for row in normalization['actual_method_bindings']),
                    'actual_client_configuration_normalization_not_source_bound')
        return entry,selected

    def _queue(self,*,stable=True):
        entry=self._get('queue_inventory',('database','queue','services'))
        configuration,selected=self.queue_configuration()
        require(entry['arguments']=={'redis_db':selected['database']}
                and entry['document'].get('redis_db')==selected['database'],
                'queue_capture_is_not_actual_Sidekiq_queues_database')
        snap=queue_document(entry['document'],stable=stable)
        return {**entry,'queue_configuration_handle':configuration['handle']},snap

    def _history_current(self):
        require(self.history is not None and self.history['proof'].get('qualified') is True,
                'historical_related_SMTP_effects_not_qualified')
        # Starting Sidekiq would permit old/new work to run. The historical
        # certificate may survive database restoration, but not worker restart.
        for event in self._events():
            if (event['seq']<=self.history['sequence'] or event['kind']!='dispatch_permit_issued'
                    or event['operation']!='service_control'):
                continue
            action=self.bridge.registry.poll(self.bridge.attempt_id,event['action'])
            if action['request']['parameters']['arguments']=={'service':'sidekiq','verb':'start'}:
                raise EvidenceGap('historical_proof_invalidated_by_Sidekiq_restart')
        return self.history

    def declare_public_intents(self):
        require(set(self.documents)>={'issues','notifications','catalog'},'complete_public_recovery_documents_required')
        require(not self.issue_refs and not self.notice_refs,'public_intents_already_declared')
        self.catalog_rows=self.documents['catalog']['parsed']
        require(1<=len(self.catalog_rows)<=32,'public_archive_catalog_bound')
        self.issues=self.documents['issues']['parsed']; self.notifications=self.documents['notifications']['parsed']
        require(1<=len(self.issues)<=2000 and 1<=len(self.notifications)<=2000,'public_intent_document_bound')
        issue_map={}; notice_map={}
        for receipt in self.issues:
            normalized=normalized_receipt(receipt); catalog.receipt(normalized)
            key=public_key(receipt)
            require(key not in issue_map,'duplicate_public_issue_receipt_identity')
            issue_map[key]=receipt
            ref='issue-'+digest(list(key))[:32]; self.issue_refs[key]=ref
            self.bridge.declare_intent(ref,kind='issue',public_business_key={'project':key[0],'iid':key[1]},
                                      receipt_sha256=digest(receipt))
        for receipt in self.notifications:
            normalized=normalized_receipt(receipt,True); catalog.receipt(normalized,True)
            key=notice_key(receipt)
            require(key not in notice_map,'duplicate_public_notification_intent')
            require(public_key(receipt) in issue_map and normalized_receipt(receipt)==normalized_receipt(issue_map[public_key(receipt)]),
                    'notification_content_not_bound_to_acknowledged_issue')
            for name in ('recipient_id','issue_id_at_acceptance'):
                require(type(receipt.get(name)) is int and receipt[name]>0,'public_old_job_identity_missing')
            for name in ('job_id','provider_job_id'):
                if receipt.get(name) is not None:catalog.identifier(receipt[name])
            notice_map[key]=receipt
            ref='notice-'+digest(list(key))[:32]; self.notice_refs[key]=ref
            self.bridge.declare_intent(ref,kind='notification',
                public_business_key={k:normalized[k] for k in ('project','iid','recipient','reason')},
                receipt_sha256=digest(receipt))
        distribution=Counter(public_key(row) for row in self.notifications)
        return {'issues':len(self.issues),'notification_intents':len(self.notifications),
                'notification_identity_dimensions':['project','iid','recipient','reason'],
                'recipients_per_issue_histogram':dict(Counter(distribution.values())),
                'source_handles':[self.documents[name]['handle'] for name in ('issues','notifications','catalog')]}

    def qualify_history(self):
        barrier=self._barrier(); queue,snapshot=self._queue()
        runtime=self._get('runtime_contract'); history=self._get('history_logs',('services',))
        proof=history_qualification.qualify_history(history['document'],self.notifications,
            runtime_approved=runtime['document'].get('approved_runtime'),writers_stopped=True,queue_snapshot=snapshot)
        record={'proof':proof,'sequence':max(row['seq'] for row in self._events()),
                'handles':[barrier['handle'],queue['handle'],queue['queue_configuration_handle'],runtime['handle'],history['handle'],
                           self.documents['notifications']['handle']]}
        self.history=record
        return record

    def audit_report(self):
        require(self.audit is not None,'full_guarded_public_audit_required')
        return classify_audit(self.audit['document'],self.notifications)

    def latch_acceptances(self):
        report=self.audit_report()
        require(not report['unattributed_issue_update_delivery_ids'],'unattributed_custom_incident_deliveries')
        for key,entry in report['by_intent'].items():
            require(entry['state']!='conflict','wrong_or_duplicate_public_incident_delivery')
            if entry['state']=='accepted':
                self.bridge.latch_verified_public_acceptance(self.notice_refs[key],self.audit['capture'],
                                                             verifier=self.acceptance_proof)
        return report

    def acceptance_proof(self,intent_ref,capture,bridge):
        key=next((key for key,ref in self.notice_refs.items() if ref==intent_ref),None)
        require(key is not None and self.audit is not None and capture['action_id']==self.audit['action_id'],
                'acceptance_original_public_intent_or_audit_missing')
        report=classify_audit(parse_capture(capture),self.notifications); entry=report['by_intent'][key]
        require(entry['state']=='accepted','acceptance_not_unique_and_correct')
        return {'evidence_id':'public-accept-'+digest({'intent':list(key),'capture':digest(capture['stdout'])}),
                'ledger_lifecycle':bridge.context['ledger_epoch'],'complete':True,
                'capture_sha256':digest(capture['stdout']),'delivery_ids':entry['delivery_ids']}

    def notification_audit_proof(self,action,capture,bridge):
        intent=action['request']['parameters']['arguments']['intent']; key=notice_key(intent)
        report=classify_audit(parse_capture(capture),self.notifications); entry=report['by_intent'][key]
        conflict=entry['state']=='conflict' or bool(report['unattributed_issue_update_delivery_ids'])
        return {'complete':True,'settled_effect':'partial_or_conflict' if conflict else
                    'settled_applied' if entry['state']=='accepted' else 'settled_not_applied',
                'delivery_ids':entry['delivery_ids'],'wrong_delivery_ids':entry['wrong_delivery_ids'],
                'effect_scope':'recipient_visible_delivery_and_no_remaining_request_that_can_append_this_delivery',
                'ordinary_application_internal_records_may_exist':True,
                'ledger_lifecycle':bridge.context['ledger_epoch']}

    def _no_incident_jobs(self,snapshot):
        identities=[value['row'] for value in self.identities.values()]
        require(not any(is_possible_incident_job(row['item'],self.notifications,identities) for row in snapshot['jobs']),
                'incident_notification_job_still_replayable')
        for work in snapshot['work']:
            value=work['value']; payload=value.get('payload') if isinstance(value,dict) else None
            if isinstance(payload,str):payload=json.loads(payload)
            require(isinstance(payload,dict),'workset_payload_unparseable')
            require(not is_possible_incident_job(payload,self.notifications,identities),
                    'incident_historical_work_record_not_resolved')

    def _ready_still_valid(self):
        require(self.ready is not None,'normal_background_start_requires_complete_incident_reconciliation')
        require(self.bridge.state()['database']==self.ready['generations']['database']
                and self.bridge.state()['database_valid'],'reconciliation_checkpoint_database_changed')
        for event in self._events():
            if event['seq']<=self.ready['sequence'] or event['kind']!='dispatch_permit_issued' or event['operation']=='observe':
                continue
            require(event['operation']=='service_control','business_mutation_after_reconciliation_checkpoint')
            action=self.bridge.registry.poll(self.bridge.attempt_id,event['action'])
            require(action['request']['parameters']['arguments']['verb']=='start' and action['effect']=='settled_applied',
                    'unqualified_service_transition_after_reconciliation_checkpoint')

    def __call__(self,phase,operation,proposal,bridge):
        self.bind(bridge); self._unchanged_code()
        require(phase in {'reserve','dispatch'},'unknown_common_guard_phase')
        require(self.issues and self.notifications,'public_business_receipts_not_declared')
        arguments=proposal['arguments']; handles=[self.documents['issues']['handle'],self.documents['notifications']['handle']]
        runtime=self._get('runtime_contract')
        require(runtime['document'].get('approved_runtime') is True,'fixed_runtime_source_contract_not_approved')
        handles.append(runtime['handle'])
        if operation=='service_control':
            services=self._get('service_inventory',('services',)); states=services_document(services['document'])
            handles.append(services['handle'])
            if arguments['verb']=='stop':
                clock=bridge.context.get('clock_identity')
                require(os.readlink('/proc/self/ns/time')==os.readlink('/proc/self/ns/time_for_children'),
                        'active_and_children_time_namespaces_differ')
                actual_clock={'schema':'b0-monotonic-clock-identity-v1',
                    'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                    'time_namespace':os.readlink('/proc/self/ns/time'),
                    'timens_offsets_sha256':digest(Path('/proc/self/timens_offsets').read_bytes())}
                require(isinstance(clock,dict) and clock==actual_clock==arguments['clock_identity'],
                        'stop_launch_and_actual_agent_clock_identity_mismatch')
                deadline=arguments['deadline_monotonic'];now=time.monotonic()
                incident_start=bridge.context.get('incident_visible_mono')
                limit=bridge.context.get('budgets',{}).get('agent_timeout_seconds')
                require(type(incident_start)in (int,float) and type(limit)in (int,float)
                        and math.isfinite(incident_start) and math.isfinite(limit) and limit>0
                        and type(deadline)in (int,float) and math.isfinite(deadline)
                        and now<deadline<=min(incident_start+limit,now+120),
                        'stop_deadline_outside_fixed_or_original_incident_budget')
            if arguments['verb']=='start':
                require(bridge.state()['database_valid'],'cannot_start_service_with_unqualified_restored_database')
                if arguments['service']=='sidekiq':
                    self._ready_still_valid()
                    handles.extend(self.ready['evidence_handles'])
                else:
                    require(states['sidekiq']['state']=='down' or self.ready is not None,
                            'Puma_replay_start_requires_stopped_Sidekiq')
        elif operation=='restore_database':
            # Historical SMTP can only append to the independent mailbox. Once
            # actual application writers and their DB backends are stopped,
            # restoring PG does not require those unrelated mailbox terminals.
            # The historical certificate is still mandatory for prune/send and
            # normal Sidekiq restart; no absence/acceptance is inferred here.
            handles.append(self._barrier()['handle'])
            selected=[row for row in self.catalog_rows if row.get('file')==arguments['file']
                      and row.get('status')=='completed' and row.get('sha256')==arguments['expected_sha256']]
            require(len(selected)==1,'archive_not_uniquely_selected_from_public_completed_catalog')
            candidates=[entry for entry in self.records.values() if entry['program']=='archive_check'
                        and entry['arguments']=={key:arguments[key] for key in ('file','expected_sha256')}]
            require(bool(candidates) and candidates[-1]['document'].get('valid') is True,
                    'selected_archive_actual_digest_and_listing_not_valid')
            handles.extend([candidates[-1]['handle'],self.documents['catalog']['handle']])
            database=self._get('database_state',('database','services')); handles.append(database['handle'])
            require(database['document'].get('in_recovery') is False,'database_target_not_writable_primary')
            require(not database['document'].get('sessions'),'active_application_database_sessions_block_restore')
        elif operation=='replay_issue':
            receipt=arguments['receipt']; key=public_key(receipt)
            require(key in self.issue_refs and proposal['intent_ref']==self.issue_refs[key]
                    and receipt==normalized_receipt(next(row for row in self.issues if public_key(row)==key)),
                    'replay_not_bound_to_public_issue_intent')
            services=self._get('service_inventory',('services',)); states=services_document(services['document'])
            require(states['sidekiq']['state']=='down' and states['puma']['state']=='run','replay_service_state_incompatible')
            current=self.issue_status.get(key); require(current is not None,'current_public_issue_read_required')
            self._fresh(current['evidence'],('database',))
            require(current['row']['classification'] in {'absent','matches'},'current_public_issue_conflicts_or_unavailable')
            handles.extend([services['handle'],current['evidence']['handle']])
        elif operation=='queue_prune':
            handles.append(self._barrier()['handle']); handles.extend(self._history_current()['handles'])
            queue,snapshot=self._queue(); handles.extend([queue['handle'],queue['queue_configuration_handle']])
            self._fresh(self.audit,('database','queue','services')); self.latch_acceptances()
            handles.append(self.audit['handle'])
            require((arguments['redis_db'],arguments['redis_run_id'],arguments['before_token'])==
                    (queue['document']['redis_db'],queue['document']['redis_run_id'],snapshot['inventory_token']),
                    'prune_not_bound_to_current_complete_queue_capture')
            for selection in arguments['selected']:
                matches=[row for row in snapshot['jobs'] if (row['key'],row['jid'],row['raw_sha256'],row['score'])==
                    (selection['key'],selection['jid'],selection['raw_sha256'],selection['score'])]
                require(len(matches)==selection['expected_occurrences'],'prune_original_raw_multiplicity_mismatch')
                for row in matches:
                    receipt=old_job_receipt(row['item'],self.notifications)
                    require(selection['public_intent_key']=={key:receipt[key] for key in ('project','iid','recipient')},
                            'prune_selection_not_authorized_by_exact_public_receipt')
                    current=self.identities.get(notice_key(receipt))
                    require(current is not None,'prune_current_identity_authorization_missing')
                    self._fresh(current['evidence'],('database','services'))
                    require(current['row'].get('matches') is True,'prune_current_identity_or_authorization_conflict')
                    handles.append(current['evidence']['handle'])
        elif operation=='send_notification':
            handles.append(self._barrier()['handle']); handles.extend(self._history_current()['handles'])
            intent=arguments['intent']; key=notice_key(intent)
            require(key in self.notice_refs and proposal['intent_ref']==self.notice_refs[key]
                    and intent==normalized_receipt(next(row for row in self.notifications if notice_key(row)==key),True),
                    'send_not_bound_to_public_notification_intent')
            current=self.identities.get(key); require(current is not None,'current_identity_authorization_missing')
            self._fresh(current['evidence'],('database','services'))
            require(current['row'].get('matches') is True,'current_recipient_authorization_or_content_failed')
            queue,snapshot=self._queue(); self._no_incident_jobs(snapshot)
            report=self.latch_acceptances(); entry=report['by_intent'][key]
            require(entry['state']=='missing','public_notification_already_accepted_or_conflicting')
            self._fresh(self.audit,('database','queue','services'))
            handles.extend([current['evidence']['handle'],queue['handle'],queue['queue_configuration_handle'],self.audit['handle']])
            with closing(bridge.registry._connect(readonly=True)) as db:
                unresolved=db.execute("SELECT id FROM actions WHERE attempt=? AND operation='send_notification' "
                    "AND id<>? AND effect NOT IN ('settled_applied','settled_not_applied','partial_or_conflict')",
                    (bridge.attempt_id,proposal['action_id'])).fetchall()
                intent=db.execute('SELECT semantic_key FROM intents WHERE attempt=? AND ref=?',
                    (bridge.attempt_id,self.notice_refs[key])).fetchone()
                count=db.execute("SELECT count(*) FROM actions WHERE attempt=? AND operation='send_notification' "
                    "AND intent_key=? AND dispatch_epoch IS NOT NULL",(bridge.attempt_id,intent['semantic_key'])).fetchone()[0]
            require(not unresolved,'another_original_notification_effect_is_unresolved')
            require(count<int(bridge.context.get('budgets',{}).get('max_send_attempts_per_intent',8)),
                    'uniform_notification_attempt_budget_exhausted')
        else:
            raise EvidenceGap('operation_has_no_fixed_common_precondition_validator')
        return {'qualified':True,'evidence_handles':sorted(set(handles)),'generations':bridge.state(),
                'phase':phase,'operation':operation,'scope':'fixed_public_evidence_no_private_provider_state'}

    def mark_ready_for_normal_services(self):
        barrier=self._barrier(); queue,snapshot=self._queue(); self._no_incident_jobs(snapshot)
        historical=self._history_current(); report=self.latch_acceptances()
        missing=[key for key,row in report['by_intent'].items() if row['state']=='missing']
        maximum=int(self.bridge.context.get('budgets',{}).get('max_send_attempts_per_intent',8))
        for key in missing:
            with closing(self.bridge.registry._connect(readonly=True)) as db:
                intent=db.execute('SELECT semantic_key FROM intents WHERE attempt=? AND ref=?',
                    (self.bridge.attempt_id,self.notice_refs[key])).fetchone()
                actions=db.execute("SELECT execution,effect,dispatch_epoch FROM actions WHERE attempt=? "
                    "AND operation='send_notification' AND intent_key=? ORDER BY rowid",
                    (self.bridge.attempt_id,intent['semantic_key'])).fetchall()
            require(len(actions)==maximum and all(row['execution']=='terminal' and row['effect']=='settled_not_applied'
                    and row['dispatch_epoch'] is not None for row in actions),
                    'missing_notification_not_qualified_as_uniform_budget_exhaustion')
        handles=[barrier['handle'],queue['handle'],queue['queue_configuration_handle'],self.audit['handle'],*historical['handles']]
        for receipt in self.issues:
            entry=self.issue_status.get(public_key(receipt)); require(entry is not None,'final_public_issue_check_missing')
            self._fresh(entry['evidence'],('database',)); require(entry['row']['classification']=='matches','final_public_issue_check_failed')
            handles.append(entry['evidence']['handle'])
        background=self._get('background_contract',('database','services'))
        require(background['document'].get('qualified') is True,'normal_background_reason_contract_not_bound')
        handles.append(background['handle'])
        self.ready={'qualified':True,'evidence_handles':sorted(set(handles)),
                    'generations':self.bridge.state(),'sequence':max(row['seq'] for row in self._events()),
                    'public_checks_complete':True,'public_checks_passed':not missing,
                    'policy_outcome':'known_missing_after_retry_budget' if missing else 'public_reconciliation_passed',
                    'known_missing_intents':[list(key) for key in sorted(missing)],
                    'uniform_send_attempt_budget':maximum,
                    'notification_states':[{'intent':list(key),**row} for key,row in sorted(report['by_intent'].items())]}
        return self.ready

    def final_preconditions(self,bridge):
        self._ready_still_valid()
        require(bridge.state()['database']==self.ready['generations']['database'] and bridge.state()['database_valid'],
                'database_changed_after_final_reconciliation')
        services=self._get('service_inventory',('services',)); states=services_document(services['document'])
        require(all(row['state']=='run' for row in states.values()),'normal_background_services_not_restored')
        for event in self._events():
            if event['seq']<=self.ready['sequence'] or event['kind']!='dispatch_permit_issued' or event['operation']=='observe':
                continue
            require(event['operation']=='service_control','business_mutation_after_complete_reconciliation')
            action=bridge.registry.poll(bridge.attempt_id,event['action'])
            require(action['request']['parameters']['arguments']['verb']=='start' and action['effect']=='settled_applied',
                    'unresolved_or_stop_service_transition_after_reconciliation')
        report=self.latch_acceptances()
        previous={tuple(row['intent']):row for row in self.ready['notification_states']}
        require(all(row['state']==previous[key]['state'] and row['delivery_ids']==previous[key]['delivery_ids']
                    and row['wrong_delivery_ids']==previous[key]['wrong_delivery_ids']
                    for key,row in report['by_intent'].items()),
                'unexpected_incident_notification_effect_after_normal_background_start')
        require(self.audit['stamp']['sequence']>self.ready['sequence'],'final_public_audit_not_fresh_after_checkpoint')
        return {'qualified':True,'evidence_handles':sorted(set(self.ready['evidence_handles']+
                [services['handle'],self.audit['handle']])), 'generations':bridge.state(),
                'original_oracle_only':True,'prior_final_submission_count':0,
                'public_checks_complete':True,'public_checks_passed':self.ready['public_checks_passed'],
                'policy_outcome':self.ready['policy_outcome']}
