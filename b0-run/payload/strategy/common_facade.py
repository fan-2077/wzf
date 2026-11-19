"""Trusted public_result_v1 action boundary with explicit policy scope.

Deploy this callable with the bridge. Models may choose finite catalog arguments
and opaque evidence handles; they never receive this object's mutable internals,
the registry adapter, callbacks, or an ability to manufacture a proof. Both
reservation and actual dispatch recheck the same public evidence conditions.
"""
from __future__ import annotations

from contextlib import closing
from registry_v2 import CLOSED_ACTION_EFFECTS
import base64
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import re
import time

import catalog
import history_qualification
import proofs
from common_io import canonical, digest, parse_capture
from proofs import (EvidenceGap, KnownBusinessFailure, require, notice_key, public_key, normalized_receipt,
                    audit_document, classify_audit, queue_document, old_job_receipt,
                    is_possible_incident_job, services_document, writer_barrier)


class CommonFacade:
    def __init__(self):
        self.bridge=None; self.records={}; self.latest={}; self.documents={}
        self.issues=[]; self.notifications=[]; self.catalog_rows=[]
        self.issue_refs={}; self.notice_refs={}; self.identities={}; self.issue_status={}
        self.history=None; self.audit=None; self.ready=None; self.final_snapshot=None; self.final_admission=None
        self.history_status="not_evaluated"; self.history_error=None
        self.code_hashes={str(Path(module.__file__).resolve()):digest(Path(module.__file__).read_bytes())
                          for module in (proofs,history_qualification,catalog)}
        self.code_hashes[str(Path(__file__).resolve())]=digest(Path(__file__).read_bytes())

    def bind(self,bridge):
        require(self.bridge is None or self.bridge is bridge,'common_facade_bridge_rebinding_forbidden')
        require(bridge.context.get('protocol_id')=='public_result_v1','public_result_protocol_not_bound')
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
                CLOSED_ACTION_EFFECTS,
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
            # Post-terminal send snapshots use the bridge's own recorded
            # ticket guards after finish_notification_snapshot. General audits
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

    def historical_assurance(self):
        # Diagnostic facts remain false/unknown when the historical algorithm
        # cannot qualify them. Not required is never converted to qualified.
        status=self.history_status
        handles=self.history.get('handles',[]) if self.history else []
        return {'status':status,'required_for_action_admission':False,
                'evidence_handles':list(handles),'all_historical_effects_settled_claimed':False}

    def history_diagnostic_failed(self,error):
        self.history_status='unknown'
        self.history_error={'type':type(error).__name__,'message':str(error)}
        return {'historical_terminal_proof':self.historical_assurance(),
                'error':self.history_error,'new_business_permission_from_diagnostic':False}

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
        self.history_status="qualified" if proof.get("qualified") is True else "unqualified"
        return {**record,"historical_terminal_proof":self.historical_assurance(),
                "new_business_permission_from_diagnostic":False}

    def audit_report(self):
        require(self.audit is not None,'full_guarded_public_audit_required')
        return classify_audit(self.audit['document'],self.notifications)

    def accepted_intent_skip(self,receipt):
        """A permanent verified positive only suppresses work; it grants none."""
        self._unchanged_code()
        owned=self.owned_execution_state()
        require(owned['all_owned_actions_closed'],'accepted_skip_cannot_bypass_owned_unresolved_execution')
        key=notice_key(receipt);ref=self.notice_refs.get(key)
        require(ref is not None,'accepted_skip_public_intent_not_declared')
        with closing(self.bridge.registry._connect(readonly=True)) as db:
            row=db.execute('SELECT t.id,t.scope,t.ledger,t.state,i.dbkey,i.kind,i.semantic_key,i.receipt_sha '
                'FROM attempts t JOIN intents i ON i.attempt=t.id WHERE t.id=? AND i.ref=?',
                (self.bridge.attempt_id,ref)).fetchone()
            require(row is not None and row['state']=='active' and row['kind']=='notification'
                    and row['scope']==self.bridge.context['physical_scope_id']
                    and row['ledger']==self.bridge.context['ledger_epoch']
                    and row['receipt_sha']==digest(receipt),
                    'accepted_skip_current_attempt_scope_ledger_or_receipt_mismatch')
            business={name:receipt[name] for name in ('project','iid','recipient','reason')}
            expected_key=digest({'database':row['dbkey'],'kind':'notification','business':business})
            require(row['semantic_key']==expected_key,'accepted_skip_semantic_intent_mismatch')
            accepted=db.execute('SELECT evidence_id,payload FROM public_acceptances '
                'WHERE scope=? AND ledger=? AND intent_key=?',
                (row['scope'],row['ledger'],row['semantic_key'])).fetchone()
        if accepted is None:return None
        proof=json.loads(accepted['payload'])
        require(set(proof)=={'evidence_id','ledger_lifecycle','complete','capture_sha256','delivery_ids'}
                and proof['evidence_id']==accepted['evidence_id'] and proof['complete'] is True
                and proof['ledger_lifecycle']==row['ledger']
                and isinstance(proof['capture_sha256'],str)
                and bool(re.fullmatch(r'[0-9a-f]{64}',proof['capture_sha256']))
                and isinstance(proof['delivery_ids'],list) and bool(proof['delivery_ids'])
                and all(type(value) is int and value>0 for value in proof['delivery_ids']),
                'accepted_skip_permanent_positive_record_invalid')
        return {'schema':'b0-accepted-intent-skip-v1','attempt_id':self.bridge.attempt_id,
                'physical_scope_id':row['scope'],'ledger_epoch':row['ledger'],
                'intent':list(key),'intent_ref':ref,'intent_semantic_key':row['semantic_key'],
                'receipt_sha256':row['receipt_sha'],'evidence_id':accepted['evidence_id'],
                'acceptance_payload_sha256':digest(accepted['payload'].encode()),
                'original_capture_sha256':proof['capture_sha256'],'delivery_ids':proof['delivery_ids'],
                'owned_execution_check':owned,'locks_changed':False,'business_dispatches':0,
                'claim':'previous_verified_acceptance_suppresses_resend_only_not_no_duplicates_or_causal_effect'}

    def latch_acceptances(self,*,reject_conflicts=True):
        report=self.audit_report()
        # Preserve each real positive before rejecting a different conflicting
        # intent. A failed policy must not lose already observed acceptances.
        for key,entry in report['by_intent'].items():
            if entry['state']=='accepted':
                self.bridge.latch_verified_public_acceptance(self.notice_refs[key],self.audit['capture'],
                                                             verifier=self.acceptance_proof)
        if reject_conflicts:
            if report['unattributed_issue_update_delivery_ids']:
                raise KnownBusinessFailure('unattributed_custom_incident_deliveries')
            if any(entry['state']=='conflict' for entry in report['by_intent'].values()):
                raise KnownBusinessFailure('wrong_or_duplicate_public_incident_delivery')
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

    def notification_snapshot_proof(self,action,capture,bridge):
        require(action['operation']=='send_notification' and action['execution']=='terminal',
                'notification_snapshot_requires_original_owned_terminal')
        intent=action['request']['parameters']['arguments']['intent']; key=notice_key(intent)
        document=parse_capture(capture)
        report=classify_audit(document,self.notifications); entry=report['by_intent'][key]
        conflict=entry['state']=='conflict' or bool(report['unattributed_issue_update_delivery_ids'])
        return {'protocol_id':'public_result_v1','complete':True,'owned_action_terminal':True,
                'intent_snapshot_state':'conflict' if conflict else entry['state'],
                'causal_attribution_to_this_action':'unknown',
                'historical_terminal_proof':self.historical_assurance(),
                'delivery_ids':entry['delivery_ids'],'wrong_delivery_ids':entry['wrong_delivery_ids'],
                'unattributed_issue_update_delivery_ids':report['unattributed_issue_update_delivery_ids'],
                'snapshot_id':document['snapshot'],'snapshot_total':document['total'],
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
            # Historical SMTP qualification is separately recorded in this
            # profile; no historical absence/acceptance is inferred here.
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
            handles.append(self._barrier()['handle'])
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
            handles.append(self._barrier()['handle'])
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
                    "AND id<>? AND effect NOT IN ('settled_applied','settled_not_applied','partial_or_conflict','snapshot_closed')",
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

    def owned_execution_state(self,*,accepted_submission=None):
        require(self.bridge.registry is not None,'owned_registry_not_initialized')
        with closing(self.bridge.registry._connect(readonly=True)) as db:
            actions=[dict(row) for row in db.execute(
                'SELECT id,operation,execution,effect,dispatch_epoch,settlement_evidence FROM actions '
                'WHERE attempt=? ORDER BY rowid',(self.bridge.attempt_id,))]
            locks=[dict(row) for row in db.execute('SELECT * FROM locks WHERE attempt=?',
                                                   (self.bridge.attempt_id,))]
        finals=[row for row in actions if row['operation']=='final_submit']
        pending_final_ids=set();receipt_raw_verified=False;receipt_error=None
        if accepted_submission is not None:
            # Report-only exemption for one exact accepted request whose raw
            # request/response is independently rebound by the bridge reader.
            try:
                require(isinstance(accepted_submission,dict) and len(finals)==1,
                        'report_original_submission_not_unique')
                action_id=accepted_submission.get('action_id')
                actual=self.bridge.read_final_submission(action_id)
                fields=('schema','attempt_id','action_id','native_call_id','response_sha256',
                        'state','submission_state')
                require(all(actual.get(key)==accepted_submission.get(key) for key in fields)
                        and actual.get('attempt_id')==self.bridge.attempt_id
                        and actual.get('state')=='accepted_pending_evaluation'
                        and actual.get('submission_state')=='accepted_for_evaluation'
                        and finals[0]['id']==action_id and finals[0]['dispatch_epoch'] is not None
                        and actual.get('original_action',{}).get('operation')=='final_submit',
                        'report_original_submission_raw_receipt_binding_failed')
                pending_final_ids={action_id};receipt_raw_verified=True
            except Exception as error:
                receipt_error={'type':type(error).__name__,'message':str(error)}
        unresolved=[row for row in actions
                    if row['id'] not in pending_final_ids and not
                    ((row['execution']=='terminal' and row['effect'] in CLOSED_ACTION_EFFECTS)
                     or (row['execution']=='not_dispatched' and row['dispatch_epoch'] is None
                         and row['effect']=='settled_not_applied'))]
        other_locks=[row for row in locks if row['action'] not in pending_final_ids]
        return {'owned_unresolved_action_ids':[row['id'] for row in unresolved],
                'unresolved_actions':unresolved,'resource_locks':other_locks,
                'all_owned_actions_closed':not unresolved and not other_locks,
                'final_submission_actions':finals,'registered_action_count':len(actions),
                'accepted_original_submission_raw_verified':receipt_raw_verified,
                'accepted_original_submission_binding_error':receipt_error,
                'point':'after_original_submission' if accepted_submission is not None else 'before_original_submission'}

    def public_business_snapshot(self):
        result={'schema':'b0-public-business-snapshot-v1','status':'incomplete',
                'accepted':None,'missing':None,'duplicates':None,'wrong_recipients':None,
                'unattributed_delivery_ids':[],'notification_states':[],
                'issue_states':[],'services':None,'database_valid':None,
                'queue_incident_jobs_absent':None,'evidence_handles':[],
                'incomplete_reasons':[],'known_failure_reasons':[],
                'scope':'observed_public_state_only_not_future_historical_effect_guarantee'}
        known=result['known_failure_reasons']; missing=result['incomplete_reasons']
        state=self.bridge.state()
        result['database_valid']=state.get('database_valid')
        if state.get('database_valid') is False:known.append('database_not_valid')
        elif state.get('database_valid') is not True:missing.append('database_validity_unknown')
        try:
            audit=self._fresh(self.audit,('database','queue','services'))
            report=self.audit_report()
            result['accepted']=sum(row['state']=='accepted' for row in report['by_intent'].values())
            result['missing']=sum(row['state']=='missing' for row in report['by_intent'].values())
            result['duplicates']=sum(max(0,len(row['delivery_ids'])-1) for row in report['by_intent'].values())
            result['wrong_recipients']=sum(len(row['wrong_delivery_ids']) for row in report['by_intent'].values())
            result['unattributed_delivery_ids']=report['unattributed_issue_update_delivery_ids']
            result['notification_states']=[{'intent':list(key),**row} for key,row in sorted(report['by_intent'].items())]
            result['audit_snapshot']=report['snapshot'];result['evidence_handles'].append(audit['handle'])
            if result['missing']:known.append('notifications_missing_in_snapshot')
            if result['duplicates']:known.append('duplicate_notifications_observed')
            if result['wrong_recipients']:known.append('wrong_notifications_observed')
            if result['unattributed_delivery_ids']:known.append('unattributed_incident_notifications_observed')
        except (EvidenceGap,KeyError,TypeError,ValueError) as error:
            missing.append('public_audit:'+str(error))
        if not self.issues:missing.append('public_issue_receipts_missing')
        for receipt in self.issues:
            key=public_key(receipt)
            try:
                entry=self.issue_status.get(key);require(entry is not None,'current_issue_read_missing')
                self._fresh(entry['evidence'],('database',))
                classification=entry['row']['classification']
                result['issue_states'].append({'public_key':list(key),'classification':classification,
                                               'evidence_handle':entry['evidence']['handle']})
                result['evidence_handles'].append(entry['evidence']['handle'])
                if classification in {'absent','conflict'}:known.append('issue_'+classification+':'+str(key))
                elif classification!='matches':missing.append('issue_unavailable:'+str(key))
            except (EvidenceGap,KeyError,TypeError,ValueError) as error:
                missing.append('issue:'+str(key)+':'+str(error))
        try:
            services=self._get('service_inventory',('services',)); states=services_document(services['document'])
            result['services']={name:row['state'] for name,row in states.items()}
            result['evidence_handles'].append(services['handle'])
            if not all(row['state']=='run' for row in states.values()):known.append('normal_services_not_running')
        except (EvidenceGap,KeyError,TypeError,ValueError) as error:
            missing.append('services:'+str(error))
        try:
            queue,snapshot=self._queue(stable=False)
            identities=[value['row'] for value in self.identities.values()]
            incident=[row for row in snapshot['jobs'] if is_possible_incident_job(row['item'],self.notifications,identities)]
            work=[]
            for row in snapshot['work']:
                value=row['value'];payload=value.get('payload') if isinstance(value,dict) else None
                if isinstance(payload,str):payload=json.loads(payload)
                require(isinstance(payload,dict),'workset_payload_unparseable')
                if is_possible_incident_job(payload,self.notifications,identities):work.append(row)
            result['queue_incident_jobs_absent']=not incident and not work
            result['evidence_handles'].extend([queue['handle'],queue['queue_configuration_handle']])
            if incident or work:known.append('incident_jobs_present_in_current_queue_snapshot')
        except (EvidenceGap,KeyError,TypeError,ValueError) as error:
            missing.append('queue:'+str(error))
        result['evidence_handles']=sorted(set(result['evidence_handles']))
        result['status']='known_fail' if known else 'incomplete' if missing else 'pass'
        return result

    def mark_ready_for_normal_services(self):
        barrier=self._barrier(); queue,snapshot=self._queue(); self._no_incident_jobs(snapshot)
        report=self.latch_acceptances()
        owned=self.owned_execution_state()
        require(owned['all_owned_actions_closed'],'owned_actions_unresolved_before_normal_services')
        handles=[barrier['handle'],queue['handle'],queue['queue_configuration_handle'],self.audit['handle']]
        for receipt in self.issues:
            entry=self.issue_status.get(public_key(receipt));require(entry is not None,'final_public_issue_check_missing')
            self._fresh(entry['evidence'],('database',));require(entry['row']['classification']=='matches','final_public_issue_check_failed')
            handles.append(entry['evidence']['handle'])
        for receipt in self.notifications:
            entry=self.identities.get(notice_key(receipt));require(entry is not None,'normal_start_identity_missing')
            self._fresh(entry['evidence'],('database','services'))
            require(entry['row'].get('matches') is True,'normal_start_identity_or_authorization_conflict')
            handles.append(entry['evidence']['handle'])
        background=self._get('background_contract',('database','services'))
        require(background['document'].get('qualified') is True,'normal_background_reason_contract_not_bound')
        handles.append(background['handle'])
        absent=[list(key) for key,row in sorted(report['by_intent'].items()) if row['state']=='missing']
        self.ready={'qualified':True,'protocol_id':'public_result_v1','evidence_handles':sorted(set(handles)),
                    'generations':self.bridge.state(),'sequence':max(row['seq'] for row in self._events()),
                    'historical_terminal_required':False,'historical_terminal_proof':self.historical_assurance(),
                    'public_checks_complete':True,'public_checks_passed':not absent,
                    'policy_outcome':'public_snapshot_has_missing' if absent else 'public_snapshot_all_accepted',
                    'known_missing_intents':absent,
                    'notification_states':[{'intent':list(key),**row} for key,row in sorted(report['by_intent'].items())]}
        return self.ready

    def final_preconditions(self,bridge):
        self.bind(bridge);self._unchanged_code()
        require(bridge.qualification.get('actual_native_mcp_qualified') is True,
                'original_evaluation_requires_actual_common_native_qualification')
        owned=self.owned_execution_state()
        require(owned['all_owned_actions_closed'],'original_evaluation_owned_actions_or_locks_unresolved')
        require(not owned['final_submission_actions'],'original_evaluation_already_reserved_or_dispatched')
        # Recheck actual public target identity. Business success or the old
        # historical proof is not substituted for this execution boundary.
        identities={name:bridge._current_target(name) for name in sorted(bridge.targets)}
        guard=bridge.guard.check('final_submit')
        require(guard.get('valid') is True and guard.get('ledger_epoch')==bridge.context['ledger_epoch'],
                'original_evaluation_ledger_identity_not_continuous')
        snapshot=self.public_business_snapshot()
        handles=snapshot['evidence_handles']+['native-qualification:'+bridge.qualification['action_id'],
                 'ledger-guard:'+str(guard['sequence'])+':'+guard['response_sha256']]
        self.final_snapshot=snapshot
        self.final_admission={'qualified':True,'protocol_id':'public_result_v1',
            'execution_ready_for_original_evaluation':True,'evidence_handles':sorted(set(handles)),
            'generations':bridge.state(),'owned_execution_before_submit':owned,
            'target_identities':identities,'ledger_guard':guard,
            'original_oracle_only':True,'prior_final_submission_count':0,
            'public_snapshot_status':snapshot['status'],
            'public_checks_complete':not snapshot['incomplete_reasons'],
            'public_checks_passed':True if snapshot['status']=='pass' else False if snapshot['status']=='known_fail' else None,
            'historical_terminal_required':False,'historical_terminal_proof':self.historical_assurance()}
        return self.final_admission
