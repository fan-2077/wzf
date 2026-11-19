"""Fresh full SREGym incident, public deterministic solver, one original oracle.

Only the phase-ledger observer adds a pre-cleanup evidence snapshot. Conductor,
fault injection, oracle, deployment and cleanup source files remain unchanged.
"""
from __future__ import annotations
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import threading
import time
import traceback
import uuid

from public_result_evidence import PROTOCOL, bind_submission, retain_original, classification
from host_ingress import HostIngressGuard
from host_lifecycle import LedgerLifecycleGuard, atomic, canonical
from runtime_boundary import inspect_agent_container, verify_native_boundary, stop_owned_container, read_http, save, sha_file

TASK='gitlab_notification_intermittent_replicated'
AGENT='b0-public-baseline'
PLAN=json.loads((Path(__file__).resolve().parent/'execution_plan.json').read_text())
BRANCH=PLAN['branch_ref']
BUDGETS={'agent_timeout_seconds':7200, 'max_native_calls':30000,
         'max_ledger_checks':4096, 'max_send_attempts_per_intent':8,
         'cpu':4,'memory_bytes':8*1024**3,'model_calls':0,
         'budget_scope':'separate public_result_v1 engineering B0-P; future comparison arms share the declared tools and aggregate limits'}

def monotonic_clock_identity():
    """Bind public deadlines to this actual Linux monotonic clock domain."""
    boot_id=Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
    time_namespace=os.readlink('/proc/self/ns/time')
    children_namespace=os.readlink('/proc/self/ns/time_for_children')
    offsets=Path('/proc/self/timens_offsets').read_bytes()
    if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',boot_id):
        raise RuntimeError('Invalid actual monotonic boot identity')
    if not re.fullmatch(r'time:\[[0-9]+\]',time_namespace) or not offsets:
        raise RuntimeError('Invalid actual monotonic time namespace identity')
    if children_namespace!=time_namespace:
        raise RuntimeError('Current and child monotonic time namespaces differ')
    return {'schema':'b0-monotonic-clock-identity-v1','boot_id':boot_id,
            'time_namespace':time_namespace,'timens_offsets_sha256':hashlib.sha256(offsets).hexdigest()}

def safe_json(path, maximum=32*1024*1024):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as source:
        metadata=os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 or metadata.st_size>maximum:
            raise RuntimeError('Invalid owned JSON evidence')
        return json.loads(source.read(maximum+1))

def phase_timing(path,attempt):
    rows=[json.loads(line) for line in path.read_text().splitlines() if line]
    starts=[r for r in rows if r.get('phase')=='stage:mitigation' and r.get('event')=='start']
    ends=[r for r in rows if r.get('phase')=='evaluate:mitigation' and r.get('event')=='end']
    valid=len(starts)==len(ends)==1 and all(r.get('attempt_id')==attempt for r in rows)
    valid=valid and type(starts[0]['mono']) in (int,float) and type(ends[0]['mono']) in (int,float) and ends[0]['mono']>=starts[0]['mono']
    suspended=any(float(r.get('suspended_s',0))>0 for r in rows)
    return {'start_count':len(starts),'evaluation_end_count':len(ends),
            'valid':bool(valid and not suspended),'suspended_record_present':suspended,
            'seconds':ends[0]['mono']-starts[0]['mono'] if valid and not suspended else None,
            'scope':'first incident visibility through unique original evaluation end, same native monotonic clock',
            'success_speed_comparison':False}

async def main():
    if (PLAN.get('mode') != 'public_b0' or PLAN.get('protocol_id') != PROTOCOL
            or BRANCH != 'refs/heads/sre-b0-public-result-v3-20261119'):
        raise RuntimeError('Independent public-result protocol and branch binding differ')
    expected={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted',
              'GITHUB_REPOSITORY':'fan-2077/wzf','GITHUB_REF':BRANCH,'GITHUB_RUN_ATTEMPT':'1'}
    for key,value in expected.items():
        if os.environ.get(key)!=value: raise RuntimeError('Refusing unreviewed host context: '+key)
    out=Path(os.environ['B0_RESULTS']).resolve()
    out.mkdir(parents=True,exist_ok=True)
    agent_logs=out/'agent';agent_logs.mkdir(exist_ok=False)
    run_id=os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']
    state={'scope':PLAN['mode'],'protocol_id':PROTOCOL,'baseline_variant':'B0-P','task':TASK,
           'attempt_id':run_id,'budgets':BUDGETS,'model_executed':False,
           'original_mitigation_success':None,'b0_pass':False,'cleanup':[]}
    ingress=HostIngressGuard(run_id,out)
    conductor=launcher=process=api_thread=lifecycle=None
    started=time.monotonic()
    pre_cleanup_captured=False

    def pre_cleanup_snapshot():
        nonlocal pre_cleanup_captured
        if pre_cleanup_captured: return
        pre_cleanup_captured=True
        # This callback is entered by the original cleanup phase, after its
        # original evaluation result was stored and before reference recovery.
        frozen={'attempt_id':run_id,'monotonic':time.monotonic(),
                'native_result':dict(conductor.results),
                'stage':conductor.submission_stage,
                'reference_cleanup_has_started_business_repair':False}
        try:
            if lifecycle and lifecycle.baseline is not None:
                frozen['ledger_guard_final_before_reference_cleanup']=lifecycle.check(uuid.uuid4().hex,cause='host_pre_cleanup')
                lifecycle.stop()
        except BaseException as exc:
            frozen['guard_error']={'type':type(exc).__name__,'message':str(exc)}
            state['pre_cleanup_guard_error']=str(exc)
        try:
            save(out/'native-result-before-reference-cleanup.json',frozen)
        except BaseException as exc:
            state['pre_cleanup_snapshot_error']=str(exc)

    try:
        if ingress.active_listeners(): raise RuntimeError('Native ports already in use')
        ingress.install()
        from logger import init_logger
        from sregym.agent_launcher import AgentLauncher
        from sregym.agent_registry import AgentRegistration
        from sregym.conductor.conductor import Conductor,ConductorConfig
        from sregym.conductor.conductor_api import run_api
        from sregym.phases import PhaseLedger
        from sregym.profile import set_profile
        from sregym.service.container_runner import get_container_host_bind_address
        from sregym.service.internet_policy import InternetPolicy
        init_logger();set_profile('full')
        bridge=get_container_host_bind_address()
        os.environ.update(API_BIND_HOST=bridge,API_PORT='8000',MCP_SERVER_PORT='9954',AGENT_LOGS_DIR=str(agent_logs))
        policy=InternetPolicy.from_mode('filtered',agent_name=None,model_id=None,additional_allowed_endpoints=())
        config=ConductorConfig(deploy_loki=False,internet_policy=policy,
            k8s_proxy_listen_host=bridge,k8s_proxy_listen_port=16443,
            block_workload_creation=True,stages=('mitigation',))
        conductor=Conductor(config=config)
        conductor.problem_id=TASK;conductor.register_agent(AGENT)

        class EvidencePhaseLedger(PhaseLedger):
            def record(self,phase,event,**fields):
                super().record(phase,event,**fields)
                if phase=='cleanup' and event=='start':
                    pre_cleanup_snapshot()

        conductor.phases=EvidencePhaseLedger(out/'native-phases.jsonl',context={
            'attempt_id':run_id,'problem_id':TASK,'agent':AGENT})
        launcher=AgentLauncher();launcher.set_internet_policy(policy);launcher.set_container_hardening(True)
        launcher.enable_container_isolation(image=os.environ['B0_AGENT_IMAGE'],k8s_proxy_port=16443)
        runner_config=launcher._container_runner.config
        runner_config.forward_host_credentials=False;runner_config.codex_auth='none'
        runner_config.published_ports=[];runner_config.sregym_apps_path=None;runner_config.sregym_app_subdirs=[]
        runner_config.cpus,runner_config.memory=4.0,'8g'
        incident_clock_identity=monotonic_clock_identity()
        save(out/'incident-clock-identity.json',incident_clock_identity)
        await conductor.start_problem()
        if monotonic_clock_identity()!=incident_clock_identity:
            raise RuntimeError('Incident visibility monotonic clock identity changed')
        if conductor.submission_stage!='mitigation' or not conductor.fault_injected:
            raise RuntimeError('Original mitigation incident not ready')
        ledger=[json.loads(line) for line in (out/'native-phases.jsonl').read_text().splitlines() if line]
        visible=[r['mono'] for r in ledger if r.get('phase')=='stage:mitigation' and r.get('event')=='start']
        if len(visible)!=1: raise RuntimeError('Initial incident visibility clock is ambiguous')
        conductor.agent_timeout_seconds=BUDGETS['agent_timeout_seconds']
        conductor.agent_deadline_monotonic=visible[0]+BUDGETS['agent_timeout_seconds']
        conductor.start_k8s_proxy()
        launcher.set_agent_kubeconfig(conductor.get_agent_kubeconfig_path())
        api_thread=threading.Thread(target=run_api,args=(conductor,),daemon=True);api_thread.start()
        api_origin='http://'+bridge+':8000'
        ready_deadline=time.monotonic()+45
        while True:
            try:
                public_status=read_http(api_origin,'/status')
                if public_status.get('stage')=='mitigation':break
            except OSError:pass
            if time.monotonic()>ready_deadline:raise TimeoutError('Original API unavailable')
            await asyncio.sleep(.25)
        save(out/'public-get-app.json',read_http(api_origin,'/get_app'))
        save(out/'public-status-before-agent.json',public_status)
        lifecycle=LedgerLifecycleGuard(attempt_id=run_id,agent_logs=agent_logs,evidence=out/'ledger-lifecycle-host',
            source_root=Path.cwd(),maximum_requests=BUDGETS['max_ledger_checks'])
        initial=lifecycle.initialize();lifecycle.start()
        nodes=subprocess.run(['kubectl','get','nodes','-o','json','--request-timeout=15s'],capture_output=True,text=True,timeout=20,check=True)
        node_identities=sorted((p['metadata']['name'],p['metadata']['uid']) for p in json.loads(nodes.stdout)['items'])
        physical_scope_id=hashlib.sha256(canonical({'namespace_uid':initial['namespace_uid'],'node_identities':node_identities})).hexdigest()
        save(out/'physical-scope-identity.json',{'attempt_id':run_id,'physical_scope_id':physical_scope_id,
            'namespace_uid':initial['namespace_uid'],'node_identities':node_identities})
        registration=AgentRegistration(name=AGENT,container_isolation=True,cluster_access=True,
            kickoff_command='/opt/native/bin/python -B /opt/b0/integration/agent_entry.py',kickoff_env={
                'API_PORT':'8000','MCP_SERVER_PORT':'9954','B0_ATTEMPT_ID':run_id,'B0_LOG_ROOT':'/logs',
                'SRE_NATIVE_API_URL':'http://host.docker.internal:8000',
                'SRE_NATIVE_MCP_URL':'http://host.docker.internal:9954',
                'SRE_NATIVE_ATTEMPT_ID':run_id,'SRE_NATIVE_ROLE':'script',
                'SRE_NATIVE_LOG_DIR':'/logs/native-transport','SRE_NATIVE_PYTHON':'/opt/native/bin/python'})
        process=await launcher.ensure_started(registration)
        if process is None or not process.container_name:raise RuntimeError('Native launcher did not create solver')
        state['solver_process_launched']=True
        inspection_deadline=time.monotonic()+30
        while True:
            try:
                inspection=inspect_agent_container(process.container_name,os.environ['B0_AGENT_IMAGE_ID'],agent_logs,
                    launcher._container_runner._egress._cert_volume)
                break
            except subprocess.CalledProcessError:
                if process.proc.poll() is not None or time.monotonic()>inspection_deadline:raise
                await asyncio.sleep(.2)
        save(out/'container-inspection.json',inspection)
        if not inspection['passed']:raise RuntimeError('Solver container boundary inspection failed')
        state['boundary_proof']=verify_native_boundary(process.container_name,out,agent_logs,inspection,run_id)
        if monotonic_clock_identity()!=incident_clock_identity:
            raise RuntimeError('Solver launch monotonic clock identity changed')
        launch={'schema':'b0-launch-context-v1','attempt_id':run_id,'namespace':'gitlab-ce',
            'namespace_uid':initial['namespace_uid'],'physical_scope_id':physical_scope_id,
            'ledger_epoch':initial['ledger_epoch'],'boundary_proof_sha256':sha_file(out/'host-retained-boundary-proof.json'),
            'budgets':BUDGETS,'incident_visible_mono':visible[0],'clock_identity':incident_clock_identity,
            'shared_capability_version':'public-actions-public-result-v1',
            'protocol_id':PROTOCOL,
            'mode':PLAN['mode'],'allowed_operations':PLAN['allowed_operations'],
            'transport_evidence_level':'native_filtered_execution',
            'host_guard_contract':'neutral lifecycle only; no provider state or effect answer',
            'reference_informed':True}
        save(out/'host-launch-context.json',launch);atomic(agent_logs/'b0-launch-context.json',launch)
        heartbeat=time.monotonic()
        while process.proc.poll() is None:
            if time.monotonic()>conductor.agent_deadline_monotonic:raise TimeoutError('B0 first-visibility budget exhausted')
            if time.monotonic()-heartbeat>=20:
                progress=agent_logs/'b0-progress.json'
                try: value=safe_json(progress,16384) if progress.exists() else {'stage':'running'}
                except Exception:value={'stage':'progress_unavailable'}
                print(json.dumps({'b0_progress':value,'elapsed_since_incident':time.monotonic()-visible[0]},ensure_ascii=False),flush=True)
                heartbeat=time.monotonic()
            await asyncio.sleep(.5)
        state['agent_process_exit_code']=process.proc.returncode
        state['internet_policy_result']=launcher.internet_policy_result(process)
        state['agent_result']=safe_json(agent_logs/'b0-agent-result.json')
        # The HTTP acknowledgement is not the result. Wait for the one original
        # evaluator and its native automatic cleanup, retaining the earlier
        # snapshot via the phase observer before privileged cleanup can repair.
        if conductor.close_submissions():
            await conductor.wait_for_submission_evaluations(timeout=900)
            await conductor.wait_for_submission_work(timeout=max(900,float(getattr(conductor.problem,'cleanup_timeout_seconds',900))))
        state['native_result_after_solver']=dict(conductor.results)
        agent=state['agent_result']
        state['submission_binding']=bind_submission(agent,agent_logs,run_id,launch)
        integrity=agent.get('execution_integrity') or {}
        final_actions=integrity.get('original_submission_actions')
        post_submit_closed=(integrity.get('status')=='verified'
            and integrity.get('accepted_original_submission_raw_verified') is True
            and integrity.get('accepted_original_submission_binding_error') is None
            and integrity.get('owned_unresolved_action_ids_at_exit')==[]
            and integrity.get('resource_locks_at_exit_excluding_original_evaluation')==[]
            and canonical(integrity.get('source_and_target_bindings'))==canonical(agent.get('evaluation_readiness'))
            and isinstance(final_actions,list) and len(final_actions)==1
            and final_actions[0].get('id')==state['submission_binding'].get('action_id')
            and final_actions[0].get('operation')=='final_submit'
            and final_actions[0].get('execution')=='running'
            and final_actions[0].get('effect')=='unknown'
            and final_actions[0].get('dispatch_epoch') is not None)
        state['acceptance_checks']={
            'original_full_task_unchanged':True,
            'container_boundary':inspection['passed'] is True,
            'native_boundary':state['boundary_proof'].get('native_filtered_boundary_verified') is True,
            'solver_process_completed':process.proc.returncode==0,
            'solver_declares_complete':agent.get('status')=='awaiting_original_host_evaluation',
            'no_controller_execution_error':agent.get('error') is None,
            'only_bound_original_final_pending_at_solver_exit':post_submit_closed,
            'independent_protocol_bound':state['submission_binding']['profile_binding_valid'],
            'original_submission_acceptance_receipt_present':state['submission_binding']['receipt_structure_valid'],
            'original_submission_raw_binding':state['submission_binding']['receipt_raw_binding_valid'],
            'execution_readiness_bound_to_original_request':state['submission_binding']['readiness_bound_to_original_request'],
            'agent_does_not_invent_original_result':'business_success' in agent and agent['business_success'] is None,
            'one_solver_submit':type(agent.get('submit_calls')) is int and agent['submit_calls']==1}
        # The final assessment runs below after every cleanup path, using only
        # the immutable pre-reference-cleanup snapshot. Late solver evidence is
        # retained separately and never substitutes for this normal ingestion.
    except BaseException as exc:
        state['b0_pass']=False;state['error']={'type':type(exc).__name__,'message':str(exc)}
        state.setdefault('classification','ENGINEERING_FAILURE')
        traceback.print_exc()
    finally:
        def cleanup_step(name,operation):
            try:
                operation();state['cleanup'].append({'operation':name,'passed':True});return True
            except BaseException as exc:
                state['cleanup'].append({'operation':name,'passed':False,'error':str(exc)});return False
        if conductor:
            cleanup_step('close_submissions',conductor.close_submissions)
            if conductor.missing_submission_stages():
                cleanup_step('record_incomplete_attempt',lambda:conductor.record_incomplete_attempt(
                    state.get('classification','b0_no_submission'),agent_return_code=state.get('agent_process_exit_code')))
            if conductor.close_submissions():
                try:
                    await conductor.wait_for_submission_work(timeout=max(900,float(getattr(conductor.problem,'cleanup_timeout_seconds',900))))
                    state['cleanup'].append({'operation':'wait_accepted_original_submission_work','passed':True})
                except BaseException as exc:
                    conductor.abandon_submission_work()
                    state['cleanup'].append({'operation':'wait_accepted_original_submission_work','passed':False,'error':str(exc)})
        if launcher:cleanup_step('stop_solver_and_egress',lambda:launcher.cleanup_all(timeout=30))
        stopped=cleanup_step('verify_owned_solver_removed',lambda:stop_owned_container(process.container_name if process else None))
        # A deadline exception can bypass normal result ingestion while the
        # solver has already written diagnostic evidence. Retain it separately:
        # late evidence must never become timely completion or an oracle result.
        state['solver_execution_evidence']={}
        for name in ('entrypoint-resource-before.json','entrypoint-execution.json','b0-agent-result.json'):
            path=agent_logs/name
            if not path.exists():continue
            try:
                value=safe_json(path)
                state['solver_execution_evidence'][name]={'sha256':sha_file(path),'document':value}
            except BaseException as exc:
                state['solver_execution_evidence'][name]={'read_error':type(exc).__name__+': '+str(exc)}
        execution=state['solver_execution_evidence'].get('entrypoint-execution.json',{}).get('document',{})
        state['solver_entrypoint_execution_observed']=(isinstance(execution,dict)
            and execution.get('scope')=='isolated deterministic baseline runtime'
            and type(execution.get('exit_code')) is int)
        state['agent_result_ingested_in_normal_path']='agent_result' in state
        state['diagnostic_evidence_changes_runtime_verdict']=False
        if conductor and conductor.problem is not None and stopped:
            try:
                fut=conductor.finish_problem_in_background()
                await asyncio.wait_for(asyncio.wrap_future(fut),timeout=max(900,float(getattr(conductor.problem,'cleanup_timeout_seconds',900))))
                state['cleanup'].append({'operation':'original_reference_lifecycle_cleanup','passed':not conductor.results.get('cleanup_failed',False)})
            except BaseException as exc:
                conductor.abandon_submission_work()
                state['cleanup'].append({'operation':'original_reference_lifecycle_cleanup','passed':False,'error':str(exc)})
            cleanup_step('save_final_native_result',lambda:save(out/'native-result-after-cleanup.json',conductor.results))
        if lifecycle:cleanup_step('stop_owned_lifecycle_guard',lifecycle.stop)
        if api_thread:
            from sregym.conductor.conductor_api import request_shutdown
            cleanup_step('request_api_shutdown',request_shutdown)
            cleanup_step('join_api_thread',lambda:api_thread.join(timeout=15))
        if conductor:
            cleanup_step('stop_mcp_forward',conductor.mcp_server.stop_port_forward)
            cleanup_step('stop_k8s_proxy',conductor.stop_k8s_proxy)
        cleanup_step('remove_owned_ingress_after_listeners',ingress.remove_after_listeners_stop)
        state['elapsed_seconds']=time.monotonic()-started
        state['cleanup_passed']=bool(state['cleanup']) and all(x['passed'] for x in state['cleanup'])
        try:
            original=retain_original(out,run_id)
        except BaseException as exc:
            original={'original_mitigation_success':None,'original_result_source':None,
                      'original_result_source_sha256':None,'original_result_type_valid':False,
                      'pre_cleanup_source_identity_valid':False,'pre_cleanup_snapshot_order_valid':False,
                      'ledger_continuous_before_reference_cleanup':False,
                      'original_evaluation_start_count':None,'original_evaluation_end_count':None,
                      'timing':{'valid':False,'seconds':None},
                      'source_errors':[type(exc).__name__+': '+str(exc)]}
            state['original_result_retention_error']=original['source_errors'][0]
        state['original_evaluation']=original
        state['original_mitigation_success']=original['original_mitigation_success']
        state['timing']=original['timing']
        checks=state.setdefault('acceptance_checks',{'normal_solver_ingestion_and_submission_binding':False})
        checks.update({
            'original_evaluation_boolean_result':type(original['original_mitigation_success']) is bool,
            'one_original_evaluation':original['original_evaluation_start_count']==1
                and original['original_evaluation_end_count']==1,
            'one_valid_full_clock':original['timing']['valid'] is True,
            'original_result_type_valid':original['original_result_type_valid'] is True,
            'pre_cleanup_source_identity_valid':original['pre_cleanup_source_identity_valid'] is True,
            'pre_cleanup_snapshot_order_valid':original['pre_cleanup_snapshot_order_valid'] is True,
            'ledger_continuous_before_reference_cleanup':original['ledger_continuous_before_reference_cleanup'] is True,
            'pre_cleanup_evidence_saved':bool(original['original_result_source_sha256'])
                and not original['source_errors'] and not state.get('pre_cleanup_snapshot_error')
                and not state.get('pre_cleanup_guard_error')})
        state['attempt_valid']=all(value is True for value in checks.values())
        state['passed']=state['attempt_valid'] and state['cleanup_passed'] and not state.get('error')
        state['valid_complete_attempt']=state['passed']
        state['b0_pass']=state['passed'] and original['original_mitigation_success'] is True
        state['qualified_original_success']=None if state['b0_pass'] else False
        state['independent_original_artifact_review']='pending'
        state['classification']=classification(original['original_mitigation_success'],state['passed'])
        agent=state.get('agent_result') or {}
        snapshot=agent.get('public_business_snapshot')
        assurance=agent.get('additional_assurance')
        state['public_business_snapshot']=snapshot if isinstance(snapshot,dict) else {
            'status':'incomplete','reason':'normal_controller_snapshot_not_available'}
        state['additional_assurance']=assurance if isinstance(assurance,dict) else {
            'historical_terminal_required':False,'historical_terminal_proof':{'status':'not_evaluated'},
            'reason':'normal_controller_assurance_not_available'}
        public_status=state['public_business_snapshot'].get('status')
        raw=original['original_mitigation_success']
        state['public_check_oracle_disagreement']=(type(raw) is bool
            and ((raw is True and public_status=='known_fail') or (raw is False and public_status=='pass')))
        state['submission_resolution']={
            'schema':'b0-public-result-original-evaluation-resolution-v1','protocol_id':PROTOCOL,
            'attempt_id':run_id,'agent_has_seen_original_oracle_result':False,
            'original_evaluation':original,
            'execution_integrity':{'checks':checks,'valid_complete_attempt':state['passed'],
                'submission_binding':state.get('submission_binding'),
                'independent_registry_and_native_transport_review':'pending'},
            'public_business_snapshot':state['public_business_snapshot'],
            'additional_assurance':state['additional_assurance'],
            'qualified_original_success':state['qualified_original_success'],
            'independent_original_artifact_review':'pending'}
        save(out/'original-evaluation-host-resolution.json',state['submission_resolution'])
        save(out/'b0-native-result.json',state)
    return 0 if state.get('passed') else 1

if __name__=='__main__':raise SystemExit(asyncio.run(main()))
