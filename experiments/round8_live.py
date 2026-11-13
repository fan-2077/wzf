"""Bounded native 8B protocol integration, NOT an efficiency benchmark.
Four role contexts share weights and public information. Request paths are scripted.
"""
from __future__ import annotations
from pathlib import Path
import concurrent.futures,json,os,signal,threading,time,sys
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import native_run as n
from round8_task import DecisionGate,ContractError,forecast_rows,simulate,expected_scores,save,canonical
from round8_feedback import Ledger
ROOT=n.ROOT;OUT=ROOT/'results/round8';OUT.mkdir(parents=True,exist_ok=True)
CASES=[{'id':'A','prior':'short','update':'long','truth':750},{'id':'B','prior':'long','update':'short','truth':180},{'id':'C','prior':'short','update':'ambiguous','truth':450},{'id':'D','prior':'long','update':'short','truth':900}]
ROLES={'event':'Review estimate sources, uncertainty and state freshness.','route':'Review legal route commitments and expected arrival cost.','network':'Review expected queue constraint and external network impact.','signal':'Review controller compatibility; temporary blockage does not make a route permanently impossible.'}
FORMAT={'version':1,'policy':'wait or reroute','evidence_ids':['copy exact CURRENT ids'],'reason':'one short evidence-based sentence'}
TRACE=[];LOCK=threading.RLock();CASE=None;GATE=None;RAW=None;VERIFIED=False;UPDATES=0;EXECUTIONS=0;CURRENT_DIR=None

def public():
    d=GATE.public();scores=expected_scores(GATE.rows,GATE.weights)
    d['calculator']={p:scores[p] for p in ['wait','reroute']}
    d['route_and_signal_facts']={'first_movement_preserved':True,'both_policies_native_feasible_under_forecast_scenarios':True,'fault_is_temporary':True,'remaining_actual_duration':'not disclosed'}
    return d

def handle(op,args):
    global RAW,VERIFIED,UPDATES,EXECUTIONS
    if op=='get_case':return {'ok':True,'public':public()}
    if op=='publish_update':
        if UPDATES:raise ContractError('update already published')
        GATE.update(CASE['update']);UPDATES+=1;return {'ok':True,'public':public(),'notice':'scripted forecast update, simulator remains at decision snapshot 705'}
    if op=='execute_plan':
        receipt=GATE.commit(args);EXECUTIONS+=1
        RAW=simulate(CASE['truth'],receipt['policy'],CURRENT_DIR/'realized_execution.json')
        return {'ok':True,'receipt':receipt,'note':'execution completed, requires independent result readback'}
    if op=='verify_execution':
        if RAW is None:raise ContractError('no execution')
        raw=json.loads((CURRENT_DIR/'realized_execution.json').read_text());VERIFIED=raw['passed']
        return {'ok':True,'verified':VERIFIED,'arrival':raw['arrival'],'mean_queue':raw['mean_queue'],'route_exact':raw['route_exact'],'phase_enforced':raw['phase_enforced'],'destination_reached':raw['destination_reached']}
    if op=='finish':return {'ok':VERIFIED,'finished':VERIFIED}
    raise ContractError('unknown operation')

class Service(BaseHTTPRequestHandler):
    def do_GET(self):self.send_response(200);self.end_headers();self.wfile.write(b'{"ready":true}')
    def do_POST(self):
        req={}
        try:
            req=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            if set(req)!={'operation','arguments'}:raise ContractError('RPC schema')
            with LOCK:answer=handle(req['operation'],req['arguments'])
        except Exception as e:answer={'ok':False,'error':type(e).__name__,'detail':str(e)}
        row={'request':req,'response':answer,'wall_time':time.time()}
        with LOCK:
            if CURRENT_DIR:
                with (CURRENT_DIR/'tool_rpc.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
        self.send_response(200);self.end_headers();self.wfile.write(json.dumps(answer).encode())
    def log_message(self,*a):pass

def ask(role,context,question,validate=None):
    context.append({'role':'user','content':question+' /no_think'})
    for attempt in range(2):
        text,record=n.model(role,context,192);context.append({'role':'assistant','content':text});row={'role':role,'attempt':attempt,'record':record}
        try:
            obj=json.loads(text)
            if not isinstance(obj,dict):raise ValueError('object required')
            if validate:validate(obj)
            row['accepted']=True;row['parsed']=obj
        except Exception as e:
            row['accepted']=False;row['validation_error']=str(e)
            context.append({'role':'user','content':'Format/evidence validation failed: '+str(e)+'. Correct the JSON using the same public facts; no answer is supplied.'})
        with LOCK:
            TRACE.append(row)
            with (CURRENT_DIR/'model_trace.jsonl').open('a') as f:f.write(json.dumps(row,ensure_ascii=False)+'\n')
        if row['accepted']:return obj
    raise RuntimeError('model response rejected after one format repair: '+role)

def context(role):
    return [{'role':'system','content':'You are the '+role+' specialist in a SIMULATION-only integration test. '+ROLES.get(role,'Perform all four professional reviews yourself.')+' Use only current public evidence. Both policies may be physically feasible. Minimize expected arrival under the supplied probability distribution subject to queue cap; do not pretend expected optimum guarantees the realized fastest arrival. Return compact JSON only. No unobserved experiment claims. Evidence IDs and versions must match exactly. Public calculator numbers are deterministic tools available to every mode.'}]

def artifact_check(obj):
    if type(obj.get('version')) is not int or obj['version']!=GATE.version:raise ValueError('stale artifact version')
    if obj.get('policy') not in ['wait','reroute']:raise ValueError('policy must be wait or reroute')
    if set(obj.get('evidence_ids',[]))!=set(GATE.public()['evidence_ids']):raise ValueError('use current registered evidence ids')
    if not isinstance(obj.get('reason'),str) or not obj['reason']:raise ValueError('reason required')

def plan(obj):return {'task_id':GATE.task_id,'version':obj['version'],'policy':obj['policy'],'evidence_ids':obj['evidence_ids']}
def tool(op,args=None):
    response,record=n.tool('round8_'+(CASE['id'] if CASE else 'unknown'),op,args or {})
    save(CURRENT_DIR/f'tool_{len(list(CURRENT_DIR.glob("tool_*.json"))):03d}_{op}.json',record);return response

def stale_probe(old):
    before=EXECUTIONS;response=tool('execute_plan',plan(old))
    if response.get('ok') or EXECUTIONS!=before or GATE.executed:raise AssertionError('stale action was executed')
    save(CURRENT_DIR/'stale_rejection.json',{'response':response,'executions_before':before,'executions_after':EXECUTIONS,'scope':'harness-submitted old plan, not counted as model mistake'})

def single():
    ctx=context('single');d=tool('get_case')['public']
    first=ask('single',ctx,'Initial assessment: '+canonical(d)+' Output schema '+canonical(FORMAT),artifact_check)
    updated=tool('publish_update')['public'];stale_probe(first)
    second=ask('single',ctx,'A new estimate supersedes the old one: '+canonical(updated)+'. Reassess and return the same schema.',artifact_check)
    return first,second,{'contexts':{'single':ctx},'scope':'one fully informed model; calculator and all evidence available'}

def team():
    d=tool('get_case')['public'];ledger=Ledger(GATE.task_id,ROLES);ledger.set_evidence(d)
    contexts={r:context(r) for r in ROLES};initial={}
    def one(role):
        obj=ask(role,contexts[role],'Initial professional assessment: '+canonical(d)+' Schema '+canonical(FORMAT),artifact_check);return role,obj
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for role,obj in pool.map(one,ROLES):initial[role]=obj;ledger.artifact(role+'_v1',role,obj)
    updated=tool('publish_update')['public'];ledger.set_evidence(updated);stale_probe(initial['route'])
    paths=[('route','event','Recheck recovery estimate and expected policy; distinguish uncertainty from known future.'),('network','route','Recheck expected arrival and legal path; is the original route permanently impossible?'),('signal','network','Recheck whether expected network queue cap rejects either policy; cite the current evidence.')]
    for i,(requester,responder,question) in enumerate(paths,1):
        rid=f'q{i}';pid=f'r{i}';subject=requester+'_v1'
        req=ledger.request(rid,requester,responder,subject,question,updated['evidence_ids'],revalidate=True)
        reply_schema={'request_id':rid,'version':2,'evidence_ids':updated['evidence_ids'],'answer':'brief evidence-based answer'}
        def reply_check(obj):
            if obj.get('request_id')!=rid or obj.get('version')!=GATE.version or set(obj.get('evidence_ids',[]))!=set(updated['evidence_ids']) or not obj.get('answer'):raise ValueError('reply id/version/evidence/answer invalid')
        rep=ask(responder,contexts[responder],'Peer request '+canonical(req)+' Current public facts '+canonical(updated)+' Return '+canonical(reply_schema),reply_check)
        record=ledger.reply(pid,rid,responder,requester,rep);schema=dict(FORMAT,version=2,consumed_request_id=rid)
        def revision_check(obj):
            artifact_check(obj)
            if obj.get('consumed_request_id')!=rid:raise ValueError('must identify consumed request')
        rev=ask(requester,contexts[requester],'Consume this actual peer reply '+canonical(record)+' Current public facts '+canonical(updated)+' Revalidate your old artifact; return '+canonical(schema),revision_check)
        ledger.artifact(requester+'_v2',requester,rev,subject,pid);save(CURRENT_DIR/'ledger.partial.json',ledger.snapshot())
    obj=ask('route',contexts['route'],'Finalize the executable policy from current public facts and actual peer records. '+canonical(updated)+' Peer revisions: '+canonical({k:v for k,v in ledger.snapshot()['artifacts'].items() if v['version']==2})+' Return '+canonical(FORMAT),artifact_check)
    return initial['route'],obj,{'ledger':ledger.snapshot(),'contexts':contexts,'scope':'four role contexts; three scripted request-reply-consume paths; no autonomous decomposition or causal-benefit claim'}

def run_case(case,mode,rows):
    global CASE,GATE,RAW,VERIFIED,UPDATES,EXECUTIONS,CURRENT_DIR,TRACE
    CASE=dict(case);GATE=DecisionGate(case['id'],rows,case['prior']);RAW=None;VERIFIED=False;UPDATES=0;EXECUTIONS=0;TRACE=[]
    CURRENT_DIR=OUT/(case['id']+'_'+mode);CURRENT_DIR.mkdir(exist_ok=False)
    result={'case':{k:v for k,v in case.items() if k!='truth'},'mode':mode,'error':None,'single_repetition':True};begin=time.monotonic()
    try:
        first,last,details=single() if mode=='single' else team()
        result['initial']=first;result['final']=last;result['details']=details
        execution=tool('execute_plan',plan(last));result['execution_receipt']=execution
        if not execution.get('ok'):raise RuntimeError('final action rejected: '+canonical(execution))
        result['verification']=tool('verify_execution');result['completed']=bool(tool('finish')['ok'])
        result['expected_optimal']=last['policy']==expected_scores(rows,GATE.weights)['best']
    except Exception as e:result['error']={'type':type(e).__name__,'message':str(e)};result['completed']=False
    result['service_seconds_including_model_and_execution']=time.monotonic()-begin;result['model_attempts']=len(TRACE);result['native_executions']=EXECUTIONS
    result['no_hidden_future_in_model_prompts']=not any('"truth"' in canonical(x['record']['request']) or '"duration":'+str(case['truth'])+',' in canonical(x['record']['request']) for x in TRACE)
    if RAW:
        opposite='reroute' if RAW['policy']=='wait' else 'wait';other=simulate(case['truth'],opposite,CURRENT_DIR/'judge_only_counterfactual.json')
        result['hindsight_judge']={'realized_duration':case['truth'],'chosen_arrival':RAW['arrival'],'other_arrival':other['arrival'],'arrival_regret':max(0,RAW['arrival']-other['arrival']),'scope':'offline hindsight, not policy information or task-time component'}
    save(CURRENT_DIR/'summary.json',result);print(case['id'],mode,result['completed'],result.get('expected_optimal'),result['error'],flush=True)
    return {k:v for k,v in result.items() if k!='details'}

def main():
    save(OUT/'frozen_protocol.json',{'cases':CASES,'scope':'synthetic estimate-update cases, one roadnet/vehicle; truth evaluator-only; no generalization or speed claim','team_paths':'scripted 3 pair revalidation after update','model':'official pinned Qwen3-8B Q4_K_M via native AIOS','forecast_work_shared_by_modes':True})
    t=time.monotonic();rows=forecast_rows(OUT/'forecast_tools');save(OUT/'forecast_rows.json',rows);save(OUT/'forecast_cost.json',{'seconds':time.monotonic()-t})
    service=ThreadingHTTPServer(('127.0.0.1',18083),Service);threading.Thread(target=service.serve_forever,daemon=True).start();results=[]
    try:
        binary=next((ROOT/'bin').rglob('llama-server'));weight=ROOT/'model/Qwen3-8B-Q4_K_M.gguf'
        model_server=n.start([str(binary),'-m',str(weight),'--host','127.0.0.1','--port','18080','-t','4','-tb','4','-c','16384','-np','4','-ngl','0','--jinja','--chat-template-kwargs','{"enable_thinking":false}','--alias','qwen3-8b'],'round8_llama.log');n.wait('http://127.0.0.1:18080/health',model_server,240)
        env=dict(n.ENV);env['PYTHONPATH']=str(ROOT/'upstream/AIOS_compat')
        kernel=n.start([sys.executable,'-m','runtime.launch'],'round8_aios.log',cwd=ROOT/'upstream/AIOS_compat',env=env);n.wait(n.BASE+'/core/llms/list',kernel,240)
        for case in CASES:results.append(run_case(case,'single',rows))
        results.append(run_case(CASES[0],'team',rows))
    finally:
        for p in reversed(n.PROCESSES):
            if p.poll() is None:
                os.killpg(p.pid,signal.SIGTERM)
                try:p.wait(timeout=10)
                except Exception:os.killpg(p.pid,signal.SIGKILL);p.wait()
        for f in n.HANDLES:f.close()
        service.shutdown();service.server_close()
        save(OUT/'summary.json',{'results':results,'competition_speedup_proven':False,'multiagent_necessity_proven':False,'new_native_model_runs':True,'independent_research_subagents':False,'scope':'actual 8B role contexts, not separate hosted research agents'})
    if not results or any(not r['completed'] for r in results):raise SystemExit(1)
if __name__=='__main__':main()
