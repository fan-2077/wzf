"""Native 8B role-collaboration integration pilot, NOT a new traffic benchmark.
The task is the disclosed, exhaustively solved development regression.
All modes share original AIOS managers, SDK, tools, model, CPU and budgets.
No-feedback and single modes are architecture ablations, not speed baselines.
A fresh model/kernel/tool server is started for every mode. Setup is excluded
identically from service task latency and recorded separately. One run/mode
cannot establish a performance distribution or contest compliance.
"""
from pathlib import Path
import concurrent.futures, copy, json, math, os, shutil, signal, sys, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import native_run as n
ROOT=n.ROOT;RESULTS=n.OUT;SUITE=RESULTS/'comparison';SUITE.mkdir(parents=True,exist_ok=True)
ROLES={
 'event':'Check incident provenance, state versions and what remains unverified before real execution.',
 'network':'Check network queue constraints; reject faster but infeasible options; examine numerical evidence.',
 'signal':'Check the signal-policy choices, their dependence on a route, and what is measured versus commanded.',
 'route':'Check destination and route requirements; identify the fastest feasible option and needed execution evidence.'}
LIMIT={'model_calls':16,'requested_output_tokens':3072,'candidate_simulations':9,'terminal_replay':1}
STATE={'mode':None,'dir':None,'records':[],'lock':threading.Lock()}

def write(p,obj):
    p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(obj,indent=2,ensure_ascii=False,allow_nan=False))
def optimal_ids(rows):
    feasible=[r for r in rows if r['passed']]
    if not feasible:return []
    t=min(r['elapsed_sim_s'] for r in feasible)
    tied=[r for r in feasible if math.isclose(r['elapsed_sim_s'],t,rel_tol=0,abs_tol=1e-9)]
    q=min(r['mean_queue'] for r in tied)
    return sorted(r['candidate_id'] for r in tied if math.isclose(r['mean_queue'],q,rel_tol=0,abs_tol=1e-9))
def parse(text):
    value=json.loads(text)
    if not isinstance(value,dict):raise ValueError('JSON object required')
    return value

class Capture(BaseHTTPRequestHandler):
    def forward(self):
        data=self.rfile.read(int(self.headers.get('Content-Length','0'))) if self.command=='POST' else None
        begin=time.monotonic();status=500;body=b''
        try:
            request=urllib.request.Request('http://127.0.0.1:18080'+self.path,data=data,method=self.command,headers={'Content-Type':'application/json'})
            with urllib.request.urlopen(request,timeout=600) as response:body=response.read();status=response.status
        except Exception as e:body=json.dumps({'error':type(e).__name__,'detail':str(e)}).encode()
        record={'method':self.command,'path':self.path,'start_monotonic':begin,'end_monotonic':time.monotonic(),'status':status}
        if data:
            try:record['request']=json.loads(data)
            except Exception:record['request_decode_failed']=True
        try:record['response']=json.loads(body)
        except Exception:record['response_decode_failed']=True
        with STATE['lock']:
            STATE['records'].append(record)
            with (STATE['dir']/'backend.jsonl').open('a') as f:f.write(json.dumps(record,ensure_ascii=False)+'\n')
        self.send_response(status);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(body)
    do_GET=forward;do_POST=forward
    def log_message(self,*args):pass

class ModelBudget:
    def __init__(self):self.lock=threading.Lock();self.calls=0;self.requested=0;self.records=[]
    def ask(self,role,messages,max_tokens):
        with self.lock:
            if self.calls>=LIMIT['model_calls'] or self.requested+max_tokens>LIMIT['requested_output_tokens']:raise RuntimeError('shared model budget exhausted')
            self.calls+=1;self.requested+=max_tokens
        text,record=n.model(role,messages,max_tokens)
        with self.lock:self.records.append(record)
        with STATE['lock']:
            with (STATE['dir']/'model_trace.jsonl').open('a') as f:f.write(json.dumps(record,ensure_ascii=False)+'\n')
        return text,parse(text)

GENERAL=('Work only on the disclosed traffic regression. All roles have identical access to case and candidate evidence. '
 'Goal: among feasible candidates minimize elapsed_sim_s, then mean_queue. Exact ties are equally optimal. '
 'Do not invent numbers or claim execution before verify_execution. Candidate scores are public simulation evidence, not a hidden judge. '
 'Use the tool observations rather than voting. This fixed nine-option task is already solvable by a deterministic script; do not claim agent necessity.')

def business(operation,args,trace):
    response,record=n.tool('comparison_'+STATE['mode'],operation,args);trace.append(record)
    with (STATE['dir']/'tool_trace.jsonl').open('a') as f:f.write(json.dumps(record,ensure_ascii=False)+'\n')
    return response

def single(budget,trace):
    instructions=(GENERAL+' You are one fully equipped agent with all four professional responsibilities: '+json.dumps(ROLES)+
      ' Return one JSON object per turn: {"tool":"get_case","arguments":{}}. Allowed tools and schemas: get_case({}), evaluate_candidates({}), '
      'execute_plan({"candidate_id":"<id from evidence>","expected_version":0}), verify_execution({}), finish({}). '
      'Use actual current version. evaluate_candidates runs all nine options. execute_plan runs a fresh verification replay. '
      'Get case and evidence, choose, execute, verify, then finish. You may call any of these tools; no hidden restrictions.')
    messages=[{'role':'system','content':instructions},{'role':'user','content':'Handle the case now. /no_think'}]
    for step in range(12):
        text,a=budget.ask('strong_single',messages,192);messages.append({'role':'assistant','content':text})
        if set(a)!={'tool','arguments'} or not isinstance(a['arguments'],dict):result={'ok':False,'error':'exact tool/arguments object required'}
        elif a['tool'] not in {'get_case','evaluate_candidates','execute_plan','verify_execution','finish'}:result={'ok':False,'error':'unknown tool'}
        else:result=business(a['tool'],a['arguments'],trace)
        messages.append({'role':'user','content':json.dumps(result)})
        if a.get('tool')=='finish' and result.get('ok'):return {'completed':True,'messages':messages}
    return {'completed':False,'messages':messages,'failure':'turn_limit'}

def team(mode,budget,trace):
    case=business('get_case',{},trace);evidence=business('evaluate_candidates',{},trace)
    dossier=json.dumps({'case':case,'candidate_evidence':evidence},separators=(',',':'))
    contexts={};initial={};replies={}
    def initial_role(role):
        messages=[{'role':'system','content':GENERAL+' Your independent responsibility is '+ROLES[role]+' Other roles: '+json.dumps(ROLES)+
          ' Return JSON keys candidate_id, evidence, unresolved, request_to, question. request_to is another role or null. '
          'Ask a peer only a specific question that could change a decision. Do not ask for pointless approval. Under 100 words.'},
          {'role':'user','content':dossier+' /no_think'}]
        text,value=budget.ask(role,messages,192);messages.append({'role':'assistant','content':text});contexts[role]=messages;return role,value
    def apply(fn):
        if mode=='multi_serial':return [fn(r) for r in ROLES]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:return list(ex.map(fn,ROLES))
    for role,value in apply(initial_role):initial[role]=value
    write(STATE['dir']/'initial_positions.json',initial)
    requests=[]
    for src,v in initial.items():
        dst=v.get('request_to');q=v.get('question')
        if dst in ROLES and dst!=src and isinstance(q,str) and q.strip():requests.append({'from':src,'to':dst,'question':q})
    if mode!='no_feedback':
        def peer_role(role):
            incoming=[r for r in requests if r['to']==role]
            msg={'peer_positions':initial,'incoming_requests':incoming,'instruction':'Review actual peer evidence. Answer incoming requests with answers as {peer_role:answer}; revise your candidate only when justified. Return JSON keys candidate_id, answers, changed, reason. Do not fabricate changed work. Under 120 words.'}
            contexts[role].append({'role':'user','content':json.dumps(msg)+' /no_think'})
            text,value=budget.ask(role,contexts[role],240);contexts[role].append({'role':'assistant','content':text});return role,value
        for role,value in apply(peer_role):replies[role]=value
        # Deliver peer replies to requester contexts; no synthetic acknowledgement.
        for r in requests:
            answer=replies.get(r['to'],{}).get('answers',{})
            if isinstance(answer,dict) and r['from'] in answer:
                contexts[r['from']].append({'role':'user','content':json.dumps({'reply_from':r['to'],'question':r['question'],'answer':answer[r['from']]})})
    bundle={'initial_positions':initial,'requests':requests,'peer_replies':replies}
    write(STATE['dir']/'collaboration_messages.json',bundle);write(STATE['dir']/'contexts.json',contexts)
    final_messages=[{'role':'system','content':GENERAL+' Act as the team execution synthesizer. Return JSON keys candidate_id, expected_version, justification. Use all actual evidence; peer majority is not an acceptance rule. Under 100 words.'},
                    {'role':'user','content':dossier+'\n'+json.dumps(bundle)+' /no_think'}]
    _,decision=budget.ask('team_execution_synthesizer',final_messages,192)
    execution=business('execute_plan',{'candidate_id':decision.get('candidate_id'),'expected_version':decision.get('expected_version')},trace)
    verification=business('verify_execution',{},trace) if execution.get('ok') else None
    finished=business('finish',{},trace)
    return {'completed':bool(finished.get('ok')),'decision':decision,'execution':execution,'verification':verification,'collaboration':bundle,
            'scope':'four role contexts plus a synthesizer; initial parallel phases and one peer-review exchange are harness-scheduled, not autonomous task decomposition'}

def stop_services():
    for p in reversed(n.PROCESSES):
        if p.poll() is None:
            os.killpg(p.pid,signal.SIGTERM)
            try:p.wait(timeout=8)
            except Exception:os.killpg(p.pid,signal.SIGKILL);p.wait()
    n.PROCESSES.clear()
    for f in n.HANDLES:f.close()
    n.HANDLES.clear()

def run_mode(mode):
    directory=SUITE/mode;directory.mkdir(exist_ok=False);STATE.update(mode=mode,dir=directory,records=[])
    trafficdir=RESULTS/'traffic'
    if trafficdir.exists():raise RuntimeError('Do not reuse mutable traffic state')
    budget=ModelBudget();trace=[];result={'mode':mode,'declared_budget':LIMIT,'repetitions':1,'error':None};setup_start=time.monotonic();task_started=None
    proxy=ThreadingHTTPServer(('127.0.0.1',18084),Capture);threading.Thread(target=proxy.serve_forever,daemon=True).start()
    try:
        binary=next((ROOT/'bin').rglob('llama-server'))
        server=n.start([str(binary),'-m',str(ROOT/'model/Qwen3-8B-Q4_K_M.gguf'),'--host','127.0.0.1','--port','18080','-t','4','-tb','4','-c','16384','-np','4','-ngl','0','--jinja','--chat-template-kwargs','{"enable_thinking":false}','--alias','qwen3-8b'],str(directory.relative_to(RESULTS)/'llama.log'))
        n.wait('http://127.0.0.1:18080/health',server,240)
        traffic=n.start([sys.executable,str(ROOT/'experiments/traffic_regression.py')],str(directory.relative_to(RESULTS)/'traffic.log'))
        n.wait('http://127.0.0.1:18083/health',traffic,60)
        env=dict(n.ENV);env['PYTHONPATH']=str(ROOT/'upstream/AIOS_compat')
        kernel=n.start([sys.executable,'-m','runtime.launch'],str(directory.relative_to(RESULTS)/'aios.log'),cwd=ROOT/'upstream/AIOS_compat',env=env)
        n.wait(n.BASE+'/core/llms/list',kernel,240)
        result['setup_seconds']=time.monotonic()-setup_start;task_started=time.monotonic()
        result['task']=single(budget,trace) if mode=='single' else team(mode,budget,trace)
    except Exception as e:result['error']={'type':type(e).__name__,'message':str(e)}
    finally:
        if task_started is not None:result['full_service_task_seconds']=time.monotonic()-task_started
        stop_services();proxy.shutdown();proxy.server_close()
        result['model_calls']=budget.calls;result['requested_output_tokens']=budget.requested
        records=STATE['records'];calls=[r for r in records if r['path'].endswith('/chat/completions')]
        result['backend_calls']=len(calls)
        result['usage']={k:sum(r.get('response',{}).get('usage',{}).get(k,0) for r in calls) for k in ['prompt_tokens','completion_tokens','total_tokens']}
        result['finish_reasons']=[c.get('finish_reason') for r in calls for c in r.get('response',{}).get('choices',[])]
        if trafficdir.exists():
            candidate=trafficdir/'candidate_evidence.json';selected=trafficdir/'selected_execution.json';verified=trafficdir/'verification.json'
            if candidate.exists() and selected.exists() and verified.exists():
                rows=json.loads(candidate.read_text());sel=json.loads(selected.read_text());ids=optimal_ids(rows);v=json.loads(verified.read_text())
                result['independent_objective_audit']={'feasible':v['passed'],'replay_identical':v['independent_replay_identical'],'optimal_candidate_ids':ids,'selected_id':sel['candidate_id'],'optimal_objective':sel['candidate_id'] in ids,'elapsed_sim_s':sel['elapsed_sim_s'],'mean_queue':sel['mean_queue'],'queue_change_percent':v['queue_change_percent']}
            shutil.move(str(trafficdir),str(directory/'traffic'))
        write(directory/'summary.json',result)
    print(mode,json.dumps({k:v for k,v in result.items() if k!='task'},ensure_ascii=False),flush=True);return result

def main():
    import yaml
    config=ROOT/'upstream/AIOS_compat/aios/config/config.yaml';data=yaml.safe_load(config.read_text())
    data['llms']['models'][0]['hostname']='http://127.0.0.1:18084/v1';config.write_text(yaml.safe_dump(data,sort_keys=False))
    source=ROOT/'experiments/traffic_regression.py';a=source.read_text();old="r['candidate_id']==best['candidate_id']"
    assert a.count(old)==1
    b=a.replace(old,"(abs(r['elapsed_sim_s']-best['elapsed_sim_s'])<=1e-9 and abs(r['mean_queue']-best['mean_queue'])<=1e-9)")
    source.write_text(b)
    import difflib
    (RESULTS/'tie_objective.patch').write_text(''.join(difflib.unified_diff(a.splitlines(True),b.splitlines(True),'before/traffic_regression.py','executed/traffic_regression.py')))
    # Frozen pilot order: not a repeated or randomized performance study.
    order=['single','multi_parallel','no_feedback','multi_serial'];write(SUITE/'protocol.json',{'order':order,'budget':LIMIT,'shared_information':True,'setup_excluded_identically':True,'fresh_server_per_mode':True,'task':'already solved static development regression','scope':'integration and coordination-cost pilot; no contest compliance claim','output_format':'JSON via native LLM query; no mocked model responses'})
    outcomes=[run_mode(mode) for mode in order]
    rows=[{k:v for k,v in o.items() if k!='task'} for o in outcomes];summary={'modes':rows,'competition_speedup_proven':False,'multiagent_necessity_proven':False,'repetitions_per_mode':1}
    by={r['mode']:r for r in rows}
    if all(by[m].get('full_service_task_seconds') and not by[m]['error'] for m in ['multi_serial','multi_parallel']):
        summary['observed_pilot_time_reduction']=1-by['multi_parallel']['full_service_task_seconds']/by['multi_serial']['full_service_task_seconds']
    write(SUITE/'summary.json',summary)
    if any(o['error'] or not o.get('task',{}).get('completed') for o in outcomes):raise SystemExit(1)
if __name__=='__main__':main()
