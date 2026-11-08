"""AI-assisted integration probe; not an agent superiority or speed benchmark.
Starts only ephemeral loopback services on a bounded CI runner. All model and
business tool calls go through the native SDK and original AIOS managers.
"""
from pathlib import Path
import concurrent.futures, copy, json, os, signal, subprocess, sys, time, urllib.request
ROOT=Path.cwd().resolve();OUT=ROOT/'results';OUT.mkdir(exist_ok=True)
ENV=dict(os.environ)
for key in ['OPENAI_API_KEY','ANTHROPIC_API_KEY','GROQ_API_KEY','GEMINI_API_KEY','GOOGLE_API_KEY','HF_TOKEN','HF_AUTH_TOKEN','HUGGING_FACE_HUB_TOKEN']:ENV.pop(key,None)
ENV.update({'XDG_CACHE_HOME':str(ROOT/'isolated/cache'),'ANONYMIZED_TELEMETRY':'False','HF_HUB_DISABLE_TELEMETRY':'1','TOKENIZERS_PARALLELISM':'false','OMP_NUM_THREADS':'1','LITELLM_LOCAL_MODEL_COST_MAP':'True','PYTHONUNBUFFERED':'1','NO_PROXY':'localhost,127.0.0.1'})
BASE='http://127.0.0.1:18082';PROCESSES=[];HANDLES=[]
def save(name,value):
    p=OUT/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False))
def start(cmd,log,cwd=ROOT,env=ENV):
    f=(OUT/log).open('w');HANDLES.append(f);p=subprocess.Popen(cmd,cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT,start_new_session=True);PROCESSES.append(p);return p

def wait(url,proc,seconds):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        if proc.poll() is not None:raise RuntimeError('Service exited: '+url)
        try:
            with urllib.request.urlopen(url,timeout=2) as r:return json.load(r)
        except Exception:time.sleep(1)
    raise TimeoutError('Service not ready: '+url)

def model(agent,messages,tokens=128):
    from cerebrum.llm.apis import LLMQuery
    from cerebrum.utils.communication import send_request
    q=LLMQuery(messages=messages,action_type='chat_with_json_output',temperature=0,max_new_tokens=tokens,message_return_type='json',response_format={'type':'json_object'})
    begin=time.monotonic();reply=send_request(agent,q,base_url=BASE)
    entry={'agent':agent,'request':copy.deepcopy(q.model_dump()),'reply':reply,'wall_seconds':time.monotonic()-begin}
    response=reply['response']
    if response.get('error'):raise RuntimeError(str(response['error']))
    return response['response_message'],entry

def tool(agent,operation,args):
    from cerebrum.tool.apis import ToolQuery
    from cerebrum.utils.communication import send_request
    q=ToolQuery(tool_calls=[{'name':'competition_validation/traffic_regression','parameters':{'operation':operation,'arguments':args}}])
    begin=time.monotonic();reply=send_request(agent,q,base_url=BASE)
    result=json.loads(reply['response']['response_message'])
    return result,{'agent':agent,'request':copy.deepcopy(q.model_dump()),'reply':reply,'wall_seconds':time.monotonic()-begin}

def run_single():
    system=('You are a traffic incident execution agent. Use the tools to choose and execute the fastest FEASIBLE route-signal candidate. '
      'Only JSON per turn: {"tool":"name","arguments":{}}. Tools: get_case({}); evaluate_candidates({}) computes the nine public options; '
      'execute_plan({"candidate_id":"r1-bounded","expected_version":0}) executes a chosen option in a NEW simulation; '
      'verify_execution({}) reads its actual result; finish({}) ends only after verified execution. '
      'The candidate_id above is schema syntax only, not a recommended answer. Read the data before selecting. '
      'Minimize elapsed_sim_s subject to all contract constraints, not speed alone. A successful call does not itself prove completion. '
      'Do not claim real road deployment, multiple agents or superiority.')
    messages=[{'role':'system','content':system},{'role':'user','content':'Handle the regression incident. Read the case, compare actual candidate evidence, execute the best feasible option, verify the new result and finish. /no_think'}]
    trace=[];complete=False;error=None;begin=time.monotonic()
    try:
        for index in range(9):
            text,m=model('traffic_single_regression',messages,112);entry={'step':index,'model':m};trace.append(entry)
            messages.append({'role':'assistant','content':text})
            try:
                action=json.loads(text)
                if set(action)!={'tool','arguments'} or not isinstance(action['arguments'],dict):raise ValueError('exact tool/arguments schema required')
                if action['tool'] not in {'get_case','evaluate_candidates','execute_plan','verify_execution','finish'}:raise ValueError('unknown tool')
            except Exception as e:
                feedback={'ok':False,'error':'invalid_schema','detail':str(e)};entry['result']=feedback
                messages.append({'role':'user','content':json.dumps(feedback)});continue
            response,t=tool('traffic_single_regression',action['tool'],action['arguments']);entry['tool']=t;entry['result']=response
            save('single_agent_trace.partial.json',trace)
            print('Single step',index,action['tool'],response.get('ok'),flush=True)
            if action['tool']=='finish' and response.get('ok'):complete=True;break
            messages.append({'role':'user','content':json.dumps({'tool_result':response},ensure_ascii=False)})
    except Exception as e:error={'type':type(e).__name__,'message':str(e)}
    output={'scope':'real 8B + native Cerebrum + compatible official AIOS entry + native tool manager + fresh CityFlow execution','complete':complete,'error':error,'wall_seconds':time.monotonic()-begin,'trace':trace,'is_multiagent':False,'competition_speedup_proven':False}
    save('single_agent_native_result.json',output);return output

def run_reviewer(name,focus):
    # Explicitly supplied evidence, not secret answers. No autonomous web research claim.
    facts={'contest':'at least four DIFFERENT AGENT TYPES, four parallel subtasks, three bidirectional different-type pairs, dependencies, total concurrent time <=0.8 serial time',
      'interpretation_boundary':'The quoted task does NOT require different model weights. Shared model weights alone prove neither homogeneous roles nor heterogeneous roles. Role responsibilities, state, methods, deliverables and actual interaction must be checked.',
      'known_regression':'exactly nine public options and budget nine; an exhaustive deterministic solver already achieves the feasible optimum of that set',
      'time_scope':'prior tool-only measurements: serial 3.108366 seconds, parallel 1.302701 seconds. No full model+communication+verification comparison exists.',
      'computed_reduction_percent':(1-1.302701/3.108366)*100,
      'completion_evidence':'A route API return true can disagree with actual traversal; use fresh trajectory and destination observations.',
      'not_measured':'No fair four-agent versus single-agent benefit or full-task speed result has been measured.'}
    prior_errors='An earlier model review incorrectly asserted that shared weights imply one agent type, and two reviews rounded the tool reduction to 60% or 60.5%. These claims must not be carried forward.'
    messages=[{'role':'system','content':'You are an independent review context. '+focus+' Use only supplied facts. Return JSON keys corrected_finding, next_test, still_unproven. Under 110 words. No invented experiments.'},
              {'role':'user','content':json.dumps(facts)+'\n'+prior_errors+' /no_think'}]
    text,record=model(name,messages,210);record['scope']='one independent evidence-grounded review context, not a tool-using research agent or operational traffic specialist';save('reviews/'+name+'.json',record)
    return {'role':name,'content':text}

def main():
    outcome={'scope':'bounded native runtime feasibility','real_model':False,'native_aios':False,'single_agent_completed':False,'review_contexts':0,'contest_speedup_proven':False}
    try:
        binary=next((ROOT/'bin').rglob('llama-server'));weight=ROOT/'model/Qwen3-8B-Q4_K_M.gguf'
        server=start([str(binary),'-m',str(weight),'--host','127.0.0.1','--port','18080','-t','4','-tb','4','-c','16384','-np','4','-ngl','0','--jinja','--chat-template-kwargs','{"enable_thinking":false}','--alias','qwen3-8b'],'native_llama.log')
        save('model_health.json',wait('http://127.0.0.1:18080/health',server,240));outcome['real_model']=True
        traffic=start([sys.executable,str(ROOT/'experiments/traffic_regression.py')],'traffic_server.log');wait('http://127.0.0.1:18083/health',traffic,30)
        nativeenv=dict(ENV);nativeenv['PYTHONPATH']=str(ROOT/'upstream/AIOS_compat')
        kernel=start([sys.executable,'-m','runtime.launch'],'native_aios.log',cwd=ROOT/'upstream/AIOS_compat',env=nativeenv)
        save('aios_models.json',wait(BASE+'/core/llms/list',kernel,240));outcome['native_aios']=True
        single=run_single();outcome['single_agent_completed']=single['complete']
        roles={'task_reviewer':'Audit real necessity of heterogeneous collaboration.', 'systems_reviewer':'Audit the distinction between tool time and full-task time.', 'verification_reviewer':'Audit evidence freshness and observed action completion.', 'experiment_reviewer':'Specify one fair falsifiable comparison against strong scripts and a fully equipped single agent.'}
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            future=[ex.submit(run_reviewer,n,f) for n,f in roles.items()];reviews=[x.result() for x in future]
        outcome['review_contexts']=len(reviews);save('review_outputs.json',reviews)
        # Independent final check reads actual native outputs, not the model's verbal claim.
        resultpath=OUT/'traffic/verification.json'
        if resultpath.exists():outcome['external_verdict']=json.loads(resultpath.read_text())
    except Exception as e:outcome['error']={'type':type(e).__name__,'message':str(e)}
    finally:
        save('native_status.json',outcome)
        for p in reversed(PROCESSES):
            if p.poll() is None:
                os.killpg(p.pid,signal.SIGTERM)
                try:p.wait(timeout=10)
                except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
        for f in HANDLES:f.close()
    print(json.dumps(outcome,ensure_ascii=False,indent=2),flush=True)
    if not outcome.get('native_aios') or not outcome.get('single_agent_completed'):raise SystemExit(1)
if __name__=='__main__':main()
