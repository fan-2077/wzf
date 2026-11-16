"""Read-only local-8B audit agents, not traffic-control agents or contest evidence.
Four independent tool-using contexts inspect and execute bounded protocol probes.
All tools are predefined Python functions; no model-generated code is executed.
Sources and counterexamples are retained whether model findings are correct or not.
"""
from pathlib import Path
import concurrent.futures, dataclasses, hashlib, inspect, json, os, signal, subprocess, sys, threading, time, urllib.request
import collaboration_protocol as old
ROOT=Path.cwd();OUT=ROOT/'results';OUT.mkdir(exist_ok=True)
ROLES={'freshness':'Check whether replies remain usable after the world version changes.',
       'evidence':'Check whether a claim with a nonexistent evidence reference can be marked executable.',
       'change':'Distinguish message consumption from a demonstrated change of an action or a conclusion.',
       'pairs':'Check whether reciprocal exchanges are counted as one or two different unordered role pairs.'}
SOURCES={'freshness':['submit_reply','consume_and_revise','advance_environment'],
         'evidence':['add_artifact','valid_for_execution'],
         'change':['consume_and_revise'],
         'pairs':['consume_and_revise']}
LOCK=threading.Lock()
def save(path,value):path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False))
def art(aid,role='route',v=0,rev=None,cons=(),refs=('E0',),action='wait',finding='Inspect route and queue'):
    return old.Artifact(aid,role,'T',v,refs,'candidate',action,finding,('queue',),(),rev,cons)
def setup():
    l=old.CollaborationLedger(0);l.add_artifact(art('A'))
    l.open_request(old.ReviewRequest('Q','route','network','A','Check queue',('E0',),0));return l

def probe(case):
    if case=='freshness':
        l=setup();l.advance_environment(1)
        accepted_reply=accepted_revision=False;errors=[]
        try:l.submit_reply(old.ReviewReply('R','Q','network','route','Old queue is fine',('E0',)));accepted_reply=True
        except Exception as e:errors.append(str(e))
        try:l.consume_and_revise(art('A1',v=1,rev='A',cons=('R',)));accepted_revision=True
        except Exception as e:errors.append(str(e))
        return {'evidence_id':'probe:freshness','current_version':1,'request_version':0,'reply_accepted':accepted_reply,'revision_accepted':accepted_revision,'executable':l.valid_for_execution('A1'),'errors':errors}
    if case=='evidence':
        l=old.CollaborationLedger(0);l.add_artifact(art('A',refs=('DOES_NOT_EXIST',)))
        return {'evidence_id':'probe:evidence','evidence_ref':'DOES_NOT_EXIST','registry_exists':hasattr(l,'evidence'),'executable':l.valid_for_execution('A')}
    if case=='change':
        l=setup();l.submit_reply(old.ReviewReply('R','Q','network','route','Agree',('E0',)))
        l.consume_and_revise(art('A1',rev='A',cons=('R',)))
        return {'evidence_id':'probe:change','old_action':l.artifacts['A'].recommended_action_id,'new_action':l.artifacts['A1'].recommended_action_id,'old_finding':l.artifacts['A'].finding,'new_finding':l.artifacts['A1'].finding,'completed_pairs':sorted(l.completed_pairs),'note':'A justified no-change may be valid protocol behavior, but is not a changed-action result.'}
    if case=='pairs':
        l=setup();l.submit_reply(old.ReviewReply('R','Q','network','route','Check passed',('E0',)))
        l.consume_and_revise(art('A1',rev='A',cons=('R',)))
        l.add_artifact(art('B',role='network'))
        l.open_request(old.ReviewRequest('Q2','network','route','B','Check route',('E0',),0))
        l.submit_reply(old.ReviewReply('R2','Q2','route','network','Route passed',('E0',)))
        l.consume_and_revise(art('B1',role='network',rev='B',cons=('R2',)))
        return {'evidence_id':'probe:pairs','ordered_completed_pairs':sorted(l.completed_pairs),'ordered_count':len(l.completed_pairs),'unordered_count':len({tuple(sorted(x)) for x in l.completed_pairs})}
    raise ValueError('unknown probe')

def tool(name,case):
    if case not in ROLES:raise ValueError('unknown case')
    if name=='inspect':return {'evidence_id':'source:'+case,'source':''.join(inspect.getsource(getattr(old.CollaborationLedger,k)) for k in SOURCES[case])}
    if name=='probe':return probe(case)
    raise ValueError('unknown tool')

def query(messages,limit=144):
    req={'model':'qwen3-8b','messages':messages,'temperature':0,'seed':19,'max_tokens':limit,'stream':False,'response_format':{'type':'json_object'},'chat_template_kwargs':{'enable_thinking':False}}
    start=time.monotonic();r=urllib.request.Request('http://127.0.0.1:18080/v1/chat/completions',data=json.dumps(req).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(r,timeout=480) as response:payload=json.load(response)
    return payload,{'request':req,'response':payload,'wall_seconds':time.monotonic()-start}

def agent(role,goal):
    system=('You are a read-only protocol audit subagent. '+goal+' All roles may access all cases. '
      'Use tools before final judgment: inspect returns source; probe executes the exact old class on a bounded case. '
      'Respond with one JSON object only. Tool form: {"tool":"inspect","case_id":"'+role+'"} or {"tool":"probe","case_id":"'+role+'"}. '
      'Final form: {"tool":"finish","finding":"short finding","evidence_ids":["source:'+role+'","probe:'+role+'"],"limitation":"what this does not prove"}. '
      'Do not invent observations; a protocol probe is not a traffic experiment. Keep final response under 90 words.')
    msgs=[{'role':'system','content':system},{'role':'user','content':'Inspect the relevant code, run your probe, then judge the invariant. /no_think'}]
    seen=set();trace=[];success=False;final=None
    for step in range(5):
        response,raw=query(msgs);text=response['choices'][0]['message']['content'];entry={'step':step,'model':raw};trace.append(entry)
        msgs.append({'role':'assistant','content':text})
        try:
            action=json.loads(text)
            if action.get('tool')=='finish':
                refs=action.get('evidence_ids',[])
                if not {'source:'+role,'probe:'+role}.issubset(seen) or not set(refs).issubset(seen):raise ValueError('Must actually inspect and probe before final; cite only observed IDs')
                success=True;final=action;break
            result=tool(action['tool'],action['case_id']);seen.add(result['evidence_id']);entry['tool_result']=result
        except Exception as e:result={'error':type(e).__name__,'detail':str(e)};entry['tool_result']=result
        msgs.append({'role':'user','content':json.dumps(result,separators=(',',':'))+' /no_think'})
        save(OUT/'agents'/(role+'.partial.json'),trace)
    value={'role':role,'goal':goal,'completed':success,'final':final,'observed_evidence_ids':sorted(seen),'trace':trace,'independent_context':True,'shared_model_weights':True,'scope':'read-only code audit helper, not a deployed traffic specialist'}
    save(OUT/'agents'/(role+'.json'),value);print(role,'completed',success,flush=True);return value

def main():
    source=Path(old.__file__);save(OUT/'source_manifest.json',{'path':str(source),'sha256':hashlib.sha256(source.read_bytes()).hexdigest()});(OUT/'old_protocol.py').write_bytes(source.read_bytes())
    expected={c:probe(c) for c in ROLES};save(OUT/'direct_probe_results.json',expected)
    binary=next((ROOT/'bin').rglob('llama-server'));f=(OUT/'server.log').open('w');p=subprocess.Popen([str(binary),'-m',str(ROOT/'model/Qwen3-8B-Q4_K_M.gguf'),'--host','127.0.0.1','--port','18080','-t','4','-tb','4','-c','12288','-np','4','-ngl','0','--jinja','--chat-template-kwargs','{"enable_thinking":false}','--alias','qwen3-8b'],stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
    try:
        for _ in range(180):
            if p.poll() is not None:raise RuntimeError('model server exited')
            try:
                with urllib.request.urlopen('http://127.0.0.1:18080/health',timeout=2) as r:
                    if json.load(r).get('status')=='ok':break
            except Exception:time.sleep(1)
        else:raise TimeoutError('model unavailable')
        begin=time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures=[pool.submit(agent,r,g) for r,g in ROLES.items()];results=[]
            for future in futures:
                try:results.append(future.result())
                except Exception as e:results.append({'completed':False,'error':str(e)})
        save(OUT/'review_summary.json',{'contexts':4,'completed':sum(x['completed'] for x in results),'wall_seconds':time.monotonic()-begin,'actual_model_calls':sum(len(x.get('trace',[])) for x in results),'research_helpers_only':True,'traffic_agents_tested':False,'aios_kernel_in_this_run':False,'agent_results':[{'role':x.get('role'),'completed':x['completed'],'final':x.get('final'),'error':x.get('error')} for x in results]})
    finally:
        if p.poll() is None:
            os.killpg(p.pid,signal.SIGTERM)
            try:p.wait(timeout=10)
            except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
        f.close()
    manifest={str(q.relative_to(OUT)):hashlib.sha256(q.read_bytes()).hexdigest() for q in sorted(OUT.rglob('*')) if q.is_file() and q.name!='MANIFEST.json'};save(OUT/'MANIFEST.json',manifest)
if __name__=='__main__':main()
