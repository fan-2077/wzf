"""Real Qwen3-8B protocol integration using replayed traffic evidence.
Three isolated, deliberately seeded bad-plan fixtures; NOT a live traffic task,
AIOS speed benchmark, autonomous task allocation or evidence of necessity.
Message envelopes are assigned by the router; model outputs supply question,
answer and revision payload. No fallback or corrective answer is synthesized.
"""
from pathlib import Path
import dataclasses, hashlib, json, math, os, signal, subprocess, time, urllib.request
from evidence_ledger import Ledger
from protocol_audit_agents import query
ROOT=Path.cwd();OUT=ROOT/'results';OUT.mkdir(exist_ok=True)
def save(p,obj):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(obj,ensure_ascii=False,indent=2,allow_nan=False))
def valid(case,action):
    e=case['evidence']
    if case['id']=='queue_contract':
        if set(action)!={'candidate'}:return False
        eligible=[x for x in e['candidates'] if x['queue_change_percent']<=e['queue_cap_percent']]
        best=min((x['elapsed_sim_s'],x['mean_queue']) for x in eligible)
        return any(x['candidate_id']==action['candidate'] and (x['elapsed_sim_s'],x['mean_queue'])==best for x in eligible)
    if case['id']=='phase_hold_contract':
        return set(action)=={'phase'} and type(action['phase']) is int and action['phase']==e['held_phase'] and e['hold_start']<=e['simulation_time']<e['hold_release']
    if case['id']=='receipt_vs_outcome':
        actual=all(x in e['visited_roads'] for x in e['requested_anchors'])
        return set(action)=={'complete'} and type(action['complete']) is bool and action['complete']==actual
    raise ValueError('unknown case')
def call(ctx,label,trace,tokens=120):
    reply,record=query(ctx,tokens);text=reply['choices'][0]['message']['content'];trace.append({'label':label,'record':record})
    ctx.append({'role':'assistant','content':text});value=json.loads(text)
    if not isinstance(value,dict):raise ValueError('JSON object required')
    if reply['choices'][0].get('finish_reason')!='stop':raise ValueError('truncated or nonterminal generation')
    return value

def run_case(case,control_first):
    d=OUT/'closures'/case['id'];d.mkdir(parents=True,exist_ok=False)
    l=Ledger(env_version=1);eid=case['evidence_id'];task=case['id'];owner=case['requester'];peer=case['peer'];trace=[]
    l.register_evidence(eid,task,case['evidence']);l.publish('initial',owner,task,[eid],case['initial_action'],'Deliberately seeded unapproved bad plan; not a new model mistake')
    prompt={'instruction':case['action_spec'],'proposed_action':case['initial_action'],'evidence':{eid:case['evidence']},'source':case['source'],'scope':'Protocol fixture. No live control and no hidden answers. All roles see the same evidence.'}
    base='Use only supplied evidence. Return one compact JSON object, no prose or thinking. Never invent evidence IDs.'
    result={'case':case,'control_first':control_first,'initial_action_valid':valid(case,case['initial_action']),'scope':'replayed-evidence protocol integration, not new traffic execution'}
    def control():
        c=[{'role':'system','content':base+' You are one fully informed agent responsible for all constraints. Return {"action":{...},"evidence_refs":["id"],"reason":"brief"}.'},{'role':'user','content':json.dumps(prompt)+' Correct or retain the proposal. /no_think'}]
        v=call(c,'single_no_peer',trace);ok=valid(case,v.get('action',{})) and v.get('evidence_refs')==[eid]
        return {'output':v,'semantic_pass':ok}
    try:
        if control_first:result['single_control']=control()
        requester=[{'role':'system','content':base+' You are the '+owner+' requester. Your next turn should ask the '+peer+' specialist ONE concrete question needed to inspect this proposal. Return {"question":"..."}. You will receive its reply and then revise your own artifact.'},{'role':'user','content':json.dumps(prompt)+' /no_think'}]
        q=call(requester,'requester_question',trace,80)
        if set(q)!={'question'}:raise ValueError('question schema')
        req=l.request('Q',owner,peer,'initial',q['question'])
        peer_ctx=[{'role':'system','content':base+' You are the '+peer+' reviewer. Return {"answer":"brief evidence-based answer","evidence_refs":["id"]}. Do not claim real execution.'},{'role':'user','content':json.dumps({'case':prompt,'request':dataclasses.asdict(req)})+' /no_think'}]
        answer=call(peer_ctx,'peer_reply',trace,144)
        if set(answer)!={'answer','evidence_refs'}:raise ValueError('reply schema')
        rep=l.reply('R','Q',peer,owner,answer['evidence_refs'],answer['answer'])
        requester.append({'role':'user','content':json.dumps({'delivered_reply':dataclasses.asdict(rep),'instruction':'Consume this addressed reply now. Emit your own revised artifact as {action:{...},evidence_refs:[id],reason:brief}. Return an unchanged action if evidence warrants it; no forced change. Do not declare physical execution.'})+' /no_think'})
        revision=call(requester,'requester_consumes_reply',trace,144)
        if set(revision)!={'action','evidence_refs','reason'}:raise ValueError('revision schema')
        revised=l.revise('revised',owner,'initial',['R'],revision['evidence_refs'],revision['action'],revision['reason'])
        passed=valid(case,revision['action']);l.register_evidence('CHECK',task,{'artifact':revised.aid,'semantic_pass':passed},producer='verifier')
        l.approve('revised',passed=passed,checks=['fixture_semantics','provenance'],evidence=['CHECK'])
        result.update({'question':q,'reply':answer,'revision':revision,'semantic_pass':passed,'approved':l.executable('revised'),'ledger':l.summary(),'closures':l.closures,'error':None})
        if not control_first:result['single_control']=control()
    except Exception as e:result['error']={'type':type(e).__name__,'message':str(e)};result['ledger']=l.summary()
    finally:
        result['model_calls']=len(trace);result['raw_trace']=trace
        result['usage']={k:sum(x['record']['response'].get('usage',{}).get(k,0) for x in trace) for k in ['prompt_tokens','completion_tokens','total_tokens']}
        save(d/'result.json',result)
    print(task,'error',result.get('error'),'pass',result.get('semantic_pass'),'control',result.get('single_control',{}).get('semantic_pass'),flush=True)
    return result

def main():
    cases_path=ROOT/'experiments/feedback_closure_cases.json';cases=json.loads(cases_path.read_text());save(OUT/'frozen_cases.json',cases)
    save(OUT/'case_manifest.json',{'sha256':hashlib.sha256(cases_path.read_bytes()).hexdigest(),'read_only_evidence_replay':True,'initial_bad_plans_injected':True,'metadata_router_assigned':True})
    # Deterministic reference checks are not exposed to the peer prompt.
    assert all(not valid(c,c['initial_action']) for c in cases['cases'])
    binary=next((ROOT/'bin').rglob('llama-server'));log=(OUT/'server.log').open('w')
    p=subprocess.Popen([str(binary),'-m',str(ROOT/'model/Qwen3-8B-Q4_K_M.gguf'),'--host','127.0.0.1','--port','18080','-t','4','-tb','4','-c','8192','-np','2','-ngl','0','--jinja','--chat-template-kwargs','{"enable_thinking":false}','--alias','qwen3-8b'],stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    try:
        for _ in range(180):
            if p.poll() is not None:raise RuntimeError('model server exited')
            try:
                with urllib.request.urlopen('http://127.0.0.1:18080/health',timeout=2) as r:
                    if json.load(r).get('status')=='ok':break
            except Exception:time.sleep(1)
        else:raise TimeoutError('model server unavailable')
        start=time.monotonic();rows=[run_case(c,i%2==0) for i,c in enumerate(cases['cases'])]
        save(OUT/'closure_summary.json',{'cases':len(rows),'valid_closures':sum(x.get('approved',False) for x in rows),'single_controls_passed':sum(x.get('single_control',{}).get('semantic_pass',False) for x in rows),'total_model_calls':sum(x['model_calls'] for x in rows),'wall_seconds':time.monotonic()-start,'aios_in_this_run':False,'new_traffic_simulation':False,'same_task_three_pairs_proven':False,'superiority_proven':False,'rows':[{k:v for k,v in x.items() if k not in ['raw_trace','case']} for x in rows]})
    finally:
        if p.poll() is None:
            os.killpg(p.pid,signal.SIGTERM)
            try:p.wait(timeout=10)
            except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
        log.close()
if __name__=='__main__':main()
