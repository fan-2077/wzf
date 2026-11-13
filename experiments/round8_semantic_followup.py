"""Targeted repair after an observed failure; not a randomized ablation.
Amended unit/statistic schema plus explicit diagnostic feedback, original errors retained.
"""
from pathlib import Path
import json,signal,os,time,threading,copy
from http.server import ThreadingHTTPServer
import native_run as n
import round8_live as live
from round8_task import DecisionGate,forecast_rows,expected_scores,save,canonical,simulate
from round8_quantitative import verify_claims,ClaimError
ROOT=n.ROOT;OUT=ROOT/'results/semantic_followup';OUT.mkdir(parents=True,exist_ok=True)
OLD_REPLY={'answer':'The wait policy minimizes expected arrival under the synthetic forecast distribution with an expected arrival of 1310.0 at 120 minutes, and the lowest expected queue of 81.36. Uncertainty is reflected in the probabilistic distribution of scenarios, but known future conditions are not disclosed. The reroute policy has higher expected arrival and queue across all scenarios.','evidence_ids':['A:forecast:v2','A:estimate:v2'],'request_id':'q1','version':2}
OLD_REVISION={'consumed_request_id':'q1','evidence_ids':['A:forecast:v2','A:estimate:v2'],'policy':'wait','reason':'The wait policy minimizes expected arrival under the synthetic forecast distribution with the lowest expected arrival of 1310.0 at 120 minutes, while respecting the queue cap relative to wait.','version':2}
TRACE=[]
def ask(role,messages,public,request_key):
    for attempt in range(2):
        text,rec=n.model(role,copy.deepcopy(messages),320)
        row={'role':role,'attempt':attempt,'request_record':rec}
        messages.append({'role':'assistant','content':text})
        try:
            obj=json.loads(text)
            if obj.get(request_key)!='q1-repair':raise ClaimError('exact consumed/request ID required')
            checked=verify_claims(public,obj)
            row.update(accepted=True,parsed=obj,check=checked)
        except Exception as e:
            row.update(accepted=False,error=str(e))
            messages.append({'role':'user','content':'Public numerical/schema check rejected this message: '+str(e)+'. Correct your response using only the supplied public facts. No realized future is provided. /no_think'})
        TRACE.append(row)
        with (OUT/'model_trace.jsonl').open('a') as f:f.write(json.dumps(row,ensure_ascii=False)+'\n')
        if row['accepted']:return obj
    raise RuntimeError('typed claim repair exhausted for '+role)
def rpc(operation,args=None):
    response,record=n.tool('round8_semantic_repair',operation,args or {})
    save(OUT/('rpc_'+operation+'.json'),record);return response

def main():
    save(OUT/'protocol.json',{'source_run':43360324063,'source_event_reply_index':4,'source_route_revision_index':5,
      'scope':'post-failure interface repair pilot, same public evidence and model; cannot isolate contribution of schema from diagnostic prompting',
      'old_peer_reply':OLD_REPLY,'old_requester_revision':OLD_REVISION,'new_info':'explicit simulated-second/vehicle units and probability-weighted aggregation contract; no private realized duration',
      'max_model_calls':4,'max_tokens_per_call':320,'role_pair':['route','event']})
    rows=forecast_rows(OUT/'forecast_tools');save(OUT/'forecast_rows.json',rows)
    live.CASE={'id':'A','prior':'short','update':'long','truth':750};live.GATE=DecisionGate('A',rows,'short');live.GATE.update('long')
    live.CURRENT_DIR=OUT/'execution';live.CURRENT_DIR.mkdir(exist_ok=True);live.RAW=None;live.VERIFIED=False;live.UPDATES=1;live.EXECUTIONS=0
    service=ThreadingHTTPServer(('127.0.0.1',18083),live.Service);threading.Thread(target=service.serve_forever,daemon=True).start()
    result={'completed':False,'error':None,'causal_improvement_proven':False};start=time.monotonic()
    try:
        binary=next((ROOT/'bin').rglob('llama-server'));weight=ROOT/'model/Qwen3-8B-Q4_K_M.gguf'
        server=n.start([str(binary),'-m',str(weight),'--host','127.0.0.1','--port','18080','-t','4','-tb','4','-c','8192','-np','2','-ngl','0','--jinja','--chat-template-kwargs','{"enable_thinking":false}','--alias','qwen3-8b'],'followup_llama.log')
        n.wait('http://127.0.0.1:18080/health',server,240)
        env=dict(n.ENV);env['PYTHONPATH']=str(ROOT/'upstream/AIOS_compat')
        kernel=n.start([os.sys.executable,'-m','runtime.launch'],'followup_aios.log',cwd=ROOT/'upstream/AIOS_compat',env=env);n.wait(n.BASE+'/core/llms/list',kernel,240)
        public=rpc('get_case')['public']
        public['explicit_quantity_contract']={'duration_support_unit':'sim_s','expected_arrival_unit':'sim_s','expected_arrival_meaning':'absolute simulation arrival clock, probability weighted over all support values',
           'expected_queue_unit':'vehicles','expected_queue_meaning':'probability-weighted time-average queued vehicle count','aggregation':'probability_weighted_mean'}
        scores=expected_scores(rows,public['probabilities'])
        valid={'version':2,'aggregation':'probability_weighted_mean','evidence_ids':public['evidence_ids'],'policy':'reroute',
               'quantities':{m:{'unit':u,**{p:scores[p][m] for p in ['wait','reroute']}} for m,u in [('expected_arrival','sim_s'),('expected_queue','vehicles')]}}
        # Replay manually annotated error patterns. These objects are test fixtures,
        # NOT claims that the old model emitted the new schema.
        bad_value=copy.deepcopy(valid);bad_value['quantities']['expected_arrival']['wait']=1310
        bad_unit=copy.deepcopy(valid);bad_unit['quantities']['expected_arrival']['unit']='minutes'
        rejected=[]
        for name,payload in [('single_scenario_as_expectation',bad_value),('minutes_instead_of_simulated_seconds',bad_unit)]:
            try:verify_claims(public,payload);raise AssertionError('bad claim accepted')
            except ClaimError as e:rejected.append({'fixture':name,'rejected':True,'error':str(e)})
        result['old_error_pattern_checks']=rejected;save(OUT/'error_pattern_checks.json',rejected)
        shape={'version':2,'aggregation':'probability_weighted_mean','evidence_ids':public['evidence_ids'],'policy':'wait or reroute',
               'quantities':{'expected_arrival':{'unit':'sim_s','wait':'number','reroute':'number'},'expected_queue':{'unit':'vehicles','wait':'number','reroute':'number'}}}
        event_ctx=[{'role':'system','content':'You are the event/recovery-estimate reviewer in a simulation. Return numerical claims with explicit units and probability-weighted statistics. Refer to current public tool evidence. A single conditional scenario is not the expectation. Do not predict hidden actual recovery time. No free-form prose; JSON only.'},
                   {'role':'assistant','content':canonical(OLD_REPLY)},
                   {'role':'user','content':'Requester route reopens q1 as q1-repair. Your earlier answer was flagged for using a conditional value as an expectation and unsupported minutes. Re-evaluate using '+canonical(public)+'. Return '+canonical(dict(shape,request_id='q1-repair'))+' /no_think'}]
        reply=ask('event',event_ctx,public,'request_id');result['repaired_peer_reply']=reply
        route_ctx=[{'role':'system','content':'You are the original route requester. Read the corrected peer reply, check its typed evidence against the same public calculator, and revise your prior artifact. Select the feasible policy minimizing expected arrival; ties minimize expected queue. JSON only.'},
                   {'role':'assistant','content':canonical(OLD_REVISION)},
                   {'role':'user','content':'Actual peer reply: '+canonical(reply)+' Current public evidence: '+canonical(public)+'. Return '+canonical(dict(shape,consumed_request_id='q1-repair'))+' /no_think'}]
        revised=ask('route',route_ctx,public,'consumed_request_id');result['requester_revision']=revised
        result['policy_changed']=revised['policy']!=OLD_REVISION['policy']
        request={'task_id':'A','version':2,'policy':revised['policy'],'evidence_ids':revised['evidence_ids']}
        result['execution']=rpc('execute_plan',request)
        if not result['execution'].get('ok'):raise RuntimeError('execution rejected')
        result['verification']=rpc('verify_execution');result['completed']=bool(rpc('finish').get('ok'))
        result['expected_optimal']=verify_claims(public,revised)['policy_expected_optimal']
        result['contexts']={'event':event_ctx,'route':route_ctx}
    except Exception as e:result['error']={'type':type(e).__name__,'message':str(e)}
    finally:
        result['total_model_calls']=len(TRACE);result['whole_probe_wall_seconds']=time.monotonic()-start
        for p in reversed(n.PROCESSES):
            if p.poll() is None:
                os.killpg(p.pid,signal.SIGTERM)
                try:p.wait(timeout=10)
                except Exception:os.killpg(p.pid,signal.SIGKILL);p.wait()
        for f in n.HANDLES:f.close()
        service.shutdown();service.server_close();save(OUT/'summary.json',result)
    print(json.dumps({k:v for k,v in result.items() if k!='contexts'},indent=2),flush=True)
    if not result['completed']:raise SystemExit(1)
if __name__=='__main__':main()
