"""Real native simulator tool for an already-solved regression case.
No LLM is implemented here. Rule controls are not agents. Candidate results are
computed anew, not copied from prior runs. No real road or device is controlled.
"""
from pathlib import Path
import ast, hashlib, json, os, subprocess, sys, time, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from concurrent.futures import ThreadPoolExecutor
ROOT=Path.cwd().resolve(); OUT=ROOT/'results/traffic';OUT.mkdir(parents=True,exist_ok=True)
CASE={'id':'t700_i1','warmup':700,'horizon':1200,'hold_seconds':420,'queue_cap_relative':0.05,
 'vehicle':'flow_1457_0','destination':'road_3_3_3','fault':{'iid':'intersection_2_3','phase':2,'start':700,'release':1120},
 'routes':[['road_3_2_2','road_2_2_2','road_1_2_1','road_1_3_0','road_2_3_0','road_3_3_3'],
 ['road_3_2_2','road_2_2_2','road_1_2_1','road_1_3_1','road_1_4_0','road_2_4_0','road_3_4_3','road_3_3_3'],
 ['road_3_2_2','road_2_2_2','road_1_2_3','road_1_1_0','road_2_1_1','road_2_2_1','road_2_3_0','road_3_3_3']],
 'prior_contract_hash':'1c883e8cc68cc9a9b23d1530a3f037e632640f28706121e5c54466cd0fc5cfc8',
 'scope':'known development regression; no generalization or multi-agent necessity claim'}
PLANS={f'r{i}-{p}':{'route_index':i,'priority':p} for i in range(3) for p in ['none','task','bounded']}
def dump(p,x):p.write_text(json.dumps(x,ensure_ascii=False,indent=2,allow_nan=False))
def worker(cid,tag):
    sys.path.insert(0,str(ROOT/'native_build'));sys.path.insert(0,str(ROOT/'upstream/CoLLMLight'))
    import cityflow
    from models.maxpressure_agent import MaxPressureAgent
    data=ROOT/'upstream/CoLLMLight/data/Hangzhou/4_4';road=json.loads((data/'roadnet_4_4.json').read_text())
    intersections={x['id']:x for x in road['intersections'] if not x['virtual']}
    tree=ast.parse((ROOT/'upstream/CoLLMLight/utils/cityflow_env.py').read_text())
    cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Intersection')
    fn=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='_get_traffic_movement_pressure_general');fn.decorator_list=[]
    namespace={};exec(compile(ast.Module(body=[fn],type_ignores=[]),'pinned_upstream_pressure','exec'),namespace)
    pressure=namespace[fn.name]
    mov={}
    for iid,x in intersections.items():
        for j,m in enumerate(x['roadLinks']):mov[m['startRoad'],m['endRoad']]={'iid':iid,'phases':[p for p,ph in enumerate(x['trafficLight']['lightphases'][:5]) if j in ph['availableRoadLinks']]}
    cfg={'interval':1.0,'seed':7,'dir':str(data)+'/', 'roadnetFile':'roadnet_4_4.json','flowFile':'anon_4_4_hangzhou_real.json','rlTrafficLight':True,'laneChange':False,'saveReplay':False,'roadnetLogFile':'unused.json','replayLogFile':'unused.txt'}
    conf=OUT/(tag+'_config.json');dump(conf,cfg);e=cityflow.Engine(str(conf),thread_num=1)
    policies={i:MaxPressureAgent({}, {'PHASE':{p:[] for p in range(1,5)}},{},0,i) for i in intersections}
    phases={i:1 for i in intersections};pending={};last={i:0 for i in intersections};commands=[];viol=[]
    def setphase(i,p):e.set_tl_phase(i,p);commands.append({'t':e.get_current_time(),'iid':i,'phase':p})
    for i in phases:setphase(i,1)
    def state(i,w):
        _,x,y=i.split('_');x=int(x);y=int(y)
        ins=[f'road_{x-1}_{y}_0',f'road_{x+1}_{y}_2',f'road_{x}_{y+1}_3',f'road_{x}_{y-1}_1']
        outs=[f'road_{x}_{y}_0',f'road_{x}_{y}_2',f'road_{x}_{y}_3',f'road_{x}_{y}_1']
        a=[w.get(f'{r}_{l}',0) for r in ins for l in range(3)];b=[w.get(f'{r}_{l}',0) for r in outs for l in range(3)];z=pressure(a,b)
        return {'cur_phase':[phases[i]],'traffic_movement_pressure_queue':z,'phase_pressures':[z[1]+z[4],z[7]+z[10],z[0]+z[3],z[6]+z[9]]}
    def tick(fault=None,priority='none'):
        now=e.get_current_time()
        for i,(ready,p) in list(pending.items()):
            if now>=ready:
                if fault and i==fault['iid'] and fault['start']<=now<fault['release']:p=fault['phase']
                if phases[i]!=p:setphase(i,p);phases[i]=p;last[i]=now
                del pending[i]
        if now and int(now)%35==0:
            waiting=e.get_lane_waiting_vehicle_count();preferred=None
            if priority!='none' and CASE['vehicle'] in e.get_vehicles():
                info=e.get_vehicle_info(CASE['vehicle']);path=info.get('route','').split()
                if info.get('road') and len(path)>1 and path[0]==info['road']:
                    m=mov.get((path[0],path[1]));valid=[] if m is None else [p for p in m['phases'] if 1<=p<=4]
                    if valid and len(valid)<4:
                        permit=True
                        if priority=='bounded':
                            s=state(m['iid'],waiting);permit=max(s['phase_pressures'])-s['phase_pressures'][valid[0]-1]<=12
                        if permit:preferred=(m['iid'],valid[0])
            for i in phases:
                held=fault and i==fault['iid'] and fault['start']<=now<fault['release']
                p=fault['phase'] if held else int(policies[i].choose_action(int(now),state(i,waiting)))+1
                if preferred and preferred[0]==i and not held:p=preferred[1]
                if i not in pending and p!=phases[i]:
                    if now-last[i]<30-1e-9:viol.append({'t':now,'iid':i,'rule':'minimum_green'})
                    setphase(i,0);phases[i]=0;pending[i]=(now+5,p)
        e.next_step()
    start=time.monotonic()
    while e.get_current_time()<CASE['warmup']:tick()
    assert phases[CASE['fault']['iid']]==CASE['fault']['phase']
    plan=PLANS[cid];vid=CASE['vehicle'];path=CASE['routes'][plan['route_index']]
    before=e.get_vehicle_info(vid);assert before.get('route','').split()==CASE['routes'][0]
    accepted=True;readback=True
    if plan['route_index']:
        accepted=bool(e.set_vehicle_route(vid,path[1:]));readback=e.get_vehicle_info(vid).get('route','').split()==path
    visited=[];arrival=None;queue=0;samples=[]
    def observe():samples.append({'time':e.get_current_time(),'phase':e.observe_tl_phase(CASE['fault']['iid'])})
    observe()
    for _ in range(CASE['horizon']):
        live=set(e.get_vehicles(include_waiting=True))
        if vid in live:
            r=e.get_vehicle_info(vid).get('road')
            if r and (not visited or visited[-1]!=r):visited.append(r)
        elif arrival is None:arrival=e.get_current_time()
        tick(CASE['fault'],plan['priority'])
        if e.get_current_time()<CASE['fault']['release']:observe()
        queue+=sum(e.get_lane_waiting_vehicle_count().values())
    if arrival is None and vid not in e.get_vehicles(include_waiting=True):arrival=e.get_current_time()
    record={'candidate_id':cid,'plan':plan,'native_route_accepted':accepted,'route_readback':readback,'requested_route':path,'visited_roads':visited,'route_fulfilled':arrival is not None and visited==path,'destination_observed':CASE['destination'] in visited,'elapsed_sim_s':None if arrival is None else arrival-CASE['warmup'],'mean_queue':queue/CASE['horizon'],'fault_samples':samples,'signal_violations':viol,'signal_commands':commands,'wall_s':time.monotonic()-start,'scope':'fresh native CityFlow run, deterministic controller, not an agent'}
    dump(OUT/(tag+'.json'),record);sys.stdout.flush();sys.stderr.flush();os._exit(0)

def run(cid,tag):
    with (OUT/(tag+'.log')).open('w') as f:
        p=subprocess.run([sys.executable,__file__,'worker',cid,tag],stdout=f,stderr=subprocess.STDOUT,timeout=90)
    if p.returncode:raise RuntimeError(f'worker failed {tag}: {p.returncode}')
    return json.loads((OUT/(tag+'.json')).read_text())
def verdict(r,b):
    failures=[]
    for key in ['native_route_accepted','route_readback','route_fulfilled','destination_observed']:
        if r[key] is not True:failures.append(key)
    if r['elapsed_sim_s'] is None:failures.append('arrival_missing')
    if r['signal_violations']:failures.append('signal_constraints')
    if len(r['fault_samples'])!=420 or any(x['phase']!=2 for x in r['fault_samples']):failures.append('incident_not_enforced')
    ratio=r['mean_queue']/b['mean_queue']-1
    if ratio>CASE['queue_cap_relative']+1e-9:failures.append('queue_cap')
    return {'passed':not failures,'failures':failures,'queue_change_percent':ratio*100}
STATE={'version':0,'candidates':{},'execution':None,'verified':False};LOCK=threading.RLock()
def handle(op,args):
    if not isinstance(args,dict):return {'ok':False,'error':'arguments must be object'}
    if op=='get_case':return {'ok':True,'case':CASE,'version':STATE['version'],'candidate_ids':list(PLANS),'objective':'minimum elapsed time among feasible candidates, then lowest mean queue','tools':'get_case({}), evaluate_candidates({}), execute_plan({candidate_id,expected_version}), verify_execution({}), finish({})'}
    if op=='evaluate_candidates':
        if not STATE['candidates']:
            with ThreadPoolExecutor(max_workers=4) as ex:
                results=list(ex.map(lambda c:run(c,'candidate_'+c),PLANS))
            STATE['candidates']={r['candidate_id']:r for r in results}
        baseline=STATE['candidates']['r0-none'];rows=[]
        for cid,r in STATE['candidates'].items():rows.append({'candidate_id':cid,'elapsed_sim_s':r['elapsed_sim_s'],'mean_queue':r['mean_queue'],**verdict(r,baseline)})
        dump(OUT/'candidate_evidence.json',rows)
        return {'ok':True,'version':STATE['version'],'simulations_used':9,'remaining_candidate_budget':0,'rows':rows}
    if op=='execute_plan':
        if set(args)!={'candidate_id','expected_version'} or type(args['expected_version']) is not int:return {'ok':False,'error':'strict schema'}
        if args['expected_version']!=STATE['version']:return {'ok':False,'error':'stale_version','current_version':STATE['version']}
        if STATE['execution'] is not None:return {'ok':False,'error':'execution_already_committed'}
        cid=args['candidate_id']
        if cid not in STATE['candidates']:return {'ok':False,'error':'candidate must be evaluated first'}
        b=STATE['candidates']['r0-none'];v=verdict(STATE['candidates'][cid],b)
        if not v['passed']:return {'ok':False,'error':'candidate violates contract','verdict':v}
        r=run(cid,'selected_execution');STATE['execution']=r;STATE['verified']=False;STATE['version']+=1
        dump(OUT/'state.json',STATE)
        return {'ok':True,'version':STATE['version'],'execution_id':'selected_execution','note':'New simulation executed. Read verify_execution before declaring success.'}
    if op=='verify_execution':
        if STATE['execution'] is None:return {'ok':False,'error':'no_execution'}
        r=json.loads((OUT/'selected_execution.json').read_text());b=STATE['candidates']['r0-none'];v=verdict(r,b)
        eligible=[x for x in STATE['candidates'].values() if verdict(x,b)['passed']]
        best=min(eligible,key=lambda x:(x['elapsed_sim_s'],x['mean_queue'],x['candidate_id']))
        same=all(r[k]==STATE['candidates'][r['candidate_id']][k] for k in ['visited_roads','elapsed_sim_s','mean_queue','signal_violations'])
        result={'ok':True,**v,'candidate_id':r['candidate_id'],'elapsed_sim_s':r['elapsed_sim_s'],'independent_replay_identical':same,'best_within_exhaustive_candidate_set':r['candidate_id']==best['candidate_id']}
        STATE['verified']=v['passed'] and same;dump(OUT/'verification.json',result);return result
    if op=='finish':return {'ok':STATE['verified'],'status':'completed' if STATE['verified'] else 'not_completed','error':None if STATE['verified'] else 'must_execute_and_verify','version':STATE['version']}
    return {'ok':False,'error':'unknown_operation'}
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body=json.dumps({'ready':True}).encode();self.send_response(200);self.end_headers();self.wfile.write(body)
    def do_POST(self):
        try:
            request=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            if set(request)!={'operation','arguments'}:raise ValueError('operation and arguments required')
            with LOCK:response=handle(request['operation'],request['arguments'])
        except Exception as e:response={'ok':False,'error':type(e).__name__,'detail':str(e)}
        with (OUT/'rpc_trace.jsonl').open('a') as f:f.write(json.dumps({'request':request,'response':response,'wall_time':time.time()},ensure_ascii=False)+'\n')
        self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps(response).encode())
    def log_message(self,*a):pass
if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='worker':worker(sys.argv[2],sys.argv[3])
    else:dump(OUT/'contract.json',CASE);ThreadingHTTPServer(('127.0.0.1',18083),Handler).serve_forever()
