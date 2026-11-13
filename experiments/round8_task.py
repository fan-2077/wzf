"""Round 8 deterministic task infrastructure, not an agent or a public benchmark.
Synthetic forecast weights are public. Realized durations are evaluator-only.
"""
from __future__ import annotations
import hashlib,json,math,os,subprocess,sys,time
from pathlib import Path
from typing import Any
SUPPORT=(120,300,600,900)
DISTRIBUTIONS={'short':(.7,.2,.1,0.),'long':(0.,.1,.3,.6),'ambiguous':(.25,.25,.25,.25)}
POLICIES=('wait','reroute')
ROOT=Path(os.environ.get('ROUND8_ROOT',Path.cwd())).resolve()
ROOT_SOURCE=ROOT/'experiments/dynamic_event_probe.py'
PLANNED=['road_3_2_2','road_2_2_2','road_1_2_1','road_1_3_1','road_1_4_0','road_2_4_0','road_3_4_3','road_3_3_3']
REROUTE=['road_3_2_2','road_2_2_2','road_1_2_1','road_1_3_0','road_2_3_0','road_3_3_3']
VEHICLE='flow_1457_0'
def canonical(x:Any)->str:return json.dumps(x,sort_keys=True,separators=(',',':'),allow_nan=False)
def digest(x:Any)->str:return hashlib.sha256(canonical(x).encode()).hexdigest()
def save(path:Path,x:Any)->None:
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(x,indent=2,ensure_ascii=False,allow_nan=False))
def native_worker(duration:int,policy:str,path:Path,seed:int=7)->None:
    if type(duration) is not int or duration<0 or policy not in POLICIES:raise ValueError('worker arguments')
    source=ROOT_SOURCE.read_text();marker='# Freeze a route plan at t=700.'
    if source.count(marker)!=1:raise RuntimeError('pinned round7 source layout changed')
    header=source.split(marker)[0]
    work=path.parent/(path.stem+'_runtime');work.mkdir(parents=True,exist_ok=True)
    for name in ['upstream','native_build']:
        link=work/name
        if not link.exists():link.symlink_to(ROOT/name,target_is_directory=True)
    old=Path.cwd();os.chdir(work)
    try:
        header=header.replace("'seed':7",f"'seed':{seed}")
        ns={'__name__':'round8_native_engine'};exec(compile(header,str(ROOT_SOURCE),'exec'),ns)
        e=ns['engine'];tick=ns['tick'];setp=ns['setp'];routes=ns['ROUTES']
        initial={'iid':'intersection_2_3','phase':2,'start':700,'release':1500}
        while e.get_current_time()<700:tick([initial])
        if e.get_vehicle_info(VEHICLE)['route'].split()!=routes[0]:raise RuntimeError('initial vehicle mismatch')
        if not e.set_vehicle_route(VEHICLE,PLANNED[1:]):raise RuntimeError('initial plan rejected')
        while e.get_current_time()<705:tick([initial])
        second={'iid':'intersection_1_3','phase':1,'start':705,'release':705+duration}
        if duration:setp(second['iid'],second['phase']);ns['pending'].pop(second['iid'],None)
        requested=REROUTE if policy=='reroute' else PLANNED
        accepted=True if policy=='wait' else bool(e.set_vehicle_route(VEHICLE,REROUTE[1:]))
        observed=e.get_vehicle_info(VEHICLE)['route'].split()
        roads=[];arrival=None;queue=0;phase_samples=[];start=time.monotonic()
        for _ in range(3000):
            t=e.get_current_time()
            if t<second['release']:phase_samples.append({'time':t,'phase':e.observe_tl_phase(second['iid'])})
            live=set(e.get_vehicles(include_waiting=True))
            if VEHICLE in live:
                r=e.get_vehicle_info(VEHICLE).get('road')
                if r and (not roads or roads[-1]!=r):roads.append(r)
            elif arrival is None:arrival=t
            tick([initial,second]);queue+=sum(e.get_lane_waiting_vehicle_count().values())
        if arrival is None and VEHICLE not in e.get_vehicles(include_waiting=True):arrival=e.get_current_time()
        raw={'duration':duration,'policy':policy,'seed':seed,'decision_time':705,'horizon':3000,'initial_route':PLANNED,
             'requested_route':requested,'route_accepted':accepted,'route_readback':observed,'visited_roads':roads,
             'arrival':arrival,'mean_queue':queue/3000,'phase_samples':phase_samples,
             'phase_enforced':len(phase_samples)==min(duration,3000) and all(x['phase']==1 for x in phase_samples),
             'route_exact':roads==requested,'destination_reached':arrival is not None and roads[-1:]==[PLANNED[-1]],
             'worker_wall_seconds':time.monotonic()-start,'controller_source_sha256':hashlib.sha256(source.encode()).hexdigest()}
        raw['passed']=bool(raw['route_accepted'] and observed==requested and raw['route_exact'] and raw['destination_reached'] and raw['phase_enforced'])
        save(path,raw);sys.stdout.flush();sys.stderr.flush();os._exit(0 if raw['passed'] else 2)
    finally:os.chdir(old)
def simulate(duration:int,policy:str,path:Path,seed:int=7)->dict:
    path=path.resolve();path.parent.mkdir(parents=True,exist_ok=True)
    with path.with_suffix('.log').open('w') as log:
        p=subprocess.run([sys.executable,str(Path(__file__).resolve()),'worker',str(duration),policy,str(path),str(seed)],stdout=log,stderr=subprocess.STDOUT,timeout=120)
    if p.returncode or not path.exists():raise RuntimeError(f'native simulation failed: {path} code={p.returncode}')
    return json.loads(path.read_text())
def forecast_rows(output_dir:Path)->list[dict]:
    rows=[]
    for duration in SUPPORT:
        pair={p:simulate(duration,p,output_dir/f'{duration}_{p}.json') for p in POLICIES}
        rows.append({'duration':duration,'arrival':{p:pair[p]['arrival'] for p in POLICIES},
                     'mean_queue':{p:pair[p]['mean_queue'] for p in POLICIES},
                     'all_native_checks_passed':all(x['passed'] for x in pair.values())})
    return rows
def expected_scores(rows:list[dict],weights:list[float]|tuple[float,...])->dict:
    if len(rows)!=len(weights) or not math.isclose(sum(weights),1,abs_tol=1e-9) or any(not math.isfinite(w) or w<0 for w in weights):raise ValueError('invalid probability distribution')
    scores={p:{'expected_arrival':sum(w*r['arrival'][p] for w,r in zip(weights,rows)),
               'expected_queue':sum(w*r['mean_queue'][p] for w,r in zip(weights,rows))} for p in POLICIES}
    reference=scores['wait']['expected_queue']
    for p in POLICIES:scores[p]['feasible']=scores[p]['expected_queue']<=reference*1.05+1e-9
    scores['best']=min((p for p in POLICIES if scores[p]['feasible']),key=lambda p:(scores[p]['expected_arrival'],scores[p]['expected_queue']))
    return scores
class ContractError(ValueError):pass
class DecisionGate:
    def __init__(self,task_id:str,rows:list[dict],prior:str):
        self.task_id=task_id;self.rows=json.loads(canonical(rows));self.version=1
        self.weights=list(DISTRIBUTIONS[prior]);self.name=prior;self.log=[];self.executed=False;self.registry={};self._publish()
    def _publish(self):
        self.forecast_id=f'{self.task_id}:forecast:v{self.version}';self.weights_id=f'{self.task_id}:estimate:v{self.version}'
        self.registry[self.forecast_id]={'task':self.task_id,'version':self.version,'payload':self.rows}
        self.registry[self.weights_id]={'task':self.task_id,'version':self.version,'payload':self.weights}
    def public(self)->dict:
        return {'task_id':self.task_id,'version':self.version,'evidence_ids':[self.forecast_id,self.weights_id],
                'duration_support':list(SUPPORT),'probabilities':self.weights,'forecast_scenarios':self.rows,
                'queue_cap_relative_to_wait':0.05,'decision_rule':'minimize expected arrival among feasible policies; ties minimize expected queue',
                'scope':'synthetic forecast distribution; exact simulation at assumptions, not known realized future'}
    def update(self,estimate:str)->None:
        if self.executed:raise ContractError('update after commit')
        self.version+=1;self.weights=list(DISTRIBUTIONS[estimate]);self.name=estimate;self._publish();self.log.append({'event':'estimate_updated','version':self.version})
    def validate(self,plan:dict,semantic:bool=False)->dict:
        if set(plan)!={'task_id','version','policy','evidence_ids'}:raise ContractError('schema')
        if plan['task_id']!=self.task_id:raise ContractError('task mismatch')
        if type(plan['version']) is not int or plan['version']!=self.version:raise ContractError('stale version')
        if plan['policy'] not in POLICIES:raise ContractError('unknown policy')
        refs=plan['evidence_ids']
        if not isinstance(refs,list) or set(refs)!={self.forecast_id,self.weights_id} or len(refs)!=2:raise ContractError('missing or invented evidence')
        for ref in refs:
            item=self.registry.get(ref)
            if not item or item['task']!=self.task_id or item['version']!=self.version:raise ContractError('stale evidence')
        scores=expected_scores(self.rows,self.weights)
        if not scores[plan['policy']]['feasible']:raise ContractError('queue constraint')
        if semantic and plan['policy']!=scores['best']:raise ContractError('not expected-optimal')
        return scores
    def commit(self,plan:dict)->dict:
        if self.executed:raise ContractError('already committed')
        self.validate(plan);self.executed=True;self.log.append({'event':'committed','plan':plan})
        return {'accepted':True,'policy':plan['policy'],'version':self.version}
if __name__=='__main__' and len(sys.argv)>1 and sys.argv[1]=='worker':native_worker(int(sys.argv[2]),sys.argv[3],Path(sys.argv[4]),int(sys.argv[5]))
