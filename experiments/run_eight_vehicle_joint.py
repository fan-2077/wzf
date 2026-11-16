from pathlib import Path
import sys,json,time,itertools,hashlib
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import traffic_env as t
OUT=ROOT/'results'/'round10'/'joint';OUT.mkdir(parents=True,exist_ok=True)
frozen=json.loads((ROOT/'results'/'round10'/'frozen_eight_candidates.json').read_text())
VEH=frozen['selected'];N=len(VEH)
DURATION=540;HORIZON=3000;SEED=7
def run(mask):
 label=format(mask,'0{}b'.format(N))
 d=OUT/('combo_'+label);d.mkdir(parents=True,exist_ok=True)
 lab=t.Lab(DURATION,d,seed=SEED);e=lab.engine
 while e.get_current_time()<705:lab.tick([lab.initial])
 selected={}
 for i,c in enumerate(VEH):
  info=e.get_vehicle_info(c['vehicle']);route=info.get('route','').split()
  assert info.get('road')==c['current'] and info.get('drivable')==c['drivable'] and route==c['route'],(c['vehicle'],info,c)
  selected[c['vehicle']]={'initial_route':route,'action':'reroute' if mask&(1<<i) else 'wait'}
 lab.setphase(lab.second['iid'],lab.second['phase'],'second_fault_injected');lab.version=2
 for i,c in enumerate(VEH):
  if mask&(1<<i):
   ok=e.set_vehicle_route(c['vehicle'],c['alternative'][1:])
   read=e.get_vehicle_info(c['vehicle'])['route'].split()
   assert ok and read==c['alternative'],(c['vehicle'],ok,read,c['alternative'])
   selected[c['vehicle']]['executed_route']=read
  else:selected[c['vehicle']]['executed_route']=c['route']
 visited={c['vehicle']:[] for c in VEH};arrivals={c['vehicle']:None for c in VEH};queue=[];phase=[]
 start=time.monotonic()
 for _ in range(HORIZON):
  now=e.get_current_time();live=set(e.get_vehicles(include_waiting=True))
  for c in VEH:
   vid=c['vehicle']
   if vid in live:
    info=e.get_vehicle_info(vid);road=info.get('road')
    if road and (not visited[vid] or visited[vid][-1]!=road):visited[vid].append(road)
   elif arrivals[vid] is None:arrivals[vid]=now
  if lab.second['start']<=now<lab.second['release']:phase.append(e.observe_tl_phase(lab.second['iid']))
  lab.tick([lab.initial,lab.second]);queue.append(sum(e.get_lane_waiting_vehicle_count().values()))
 for c in VEH:
  vid=c['vehicle']
  if arrivals[vid] is None and vid not in e.get_vehicles(include_waiting=True):arrivals[vid]=e.get_current_time()
 per={}
 for c in VEH:
  vid=c['vehicle'];route=selected[vid]['executed_route']
  per[vid]={'action':selected[vid]['action'],'arrival_time':arrivals[vid],
   'destination':route[-1],'visited_roads':visited[vid],
   'route_verified':visited[vid]==route,
   'destination_reached':arrivals[vid] is not None and bool(visited[vid]) and visited[vid][-1]==route[-1]}
 result={'mask':label,'duration_s':DURATION,'seed':SEED,'vehicles':per,
  'mean_network_queue':sum(queue)/len(queue),'queue_samples':len(queue),
  'fault_samples':len(phase),'fault_enforced':len(phase)==DURATION and all(x==1 for x in phase),
  'all_destinations_reached':all(x['destination_reached'] for x in per.values()),
  'all_routes_verified':all(x['route_verified'] for x in per.values()),
  'sum_arrival_times':sum(x['arrival_time'] for x in per.values() if x['arrival_time'] is not None),
  'wall_seconds':time.monotonic()-start,
  'scope':'8-vehicle joint assignment, fixed public demand, one event; deterministic native simulation, no LLM/agents'}
 (d/'result.json').write_text(json.dumps(result,indent=2))
 return result
rows=[];begin=time.monotonic()
for mask in range(1<<N):
 label=format(mask,'0{}b'.format(N));p=OUT/('combo_'+label)/'result.json'
 x=json.loads(p.read_text()) if p.exists() else run(mask)
 rows.append(x)
 (OUT/'partial_summary.json').write_text(json.dumps([{k:v for k,v in x.items() if k!='vehicles'} for x in rows],indent=2))
 print('completed',len(rows),'/',1<<N,'mask',label,'sum',x['sum_arrival_times'],flush=True)
base=next(x for x in rows if x['mask']=='0'*N)
feasible=[x for x in rows if x['all_destinations_reached'] and x['all_routes_verified'] and x['fault_enforced'] and x['mean_network_queue']<=base['mean_network_queue']*1.05]
best=min(feasible,key=lambda x:(x['sum_arrival_times'],x['mean_network_queue'],x['mask'])) if feasible else None
# Derive each vehicle's locally preferred action from one-bit experiments.
local=[]
for i,c in enumerate(VEH):
 one=next(x for x in rows if x['mask']==format(1<<i,'0{}b'.format(N)))
 zero=base
 va=one['vehicles'][c['vehicle']]['arrival_time'];vw=zero['vehicles'][c['vehicle']]['arrival_time']
 local.append(1 if va<vw else 0)
local_mask=''.join(str(v) for v in local)
local_row=next(x for x in rows if x['mask']==local_mask)
summary={'vehicles':N,'combinations':len(rows),'expected_combinations':1<<N,
 'all_scenarios_complete':len(rows)==(1<<N),
 'all_faults_enforced':all(x['fault_enforced'] for x in rows),
 'all_destinations_and_routes_verified':all(x['all_destinations_reached'] and x['all_routes_verified'] for x in rows),
 'queue_cap_relative_to_all_wait':0.05,'all_wait_baseline_queue':base['mean_network_queue'],
 'feasible_combinations':len(feasible),'best_feasible_mask':None if best is None else best['mask'],
 'best_feasible_sum_arrival_times':None if best is None else best['sum_arrival_times'],
 'best_feasible_mean_queue':None if best is None else best['mean_network_queue'],
 'all_wait_sum_arrival_times':base['sum_arrival_times'],
 'best_vs_all_wait_delta_sim_s':None if best is None else best['sum_arrival_times']-base['sum_arrival_times'],
 'local_best_mask':local_mask,'local_best_sum_arrival_times':local_row['sum_arrival_times'],
 'local_best_vs_all_wait_delta_sim_s':local_row['sum_arrival_times']-base['sum_arrival_times'],
 'local_best_worse_than_all_wait':local_row['sum_arrival_times']>base['sum_arrival_times'],
 'rows':[{k:v for k,v in x.items() if k!='vehicles'}|{'vehicles':{vid:{'action':q['action'],'arrival_time':q['arrival_time'],'route_verified':q['route_verified']} for vid,q in x['vehicles'].items()}} for x in rows],
 'wall_seconds':time.monotonic()-begin,
 'scope':'exhaustive 8-vehicle wait/reroute assignments, one fixed demand and one event; deterministic baseline, no LLM/agents'}
(OUT/'summary.json').write_text(json.dumps(summary,indent=2));print('SUMMARY',json.dumps({k:v for k,v in summary.items() if k!='rows'},indent=2))
if not summary['all_scenarios_complete'] or not summary['all_faults_enforced'] or not summary['all_destinations_and_routes_verified']:raise SystemExit(1)
