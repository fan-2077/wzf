from pathlib import Path
import json,sys,time,ast,collections,itertools,hashlib
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'native_build'))
import cityflow
ROOT=Path.cwd(); DATA=ROOT/'upstream/CoLLMLight/data/Hangzhou/4_4'
ROAD=json.loads((DATA/'roadnet_4_4.json').read_text())
INTER={x['id']:x for x in ROAD['intersections'] if not x['virtual']}
ROADS={x['id']:x for x in ROAD['roads']}
tree=ast.parse((ROOT/'upstream/CoLLMLight/utils/cityflow_env.py').read_text())
cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Intersection')
fn=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='_get_traffic_movement_pressure_general');fn.decorator_list=[]
ns={};exec(compile(ast.Module(body=[fn],type_ignores=[]),'pinned_pressure','exec'),ns);PRESS=ns[fn.name]
MOV={}
for iid,x in INTER.items():
 for m in x['roadLinks']:
  phases=[p for p,ph in enumerate(x['trafficLight']['lightphases'][:5]) if next(j for j,z in enumerate(x['roadLinks']) if z is m) in ph['availableRoadLinks']]
  MOV[m['startRoad'],m['endRoad']]={'iid':iid,'phases':phases}
OUT=ROOT/'results/round10';OUT.mkdir(parents=True,exist_ok=True)
INITIAL={'iid':'intersection_2_3','phase':2,'start':700,'release':1500}
SECOND={'iid':'intersection_1_3','phase':1,'start':705,'release':1245}
DURATION=540;HORIZON=3000;SEED=7
CFG={'interval':1.0,'seed':SEED,'dir':str(DATA)+'/','roadnetFile':'roadnet_4_4.json','flowFile':'anon_4_4_hangzhou_real.json','rlTrafficLight':True,'laneChange':False,'saveReplay':False,'roadnetLogFile':'unused.json','replayLogFile':'unused.txt'}
def bfs(start,dest,forbidden,first_allowed):
 q=collections.deque([(start,[start])]);seen={start}
 while q:
  road,path=q.popleft()
  if road==dest:return path
  end=ROADS[road]['endIntersection']
  if end not in INTER:continue
  for m in INTER[end]['roadLinks']:
   if m['startRoad']!=road:continue
   nxt=m['endRoad']
   if (road,nxt)==forbidden or nxt in seen:continue
   if len(path)==1 and nxt not in first_allowed:continue
   seen.add(nxt);q.append((nxt,path+[nxt]))
 return None
class Sim:
 def __init__(self,tag):
  self.dir=OUT/tag;self.dir.mkdir(parents=True,exist_ok=True)
  cfg=self.dir/'config.json';cfg.write_text(json.dumps(CFG))
  self.e=cityflow.Engine(str(cfg),thread_num=1)
  self.phase={i:1 for i in INTER};self.pending={};self.last={i:0 for i in INTER}
  for i in self.phase:self.e.set_tl_phase(i,1)
 def setp(self,i,p):
  self.e.set_tl_phase(i,p);self.phase[i]=p;self.last[i]=self.e.get_current_time()
 def pressure(self,i,w):
  _,x,y=i.split('_');x=int(x);y=int(y)
  ins=[f'road_{x-1}_{y}_0',f'road_{x+1}_{y}_2',f'road_{x}_{y+1}_3',f'road_{x}_{y-1}_1']
  outs=[f'road_{x}_{y}_0',f'road_{x}_{y}_2',f'road_{x}_{y}_3',f'road_{x}_{y}_1']
  return PRESS([w.get(f'{r}_{l}',0) for r in ins for l in range(3)],[w.get(f'{r}_{l}',0) for r in outs for l in range(3)])
 def tick(self):
  now=self.e.get_current_time();faults=[INITIAL,SECOND]
  for iid,(ready,p) in list(self.pending.items()):
   if now>=ready:
    active=next((f for f in faults if f['iid']==iid and f['start']<=now<f['release']),None)
    self.setp(iid,active['phase'] if active else p);del self.pending[iid]
  if now and int(now)%35==0:
   w=self.e.get_lane_waiting_vehicle_count()
   for iid in self.phase:
    active=next((f for f in faults if f['iid']==iid and f['start']<=now<f['release']),None)
    if active:
     if self.phase[iid]!=active['phase']:self.setp(iid,active['phase'])
     self.pending.pop(iid,None);continue
    z=self.pressure(iid,w);v=[z[1]+z[4],z[7]+z[10],z[0]+z[3],z[6]+z[9]]
    p=max(range(4),key=lambda k:v[k])+1
    if iid not in self.pending and p!=self.phase[iid]:
     self.setp(iid,0);self.pending[iid]=(now+5,p)
  self.e.next_step()
 def warm(self):
  while self.e.get_current_time()<705:self.tick()
  self.setp(SECOND['iid'],SECOND['phase'])
def discover():
 sim=Sim('discovery');sim.warm();e=sim.e;candidates=[]
 for vid in sorted(e.get_vehicles(include_waiting=True)):
  try:info=e.get_vehicle_info(vid)
  except Exception:continue
  cur=info.get('road','');route=info.get('route','').split();dr=info.get('drivable','')
  if cur not in ROADS or len(route)<3 or not dr.startswith(cur+'_'):continue
  try:lane=int(dr.rsplit('_',1)[1]);pos=route.index(cur)
  except Exception:continue
  end=ROADS[cur]['endIntersection']
  if end not in INTER:continue
  first=[m['endRoad'] for m in INTER[end]['roadLinks'] if m['startRoad']==cur and any(int(ll['startLaneIndex'])==lane for ll in m['laneLinks'])]
  if not first:continue
  for k in range(pos+1,min(len(route)-1,pos+8)):
   a,b=route[k],route[k+1];m=MOV.get((a,b))
   if not m or m['iid']!=SECOND['iid'] or SECOND['phase'] in m['phases']:continue
   alt=bfs(cur,route[-1],(a,b),set(first))
   if alt and len(alt)>2 and alt[1] in first:
    candidates.append({'vehicle':vid,'current':cur,'lane':lane,'drivable':dr,'route':route,'blocked_move':[a,b],'required_phases':m['phases'],'alternative':alt})
    break
 selected=[];used=set()
 for c in candidates:
  if c['current'] in used:continue
  selected.append(c);used.add(c['current'])
  if len(selected)==8:break
 result={'candidate_count':len(candidates),'selected_count':len(selected),'selection_rule':'sorted vehicle IDs at t=705 before joint outcome runs; first eight lane-feasible candidates on distinct current roads','selected':selected,'all_candidates':candidates}
 (OUT/'frozen_eight_candidates.json').write_text(json.dumps(result,indent=2))
 if len(selected)!=8:raise RuntimeError('Expected 8 candidates, found '+str(len(selected)))
 return selected
def run(mask,vehicles):
 label=format(mask,'08b');sim=Sim('joint/combo_'+label);sim.warm();e=sim.e
 for c in vehicles:
  info=e.get_vehicle_info(c['vehicle'])
  assert info['road']==c['current'] and info['drivable']==c['drivable'] and info['route'].split()==c['route'],(c,info)
 per={}
 for i,c in enumerate(vehicles):
  action='reroute' if mask&(1<<i) else 'wait';route=c['alternative'] if action=='reroute' else c['route']
  if action=='reroute':
   ok=e.set_vehicle_route(c['vehicle'],route[1:]);read=e.get_vehicle_info(c['vehicle'])['route'].split()
   assert ok and read==route,(c['vehicle'],ok,read,route)
  per[c['vehicle']]={'action':action,'route':route,'visited':[],'arrival':None}
 queues=[];phases=[];start=time.monotonic()
 for _ in range(HORIZON):
  now=e.get_current_time();live=set(e.get_vehicles(include_waiting=True))
  for vid,x in per.items():
   if vid in live:
    road=e.get_vehicle_info(vid).get('road')
    if road and (not x['visited'] or x['visited'][-1]!=road):x['visited'].append(road)
   elif x['arrival'] is None:x['arrival']=now
  if SECOND['start']<=now<SECOND['release']:phases.append(e.observe_tl_phase(SECOND['iid']))
  sim.tick();queues.append(sum(e.get_lane_waiting_vehicle_count().values()))
 for vid,x in per.items():
  if x['arrival'] is None and vid not in e.get_vehicles(include_waiting=True):x['arrival']=e.get_current_time()
  x['route_verified']=x['visited']==x['route'];x['destination_reached']=x['arrival'] is not None and x['visited'][-1]==x['route'][-1]
 result={'mask':label,'vehicles':per,'sum_arrival_times':sum(x['arrival'] for x in per.values() if x['arrival'] is not None),
  'mean_network_queue':sum(queues)/len(queues),'queue_samples':len(queues),'fault_samples':len(phases),
  'fault_enforced':len(phases)==DURATION and all(p==1 for p in phases),
  'all_routes_verified':all(x['route_verified'] for x in per.values()),'all_destinations_reached':all(x['destination_reached'] for x in per.values()),
  'wall_seconds':time.monotonic()-start}
 d=OUT/'joint'/('combo_'+label);(d/'result.json').write_text(json.dumps(result,indent=2))
 return result
def main():
 vehicles=discover();joint=OUT/'joint';joint.mkdir(exist_ok=True)
 rows=[];begin=time.monotonic()
 for mask in range(256):
  label=format(mask,'08b');p=joint/('combo_'+label)/'result.json'
  x=json.loads(p.read_text()) if p.exists() else run(mask,vehicles);rows.append(x)
  if len(rows)%8==0:
   (joint/'partial.json').write_text(json.dumps([{k:v for k,v in r.items() if k!='vehicles'} for r in rows],indent=2))
   print('progress',len(rows),'/256',flush=True)
 base=next(x for x in rows if x['mask']=='00000000')
 feasible=[x for x in rows if x['all_routes_verified'] and x['all_destinations_reached'] and x['fault_enforced'] and x['mean_network_queue']<=base['mean_network_queue']*1.05]
 best=min(feasible,key=lambda x:(x['sum_arrival_times'],x['mean_network_queue'],x['mask']))
 local=[]
 for i,c in enumerate(vehicles):
  one=next(x for x in rows if x['mask']==format(1<<i,'08b'))
  local.append(1 if one['vehicles'][c['vehicle']]['arrival']<base['vehicles'][c['vehicle']]['arrival'] else 0)
 localmask=''.join(map(str,local));localrow=next(x for x in rows if x['mask']==localmask)
 summary={'vehicle_count':8,'combinations':len(rows),'expected':256,'all_complete':len(rows)==256,
  'all_routes_verified':all(x['all_routes_verified'] for x in rows),'all_destinations_reached':all(x['all_destinations_reached'] for x in rows),
  'all_faults_enforced':all(x['fault_enforced'] for x in rows),'queue_cap':0.05,'baseline_mask':base['mask'],
  'baseline_sum':base['sum_arrival_times'],'baseline_queue':base['mean_network_queue'],
  'feasible_count':len(feasible),'joint_best_mask':best['mask'],'joint_best_sum':best['sum_arrival_times'],
  'joint_best_queue':best['mean_network_queue'],'joint_best_delta_vs_wait':best['sum_arrival_times']-base['sum_arrival_times'],
  'local_best_mask':localmask,'local_best_sum':localrow['sum_arrival_times'],
  'local_best_delta_vs_wait':localrow['sum_arrival_times']-base['sum_arrival_times'],
  'local_best_worse_than_wait':localrow['sum_arrival_times']>base['sum_arrival_times'],
  'wall_seconds':time.monotonic()-begin,'scope':'256 exhaustive assignments, one fixed demand, one network, one event, native deterministic simulator; no LLM or agents'}
 (OUT/'joint'/'summary.json').write_text(json.dumps(summary,indent=2))
 print('SUMMARY',json.dumps(summary,indent=2),flush=True)
 if not summary['all_complete'] or not summary['all_routes_verified'] or not summary['all_destinations_reached'] or not summary['all_faults_enforced']:raise SystemExit(1)
if __name__=='__main__':main()
