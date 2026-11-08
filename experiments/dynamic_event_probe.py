"""Dynamic traffic event probe: a second signal-controller failure invalidates a
previous route after planning. This is a deterministic environment/plan-invalidation
test, NOT a language-agent or multi-agent result. Uses native CityFlow and public
CoLLMLight roadnet/flow. No real traffic infrastructure is controlled.
"""
from pathlib import Path
import ast,json,sys,time,hashlib
ROOT=Path.cwd().resolve();OUT=ROOT/'results/dynamic_event';OUT.mkdir(parents=True,exist_ok=True)
sys.path.insert(0,str(ROOT/'native_build'));sys.path.insert(0,str(ROOT/'upstream/CoLLMLight'))
import cityflow
DATA=ROOT/'upstream/CoLLMLight/data/Hangzhou/4_4'
ROAD=json.loads((DATA/'roadnet_4_4.json').read_text())
INTER={x['id']:x for x in ROAD['intersections'] if not x['virtual']}
ROADS={x['id']:x for x in ROAD['roads']}
tree=ast.parse((ROOT/'upstream/CoLLMLight/utils/cityflow_env.py').read_text())
cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Intersection')
fn=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='_get_traffic_movement_pressure_general');fn.decorator_list=[]
ns={};exec(compile(ast.Module(body=[fn],type_ignores=[]),'pinned_pressure','exec'),ns);pressure=ns[fn.name]
MOV={}
for iid,x in INTER.items():
 for j,m in enumerate(x['roadLinks']):
  phases=[p for p,ph in enumerate(x['trafficLight']['lightphases'][:5]) if j in ph['availableRoadLinks']]
  MOV[m['startRoad'],m['endRoad']]={'iid':iid,'phases':phases,'link_index':j}
ROUTES=[
['road_3_2_2','road_2_2_2','road_1_2_1','road_1_3_0','road_2_3_0','road_3_3_3'],
['road_3_2_2','road_2_2_2','road_1_2_1','road_1_3_1','road_1_4_0','road_2_4_0','road_3_4_3','road_3_3_3'],
['road_3_2_2','road_2_2_2','road_1_2_3','road_1_1_0','road_2_1_1','road_2_2_1','road_2_3_0','road_3_3_3']]
CFG={'interval':1.0,'seed':7,'dir':str(DATA)+'/', 'roadnetFile':'roadnet_4_4.json','flowFile':'anon_4_4_hangzhou_real.json','rlTrafficLight':True,'laneChange':False,'saveReplay':False,'roadnetLogFile':'unused.json','replayLogFile':'unused.txt'}
(ROOT/'results').mkdir(exist_ok=True);(OUT/'config.json').write_text(json.dumps(CFG))
engine=cityflow.Engine(str(OUT/'config.json'),thread_num=1)
class MaxPressurePolicy:
 def choose_action(self,count,state):
  z=state['traffic_movement_pressure_queue']
  values=[z[1]+z[4],z[7]+z[10],z[0]+z[3],z[6]+z[9]]
  return max(range(4),key=lambda i:values[i])
policies={i:MaxPressurePolicy() for i in INTER}
phases={i:1 for i in INTER};pending={};last={i:0 for i in INTER};commands=[]
def setp(i,p):
 engine.set_tl_phase(i,p);phases[i]=p;last[i]=engine.get_current_time();commands.append({'time':engine.get_current_time(),'intersection':i,'phase':p})
for i in phases:setp(i,1)
def pressure_state(i,waiting):
 _,x,y=i.split('_');x=int(x);y=int(y)
 ins=[f'road_{x-1}_{y}_0',f'road_{x+1}_{y}_2',f'road_{x}_{y+1}_3',f'road_{x}_{y-1}_1']
 outs=[f'road_{x}_{y}_0',f'road_{x}_{y}_2',f'road_{x}_{y}_3',f'road_{x}_{y}_1']
 a=[waiting.get(f'{r}_{l}',0) for r in ins for l in range(3)];b=[waiting.get(f'{r}_{l}',0) for r in outs for l in range(3)]
 z=pressure(a,b);return {'cur_phase':[phases[i]],'traffic_movement_pressure_queue':z,'phase_pressures':[z[1]+z[4],z[7]+z[10],z[0]+z[3],z[6]+z[9]]}
def tick(faults):
 now=engine.get_current_time()
 for i,(ready,p) in list(pending.items()):
  if now>=ready:
   if any(f['iid']==i and f['start']<=now<f['release'] for f in faults):p=next(f['phase'] for f in faults if f['iid']==i and f['start']<=now<f['release'])
   setp(i,p);del pending[i]
 waiting=engine.get_lane_waiting_vehicle_count()
 if now and int(now)%35==0:
  for i in phases:
   active=next((f for f in faults if f['iid']==i and f['start']<=now<f['release']),None)
   if active:
    if phases[i]!=active['phase']:setp(i,active['phase'])
    pending.pop(i,None);continue
   p=int(policies[i].choose_action(int(now),pressure_state(i,waiting)))+1
   if i not in pending and p!=phases[i]:
    setp(i,0);pending[i]=(now+5,p)
 engine.next_step()
def bfs(start,dest,forbidden,first_allowed=None):
 from collections import deque
 q=deque([(start,[start])]);seen={start}
 while q:
  road,path=q.popleft()
  if road==dest:return path
  end=ROADS[road]['endIntersection']
  if end not in INTER:continue
  for m in INTER[end]['roadLinks']:
   if m['startRoad']!=road:continue
   nxt=m['endRoad']
   if (road,nxt)==forbidden or nxt in seen:continue
   if len(path)==1 and first_allowed is not None and nxt not in first_allowed:continue
   seen.add(nxt);q.append((nxt,path+[nxt]))
 return None
# Freeze a route plan at t=700. A later event blocks a FUTURE movement,
# while preserving the first movement from the vehicle's current lane.
initial={'iid':'intersection_2_3','phase':2,'start':700,'release':1500}
while engine.get_current_time()<700:tick([initial])
vid='flow_1457_0';dest='road_3_3_3';planned=ROUTES[1]
assert engine.get_vehicle_info(vid)['route'].split()==ROUTES[0]
assert engine.set_vehicle_route(vid,planned[1:])
assert engine.get_vehicle_info(vid)['route'].split()==planned
plan_record={'environment_version':1,'planned_at':700,'route':planned,'vehicle':vid,'destination':dest}
while engine.get_current_time()<705:tick([initial])
info=engine.get_vehicle_info(vid);current=info['road'];live_route=info['route'].split()
if live_route[0]!=current:raise RuntimeError('vehicle route snapshot does not start at current road')
if len(live_route)<4:raise RuntimeError('insufficient future route for dynamic event')
first_next=live_route[1]
blocked=None;alternative=None
# Search later planned transitions, never the current lane's immediate movement.
for pos in range(2,len(live_route)-1):
 a,b=live_route[pos],live_route[pos+1]
 movement=MOV.get((a,b))
 if movement is None or movement['iid']==initial['iid']:continue
 forbidden_phases=[p for p in range(1,5) if p not in movement['phases']]
 if not forbidden_phases:continue
 candidate=bfs(current,dest,(a,b),{first_next})
 if candidate and len(candidate)>2 and candidate[1]==first_next:
  blocked={'from_road':a,'to_road':b,'iid':movement['iid'],'blocked_phase':forbidden_phases[0],
           'permitted_phases':movement['phases'],'link_index':movement['link_index'],
           'preserved_first_movement':[current,first_next]}
  alternative=candidate;break
if blocked is None:raise RuntimeError('No alternate route preserving the current lane commitment was found')
second={'iid':blocked['iid'],'phase':blocked['blocked_phase'],'start':705,'release':1005}
setp(second['iid'],second['phase'])
event={'environment_version':2,'time':705,'kind':'signal_controller_stuck','intersection':second['iid'],
       'held_phase':second['phase'],'release':second['release'],'blocked_movement':[blocked['from_road'],blocked['to_road']]}
old_plan_valid=False
new_route=alternative
route_before=engine.get_vehicle_info(vid)
route_set_result=engine.set_vehicle_route(vid,new_route[1:])
route_readback=engine.get_vehicle_info(vid)['route'].split()
if not route_set_result or route_readback!=new_route:
 (OUT/'route_replan_failure.json').write_text(json.dumps({'vehicle':vid,'vehicle_live':vid in engine.get_vehicles(include_waiting=True),
  'vehicle_before':route_before,'current_road':current,'blocked':blocked,'alternative':alternative,
  'new_route':new_route,'set_result':route_set_result,'readback':route_readback},indent=2))
 raise RuntimeError('native route replanning rejected; see route_replan_failure.json')
# Simulate to event release while enforcing both controller failures.
visited=[];arrive=None;queue_sum=0;phase_obs=[{'time':engine.get_current_time(),'phase':engine.observe_tl_phase(second['iid'])}]
start=time.monotonic()
for _ in range(3000):
 live=set(engine.get_vehicles(include_waiting=True))
 if vid in live:
  r=engine.get_vehicle_info(vid).get('road')
  if r and (not visited or visited[-1]!=r):visited.append(r)
 elif arrive is None:arrive=engine.get_current_time()
 tick([initial,second])
 if engine.get_current_time()<1005:phase_obs.append({'time':engine.get_current_time(),'phase':engine.observe_tl_phase(second['iid'])})
 queue_sum+=sum(engine.get_lane_waiting_vehicle_count().values())
if arrive is None and vid not in engine.get_vehicles(include_waiting=True):arrive=engine.get_current_time()
final_vehicle_info=engine.get_vehicle_info(vid) if vid in engine.get_vehicles(include_waiting=True) else None
record={'final_vehicle_info':final_vehicle_info,'scenario':'dynamic second signal-controller fault after route plan','initial_plan':plan_record,'second_event':event,'old_plan_valid_after_event':old_plan_valid,'blocked_movement':blocked,'new_route':new_route,'route_readback':route_readback,'route_set_accepted':True,'visited_roads':visited,'destination_reached':arrive is not None and dest in visited,'arrival_time':arrive,'simulated_seconds_after_replan':3000,'mean_network_queue_during_window':queue_sum/3000,'second_fault_samples':phase_obs,'second_fault_enforced':len(phase_obs)==300 and all(x['phase']==second['phase'] for x in phase_obs),'new_route_avoids_blocked_movement':all(not (visited[i]==blocked['from_road'] and visited[i+1]==blocked['to_road']) for i in range(len(visited)-1)),'new_environment_version':2,'stale_plan_rejected_by_contract':not old_plan_valid,'wall_seconds':time.monotonic()-start,'scope':'one deterministic dynamic event proof; not LLM, not multi-agent, not generalization'}
# Fair no-replan baseline: fresh engine, same seed, same initial route, same two
# faults, same simulation horizon. The only intervention removed is route replanning.
engine=cityflow.Engine(str(OUT/'config.json'),thread_num=1)
phases={i:1 for i in INTER};pending={};last={i:0 for i in INTER};commands=[]
for i in phases:setp(i,1)
while engine.get_current_time()<700:tick([initial])
baseline_before=engine.get_vehicle_info(vid)
assert baseline_before['route'].split()==ROUTES[0]
assert engine.set_vehicle_route(vid,planned[1:])
assert engine.get_vehicle_info(vid)['route'].split()==planned
while engine.get_current_time()<705:tick([initial])
baseline_second={'iid':blocked['iid'],'phase':blocked['blocked_phase'],'start':705,'release':1005}
setp(baseline_second['iid'],baseline_second['phase'])
baseline_visited=[];baseline_arrival=None;baseline_queue=0
for _ in range(3000):
 live=set(engine.get_vehicles(include_waiting=True))
 if vid in live:
  road=engine.get_vehicle_info(vid).get('road')
  if road and (not baseline_visited or baseline_visited[-1]!=road):baseline_visited.append(road)
 elif baseline_arrival is None:baseline_arrival=engine.get_current_time()
 tick([initial,baseline_second])
 baseline_queue+=sum(engine.get_lane_waiting_vehicle_count().values())
if baseline_arrival is None and vid not in engine.get_vehicles(include_waiting=True):baseline_arrival=engine.get_current_time()
record['no_replan_baseline']={'initial_route':planned,'visited_roads':baseline_visited,
 'destination_reached':baseline_arrival is not None and dest in baseline_visited,
 'arrival_time':baseline_arrival,'mean_network_queue_during_window':baseline_queue/3000,
 'blocked_movement_traversed':any(baseline_visited[i]==blocked['from_road'] and baseline_visited[i+1]==blocked['to_road'] for i in range(len(baseline_visited)-1)),
 'scope':'same seed, same initial route and faults, no route intervention'}
record['reroute_vs_no_replan_arrival_delta_sim_s']=None if baseline_arrival is None else baseline_arrival-arrive
(OUT/'result.json').write_text(json.dumps(record,indent=2))
assert record['second_fault_enforced'] and record['new_route_avoids_blocked_movement'] and record['destination_reached']
print(json.dumps(record,indent=2))
