from pathlib import Path
import ast, collections, hashlib, json, sys, time
ROOT=Path.cwd(); DATA=ROOT/'upstream/CoLLMLight/data/Hangzhou/4_4'
sys.path.insert(0,str(ROOT/'native_build'))
import cityflow
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
CFG={'interval':1.0,'seed':7,'dir':str(DATA)+'/', 'roadnetFile':'roadnet_4_4.json','flowFile':'anon_4_4_hangzhou_real.json','rlTrafficLight':True,'laneChange':False,'saveReplay':False,'roadnetLogFile':'unused.json','replayLogFile':'unused.txt'}
OUT=ROOT/'results';OUT.mkdir(exist_ok=True);(OUT/'config.json').write_text(json.dumps(CFG))
def pressure_state(i,w,phases):
 _,x,y=i.split('_');x=int(x);y=int(y)
 ins=[f'road_{x-1}_{y}_0',f'road_{x+1}_{y}_2',f'road_{x}_{y+1}_3',f'road_{x}_{y-1}_1']
 outs=[f'road_{x}_{y}_0',f'road_{x}_{y}_2',f'road_{x}_{y}_3',f'road_{x}_{y}_1']
 a=[w.get(f'{r}_{l}',0) for r in ins for l in range(3)];b=[w.get(f'{r}_{l}',0) for r in outs for l in range(3)]
 z=pressure(a,b);return {'cur_phase':[phases[i]],'traffic_movement_pressure_queue':z}
e=cityflow.Engine(str(OUT/'config.json'),thread_num=1)
phases={i:1 for i in INTER};pending={};last={i:0 for i in INTER}
for i in phases:e.set_tl_phase(i,1)
initial={'iid':'intersection_2_3','phase':2,'start':700,'release':1500}
def tick():
 now=e.get_current_time()
 for i,(ready,p) in list(pending.items()):
  if now>=ready:
   if i==initial['iid'] and initial['start']<=now<initial['release']:p=initial['phase']
   e.set_tl_phase(i,p);phases[i]=p;last[i]=now;del pending[i]
 if now and int(now)%35==0:
  w=e.get_lane_waiting_vehicle_count()
  for i in phases:
   if i==initial['iid'] and initial['start']<=now<initial['release']:
    if phases[i]!=initial['phase']:e.set_tl_phase(i,initial['phase']);phases[i]=initial['phase']
    pending.pop(i,None);continue
   z=pressure_state(i,w,phases)['traffic_movement_pressure_queue']
   vals=[z[1]+z[4],z[7]+z[10],z[0]+z[3],z[6]+z[9]]
   p=max(range(4),key=lambda k:vals[k])+1
   if i not in pending and p!=phases[i]:
    e.set_tl_phase(i,0);phases[i]=0;pending[i]=(now+5,p)
 e.next_step()
while e.get_current_time()<705:tick()
def bfs(start,dest,forbidden,first_allowed):
 q=collections.deque([(start,[start])]);seen={start}
 while q:
  road,path=q.popleft()
  if road==dest:return path
  end=ROADS[road]['endIntersection']
  if end not in INTER:continue
  for rl in INTER[end]['roadLinks']:
   if rl['startRoad']!=road:continue
   nxt=rl['endRoad']
   if (road,nxt)==forbidden or nxt in seen:continue
   if len(path)==1 and nxt not in first_allowed:continue
   seen.add(nxt);q.append((nxt,path+[nxt]))
 return None
candidates=[]
for vid in sorted(e.get_vehicles(include_waiting=True)):
 try:info=e.get_vehicle_info(vid)
 except Exception:continue
 cur=info.get('road','');route=info.get('route','').split();drivable=info.get('drivable','')
 if cur not in ROADS or len(route)<4 or not drivable.startswith(cur+'_'):continue
 try:lane=int(drivable.rsplit('_',1)[1]);pos=route.index(cur)
 except Exception:continue
 end=ROADS[cur]['endIntersection']
 if end not in INTER:continue
 first=[]
 for rl in INTER[end]['roadLinks']:
  if rl['startRoad']==cur and any(int(ll['startLaneIndex'])==lane for ll in rl['laneLinks']):first.append(rl['endRoad'])
 if not first:continue
 for k in range(pos+1,min(len(route)-1,pos+9)):
  a,b=route[k],route[k+1];m=MOV.get((a,b))
  if not m or 1 in m['phases']:continue
  alt=bfs(cur,route[-1],(a,b),set(first))
  if alt and len(alt)>2 and alt[1] in first:
   candidates.append({'vehicle':vid,'current':cur,'lane':lane,'drivable':drivable,'route':route,'blocked_move':[a,b],
    'intersection':m['iid'],'required_phases':m['phases'],'alternative':alt,'route_position':k-pos})
   break
by=collections.defaultdict(list)
for c in candidates:by[c['intersection']].append(c)
ranked=sorted(((iid,items) for iid,items in by.items()),key=lambda x:(-len(x[1]),x[0]))
result={'time':705,'candidate_count':len(candidates),'by_intersection':{k:len(v) for k,v in sorted(by.items())},
 'ranked_intersections':[{'intersection':k,'count':len(v),'vehicles':[x['vehicle'] for x in v[:20]]} for k,v in ranked],
 'candidates':candidates,'scope':'pre-outcome lane-feasible candidates on fixed public demand; no LLM/AIOS'}
(OUT/'candidate_pool.json').write_text(json.dumps(result,indent=2))
print(json.dumps({k:v for k,v in result.items() if k!='candidates'},indent=2))
