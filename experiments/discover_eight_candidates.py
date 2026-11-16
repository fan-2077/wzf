from pathlib import Path
import sys,json,collections,hashlib
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import traffic_env as t
OUT=ROOT/'results'/'round10';OUT.mkdir(parents=True,exist_ok=True)
lab=t.Lab(540,OUT/'discovery',seed=7);e=lab.engine
while e.get_current_time()<705:lab.tick([lab.initial])
roads=t.ROADS;inter=t.INTER
mov={}
for iid,x in inter.items():
 for j,m in enumerate(x['roadLinks']):
  phases=[p for p,ph in enumerate(x['trafficLight']['lightphases'][:5]) if j in ph['availableRoadLinks']]
  mov[m['startRoad'],m['endRoad']]={'iid':iid,'phases':phases}
def bfs(start,dest,forbidden,first_allowed):
 q=collections.deque([(start,[start])]);seen={start}
 while q:
  road,path=q.popleft()
  if road==dest:return path
  end=roads[road]['endIntersection']
  if end not in inter:continue
  for m in inter[end]['roadLinks']:
   if m['startRoad']!=road:continue
   nxt=m['endRoad']
   if (road,nxt)==forbidden or nxt in seen:continue
   if len(path)==1 and nxt not in first_allowed:continue
   seen.add(nxt);q.append((nxt,path+[nxt]))
 return None
candidates=[]
for vid in sorted(e.get_vehicles(include_waiting=True)):
 try:info=e.get_vehicle_info(vid)
 except Exception:continue
 current=info.get('road','');route=info.get('route','').split();drivable=info.get('drivable','')
 if current not in roads or len(route)<3 or not drivable.startswith(current+'_'):continue
 try:lane=int(drivable.rsplit('_',1)[1])
 except Exception:continue
 try:pos=route.index(current)
 except ValueError:continue
 if pos+2>=len(route):continue
 end=roads[current]['endIntersection']
 if end not in inter:continue
 first=[]
 for rl in inter[end]['roadLinks']:
  if rl['startRoad']==current and any(int(ll['startLaneIndex'])==lane for ll in rl['laneLinks']):first.append(rl['endRoad'])
 if not first:continue
 for k in range(pos+1,min(len(route)-1,pos+8)):
  a,b=route[k],route[k+1]
  m=mov.get((a,b))
  if not m or m['iid']!='intersection_1_3' or 1 in m['phases']:continue
  alt=bfs(current,route[-1],(a,b),set(first))
  if alt and len(alt)>2 and alt[1] in first:
   candidates.append({'vehicle':vid,'current':current,'lane':lane,'drivable':drivable,'route':route,
    'blocked_move':[a,b],'required_phases':m['phases'],'alternative':alt,'route_position':k-pos})
   break
selected=[];used_roads=set()
for c in candidates:
 if c['current'] in used_roads:continue
 selected.append(c);used_roads.add(c['current'])
 if len(selected)==8:break
result={'candidate_count':len(candidates),'selected_count':len(selected),'selection_rule':'at t=705 before second fault outcome runs, sorted vehicle IDs, first 8 candidates on distinct current roads with lane-feasible alternatives and a future phase-1-blocked movement at intersection_1_3','selected':selected,'all_candidates_first_100':candidates[:100],'seed':7,'fixed_demand_file':True}
(OUT/'frozen_eight_candidates.json').write_text(json.dumps(result,indent=2))
print(json.dumps({'candidate_count':len(candidates),'selected_count':len(selected),'selected':selected},indent=2))
if len(selected)<8:raise SystemExit('Fewer than 8 eligible vehicles; do not silently lower the target')
