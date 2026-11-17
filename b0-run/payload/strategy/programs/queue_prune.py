PRUNE_LUA = r'''
local n=tonumber(ARGV[1])
local entries={}
local p=2
for i=1,n do
  local key,kind,raw,score=ARGV[p],ARGV[p+1],ARGV[p+2],ARGV[p+3]
  local expected,count=tonumber(ARGV[p+4]),tonumber(ARGV[p+5])
  p=p+6
  local typ=redis.call('TYPE',key)['ok']
  if typ~=kind then return {'precondition_failed',tostring(i),'type'} end
  if kind=='list' then
    local actual=0
    for _,v in ipairs(redis.call('LRANGE',key,0,-1)) do if v==raw then actual=actual+1 end end
    if actual~=expected or count>actual then return {'precondition_failed',tostring(i),'count'} end
  elseif kind=='zset' then
    local current=redis.call('ZSCORE',key,raw)
    if current~=score or expected~=1 or count~=1 then return {'precondition_failed',tostring(i),'score'} end
  else return {'precondition_failed',tostring(i),'unsupported'} end
  entries[i]={key,kind,raw,count}
end
local result={'applied'}
for i,e in ipairs(entries) do
  local removed
  if e[2]=='list' then removed=redis.call('LREM',e[1],e[4],e[3])
  else removed=redis.call('ZREM',e[1],e[3]) end
  table.insert(result,tostring(removed))
end
return result
'''

try:
    server=txt(conn.call('INFO','server'))
    info={line.split(':',1)[0]:line.split(':',1)[1] for line in server.splitlines() if ':' in line and not line.startswith('#')}
    if info.get('run_id')!=cfg['redis_run_id']:raise RuntimeError('Redis_instance_changed')
    before=inspect_queue(conn)
    if before['inventory_token']!=cfg['before_token']:raise RuntimeError('queue_capture_changed_before_prune')
    if before['work']:raise RuntimeError('workset_present_prune_refused')
    selected=cfg['selected'];args=[str(len(selected))];validated=[];seen=set()
    for sel in selected:
        key=(sel['key'],sel['raw_sha256'],sel['score'])
        if key in seen:raise RuntimeError('duplicate_selection')
        seen.add(key)
        matches=[row for row in before['jobs'] if (row['key'],row['raw_sha256'],row['score'])==key]
        if len(matches)!=sel['expected_occurrences'] or not matches or any(row['jid']!=sel['jid'] for row in matches):
            raise RuntimeError('selected_payload_or_count_changed')
        if sel['delete_count']>len(matches):raise RuntimeError('selected_delete_count_exceeds_count')
        raw=base64.b64decode(matches[0]['raw_base64'],validate=True)
        if any(base64.b64decode(row['raw_base64'],validate=True)!=raw for row in matches):raise RuntimeError('digest_collision_or_payload_ambiguity')
        if matches[0]['type']=='zset' and (sel['expected_occurrences']!=1 or sel['delete_count']!=1):raise RuntimeError('zset_selection_invalid')
        args.extend([sel['key'],matches[0]['type'],raw,sel['score'] or '',str(sel['expected_occurrences']),str(sel['delete_count'])])
        validated.append({**sel,'type':matches[0]['type']})
    response=conn.call('EVAL',PRUNE_LUA,0,*args)
    after=inspect_queue(conn)
    tag=txt(response[0])
    removed=[int(txt(x)) for x in response[1:]] if tag=='applied' else []
    remaining_counts={ (row['key'],row['raw_sha256'],row['score']):row['delete_count'] for row in selected }
    expected=[]
    for row in before['jobs']:
        key=(row['key'],row['raw_sha256'],row['score'])
        if remaining_counts.get(key,0)>0:
            remaining_counts[key]-=1
        else:expected.append(row)
    def sequence(rows):
        grouped={}
        for row in rows:grouped.setdefault(row['key'],[]).append((row['type'],row['raw_sha256'],row['score']))
        return {k:v for k,v in grouped.items() if v}
    preserved=sequence(expected)==sequence(after['jobs']) and before['work']==after['work']
    server_after=txt(conn.call('INFO','server'))
    info_after={line.split(':',1)[0]:line.split(':',1)[1] for line in server_after.splitlines() if ':' in line and not line.startswith('#')}
    stable_instance=info_after.get('run_id')==cfg['redis_run_id']
    applied=tag=='applied' and removed==[row['delete_count'] for row in selected] and preserved and stable_instance
    emit({'kind':'queue_prune','redis_db':cfg['redis_db'],'peer':conn.peer,'redis_run_id':info.get('run_id'),
        'before':before,'selected':validated,'redis_reply':[txt(x) for x in response],'removed_counts':removed,
        'after':after,'unselected_sequence_and_multiplicity_preserved':preserved,'instance_unchanged':stable_instance,
        'classification':'applied' if applied else 'partial_or_conflict' if tag=='applied' else 'not_applied',
        'commands':commands,'source_complete':True})
finally:
    conn.close()
