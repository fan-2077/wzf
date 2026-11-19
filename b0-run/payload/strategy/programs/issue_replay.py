r=cfg['receipt']
who=request('GET','/api/v4/user')
if who['status']!=200 or who['body'].get('is_admin') is not True:
    raise RuntimeError('explicit_iid_requires_current_admin_in_this_tool')
user={'id':who['body']['id'],'is_admin':True,'state':who['body'].get('state')}
before=request('GET','/api/v4/projects/%d/issues/%d'%(r['project'],r['iid']))
if before['status']==200:
    emit({'kind':'issue_replay','dispatched_post':False,'before':before,'user':user,
          'classification':'already_matches' if matches(before['body'],r) else 'conflict'})
elif before['status']!=404:
    emit({'kind':'issue_replay','dispatched_post':False,'before':before,'user':user,'classification':'precondition_unavailable'})
else:
    payload={key:r[key] for key in ('iid','title','description','confidential')}
    res=request('POST','/api/v4/projects/%d/issues'%r['project'],payload, cfg['correlation_id'])
    post=request('GET','/api/v4/projects/%d/issues/%d'%(r['project'],r['iid'])) if res['status']==201 else None
    ok=res['status']==201 and matches(res['body'],r) and post['status']==200 and matches(post['body'],r)
    emit({'kind':'issue_replay','dispatched_post':True,'before':before,'user':user,'response':res,'post':post,
          'classification':'created_and_verified' if ok else 'partial_or_conflict',
          'mode':'explicit_public_iid','http_synchronous_response_complete':res['response_complete']})
