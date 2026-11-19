results=[]
for r in cfg['receipts']:
    res=request('GET', '/api/v4/projects/%d/issues/%d'%(r['project'],r['iid']))
    if res['status']==404:
        classification='absent'; obj=None
    elif res['status']==200:
        obj=public_issue(res['body']); classification='matches' if matches(obj,r) else 'conflict'
    else:
        classification='unavailable'; obj=None
    results.append({'key':{'project':r['project'],'iid':r['iid']},'classification':classification,'issue':obj,'response':res})
emit({'kind':'issue_inventory','results':results,'source_complete':True})
