"""Pre-run source fixes, recorded as an exact diff. No result-dependent tuning."""
from pathlib import Path
import difflib
p=Path('experiments/round8_live.py');a=p.read_text();b=a
old="""    context.append({'role':'user','content':question+' /no_think'})
    for attempt in range(2):
        text,record=n.model(role,context,192);context.append({'role':'assistant','content':text});row={'role':role,'attempt':attempt,'record':record}
"""
new="""    previous=[m for m in context[1:] if m['role']=='assistant'][-2:]
    user={'role':'user','content':question+' /no_think'}
    context.append(user)
    working=[dict(context[0]),*previous,user]
    for attempt in range(2):
        text,record=n.model(role,json.loads(json.dumps(working)),192)
        context.append({'role':'assistant','content':text});working.append({'role':'assistant','content':text})
        row={'role':role,'attempt':attempt,'record':record,'context_policy':'exact latest two own outputs plus current evidence and current peer reply; all older material retained in external trace'}
"""
assert b.count(old)==1;b=b.replace(old,new)
old="""            context.append({'role':'user','content':'Format/evidence validation failed: '+str(e)+'. Correct the JSON using the same public facts; no answer is supplied.'})"""
new="""            repair={'role':'user','content':'Format/evidence validation failed: '+str(e)+'. Correct the JSON using the same public facts; no answer is supplied.'}
            context.append(repair);working.append(repair)"""
assert b.count(old)==1;b=b.replace(old,new)
b=b.replace('canonical(FORMAT)','canonical(dict(FORMAT,version=GATE.version))')
old="""    result['no_hidden_future_in_model_prompts']=not any('\"truth\"' in canonical(x['record']['request']) or '\"duration\":'+str(case['truth'])+',' in canonical(x['record']['request']) for x in TRACE)"""
new="""    result['no_explicit_private_future_fields_in_prompts']=not any(any(key in canonical(x['record']['request']) for key in ['\"truth\"','\"realized_duration\"','\"actual_release\"']) for x in TRACE)
    result['leak_audit_scope']='field-exclusion check, not adversarial sandbox isolation; public forecasts may legitimately include the realized duration as one possible assumption'"""
assert b.count(old)==1;b=b.replace(old,new)
b=b.replace("'new_native_model_runs':True","'new_native_model_runs':any(x.get('model_attempts',0)>0 for x in results)")
p.write_text(b)
out=Path('results');out.mkdir(exist_ok=True)
(out/'round8_prerun.patch').write_text(''.join(difflib.unified_diff(a.splitlines(True),b.splitlines(True),'committed/round8_live.py','executed/round8_live.py')))
compile(b,str(p),'exec')
print('Applied pre-run context and audit guards; exact diff preserved.')
