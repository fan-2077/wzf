"""Typed numerical evidence contract. Checks public quantities, not private outcomes.
This is not a natural-language truth checker or an optimal-policy substitute.
"""
from math import isfinite,isclose
from round8_task import expected_scores
class ClaimError(ValueError):pass
UNITS={'expected_arrival':'sim_s','expected_queue':'vehicles'}
def verify_claims(public,payload):
 if type(payload.get('version')) is not int or payload['version']!=public['version']:raise ClaimError('stale evidence version')
 if payload.get('aggregation')!='probability_weighted_mean':raise ClaimError('aggregation must be probability_weighted_mean, not one scenario or the minimum')
 refs=payload.get('evidence_ids')
 if not isinstance(refs,list) or len(refs)!=2 or set(refs)!=set(public['evidence_ids']):raise ClaimError('registered current evidence IDs required')
 if payload.get('policy') not in ['wait','reroute']:raise ClaimError('unknown policy')
 q=payload.get('quantities')
 if not isinstance(q,dict) or set(q)!=set(UNITS):raise ClaimError('both expected_arrival and expected_queue required')
 truth=expected_scores(public['forecast_scenarios'],public['probabilities'])
 for metric,unit in UNITS.items():
  values=q[metric]
  if not isinstance(values,dict) or set(values)!={'wait','reroute','unit'}:raise ClaimError('metric schema')
  if values['unit']!=unit:raise ClaimError(metric+' has incorrect unit; expected '+unit)
  for p in ['wait','reroute']:
   v=values[p]
   if type(v) not in [int,float] or not isfinite(v):raise ClaimError('finite numeric values required')
   if not isclose(v,truth[p][metric],rel_tol=0,abs_tol=0.001):raise ClaimError(metric+'/'+p+' contradicts the weighted public tool evidence')
 return {'numerical_claims_verified':True,'policy_expected_optimal':payload['policy']==truth['best'],
         'scope':'typed public quantities only; no private truth is used, no action silently replaced'}
