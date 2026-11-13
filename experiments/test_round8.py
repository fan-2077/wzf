import unittest
from round8_task import DecisionGate,ContractError,expected_scores
from round8_feedback import Ledger,ProtocolError
ROWS=[{'duration':d,'arrival':{'wait':w,'reroute':1652.},'mean_queue':{'wait':100.,'reroute':100.},'all_native_checks_passed':True} for d,w in zip([120,300,600,900],[1310.,1347.,1777.,1973.])]
def art(g,policy='wait'):
 return {'version':g.version,'policy':policy,'evidence_ids':g.public()['evidence_ids'],'reason':'inspect current public facts'}
def plan(g,policy='wait'):
 return {'task_id':g.task_id,'version':g.version,'policy':policy,'evidence_ids':g.public()['evidence_ids']}
class GateTests(unittest.TestCase):
 def setUp(self):self.g=DecisionGate('t',ROWS,'short')
 def test_expected_boundary(self):
  self.assertEqual(expected_scores(ROWS,[.7,.2,.1,0])['best'],'wait');self.assertEqual(expected_scores(ROWS,[0,.1,.3,.6])['best'],'reroute')
 def test_stale_commit_rejected_no_write(self):
  p=plan(self.g);self.g.update('long')
  with self.assertRaisesRegex(ContractError,'stale'):self.g.commit(p)
  self.assertFalse(self.g.executed)
 def test_forged_refs(self):
  p=plan(self.g);p['evidence_ids'][0]='made-up'
  with self.assertRaises(ContractError):self.g.commit(p)
 def test_old_refs_new_version(self):
  p=plan(self.g);self.g.update('long');p['version']=2
  with self.assertRaises(ContractError):self.g.commit(p)
 def test_wrong_task(self):
  p=plan(self.g);p['task_id']='other'
  with self.assertRaises(ContractError):self.g.commit(p)
 def test_boolean_version(self):
  p=plan(self.g);p['version']=True
  with self.assertRaises(ContractError):self.g.commit(p)
 def test_bad_policy(self):
  p=plan(self.g);p['policy']='teleport'
  with self.assertRaises(ContractError):self.g.commit(p)
 def test_duplicate_commit(self):
  self.g.commit(plan(self.g))
  with self.assertRaises(ContractError):self.g.commit(plan(self.g))
 def test_update_after_commit(self):
  self.g.commit(plan(self.g))
  with self.assertRaises(ContractError):self.g.update('long')
 def test_gate_does_not_secretly_replace_suboptimal_policy(self):
  self.g.update('long');p=plan(self.g,'wait');self.assertTrue(self.g.commit(p)['accepted'])
  with self.assertRaises(ContractError):self.g.validate(p,semantic=True)
 def test_probability_nan(self):
  with self.assertRaises(ValueError):expected_scores(ROWS,[float('nan'),.2,.3,.5])
 def test_probability_negative(self):
  with self.assertRaises(ValueError):expected_scores(ROWS,[-1,1,1,0])
class LedgerTests(unittest.TestCase):
 def setUp(self):
  self.g=DecisionGate('t',ROWS,'short');self.l=Ledger('t',['route','event','network','signal']);self.l.set_evidence(self.g.public());self.l.artifact('a','route',art(self.g))
 def req(self):return self.l.request('q','route','event','a','What changed?',self.g.public()['evidence_ids'])
 def reply(self):return {'request_id':'q','version':self.g.version,'evidence_ids':self.g.public()['evidence_ids'],'answer':'Use current estimate'}
 def close(self):
  self.req();self.l.reply('r','q','event','route',self.reply());p=art(self.g);p['consumed_request_id']='q';return self.l.artifact('b','route',p,'a','r')
 def test_structural_close(self):self.close();self.assertEqual(self.l.snapshot()['unique_pairs'],[['event','route']])
 def test_no_pair_before_consumption(self):self.req();self.l.reply('r','q','event','route',self.reply());self.assertFalse(self.l.snapshot()['closed'])
 def test_unknown_artifact_evidence(self):
  p=art(self.g);p['evidence_ids']=['imaginary']
  with self.assertRaises(ProtocolError):self.l.artifact('b','event',p)
 def test_unknown_reply_evidence(self):
  self.req();p=self.reply();p['evidence_ids']=['fake']
  with self.assertRaises(ProtocolError):self.l.reply('r','q','event','route',p)
 def test_wrong_peer(self):
  self.req()
  with self.assertRaises(ProtocolError):self.l.reply('r','q','network','route',self.reply())
 def test_self_review(self):
  with self.assertRaises(ProtocolError):self.l.request('q','route','route','a','x',self.g.public()['evidence_ids'])
 def test_stale_request(self):
  self.req();self.g.update('long');self.l.set_evidence(self.g.public())
  with self.assertRaises(ProtocolError):self.l.reply('r','q','event','route',self.reply())
 def test_stale_reply_cannot_launder_into_fresh_revision(self):
  self.req();self.l.reply('r','q','event','route',self.reply());self.g.update('long');self.l.set_evidence(self.g.public());p=art(self.g);p['consumed_request_id']='q'
  with self.assertRaises(ProtocolError):self.l.artifact('b','route',p,'a','r')
 def test_wrong_request_id(self):
  self.req();p=self.reply();p['request_id']='other'
  with self.assertRaises(ProtocolError):self.l.reply('r','q','event','route',p)
 def test_missing_consumed_id(self):
  self.req();self.l.reply('r','q','event','route',self.reply())
  with self.assertRaises(ProtocolError):self.l.artifact('b','route',art(self.g),'a','r')
 def test_revision_wrong_owner(self):
  self.req();self.l.reply('r','q','event','route',self.reply());p=art(self.g);p['consumed_request_id']='q'
  with self.assertRaises(ProtocolError):self.l.artifact('b','network',p,'a','r')
 def test_unknown_role(self):
  with self.assertRaises(ProtocolError):self.l.artifact('b','wizard',art(self.g))
 def test_empty_reason(self):
  p=art(self.g);p['reason']=''
  with self.assertRaises(ProtocolError):self.l.artifact('b','route',p)
 def test_explicit_revalidation_after_update(self):
  self.g.update('long');self.l.set_evidence(self.g.public())
  with self.assertRaises(ProtocolError):self.req()
  self.l.request('q','route','event','a','Update',self.g.public()['evidence_ids'],revalidate=True)
  self.l.reply('r','q','event','route',self.reply());p=art(self.g,'reroute');p['consumed_request_id']='q';self.l.artifact('b','route',p,'a','r')
  self.assertTrue(self.l.closed[0]['policy_changed'])
 def test_external_return_mutation_does_not_mutate_ledger(self):
  x=self.close();x['payload']['policy']='invalid';self.assertEqual(self.l.snapshot()['artifacts']['b']['payload']['policy'],'wait')
 def test_duplicate_reply_reuse(self):
  self.close();p=art(self.g);p['consumed_request_id']='q'
  with self.assertRaises(ProtocolError):self.l.artifact('c','route',p,'a','r')
 def test_reverse_direction_same_type_pair_not_double_counted(self):
  self.close();self.l.artifact('c','event',art(self.g));self.l.request('q2','event','route','c','Check',self.g.public()['evidence_ids'])
  r=self.reply();r['request_id']='q2';self.l.reply('r2','q2','route','event',r);p=art(self.g);p['consumed_request_id']='q2';self.l.artifact('d','event',p,'c','r2')
  self.assertEqual(len(self.l.snapshot()['unique_pairs']),1)
if __name__=='__main__':unittest.main()
