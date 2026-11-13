"""Reference protocol. Structural closure does NOT imply causal collaboration benefit."""
from __future__ import annotations
import json
class ProtocolError(ValueError):pass
def freeze(x):return json.loads(json.dumps(x,sort_keys=True,allow_nan=False))
class Ledger:
    def __init__(self,task_id,roles):
        self.task_id=task_id;self.roles=frozenset(roles);self.version=1
        self._evidence={};self._artifacts={};self._requests={};self._replies={};self._used=set();self.closed=[]
    def set_evidence(self,public):
        v=public['version']
        if public['task_id']!=self.task_id or type(v) is not int or v<self.version:raise ProtocolError('invalid public version')
        self.version=v
        for ref in public['evidence_ids']:
            rec={'task':self.task_id,'version':v,'payload':freeze(public)}
            if ref in self._evidence and self._evidence[ref]!=rec:raise ProtocolError('evidence ID overwritten')
            self._evidence[ref]=rec
    def _refs(self,refs):
        if not isinstance(refs,list) or not refs or len(set(refs))!=len(refs):raise ProtocolError('invalid refs')
        for ref in refs:
            rec=self._evidence.get(ref)
            if not rec:raise ProtocolError('unregistered evidence')
            if rec['version']!=self.version:raise ProtocolError('stale evidence')
    def artifact(self,aid,role,payload,revision_of=None,consumed=None):
        if not aid or aid in self._artifacts or role not in self.roles:raise ProtocolError('identity')
        if type(payload.get('version')) is not int or payload['version']!=self.version:raise ProtocolError('stale artifact')
        if payload.get('policy') not in [None,'wait','reroute']:raise ProtocolError('invalid policy')
        self._refs(payload.get('evidence_ids'))
        if not isinstance(payload.get('reason'),str) or not payload['reason'].strip():raise ProtocolError('empty reason')
        if revision_of is None and consumed is not None:raise ProtocolError('reply without revision')
        if revision_of is not None:
            old=self._artifacts.get(revision_of)
            if not old or old['role']!=role:raise ProtocolError('wrong revision owner')
            rep=self._replies.get(consumed)
            if not rep or consumed in self._used:raise ProtocolError('unknown or used reply')
            req=self._requests[rep['request_id']]
            if req['from']!=role or req['subject']!=revision_of:raise ProtocolError('wrong reply subject')
            if req['version']!=self.version or rep['version']!=self.version:raise ProtocolError('stale exchange')
            if payload.get('consumed_request_id')!=req['id']:raise ProtocolError('requester did not identify consumed request')
            if not set(rep['payload']['evidence_ids']).issubset(payload['evidence_ids']):raise ProtocolError('reply evidence omitted')
        stored={'id':aid,'role':role,'version':self.version,'payload':freeze(payload),'revision_of':revision_of,'reply_id':consumed}
        self._artifacts[aid]=stored
        if revision_of is not None:
            self._used.add(consumed)
            self.closed.append({'request_id':req['id'],'pair':sorted([req['from'],req['to']]),'before':revision_of,'after':aid,
                                'policy_changed':old['payload']['policy']!=payload['policy'],
                                'evidence_changed':set(old['payload']['evidence_ids'])!=set(payload['evidence_ids']),
                                'scope':'protocol closure only; not proof the peer caused improvement'})
        return freeze(stored)
    def request(self,rid,sender,recipient,subject,question,refs,revalidate=False):
        if not rid or rid in self._requests:raise ProtocolError('duplicate request')
        if sender==recipient or sender not in self.roles or recipient not in self.roles:raise ProtocolError('not different peer types')
        art=self._artifacts.get(subject)
        if not art or art['role']!=sender:raise ProtocolError('subject ownership')
        if art['version']!=self.version and not revalidate:raise ProtocolError('stale subject requires explicit revalidation')
        self._refs(refs)
        if not isinstance(question,str) or not question.strip():raise ProtocolError('empty question')
        req={'id':rid,'from':sender,'to':recipient,'subject':subject,'version':self.version,'question':question,'refs':refs,'revalidate':revalidate}
        self._requests[rid]=freeze(req);return freeze(req)
    def reply(self,pid,rid,sender,recipient,payload):
        if not pid or pid in self._replies:raise ProtocolError('duplicate reply')
        req=self._requests.get(rid)
        if not req or req['version']!=self.version:raise ProtocolError('unknown or stale request')
        if req['to']!=sender or req['from']!=recipient:raise ProtocolError('reply identity mismatch')
        if payload.get('request_id')!=rid:raise ProtocolError('wrong request ID')
        if type(payload.get('version')) is not int or payload['version']!=self.version:raise ProtocolError('stale reply')
        self._refs(payload.get('evidence_ids'))
        if not isinstance(payload.get('answer'),str) or not payload['answer'].strip():raise ProtocolError('empty answer')
        rep={'id':pid,'request_id':rid,'from':sender,'to':recipient,'version':self.version,'payload':freeze(payload)}
        self._replies[pid]=rep;return freeze(rep)
    def snapshot(self):
        return freeze({'task':self.task_id,'version':self.version,'artifacts':self._artifacts,'requests':self._requests,'replies':self._replies,
                       'closed':self.closed,'unique_pairs':sorted(set(tuple(x['pair']) for x in self.closed))})
