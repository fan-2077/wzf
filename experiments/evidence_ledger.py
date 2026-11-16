"""Feedback ledger reference. Tool evidence/approvals are trusted-adapter APIs,
not model tools. Verifies provenance and freshness, not truth of arbitrary prose.
This is not an AIOS scheduler, traffic planner or proof of agent superiority.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib,json
from typing import Any
class ProtocolError(ValueError): pass
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
def digest(v):return hashlib.sha256(canonical(v).encode()).hexdigest()
def text(v,label):
    if not isinstance(v,str) or not v.strip():raise ProtocolError(label+': nonempty string required')
    return v
def version(v):
    if type(v) is not int or v<0:raise ProtocolError('version: nonnegative integer required')
    return v
def refs(v):
    if not isinstance(v,(tuple,list)) or not v:raise ProtocolError('nonempty references required')
    v=tuple(text(x,'reference') for x in v)
    if len(v)!=len(set(v)):raise ProtocolError('duplicate reference')
    return v
@dataclass(frozen=True)
class Evidence:
    ref:str;task:str;version:int;payload:str;parents:tuple[str,...];producer:str;digest:str
@dataclass(frozen=True)
class Artifact:
    aid:str;owner:str;task:str;version:int;evidence:tuple[str,...];action:str;finding:str;previous:str|None;consumed:tuple[str,...]
@dataclass(frozen=True)
class Request:
    qid:str;sender:str;recipient:str;subject:str;version:int;question:str
@dataclass(frozen=True)
class Reply:
    rid:str;qid:str;sender:str;recipient:str;version:int;evidence:tuple[str,...];answer:str
@dataclass(frozen=True)
class Approval:
    aid:str;artifact_hash:str;version:int;passed:bool;checks:tuple[str,...];evidence:tuple[str,...]
class Ledger:
    def __init__(self,roles=('event','network','signal','route'),env_version=0):
        self.roles=frozenset(roles)
        if len(self.roles)<2 or any(not isinstance(x,str) or not x for x in self.roles):raise ProtocolError('at least two named roles')
        self.version=version(env_version);self.evidence={};self.artifacts={};self.heads={};self.requests={};self.replies={};self.answered=set();self.consumed=set();self.invalid=set();self.closures=[];self.approvals={}
    def _role(self,r):
        if r not in self.roles:raise ProtocolError('unknown role')
    def advance(self,v):
        v=version(v)
        if v<=self.version:raise ProtocolError('version must increase')
        self.version=v
    def register_evidence(self,ref,task,payload,*,producer='tool',parents=()):
        ref=text(ref,'ref');task=text(task,'task')
        if ref in self.evidence:raise ProtocolError('immutable evidence ID already exists')
        if producer not in {'tool','verifier'}:raise ProtocolError('untrusted evidence producer')
        parents=tuple(parents)
        if parents:self._evidence(parents,task)
        body=canonical(payload);e=Evidence(ref,task,self.version,body,parents,producer,digest([ref,task,self.version,body,parents,producer]));self.evidence[ref]=e;return e
    def invalidate(self,ref):
        if ref not in self.evidence:raise ProtocolError('unknown evidence')
        self.invalid.add(ref)
    def _evidence(self,ids,task):
        ids=refs(ids)
        def visit(eid,active):
            if eid in active:raise ProtocolError('cyclic dependency')
            e=self.evidence.get(eid)
            if not e or eid in self.invalid:raise ProtocolError('missing/invalid evidence')
            if e.task!=task or e.version!=self.version:raise ProtocolError('cross-task or stale evidence')
            for p in e.parents:visit(p,active|{eid})
        for eid in ids:visit(eid,set())
        return ids
    def _current(self,aid):
        a=self.artifacts.get(aid)
        if not a:raise ProtocolError('missing artifact')
        if a.version!=self.version:raise ProtocolError('stale artifact')
        if self.heads.get((a.owner,a.task))!=aid:raise ProtocolError('superseded artifact')
        self._evidence(a.evidence,a.task);return a
    def publish(self,aid,owner,task,evidence,action,finding):
        self._role(owner);text(aid,'artifact');text(task,'task')
        if aid in self.artifacts:raise ProtocolError('duplicate artifact ID')
        ev=self._evidence(evidence,task);text(finding,'finding')
        if not isinstance(action,dict):raise ProtocolError('action must be object')
        a=Artifact(aid,owner,task,self.version,ev,canonical(action),finding,self.heads.get((owner,task)),())
        self.artifacts[aid]=a;self.heads[owner,task]=aid;return a
    def request(self,qid,sender,recipient,subject,question):
        text(qid,'request');self._role(sender);self._role(recipient)
        if qid in self.requests:raise ProtocolError('duplicate request')
        if sender==recipient:raise ProtocolError('self-review')
        a=self._current(subject)
        if a.owner!=sender:raise ProtocolError('requester must own subject')
        q=Request(qid,sender,recipient,subject,self.version,text(question,'question'));self.requests[qid]=q;return q
    def reply(self,rid,qid,sender,recipient,evidence,answer):
        text(rid,'reply');self._role(sender);self._role(recipient)
        if rid in self.replies:raise ProtocolError('duplicate reply')
        q=self.requests.get(qid)
        if not q or qid in self.answered:raise ProtocolError('unknown or already answered request')
        if q.version!=self.version:raise ProtocolError('stale request')
        if (sender,recipient)!=(q.recipient,q.sender):raise ProtocolError('incorrect message route')
        a=self._current(q.subject);ev=self._evidence(evidence,a.task)
        r=Reply(rid,qid,sender,recipient,self.version,ev,text(answer,'answer'));self.replies[rid]=r;self.answered.add(qid);return r
    def revise(self,aid,owner,previous,reply_ids,evidence,action,finding):
        self._role(owner);text(aid,'artifact')
        if aid in self.artifacts:raise ProtocolError('duplicate artifact')
        old=self._current(previous)
        if old.owner!=owner:raise ProtocolError('wrong revision owner')
        ids=refs(reply_ids);ev=self._evidence(evidence,old.task);required=set();roles=set()
        for rid in ids:
            r=self.replies.get(rid)
            if not r or rid in self.consumed:raise ProtocolError('unknown or consumed reply')
            q=self.requests[r.qid]
            if r.version!=self.version or q.version!=self.version:raise ProtocolError('stale reply')
            if r.recipient!=owner or q.subject!=previous:raise ProtocolError('reply belongs to other subject')
            self._evidence(r.evidence,old.task);required.update(r.evidence);roles.add(tuple(sorted((owner,r.sender))))
        if not required.issubset(ev):raise ProtocolError('revision omits peer evidence')
        if not isinstance(action,dict):raise ProtocolError('action must be object')
        body=canonical(action);finding=text(finding,'finding');a=Artifact(aid,owner,old.task,self.version,ev,body,finding,previous,ids)
        self.artifacts[aid]=a;self.heads[owner,old.task]=aid;self.consumed.update(ids)
        self.closures.append({'artifact':aid,'previous':previous,'reply_ids':list(ids),'pairs':[list(p) for p in sorted(roles)],'action_payload_changed':body!=old.action,'finding_changed':finding!=old.finding,'evidence_added':sorted(set(ev)-set(old.evidence)),'causal_benefit_proven':False});return a
    def approve(self,aid,*,passed,checks,evidence):
        a=self._current(aid)
        if type(passed) is not bool:raise ProtocolError('passed must be bool')
        checks=refs(checks);ev=self._evidence(evidence,a.task)
        if any(self.evidence[x].producer!='verifier' for x in ev):raise ProtocolError('requires verifier evidence')
        ap=Approval(aid,digest([a.aid,a.action,a.evidence,a.version]),self.version,passed,checks,ev);self.approvals[aid]=ap;return ap
    def executable(self,aid):
        try:
            a=self._current(aid);ap=self.approvals.get(aid)
            if not ap or not ap.passed or ap.version!=self.version:return False
            self._evidence(ap.evidence,a.task)
            return ap.artifact_hash==digest([a.aid,a.action,a.evidence,a.version])
        except ProtocolError:return False
    def summary(self):
        pairs={tuple(p) for c in self.closures for p in c['pairs']};changed={tuple(p) for c in self.closures if c['action_payload_changed'] for p in c['pairs']}
        return {'reply_consumptions':len(self.consumed),'unordered_pairs':sorted(pairs),'unordered_pair_count':len(pairs),'action_payload_change_closures':sum(c['action_payload_changed'] for c in self.closures),'pairs_with_action_payload_change':sorted(changed),'causal_benefit_proven':False,'competition_requirements_proven':False}
