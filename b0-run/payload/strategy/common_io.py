"""Common non-model driver plumbing for the fixed public action catalog."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import traceback

from native_bridge import NativeActionBridge

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)

def digest(value):
    return hashlib.sha256(value if isinstance(value,bytes) else canonical(value).encode()).hexdigest()

def parse_capture(capture):
    if capture.get('exit_code') != 0 or capture.get('query',{}).get('target_process_terminal') is not True:
        raise RuntimeError('fixed_program_did_not_complete_successfully')
    rows=[line[len(b'B0_RESULT:'):] for line in capture['stdout'].splitlines() if line.startswith(b'B0_RESULT:')]
    if len(rows)!=1:raise RuntimeError('expected_exactly_one_complete_public_result')
    value=json.loads(rows[0])
    if not isinstance(value,dict):raise RuntimeError('public_result_must_be_object')
    return value

def observation_proof(action,capture,bridge):
    if action['operation']!='observe':raise RuntimeError('observation_proof_for_business_action_forbidden')
    value=parse_capture(capture)
    return {'execution_terminal_qualified':True,'settled_effect':'read_only',
            'claim':'fixed_observer_completed_not_a_business_server_terminal',
            'source_complete':value.get('source_complete'),
            'capture_sha256':digest(capture['stdout']), 'kind':value.get('kind')}

class Driver:
    def __init__(self,catalog):
        self.logs=Path('/logs')
        self.context=json.loads((self.logs/'b0-launch-context.json').read_bytes())
        if self.context['attempt_id']!=os.environ['SRE_NATIVE_ATTEMPT_ID']:
            raise RuntimeError('launcher_environment_attempt_mismatch')
        self.output=self.logs/'b0-strategy'
        self.output.mkdir(mode=0o700,parents=False,exist_ok=False)
        self.calls=0;self.actions=0;self.failures=[]
        self.started=time.monotonic()
        self.wall_limit=float(self.context.get('budgets',{}).get('agent_timeout_seconds',self.context.get('budgets',{}).get('wall_seconds',3600)))
        self.native_python=os.environ['SRE_NATIVE_PYTHON']
        self.native_path=Path('/opt/b0/native_adapter/native_transport.py')
        self.bridge=NativeActionBridge(launch_context=self.context,evidence_directory=self.logs/'b0-common',
            logs_directory=self.logs,transport=lambda command,call_id:self.native('kubectl',{'cmd':command},call_id),
            submit_transport=lambda solution,call_id:self.native('submit',{'solution':solution},call_id),
            api_read_transport=lambda operation,call_id:self.native(operation,{},call_id),catalog=catalog,role='script')

    def check_time(self):
        if time.monotonic()-self.started>self.wall_limit:raise RuntimeError('total_attempt_wall_budget_exhausted')

    def native(self,operation,arguments,call_id):
        self.check_time();self.calls+=1
        request={'operation':operation,'arguments':arguments,'call_id':call_id}
        timeout=min(3700,max(30,self.wall_limit-(time.monotonic()-self.started)))
        result=subprocess.run([self.native_python,str(self.native_path)],input=canonical(request).encode(),
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=dict(os.environ),timeout=timeout,check=False)
        (self.output/(call_id+'.native-stderr')).write_bytes(result.stderr)
        if result.returncode!=0:raise RuntimeError('native_worker_process_failed_'+str(result.returncode))
        value=json.loads(result.stdout)
        if not isinstance(value,dict):raise RuntimeError('native_worker_nonobject')
        return value

    def initialize(self):
        self.bridge.bootstrap()
        return self.bridge.qualify_native_chain()

    def run(self,name,args,*,settle=True,intent_ref=None):
        self.check_time();self.actions+=1
        action_id='script-%04d-%s'%(self.actions,name)
        self.bridge.reserve(action_id,name,args,intent_ref=intent_ref)
        started=self.bridge.execute_once(action_id)
        if started.get('state')=='unknown':raise RuntimeError('action_start_unknown_'+action_id)
        query=self.bridge.query(action_id)
        deadline=min(time.monotonic()+45,self.started+self.wall_limit)
        while query.get('state')=='running' and time.monotonic()<deadline:
            time.sleep(0.2);query=self.bridge.query(action_id)
        capture=self.bridge.capture_all(action_id,query=query)
        value=parse_capture(capture)
        (self.output/(action_id+'.document.json')).write_text(canonical(value)+'\n')
        if settle:
            self.bridge.settle_verified(action_id,capture,verifier=observation_proof)
        return capture,value

    def collect(self,name,args):
        try:
            capture,value=self.run(name,args)
            return {'action_id':capture['action_id'],'document':value,'capture_sha256':digest(capture['stdout'])}
        except Exception as exc:
            record={'program':name,'error_type':type(exc).__name__,'error':str(exc),
                    'traceback':traceback.format_exc(),'action_index':self.actions}
            self.failures.append(record)
            return {'collection_error':record}

    def guarded_audit(self):
        before=self.bridge.guard.check('public_audit_before')
        capture,value=self.run('public_audit',{})
        after=self.bridge.guard.check('public_audit_after')
        if not before.get('valid') or not after.get('valid') or before['ledger_epoch']!=after['ledger_epoch']:
            raise RuntimeError('ledger_epoch_not_current')
        capture['ledger_guards']={'before':before,'after':after}
        return capture,value

def decode_recovery_document(collection):
    doc=collection['document']
    raw=base64.b64decode(doc['data_base64'],validate=True)
    if len(raw)!=doc['bytes'] or hashlib.sha256(raw).hexdigest()!=doc['sha256'] or doc['source_complete'] is not True:
        raise RuntimeError('recovery_public_document_incomplete')
    return json.loads(raw)

def write_result(result):
    path=Path('/logs/b0-agent-result.json')
    with path.open('x') as output:
        output.write(canonical(result)+'\n');output.flush();os.fsync(output.fileno())
