"""Common non-model driver plumbing for the fixed public action catalog."""
from __future__ import annotations
import base64
import hashlib
import json
import lzma
import math
import os
from pathlib import Path
import re
import subprocess
import time
import traceback
import zlib

from native_bridge import NativeActionBridge

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)

def digest(value):
    return hashlib.sha256(value if isinstance(value,bytes) else canonical(value).encode()).hexdigest()

def parse_capture(capture):
    if capture.get('exit_code') != 0 or capture.get('query',{}).get('target_process_terminal') is not True:
        raise RuntimeError('fixed_program_did_not_complete_successfully')
    # PostgreSQL json_agg emits valid JSON across physical lines. Preserve the
    # complete value after the single marker instead of retaining its first
    # line. json.loads rejects any non-whitespace suffix or second JSON value.
    stdout=capture['stdout']
    markers=list(re.finditer(br'(?m)^(B0_RESULT(?:_ZLIB|_GZIP|_XZ)?):',stdout))
    if len(markers)!=1:raise RuntimeError('expected_exactly_one_complete_public_result')
    marker=markers[0];raw=stdout[marker.end():]
    if marker.group(1)!=b'B0_RESULT':
        envelope=json.loads(raw)
        encoding={b'B0_RESULT_GZIP':'gzip+base64',b'B0_RESULT_ZLIB':'zlib+base64',
                  b'B0_RESULT_XZ':'xz+base64'}[marker.group(1)]
        if (not isinstance(envelope,dict)
                or set(envelope)!={'encoding','uncompressed_bytes','uncompressed_sha256','data_base64'}
                or envelope['encoding']!=encoding or type(envelope['uncompressed_bytes'])is not int
                or not 0<=envelope['uncompressed_bytes']<=64*1024*1024):
            raise RuntimeError('compressed_public_result_invalid_envelope')
        compressed=base64.b64decode(envelope['data_base64'],validate=True)
        if encoding=='xz+base64':
            decoder=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=64*1024*1024)
            raw=decoder.decompress(compressed,max_length=envelope['uncompressed_bytes']+1)
            trailing=decoder.unused_data
        else:
            decoder=zlib.decompressobj(16+zlib.MAX_WBITS if encoding=='gzip+base64' else zlib.MAX_WBITS)
            raw=decoder.decompress(compressed,envelope['uncompressed_bytes']+1)
            trailing=decoder.unused_data or decoder.unconsumed_tail
        if (not decoder.eof or trailing
                or len(raw)!=envelope['uncompressed_bytes'] or digest(raw)!=envelope['uncompressed_sha256']):
            raise RuntimeError('compressed_public_result_not_exact_lossless_content')
    if len(raw)>64*1024*1024:raise RuntimeError('public_result_exceeds_decoded_bound')
    value=json.loads(raw)
    if not isinstance(value,dict):raise RuntimeError('public_result_must_be_object')
    return value

def observation_proof(action,capture,bridge):
    if action['operation']!='observe':raise RuntimeError('observation_proof_for_business_action_forbidden')
    value=parse_capture(capture)
    return {'execution_terminal_qualified':True,'settled_effect':'read_only',
            'claim':'fixed_observer_completed_not_a_business_server_terminal',
            'source_complete':value.get('source_complete'),
            'capture_sha256':digest(capture['stdout']), 'kind':value.get('kind')}

def failed_observation_proof(action,capture,bridge):
    if action['operation']!='observe' or capture.get('query',{}).get('target_process_terminal') is not True:
        raise RuntimeError('failed_observation_has_no_bound_original_target_terminal')
    return {'execution_terminal_qualified':True,'settled_effect':'read_only','source_complete':False,
            'claim':'fixed_read_only_program_exited_with_unusable_evidence_no_business_write_was_enabled',
            'exit_code':capture.get('exit_code'),'capture_sha256':digest(capture['stdout'])}

class ObservationUnavailable(RuntimeError):
    pass

class Driver:
    def __init__(self,catalog,*,trusted_precondition_verifier=None,settle_failed_observers=False):
        self.logs=Path('/logs')
        self.context=json.loads((self.logs/'b0-launch-context.json').read_bytes())
        if self.context['attempt_id']!=os.environ['SRE_NATIVE_ATTEMPT_ID']:
            raise RuntimeError('launcher_environment_attempt_mismatch')
        self.output=self.logs/'b0-strategy'
        self.output.mkdir(mode=0o700,parents=False,exist_ok=False)
        self.calls=0;self.actions=0;self.failures=[]
        self.catalog=catalog;self.settle_failed_observers=settle_failed_observers
        self.initialized=time.monotonic()
        self.started=float(self.context.get('incident_visible_mono',self.initialized)) if settle_failed_observers else self.initialized
        if not math.isfinite(self.started) or self.started<0 or self.started>self.initialized:
            raise RuntimeError('launcher_incident_visible_monotonic_clock_invalid')
        self.wall_limit=float(self.context.get('budgets',{}).get('agent_timeout_seconds',self.context.get('budgets',{}).get('wall_seconds',3600)))
        self.native_python=os.environ['SRE_NATIVE_PYTHON']
        self.native_path=Path('/opt/b0/native_adapter/native_transport.py')
        extra={'trusted_precondition_verifier':trusted_precondition_verifier} if trusted_precondition_verifier is not None else {}
        self.bridge=NativeActionBridge(launch_context=self.context,evidence_directory=self.logs/'b0-common',
            logs_directory=self.logs,transport=lambda command,call_id:self.native('kubectl',{'cmd':command},call_id),
            submit_transport=lambda solution,call_id:self.native('submit',{'solution':solution},call_id),
            api_read_transport=lambda operation,call_id:self.native(operation,{},call_id),catalog=catalog,role='script',**extra)

    def check_time(self):
        if time.monotonic()-self.started>self.wall_limit:raise RuntimeError('total_attempt_wall_budget_exhausted')

    def native(self,operation,arguments,call_id):
        self.check_time();self.calls+=1
        request={'operation':operation,'arguments':arguments,'call_id':call_id}
        remaining=self.wall_limit-(time.monotonic()-self.started)
        if remaining<=0:raise RuntimeError('total_attempt_wall_budget_exhausted_before_native_dispatch')
        # Preserve the pinned transport's 330-second read budget while bounding
        # an otherwise unbounded SSE teardown. A lost worker result stays
        # unknown; only the original registered target may subsequently be read.
        timeout=min(370,remaining)
        child_environment=dict(os.environ)
        child_environment['SRE_NATIVE_TIMEOUT_SECONDS']=str(min(float(os.environ.get('SRE_NATIVE_TIMEOUT_SECONDS','330')),timeout))
        worker_started=time.monotonic()
        try:
            result=subprocess.run([self.native_python,str(self.native_path)],input=canonical(request).encode(),
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=child_environment,timeout=timeout,check=False)
        except subprocess.TimeoutExpired as error:
            stdout=error.stdout or b'';stderr=error.stderr or b''
            (self.output/(call_id+'.native-timeout-stdout')).write_bytes(stdout)
            (self.output/(call_id+'.native-timeout-stderr')).write_bytes(stderr)
            (self.output/(call_id+'.native-timeout.json')).write_text(canonical({
                'call_id':call_id,'operation':operation,'request_sha256':digest(request),
                'timeout_seconds':timeout,'elapsed_seconds':time.monotonic()-worker_started,
                'incident_remaining_before_worker':remaining,'outcome':'unknown',
                'stdout_available':error.stdout is not None,'stderr_available':error.stderr is not None,
                'stdout_bytes':len(stdout),'stderr_bytes':len(stderr),
                'stdout_sha256':digest(stdout),'stderr_sha256':digest(stderr),
                'new_business_dispatch_permitted':False})+'\n')
            raise
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
        # After an ambiguous launch reply, only query this original action.
        # No new ID or repeat body dispatch is issued to resolve uncertainty.
        query=self.bridge.query(action_id)
        deadline=self.started+self.wall_limit if self.settle_failed_observers else min(time.monotonic()+45,self.started+self.wall_limit)
        while query.get('state')=='running' and time.monotonic()<deadline:
            time.sleep(0.5);query=self.bridge.query(action_id)
        capture=self.bridge.capture_all(action_id,query=query)
        try:
            value=parse_capture(capture)
        except Exception as exc:
            if self.settle_failed_observers and self.catalog.PROGRAMS[name]['operation']=='observe':
                self.bridge.settle_verified(action_id,capture,verifier=failed_observation_proof)
                (self.output/(action_id+'.unavailable.json')).write_text(canonical({'action_id':action_id,
                    'program':name,'exit_code':capture.get('exit_code'),'error':str(exc),
                    'source_complete':False,'business_effect':'read_only'})+'\n')
                raise ObservationUnavailable(name+': '+str(exc)) from exc
            raise
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
