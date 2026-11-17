"""Common neutral ledger-lifecycle guard; host metadata never reaches the solver.

The proof is conditional on the dedicated trusted launcher, unchanged fixed
provider, no outside administrator, and denied solver access to provider control.
Endpoint observations do not constitute continuous or adversarial monitoring.
No database row, fault setting, message count, or recovery answer is read here.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import threading
import time
import uuid

NONCE = re.compile(r'[a-f0-9]{32}\Z')
NAMESPACE = 'gitlab-ce'
FILES = ('mail_sink.py', 'ambiguous_mail_sink.py', 'intermittent_mail_sink.py')
REQUEST_SCHEMA = 'b0-ledger-guard-request-v1'
RESPONSE_SCHEMA = 'b0-ledger-guard-response-v1'

# This fixed host-side observation reads only file identity and source bytes.
# It opens neither the SQLite database nor its journal as database content.
PROVIDER_OBSERVATION = r'''
import hashlib,json,os,stat
from pathlib import Path
def ident(path):
    s=os.stat(path,follow_symlinks=False)
    if not stat.S_ISREG(s.st_mode): raise RuntimeError('Expected regular ledger')
    return {'device':s.st_dev,'inode':s.st_ino,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'nlink':s.st_nlink}
def ns(name): return os.readlink('/proc/1/ns/'+name)
source={name:hashlib.sha256(Path('/runtime/'+name).read_bytes()).hexdigest() for name in ('mail_sink.py','ambiguous_mail_sink.py','intermittent_mail_sink.py')}
mounts=[line for line in Path('/proc/1/mountinfo').read_text().splitlines() if line.split()[4] in ('/data','/runtime')]
cmd=Path('/proc/1/cmdline').read_bytes().split(b'\0')
if cmd[-1]==b'': cmd.pop()
data={'ledger':ident('/data/mailbox.sqlite'),'source_sha256':source,
      'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
      'pid_namespace':ns('pid'),'mount_namespace':ns('mnt'),
      'pid1_start_ticks':Path('/proc/1/stat').read_text().rsplit(')',1)[1].split()[19],
      'pid1_command':[x.decode() for x in cmd],'mounts':mounts}
if len(mounts)!=2: raise RuntimeError('Expected data and runtime mounts')
print(json.dumps(data,sort_keys=True))
'''

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def atomic(path, value):
    raw = canonical(value) + b'\n'
    temp = path.with_name('.' + path.name + '.' + uuid.uuid4().hex + '.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        os.chmod(temp, 0o644)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)

class LedgerLifecycleGuard:
    def __init__(self, *, attempt_id, agent_logs, evidence, source_root, maximum_requests=1024):
        self.attempt_id = attempt_id
        self.agent_logs, self.evidence = Path(agent_logs), Path(evidence)
        self.source_root = Path(source_root)
        self.maximum_requests = maximum_requests
        self.requests = self.agent_logs / 'lifecycle-requests'
        self.responses = self.agent_logs / 'lifecycle-responses'
        self.requests.mkdir(mode=0o777)
        self.responses.mkdir(mode=0o755)
        # The isolated agent runs as root; file IPC is not an authentication
        # boundary against hostile code with the same access to its own logs.
        self.evidence.mkdir(mode=0o700)
        self.expected_sources = {name: hashlib.sha256((self.source_root / 'sregym/service/apps/gitlab/runtime' / name).read_bytes()).hexdigest() for name in FILES}
        self.invalid = False
        self.reason = 'not_initialized'
        self.epoch = None
        self.baseline = None
        self.sequence = 0
        self.processed = set()
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.thread = None

    def kubectl(self, args):
        completed = subprocess.run(['kubectl', *args, '--request-timeout=15s'],
                                   capture_output=True, text=True, timeout=25, check=True)
        return json.loads(completed.stdout)

    def snapshot(self):
        namespace = self.kubectl(['get', 'namespace', NAMESPACE, '-o', 'json'])
        objects = self.kubectl(['get', 'pods', '-n', NAMESPACE, '-l', 'app=notification-mailbox', '-o', 'json'])
        pods = objects['items']
        if len(pods) != 1:
            raise RuntimeError('Provider Pod identity is not unique')
        pod = pods[0]
        if pod['metadata'].get('deletionTimestamp') or pod['status'].get('phase') != 'Running':
            raise RuntimeError('Provider Pod is not stably running')
        containers = pod['spec']['containers']
        if len(containers) != 1 or containers[0]['name'] != 'mailbox':
            raise RuntimeError('Unexpected provider container set')
        container = containers[0]
        states = pod['status'].get('containerStatuses', [])
        if len(states) != 1 or states[0]['name'] != 'mailbox':
            raise RuntimeError('Provider runtime identity is unavailable')
        state = states[0]
        if not state.get('ready') or not state.get('state', {}).get('running') or not state.get('containerID') or not state.get('imageID'):
            raise RuntimeError('Provider container is not ready')
        if container.get('command') != ['python', '-u', '/runtime/intermittent_mail_sink.py'] or container.get('args'):
            raise RuntimeError('Unexpected provider entrypoint')
        if container.get('image') != 'python:3.12.13-alpine3.23':
            raise RuntimeError('Unexpected declared provider image')
        data_mount = [m for m in container.get('volumeMounts', []) if m.get('mountPath') == '/data']
        runtime_mount = [m for m in container.get('volumeMounts', []) if m.get('mountPath') == '/runtime']
        if len(data_mount) != 1 or len(runtime_mount) != 1 or runtime_mount[0].get('readOnly') is not True:
            raise RuntimeError('Provider mount scope differs')
        volumes = {v['name']:v for v in pod['spec']['volumes']}
        claim = volumes[data_mount[0]['name']].get('persistentVolumeClaim', {}).get('claimName')
        runtime_name = volumes[runtime_mount[0]['name']].get('configMap', {}).get('name')
        if claim != 'notification-mailbox' or runtime_name != 'notification-provider-runtime':
            raise RuntimeError('Unexpected provider persistence or source mount')
        pvc = self.kubectl(['get', 'pvc', claim, '-n', NAMESPACE, '-o', 'json'])
        if pvc['status'].get('phase') != 'Bound' or not pvc['spec'].get('volumeName'):
            raise RuntimeError('Provider volume is not bound')
        pv = self.kubectl(['get', 'pv', pvc['spec']['volumeName'], '-o', 'json'])
        claim_ref = pv['spec'].get('claimRef', {})
        if claim_ref.get('uid') != pvc['metadata']['uid'] or claim_ref.get('namespace') != NAMESPACE or claim_ref.get('name') != claim:
            raise RuntimeError('Provider persistent volume claim binding differs')
        # Pass all kubectl options before --: the fixed Python program receives
        # no appended CLI flags and no credentials or provider configuration.
        completed = subprocess.run(['kubectl', '--request-timeout=20s', 'exec', '-n', NAMESPACE,
                                    pod['metadata']['name'], '-c', 'mailbox', '--',
                                    'python', '-I', '-S', '-c', PROVIDER_OBSERVATION],
                                   capture_output=True, text=True, timeout=30, check=True)
        observed = json.loads(completed.stdout)
        if observed.get('source_sha256') != self.expected_sources:
            raise RuntimeError('Mounted provider source differs from pinned public source')
        if observed.get('pid1_command') != ['python', '-u', '/runtime/intermittent_mail_sink.py']:
            raise RuntimeError('Provider process identity differs')
        if observed.get('ledger', {}).get('nlink') != 1:
            raise RuntimeError('Ledger has an unexpected link identity')
        # Ignore mutable resourceVersion/health timestamps and data-file size.
        # These are expected to change with legitimate append-only delivery.
        return {'namespace_uid': namespace['metadata']['uid'],
                'pod': {'name': pod['metadata']['name'], 'uid': pod['metadata']['uid'],
                        'node': pod['spec']['nodeName']},
                'container': {'name': 'mailbox', 'container_id': state['containerID'],
                              'restart_count': state['restartCount'], 'image_id': state['imageID'],
                              'started_at': state['state']['running']['startedAt']},
                'pvc': {'name': claim, 'uid': pvc['metadata']['uid'], 'volume_name': pvc['spec']['volumeName']},
                'pv': {'uid': pv['metadata']['uid'], 'claim_uid': claim_ref['uid']},
                'mount_spec_sha256': sha({'volumes':pod['spec']['volumes'],'mounts':container['volumeMounts']}),
                'provider_observation': observed}

    def initialize(self):
        with self.lock:
            if self.baseline is not None or self.epoch is not None:
                raise RuntimeError('A ledger guard cannot reset or start a second epoch')
            first = self.snapshot()
            second = self.snapshot()
            if first != second:
                raise RuntimeError('Provider identity changed during guard initialization')
            self.baseline = first
            self.epoch = sha({'attempt_id': self.attempt_id, 'physical_ledger': first})
            self.reason = 'continuous_with_bound_instance'
            atomic(self.evidence / 'initial-binding.json', {
                'schema':'b0-host-ledger-binding-v1', 'attempt_id':self.attempt_id,
                'ledger_epoch': self.epoch, 'snapshot': first,
                'second_observation_equal': True, 'observation_program_sha256': hashlib.sha256(PROVIDER_OBSERVATION.encode()).hexdigest(),
                'contract':'Trusted launcher; fixed append-only provider; no outside admin; denied solver provider control; no database content read',
                'not_claimed':'Continuous monitoring or hostile-same-UID authentication'})
            return {'namespace_uid': first['namespace_uid'], 'ledger_epoch': self.epoch}

    def check(self, nonce, *, cause='solver_request'):
        with self.lock:
            if self.baseline is None:
                raise RuntimeError('Guard has no bound ledger')
            self.sequence += 1
            started = time.monotonic()
            observed, error = None, None
            if not self.invalid:
                try:
                    observed = self.snapshot()
                    if observed != self.baseline:
                        self.invalid, self.reason = True, 'bound_instance_changed'
                except Exception as exc:
                    self.invalid, self.reason = True, 'observation_unavailable'
                    # Only this host-retained record contains diagnostic details.
                    error = {'type':type(exc).__name__, 'message':str(exc)}
            response = {'schema':RESPONSE_SCHEMA, 'attempt_id':self.attempt_id,
                        'nonce':nonce, 'sequence':self.sequence, 'ledger_epoch':self.epoch,
                        'valid':not self.invalid, 'reason_code':self.reason}
            atomic(self.evidence / f'{self.sequence:05d}-{nonce}.json', {
                'response':response, 'cause':cause, 'started_mono':started,
                'ended_mono':time.monotonic(), 'observation':observed, 'error':error})
            return response

    def read_request(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            s = os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or not 0 < s.st_size <= 2048:
                raise ValueError('Invalid lifecycle request file')
            data = os.read(fd, 2049)
            if len(data) != s.st_size:
                raise ValueError('Lifecycle request changed while read')
            request = json.loads(data)
        finally:
            os.close(fd)
        nonce = path.stem
        if (not NONCE.fullmatch(nonce) or request != {'schema':REQUEST_SCHEMA,
                'attempt_id':self.attempt_id, 'nonce':nonce}):
            raise ValueError('Invalid lifecycle request envelope')
        return request

    def _serve(self):
        try:
            while not self.stop_event.is_set():
                for path in sorted(self.requests.iterdir()):
                    if not path.name.endswith('.json') or path.name in self.processed:
                        continue
                    self.processed.add(path.name)
                    if len(self.processed) > self.maximum_requests:
                        raise RuntimeError('Lifecycle request budget exceeded')
                    request = self.read_request(path)
                    response = self.check(request['nonce'])
                    atomic(self.responses / path.name, response)
                self.stop_event.wait(0.05)
        except BaseException as exc:
            with self.lock:
                self.invalid, self.reason = True, 'guard_worker_failed'
            atomic(self.evidence / 'worker-error.json', {'type':type(exc).__name__, 'message':str(exc)})

    def start(self):
        if self.baseline is None or self.thread is not None:
            raise RuntimeError('Guard start state invalid')
        self.thread = threading.Thread(target=self._serve, name='b0-ledger-lifecycle', daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=150)
        complete = self.thread is None or not self.thread.is_alive()
        atomic(self.evidence / 'host-guard-final.json', {
            'attempt_id':self.attempt_id, 'ledger_epoch':self.epoch,
            'checks':self.sequence, 'requests':len(self.processed),
            'valid_until_last_check':not self.invalid, 'reason_code':self.reason,
            'worker_stopped':complete})
        if not complete:
            raise RuntimeError('Lifecycle guard worker did not stop')
        return not self.invalid
