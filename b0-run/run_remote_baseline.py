"""Run one fresh original incident through the common public B0 action surface."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import time
import traceback

import native_host_runtime as infra
import cleanup_owned

HERE = Path(__file__).resolve().parent
PLAN = json.loads((HERE/'execution_plan.json').read_text())
BRANCH = PLAN['branch_ref']

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()

def verify_package():
    manifest = json.loads((HERE/'PACKAGE_MANIFEST.json').read_text())
    paths = list(HERE.rglob('*'))
    if any(p.is_symlink() for p in paths):
        raise RuntimeError('Reviewed package contains a symlink')
    files = {str(p.relative_to(HERE)) for p in paths if p.is_file() and p.name != 'PACKAGE_MANIFEST.json'}
    if files != set(manifest['files']):
        raise RuntimeError('Reviewed package file set differs')
    for name, digest in manifest['files'].items():
        if sha(HERE/name) != digest:
            raise RuntimeError('Reviewed package hash differs: '+name)
    return sha(HERE/'PACKAGE_MANIFEST.json')

def configure():
    infra.REF = BRANCH
    infra.RESULTS = Path(os.environ['GITHUB_WORKSPACE'])/'b0-results'
    infra.START = time.monotonic()
    infra.DEADLINE = infra.START+138*60
    infra.STATE.clear()
    infra.STATE.update({'scope':PLAN['mode'],
        'source_commit':infra.COMMIT,'task':infra.TASK,'profile':'full','deploy_loki':False,
        'agent_executed':False,'model_executed':False,'user_repository_checked_out':True,
        'checkout_scope':'only reviewed b0-run directory at triggering commit',
        'cluster_creation_attempted':False,'ownership_initialized':False,
        'cleanup_verified':False,'commands':[],'b0_pass':False,'agent_recovery_success':None})
    infra.guard()
    if os.environ.get('GITHUB_RUN_ATTEMPT') != '1':
        raise RuntimeError('Only an initial attempt is admitted; failures require a new reviewed attempt')
    infra.STATE['reviewed_package_manifest_sha256'] = verify_package()
    infra.RESULTS.mkdir(exist_ok=False)

def build_image():
    context = infra.WORK/'image-context'
    context.mkdir()
    shutil.copytree(HERE/'payload', context/'payload')
    shutil.copyfile(HERE/'Dockerfile', context/'Dockerfile')
    image = 'sre-b0-public:'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']
    base_tag = 'python:3.11.17-slim-trixie'
    infra.command('resolve_official_python_base',['docker','pull',base_tag],timeout=240)
    _, digests = infra.command('python_base_digests',['docker','image','inspect',base_tag,'--format','{{json .RepoDigests}}'])
    base = next((x for x in json.loads(digests) if re.fullmatch(r'(?:docker.io/library/)?python@sha256:[0-9a-f]{64}',x)),None)
    if base is None: raise RuntimeError('Official Python image digest missing')
    infra.STATE['resolved_python_base_image']=base
    infra.command('build_common_baseline_image',['docker','build','--progress=plain','--build-arg','PYTHON_IMAGE='+base,'--tag',image,str(context)],timeout=1200)
    _, identity=infra.command('agent_image_identity',['docker','image','inspect',image,'--format','{{.Id}}'])
    infra.STATE['agent_image'],infra.STATE['agent_image_id']=image,identity.strip()
    infra.command('agent_image_metadata',['docker','image','inspect',image])
    preflight = infra.RESULTS/'image-preflight'
    preflight.mkdir()
    name='b0-image-preflight-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']
    infra.command('image_common_runtime_preflight',['docker','run','--rm','--name',name,'--network=none',
        '--cpus=4','--memory=8g','--cap-drop=ALL','--cap-add=DAC_OVERRIDE','--security-opt=no-new-privileges',
        '-v',str(preflight)+':/logs',image,'/opt/native/bin/python -B /opt/b0/integration/agent_entry.py --preflight'],timeout=180)
    infra.ENV.update(B0_AGENT_IMAGE=image,B0_AGENT_IMAGE_ID=identity.strip(),
                     B0_RESULTS=str(infra.RESULTS/'native'),PYTHONPATH=str(infra.REPO))

def execute_baseline():
    if infra.DEADLINE-time.monotonic() < 95*60:
        raise RuntimeError('Insufficient remaining budget for first fresh baseline and cleanup')
    rc,_=infra.command('original_native_b0_lifecycle',[
        str(infra.REPO/'.venv/bin/python'),str(HERE/'native_b0_entry.py')],
        timeout=105*60,required=False,cwd=infra.REPO)
    result=infra.RESULTS/'native/b0-native-result.json'
    data=json.loads(result.read_text()) if result.exists() else {}
    infra.STATE.update(native_command_exit_code=rc,native_b0_result=data,
        agent_executed='agent_result' in data,model_executed=False,
        agent_recovery_success=data.get('original_mitigation_success'))
    infra.STATE['source_hashes_after']={name:sha(infra.REPO/name) for name in infra.STATE['source_hashes_before']}
    diff,_=infra.command('tracked_source_unchanged',['git','-C',str(infra.REPO),'diff','--exit-code','--ignore-submodules=untracked','HEAD','--'],required=False)
    unchanged=diff==0 and infra.STATE['source_hashes_before']==infra.STATE['source_hashes_after']
    infra.STATE['source_inputs_unchanged']=unchanged
    infra.STATE['runtime_pass']=rc==0 and data.get('passed') is True and unchanged
    infra.STATE['b0_pass']=data.get('b0_pass') is True and infra.STATE['runtime_pass']

def main():
    def interrupted(signum,frame): raise RuntimeError('Hosted runner interrupted by signal '+str(signum))
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    try:
        configure()
        run=os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']
        cleanup_owned.claim(infra.RESULTS/'ownership.json',work=Path(os.environ['RUNNER_TEMP'])/('sre-native-'+run),cluster='sre-native-'+run)
        infra.prepare()
        extra=['sregym/conductor/conductor_api.py','sregym/phases.py',
               'sregym/service/apps/gitlab/runtime/mail_sink.py','sregym/service/apps/gitlab/runtime/ambiguous_mail_sink.py',
               'mcp_server/kubectl_server_helper/kubectl.py','mcp_server/kubectl_server_helper/kubectl_cmd_runner.py']
        infra.STATE['source_hashes_before'].update({name:sha(infra.REPO/name) for name in extra})
        build_image()
        execute_baseline()
    except BaseException as exc:
        infra.STATE['b0_pass']=False
        infra.STATE['error']={'type':type(exc).__name__,'message':str(exc)}
        traceback.print_exc()
    finally:
        scope=infra.RESULTS/'ownership.json'
        if scope.is_file():
            try:
                extra=cleanup_owned.cleanup(scope)
                infra.save('b0-extra-cleanup.json',extra)
                infra.STATE['extra_cleanup_verified']=extra['passed']
            except BaseException as exc:
                infra.STATE['extra_cleanup_error']=str(exc)
                infra.STATE['extra_cleanup_verified']=False
        else:
            infra.STATE['extra_cleanup_verified']=not infra.STATE.get('agent_executed')
        try: infra.cleanup()
        except BaseException as exc:
            infra.STATE['cleanup_error']={'type':type(exc).__name__,'message':str(exc)}
            infra.STATE['cleanup_verified']=False
        infra.STATE['elapsed_seconds_including_cleanup']=time.monotonic()-infra.START
        infra.STATE['passed']=bool(infra.STATE.get('runtime_pass') and infra.STATE.get('cleanup_verified')
            and infra.STATE.get('extra_cleanup_verified') and infra.STATE.get('source_inputs_unchanged') is True
            and not infra.STATE.get('error') and not infra.STATE.get('cleanup_error'))
        infra.save('b0-execution-summary.json',infra.STATE)
        infra.save('evidence-inventory-pending.json',{'complete':False,'scope':'strict post-cleanup owned export'})
    return 0 if infra.STATE.get('passed') else 1

if __name__=='__main__': raise SystemExit(main())
