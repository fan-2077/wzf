"""Parse frozen Ruby sources in the task image without executing their bodies."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import traceback

HERE = Path(__file__).resolve().parent
OUT = Path(os.environ['GITHUB_WORKSPACE']) / 'b0-ruby-syntax-repair-result'
RESULT = {'schema':'b0-ruby-parse-only-v1','passed':False,
          'native_calls':0,'business_actions':0,'rails_application_started':False,
          'scope':'Ruby syntax only; no runtime, authorization, SMTP, or recovery qualification',
          'run_id':os.environ.get('GITHUB_RUN_ID'),'attempt':os.environ.get('GITHUB_RUN_ATTEMPT'),
          'commit':os.environ.get('GITHUB_SHA'),'ref':os.environ.get('GITHUB_REF'),
          'commands':[],'programs':[]}
CONTAINERS=[]

def command(label, argv, timeout=60):
    start=time.monotonic()
    try:
        proc=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
        rc,raw=proc.returncode,proc.stdout
    except subprocess.TimeoutExpired as error:
        rc,raw=124,(error.stdout or b'')+b'\nTIMEOUT\n'
    path=OUT/(label+'.log')
    path.write_bytes(raw)
    RESULT['commands'].append({'label':label,'argv':argv,'exit_code':rc,
        'elapsed_seconds':time.monotonic()-start,'output_path':path.name,
        'output_sha256':hashlib.sha256(raw).hexdigest(),'output_bytes':len(raw)})
    return rc,raw

def invoke(image_id, label, ruby_args):
    name='b0-ruby-repair-'+RESULT['run_id']+'-'+label.replace('_','-')
    CONTAINERS.append(name)
    return command(label,['docker','run','--rm','--name',name,'--network=none',
        '--read-only','--cap-drop=ALL','--security-opt=no-new-privileges',
        '--pids-limit=64','--cpus=2','--memory=512m',
        '-v',str(HERE/'programs')+':/source:ro',
        '--entrypoint','/opt/gitlab/embedded/bin/ruby',image_id,*ruby_args],timeout=30)

def main():
    OUT.mkdir(exist_ok=False)
    try:
        assert os.environ['GITHUB_REPOSITORY']=='fan-2077/wzf'
        assert os.environ.get('GITHUB_ACTIONS')=='true'
        assert os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted'
        assert re.fullmatch(r'[0-9]+',RESULT['run_id'] or '')
        assert RESULT['ref']=='refs/heads/sre-b0-read-repair-20261117'
        assert RESULT['attempt']=='1'
        raw=(HERE/'programs/MANIFEST.json').read_bytes()
        assert hashlib.sha256(raw).hexdigest()=='49a79ac4925319992015284e7f48bce95e3d5271a87ec11b357cb8cb0390fc6f'
        manifest=json.loads(raw)
        rows=manifest['programs']
        assert len(rows)==2 and {r['path'] for r in rows}=={'runtime_contract.rb','background_contract.rb'}
        assert set(p.name for p in (HERE/'programs').iterdir())=={'MANIFEST.json'}|{r['path'] for r in rows}
        for row in rows:
            assert re.fullmatch(r'[a-z_]+\.rb',row['path'])
            path=HERE/'programs'/row['path']
            assert not path.is_symlink() and path.is_file()
            source=path.read_bytes()
            assert len(source)==row['bytes'] and hashlib.sha256(source).hexdigest()==row['sha256']
        shutil.copytree(HERE/'programs',OUT/'frozen_sources')
        RESULT['source_manifest_sha256']=hashlib.sha256(raw).hexdigest()
        expected_names={'b0-ruby-repair-'+RESULT['run_id']+'-'+label.replace('_','-')
            for label in ['ruby_version']+['parse_'+Path(row['path']).stem for row in rows]}
        rc,raw=command('preexisting_containers',['docker','ps','-a','--format','{{.Names}}'],timeout=30)
        assert rc==0 and not (set(raw.decode('utf-8','replace').splitlines()) & expected_names), 'owned names already occupied'
        RESULT['expected_container_names']=sorted(expected_names)
        RESULT['all_expected_names_absent_before_any_run']=True
        RESULT['ownership_scope']='exclusive GitHub-hosted job; all three names checked before any container launch'
        image='gitlab/gitlab-ce:18.11.12-ce.0'
        rc,_=command('pull_image',['docker','pull',image],timeout=480)
        assert rc==0, 'image pull failed'
        rc,raw=command('image_identity',['docker','image','inspect',image],timeout=30)
        assert rc==0
        meta=json.loads(raw)[0]
        image_id=meta['Id']
        assert re.fullmatch(r'sha256:[0-9a-f]{64}',image_id)
        RESULT['image_tag']=image
        RESULT['image_id']=image_id
        RESULT['repo_digests']=meta['RepoDigests']
        rc,raw=invoke(image_id,'ruby_version',['--version'])
        assert rc==0
        RESULT['ruby_version']=raw.decode('utf-8','replace').strip()
        for row in rows:
            rc,raw=invoke(image_id,'parse_'+Path(row['path']).stem,['-c','/source/'+row['path']])
            RESULT['programs'].append({**row,'exit_code':rc,
                'syntax_ok':rc==0 and raw.strip()==b'Syntax OK'})
        RESULT['passed']=all(r['syntax_ok'] for r in RESULT['programs'])
    except BaseException as error:
        RESULT['error']={'type':type(error).__name__,'message':str(error)}
        (OUT/'exception.txt').write_text(traceback.format_exc())
    finally:
        for index,name in enumerate(CONTAINERS):
            command('remove_owned_'+str(index),['docker','rm','-f',name],timeout=30)
        rc,raw=command('remaining_containers',['docker','ps','-a','--format','{{.Names}}'],timeout=30)
        names=set(raw.decode('utf-8','replace').splitlines())
        RESULT['owned_containers_remaining']=sorted(names & set(CONTAINERS))
        RESULT['cleanup_verified']=rc==0 and not RESULT['owned_containers_remaining']
        RESULT['passed']=RESULT['passed'] and RESULT['cleanup_verified']
        (OUT/'RESULT.json').write_text(json.dumps(RESULT,indent=2)+'\n')
        print(json.dumps({k:RESULT[k] for k in ('passed','scope','native_calls','business_actions','cleanup_verified')}),flush=True)
    return 0 if RESULT['passed'] else 1

if __name__=='__main__':
    raise SystemExit(main())
