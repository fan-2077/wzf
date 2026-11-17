"""Parse frozen Ruby sources in the task image without executing their bodies."""
import hashlib
import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import traceback

HERE = Path(__file__).resolve().parent
OUT = Path(os.environ['GITHUB_WORKSPACE']) / 'b0-ruby-service-clock-result'
RESULT = {'schema':'b0-ruby-parse-and-readonly-probes-v1','passed':False,
          'native_calls':0,'business_actions':0,'rails_application_started':False,
          'scope':'Changed Ruby syntax when bound; fixed read-only clock/source probes; no service, Rails, SMTP, authorization, or recovery execution',
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
    name='b0-service-clock-'+RESULT['run_id']+'-'+label.replace('_','-')
    CONTAINERS.append(name)
    return command(label,['docker','run','--rm','--name',name,'--network=none',
        '--read-only','--cap-drop=ALL','--security-opt=no-new-privileges',
        '--pids-limit=64','--cpus=2','--memory=512m',
        '-v',str(HERE/'programs')+':/source:ro',
        '--entrypoint','/opt/gitlab/embedded/bin/ruby',image_id,*ruby_args],timeout=30)

def host_clock_snapshot(label):
    values={};errors=[]
    for name,path,link in [('boot_id','/proc/sys/kernel/random/boot_id',False),
        ('time_namespace','/proc/self/ns/time',True),('time_namespace_for_children','/proc/self/ns/time_for_children',True),
        ('timens_offsets','/proc/self/timens_offsets',False)]:
        try:
            raw=os.readlink(path).encode() if link else Path(path).read_bytes()
            values[name]=raw
            (OUT/(label+'.'+name)).write_bytes(raw)
        except OSError as error:
            errors.append({'name':name,'path':path,'type':type(error).__name__,'message':str(error)})
    evidence={'read_errors':errors,'monotonic':time.monotonic(),
        'observed_fields':{k:{'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()} for k,v in values.items()}}
    valid=(not errors and len(values)==4
        and bool(re.fullmatch(rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',values['boot_id'].strip()))
        and bool(re.fullmatch(rb'time:\[[0-9]+\]',values['time_namespace']))
        and values['time_namespace']==values['time_namespace_for_children'] and bool(values['timens_offsets']))
    evidence['valid_identity_inputs']=valid
    if valid:
        evidence['identity']={'schema':'b0-monotonic-clock-identity-v1','boot_id':values['boot_id'].strip().decode('ascii'),
            'time_namespace':values['time_namespace'].decode('ascii'),'timens_offsets_sha256':hashlib.sha256(values['timens_offsets']).hexdigest()}
    RESULT[label]=evidence
    (OUT/(label+'.json')).write_text(json.dumps(evidence,indent=2)+'\n')
    return evidence.get('identity')

def run_readonly_probes(image_id,manifest):
    RESULT['clock_identity_qualified']=False
    RESULT['fixed_source_capture_complete']=False
    RESULT['fixed_source_contract_qualified']=False
    errors=[]
    try:
        before=host_clock_snapshot('host_clock_before')
        rc,raw=invoke(image_id,'clock_identity',['/source/clock_identity_probe.rb'])
        after=host_clock_snapshot('host_clock_after')
        assert rc==0
        probe=json.loads(raw)
        (OUT/'container_clock.json').write_text(json.dumps(probe,indent=2)+'\n')
        assert probe['schema']=='b0-readonly-clock-probe-v1'
        assert probe.get('valid_identity_inputs') is True and probe.get('read_errors')==[]
        boot=base64.b64decode(probe['boot_id_base64'],validate=True)
        offsets=base64.b64decode(probe['timens_offsets_base64'],validate=True)
        assert re.fullmatch(rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',boot.strip())
        assert offsets and probe['time_namespace']==probe['time_namespace_for_children']
        assert re.fullmatch(r'time:\[[0-9]+\]',probe['time_namespace'])
        identity={'schema':'b0-monotonic-clock-identity-v1','boot_id':boot.strip().decode('ascii'),
            'time_namespace':probe['time_namespace'],'timens_offsets_sha256':hashlib.sha256(offsets).hexdigest()}
        for suffix,value in [('boot_id',boot),('timens_offsets',offsets),('time_namespace',probe['time_namespace'].encode()),('time_namespace_for_children',probe['time_namespace_for_children'].encode())]:
            (OUT/('container_clock.'+suffix)).write_bytes(value)
        assert before is not None and identity==probe['identity']==before==after
        RESULT['container_clock_identity']=identity
        RESULT['clock_identity_qualified']=True
    except BaseException as error:
        errors.append({'probe':'clock_identity','type':type(error).__name__,'message':str(error)})
        (OUT/'clock_exception.txt').write_text(traceback.format_exc())
    try:
        rc,raw=invoke(image_id,'fixed_sources',['/source/fixed_sources_probe.rb'])
        assert rc==0
        probe=json.loads(raw)
        assert probe['schema']=='b0-fixed-image-sources-probe-v1' and probe['service_started'] is False and probe['business_actions']==0
        expected={v['name']:v for v in manifest['fixed_source_contract']}
        rows=probe['sources']
        assert len(rows)==len(expected)==13 and {r['name'] for r in rows}==set(expected)
        directory=OUT/'fixed_image_sources';directory.mkdir()
        qualifications=[];captured=[];metadata=None
        for row in rows:
            contract=expected[row['name']]
            assert all(row[k]==v for k,v in contract.items())
            summary={k:v for k,v in row.items() if k!='data_base64'}
            if row.get('complete') is True:
                data=base64.b64decode(row['data_base64'],validate=True)
                assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
                assert len(row['resolved_paths'])==1 and row['path']==row['resolved_paths'][0]
                if not contract['unique_glob']:assert row['path']==contract['path_or_pattern']
                (directory/row['name']).write_bytes(data)
                matched=contract['expected_sha256'] is None or row['sha256']==contract['expected_sha256']
                summary['expected_hash_matches']=matched
                qualifications.append(matched)
                captured.append(True)
                if row['name']=='version_manifest':metadata=json.loads(data)
            else:
                captured.append(False);qualifications.append(False)
            RESULT.setdefault('fixed_sources',[]).append(summary)
        RESULT['generated_runtime_paths']=probe['generated_runtime_paths']
        RESULT['fixed_source_capture_complete']=all(captured) and probe['all_fixed_sources_complete'] is True
        RESULT['version_manifest_top_level_type']=type(metadata).__name__
        RESULT['version_manifest_top_level_keys']=sorted(metadata) if isinstance(metadata,dict) else None
        software=metadata.get('software') if isinstance(metadata,dict) else None
        runit=software.get('runit') if isinstance(software,dict) else None
        RESULT['observed_expected_runit_metadata_path']=runit
        RESULT['expected_runit_metadata_path_present']=isinstance(runit,dict) and 'version' in runit
        RESULT['runit_version_contract_qualified']=isinstance(runit,dict) and runit.get('version')=='2.1.2'
        RESULT['fixed_source_contract_qualified']=all(qualifications) and RESULT['runit_version_contract_qualified']
    except BaseException as error:
        errors.append({'probe':'fixed_sources','type':type(error).__name__,'message':str(error)})
        (OUT/'sources_exception.txt').write_text(traceback.format_exc())
    RESULT['probe_errors']=errors


def main():
    OUT.mkdir(exist_ok=False)
    try:
        assert os.environ['GITHUB_REPOSITORY']=='fan-2077/wzf'
        assert os.environ.get('GITHUB_ACTIONS')=='true'
        assert os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted'
        assert re.fullmatch(r'[0-9]+',RESULT['run_id'] or '')
        assert RESULT['ref']=='refs/heads/sre-b0-service-clock-20261117'
        assert RESULT['attempt']=='1'
        raw=(HERE/'programs/MANIFEST.json').read_bytes()
        assert hashlib.sha256(raw).hexdigest()=='706d6e105881121f39710694c081dfe1e189bb49650d49b706833991240a0e56'
        manifest=json.loads(raw)
        rows=manifest['programs']
        assert manifest['syntax_binding_status']=='pending_frozen_strategy_v5' and rows==[]
        probes=manifest['probes']
        assert {r['path'] for r in probes}=={'clock_identity_probe.rb','fixed_sources_probe.rb'}
        RESULT['syntax_binding_status']=manifest['syntax_binding_status']
        RESULT['changed_ruby_syntax_qualified']=False
        assert set(p.name for p in (HERE/'programs').iterdir())=={'MANIFEST.json'}|{r['path'] for r in rows+probes}
        for row in rows+probes:
            assert re.fullmatch(r'[a-z_]+\.rb',row['path'])
            path=HERE/'programs'/row['path']
            assert not path.is_symlink() and path.is_file()
            source=path.read_bytes()
            assert len(source)==row['bytes'] and hashlib.sha256(source).hexdigest()==row['sha256']
        shutil.copytree(HERE/'programs',OUT/'frozen_sources')
        RESULT['source_manifest_sha256']=hashlib.sha256(raw).hexdigest()
        expected_names={'b0-service-clock-'+RESULT['run_id']+'-'+label.replace('_','-')
            for label in ['ruby_version','clock_identity','fixed_sources']+['parse_'+Path(row['path']).stem for row in rows]}
        rc,raw=command('preexisting_containers',['docker','ps','-a','--format','{{.Names}}'],timeout=30)
        assert rc==0 and not (set(raw.decode('utf-8','replace').splitlines()) & expected_names), 'owned names already occupied'
        RESULT['expected_container_names']=sorted(expected_names)
        RESULT['all_expected_names_absent_before_any_run']=True
        RESULT['ownership_scope']='exclusive GitHub-hosted job; all declared names checked before any container launch'
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
        RESULT['changed_ruby_syntax_qualified']=bool(rows) and all(r['syntax_ok'] for r in RESULT['programs'])
        run_readonly_probes(image_id,manifest)
        RESULT['passed']=RESULT['clock_identity_qualified'] and RESULT['fixed_source_capture_complete'] and RESULT['fixed_source_contract_qualified']
        RESULT['classification']='READONLY_PROBES_QUALIFIED_RUBY_NOT_ATTEMPTED' if RESULT['passed'] and not rows else 'READONLY_PROBES_NOT_QUALIFIED'
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
