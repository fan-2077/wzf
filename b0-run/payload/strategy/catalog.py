"""Common, finite, caller-visible action programs; no reference recovery macro.

Each program performs exactly its declared primitive and captures its own proof.
The controller (and later all agent arms) must select archives, issues, jobs and
notification intents explicitly. Runtime private task/fault files are absent.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import shlex

HERE = Path(__file__).resolve().parent
PROGRAM_DIRECTORY = HERE / 'programs'

def source(name):
    return (PROGRAM_DIRECTORY / name).read_text()

APPLICATION_SOURCES = {
    'lib/api/issues.rb':'06cb42f4cdde9a0ac1cf7cc11dfeb089de52da7e3b954709f27311b7e2e4571a',
    'app/services/issues/create_service.rb':'8cc0fa10b9db97a57c9e150bdca18bd752a24c636feb5e1704ab577ce35ff0fc',
    'app/services/issues/base_service.rb':'c3f44b3c6b61d089e174f4a183227a2c8e2516cf4e756408002806037b3ba12b',
    'app/services/issuable_base_service.rb':'379fe82293adb1988de0db0dd8ef44895d6459b018b70cb7c28efbd77ea309bc',
    'app/mailers/notify.rb':'cb2f63bab9042a36ff9bac9eb93ce83689d30238f80ce55ca322bd80d2711029',
    'app/mailers/emails/issues.rb':'22960e4879f28927011fa01784be95cdafde16658fe9dbdb14d88434a27b591e',
    'lib/gitlab/sidekiq_logging/structured_logger.rb':'f1db323070029462e7c7cba56dd7abb7ff83b2e6bd21e71b798bf162a7dea68a',
    'lib/gitlab/sidekiq_logging/json_formatter.rb':'600d58650098aea2b28b7224f8ca98e78a7d5b3f6590fb5db8bc0674867f6e9f',
    'vendor/gems/sidekiq/lib/sidekiq/processor.rb':'94821033c323767de1518ab34f7083ccd64dac761922f3132771d24bba4073d7',
    'vendor/gems/sidekiq/lib/sidekiq/manager.rb':'d987a7b23a44472e47c010f02630e9d06c03a85dd10fa2c9968ca43ee60722d4',
    'config/initializers/sidekiq.rb':'ae4a73d4447c2ac8a1998a8baceea9d0c55965742f682b5fed823428eb37a3d6',
    'vendor/gems/sidekiq/lib/sidekiq/api.rb':'0370bde2d73f166c53633804a54027bf1d448bd6cc2038a5cdc287bdb8bb4f8b',
    'vendor/gems/sidekiq-reliable-fetch/lib/sidekiq/base_reliable_fetch.rb':'05042b331bda2bdbc8e14d2462f357416da51cbbcca77ff9b57d54f5ff264bd8',
    'vendor/gems/sidekiq-reliable-fetch/lib/sidekiq/interrupted_set.rb':'ed328fbf75308acbb33ee25b865f333b320fde94aecc869e01a3117b7e1064f2',
    'vendor/gems/sidekiq-reliable-fetch/lib/sidekiq/semi_reliable_fetch.rb':'f7bee9ee0dc6ca90acaf5270315b0389d0f72a4909475c0debed5d392fcbd8b1',
}

def shell(name):
    return 'sh -c ' + shlex.quote(source(name)) + ' b0-fixed-body "$1"'

def python(name, common=None):
    text = (source(common)+'\n' if common else '') + source(name)
    return 'python -I -S -c ' + shlex.quote(text) + ' "$1"'

def ruby(name, rails=False):
    supervision=source('service_supervision.rb')+'\n' if name in {
        'service_inventory.rb','service_control.rb','identity_authorization.rb','background_contract.rb','notification_send.rb'} else ''
    text=source('ruby_common.rb')+'\n'+supervision+source(name)
    program=('gitlab-rails runner ' if rails else '/opt/gitlab/embedded/bin/ruby -e ')
    return 'B0_ARGUMENTS="$1" '+program+shlex.quote(text)

runtime_source = ('require "json"\nB0_EXPECTED_APPLICATION_SOURCES = JSON.parse('+json.dumps(json.dumps(APPLICATION_SOURCES,sort_keys=True,separators=(',',':')))+')\n'+source('redis_config_diagnostics.rb')+'\n'+source('runtime_contract.rb'))

PROGRAMS = {
    'runtime_contract':{'operation':'observe','target':'gitlab',
        'body_shell':'cd /opt/gitlab/embedded/service/gitlab-rails && /opt/gitlab/embedded/bin/bundle exec /opt/gitlab/embedded/bin/ruby -e '+shlex.quote(runtime_source)},
    'recovery_files':{'operation':'observe','target':'recovery_console','body_shell':shell('recovery_files.sh')},
    'archive_check':{'operation':'observe','target':'recovery_console','body_shell':shell('archive_check.sh')},
    'database_state':{'operation':'observe','target':'recovery_console','body_shell':shell('database_state.sh')},
    'public_audit':{'operation':'observe','target':'application_client','body_shell':python('public_audit.py','http_common.py')},
    'issue_inventory':{'operation':'observe','target':'application_client','body_shell':python('issue_inventory.py','http_common.py')},
    'queue_inventory':{'operation':'observe','target':'application_client','body_shell':python('queue_inventory.py','redis_common.py')},
    'history_logs':{'operation':'observe','target':'gitlab','body_shell':ruby('history_logs.rb')},
    'identity_authorization':{'operation':'observe','target':'gitlab','body_shell':ruby('identity_authorization.rb',rails=True)},
    'http_completion':{'operation':'observe','target':'gitlab','body_shell':ruby('http_completion.rb')},
    'service_inventory':{'operation':'observe','target':'gitlab','body_shell':ruby('service_inventory.rb')},
    'background_contract':{'operation':'observe','target':'gitlab','body_shell':ruby('background_contract.rb',rails=True)},
    'service_control':{'operation':'service_control','target':'gitlab','body_shell':ruby('service_control.rb')},
    'archive_restore':{'operation':'restore_database','target':'recovery_console','body_shell':shell('archive_restore.sh')},
    'issue_replay':{'operation':'replay_issue','target':'application_client','body_shell':python('issue_replay.py','http_common.py')},
    'queue_prune':{'operation':'queue_prune','target':'application_client','body_shell':python('queue_prune.py','redis_common.py')},
    'notification_send':{'operation':'send_notification','target':'gitlab','body_shell':ruby('notification_send.rb',rails=True)},
}

def exact(args, fields):
    if not isinstance(args,dict) or set(args)!=set(fields):
        raise ValueError('Unknown/missing fixed program parameter')

def identifier(value, maxlen=128):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,'+str(maxlen)+'}',value):
        raise ValueError('Invalid bounded identifier')

def sha(value):
    if not isinstance(value,str) or not re.fullmatch(r'[0-9a-f]{64}',value):raise ValueError('Invalid digest')

def receipt(r, notification=False):
    fields={'project','iid','title','description','confidential'}
    if notification:fields|={'recipient','reason'}
    exact(r,fields)
    if any(type(r[k]) is not int or not 1<=r[k]<=2**53-1 for k in ('project','iid')):raise ValueError('Invalid public issue identity')
    if type(r['confidential']) is not bool:raise ValueError('Confidentiality must be boolean')
    if any(not isinstance(r[k],str) or len(r[k].encode())>65536 or '\x00' in r[k] for k in ('title','description')):raise ValueError('Invalid public issue text')
    if not r['title']:raise ValueError('Empty issue title')
    if notification:
        if r['reason']!='issue-update':raise ValueError('Unsupported notification reason')
        if not isinstance(r['recipient'],str) or not re.fullmatch(r'[A-Za-z0-9_.+-]{1,100}@example\.test',r['recipient']):raise ValueError('Only local synthetic recipient')

def validate_arguments(name,args):
    if name not in PROGRAMS:raise ValueError('Unknown fixed program')
    if name in ('runtime_contract','public_audit','service_inventory','background_contract'):
        exact(args,())
    elif name=='recovery_files':
        exact(args,('kind',))
        if args['kind'] not in ('catalog','issues','notifications'):raise ValueError('Unknown recovery document')
    elif name in ('archive_check','archive_restore'):
        fields={'file','expected_sha256'}
        if name=='archive_restore':fields.add('action_tag')
        exact(args,fields)
        f=args['file']
        if not isinstance(f,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}',f) or '..' in f:raise ValueError('Invalid archive name')
        sha(args['expected_sha256'])
        if name=='archive_restore':identifier(args['action_tag'],48)
    elif name=='database_state':
        exact(args,('action_tag',));identifier(args['action_tag'],48)
    elif name=='service_control':
        fields={'service','verb'}
        if isinstance(args,dict) and args.get('verb')=='stop':fields|={'clock_identity','deadline_monotonic'}
        exact(args,fields)
        if args['service'] not in ('sidekiq','puma') or args['verb'] not in ('stop','start'):raise ValueError('Invalid fixed service action')
        if args['verb']=='stop':
            if type(args['deadline_monotonic'])not in (int,float) or not 0<args['deadline_monotonic']<10**12:
                raise ValueError('Invalid fixed stop deadline')
            clock=args['clock_identity'];exact(clock,('schema','boot_id','time_namespace','timens_offsets_sha256'))
            if clock['schema']!='b0-monotonic-clock-identity-v1':raise ValueError('Invalid clock schema')
            if not isinstance(clock['boot_id'],str) or not re.fullmatch(r'[a-f0-9-]{36}',clock['boot_id']):raise ValueError('Invalid boot identity')
            if not isinstance(clock['time_namespace'],str) or not re.fullmatch(r'time:\[[0-9]+\]',clock['time_namespace']):raise ValueError('Invalid time namespace')
            sha(clock['timens_offsets_sha256'])
    elif name=='queue_inventory':
        exact(args,('redis_db',))
        if type(args['redis_db'])is not int or not 0<=args['redis_db']<=15:raise ValueError('Invalid Redis database')
    elif name=='history_logs':
        exact(args,('job_ids',))
        if not isinstance(args['job_ids'],list) or len(args['job_ids'])>2000 or len(set(args['job_ids']))!=len(args['job_ids']):raise ValueError('Invalid job identity list')
        for value in args['job_ids']:identifier(value)
    elif name=='issue_inventory':
        exact(args,('receipts',))
        if not isinstance(args['receipts'],list) or not 1<=len(args['receipts'])<=2000:raise ValueError('Receipt list bound')
        for r in args['receipts']:receipt(r)
    elif name=='issue_replay':
        exact(args,('receipt','correlation_id'));receipt(args['receipt']);identifier(args['correlation_id'])
    elif name=='identity_authorization':
        exact(args,('intents',))
        if not isinstance(args['intents'],list) or not 1<=len(args['intents'])<=2000:raise ValueError('Intent list bound')
        for r in args['intents']:receipt(r,notification=True)
    elif name=='http_completion':
        exact(args,('request_id',));identifier(args['request_id'])
    elif name=='notification_send':
        exact(args,('intent',));receipt(args['intent'],notification=True)
    elif name=='queue_prune':
        exact(args,('redis_db','redis_run_id','before_token','selected'))
        if type(args['redis_db'])is not int or not 0<=args['redis_db']<=15:raise ValueError('Invalid Redis database')
        if not isinstance(args['redis_run_id'],str) or not re.fullmatch(r'[0-9a-f]{40}',args['redis_run_id']):raise ValueError('Invalid Redis instance')
        sha(args['before_token'])
        if not isinstance(args['selected'],list) or not 1<=len(args['selected'])<=128:raise ValueError('Selected job bound')
        for row in args['selected']:
            exact(row,('key','jid','raw_sha256','score','expected_occurrences','delete_count','public_intent_key'))
            key=row['key']
            if not isinstance(key,str) or len(key)>512 or '\x00' in key or not (key.startswith('queue:') or key.startswith('working:queue:') or key in {'retry','schedule','dead','interrupted'}):raise ValueError('Queue resource outside allowlist')
            identifier(row['jid']);sha(row['raw_sha256'])
            if row['score'] is not None and (not isinstance(row['score'],str) or not re.fullmatch(r'-?[0-9]+(?:\.[0-9]+)?(?:e[+-]?[0-9]+)?',row['score'],re.I)):raise ValueError('Invalid exact zset score')
            if any(type(row[k])is not int or not 1<=row[k]<=100000 for k in ('expected_occurrences','delete_count')) or row['delete_count']>row['expected_occurrences']:raise ValueError('Invalid exact multiplicity')
            exact(row['public_intent_key'],('project','iid','recipient'))
            if any(type(row['public_intent_key'][k])is not int or row['public_intent_key'][k]<1 for k in ('project','iid')):raise ValueError('Invalid public intent key')
            if not isinstance(row['public_intent_key']['recipient'],str) or not re.fullmatch(r'[A-Za-z0-9_.+-]{1,100}@example\.test',row['public_intent_key']['recipient']):raise ValueError('Invalid synthetic recipient')
    else:raise ValueError('Unimplemented fixed validator')
    if len(json.dumps(args,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode())>1048576:
        raise ValueError('Fixed parameter document exceeds bound')
    return args
