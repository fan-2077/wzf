#!/usr/bin/env python3
"""Run a fixed-image, network-isolated observer diagnostic, not a recovery trial."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
import uuid

IMAGE = 'gitlab/gitlab-ce@sha256:9dc94c49789d1ffec78e1998b088c83d7d1d9d5f2dc8b388cbb2bd2de328dd21'
EXPECTED_IMAGE_ID = 'sha256:0029d206bc0ef152211b66627f8e06705a20a475bd4169aa6b9c2adf88d41f09'
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def cleanup_owned(output: Path, run):
    state = json.loads((output / 'owner.json').read_text())
    token = state.get('owner_token', '')
    name = state.get('container_name', '')
    container_id = state.get('container_id')
    if not re.fullmatch(r'[0-9a-f]{32}', token) or name != 'b0-writer-probe-' + token:
        raise RuntimeError('Invalid saved diagnostic ownership identity')
    if container_id is not None and not re.fullmatch(r'[0-9a-f]{64}', container_id):
        raise RuntimeError('Invalid saved immutable container identity')
    selector = container_id or name
    result = run('cleanup_identity', ['docker', 'container', 'inspect', selector], check=False)
    if result.returncode:
        if b'No such container' in result.stderr or b'No such object' in result.stderr:
            return {'passed': True, 'already_absent': True}
        raise RuntimeError('Cannot establish owned diagnostic container state')
    identities = json.loads(result.stdout)
    if len(identities) != 1:
        raise RuntimeError('Container inspection did not resolve one identity')
    identity = identities[0]
    if identity.get('Config', {}).get('Labels', {}).get('b0.writer_probe_owner') != token:
        raise RuntimeError('Owned container label mismatch; no removal attempted')
    if identity.get('Name') != '/' + name:
        raise RuntimeError('Owned container name mismatch; no removal attempted')
    actual_id = identity.get('Id', '')
    if not re.fullmatch(r'[0-9a-f]{64}', actual_id) or (container_id and actual_id != container_id):
        raise RuntimeError('Owned immutable container identity mismatch; no removal attempted')
    cleanup = run('cleanup', ['docker', 'rm', '--force', '--volumes', actual_id], check=False)
    return {'passed': cleanup.returncode == 0, 'removed_container_id': actual_id}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cleanup-only', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if not args.cleanup_only and any(output.iterdir()):
        raise RuntimeError('Diagnostic output directory must be empty')
    token = uuid.uuid4().hex
    name = 'b0-writer-probe-' + token
    label = 'b0.writer_probe_owner'
    events = []
    summary = {'schema': 'b0-writer-probe-host-v1', 'image': IMAGE,
               'expected_image_id': EXPECTED_IMAGE_ID, 'container_name': name,
               'owner_token': token, 'business_actions': 0, 'scope': 'isolated synthetic service fixture'}

    def run(stage, command, timeout=60, check=True):
        if args.cleanup_only:
            stage = 'fallback_' + stage
        started = time.monotonic()
        timed_out = None
        try:
            p = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            timed_out = error
            p = subprocess.CompletedProcess(command, None, error.stdout or b'', error.stderr or b'')
        (output / (stage + '.stdout')).write_bytes(p.stdout)
        (output / (stage + '.stderr')).write_bytes(p.stderr)
        events.append({'stage': stage, 'argv': command, 'exit_code': p.returncode,
                       'elapsed_seconds': time.monotonic() - started,
                       'timeout_seconds': timeout, 'timed_out': timed_out is not None,
                       'stdout_sha256': hashlib.sha256(p.stdout).hexdigest(),
                       'stderr_sha256': hashlib.sha256(p.stderr).hexdigest()})
        if timed_out is not None:
            raise timed_out
        if check and p.returncode:
            raise RuntimeError(f'{stage} failed with exit code {p.returncode}; see saved raw output')
        return p

    if args.cleanup_only:
        if not (output / 'owner.json').exists():
            result = {'passed': True, 'nothing_owned_by_this_diagnostic': True}
        else:
            try:
                result = cleanup_owned(output, run)
            except Exception as error:
                result = {'passed': False, 'error': {'type': type(error).__name__, 'message': str(error)}}
        result['events'] = events
        (output / 'cleanup-only.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result))
        return 0 if result['passed'] else 1

    owner = {'schema': 'b0-writer-probe-owner-v1', 'container_name': name, 'owner_token': token,
             'image': IMAGE, 'container_id': None}
    def save_owner():
        pending = output / 'owner.pending.json'
        pending.write_text(json.dumps(owner, indent=2) + '\n')
        pending.replace(output / 'owner.json')

    save_owner()
    creation_started = False
    try:
        run('pull', ['docker', 'pull', IMAGE], timeout=900)
        inspect = json.loads(run('image_identity', ['docker', 'image', 'inspect', IMAGE]).stdout)[0]
        summary['actual_image'] = {k: inspect.get(k) for k in ('Id', 'RepoDigests', 'Architecture', 'Os')}
        if inspect['Id'] != EXPECTED_IMAGE_ID or IMAGE not in inspect.get('RepoDigests', []):
            raise RuntimeError('Fixed GitLab image identity mismatch')
        manifest = []
        for path in sorted(HERE.iterdir()):
            if path.is_file():
                manifest.append({'path': str(path.relative_to(REPO)), 'bytes': path.stat().st_size,
                                 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        for base in ('ruby_common.rb', 'service_supervision.rb'):
            path = REPO / 'b0-run/payload/strategy/programs' / base
            manifest.append({'path': str(path.relative_to(REPO)), 'bytes': path.stat().st_size,
                             'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        summary['source_manifest'] = manifest
        exists = run('name_check', ['docker', 'container', 'inspect', name], check=False)
        if exists.returncode == 0:
            raise RuntimeError('Diagnostic container name already exists')
        creation_started = True
        creation = run('create', ['docker', 'create', '--name', name, '--label', label + '=' + token,
                      '--network', 'none', '--cpus', '2', '--memory', '2g',
                      '--volume', str(HERE) + ':/probe:ro',
                      '--volume', str(REPO / 'b0-run/payload/strategy/programs') + ':/programs:ro',
                      '--volume', str(output) + ':/out', '--entrypoint', '/opt/gitlab/embedded/bin/ruby',
                      IMAGE, '/probe/probe.rb'])
        container_id = creation.stdout.decode().strip()
        if not re.fullmatch(r'[0-9a-f]{64}', container_id):
            raise RuntimeError('Docker create did not return an immutable container ID')
        owner['container_id'] = container_id
        save_owner()
        summary['container_id'] = container_id
        container = json.loads(run('container_identity', ['docker', 'container', 'inspect', container_id]).stdout)[0]
        hc = container['HostConfig']
        mounts = container.get('Mounts', [])
        summary['container_boundary'] = {
            'Id': container['Id'], 'Image': container['Image'], 'User': container['Config'].get('User'),
            'NetworkMode': hc.get('NetworkMode'), 'Privileged': hc.get('Privileged'),
            'CapAdd': hc.get('CapAdd'), 'CapDrop': hc.get('CapDrop'),
            'PidMode': hc.get('PidMode'), 'IpcMode': hc.get('IpcMode'), 'Mounts': mounts}
        expected_binds = {'/probe': (str(HERE), False),
                          '/programs': (str(REPO / 'b0-run/payload/strategy/programs'), False),
                          '/out': (str(output), True)}
        actual_binds = {m['Destination']: (m['Source'], m['RW']) for m in mounts if m['Type'] == 'bind'}
        if (container['Id'] != container_id or container['Image'] != EXPECTED_IMAGE_ID
                or hc.get('NetworkMode') != 'none' or hc.get('Privileged') is not False
                or hc.get('CapAdd') or hc.get('PidMode') == 'host' or hc.get('IpcMode') == 'host'
                or actual_binds != expected_binds):
            raise RuntimeError('Actual diagnostic container boundary differs from requested isolation')
        execution = run('execute', ['docker', 'start', '--attach', container_id], timeout=180, check=False)
        summary['container_exit_code'] = execution.returncode
        diagnostic = json.loads((output / 'probe.json').read_text())
        summary['diagnostic_passed'] = diagnostic.get('passed') is True and execution.returncode == 0
        summary['checks'] = diagnostic.get('checks', {})
        summary['error'] = diagnostic.get('error')
    except Exception as error:
        summary['diagnostic_passed'] = False
        summary['host_error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        if creation_started:
            try:
                cleanup = cleanup_owned(output, run)
                summary['cleanup'] = cleanup
                summary['cleanup_passed'] = cleanup['passed']
            except Exception as error:
                summary['cleanup_passed'] = False
                summary['cleanup_error'] = {'type': type(error).__name__, 'message': str(error)}
        else:
            summary['cleanup_passed'] = True
        summary['passed'] = summary.get('diagnostic_passed') is True and summary['cleanup_passed'] is True
        summary['events'] = events
        (output / 'host-summary.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n')
        print(json.dumps({'passed': summary['passed'], 'checks': summary.get('checks'),
                          'host_error': summary.get('host_error'), 'error': summary.get('error')}, ensure_ascii=False))
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
