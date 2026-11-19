"""Compile the five generated Ruby bodies in the fixed GitLab image only."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'b0-run/payload/strategy'))
import catalog

IMAGE = 'gitlab/gitlab-ce@sha256:9dc94c49789d1ffec78e1998b088c83d7d1d9d5f2dc8b388cbb2bd2de328dd21'
IMAGE_ID = 'sha256:0029d206bc0ef152211b66627f8e06705a20a475bd4169aa6b9c2adf88d41f09'
NAMES = ('service_control', 'service_inventory', 'identity_authorization',
         'background_contract', 'notification_send')


def main():
    output = ROOT / 'writer-fence-syntax-results'
    output.mkdir(exist_ok=False)
    inputs = output / 'inputs'
    inputs.mkdir()
    rows = []
    for name in NAMES:
        shell = catalog.PROGRAMS[name]['body_shell']
        body = shlex.split(shell)[-1].encode()
        (inputs / (name + '.rb')).write_bytes(body)
        rows.append({'name': name, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
                     'body_shell_sha256': hashlib.sha256(shell.encode()).hexdigest()})
    token = uuid.uuid4().hex
    name = 'b0-ruby-syntax-' + token
    result = {'schema': 'b0-fixed-image-ruby-syntax-v1', 'image': IMAGE,
              'expected_image_id': IMAGE_ID, 'inputs': rows,
              'scope': 'syntax compilation only; no application boot or business operation',
              'business_operations': 0, 'model_calls': 0, 'events': []}
    def run(stage, command, timeout, *, check=True):
        timed_out = None
        try:
            process = subprocess.run(command, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            timed_out = error
            process = subprocess.CompletedProcess(command, None, error.stdout or b'', error.stderr or b'')
        (output / (stage + '.stdout')).write_bytes(process.stdout)
        (output / (stage + '.stderr')).write_bytes(process.stderr)
        result['events'].append({'stage': stage, 'argv': command, 'exit_code': process.returncode,
                                 'timeout_seconds': timeout, 'timed_out': timed_out is not None})
        if timed_out is not None:
            raise timed_out
        if check:
            process.check_returncode()
        return process
    try:
        run('pull', ['docker', 'pull', IMAGE], 900)
        actual = json.loads(run('image_identity', ['docker', 'image', 'inspect', IMAGE], 30).stdout)[0]
        result['actual_image_id'] = actual['Id']
        if actual['Id'] != IMAGE_ID or IMAGE not in actual['RepoDigests']:
            raise RuntimeError('Fixed GitLab image identity differs')
        code = 'require "json"; ARGV.each { |p| RubyVM::InstructionSequence.compile(File.binread(p),p); puts JSON.generate({file:p,syntax:"ok"}) }'
        run('compile', ['docker', 'run', '--rm', '--name', name,
            '--label', 'b0.syntax_owner=' + token, '--network', 'none', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--cpus', '1', '--memory', '512m',
            '-v', str(inputs) + ':/inputs:ro', '--entrypoint', '/opt/gitlab/embedded/bin/ruby', IMAGE,
            '-e', code, *['/inputs/' + x + '.rb' for x in NAMES]], 60)
        lines = (output / 'compile.stdout').read_text().splitlines()
        observed = [json.loads(x) for x in lines]
        if observed != [{'file': '/inputs/' + x + '.rb', 'syntax': 'ok'} for x in NAMES]:
            raise RuntimeError('Generated Ruby syntax results differ from complete input set')
        result['syntax_passed'] = True
    except Exception as error:
        result['syntax_passed'] = False
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        try:
            probe = run('cleanup_inspect', ['docker', 'container', 'inspect', name], 30, check=False)
            if probe.returncode == 0:
                current = json.loads(probe.stdout)[0]
                if current['Config'].get('Labels', {}).get('b0.syntax_owner') != token or current['Image'] != IMAGE_ID:
                    raise RuntimeError('Owned syntax container identity differs; removal not attempted')
                cleanup = run('cleanup_remove', ['docker', 'rm', '-f', '-v', current['Id']], 30, check=False)
                if cleanup.returncode != 0:
                    raise RuntimeError('Owned syntax container removal failed with exit code ' + str(cleanup.returncode))
                result['cleanup_passed'] = True
            else:
                result['cleanup_passed'] = b'No such' in probe.stderr
                if not result['cleanup_passed']:
                    raise RuntimeError('Owned syntax container absence could not be established')
        except Exception as error:
            result['cleanup_passed'] = False
            result['cleanup_error'] = {'type': type(error).__name__, 'message': str(error)}
        result['passed'] = bool(result.get('syntax_passed') and result['cleanup_passed'])
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'passed': result['passed'], 'error': result.get('error'),
                          'cleanup_error': result.get('cleanup_error')}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
