"""Strict post-cleanup export; source tree is never chmod/chown'ed or rewritten.

The runner claims one private output directory, then invokes this fixed worker
through sudo. Only a complete verified tar and a small status report are public.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile

SCHEMA = 'b0-owned-evidence-export-v1'
IDENTITY_KEYS = ('GITHUB_REPOSITORY', 'GITHUB_REF', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')
B0_REF = 'refs/heads/sre-b0-public-result-v2-20261119'
DIAGNOSTIC_REF = 'refs/heads/sre-b0-export-diagnostic-unused'
PRESERVE = (*IDENTITY_KEYS, 'GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT', 'GITHUB_WORKSPACE', 'RUNNER_TEMP', 'GITHUB_SHA')
ARCHIVE, STATUS = 'evidence.tar.gz', 'EXPORT_STATUS.json'
RESERVED = {'FINAL_REMOTE_VERDICT.json', 'ARTIFACT_MANIFEST.json', 'EVIDENCE_EXPORT_METADATA.json'}
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK

class ExportError(RuntimeError):
    pass

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')

def digest(data):
    return hashlib.sha256(data).hexdigest()

def absolute_path(value):
    if not isinstance(value, str) or not value.startswith('/') or os.path.normpath(value) != value:
        raise ExportError('A normalized absolute trusted path is required')
    return value

def context(uid=None, gid=None):
    identity = {key: os.environ.get(key) for key in IDENTITY_KEYS}
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or identity['GITHUB_REPOSITORY'] != 'fan-2077/wzf'
            or identity['GITHUB_REF'] not in {B0_REF, 'refs/heads/sre-b0-read-repair-20261117'}
            or not re.fullmatch(r'[1-9][0-9]*', identity['GITHUB_RUN_ID'] or '')
            or identity['GITHUB_RUN_ATTEMPT'] != '1'):
        raise ExportError('Export is limited to one reviewed hosted attempt')
    workspace = absolute_path(os.environ.get('GITHUB_WORKSPACE'))
    temporary = absolute_path(os.environ.get('RUNNER_TEMP'))
    uid, gid = os.getuid() if uid is None else uid, os.getgid() if gid is None else gid
    if type(uid) is not int or type(gid) is not int or uid <= 0 or gid < 0:
        raise ExportError('A non-root runner identity is required')
    key = identity['GITHUB_RUN_ID'] + '-' + identity['GITHUB_RUN_ATTEMPT']
    return {'identity': identity, 'workspace': workspace, 'runner_temp': temporary,
            'uid': uid, 'gid': gid, 'run_key': key, 'output': temporary + '/sre-b0-export-' + key,
            'diagnostic': identity['GITHUB_REF'] == DIAGNOSTIC_REF}

@contextmanager
def absolute_directory(path):
    """Open each trusted absolute-path component without following links."""
    absolute_path(path)
    fd = os.open('/', READ_FLAGS | os.O_DIRECTORY)
    try:
        for component in path.split('/')[1:]:
            if not component:
                continue
            child = os.open(component, READ_FLAGS | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)

def same_entry(parent, name, fd):
    actual, opened = os.stat(name, dir_fd=parent, follow_symlinks=False), os.fstat(fd)
    if (actual.st_dev, actual.st_ino, stat.S_IFMT(actual.st_mode)) != (opened.st_dev, opened.st_ino, stat.S_IFMT(opened.st_mode)):
        raise ExportError('Evidence path changed while open: ' + name)

def mount_id(fd):
    lines = Path('/proc/self/fdinfo/' + str(fd)).read_text().splitlines()
    found = [line.split(':', 1)[1].strip() for line in lines if line.startswith('mnt_id:')]
    if len(found) != 1 or not found[0].isdigit():
        raise ExportError('Cannot bind evidence descriptor to its mount')
    return int(found[0])

def metadata(fd):
    s = os.fstat(fd)
    kind = 'file' if stat.S_ISREG(s.st_mode) else 'directory' if stat.S_ISDIR(s.st_mode) else None
    if kind is None or (kind == 'file' and s.st_nlink != 1):
        raise ExportError('Only directories and single-link regular files are admitted')
    return {'kind': kind, 'device': s.st_dev, 'inode': s.st_ino, 'mount_id': mount_id(fd),
            'mode': stat.S_IMODE(s.st_mode), 'uid': s.st_uid, 'gid': s.st_gid, 'nlink': s.st_nlink,
            'size': s.st_size, 'mtime_ns': s.st_mtime_ns, 'ctime_ns': s.st_ctime_ns}

def hash_fd(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    while data := os.read(fd, 1024 * 1024):
        h.update(data)
    return h.hexdigest()

@contextmanager
def child_fd(parent, name, directory=False):
    if not isinstance(name, str) or name in {'', '.', '..'} or '/' in name or '\x00' in name:
        raise ExportError('Invalid relative evidence component')
    s = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if not (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)):
        raise ExportError('Links and special evidence nodes are forbidden: ' + name)
    if stat.S_ISREG(s.st_mode) and s.st_nlink != 1:
        raise ExportError('Hard-linked evidence is forbidden: ' + name)
    flags = READ_FLAGS | (os.O_DIRECTORY if directory or stat.S_ISDIR(s.st_mode) else 0)
    fd = os.open(name, flags, dir_fd=parent)
    try:
        same_entry(parent, name, fd)
        current = os.fstat(fd)
        if (s.st_dev, s.st_ino, stat.S_IFMT(s.st_mode)) != (current.st_dev, current.st_ino, stat.S_IFMT(current.st_mode)):
            raise ExportError('Evidence node replaced during open: ' + name)
        metadata(fd)
        yield fd
        same_entry(parent, name, fd)
    finally:
        os.close(fd)

def inventory(root):
    """No glob suppression: unreadable, hidden and empty directories count."""
    root_meta, entries = metadata(root), {}
    def visit(fd, rel):
        before = metadata(fd)
        if before['device'] != root_meta['device'] or before['mount_id'] != root_meta['mount_id']:
            raise ExportError('Evidence crosses its original filesystem mount: ' + rel)
        item = dict(before)
        if before['kind'] == 'file':
            item['sha256'] = hash_fd(fd)
        else:
            names = sorted(os.listdir(fd))
            for name in names:
                with child_fd(fd, name) as child:
                    visit(child, name if rel == '.' else rel + '/' + name)
            if sorted(os.listdir(fd)) != names:
                raise ExportError('Evidence directory changed during enumeration: ' + rel)
        if metadata(fd) != before:
            raise ExportError('Evidence metadata changed during enumeration: ' + rel)
        entries[rel] = item
    visit(root, '.')
    return entries

def read_json(root, name, runner_uid, limit=16 * 1024 * 1024, expected_sha256=None):
    with child_fd(root, name) as fd:
        before = metadata(fd)
        if before['kind'] != 'file' or before['uid'] != runner_uid or before['size'] > limit:
            raise ExportError('Untrusted or oversized host receipt: ' + name)
        data = b''
        while block := os.read(fd, min(1024 * 1024, limit + 1 - len(data))):
            data += block
            if len(data) > limit:
                raise ExportError('Oversized host receipt: ' + name)
        if metadata(fd) != before:
            raise ExportError('Host receipt changed while read: ' + name)
    if expected_sha256 is not None and digest(data) != expected_sha256:
        raise ExportError('Host receipt differs from the inventoried bytes: ' + name)
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ExportError('Host receipt is not an object: ' + name)
    return value

def verify_receipts(root, ctx, snapshot=None):
    def receipt(name, limit=16 * 1024 * 1024):
        expected = snapshot[name]['sha256'] if snapshot is not None else None
        return read_json(root, name, ctx['uid'], limit, expected_sha256=expected)
    owner = receipt('ownership.json', 65536)
    if (owner.get('identity') != ctx['identity'] or owner.get('dedicated_host') is not True
            or owner.get('native_ports_unused_before_b0') is not True
            or owner.get('empty_prefixes_before_b0') != {'container': [], 'network': [], 'volume': []}
            or owner.get('work') != ctx['runner_temp'] + '/sre-native-' + ctx['run_key']
            or owner.get('cluster') != 'sre-native-' + ctx['run_key']):
        raise ExportError('Ownership receipt does not authorize this evidence tree')
    cleanup = receipt('workflow-fallback-cleanup.json')
    if cleanup.get('passed') is not True or cleanup.get('full') is not True:
        raise ExportError('Verified full workflow cleanup is required before export')
    return receipt('b0-execution-summary.json'), cleanup

def atomic_json(output, name, value, ctx):
    pending = '.' + name + '.pending'
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=output)
    try:
        data = encoded(value)
        while data:
            data = data[os.write(fd, data):]
        os.fsync(fd)
        if os.geteuid() == 0:
            os.fchown(fd, ctx['uid'], ctx['gid'])
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    os.replace(pending, name, src_dir_fd=output, dst_dir_fd=output)
    os.fsync(output)

def status_base(ctx):
    return {'schema': SCHEMA, 'identity': ctx['identity'], 'export_passed': False,
            'final_verdict_passed': False, 'archive': None, 'diagnostic_only': ctx['diagnostic'],
            'raw_tree_upload_allowed': False, 'original_permissions_or_ownership_changed': False}

def verify_output(output, ctx):
    m = metadata(output)
    if m['kind'] != 'directory' or m['uid'] != ctx['uid'] or m['mode'] != 0o700:
        raise ExportError('Output directory is not owned privately by this runner')
    old = read_json(output, STATUS, ctx['uid'], 65536)
    if old.get('identity') != ctx['identity'] or old.get('export_passed') is not False:
        raise ExportError('Output directory is not a fresh export claim')
    if sorted(os.listdir(output)) != [STATUS]:
        raise ExportError('Output claim already contains unexpected files')

def tar_info(name, size=0, directory=False):
    info = tarfile.TarInfo(name + '/' if directory else name)
    info.type, info.mode = (tarfile.DIRTYPE, 0o755) if directory else (tarfile.REGTYPE, 0o644)
    info.uid = info.gid = info.mtime = 0
    info.size = 0 if directory else size
    return info

def add_original_tree(archive, root, snapshot):
    def visit(fd, rel):
        meta, expected = metadata(fd), snapshot[rel]
        if meta != {k: v for k, v in expected.items() if k != 'sha256'}:
            raise ExportError('Source changed before archiving: ' + rel)
        name = 'b0-results' if rel == '.' else 'b0-results/' + rel
        if meta['kind'] == 'directory':
            archive.addfile(tar_info(name, directory=True))
            for entry in sorted(os.listdir(fd)):
                with child_fd(fd, entry) as child:
                    visit(child, entry if rel == '.' else rel + '/' + entry)
        else:
            os.lseek(fd, 0, os.SEEK_SET)
            with os.fdopen(os.dup(fd), 'rb') as stream:
                archive.addfile(tar_info(name, meta['size']), stream)
        if metadata(fd) != meta:
            raise ExportError('Source changed while archiving: ' + rel)
    visit(root, '.')

def verify_archive(fd, snapshot, derived):
    expected = {'b0-results' if name == '.' else 'b0-results/' + name:
                {'kind': item['kind'], 'sha256': item.get('sha256')} for name, item in snapshot.items()}
    expected.update({'b0-results/' + name: {'kind': 'file', 'sha256': digest(data)} for name, data in derived.items()})
    seen = set()
    os.lseek(fd, 0, os.SEEK_SET)
    with os.fdopen(os.dup(fd), 'rb') as stream, tarfile.open(fileobj=stream, mode='r:gz') as archive:
        for item in archive:
            if item.name in seen or item.name not in expected:
                raise ExportError('Unexpected or duplicate archive member')
            seen.add(item.name)
            want = expected[item.name]
            if want['kind'] == 'directory':
                if not item.isdir():
                    raise ExportError('Archive directory type changed')
            else:
                if not item.isfile() or item.islnk() or item.issym():
                    raise ExportError('Archive contains a nonregular file')
                h = hashlib.sha256()
                with archive.extractfile(item) as data:
                    while block := data.read(1024 * 1024):
                        h.update(block)
                if h.hexdigest() != want['sha256']:
                    raise ExportError('Archive file content differs from the original')
    if seen != set(expected):
        raise ExportError('Archive file set is incomplete')

def perform_export(ctx, output, verdict_builder):
    """Worker core; local tests may invoke it only against owned fixtures."""
    verify_output(output, ctx)
    pending, archive_fd, published = '.' + ARCHIVE + '.pending', None, False
    try:
        with absolute_directory(ctx['workspace']) as workspace:
            with child_fd(workspace, 'b0-results', directory=True) as root:
                verify_receipts(root, ctx)  # Authorize before recursively reading evidence.
                before = inventory(root)
                run, cleanup = verify_receipts(root, ctx, before)
                if any(name in before for name in RESERVED):
                    raise ExportError('Derived seal names already exist in the original tree')
                verdict = verdict_builder(run, cleanup, diagnostic=ctx['diagnostic'])
                export_record = {'schema': SCHEMA, 'identity': ctx['identity'], 'complete_strict_inventory': True,
                    'source_entries': before, 'original_permissions_or_ownership_changed': False,
                    'archive_header_modes': {'directory': '0755', 'file': '0644'},
                    'source_contents_preserved': True, 'hidden_and_empty_directories_included': True}
                derived = {'FINAL_REMOTE_VERDICT.json': encoded(verdict), 'EVIDENCE_EXPORT_METADATA.json': encoded(export_record)}
                files = {name: item['sha256'] for name, item in before.items() if item['kind'] == 'file'}
                files.update({name: digest(data) for name, data in derived.items()})
                derived['ARTIFACT_MANIFEST.json'] = encoded({'files': files,
                    'directories': sorted(name for name, item in before.items() if item['kind'] == 'directory'),
                    'complete': True, 'scope': 'all original evidence and derived final seal, excluding this manifest itself'})
                archive_fd = os.open(pending, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=output)
                with os.fdopen(os.dup(archive_fd), 'wb') as stream:
                    with tarfile.open(fileobj=stream, mode='w:gz', compresslevel=1) as archive:
                        add_original_tree(archive, root, before)
                        for name, data in sorted(derived.items()):
                            archive.addfile(tar_info('b0-results/' + name, len(data)), io.BytesIO(data))
                    stream.flush()
                    os.fsync(stream.fileno())
                verify_archive(archive_fd, before, derived)
                if inventory(root) != before:
                    raise ExportError('Original evidence changed during export')
                same_entry(workspace, 'b0-results', root)
                archive_hash, archive_size = hash_fd(archive_fd), os.fstat(archive_fd).st_size
                if os.geteuid() == 0:
                    os.fchown(archive_fd, ctx['uid'], ctx['gid'])
                os.fchmod(archive_fd, 0o600)
                os.fsync(archive_fd)
                os.link(pending, ARCHIVE, src_dir_fd=output, dst_dir_fd=output, follow_symlinks=False)
                published = True
                os.unlink(pending, dir_fd=output)
                os.fsync(output)
                result = {**status_base(ctx), 'export_passed': True, 'final_verdict_passed': verdict['passed'],
                    'archive': {'name': ARCHIVE, 'sha256': archive_hash, 'bytes': archive_size},
                    'source_file_count': sum(x['kind'] == 'file' for x in before.values()),
                    'source_directory_count': sum(x['kind'] == 'directory' for x in before.values()),
                    'strict_archive_file_set_verified': True, 'source_content_hashes_preserved': True, 'error': None}
                atomic_json(output, STATUS, result, ctx)
                return result
    except BaseException as error:
        if published:
            os.unlink(ARCHIVE, dir_fd=output)
        try:
            os.unlink(pending, dir_fd=output)
        except FileNotFoundError:
            pass
        atomic_json(output, STATUS, {**status_base(ctx), 'error': {'type': type(error).__name__, 'message': str(error)}}, ctx)
        raise
    finally:
        if archive_fd is not None:
            os.close(archive_fd)

def load_verdict_builder():
    path = Path(__file__).absolute().parent / 'seal_remote_evidence.py'
    spec = importlib.util.spec_from_file_location('reviewed_b0_sealer', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_verdict

def qualify_upload_paths(output, ctx, result):
    expected = {STATUS, ARCHIVE} if result.get('export_passed') is True else {STATUS}
    if set(os.listdir(output)) != expected or result.get('identity') != ctx['identity']:
        raise ExportError('Export directory has unqualified upload paths')
    with child_fd(output, STATUS) as fd:
        s = metadata(fd)
        if s['uid'] != ctx['uid'] or s['mode'] != 0o600:
            raise ExportError('Export status is not a runner-owned regular file')
    if ARCHIVE in expected:
        with child_fd(output, ARCHIVE) as fd:
            s = metadata(fd)
            claim = result.get('archive') or {}
            if (s['uid'] != ctx['uid'] or s['mode'] != 0o600 or claim.get('name') != ARCHIVE
                    or s['size'] != claim.get('bytes') or hash_fd(fd) != claim.get('sha256')):
                raise ExportError('Published archive identity differs from export status')
    # This is a fixed boolean, never a source-derived path or text value.
    output_path = os.environ.get('GITHUB_OUTPUT')
    if output_path:
        fd = os.open(absolute_path(output_path), os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        try:
            s = os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_uid != ctx['uid']:
                raise ExportError('Workflow output channel identity is invalid')
            os.write(fd, b'evidence_paths_ready=true\n')
        finally:
            os.close(fd)

def privileged_main():
    if os.geteuid() != 0 or not os.environ.get('SUDO_UID') or not os.environ.get('SUDO_GID'):
        raise ExportError('The worker requires the runner-invoked sudo identity')
    ctx = context(int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))
    with absolute_directory(ctx['output']) as output:
        result = perform_export(ctx, output, load_verdict_builder())
    print(json.dumps(result))
    return 0

def runner_main():
    ctx = context()
    with absolute_directory(ctx['runner_temp']) as parent:
        name = 'sre-b0-export-' + ctx['run_key']
        os.mkdir(name, 0o700, dir_fd=parent)
        with child_fd(parent, name, directory=True) as output:
            atomic_json(output, STATUS, {**status_base(ctx), 'phase': 'claimed'}, ctx)
            command = ['sudo', '-n', '--preserve-env=' + ','.join(PRESERVE), '/usr/bin/python3', '-I', '-S', '-B',
                       str(Path(__file__).absolute()), '--privileged']
            try:
                completed = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False)
                if completed.returncode != 0:
                    failure = {**status_base(ctx), 'error': {'type': 'PrivilegedExportFailed',
                               'message': (completed.stderr or completed.stdout)[-6000:]}, 'worker_exit_code': completed.returncode}
                    observed = read_json(output, STATUS, ctx['uid'], 65536)
                    if not observed.get('error'):
                        atomic_json(output, STATUS, failure, ctx)
                result = read_json(output, STATUS, ctx['uid'], 65536)
            except Exception as error:
                result = {**status_base(ctx), 'error': {'type': type(error).__name__, 'message': str(error)}}
                atomic_json(output, STATUS, result, ctx)
            qualify_upload_paths(output, ctx, result)
            print(json.dumps(result))
            return 0 if result.get('export_passed') is True and result.get('final_verdict_passed') is True else 1

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--privileged', action='store_true')
    args = parser.parse_args()
    raise SystemExit(privileged_main() if args.privileged else runner_main())
