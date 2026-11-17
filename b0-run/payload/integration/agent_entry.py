"""Isolated deterministic entrypoint; no model, native source, or judge access."""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import sqlite3
import sys
import time
import traceback

LOGS=Path('/logs')
ROOT=Path('/opt/b0')

def save(path,value):
    raw=json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n'
    temporary=path.with_name('.'+path.name+'.pending')
    with temporary.open('x') as output:
        output.write(raw);output.flush();os.fsync(output.fileno())
    temporary.replace(path)

def resources():
    value={}
    for name in ('memory.peak','memory.current','memory.max','memory.events','cpu.max','cpu.stat'):
        path=Path('/sys/fs/cgroup')/name
        if path.is_file():value[name]=path.read_text().strip()
    return value

def retain_build_record():
    target=LOGS/'image-build-record'
    shutil.copytree(ROOT/'build-record',target)
    save(LOGS/'agent-payload-hashes.json',{
        str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(ROOT.rglob('*')) if p.is_file() and not p.is_symlink() and p.suffix in {'.py','.sh','.rb','.json','.txt'}})

def preflight():
    from native_transport import check_client_versions
    from native_bridge import sqlite_runtime
    actual=sqlite_runtime()
    if actual['sqlite_version']!='3.54.1':raise RuntimeError('Pinned common SQLite not loaded')
    if actual['sqlite_source_id']!='2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76':
        raise RuntimeError('Pinned SQLite source identity differs')
    if sys.version_info[:3]!=(3,11,17):raise RuntimeError('Pinned Python version differs')
    for path in ROOT.rglob('*.py'):ast.parse(path.read_text())
    database=LOGS/'preflight.sqlite'
    a=sqlite3.connect(database,timeout=.01,isolation_level=None)
    b=sqlite3.connect(database,timeout=.01,isolation_level=None)
    try:
        assert a.execute('PRAGMA journal_mode=WAL').fetchone()[0]=='wal'
        a.execute('CREATE TABLE receipt(id TEXT PRIMARY KEY, value TEXT NOT NULL)')
        a.execute('BEGIN IMMEDIATE');a.execute("INSERT INTO receipt VALUES('once','committed')")
        blocked=False
        try:b.execute('BEGIN IMMEDIATE')
        except sqlite3.OperationalError:blocked=True
        assert blocked
        a.execute('COMMIT')
        assert b.execute('SELECT * FROM receipt').fetchall()==[('once','committed')]
        duplicate=False
        try:b.execute("INSERT INTO receipt VALUES('once','duplicate')")
        except sqlite3.IntegrityError:duplicate=True
        assert duplicate
    finally:a.close();b.close()
    result={'scope':'real_image_local_runtime_only','passed':True,
            'python':sys.version,'sqlite':actual,'native_clients':check_client_versions(),
            'sqlite_writer_exclusion':blocked,'sqlite_unique_receipt':duplicate,
            'native_mcp_calls':0,'business_operations':0,'model_calls':0,'resources':resources()}
    save(LOGS/'image-preflight.json',result)
    print(json.dumps(result),flush=True)
    return 0

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');args=parser.parse_args()
    retain_build_record()
    if args.preflight:return preflight()
    started=time.monotonic();result_path=LOGS/'b0-agent-result.json'
    launcher=LOGS/'b0-launch-context.json'
    exit_code=1
    try:
        while not launcher.exists():
            if time.monotonic()-started>180:raise TimeoutError('Reviewed host launch context unavailable')
            time.sleep(.1)
        if launcher.is_symlink():raise RuntimeError('Launch context cannot be a symlink')
        context=json.loads(launcher.read_text())
        if context.get('attempt_id')!=os.environ['B0_ATTEMPT_ID']:
            raise RuntimeError('Launch attempt identity differs')
        proof=LOGS/'b0-native-boundary.json'
        if not proof.is_file() or hashlib.sha256(proof.read_bytes()).hexdigest()!=context['boundary_proof_sha256']:
            raise RuntimeError('Bound native boundary proof differs')
        save(LOGS/'entrypoint-resource-before.json',resources())
        module={'native_readonly_qualification':'initial_qualification','public_b0':'controller'}.get(context.get('mode'))
        if module is None:raise RuntimeError('Unknown declared execution mode')
        try:
            runpy.run_module(module,run_name='__main__')
            exit_code=0
        except SystemExit as exc:
            exit_code=exc.code if type(exc.code) is int else 0 if exc.code is None else 1
        if not result_path.is_file():raise RuntimeError('Solver did not retain a final result')
    except BaseException as exc:
        error={'type':type(exc).__name__,'message':str(exc)}
        traceback.print_exc()
        if not result_path.exists():
            save(result_path,{'attempt_id':os.environ.get('B0_ATTEMPT_ID'),'status':'engineering_failure',
                'qualified_read_chain':False,'business_operations':0,'submit_calls':0,'error':error,
                'counts_note':'bootstrap failed before controller result; no successful execution inferred'})
        else:save(LOGS/'entrypoint-error.json',error)
        exit_code=1
    finally:
        save(LOGS/'entrypoint-resource-after.json',resources())
        save(LOGS/'entrypoint-execution.json',{'exit_code':exit_code,'elapsed_seconds':time.monotonic()-started,
            'model_calls':0,'scope':'isolated deterministic baseline runtime'})
    return exit_code

if __name__=='__main__':raise SystemExit(main())
