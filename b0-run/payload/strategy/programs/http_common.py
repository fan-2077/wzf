import base64
import hashlib
import json
import lzma
import sys
import time
import zlib
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit, parse_qs
from urllib.request import Request, HTTPRedirectHandler, build_opener

MAX_RESPONSE = 8 * 1024 * 1024

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def request(method, path, payload=None, correlation=None):
    headers = {}
    base = 'http://notification-mailbox:8080' if path.startswith('/messages') else 'http://gitlab-ce'
    if base == 'http://gitlab-ce':
        headers['PRIVATE-TOKEN'] = Path('/credentials/token').read_text().strip()
    if correlation is not None:
        headers['X-Request-ID'] = correlation
    data = None
    if payload is not None:
        data = json.dumps(payload, separators=(',', ':'), ensure_ascii=True).encode()
        headers['Content-Type'] = 'application/json'
    req = Request(base + path, data=data, headers=headers, method=method)
    start = time.monotonic()
    try:
        response = build_opener(NoRedirect()).open(req, timeout=60)
    except HTTPError as exc:
        response = exc
    with response:
        body = response.read(MAX_RESPONSE + 1)
        status = response.code
        public_headers = {k.lower(): response.headers[k] for k in ('Content-Length', 'Content-Type', 'X-Request-ID', 'X-Next-Page', 'X-Total', 'X-Total-Pages') if response.headers.get(k) is not None}
    if len(body) > MAX_RESPONSE:
        raise RuntimeError('response_over_limit')
    if public_headers.get('content-length') is not None and int(public_headers['content-length']) != len(body):
        raise RuntimeError('incomplete_http_response')
    return {'method':method, 'path':path, 'status':status, 'headers':public_headers,
            'body_bytes':len(body), 'body_sha256':hashlib.sha256(body).hexdigest(),
            'body_base64':base64.b64encode(body).decode(), 'body':json.loads(body),
            'monotonic_start':start, 'monotonic_end':time.monotonic(),
            'response_complete':True, 'automatic_retries':0}

def emit(obj):
    raw=json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
    compressed=zlib.compress(raw)
    marker,encoding='B0_RESULT_ZLIB:','zlib+base64'
    if len(compressed)>4096:
        candidate=lzma.compress(raw,format=lzma.FORMAT_XZ,preset=3)
        if len(candidate)<len(compressed):
            compressed=candidate
            marker,encoding='B0_RESULT_XZ:','xz+base64'
    envelope={'encoding':encoding,'uncompressed_bytes':len(raw),
              'uncompressed_sha256':hashlib.sha256(raw).hexdigest(),
              'data_base64':base64.b64encode(compressed).decode()}
    print(marker+json.dumps(envelope,sort_keys=True,separators=(',',':')))

def public_issue(obj):
    return {key:obj[key] for key in ('id','project_id','iid','title','description','confidential')}

def matches(obj, r):
    return (obj['project_id'] == r['project'] and all(obj[k] == r[k] for k in ('iid','title','description','confidential')))

cfg = json.loads(sys.argv[1])
