"""Fixed collectors for visible containers; never accept caller-supplied code.

The shell collectors only write temporary capture files under /tmp and remove
them. They never write business, queue, archive or delivery-ledger state.
"""

FILE_CHUNK_SH = r'''
set -eu
path=$1; offset=$2; count=$3
case "$path" in /recovery/backups/*|/recovery/journal/acknowledged-issues.json|/recovery/journal/acknowledged-notifications.json) ;; *) exit 64;; esac
if [ ! -e "$path" ]; then printf '{"status":"missing"}\n'; exit 0; fi
if [ ! -f "$path" ] || [ -L "$path" ] || [ "$(readlink -f -- "$path")" != "$path" ]; then printf '{"status":"unsafe_file"}\n'; exit 0; fi
before=$(stat -c '%d:%i:%s:%Y:%Z' -- "$path")
size=$(stat -c '%s' -- "$path")
hash1=$(sha256sum -- "$path"); hash1=${hash1%% *}
if [ "$offset" -gt "$size" ]; then printf '{"status":"invalid_offset"}\n'; exit 0; fi
data=$(dd if="$path" bs=1 skip="$offset" count="$count" status=none | base64 | tr -d '\n')
hash2=$(sha256sum -- "$path"); hash2=${hash2%% *}
after=$(stat -c '%d:%i:%s:%Y:%Z' -- "$path")
if [ "$before" != "$after" ] || [ "$hash1" != "$hash2" ]; then printf '{"status":"source_changed"}\n'; exit 0; fi
printf '{"status":"ok","source_version":"%s","document_sha256":"%s","byte_length":%s,"offset":%s,"chunk_base64":"%s"}\n' "$before" "$hash1" "$size" "$offset" "$data"
'''


CAPTURE_CHUNK_SH = r'''
set -eu
mode=$1; arg=$2; start=$3; amount=$4; offset=$5; count=$6
source_version=live_observation
archive_sha=
if [ "$mode" = archive_list ]; then
  case "$arg" in /recovery/backups/*) ;; *) exit 64;; esac
  if [ ! -e "$arg" ]; then printf '{"status":"missing"}\n'; exit 0; fi
  if [ ! -f "$arg" ] || [ -L "$arg" ] || [ "$(readlink -f -- "$arg")" != "$arg" ]; then printf '{"status":"unsafe_file"}\n'; exit 0; fi
  source_version=$(stat -c '%d:%i:%s:%Y:%Z' -- "$arg")
  archive_sha=$(sha256sum -- "$arg"); archive_sha=${archive_sha%% *}
fi
tmp=$(mktemp -d /tmp/g1-typed-read.XXXXXXXX)
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM
rc=0
case "$mode" in
  archive_list) pg_restore --list "$arg" >"$tmp/out" 2>"$tmp/err" || rc=$? ;;
  redis_range)
    case "$arg" in queue:mailers) verb=LRANGE;; retry|schedule|dead) verb=ZRANGE;; *) exit 64;; esac
    end=$((start+amount-1))
    redis-cli -2 --json -e "$verb" "$arg" "$start" "$end" >"$tmp/out" 2>"$tmp/err" || rc=$? ;;
  sidekiq_status) gitlab-ctl status sidekiq >"$tmp/out" 2>"$tmp/err" || rc=$? ;;
  *) exit 64 ;;
esac
if [ "$mode" = archive_list ]; then
  after=$(stat -c '%d:%i:%s:%Y:%Z' -- "$arg")
  hash2=$(sha256sum -- "$arg"); hash2=${hash2%% *}
  if [ "$source_version" != "$after" ] || [ "$archive_sha" != "$hash2" ]; then printf '{"status":"source_changed"}\n'; exit 0; fi
fi
{
  printf '{"target_exit_code":%s,"stdout_base64":"' "$rc"
  base64 <"$tmp/out" | tr -d '\n'
  printf '","stderr_base64":"'
  base64 <"$tmp/err" | tr -d '\n'
  printf '"}'
} >"$tmp/document"
size=$(stat -c '%s' "$tmp/document")
if [ "$size" -gt 1048576 ]; then printf '{"status":"document_too_large"}\n'; exit 0; fi
hash=$(sha256sum "$tmp/document"); hash=${hash%% *}
data=$(dd if="$tmp/document" bs=1 skip="$offset" count="$count" status=none | base64 | tr -d '\n')
printf '{"status":"ok","source_version":"%s","archive_sha256":"%s","document_sha256":"%s","byte_length":%s,"offset":%s,"chunk_base64":"%s"}\n' "$source_version" "$archive_sha" "$hash" "$size" "$offset" "$data"
'''


HTTP_CHUNK_PY = r'''
import base64, hashlib, json, sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def emit(value):
    print(json.dumps(value, separators=(",", ":"), ensure_ascii=True))

try:
    cfg = json.loads(sys.argv[1])
    mode, offset, count = cfg["mode"], cfg["offset"], cfg["count"]
    headers = {}
    if mode == "audit":
        q = {"after": cfg["after"]}
        if cfg["through"] is not None:
            q["through"] = cfg["through"]
        url = "http://notification-mailbox:8080/messages?" + urlencode(q)
    elif mode == "issue":
        url = "http://gitlab-ce/api/v4/projects/%d/issues/%d" % (cfg["project"], cfg["iid"])
        headers["PRIVATE-TOKEN"] = Path("/credentials/token").read_text().strip()
    else:
        raise ValueError("unsupported mode")
    request = Request(url, headers=headers, method="GET")
    try:
        response = build_opener(NoRedirect()).open(request, timeout=10)
    except HTTPError as exc:
        response = exc
    with response:
        status = response.code
        raw = response.read(1048577)
    if len(raw) > 1048576:
        emit({"status":"document_too_large", "http_status":status})
    elif status != 200:
        # Preserve HTTP status, without echoing auth headers, URLs or HTML bodies.
        emit({"status":"http_error", "http_status":status})
    else:
        obj = json.loads(raw)
        if mode == "issue":
            fields = ("id", "project_id", "iid", "title", "description", "confidential")
            obj = {k:obj[k] for k in fields}
        blob = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        if offset < 0 or offset > len(blob) or not 0 < count <= 3072:
            raise ValueError("invalid chunk")
        part = blob[offset:offset+count]
        emit({"status":"ok", "http_status":status,
              "document_sha256":hashlib.sha256(blob).hexdigest(),
              "byte_length":len(blob), "offset":offset,
              "chunk_base64":base64.b64encode(part).decode(),
              "snapshot":obj.get("snapshot") if mode == "audit" else None})
except Exception as exc:
    # Exception messages may contain headers or response bodies: return only type.
    emit({"status":"collector_error", "error_type":type(exc).__name__})
'''
