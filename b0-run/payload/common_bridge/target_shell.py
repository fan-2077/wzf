"""Fixed POSIX-shell action envelope. Caller parameters never contain shell code.

The envelope qualifies only its own foreground body and immutable capture.
Business-server terminal/effect proof is supplied separately by fixed validators.
The target's /tmp and same-UID processes are a trusted boundary, not adversarial.
"""
from __future__ import annotations
import base64
import gzip
import hashlib
import io
import shlex
from urllib.parse import quote, urlencode

SCHEMA = 'sregym-fixed-action-shell-v2'
MAX_CAPTURE_BYTES = 32 * 1024 * 1024
CHUNK_BYTES = 6144
MAX_EXEC_REQUEST_LINE_BYTES = 61440

# Only a representation of source(body_shell) changes. The original source,
# program hash, $0/$@, foreground PID and target claim protocol stay intact.
# FD 3 carries bytes and FD 4 carries statuses inside command substitutions;
# gzip bytes never enter a shell variable. No pipefail extension is assumed.
SOURCE_DECODER = r'''set -eu
b0_encoded=$1
b0_expected_sha=$2
b0_expected_bytes=$3
shift 3
case "$b0_expected_sha" in ''|*[!a-f0-9]*) exit 71;; esac
[ ${#b0_expected_sha} -eq 64 ] || exit 71
case "$b0_expected_bytes" in ''|*[!0-9]*) exit 72;; esac
[ "$b0_expected_bytes" -gt 0 ] || exit 72
b0_decode() {
  {
    b0_decode_status=$(
      exec 4>&1
      b0_gzip_rc=0
      {
        b0_base64_rc=0
        printf '%s' "$b0_encoded" | base64 -d || b0_base64_rc=$?
        printf 'base64:%s\n' "$b0_base64_rc" >&4
      } | gzip -dc >&3 || b0_gzip_rc=$?
      printf 'gzip:%s\n' "$b0_gzip_rc"
    )
  } 3>&1
  [ "$b0_decode_status" = 'base64:0
gzip:0' ]
}
# Hash the raw decoded stream before command substitution can discard NUL.
# Recover both the decoder and digest process statuses independently too.
b0_raw_digest() {
  {
    b0_digest_status=$(
      exec 4>&1
      b0_sha_rc=0
      {
        b0_decode_rc=0
        b0_decode || b0_decode_rc=$?
        printf 'decode:%s\n' "$b0_decode_rc" >&4
      } | sha256sum >&3 || b0_sha_rc=$?
      printf 'sha:%s\n' "$b0_sha_rc"
    )
  } 3>&1
  [ "$b0_digest_status" = 'decode:0
sha:0' ]
}
b0_raw_sha=$(b0_raw_digest) || exit 73
[ "$b0_raw_sha" = "$b0_expected_sha  -" ] || exit 74
# The non-newline sentinel preserves every trailing LF of the exact source.
b0_with_sentinel=$(b0_decode || exit 75; printf '.') || exit 75
b0_source=${b0_with_sentinel%.}
b0_actual_bytes=$(printf '%s' "$b0_source" | wc -c) || exit 76
[ "$b0_actual_bytes" -eq "$b0_expected_bytes" ] || exit 76
b0_actual_sha=$(printf '%s' "$b0_source" | sha256sum) || exit 77
[ "$b0_actual_sha" = "$b0_expected_sha  -" ] || exit 77
exec sh -c "$b0_source" "$0" "$@"
'''

BASE = r'''set -eu
umask 077
mode=$1
root=$2
action=$3
binding=$4
params=$5
offset=$6
count=$7
stream=$8
expected_root_identity=$9
expected_lifecycle=${10}
case "$mode" in init|start|query|chunk) ;; *) exit 81;; esac
case "$root" in /tmp/sregym-fixed-action-v2-*) ;; *) exit 82;; esac
rootbase=${root#/tmp/sregym-fixed-action-v2-}
case "$rootbase" in ''|*[!a-f0-9]*) exit 83;; esac
[ ${#rootbase} -eq 64 ] || exit 84
case "$action" in ''|*[!a-f0-9]*) exit 85;; esac
[ ${#action} -eq 64 ] || exit 86
case "$binding" in ''|*[!a-f0-9]*) exit 87;; esac
[ ${#binding} -eq 64 ] || exit 88
case "$offset:$count" in *[!0-9:]*) exit 89;; esac
[ "$count" -ge 1 ] && [ "$count" -le 6144 ] || exit 90
[ "$offset" -le 33554432 ] || exit 91
case "$stream" in stdout|stderr) ;; *) exit 92;; esac
b0_unknown() { printf '{"schema":"sregym-fixed-action-shell-v2","state":"unknown","reason":"%s"}\n' "$1"; }
b0_checked_dir() {
  [ -d "$1" ] && [ ! -L "$1" ] || return 1
  [ "$(stat -c %a "$1")" = 700 ] || return 1
  [ "$(stat -c %u "$1")" = "$(id -u)" ] || return 1
}
b0_checked_file() {
  [ -f "$1" ] && [ ! -L "$1" ] || return 1
  [ "$(stat -c %a "$1")" = 600 ] || return 1
  [ "$(stat -c %u "$1")" = "$(id -u)" ] || return 1
  [ "$(stat -c %h "$1")" = 1 ] || return 1
}
b0_new_file() {
  # Noclobber is the exclusive file creation boundary. Own tmp directories are
  # trusted; no untrusted scripts or arbitrary paths can reach this operation.
  (set -C; printf '%s' "$2" > "$1")
  sync -f "$1"
}
b0_proc() {
  wanted=$1
  [ -r "/proc/$wanted/stat" ] || return 1
  line=$(cat "/proc/$wanted/stat") || return 1
  rest=${line##*) }
  [ "$rest" != "$line" ] || return 1
  set -- $rest
  [ "$#" -ge 20 ] || return 1
  process_state=$1
  shift 19
  process_start=$1
  case "$process_start" in ''|*[!0-9]*) return 1;; esac
  printf '%s %s' "$process_state" "$process_start"
}
b0_lifecycle() {
  boot=$(cat /proc/sys/kernel/random/boot_id)
  pidns=$(readlink "/proc/$$/ns/pid")
  mountns=$(readlink "/proc/$$/ns/mnt")
  p1=$(b0_proc 1) || return 1
  p1start=${p1#* }
  case "$boot" in ''|*[!a-f0-9-]*) return 1;; esac
  case "$pidns" in pid:\[*\]) ;; *) return 1;; esac
  case "$mountns" in mnt:\[*\]) ;; *) return 1;; esac
  printf '%s|%s|%s|%s' "$boot" "$pidns" "$mountns" "$p1start"
}
b0_digest() { sha256sum "$1" | cut -d ' ' -f 1; }
b0_size() { wc -c < "$1" | tr -d '[:space:]'; }
# All helpers needed later are exercised on the real target by init. There is
# no alternate language, helper installation or retry fallback.
if [ "$mode" = init ]; then
  [ "$expected_root_identity" = - ] && [ "$expected_lifecycle" = - ] || exit 93
  if [ -e "$root" ] || [ -L "$root" ]; then
    b0_unknown root_already_exists
    exit 0
  fi
  life=$(b0_lifecycle) || { b0_unknown lifecycle_unavailable; exit 0; }
  mkdir -m 700 "$root" || { b0_unknown root_creation_failed; exit 0; }
  b0_new_file "$root/lifecycle" "$life"
  b0_new_file "$root/owner" "$binding"
  # Qualify base64, dd, sha256sum, stat and sync at the exact target runtime.
  b0_new_file "$root/probe" 'fixed-capture-probe'
  encoded=$(dd if="$root/probe" bs=1 skip=0 count=5 2>/dev/null | base64 | tr -d '\n')
  [ "$encoded" = Zml4ZWQ= ] || { b0_unknown runtime_tool_contract_failed; exit 0; }
  sync -f "$root"
  printf '{"schema":"sregym-fixed-action-shell-v2","state":"initialized","lifecycle":"%s","root_identity":"%s","uid":%s,"probe_sha256":"%s","probe_bytes":%s}\n' "$life" "$(stat -c '%d:%i' "$root")" "$(id -u)" "$(b0_digest "$root/probe")" "$(b0_size "$root/probe")"
  exit 0
fi
b0_checked_dir "$root" || { b0_unknown root_missing_or_invalid; exit 0; }
b0_checked_file "$root/lifecycle" && b0_checked_file "$root/owner" || { b0_unknown root_records_invalid; exit 0; }
[ "$(cat "$root/owner")" = "$rootbase" ] || { b0_unknown root_owner_binding_mismatch; exit 0; }
life=$(b0_lifecycle) || { b0_unknown lifecycle_unavailable; exit 0; }
[ "$(cat "$root/lifecycle")" = "$life" ] || { b0_unknown lifecycle_changed; exit 0; }
root_identity=$(stat -c '%d:%i' "$root")
[ "$root_identity" = "$expected_root_identity" ] || { b0_unknown original_root_identity_changed; exit 0; }
[ "$life" = "$expected_lifecycle" ] || { b0_unknown original_lifecycle_changed; exit 0; }
dir=$root/$action
if [ "$mode" = start ]; then
  if mkdir -m 700 "$dir" 2>/dev/null; then
    b0_new_file "$dir/binding" "$binding"
    b0_new_file "$dir/parameters" "$params"
    own=$(b0_proc $$) || { b0_unknown own_process_unavailable; exit 0; }
    ownstart=${own#* }
    b0_new_file "$dir/process" "$$ $ownstart"
    b0_new_file "$dir/lifecycle" "$life"
    sync -f "$dir"
    # All business code is fixed by the trusted program catalog. One unique
    # target claim precedes the first body entry. No shell source is read from
    # caller parameters or from action records.
    b0_new_file "$dir/body_started" "$binding"
    (set -C; : > "$dir/stdout"; : > "$dir/stderr")
    rc=0
    b0_body "$params" > "$dir/stdout" 2> "$dir/stderr" || rc=$?
    sync -f "$dir/stdout"
    sync -f "$dir/stderr"
    out_size=$(b0_size "$dir/stdout")
    err_size=$(b0_size "$dir/stderr")
    [ "$out_size" -le 33554432 ] && [ "$err_size" -le 33554432 ] || { b0_unknown capture_budget_exceeded; exit 0; }
    b0_new_file "$dir/manifest" "$binding $rc $(b0_digest "$dir/stdout") $out_size $(b0_digest "$dir/stderr") $err_size"
    b0_new_file "$dir/completion" "$binding"
    sync -f "$dir"
    # This start response is not target terminal evidence; its shell is still
    # alive here. A separate query checks PID/starttime after response return.
    printf '{"schema":"sregym-fixed-action-shell-v2","state":"body_completed","binding":"%s","target_claim_won":true,"body_started":true,"exit_code":%s,"process_pid":%s,"process_starttime":%s,"lifecycle":"%s"}\n' "$binding" "$rc" "$$" "$ownstart" "$life"
    exit 0
  fi
  # Duplicate physical delivery follows the query-only path and never runs body.
fi
b0_checked_dir "$dir" || { b0_unknown action_missing_or_invalid; exit 0; }
dir_identity=$(stat -c '%d:%i' "$dir")
for file in binding parameters process lifecycle body_started; do
  b0_checked_file "$dir/$file" || { b0_unknown action_record_missing; exit 0; }
done
[ "$(cat "$dir/binding")" = "$binding" ] && [ "$(cat "$dir/body_started")" = "$binding" ] || { b0_unknown binding_mismatch; exit 0; }
[ "$(cat "$dir/parameters")" = "$params" ] || { b0_unknown parameters_mismatch; exit 0; }
[ "$(cat "$dir/lifecycle")" = "$life" ] || { b0_unknown claim_lifecycle_mismatch; exit 0; }
read -r target_pid target_start < "$dir/process" || true
case "$target_pid:$target_start" in ''|*[!0-9:]*) b0_unknown process_record_invalid; exit 0;; esac
[ -n "$target_pid" ] && [ -n "$target_start" ] || { b0_unknown process_record_invalid; exit 0; }
process_terminal=false
process_observation=running
if current=$(b0_proc "$target_pid"); then
  current_state=${current%% *}
  current_start=${current#* }
  [ "$current_start" = "$target_start" ] || { b0_unknown pid_reused; exit 0; }
  if [ "$current_state" = Z ]; then process_terminal=true; process_observation=zombie; fi
else
  if [ -d "/proc/$target_pid" ]; then b0_unknown process_unreadable; exit 0; fi
  process_terminal=true
  process_observation=absent
fi
if [ ! -f "$dir/completion" ]; then
  if [ "$process_terminal" = true ]; then b0_unknown terminal_without_complete_capture; else
    printf '{"schema":"sregym-fixed-action-shell-v2","state":"running","binding":"%s","process_pid":%s,"process_starttime":%s,"lifecycle":"%s"}\n' "$binding" "$target_pid" "$target_start" "$life"
  fi
  exit 0
fi
for file in manifest completion stdout stderr; do
  b0_checked_file "$dir/$file" || { b0_unknown capture_record_invalid; exit 0; }
done
[ "$(cat "$dir/completion")" = "$binding" ] || { b0_unknown completion_mismatch; exit 0; }
read -r manifest_binding rc out_sha out_size err_sha err_size < "$dir/manifest" || true
[ "$manifest_binding" = "$binding" ] || { b0_unknown manifest_binding_mismatch; exit 0; }
case "$rc:$out_size:$err_size" in *[!0-9:]*) b0_unknown manifest_numeric_invalid; exit 0;; esac
case "$out_sha$err_sha" in ''|*[!a-f0-9]*) b0_unknown manifest_digest_invalid; exit 0;; esac
[ ${#out_sha} -eq 64 ] && [ ${#err_sha} -eq 64 ] || { b0_unknown manifest_digest_invalid; exit 0; }
[ "$out_size" -le 33554432 ] && [ "$err_size" -le 33554432 ] && [ "$rc" -le 255 ] || { b0_unknown manifest_bounds_invalid; exit 0; }
[ "$(b0_digest "$dir/stdout")" = "$out_sha" ] && [ "$(b0_digest "$dir/stderr")" = "$err_sha" ] && [ "$(b0_size "$dir/stdout")" = "$out_size" ] && [ "$(b0_size "$dir/stderr")" = "$err_size" ] || { b0_unknown capture_changed; exit 0; }
state=running
if [ "$process_terminal" = true ]; then state=target_terminal; fi
chunk=''
if [ "$mode" = chunk ]; then
  size=$out_size
  if [ "$stream" = stderr ]; then size=$err_size; fi
  [ "$offset" -le "$size" ] || { b0_unknown offset_out_of_range; exit 0; }
  chunk=$(dd if="$dir/$stream" bs=1 skip="$offset" count="$count" 2>/dev/null | base64 | tr -d '\n')
fi
# Check the same directory and capture after reading; any evidence change keeps
# the action unknown. Atime changes from reads are not claimed immutable.
[ "$(stat -c '%d:%i' "$root")" = "$root_identity" ] && [ "$(stat -c '%d:%i' "$dir")" = "$dir_identity" ] || { b0_unknown directory_replaced; exit 0; }
[ "$(b0_digest "$dir/stdout")" = "$out_sha" ] && [ "$(b0_digest "$dir/stderr")" = "$err_sha" ] || { b0_unknown capture_changed_during_query; exit 0; }
printf '{"schema":"sregym-fixed-action-shell-v2","state":"%s","binding":"%s","target_claim_won":false,"target_process_terminal":%s,"process_observation":"%s","process_pid":%s,"process_starttime":%s,"lifecycle":"%s","root_identity":"%s","action_directory_identity":"%s","exit_code":%s,"stdout_sha256":"%s","stdout_bytes":%s,"stderr_sha256":"%s","stderr_bytes":%s,"stream":"%s","offset":%s,"chunk_base64":"%s"}\n' "$state" "$binding" "$process_terminal" "$process_observation" "$target_pid" "$target_start" "$life" "$root_identity" "$dir_identity" "$rc" "$out_sha" "$out_size" "$err_sha" "$err_size" "$stream" "$offset" "$chunk"
'''


def source(body_shell: str) -> str:
    if not isinstance(body_shell, str) or not body_shell.strip() or '\x00' in body_shell:
        raise ValueError('Expected a fixed trusted shell body')
    return 'b0_body() {\n' + body_shell + '\n}\n' + BASE


def program_sha256(body_shell: str) -> str:
    return hashlib.sha256(source(body_shell).encode()).hexdigest()


def encoded_source_argv(fixed_source: str, command_zero: str, arguments: list[str]) -> list[str]:
    """Encode trusted source only; every caller parameter remains a data argv."""
    if not isinstance(fixed_source, str) or not fixed_source or '\x00' in fixed_source:
        raise ValueError('Expected nonempty NUL-free trusted source')
    raw = fixed_source.encode('utf-8')
    output = io.BytesIO()
    # GzipFile fixes the header OS byte as well as time/name metadata.
    with gzip.GzipFile(fileobj=output, mode='wb', filename='', compresslevel=9, mtime=0) as stream:
        stream.write(raw)
    packed = base64.b64encode(output.getvalue()).decode('ascii')
    return ['sh', '-c', SOURCE_DECODER, command_zero, packed,
            hashlib.sha256(raw).hexdigest(), str(len(raw)), *arguments]


def exec_request_line_bytes(namespace: str, pod: str, container: str, command: list[str]) -> int:
    """Pinned kubectl 1.32.5 noninteractive exec, origin-form POST HTTP/1.1.

    PodExecOptions omits false stdin/tty, repeats command in argv order, and
    enables stderr/stdout. urlencode uses the same UTF-8 QueryEscape rules as
    Go net/url.Values.Encode (space '+', literal plus '%2B', '~' unescaped).
    POST is one byte longer than its WebSocket GET alternative. This is a
    request-line calculation, not captured network wire-byte accounting.
    """
    path = '/api/v1/namespaces/' + quote(namespace, safe='') + '/pods/' + quote(pod, safe='') + '/exec'
    query = urlencode([('command', value) for value in command]
                      + [('container', container), ('stderr', 'true'), ('stdout', 'true')])
    return len(('POST ' + path + '?' + query + ' HTTP/1.1\r\n').encode('ascii'))


def require_exec_budget(namespace: str, pod: str, container: str, command: list[str]) -> int:
    size = exec_request_line_bytes(namespace, pod, container, command)
    if size > MAX_EXEC_REQUEST_LINE_BYTES:
        raise ValueError('Fixed exec request line exceeds conservative transport budget: '
                         + str(size) + ' > ' + str(MAX_EXEC_REQUEST_LINE_BYTES))
    return size


def argv(body_shell: str, *, mode: str, root: str, action: str, binding: str,
         parameters_json: str, offset: int = 0, count: int = CHUNK_BYTES,
         stream: str = 'stdout', expected_root_identity: str | None = None,
         expected_lifecycle: str | None = None) -> list[str]:
    if mode not in {'init', 'start', 'query', 'chunk'}:
        raise ValueError('Invalid envelope mode')
    if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= MAX_CAPTURE_BYTES:
        raise ValueError('Invalid offset')
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= CHUNK_BYTES:
        raise ValueError('Invalid count')
    if stream not in {'stdout', 'stderr'}:
        raise ValueError('Invalid capture stream')
    if mode == 'init':
        if expected_root_identity is not None or expected_lifecycle is not None:
            raise ValueError('Initialization cannot claim a pre-existing root')
        expected_root_identity = expected_lifecycle = '-'
    elif (not isinstance(expected_root_identity, str) or not expected_root_identity
          or not isinstance(expected_lifecycle, str) or not expected_lifecycle):
        raise ValueError('Original measured root and Linux lifecycle are required')
    return encoded_source_argv(source(body_shell), 'sregym-fixed-action-v2',
        [mode, root, action, binding, parameters_json, str(offset), str(count), stream,
         expected_root_identity, expected_lifecycle])
