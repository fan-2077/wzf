"""Fixed POSIX-shell action envelope. Caller parameters never contain shell code.

The envelope qualifies only its own foreground body and immutable capture.
Business-server terminal/effect proof is supplied separately by fixed validators.
The target's /tmp and same-UID processes are a trusted boundary, not adversarial.
"""
from __future__ import annotations
import hashlib
import shlex

SCHEMA = 'sregym-fixed-action-shell-v2'
MAX_CAPTURE_BYTES = 32 * 1024 * 1024
CHUNK_BYTES = 4096

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
[ "$count" -ge 1 ] && [ "$count" -le 4096 ] || exit 90
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
    return ['sh', '-c', source(body_shell), 'sregym-fixed-action-v2', mode, root,
            action, binding, parameters_json, str(offset), str(count), stream,
            expected_root_identity, expected_lifecycle]
