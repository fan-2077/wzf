set -eu
cfg=$1
file=$(printf '%s' "$cfg" | sed -n 's/^.*"file":"\([A-Za-z0-9_.-]*\)".*$/\1/p')
expected=$(printf '%s' "$cfg" | sed -n 's/^.*"expected_sha256":"\([a-f0-9]*\)".*$/\1/p')
tag=$(printf '%s' "$cfg" | sed -n 's/^.*"action_tag":"\([a-zA-Z0-9_-]*\)".*$/\1/p')
case "$file" in ''|.*|*..*) exit 64;; esac
[ "${#expected}" -eq 64 ] && [ -n "$tag" ] && [ "${#tag}" -le 48 ]
path=/recovery/backups/$file
[ -f "$path" ] && [ ! -L "$path" ] && [ "$(readlink -f "$path")" = "$path" ]
sha1=$(sha256sum "$path"); sha1=${sha1%% *}
[ "$sha1" = "$expected" ]
pg_restore --list "$path" >/dev/null
tmp=$(mktemp -d /tmp/b0-restore.XXXXXXXX)
restore_pid=
restore_waited=false
finish_owned_child() {
  # The action shell never leaves an already-dispatched owned restore running
  # while reporting its own successful terminal. On interruption, wait for the
  # original shell job; never signal an arbitrary or reused numeric PID.
  if [ -n "$restore_pid" ] && [ "$restore_waited" = false ]; then
    wait "$restore_pid" 2>/dev/null || true
    restore_waited=true
  fi
  rm -rf -- "$tmp"
}
trap finish_owned_child EXIT
trap 'exit 130' HUP INT TERM
export PGAPPNAME=b0-reset-$tag
# This stage commits separately from pg_restore, and is reported separately.
reset_rc=0
psql -X -v ON_ERROR_STOP=1 -At >"$tmp/reset" 2>"$tmp/reset.err" <<'B0_SQL' || reset_rc=$?
BEGIN;
SELECT json_build_object('pid',pg_backend_pid(),'backend_start',backend_start,'application_name',application_name,'xid',txid_current(),'server_address',inet_server_addr(),'postmaster_start',pg_postmaster_start_time()) FROM pg_stat_activity WHERE pid=pg_backend_pid();
DO $$ DECLARE n text; BEGIN
  FOR n IN SELECT nspname FROM pg_namespace WHERE nspname NOT LIKE 'pg_%' AND nspname <> 'information_schema' LOOP
    EXECUTE format('DROP SCHEMA %I CASCADE', n);
  END LOOP;
  CREATE SCHEMA public AUTHORIZATION gitlab_ce;
END $$;
COMMIT;
B0_SQL
restore_rc=125
: >"$tmp/backend-samples"
: >"$tmp/backend-samples.err"
monitor_queries=0
if [ "$reset_rc" -eq 0 ]; then
  export PGAPPNAME=b0-restore-$tag
  restore_rc=0
  pg_restore --exit-on-error --single-transaction --clean --if-exists --no-owner --no-privileges --dbname=gitlab_ce "$path" >"$tmp/restore" 2>"$tmp/restore.err" &
  restore_pid=$!
  # Only this owned child is observed and waited. No arbitrary PID termination.
  restore_process_stat=$(cat "/proc/$restore_pid/stat" 2>/dev/null || true)
  restore_start_ticks=$(printf '%s' "$restore_process_stat" | sed 's/^.*) //' | awk '{print $20}')
  while kill -0 "$restore_pid" 2>/dev/null; do
    current_stat=$(cat "/proc/$restore_pid/stat" 2>/dev/null || true)
    current_start_ticks=$(printf '%s' "$current_stat" | sed 's/^.*) //' | awk '{print $20}')
    [ -n "$restore_start_ticks" ] && [ "$current_start_ticks" = "$restore_start_ticks" ] || break
    monitor_queries=$((monitor_queries+1))
    PGAPPNAME=b0-monitor-$tag psql -X -v ON_ERROR_STOP=1 -At -c "SELECT COALESCE(json_agg(s),'[]'::json) FROM (SELECT pid,backend_start,application_name,state,xact_start,backend_xid,wait_event_type FROM pg_stat_activity WHERE datname=current_database() AND application_name='b0-restore-$tag')s;" >>"$tmp/backend-samples" 2>>"$tmp/backend-samples.err" || true
    # Some shells may reap an asynchronous child before wait. Reused numeric
    # PIDs cannot match the captured start ticks. wait returns the owned job's
    # exit status; neither PID disappearance nor this loop proves DB terminal.
    child_state=$(printf '%s' "$current_stat" | sed 's/^.*) //' | awk '{print $1}')
    [ "$child_state" = Z ] && break
    [ -z "$child_state" ] && break
    sleep 0.2
  done
  wait "$restore_pid" || restore_rc=$?
  restore_waited=true
else
  : >"$tmp/restore"; : >"$tmp/restore.err"
  restore_pid=0; restore_process_stat=; restore_waited=true
fi
export PGAPPNAME=b0-confirm-$tag
confirm_rc=0
psql -X -v ON_ERROR_STOP=1 -At -c "SELECT json_build_object('server_address',inet_server_addr(),'postmaster_start',pg_postmaster_start_time(),'issues_present',to_regclass('public.issues') IS NOT NULL,'matching_sessions',COALESCE((SELECT json_agg(s) FROM (SELECT pid,backend_start,application_name,state,xact_start,backend_xid FROM pg_stat_activity WHERE datname=current_database() AND application_name IN ('b0-reset-$tag','b0-restore-$tag'))s),'[]'::json));" >"$tmp/confirm" 2>"$tmp/confirm.err" || confirm_rc=$?
sha2=$(sha256sum "$path"); sha2=${sha2%% *}
printf 'B0_RESULT:{"file":"%s","archive_sha_before":"%s","archive_sha_after":"%s","reset_exit":%s,"restore_exit":%s,"confirmation_exit":%s,"reset_stdout_base64":"%s","reset_stderr_base64":"%s","restore_stdout_base64":"%s","restore_stderr_base64":"%s","confirmation_base64":"%s","confirmation_stderr_base64":"%s","restore_child_pid":%s,"restore_child_stat_base64":"%s","backend_samples_base64":"%s","backend_samples_stderr_base64":"%s","monitor_queries":%s}\n' "$file" "$sha1" "$sha2" "$reset_rc" "$restore_rc" "$confirm_rc" "$(base64 <"$tmp/reset" | tr -d '\n')" "$(base64 <"$tmp/reset.err" | tr -d '\n')" "$(base64 <"$tmp/restore" | tr -d '\n')" "$(base64 <"$tmp/restore.err" | tr -d '\n')" "$(base64 <"$tmp/confirm" | tr -d '\n')" "$(base64 <"$tmp/confirm.err" | tr -d '\n')" "$restore_pid" "$(printf '%s' "$restore_process_stat" | base64 | tr -d '\n')" "$(base64 <"$tmp/backend-samples" | tr -d '\n')" "$(base64 <"$tmp/backend-samples.err" | tr -d '\n')" "$monitor_queries"
