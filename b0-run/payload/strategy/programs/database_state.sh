set -eu
cfg=$1
tag=$(printf '%s' "$cfg" | sed -n 's/^.*"action_tag":"\([a-zA-Z0-9_-]*\)".*$/\1/p')
[ -n "$tag" ] && [ "${#tag}" -le 48 ]
export PGAPPNAME=b0-observe-$tag
psql -X -v ON_ERROR_STOP=1 -At -c "SELECT 'B0_RESULT:' || json_build_object('server_version',current_setting('server_version'),'server_address',inet_server_addr(),'server_port',inet_server_port(),'postmaster_start',pg_postmaster_start_time(),'database_oid',(SELECT oid FROM pg_database WHERE datname=current_database()),'in_recovery',pg_is_in_recovery(),'issues_present',to_regclass('public.issues') IS NOT NULL,'sessions',COALESCE((SELECT json_agg(s) FROM (SELECT pid,backend_start,application_name,state,xact_start,backend_xid,wait_event_type FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() ORDER BY pid)s),'[]'::json))::text;"
