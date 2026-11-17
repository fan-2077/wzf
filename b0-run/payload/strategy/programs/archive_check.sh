set -eu
cfg=$1
file=$(printf '%s' "$cfg" | sed -n 's/^.*"file":"\([A-Za-z0-9_.-]*\)".*$/\1/p')
expected=$(printf '%s' "$cfg" | sed -n 's/^.*"expected_sha256":"\([a-f0-9]*\)".*$/\1/p')
case "$file" in ''|.*|*..*) exit 64;; esac
[ "${#expected}" -eq 64 ]
path=/recovery/backups/$file
if [ ! -f "$path" ]; then printf 'B0_RESULT:{"valid":false,"reason":"missing"}\n'; exit 0; fi
[ ! -L "$path" ] && [ "$(readlink -f "$path")" = "$path" ]
sha1=$(sha256sum "$path"); sha1=${sha1%% *}
if [ "$sha1" != "$expected" ]; then printf 'B0_RESULT:{"valid":false,"reason":"digest_mismatch","sha256":"%s"}\n' "$sha1"; exit 0; fi
tmp=$(mktemp -d /tmp/b0-archive-check.XXXXXXXX)
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM
rc=0
pg_restore --list "$path" >"$tmp/list" 2>"$tmp/err" || rc=$?
sha2=$(sha256sum "$path"); sha2=${sha2%% *}
[ "$sha1" = "$sha2" ]
valid=false; [ "$rc" -eq 0 ] && valid=true
listing=$(base64 <"$tmp/list" | tr -d '\n')
err=$(base64 <"$tmp/err" | tr -d '\n')
printf '{"valid":%s,"file":"%s","sha256":"%s","pg_restore_exit":%s,"list_base64":"%s","stderr_base64":"%s"}\n' "$valid" "$file" "$sha1" "$rc" "$listing" "$err" >"$tmp/result"
# Retain every original pg_restore listing byte, but avoid thousands of
# native round trips for its large base64 JSON representation.
command -v gzip >/dev/null
bytes=$(wc -c <"$tmp/result")
[ "$bytes" -le 67108864 ]
result_sha=$(sha256sum "$tmp/result"); result_sha=${result_sha%% *}
gzip -n -9 -c "$tmp/result" >"$tmp/result.gz"
printf 'B0_RESULT_GZIP:{"encoding":"gzip+base64","uncompressed_bytes":%s,"uncompressed_sha256":"%s","data_base64":"' "$bytes" "$result_sha"
base64 <"$tmp/result.gz" | tr -d '\n'
printf '"}\n'
