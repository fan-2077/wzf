set -eu
cfg=$1
kind=$(printf '%s' "$cfg" | sed -n 's/^.*"kind":"\([a-z]*\)".*$/\1/p')
case "$kind" in
  catalog) path=/recovery/backups/catalog.json;;
  issues) path=/recovery/journal/acknowledged-issues.json;;
  notifications) path=/recovery/journal/acknowledged-notifications.json;;
  *) exit 64;;
esac
[ -f "$path" ] && [ ! -L "$path" ] && [ "$(readlink -f "$path")" = "$path" ]
before=$(stat -c '%d:%i:%s:%Y:%Z' "$path")
size=$(stat -c %s "$path")
[ "$size" -le 4194304 ]
sha1=$(sha256sum "$path"); sha1=${sha1%% *}
data=$(base64 <"$path" | tr -d '\n')
sha2=$(sha256sum "$path"); sha2=${sha2%% *}
[ "$sha1" = "$sha2" ] && [ "$before" = "$(stat -c '%d:%i:%s:%Y:%Z' "$path")" ]
printf 'B0_RESULT:{"kind":"%s","path":"%s","source_version":"%s","bytes":%s,"sha256":"%s","data_base64":"%s","source_complete":true}\n' "$kind" "$path" "$before" "$size" "$sha1" "$data"
