#!/bin/sh
# Incremental update for the already installed Merlin 380 fancyss 4.38.3.
# Payload hashes detect incomplete/corrupt transfers; install only a trusted package.
set -eu
umask 077
KS_ROOT=/koolshare
JFFS_ROOT=/jffs
RUN_ROOT=/tmp
PATH="$KS_ROOT/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

fail() { printf 'Enhancement: %s\n' "$1" >&2; exit 1; }
allowed_path() {
  case "$1" in
    bin/anytls|bin/ss-flock|scripts/ss_anytls.sh|scripts/ss_health.sh|scripts/ss_routing.sh|scripts/ss_dns_hooks.sh|scripts/ss_webtest.sh|scripts/uninstall_shadowsocks.sh|ss/ssconfig.sh|ss/cru/foreign.sh|ss/rules/dnsmasq.postconf|ss/rules/cacert.pem|ss/rules/cacert.pem.sha256|webs/Main_Ss_Content.asp|res/ss-health.js|res/ss-health.css|res/icon-shadowsocks.png) return 0 ;;
    *) return 1 ;;
  esac
}
# Merlin 380 does not provide standalone mktemp/stat applets.
mktemp() { "$RUNTIME_TOOL" mktemp "$@"; }
file_mode() { "$RUNTIME_TOOL" mode "$1"; }
dbus_exists() { dbus list "$1" | awk -F= -v key="$1" '$1 == key {found=1} END {exit !found}'; }
allowed_key() {
  case "$1" in
    ss_basic_bypass_macs|ss_basic_uu_macs|ss_basic_anytls_min_idle|ss_basic_anytls_idle_check|ss_basic_anytls_idle_timeout|ss_basic_anytls_handshake|ss_basic_anytls_alpn|ss_basic_anytls_fingerprint|ss_basic_anytls_hosts|ss_basic_rule_update|ss_basic_node_update|ss_basic_server_resolver|ss_basic_health_interval|ss_basic_health_timeout|ss_basic_health_failures|ss_basic_allowinsecure|ss_basic_enable) return 0 ;;
    ssconf_basic_allowinsecure_*)
      node_suffix=${1#ssconf_basic_allowinsecure_}
      case "$node_suffix" in ''|*[!0-9]*) return 1 ;; esac
      [ "${#node_suffix}" -le 6 ] && [ "$node_suffix" -gt 0 ] ;;
    *) return 1 ;;
  esac
}
restore_files() {
  restore_rc=0
  while IFS='|' read -r relative kind mode; do
    allowed_path "$relative" || { restore_rc=1; continue; }
    destination="$KS_ROOT/$relative"
    case "$kind" in
      absent) rm -f "$destination" || restore_rc=1 ;;
      file)
        temp=$(mktemp "$(dirname "$destination")/.r7000-restore.XXXXXX") || { restore_rc=1; continue; }
        if cp -p "$BACKUP/files/$relative" "$temp" && chmod "$mode" "$temp" && mv -f "$temp" "$destination"; then :; else rm -f "$temp"; restore_rc=1; fi ;;
      link)
        temp=$(mktemp "$(dirname "$destination")/.r7000-restore.XXXXXX") || { restore_rc=1; continue; }
        rm -f "$temp"
        if ln -s "$(cat "$BACKUP/files/$relative")" "$temp" && mv -f "$temp" "$destination"; then :; else rm -f "$temp"; restore_rc=1; fi ;;
      *) restore_rc=1 ;;
    esac
  done < "$BACKUP/files.list"
  return "$restore_rc"
}
restore_settings() {
  restore_rc=0
  while IFS= read -r key; do
    allowed_key "$key" || { restore_rc=1; continue; }
    [ "$key" = ss_basic_enable ] && continue
    if [ "$(cat "$BACKUP/dbus/$key.kind")" = present ]; then
      dbus set "$key=$(cat "$BACKUP/dbus/$key")" || restore_rc=1
    else
      dbus remove "$key" || restore_rc=1
    fi
  done < "$BACKUP/dbus.list"
  # After touching service runtime the old service must remain disabled.
  # Before that point its original process still runs, so preserve its UI flag.
  dbus set "ss_basic_enable=${1:-0}" || restore_rc=1
  return "$restore_rc"
}

# The private backup contains this same installer, so manual restoration needs
# no downloaded package and never invokes an old service start/stop entry point.
if [ "${1:-}" = --restore-files ]; then
  [ "$#" -eq 2 ] || fail 'Invalid restore arguments.'
  BACKUP=$2
  case "$BACKUP" in "$JFFS_ROOT/.r7000-backups/"*) ;; *) fail 'Invalid backup location.' ;; esac
  [ -d "$BACKUP" ] && [ ! -L "$BACKUP" ] && [ -f "$BACKUP/files.list" ] && [ -f "$BACKUP/dbus.list" ] || fail 'Backup is incomplete.'
  RUNTIME_TOOL="$BACKUP/runtime-tool"
  [ -f "$RUNTIME_TOOL" ] && [ ! -L "$RUNTIME_TOOL" ] && [ -x "$RUNTIME_TOOL" ] || fail 'The private restore tool is missing.'
  [ "$(dbus get ss_basic_enable)" != 1 ] || fail 'Use the enhanced safe stop first; this restore never stops a running service.'
  while IFS='|' read -r relative kind mode; do
    allowed_path "$relative" || fail 'Invalid backup file record.'
    case "$kind:$mode" in absent:0|link:0) ;; file:*) case "$mode" in ''|*[!0-7]*) fail 'Invalid backup mode.' ;; esac ;; *) fail 'Invalid backup record.' ;; esac
  done < "$BACKUP/files.list"
  restore_files && restore_settings || fail 'Restore was incomplete; retain the private backup for recovery.'
  printf 'Files and settings restored. Science remains disabled; do not run the old start/stop.\n'
  exit 0
fi

SETTINGS=
MIGRATION=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --settings) [ "$#" -ge 2 ] && [ -z "$SETTINGS" ] || fail 'Invalid settings arguments.'; SETTINGS=$2; shift 2 ;;
    --migration=phone-insecure) [ -z "$MIGRATION" ] || fail 'Duplicate migration option.'; MIGRATION=phone-insecure; shift ;;
    *) fail 'Usage: install.sh [--settings private-settings] [--migration=phone-insecure]' ;;
  esac
done
PACKAGE=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
PAYLOAD="$PACKAGE/payload"
RUNTIME_TOOL="$PAYLOAD/bin/ss-flock"
[ "$(awk '$1 == "Uid:" {print $2; exit}' /proc/self/status)" = 0 ] || fail 'Run this installer as root.'
[ "$(uname -m)" = armv7l ] || fail 'This package requires Merlin 380 armv7l.'
[ -d "$KS_ROOT" ] || fail 'The installed root directory is missing.'
# /koolshare -> /jffs/.koolshare is the standard Merlin layout. Resolve only
# this root; destination parents below it must still be real directories.
KS_ROOT=$(CDPATH= cd -P "$KS_ROOT" && pwd) || fail 'Cannot resolve the installed root directory.'
[ -f "$KS_ROOT/ss/version" ] && [ "$(cat "$KS_ROOT/ss/version")" = 4.38.3 ] || fail 'An installed fancyss 4.38.3 is required.'
[ -d "$PAYLOAD" ] && [ ! -L "$PAYLOAD" ] && [ -f "$PACKAGE/manifest.md5" ] && [ ! -L "$PACKAGE/manifest.md5" ] || fail 'Payload or manifest is missing.'
awk 'NF != 2 || length($1) != 32 || $1 !~ /^[0-9a-fA-F]+$/ || $2 !~ /^[A-Za-z0-9._\/-]+$/ || $2 ~ /(^|\/)\.\.?($|\/)/ || $2 ~ /\/\// || $2 ~ /^\// {exit 1} {if (seen[$2]++) exit 1; count++} END {if (count != 17) exit 1}' "$PACKAGE/manifest.md5" || fail 'Manifest format or file count is invalid.'

WORK=$(mktemp -d "$RUN_ROOT/r7000-enhancement.XXXXXX") || fail 'Cannot allocate private work directory.'
LOCK="$RUN_ROOT/r7000-enhancement.lock"
BACKUP=
MUTATED=0
STOP_ATTEMPTED=0
COMMITTED=0
LOCKED=0
finish() {
  status=$?
  trap - 0 HUP INT TERM
  set +e
  if [ "$MUTATED" = 1 ] && [ "$COMMITTED" != 1 ]; then
    rollback_ok=1
    rollback_enable=$original_enabled
    if [ "$STOP_ATTEMPTED" = 1 ]; then
      # This entry point is known to be the new one, with all dependencies.
      sh "$KS_ROOT/ss/ssconfig.sh" stop >> "$BACKUP/service.log" 2>&1 || rollback_ok=0
      rollback_enable=0
    fi
    restore_files || rollback_ok=0
    restore_settings "$rollback_enable" || rollback_ok=0
    if [ "$rollback_ok" = 1 ]; then
      printf 'Enhancement failed. Previous files/settings restored; enable=%s. Backup: %s\n' "$rollback_enable" "$BACKUP" >&2
    else
      printf 'Enhancement failed and recovery is incomplete; retain backup: %s\n' "$BACKUP" >&2
    fi
    [ "$status" -ne 0 ] || status=1
  fi
  if [ -d "$WORK/staged" ]; then
    find "$WORK/staged" -print > "$WORK/staged.entries"
    while IFS= read -r record; do
      [ ! -f "$record" ] || rm -f "$(cat "$record")"
    done < "$WORK/staged.entries"
  fi
  rm -rf "$WORK"
  [ "$LOCKED" = 0 ] || rmdir "$LOCK" 2>/dev/null
  exit "$status"
}
trap finish 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$LOCK" 2>/dev/null || fail 'Another enhancement installer is active.'
LOCKED=1
awk '{print $2}' "$PACKAGE/manifest.md5" | sort > "$WORK/paths"
find "$PAYLOAD" -print > "$WORK/payload.entries" || fail 'Cannot list the payload.'
: > "$WORK/actual.unsorted"
while IFS= read -r entry; do
  [ ! -L "$entry" ] || fail 'Payload links and special files are not accepted.'
  if [ -f "$entry" ]; then
    printf '%s\n' "${entry#"$PAYLOAD/"}" >> "$WORK/actual.unsorted"
  elif [ -d "$entry" ]; then :
  else fail 'Payload links and special files are not accepted.'; fi
done < "$WORK/payload.entries"
sort "$WORK/actual.unsorted" > "$WORK/actual"
cmp -s "$WORK/paths" "$WORK/actual" || fail 'Payload and manifest file sets differ.'
while IFS= read -r relative; do
  allowed_path "$relative" || fail 'A payload path is outside the enhancement allowlist.'
  parent=$(dirname "$KS_ROOT/$relative")
  while [ "$parent" != "$KS_ROOT" ]; do
    [ -d "$parent" ] && [ ! -L "$parent" ] || fail 'An installed destination parent is missing or is a symlink.'
    parent=$(dirname "$parent")
  done
  [ ! -d "$KS_ROOT/$relative" ] || fail 'An installed destination is a directory.'
done < "$WORK/paths"
(cd "$PAYLOAD" && md5sum -c "$PACKAGE/manifest.md5") > "$WORK/checksums.log" 2>&1 || fail 'Payload checksum verification failed.'
sh -n "$PAYLOAD/ss/ssconfig.sh" || fail 'The new service script has invalid shell syntax.'
for relative in scripts/ss_anytls.sh scripts/ss_health.sh scripts/ss_routing.sh scripts/ss_dns_hooks.sh scripts/ss_webtest.sh scripts/uninstall_shadowsocks.sh ss/cru/foreign.sh ss/rules/dnsmasq.postconf; do
  sh -n "$PAYLOAD/$relative" || fail 'A payload script has invalid shell syntax.'
done
"$PAYLOAD/bin/anytls" -version > "$WORK/client-version" 2>&1 || fail 'The AnyTLS client cannot run on this router.'
grep -q -- '-r7000\.' "$WORK/client-version" || fail 'The AnyTLS client is not the enhanced R7000 build.'
# Health and service locking require locks on inherited descriptors to remain
# held after the helper exits, then release explicitly. Filename-only tests do
# not establish that contract.
(
  exec 9>"$WORK/flock-test"
  "$PAYLOAD/bin/ss-flock" -n 9 || exit 1
  (exec 8>"$WORK/flock-test"; ! "$PAYLOAD/bin/ss-flock" -n 8) || exit 1
  "$PAYLOAD/bin/ss-flock" -u 9 || exit 1
  (exec 8>"$WORK/flock-test"; "$PAYLOAD/bin/ss-flock" -n 8)
) || fail 'The private flock helper does not support inherited descriptor locking.'

mkdir "$WORK/desired"
cat > "$WORK/defaults" <<'DEFAULTS'
ss_basic_bypass_macs=
ss_basic_uu_macs=
ss_basic_anytls_min_idle=0
ss_basic_anytls_idle_check=30
ss_basic_anytls_idle_timeout=30
ss_basic_anytls_handshake=8
ss_basic_anytls_alpn=h2
ss_basic_anytls_fingerprint=chrome
ss_basic_anytls_hosts=
ss_basic_health_interval=30
ss_basic_health_timeout=10
ss_basic_health_failures=3
DEFAULTS
while IFS='=' read -r key value; do
  existing=$(dbus get "$key")
  [ -z "$existing" ] || value=$existing
  printf '%s' "$value" > "$WORK/desired/$key"
done < "$WORK/defaults"
if [ -n "$SETTINGS" ]; then
  [ -f "$SETTINGS" ] && [ ! -L "$SETTINGS" ] || fail 'The settings file must be a regular private file.'
  case "$(file_mode "$SETTINGS")" in 400|600) ;; *) fail 'The settings file must have mode 600 or 400.' ;; esac
  [ "$(wc -c < "$SETTINGS")" -le 8192 ] || fail 'The settings file is too large.'
  : > "$WORK/private.keys"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|\#*) continue ;; *=*) key=${line%%=*}; value=${line#*=} ;; *) fail 'Invalid settings line.' ;; esac
    allowed_key "$key" || fail 'A settings key is not allowed.'
    case "$key" in ss_basic_enable|ssconf_*) fail 'A settings key is not allowed.' ;; esac
    grep -Fqx "$key" "$WORK/private.keys" && fail 'A settings key is duplicated.'
    printf '%s\n' "$key" >> "$WORK/private.keys"
    printf '%s' "$value" > "$WORK/desired/$key"
  done < "$SETTINGS"
fi
normalized_hosts=$(SS_ANYTLS_KOOLSHARE="$PAYLOAD" sh "$PAYLOAD/scripts/ss_anytls.sh" normalize-hosts "$(cat "$WORK/desired/ss_basic_anytls_hosts")") || fail 'The AnyTLS hosts setting is invalid.'
printf '%s' "$normalized_hosts" > "$WORK/desired/ss_basic_anytls_hosts"
# These two options are changed only when explicitly supplied privately.
for key in ss_basic_rule_update ss_basic_node_update; do
  if [ -f "$WORK/desired/$key" ]; then
    case "$(cat "$WORK/desired/$key")" in 0|1) ;; *) fail 'An automatic update flag is invalid.' ;; esac
  fi
done
if [ -f "$WORK/desired/ss_basic_server_resolver" ]; then
  case "$(cat "$WORK/desired/ss_basic_server_resolver")" in 1|2|3|4|5|6|7|8|9|10|11|12|13) ;; *) fail 'The server resolver preset is invalid.' ;; esac
fi
. "$PAYLOAD/scripts/ss_routing.sh"
# Validate the existing profiles too, since the safe pre-update stop reads them.
ss_routing_load_bypass_macs || fail 'The installed MAC profiles are invalid or overlap.'
for key in ss_basic_bypass_macs ss_basic_uu_macs; do
  normalized=$(ss_routing_normalize_macs < "$WORK/desired/$key") || fail 'A device MAC profile is invalid.'
  printf '%s\n' "$normalized" | awk 'NF {if (n++) printf ","; printf "%s",$0}' > "$WORK/desired/$key"
done
bypass=$(cat "$WORK/desired/ss_basic_bypass_macs")
uu=$(cat "$WORK/desired/ss_basic_uu_macs")
for mac in $(printf '%s' "$uu" | tr ',' ' '); do
  printf '%s' "$bypass" | tr ',' '\n' | grep -Fqx "$mac" && fail 'Device MAC profiles overlap.'
done
validate_number() {
  value=$(cat "$WORK/desired/$1")
  case "$value" in ''|*[!0-9]*) fail 'A numeric setting is invalid.' ;; esac
  [ "${#value}" -le 3 ] && [ "$value" -ge "$2" ] && [ "$value" -le "$3" ] || fail 'A numeric setting is out of range.'
}
validate_number ss_basic_anytls_min_idle 0 20
validate_number ss_basic_anytls_idle_check 5 300
validate_number ss_basic_anytls_idle_timeout 5 600
validate_number ss_basic_anytls_handshake 3 20
case "$(cat "$WORK/desired/ss_basic_anytls_alpn")" in auto|h2|http/1.1|h2,http/1.1|http/1.1,h2) ;; *) fail 'The ALPN setting is invalid.' ;; esac
case "$(cat "$WORK/desired/ss_basic_anytls_fingerprint")" in chrome|standard) ;; *) fail 'The fingerprint setting is invalid.' ;; esac
case "$(cat "$WORK/desired/ss_basic_health_interval")" in 30|60|120) ;; *) fail 'The health interval is invalid.' ;; esac
case "$(cat "$WORK/desired/ss_basic_health_timeout")" in 6|8|10) ;; *) fail 'The health timeout is invalid.' ;; esac
validate_number ss_basic_health_failures 1 5
if [ -f "$WORK/desired/ss_basic_allowinsecure" ]; then
  case "$(cat "$WORK/desired/ss_basic_allowinsecure")" in 0|1) ;; *) fail 'The TLS migration flag is invalid.' ;; esac
  node=$(dbus get ssconf_basic_node)
  case "$node" in ''|*[!0-9]*) fail 'The selected node is invalid for TLS migration.' ;; esac
  [ "${#node}" -le 6 ] && [ "$node" -gt 0 ] &&
    [ "$(dbus get ss_basic_type)" = 4 ] && [ "$(dbus get ss_basic_trojan_binary)" = AnyTLS ] &&
    [ "$(dbus get "ssconf_basic_type_$node")" = 4 ] && [ "$(dbus get "ssconf_basic_trojan_binary_$node")" = AnyTLS ] || fail 'TLS migration requires a selected AnyTLS node.'
  cp "$WORK/desired/ss_basic_allowinsecure" "$WORK/desired/ssconf_basic_allowinsecure_$node"
fi
if [ "$MIGRATION" = phone-insecure ]; then
  [ -f "$WORK/desired/ss_basic_allowinsecure" ] && [ "$(cat "$WORK/desired/ss_basic_allowinsecure")" = 1 ] || fail 'Phone-compatible migration requires an explicit private ss_basic_allowinsecure=1.'
  dbus list ssconf_basic_type_ > "$WORK/node-types"
  while IFS='=' read -r key value; do
    case "$key" in ssconf_basic_type_*) suffix=${key#ssconf_basic_type_} ;; *) continue ;; esac
    case "$suffix" in ''|*[!0-9]*) continue ;; esac
    [ "${#suffix}" -le 6 ] && [ "$suffix" -gt 0 ] && [ "$value" = 4 ] || continue
    if [ "$(dbus get "ssconf_basic_trojan_binary_$suffix")" = AnyTLS ]; then
      printf '1' > "$WORK/desired/ssconf_basic_allowinsecure_$suffix"
    fi
  done < "$WORK/node-types"
fi
original_enabled=$(dbus get ss_basic_enable)
case "$original_enabled" in ''|0|1) ;; *) fail 'The installed enable flag is invalid.' ;; esac
payload_kb=$(du -sk "$PAYLOAD" | awk '{print $1}')
backup_kb=0
while IFS= read -r relative; do
  if [ -e "$KS_ROOT/$relative" ] || [ -L "$KS_ROOT/$relative" ]; then
    size=$(du -sk "$KS_ROOT/$relative" | awk '{print $1}')
    backup_kb=$((backup_kb+size))
  fi
done < "$WORK/paths"
runtime_kb=$(du -sk "$RUNTIME_TOOL" | awk '{print $1}')
required_kb=$((payload_kb+backup_kb+runtime_kb+1024))
for volume in "$KS_ROOT" "$JFFS_ROOT"; do
  available_kb=$(df -Pk "$volume" | awk 'NR == 2 {print $4}')
  case "$available_kb" in ''|*[!0-9]*) fail 'Cannot determine available storage.' ;; esac
  [ "$available_kb" -ge "$required_kb" ] || fail 'Insufficient space for the update and private rollback backup.'
done

[ ! -L "$JFFS_ROOT/.r7000-backups" ] || fail 'The backup directory cannot be a symlink.'
mkdir -p "$JFFS_ROOT/.r7000-backups"
chmod 700 "$JFFS_ROOT/.r7000-backups"
BACKUP=$(mktemp -d "$JFFS_ROOT/.r7000-backups/$(date +%Y%m%d-%H%M%S).XXXXXX")
mkdir "$BACKUP/files" "$BACKUP/dbus"
: > "$BACKUP/files.list"
while IFS= read -r relative; do
  destination="$KS_ROOT/$relative"
  mkdir -p "$BACKUP/files/$(dirname "$relative")"
  if [ -L "$destination" ]; then
    readlink "$destination" > "$BACKUP/files/$relative"
    printf '%s|link|0\n' "$relative" >> "$BACKUP/files.list"
  elif [ -f "$destination" ]; then
    mode=$(file_mode "$destination")
    cp -p "$destination" "$BACKUP/files/$relative"
    chmod 600 "$BACKUP/files/$relative"
    printf '%s|file|%s\n' "$relative" "$mode" >> "$BACKUP/files.list"
  elif [ ! -e "$destination" ]; then
    printf '%s|absent|0\n' "$relative" >> "$BACKUP/files.list"
  else fail 'An installed destination is not a regular file or link.'; fi
done < "$WORK/paths"
find "$WORK/desired" -print > "$WORK/desired.entries"
: > "$WORK/desired.keys"
while IFS= read -r entry; do
  [ ! -f "$entry" ] || printf '%s\n' "${entry##*/}" >> "$WORK/desired.keys"
done < "$WORK/desired.entries"
sort "$WORK/desired.keys" > "$BACKUP/dbus.list"
printf '%s\n' ss_basic_enable >> "$BACKUP/dbus.list"
while IFS= read -r key; do
  if dbus_exists "$key"; then
    printf 'present' > "$BACKUP/dbus/$key.kind"
    dbus get "$key" > "$BACKUP/dbus/$key"
  else printf 'absent' > "$BACKUP/dbus/$key.kind"; fi
done < "$BACKUP/dbus.list"
cp "$RUNTIME_TOOL" "$BACKUP/runtime-tool"
cp "$PACKAGE/manifest.md5" "$BACKUP/new-manifest.md5"
cp "$0" "$BACKUP/installer.sh"
cat > "$BACKUP/restore-files.sh" <<'RESTORE'
#!/bin/sh
backup=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
exec /bin/sh "$backup/installer.sh" --restore-files "$backup"
RESTORE
cat > "$BACKUP/RESTORE.txt" <<'README'
This private directory contains previous file bytes/modes and previous values of
only the enhancement settings/TLS flags. Treat the whole directory as private.

After a service stop/start attempt, automatic failure restores files/settings
and sets ss_basic_enable=0. Before touching service runtime it preserves the
original enabled state, because the original process is still running.
It intentionally does not run the old start/stop, which can erase UU rules.
Do not restart the restored old plugin before repairing its unsafe entry point.

For manual file/settings restoration, first use the ENHANCED safe stop and keep
Science disabled. Then run: sh /path/to/this/backup/restore-files.sh
The restore helper does not stop or restart services and always leaves disabled.
UU files/processes and external DNS hooks/conf.add are not payload destinations.
Keep this backup until the enhanced service and PS5/UU coexistence are verified.
README
find "$BACKUP" -print > "$WORK/backup.entries"
while IFS= read -r entry; do
  if [ -f "$entry" ]; then chmod 600 "$entry"
  elif [ -d "$entry" ]; then chmod 700 "$entry"; fi
done < "$WORK/backup.entries"
chmod 700 "$BACKUP/runtime-tool"

# Copy and set modes for the whole payload before replacing any live file.
# Thus space/copy failures do not leave half the safe-stop dependencies live.
mkdir "$WORK/staged"
stage_one() {
  relative=$1
  destination="$KS_ROOT/$relative"
  mkdir -p "$WORK/staged/$(dirname "$relative")"
  temp=$(mktemp "$(dirname "$destination")/.r7000-enhancement.XXXXXX")
  printf '%s' "$temp" > "$WORK/staged/$relative"
  cp "$PAYLOAD/$relative" "$temp"
  case "$relative" in bin/*|scripts/*|ss/ssconfig.sh|ss/cru/*|ss/rules/dnsmasq.postconf) chmod 755 "$temp" ;; *) chmod 644 "$temp" ;; esac
}
commit_one() {
  relative=$1
  temp=$(cat "$WORK/staged/$relative")
  [ ! -e "$temp" ] || mv -f "$temp" "$KS_ROOT/$relative"
}
while IFS= read -r relative; do stage_one "$relative"; done < "$WORK/paths"
MUTATED=1
# Install every dependency before the new safe service entry point; never call
# the original stop, whose global OUTPUT flush would erase UU routing rules.
for relative in bin/ss-flock scripts/ss_routing.sh scripts/ss_dns_hooks.sh scripts/ss_health.sh scripts/ss_anytls.sh ss/ssconfig.sh; do
  commit_one "$relative"
done
if [ "$original_enabled" = 1 ]; then
  STOP_ATTEMPTED=1
  sh "$KS_ROOT/ss/ssconfig.sh" stop >> "$BACKUP/service.log" 2>&1 || fail 'The enhanced safe stop failed.'
fi
while IFS= read -r relative; do commit_one "$relative"; done < "$WORK/paths"
while IFS= read -r key; do
  [ "$key" = ss_basic_enable ] && continue
  dbus set "$key=$(cat "$WORK/desired/$key")" || fail 'Cannot apply an enhancement setting.'
done < "$BACKUP/dbus.list"
if [ "$original_enabled" = 1 ]; then
  dbus set ss_basic_enable=1
  sh "$KS_ROOT/ss/ssconfig.sh" start >> "$BACKUP/service.log" 2>&1 || fail 'The enhanced start failed.'
  [ "$(dbus get ss_basic_enable)" = 1 ] || fail 'The service disabled itself during startup.'
  if [ "$(dbus get ss_basic_type)" = 4 ] && [ "$(dbus get ss_basic_trojan_binary)" = AnyTLS ]; then
    ready=0
    attempt=0
    while [ "$attempt" -lt 5 ]; do
      if pidof anytls >/dev/null 2>&1 && netstat -lnt 2>/dev/null | awk '$1 ~ /^tcp/ && $6 == "LISTEN" {if ($4 ~ /:23456$/) socks=1; if ($4 ~ /:3333$/) nat=1} END {exit !(socks && nat)}'; then ready=1; break; fi
      attempt=$((attempt+1))
      sleep 1
    done
    [ "$ready" = 1 ] || fail 'AnyTLS process or SOCKS/NAT listeners did not become ready.'
  fi
fi
COMMITTED=1
printf 'Enhancement installed; previous enabled state preserved. Private backup: %s\n' "$BACKUP"
