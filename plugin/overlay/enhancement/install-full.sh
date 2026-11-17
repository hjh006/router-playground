#!/bin/sh
# Complete, offline Merlin 380 install. Never invokes the original installer.
set -eu
umask 077
KS_ROOT=/koolshare
JFFS_ROOT=/jffs
RUN_ROOT=/tmp
PATH="$KS_ROOT/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
FULL_FILE_COUNT=@@FULL_FILE_COUNT@@

fail() { printf 'Full installation: %s\n' "$1" >&2; exit 1; }
allowed_path() {
  case "/$1/" in *'/../'*|*'/./'*|*'//'*) return 1 ;; esac
  case "$1" in
    bin/anytls|bin/ss-flock|bin/ss-https-probe|bin/base64_encode|bin/cdns|bin/chinadns|bin/chinadns1|bin/chinadns-ng|bin/client_linux_arm5|bin/dns2socks|bin/dnsmasq|bin/haproxy|bin/haveged|bin/hysteria|bin/httping|bin/https_dns_proxy|bin/jq|bin/koolbox|bin/koolgame|bin/naive|bin/obfs-local|bin/pdu|bin/resolveip|bin/rss-local|bin/rss-redir|bin/smartdns|bin/speederv1|bin/speederv2|bin/ss-local|bin/ss-redir|bin/ss-tunnel|bin/udp2raw|bin/xray) return 0 ;;
    scripts/ss_*.sh|scripts/uninstall_shadowsocks.sh|ss/ssconfig.sh|ss/version|ss/cru/*.sh|ss/rules/*|webs/Main_Ss*.asp|res/layer/*) return 0 ;;
    res/shadowsocks.css|res/ss-menu.js|res/ss-health.js|res/ss-health.css|res/icon-shadowsocks.png|res/ss_proc_status.htm|res/ss_udp_status.htm|res/all.png|res/chn.png|res/game.png|res/gameV2.png|res/gfw.png|res/gfwlist.png) return 0 ;;
    bin/rss-tunnel|bin/base64|bin/shuf|bin/netstat|bin/base64_decode|init.d/S99socks5.sh) return 0 ;;
    *) return 1 ;;
  esac
}
allowed_key() {
  case "$1" in
    ss_basic_enable|ss_basic_mode|ss_basic_allowinsecure|ss_basic_adblock_enable|ss_basic_adblock_domains|ss_basic_adblock_allow|ss_basic_bypass_macs|ss_basic_uu_macs|ss_basic_uu_tcp_policy|ss_basic_uu_interval|ss_basic_failover_enable|ss_basic_failover_country|ss_basic_failover_nodes|ss_basic_failover_countries|ss_basic_failover_failures|ss_basic_failover_recoveries|ss_basic_failover_cooldown|ss_basic_failover_timeout|ss_basic_failover_budget|ss_basic_failover_direct|ss_basic_anytls_min_idle|ss_basic_anytls_idle_check|ss_basic_anytls_idle_timeout|ss_basic_anytls_handshake|ss_basic_anytls_alpn|ss_basic_anytls_fingerprint|ss_basic_anytls_hosts|ss_basic_health_interval|ss_basic_health_timeout|ss_basic_health_failures|ss_basic_rule_update|ss_basic_node_update|ss_basic_server_resolver|ss_basic_server_resolver_user|ss_basic_ss_v2ray_plugin|ss_dns_china|ss_foreign_dns|ss_acl_default_mode|ss_acl_default_port|ss_basic_version_local|ss_basic_install_status|softcenter_module_shadowsocks_install|softcenter_module_shadowsocks_version|softcenter_module_shadowsocks_title|softcenter_module_shadowsocks_description|softcenter_module_shadowsocks_home_url) return 0 ;;
    *) return 1 ;;
  esac
}
mktemp() { "$RUNTIME_TOOL" mktemp "$@"; }
file_mode() { "$RUNTIME_TOOL" mode "$1"; }
dbus_exists() { dbus list "$1" | awk -F= -v key="$1" '$1==key {found=1} END {exit !found}'; }
restore_files() {
  restore_rc=0
  while IFS='|' read -r relative kind mode; do
    allowed_path "$relative" || { restore_rc=1; continue; }
    destination="$KS_ROOT/$relative"
    case "$kind" in
      absent) rm -f "$destination" || restore_rc=1 ;;
      file)
        temp=$(mktemp "$(dirname "$destination")/.r7000-full-restore.XXXXXX") || { restore_rc=1; continue; }
        if cp -p "$BACKUP/files/$relative" "$temp" && chmod "$mode" "$temp" && mv -f "$temp" "$destination"; then :; else rm -f "$temp"; restore_rc=1; fi ;;
      link)
        temp=$(mktemp "$(dirname "$destination")/.r7000-full-restore.XXXXXX") || { restore_rc=1; continue; }
        rm -f "$temp"
        if ln -s "$(cat "$BACKUP/files/$relative")" "$temp" && mv -f "$temp" "$destination"; then :; else rm -f "$temp"; restore_rc=1; fi ;;
      *) restore_rc=1 ;;
    esac
  done < "$BACKUP/files.list"
  while IFS= read -r key; do
    allowed_key "$key" || { restore_rc=1; continue; }
    if [ "$(cat "$BACKUP/dbus/$key.kind")" = present ]; then
      dbus set "$key=$(cat "$BACKUP/dbus/$key")" || restore_rc=1
    else dbus remove "$key" || restore_rc=1; fi
  done < "$BACKUP/dbus.list"
  return "$restore_rc"
}
remove_created_dirs() {
  [ -f "$BACKUP/created-dirs" ] || return 0
  awk '{a[NR]=$0} END {for(i=NR;i>0;i--) print a[i]}' "$BACKUP/created-dirs" |
  while IFS= read -r relative; do rmdir "$KS_ROOT/$relative" 2>/dev/null || :; done
}

[ "$(awk '$1=="Uid:" {print $2;exit}' /proc/self/status)" = 0 ] || fail 'Run this installer as root.'
[ "$(uname -m)" = armv7l ] || fail 'Merlin 380 armv7l is required.'
case "$(uname -r)" in 2.6.36.4*) ;; *) fail 'Linux 2.6.36.4 is required.' ;; esac
case "$(nvram get buildno)" in 380|380.*|380_*) ;; *) fail 'Merlin 380 firmware is required.' ;; esac
firmware=$(nvram get extendno)
case "$firmware" in *X*) firmware=${firmware##*X} ;; *) fail 'Koolshare Merlin X7.2 or newer is required.' ;; esac
printf '%s\n' "$firmware" | awk -F. '$1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && ($1>7 || ($1==7 && $2>=2)) {ok=1} END {exit !ok}' || fail 'Koolshare Merlin X7.2 or newer is required.'
[ -d "$KS_ROOT" ] && [ -d "$JFFS_ROOT" ] || fail 'Koolshare/JFFS directories are missing.'
KS_ROOT=$(CDPATH= cd -P "$KS_ROOT" && pwd) || fail 'Cannot resolve the Koolshare directory.'
for directory in bin scripts webs res init.d; do
  [ -d "$KS_ROOT/$directory" ] && [ ! -L "$KS_ROOT/$directory" ] || fail 'A software-center directory is missing or is a symlink.'
done

if [ "${1:-}" = --restore-files ]; then
  [ "$#" -eq 2 ] || fail 'Invalid restore arguments.'
  BACKUP=$2
  case "$BACKUP" in "$JFFS_ROOT/.r7000-full-backups/"*) ;; *) fail 'Invalid backup location.' ;; esac
  [ -d "$BACKUP" ] && [ ! -L "$BACKUP" ] && [ -f "$BACKUP/files.list" ] && [ -f "$BACKUP/dbus.list" ] || fail 'The backup is incomplete.'
  [ "$(dbus get ss_basic_enable)" != 1 ] || fail 'Stop the enhanced service safely before restoration.'
  RUNTIME_TOOL="$BACKUP/runtime-tool"
  [ -f "$RUNTIME_TOOL" ] && [ ! -L "$RUNTIME_TOOL" ] && [ -x "$RUNTIME_TOOL" ] || fail 'The private restore tool is missing.'
  while IFS='|' read -r relative kind mode; do
    allowed_path "$relative" || fail 'An invalid path is present in the private backup.'
    case "$kind:$mode" in absent:0|link:0) ;; file:*)
      case "$mode" in ''|*[!0-7]*) fail 'An invalid file mode is present in the backup.' ;; esac ;;
      *) fail 'An invalid file record is present in the backup.' ;;
    esac
    [ ! -d "$KS_ROOT/$relative" ] || fail 'A restore destination is a directory.'
    parent=$(dirname "$KS_ROOT/$relative")
    while [ "$parent" != "$KS_ROOT" ]; do
      [ -d "$parent" ] && [ ! -L "$parent" ] || fail 'A restore destination parent is missing or is a symlink.'
      parent=$(dirname "$parent")
    done
  done < "$BACKUP/files.list"
  restore_files || fail 'Restoration was incomplete; keep the backup.'
  remove_created_dirs
  printf 'Full-installation files and settings restored; no services were started.\n'
  exit 0
fi
[ "$#" -eq 0 ] || fail 'This public installer accepts no private settings.'
PACKAGE=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
if [ -f "$KS_ROOT/ss/version" ]; then
  [ "$(cat "$KS_ROOT/ss/version")" = 4.38.3 ] || fail 'An existing plugin must be the supported 4.38.3 baseline.'
  [ -d "$PACKAGE/update" ] && [ ! -L "$PACKAGE/update" ] && [ -f "$PACKAGE/update/install.sh" ] && [ ! -L "$PACKAGE/update/install.sh" ] || fail 'The enhanced update entry point is missing.'
  printf 'Existing 4.38.3 detected; using the enhanced safe updater.\n'
  exec /bin/sh "$PACKAGE/update/install.sh"
fi
# A missing version is not proof that a previous install can be overwritten.
fresh_state_guard() {
  [ ! -e "$KS_ROOT/ss/version" ] && [ ! -L "$KS_ROOT/ss/version" ] || fail 'Plugin state changed; rerun the installer to select the supported update path.'
  [ ! -L "$KS_ROOT/ss" ] || fail 'An existing plugin directory is a symlink.'
  if [ -d "$KS_ROOT/ss" ]; then
    [ -z "$(find "$KS_ROOT/ss" -print | sed '1d')" ] || fail 'Unrecognized plugin files exist; migrate or restore them first.'
  fi
  [ -z "$(find "$KS_ROOT/scripts" -name 'ss_*.sh' -print)" ] || fail 'Unrecognized plugin scripts exist; migrate or restore them first.'
  [ -z "$(find "$KS_ROOT/webs" -name 'Main_Ss*.asp' -print)" ] || fail 'Unrecognized plugin pages exist; migrate or restore them first.'
  [ -z "$(dbus list ssconf_basic_)" ] || fail 'Existing node settings were found; preserve and migrate them first.'
  [ -z "$(dbus get ss_basic_server)$(dbus get ss_basic_password)" ] || fail 'Existing node settings were found; preserve and migrate them first.'
  [ "$(dbus get ss_basic_enable)" != 1 ] || fail 'An unrecognized proxy is enabled.'
  [ -z "$(dbus get softcenter_module_shadowsocks_install)" ] || fail 'An incomplete plugin registration exists.'
}
fresh_state_guard

FILES="$PACKAGE/files"
RUNTIME_TOOL="$FILES/bin/ss-flock"
[ -d "$FILES" ] && [ ! -L "$FILES" ] && [ -f "$PACKAGE/manifest-full.md5" ] && [ ! -L "$PACKAGE/manifest-full.md5" ] || fail 'The full payload or manifest is missing.'
case "$FULL_FILE_COUNT" in ''|*[!0-9]*) fail 'The full manifest count was not set by the builder.' ;; esac
awk -v expected="$FULL_FILE_COUNT" 'NF!=2 || length($1)!=32 || $1 !~ /^[0-9a-fA-F]+$/ || $2 !~ /^[A-Za-z0-9._\/-]+$/ || $2 ~ /(^|\/)\.\.?($|\/)/ || $2 ~ /\/\// || $2 ~ /^\// {exit 1} {if(seen[$2]++) exit 1;count++} END {if(count!=expected || count<10) exit 1}' "$PACKAGE/manifest-full.md5" || fail 'The full manifest format or count is invalid.'
[ -f "$RUNTIME_TOOL" ] && [ ! -L "$RUNTIME_TOOL" ] && [ -x "$RUNTIME_TOOL" ] || fail 'The private runtime helper is missing.'
WORK=$(mktemp -d "$RUN_ROOT/r7000-full.XXXXXX") || fail 'Cannot allocate private work space.'
LOCK="$RUN_ROOT/r7000-enhancement.lock"
BACKUP=
MUTATED=0
COMMITTED=0
LOCKED=0
finish() {
  result=$?
  trap - 0 HUP INT TERM
  set +e
  if [ "$MUTATED" = 1 ] && [ "$COMMITTED" != 1 ]; then
    if restore_files; then printf 'Full installation failed; previous files/settings restored. Backup: %s\n' "$BACKUP" >&2
    else printf 'Full installation failed; recovery incomplete. Keep backup: %s\n' "$BACKUP" >&2; fi
    [ "$result" -ne 0 ] || result=1
  fi
  if [ -d "$WORK/staged" ]; then
    find "$WORK/staged" -print > "$WORK/staged.entries"
    while IFS= read -r entry; do [ ! -f "$entry" ] || rm -f "$(cat "$entry")"; done < "$WORK/staged.entries"
  fi
  if [ -n "$BACKUP" ] && [ "$COMMITTED" != 1 ]; then remove_created_dirs; fi
  rm -rf "$WORK"
  [ "$LOCKED" = 0 ] || rmdir "$LOCK" 2>/dev/null
  exit "$result"
}
trap finish 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$LOCK" 2>/dev/null || fail 'Another installer is active.'
LOCKED=1
fresh_state_guard
awk '{print $2}' "$PACKAGE/manifest-full.md5" | sort > "$WORK/paths"
find "$FILES" -print > "$WORK/payload.entries"
: > "$WORK/actual.unsorted"
while IFS= read -r path; do
  [ ! -L "$path" ] || fail 'Payload links are not accepted.'
  if [ -f "$path" ]; then printf '%s\n' "${path#"$FILES/"}" >> "$WORK/actual.unsorted"
  elif [ -d "$path" ]; then :; else fail 'Payload special files are not accepted.'; fi
done < "$WORK/payload.entries"
sort "$WORK/actual.unsorted" > "$WORK/actual"
cmp -s "$WORK/paths" "$WORK/actual" || fail 'Full payload and manifest file sets differ.'
while IFS= read -r relative; do
  allowed_path "$relative" || fail 'A full payload path is outside the plugin allowlist.'
  case "$relative" in bin/rss-tunnel|bin/base64|bin/shuf|bin/netstat|bin/base64_decode|init.d/S99socks5.sh|scripts/ss_install.sh) fail 'The full payload contains a reserved generated path.' ;; esac
done < "$WORK/paths"
for required in bin/anytls bin/ss-flock bin/ss-https-probe bin/koolbox bin/base64_encode bin/rss-local scripts/ss_socks5.sh scripts/ss_failover.sh scripts/ss_adblock.sh scripts/uninstall_shadowsocks.sh ss/version ss/ssconfig.sh webs/Main_Ss_Content.asp; do
  grep -Fqx "$required" "$WORK/paths" || fail 'A required full payload file is missing.'
done
[ "$(cat "$FILES/ss/version")" = 4.38.3 ] || fail 'The full payload is not the supported baseline.'
(cd "$FILES" && md5sum -c "$PACKAGE/manifest-full.md5") > "$WORK/checksums.log" 2>&1 || fail 'Full payload checksum verification failed.'
while IFS= read -r relative; do
  case "$relative" in scripts/*.sh|ss/ssconfig.sh|ss/cru/*.sh|ss/rules/dnsmasq.postconf) sh -n "$FILES/$relative" || fail 'A full payload shell script has invalid syntax.' ;; esac
done < "$WORK/paths"
"$FILES/bin/anytls" -version > "$WORK/client-version" 2>&1 || fail 'The enhanced client cannot run on this router.'
grep -q -- '-r7000\.' "$WORK/client-version" || fail 'The full payload client is not the enhanced build.'
"$FILES/bin/ss-https-probe" -h > "$WORK/probe-help" 2>&1 || fail 'The full payload HTTPS probe cannot run on this router.'
(
  exec 9>"$WORK/flock-test"
  "$RUNTIME_TOOL" -n 9 || exit 1
  (exec 8>"$WORK/flock-test"; ! "$RUNTIME_TOOL" -n 8) || exit 1
  "$RUNTIME_TOOL" -u 9 || exit 1
  (exec 8>"$WORK/flock-test"; "$RUNTIME_TOOL" -n 8)
) || fail 'Inherited descriptor locking is unavailable.'
cat > "$WORK/links" <<'LINKS'
bin/rss-tunnel|rss-local
bin/base64|koolbox
bin/shuf|koolbox
bin/netstat|koolbox
bin/base64_decode|base64_encode
init.d/S99socks5.sh|../scripts/ss_socks5.sh
LINKS
cp "$WORK/paths" "$WORK/destinations.unsorted"
while IFS='|' read -r relative target; do printf '%s\n' "$relative" >> "$WORK/destinations.unsorted"; done < "$WORK/links"
sort "$WORK/destinations.unsorted" > "$WORK/destinations"
backup_kb=0
while IFS= read -r relative; do
  destination="$KS_ROOT/$relative"
  [ ! -d "$destination" ] || fail 'A destination is a directory or a link to a directory.'
  parent=$(dirname "$destination")
  while [ "$parent" != "$KS_ROOT" ]; do
    [ ! -L "$parent" ] || fail 'A destination parent is a symlink.'
    if [ -e "$parent" ]; then [ -d "$parent" ] || fail 'A destination parent is not a directory.'; fi
    parent=$(dirname "$parent")
  done
  if [ -L "$destination" ]; then
    target=$(readlink "$destination")
    [ -n "$target" ] && [ "$(printf '%s' "$target" | wc -l)" -eq 0 ] || fail 'A destination link cannot be backed up exactly.'
  elif [ -e "$destination" ]; then
    [ -f "$destination" ] || fail 'A destination is not a regular file or link.'
    size=$(du -sk "$destination" | awk '{print $1}')
    backup_kb=$((backup_kb+size))
  fi
done < "$WORK/destinations"
payload_kb=$(du -sk "$FILES" | awk '{print $1}')
runtime_kb=$(du -sk "$RUNTIME_TOOL" | awk '{print $1}')
required_kb=$((payload_kb+backup_kb+runtime_kb+2048))
for volume in "$KS_ROOT" "$JFFS_ROOT"; do
  available=$(df -Pk "$volume" | awk 'NR==2 {print $4}')
  case "$available" in ''|*[!0-9]*) fail 'Cannot determine free storage.' ;; esac
  [ "$available" -ge "$required_kb" ] || fail 'Insufficient storage for full files and private rollback backup.'
done
[ ! -L "$JFFS_ROOT/.r7000-full-backups" ] || fail 'The private backup parent is a symlink.'
mkdir -p "$JFFS_ROOT/.r7000-full-backups"
chmod 700 "$JFFS_ROOT/.r7000-full-backups"
BACKUP=$(mktemp -d "$JFFS_ROOT/.r7000-full-backups/$(date +%Y%m%d-%H%M%S).XXXXXX")
mkdir "$BACKUP/files" "$BACKUP/dbus"
: > "$BACKUP/files.list"
: > "$BACKUP/created-dirs"
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
  else printf '%s|absent|0\n' "$relative" >> "$BACKUP/files.list"; fi
done < "$WORK/destinations"
cat > "$WORK/defaults" <<'DEFAULTS'
ss_basic_adblock_enable=0
ss_basic_adblock_domains=
ss_basic_adblock_allow=
ss_basic_enable=0
ss_basic_mode=1
ss_basic_allowinsecure=0
ss_basic_bypass_macs=
ss_basic_uu_macs=
ss_basic_uu_tcp_policy=gfwlist
ss_basic_uu_interval=5
ss_basic_failover_enable=0
ss_basic_failover_country=auto
ss_basic_failover_nodes=
ss_basic_failover_countries=
ss_basic_failover_failures=3
ss_basic_failover_recoveries=2
ss_basic_failover_cooldown=120
ss_basic_failover_timeout=5
ss_basic_failover_budget=60
ss_basic_failover_direct=1
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
ss_basic_rule_update=0
ss_basic_node_update=0
ss_basic_server_resolver=1
ss_basic_server_resolver_user=
ss_basic_ss_v2ray_plugin=0
ss_dns_china=11
ss_foreign_dns=3
ss_acl_default_mode=1
ss_acl_default_port=all
ss_basic_version_local=4.38.3
ss_basic_install_status=0
softcenter_module_shadowsocks_install=4
softcenter_module_shadowsocks_version=4.38.3
softcenter_module_shadowsocks_title=科学上网
softcenter_module_shadowsocks_description=科学上网 R7000 增强 r5 for Merlin 380
softcenter_module_shadowsocks_home_url=Main_Ss_Content.asp
DEFAULTS
# Exercise the same pure schema validator used by service starts; no runtime is
# created, no service is started, and only the fixed proposed defaults are read.
(
  trap - 0 HUP INT TERM
  dbus() {
    [ "${1:-}" = get ] || return 1
    awk -F= -v key="${2:-}" '$1==key {print substr($0,length($1)+2);found=1;exit} END {if(!found)exit 1}' "$WORK/defaults"
  }
  set -- validate
  . "$FILES/scripts/ss_routing.sh"
  ss_routing_load_bypass_macs || exit 1
  . "$FILES/scripts/ss_failover.sh"
) || fail 'The full payload routing/failover defaults are invalid.'
(
  trap - 0 HUP INT TERM
  dbus() {
    [ "${1:-}" = get ] || return 1
    awk -F= -v key="${2:-}" '$1==key {print substr($0,length($1)+2);found=1;exit} END {if(!found)exit 1}' "$WORK/defaults"
  }
  SS_ADBLOCK_LIBRARY=0
  set -- validate
  . "$FILES/scripts/ss_adblock.sh"
) || fail 'The full payload ad-domain defaults are invalid.'
: > "$BACKUP/dbus.list"
while IFS='=' read -r key value; do
  allowed_key "$key" || fail 'An internal settings key is invalid.'
  printf '%s\n' "$key" >> "$BACKUP/dbus.list"
  if dbus_exists "$key"; then
    printf present > "$BACKUP/dbus/$key.kind"
    dbus get "$key" > "$BACKUP/dbus/$key"
  else printf absent > "$BACKUP/dbus/$key.kind"; fi
done < "$WORK/defaults"
cp "$RUNTIME_TOOL" "$BACKUP/runtime-tool"
chmod 700 "$BACKUP/runtime-tool"
cp "$0" "$BACKUP/installer.sh"
chmod 600 "$BACKUP/installer.sh"
cat > "$BACKUP/restore-files.sh" <<'RESTORE'
#!/bin/sh
backup=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
exec /bin/sh "$backup/installer.sh" --restore-files "$backup"
RESTORE
cat > "$BACKUP/RESTORE.txt" <<'RESTORE'
This directory is private. It contains original shared file bytes/link targets,
modes and the existence/value of only settings changed by this fresh install.
The fresh installer does not stop/start a service or modify UU/DNS hooks.
To restore, safely stop the enhanced proxy and keep it disabled, then run:
  sh /path/to/this/backup/restore-files.sh
The restore entry never starts/stops old services. Keep unrelated UU/DNS state.
RESTORE
find "$BACKUP" -print > "$WORK/backup.entries"
while IFS= read -r entry; do
  if [ -d "$entry" ]; then chmod 700 "$entry"
  elif [ -f "$entry" ] && [ "$entry" != "$BACKUP/runtime-tool" ]; then chmod 600 "$entry"; fi
done < "$WORK/backup.entries"
# Build parents without following links and remember only directories we create.
ensure_parent() {
  parent_relative=$1
  current="$KS_ROOT"
  prefix=
  old_ifs=$IFS
  IFS=/
  set -- $parent_relative
  IFS=$old_ifs
  for part do
    current="$current/$part"
    if [ -z "$prefix" ]; then prefix=$part; else prefix="$prefix/$part"; fi
    [ ! -L "$current" ] || fail 'A destination parent became a symlink.'
    if [ ! -d "$current" ]; then
      mkdir "$current"
      chmod 755 "$current"
      printf '%s\n' "$prefix" >> "$BACKUP/created-dirs"
    fi
  done
}
mkdir "$WORK/staged"
while IFS= read -r relative; do
  ensure_parent "$(dirname "$relative")"
  mkdir -p "$WORK/staged/$(dirname "$relative")"
  destination="$KS_ROOT/$relative"
  temp=$(mktemp "$(dirname "$destination")/.r7000-full-stage.XXXXXX")
  printf '%s' "$temp" > "$WORK/staged/$relative"
  if grep -Fqx "$relative" "$WORK/paths"; then
    cp "$FILES/$relative" "$temp"
    case "$relative" in bin/*|scripts/*|ss/ssconfig.sh|ss/cru/*|ss/rules/dnsmasq.postconf) chmod 755 "$temp" ;; *) chmod 644 "$temp" ;; esac
  else
    target=$(awk -F'|' -v key="$relative" '$1==key {print $2}' "$WORK/links")
    rm -f "$temp"
    ln -s "$target" "$temp"
  fi
done < "$WORK/destinations"
MUTATED=1
while IFS= read -r relative; do
  temp=$(cat "$WORK/staged/$relative")
  # Existing common executable tools are valid platform choices, not ours to relink.
  case "$relative" in bin/base64|bin/shuf|bin/netstat)
    if [ -x "$KS_ROOT/$relative" ]; then rm -f "$temp"; continue; fi ;;
  esac
  mv -f "$temp" "$KS_ROOT/$relative"
done < "$WORK/destinations"
while IFS='=' read -r key value; do dbus set "$key=$value" || fail 'Cannot register a full-installation setting.'; done < "$WORK/defaults"
COMMITTED=1
printf 'Full installation completed (proxy disabled). Configure your own node before enabling. Private backup: %s\n' "$BACKUP"
