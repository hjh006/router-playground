#!/bin/sh
# Optional LAN DNS filtering. No downloaded lists, query logs, global DNS edits,
# IPv6 rules, or changes to UU/device VPNs. All runtime files are private RAM.
KS_ROOT=/koolshare
STATE_DIR=/tmp/ss_adblock
RULE_DIR=/tmp/ss_adblock_dns-rules
LOCK_FILE=/var/lock/ss-adblock.lock
PASSWD_FILE=/etc/passwd
GROUP_FILE=/etc/group
PUBLIC_JSON=/tmp/ss_adblock.json
PROC_ROOT=/proc
PORT=530
MAX_HISTORY=2048
MAX_RELOADS=64
CHAIN=SS_ADBLOCK
SELF=$0
PATH="$KS_ROOT/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
umask 077
FLOCK="$KS_ROOT/bin/ss-flock"
LOCKED=0
WEB_LOCKED=0

protected_domains() {
  printf '%s\n' youtube.com youtube-nocookie.com youtu.be googlevideo.com ytimg.com ggpht.com googleapis.com gvt1.com gvt2.com gstatic.com google.com doubleclick.net googlesyndication.com googleadservices.com googletagservices.com google-analytics.com googletagmanager.com playstation.com playstation.net sonyentertainmentnetwork.com sony.com sony.net 163.com 126.net netease.com uux.cn localhost local localdomain lan home home.arpa router.asus.com asusrouter.com routerlogin.net routerlogin.com
}
bundled_domains() {
  # A small original selection of advertising networks, not a copied filter
  # subscription. Users can exempt any domain or disable the feature entirely.
  printf '%s\n' adnxs.com adsrvr.org advertising.com adtechus.com adtech.de pubmatic.com rubiconproject.com openx.net openx.com criteo.com criteo.net casalemedia.com indexww.com contextweb.com bidswitch.net bidr.io lijit.com sovrn.com sharethrough.com smartadserver.com taboola.com outbrain.com revcontent.com mgid.com adform.net adform.com media.net yieldmo.com yieldlab.net yieldlove.com gumgum.com teads.tv
}
normalize_encoded() {
  # Decode and validate in one awk process: shell command substitution must
  # never be allowed to silently discard an encoded NUL/control byte.
  printf '%s\n' "$1" | LC_ALL=C awk -v mode="$2" -v protected="$(protected_domains | tr '\n' ' ')" '
    function byte(n) {if(++bytes>8192 || (n<32 && n!=9 && n!=10 && n!=13) || n>126){bad=1;return} text=text sprintf("%c",n)}
    function suffix(a,b){return a==b || (length(a)>length(b) && substr(a,length(a)-length(b),1)=="." && substr(a,length(a)-length(b)+1)==b)}
    BEGIN{alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";np=split(protected,p," ")}
    NR!=1{bad=1}
    NR==1{
      if(length($0)>10924 || length($0)%4 || $0~/[^A-Za-z0-9+\/=]/){bad=1;next}
      for(i=1;i<=length($0);i+=4){
        x=substr($0,i,4);a=index(alphabet,substr(x,1,1))-1;b=index(alphabet,substr(x,2,1))-1;c=index(alphabet,substr(x,3,1))-1;d=index(alphabet,substr(x,4,1))-1
        if(a<0||b<0){bad=1;break}byte(a*4+int(b/16))
        if(substr(x,3,1)=="="){if(substr(x,4,1)!="="||i+3!=length($0)||b%16)bad=1;break}
        if(c<0){bad=1;break}byte((b%16)*16+int(c/4))
        if(substr(x,4,1)=="="){if(i+3!=length($0)||c%4)bad=1;break}
        if(d<0){bad=1;break}byte((c%4)*64+d)
      }
    }
    END{
      if(NR!=1||bad)exit 1
      lines=split(text,row,"\n")
      for(i=1;i<=lines;i++){
        domain=row[i];sub(/\r$/,"",domain);gsub(/^[ \t]+|[ \t]+$/,"",domain);if(domain=="")continue
        if(++count>256 || length(domain)>253 || domain!~/^[A-Za-z0-9.-]+$/){bad=1;break}
        domain=tolower(domain);n=split(domain,label,".");if(n<2||label[n]!~/[a-z]/){bad=1;break}
        for(j=1;j<=n;j++)if(length(label[j])<1||length(label[j])>63||label[j]~/^-/||label[j]~/-$/)bad=1
        if(mode=="block")for(j=1;j<=np;j++)if(suffix(domain,p[j])||suffix(p[j],domain))bad=1
        if(bad)break
        if(!seen[domain]++)out[++total]=domain
      }
      if(bad)exit 1
      for(i=1;i<=total;i++)print out[i]
    }'
}
settings() {
  ENABLED=$(dbus get ss_basic_adblock_enable 2>/dev/null);[ -n "$ENABLED" ] || ENABLED=0
  case "$ENABLED" in 0|1) ;; *) ENABLED=0;return 1 ;; esac
  EXTRAS=$(normalize_encoded "$(dbus get ss_basic_adblock_domains 2>/dev/null)" block) || return 1
  ALLOWS=$(normalize_encoded "$(dbus get ss_basic_adblock_allow 2>/dev/null)" allow) || return 1
}
compile_domains() {
  { bundled_domains; printf '%s\n' "$EXTRAS"; } | LC_ALL=C awk -v allows="$(printf '%s\n' "$ALLOWS" | tr '\n' ' ')" '
    function suffix(a,b){return a==b || (length(a)>length(b)&&substr(a,length(a)-length(b),1)=="."&&substr(a,length(a)-length(b)+1)==b)}
    BEGIN{n=split(allows,a," ")} NF{for(i=1;i<=n;i++)if(a[i]!=""&&suffix($0,a[i]))next;if(!seen[$0]++)print}'
}
core_active() {
  [ "$(dbus get ss_basic_enable)" = 1 ] && [ "$(cat /tmp/ss_failover/mode 2>/dev/null)" = proxy ]
}
valid_lan_ip() {
  printf '%s\n' "$1" | awk -F. 'NF!=4{exit 1}{for(i=1;i<=4;i++)if($i!~/^[0-9]+$/||length($i)>3||(length($i)>1&&substr($i,1,1)=="0")||$i+0>255)exit 1;if($1==0||$1==127||$1>=224)exit 1}'
}
geometry() {
  LAN_IP=$(nvram get lan_ipaddr);LAN_IF=$(nvram get lan_ifname);[ -n "$LAN_IF" ] || LAN_IF=br0
  case "$LAN_IF" in ''|*[!A-Za-z0-9_.:-]*) return 1 ;; esac
  [ "${#LAN_IF}" -le 15 ] && valid_lan_ip "$LAN_IP"
}
root_owned() { [ ! -L "$1" ] && LC_ALL=C ls -nd "$1" 2>/dev/null | awk -v mode="${2:-}" 'NR==1&&$3==0&&(mode==""||substr($1,1,10)==mode){ok=1}END{exit !ok}'; }
safe_state() {
  [ ! -L "$STATE_DIR" ] || return 1
  if [ -e "$STATE_DIR" ];then [ -d "$STATE_DIR" ] && root_owned "$STATE_DIR" drwx------ || return 1;fi
  local name
  for name in ss-adblock-flock ss-adblock-dns keeper.sh;do
    [ ! -e "$STATE_DIR/$name" ] && [ ! -L "$STATE_DIR/$name" ] && continue
    [ -f "$STATE_DIR/$name" ] && root_owned "$STATE_DIR/$name" -rwx------ || return 1
  done
}
select_flock() {
  safe_state || return 1
  if [ "$SELF" = "$STATE_DIR/keeper.sh" ] && [ -x "$STATE_DIR/ss-adblock-flock" ];then FLOCK="$STATE_DIR/ss-adblock-flock"
  elif [ -x "$KS_ROOT/bin/ss-flock" ];then FLOCK="$KS_ROOT/bin/ss-flock"
  else FLOCK="$STATE_DIR/ss-adblock-flock";fi
  [ -x "$FLOCK" ]
}
init_state() {
  select_flock || return 1
  [ ! -L "$LOCK_FILE" ] || return 1
  if [ ! -e "$LOCK_FILE" ];then (umask 077;set -C;: > "$LOCK_FILE") 2>/dev/null || [ -f "$LOCK_FILE" ] || return 1;fi
  [ -f "$LOCK_FILE" ] && root_owned "$LOCK_FILE" -rw------- || return 1
  exec 5>"$LOCK_FILE";"$FLOCK" -x 5 || return 1;LOCKED=1
  safe_state && mkdir -p "$STATE_DIR" && root_owned "$STATE_DIR" && chmod 700 "$STATE_DIR" || return 1
  for name in lock owner current current.new mode intent resume retire drain.lock keeper.sh ss-adblock-dns ss-adblock-flock;do [ ! -L "$STATE_DIR/$name" ] || return 1;done
  trap finish EXIT;trap 'exit 129' HUP;trap 'exit 130' INT;trap 'exit 143' TERM
}
finish() {
  local rc=$?
  trap - EXIT HUP INT TERM
  [ "$LOCKED" != 1 ] || "$FLOCK" -u 5 >/dev/null 2>&1
  [ "$WEB_LOCKED" != 1 ] || "$FLOCK" -u 7 >/dev/null 2>&1
  exec 5>&- 7>&-
  exit "$rc"
}
private_read() { [ -f "$STATE_DIR/$1" ] && [ ! -L "$STATE_DIR/$1" ] && cat "$STATE_DIR/$1"; }
current_generation() { private_read current; }
generation_valid() { case "$1" in generation.*) ;; *)return 1;;esac;case "$1" in *[!A-Za-z0-9._-]*|*..*)return 1;;esac;[ "${#1}" -le 64 ]; }
status_link() {
  local link="$KS_ROOT/res/ss-adblock-status.js"
  [ ! -L "$PUBLIC_JSON" ] && { [ ! -e "$PUBLIC_JSON" ] || [ -f "$PUBLIC_JSON" ]; } || return 1
  [ -d "$KS_ROOT/res" ] && [ ! -L "$KS_ROOT/res" ] || return 1
  if [ ! -e "$link" ] && [ ! -L "$link" ];then ln -s "$PUBLIC_JSON" "$link" 2>/dev/null || return 1;fi
  [ -L "$link" ] && [ "$(readlink "$link")" = "$PUBLIC_JSON" ]
}
publish() {
  local state=$1 running=$2 message=$3 domains=${4:-0} excluded=${5:-0} pins=${6:-null} tmp mode
  [ "$(private_read uninstalled)" != 1 ] || return 0
  status_link || return 1
  mode=$(private_read mode);[ "$mode" = filter ] || mode=passthrough
  tmp=$("$FLOCK" mktemp "$STATE_DIR/status.XXXXXX") || return 1
  printf '{"version":1,"enabled":%s,"state":"%s","running":%s,"domains":%s,"excluded_devices":%s,"message":"%s","mode":"%s","pending_flows":%s}\n' \
    "$([ "${ENABLED:-0}" = 1 ] && printf true || printf false)" "$state" "$running" "$domains" "$excluded" "$message" "$mode" "$pins" > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$PUBLIC_JSON"
}
process_matches() {
  local generation=$1 pid=$2 token=$3 comm exe now
  case "$pid:$token" in *[!0-9:]*|:|*:)return 1;;esac
  [ -n "$pid" ] && [ -n "$token" ] || return 1
  comm=$(cat "$PROC_ROOT/$pid/comm" 2>/dev/null) || comm=$(awk '{sub(/^\(/,"",$2);sub(/\)$/, "",$2);print $2}' "$PROC_ROOT/$pid/stat" 2>/dev/null)
  [ "$comm" = ss-adblock-dns ] || return 1
  exe=$(readlink "$PROC_ROOT/$pid/exe" 2>/dev/null) || exe=
  [ -z "$exe" ] || [ "$exe" = "$STATE_DIR/ss-adblock-dns" ] || return 1
  now=$(awk '{print $22}' "$PROC_ROOT/$pid/stat" 2>/dev/null);[ "$now" = "$token" ] || return 1
  tr '\000' '\n' < "$PROC_ROOT/$pid/cmdline" 2>/dev/null | awk -v exe="$STATE_DIR/ss-adblock-dns" -v conf="--conf-file=$STATE_DIR/$generation/dns.conf" 'NR==1&&$0==exe{a=1}$0=="--keep-in-foreground"{b=1}$0==conf{c=1}END{exit !(a&&b&&c&&NR==3)}' || return 1
  kill -0 "$pid" 2>/dev/null
}
identity() {
  local generation=$1 pid token
  generation_valid "$generation" && [ -f "$STATE_DIR/$generation/identity" ] && [ ! -L "$STATE_DIR/$generation/identity" ] || return 1
  read -r pid token < "$STATE_DIR/$generation/identity"
  process_matches "$generation" "$pid" "$token" || return 1
  CHILD_PID=$pid
}
listeners() {
  local pid=$1 ip=$2 rows
  rows=$(netstat -lnptu 2>/dev/null) || rows=$(netstat -ln 2>/dev/null) || return 1
  printf '%s\n' "$rows" | awk -v pid="$pid" -v ip="$ip" -v port="$PORT" '
    $1~/^(tcp|udp)$/&&($4=="127.0.0.1:"port||$4==ip":"port){if($1=="tcp"&&$6!="LISTEN")next;if($NF~/^[0-9]+\//){split($NF,o,"/");if(o[1]!=pid)bad=1}if($4=="127.0.0.1:"port)lo[$1]=1;if($4==ip":"port)lan[$1]=1}END{exit !(lo["tcp"]&&lo["udp"]&&lan["tcp"]&&lan["udp"]&&!bad)}'
}
port_free() { netstat -lnptu 2>/dev/null | awk -v port="$PORT" '$1~/^(tcp|udp)$/&&$4~(":"port"$"){busy=1}END{exit busy}'; }
flow_count() {
  local ip=$1 source
  valid_lan_ip "$ip" || return 1
  if [ -r "$PROC_ROOT/net/nf_conntrack" ];then source="$PROC_ROOT/net/nf_conntrack"
  elif [ -r "$PROC_ROOT/net/ip_conntrack" ];then source="$PROC_ROOT/net/ip_conntrack";else return 1;fi
  LC_ALL=C awk -v ip="$ip" -v port="$PORT" '
    {bytes+=length($0)+1;if(NR>65536||bytes>8388608){bad=1;exit}proto=($1=="ipv4"?$3:$1);if($1=="ipv6"||(proto!="udp"&&proto!="tcp"))next
    ns=nd=nsp=ndp=0;for(i=1;i<=NF;i++){if($i~/^src=/)src[++ns]=substr($i,5);if($i~/^dst=/)dst[++nd]=substr($i,5);if($i~/^sport=/)sp[++nsp]=substr($i,7);if($i~/^dport=/)dp[++ndp]=substr($i,7)}
    if(ns!=2||nd!=2||nsp!=2||ndp!=2){bad=1;next}if(dp[1]==53&&src[2]==ip&&sp[2]==port)count++}
    END{if(bad)exit 1;print count+0}' "$source"
}
pins_for() { local ip;ip=$(cat "$STATE_DIR/$1/lan-ip" 2>/dev/null) || return 1;flow_count "$ip"; }
close_tcp_workers() {
  local generation=$1 master start pgid sid stat pid token parent group session current
  [ -f "$STATE_DIR/$generation/ancestry" ] || return 1
  read -r master start pgid sid < "$STATE_DIR/$generation/ancestry"
  case "$master:$start:$pgid:$sid" in *[!0-9:]*|'')return 1;;esac
  : > "$STATE_DIR/$generation/workers.snapshot"
  for stat in "$PROC_ROOT"/[0-9]*/stat;do
    [ -f "$stat" ] || continue
    current=$(awk '$2=="(ss-adblock-dns)"{print $1,$4,$5,$6,$22}' "$stat")
    [ -n "$current" ] || continue
    read -r pid parent group session token <<WORKER
$current
WORKER
    [ "$pid" != "$master" ] && [ "$token" -ge "$start" ] || continue
    if [ "$parent" = "$master" ] || { ! identity "$generation" && [ "$parent" = 1 ] && [ "$group:$session" = "$pgid:$sid" ]; };then
      process_matches "$generation" "$pid" "$token" || continue
      printf '%s %s\n' "$pid" "$token" >> "$STATE_DIR/$generation/workers.snapshot"
    fi
  done
  while read -r pid token;do
    [ -n "$pid" ] || continue
    process_matches "$generation" "$pid" "$token" && kill "$pid" 2>/dev/null || true
  done < "$STATE_DIR/$generation/workers.snapshot"
  if [ -s "$STATE_DIR/$generation/workers.snapshot" ];then
    sleep 1 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
    while read -r pid token;do
      process_matches "$generation" "$pid" "$token" && kill -KILL "$pid" 2>/dev/null || true
    done < "$STATE_DIR/$generation/workers.snapshot"
  fi
}
owned_chain() { [ "$(private_read owner)" = ss-adblock-v1 ]; }
remove_hooks() {
  owned_chain || return 0
  iptables -t nat -S PREROUTING 2>/dev/null | while IFS= read -r rule;do
    case "$rule" in '-A PREROUTING '*) ;; *)continue;;esac
    [ "${rule##* }" = "$CHAIN" ] || continue
    set -f;set -- $rule;shift 2;iptables -t nat -D PREROUTING "$@" >/dev/null 2>&1
  done
}
detach() {
  local n rules
  owned_chain || return 0
  for n in 1 2 3;do
    remove_hooks;iptables -t nat -F "$CHAIN" >/dev/null 2>&1 || true;iptables -t nat -X "$CHAIN" >/dev/null 2>&1 || true
    rules=$(iptables -t nat -S PREROUTING 2>/dev/null) || return 1
    if ! printf '%s\n' "$rules" | awk -v chain="$CHAIN" '$1=="-A"&&$NF==chain{found=1}END{exit !found}';then return 0;fi
    sleep 1 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
  done;return 1
}
prepare_private() {
  local uid gid group tmp
  uid=$(awk -F: '$1=="nobody"{print $3;exit}' "$PASSWD_FILE");gid=$(awk -F: '$1=="nobody"{print $4;exit}' "$PASSWD_FILE")
  case "$uid:$gid" in *[!0-9:]*|:|*:)return 1;;esac;[ "$uid" -gt 0 ] || return 1
  group=$(awk -F: -v gid="$gid" '$3==gid{print $1;exit}' "$GROUP_FILE")
  case "$group" in ''|*[!A-Za-z0-9_-]*)return 1;;esac
  DNS_GROUP=$group;DNS_GID=$gid
  [ ! -L "$RULE_DIR" ] || return 1
  if [ -e "$RULE_DIR" ];then [ -d "$RULE_DIR" ] && root_owned "$RULE_DIR" drwx--x--- || return 1;fi
  mkdir -p "$RULE_DIR" && chown "0:$gid" "$RULE_DIR" && chmod 710 "$RULE_DIR" || return 1
  [ ! -L "$RULE_DIR/servers" ] || return 1
  if [ -e "$RULE_DIR/servers" ];then [ -f "$RULE_DIR/servers" ] && root_owned "$RULE_DIR/servers" || return 1
  else : > "$RULE_DIR/servers";fi
  chown "0:$gid" "$RULE_DIR/servers" && chmod 640 "$RULE_DIR/servers" || return 1
  for tmp in keeper.sh ss-adblock-flock ss-adblock-dns;do [ ! -L "$STATE_DIR/$tmp" ] && [ ! -L "$STATE_DIR/$tmp.new" ] || return 1;done
  if [ ! -x "$STATE_DIR/ss-adblock-flock" ];then cp "$FLOCK" "$STATE_DIR/ss-adblock-flock.new" && chmod 700 "$STATE_DIR/ss-adblock-flock.new" && mv -f "$STATE_DIR/ss-adblock-flock.new" "$STATE_DIR/ss-adblock-flock" || return 1;fi
  FLOCK="$STATE_DIR/ss-adblock-flock"
  [ "$SELF" = "$STATE_DIR/keeper.sh" ] || { cp "$SELF" "$STATE_DIR/keeper.sh.new" && chmod 700 "$STATE_DIR/keeper.sh.new" && mv -f "$STATE_DIR/keeper.sh.new" "$STATE_DIR/keeper.sh"; } || return 1
  if [ ! -x "$STATE_DIR/ss-adblock-dns" ];then cp "$KS_ROOT/bin/dnsmasq" "$STATE_DIR/ss-adblock-dns.new" && chmod 700 "$STATE_DIR/ss-adblock-dns.new" && mv -f "$STATE_DIR/ss-adblock-dns.new" "$STATE_DIR/ss-adblock-dns" || return 1;fi
  printf '%s\n' "$gid" > "$STATE_DIR/rules-gid"
}
config() {
  local directory=$1
  printf '%s\n' "port=$PORT" "listen-address=127.0.0.1,$LAN_IP" bind-interfaces no-resolv no-poll no-hosts cache-size=0 user=nobody "group=$DNS_GROUP" "pid-file=$directory/dns.pid" "log-facility=$directory/dns.log" 'server=127.0.0.1#53' "servers-file=$RULE_DIR/servers"
}
render_rules() {
  local mode=$1 history=$2
  # This vendor binary can retain local and more-specific forwarding entries
  # across HUP. Every former block or allow name needs an explicit current
  # decision, including a removed allow below a still-blocked parent.
  awk -v mode="$mode" -v blocks="$(printf '%s\n' "${DOMAINS:-}" | tr '\n' ' ')" -v allows="$(printf '%s\n' "${ALLOWS:-}" | tr '\n' ' ')" '
    function suffix(a,b){return a==b||(length(a)>length(b)&&substr(a,length(a)-length(b),1)=="."&&substr(a,length(a)-length(b)+1)==b)}
    BEGIN{nb=split(blocks,b," ");na=split(allows,a," ")}
    NF{block=0;if(mode=="filter"){for(i=1;i<=nb;i++)if(b[i]!=""&&suffix($0,b[i]))block=1;for(i=1;i<=na;i++)if(a[i]!=""&&suffix($0,a[i]))block=0}
    printf "server=/%s/%s\n",$0,(block?"":"127.0.0.1#53");seen[$0]=1}
    END{if(mode=="filter")for(i=1;i<=na;i++)if(a[i]!=""&&!seen[a[i]]++)printf "server=/%s/127.0.0.1#53\n",a[i]}' "$history"
}
replace_rules() {
  local generation=$1 mode=$2 offline=${3:-0} directory candidate gid count reloads
  directory="$STATE_DIR/$generation";candidate=$("$FLOCK" mktemp "$RULE_DIR/.servers.XXXXXX") || return 1
  [ ! -L "$directory/history" ] && [ ! -L "$directory/history.next" ] || { rm -f "$candidate";return 1; }
  {
    [ ! -f "$directory/history" ] || cat "$directory/history"
    [ "$mode" != filter ] || printf '%s\n' "${DOMAINS:-}"
    [ "$mode" != filter ] || printf '%s\n' "${ALLOWS:-}"
  } | awk 'NF{if(length($0)>253||$0!~/^[A-Za-z0-9.-]+$/){bad=1;next}if(!seen[$0]++)print}END{exit bad}' > "$directory/history.next" || { rm -f "$candidate";return 1; }
  count=$(awk 'END{print NR+0}' "$directory/history.next")
  reloads=$(cat "$directory/reloads" 2>/dev/null);case "$reloads" in ''|*[!0-9]*)reloads=0;;esac
  if [ "$mode" = filter ] && { [ "$count" -gt "$MAX_HISTORY" ] || [ "$reloads" -ge "$MAX_RELOADS" ]; };then rm -f "$candidate" "$directory/history.next";return 2;fi
  render_rules "$mode" "$directory/history.next" > "$candidate" || { rm -f "$candidate";return 1; }
  gid=$(private_read rules-gid);case "$gid" in ''|*[!0-9]*)rm -f "$candidate";return 1;;esac
  chown "0:$gid" "$candidate" && chmod 640 "$candidate" || { rm -f "$candidate";return 1; }
  awk -v file="$candidate" '/^servers-file=/{print "servers-file="file;next}{print}' "$directory/dns.conf" > "$directory/check.conf"
  "$STATE_DIR/ss-adblock-dns" --test "--conf-file=$directory/check.conf" > "$directory/test.log" 2>&1 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- || { rm -f "$candidate";return 1; }
  if [ "$offline" != 1 ] && [ "$(private_read mode)" = "$mode" ] && cmp -s "$candidate" "$RULE_DIR/servers";then rm -f "$candidate" "$directory/history.next";return 0;fi
  mv -f "$directory/history.next" "$directory/history" || { rm -f "$candidate";return 1; }
  mv -f "$candidate" "$RULE_DIR/servers" || return 1
  if [ "$offline" != 1 ];then
    identity "$generation" || return 1
    kill -HUP "$CHILD_PID" || return 1
    # HUP is asynchronous. In particular, a reload without TCP forks used to
    # return immediately and expose the preceding rules to the next query.
    sleep 1 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
    identity "$generation" || return 1
    close_tcp_workers "$generation" || return 1
    identity "$generation" || return 1
    printf '%s\n' "$((reloads+1))" > "$directory/reloads"
  fi
  printf '%s\n' "$mode" > "$STATE_DIR/mode"
}
start_master() {
  local directory=$1 generation=${1##*/} pid token n=0 ip
  ip=$(cat "$directory/lan-ip")
  rm -f "$directory/ready"
  printf '0\n' > "$directory/reloads"
  "$STATE_DIR/ss-adblock-dns" --keep-in-foreground "--conf-file=$directory/dns.conf" </dev/null >> "$directory/runtime.log" 2>&1 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- &
  pid=$!;MASTER_PID=$pid
  while [ "$n" -lt 5 ];do
    token=$(awk '{print $22}' "$PROC_ROOT/$pid/stat" 2>/dev/null)
    if [ -n "$token" ];then
      printf '%s %s\n' "$pid" "$token" > "$directory/identity"
      awk '{print $1,$22,$5,$6}' "$PROC_ROOT/$pid/stat" > "$directory/ancestry"
    fi
    if identity "$generation" && listeners "$pid" "$ip";then : > "$directory/ready";return 0;fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 1 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-;n=$((n+1))
  done
  return 1
}
supervisor_alive() {
  local generation=$1 pid token now
  [ -f "$STATE_DIR/$generation/supervisor" ] || return 1
  read -r pid token < "$STATE_DIR/$generation/supervisor"
  case "$pid:$token" in *[!0-9:]*|:|*:)return 1;;esac
  now=$(awk '{print $22}' "$PROC_ROOT/$pid/stat" 2>/dev/null)
  [ "$now" = "$token" ] && kill -0 "$pid" 2>/dev/null
}
restart_drained() {
  local generation=$1 pins n=0
  printf '1\n' > "$STATE_DIR/resume"
  passthrough || return 1
  pins=$(pins_for "$generation") || pins=null
  if [ "$pins" != 0 ];then publish draining true awaiting_dns_drain 0 "$EXCLUDED_COUNT" "$pins";return 2;fi
  detach && close_tcp_workers "$generation" || return 1
  # No legacy mappings remain. Fence the old wait supervisor before replacing
  # this master; it must never restart or remove the succeeding generation.
  rm -f "$STATE_DIR/current"
  if identity "$generation";then kill "$CHILD_PID" 2>/dev/null || true;fi
  while identity "$generation" && [ "$n" -lt 3 ];do sleep 1 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-;n=$((n+1));done
  identity "$generation" && return 1
  rm -f "$STATE_DIR/captured-profiles" "$STATE_DIR/retire"
  start_generation
}
start_generation() {
  local directory generation n=0
  port_free || return 1
  directory=$("$FLOCK" mktemp -d "$STATE_DIR/generation.XXXXXX") || return 1;generation=${directory##*/}
  config "$directory" > "$directory/dns.conf";printf '%s\n' "$LAN_IP" > "$directory/lan-ip"
  printf '%s\n' "$LAN_IF" > "$directory/lan-if"
  : > "$directory/history"
  replace_rules "$generation" passthrough 1 || return 1
  "$STATE_DIR/ss-adblock-dns" --test "--conf-file=$directory/dns.conf" > "$directory/test.log" 2>&1 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- || return 1
  printf '%s\n' passthrough > "$STATE_DIR/mode"
  printf '%s\n' "$generation" > "$STATE_DIR/current.new" && mv -f "$STATE_DIR/current.new" "$STATE_DIR/current" || return 1
  sh "$STATE_DIR/keeper.sh" _supervise "$generation" </dev/null > "$directory/supervisor.log" 2>&1 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- &
  while [ "$n" -lt 5 ];do
    if [ -f "$directory/ready" ] && identity "$generation" && listeners "$CHILD_PID" "$LAN_IP";then return 0;fi
    sleep 1 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-;n=$((n+1))
  done;return 1
}
ensure_monitor() {
  sh "$STATE_DIR/keeper.sh" _drain </dev/null >> "$STATE_DIR/drain.log" 2>&1 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- &
}
passthrough() {
  local generation pins=null running=false state=off
  generation=$(current_generation)
  if [ -n "$generation" ] && identity "$generation";then
    replace_rules "$generation" passthrough || { detach;publish error true reload_failed 0 0 null || true;return 1; }
    running=true;ensure_monitor
    pins=$(pins_for "$generation") || pins=null
  fi
  detach || { publish error "$running" hook_cleanup_failed 0 0 "$pins" || true;return 1; }
  [ "$(private_read resume)" != 1 ] || state=draining
  publish "$state" "$running" passthrough 0 0 "$pins"
}
fail_open() { passthrough || true;publish error "$([ -n "$(current_generation)" ]&&identity "$(current_generation)"&&printf true||printf false)" "$1" 0 0 null || true;return 1; }
firewall() {
  local directory=$1 mac
  if iptables -t nat -S "$CHAIN" >/dev/null 2>&1 && ! owned_chain; then return 1; fi
  printf '%s\n' ss-adblock-v1 > "$STATE_DIR/owner"
  # Write this before the atomic kernel commit, so even an interrupted apply
  # will retire any mappings that its transaction might have installed.
  : > "$directory/intercepted" || return 1
  remove_hooks
  {
    printf '*nat\n:%s - [0:0]\n-F %s\n' "$CHAIN" "$CHAIN"
    for mac in $EXCLUDED; do printf '%s\n' "-A $CHAIN -m mac --mac-source $mac -j RETURN"; done
    printf '%s\n' "-A $CHAIN -p udp --dport 53 -j DNAT --to-destination $LAN_IP:$PORT" "-A $CHAIN -p tcp --dport 53 -j DNAT --to-destination $LAN_IP:$PORT"
    printf '%s\n' "-I PREROUTING 1 -i $LAN_IF -p udp --dport 53 -j $CHAIN" "-I PREROUTING 1 -i $LAN_IF -p tcp --dport 53 -j $CHAIN" COMMIT
  } > "$directory/firewall.rules"
  iptables-restore --noflush < "$directory/firewall.rules" 5>&- 6>&- 7>&- 8>&- 9>&-
}
hooks_ok() {
  local rules
  rules=$(iptables -t nat -S PREROUTING 2>/dev/null) || return 1
  printf '%s\n' "$rules" | awk -v iface="$LAN_IF" -v chain="$CHAIN" '
    $1=="-A"{position++;target="";dev="";proto="";port="";for(i=3;i<NF;i++){if($i=="-j")target=$(i+1);if($i=="-i")dev=$(i+1);if($i=="-p")proto=$(i+1);if($i=="--dport")port=$(i+1)}
    if(target==chain){n++;if(position>2||dev!=iface||port!=53||(proto!="tcp"&&proto!="udp")||seen[proto]++)bad=1}}
    END{exit !(n==2&&!bad)}' || return 1
  rules=$(iptables -t nat -S "$CHAIN" 2>/dev/null) || return 1
  printf '%s\n' "$rules" | awk -v macs="$(printf '%s\n' "$EXCLUDED" | tr '\n' ' ')" -v dest="$LAN_IP:$PORT" '
    BEGIN{n=split(macs,m," ");for(i=1;i<=n;i++)if(m[i]!="")expected[m[i]]=1}
    $1=="-A"{target="";mac="";proto="";port="";address="";for(i=3;i<NF;i++){if($i=="-j")target=$(i+1);if($i=="--mac-source")mac=toupper($(i+1));if($i=="-p")proto=$(i+1);if($i=="--dport")port=$(i+1);if($i=="--to-destination")address=$(i+1)}
    if(target=="RETURN"&&mac in expected){if(dnat||seenmac[mac]++)bad=1}else if(target=="DNAT"&&address==dest&&port==53&&(proto=="tcp"||proto=="udp")){dnat++;if(seenproto[proto]++)bad=1}else bad=1}
    END{for(mac in expected)if(!seenmac[mac])bad=1;exit !(dnat==2&&!bad)}'
}
apply() {
  local generation fingerprint profiles old_profiles pins rc geometry_changed=0
  settings || { ENABLED=0;printf '0\n' > "$STATE_DIR/intent";fail_open invalid_settings;return 1; }
  status_link || { passthrough;return 1; }
  printf '%s\n' "$ENABLED" > "$STATE_DIR/intent"
  if [ "$ENABLED" != 1 ] || ! core_active;then printf '0\n' > "$STATE_DIR/resume";passthrough;return $?;fi
  [ "$(private_read uninstalled)" != 1 ] || return 1
  . "$KS_ROOT/scripts/ss_routing.sh"
  ss_routing_load_bypass_macs && geometry || { fail_open invalid_devices;return 1; }
  EXCLUDED=$(printf '%s\n%s\n' "$SS_ROUTING_BYPASS_MACS" "$SS_ROUTING_UU_MACS" | awk 'NF&&!seen[$0]++')
  EXCLUDED_COUNT=$(printf '%s\n' "$EXCLUDED" | awk 'NF{n++}END{print n+0}')
  DOMAINS=$(compile_domains);DOMAIN_COUNT=$(printf '%s\n' "$DOMAINS" | awk 'NF{n++}END{print n+0}')
  fingerprint=$(printf '%s\n%s\n' "$DOMAINS" "$ALLOWS" | md5sum | awk '{print $1}')
  profiles=$(printf '%s\n' "$EXCLUDED" | sort | md5sum | awk '{print $1}')
  prepare_private || { fail_open private_runtime_failed;return 1; }
  generation=$(current_generation)
  if [ -z "$generation" ] || ! identity "$generation";then
    if [ -n "$generation" ] && supervisor_alive "$generation";then detach;publish error false forwarder_recovering 0 0 null;return 1;fi
    [ -z "$generation" ] || { detach;close_tcp_workers "$generation" || true; }
    start_generation || { fail_open startup_failed;return 1; }
    generation=$(current_generation)
  fi
  [ "$(cat "$STATE_DIR/$generation/lan-ip")" = "$LAN_IP" ] && [ "$(cat "$STATE_DIR/$generation/lan-if")" = "$LAN_IF" ] || geometry_changed=1
  old_profiles=$(private_read captured-profiles)
  if [ "$geometry_changed" = 1 ] || { [ -n "$old_profiles" ] && [ "$old_profiles" != "$profiles" ]; };then
    if restart_drained "$generation";then generation=$(current_generation)
    else rc=$?;[ "$rc" != 2 ] || return 0;fail_open restart_failed;return 1;fi
  fi
  if [ "$(private_read mode)" != filter ] || [ "$(cat "$STATE_DIR/$generation/fingerprint" 2>/dev/null)" != "$fingerprint" ];then
    if replace_rules "$generation" filter;then :
    else
      rc=$?
      if [ "$rc" = 2 ];then
        if restart_drained "$generation";then generation=$(current_generation);replace_rules "$generation" filter || { fail_open reload_failed;return 1; }
        else rc=$?;[ "$rc" != 2 ] || return 0;fail_open restart_failed;return 1;fi
      else fail_open reload_failed;return 1;fi
    fi
  fi
  printf '%s\n' "$fingerprint" > "$STATE_DIR/$generation/fingerprint"
  printf '%s\n' "$profiles" > "$STATE_DIR/$generation/profiles"
  printf '0\n' > "$STATE_DIR/resume"
  hooks_ok || firewall "$STATE_DIR/$generation" || { fail_open firewall_failed;return 1; }
  printf '%s\n' "$profiles" > "$STATE_DIR/captured-profiles"
  publish active true filtering "$DOMAIN_COUNT" "$EXCLUDED_COUNT" null
}
retire_cleanup() {
  local resume
  resume=$(private_read resume)
  rm -f "$STATE_DIR/current" "$STATE_DIR/retire" "$STATE_DIR/captured-profiles"
  if [ "$(private_read uninstalled)" = 1 ];then
    rm -rf "$RULE_DIR" "$STATE_DIR"
    LOCKED=0;exec 5>&-
  else
    ENABLED=$(private_read intent);[ "$ENABLED" = 1 ] || ENABLED=0
    publish "$([ "$resume" = 1 ]&&printf draining||printf off)" false retired 0 0 0 || true
    if [ "$resume" = 1 ] && [ -x "$KS_ROOT/scripts/ss_adblock.sh" ];then
      sh "$KS_ROOT/scripts/ss_adblock.sh" </dev/null >/dev/null 2>&1 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- &
    fi
  fi
}
supervise() {
  local generation=$1 directory pid current pins n=0 token
  generation_valid "$generation" || return 1;directory="$STATE_DIR/$generation"
  [ -d "$directory" ] && [ ! -L "$directory" ] || return 1
  select_flock || return 1
  while :;do
    [ "$(current_generation)" = "$generation" ] || return 0
    if start_master "$directory";then pid=$MASTER_PID;else pid=$MASTER_PID;fi
    token=$(awk '{print $22}' "$PROC_ROOT/$$/stat" 2>/dev/null)
    [ -z "$token" ] || printf '%s %s\n' "$$" "$token" > "$directory/supervisor"
    if identity "$generation";then
      init_state || return 1
      if [ "$(current_generation)" != "$generation" ];then
        close_tcp_workers "$generation" || true
        identity "$generation" && kill "$CHILD_PID" 2>/dev/null || true
        return 0
      fi
      if [ "$(private_read mode)" != filter ];then
        ENABLED=$(private_read intent);[ "$ENABLED" = 1 ] || ENABLED=0
        publish "$([ "$ENABLED" = 1 ]&&printf error||printf off)" true passthrough 0 0 null || true
        ensure_monitor
      fi
      "$FLOCK" -u 5;LOCKED=0;exec 5>&-
    fi
    wait "$pid" 2>/dev/null || true
    init_state || return 1
    current=$(current_generation)
    [ "$current" = "$generation" ] || return 0
    pins=$(pins_for "$generation") || pins=null
    if [ "$(private_read retire)" = "$generation" ] && [ "$(private_read mode)" != filter ] && [ "$pins" = 0 ];then close_tcp_workers "$generation" || true;retire_cleanup;return 0;fi
    detach || true;close_tcp_workers "$generation" || true
    if [ "$(private_read mode)" = filter ] && [ "$(private_read intent)" = 1 ];then printf '1\n' > "$STATE_DIR/resume";fi
    # A failed master is always replaced with forwarding-only rules first.
    # All old local entries died with this master and its verified workers.
    # The replacement starts forwarding-only; no public dependency is needed.
    : > "$directory/history"
    replace_rules "$generation" passthrough 1 || return 1
    printf '%s\n' passthrough > "$STATE_DIR/mode"
    rm -f "$STATE_DIR/retire"
    ENABLED=$(private_read intent);[ "$ENABLED" = 1 ] || ENABLED=0
    publish "$([ "$ENABLED" = 1 ]&&printf error||printf off)" false forwarder_recovering 0 0 "$pins" || true
    "$FLOCK" -u 5;LOCKED=0;exec 5>&-
    # Bounded retries per cycle; a retained private supervisor never relies on
    # /koolshare to rescue legacy UDP mappings after uninstall.
    n=$((n+1));sleep "$([ "$n" -lt 3 ]&&printf 1||printf 5)" 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
    ensure_monitor
  done
}
drain() {
  local generation pins n=0
  select_flock || return 1
  [ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR/drain.lock" ] || return 0
  exec 4>"$STATE_DIR/drain.lock";"$FLOCK" -n 4 || { exec 4>&-;return 0; }
  trap '"$FLOCK" -u 4 >/dev/null 2>&1;exec 4>&-' EXIT
  while [ -d "$STATE_DIR" ];do
    exec 5>"$LOCK_FILE"
    if "$FLOCK" -n 5;then
      generation=$(current_generation)
      if [ -z "$generation" ] || [ "$(private_read mode)" = filter ];then "$FLOCK" -u 5;exec 5>&-;return 0;fi
      pins=$(pins_for "$generation") || pins=null
      if [ "$pins" = 0 ] && identity "$generation" && detach;then
        close_tcp_workers "$generation" || true
        printf '%s\n' "$generation" > "$STATE_DIR/retire"
        kill "$CHILD_PID" 2>/dev/null || true
        "$FLOCK" -u 5;exec 5>&-;return 0
      fi
      "$FLOCK" -u 5
    fi
    exec 5>&-
    sleep 5 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
  done
}
uninstall() {
  ENABLED=0;printf '0\n' > "$STATE_DIR/intent";printf '0\n' > "$STATE_DIR/resume"
  passthrough || return 1
  # All executable/config dependencies used by surviving workers are now RAM
  # copies. The uninstaller may remove public code, DBus keys and status links.
  printf '1\n' > "$STATE_DIR/uninstalled"
  cru d ss_adblock >/dev/null 2>&1
  if [ -n "$(current_generation)" ];then
    [ -x "$STATE_DIR/keeper.sh" ] && [ -x "$STATE_DIR/ss-adblock-flock" ] && [ -x "$STATE_DIR/ss-adblock-dns" ] || return 1
    identity "$(current_generation)" || return 1
    ensure_monitor
  else
    [ ! -d "$RULE_DIR" ] || { root_owned "$RULE_DIR" && rm -rf "$RULE_DIR"; }
    rm -rf "$STATE_DIR"
    LOCKED=0;exec 5>&-
  fi
}
sync_cron() {
  cru d ss_adblock >/dev/null 2>&1
  if [ "$(dbus get ss_basic_adblock_enable)" = 1 ] && core_active;then cru a ss_adblock '* * * * * /koolshare/scripts/ss_adblock.sh >/dev/null 2>&1';fi
}

if [ "${SS_ADBLOCK_LIBRARY:-0}" != 1 ];then
  case "${1:-web}" in
    validate) settings || { printf '%s\n' 'Invalid ad-domain settings.' >&2;exit 2; };exit 0 ;;
    status) if [ -f "$PUBLIC_JSON" ] && [ ! -L "$PUBLIC_JSON" ];then cat "$PUBLIC_JSON";else printf '%s\n' '{"version":1,"enabled":false,"state":"off","running":false,"domains":0,"excluded_devices":0,"message":"inactive","mode":"passthrough","pending_flows":0}';fi;exit 0 ;;
    _supervise) [ "$#" = 2 ] || exit 2;supervise "$2";exit $? ;;
    _drain) drain;exit $? ;;
    web) select_flock || exit 1;exec 7>/var/lock/koolss.lock;"$FLOCK" -x 7 || exit 1;WEB_LOCKED=1 ;;
    apply|reconcile|stop|uninstall) ;;
    *) exit 2 ;;
  esac
  init_state || exit 1
  case "${1:-web}" in
    stop) ENABLED=$(dbus get ss_basic_adblock_enable);[ "$ENABLED" = 1 ] || ENABLED=0;printf '0\n' > "$STATE_DIR/resume";cru d ss_adblock >/dev/null 2>&1;passthrough ;;
    uninstall) uninstall ;;
    *) apply;result=$?;[ "${1:-web}" != web ] || sync_cron;exit "$result" ;;
  esac
fi
