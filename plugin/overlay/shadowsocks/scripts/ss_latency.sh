#!/bin/sh
# Saved-node entry TCP samples with a read-only OUTPUT path guard. No configuration writes.
KS_ROOT=/koolshare
STATE_DIR=/tmp/ss_latency
PUBLIC_JSON=/tmp/ss_latency.json
PROC_ROOT=/proc
TIMEOUT=5
BUDGET=25
PATH="$KS_ROOT/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
umask 077
FLOCK="$KS_ROOT/bin/ss-flock"
CHILD_PID= CHILD_TOKEN=

get() { dbus get "$1" 2>/dev/null; }
valid_id() { case "$1" in ''|0*|*[!0-9]*) return 1 ;; esac; [ "${#1}" -le 6 ]; }
valid_nonce() { case "$1" in *[!0-9a-f]*) return 1 ;; esac; [ "${#1}" = 32 ]; }
valid_ipv4() { printf '%s\n' "$1" | awk -F. 'NF!=4{exit 1}{for(i=1;i<=4;i++)if($i!~/^[0-9]+$/||length($i)>3||(length($i)>1&&substr($i,1,1)=="0")||$i+0>255)exit 1}'; }
root_owned() { [ ! -L "$1" ] && LC_ALL=C ls -nd "$1" 2>/dev/null | awk -v mode="$2" 'NR==1&&$3==0&&substr($1,1,10)==mode{ok=1}END{exit !ok}'; }
setup() {
    [ -x "$FLOCK" ] && [ ! -L "$STATE_DIR" ] || return 1
    if [ ! -e "$STATE_DIR" ];then mkdir -m 700 "$STATE_DIR" 2>/dev/null || [ -d "$STATE_DIR" ] || return 1;fi
    root_owned "$STATE_DIR" drwx------ || return 1
    local name link="$KS_ROOT/res/ss-latency-status.js"
    for name in job.lock metadata.lock job cancel snapshot snapshot.next;do
      [ ! -L "$STATE_DIR/$name" ] || return 1
      [ ! -e "$STATE_DIR/$name" ] || root_owned "$STATE_DIR/$name" -rw------- || return 1
    done
    [ ! -L "$STATE_DIR/public" ] && { [ ! -e "$STATE_DIR/public" ] || root_owned "$STATE_DIR/public" -rw------- || root_owned "$STATE_DIR/public" -rw-r--r-- ; } || return 1
    [ ! -L "$PUBLIC_JSON" ] && { [ ! -e "$PUBLIC_JSON" ] || root_owned "$PUBLIC_JSON" -rw-r--r-- ; } || return 1
    [ -d "$KS_ROOT/res" ] && [ ! -L "$KS_ROOT/res" ] || return 1
    if [ ! -e "$link" ] && [ ! -L "$link" ];then ln -s "$PUBLIC_JSON" "$link" 2>/dev/null || :;fi
    [ -L "$link" ] && [ "$(readlink "$link")" = "$PUBLIC_JSON" ] || return 1
    exec 8>"$STATE_DIR/metadata.lock"
    exec 9>"$STATE_DIR/job.lock"
}
root_regular() {
    [ -f "$1" ] && [ ! -L "$1" ] && LC_ALL=C ls -nd "$1" 2>/dev/null |
      awk 'NR==1&&substr($1,1,1)=="-"&&$3==0{ok=1}END{exit !ok}'
}
claim_mailbox() {
    local request="$STATE_DIR/request" claim="$STATE_DIR/request.claim.$$" payload="$STATE_DIR/request.data.$$" size invalid parsed rc=2
    "$FLOCK" -x 8 || return 1
    # Uploads do not take our lock. Claim one inode, then validate its entire
    # canonical record. A partial/overwritten upload is never an instruction.
    if root_regular "$request" && [ ! -e "$claim" ] && [ ! -L "$claim" ] &&
      [ ! -e "$payload" ] && [ ! -L "$payload" ] && mv "$request" "$claim";then
      # A concurrent uploader may still have the claimed inode open. Parse a
      # private copy so later writes cannot change already validated bytes.
      if root_regular "$claim" && chmod 600 "$claim" &&
        dd if="$claim" of="$payload" bs=129 count=1 2>/dev/null && chmod 600 "$payload";then
        size=$(wc -c < "$payload")
        if [ "$size" -gt 0 ] && [ "$size" -le 128 ];then
          # Count forbidden bytes before shell substitution/awk can hide NULs.
          invalid=$(LC_ALL=C tr -d 'a-z0-9 \n' < "$payload" | wc -c)
          if [ "$invalid" -eq 0 ] && [ "$(wc -l < "$payload")" -eq 1 ];then
            if parsed=$(LC_ALL=C awk '
              NR!=1{bad=1;next}
              NR==1{
                if($1=="start"&&NF==3&&$0==$1" "$2" "$3&&$2~/^[1-9][0-9]*$/&&length($2)<=6&&$3~/^[0-9a-f]+$/&&length($3)==32)ok=1
                else if($1=="cancel"&&NF==2&&$0==$1" "$2&&$2~/^[0-9a-f]+$/&&length($2)==32)ok=1
                else bad=1
                if(ok)print $0
              }END{exit bad||!ok||NR!=1}' "$payload");then
              # Only validated decimal/hex tokens reach the existing CLI.
              set -- $parsed
              MAILBOX_ACTION=$1 MAILBOX_ARG1=$2 MAILBOX_ARG2=${3:-}
              rc=0
            fi
          fi
        fi
      fi
      rm -f "$claim" "$payload"
    fi
    # Never retain 8 while start takes 9 then 8, or cancel takes 8 then try-9.
    "$FLOCK" -u 8
    return "$rc"
}
snapshot() {
    local key value
    for key in type trojan_binary use_kcp server port;do
      value=$(get "ssconf_basic_${key}_$NODE");printf '%s=%s\n' "$key" "$value"
    done
    for key in ss_basic_anytls_hosts ss_basic_server_resolver ss_basic_server_resolver_user;do
      value=$(get "$key");printf '%s=%s\n' "$key" "$value"
    done
    # Preset 1 uses this existing WAN resolver; observe it without changing it.
    printf 'wan_dns=%s\n' "$(nvram get wan0_dns 2>/dev/null)"
}
unchanged() { snapshot > "$STATE_DIR/snapshot.next" && cmp -s "$STATE_DIR/snapshot" "$STATE_DIR/snapshot.next"; }
cancelled() { [ "$(cat "$STATE_DIR/cancel" 2>/dev/null)" = "$NONCE" ]; }
clock() { awk '{printf "%d",$1;ok=1}END{exit !ok}' "$PROC_ROOT/uptime" 2>/dev/null || date +%s; }
budget_expired() { [ "$TICKS" -ge "$BUDGET" ] || [ "$(clock)" -ge "$END_AT" ]; }
publish() {
    local state=$1 reason=$2 ms=${3:-null} now
    "$FLOCK" -x 8 || return 1
    if [ "$(awk '{print $1}' "$STATE_DIR/job" 2>/dev/null)" != "$NONCE" ];then "$FLOCK" -u 8;return 1;fi
    now=$(date +%s)
    printf '{"version":1,"job_id":"%s","node_id":%s,"method":"router_tcp","transport":"ram_mailbox_v1","state":"%s","reason":"%s","latency_ms":%s,"checked_at":%s,"started_at":%s,"fingerprint":"%s","target":"entry","timeout_sec":5,"budget_sec":25}\n' \
      "$NONCE" "$NODE" "$state" "$reason" "$ms" "$now" "$STARTED" "$FINGERPRINT" > "$STATE_DIR/public" &&
      chmod 644 "$STATE_DIR/public" && mv -f "$STATE_DIR/public" "$PUBLIC_JSON"
    local rc=$?
    "$FLOCK" -u 8
    return "$rc"
}
token() { awk '{print $22}' "$PROC_ROOT/$1/stat" 2>/dev/null; }
stop_pid() {
    [ -n "$1" ] && [ -n "$2" ] || return 0
    if [ "$(token "$1")" = "$2" ];then
      # Let the TCP tool cancel/reap its own read-only guard commands first.
      kill -TERM "$1" 2>/dev/null
      if kill -0 "$1" 2>/dev/null;then sleep 1;fi
      [ "$(token "$1")" != "$2" ] || kill -KILL "$1" 2>/dev/null
    fi
    wait "$1" 2>/dev/null || :
}
cleanup() {
    stop_pid "$CHILD_PID" "$CHILD_TOKEN";CHILD_PID= CHILD_TOKEN=
    rm -f "$STATE_DIR/dns" "$STATE_DIR/metrics" "$STATE_DIR/snapshot" "$STATE_DIR/snapshot.next"
}
finish() {
    local rc=$?
    trap - EXIT HUP INT TERM
    cleanup
    "$FLOCK" -u 9 >/dev/null 2>&1 || :
    exec 8>&- 9>&-
    exit "$rc"
}
wait_child() {
    local limit=$1 ticks=0 rc
    CHILD_TOKEN=$(token "$CHILD_PID")
    while kill -0 "$CHILD_PID" 2>/dev/null;do
      cancelled && { stop_pid "$CHILD_PID" "$CHILD_TOKEN";CHILD_PID=;return 125; }
      if [ "$ticks" -ge "$limit" ] || budget_expired;then
        stop_pid "$CHILD_PID" "$CHILD_TOKEN";CHILD_PID=;return 124
      fi
      sleep 1; ticks=$((ticks+1));TICKS=$((TICKS+1))
    done
    wait "$CHILD_PID";rc=$?;CHILD_PID= CHILD_TOKEN=
    return "$rc"
}
resolver() {
    local preset value
    preset=$(get ss_basic_server_resolver)
    case "$preset" in
      2) value=223.5.5.5 ;; 3) value=223.6.6.6 ;; 4) value=114.114.114.114 ;; 5) value=114.114.115.115 ;;
      6) value=1.2.4.8 ;; 7) value=210.2.4.8 ;; 8) value=117.50.11.11 ;; 9) value=117.50.22.22 ;;
      10) value=180.76.76.76 ;; 11) value=119.29.29.29 ;; 12) value=$(get ss_basic_server_resolver_user) ;; 13) value=8.8.8.8 ;;
      *) value=$(nvram get wan0_dns 2>/dev/null | awk '{print $1;exit}'); valid_ipv4 "$value" || value=114.114.114.114 ;;
    esac
    ss_dns_normalize_resolver "$value"
}
run_job() {
    trap finish EXIT
    trap 'publish cancelled interrupted;exit 0' HUP INT TERM
    TICKS=0
    END_AT=$(($(clock)+BUDGET))
    [ "$(get "ssconf_basic_type_$NODE")" = 4 ] && [ "$(get "ssconf_basic_trojan_binary_$NODE")" = AnyTLS ] &&
      [ "$(get "ssconf_basic_use_kcp_$NODE")" != 1 ] || { publish failed unsupported_node;return; }
    local host port ip dns rc state reason ms samples successes values median
    host=$(get "ssconf_basic_server_$NODE");port=$(get "ssconf_basic_port_$NODE")
    case "$port" in ''|*[!0-9]*) publish failed invalid_settings;return ;; esac
    [ "${#port}" -le 5 ] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || { publish failed invalid_settings;return; }
    [ -x "$KS_ROOT/bin/ss-tcp-probe" ] || { publish failed missing_component;return; }
    . "$KS_ROOT/scripts/ss_dns_hooks.sh"
    ip=$(sh "$KS_ROOT/scripts/ss_anytls.sh" map-host "$host" 2>/dev/null) || { publish failed invalid_hosts;return; }
    if ! valid_ipv4 "$ip";then
      dns=$(resolver) || { publish dns_failed invalid_resolver;return; }
      "$KS_ROOT/bin/ss-https-probe" -resolve "$ip" -dns "$dns" -ca "$KS_ROOT/ss/rules/cacert.pem" -timeout 5s > "$STATE_DIR/dns" 2>/dev/null 8>&- 9>&- &
      CHILD_PID=$!;wait_child 6;rc=$?
      [ "$rc" != 125 ] || { publish cancelled cancelled;return; }
      [ "$rc" = 0 ] || { publish dns_failed dns_failed;return; }
      ip=$(awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/{print;exit}' "$STATE_DIR/dns")
    fi
    valid_ipv4 "$ip" || { publish dns_failed dns_failed;return; }
    unchanged || { publish changed node_changed;return; }
    cancelled && { publish cancelled cancelled;return; }
    # The tool proves the real router OUTPUT path before/after sampling. Unknown
    # rules, redirects or guard-read failures produce path_unverified, never ms.
    "$KS_ROOT/bin/ss-tcp-probe" -address "$ip:$port" -timeout 5s -samples 3 > "$STATE_DIR/metrics" 2>/dev/null 8>&- 9>&- &
    CHILD_PID=$!;wait_child 20;rc=$?
    cancelled && { publish cancelled cancelled;return; }
    unchanged || { publish changed node_changed;return; }
    budget_expired && { publish timeout budget;return; }
    case "$rc" in 124) publish timeout timeout;return ;; 125) publish cancelled cancelled;return ;; esac
    # Only the fixed, compact tool protocol is accepted; no response is evaluated.
    [ "$(wc -c < "$STATE_DIR/metrics")" -le 4096 ] &&
      LC_ALL=C awk 'NR==1&&substr($0,1,1)=="{"&&substr($0,length($0),1)=="}"{ok=1}END{exit !(NR==1&&ok)}' "$STATE_DIR/metrics" &&
      grep -Eq '"version":1[,}]' "$STATE_DIR/metrics" &&
      grep -q '"method":"router_tcp"' "$STATE_DIR/metrics" &&
      grep -q '"target":"entry"' "$STATE_DIR/metrics" || { publish failed invalid_metrics;return; }
    state=$(sed -n 's/.*"state":"\([a-z_]*\)".*/\1/p' "$STATE_DIR/metrics")
    reason=$(sed -n 's/.*"reason":"\([a-z_]*\)".*/\1/p' "$STATE_DIR/metrics")
    [ -n "$reason" ] && [ "${#reason}" -le 48 ] || reason=probe_failed
    case "$state:$rc" in
      path_unverified:2) publish path_unverified "$reason";return ;;
      timeout:1) publish timeout "$reason";return ;;
      failed:1) publish failed "$reason";return ;;
      ok:0) ;;
      *) publish failed invalid_metrics;return ;;
    esac
    samples=$(sed -n 's/.*"samples":\([0-9][0-9]*\)[,}].*/\1/p' "$STATE_DIR/metrics")
    successes=$(sed -n 's/.*"successes":\([0-9][0-9]*\)[,}].*/\1/p' "$STATE_DIR/metrics")
    ms=$(sed -n 's/.*"latency_ms":\([0-9][0-9]*\)[,}].*/\1/p' "$STATE_DIR/metrics")
    values=$(sed -n 's/.*"samples_ms":\[\([0-9,]*\)\].*/\1/p' "$STATE_DIR/metrics")
    [ "$samples" = 3 ] && [ "$successes" = 3 ] || { publish failed invalid_metrics;return; }
    median=$(printf '%s\n' "$values" | LC_ALL=C awk -F, '
      NF!=3{exit 1}{for(i=1;i<=3;i++){if($i!~/^(0|[1-9][0-9]*)$/||length($i)>4||$i+0>5000)exit 1;a[i]=$i+0}
      for(i=1;i<=3;i++)for(j=i+1;j<=3;j++)if(a[i]>a[j]){v=a[i];a[i]=a[j];a[j]=v}printf "%d",a[2]}') || { publish failed invalid_metrics;return; }
    [ "$ms" = "$median" ] || { publish failed invalid_metrics;return; }
    publish ok measured "$ms"
}

SETUP_READY=0
if [ "$#" = 0 ];then
    if [ ! -e "$STATE_DIR/request" ] && [ ! -L "$STATE_DIR/request" ];then
      printf '%s\n' 'Usage: ss_latency.sh start NODE_ID NONCE | cancel NONCE | status' >&2;exit 2
    fi
    setup || exit 1
    claim_mailbox || { printf '%s\n' 'Invalid measurement request.' >&2;exit 2; }
    if [ "$MAILBOX_ACTION" = start ];then set -- start "$MAILBOX_ARG1" "$MAILBOX_ARG2"
    else set -- cancel "$MAILBOX_ARG1";fi
    SETUP_READY=1
fi
case "${1:-}" in
  start) [ "$#" = 3 ] && valid_id "$2" && valid_nonce "$3" || exit 2 ;;
  cancel) [ "$#" = 2 ] && valid_nonce "$2" || exit 2 ;;
  status) [ "$#" = 1 ] || exit 2 ;;
  *) printf '%s\n' 'Usage: ss_latency.sh start NODE_ID NONCE | cancel NONCE | status' >&2;exit 2 ;;
esac
[ "$SETUP_READY" = 1 ] || setup || exit 1
case "$1" in
  start)
    NODE=$2 NONCE=$3
    # ponytail: one router-wide job; separate ports only if hardware permits concurrency.
    "$FLOCK" -n 9 || exit 3
    [ "$(cat "$STATE_DIR/job" 2>/dev/null)" != "$NONCE $NODE" ] || exit 0
    snapshot > "$STATE_DIR/snapshot" || exit 1
    # Entry identity contains no node authentication material.
    FINGERPRINT=$(md5sum "$STATE_DIR/snapshot" | awk '{print $1}')
    STARTED=$(date +%s)
    "$FLOCK" -x 8 || exit 1
    printf '%s %s\n' "$NONCE" "$NODE" > "$STATE_DIR/job"
    rm -f "$STATE_DIR/cancel"
    "$FLOCK" -u 8
    publish running probing || exit 1
    (run_job) </dev/null >/dev/null 2>&1 &
    exec 8>&- 9>&-
    ;;
  cancel)
    "$FLOCK" -x 8 || exit 1
    if [ "$(awk '{print $1}' "$STATE_DIR/job" 2>/dev/null)" = "$2" ];then
      if "$FLOCK" -n 9;then "$FLOCK" -u 9
      else printf '%s\n' "$2" > "$STATE_DIR/cancel";fi
    fi
    "$FLOCK" -u 8
    ;;
  status)
    "$FLOCK" -x 8 || exit 1
    RESET_IDLE=0 IDLE_LOCKED=0
    if [ -f "$PUBLIC_JSON" ] && ! { grep -q '"method":"router_tcp"' "$PUBLIC_JSON" &&
      grep -q '"target":"entry"' "$PUBLIC_JSON" && grep -q '"transport":"ram_mailbox_v1"' "$PUBLIC_JSON"; };then
      # A previous measurement schema may survive an add-on update in RAM.
      # Never replace an in-flight job's result or stop its process.
      if "$FLOCK" -n 9;then IDLE_LOCKED=1 RESET_IDLE=1
      else "$FLOCK" -u 8;exit 1;fi
    fi
    if [ ! -f "$PUBLIC_JSON" ] || [ "$RESET_IDLE" = 1 ];then
      printf '%s\n' '{"version":1,"method":"router_tcp","transport":"ram_mailbox_v1","target":"entry","state":"idle","reason":"","job_id":"","node_id":0,"latency_ms":null,"checked_at":0}' > "$STATE_DIR/public" &&
        chmod 644 "$STATE_DIR/public" && mv -f "$STATE_DIR/public" "$PUBLIC_JSON" || exit 1
    fi
    [ "$IDLE_LOCKED" != 1 ] || "$FLOCK" -u 9
    "$FLOCK" -u 8
    cat "$PUBLIC_JSON"
    ;;
esac
