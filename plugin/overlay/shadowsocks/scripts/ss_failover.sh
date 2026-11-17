#!/bin/sh
# Bounded AnyTLS failover. State is RAM-only; node credentials never enter status.
KS_ROOT=/koolshare
STATE_DIR=/tmp/ss_failover
PUBLIC_JSON=/tmp/ss_failover.json
PROC_ROOT=/proc
PROBE_PORT=23457
PATH="$KS_ROOT/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
umask 077
FLOCK="$KS_ROOT/bin/ss-flock"
CLIENT_PID=
DNS_PID=
WATCH_PID=

get() { dbus get "$1" 2>/dev/null; }
number() {
    local value
    value=$(get "$1")
    [ -n "$value" ] || value=$2
    case "$value" in ''|*[!0-9]*) return 1 ;; esac
    [ "${#value}" -le 6 ] && [ "$value" -ge "$3" ] && [ "$value" -le "$4" ] || return 1
    printf '%s' "$value" | awk '{printf "%d",$1}'
}
normalize_ids() {
    LC_ALL=C awk '{gsub(/,/," "); for(i=1;i<=NF;i++) {
      if($i !~ /^[0-9]+$/ || length($i)>6 || $i+0<1 || $i+0>999999) exit 2
      id=sprintf("%d",$i); if(!seen[id]++){a[++n]=id;if(n>128)exit 2}
    }} END {if(n<=128)for(i=1;i<=n;i++)printf "%s%s",(i==1?"":","),a[i]}'
}
normalize_countries() {
    LC_ALL=C awk '{gsub(/,/," "); for(i=1;i<=NF;i++) {
      if(split($i,p,"=")!=2 || p[1]!~/^[0-9]+$/ || length(p[1])>6 || p[1]+0<1 || p[1]+0>999999 || p[2]!~/^[A-Za-z][A-Za-z]$/)exit 2
      id=sprintf("%d",p[1]);code=toupper(p[2]);if(id in map && map[id]!=code)exit 2
      if(!(id in map)){a[++n]=id;if(n>128)exit 2} map[id]=code
    }} END {if(n<=128)for(i=1;i<=n;i++)printf "%s%s=%s",(i==1?"":","),a[i],map[a[i]]}'
}
settings() {
    ENABLED=$(number ss_basic_failover_enable 0 0 1) || return 1
    COUNTRY=$(get ss_basic_failover_country); [ -n "$COUNTRY" ] || COUNTRY=auto
    case "$COUNTRY" in auto) ;; [A-Za-z][A-Za-z]) COUNTRY=$(printf '%s' "$COUNTRY" | tr 'a-z' 'A-Z') ;; *) return 1 ;; esac
    CANDIDATES=$(get ss_basic_failover_nodes | normalize_ids) || return 1
    COUNTRY_MAP=$(get ss_basic_failover_countries | normalize_countries) || return 1
    FAILURES=$(number ss_basic_failover_failures 3 1 5) || return 1
    RECOVERIES=$(number ss_basic_failover_recoveries 2 1 3) || return 1
    COOLDOWN=$(number ss_basic_failover_cooldown 120 30 600) || return 1
    TIMEOUT=$(number ss_basic_failover_timeout 5 3 8) || return 1
    BUDGET=$(number ss_basic_failover_budget 60 20 120) || return 1
    DIRECT=$(number ss_basic_failover_direct 1 0 1) || return 1
    [ "$BUDGET" -ge $((3*TIMEOUT+8)) ] || return 1
}
valid_id() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; [ "${#1}" -le 6 ] && [ "$1" -ge 1 ] && [ "$1" -le 999999 ]; }
valid_ipv4() {
    printf '%s\n' "$1" | awk -F. 'NF!=4{exit 1}{for(i=1;i<=4;i++)if($i!~/^[0-9]+$/ || length($i)>3 || $i+0>255)exit 1}'
}
country_for() {
    local code name
    code=$(printf '%s\n' "$COUNTRY_MAP" | tr ',' '\n' | awk -F= -v id="$1" '$1==id{print $2;exit}')
    if [ -n "$code" ]; then printf '%s' "$code"; return; fi
    name=$(get "ssconf_basic_name_$1" | tr 'A-Z' 'a-z')
    code=$(printf '%s' "$name" | LC_ALL=C awk -v alphabet='🇦🇧🇨🇩🇪🇫🇬🇭🇮🇯🇰🇱🇲🇳🇴🇵🇶🇷🇸🇹🇺🇻🇼🇽🇾🇿' '
      BEGIN{letters="ABCDEFGHIJKLMNOPQRSTUVWXYZ";for(i=1;i<=26;i++)map[substr(alphabet,(i-1)*4+1,4)]=substr(letters,i,1)}
      {for(i=1;i<=length($0)-7;i++){a=substr($0,i,4);b=substr($0,i+4,4);if(a in map && b in map){printf "%s%s",map[a],map[b];exit}}}')
    if [ -n "$code" ];then printf '%s' "$code";return;fi
    # Flags precede transit-city words (e.g. a JP node routed via Hong Kong).
    case "$name" in
      *🇭🇰*) printf HK;return ;; *🇲🇴*) printf MO;return ;; *🇹🇼*) printf TW;return ;;
      *🇯🇵*) printf JP;return ;; *🇸🇬*) printf SG;return ;; *🇺🇸*) printf US;return ;;
      *🇬🇧*) printf GB;return ;; *🇰🇷*) printf KR;return ;; *🇦🇺*) printf AU;return ;;
      *🇨🇦*) printf CA;return ;; *🇩🇪*) printf DE;return ;; *🇫🇷*) printf FR;return ;;
      *🇳🇱*) printf NL;return ;; *🇷🇺*) printf RU;return ;; *🇹🇷*) printf TR;return ;; *🇦🇪*) printf AE;return ;;
    esac
    case "$name" in
      *🇭🇰*|*香港*|*hongkong*|*hong\ kong*) printf HK; return ;;
      *🇲🇴*|*澳门*|*澳門*|*macau*|*macao*) printf MO; return ;;
      *🇹🇼*|*台湾*|*台灣*|*taiwan*|*taipei*) printf TW; return ;;
      *🇯🇵*|*日本*|*东京*|*東京*|*大阪*|*japan*|*tokyo*|*osaka*) printf JP; return ;;
      *🇸🇬*|*新加坡*|*狮城*|*singapore*) printf SG; return ;;
      *🇺🇸*|*美国*|*美國*|*美西*|*美东*|*洛杉矶*|*united\ states*) printf US; return ;;
      *🇬🇧*|*英国*|*英國*|*伦敦*|*united\ kingdom*|*britain*|*london*) printf GB; return ;;
      *🇰🇷*|*韩国*|*韓國*|*首尔*|*korea*|*seoul*) printf KR; return ;;
      *🇦🇺*|*澳大利亚*|*澳洲*|*悉尼*|*australia*|*sydney*) printf AU; return ;;
      *🇨🇦*|*加拿大*|*canada*) printf CA; return ;;
      *🇩🇪*|*德国*|*德國*|*法兰克福*|*germany*|*frankfurt*) printf DE; return ;;
      *🇫🇷*|*法国*|*法國*|*巴黎*|*france*|*paris*) printf FR; return ;;
      *🇳🇱*|*荷兰*|*荷蘭*|*netherlands*|*amsterdam*) printf NL; return ;;
      *🇷🇺*|*俄罗斯*|*俄羅斯*|*russia*) printf RU; return ;;
      *🇹🇷*|*土耳其*|*turkey*|*türkiye*) printf TR; return ;;
      *🇦🇪*|*阿联酋*|*阿聯酋*|*迪拜*|*dubai*) printf AE; return ;;
    esac
    printf '%s\n' "$name" | LC_ALL=C awk '
      {gsub(/[^a-z]/," ");for(i=1;i<=NF;i++) {
        t=toupper($i);if(t=="UK")t="GB";if(t=="USA")t="US"
        if(t~/^(HK|MO|TW|JP|SG|US|GB|KR|AU|CA|DE|FR|NL|RU|TR|AE)$/){print t;found=1;exit}
      }} END{if(!found)printf "XX"}'
}
private_read() { [ -f "$STATE_DIR/$1" ] && [ ! -L "$STATE_DIR/$1" ] && cat "$STATE_DIR/$1"; }
current_node() {
    local value
    value=$(get ssconf_basic_node)
    if valid_id "$value";then printf '%s' "$value" | awk '{printf "%d",$1}';else printf 0;fi
}
same_snapshot() { [ "$(private_read generation)" = "$GEN" ] && [ "$(current_node)" = "$NODE" ]; }
write_state() {
    local temporary="$STATE_DIR/$1.$$" rc=0
    [ "${METADATA_LOCKED:-0}" = 1 ] || "$FLOCK" -x 8 || return 1
    if [ -n "${GEN:-}" ] && [ "${RESETTING:-0}" != 1 ];then
      if [ "${UNCONDITIONAL:-0}" = 1 ];then same_snapshot || rc=75;else alive || rc=75;fi
    fi
    if [ "$rc" = 0 ];then printf '%s\n' "$2" > "$temporary" && chmod 600 "$temporary" && mv -f "$temporary" "$STATE_DIR/$1" || rc=1;fi
    [ "${METADATA_LOCKED:-0}" = 1 ] || "$FLOCK" -u 8
    return "$rc"
}
mode() {
    local value
    value=$(private_read mode)
    case "$value" in proxy|direct|error) printf '%s' "$value" ;; *) printf proxy ;; esac
}
alive() {
    same_snapshot && [ "$(get ss_basic_enable)" = 1 ] && [ "$(get ss_basic_failover_enable)" = 1 ]
}
counter() {
    local value
    value=$(private_read "$1")
    case "$value" in ''|*[!0-9]*) value=0 ;; esac
    [ "${#value}" -le 10 ] || value=0
    printf '%s' "$value"
}
clear_scan() { rm -f "$STATE_DIR/queue" "$STATE_DIR/all" "$STATE_DIR/results" "$STATE_DIR/cursor" "$STATE_DIR/phase" "$STATE_DIR/scan_identity" "$STATE_DIR/winner"; }
publish() {
    local state=$1 reason=$2 best=${3:-0} latency=${4:-null} scanned=${5:-0} total=${6:-0} current_country changed failures now path_mode
    "$FLOCK" -x 8 || return 1
    if [ "${UNCONDITIONAL:-0}" = 1 ];then
      same_snapshot || { "$FLOCK" -u 8;return 75; }
    else alive || { "$FLOCK" -u 8;return 75; };fi
    current_country=XX; valid_id "${NODE:-0}" && current_country=$(country_for "$NODE")
    changed=$(counter changed_at);failures=$(counter failures);now=$(date +%s);path_mode=$(mode)
    [ ! -L "$PUBLIC_JSON" ] || { "$FLOCK" -u 8; return 1; }
    printf '{"version":1,"state":"%s","mode":"%s","current_node":%s,"country":"%s","preferred_country":"%s","scanned":%s,"total":%s,"best_node":%s,"best_ms":%s,"failures":%s,"checked_at":%s,"changed_at":%s,"reason":"%s"}\n' \
      "$state" "$path_mode" "${NODE:-0}" "$current_country" "${PREFERRED:-XX}" "$scanned" "$total" "$best" "$latency" "$failures" "$now" "$changed" "$reason" > "$STATE_DIR/public.$$" &&
      chmod 644 "$STATE_DIR/public.$$" && mv -f "$STATE_DIR/public.$$" "$PUBLIC_JSON"
    local rc=$?
    "$FLOCK" -u 8
    return "$rc"
}
cleanup() {
    [ -z "$DNS_PID" ] || { kill -KILL "$DNS_PID" 2>/dev/null; wait "$DNS_PID" 2>/dev/null; }
    [ -z "$CLIENT_PID" ] || { kill "$CLIENT_PID" 2>/dev/null; wait "$CLIENT_PID" 2>/dev/null; }
    [ -z "$WATCH_PID" ] || { kill "$WATCH_PID" 2>/dev/null; wait "$WATCH_PID" 2>/dev/null; }
    DNS_PID=;CLIENT_PID=;WATCH_PID=
    rm -f "$STATE_DIR/dns.$$" "$STATE_DIR/latencies.$$" "$STATE_DIR/client.$$" "$STATE_DIR/results.$$"
}
finish() {
    local rc=$?
    trap - EXIT HUP INT TERM
    cleanup
    # Explicit unlock also releases inherited open descriptions held by a child.
    "$FLOCK" -u 8 >/dev/null 2>&1 || :
    "$FLOCK" -u 9 >/dev/null 2>&1 || :
    exec 8>&- 9>&-
    exit "$rc"
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
resolve_node() {
    local host=$1 dns=$2 attempt=0 modern=0 rc
    if valid_ipv4 "$host"; then printf '%s' "$host"; return 0; fi
    if [ -x "$KS_ROOT/bin/ss-https-probe" ]; then
      modern=1
      "$KS_ROOT/bin/ss-https-probe" -resolve "$host" -dns "$dns" -ca "$KS_ROOT/ss/rules/cacert.pem" -timeout 5s > "$STATE_DIR/dns.$$" 2>/dev/null 8>&- 9>&- &
    else
      case "$dns" in *:53) dns=${dns%:53} ;; *) return 1 ;; esac
      nslookup "$host" "$dns" > "$STATE_DIR/dns.$$" 2>/dev/null 8>&- 9>&- &
    fi
    DNS_PID=$!
    while kill -0 "$DNS_PID" 2>/dev/null && [ "$attempt" -lt 5 ]; do sleep 1;attempt=$((attempt+1));done
    if kill -0 "$DNS_PID" 2>/dev/null; then kill -KILL "$DNS_PID" 2>/dev/null;fi
    wait "$DNS_PID" 2>/dev/null; rc=$?; DNS_PID=
    [ "$rc" = 0 ] || return 1
    if [ "$modern" = 1 ]; then
      awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/{print;exit}' "$STATE_DIR/dns.$$"
    else
      awk '/^Name:/{answer=1;next} answer && /Address/{for(i=2;i<=NF;i++)if($i~/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/){n=split($i,a,".");ok=n==4;for(j=1;j<=n;j++)if(length(a[j])>3 || a[j]+0>255)ok=0;if(ok){print $i;exit}}}' "$STATE_DIR/dns.$$"
    fi
}

probe_targets() {
    local proxy=$1 target metrics rc http seconds passed=0 failed=0
    : > "$STATE_DIR/latencies.$$"
    for target in google youtube telegram; do
      if [ -x "$KS_ROOT/bin/ss-https-probe" ]; then
        metrics=$("$KS_ROOT/bin/ss-https-probe" -proxy "$proxy" -ca "$KS_ROOT/ss/rules/cacert.pem" -target "$target" -timeout "${TIMEOUT}s" -format curl 2>/dev/null 8>&- 9>&-);rc=$?
      else
        local url
        case "$target" in google) url=https://www.gstatic.com/generate_204 ;; youtube) url=https://www.youtube.com/generate_204 ;; *) url=https://telegram.org/ ;; esac
        metrics=$(curl --cacert "$KS_ROOT/ss/rules/cacert.pem" --socks5-hostname "$proxy" --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" -sS -o /dev/null --write-out '%{http_code}|%{time_total}' "$url" 2>/dev/null 8>&- 9>&-);rc=$?
      fi
      http=${metrics%%|*};seconds=${metrics#*|}
      case "$rc:$http" in 0:200|0:204|0:301|0:302|0:307|0:308)
        if printf '%s\n' "$seconds" | awk '/^[0-9]+([.][0-9]+)?$/{ok=1;printf "%.0f\n",$1*1000} END{exit !ok}' >> "$STATE_DIR/latencies.$$"; then passed=$((passed+1));else failed=$((failed+1));fi ;;
        *) failed=$((failed+1)) ;;
      esac
      [ "$passed" -ge 2 ] && break
      [ "$failed" -ge 2 ] && break
    done
    [ "$passed" -ge 2 ] || return 1
    PROBE_MS=$(sort -n "$STATE_DIR/latencies.$$" | awk '{a[NR]=$1}END{if(NR%2)print a[(NR+1)/2];else printf "%.0f",(a[NR/2]+a[NR/2+1])/2}')
    case "$PROBE_MS" in ''|*[!0-9]*) return 1 ;; esac
}
probe_candidate() {
    local id=$1 host port password sni insecure ip dns attempt=0 start_token
    [ "$(get "ssconf_basic_type_$id")" = 4 ] && [ "$(get "ssconf_basic_trojan_binary_$id")" = AnyTLS ] || return 1
    [ "$(get "ssconf_basic_use_kcp_$id")" != 1 ] || return 1
    host=$(get "ssconf_basic_server_$id");port=$(get "ssconf_basic_port_$id")
    sni=$(get "ssconf_basic_trojan_sni_$id");[ -n "$sni" ] || sni=$host
    case "$port" in ''|*[!0-9]*) return 1 ;; esac
    [ "${#port}" -le 5 ] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || return 1
    ip=$(sh "$KS_ROOT/scripts/ss_anytls.sh" map-host "$host" 2>/dev/null) || return 1
    dns=$(resolver) || return 1
    # No pipeline owns nslookup: the exact resolver child can always be reaped.
    if ! valid_ipv4 "$ip"; then
      resolve_node "$ip" "$dns" > "$STATE_DIR/address.$$";ip=$(cat "$STATE_DIR/address.$$");rm -f "$STATE_DIR/address.$$"
    fi
    valid_ipv4 "$ip" || return 1
    password=$(get "ssconf_basic_password_$id" | "$KS_ROOT/bin/base64_decode" 2>/dev/null)
    [ -n "$password" ] || return 1
    insecure=$(get "ssconf_basic_allowinsecure_$id");case "$insecure" in 1) ;; *) insecure=0 ;; esac
    if netstat -lnt 2>/dev/null | awk -v port="$PROBE_PORT" '$1~/^tcp/ && $4~(":"port"$"){found=1}END{exit !found}'; then return 2;fi
    SS_ANYTLS_INSECURE="$insecure" sh "$KS_ROOT/scripts/ss_anytls.sh" -m 0 -socks "127.0.0.1:$PROBE_PORT" -s "$ip:$port" -p "$password" -sni "$sni" > "$STATE_DIR/client.$$" 2>&1 8>&- 9>&- &
    CLIENT_PID=$!
    password=
    while [ "$attempt" -lt 2 ]; do
      if ! kill -0 "$CLIENT_PID" 2>/dev/null;then cleanup;return 1;fi
      if netstat -lntp 2>/dev/null | awk -v port="$PROBE_PORT" -v pid="$CLIENT_PID" '$1~/^tcp/ && $4=="127.0.0.1:"port && $6=="LISTEN" && $7~("^"pid"/"){found=1}END{exit !found}'; then break;fi
      sleep 1;attempt=$((attempt+1))
    done
    if [ "$attempt" -ge 2 ];then cleanup;return 1;fi
    start_token=$(awk '{print $22}' "$PROC_ROOT/$CLIENT_PID/stat" 2>/dev/null)
    if [ -n "$start_token" ]; then
      (trap - EXIT HUP INT TERM;sleep $((3*TIMEOUT+3));[ "$(awk '{print $22}' "$PROC_ROOT/$CLIENT_PID/stat" 2>/dev/null)" != "$start_token" ] || kill "$CLIENT_PID" 2>/dev/null) 8>&- 9>&- &
      WATCH_PID=$!
    fi
    probe_targets "127.0.0.1:$PROBE_PORT"; local rc=$?
    cleanup
    return "$rc"
}
collect() {
    local ids id count=0
    if [ -n "$CANDIDATES" ]; then ids=$(printf '%s' "$CANDIDATES" | tr ',' ' ')
    else ids=$(dbus list ssconf_basic_type_ 2>/dev/null | awk -F= '$1~/^ssconf_basic_type_[0-9]+$/ && $2==4{sub(/^ssconf_basic_type_/,"",$1);if(length($1)<=6 && $1+0>0)printf "%d\n",$1}' | sort -n);fi
    : > "$STATE_DIR/all.$$"
    for id in $ids; do
      valid_id "$id" || return 1
      [ "$(get "ssconf_basic_type_$id")" = 4 ] && [ "$(get "ssconf_basic_trojan_binary_$id")" = AnyTLS ] || continue
      [ "$(get "ssconf_basic_use_kcp_$id")" != 1 ] || continue
      count=$((count+1));[ "$count" -le 128 ] || return 1
      printf '%s %s\n' "$id" "$(country_for "$id")" >> "$STATE_DIR/all.$$"
    done
    mv -f "$STATE_DIR/all.$$" "$STATE_DIR/all"
}
phase_queue() {
    local phase=$1
    if [ "$phase" = same ];then awk -v c="$PREFERRED" 'c!="XX" && $2==c' "$STATE_DIR/all" > "$STATE_DIR/queue"
    else awk -v c="$PREFERRED" 'c=="XX" || $2!=c' "$STATE_DIR/all" > "$STATE_DIR/queue";fi
    : > "$STATE_DIR/results"
    write_state phase "$phase" && write_state cursor 0
}
service_action() {
    local action=$1 target=${2:-} rc actual
    alive || return 75
    if [ "$action" = failover-switch ];then sh "$KS_ROOT/ss/ssconfig.sh" "$action" "$target" "$NODE" "$GEN" >/dev/null 2>&1 8>&- 9>&-
    else sh "$KS_ROOT/ss/ssconfig.sh" "$action" "$NODE" "$GEN" >/dev/null 2>&1 8>&- 9>&-;fi
    rc=$?
    [ "$rc" -eq 75 ] && return 75
    [ "$(private_read generation)" = "$GEN" ] && [ "$(get ss_basic_enable)" = 1 ] && [ "$(get ss_basic_failover_enable)" = 1 ] || return 75
    actual=$(current_node)
    if [ "$action" = failover-switch ];then
      # Selection can land before startup fails. Adopt only this action's ID;
      # an unrelated manual selection invalidates the result instead.
      if [ "$actual" = "$target" ];then NODE=$target
      elif [ "$actual" != "$NODE" ] || [ "$rc" -eq 0 ];then return 75;fi
      [ "$rc" -ne 0 ] || [ "$(mode)" = proxy ] || return 1
    elif [ "$rc" -eq 0 ];then
      [ "$actual" = "$NODE" ] || return 75
      [ "$(mode)" = direct ] || return 1
    fi
    return "$rc"
}
best_result() {
    awk 'NR==1 || $3<ms || ($3==ms && $1<id){id=$1;ms=$3}END{if(NR)print id,ms}' "$STATE_DIR/results"
}
discard_winner() {
    local failed=$1 next rc=0
    "$FLOCK" -x 8 || return 1
    METADATA_LOCKED=1
    if ! alive;then rc=75
    elif ! { awk -v id="$failed" '$1!=id' "$STATE_DIR/results" > "$STATE_DIR/results.$$" && mv -f "$STATE_DIR/results.$$" "$STATE_DIR/results"; };then rc=1
    else
      rm -f "$STATE_DIR/winner" || rc=1
      if [ "$rc" = 0 ];then write_state recover_count 0 && write_state recover_node 0 || rc=$?;fi
      if [ "$rc" = 0 ];then next=$(best_result) || rc=1;fi
      if [ "$rc" = 0 ] && [ -n "$next" ];then
        set -- $next
        # A backup starts fresh confirmations; another node's failure cannot
        # turn an old scan success into its final recovery confirmation.
        write_state winner "$1 $2" && write_state recover_node "$1" || rc=$?
      fi
    fi
    METADATA_LOCKED=0
    "$FLOCK" -u 8
    [ "$rc" = 0 ] || return "$rc"
    alive || return 75
    if [ -n "$next" ];then set -- $next;publish recovering winner_changed "$1" "$2"
    else scan;fi
}
recover_winner() {
    local best=$1 last_ms=$2 successes previous changed now rc
    # A completed scan survives budget boundaries. Confirm only its winner on
    # following ticks rather than needlessly rescanning every country again.
    if [ $((END_AT-$(date +%s))) -lt $((3*TIMEOUT+8)) ];then publish recovering winner_recheck "$best" "$last_ms";return;fi
    probe_candidate "$best";rc=$?
    alive || return 75
    if [ "$rc" = 2 ];then publish error probe_port_busy "$best" "$last_ms";return 1;fi
    if [ "$rc" -ne 0 ];then discard_winner "$best";return $?;fi
    previous=$(private_read recover_node);successes=$(counter recover_count)
    if [ "$previous" = "$best" ];then successes=$((successes+1));else successes=1;fi
    write_state recover_node "$best" && write_state recover_count "$successes" || return 1
    changed=$(counter changed_at);now=$(date +%s)
    if [ "$successes" -lt "$RECOVERIES" ];then publish recovering recovery_confirmation "$best" "$PROBE_MS";return;fi
    if [ "$changed" -gt 0 ] && [ $((now-changed)) -lt "$COOLDOWN" ];then publish cooldown switch_cooldown "$best" "$PROBE_MS";return;fi
    service_action failover-switch "$best";rc=$?
    [ "$rc" -ne 75 ] || return 75
    if [ "$rc" -ne 0 ];then clear_scan;publish error switch_failed;return 1;fi
    clear_scan;write_state failures 0;write_state recover_count 0;write_state changed_at "$(date +%s)"
    publish switched candidate_selected "$best" "$PROBE_MS"
}
scan() {
    local identity phase cursor total id code rc best best_ms rest scanned state
    identity=$(printf '%s\n' "$GEN|$NODE|$COUNTRY|$CANDIDATES|$COUNTRY_MAP|$TIMEOUT" | md5sum | awk '{print $1}')
    if [ "$(private_read scan_identity)" != "$identity" ];then
      clear_scan;collect || { publish error candidate_limit;return 1; }
      phase_queue same || return 1
      write_state scan_identity "$identity" || return 1
    fi
    best=$(private_read winner)
    if [ -n "$best" ];then set -- $best;recover_winner "$1" "$2";return;fi
    while alive; do
      phase=$(private_read phase);cursor=$(counter cursor)
      total=$(wc -l < "$STATE_DIR/queue" 2>/dev/null | tr -d ' ')
      case "$total" in ''|*[!0-9]*) return 75 ;; esac
      while [ "$cursor" -lt "$total" ];do
        rest=$((END_AT-$(date +%s)))
        [ "$rest" -ge $((3*TIMEOUT+8)) ] || break
        id=$(awk -v n=$((cursor+1)) 'NR==n{print $1}' "$STATE_DIR/queue")
        code=$(awk -v n=$((cursor+1)) 'NR==n{print $2}' "$STATE_DIR/queue")
        probe_candidate "$id";rc=$?
        alive || return 75
        if [ "$rc" = 2 ];then publish error probe_port_busy 0 null "$cursor" "$total";return 1;fi
        [ "$rc" -ne 0 ] || printf '%s %s %s\n' "$id" "$code" "$PROBE_MS" >> "$STATE_DIR/results"
        cursor=$((cursor+1));write_state cursor "$cursor" || return 1
      done
      if [ "$cursor" -lt "$total" ];then
        state=scanning_proxy;[ "$(mode)" != direct ] || state=scanning_direct
        [ "$(mode)" != error ] || state=error
        publish "$state" candidate_scan 0 null "$cursor" "$total";return
      fi
      best=$(best_result)
      if [ -n "$best" ];then
        set -- $best;best=$1;best_ms=$2
        write_state winner "$best $best_ms" || return 1
        write_state recover_node "$best" && write_state recover_count 1 || return 1
        if [ "$RECOVERIES" -gt 1 ];then publish recovering recovery_confirmation "$best" "$best_ms" "$cursor" "$total";return;fi
        recover_winner "$best" "$best_ms";return
      fi
      if [ "$phase" = same ];then phase_queue other || return 1;continue;fi
      clear_scan;write_state recover_count 0
      if [ "$DIRECT" = 1 ] && [ "$(mode)" != direct ];then service_action failover-direct;rc=$?;[ "$rc" -ne 75 ] || return 75;fi
      if [ "$(mode)" = direct ];then publish direct all_candidates_failed 0 null "$cursor" "$total"
      else publish error all_candidates_failed 0 null "$cursor" "$total";fi
      return
    done
    return 75
}
tick() {
    "$FLOCK" -n 9 || return 0
    NODE=$(current_node)
    "$FLOCK" -x 8 || return 1
    METADATA_LOCKED=1
    GEN=$(private_read generation)
    if [ -z "$GEN" ];then write_state generation "$(date +%s).$$" || return 1;GEN=$(private_read generation);fi
    METADATA_LOCKED=0
    "$FLOCK" -u 8
    case "$GEN" in ''|*[!A-Za-z0-9._-]*) return 1 ;; esac
    [ "${#GEN}" -le 64 ] || return 1
    PREFERRED=$COUNTRY;[ "$PREFERRED" != auto ] || PREFERRED=$(country_for "$NODE")
    if [ "$ENABLED" != 1 ] || [ "$(get ss_basic_enable)" != 1 ] || ! valid_id "$NODE" ||
       [ "$(get ss_basic_type)" != 4 ] || [ "$(get ss_basic_trojan_binary)" != AnyTLS ];then
      UNCONDITIONAL=1;clear_scan;publish disabled disabled;return
    fi
    END_AT=$(($(date +%s)+BUDGET))
    if [ "$(mode)" = proxy ];then
      if probe_targets 127.0.0.1:23456;then
        alive || return 75
        write_state failures 0;write_state recover_count 0;clear_scan
        publish healthy current_healthy;return
      fi
      alive || return 75
      local failures rc
      failures=$(counter failures);failures=$((failures+1));write_state failures "$failures" || return 1
      if [ "$failures" -lt "$FAILURES" ];then publish confirming current_failed;return;fi
      if [ "$DIRECT" = 1 ];then
        service_action failover-direct;rc=$?
        [ "$rc" -ne 75 ] || return 75
        [ "$rc" -eq 0 ] || publish error direct_failed
      fi
    fi
    scan
}

# Validation is intentionally pure: service calls it before legacy DBus eval.
case "${1:-tick}" in validate) settings || { printf '%s\n' 'Invalid failover settings.' >&2;exit 2; };exit 0 ;; esac
. "$KS_ROOT/scripts/ss_dns_hooks.sh"
if ! settings;then
  # Stopping must always invalidate an in-flight controller, even when the
  # saved settings are malformed. No malformed value reaches public status.
  [ "${1:-tick}" = reset ] || { printf '%s\n' 'Invalid failover settings.' >&2;exit 2; }
  ENABLED=0;COUNTRY=auto;COUNTRY_MAP=
fi
# Expose only the fixed RAM JSON destination. Never replace a foreign file or
# link; a concurrent initializer creating the same target is harmless.
STATUS_LINK="$KS_ROOT/res/ss-failover-status.js"
[ -d "$KS_ROOT/res" ] && [ ! -L "$KS_ROOT/res" ] && [ ! -L "$PUBLIC_JSON" ] || exit 1
{ [ ! -e "$PUBLIC_JSON" ] || [ -f "$PUBLIC_JSON" ]; } || exit 1
if [ ! -L "$STATUS_LINK" ] && [ ! -e "$STATUS_LINK" ];then
  ln -s "$PUBLIC_JSON" "$STATUS_LINK" 2>/dev/null || :
fi
[ -L "$STATUS_LINK" ] && [ "$(readlink "$STATUS_LINK")" = "$PUBLIC_JSON" ] || exit 1
[ -x "$FLOCK" ] && [ ! -L "$STATE_DIR" ] && mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR" || exit 1
for name in commit.lock tick.lock;do [ ! -L "$STATE_DIR/$name" ] || exit 1;done
exec 8>"$STATE_DIR/commit.lock"
exec 9>"$STATE_DIR/tick.lock"
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
case "${1:-tick}" in
  tick) tick ;;
  reset)
    "$FLOCK" -x 8 || exit 1
    METADATA_LOCKED=1;RESETTING=1
    write_state generation "$(date +%s).$$" || exit 1
    clear_scan;write_state failures 0;write_state recover_count 0;write_state changed_at 0
    GEN=$(private_read generation)
    METADATA_LOCKED=0;RESETTING=0
    "$FLOCK" -u 8
    NODE=$(current_node)
    PREFERRED=$COUNTRY;[ "$PREFERRED" != auto ] || PREFERRED=$(country_for "$NODE")
    UNCONDITIONAL=1
    if [ "$ENABLED" = 1 ] && [ "$(get ss_basic_enable)" = 1 ] && valid_id "$NODE" &&
       [ "$(get ss_basic_type)" = 4 ] && [ "$(get ss_basic_trojan_binary)" = AnyTLS ];then publish confirming reset
    else publish disabled disabled;fi ;;
  status) [ ! -L "$PUBLIC_JSON" ] && [ -f "$PUBLIC_JSON" ] && cat "$PUBLIC_JSON" ;;
  *) printf '%s\n' 'Usage: ss_failover.sh validate|tick|reset|status' >&2;exit 2 ;;
esac
