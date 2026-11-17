#!/bin/sh
# Bounded HTTPS probes and a RAM-only twenty-round history. No credentials exported.
KS_ROOT=${SS_HEALTH_KOOLSHARE:-/koolshare}
STATE_DIR=${SS_HEALTH_STATE:-/tmp/ss_health}
PUBLIC_JSON=${SS_HEALTH_JSON:-/tmp/ss_health.json}
FLOCK="$KS_ROOT/bin/ss-flock"
HTTPS_PROBE="$KS_ROOT/bin/ss-https-probe"
[ -x "$FLOCK" ] || { printf '%s\n' 'Health prerequisite missing: ss-flock' >&2; exit 1; }
PATH="$KS_ROOT/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
export PATH
INTERVAL=30
PROBE_TIMEOUT=10
CONNECT_TIMEOUT=5
FAILURE_THRESHOLD=3
umask 077
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
# Never unlink lock files: flock ownership belongs to the open file description.
exec 8> "$STATE_DIR/commit.lock"
exec 9> "$STATE_DIR/probe.lock"
finish() {
  result=$?
  trap - 0 HUP INT TERM
  # Explicit unlock matters when descendants outlive the shell: the private
  # helper locks inherited open-file descriptions, not process-local handles.
  "$FLOCK" -u 8 >/dev/null 2>&1 || :
  "$FLOCK" -u 9 >/dev/null 2>&1 || :
  exec 8>&- 9>&-
  rm -f "$STATE_DIR/targets.$$" "$STATE_DIR/latencies.$$" "$STATE_DIR/history.$$" "$STATE_DIR/state.$$"
  exit "$result"
}
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

read_settings() {
  node=$(dbus get ssconf_basic_node)
  case "$node" in ''|*[!0-9]*) node=0 ;; esac
  enabled=$(dbus get ss_basic_enable)
  [ "$enabled" = 1 ] && enabled=true || enabled=false
  value=$(dbus get ss_basic_health_interval)
  case "$value" in 30|60|120) INTERVAL=$value ;; *) INTERVAL=30 ;; esac
  value=$(dbus get ss_basic_health_timeout)
  case "$value" in 6|8|10) PROBE_TIMEOUT=$value ;; *) PROBE_TIMEOUT=10 ;; esac
  CONNECT_TIMEOUT=$PROBE_TIMEOUT
  value=$(dbus get ss_basic_health_failures)
  case "$value" in 1|2|3|4|5) FAILURE_THRESHOLD=$value ;; *) FAILURE_THRESHOLD=3 ;; esac
  if [ "$(readlink "$KS_ROOT/res/ss-health-status.js" 2>/dev/null)" != "$PUBLIC_JSON" ]; then
    ln -sf "$PUBLIC_JSON" "$KS_ROOT/res/ss-health-status.js"
  fi
}

new_generation() {
  printf '%s-%s\n' "$(date +%s)" "$$" > "$STATE_DIR/generation"
  rm -f "$STATE_DIR/history" "$STATE_DIR/state"
}

publish() {
  tmp=$("$FLOCK" mktemp "$STATE_DIR/json.XXXXXX") || return 1
  cat > "$tmp"
  chmod 644 "$tmp"
  mv -f "$tmp" "$PUBLIC_JSON"
}

initial() {
  printf '{"version":1,"enabled":%s,"node_id":%s,"checked_at":0,"interval_sec":%s,"status":"checking","total":0,"success":0,"last_latency_ms":null,"median_ms":null,"p95_ms":null,"jitter_ms":null,"consecutive_failures":0,"targets":[]}\n' "$enabled" "$node" "$INTERVAL" | publish
  if [ "$enabled" = true ]; then legacy='国外连接 - 检测中'; else legacy='国外连接 - 未启用'; fi
  nvram set "ss_foreign_state=$legacy"
}

case "${1:-refresh}" in
  reset|stop)
    "$FLOCK" -x 8 || exit 1
    read_settings
    new_generation
    [ "$1" = stop ] && enabled=false
    initial
    "$FLOCK" -u 8
    if [ "$1" = reset ]; then
      "$0" refresh 8>&- 9>&- >/dev/null 2>&1 &
    fi
    exit 0
    ;;
esac

# FD 9 covers only one probe worker. FD 8 protects short metadata transactions,
# so reset/stop can invalidate an in-flight worker without waiting for its probes.
"$FLOCK" -n 9 || exit 0
"$FLOCK" -x 8 || exit 1
read_settings
if [ "$enabled" = false ]; then new_generation; initial; exit 0; fi
oldnode=0 oldfail=0 oldchecked=0
if [ -f "$STATE_DIR/state" ]; then read -r oldnode oldfail oldchecked < "$STATE_DIR/state"; fi
for value in "$oldnode" "$oldfail" "$oldchecked"; do
  case "$value" in ''|*[!0-9]*) oldnode=0 oldfail=0 oldchecked=0; break ;; esac
done
now=$(date +%s)
if [ "$node" = "$oldnode" ] && [ "${1:-refresh}" != force ] && [ $((now-oldchecked)) -ge 0 ] && [ $((now-oldchecked)) -lt "$INTERVAL" ]; then exit 0; fi
generation=$(cat "$STATE_DIR/generation" 2>/dev/null)
if [ -z "$generation" ]; then
  generation="$now-$$"
  printf '%s\n' "$generation" > "$STATE_DIR/generation"
fi
if [ "$node" != "$oldnode" ]; then
  oldfail=0
  rm -f "$STATE_DIR/history"
  initial
fi
"$FLOCK" -u 8
: > "$STATE_DIR/targets.$$"
: > "$STATE_DIR/latencies.$$"

probe() {
  id="$1" label="$2" url="$3" method="$4"
  if [ -x "$HTTPS_PROBE" ]; then
    set -- "$HTTPS_PROBE" -proxy 127.0.0.1:23456 -ca "$KS_ROOT/ss/rules/cacert.pem" \
      -target "$id" -timeout "${PROBE_TIMEOUT}s" -format curl
  else
    # Only absence selects the legacy backend; never retry a TLS failure via
    # another implementation or disable destination certificate verification.
    set -- curl --cacert "$KS_ROOT/ss/rules/cacert.pem" --socks5-hostname 127.0.0.1:23456 --connect-timeout "$CONNECT_TIMEOUT" --max-time "$PROBE_TIMEOUT" -sS -o /dev/null --write-out '%{http_code}|%{time_total}' "$url"
    [ "$method" = HEAD ] && set -- "$@" -I
  fi
  metrics=$("$@" 8>&- 9>&- 2>/dev/null)
  rc=$?
  http=${metrics%%|*} seconds=${metrics#*|}
  case "$http" in [0-9][0-9][0-9]) ;; *) http=000 ;; esac
  state=network_error latency=null
  case "$rc" in
    0)
      case "$http" in
        200|204|301|302|307|308)
          state=ok
          latency=$(printf '%s\n' "$seconds" | awk '/^[0-9]+([.][0-9]+)?$/ {printf "%.0f",$1*1000}')
          [ -n "$latency" ] || latency=null
          ;;
        *) state=http_error ;;
      esac
      ;;
    28) state=timeout ;;
    6) state=dns_error ;;
    35|51|60) state=tls_error ;;
    2|58|59|77|126|127) state=local_error ;;
  esac
  [ "$state" = ok ] && [ "$latency" != null ] && echo "$latency" >> "$STATE_DIR/latencies.$$"
  printf '{"id":"%s","label":"%s","state":"%s","latency_ms":%s,"http_code":%s}\n' "$id" "$label" "$state" "$latency" "$((http+0))" >> "$STATE_DIR/targets.$$"
}

if ! netstat -nl 2>/dev/null | grep -Eq '[:.]23456[[:space:]]'; then
  printf '{"id":"proxy","label":"节点连接","state":"proxy_unavailable","latency_ms":null,"http_code":0}\n' > "$STATE_DIR/targets.$$"
else
  probe google 'Google HTTPS' https://www.gstatic.com/generate_204 GET
  probe youtube 'YouTube HTTPS' https://www.youtube.com/generate_204 GET
  probe telegram 'Telegram HTTPS' https://telegram.org/ HEAD
fi

# A node switch or restart invalidates in-flight results instead of mixing histories.
"$FLOCK" -x 8 || exit 1
[ "$(dbus get ss_basic_enable)" = 1 ] || exit 0
[ "$(dbus get ssconf_basic_node)" = "$node" ] || exit 0
[ "$(cat "$STATE_DIR/generation" 2>/dev/null)" = "$generation" ] || exit 0
checked=$(date +%s)
passed=$(grep -c '"state":"ok"' "$STATE_DIR/targets.$$")
status=degraded full=0
if [ "$passed" -eq 3 ]; then status=healthy; full=1; fi
if [ "$passed" -eq 0 ]; then failures=$((oldfail+1)); else failures=0; fi
if [ "$failures" -ge "$FAILURE_THRESHOLD" ] || grep -q proxy_unavailable "$STATE_DIR/targets.$$"; then status=down; fi
last=null
if [ -s "$STATE_DIR/latencies.$$" ]; then
  last=$(sort -n "$STATE_DIR/latencies.$$" | awk '{a[NR]=$1} END {n=NR; if(n%2) print a[(n+1)/2]; else printf "%.0f\n",(a[n/2]+a[n/2+1])/2}')
fi
printf '%s %s %s\n' "$checked" "$last" "$full" >> "$STATE_DIR/history" || exit 1
tail -n 20 "$STATE_DIR/history" > "$STATE_DIR/history.$$" || exit 1
mv -f "$STATE_DIR/history.$$" "$STATE_DIR/history" || exit 1
stats=$(awk '{total++;success+=$3;if($2!="null"){if(n){delta=$2-prev;if(delta<0)delta=-delta;jitter+=delta;}a[++n]=$2;prev=$2;}} END {for(i=1;i<=n;i++)for(j=i+1;j<=n;j++)if(a[j]<a[i]){t=a[i];a[i]=a[j];a[j]=t;}median="null";p95="null";jit="null";if(n){if(n%2)median=a[(n+1)/2];else median=int((a[n/2]+a[n/2+1])/2+0.5);p95=a[int((n*95+99)/100)];}if(n>1)jit=int(jitter/(n-1)+0.5);printf "\"total\":%d,\"success\":%d,\"median_ms\":%s,\"p95_ms\":%s,\"jitter_ms\":%s",total,success,median,p95,jit;}' "$STATE_DIR/history")
targets=$(awk 'BEGIN{sep=""}{printf "%s%s",sep,$0;sep=","}' "$STATE_DIR/targets.$$")
printf '{"version":1,"enabled":true,"node_id":%s,"checked_at":%s,"interval_sec":%s,"status":"%s",%s,"last_latency_ms":%s,"consecutive_failures":%s,"targets":[%s]}\n' "$node" "$checked" "$INTERVAL" "$status" "$stats" "$last" "$failures" "$targets" | publish || exit 1
printf '%s %s %s\n' "$node" "$failures" "$checked" > "$STATE_DIR/state.$$" || exit 1
mv -f "$STATE_DIR/state.$$" "$STATE_DIR/state" || exit 1
display_time=$(date '+%Y-%m-%d %H:%M:%S')
case "$status" in
  healthy) legacy="国外连接 【$display_time】 ✓ ${last} ms" ;;
  degraded) legacy="国外连接 【$display_time】 部分检测未通过" ;;
  *) legacy="国外连接 【$display_time】 连续检测未通过" ;;
esac
nvram set "ss_foreign_state=$legacy"
"$FLOCK" -u 8
