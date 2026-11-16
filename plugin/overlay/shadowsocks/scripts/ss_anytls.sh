#!/bin/sh
# Keep the legacy client usable for rollback while sharing the enhanced defaults.
KS_ROOT=${SS_ANYTLS_KOOLSHARE:-/koolshare}
CLIENT="$KS_ROOT/bin/anytls"
PATH="$KS_ROOT/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
export PATH
normalize_hosts() {
  printf '%s' "$1" | SS_ANYTLS_MAP_HOST="${2:-}" SS_ANYTLS_MAP_MODE="${3:-0}" LC_ALL=C awk '
  function trim(s) { sub(/^[ \t\r]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
  function host(s, labels,n,i,label) {
    s=tolower(trim(s))
    if (s ~ /^[0-9.]+$/) {
      n=split(s,labels,"."); if(n!=4) return ""
      for(i=1;i<=n;i++) if(labels[i]!~/^[0-9]+$/ || length(labels[i])>3 || (length(labels[i])>1 && substr(labels[i],1,1)=="0") || labels[i]+0>255) return ""
      return s
    }
    sub(/\.$/,"",s)
    if(length(s)<1 || length(s)>253 || s!~/^[a-z0-9.-]+$/) return ""
    n=split(s,labels,".")
    for(i=1;i<=n;i++) {
      label=labels[i]
      if(length(label)<1 || length(label)>63 || label!~/^[a-z0-9]/ || label!~/[a-z0-9]$/) return ""
    }
    return s
  }
  {
    count=split($0,items,",")
    for(j=1;j<=count;j++) {
      item=trim(items[j]); if(item=="") continue
      if(++entries>32 || split(item,pair,"=")!=2) { bad=1; exit 2 }
      key=host(pair[1]); value=host(pair[2])
      if(key=="" || value=="" || (key in map && map[key]!=value)) { bad=1; exit 2 }
      if(!(key in map)) order[++size]=key
      map[key]=value
    }
  }
  END {
    if(bad) exit 2
    for(i=1;i<=size;i++) {
      current=order[i]; hops=0
      while(current in map) {
        if(++hops>4) exit 2
        current=map[current]
      }
    }
    if(ENVIRON["SS_ANYTLS_MAP_MODE"]=="1") {
      current=host(ENVIRON["SS_ANYTLS_MAP_HOST"])
      if(current=="") exit 2
      for(i=0;i<4 && current in map;i++) current=map[current]
      printf "%s",current
      exit 0
    }
    for(i=1;i<=size;i++) printf "%s%s=%s", (i==1?"":","),order[i],map[order[i]]
  }'
}
invalid_hosts() {
  printf '%s\n' 'ss_anytls: invalid hosts mapping' >&2
  exit 2
}
# These utility commands must never probe/start the client or read node secrets.
case "${1:-}" in
  normalize-hosts)
    [ "$#" -eq 2 ] || invalid_hosts
    normalize_hosts "$2" || invalid_hosts
    exit 0
    ;;
  validate-hosts)
    [ "$#" -eq 1 ] || invalid_hosts
    hosts_raw=$(dbus get ss_basic_anytls_hosts) || invalid_hosts
    normalize_hosts "$hosts_raw" >/dev/null || invalid_hosts
    exit 0
    ;;
  map-host)
    [ "$#" -eq 2 ] || invalid_hosts
    hosts_raw=$(dbus get ss_basic_anytls_hosts) || invalid_hosts
    normalize_hosts "$hosts_raw" "$2" 1 || invalid_hosts
    exit 0
    ;;
esac
hosts_raw=$(dbus get ss_basic_anytls_hosts) || invalid_hosts
hosts=$(normalize_hosts "$hosts_raw") || invalid_hosts
# Rotate positional parameters once, preserving exact quoting and argument order.
# Only a value of the exact -s flag is eligible; password/SNI values stay opaque.
remaining=$#
next_value=''
parsing=1
while [ "$remaining" -gt 0 ]; do
  argument=$1
  shift
  if [ "$next_value" = server ]; then
    case "$argument" in
      ''|*[!a-zA-Z0-9.:-]*) ;;
      *)
        mapped=$(printf '%s\n' "$argument" | LC_ALL=C awk -v entries="$hosts" '
          BEGIN { n=split(entries,pairs,","); for(i=1;i<=n;i++) if(split(pairs[i],pair,"=")==2) map[pair[1]]=pair[2] }
          {
            if(split($0,server,":")!=2 || server[2]!~/^[0-9]+$/ || length(server[2])>5 || server[2]+0<1 || server[2]+0>65535) exit
            key=tolower(server[1]); sub(/\.$/,"",key)
            if(!(key in map)) exit
            for(i=0;i<4 && key in map;i++) key=map[key]
            printf "%s",key
          }')
        [ -z "$mapped" ] || argument="$mapped:${argument##*:}"
        ;;
    esac
    next_value=''
  elif [ "$next_value" = opaque ]; then
    next_value=''
  elif [ "$parsing" -eq 1 ]; then
    case "$argument" in
      -s) next_value=server ;;
      -p|-sni|-m|-l|-socks|-nat|-alpn|-fingerprint|-handshake-timeout|-idle-check|-idle-timeout) next_value=opaque ;;
      --) parsing=0 ;;
      -*) ;;
      *) parsing=0 ;;
    esac
  fi
  set -- "$@" "$argument"
  remaining=$((remaining-1))
done
number() {
  value=$(dbus get "$1")
  case "$value" in ''|*[!0-9]*) value="$2" ;; esac
  if [ "${#value}" -gt 3 ] || [ "$value" -lt "$3" ] || [ "$value" -gt "$4" ]; then value="$2"; fi
  printf '%s' "$value" | awk '{printf "%d",$1}'
}
minimum=$(number ss_basic_anytls_min_idle 0 0 20)
idle_check=$(number ss_basic_anytls_idle_check 30 5 300)
idle_timeout=$(number ss_basic_anytls_idle_timeout 30 5 600)
handshake=$(number ss_basic_anytls_handshake 8 3 20)
alpn=$(dbus get ss_basic_anytls_alpn)
case "$alpn" in
  auto) alpn='' ;;
  h2|http/1.1|h2,http/1.1|http/1.1,h2) ;;
  *) alpn=h2 ;;
esac
fingerprint=$(dbus get ss_basic_anytls_fingerprint)
case "$fingerprint" in chrome|standard) ;; *) fingerprint=chrome ;; esac
case "${SS_ANYTLS_INSECURE:-1}" in 0|false) insecure=false ;; *) insecure=true ;; esac
version=$("$CLIENT" -version 2>/dev/null)
case "$version" in
  *-r7000.3*)
    exec "$CLIENT" -m "$minimum" -idle-check "${idle_check}s" -idle-timeout "${idle_timeout}s" -handshake-timeout "${handshake}s" -alpn "$alpn" -fingerprint "$fingerprint" "-insecure=$insecure" "$@"
    ;;
  *-r7000.2*)
    exec "$CLIENT" -m "$minimum" -handshake-timeout "${handshake}s" -alpn "$alpn" -fingerprint "$fingerprint" "-insecure=$insecure" "$@"
    ;;
  *-r7000.*)
    exec "$CLIENT" -m "$minimum" -handshake-timeout "${handshake}s" -alpn "$alpn" "-insecure=$insecure" "$@"
    ;;
  *) exec "$CLIENT" -m "$minimum" "$@" ;;
esac
