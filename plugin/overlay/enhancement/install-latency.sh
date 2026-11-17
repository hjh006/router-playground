#!/bin/sh
# Install only the independent latency TCP probe, launcher, script and capability descriptor.
KS_ROOT=/koolshare
PACKAGE=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 1
PAYLOAD="$PACKAGE/payload"
umask 077
fail() { printf '%s\n' "$1" >&2; exit 1; }
for file in scripts/ss_anytls.sh scripts/ss_dns_hooks.sh bin/ss-https-probe bin/ss-flock ss/rules/cacert.pem; do
    [ -f "$KS_ROOT/$file" ] || fail 'The existing enhanced AnyTLS plugin is required.'
done
[ -d "$KS_ROOT/bin" ] && [ ! -L "$KS_ROOT/bin" ] &&
    [ -d "$KS_ROOT/scripts" ] && [ ! -L "$KS_ROOT/scripts" ] &&
    [ -d "$KS_ROOT/res" ] && [ ! -L "$KS_ROOT/res" ] || fail 'Unexpected plugin directory.'
for file in bin/ss-tcp-probe bin/ss_latency.sh scripts/ss_latency.sh res/ss-latency-capabilities.js; do
    [ -f "$PAYLOAD/$file" ] && [ ! -L "$PAYLOAD/$file" ] && [ ! -L "$KS_ROOT/$file" ] || fail 'Unexpected measurement file.'
done
sh -n "$PAYLOAD/bin/ss_latency.sh" && sh -n "$PAYLOAD/scripts/ss_latency.sh" || fail 'Invalid measurement script.'
(cd "$PAYLOAD" && md5sum -c "$PACKAGE/manifest.md5") >/dev/null 2>&1 || fail 'Measurement payload checksum failed.'
chmod 755 "$PAYLOAD/bin/ss-tcp-probe" && "$PAYLOAD/bin/ss-tcp-probe" -h >/dev/null 2>&1 || fail 'Cannot run TCP measurement tool.'
BACKUP="$PACKAGE/latency-backup.$$"
mkdir -m 700 "$BACKUP" || fail 'Cannot create temporary backup.'
for file in bin/ss-tcp-probe bin/ss_latency.sh scripts/ss_latency.sh res/ss-latency-capabilities.js; do
    if [ -e "$KS_ROOT/$file" ]; then
        [ -f "$KS_ROOT/$file" ] || fail 'Unexpected existing measurement path.'
        mkdir -p "$BACKUP/$(dirname "$file")" && cp -p "$KS_ROOT/$file" "$BACKUP/$file" || fail 'Cannot back up measurement file.'
    fi
done
CHANGED=0 SUCCESS=0
finish() {
    local rc=$?
    trap - EXIT HUP INT TERM
    if [ "$CHANGED" = 1 ] && [ "$SUCCESS" != 1 ]; then
        for file in bin/ss-tcp-probe bin/ss_latency.sh scripts/ss_latency.sh res/ss-latency-capabilities.js; do
            if [ -f "$BACKUP/$file" ]; then cp -p "$BACKUP/$file" "$KS_ROOT/$file"; else rm -f "$KS_ROOT/$file"; fi
        done
    fi
    rm -f "$KS_ROOT/bin/.ss-tcp-probe.new.$$" "$KS_ROOT/bin/.ss_latency.new.$$" "$KS_ROOT/scripts/.ss_latency.new.$$" "$KS_ROOT/res/.ss-latency-capabilities.new.$$"
    rm -rf "$BACKUP"
    exit "$rc"
}
trap finish EXIT
trap 'exit 1' HUP INT TERM
cp "$PAYLOAD/bin/ss-tcp-probe" "$KS_ROOT/bin/.ss-tcp-probe.new.$$" &&
    chmod 755 "$KS_ROOT/bin/.ss-tcp-probe.new.$$" &&
    cp "$PAYLOAD/bin/ss_latency.sh" "$KS_ROOT/bin/.ss_latency.new.$$" &&
    chmod 755 "$KS_ROOT/bin/.ss_latency.new.$$" &&
    cp "$PAYLOAD/scripts/ss_latency.sh" "$KS_ROOT/scripts/.ss_latency.new.$$" &&
    chmod 755 "$KS_ROOT/scripts/.ss_latency.new.$$" &&
    cp "$PAYLOAD/res/ss-latency-capabilities.js" "$KS_ROOT/res/.ss-latency-capabilities.new.$$" &&
    chmod 644 "$KS_ROOT/res/.ss-latency-capabilities.new.$$" || fail 'Cannot stage measurement files.'
CHANGED=1
mv -f "$KS_ROOT/bin/.ss-tcp-probe.new.$$" "$KS_ROOT/bin/ss-tcp-probe" &&
    mv -f "$KS_ROOT/bin/.ss_latency.new.$$" "$KS_ROOT/bin/ss_latency.sh" &&
    mv -f "$KS_ROOT/scripts/.ss_latency.new.$$" "$KS_ROOT/scripts/ss_latency.sh" &&
    mv -f "$KS_ROOT/res/.ss-latency-capabilities.new.$$" "$KS_ROOT/res/ss-latency-capabilities.js" || fail 'Cannot install measurement files.'
sh "$KS_ROOT/scripts/ss_latency.sh" status >/dev/null || fail 'Cannot initialize measurement status.'
SUCCESS=1
printf '%s\n' 'Router latency component installed. Existing services and configuration were not changed.'
