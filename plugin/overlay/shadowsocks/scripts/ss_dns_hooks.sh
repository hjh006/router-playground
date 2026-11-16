#!/bin/sh

SS_DNS_STATE=/jffs/.fancyss-dns
SS_DNS_HOOK=/jffs/scripts/dnsmasq.postconf
SS_DNS_TEMPLATE=/koolshare/ss/rules/dnsmasq.postconf

ss_dns_is_owned_wrapper() {
	[ -f "$SS_DNS_STATE/wrapper" ] && [ -f "$SS_DNS_HOOK" ] &&
		[ ! -L "$SS_DNS_HOOK" ] && cmp -s "$SS_DNS_HOOK" "$SS_DNS_STATE/wrapper"
}

ss_dns_is_legacy_hook() {
	if [ -L "$SS_DNS_HOOK" ]; then
		[ "$(readlink "$SS_DNS_HOOK")" = "$SS_DNS_TEMPLATE" ]
	elif [ -f "$SS_DNS_HOOK" ]; then
		cmp -s "$SS_DNS_HOOK" "$SS_DNS_TEMPLATE" ||
			[ "$(md5sum "$SS_DNS_HOOK" | awk '{print $1}')" = "a81c872b4165bcace3d87fd6cb940887" ]
	else
		return 1
	fi
}

ss_dns_previous_matches() {
	if [ -L "$SS_DNS_STATE/previous.postconf" ]; then
		[ -L "$SS_DNS_HOOK" ] &&
			[ "$(readlink "$SS_DNS_HOOK")" = "$(readlink "$SS_DNS_STATE/previous.postconf")" ]
	else
		[ ! -L "$SS_DNS_HOOK" ] && cmp -s "$SS_DNS_HOOK" "$SS_DNS_STATE/previous.postconf"
	fi
}

ss_dns_clear_state() {
	rm -f "$SS_DNS_STATE/wrapper" "$SS_DNS_STATE/previous.kind" \
		"$SS_DNS_STATE/previous.postconf" "$SS_DNS_STATE/previous.run" \
		"$SS_DNS_STATE/install" "$SS_DNS_STATE/restore"
	rmdir "$SS_DNS_STATE" 2>/dev/null || true
}

ss_dns_hooks_remove() {
	if [ -L "$SS_DNS_STATE" ]; then
		printf '%s\n' 'DNS ownership directory is a symlink; preserved existing files.' >&2
		return 1
	fi
	if [ ! -f "$SS_DNS_STATE/wrapper" ]; then
		# Migrate only the known old Science hook, never an unknown shared hook.
		ss_dns_is_legacy_hook && rm -f "$SS_DNS_HOOK"
		return 0
	fi
	if ! ss_dns_is_owned_wrapper; then
		printf '%s\n' 'DNS hook was changed externally; preserved it and the private backup.' >&2
		return 0
	fi
	case "$(cat "$SS_DNS_STATE/previous.kind" 2>/dev/null)" in
		external)
			if [ ! -e "$SS_DNS_STATE/previous.postconf" ] && [ ! -L "$SS_DNS_STATE/previous.postconf" ]; then
				printf '%s\n' 'Previous DNS hook backup is missing; refusing an unsafe restore.' >&2
				return 1
			fi
			cp -a "$SS_DNS_STATE/previous.postconf" "$SS_DNS_STATE/restore" || return 1
			mv -f "$SS_DNS_STATE/restore" "$SS_DNS_HOOK" || return 1
			;;
		absent|legacy) rm -f "$SS_DNS_HOOK" || return 1 ;;
		*) printf '%s\n' 'Invalid DNS hook ownership state; preserved existing files.' >&2; return 1 ;;
	esac
	ss_dns_clear_state
}

ss_dns_hooks_install() {
	ss_dns_is_owned_wrapper && return 0
	if [ -L "$SS_DNS_STATE" ] || [ -e "$SS_DNS_STATE/wrapper" ] || [ -L "$SS_DNS_STATE/wrapper" ] ||
		[ -e "$SS_DNS_STATE/previous.kind" ] || [ -L "$SS_DNS_STATE/previous.kind" ] ||
		[ -e "$SS_DNS_STATE/previous.postconf" ] || [ -L "$SS_DNS_STATE/previous.postconf" ]; then
		printf '%s\n' 'DNS hook ownership changed; preserved it and any existing backup.' >&2
		return 1
	fi
	[ -f "$SS_DNS_TEMPLATE" ] || return 1
	mkdir -p /jffs/scripts "$SS_DNS_STATE" || return 1
	chmod 700 "$SS_DNS_STATE" || return 1
	local previous_kind=absent
	if ss_dns_is_legacy_hook; then
		previous_kind=legacy
	elif [ -e "$SS_DNS_HOOK" ] || [ -L "$SS_DNS_HOOK" ]; then
		[ ! -d "$SS_DNS_HOOK" ] || return 1
		if [ -x "$SS_DNS_HOOK" ]; then
			local first_line
			IFS= read -r first_line < "$SS_DNS_HOOK"
			case "$first_line" in
				'#!/bin/sh'|'#!/bin/ash') ;;
				*) printf '%s\n' 'Nonstandard DNS hook interpreter/options; preserved the hook without replacing it.' >&2; return 1 ;;
			esac
		fi
		cp -a "$SS_DNS_HOOK" "$SS_DNS_STATE/previous.postconf" || return 1
		if [ -x "$SS_DNS_HOOK" ]; then
			cp -pL "$SS_DNS_HOOK" "$SS_DNS_STATE/previous.run" || return 1
		fi
		previous_kind=external
	fi
	(umask 077
	printf '%s\n' "$previous_kind" > "$SS_DNS_STATE/previous.kind"
	cat > "$SS_DNS_STATE/wrapper" <<'SS_DNS_WRAPPER'
#!/bin/sh
# fancyss-managed-dns-postconf-v1
science_rc=0
/koolshare/ss/rules/dnsmasq.postconf "$@" || science_rc=$?
previous_rc=0
if [ -x /jffs/.fancyss-dns/previous.run ]; then
	# Preserve the original hook's $0 and positional arguments. Run it last,
	# so this plugin cannot erase changes made by UU or a user-owned hook.
	/bin/sh -c 'previous_script=$1; shift; . "$previous_script"' \
		/jffs/scripts/dnsmasq.postconf /jffs/.fancyss-dns/previous.run "$@" || previous_rc=$?
fi
[ "$previous_rc" -eq 0 ] || exit "$previous_rc"
exit "$science_rc"
SS_DNS_WRAPPER
	) || return 1
	case "$previous_kind" in
		external) ss_dns_previous_matches || return 1 ;;
		legacy) ss_dns_is_legacy_hook || return 1 ;;
		absent) [ ! -e "$SS_DNS_HOOK" ] && [ ! -L "$SS_DNS_HOOK" ] || return 1 ;;
	esac
	cp "$SS_DNS_STATE/wrapper" "$SS_DNS_STATE/install" || return 1
	chmod 755 "$SS_DNS_STATE/install" || return 1
	mv -f "$SS_DNS_STATE/install" "$SS_DNS_HOOK"
}

ss_dns_remove_link() {
	local link="$1"
	local target="$2"
	[ -L "$link" ] && [ "$(readlink "$link")" = "$target" ] && rm -f "$link"
	return 0
}

ss_dns_clear_fragment_links() {
	ss_dns_remove_link /jffs/configs/dnsmasq.d/custom.conf /tmp/custom.conf
	ss_dns_remove_link /jffs/configs/dnsmasq.d/wblist.conf /tmp/wblist.conf
	ss_dns_remove_link /jffs/configs/dnsmasq.d/cdn.conf /tmp/sscdn.conf
	ss_dns_remove_link /jffs/configs/dnsmasq.d/gfwlist.conf /tmp/gfwlist.conf
	ss_dns_remove_link /jffs/configs/dnsmasq.d/gfwlist.conf /koolshare/ss/rules/gfwlist.conf
	ss_dns_remove_link /jffs/configs/dnsmasq.d/ss_host.conf /tmp/ss_host.conf
	ss_dns_remove_link /jffs/configs/dnsmasq.d/fancyss-server.conf /tmp/fancyss-server.conf
}

ss_dns_install_link() {
	local target="$1"
	local link="$2"
	if [ -e "$link" ] || [ -L "$link" ]; then
		if [ ! -L "$link" ] || [ "$(readlink "$link")" != "$target" ]; then
			printf '%s\n' 'A DNS fragment is owned by another configuration; preserved it.' >&2
			return 1
		fi
	fi
	ln -sf "$target" "$link"
}

ss_dns_write_server_config() {
	printf 'server=/%s/%s#53\n' "$1" "$2" > /tmp/fancyss-server.conf || return 1
	ss_dns_install_link /tmp/fancyss-server.conf /jffs/configs/dnsmasq.d/fancyss-server.conf
}
