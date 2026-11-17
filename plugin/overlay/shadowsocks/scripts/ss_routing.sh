#!/bin/sh

# Routing helpers for the Merlin 380 daily-use profile. No configuration is
# evaluated here: MAC input is validated before ssconfig's legacy dbus export.

ss_routing_normalize_macs() {
	LC_ALL=C awk '
	{
		gsub(/,/, "\n")
		count = split($0, parts, "\n")
		for (i = 1; i <= count; i++) {
			mac = parts[i]
			gsub(/^[ \t\r]+|[ \t\r]+$/, "", mac)
			if (mac == "") continue
			if (length(mac) != 17 || mac !~ /^[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]$/) {
				invalid = 1
				continue
			}
			mac = toupper(mac)
			if (mac == "00:00:00:00:00:00" || index("13579BDF", substr(mac, 2, 1))) {
				invalid = 1
				continue
			}
			if (!seen[mac]++) {
				macs[++total] = mac
				if (total > 32) invalid = 1
			}
		}
	}
	END {
		if (invalid) exit 1
		for (i = 1; i <= total; i++) print macs[i]
	}'
}

ss_routing_load_bypass_macs() {
	local raw_macs
	raw_macs=$(dbus get ss_basic_bypass_macs 2>/dev/null)
	SS_ROUTING_BYPASS_MACS=$(printf '%s\n' "$raw_macs" | ss_routing_normalize_macs) || return 1
	raw_macs=$(dbus get ss_basic_uu_macs 2>/dev/null)
	SS_ROUTING_UU_MACS=$(printf '%s\n' "$raw_macs" | ss_routing_normalize_macs) || return 1
	local uu_mac
	for uu_mac in $SS_ROUTING_UU_MACS; do
		printf '%s\n' "$SS_ROUTING_BYPASS_MACS" | grep -Fqx "$uu_mac" && return 1
	done
	ss_routing_load_uu_tcp_policy || return 1
	ss_routing_load_uu_interval || return 1
	return 0
}

ss_routing_load_uu_interval() {
	local value
	value=$(dbus get ss_basic_uu_interval 2>/dev/null)
	[ -n "$value" ] || value=5
	case "$value" in *[!0-9]*|'') return 1 ;; esac
	[ "${#value}" -le 2 ] && [ "$value" -ge 2 ] && [ "$value" -le 30 ] || return 1
	SS_ROUTING_UU_INTERVAL=$value
}

ss_routing_load_uu_tcp_policy() {
	local raw_policy
	raw_policy=$(dbus get ss_basic_uu_tcp_policy 2>/dev/null)
	case "$raw_policy" in
		'') SS_ROUTING_UU_TCP_POLICY=gfwlist ;;
		gfwlist|foreign|direct) SS_ROUTING_UU_TCP_POLICY=$raw_policy ;;
		*) return 1 ;;
	esac
}

ss_routing_uu_target_chain() {
	case "${SS_ROUTING_UU_TCP_POLICY:-gfwlist}" in
		gfwlist) printf '%s\n' SHADOWSOCKS_GFW ;;
		foreign) printf '%s\n' SHADOWSOCKS_CHN ;;
		direct) printf '%s\n' RETURN ;;
		*) return 1 ;;
	esac
}

ss_routing_is_anytls() {
	[ "$ss_basic_type" = "4" ] && [ "$ss_basic_trojan_binary" = "AnyTLS" ]
}

ss_routing_add_mac_returns() {
	local table="$1"
	local chain="$2"
	local protocol="$3"
	local profile_macs="${4-$SS_ROUTING_BYPASS_MACS}"
	local bypass_mac
	for bypass_mac in $profile_macs; do
		iptables -t "$table" -A "$chain" -p "$protocol" \
			-m mac --mac-source "$bypass_mac" -j RETURN || return 1
	done
}

ss_routing_add_uu_tcp_routes() {
	local uu_mac target_chain
	target_chain=$(ss_routing_uu_target_chain) || return 1
	for uu_mac in $SS_ROUTING_UU_MACS; do
		if [ "$target_chain" = RETURN ]; then
			iptables -t nat -A SHADOWSOCKS -p tcp -m mac --mac-source "$uu_mac" \
				-j RETURN || return 1
			continue
		fi
		# Start fail-closed for UU while discovering its policy-route targets.
		iptables -t nat -A SHADOWSOCKS -p tcp -m mac --mac-source "$uu_mac" \
			-j RETURN || return 1
		iptables -t nat -A SHADOWSOCKS -p tcp -m mac --mac-source "$uu_mac" \
			-g "$target_chain" || return 1
	done
	[ "$target_chain" != RETURN ] || return 0
	ss_routing_update_uu_tcp_bypasses
}

ss_routing_uu_set_name() {
	printf 'fssuu_%s' "$(printf '%s' "$1" | tr -d ':')"
}

ss_routing_uu_main_position() {
	# Accept only the exact rules generated here; never delete foreign rules.
	iptables -t nat -S SHADOWSOCKS 2>/dev/null | awk -v mac="$1" -v target="$2" '
		$1 == "-A" && $2 == "SHADOWSOCKS" {
			position++
			if (NF == 10 && $3 == "-p" && $4 == "tcp" && $5 == "-m" && $6 == "mac" && $7 == "--mac-source" && toupper($8) == mac &&
				(($9 == "-g" && ($10 == "SHADOWSOCKS_CHN" || $10 == "SHADOWSOCKS_GFW") && (target == "GOTO" || $10 == target)) ||
				 ($9 == "-j" && target == "RETURN" && $10 == "RETURN"))) {
				print position; exit
			}
		}'
}

ss_routing_uu_set_position() {
	iptables -t nat -S SHADOWSOCKS 2>/dev/null | awk -v mac="$1" -v name="$2" '
		$1=="-A" && $2=="SHADOWSOCKS" {
			position++
			if (NF==15 && $3=="-p" && $4=="tcp" && $5=="-m" && $6=="mac" && $7=="--mac-source" && toupper($8)==mac &&
				$9=="-m" && $10=="set" && $11=="--match-set" && $12==name && $13=="dst" && $14=="-j" && $15=="RETURN") {print position;exit}
		}'
}

ss_routing_uu_policy_tables() {
	# Source-specific, unmarked policy routes are UU's TCP destinations. Its
	# separate fwmark rule/default table handles UDP and must not be imported.
	awk -v source="$1" '
		{
			matches=0; marked=0
			for (i=1;i<NF;i++) {
				if ($i == "from" && ($(i+1) == source || $(i+1) == source "/32")) matches=1
				if ($i == "fwmark") marked=1
			}
			if (!matches || marked) next
			if (NF != 5 || $1 !~ /^[0-9]+:$/ || $2 != "from" || $4 != "lookup" || $5 !~ /^[0-9]+$/ || length($5) > 10 || $5+0 < 1 || $5+0 > 4294967295) {bad=1; next}
			if (!seen[$5]++) tables[++count]=$5
		}
		END {if (bad || count > 16) exit 2; if (!count) exit 1; for (i=1;i<=count;i++) print tables[i]}'
}

ss_routing_uu_route_cidrs() {
	# Kernel route output is data, never shell input. Validate all destinations
	# before emitting any restore commands; an unsupported row fails closed.
	awk '
		function ipv4(value, a,n,i) {
			if (value !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 0
			n=split(value,a,".")
			for (i=1;i<=n;i++) if (length(a[i]) > 3 || a[i]+0 > 255) return 0
			return n==4
		}
		NF {
			if ($1 == "default") next
			n=split($1,parts,"/")
			if (n > 2 || !ipv4(parts[1]) || (n == 2 && (parts[2] !~ /^[0-9]+$/ || length(parts[2]) > 2 || parts[2]+0 > 32))) {bad=1; next}
			if (n == 2 && parts[2]+0 == 0) next
			prefix=(n == 1 ? 32 : parts[2]+0)
			split(parts[1],octets,".")
			cidr=sprintf("%d.%d.%d.%d/%d",octets[1],octets[2],octets[3],octets[4],prefix)
			if (!seen[cidr]++) cidrs[++count]=cidr
		}
		END {if (bad || count > 65536) exit 1; for (i=1;i<=count;i++) print cidrs[i]}'
}

ss_routing_update_uu_tcp_bypasses() {
	local uu_mac set_name goto_position guard_position uu_ip tables table found_tables
	local state rules_file routes_file cidrs_file restore_file prerouting_file temp_set parse_rc have_mapping have_claim target_chain set_position valid_guard
	target_chain=$(ss_routing_uu_target_chain) || return 1
	if [ "$target_chain" = RETURN ]; then
		ss_routing_sync_uu_policy_routes
		return
	fi
	state=${SS_ROUTING_UU_STATE:-/tmp/ss_uu_routing}
	for uu_mac in $SS_ROUTING_UU_MACS; do
		goto_position=$(ss_routing_uu_main_position "$uu_mac" "$target_chain")
		[ -n "$goto_position" ] || continue
		set_name=$(ss_routing_uu_set_name "$uu_mac")
		set_position=$(ss_routing_uu_set_position "$uu_mac" "$set_name")
		valid_guard=0
		# The kernel keeps an ipset alive while this exact rule references it.
		if [ -n "$set_position" ] && [ "$set_position" -lt "$goto_position" ]; then
			valid_guard=1
			# Keep the active set/rule throughout discovery and atomic swap.
			while iptables -t nat -D SHADOWSOCKS -p tcp -m mac --mac-source "$uu_mac" -j RETURN >/dev/null 2>&1; do :; done
		else
			guard_position=$(ss_routing_uu_main_position "$uu_mac" RETURN)
			if [ -z "$guard_position" ] || [ "$guard_position" -ge "$goto_position" ]; then
				iptables -t nat -I SHADOWSOCKS "$goto_position" -p tcp -m mac --mac-source "$uu_mac" -j RETURN || return 1
			fi
			while iptables -t nat -D SHADOWSOCKS -p tcp -m mac --mac-source "$uu_mac" \
				-m set --match-set "$set_name" dst -j RETURN >/dev/null 2>&1; do :; done
		fi
		[ ! -L "$state" ] && (umask 077; mkdir -p "$state") && chmod 700 "$state" || continue
		rules_file="$state/rules.$$"
		routes_file="$state/routes.$$"
		cidrs_file="$state/cidrs.$$"
		restore_file="$state/restore.$$"
		prerouting_file="$state/prerouting.$$"
		if ! (umask 077; ip rule show > "$rules_file"); then rm -f "$rules_file"; continue; fi
		if ! (umask 077; iptables -t nat -S PREROUTING > "$prerouting_file"); then rm -f "$rules_file" "$prerouting_file"; continue; fi
		(umask 077; : > "$cidrs_file"; : > "$routes_file"; : > "$restore_file") || continue
		found_tables=0
		have_mapping=0
		have_claim=0
		for uu_ip in $(ss_routing_uu_ipv4_for_mac "$uu_mac"); do
			have_mapping=1
			[ -z "$(ss_routing_uu_return_position_from_rules "$uu_ip" < "$prerouting_file")" ] || have_claim=1
			if tables=$(ss_routing_uu_policy_tables "$uu_ip" < "$rules_file"); then :; else
				parse_rc=$?
				if [ "$parse_rc" = 2 ]; then have_claim=1; found_tables=0; break; fi
				continue
			fi
			have_claim=1
			found_tables=1
			for table in $tables; do
				if ! ip route show table "$table" > "$routes_file" ||
					! ss_routing_uu_route_cidrs < "$routes_file" >> "$cidrs_file"; then
					found_tables=0
					break
				fi
			done
			[ "$found_tables" = 1 ] || break
		done
		if [ "$have_mapping" = 1 ] && [ "$have_claim" = 0 ]; then
			# UU is explicitly inactive for this device. Keep YouTube working
			# through the existing MAC CHN route, rather than bypassing all TCP.
			while iptables -t nat -D SHADOWSOCKS -p tcp -m mac --mac-source "$uu_mac" \
				-j RETURN >/dev/null 2>&1; do :; done
			while iptables -t nat -D SHADOWSOCKS -p tcp -m mac --mac-source "$uu_mac" \
				-m set --match-set "$set_name" dst -j RETURN >/dev/null 2>&1; do :; done
			ipset destroy "$set_name" >/dev/null 2>&1 || true
			rm -f "$state/$set_name.cidrs"
			rm -f "$rules_file" "$routes_file" "$cidrs_file" "$restore_file" "$prerouting_file"
			continue
		fi
		if [ "$found_tables" != 1 ] || [ ! -s "$cidrs_file" ]; then
			rm -f "$rules_file" "$routes_file" "$cidrs_file" "$restore_file" "$prerouting_file"
			continue
		fi
		temp_set="${set_name}_t"
		ipset destroy "$temp_set" >/dev/null 2>&1 || true
		(umask 077
			printf 'create %s hash:net family inet hashsize 1024 maxelem 65536\n' "$temp_set"
			awk -v name="$temp_set" '!seen[$0]++ {print "add " name " " $0}' "$cidrs_file"
		) > "$restore_file"
		if ipset restore < "$restore_file" >/dev/null 2>&1 &&
			ipset -! create "$set_name" hash:net family inet hashsize 1024 maxelem 65536 >/dev/null 2>&1 &&
			ipset swap "$temp_set" "$set_name" >/dev/null 2>&1; then
			guard_position=$(ss_routing_uu_main_position "$uu_mac" RETURN)
			if [ "$valid_guard" != 1 ] && [ -n "$guard_position" ]; then
				iptables -t nat -R SHADOWSOCKS "$guard_position" -p tcp -m mac --mac-source "$uu_mac" \
					-m set --match-set "$set_name" dst -j RETURN || return 1
			fi
			chmod 600 "$cidrs_file"
			mv -f "$cidrs_file" "$state/$set_name.cidrs"
		fi
		ipset destroy "$temp_set" >/dev/null 2>&1 || true
		rm -f "$rules_file" "$routes_file" "$cidrs_file" "$restore_file" "$prerouting_file"
	done
	return 0
}

ss_routing_clear_uu_sets() {
	local state entry set_name uu_mac suffix
	state=${SS_ROUTING_UU_STATE:-/tmp/ss_uu_routing}
	[ ! -L "$state" ] || return 0
	for uu_mac in $SS_ROUTING_UU_MACS; do
		set_name=$(ss_routing_uu_set_name "$uu_mac")
		ipset destroy "${set_name}_t" >/dev/null 2>&1 || true
		ipset destroy "$set_name" >/dev/null 2>&1 || true
	done
	for entry in "$state"/fssuu_*.cidrs; do
		[ -f "$entry" ] || continue
		set_name=${entry##*/}
		set_name=${set_name%.cidrs}
		case "$set_name" in fssuu_????????????) ;; *) continue ;; esac
		case "${set_name#fssuu_}" in *[!0-9A-F]*) continue ;; esac
		ipset destroy "${set_name}_t" >/dev/null 2>&1 || true
		ipset destroy "$set_name" >/dev/null 2>&1 || true
		rm -f "$entry"
	done
	for entry in "$state"/rules.* "$state"/routes.* "$state"/cidrs.* "$state"/restore.* "$state"/prerouting.*; do
		suffix=${entry##*.}
		case "$suffix" in ''|*[!0-9]*) continue ;; esac
		[ ! -f "$entry" ] || rm -f "$entry"
	done
	rmdir "$state" 2>/dev/null || true
}

ss_routing_uu_ipv4_for_mac() {
	local wanted_mac="$1"
	{
		ip neigh show dev br0 2>/dev/null | awk -v mac="$wanted_mac" '
			{for (i=1;i<NF;i++) if ($i == "lladdr" && toupper($(i+1)) == mac) print $1}'
		if [ -r /var/lib/misc/dnsmasq.leases ]; then
			awk -v mac="$wanted_mac" 'toupper($2) == mac {print $3}' /var/lib/misc/dnsmasq.leases
		fi
	} | awk '
		/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
			n=split($0, octets, "."); valid=(n==4)
			for (i=1;i<=n;i++) if (octets[i] > 255 || length(octets[i]) > 3) valid=0
			if (valid && !seen[$0]++) print
		}'
}

ss_routing_uu_return_position() {
	iptables -t nat -S PREROUTING 2>/dev/null | ss_routing_uu_return_position_from_rules "$1"
}

ss_routing_uu_return_position_from_rules() {
	awk -v source="$1/32" '
		$1 == "-A" && $2 == "PREROUTING" {
			position++
			if (NF == 8 && $3 == "-s" && $4 == source && $5 == "-i" && $6 == "br0" && $7 == "-j" && $8 == "RETURN") {
				print position; exit
			}
		}'
}

ss_routing_uu_jumps() {
	iptables -t nat -S PREROUTING 2>/dev/null | awk '
		$1 == "-A" && $2 == "PREROUTING" {
			position++
			if (NF == 12 && $3 == "-i" && $4 == "br0" && $5 == "-p" && $6 == "tcp" && $7 == "-m" && $8 == "mac" && $9 == "--mac-source" && $11 == "-j" && $12 == "SHADOWSOCKS")
				print position, toupper($10)
		}'
}

ss_routing_remove_uu_mac_jump() {
	while iptables -t nat -D PREROUTING -i br0 -p tcp -m mac \
		--mac-source "$1" -j SHADOWSOCKS >/dev/null 2>&1; do :; done
}

ss_routing_sync_uu_policy_routes() {
	# Only edit exact MAC rules generated by this helper. The temporary RETURN
	# guard remains in place until the UU destination set has been refreshed.
	local uu_mac target_chain goto_position return_position old_chain set_name
	target_chain=$(ss_routing_uu_target_chain) || return 1
	for uu_mac in $SS_ROUTING_UU_MACS; do
		goto_position=$(ss_routing_uu_main_position "$uu_mac" GOTO)
		return_position=$(ss_routing_uu_main_position "$uu_mac" RETURN)
		if [ "$target_chain" = RETURN ]; then
			if [ -z "$return_position" ] || { [ -n "$goto_position" ] && [ "$return_position" -ge "$goto_position" ]; }; then
				iptables -t nat -I SHADOWSOCKS "${goto_position:-1}" -p tcp -m mac \
					--mac-source "$uu_mac" -j RETURN || return 1
			fi
			for old_chain in SHADOWSOCKS_CHN SHADOWSOCKS_GFW; do
				while iptables -t nat -D SHADOWSOCKS -p tcp -m mac --mac-source "$uu_mac" \
					-g "$old_chain" >/dev/null 2>&1; do :; done
			done
			set_name=$(ss_routing_uu_set_name "$uu_mac")
			while iptables -t nat -D SHADOWSOCKS -p tcp -m mac --mac-source "$uu_mac" \
				-m set --match-set "$set_name" dst -j RETURN >/dev/null 2>&1; do :; done
			ss_routing_remove_uu_mac_jump "$uu_mac"
		elif [ -n "$goto_position" ]; then
			iptables -t nat -R SHADOWSOCKS "$goto_position" -p tcp -m mac \
				--mac-source "$uu_mac" -g "$target_chain" || return 1
			for old_chain in SHADOWSOCKS_CHN SHADOWSOCKS_GFW; do
				[ "$old_chain" != "$target_chain" ] || continue
				while iptables -t nat -D SHADOWSOCKS -p tcp -m mac --mac-source "$uu_mac" \
					-g "$old_chain" >/dev/null 2>&1; do :; done
			done
		elif [ -n "$return_position" ]; then
			# Switching from the direct profile: keep its RETURN until set refresh.
			iptables -t nat -I SHADOWSOCKS "$((return_position+1))" -p tcp -m mac \
				--mac-source "$uu_mac" -g "$target_chain" || return 1
		fi
	done
}

ss_routing_reconcile_uu() {
	# UU puts terminal per-device RETURN rules after its own DNATs. A global
	# appended jump cannot reach those devices. Locate their current IPv4 only
	# to identify that exact RETURN; the inserted exception remains MAC based.
	local uu_mac uu_ip return_position found_position current_positions old_mac target_chain
	target_chain=$(ss_routing_uu_target_chain) || return 1
	ss_routing_sync_uu_policy_routes || return 1
	if [ "$target_chain" = RETURN ]; then
		for old_mac in $(ss_routing_uu_jumps | awk '{print $2}' | ss_routing_normalize_macs); do
			ss_routing_remove_uu_mac_jump "$old_mac"
		done
		ss_routing_clear_uu_sets
		return 0
	fi
	ss_routing_update_uu_tcp_bypasses || return 1
	for old_mac in $(ss_routing_uu_jumps | awk '{print $2}' | ss_routing_normalize_macs); do
		printf '%s\n' "$SS_ROUTING_UU_MACS" | grep -Fqx "$old_mac" || ss_routing_remove_uu_mac_jump "$old_mac"
	done
	for uu_mac in $SS_ROUTING_UU_MACS; do
		if [ -z "$(ss_routing_uu_main_position "$uu_mac" "$target_chain")" ]; then
			# A newly saved profile may precede its service restart. Do not
			# bypass UU's terminal RETURN until this MAC has its owned route.
			ss_routing_remove_uu_mac_jump "$uu_mac"
			continue
		fi
		found_position=0
		for uu_ip in $(ss_routing_uu_ipv4_for_mac "$uu_mac"); do
			return_position=$(ss_routing_uu_return_position "$uu_ip")
			if [ -n "$return_position" ]; then
				found_position=1
				current_positions=$(ss_routing_uu_jumps | awk -v mac="$uu_mac" '$2 == mac {print $1}')
				if [ "$current_positions" != "$((return_position-1))" ]; then
					ss_routing_remove_uu_mac_jump "$uu_mac"
					return_position=$(ss_routing_uu_return_position "$uu_ip")
					[ -n "$return_position" ] || break
					iptables -t nat -I PREROUTING "$return_position" -i br0 -p tcp \
						-m mac --mac-source "$uu_mac" -j SHADOWSOCKS || return 1
				fi
				break
			fi
		done
		if [ "$found_position" = 0 ]; then
			ss_routing_remove_uu_mac_jump "$uu_mac"
			if [ "${1:-0}" = 1 ]; then
				logger -t fancyss 'UU coexistence: no matching LAN IPv4/UU RETURN was found; skipped the scoped TCP exception.'
			fi
		fi
	done
}

ss_routing_add_prerouting_jump() {
	ss_routing_reconcile_uu 1 || return 1
	# Other devices still give every existing accelerator/DNAT hook priority.
	iptables -t nat -A PREROUTING -p tcp -j SHADOWSOCKS
}

ss_routing_remove_jumps() {
	local table="$1"
	local chain="$2"
	local wanted_target="$3"
	iptables -t "$table" -S "$chain" 2>/dev/null | while IFS= read -r owned_rule; do
		case "$owned_rule" in "-A $chain "*) ;; *) continue ;; esac
		target=${owned_rule##* }
		if [ "$wanted_target" = "SHADOWSOCKS_DNS_" ]; then
			case "$target" in SHADOWSOCKS_DNS_*) ;; *) continue ;; esac
			bridge_number=${target#SHADOWSOCKS_DNS_}
			case "$bridge_number" in ''|*[!0-9]*) continue ;; esac
		else
			[ "$target" = "$wanted_target" ] || continue
		fi
		# Rules generated by this plugin contain plain iptables tokens. Split
		# them as arguments, never execute/evaluate text or delete by row index.
		set -f
		set -- $owned_rule
		shift 2
		iptables -t "$table" -D "$chain" "$@" >/dev/null 2>&1
	done
}

ss_routing_remove_output_rules() {
	# Never flush OUTPUT: UU and other router plugins may own rules there.
	while iptables -t nat -D OUTPUT -p tcp -m set --match-set router dst \
		-j REDIRECT --to-ports 3333 >/dev/null 2>&1; do :; done
	ss_routing_remove_jumps nat OUTPUT SHADOWSOCKS_EXT
}

ss_routing_remove_dns_rules() {
	ss_routing_remove_jumps nat PREROUTING SHADOWSOCKS_DNS_
	iptables -t nat -S 2>/dev/null | while read -r operation chain rest; do
		[ "$operation" = "-N" ] || continue
		case "$chain" in SHADOWSOCKS_DNS_*) ;; *) continue ;; esac
		bridge_number=${chain#SHADOWSOCKS_DNS_}
		case "$bridge_number" in ''|*[!0-9]*) continue ;; esac
		iptables -t nat -F "$chain" >/dev/null 2>&1
		iptables -t nat -X "$chain" >/dev/null 2>&1
	done
}

ss_routing_watch_allowed() {
	[ "$(dbus get ss_basic_enable 6>&- 7>&- 8>&- 9>&-)" = 1 ] || return 1
	case "$(cat /tmp/ss_failover/mode 2>/dev/null 6>&- 7>&- 8>&- 9>&-)" in proxy|'') return 0 ;; *) return 1 ;; esac
}

ss_routing_watch_snapshot() {
	local rules mac address selected tables table
	rules=$(ip rule show 2>/dev/null) || return 1
	printf 'profiles:%s|%s|%s\n%s\n' "$SS_ROUTING_UU_TCP_POLICY" "$SS_ROUTING_UU_MACS" "$SS_ROUTING_BYPASS_MACS" "$rules"
	iptables -t nat -S PREROUTING 2>/dev/null || return 1
	iptables -t mangle -S PREROUTING 2>/dev/null || return 1
	iptables -t nat -S SHADOWSOCKS 2>/dev/null || return 1
	tables=
	for mac in $SS_ROUTING_UU_MACS; do
		for address in $(ss_routing_uu_ipv4_for_mac "$mac"); do
			printf 'mapping:%s:%s\n' "$mac" "$address"
			selected=$(printf '%s\n' "$rules" | ss_routing_uu_policy_tables "$address") || selected=
			tables="$tables $selected"
		done
	done
	for table in $(printf '%s\n' "$tables" | tr ' ' '\n' | awk 'NF && !seen[$0]++'); do
		printf 'table:%s\n' "$table"
		ip route show table "$table" 2>/dev/null || return 1
	done
}

ss_routing_watch_digest() {
	local snapshot
	snapshot=$(ss_routing_watch_snapshot) || return 1
	printf '%s\n' "$snapshot" | md5sum | awk '{print $1}'
}

ss_routing_watch_finish() {
	local rc=$?
	trap - EXIT HUP INT TERM
	if [ "${SS_ROUTING_WATCH_CORE_LOCKED:-0}" = 1 ]; then "$SS_ROUTING_WATCH_FLOCK" -u 7 >/dev/null 2>&1; fi
	exec 7>&-
	if [ "${SS_ROUTING_WATCH_LOCKED:-0}" = 1 ]; then
		rm -f "$SS_ROUTING_WATCH_DIR/pid"
		"$SS_ROUTING_WATCH_FLOCK" -u 6 >/dev/null 2>&1
	fi
	exec 6>&-
	exit "$rc"
}

ss_routing_watch() {
	local digest previous= state
	umask 077
	SS_ROUTING_WATCH_FLOCK=${SS_ROUTING_WATCH_FLOCK:-/koolshare/bin/ss-flock}
	SS_ROUTING_WATCH_DIR=${SS_ROUTING_WATCH_STATE:-/tmp/ss_uu_watch}
	SS_ROUTING_WATCH_LOCKED=0
	SS_ROUTING_WATCH_CORE_LOCKED=0
	# Never retain locks inherited from a service/controller launcher.
	exec 7>&- 8>&- 9>&-
	ss_routing_watch_allowed || return 0
	[ ! -L "$SS_ROUTING_WATCH_DIR" ] && mkdir -p "$SS_ROUTING_WATCH_DIR" && chmod 700 "$SS_ROUTING_WATCH_DIR" || return 1
	for state in lock pid digest; do [ ! -L "$SS_ROUTING_WATCH_DIR/$state" ] || return 1; done
	exec 6>"$SS_ROUTING_WATCH_DIR/lock"
	"$SS_ROUTING_WATCH_FLOCK" -n 6 || { exec 6>&-; return 0; }
	SS_ROUTING_WATCH_LOCKED=1
	trap ss_routing_watch_finish EXIT
	trap 'exit 129' HUP
	trap 'exit 130' INT
	trap 'exit 143' TERM
	printf '%s\n' "$$" > "$SS_ROUTING_WATCH_DIR/pid"
	while ss_routing_watch_allowed; do
		ss_routing_load_bypass_macs || return 1
		[ -n "$SS_ROUTING_UU_MACS" ] || return 0
		exec 7>/var/lock/koolss.lock
		if "$SS_ROUTING_WATCH_FLOCK" -n 7; then
			SS_ROUTING_WATCH_CORE_LOCKED=1
			if ss_routing_watch_allowed && ss_routing_load_bypass_macs && [ -n "$SS_ROUTING_UU_MACS" ]; then
				if digest=$(trap - EXIT HUP INT TERM; ss_routing_watch_digest 6>&- 7>&- 8>&- 9>&-) && [ "$digest" != "$previous" ]; then
					if (trap - EXIT HUP INT TERM; exec 6>&- 7>&- 8>&- 9>&-; ss_routing_reconcile_uu); then
						# A UU firewall rebuild may also move/remove the optional
						# DNS filter hook. Repair only its owned chain, under this
						# service lock; failure leaves normal DNS available.
						if [ -x /koolshare/scripts/ss_adblock.sh ] && [ "$(dbus get ss_basic_adblock_enable 6>&- 7>&- 8>&- 9>&-)" = 1 ]; then
							sh /koolshare/scripts/ss_adblock.sh reconcile 5>&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 || :
						fi
						# Keep the pre-reconcile digest: a concurrent UU rebuild
						# must still trigger the following pass. Our own entry
						# repair may cause one additional pass, then settles.
						previous=$digest
						printf '%s\n' "$digest" > "$SS_ROUTING_WATCH_DIR/digest"
					fi
				fi
			fi
			"$SS_ROUTING_WATCH_FLOCK" -u 7
			SS_ROUTING_WATCH_CORE_LOCKED=0
		fi
		exec 7>&-
		sleep "$SS_ROUTING_UU_INTERVAL" 6>&- 7>&- 8>&- 9>&-
	done
}

if [ "${1:-}" = reconcile-uu ] || [ "${1:-}" = watch-uu ]; then
	PATH=/koolshare/bin:/usr/sbin:/usr/bin:/sbin:/bin
	export PATH
	if [ "$1" = watch-uu ]; then ss_routing_watch; exit $?; fi
	[ "$(dbus get ss_basic_enable)" = 1 ] || exit 0
	exec 7>/var/lock/koolss.lock
	/koolshare/bin/ss-flock -n 7 || exit 0
	trap '/koolshare/bin/ss-flock -u 7 >/dev/null 2>&1; exec 7>&-' EXIT
	[ "$(dbus get ss_basic_enable)" = 1 ] || exit 0
	case "$(cat /tmp/ss_failover/mode 2>/dev/null)" in direct|error) exit 0 ;; esac
	iptables -t nat -S SHADOWSOCKS >/dev/null 2>&1 || exit 0
	ss_routing_load_bypass_macs || exit 1
	ss_routing_reconcile_uu
fi
