import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1] / "shadowsocks"
HELPER = ROOT / "scripts/ss_routing.sh"
SOURCE = (Path(os.environ.get("SS_ROUTING_SOURCE_ROOT", ROOT)) / "ss/ssconfig.sh").read_text()
MACS = "02:00:00:00:00:01\n02:00:00:00:00:02"

MOCK = r'''#!/usr/bin/env python3
import fcntl, json, os, pathlib, shlex, sys
p=pathlib.Path(os.environ['MOCK_STATE'])
s=json.loads(p.read_text()); cmd=pathlib.Path(sys.argv[0]).name; a=sys.argv[1:]
with open(os.environ['MOCK_LOG'],'a') as f:f.write(json.dumps([cmd]+a)+'\n')
def finish(rc=0):p.write_text(json.dumps(s));sys.exit(rc)
if cmd=='logger':finish()
if cmd=='ss-https-probe':
 if '-resolve' not in a:finish(2)
 if s.get('bootstrap_dns_fail'):finish(1)
 for address in s.get('bootstrap_addresses',['203.0.113.7']):print(address)
 finish()
if cmd=='ss-flock':
 if s.get('locked'):finish(1)
 try:fcntl.flock(int(a[-1]),fcntl.LOCK_UN if '-u' in a else fcntl.LOCK_EX|(fcntl.LOCK_NB if '-n' in a else 0))
 except BlockingIOError:finish(1)
 finish()
if cmd=='ipset':
 if s.get('ipset_unavailable'):finish(127)
 sets=s.setdefault('sets',{})
 if a[0]=='restore':
  for line in sys.stdin.read().splitlines():
   tokens=shlex.split(line)
   if tokens[0]=='create':sets[tokens[1]]=[]
   elif tokens[0]=='add':sets[tokens[1]].append(tokens[2])
  finish(1 if s.get('restore_fail') else 0)
 if a[:2]==['-!','create']:
  sets.setdefault(a[2],[]);finish()
 if a[0]=='destroy':
  if a[1] not in sets:finish(1)
  del sets[a[1]];finish()
 if a[0]=='swap':
  if s.get('swap_fail'):finish(1)
  sets[a[1]],sets[a[2]]=sets[a[2]],sets[a[1]];finish()
 finish(1)
if cmd=='dbus':
 if a[0]=='get':print(s.get('dbus',{}).get(a[1],''));finish()
 if a[0]=='list':
  for k,v in s.get('dbus',{}).items():
   if k.startswith(a[1]):print(k+'='+v)
 finish()
if cmd=='ifconfig':
 if not a:print('br0 Link encap:Ethernet\nbr1 Link encap:Ethernet')
 else:print('          inet addr:192.168.'+('50' if a[0]=='br0' else '51')+'.1  Bcast:192.168.50.255')
 finish()
if cmd=='nvram':
 if a[0]=='get':print(s.get('nvram',{}).get(a[1],''))
 finish()
if cmd=='ip':
 if a==['rule','show']:
  if s.get('rule_read_fail'):finish(1)
  for line in s.get('rule_output',[]):print(line)
  finish()
 if a[:4]==['route','show','table',a[-1]]:
  if a[-1] in s.get('route_fail_tables',[]):finish(1)
  for line in s.get('routes',{}).get(a[-1],[]):print(line)
  finish()
 if a[:2]==['neigh','show']:
  for line in s.get('neighbours',[]):print(line)
  finish()
 if a[:2]==['rule','del']:
  if a[2:] in s['ip_rules']:s['ip_rules'].remove(a[2:]);finish()
  finish(1)
 finish()
if cmd!='iptables':finish(1)
table='filter'
if '-t' in a:
 i=a.index('-t');table=a[i+1];a=a[:i]+a[i+2:]
t=s['tables'][table];op=a[0];chain=a[1] if len(a)>1 else None
if op=='-S':
 names=[chain] if chain else list(t)
 for name in names:
  if name not in t:finish(1)
  print('-P '+name+' ACCEPT' if name in ['OUTPUT','PREROUTING','FORWARD'] else '-N '+name)
  for rule in t[name]:print(shlex.join(['-A',name]+rule))
 sys.exit(0)
if op=='-N':
 if chain in t:finish(1)
 t[chain]=[];finish()
if op=='-F':
 if chain is None:
  for c in t:t[c]=[]
 elif chain in t:t[chain]=[]
 else:finish(1)
 finish()
if op=='-X':
 if chain not in t or t[chain]:finish(1)
 if any(rule[-2:]==['-j',chain] for rules in t.values() for rule in rules):finish(1)
 del t[chain];finish()
if op=='-A':
 if chain not in t:finish(1)
 t[chain].append(a[2:]);finish()
if op=='-I':
 if chain not in t:finish(1)
 t[chain].insert(int(a[2])-1,a[3:]);finish()
if op=='-R':
 if chain not in t or int(a[2])>len(t[chain]):finish(1)
 t[chain][int(a[2])-1]=a[3:];finish()
if op=='-D':
 if chain not in t or a[2:] not in t[chain]:finish(1)
 t[chain].remove(a[2:]);finish()
finish(1)
'''


def function(name):
    return re.search(r"(?ms)^" + re.escape(name) + r"\(\)\s*\{.*?^\}", SOURCE).group()


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.state = self.base / "state.json"
        self.log = self.base / "log.jsonl"
        self.bin = self.base / "bin"
        self.bin.mkdir()
        (self.bin / "mock").write_text(MOCK)
        (self.bin / "mock").chmod(0o755)
        for name in ["iptables", "dbus", "ifconfig", "nvram", "ip", "logger", "ss-flock", "ipset", "ss-https-probe"]:
            (self.bin / name).symlink_to("mock")
        self.initial = {
            "tables": {k: {c: [] for c in ["OUTPUT", "PREROUTING", "FORWARD"]} for k in ["nat", "mangle", "filter"]},
            "ip_rules": [["fwmark", "0x07", "table", "310"], ["fwmark", "0x09", "table", "310"]],
            "dbus": {},
            "nvram": {"jffs2_scripts": "1", "dhcp_dns1_x": "114.114.114.114"},
        }
        self.write_state(self.initial)

    def tearDown(self):
        self.tmp.cleanup()

    def write_state(self, value):
        self.state.write_text(json.dumps(value))

    def shell(self, code, data=None):
        env = dict(os.environ, PATH=str(self.bin) + ":" + os.environ["PATH"], MOCK_STATE=str(self.state), MOCK_LOG=str(self.log), SS_ROUTING_UU_STATE=str(self.base / "uu-state"))
        return subprocess.run(["/bin/bash", "-c", '. "$1"\n. "$2"\n' + code, "routing-test", str(HELPER), str(ROOT / 'scripts/ss_dns_hooks.sh')], input=data, text=True, capture_output=True, env=env)

    def commands(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_anytls_bootstrap_maps_before_custom_port_dns_and_dials_resolved_ip(self):
        mapper = self.base / "mapper.sh"
        mapper.write_text('test "$1" = map-host || exit 2\nprintf mapped.example.test\n')
        body = function("resolv_server_ip").replace("/koolshare/scripts/ss_anytls.sh", str(mapper))
        body = body.replace("/koolshare/bin/ss-https-probe", str(self.bin / "ss-https-probe"))
        body = body.replace("/tmp/ss_host.conf", str(self.base / "ss_host.conf"))
        self.initial["bootstrap_addresses"] = ["203.0.113.7", "203.0.113.8"]
        self.write_state(self.initial)
        result = self.shell(body + r'''
ss_basic_type=4; ss_basic_trojan_binary=AnyTLS; ss_basic_server=original.example.test
echo_date() { :; }
get_server_resolver() { printf 192.0.2.53:7874; }
close_in_five() { exit 17; }
ss_dns_write_server_config() { echo unexpected-DNS-fragment; exit 18; }
nslookup() { exit 18; }
resolv_server_ip
printf 'resolved=%s|%s\n' "$ss_basic_server" "$ss_basic_server_ip"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("unexpected-DNS-fragment", result.stdout)
        self.assertIn("resolved=203.0.113.7|203.0.113.7", result.stdout)
        query = [c for c in self.commands() if c[0] == "ss-https-probe"]
        self.assertEqual(query[0][1:5], ["-resolve", "mapped.example.test", "-dns", "192.0.2.53:7874"])

    def test_anytls_hostname_containing_ipv4_still_uses_independent_dns(self):
        mapper = self.base / "embedded-ip-mapper.sh"
        mapper.write_text('printf 203.0.113.99.edge.example.test\n')
        body = function("resolv_server_ip").replace("/koolshare/scripts/ss_anytls.sh", str(mapper))
        body = body.replace("/koolshare/bin/ss-https-probe", str(self.bin / "ss-https-probe"))
        body = body.replace("/tmp/ss_host.conf", str(self.base / "ss_host.conf"))
        result = self.shell(body + r'''
ss_basic_type=4; ss_basic_trojan_binary=AnyTLS; ss_basic_server=original.example.test
echo_date() { :; }
get_server_resolver() { printf https://dns.example.test/query; }
close_in_five() { exit 17; }
ss_dns_write_server_config() { exit 18; }
resolv_server_ip
printf 'resolved=%s\n' "$ss_basic_server"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('resolved=203.0.113.7', result.stdout)
        queries = [c for c in self.commands() if c[0] == 'ss-https-probe']
        self.assertEqual(queries[0][1:5], ['-resolve','203.0.113.99.edge.example.test','-dns','https://dns.example.test/query'])

    def test_anytls_bootstrap_does_not_fall_back_to_proxy_dependent_dns(self):
        mapper = self.base / "mapper.sh"
        mapper.write_text('printf mapped.example.test\n')
        body = function("resolv_server_ip").replace("/koolshare/scripts/ss_anytls.sh", str(mapper))
        body = body.replace("/koolshare/bin/ss-https-probe", str(self.bin / "ss-https-probe"))
        self.initial["bootstrap_dns_fail"] = True
        self.write_state(self.initial)
        result = self.shell(body + r'''
ss_basic_type=4; ss_basic_trojan_binary=AnyTLS; ss_basic_server=original.example.test
echo_date() { :; }
get_server_resolver() { printf 192.0.2.53:7874; }
close_in_five() { exit 17; }
ss_dns_write_server_config() { :; }
nslookup() { exit 18; }
resolveip() { exit 19; }
resolv_server_ip
''')
        self.assertEqual(result.returncode, 17, result.stderr)

    def test_normalizes_deduplicates_unicast_and_private_macs(self):
        r = self.shell("ss_routing_normalize_macs", " 02:aa:00:00:00:01,02:AA:00:00:00:01\n 0a:00:00:00:00:02\r\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, "02:AA:00:00:00:01\n0A:00:00:00:00:02\n")

    def test_rejects_malformed_multicast_zero_and_injection_without_partial_output(self):
        for invalid in ["00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "01:00:5E:00:00:01", "02-00-00-00-00-01", "02:00:00:00:00:01; touch /tmp/should-not-run", "$(touch /tmp/should-not-run)", "02:00:00:00:00:01 02:00:00:00:00:02"]:
            with self.subTest(invalid=invalid):
                r = self.shell("ss_routing_normalize_macs", MACS + "\n" + invalid)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(r.stdout, "")

    def test_device_bound_is_enforced(self):
        valid = "\n".join(f"02:00:00:00:00:{i:02X}" for i in range(1, 33))
        self.assertEqual(self.shell("ss_routing_normalize_macs", valid).returncode, 0)
        self.assertNotEqual(self.shell("ss_routing_normalize_macs", valid + "\n02:00:00:00:00:21").returncode, 0)

    def test_uu_and_bypass_profiles_cannot_overlap(self):
        self.initial["dbus"] = {"ss_basic_bypass_macs": "02:aa:00:00:00:01", "ss_basic_uu_macs": "02:AA:00:00:00:01"}
        self.write_state(self.initial)
        self.assertNotEqual(self.shell("ss_routing_load_bypass_macs").returncode, 0)
        self.initial["dbus"]["ss_basic_uu_macs"] = "02:AA:00:00:00:02"
        self.write_state(self.initial)
        r = self.shell('ss_routing_load_bypass_macs && printf "%s|%s" "$SS_ROUTING_BYPASS_MACS" "$SS_ROUTING_UU_MACS"')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, "02:AA:00:00:00:01|02:AA:00:00:00:02")

    def test_uu_tcp_policy_defaults_to_gfwlist_and_accepts_only_named_policies(self):
        for policy, target in [("", "SHADOWSOCKS_GFW"), ("gfwlist", "SHADOWSOCKS_GFW"),
                               ("foreign", "SHADOWSOCKS_CHN"), ("direct", "RETURN")]:
            with self.subTest(policy=policy):
                self.initial["dbus"]["ss_basic_uu_tcp_policy"] = policy
                self.write_state(self.initial)
                result = self.shell('ss_routing_load_bypass_macs && ss_routing_uu_target_chain')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), target)
        for invalid in ["invalid", "GFWLIST", "foreign; touch /tmp/should-not-run", "$(touch /tmp/should-not-run)"]:
            with self.subTest(invalid=invalid):
                self.initial["dbus"]["ss_basic_uu_tcp_policy"] = invalid
                self.write_state(self.initial)
                self.assertNotEqual(self.shell('ss_routing_load_bypass_macs').returncode, 0)

    def test_uu_foreign_policy_keeps_domestic_direct_overseas_proxy_option(self):
        self.initial["tables"]["nat"]["SHADOWSOCKS"] = []
        self.initial["neighbours"] = ['192.168.50.34 lladdr 02:00:00:00:00:02 REACHABLE']
        self.write_state(self.initial)
        result = self.shell('SS_ROUTING_UU_MACS="02:00:00:00:00:02"; SS_ROUTING_UU_TCP_POLICY=foreign; ss_routing_add_uu_tcp_routes')
        self.assertEqual(result.returncode, 0, result.stderr)
        rules = json.loads(self.state.read_text())["tables"]["nat"]["SHADOWSOCKS"]
        self.assertEqual(rules, [["-p", "tcp", "-m", "mac", "--mac-source", "02:00:00:00:00:02", "-g", "SHADOWSOCKS_CHN"]])

    def test_uu_direct_policy_removes_only_owned_exception_and_keeps_uu_game_rules(self):
        mac, other, goto = self.uu_tcp_policy_fixture()
        set_name = 'fssuu_020000000002'
        set_return = ["-p", "tcp", "-m", "mac", "--mac-source", mac, "-m", "set", "--match-set", set_name, "dst", "-j", "RETURN"]
        self.initial["tables"]["nat"]["SHADOWSOCKS"] = [other, set_return, goto]
        dnat = ["-s", "192.168.50.34/32", "-i", "br0", "-p", "tcp", "--dport", "3074", "-j", "DNAT", "--to-destination", "10.1.1.1:3074"]
        terminal = ["-s", "192.168.50.34/32", "-i", "br0", "-j", "RETURN"]
        scoped = ["-i", "br0", "-p", "tcp", "-m", "mac", "--mac-source", mac, "-j", "SHADOWSOCKS"]
        global_jump = ["-p", "tcp", "-j", "SHADOWSOCKS"]
        self.initial["tables"]["nat"]["PREROUTING"] = [dnat, scoped, terminal, global_jump]
        self.initial["sets"] = {set_name: ['1.2.3.0/24'], 'UU_OTHER': ['10.0.0.0/8']}
        self.write_state(self.initial)
        result = self.shell(f'SS_ROUTING_UU_MACS="{mac}"; SS_ROUTING_UU_TCP_POLICY=direct; ss_routing_reconcile_uu; ss_routing_reconcile_uu')
        self.assertEqual(result.returncode, 0, result.stderr)
        state = json.loads(self.state.read_text())
        self.assertEqual(state["tables"]["nat"]["SHADOWSOCKS"], [other, ["-p", "tcp", "-m", "mac", "--mac-source", mac, "-j", "RETURN"]])
        self.assertEqual(state["tables"]["nat"]["PREROUTING"], [dnat, terminal, global_jump])
        self.assertEqual(state['sets'], {'UU_OTHER': ['10.0.0.0/8']})
        self.assertEqual(state['rule_output'], self.initial['rule_output'])
        self.assertFalse(any(cmd[0] == 'iptables' and '-F' in cmd for cmd in self.commands()))

    def test_uu_reconcile_switches_gfwlist_foreign_direct_without_stale_owned_gotos(self):
        mac, other, _ = self.uu_tcp_policy_fixture()
        dnat = ["-s", "192.168.50.34/32", "-i", "br0", "-p", "tcp", "--dport", "3074", "-j", "DNAT", "--to-destination", "10.1.1.1:3074"]
        terminal = ["-s", "192.168.50.34/32", "-i", "br0", "-j", "RETURN"]
        self.initial["tables"]["nat"]["PREROUTING"] = [dnat, terminal]
        self.write_state(self.initial)
        for policy, target in [('foreign', 'SHADOWSOCKS_CHN'), ('gfwlist', 'SHADOWSOCKS_GFW'),
                               ('direct', None), ('gfwlist', 'SHADOWSOCKS_GFW')]:
            with self.subTest(policy=policy):
                result = self.shell(f'SS_ROUTING_UU_MACS="{mac}"; SS_ROUTING_UU_TCP_POLICY={policy}; ss_routing_reconcile_uu')
                self.assertEqual(result.returncode, 0, result.stderr)
                state = json.loads(self.state.read_text())
                rules = state['tables']['nat']['SHADOWSOCKS']
                gotos = [rule for rule in rules if '--mac-source' in rule and mac in rule and '-g' in rule]
                self.assertEqual([rule[-1] for rule in gotos], [target] if target else [])
                self.assertEqual(rules[0], other)
                self.assertEqual(state['tables']['nat']['PREROUTING'][0], dnat)
                self.assertIn(terminal, state['tables']['nat']['PREROUTING'])
                scoped = [rule for rule in state['tables']['nat']['PREROUTING'] if '--mac-source' in rule and mac in rule]
                self.assertEqual(len(scoped), 1 if target else 0)

    def test_invalid_backend_input_is_rejected_before_legacy_eval(self):
        self.initial["dbus"]["ss_basic_bypass_macs"] = "$(touch /tmp/should-not-run)"
        self.write_state(self.initial)
        clone = SOURCE.replace(". /koolshare/scripts/ss_routing.sh", '. "' + str(HELPER) + '"', 1)
        r = self.shell(clone)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(any(c[:2] == ["dbus", "export"] for c in self.commands()))
        self.assertFalse(any(c[0] == "iptables" for c in self.commands()))

    def test_invalid_uu_policy_is_rejected_before_legacy_eval(self):
        self.initial["dbus"]["ss_basic_uu_tcp_policy"] = "$(touch /tmp/should-not-run)"
        self.write_state(self.initial)
        clone = SOURCE.replace(". /koolshare/scripts/ss_routing.sh", '. "' + str(HELPER) + '"', 1)
        result = self.shell(clone)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(command[:2] == ["dbus", "export"] for command in self.commands()))
        self.assertFalse(any(command[0] == "iptables" for command in self.commands()))

    def test_output_cleanup_preserves_unrelated_rules_and_is_idempotent(self):
        foreign = [["-p", "udp", "-j", "UU_OUTPUT"], ["-p", "tcp", "--dport", "443", "-j", "MY_SHADOWSOCKS_EXT"], ["-p", "tcp", "-j", "REDIRECT", "--to-ports", "10999"]]
        owned = [["-p", "tcp", "-m", "mark", "--mark", mark, "-j", "SHADOWSOCKS_EXT"] for mark in ["0xc0a83100/0xffffff00", "0xc0a83200/0xffffff00"]]
        redirect = ["-p", "tcp", "-m", "set", "--match-set", "router", "dst", "-j", "REDIRECT", "--to-ports", "3333"]
        self.initial["tables"]["nat"]["OUTPUT"] = foreign[:1] + owned + [redirect, redirect] + foreign[1:]
        self.write_state(self.initial)
        r = self.shell("ss_routing_remove_output_rules\nss_routing_remove_output_rules")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(self.state.read_text())["tables"]["nat"]["OUTPUT"], foreign)
        self.assertFalse(any(c[0] == "iptables" and c[-2:] == ["-F", "OUTPUT"] for c in self.commands()))

    def test_dns_cleanup_preserves_foreign_and_similarly_named_chains(self):
        nat = self.initial["tables"]["nat"]
        nat.update({"SHADOWSOCKS_DNS_0": [], "SHADOWSOCKS_DNS_12": [], "SHADOWSOCKS_DNS_uu": [["-j", "RETURN"]], "UU_DNS": []})
        nat["PREROUTING"] = [["-p", "udp", "-j", t] for t in ["UU_DNS", "SHADOWSOCKS_DNS_0", "SHADOWSOCKS_DNS_12", "SHADOWSOCKS_DNS_uu"]]
        self.write_state(self.initial)
        r = self.shell("ss_routing_remove_dns_rules\nss_routing_remove_dns_rules")
        self.assertEqual(r.returncode, 0, r.stderr)
        nat = json.loads(self.state.read_text())["tables"]["nat"]
        self.assertEqual(nat["PREROUTING"], [["-p", "udp", "-j", "UU_DNS"], ["-p", "udp", "-j", "SHADOWSOCKS_DNS_uu"]])
        self.assertNotIn("SHADOWSOCKS_DNS_12", nat)
        self.assertIn("SHADOWSOCKS_DNS_uu", nat)

    def test_mac_returns_precede_tcp_routing_and_dns_dnat(self):
        defs = "\n".join(function(n) for n in ["factor", "get_action_chain", "get_jump_mode", "get_mode_name", "lan_acess_control", "apply_nat_rules", "dns_hijack_control"])
        code = defs + '\necho_date(){ :; }; close_in_five(){ exit 77; }; load_tproxy(){ :; }\n'
        code += "SS_ROUTING_BYPASS_MACS='" + MACS + "'\nss_basic_type=4; ss_basic_trojan_binary=AnyTLS; mangle=1; ss_routing_is_anytls && mangle=0\n"
        code += "ss_basic_mode=3; ss_basic_udp_sync=1; ss_acl_default_mode=3; ss_acl_default_port=all; ss_basic_dns_hijack=1; ip_prefix_hex=0xc0a83200/0xffffff00\napply_nat_rules\ndns_hijack_control"
        self.initial["dbus"].update({"ss_acl_mode_1": "3", "ss_acl_ip_1": "192.168.50.60", "ss_acl_port_1": "all", "ss_acl_name_1": "game"})
        self.write_state(self.initial)
        r = self.shell(code)
        self.assertEqual(r.returncode, 0, r.stderr)
        state = json.loads(self.state.read_text())
        for chain in ["SHADOWSOCKS", "SHADOWSOCKS_DNS_0", "SHADOWSOCKS_DNS_1"]:
            rules = state["tables"]["nat"][chain]
            self.assertEqual([rule[rule.index("--mac-source") + 1] for rule in rules[:2]], MACS.splitlines())
            self.assertTrue(all(rule[-2:] == ["-j", "RETURN"] for rule in rules[:2]))
        self.assertEqual(state["tables"]["nat"]["SHADOWSOCKS_DNS_0"][-1][-2:], ["--to", "192.168.50.1:53"])
        self.assertFalse(any(c[0] == "iptables" and "mangle" in c and any(x in c for x in ["-N", "-A", "-I"]) for c in self.commands()))
        self.assertFalse(any(c[0] == "ip" and c[1:3] == ["rule", "add"] for c in self.commands()))

    def test_cleanup_preserves_foreign_rules_even_with_invalid_mode(self):
        self.initial["tables"]["nat"]["OUTPUT"] = [["-j", "UU_OUTPUT"]]
        self.initial["tables"]["mangle"]["PREROUTING"] = [["-j", "UU_MANGLE"], ["-j", "SHADOWSOCKS"]]
        self.initial["tables"]["mangle"]["UU_MANGLE"] = [["-j", "RETURN"]]
        self.initial["tables"]["filter"]["FORWARD"] = [["-j", "UU_FILTER"]]
        self.write_state(self.initial)
        r = self.shell(function("get_action_chain") + "\n" + function("flush_nat") + "\necho_date(){ :; }; ipset(){ :; }; ss_basic_mode=invalid; flush_nat\nflush_nat")
        self.assertEqual(r.returncode, 0, r.stderr)
        state = json.loads(self.state.read_text())
        self.assertEqual(state["tables"]["nat"]["OUTPUT"], [["-j", "UU_OUTPUT"]])
        self.assertEqual(state["tables"]["mangle"]["PREROUTING"], [["-j", "UU_MANGLE"]])
        self.assertEqual(state["tables"]["mangle"]["UU_MANGLE"], [["-j", "RETURN"]])
        self.assertEqual(state["tables"]["filter"]["FORWARD"], [["-j", "UU_FILTER"]])
        self.assertEqual(state["ip_rules"], [["fwmark", "0x09", "table", "310"]])

    def test_detection_preserves_existing_dhcp_dns(self):
        r = self.shell(function("detect") + "\necho_date(){ :; }; close_in_five(){ exit 77; }; detect")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(any(c[:2] in [["nvram", "unset"], ["nvram", "commit"]] for c in self.commands()))

    def test_uu_profile_retains_video_tcp_without_bypassing_dns(self):
        defs = "\n".join(function(n) for n in ["factor", "get_action_chain", "get_jump_mode", "get_mode_name", "lan_acess_control", "apply_nat_rules", "dns_hijack_control", "chromecast"])
        code = defs + '\necho_date(){ :; }; close_in_five(){ exit 77; }; load_tproxy(){ :; }\n'
        code += "SS_ROUTING_BYPASS_MACS='02:00:00:00:00:01'; SS_ROUTING_UU_MACS='02:00:00:00:00:02'\n"
        code += "ss_basic_type=4; ss_basic_trojan_binary=AnyTLS; mangle=1; ss_routing_is_anytls && mangle=0\n"
        code += "ss_basic_mode=1; ss_basic_udp_sync=0; ss_acl_default_mode=1; ss_acl_default_port=all; ss_basic_dns_hijack=1; ip_prefix_hex=0xc0a83200/0xffffff00\napply_nat_rules\nchromecast"
        foreign = [["-p", "tcp", "--dport", "3074", "-j", "UU_GAME_NAT"], ["-p", "udp", "--dport", "53", "-j", "UU_DNS"]]
        self.initial["tables"]["nat"]["PREROUTING"] = foreign.copy()
        self.initial["tables"]["mangle"]["PREROUTING"] = [["-p", "udp", "-j", "UU_UDP"]]
        self.write_state(self.initial)
        r = self.shell(code)
        self.assertEqual(r.returncode, 0, r.stderr)
        state = json.loads(self.state.read_text())
        nat = state["tables"]["nat"]
        self.assertEqual(nat["PREROUTING"][:2], foreign)
        self.assertEqual(nat["PREROUTING"][2], ["-p", "tcp", "-j", "SHADOWSOCKS"])
        profile = next(rule for rule in nat["SHADOWSOCKS"] if rule[-2:] == ["-g", "SHADOWSOCKS_GFW"])
        self.assertIn("02:00:00:00:00:02", profile)
        self.assertNotIn("--dport", profile)
        self.assertNotIn("--dports", profile)
        dns_macs = [rule[rule.index("--mac-source") + 1] for rule in nat["SHADOWSOCKS_DNS_0"] if "--mac-source" in rule]
        self.assertEqual(dns_macs, ["02:00:00:00:00:01"])
        self.assertEqual(state["tables"]["mangle"]["PREROUTING"], [["-p", "udp", "-j", "UU_UDP"]])

    def test_uu_device_return_keeps_prior_dnat_then_mac_scoped_tcp_exception(self):
        mac = "02:00:00:00:00:02"
        self.initial["tables"]["nat"]["SHADOWSOCKS"] = [["-p", "tcp", "-m", "mac", "--mac-source", mac, "-g", "SHADOWSOCKS_GFW"]]
        dnat = ["-s", "192.168.50.34/32", "-i", "br0", "-p", "tcp", "--dport", "3074", "-j", "DNAT", "--to-destination", "10.1.1.1:3074"]
        terminal = ["-s", "192.168.50.34/32", "-i", "br0", "-j", "RETURN"]
        other = ["-s", "192.168.50.99/32", "-i", "br0", "-j", "RETURN"]
        self.initial["tables"]["nat"]["PREROUTING"] = [other, dnat, terminal]
        self.initial["neighbours"] = [f"192.168.50.34 dev br0 lladdr {mac.lower()} REACHABLE"]
        self.write_state(self.initial)
        code = f"SS_ROUTING_UU_MACS='{mac}'; ss_routing_add_prerouting_jump"
        self.assertEqual(self.shell(code).returncode, 0)
        rules = json.loads(self.state.read_text())["tables"]["nat"]["PREROUTING"]
        self.assertEqual(rules[:2], [other, dnat])
        self.assertEqual(rules[2], ["-i", "br0", "-p", "tcp", "-m", "mac", "--mac-source", mac, "-j", "SHADOWSOCKS"])
        self.assertEqual(rules[3], terminal)
        self.assertEqual(rules[4], ["-p", "tcp", "-j", "SHADOWSOCKS"])
        self.assertEqual(self.shell("ss_routing_remove_jumps nat PREROUTING SHADOWSOCKS").returncode, 0)
        self.assertEqual(json.loads(self.state.read_text())["tables"]["nat"]["PREROUTING"], [other, dnat, terminal])

    def test_uu_exception_relocates_after_dhcp_change_and_uses_lease_fallback(self):
        mac = "02:00:00:00:00:02"
        self.initial["tables"]["nat"]["SHADOWSOCKS"] = [["-p", "tcp", "-m", "mac", "--mac-source", mac, "-g", "SHADOWSOCKS_GFW"]]
        lease = self.base / "leases"
        lease.write_text(f"9999999999 {mac.lower()} 192.168.50.77 console *\n")
        cloned = self.base / "routing.sh"
        cloned.write_text(HELPER.read_text().replace("/var/lib/misc/dnsmasq.leases", str(lease)))
        terminal = ["-s", "192.168.50.77/32", "-i", "br0", "-j", "RETURN"]
        self.initial["tables"]["nat"]["PREROUTING"] = [terminal]
        self.initial["neighbours"] = [f"999.1.1.1 lladdr {mac} STALE"]
        self.write_state(self.initial)
        result = self.shell(f'. "{cloned}"; SS_ROUTING_UU_MACS="{mac}"; ss_routing_add_prerouting_jump')
        self.assertEqual(result.returncode, 0, result.stderr)
        rules = json.loads(self.state.read_text())["tables"]["nat"]["PREROUTING"]
        self.assertIn(mac, rules[0])
        self.assertNotIn("192.168.50.77/32", rules[0])
        self.assertEqual(rules[1], terminal)

    def test_uu_reconcile_repairs_background_rebuild_and_duplicate_jumps_only(self):
        mac = "02:00:00:00:00:02"
        self.initial["tables"]["nat"]["SHADOWSOCKS"] = [["-p", "tcp", "-m", "mac", "--mac-source", mac, "-g", "SHADOWSOCKS_GFW"]]
        scoped = ["-i", "br0", "-p", "tcp", "-m", "mac", "--mac-source", mac, "-j", "SHADOWSOCKS"]
        game = ["-s", "192.168.50.34/32", "-i", "br0", "-p", "tcp", "--dport", "3074", "-j", "UU_GAME"]
        terminal = ["-s", "192.168.50.34/32", "-i", "br0", "-j", "RETURN"]
        self.initial["tables"]["nat"]["PREROUTING"] = [scoped, game, terminal, scoped, ["-p", "tcp", "-j", "SHADOWSOCKS"]]
        self.initial["neighbours"] = [f"192.168.50.34 lladdr {mac} REACHABLE"]
        self.write_state(self.initial)
        code = f'SS_ROUTING_UU_MACS="{mac}"; ss_routing_reconcile_uu'
        self.assertEqual(self.shell(code).returncode, 0)
        expected = [game, scoped, terminal, ["-p", "tcp", "-j", "SHADOWSOCKS"]]
        self.assertEqual(json.loads(self.state.read_text())["tables"]["nat"]["PREROUTING"], expected)
        self.log.unlink()
        self.assertEqual(self.shell(code).returncode, 0)
        mutations = [cmd for cmd in self.commands() if cmd[0] == "iptables" and "PREROUTING" in cmd and any(op in cmd for op in ["-D", "-I", "-A", "-F"])]
        self.assertEqual(mutations, [])

    def test_uu_reconcile_skips_missing_mapping_and_cleans_removed_profile(self):
        mac = "02:00:00:00:00:02"
        self.initial["tables"]["nat"]["SHADOWSOCKS"] = [["-p", "tcp", "-m", "mac", "--mac-source", mac, "-g", "SHADOWSOCKS_GFW"]]
        scoped = ["-i", "br0", "-p", "tcp", "-m", "mac", "--mac-source", mac, "-j", "SHADOWSOCKS"]
        terminal = ["-s", "192.168.50.34/32", "-i", "br0", "-j", "RETURN"]
        self.initial["tables"]["nat"]["PREROUTING"] = [scoped, terminal]
        self.write_state(self.initial)
        self.assertEqual(self.shell(f'SS_ROUTING_UU_MACS="{mac}"; ss_routing_reconcile_uu').returncode, 0)
        self.assertEqual(json.loads(self.state.read_text())["tables"]["nat"]["PREROUTING"], [terminal])
        self.initial["tables"]["nat"]["PREROUTING"] = [scoped, terminal]
        self.write_state(self.initial)
        self.assertEqual(self.shell('SS_ROUTING_UU_MACS=""; ss_routing_reconcile_uu').returncode, 0)
        self.assertEqual(json.loads(self.state.read_text())["tables"]["nat"]["PREROUTING"], [terminal])

    def test_uu_cron_owns_only_its_job(self):
        code = function("write_cron_job") + "\n" + function("kill_cron_job")
        code += '\ncru(){ printf "%s\\n" "$*"; }; sed(){ :; }; echo_date(){ :; }; SS_ROUTING_UU_MACS="02:00:00:00:00:02"; write_cron_job; kill_cron_job'
        result = self.shell(code)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("a ss_uu_coexist * * * * * /koolshare/scripts/ss_routing.sh watch-uu", result.stdout)
        self.assertNotIn("uuplugin", result.stdout)

    def test_uu_cron_respects_disabled_state_and_nonblocking_core_lock(self):
        clone = self.base / "reconcile.sh"
        code = HELPER.read_text().replace("/var/lock/koolss.lock", str(self.base / "core.lock"))
        code = code.replace("PATH=/koolshare/bin:/usr/sbin:/usr/bin:/sbin:/bin", "PATH=" + str(self.bin) + ":" + os.environ["PATH"])
        code = code.replace("/koolshare/bin/ss-flock", str(self.bin / "ss-flock"))
        clone.write_text(code)
        env = dict(os.environ, PATH=str(self.bin) + ":" + os.environ["PATH"], MOCK_STATE=str(self.state), MOCK_LOG=str(self.log))
        first = subprocess.run(["/bin/sh", str(clone), "reconcile-uu"], env=env, capture_output=True, text=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertFalse(any(cmd[0] == "ss-flock" for cmd in self.commands()))
        self.initial["dbus"]["ss_basic_enable"] = "1"
        self.initial["locked"] = True
        self.write_state(self.initial)
        self.log.unlink()
        second = subprocess.run(["/bin/sh", str(clone), "reconcile-uu"], env=env, capture_output=True, text=True)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn(["ss-flock", "-n", "7"], self.commands())
        self.assertFalse(any(cmd[0] == "iptables" for cmd in self.commands()))

    def test_uu_cron_cannot_restore_proxy_hooks_during_direct_protection(self):
        self.initial["dbus"]["ss_basic_enable"] = "1"
        self.write_state(self.initial)
        mode = self.base / "failover-mode"
        code = HELPER.read_text().replace("/var/lock/koolss.lock", str(self.base / "core.lock"))
        code = code.replace("/tmp/ss_failover/mode", str(mode))
        code = code.replace("PATH=/koolshare/bin:/usr/sbin:/usr/bin:/sbin:/bin", "PATH=" + str(self.bin) + ":" + os.environ["PATH"])
        code = code.replace("/koolshare/bin/ss-flock", str(self.bin / "ss-flock"))
        clone = self.base / "protected-reconcile.sh"
        clone.write_text(code)
        env = dict(os.environ, PATH=str(self.bin) + ":" + os.environ["PATH"], MOCK_STATE=str(self.state), MOCK_LOG=str(self.log))
        for value in ["direct", "error"]:
            mode.write_text(value + "\n")
            if self.log.exists(): self.log.unlink()
            result = subprocess.run(["/bin/sh", str(clone), "reconcile-uu"], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(any(cmd[0] in ["iptables", "ip", "ipset"] for cmd in self.commands()))

    def uu_tcp_policy_fixture(self):
        mac = "02:00:00:00:00:02"
        other = ["-p", "tcp", "-m", "mac", "--mac-source", "02:00:00:00:00:01", "-j", "RETURN"]
        goto = ["-p", "tcp", "-m", "mac", "--mac-source", mac, "-g", "SHADOWSOCKS_GFW"]
        self.initial["tables"]["nat"]["SHADOWSOCKS"] = [other, goto]
        self.initial["neighbours"] = [f"192.168.50.34 lladdr {mac} REACHABLE"]
        self.initial["rule_output"] = [
            "0: from all lookup local",
            "32764: from 192.168.50.34 lookup 179",
            "32765: from 192.168.50.34 fwmark 0x163/0x163 lookup 163",
        ]
        self.initial["routes"] = {
            "179": ["1.2.3.0/24 via 10.1.1.1 dev tun163", "5.6.7.8 dev tun163", "default dev tun163", "0.0.0.0/0 dev tun163"],
            "163": ["default dev tun163", "0.0.0.0/1 dev tun163"],
        }
        self.write_state(self.initial)
        return mac, other, goto

    def test_uu_tcp_specific_routes_are_mac_scoped_before_goto_and_swapped_atomically(self):
        mac, other, goto = self.uu_tcp_policy_fixture()
        result = self.shell(f'SS_ROUTING_UU_MACS="{mac}"; ss_routing_update_uu_tcp_bypasses')
        self.assertEqual(result.returncode, 0, result.stderr)
        state = json.loads(self.state.read_text())
        name = "fssuu_020000000002"
        self.assertEqual(state["sets"][name], ["1.2.3.0/24", "5.6.7.8/32"])
        self.assertNotIn(name + "_t", state["sets"])
        rules = state["tables"]["nat"]["SHADOWSOCKS"]
        self.assertEqual(rules[0], other)
        self.assertEqual(rules[1], ["-p", "tcp", "-m", "mac", "--mac-source", mac, "-m", "set", "--match-set", name, "dst", "-j", "RETURN"])
        self.assertEqual(rules[2], goto)
        commands = self.commands()
        guard = next(i for i,c in enumerate(commands) if c[0] == "iptables" and "-I" in c)
        policy_read = commands.index(["ip", "rule", "show"])
        swapped = commands.index(["ipset", "swap", name + "_t", name])
        activated = next(i for i,c in enumerate(commands) if c[0] == "iptables" and "-R" in c)
        self.assertLess(guard, policy_read)
        self.assertLess(swapped, activated)
        self.assertNotIn(["ip", "route", "show", "table", "163"], commands)
        self.assertEqual((self.base / "uu-state").stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in (self.base / "uu-state").iterdir()))

    def test_uu_tcp_updates_dynamic_table_ids_and_preserves_foreign_rules(self):
        mac, other, goto = self.uu_tcp_policy_fixture()
        code = f'SS_ROUTING_UU_MACS="{mac}"; ss_routing_update_uu_tcp_bypasses'
        self.assertEqual(self.shell(code).returncode, 0)
        state = json.loads(self.state.read_text())
        state["rule_output"][1] = "100: from 192.168.50.34/32 lookup 481"
        state["routes"]["481"] = ["9.8.0.0/16 dev tun912"]
        self.write_state(state)
        self.assertEqual(self.shell(code).returncode, 0)
        updated = json.loads(self.state.read_text())
        self.assertEqual(updated["sets"]["fssuu_020000000002"], ["9.8.0.0/16"])
        rules = updated["tables"]["nat"]["SHADOWSOCKS"]
        self.assertEqual(len(rules), 3)
        self.assertEqual(rules[0], other)
        self.assertEqual(rules[-1], goto)
        self.assertEqual(updated["rule_output"], state["rule_output"])
        self.assertEqual(updated["routes"], state["routes"])

    def test_uu_tcp_read_and_atomic_update_failures_keep_existing_set_guard(self):
        mac, other, goto = self.uu_tcp_policy_fixture()
        code = f'SS_ROUTING_UU_MACS="{mac}"; ss_routing_update_uu_tcp_bypasses'
        self.assertEqual(self.shell(code).returncode, 0)
        baseline = json.loads(self.state.read_text())
        failures = [
            {"rule_read_fail": True}, {"route_fail_tables": ["179"]},
            {"restore_fail": True}, {"swap_fail": True}, {"ipset_unavailable": True},
            {"routes": {"179": []}}, {"routes": {"179": ["default dev tun163"]}},
            {"routes": {"179": ["999.2.3.0/24 dev tun163"]}},
            {"routes": {"179": ["1.2.3.0/33 dev tun163"]}},
            {"rule_output": ["32764: from 192.168.50.34 lookup 179;touch"]},
            {"neighbours": []},
        ]
        for failure in failures:
            with self.subTest(failure=failure):
                current = json.loads(json.dumps(baseline))
                current.update(failure)
                self.write_state(current)
                result = self.shell(code)
                self.assertEqual(result.returncode, 0, result.stderr)
                state = json.loads(self.state.read_text())
                rules = state["tables"]["nat"]["SHADOWSOCKS"]
                self.assertEqual(rules[0], other)
                self.assertEqual(rules[1], baseline["tables"]["nat"]["SHADOWSOCKS"][1])
                self.assertEqual(rules[2], goto)
                self.assertEqual(state["sets"]["fssuu_020000000002"], baseline["sets"]["fssuu_020000000002"])

    def test_uu_refresh_keeps_active_rule_until_atomic_swap_without_whole_tcp_guard(self):
        mac, _, _ = self.uu_tcp_policy_fixture()
        code = f'SS_ROUTING_UU_MACS="{mac}"; ss_routing_update_uu_tcp_bypasses'
        self.assertEqual(self.shell(code).returncode, 0)
        self.log.unlink()
        self.assertEqual(self.shell(code).returncode, 0)
        commands = self.commands()
        self.assertTrue(any(c[:2] == ['ipset', 'swap'] for c in commands))
        self.assertFalse(any(c[0] == 'iptables' and any(op in c for op in ['-I', '-R']) for c in commands))
        self.assertFalse(any(c[0] == 'iptables' and '-D' in c and '--match-set' in c for c in commands))

    def test_uu_first_failed_discovery_still_installs_conservative_guard(self):
        mac, other, goto = self.uu_tcp_policy_fixture()
        self.initial['rule_read_fail'] = True
        self.write_state(self.initial)
        self.assertEqual(self.shell(f'SS_ROUTING_UU_MACS="{mac}"; ss_routing_update_uu_tcp_bypasses').returncode, 0)
        rules = json.loads(self.state.read_text())['tables']['nat']['SHADOWSOCKS']
        self.assertEqual(rules, [other, ['-p','tcp','-m','mac','--mac-source',mac,'-j','RETURN'], goto])

    def test_uu_inactive_clears_guards_but_claimed_empty_preserves_last_valid_set(self):
        mac, other, goto = self.uu_tcp_policy_fixture()
        code = f'SS_ROUTING_UU_MACS="{mac}"; ss_routing_update_uu_tcp_bypasses'
        self.assertEqual(self.shell(code).returncode, 0)
        state = json.loads(self.state.read_text())
        state["rule_output"] = ["0: from all lookup local", "32765: from 192.168.50.34 fwmark 1 lookup 163"]
        self.write_state(state)
        self.assertEqual(self.shell(code).returncode, 0)
        inactive = json.loads(self.state.read_text())
        self.assertEqual(inactive["tables"]["nat"]["SHADOWSOCKS"], [other, goto])
        self.assertNotIn('fssuu_020000000002', inactive['sets'])
        state["tables"]["nat"]["PREROUTING"] = [["-s", "192.168.50.34/32", "-i", "br0", "-j", "RETURN"]]
        self.write_state(state)
        self.assertEqual(self.shell(code).returncode, 0)
        rules = json.loads(self.state.read_text())["tables"]["nat"]["SHADOWSOCKS"]
        self.assertEqual(rules[1], state['tables']['nat']['SHADOWSOCKS'][1])
        self.assertEqual(rules[2], goto)

    def test_uu_owned_set_cleanup_leaves_other_sets(self):
        mac, _, _ = self.uu_tcp_policy_fixture()
        code = f'SS_ROUTING_UU_MACS="{mac}"; ss_routing_update_uu_tcp_bypasses'
        self.assertEqual(self.shell(code).returncode, 0)
        state = json.loads(self.state.read_text())
        state["sets"]["UU_GAME"] = ["10.0.0.0/8"]
        self.write_state(state)
        self.assertEqual(self.shell('SS_ROUTING_UU_MACS=""; ss_routing_clear_uu_sets').returncode, 0)
        self.assertEqual(json.loads(self.state.read_text())["sets"], {"UU_GAME": ["10.0.0.0/8"]})

    def test_uu_pending_profile_without_owned_main_goto_keeps_terminal_return(self):
        mac = "02:00:00:00:00:02"
        old_jump = ["-i", "br0", "-p", "tcp", "-m", "mac", "--mac-source", mac, "-j", "SHADOWSOCKS"]
        terminal = ["-s", "192.168.50.34/32", "-i", "br0", "-j", "RETURN"]
        self.initial["tables"]["nat"]["SHADOWSOCKS"] = [["-p", "tcp", "-j", "SHADOWSOCKS_CHN"]]
        self.initial["tables"]["nat"]["PREROUTING"] = [old_jump, terminal]
        self.initial["neighbours"] = [f"192.168.50.34 lladdr {mac} REACHABLE"]
        self.write_state(self.initial)
        result = self.shell(f'SS_ROUTING_UU_MACS="{mac}"; ss_routing_reconcile_uu')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.state.read_text())["tables"]["nat"]["PREROUTING"], [terminal])

    def test_uu_interval_defaults_and_bounds_are_validated_without_eval(self):
        for value, expected in [('', '5'), ('2', '2'), ('5', '5'), ('30', '30')]:
            self.initial['dbus']['ss_basic_uu_interval'] = value
            self.write_state(self.initial)
            result = self.shell('ss_routing_load_bypass_macs && printf "%s" "$SS_ROUTING_UU_INTERVAL"')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, expected)
        for value in ['1', '31', '-2', '2.5', '5;touch marker', ' 5', '99999']:
            self.initial['dbus']['ss_basic_uu_interval'] = value
            self.write_state(self.initial)
            self.assertNotEqual(self.shell('ss_routing_load_bypass_macs').returncode, 0)

    def test_watch_digest_detects_game_route_change_without_rule_change(self):
        mac, _, _ = self.uu_tcp_policy_fixture()
        code = f'SS_ROUTING_UU_MACS="{mac}"; SS_ROUTING_BYPASS_MACS=; SS_ROUTING_UU_TCP_POLICY=foreign; ss_routing_watch_digest'
        first = self.shell(code)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertRegex(first.stdout, r'^[0-9a-f]{32}\n$')
        self.assertEqual(self.shell(code).stdout, first.stdout)
        self.initial['routes']['179'].append('203.0.113.7/32 dev tun163')
        self.write_state(self.initial)
        self.assertNotEqual(self.shell(code).stdout, first.stdout)
        self.assertFalse(any(c[0]=='ipset' for c in self.commands()))

    def watch_clone(self):
        code = HELPER.read_text().replace('/var/lock/koolss.lock', str(self.base/'core.lock'))
        code = code.replace('/tmp/ss_failover/mode', str(self.base/'mode'))
        code = code.replace('PATH=/koolshare/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'PATH='+str(self.bin)+':'+os.environ['PATH'])
        code = code.replace('/koolshare/bin/ss-flock', str(self.bin/'ss-flock'))
        clone = self.base/'watch-helper.sh';clone.write_text(code)
        return clone

    def watch_env(self):
        return dict(os.environ, PATH=str(self.bin)+':'+os.environ['PATH'], MOCK_STATE=str(self.state),
                    MOCK_LOG=str(self.log), SS_ROUTING_WATCH_STATE=str(self.base/'watch-state'),
                    SS_ROUTING_WATCH_FLOCK=str(self.bin/'ss-flock'))

    def test_watch_only_reconciles_changed_digest_and_hot_reads_interval_without_child_locks(self):
        clone = self.watch_clone();control = self.base/'control';control.mkdir()
        (control/'run').touch();(control/'snapshot').write_text('first');(control/'interval').write_text('5')
        body = r'''
. "$1"
control=$2
ss_routing_watch_allowed(){ [ -f "$control/run" ]; }
ss_routing_load_bypass_macs(){ SS_ROUTING_UU_MACS=02:00:00:00:00:02; SS_ROUTING_UU_INTERVAL=$(cat "$control/interval"); }
ss_routing_watch_snapshot(){ cat "$control/snapshot"; }
ss_routing_reconcile_uu(){
  if (: >&6) 2>/dev/null || (: >&7) 2>/dev/null; then echo inherited-lock >> "$control/errors"; fi
  echo refresh >> "$control/refreshes"
}
sleep(){
  if (: >&6) 2>/dev/null || (: >&7) 2>/dev/null; then echo inherited-lock >> "$control/errors"; fi
  echo "$1" >> "$control/sleeps"
  n=$(wc -l < "$control/sleeps" | tr -d ' ')
  case "$n" in 1) echo 2 > "$control/interval" ;; 2) echo second > "$control/snapshot" ;; 4) rm "$control/run" ;; esac
}
ss_routing_watch
'''
        result = subprocess.run(['/bin/bash','-c',body,'watch-test',str(clone),str(control)],
                                env=self.watch_env(),capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((control/'refreshes').read_text().splitlines(), ['refresh','refresh'])
        self.assertEqual((control/'sleeps').read_text().splitlines(), ['5','2','2','2'])
        self.assertFalse((control/'errors').exists())
        state=self.base/'watch-state'
        self.assertEqual(state.stat().st_mode & 0o777, 0o700)
        self.assertEqual((state/'digest').stat().st_mode & 0o777, 0o600)
        self.assertFalse((state/'pid').exists())
        self.assertIn(['ss-flock','-u','6'], self.commands())

    def test_watch_singleton_releases_lock_on_signal_and_sleep_holds_no_lock(self):
        import fcntl
        clone = self.watch_clone()
        body = r'''
. "$1"
ss_routing_watch_allowed(){ return 0; }
ss_routing_load_bypass_macs(){ SS_ROUTING_UU_MACS=02:00:00:00:00:02; SS_ROUTING_UU_INTERVAL=2; }
ss_routing_watch_snapshot(){ printf stable; }
ss_routing_reconcile_uu(){ :; }
sleep(){ /bin/sleep 0.1; }
ss_routing_watch
'''
        args=['/bin/bash','-c',body,'watch-test',str(clone)]
        first=subprocess.Popen(args,env=self.watch_env(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            pidfile=self.base/'watch-state/pid';deadline=time.monotonic()+3
            while not pidfile.exists() and time.monotonic()<deadline:time.sleep(0.01)
            self.assertTrue(pidfile.exists())
            pid=pidfile.read_text()
            second=subprocess.run(args,env=self.watch_env(),capture_output=True,text=True,timeout=3)
            self.assertEqual(second.returncode,0,second.stderr)
            self.assertEqual(pidfile.read_text(),pid)
            first.terminate();first.communicate(timeout=3)
            self.assertFalse(pidfile.exists())
            with (self.base/'watch-state/lock').open('w') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        finally:
            if first.poll() is None:first.kill();first.communicate()

    def test_watch_exits_without_snapshot_or_routes_when_disabled_or_direct(self):
        clone=self.watch_clone()
        for enabled,mode in [('0','proxy'),('1','direct'),('1','error')]:
            self.initial['dbus']['ss_basic_enable']=enabled;self.write_state(self.initial)
            (self.base/'mode').write_text(mode)
            if self.log.exists():self.log.unlink()
            result=subprocess.run(['/bin/sh',str(clone),'watch-uu'],env=self.watch_env(),capture_output=True,text=True,timeout=3)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertFalse(any(c[0] in ['iptables','ip','ipset'] for c in self.commands()))
            self.assertFalse((self.base/'watch-state').exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
