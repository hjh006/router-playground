import os
import re
import shlex
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1] / "shadowsocks"
SOURCE = (ROOT / "scripts/ss_dns_hooks.sh").read_text()


class DnsHookTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.jffs = self.base / "jffs"
        self.kool = self.base / "koolshare"
        self.temp = self.base / "runtime"
        for p in [self.jffs / "scripts", self.jffs / "configs/dnsmasq.d", self.kool / "ss/rules", self.temp]:
            p.mkdir(parents=True)
        self.helper = self.base / "hooks.sh"
        self.helper.write_text(SOURCE.replace("/tmp/", str(self.temp) + "/").replace("/jffs", str(self.jffs)).replace("/koolshare", str(self.kool)))
        self.hook = self.jffs / "scripts/dnsmasq.postconf"
        self.state = self.jffs / ".fancyss-dns"
        self.template = self.kool / "ss/rules/dnsmasq.postconf"
        self.template.write_text('#!/bin/sh\nprintf "science\\n" >> "$1"\n')
        self.template.chmod(0o755)
        self.conf_add = self.jffs / "configs/dnsmasq.conf.add"
        self.conf_add.write_text("server=/game.test/192.0.2.1\n# user/UU content\n")

    def tearDown(self):
        self.tmp.cleanup()

    def shell(self, command):
        return subprocess.run(["/bin/sh", "-c", '. "$1"\n' + command, "hook-test", str(self.helper)], capture_output=True, text=True)

    def test_sourcing_helper_and_normalizing_resolver_are_pure(self):
        before = set(self.base.rglob("*"))
        original = self.conf_add.read_bytes()
        result = self.shell('ss_dns_normalize_resolver "192.0.2.1:7874"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "192.0.2.1:7874\n")
        self.assertEqual(set(self.base.rglob("*")), before)
        self.assertEqual(self.conf_add.read_bytes(), original)

    def test_resolver_normalization_returns_explicit_canonical_port(self):
        cases = {
            "192.0.2.1": "192.0.2.1:53",
            "192.0.2.1:53": "192.0.2.1:53",
            "192.0.2.1:00053": "192.0.2.1:53",
            "198.51.100.254:7874": "198.51.100.254:7874",
            "203.0.113.1:1": "203.0.113.1:1",
            "203.0.113.255:65535": "203.0.113.255:65535",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                result = self.shell("ss_dns_normalize_resolver " + shlex.quote(raw))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected + "\n")

    def test_resolver_rejects_nonliteral_ambiguous_and_executable_input(self):
        marker = self.base / "must-not-exist"
        cases = [
            "", " ", "192.0.2.1 ", " 192.0.2.1", "192.0.2.1\t",
            "192.0.2.1\r", "192.0.2.1\n", "192.0.2.1\n198.51.100.1",
            "192.0.2.1\x1f", "udp://192.0.2.1:7874", "tcp://192.0.2.1:53",
            "http://dns.example/dns-query", "dns.example", "192.0.2.1#7874",
            "192.0.2.1/32", "[::1]:53", "::1", "192.0.2", "192.0.2.1.5",
            "192..2.1", "192.0.2.256", "192.0.2.-1", "+192.0.2.1",
            "0192.0.2.1", "192.00.2.1", "192.0.02.1", "192.0.2.01",
            "0xc0.0.2.1", r"\06192.0.2.1", "192.0.2.1:", "192.0.2.1:0",
            "192.0.2.1:-1", "192.0.2.1:+53", "192.0.2.1:65536",
            "192.0.2.1:999999999999999", "192.0.2.1:53:54", "192.0.2.1:5e1",
            "192.0.2.1:53.0", "192.0.2.1: 53", "192.0.2.1:53\n",
            "192.0.2.1;touch " + str(marker), "$(touch " + str(marker) + ")",
            "`touch " + str(marker) + "`",
        ]
        for raw in cases:
            with self.subTest(raw=raw):
                result = self.shell("ss_dns_normalize_resolver " + shlex.quote(raw))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
        self.assertFalse(marker.exists())

    def test_doh_and_mixed_resolver_lists_preserve_quoted_uri_components(self):
        cases = {
            "https://DNS.Example/custom/resolve?key=sample&edns=1":
                "https://dns.example/custom/resolve?key=sample&edns=1",
            "https://192.0.2.1:00853/v1/query?value=%2c%23%2F":
                "https://192.0.2.1:853/v1/query?value=%2c%23%2F",
            "https://dns.example/": "https://dns.example/",
            "192.0.2.1,https://DNS.Example/custom?q=a+b&key=sample,198.51.100.1:7874,https://203.0.113.1:443/v2/query":
                "192.0.2.1:53,https://dns.example/custom?q=a+b&key=sample,198.51.100.1:7874,https://203.0.113.1:443/v2/query",
        }
        before = set(self.base.rglob("*"))
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                result = self.shell("ss_dns_normalize_resolver " + shlex.quote(raw))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected + "\n")
        self.assertEqual(set(self.base.rglob("*")), before)

    def test_bad_doh_urls_and_lists_have_no_partial_output_or_execution(self):
        marker = self.base / "must-not-exist"
        cases = [
            ",192.0.2.1", "192.0.2.1,", "192.0.2.1,,198.51.100.1",
            ",", "192.0.2.1,192.0.2.2,192.0.2.3,192.0.2.4,192.0.2.5",
            "192.0.2.1,not-a-resolver", "192.0.2.1,https://dns.example/\n",
            "https://dns.example/query?list=a,b", "HTTPS://dns.example/query",
            "http://dns.example/query", "https://dns.example", "https:///query",
            "https://user@dns.example/query", "https://user:password@dns.example/query",
            "https://user%40dns.example/query", "https://dns.example/query#fragment",
            "https://dns.example:/query", "https://dns.example:0/query",
            "https://dns.example:65536/query", "https://dns.example:-1/query",
            "https://dns.example:443:53/query", "https://[2001:db8::1]/query",
            "https://192.0.02.1/query", "https://192.0.2.256/query",
            "https://dns..example/query", "https://-dns.example/query",
            "https://dns-.example/query", "https://dns_example/query",
            "https://dns.example./query", "https://" + "a" * 64 + ".example/query",
            "https://" + ".".join(["a" * 63] * 4) + "/query",
            "https://dñs.example/query", "https://dns.example/query?key=has space",
            "https://dns.example/query\t", "https://dns.example/query\r",
            "https://dns.example/query\x1f", "https://dns.example/query?bad=%",
            "https://dns.example/query?bad=%0", "https://dns.example/query?bad=%GG",
            r"https://dns.example/query\tail", "https://dns.example/query;echo",
            "https://dns.example/query|echo", "https://dns.example/query>output",
            "https://dns.example/query?key='quote'", 'https://dns.example/query?key="quote"',
            "https://dns.example/query{brace}", "https://dns.example/query?key=$(touch " + str(marker) + ")",
            "https://dns.example/query?key=`touch " + str(marker) + "`",
        ]
        for raw in cases:
            with self.subTest(raw=raw):
                result = self.shell("ss_dns_normalize_resolver " + shlex.quote(raw))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                # A valid earlier endpoint must not leak on a later failure.
                result = self.shell("ss_dns_normalize_resolver " + shlex.quote("198.51.100.1," + raw))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
        self.assertFalse(marker.exists())

    def test_doh_and_lists_cannot_be_written_as_legacy_udp_fragments(self):
        output = self.temp / "fancyss-server.conf"
        link = self.jffs / "configs/dnsmasq.d/fancyss-server.conf"
        output.write_text("server=/existing.example/192.0.2.1#53\n")
        link.symlink_to(output)
        original = output.read_bytes()
        for raw in ["https://dns.example/custom?key=sample&edns=1",
                    "192.0.2.1,198.51.100.1:7874",
                    "192.0.2.1,https://dns.example/query"]:
            with self.subTest(raw=raw):
                result = self.shell("ss_dns_write_server_config node.example " + shlex.quote(raw))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertEqual(output.read_bytes(), original)
                self.assertEqual(link.resolve(), output.resolve())

    def test_server_fragment_uses_requested_port_without_changing_other_dns(self):
        before = self.conf_add.read_bytes()
        output = self.temp / "fancyss-server.conf"
        link = self.jffs / "configs/dnsmasq.d/fancyss-server.conf"
        for resolver, expected in [
            ("192.0.2.1", "server=/node.example/192.0.2.1#53\n"),
            ("192.0.2.1:53", "server=/node.example/192.0.2.1#53\n"),
            ("192.0.2.1:00053", "server=/node.example/192.0.2.1#53\n"),
            ("198.51.100.1:7874", "server=/node.example/198.51.100.1#7874\n"),
            ("203.0.113.1:65535", "server=/node.example/203.0.113.1#65535\n"),
        ]:
            with self.subTest(resolver=resolver):
                result = self.shell("ss_dns_write_server_config node.example " + shlex.quote(resolver))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output.read_text(), expected)
                self.assertTrue(link.is_symlink())
                self.assertEqual(link.resolve(), output.resolve())
                self.assertEqual(self.conf_add.read_bytes(), before)

    def test_invalid_resolver_preserves_existing_server_fragment(self):
        output = self.temp / "fancyss-server.conf"
        link = self.jffs / "configs/dnsmasq.d/fancyss-server.conf"
        output.write_text("server=/existing.example/192.0.2.1\n")
        link.symlink_to(output)
        original = output.read_bytes()
        result = self.shell("ss_dns_write_server_config node.example 'udp://198.51.100.1:7874'")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), original)
        self.assertEqual(link.resolve(), output.resolve())

    def test_unknown_hook_is_chained_once_and_restored_exactly(self):
        original = '#!/bin/sh\nprintf "previous:%s:%s\\n" "$0" "$1" >> "$1"\n'
        self.hook.write_text(original)
        self.hook.chmod(0o750)
        conf_before = self.conf_add.read_bytes()
        r = self.shell("ss_dns_hooks_install\nss_dns_hooks_install")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        config = self.base / "dns config.conf"
        subprocess.run([str(self.hook), str(config)], check=True)
        self.assertEqual(config.read_text().splitlines(), ["science", f"previous:{self.hook}:{config}"])
        self.assertEqual(self.shell("ss_dns_hooks_remove\nss_dns_hooks_remove").returncode, 0)
        self.assertEqual(self.hook.read_text(), original)
        self.assertEqual(stat.S_IMODE(self.hook.stat().st_mode), 0o750)
        self.assertEqual(self.conf_add.read_bytes(), conf_before)
        self.assertFalse(self.state.exists())

    def test_relative_symlink_hook_restores_identity_and_runs(self):
        target = self.jffs / "vendor/uu-hook.sh"
        target.parent.mkdir()
        target.write_text('#!/bin/sh\nprintf "uu\\n" >> "$1"\n')
        target.chmod(0o755)
        self.hook.symlink_to("../vendor/uu-hook.sh")
        r = self.shell("ss_dns_hooks_install")
        self.assertEqual(r.returncode, 0, r.stderr)
        config = self.base / "dns.conf"
        subprocess.run([str(self.hook), str(config)], check=True)
        self.assertEqual(config.read_text(), "science\nuu\n")
        self.assertEqual(self.shell("ss_dns_hooks_remove").returncode, 0)
        self.assertTrue(self.hook.is_symlink())
        self.assertEqual(os.readlink(self.hook), "../vendor/uu-hook.sh")

    def test_unknown_replacement_is_never_deleted_or_overwritten(self):
        self.hook.write_text('#!/bin/sh\nprintf "original\\n"\n')
        self.hook.chmod(0o755)
        self.assertEqual(self.shell("ss_dns_hooks_install").returncode, 0)
        replacement = '#!/bin/sh\nprintf "replacement\\n"\n'
        self.hook.write_text(replacement)
        self.assertEqual(self.shell("ss_dns_hooks_remove\nss_dns_hooks_remove").returncode, 0)
        self.assertEqual(self.hook.read_text(), replacement)
        self.assertTrue((self.state / "previous.postconf").exists())
        self.assertNotEqual(self.shell("ss_dns_hooks_install").returncode, 0)
        self.assertEqual(self.hook.read_text(), replacement)

    def test_legacy_owned_hook_does_not_survive_plugin_stop(self):
        self.hook.symlink_to(self.template)
        self.assertEqual(self.shell("ss_dns_hooks_install\nss_dns_hooks_install\nss_dns_hooks_remove").returncode, 0)
        self.assertFalse(self.hook.exists())
        self.assertFalse(self.hook.is_symlink())
        self.assertTrue(self.conf_add.exists())

    def test_actual_legacy_regular_hook_migrates_without_false_foreign_backup(self):
        self.hook.write_bytes((Path(__file__).parent / "fixtures/dnsmasq.postconf.legacy380").read_bytes())
        self.hook.chmod(0o755)
        r = self.shell("ss_dns_hooks_install")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.state / "previous.kind").read_text(), "legacy\n")
        self.assertFalse((self.state / "previous.postconf").exists())
        self.assertEqual(self.shell("ss_dns_hooks_remove").returncode, 0)
        self.assertFalse(self.hook.exists())

    def test_unknown_nonexecutable_hook_is_preserved_but_not_executed(self):
        self.hook.write_text("not an executable shell hook\n")
        self.hook.chmod(0o640)
        self.assertEqual(self.shell("ss_dns_hooks_install").returncode, 0)
        config = self.base / "dns.conf"
        subprocess.run([str(self.hook), str(config)], check=True)
        self.assertEqual(config.read_text(), "science\n")
        self.assertEqual(self.shell("ss_dns_hooks_remove").returncode, 0)
        self.assertEqual(self.hook.read_text(), "not an executable shell hook\n")
        self.assertEqual(stat.S_IMODE(self.hook.stat().st_mode), 0o640)

    def test_unknown_interpreter_refuses_replacement(self):
        self.hook.write_text("#!/usr/bin/python\nprint('preserve me')\n")
        self.hook.chmod(0o755)
        original = self.hook.read_bytes()
        self.assertNotEqual(self.shell("ss_dns_hooks_install").returncode, 0)
        self.assertEqual(self.hook.read_bytes(), original)

    def test_unknown_dns_fragment_and_conf_add_are_preserved(self):
        fragment = self.jffs / "configs/dnsmasq.d/custom.conf"
        fragment.write_text("server=/uu.test/192.0.2.2\n")
        before = self.conf_add.read_bytes()
        r = self.shell(f'ss_dns_clear_fragment_links\nss_dns_install_link "{self.temp}/custom.conf" "{fragment}"')
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(fragment.read_text(), "server=/uu.test/192.0.2.2\n")
        self.assertEqual(self.conf_add.read_bytes(), before)

    def test_owned_fragment_removal_preserves_unknown_symlink(self):
        custom = self.jffs / "configs/dnsmasq.d/custom.conf"
        other = self.jffs / "configs/dnsmasq.d/cdn.conf"
        custom.symlink_to(self.temp / "custom.conf")
        other.symlink_to("/vendor/uu-cdn.conf")
        self.assertEqual(self.shell("ss_dns_clear_fragment_links").returncode, 0)
        self.assertFalse(custom.is_symlink())
        self.assertEqual(os.readlink(other), "/vendor/uu-cdn.conf")

    def test_generated_dns_config_preserves_foreign_resolver_directives(self):
        source = (ROOT / "ss/rules/dnsmasq.postconf").read_text()
        names = ["perpare", "ensure_no_resolv", "use_chn_plan"]
        definitions = "\n".join(re.search(r"(?ms)^" + name + r"\(\)\s*\{.*?^\}", source).group() for name in names)
        config = self.base / "dnsmasq.conf"
        original = "no-poll\nservers-file=/jffs/uu-servers.conf\nresolv-file=/tmp/user-resolv.conf\nno-resolv\n"
        config.write_text(original)
        command = definitions + '\npc_replace(){ :; }; pc_insert(){ printf "%s\\n" "$2" >> "$3"; }; CONFIG="$1"; ss_dns_china=11; ss_basic_mode=1; perpare; use_chn_plan; use_chn_plan'
        # The old template still uses /etc for inserting servers. Redirect only
        # that fixed test path; exercise the real functions without host writes.
        command = command.replace('"/etc/dnsmasq.conf"', '"$CONFIG"')
        result = subprocess.run(["/bin/bash", "-c", command, "dns-config-test", str(config)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        content = config.read_text()
        self.assertTrue(content.startswith(original))
        self.assertEqual(content.splitlines().count("no-resolv"), 1)

    def test_uu_dns_flags_follow_the_selected_tcp_policy(self):
        source = (ROOT / "ss/rules/dnsmasq.postconf").read_text().split('ISP_DNS1=', 1)[0]
        source = source.replace('source /usr/sbin/helper.sh', '')
        route_helper = Path(os.environ.get('SS_DNS_ROUTING_HELPER', ROOT / 'scripts/ss_routing.sh'))
        source = source.replace('/koolshare/scripts/ss_routing.sh', str(route_helper))
        mock = r'''
dbus() {
  case "$1:$2" in
    get:ss_basic_mode) printf '1\n' ;;
    get:ss_basic_uu_macs) printf '02:00:00:00:00:02\n' ;;
    get:ss_basic_uu_tcp_policy) printf '%s\n' "$POLICY" ;;
    list:ss_acl_mode_) [ -z "$ACL_MODE" ] || printf 'ss_acl_mode_1=%s\n' "$ACL_MODE" ;;
    *) : ;;
  esac
}
'''
        for policy, acl, expected in [('', '', '1|'), ('gfwlist', '', '1|'),
                                      ('foreign', '', '|1'), ('direct', '', '|'),
                                      ('direct', '2', '|2')]:
            with self.subTest(policy=policy, acl=acl):
                code = 'POLICY=' + shlex.quote(policy) + '; ACL_MODE=' + shlex.quote(acl) + '\n'
                code += mock + source + '\nprintf "%s|%s" "$gfw_on" "$chn_on"\n'
                result = subprocess.run(['/bin/bash', '-c', code, 'dns-flags', 'unused.conf'],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
