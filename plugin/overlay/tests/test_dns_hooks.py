import os
import re
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
