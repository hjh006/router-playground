#!/usr/bin/env python3
"""Check wrapper argv with a local fake client; no credentials or network used."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ss_anytls.sh"
MOCK = r'''
import json, os, pathlib, sys
root = pathlib.Path(os.environ["ANYTLS_WRAPPER_TEST_ROOT"])
settings = json.loads((root / "settings.json").read_text())
args = sys.argv[1:]
calls = root / "calls.json"
history = json.loads(calls.read_text()) if calls.exists() else []
history.append([pathlib.Path(sys.argv[0]).name, *args])
calls.write_text(json.dumps(history))
if pathlib.Path(sys.argv[0]).name == "dbus":
    if len(args) != 2 or args[0] != "get": raise RuntimeError("unexpected dbus mutation")
    print(settings.get(args[1], ""))
elif args == ["-version"]:
    print(settings.get("client_version", "anytls/0.0.13-r7000.3"))
    sys.exit(int(settings.get("version_exit", 0)))
else:
    (root / "argv.json").write_text(json.dumps(args))
    sys.exit(int(settings.get("client_exit", 0)))
'''


class AnyTLSWrapperTests(unittest.TestCase):
    def setUp(self):
        # Spaces in the path also catch accidental unquoted executable expansion.
        self.temp = tempfile.TemporaryDirectory(prefix="r7000 wrapper ")
        self.root = Path(self.temp.name)
        self.koolshare = self.root / "koolshare"
        self.bin = self.koolshare / "bin"
        self.bin.mkdir(parents=True)
        dispatch = self.bin / "mock_dispatch.py"
        dispatch.write_text("#!" + sys.executable + "\n" + MOCK)
        dispatch.chmod(0o755)
        for command in ("dbus", "anytls"):
            (self.bin / command).symlink_to(dispatch.name)
        self.settings = {}
        self.env = dict(os.environ, SS_ANYTLS_KOOLSHARE=str(self.koolshare),
                        ANYTLS_WRAPPER_TEST_ROOT=str(self.root))
        self.env.pop("SS_ANYTLS_INSECURE", None)

    def tearDown(self):
        self.temp.cleanup()

    def run_wrapper(self, arguments=(), insecure=None):
        (self.root / "settings.json").write_text(json.dumps(self.settings))
        for name in ("argv.json", "calls.json"):
            (self.root / name).unlink(missing_ok=True)
        env = dict(self.env)
        if insecure is not None:
            env["SS_ANYTLS_INSECURE"] = insecure
        result = subprocess.run(["/bin/sh", str(SCRIPT), *arguments], env=env,
                                capture_output=True, text=True, timeout=5)
        path = self.root / "argv.json"
        argv = json.loads(path.read_text()) if path.exists() else None
        return result, argv

    def option(self, argv, flag):
        return argv[argv.index(flag) + 1]

    def test_r7000_3_default_arguments_and_exit_status(self):
        self.settings["client_exit"] = 23
        result, argv = self.run_wrapper(["-s", "server.example:443", "-p", "dummy-secret"])
        self.assertEqual(result.returncode, 23)
        self.assertEqual(argv, ["-m", "0", "-idle-check", "30s", "-idle-timeout", "30s",
                                "-handshake-timeout", "8s", "-alpn", "h2", "-fingerprint", "chrome",
                                "-insecure=true", "-s", "server.example:443", "-p", "dummy-secret"])
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_versions_only_receive_supported_flags(self):
        cases = {
            "anytls/0.0.13-r7000.3": {"-m", "-idle-check", "-idle-timeout", "-handshake-timeout", "-alpn", "-fingerprint", "-insecure=false"},
            "anytls/0.0.13-r7000.2": {"-m", "-handshake-timeout", "-alpn", "-fingerprint", "-insecure=false"},
            "anytls/0.0.13-r7000.1": {"-m", "-handshake-timeout", "-alpn", "-insecure=false"},
            "anytls/0.0.13": {"-m"},
            "": {"-m"},
        }
        for version, expected in cases.items():
            with self.subTest(version=version):
                self.settings["client_version"] = version
                result, argv = self.run_wrapper(insecure="0")
                self.assertEqual(result.returncode, 0)
                self.assertEqual({value for value in argv if value.startswith("-")}, expected)

    def test_numeric_boundaries_and_decimal_normalization(self):
        keys = ["ss_basic_anytls_min_idle", "ss_basic_anytls_idle_check",
                "ss_basic_anytls_idle_timeout", "ss_basic_anytls_handshake"]
        flags = ["-m", "-idle-check", "-idle-timeout", "-handshake-timeout"]
        for values, expected in ((["0", "5", "5", "3"], ["0", "5s", "5s", "3s"]),
                                 (["20", "300", "600", "20"], ["20", "300s", "600s", "20s"]),
                                 (["009", "030", "060", "008"], ["9", "30s", "60s", "8s"])):
            with self.subTest(values=values):
                self.settings.update(zip(keys, values))
                result, argv = self.run_wrapper()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([self.option(argv, flag) for flag in flags], expected)

    def test_invalid_scalars_fall_back_without_shell_evaluation(self):
        marker = self.root / "must-not-exist"
        keys = ["ss_basic_anytls_min_idle", "ss_basic_anytls_idle_check",
                "ss_basic_anytls_idle_timeout", "ss_basic_anytls_handshake"]
        defaults = ["0", "30s", "30s", "8s"]
        flags = ["-m", "-idle-check", "-idle-timeout", "-handshake-timeout"]
        for values in (("21", "301", "601", "21"), ("-1", "4", "0", "2"),
                       ("999999999999999999999", "0300", "1.5", " 8"),
                       ("$(touch " + str(marker) + ")", "5; touch " + str(marker), "5\n6", "x")):
            with self.subTest(values=values):
                self.settings.update(zip(keys, values))
                result, argv = self.run_wrapper()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([self.option(argv, flag) for flag in flags], defaults)
        self.assertFalse(marker.exists())

    def test_alpn_and_fingerprint_allowlists(self):
        for alpn in ("auto", "h2", "http/1.1", "h2,http/1.1", "http/1.1,h2", "", "h2,unknown"):
            with self.subTest(alpn=alpn):
                self.settings["ss_basic_anytls_alpn"] = alpn
                result, argv = self.run_wrapper()
                self.assertEqual(result.returncode, 0)
                expected = "" if alpn == "auto" else alpn if alpn in ("h2", "http/1.1", "h2,http/1.1", "http/1.1,h2") else "h2"
                self.assertEqual(self.option(argv, "-alpn"), expected)
        for fingerprint in ("standard", "chrome", "", "unknown"):
            with self.subTest(fingerprint=fingerprint):
                self.settings["ss_basic_anytls_fingerprint"] = fingerprint
                _, argv = self.run_wrapper()
                self.assertEqual(self.option(argv, "-fingerprint"), fingerprint if fingerprint in ("standard", "chrome") else "chrome")

    def test_insecure_boolean_is_one_argument_and_legacy_default_preserved(self):
        for selected, expected in ((None, "true"), ("", "true"), ("1", "true"), ("true", "true"),
                                   ("0", "false"), ("false", "false")):
            with self.subTest(selected=selected):
                result, argv = self.run_wrapper(insecure=selected)
                self.assertEqual(result.returncode, 0)
                self.assertIn("-insecure=" + expected, argv)
                self.assertNotIn("-insecure", argv)

    def test_server_arguments_remain_separate_without_secret_output(self):
        marker = self.root / "must-not-exist"
        password = "dummy space ; $(touch " + str(marker) + ") @#&"
        passed = ["-socks", "127.0.0.1:23456", "-nat", "0.0.0.0:3333", "-s", "server.example:443",
                  "-p", password, "-sni", "certificate.example"]
        result, argv = self.run_wrapper(passed, insecure="false")
        self.assertEqual(argv[-len(passed):], passed)
        self.assertNotIn(password, result.stdout + result.stderr)
        self.assertFalse(marker.exists())

    def test_failed_version_probe_falls_back_to_legacy_flags(self):
        self.settings.update(client_version="", version_exit=2)
        result, argv = self.run_wrapper(["-s", "server.example:443"])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(argv, ["-m", "0", "-s", "server.example:443"])

    def calls(self):
        path = self.root / "calls.json"
        return json.loads(path.read_text()) if path.exists() else []

    def test_normalize_hosts_without_dbus_or_client(self):
        cases = {
            "": "",
            " \t\r\n,\n": "",
            " Origin.Example.Test. = Alias.Example.Test. \r\nOther.Example.Test=192.0.2.8":
                "origin.example.test=alias.example.test,other.example.test=192.0.2.8",
            "a.example.test=b.example.test,A.EXAMPLE.TEST.=B.EXAMPLE.TEST":
                "a.example.test=b.example.test",
            "192.0.2.1=alias.example.test": "192.0.2.1=alias.example.test",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                result, argv = self.run_wrapper(["normalize-hosts", value])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)
                self.assertEqual(result.stderr, "")
                self.assertIsNone(argv)
                self.assertEqual(self.calls(), [])

    def test_hosts_chain_rewrites_only_server_preserving_sni_password_and_exit(self):
        self.settings.update(ss_basic_anytls_hosts="origin.example.test=hop.example.test,hop.example.test=192.0.2.7",
                             client_exit=23)
        marker = self.root / "must-not-exist"
        password = "dummy ; $(touch " + str(marker) + ") @#&"
        passed = ["-socks", "127.0.0.1:23456", "-s", "ORIGIN.EXAMPLE.TEST.:0443", "-p", password,
                  "-sni", "origin.example.test"]
        result, argv = self.run_wrapper(passed)
        expected = list(passed)
        expected[3] = "192.0.2.7:0443"
        self.assertEqual(result.returncode, 23)
        self.assertEqual(argv[-len(expected):], expected)
        self.assertEqual(result.stdout + result.stderr, "")
        self.assertFalse(marker.exists())

    def test_server_matching_is_exact_and_opaque_flag_values_are_untouched(self):
        self.settings["ss_basic_anytls_hosts"] = "origin.example.test=alias.example.test"
        for passed in (["-s", "prefix.origin.example.test:443"],
                       ["-s", "origin.example.test.evil:443"],
                       ["-p", "-s", "-sni", "origin.example.test:443"],
                       ["-sni", "-s", "-p", "origin.example.test:443"],
                       ["--", "-s", "origin.example.test:443"],
                       ["positional", "-s", "origin.example.test:443"],
                       ["-s=origin.example.test:443"],
                       ["-s", "origin.example.test:99999"],
                       ["-s", "origin.example.test:443;echo bad"]):
            with self.subTest(passed=passed):
                result, argv = self.run_wrapper(passed)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(argv[-len(passed):], passed)

    def test_hosts_validation_rejects_injection_invalid_domains_cycles_and_long_chains(self):
        marker = self.root / "must-not-exist"
        invalid = [
            "a.example.test=$(touch " + str(marker) + ")", "a.example.test=alias.example.test;echo bad",
            "a.example.test=`id`", "a.example.test=alias\\056example.test", "a.example.test=alias.example.test&x",
            "*.example.test=alias.example.test", "a_b.example.test=alias.example.test", "a.example.test=::1",
            "a.example.test=256.1.2.3", "a.example.test=01.2.3.4", "1.2.3.4.=alias.example.test",
            "123=alias.example.test", "a.example.test=1.2.3", "a..example.test=alias.example.test",
            "-a.example.test=alias.example.test", "a-.example.test=alias.example.test",
            "a.example.test=ali as.example.test", "a.example.test=例子.example.test",
            "a.example.test==alias.example.test", "a.example.test=", "=alias.example.test",
            "a.example.test=a.example.test", "a.example.test=b.example.test,b.example.test=a.example.test",
            "a.example.test=b.example.test,a.example.test=c.example.test",
            ",".join(f"n{i}.example.test=n{i+1}.example.test" for i in range(5)),
            "a" * 64 + ".test=alias.example.test",
            ".".join(["a" * 63] * 4) + "=alias.example.test",
        ]
        for value in invalid:
            with self.subTest(value=value):
                result, argv = self.run_wrapper(["normalize-hosts", value])
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIsNone(argv)
                self.assertEqual(self.calls(), [])
                self.settings["ss_basic_anytls_hosts"] = value
                for args in (["validate-hosts"], ["-s", "a.example.test:443", "-p", "dummy-secret"]):
                    result, argv = self.run_wrapper(args)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertIsNone(argv)
                    self.assertEqual(self.calls(), [["dbus", "get", "ss_basic_anytls_hosts"]])
        self.assertFalse(marker.exists())

    def test_hosts_four_hop_and_32_entry_boundaries(self):
        chain = ",".join(f"n{i}.example.test=n{i+1}.example.test" for i in range(4))
        self.settings["ss_basic_anytls_hosts"] = chain
        result, argv = self.run_wrapper(["-s", "n0.example.test:443"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.option(argv, "-s"), "n4.example.test:443")
        entries = [f"source{i}.example.test=alias.example.test" for i in range(32)]
        for value in (",".join(entries), "\n".join(entries)):
            result, _ = self.run_wrapper(["normalize-hosts", value])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, ",".join(entries))
        for value in (",".join(entries + [entries[0]]), "\n".join(entries + ["extra.example.test=alias.example.test"])):
            result, _ = self.run_wrapper(["normalize-hosts", value])
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")

    def test_validate_hosts_uses_only_hosts_key_and_never_client(self):
        for value in ("", "origin.example.test=alias.example.test"):
            self.settings["ss_basic_anytls_hosts"] = value
            result, argv = self.run_wrapper(["validate-hosts"])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout + result.stderr, "")
            self.assertIsNone(argv)
            self.assertEqual(self.calls(), [["dbus", "get", "ss_basic_anytls_hosts"]])

    def test_map_host_resolves_chain_and_unmapped_host_without_client(self):
        self.settings["ss_basic_anytls_hosts"] = ",".join(
            f"n{i}.example.test=n{i+1}.example.test" for i in range(4))
        for original, expected in (("N0.Example.Test.", "n4.example.test"),
                                   ("n2.example.test", "n4.example.test"),
                                   ("Unmapped.Example.Test.", "unmapped.example.test"),
                                   ("192.0.2.4", "192.0.2.4")):
            with self.subTest(original=original):
                result, argv = self.run_wrapper(["map-host", original])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)
                self.assertEqual(result.stderr, "")
                self.assertIsNone(argv)
                self.assertEqual(self.calls(), [["dbus", "get", "ss_basic_anytls_hosts"]])
        self.settings["ss_basic_anytls_hosts"] = ""
        result, argv = self.run_wrapper(["map-host", "UNMAPPED.EXAMPLE.TEST."])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "unmapped.example.test")
        self.assertIsNone(argv)

    def test_map_host_rejects_invalid_input_and_invalid_mapping_without_client(self):
        self.settings["ss_basic_anytls_hosts"] = "origin.example.test=192.0.2.8"
        for original in ("", "-bad.example.test", "256.1.2.3", "01.2.3.4", "host.example.test:443",
                         "bad\\056example.test", "$(id)", "bad\nexample.test", "::1"):
            with self.subTest(original=original):
                result, argv = self.run_wrapper(["map-host", original])
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIsNone(argv)
                self.assertEqual(self.calls(), [["dbus", "get", "ss_basic_anytls_hosts"]])
        result, _ = self.run_wrapper(["map-host", "origin.example.test"])
        self.assertEqual(result.stdout, "192.0.2.8")
        for mapping in ("a.example.test=a.example.test", "a.example.test=$(id)",
                        ",".join(f"n{i}.example.test=n{i+1}.example.test" for i in range(5))):
            self.settings["ss_basic_anytls_hosts"] = mapping
            result, argv = self.run_wrapper(["map-host", "unmapped.example.test"])
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertIsNone(argv)
            self.assertEqual(self.calls(), [["dbus", "get", "ss_basic_anytls_hosts"]])


if __name__ == "__main__":
    unittest.main()
