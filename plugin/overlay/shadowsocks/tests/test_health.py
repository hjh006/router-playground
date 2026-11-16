#!/usr/bin/env python3
"""Exercise the real shell script with local commands; never contact a router/network."""
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ss_health.sh"
MOCK = r'''
import fcntl, json, os, pathlib, sys, tempfile, time
root = pathlib.Path(os.environ["SS_HEALTH_TEST_ROOT"])
control = json.loads((root / "control.json").read_text())
run = os.environ.get("HEALTH_TEST_RUN_ID", "main")
command = pathlib.Path(sys.argv[0]).name
if command == "ss-flock": command = "flock"
args = sys.argv[1:]
def event(**data):
    data.update(command=command, run=run)
    fd = os.open(root / "events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.write(fd, (json.dumps(data) + "\n").encode())
    os.close(fd)
def gate(count=None, target=None):
    selected = control.get("gate", {})
    if (selected.get("command") == command and selected.get("run") == run
            and ("count" not in selected or selected["count"] == count)
            and ("target" not in selected or selected["target"] == target)):
        (root / (command + "." + run + ".blocked")).touch()
        deadline = time.monotonic() + 8
        while not (root / ("release." + run)).exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("mock gate was not released")
            time.sleep(.01)
if command == "flock":
    if len(args) == 2 and args[0] == "mktemp":
        template = pathlib.Path(args[1])
        if not template.name.endswith("XXXXXX"): raise RuntimeError("invalid temp template")
        fd, path = tempfile.mkstemp(prefix=template.name[:-6], dir=template.parent)
        os.close(fd)
        print(path)
        sys.exit(0)
    if len(args) != 2 or args[0] not in ("-x", "-n", "-u") or args[1] not in ("8", "9"):
        raise RuntimeError("unexpected flock invocation")
    fd = int(args[1])
    op = fcntl.LOCK_UN if args[0] == "-u" else fcntl.LOCK_EX
    if args[0] == "-n": op |= fcntl.LOCK_NB
    event(action="attempt", fd=fd, mode=args[0])
    try: fcntl.flock(fd, op)
    except BlockingIOError: sys.exit(1)
    event(action="acquired", fd=fd, mode=args[0])
elif command == "dbus":
    if len(args) != 2 or args[0] != "get": raise RuntimeError("unexpected dbus mutation")
    print({"ssconf_basic_node": control.get("node", "1"),
           "ss_basic_enable": str(control.get("enabled", 1)),
           "ss_basic_health_interval": str(control.get("health_interval", "")),
           "ss_basic_health_timeout": str(control.get("health_timeout", "")),
           "ss_basic_health_failures": str(control.get("health_failures", ""))}.get(args[1], ""))
elif command == "netstat":
    if args != ["-nl"]: raise RuntimeError("netstat must not expose process arguments")
    if control.get("proxy", True): print("tcp 0 0 127.0.0.1:23456 0.0.0.0:* LISTEN")
elif command == "date":
    if args == ["+%s"]:
        counter = root / ("dates." + run)
        count = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(count))
        gate(count=count)
        print(control.get("now", 1700000000))
    else: print("2026-11-16 12:00:00")
elif command == "nvram":
    if len(args) != 2 or args[0] != "set" or not args[1].startswith("ss_foreign_state="):
        raise RuntimeError("unexpected nvram access")
    event(value=args[1])
elif command == "curl":
    values = {"--cacert", "--socks5-hostname", "--connect-timeout", "--max-time", "-o", "--write-out"}
    switches = {"-sS", "-I"}
    options, urls, i = {}, [], 0
    while i < len(args):
        arg = args[i]
        if arg in values and i + 1 < len(args):
            options[arg] = args[i + 1]; i += 2
        elif arg in switches: i += 1
        elif arg.startswith("-"):
            event(error="unsupported legacy curl option", option=arg); sys.exit(2)
        else: urls.append(arg); i += 1
    timeout = str(control.get("health_timeout", ""))
    if timeout not in ("6", "8", "10"): timeout = "10"
    if (len(urls) != 1 or options.get("--write-out") != "%{http_code}|%{time_total}"
            or options.get("--socks5-hostname") != "127.0.0.1:23456"
            or options.get("--connect-timeout") != timeout or options.get("--max-time") != timeout
            or options.get("--cacert") != str(root / "koolshare/ss/rules/cacert.pem")):
        event(error="unexpected curl contract"); sys.exit(2)
    url = urls[0]
    target = {"https://www.gstatic.com/generate_204": "google",
              "https://www.youtube.com/generate_204": "youtube",
              "https://telegram.org/": "telegram"}.get(url)
    if target is None: raise RuntimeError("unexpected external destination")
    event(target=target, timeout=int(timeout), connect_timeout=int(options["--connect-timeout"]))
    gate(target=target)
    response = control.get("responses", {}).get(target, {"rc": 0, "http": "204", "seconds": "0.100"})
    print(str(response.get("http", "000")) + "|" + str(response.get("seconds", "0.000")), end="")
    sys.exit(response.get("rc", 0))
else: raise RuntimeError("unexpected mock command")
'''


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="r7000-health-")
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.public = self.root / "public/ss_health.json"
        self.state.mkdir()
        self.public.parent.mkdir()
        (self.state / "generation").write_text("initial-generation\n")
        self.bin = self.root / "koolshare/bin"
        self.bin.mkdir(parents=True)
        (self.root / "koolshare/res").mkdir()
        (self.root / "koolshare/ss/rules").mkdir(parents=True)
        (self.root / "koolshare/ss/rules/cacert.pem").write_text("test-only certificate placeholder\n")
        dispatch = self.bin / "mock_dispatch.py"
        dispatch.write_text("#!" + sys.executable + "\n" + MOCK)
        dispatch.chmod(0o755)
        for command in ("ss-flock", "dbus", "netstat", "date", "nvram", "curl"):
            (self.bin / command).symlink_to(dispatch.name)
        self.control = {"enabled": 1, "node": "1", "now": 1700000000}
        self.configure()
        self.env = dict(os.environ, SS_HEALTH_TEST_ROOT=str(self.root),
                        SS_HEALTH_KOOLSHARE=str(self.root / "koolshare"),
                        SS_HEALTH_STATE=str(self.state), SS_HEALTH_JSON=str(self.public))
        self.processes = []

    def tearDown(self):
        for process in self.processes:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            if process.poll() is None:
                try:
                    process.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.communicate()
        self.temp.cleanup()

    def configure(self, **changes):
        self.control.update(changes)
        temporary = self.root / "control.new"
        temporary.write_text(json.dumps(self.control))
        temporary.replace(self.root / "control.json")

    def start(self, action="refresh", run="main"):
        process = subprocess.Popen(["/bin/sh", str(SCRIPT), action], env=dict(self.env, HEALTH_TEST_RUN_ID=run),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        self.processes.append(process)
        return process

    def finish(self, process):
        stdout, stderr = process.communicate(timeout=12)
        self.assertEqual(process.returncode, 0, (stdout, stderr))

    def run_health(self, action="force", run="main"):
        self.finish(self.start(action, run))
        return self.snapshot()

    def snapshot(self):
        return json.loads(self.public.read_text())

    def events(self, command=None):
        path = self.root / "events.jsonl"
        events = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        return [event for event in events if command is None or event["command"] == command]

    def wait_for(self, predicate):
        deadline = time.monotonic() + 5
        while not predicate():
            if time.monotonic() >= deadline:
                self.fail("mock command did not reach expected boundary")
            time.sleep(.01)

    def release(self, run="worker"):
        (self.root / ("release." + run)).touch()

    def all_responses(self, milliseconds=100, rc=0):
        return {target: {"rc": rc, "http": "204" if rc == 0 else "000", "seconds": "%.3f" % (milliseconds / 1000)}
                for target in ("google", "youtube", "telegram")}

    def test_health_degraded_down_and_recovery_contract(self):
        result = self.run_health()
        self.assertEqual((result["status"], result["success"], result["total"]), ("healthy", 1, 1))
        self.assertEqual(stat.S_IMODE(self.public.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        partial = self.all_responses()
        partial["youtube"].update(rc=28, http="000")
        self.configure(responses=partial)
        result = self.run_health()
        self.assertEqual((result["status"], result["consecutive_failures"]), ("degraded", 0))
        self.configure(responses=self.all_responses(rc=28))
        for count, expected in ((1, "degraded"), (2, "degraded"), (3, "down")):
            result = self.run_health()
            self.assertEqual((result["status"], result["consecutive_failures"]), (expected, count))
        self.configure(responses=self.all_responses())
        result = self.run_health()
        self.assertEqual((result["status"], result["consecutive_failures"]), ("healthy", 0))

    def test_proxy_absence_is_intended_immediate_down_exception(self):
        self.configure(proxy=False, health_failures="5")
        result = self.run_health()
        self.assertEqual((result["status"], result["consecutive_failures"]), ("down", 1))
        self.assertEqual(result["targets"][0]["state"], "proxy_unavailable")
        self.assertFalse(self.events("curl"))

    def test_private_flock_is_a_required_prerequisite(self):
        (self.bin / "ss-flock").unlink()
        process = self.start()
        _, stderr = process.communicate(timeout=5)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("prerequisite missing", stderr)
        self.assertFalse(self.public.exists())
        self.assertFalse(self.events())
        self.assertFalse((self.bin / "flock").exists())

    def test_legacy_curl_whitelist_and_no_new_format_variables(self):
        rejected = subprocess.run([str(self.bin / "curl"), "--http1.1"], env=self.env, capture_output=True)
        self.assertEqual(rejected.returncode, 2)
        (self.root / "events.jsonl").unlink()
        self.assertEqual(self.run_health()["status"], "healthy")
        self.assertEqual(len(self.events("curl")), 3)
        self.assertFalse(any("error" in event for event in self.events()))

    def test_cache_expires_at_thirty_seconds(self):
        first = self.run_health("refresh")
        self.assertEqual(self.run_health("refresh"), first)
        self.assertEqual(len(self.events("curl")), 3)
        self.configure(now=self.control["now"] + 30)
        self.assertEqual(self.run_health("refresh")["total"], 2)
        self.assertEqual(len(self.events("curl")), 6)

    def test_valid_configuration_and_initial_interval(self):
        for interval, timeout in ((30, 6), (60, 8), (120, 10)):
            with self.subTest(interval=interval, timeout=timeout):
                self.configure(health_interval=str(interval), health_timeout=str(timeout))
                result = self.run_health()
                self.assertEqual(result["interval_sec"], interval)
                self.assertEqual(result["status"], "healthy")
                self.assertTrue(all(event["timeout"] == timeout and event["connect_timeout"] == timeout
                                    for event in self.events("curl")[-3:]))
        result = self.run_health("stop")
        self.assertFalse(result["enabled"])
        self.assertEqual(result["interval_sec"], 120)

    def test_invalid_configuration_falls_back_to_defaults(self):
        marker = self.root / "must-not-exist"
        for interval, timeout, failures in (("31", "7", "0"), ("121", "11", "6"),
                                            ("30; touch " + str(marker), "8\n10", "03")):
            with self.subTest(interval=interval, timeout=timeout, failures=failures):
                self.configure(health_interval=interval, health_timeout=timeout, health_failures=failures,
                               responses=self.all_responses(rc=28))
                (self.state / "state").write_text("1 2 0\n")
                result = self.run_health()
                self.assertEqual((result["interval_sec"], result["status"], result["consecutive_failures"]),
                                 (30, "down", 3))
                self.assertTrue(all(event["timeout"] == 10 and event["connect_timeout"] == 10
                                    for event in self.events("curl")[-3:]))
        self.assertFalse(marker.exists())

    def test_configured_cache_intervals(self):
        for interval in (60, 120):
            with self.subTest(interval=interval):
                self.configure(health_interval=str(interval))
                first = self.run_health()
                calls = len(self.events("curl"))
                self.configure(now=first["checked_at"] + interval - 1)
                self.assertEqual(self.run_health("refresh"), first)
                self.assertEqual(len(self.events("curl")), calls)
                self.configure(now=first["checked_at"] + interval)
                result = self.run_health("refresh")
                self.assertEqual(result["interval_sec"], interval)
                self.assertEqual(len(self.events("curl")), calls + 3)

    def test_each_configured_failure_threshold(self):
        self.configure(responses=self.all_responses(rc=28))
        for threshold in range(1, 6):
            with self.subTest(threshold=threshold):
                self.configure(health_failures=str(threshold))
                if threshold > 1:
                    (self.state / "state").write_text("1 %d 0\n" % (threshold - 2))
                    result = self.run_health()
                    self.assertEqual((result["status"], result["consecutive_failures"]),
                                     ("degraded", threshold - 1))
                (self.state / "state").write_text("1 %d 0\n" % (threshold - 1))
                result = self.run_health()
                self.assertEqual((result["status"], result["consecutive_failures"]), ("down", threshold))

    def test_twenty_round_window_and_statistics(self):
        (self.state / "state").write_text("1 0 0\n")
        (self.state / "history").write_text("".join("%d %d 1\n" % (index, index * 100) for index in range(1, 24)))
        self.configure(responses=self.all_responses(2400))
        result = self.run_health()
        self.assertEqual((result["total"], result["success"], result["last_latency_ms"]), (20, 20, 2400))
        self.assertEqual((result["median_ms"], result["p95_ms"], result["jitter_ms"]), (1450, 2300, 100))
        self.assertEqual(len((self.state / "history").read_text().splitlines()), 20)

    def test_node_change_discards_previous_history_and_cache(self):
        self.run_health("refresh")
        self.configure(node="2", responses=self.all_responses(350))
        result = self.run_health("refresh")
        self.assertEqual((result["node_id"], result["total"], result["last_latency_ms"]), (2, 1, 350))

    def test_disabled_clears_cache_and_reenable_samples_immediately(self):
        self.run_health("refresh")
        self.configure(enabled=0)
        result = self.run_health("refresh")
        self.assertFalse(result["enabled"])
        self.assertEqual(result["total"], 0)
        self.assertEqual(len(self.events("curl")), 3)
        self.assertFalse((self.state / "history").exists())
        self.configure(enabled=1)
        self.assertEqual(self.run_health("refresh")["total"], 1)
        self.assertEqual(len(self.events("curl")), 6)

    def test_concurrent_refresh_runs_only_one_probe_round(self):
        self.configure(gate={"command": "curl", "run": "worker", "target": "google"})
        worker = self.start(run="worker")
        self.wait_for(lambda: (self.root / "curl.worker.blocked").exists())
        self.finish(self.start(run="other"))
        self.release()
        self.finish(worker)
        self.assertEqual(len(self.events("curl")), 3)
        self.assertEqual(self.snapshot()["total"], 1)
        self.assertEqual(self.run_health("refresh")["total"], 1)
        self.assertEqual(len(self.events("curl")), 3)

    def test_signal_exits_instead_of_publishing_after_cleanup(self):
        self.configure(gate={"command": "curl", "run": "worker", "target": "google"})
        worker = self.start(run="worker")
        self.wait_for(lambda: (self.root / "curl.worker.blocked").exists())
        worker.send_signal(signal.SIGTERM)
        self.release()
        worker.communicate(timeout=5)
        self.assertNotEqual(worker.returncode, 0)
        self.assertFalse((self.state / "history").exists())
        self.assertEqual(self.snapshot()["status"], "checking")
        self.assertFalse(list(self.state.glob("targets.*")))
        self.run_health("refresh", run="after-signal")
        self.assertEqual(self.snapshot()["status"], "healthy")

    def test_stop_during_probe_invalidates_worker(self):
        self.configure(gate={"command": "curl", "run": "worker", "target": "google"})
        worker = self.start(run="worker")
        self.wait_for(lambda: (self.root / "curl.worker.blocked").exists())
        self.run_health("stop", run="stop")
        self.release()
        self.finish(worker)
        self.assertFalse(self.snapshot()["enabled"])
        self.assertFalse((self.state / "history").exists())

    def at_commit_boundary(self, action):
        self.configure(responses=self.all_responses(111), gate={"command": "date", "run": "worker", "count": 2})
        worker = self.start(run="worker")
        self.wait_for(lambda: (self.root / "date.worker.blocked").exists())
        self.configure(responses=self.all_responses(300))
        transition = self.start(action, run=action)
        self.wait_for(lambda: any(event.get("run") == action and event.get("fd") == 8
                                  and event.get("action") == "attempt" for event in self.events("flock")))
        self.assertFalse(any(event.get("run") == action and event.get("fd") == 8
                             and event.get("action") == "acquired" for event in self.events("flock")))
        self.release()
        self.finish(worker)
        self.finish(transition)
        return self.snapshot()

    def test_stop_at_commit_boundary_cannot_be_overwritten_by_old_worker(self):
        result = self.at_commit_boundary("stop")
        self.assertFalse(result["enabled"])
        self.assertEqual(result["total"], 0)
        self.assertFalse((self.state / "history").exists())
        self.assertNotEqual((self.state / "generation").read_text().strip(), "initial-generation")

    def test_reset_at_commit_boundary_cannot_resurrect_old_history(self):
        result = self.at_commit_boundary("reset")
        self.assertIn(result["total"], (0, 1))
        self.assertNotEqual((self.state / "generation").read_text().strip(), "initial-generation")
        # The reset's refresh may have raced the retiring worker's probe lock.
        # A normal subsequent refresh must either join the new sample or take it.
        self.configure(gate={})
        self.run_health("refresh", run="after-reset")
        self.wait_for(lambda: self.snapshot()["total"] > 0)
        self.assertEqual((self.snapshot()["total"], self.snapshot()["last_latency_ms"]), (1, 300))
        self.assertNotIn(" 111 ", (self.state / "history").read_text())


if __name__ == "__main__":
    unittest.main()
