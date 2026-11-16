#!/usr/bin/env python3
"""Run synthetic JVM tests on loopback only. Requires an external org.json JAR."""
import argparse
import hashlib
import os
from pathlib import Path

from build import BUILD, ROOT, find_java, reset_build_directory, run


JSON_SHA256 = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
TESTS = ("RouterApiTest", "LatencyProbeTest", "CountryGroupsTest")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-jar", required=True, type=Path, help="External org.json:json:20240303 JAR")
    options = parser.parse_args()
    jar = options.json_jar.expanduser().resolve()
    if not jar.is_file() or hashlib.sha256(jar.read_bytes()).hexdigest() != JSON_SHA256:
        raise SystemExit("Expected the unmodified org.json:json:20240303 JAR (SHA-256 mismatch or missing file).")
    java = find_java()
    cache = BUILD / "jvm-tests"
    reset_build_directory(cache)
    sources = [ROOT / "src/cn/simon/routercontrol" / (name + ".java")
               for name in ("RouterApi", "LatencyProbe", "CountryGroups")]
    sources += [ROOT / "tests" / (name + ".java") for name in TESTS]
    run([java / "bin/javac", "-encoding", "UTF-8", "--add-modules", "jdk.httpserver",
         "-classpath", jar, "-d", cache, *sources])
    classpath = str(cache) + os.pathsep + str(jar)
    for test in TESTS:
        run([java / "bin/java", "--add-modules", "jdk.httpserver", "-classpath", classpath,
             "cn.simon.routercontrol." + test])


if __name__ == "__main__":
    main()
