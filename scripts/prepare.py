#!/usr/bin/env python3
"""Prepare a local build from user-supplied inputs; never download or run them."""

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import shlex
import shutil
import stat
import subprocess
import tarfile


ROOT = Path(__file__).resolve().parents[1]
BASE_SHA256 = "05a30314c8c6d8f33ae9c027b42927e9d17e6e648c75ac7b419282fe5c1c2adf"


def regular_file(value):
    path = Path(value).expanduser().absolute()
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("Input must be a regular file, not a link: " + str(path))
    return path


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_members(members):
    """Validate the complete archive before creating an output directory."""
    seen = set()
    for member in members:
        path = PurePosixPath(member.name)
        if (path.is_absolute() or ".." in path.parts or "\\" in member.name
                or not path.parts or path.parts[0] != "shadowsocks"):
            raise ValueError("Unsafe archive path: " + member.name)
        if not (member.isdir() or member.isfile()):
            raise ValueError("Archive links and special entries are not allowed: " + member.name)
        if path in seen:
            raise ValueError("Duplicate archive path: " + member.name)
        seen.add(path)
    return seen


def validate_overlay(overlay):
    if overlay.is_symlink() or not overlay.is_dir():
        raise ValueError("The public plugin overlay directory is missing or is a link")
    for path in overlay.rglob("*"):
        mode = path.lstat().st_mode
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError("Overlay links and special entries are not allowed: " + str(path))


def extract_regular(archive, members, destination):
    for member in members:
        target = destination.joinpath(*PurePosixPath(member.name).parts)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.extractfile(member) as source, target.open("xb") as output:
            shutil.copyfileobj(source, output)
        target.chmod(member.mode & 0o777)


def prepare(base, anytls, flock, ca_bundle, destination, root=ROOT):
    base, anytls, flock, ca_bundle = map(regular_file, (base, anytls, flock, ca_bundle))
    if sha256(base) != BASE_SHA256:
        raise ValueError("Base archive SHA256 does not match the verified fancyss 4.38.3 release")
    destination = Path(destination).expanduser().absolute()
    if os.path.lexists(destination):
        raise ValueError("Destination already exists; choose a new directory: " + str(destination))
    patch = regular_file(root / "patches/fancyss-4.38.3.patch")
    overlay = root / "plugin/overlay"
    validate_overlay(overlay)
    patch_tool = shutil.which("patch")
    if patch_tool is None:
        raise ValueError("The patch command is required")
    with tarfile.open(base, "r:gz") as archive:
        members = archive.getmembers()
        paths = validate_members(members)
        fixture_source = PurePosixPath("shadowsocks/ss/rules/dnsmasq.postconf")
        if fixture_source not in paths:
            raise ValueError("Base archive does not contain dnsmasq.postconf")
        destination.mkdir(parents=True)
        try:
            plugin = destination / "r7000-enhanced"
            plugin.mkdir()
            extract_regular(archive, members, plugin)
            fixture = plugin / "tests/fixtures/dnsmasq.postconf.legacy380"
            fixture.parent.mkdir(parents=True)
            shutil.copy2(plugin / str(fixture_source), fixture)
            command = [patch_tool, "-p1", "--batch", "--forward", "-i", str(patch)]
            subprocess.run(command + ["--dry-run"], cwd=plugin, check=True)
            subprocess.run(command, cwd=plugin, check=True)
            shutil.copytree(overlay, plugin, dirs_exist_ok=True)
            ca_target = plugin / "shadowsocks/ss/rules/cacert.pem"
            shutil.copyfile(ca_bundle, ca_target)
            ca_target.chmod(0o644)
            ca_target.with_suffix(".pem.sha256").write_text(sha256(ca_target) + "  cacert.pem\n")
            binaries = destination / "r7000-client/dist"
            binaries.mkdir(parents=True)
            for source, name in ((anytls, "anytls-client-linux-armv5-r7000.3"),
                                 (flock, "ss-flock-linux-armv5")):
                target = binaries / name
                shutil.copyfile(source, target)
                target.chmod(0o755)
        except BaseException:
            shutil.rmtree(destination)
            raise
    return destination / "r7000-enhanced/build-enhancement.py"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="Original fancyss 4.38.3 tar.gz")
    parser.add_argument("--anytls-binary", required=True, help="Locally built R7000 AnyTLS client")
    parser.add_argument("--flock-binary", required=True, help="Locally built ARM ss-flock")
    parser.add_argument("--ca-bundle", required=True, help="User-supplied PEM CA bundle")
    parser.add_argument("--dest", type=Path, default=ROOT / "build")
    args = parser.parse_args()
    try:
        script = prepare(args.base, args.anytls_binary, args.flock_binary, args.ca_bundle, args.dest)
    except (OSError, ValueError, tarfile.TarError, subprocess.CalledProcessError) as error:
        parser.exit(1, "Preparation failed: " + str(error) + "\n")
    print("Prepared locally; input binaries were not executed. Build with:")
    print("python3 " + shlex.quote(str(script)))


if __name__ == "__main__":
    main()
