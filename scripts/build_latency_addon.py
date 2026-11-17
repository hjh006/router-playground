#!/usr/bin/env python3
"""Package only the original latency component from a prepared plugin tree."""
import argparse
import gzip
import hashlib
import io
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
FILES = ("bin/ss-tcp-probe", "bin/ss_latency.sh", "scripts/ss_latency.sh", "res/ss-latency-capabilities.js")


def build(prepared, output):
    prepared, output = Path(prepared).resolve(), Path(output).resolve()
    entries = {"install.sh": (ROOT / "plugin/overlay/enhancement/install-latency.sh").read_bytes(),
               "LICENSE": (ROOT / "LICENSE").read_bytes(),
               "THIRD_PARTY_NOTICES.md": (ROOT / "THIRD_PARTY_NOTICES.md").read_bytes(),
               "licenses/Go-LICENSE.txt": (ROOT / "licenses/Go-LICENSE.txt").read_bytes()}
    manifest = []
    for name in FILES:
        if name == "bin/ss-tcp-probe":
            source = prepared.parent / "r7000-client/dist/ss-tcp-probe-linux-armv5"
            if source.is_symlink() or not source.is_file() or not 0 < source.stat().st_size <= 8 * 1024 * 1024:
                raise ValueError("Prepared local TCP probe is missing or invalid")
        else:
            source = prepared / "shadowsocks" / name
            original = ROOT / "plugin/overlay/shadowsocks" / name
            if source.is_symlink() or not source.is_file() or source.read_bytes() != original.read_bytes():
                raise ValueError("Prepared measurement file is missing or stale: " + name)
        data = source.read_bytes()
        entries["payload/" + name] = data
        manifest.append(hashlib.md5(data).hexdigest() + "  " + name)
    entries["manifest.md5"] = ("\n".join(manifest) + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for name, data in sorted(entries.items()):
                item = tarfile.TarInfo("latency/" + name)
                item.mode = 0o755 if name.endswith(".sh") or name == "payload/bin/ss-tcp-probe" else 0o644
                item.size = len(data)
                archive.addfile(item, io.BytesIO(data))
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_name(output.name + ".sha256").write_text(digest + "  " + output.name + "\n")
    return digest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared-plugin", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "outputs/r7000-latency/latency.tar.gz")
    args = parser.parse_args()
    print(build(args.prepared_plugin, args.output))
