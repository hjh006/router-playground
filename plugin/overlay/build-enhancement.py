#!/usr/bin/env python3
"""Build the private deployment and generic update from an explicit file list."""
import argparse
import hashlib
import json
import shutil
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORK = ROOT.parent
FILES = [
    'bin/anytls', 'bin/ss-flock',
    'scripts/ss_anytls.sh', 'scripts/ss_health.sh',
    'scripts/ss_routing.sh', 'scripts/ss_dns_hooks.sh',
    'scripts/ss_webtest.sh', 'scripts/uninstall_shadowsocks.sh',
    'ss/ssconfig.sh', 'ss/cru/foreign.sh',
    'ss/rules/dnsmasq.postconf', 'ss/rules/cacert.pem',
    'ss/rules/cacert.pem.sha256', 'webs/Main_Ss_Content.asp',
    'res/ss-health.js', 'res/ss-health.css', 'res/icon-shadowsocks.png',
]

def build(private=False):
    label = 'private' if private else 'generic'
    stage = WORK / ('r7000-update-' + label)
    if stage.exists():
        shutil.rmtree(stage)
    package = stage / 'shadowsocks'
    package.mkdir(parents=True)
    shutil.copy2(ROOT/'enhancement/install.sh', package/'install.sh')
    binary_sources = {
        'bin/anytls': WORK/'r7000-client/dist/anytls-client-linux-armv5-r7000.3',
        'bin/ss-flock': WORK/'r7000-client/dist/ss-flock-linux-armv5',
        'scripts/uninstall_shadowsocks.sh': ROOT/'shadowsocks/uninstall.sh',
    }
    checksums = []
    sha = {}
    for name in FILES:
        src = binary_sources.get(name, ROOT/'shadowsocks'/name)
        dst = package/'payload'/name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        dst.chmod(0o755 if name.startswith(('bin/', 'scripts/')) or name in
                  ('ss/ssconfig.sh', 'ss/cru/foreign.sh', 'ss/rules/dnsmasq.postconf') else 0o644)
        data = dst.read_bytes()
        checksums.append(hashlib.md5(data).hexdigest() + '  ' + name)
        sha[name] = hashlib.sha256(data).hexdigest()
    (package/'manifest.md5').write_text('\n'.join(checksums)+'\n')
    (package/'BUILD.json').write_text(json.dumps({
        'build': '4.38.3-r7000.3',
        'upstream': 'https://github.com/cary-sas/v2ray_bin',
        'base_release_sha256': '05a30314c8c6d8f33ae9c027b42927e9d17e6e648c75ac7b419282fe5c1c2adf',
        'files_sha256': sha,
        'personal_settings_included': private,
    }, indent=2)+'\n')
    if private:
        # User-specific selection is deliberately kept out of the source/package defaults.
        settings = json.loads((WORK/'r7000-device-state/deployment-settings.json').read_text())
        (package/'private-settings').write_text(''.join(k+'='+v+'\n' for k,v in settings.items()))
        (package/'private-settings').chmod(0o600)
        # The software center invokes install.sh with no arguments. Keep the
        # personal deployment wrapper outside the generic installer/source.
        shutil.copy2(package/'install.sh', package/'update.sh')
        (package/'install.sh').write_text(
            '#!/bin/sh\n'
            'base=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 1\n'
            'exec sh "$base/update.sh" --settings "$base/private-settings" '
            '--migration=phone-insecure\n')
        (package/'install.sh').chmod(0o755)
    archive = stage/'shadowsocks.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        tar.add(package, arcname='shadowsocks', filter=lambda item: item)
    archive.chmod(0o600 if private else 0o644)
    print(json.dumps({'package': str(archive), 'bytes': archive.stat().st_size,
                      'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
                      'payload_files': len(FILES), 'personal_settings': private}))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--private', action='store_true')
    build(parser.parse_args().private)
