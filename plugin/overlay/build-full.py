#!/usr/bin/env python3
"""Build a one-upload full offline package from the prepared, public source tree."""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import stat
import tarfile

ROOT = Path(__file__).resolve().parent
WORK = ROOT.parent
VERSION = '4.38.3-r7000.5-full.1'
NOTICE_FILES = ('LICENSE', 'THIRD_PARTY_NOTICES.md', 'MPL-2.0.txt', 'third-party-licenses.tar.gz')
ROOTS = ('bin', 'scripts', 'ss', 'webs', 'res')
OFFLINE_ONLY = '''#!/bin/sh
# The enhanced plugin is updated with its reviewed offline packages.
printf '%s\\n' '本增强版使用离线包更新。请从项目 Releases 下载完整包或增量包，通过软件中心离线安装。'
printf '%s\\n' 'https://github.com/hjh006/router-playground/releases'
exit 0
'''


def regular(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('Expected a regular, non-symlink file: ' + str(path))
    return path


def load_incremental_builder():
    spec = importlib.util.spec_from_file_location('incremental_builder', ROOT / 'build-enhancement.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT, module.WORK = ROOT, WORK
    return module


def destination_mode(name):
    return 0o755 if name.startswith(('bin/', 'scripts/')) or name.endswith('.sh') or name == 'ss/rules/dnsmasq.postconf' else 0o644


def build(notices):
    notices = Path(notices)
    for name in NOTICE_FILES:
        regular(notices / name)
    template = regular(ROOT / 'enhancement/install-full.sh').read_text()
    if template.count('@@FULL_FILE_COUNT@@') != 1:
        raise ValueError('Full installer must contain one manifest-count placeholder')
    incremental = load_incremental_builder()
    incremental.build(False)
    update = WORK / 'r7000-update-generic/shadowsocks'
    stage = WORK / 'r7000-full-generic'
    if stage.exists():
        shutil.rmtree(stage)
    package = stage / 'shadowsocks'
    files = package / 'files'
    files.mkdir(parents=True)
    for directory in ROOTS:
        source = ROOT / 'shadowsocks' / directory
        if source.is_symlink() or not source.is_dir():
            raise ValueError('Prepared source directory is missing or unsafe: ' + directory)
        for path in sorted(source.rglob('*')):
            if path.is_dir() and not path.is_symlink():
                continue
            regular(path)
            name = path.relative_to(ROOT / 'shadowsocks').as_posix()
            if name == 'ss/postscripts/change_my_name.sh':
                continue
            if not re.fullmatch(r'[A-Za-z0-9_./-]+', name):
                raise ValueError('Unexpected source path: ' + name)
            target = files / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    # The enhanced payload supplies the tested ARM binaries and safe service entry points.
    for path in sorted((update / 'payload').rglob('*')):
        if path.is_file():
            target = files / path.relative_to(update / 'payload')
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    # Never install the old self-removing installer or online updater as an entry point.
    for name in ('scripts/ss_update.sh',):
        (files / name).write_text(OFFLINE_ONLY)
    installed = sorted(p for p in files.rglob('*') if p.is_file())
    hashes = {}
    manifest = []
    for path in installed:
        name = path.relative_to(files).as_posix()
        path.chmod(destination_mode(name))
        data = path.read_bytes()
        manifest.append(hashlib.md5(data).hexdigest() + '  ' + name)
        hashes[name] = hashlib.sha256(data).hexdigest()
    if (files / 'ss/version').read_text().strip() != '4.38.3':
        raise ValueError('Prepared source does not match the fixed baseline version')
    (package / 'manifest-full.md5').write_text('\n'.join(manifest) + '\n')
    (package / 'install.sh').write_text(template.replace('@@FULL_FILE_COUNT@@', str(len(installed))))
    (package / 'install.sh').chmod(0o755)
    shutil.copytree(update, package / 'update')
    for name in NOTICE_FILES:
        target = package / 'licenses' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(notices / name, target)
        target.chmod(0o644)
    (package / 'BUILD.json').write_text(json.dumps({
        'build': VERSION,
        'package_kind': 'full-offline-fresh-or-4.38.3-update',
        'upstream': 'https://github.com/cary-sas/v2ray_bin',
        'base_release_sha256': '05a30314c8c6d8f33ae9c027b42927e9d17e6e648c75ac7b419282fe5c1c2adf',
        'fresh_file_count': len(installed),
        'files_sha256': hashes,
        'personal_settings_included': False,
        'fresh_install_starts_proxy': False,
    }, indent=2) + '\n')
    archive = stage / 'shadowsocks.tar.gz'
    with archive.open('wb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as tar:
                tar.add(package, arcname='shadowsocks', filter=incremental.archive_metadata)
    archive.chmod(0o644)
    result = {'package': str(archive), 'bytes': archive.stat().st_size,
              'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
              'fresh_files': len(installed), 'personal_settings': False}
    print(json.dumps(result))
    return archive


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--notices', type=Path, required=True,
                        help='Directory containing LICENSE, THIRD_PARTY_NOTICES.md, MPL-2.0.txt and third-party-licenses.tar.gz')
    build(parser.parse_args().notices)
