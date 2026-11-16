import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch


PUBLIC = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('full_builder', PUBLIC / 'plugin/overlay/build-full.py')
full = importlib.util.module_from_spec(spec)
spec.loader.exec_module(full)


class FullPackageTests(unittest.TestCase):
    def fixture(self, directory):
        work = Path(directory)
        root = work / 'r7000-enhanced'
        root.mkdir()
        shutil.copyfile(PUBLIC / 'plugin/overlay/build-enhancement.py', root / 'build-enhancement.py')
        with patch.object(full, 'ROOT', root), patch.object(full, 'WORK', work):
            incremental = full.load_incremental_builder()
        for name in full.ROOTS:
            (root / 'shadowsocks' / name).mkdir(parents=True)
        paths = [root / 'enhancement/install.sh', root / 'shadowsocks/uninstall.sh']
        paths += [root / 'shadowsocks' / name for name in incremental.FILES
                  if not name.startswith('bin/') and name != 'scripts/uninstall_shadowsocks.sh']
        paths += [work / 'r7000-client/dist' / name for name in
                  ('anytls-client-linux-armv5-r7000.3', 'ss-flock-linux-armv5')]
        for path in paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'public-test-payload\n')
        (root / 'enhancement/install-full.sh').write_text('#!/bin/sh\nCOUNT=@@FULL_FILE_COUNT@@\n')
        (root / 'shadowsocks/ss/version').write_text('4.38.3\n')
        (root / 'shadowsocks/install.sh').write_text('OLD-DESTRUCTIVE-INSTALLER')
        (root / 'shadowsocks/scripts/ss_update.sh').write_text('OLD-ONLINE-UPDATER')
        example = root / 'shadowsocks/ss/postscripts/change_my_name.sh'
        example.parent.mkdir(parents=True)
        example.write_text('UNNEEDED-POSTSCRIPT')
        private = work / 'r7000-device-state/deployment-settings.json'
        private.parent.mkdir()
        private.write_text('{"private":"PRIVATE-DEVICE-STATE"}')
        notices = work / 'notices'
        notices.mkdir()
        for name in full.NOTICE_FILES:
            (notices / name).write_bytes(b'public-license-test-content')
        return work, root, notices

    def test_one_upload_contains_fresh_and_update_payloads_without_private_state(self):
        with tempfile.TemporaryDirectory() as directory:
            work, root, notices = self.fixture(directory)
            with patch.object(full, 'ROOT', root), patch.object(full, 'WORK', work):
                with contextlib.redirect_stdout(io.StringIO()):
                    archive = full.build(notices)
                    first = archive.read_bytes()
                    full.build(notices)
                self.assertEqual(first, archive.read_bytes())
            with tarfile.open(fileobj=io.BytesIO(first), mode='r:gz') as tar:
                members = tar.getmembers()
                files = {m.name: tar.extractfile(m).read() for m in members if m.isfile()}
                for member in members:
                    self.assertEqual((member.uid, member.gid, member.uname, member.gname,
                                      member.mtime, member.pax_headers), (0, 0, '', '', 0, {}))
                self.assertIn('shadowsocks/install.sh', files)
                self.assertIn('shadowsocks/update/install.sh', files)
                self.assertIn('shadowsocks/files/ss/version', files)
                self.assertIn('shadowsocks/files/scripts/uninstall_shadowsocks.sh', files)
                self.assertNotIn('shadowsocks/files/ss/postscripts/change_my_name.sh', files)
                for data in files.values():
                    for secret in (b'PRIVATE-DEVICE-STATE', b'OLD-DESTRUCTIVE-INSTALLER', b'OLD-ONLINE-UPDATER'):
                        self.assertNotIn(secret, data)
                meta = json.loads(files['shadowsocks/BUILD.json'])
                self.assertFalse(meta['personal_settings_included'])
                self.assertFalse(meta['fresh_install_starts_proxy'])
                self.assertIn(str(meta['fresh_file_count']).encode(), files['shadowsocks/install.sh'])
                self.assertNotIn(b'@@FULL_FILE_COUNT@@', files['shadowsocks/install.sh'])
                update_manifest = files['shadowsocks/update/manifest.md5'].decode().splitlines()
                self.assertEqual(len(update_manifest), 17)
                for line in update_manifest:
                    name = line.split()[1]
                    self.assertEqual(files['shadowsocks/files/' + name], files['shadowsocks/update/payload/' + name])

    def test_notice_symlink_is_rejected_before_build(self):
        with tempfile.TemporaryDirectory() as directory:
            work, root, notices = self.fixture(directory)
            path = notices / 'LICENSE'
            path.unlink()
            path.symlink_to(notices / 'MPL-2.0.txt')
            with patch.object(full, 'ROOT', root), patch.object(full, 'WORK', work):
                with self.assertRaises(ValueError):
                    full.build(notices)
            self.assertFalse((work / 'r7000-full-generic').exists())


if __name__ == '__main__':
    unittest.main()
