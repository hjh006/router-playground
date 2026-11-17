import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    'package_builder', Path(__file__).resolve().parents[1] / 'plugin/overlay/build-enhancement.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class GenericReleaseTest(unittest.TestCase):
    def test_generic_package_omits_private_state_and_machine_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            root = work / 'r7000-enhanced'
            files = [root / 'enhancement/install.sh', root / 'shadowsocks/uninstall.sh']
            files += [root / 'shadowsocks' / name for name in builder.FILES
                      if name not in ('bin/anytls', 'bin/ss-flock', 'bin/ss-https-probe', 'bin/ss-tcp-probe', 'scripts/uninstall_shadowsocks.sh')]
            files += [work / 'r7000-client/dist' / name for name in
                      ('anytls-client-linux-armv5-r7000.3', 'ss-flock-linux-armv5', 'ss-https-probe-linux-armv5', 'ss-tcp-probe-linux-armv5')]
            for file in files:
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(b'synthetic-public-payload\n')
            private = work / 'r7000-device-state/deployment-settings.json'
            private.parent.mkdir()
            marker = 'PRIVATE-SETTINGS-MUST-NOT-LEAK'
            private.write_text(json.dumps({'private_test_value': marker}))
            with patch.object(builder, 'ROOT', root), patch.object(builder, 'WORK', work):
                with contextlib.redirect_stdout(io.StringIO()):
                    builder.build()
                archive = work / 'r7000-update-generic/shadowsocks.tar.gz'
                first = archive.read_bytes()
                for file in files:
                    os.utime(file, (1234567890, 1234567890))
                with contextlib.redirect_stdout(io.StringIO()):
                    builder.build()
                self.assertEqual(first, archive.read_bytes())
            self.assertEqual(first[4:8], b'\0' * 4)  # gzip timestamp
            with tarfile.open(fileobj=io.BytesIO(first), mode='r:gz') as tar:
                members = tar.getmembers()
                regular = {m.name: tar.extractfile(m).read() for m in members if m.isfile()}
                self.assertEqual(len(regular), 27)
                self.assertFalse(any('private-settings' in n for n in regular))
                for member in members:
                    self.assertEqual((member.uid, member.gid, member.uname, member.gname,
                                      member.mtime, member.pax_headers), (0, 0, '', '', 0, {}))
                for data in regular.values():
                    self.assertNotIn(marker.encode(), data)
                meta = json.loads(regular['shadowsocks/BUILD.json'])
                self.assertEqual(meta['build'], '4.38.3-r7000.5')
                self.assertIs(meta['personal_settings_included'], False)
                self.assertIn('shadowsocks/payload/bin/ss-https-probe',regular)
                self.assertIn('shadowsocks/payload/scripts/ss_failover.sh',regular)
                self.assertIn('shadowsocks/payload/scripts/ss_adblock.sh',regular)
                self.assertIn('shadowsocks/payload/bin/ss-tcp-probe',regular)
                self.assertIn('shadowsocks/payload/bin/ss_latency.sh',regular)
                self.assertIn('shadowsocks/payload/scripts/ss_latency.sh',regular)
                self.assertIn('shadowsocks/payload/res/ss-latency-capabilities.js',regular)
                manifest = regular['shadowsocks/manifest.md5'].decode().splitlines()
                self.assertEqual(len(manifest), 24)
                for line in manifest:
                    digest, name = line.split()
                    self.assertEqual(hashlib.md5(regular['shadowsocks/payload/' + name]).hexdigest(), digest)


if __name__ == '__main__':
    unittest.main()
