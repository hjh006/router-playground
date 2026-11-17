import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
GO_LICENSE_SHA256 = '2d36597f7117c38b006835ae7f537487207d8ec407aa9d9980794b2030cbc067'
spec = importlib.util.spec_from_file_location('latency_addon', ROOT/'scripts/build_latency_addon.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class LatencyAddonTests(unittest.TestCase):
    def test_archive_contains_only_owned_measurement_files_and_is_reproducible(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in builder.FILES:
                if name == 'bin/ss-tcp-probe':
                    target=root/'r7000-client/dist/ss-tcp-probe-linux-armv5'
                    target.parent.mkdir(parents=True,exist_ok=True)
                    target.write_bytes(b'synthetic-public-tcp-probe')
                    continue
                target = root/'prepared/shadowsocks'/name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT/'plugin/overlay/shadowsocks'/name, target)
            first, second = root/'one.tar.gz', root/'two.tar.gz'
            expected_payload = {}
            for name in builder.FILES:
                source = root/'r7000-client/dist/ss-tcp-probe-linux-armv5' if name=='bin/ss-tcp-probe' else root/'prepared/shadowsocks'/name
                expected_payload[name] = hashlib.sha256(source.read_bytes()).hexdigest()
            self.assertEqual(builder.build(root/'prepared', first), builder.build(root/'prepared', second))
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first) as archive:
                self.assertEqual(set(archive.getnames()), {'latency/install.sh', 'latency/LICENSE', 'latency/THIRD_PARTY_NOTICES.md',
                    'latency/licenses/Go-LICENSE.txt', 'latency/manifest.md5',
                    'latency/payload/bin/ss-tcp-probe', 'latency/payload/bin/ss_latency.sh', 'latency/payload/scripts/ss_latency.sh', 'latency/payload/res/ss-latency-capabilities.js'})
                self.assertTrue(all(m.isfile() and m.uid == m.gid == m.mtime == 0 and not m.uname and not m.gname for m in archive))
                self.assertEqual(archive.extractfile('latency/payload/bin/ss_latency.sh').read(),
                    b'#!/bin/sh\nexec /bin/sh /koolshare/scripts/ss_latency.sh "$@"\n')
                self.assertEqual(archive.getmember('latency/payload/bin/ss-tcp-probe').mode,0o755)
                for name,digest in expected_payload.items():
                    self.assertEqual(hashlib.sha256(archive.extractfile('latency/payload/'+name).read()).hexdigest(),digest)
                self.assertEqual(archive.extractfile('latency/LICENSE').read(),(ROOT/'LICENSE').read_bytes())
                self.assertEqual(archive.extractfile('latency/THIRD_PARTY_NOTICES.md').read(),(ROOT/'THIRD_PARTY_NOTICES.md').read_bytes())
                self.assertEqual(hashlib.sha256(archive.extractfile('latency/licenses/Go-LICENSE.txt').read()).hexdigest(),GO_LICENSE_SHA256)
            (root/'prepared/shadowsocks/scripts/ss_latency.sh').write_text('stale')
            with self.assertRaisesRegex(ValueError, 'stale'):
                builder.build(root/'prepared', root/'refused.tar.gz')

    def installation(self, *, failure='', existing=False):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); ks = root/'ks'; package = root/'latency'
            for sub in ('scripts', 'bin', 'ss/rules', 'res'):
                (ks/sub).mkdir(parents=True, exist_ok=True)
            for name in ('scripts/ss_anytls.sh', 'scripts/ss_dns_hooks.sh', 'bin/ss-https-probe', 'bin/ss-flock', 'ss/rules/cacert.pem'):
                (ks/name).write_text('existing dependency'); (ks/name).chmod(0o755)
            (ks/'unchanged-routing-rules').write_text('UU / bypass / DNS unchanged')
            payload = package/'payload'; (payload/'scripts').mkdir(parents=True); (payload/'res').mkdir(); (payload/'bin').mkdir()
            script = '#!/bin/sh\n[ "$1" = status ] || exit 9\n'
            script += 'exit 1\n' if failure == 'initialize' else 'printf initialized > "$LATENCY_ADDON_TEST_ROOT/initialized"\n'
            (payload/'scripts/ss_latency.sh').write_text(script)
            (payload/'bin/ss-tcp-probe').write_text('#!/bin/sh\n'+('exit 1\n' if failure=='probe' else '[ "$1" = -h ] || exit 99\n'))
            (payload/'bin/ss_latency.sh').write_bytes((ROOT/'plugin/overlay/shadowsocks/bin/ss_latency.sh').read_bytes())
            (payload/'res/ss-latency-capabilities.js').write_text('{"version":1,"transport":"ram_mailbox_v1","method":"router_tcp","target":"entry"}')
            (package/'manifest.md5').write_text(''.join(hashlib.md5((payload/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in builder.FILES))
            if failure == 'checksum': (payload/'scripts/ss_latency.sh').write_text(script+'# tampered\n')
            if existing:
                for name in builder.FILES: (ks/name).write_text('old measurement file: '+name)
            before = {str(p.relative_to(ks)):p.read_bytes() for p in ks.rglob('*') if p.is_file()}
            installer = (ROOT/'plugin/overlay/enhancement/install-latency.sh').read_text().replace('KS_ROOT=/koolshare', 'KS_ROOT='+str(ks))
            (package/'install.sh').write_text(installer)
            tools = root/'tools'; tools.mkdir()
            checksum = tools/'md5sum'
            checksum.write_text('#!'+sys.executable+'\nimport hashlib,pathlib,sys\nassert sys.argv[1]=="-c"\n'
                'for line in pathlib.Path(sys.argv[2]).read_text().splitlines():\n'
                ' digest,name=line.split(); assert hashlib.md5(pathlib.Path(name).read_bytes()).hexdigest()==digest\n')
            checksum.chmod(0o755)
            env = dict(os.environ, PATH=str(tools)+os.pathsep+os.environ['PATH'], LATENCY_ADDON_TEST_ROOT=str(root))
            result = subprocess.run(['sh', str(package/'install.sh')], env=env, capture_output=True, timeout=10)
            after = {str(p.relative_to(ks)):p.read_bytes() for p in ks.rglob('*') if p.is_file()}
            if failure:
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(before, after, 'failed install preserves the entire existing tree')
            else:
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                for name, content in before.items():
                    if name not in builder.FILES: self.assertEqual(after[name], content)
                self.assertEqual(set(after)-set(before), set(builder.FILES) if not existing else set())
                self.assertTrue((root/'initialized').is_file())
                self.assertFalse((ks/'bin/ss_latency.sh').is_symlink())
                self.assertEqual((ks/'bin/ss_latency.sh').stat().st_mode & 0o777, 0o755)
                self.assertEqual((ks/'bin/ss-tcp-probe').stat().st_mode & 0o777, 0o755)

    def test_first_install_changes_only_four_measurement_files(self): self.installation()
    def test_update_changes_only_four_measurement_files(self): self.installation(existing=True)
    def test_bad_checksum_preserves_existing_files(self): self.installation(failure='checksum', existing=True)
    def test_failed_initialization_rolls_back_previous_files(self): self.installation(failure='initialize', existing=True)
    def test_failed_first_install_removes_new_measurement_files(self): self.installation(failure='initialize')
    def test_invalid_tcp_tool_is_rejected_before_changing_installed_files(self): self.installation(failure='probe',existing=True)

    def test_builder_rejects_missing_linked_empty_or_oversized_local_tcp_tool(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);prepared=root/'prepared';prepared.mkdir()
            binary=root/'r7000-client/dist/ss-tcp-probe-linux-armv5'
            binary.parent.mkdir(parents=True)
            for kind in ['missing','linked','empty','oversized']:
                with self.subTest(kind=kind):
                    if binary.exists() or binary.is_symlink():binary.unlink()
                    if kind=='linked':
                        target=root/'tool';target.write_bytes(b'local-test-tool');binary.symlink_to(target)
                    elif kind=='empty':binary.touch()
                    elif kind=='oversized':
                        with binary.open('wb') as stream:stream.truncate(8*1024*1024+1)
                    with self.assertRaisesRegex(ValueError,'TCP probe'):
                        builder.build(prepared,root/'rejected.tar.gz')


if __name__ == '__main__': unittest.main()
