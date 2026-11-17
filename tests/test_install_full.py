"""Execute the full installer only in isolated fake-router roots."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('incremental_test_helpers', ROOT / 'plugin/overlay/tests/test_install.py')
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
PATHS = helpers.PATHS + ['bin/koolbox', 'bin/base64_encode', 'bin/rss-local', 'bin/jq',
                         'scripts/ss_socks5.sh', 'ss/version']
MOCK = r'''
import hashlib,json,os,pathlib,subprocess,sys
r=pathlib.Path(os.environ['MO_ROOT']);cmd=pathlib.Path(sys.argv[0]).name;args=sys.argv[1:]
def state(): return json.loads((r/'dbus.json').read_text())
def event(s):
 with (r/'events').open('a') as f: f.write(s+'\n')
def failing(kind,value=''):
 if os.environ.get('MO_FAIL')==kind+(':'+value if value else '') and not (r/'failed').exists():
  (r/'failed').touch();return True
 return False
if cmd=='uname': print(os.environ.get('MO_ARCH','armv7l') if args[0]=='-m' else os.environ.get('MO_KERNEL','2.6.36.4brcmarm'))
elif cmd=='nvram': print(os.environ.get('MO_BUILD','380') if args[1]=='buildno' else os.environ.get('MO_EXTEND','70_0-X7.9.1'))
elif cmd=='df': print('Filesystem 1024-blocks Used Available Capacity Mounted on\nfake 999999 0 '+os.environ.get('MO_SPACE','999999')+' 0% /')
elif cmd in ('stat','mktemp','iptables','service','killall'):
 event('forbidden:'+cmd);sys.exit(99)
elif cmd=='find':
 if '-type' in args or '-mindepth' in args: event('forbidden:find-option');sys.exit(99)
 sys.exit(subprocess.call(['/usr/bin/find']+args))
elif cmd=='md5sum':
 for line in pathlib.Path(args[1]).read_text().splitlines():
  digest,name=line.split()
  if hashlib.md5(pathlib.Path(name).read_bytes()).hexdigest()!=digest:sys.exit(1)
elif cmd=='dbus':
 d=state();action=args[0];key=args[1] if len(args)>1 else ''
 if action=='get':print(d.get(key,''))
 elif action=='list':
  for k,v in sorted(d.items()):
   if k.startswith(key):print(k+'='+v)
 elif action=='set':
  k,v=key.split('=',1)
  if failing('dbus',k):sys.exit(1)
  d[k]=v;(r/'dbus.json').write_text(json.dumps(d))
 elif action=='remove':d.pop(key,None);(r/'dbus.json').write_text(json.dumps(d))
 else:sys.exit(2)
elif cmd in ('cp','mv'):
 src=pathlib.Path(args[-2]);dest=pathlib.Path(args[-1]);rel=''
 if cmd=='cp' and '/files/' in str(src):rel=str(src).split('/files/',1)[1]
 if cmd=='mv' and str(dest).startswith(str((r/'ks').resolve())+'/'):rel=str(dest.relative_to((r/'ks').resolve()))
 if failing(cmd,rel):sys.exit(1)
 sys.exit(subprocess.call(['/bin/'+cmd]+args))
elif cmd=='mkdir':
 if os.environ.get('MO_RACE') and args[-1].endswith('r7000-enhancement.lock'):
  (r/'ks/ss').mkdir(exist_ok=True);(r/'ks/ss/version').write_text('4.38.3')
  d=state();d['ss_basic_mode']='9';(r/'dbus.json').write_text(json.dumps(d))
 sys.exit(subprocess.call(['/bin/mkdir']+args))
else:sys.exit(2)
'''


class FullInstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='r7000-full-install-test-')
        self.r = Path(self.tmp.name)
        self.ks = self.r/'ks'; self.jffs = self.r/'jffs'; self.run = self.r/'run'; self.pkg = self.r/'package'
        for p in [self.ks/selfdir for selfdir in ['bin','scripts','webs','res','init.d']] + [self.jffs, self.run, self.pkg/'files']:
            p.mkdir(parents=True)
        self.env = os.environ.copy() | {'MO_ROOT':str(self.r)}
        self.data = {'softcenter_module_uu_install':'1','uu_device':'synthetic-uu-device','ss_acl_default_port':'443'}
        self.write_state(); (self.r/'events').touch()
        for name in ['uname','nvram','df','stat','mktemp','find','md5sum','dbus','cp','mv','mkdir','iptables','service','killall']:
            p=self.ks/'bin'/name; p.write_text('#!'+sys.executable+'\n'+MOCK);p.chmod(0o755)
        for name in PATHS:
            p=self.pkg/'files'/name;p.parent.mkdir(parents=True,exist_ok=True)
            if name=='bin/anytls':p.write_text('#!/bin/sh\necho anytls/0.0.13-r7000.3\n')
            elif name=='bin/ss-flock':p.write_text('#!'+sys.executable+'\n'+helpers.FLOCK)
            elif name=='bin/ss-https-probe':p.write_text(helpers.PROBE)
            elif name in ['scripts/ss_failover.sh','scripts/ss_adblock.sh']:shutil.copyfile(ROOT/'plugin/overlay/shadowsocks'/name,p)
            elif name=='scripts/ss_dns_hooks.sh':shutil.copyfile(ROOT/'plugin/overlay/shadowsocks/scripts/ss_dns_hooks.sh',p)
            elif name=='scripts/ss_routing.sh':shutil.copyfile(ROOT/'plugin/overlay/shadowsocks/scripts/ss_routing.sh',p)
            elif name=='ss/version':p.write_text('4.38.3\n')
            elif name.endswith('.sh') or name.endswith('postconf'):
                p.write_text('#!/bin/sh\necho forbidden-service >> "$MO_ROOT/events"\nexit 99\n')
            else:p.write_text('synthetic:'+name+'\n')
            p.chmod(0o755 if name.startswith('bin/') else 0o644)
        # An unrelated shared regular helper and symlink must be restored exactly.
        (self.ks/'bin/jq').write_text('shared-jq');(self.ks/'bin/jq').chmod(0o640)
        (self.ks/'bin/shared-base64').write_text('#!/bin/sh\nexit 0\n');(self.ks/'bin/shared-base64').chmod(0o755)
        (self.ks/'bin/base64').symlink_to('shared-base64')
        (self.ks/'bin/rss-tunnel').symlink_to('/external/rss-helper')
        (self.ks/'scripts/uu-start.sh').write_text('keep-uu')
        (self.ks/'res/uu-icon.png').write_bytes(b'keep-uu-icon')
        (self.jffs/'configs').mkdir();(self.jffs/'configs/dnsmasq.conf.add').write_text('keep-dns')
        (self.r/'external-rules').write_text('keep-nat-mangle-output')
        self.original = self.snapshot()
        script=(ROOT/'plugin/overlay/enhancement/install-full.sh').read_text()
        script=script.replace('@@FULL_FILE_COUNT@@',str(len(PATHS)))
        for name,value in [('KS_ROOT',self.ks),('JFFS_ROOT',self.jffs),('RUN_ROOT',self.run)]:
            old={'KS_ROOT':'/koolshare','JFFS_ROOT':'/jffs','RUN_ROOT':'/tmp'}[name]
            script=script.replace(name+'='+old,name+"='"+str(value)+"'")
        script=script.replace('/proc/self/status',str(self.r/'proc-status'))
        self.installer=self.pkg/'install.sh';self.installer.write_text(script)
        self.manifest()

    def tearDown(self): self.tmp.cleanup()
    def write_state(self): (self.r/'dbus.json').write_text(json.dumps(self.data))
    def state(self): return json.loads((self.r/'dbus.json').read_text())
    def manifest(self):
        (self.pkg/'manifest-full.md5').write_text(''.join(hashlib.md5((self.pkg/'files'/p).read_bytes()).hexdigest()+'  '+p+'\n' for p in PATHS))
    def snapshot(self):
        return {str(p.relative_to(self.ks)):('link',os.readlink(p)) if p.is_symlink() else ('file',p.read_bytes(),stat.S_IMODE(p.stat().st_mode)) for p in self.ks.rglob('*') if p.is_file() or p.is_symlink()}
    def install(self,args=(),**env):
        e=self.env|env;uid='1000' if e.get('MO_NONROOT') else '0'
        (self.r/'proc-status').write_text('Name:\tinstaller\nUid:\t'+uid+'\t'+uid+'\t'+uid+'\t'+uid+'\n')
        out=subprocess.run(['/bin/sh',str(self.installer),*args],env=e,capture_output=True,text=True,timeout=45)
        self.assertEqual((self.r/'events').read_text(),'')
        self.assertFalse((self.run/'r7000-enhancement.lock').exists())
        self.assertFalse(list(self.run.glob('r7000-full.*')))
        self.assertFalse(list(self.ks.rglob('.r7000-full-stage.*')))
        self.assertEqual((self.ks/'scripts/uu-start.sh').read_text(),'keep-uu')
        self.assertEqual((self.jffs/'configs/dnsmasq.conf.add').read_text(),'keep-dns')
        self.assertEqual((self.r/'external-rules').read_text(),'keep-nat-mangle-output')
        return out
    def assert_restored(self):
        self.assertEqual(self.snapshot(),self.original)
        self.assertEqual(self.state(),self.data)
    def test_fresh_success_is_disabled_empty_and_registers_software_center(self):
        out=self.install();self.assertEqual(out.returncode,0,out.stderr)
        self.assertIn('Full installation completed (proxy disabled)',out.stdout)
        d=self.state();self.assertEqual(d['ss_basic_enable'],'0');self.assertEqual(d['softcenter_module_shadowsocks_install'],'4')
        for key in ['ss_basic_bypass_macs','ss_basic_uu_macs','ss_basic_anytls_hosts','ss_basic_failover_nodes','ss_basic_failover_countries','ss_basic_server_resolver_user']:self.assertEqual(d[key],'')
        for key in ['ss_basic_rule_update','ss_basic_node_update','ss_basic_allowinsecure','ss_basic_failover_enable']:self.assertEqual(d[key],'0')
        self.assertEqual(d['ss_basic_uu_tcp_policy'],'gfwlist')
        self.assertEqual(d['ss_basic_uu_interval'],'5')
        self.assertEqual(d['ss_basic_adblock_enable'],'0')
        self.assertEqual(d['ss_basic_adblock_domains'],'')
        self.assertEqual(d['ss_basic_adblock_allow'],'')
        self.assertEqual(d['ss_basic_failover_country'],'auto')
        self.assertEqual(d['ss_basic_failover_direct'],'1')
        self.assertEqual(d['ss_basic_failover_budget'],'60')
        self.assertFalse(any(k.startswith('ssconf_basic_') for k in d))
        self.assertNotIn('ss_basic_server',d);self.assertNotIn('ss_basic_password',d)
        self.assertEqual(os.readlink(self.ks/'bin/base64'),'shared-base64')
        self.assertEqual(os.readlink(self.ks/'bin/rss-tunnel'),'rss-local')
        self.assertEqual(os.readlink(self.ks/'init.d/S99socks5.sh'),'../scripts/ss_socks5.sh')
        self.assertFalse((self.ks/'scripts/ss_install.sh').exists())
    def test_probe_must_run_before_any_mutation(self):
        out=self.install(MO_BAD_PROBE='1');self.assertNotEqual(out.returncode,0)
        self.assertIn('HTTPS probe cannot run',out.stderr);self.assert_restored()
    def test_missing_new_dependency_is_rejected_with_valid_adjusted_manifest(self):
        global PATHS
        for missing in ['bin/ss-https-probe','scripts/ss_failover.sh','scripts/ss_adblock.sh']:
            with self.subTest(missing=missing):
                original_paths=PATHS;PATHS=[p for p in PATHS if p!=missing]
                content=(self.pkg/'files'/missing).read_bytes();mode=stat.S_IMODE((self.pkg/'files'/missing).stat().st_mode)
                (self.pkg/'files'/missing).unlink()
                self.installer.write_text(self.installer.read_text().replace('FULL_FILE_COUNT='+str(len(original_paths)),'FULL_FILE_COUNT='+str(len(PATHS))))
                try:
                    self.manifest();out=self.install();self.assertNotEqual(out.returncode,0)
                    self.assertIn('required full payload file is missing',out.stderr);self.assert_restored()
                finally:
                    PATHS=original_paths
                    (self.pkg/'files'/missing).write_bytes(content);(self.pkg/'files'/missing).chmod(mode)
                    self.installer.write_text(self.installer.read_text().replace('FULL_FILE_COUNT='+str(len(PATHS)-1),'FULL_FILE_COUNT='+str(len(PATHS))))
                    self.manifest()
    def test_copy_failure_does_not_change_installed_files_or_settings(self):
        out=self.install(MO_FAIL='cp:ss/ssconfig.sh');self.assertNotEqual(out.returncode,0);self.assert_restored()
    def test_mid_commit_failure_restores_shared_regular_and_symbolic_files(self):
        out=self.install(MO_FAIL='mv:ss/ssconfig.sh');self.assertNotEqual(out.returncode,0);self.assert_restored()
    def test_registration_failure_restores_files_settings_and_links(self):
        out=self.install(MO_FAIL='dbus:softcenter_module_shadowsocks_home_url');self.assertNotEqual(out.returncode,0);self.assert_restored()
    def test_insufficient_storage_fails_before_mutation(self):
        out=self.install(MO_SPACE='1');self.assertNotEqual(out.returncode,0);self.assert_restored()
    def test_architecture_kernel_firmware_and_root_are_checked(self):
        for setting in [dict(MO_ARCH='aarch64'),dict(MO_KERNEL='4.1.0'),dict(MO_BUILD='388'),dict(MO_EXTEND='X7.1'),dict(MO_NONROOT='1')]:
            with self.subTest(setting=setting):
                out=self.install(**setting);self.assertNotEqual(out.returncode,0);self.assert_restored()
    def test_corrupt_payload_rejected(self):
        (self.pkg/'files/res/icon-shadowsocks.png').write_text('corrupted')
        out=self.install();self.assertNotEqual(out.returncode,0);self.assert_restored()
    def test_extra_payload_or_symlink_rejected(self):
        extra=self.pkg/'files/res/extra.png';extra.symlink_to('/external')
        out=self.install();self.assertNotEqual(out.returncode,0);self.assert_restored()
    def test_unknown_previous_version_is_not_overwritten(self):
        (self.ks/'ss').mkdir();(self.ks/'ss/version').write_text('4.37.0')
        self.original=self.snapshot();out=self.install();self.assertNotEqual(out.returncode,0);self.assert_restored()
    def test_versionless_node_state_is_not_overwritten(self):
        self.data['ssconf_basic_name_1']='previous-node';self.write_state()
        out=self.install();self.assertNotEqual(out.returncode,0);self.assert_restored()
    def test_versionless_plugin_script_is_not_overwritten(self):
        (self.ks/'scripts/ss_old.sh').write_text('keep-old');self.original=self.snapshot()
        out=self.install();self.assertNotEqual(out.returncode,0);self.assert_restored()
    def test_child_directory_symlink_is_rejected(self):
        outside=self.r/'outside';outside.mkdir();(self.ks/'res/layer').symlink_to(outside,target_is_directory=True)
        # A payload destination under this parent proves traversal is rejected.
        p=self.pkg/'files/res/layer/layer.js';p.parent.mkdir();p.write_text('layer')
        global PATHS
        original_paths=PATHS;PATHS=PATHS+['res/layer/layer.js']
        self.installer.write_text(self.installer.read_text().replace('FULL_FILE_COUNT='+str(len(original_paths)),'FULL_FILE_COUNT='+str(len(PATHS))))
        try:
            self.manifest();self.original=self.snapshot();out=self.install();self.assertNotEqual(out.returncode,0);self.assert_restored()
        finally:PATHS=original_paths
        self.assertEqual(list(outside.iterdir()),[])
    def test_destination_symlink_to_directory_is_rejected(self):
        for relative in ['bin/jq','bin/rss-tunnel']:
            with self.subTest(relative=relative):
                target=self.ks/relative;target.unlink()
                outside=self.r/('outside-'+relative.split('/')[-1]);outside.mkdir()
                (outside/'keep').write_text('outside-data');target.symlink_to(outside,target_is_directory=True)
                self.original=self.snapshot()
                out=self.install();self.assertNotEqual(out.returncode,0);self.assert_restored()
                self.assertEqual([p.name for p in outside.iterdir()],['keep'])
                self.assertEqual((outside/'keep').read_text(),'outside-data')
                # Restore this destination before exercising the other one.
                target.unlink()
                if relative=='bin/jq':target.write_text('shared-jq');target.chmod(0o640)
                else:target.symlink_to('/external/rss-helper')
    def test_fresh_state_is_rechecked_after_acquiring_lock(self):
        out=self.install(MO_RACE='1');self.assertNotEqual(out.returncode,0)
        self.assertIn('Plugin state changed',out.stderr)
        self.assertEqual((self.ks/'ss/version').read_text(),'4.38.3')
        self.assertEqual(self.state(),self.data|{'ss_basic_mode':'9'})
        self.assertFalse((self.ks/'bin/anytls').exists())
    def test_supported_existing_baseline_uses_only_safe_update_entry(self):
        (self.ks/'ss').mkdir();(self.ks/'ss/version').write_text('4.38.3')
        (self.pkg/'update').mkdir();(self.pkg/'update/install.sh').write_text('#!/bin/sh\nprintf safe-updater\n')
        self.original=self.snapshot();out=self.install();self.assertEqual(out.returncode,0,out.stderr)
        self.assertIn('safe-updater',out.stdout);self.assert_restored()
    def test_manual_restore_reverses_only_fresh_installer_changes(self):
        out=self.install();self.assertEqual(out.returncode,0,out.stderr)
        backup=next((self.jffs/'.r7000-full-backups').iterdir())
        for p in [backup,*backup.rglob('*')]:
            mode=stat.S_IMODE(p.stat().st_mode)
            self.assertEqual(mode,0o700 if p.is_dir() or p.name=='runtime-tool' else 0o600,str(p))
        restored=self.install(['--restore-files',str(backup)]);self.assertEqual(restored.returncode,0,restored.stderr);self.assert_restored()


if __name__=='__main__':unittest.main()
