"""Run the real installer in private fake router roots; never access a router."""
import base64
import hashlib
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
PATHS = '''bin/anytls bin/ss-flock bin/ss-https-probe scripts/ss_anytls.sh scripts/ss_health.sh scripts/ss_failover.sh scripts/ss_adblock.sh scripts/ss_routing.sh scripts/ss_dns_hooks.sh scripts/ss_webtest.sh scripts/uninstall_shadowsocks.sh ss/ssconfig.sh ss/cru/foreign.sh ss/rules/dnsmasq.postconf ss/rules/cacert.pem ss/rules/cacert.pem.sha256 webs/Main_Ss_Content.asp res/ss-health.js res/ss-health.css res/icon-shadowsocks.png'''.split()
SAFE = 'bin/ss-flock bin/ss-https-probe scripts/ss_routing.sh scripts/ss_dns_hooks.sh scripts/ss_health.sh scripts/ss_anytls.sh scripts/ss_failover.sh scripts/ss_adblock.sh ss/ssconfig.sh'.split()
MOCK = r'''
import hashlib,json,os,pathlib,subprocess,sys
r=pathlib.Path(os.environ['MO_ROOT']); cmd=pathlib.Path(sys.argv[0]).name; args=sys.argv[1:]
def state(): return json.loads((r/'dbus.json').read_text())
def save(d): (r/'dbus.json').write_text(json.dumps(d))
def event(s):
 with (r/'events').open('a') as f: f.write(s+'\n')
def failing(kind,value=''):
 target=kind+(':'+value if value else '')
 if os.environ.get('MO_FAIL')==target and not (r/'failed').exists():
  (r/'failed').touch(); return True
 return False
if cmd=='uname': print(os.environ.get('MO_ARCH','armv7l'))
elif cmd=='df': print('Filesystem 1024-blocks Used Available Capacity Mounted on\nfake 999999 0 '+os.environ.get('MO_SPACE','999999')+' 0% /')
elif cmd=='sleep': pass
elif cmd in ('stat','mktemp'):
 event('forbidden-tool:'+cmd); sys.exit(99)
elif cmd=='find':
 if '-type' in args: event('forbidden-tool:find-type'); sys.exit(99)
 sys.exit(subprocess.call(['/usr/bin/find']+args))
elif cmd=='md5sum':
 if args[0]!='-c': sys.exit(2)
 for line in pathlib.Path(args[1]).read_text().splitlines():
  digest,name=line.split()
  if hashlib.md5(pathlib.Path(name).read_bytes()).hexdigest()!=digest: sys.exit(1)
elif cmd=='dbus':
 d=state(); action=args[0]; key=args[1] if len(args)>1 else ''
 if action=='get': print(d.get(key,''))
 elif action=='list':
  for k,v in sorted(d.items()):
   if k.startswith(key): print(k+'='+v)
 elif action=='set':
  k,v=key.split('=',1)
  if failing('dbus',k): sys.exit(1)
  d[k]=v; save(d)
 elif action=='remove': d.pop(key,None); save(d)
 else: sys.exit(2)
elif cmd in ('cp','mv'):
 src=pathlib.Path(args[-2]); dest=pathlib.Path(args[-1]); rel=''
 if cmd=='cp' and '/payload/' in str(src): rel=str(src).split('/payload/',1)[1]
 ks=(r/'ks').resolve()
 if cmd=='mv' and str(dest).startswith(str(ks)+'/'): rel=str(dest.relative_to(ks))
 if failing(cmd,rel): sys.exit(1)
 sys.exit(subprocess.call(['/bin/'+cmd]+args))
elif cmd=='mock-service':
 action=args[0]; event('new:'+action)
 expected=json.loads((r/'expected.json').read_text())
 for path in json.loads((r/'safe.json').read_text()):
  if hashlib.md5((r/'ks'/path).read_bytes()).hexdigest()!=expected[path]: event('bad-dependency:'+path); sys.exit(3)
 if action=='start':
  if failing('start'): sys.exit(1)
  runtime_mode=os.environ.get('MO_RUNTIME_MODE')
  if runtime_mode:
   ram=r/'run/ss_failover';ram.mkdir(mode=0o700,exist_ok=True);ram.chmod(0o700)
   (ram/'mode').write_text(runtime_mode+'\n');(ram/'mode').chmod(0o600)
   if os.environ.get('MO_PUBLIC_RAM'):ram.chmod(0o755)
   watchdog='* * * * * /bin/sh /koolshare/scripts/ss_failover.sh tick >/dev/null 2>&1 #ss_failover#'
   if os.environ.get('MO_WATCHDOG')=='wrong':watchdog=watchdog.replace('ss_failover.sh','other.sh')
   if os.environ.get('MO_WATCHDOG')=='duplicate':watchdog+='\n'+watchdog
   if os.environ.get('MO_WATCHDOG')!='missing':(r/'cron').write_text(watchdog+'\n')
  if not runtime_mode or os.environ.get('MO_KEEP_LISTENERS'):(r/'running').touch()
  if os.environ.get('MO_DISABLE_ON_START'):
   d=state(); d['ss_basic_enable']='0'; save(d)
 else:
  if failing('stop'): sys.exit(1)
  (r/'running').unlink(missing_ok=True)
elif cmd=='pidof':
 if (r/'running').exists(): print('1234')
 else: sys.exit(1)
elif cmd=='netstat':
 if (r/'running').exists() and os.environ.get('MO_FAIL')!='listeners':
  print('tcp 0 0 127.0.0.1:23456 0.0.0.0:* LISTEN\ntcp 0 0 0.0.0.0:3333 0.0.0.0:* LISTEN')
elif cmd=='cru':
 if args!=['l']:event('forbidden-tool:cru-write');sys.exit(99)
 if (r/'cron').exists():print((r/'cron').read_text(),end='')
else: sys.exit(2)
'''
PROBE = '''#!/bin/sh
[ "${MO_BAD_PROBE:-0}" != 1 ] || exit 1
[ "${1:-}" = -h ] || exit 2
printf '%s\\n' 'Usage of ss-https-probe:' >&2
'''
FLOCK = r'''
import fcntl,os,stat,subprocess,sys,tempfile
args=sys.argv[1:]
if args[0]=='mktemp':
 args.pop(0); directory=args[0]=='-d'
 if directory: args.pop(0)
 template=args[0]
 if len(args)!=1 or not template.endswith('XXXXXX'): sys.exit(2)
 parent,prefix=os.path.split(template[:-6])
 if directory: result=tempfile.mkdtemp(prefix=prefix,dir=parent)
 else:
  fd,result=tempfile.mkstemp(prefix=prefix,dir=parent); os.close(fd)
 print(result); sys.exit(0)
if args[0]=='mode':
 if len(args)!=2: sys.exit(2)
 print(format(stat.S_IMODE(os.stat(args[1]).st_mode),'o')); sys.exit(0)
flags=fcntl.LOCK_EX; unlock=False
while args and args[0].startswith('-'):
 flag=args.pop(0)
 if flag=='-x': flags|=fcntl.LOCK_EX
 elif flag=='-n': flags|=fcntl.LOCK_NB
 elif flag=='-u': unlock=True
 else: sys.exit(2)
if not flags: flags=fcntl.LOCK_EX
if unlock: flags=fcntl.LOCK_UN
if os.environ.get('MO_BAD_FLOCK'): sys.exit(0)
target=args.pop(0)
f=None
if target.isdigit(): fd=int(target)
else: f=open(target,'a'); fd=f.fileno()
try: fcntl.flock(fd,flags)
except BlockingIOError: sys.exit(1)
if args: sys.exit(subprocess.call(args))
'''

class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='r7000-install-test-')
        self.r=Path(self.tmp.name); self.ks=self.r/'ks'; self.jffs=self.r/'jffs'; self.run=self.r/'run'; self.pkg=self.r/'pkg'
        for p in [self.ks,self.jffs,self.run,self.pkg/'payload']:
            p.mkdir(parents=True)
        self.env=os.environ.copy(); self.env['MO_ROOT']=str(self.r)
        self.data={'ss_basic_enable':'1','ss_basic_type':'4','ss_basic_trojan_binary':'AnyTLS','ssconf_basic_node':'1','ssconf_basic_type_1':'4','ssconf_basic_trojan_binary_1':'AnyTLS','ssconf_basic_allowinsecure_1':'0','ssconf_basic_type_2':'4','ssconf_basic_trojan_binary_2':'AnyTLS','ssconf_basic_type_3':'4','ssconf_basic_trojan_binary_3':'Trojan','ssconf_basic_allowinsecure_3':'0','ss_basic_allowinsecure':'0','unrelated':'preserved'}
        self.write_state()
        (self.r/'events').touch(); (self.r/'running').touch()
        for path in PATHS:
            old=self.ks/path; new=self.pkg/'payload'/path
            old.parent.mkdir(parents=True,exist_ok=True); new.parent.mkdir(parents=True,exist_ok=True)
            old.write_text('old:'+path+'\n'); old.chmod(0o640)
            if path=='bin/anytls': new.write_text('#!/bin/sh\necho anytls/0.0.13-r7000.3\n')
            elif path=='bin/ss-flock': new.write_text('#!'+sys.executable+'\n'+FLOCK)
            elif path=='bin/ss-https-probe': new.write_text(PROBE)
            elif path=='ss/ssconfig.sh': new.write_text('#!/bin/sh\nexec mock-service "$1"\n'); old.write_text('#!/bin/sh\necho old:$1 >> "$MO_ROOT/events"\nexit 19\n')
            elif path in ('scripts/ss_routing.sh','scripts/ss_anytls.sh','scripts/ss_failover.sh','scripts/ss_dns_hooks.sh','scripts/ss_adblock.sh'): shutil.copyfile(ROOT/'shadowsocks'/path,new)
            elif path.endswith('.sh') or path.endswith('postconf'): new.write_text('#!/bin/sh\n# new '+path+'\n')
            else: new.write_text('new:'+path+'\n')
            new.chmod(0o755 if path.startswith('bin/') else 0o644)
        (self.ks/'ss/version').write_text('4.38.3\n')
        # Exercise absent destinations and symbolic links too.
        (self.ks/'bin/ss-flock').unlink()
        (self.ks/'bin/ss-https-probe').unlink()
        (self.ks/'scripts/ss_adblock.sh').unlink()
        link=self.ks/'res/icon-shadowsocks.png'; link.unlink(); link.symlink_to('previous-icon.png')
        (self.ks/'res/previous-icon.png').write_text('external previous icon')
        self.original=self.snapshot()
        script=(ROOT/'enhancement/install.sh').read_text()
        for name,path in [('KS_ROOT',self.ks),('JFFS_ROOT',self.jffs),('RUN_ROOT',self.run)]:
            script=script.replace(name+'='+{'KS_ROOT':'/koolshare','JFFS_ROOT':'/jffs','RUN_ROOT':'/tmp'}[name],name+"='"+str(path)+"'")
        script=script.replace('/proc/self/status', str(self.r/'proc-status'))
        self.installer=self.pkg/'install.sh'; self.installer.write_text(script)
        for cmd in ['uname','df','sleep','stat','mktemp','find','md5sum','dbus','cp','mv','mock-service','pidof','netstat','cru']:
            p=self.ks/'bin'/cmd; p.write_text('#!'+sys.executable+'\n'+MOCK); p.chmod(0o755)
        self.manifest()
        (self.r/'safe.json').write_text(json.dumps(SAFE))

    def tearDown(self): self.tmp.cleanup()
    def write_state(self): (self.r/'dbus.json').write_text(json.dumps(self.data))
    def state(self): return json.loads((self.r/'dbus.json').read_text())
    def snapshot(self):
        return {p:('link',os.readlink(self.ks/p)) if (self.ks/p).is_symlink() else ('file',(self.ks/p).read_bytes(),stat.S_IMODE((self.ks/p).stat().st_mode)) if (self.ks/p).exists() else ('absent',) for p in PATHS}
    def events(self): return (self.r/'events').read_text().splitlines()
    def manifest(self):
        entries={p:hashlib.md5((self.pkg/'payload'/p).read_bytes()).hexdigest() for p in PATHS}
        (self.pkg/'manifest.md5').write_text(''.join(v+'  '+k+'\n' for k,v in entries.items()))
        (self.r/'expected.json').write_text(json.dumps(entries))
    def settings(self,text,mode=0o600):
        p=self.r/'private-settings'; p.write_text(text); p.chmod(mode); return ['--settings',str(p)]
    def install(self,args=(),**env):
        e=self.env|env
        uid='1000' if e.get('MO_NONROOT') else '0'
        (self.r/'proc-status').write_text('Name:\ttest-installer\nUid:\t'+uid+'\t'+uid+'\t'+uid+'\t'+uid+'\n')
        result=subprocess.run(['/bin/sh',str(self.installer),*args],env=e,capture_output=True,text=True,timeout=30)
        self.assertNotIn('old:', '\n'.join(self.events()),result.stdout+result.stderr)
        self.assertFalse(any(s.startswith('forbidden-tool:') for s in self.events()),self.events())
        self.assertFalse(any(s.startswith('bad-dependency:') for s in self.events()),self.events())
        self.assertFalse((self.run/'r7000-enhancement.lock').exists())
        self.assertFalse(list(self.run.glob('r7000-enhancement.*')))
        self.assertFalse(list(self.ks.rglob('.r7000-enhancement.*')))
        return result
    def backup(self): return next((self.jffs/'.r7000-backups').iterdir())
    def assert_restored(self,enable='0'):
        self.assertEqual(self.original,self.snapshot())
        expected=self.data|{'ss_basic_enable':enable}; self.assertEqual(expected,self.state())

    def test_enabled_success_backup_modes_and_restore(self):
        out=self.install(); self.assertEqual(out.returncode,0,out.stderr)
        self.assertEqual(self.events(),['new:stop','new:start'])
        self.assertEqual(self.state()['ss_basic_enable'],'1')
        self.assertEqual(self.state()['ss_basic_anytls_fingerprint'],'chrome')
        self.assertEqual(self.state()['ss_basic_allowinsecure'],'0')
        self.assertEqual(self.state()['ss_basic_uu_tcp_policy'],'gfwlist')
        self.assertEqual(self.state()['ss_basic_failover_enable'],'0')
        self.assertEqual(self.state()['ss_basic_failover_country'],'auto')
        self.assertEqual(self.state()['ss_basic_failover_nodes'],'')
        self.assertEqual(self.state()['ss_basic_failover_countries'],'')
        self.assertEqual(self.state()['ss_basic_failover_budget'],'60')
        self.assertEqual(self.state()['ss_basic_failover_direct'],'1')
        self.assertEqual(self.state()['ss_basic_rule_update'],'0')
        self.assertEqual(self.state()['ss_basic_node_update'],'0')
        b=self.backup()
        for p in [b,*b.rglob('*')]:
            self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o700 if p.is_dir() or p.name=='runtime-tool' else 0o600,str(p))
        self.data=self.state(); self.data['ss_basic_enable']='0'; self.write_state()
        restored=self.install(['--restore-files',str(b)])
        self.assertEqual(restored.returncode,0,restored.stderr)
        self.assertEqual(self.original,self.snapshot())
        self.assertEqual(self.state()['ss_basic_enable'],'0')
        self.assertNotIn('ss_basic_health_interval',self.state())
        self.assertNotIn('ss_basic_uu_tcp_policy',self.state())
        self.assertNotIn('ss_basic_failover_enable',self.state())
        self.assertNotIn('ss_basic_rule_update',self.state())

    def test_disabled_success_never_runs_service(self):
        self.data['ss_basic_enable']='0'; self.write_state()
        result=self.install(); self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.events(),[]); self.assertEqual(self.state()['ss_basic_enable'],'0')

    def test_adblock_defaults_are_disabled_empty_and_journaled(self):
        result=self.install();self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.state()['ss_basic_adblock_enable'],'0')
        for key in ['ss_basic_adblock_domains','ss_basic_adblock_allow']:
            self.assertEqual(self.state()[key],'')
            self.assertEqual((self.backup()/'dbus'/(key+'.kind')).read_text(),'absent')
        self.assertEqual(self.events(),['new:stop','new:start'])

    def test_existing_adblock_settings_are_preserved(self):
        encoded=lambda value:base64.b64encode(value.encode()).decode()
        existing={'ss_basic_adblock_enable':'1','ss_basic_adblock_domains':encoded('Ads.Old.Example.Test\n'),
                  'ss_basic_adblock_allow':encoded('allow.example.test\n')}
        self.data.update(existing);self.write_state()
        result=self.install();self.assertEqual(result.returncode,0,result.stderr)
        for key,value in existing.items():self.assertEqual(self.state()[key],value)

    def test_adblock_private_changes_restore_original_encoded_lists(self):
        encoded=lambda value:base64.b64encode(value.encode()).decode()
        self.data.update(ss_basic_adblock_enable='0',ss_basic_adblock_domains=encoded('old-ads.example.test\n'),
                         ss_basic_adblock_allow=encoded('old-allow.example.test\n'));self.write_state()
        values='ss_basic_adblock_enable=1\nss_basic_adblock_domains='+encoded('New-Ads.Example.Test\n')+'\nss_basic_adblock_allow='+encoded('youtube.com\n')+'\n'
        result=self.install(self.settings(values),MO_FAIL='start')
        self.assertNotEqual(result.returncode,0);self.assert_restored()
        self.assertEqual(self.events(),['new:stop','new:start','new:stop'])

    def test_adblock_invalid_settings_rejected_even_disabled_before_mutation(self):
        encoded=lambda value:base64.b64encode(value.encode()).decode()
        values=['ss_basic_adblock_enable=2\n','ss_basic_adblock_domains=not-base64\n',
                'ss_basic_adblock_domains='+encoded('youtube.com\n')+'\n',
                'ss_basic_adblock_domains='+encoded('192.0.2.5\n')+'\n',
                'ss_basic_adblock_allow='+encoded('*.example.test\n')+'\n',
                'ss_basic_adblock_domains='+encoded('\n'.join('ad%d.example.test'%i for i in range(257)))+'\n']
        for value in values:
            with self.subTest(value=value[:80]):
                result=self.install(self.settings(value),SS_ADBLOCK_LIBRARY='1')
                self.assertNotEqual(result.returncode,0);self.assertIn('ad-domain',result.stderr)
                self.assertEqual(self.original,self.snapshot());self.assertEqual(self.events(),[])

    def test_adblock_valid_encoded_lists_can_exceed_old_settings_file_limit(self):
        encoded=lambda prefix:base64.b64encode('\n'.join(prefix+'%03d.example.test'%i for i in range(256)).encode()).decode()
        domains,allow=encoded('ads'),encoded('allow')
        values='ss_basic_adblock_enable=0\nss_basic_adblock_domains='+domains+'\nss_basic_adblock_allow='+allow+'\n'
        self.assertGreater(len(values),8192);self.assertLess(len(values),32768)
        result=self.install(self.settings(values));self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.state()['ss_basic_adblock_domains'],domains)
        self.assertEqual(self.state()['ss_basic_adblock_allow'],allow)

    def test_missing_adblock_dependency_commit_rolls_back_before_stop(self):
        result=self.install(MO_FAIL='mv:scripts/ss_adblock.sh');self.assertNotEqual(result.returncode,0)
        self.assert_restored('1');self.assertEqual(self.events(),[])

    def test_uu_interval_defaults_to_five_and_is_journaled(self):
        result=self.install();self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.state()['ss_basic_uu_interval'],'5')
        self.assertEqual(self.state()['ss_basic_uu_tcp_policy'],'gfwlist')
        backup=self.backup();self.assertIn('ss_basic_uu_interval',(backup/'dbus.list').read_text().splitlines())
        self.assertEqual((backup/'dbus/ss_basic_uu_interval.kind').read_text(),'absent')

    def test_invalid_uu_interval_fails_before_service_changes(self):
        for interval in ['0','1','31','5;touch-marker']:
            with self.subTest(interval=interval):
                result=self.install(self.settings('ss_basic_uu_interval='+interval+'\n'))
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(self.original,self.snapshot());self.assertEqual(self.events(),[])
                self.assertFalse((self.r/'marker').exists())

    def test_failed_uu_interval_change_restores_previous_value(self):
        self.data['ss_basic_uu_interval']='12';self.write_state()
        result=self.install(self.settings('ss_basic_uu_interval=7\n'),MO_FAIL='start')
        self.assertNotEqual(result.returncode,0);self.assert_restored()
        self.assertEqual(self.state()['ss_basic_uu_interval'],'12')
        self.assertEqual(self.events(),['new:stop','new:start','new:stop'])

    def test_existing_failover_and_uu_policy_are_preserved_and_private_changes_restore(self):
        existing = dict(ss_basic_uu_tcp_policy='foreign', ss_basic_failover_enable='1',
                        ss_basic_failover_country='HK', ss_basic_failover_nodes='1,2',
                        ss_basic_failover_countries='1=HK,2=JP', ss_basic_failover_failures='4',
                        ss_basic_failover_recoveries='3', ss_basic_failover_cooldown='90',
                        ss_basic_failover_timeout='6', ss_basic_failover_budget='40',
                        ss_basic_failover_direct='0')
        self.data.update(existing); self.write_state()
        result=self.install(); self.assertEqual(result.returncode,0,result.stderr)
        for key,value in existing.items():self.assertEqual(self.state()[key],value)
        # Roll back this successful update before exercising private overrides.
        (self.r/'dbus.json').write_text(json.dumps(self.state()|{'ss_basic_enable':'0'}))
        result=self.install(['--restore-files',str(self.backup())]);self.assertEqual(result.returncode,0,result.stderr)
        self.write_state()
        result=self.install(self.settings('ss_basic_uu_tcp_policy=gfwlist\nss_basic_failover_country=JP\nss_basic_failover_budget=60\n'),MO_FAIL='start')
        self.assertNotEqual(result.returncode,0);self.assert_restored()

    def test_invalid_failover_or_uu_settings_fail_before_mutation(self):
        cases=['ss_basic_uu_tcp_policy=global\n','ss_basic_failover_enable=2\n',
               'ss_basic_failover_budget=20\nss_basic_failover_timeout=8\n',
               'ss_basic_failover_cooldown=29\n','ss_basic_failover_country=HKG\n',
               'ss_basic_failover_nodes=1;reboot\n','ss_basic_failover_countries=1=HK,1=JP\n']
        for value in cases:
            with self.subTest(value=value):
                result=self.install(self.settings(value));self.assertNotEqual(result.returncode,0)
                self.assertEqual(self.original,self.snapshot());self.assertEqual(self.events(),[])

    def test_probe_must_run_before_mutation(self):
        result=self.install(MO_BAD_PROBE='1');self.assertNotEqual(result.returncode,0)
        self.assertIn('HTTPS probe cannot run',result.stderr)
        self.assertEqual(self.original,self.snapshot());self.assertEqual(self.events(),[])

    def test_failed_controller_commit_restores_without_stopping_old_service(self):
        result=self.install(MO_FAIL='mv:scripts/ss_failover.sh');self.assertNotEqual(result.returncode,0)
        self.assert_restored('1');self.assertEqual(self.events(),[])
        self.assertTrue((self.r/'running').exists())

    def test_standard_root_symlink_is_accepted(self):
        actual=self.r/'actual-ks'; self.ks.rename(actual); self.ks.symlink_to(actual,target_is_directory=True)
        result=self.install(); self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.events(),['new:stop','new:start'])
        self.assertTrue(self.ks.is_symlink()); self.assertEqual(self.state()['ss_basic_enable'],'1')

    def test_destination_child_symlink_is_rejected_before_mutation(self):
        actual=self.r/'other-scripts'; (self.ks/'scripts').rename(actual)
        (self.ks/'scripts').symlink_to(actual,target_is_directory=True)
        result=self.install(); self.assertNotEqual(result.returncode,0)
        self.assertIn('destination parent',result.stderr)
        self.assertEqual(self.original,self.snapshot()); self.assertEqual(self.events(),[])

    def test_existing_hosts_and_unspecified_automatic_updates_are_preserved(self):
        self.data.update(ss_basic_anytls_hosts='origin.example=alias.example',ss_basic_rule_update='1',ss_basic_node_update='1',ss_basic_server_resolver='6'); self.write_state()
        result=self.install(); self.assertEqual(result.returncode,0,result.stderr)
        current=self.state()
        for key in ('ss_basic_anytls_hosts','ss_basic_rule_update','ss_basic_node_update','ss_basic_server_resolver'):
            self.assertEqual(current[key],self.data[key])
        journal=(self.backup()/'dbus.list').read_text().splitlines()
        self.assertIn('ss_basic_anytls_hosts',journal)
        self.assertNotIn('ss_basic_rule_update',journal); self.assertNotIn('ss_basic_node_update',journal); self.assertNotIn('ss_basic_server_resolver',journal)

    def test_private_hosts_and_automatic_update_settings_are_journaled(self):
        self.data.update(ss_basic_anytls_hosts='old.example=old-alias.example',ss_basic_rule_update='1',ss_basic_node_update='1'); self.write_state()
        args=self.settings('ss_basic_anytls_hosts=New.Example.=NEW-Alias.Example.,Other.Example=OTHER-Alias.Example\nss_basic_rule_update=0\nss_basic_node_update=0\n')
        result=self.install(args); self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.state()['ss_basic_anytls_hosts'],'new.example=new-alias.example,other.example=other-alias.example')
        self.assertEqual(self.state()['ss_basic_rule_update'],'0'); self.assertEqual(self.state()['ss_basic_node_update'],'0')
        b=self.backup(); journal=(b/'dbus.list').read_text().splitlines()
        for key in ('ss_basic_anytls_hosts','ss_basic_rule_update','ss_basic_node_update'): self.assertIn(key,journal)
        (self.r/'dbus.json').write_text(json.dumps(self.state()|{'ss_basic_enable':'0'}))
        restored=self.install(['--restore-files',str(b)]); self.assertEqual(restored.returncode,0,restored.stderr)
        self.assert_restored()

    def test_failed_hosts_and_automatic_update_changes_are_restored(self):
        self.data.update(ss_basic_anytls_hosts='old.example=old-alias.example',ss_basic_rule_update='1'); self.write_state()
        args=self.settings('ss_basic_anytls_hosts=new.example=new-alias.example\nss_basic_rule_update=0\nss_basic_node_update=0\n')
        result=self.install(args,MO_FAIL='start'); self.assertNotEqual(result.returncode,0)
        self.assert_restored(); self.assertNotIn('ss_basic_node_update',self.state())

    def test_invalid_hosts_and_automatic_update_values_fail_before_mutation(self):
        for value in ('ss_basic_anytls_hosts=bad;injection=alias.example\n','ss_basic_anytls_hosts=origin.example=\n','ss_basic_rule_update=yes\n','ss_basic_node_update=2\n'):
            with self.subTest(value=value):
                result=self.install(self.settings(value)); self.assertNotEqual(result.returncode,0)
                self.assertEqual(self.original,self.snapshot()); self.assertEqual(self.events(),[])

    def test_private_server_resolver_is_applied_and_restored(self):
        self.data['ss_basic_server_resolver']='5'; self.write_state()
        result=self.install(self.settings('ss_basic_server_resolver=11\n'))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.state()['ss_basic_server_resolver'],'11')
        b=self.backup(); self.assertIn('ss_basic_server_resolver',(b/'dbus.list').read_text().splitlines())
        (self.r/'dbus.json').write_text(json.dumps(self.state()|{'ss_basic_enable':'0'}))
        result=self.install(['--restore-files',str(b)]); self.assertEqual(result.returncode,0,result.stderr)
        self.assert_restored()

    def test_invalid_server_resolver_presets_fail_before_mutation(self):
        for preset in ('0','14','01','11;touch-marker',''):
            with self.subTest(preset=preset):
                result=self.install(self.settings('ss_basic_server_resolver='+preset+'\n'))
                self.assertNotEqual(result.returncode,0); self.assertIn('resolver preset',result.stderr)
                self.assertEqual(self.original,self.snapshot()); self.assertEqual(self.events(),[])

    def test_custom_server_resolver_nonstandard_port_is_normalized_and_restored(self):
        self.data.update(ss_basic_server_resolver='5',ss_basic_server_resolver_user='192.0.2.53:5353');self.write_state()
        result=self.install(self.settings('ss_basic_server_resolver=12\nss_basic_server_resolver_user=198.51.100.53:07874\n'))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.state()['ss_basic_server_resolver'],'12')
        self.assertEqual(self.state()['ss_basic_server_resolver_user'],'198.51.100.53:7874')
        backup=self.backup();self.assertIn('ss_basic_server_resolver_user',(backup/'dbus.list').read_text().splitlines())
        (self.r/'dbus.json').write_text(json.dumps(self.state()|{'ss_basic_enable':'0'}))
        restored=self.install(['--restore-files',str(backup)]);self.assertEqual(restored.returncode,0,restored.stderr)
        self.assert_restored()

    def test_existing_custom_server_resolver_is_preserved_and_normalized(self):
        self.data.update(ss_basic_server_resolver='12',ss_basic_server_resolver_user='198.51.100.53:07874');self.write_state()
        result=self.install();self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.state()['ss_basic_server_resolver_user'],'198.51.100.53:7874')

    def test_custom_https_resolver_list_preserves_paths_and_normalizes_hosts(self):
        value='https://DNS.Example.Test/private-path?check=one&flag=two,https://Backup.Example.Test/second-private-path'
        expected='https://dns.example.test/private-path?check=one&flag=two,https://backup.example.test/second-private-path'
        result=self.install(self.settings('ss_basic_server_resolver=12\nss_basic_server_resolver_user='+value+'\n'))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.state()['ss_basic_server_resolver'],'12')
        self.assertEqual(self.state()['ss_basic_server_resolver_user'],expected)
        self.assertEqual(self.events(),['new:stop','new:start'])
        self.assertNotIn(value,result.stdout+result.stderr)
        self.assertIn('ss_basic_server_resolver_user',(self.backup()/'dbus.list').read_text().splitlines())

    def test_failed_service_start_restores_previous_https_resolver_list(self):
        previous='https://old-dns.example.test/original-private-path,192.0.2.53:5353'
        self.data.update(ss_basic_server_resolver='12',ss_basic_server_resolver_user=previous);self.write_state()
        value='https://DNS.Example.Test/private-path,https://Backup.Example.Test/second-private-path'
        result=self.install(self.settings('ss_basic_server_resolver_user='+value+'\n'),MO_FAIL='start')
        self.assertNotEqual(result.returncode,0);self.assert_restored()
        self.assertEqual(self.state()['ss_basic_server_resolver_user'],previous)
        self.assertEqual(self.events(),['new:stop','new:start','new:stop'])
        self.assertNotIn(value,result.stdout+result.stderr)

    def test_invalid_custom_server_resolver_fails_before_service_changes(self):
        for preset,value in [('12',''),('12','198.51.100.53:0'),('12','resolver.example:7874'),('12','198.51.100.53:65536'),('11','198.51.100.53;touch-marker'),('11','198.051.100.53:53')]:
            with self.subTest(preset=preset,value=value):
                result=self.install(self.settings('ss_basic_server_resolver='+preset+'\nss_basic_server_resolver_user='+value+'\n'))
                self.assertNotEqual(result.returncode,0);self.assertIn('resolver',result.stderr)
                self.assertEqual(self.original,self.snapshot());self.assertEqual(self.events(),[])

    def test_existing_custom_preset_requires_nonempty_endpoint(self):
        self.data['ss_basic_server_resolver']='12';self.write_state()
        result=self.install();self.assertNotEqual(result.returncode,0)
        self.assertIn('requires an IPv4 endpoint',result.stderr)
        self.assertEqual(self.original,self.snapshot());self.assertEqual(self.events(),[])

    def test_failed_start_restores_previous_custom_server_resolver(self):
        self.data.update(ss_basic_server_resolver='12',ss_basic_server_resolver_user='192.0.2.53:5353');self.write_state()
        result=self.install(self.settings('ss_basic_server_resolver_user=198.51.100.53:7874\n'),MO_FAIL='start')
        self.assertNotEqual(result.returncode,0);self.assert_restored()
        self.assertEqual(self.state()['ss_basic_server_resolver_user'],'192.0.2.53:5353')
        self.assertEqual(self.events(),['new:stop','new:start','new:stop'])

    def test_explicit_all_anytls_migration_preserves_other_protocol(self):
        args=self.settings('ss_basic_allowinsecure=1\nss_basic_uu_macs=aa:bb:cc:dd:ee:02\n')+['--migration=phone-insecure']
        result=self.install(args); self.assertEqual(result.returncode,0,result.stderr)
        d=self.state(); self.assertEqual([d['ss_basic_allowinsecure'],d['ssconf_basic_allowinsecure_1'],d['ssconf_basic_allowinsecure_2']],['1']*3)
        self.assertEqual(d['ssconf_basic_allowinsecure_3'],'0')
        self.assertIn('ssconf_basic_allowinsecure_2',(self.backup()/'dbus.list').read_text())

    def test_migration_requires_explicit_private_approval(self):
        result=self.install(['--migration=phone-insecure']); self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.original,self.snapshot()); self.assertEqual(self.events(),[])

    def test_invalid_private_settings_rejected_before_mutation(self):
        cases=['ss_basic_enable=1\n','ss_basic_anytls_handshake=999\n','ss_basic_anytls_alpn=$(touch marker)\n','ss_basic_health_interval=45\n','ss_basic_anytls_min_idle=1\nss_basic_anytls_min_idle=2\n','ss_basic_uu_macs=not-a-mac\n','ss_basic_uu_macs=aa:bb:cc:dd:ee:02\nss_basic_bypass_macs=AA:BB:CC:DD:EE:02\n','ss_basic_allowinsecure=maybe\n']
        for value in cases:
            with self.subTest(value=value):
                result=self.install(self.settings(value)); self.assertNotEqual(result.returncode,0)
                self.assertEqual(self.original,self.snapshot()); self.assertEqual(self.events(),[])
        result=self.install(self.settings('ss_basic_health_interval=30\n',0o644)); self.assertNotEqual(result.returncode,0)

    def test_preflight_arch_version_space_and_flock(self):
        for extra in [{'MO_ARCH':'aarch64'},{'MO_SPACE':'1'},{'MO_BAD_FLOCK':'1'},{'MO_NONROOT':'1'}]:
            with self.subTest(extra=extra):
                result=self.install(**extra); self.assertNotEqual(result.returncode,0)
                self.assertEqual(self.original,self.snapshot()); self.assertEqual(self.events(),[])
        (self.ks/'ss/version').write_text('4.38.2\n')
        self.assertNotEqual(self.install().returncode,0)

    def test_space_reserves_independent_restore_tool_copy(self):
        def kb(path): return int(subprocess.check_output(['du','-sk',str(path)],text=True).split()[0])
        available=kb(self.pkg/'payload')+sum(kb(self.ks/p) for p in PATHS if (self.ks/p).exists() or (self.ks/p).is_symlink())+1024
        result=self.install(MO_SPACE=str(available)); self.assertNotEqual(result.returncode,0)
        self.assertIn('Insufficient space',result.stderr)
        self.assertEqual(self.original,self.snapshot()); self.assertEqual(self.events(),[])

    def test_checksum_tampering_and_extra_file(self):
        target=self.pkg/'payload/res/ss-health.js'; target.write_text('corrupted')
        self.assertNotEqual(self.install().returncode,0); self.assertEqual(self.original,self.snapshot())
        self.manifest(); (self.pkg/'payload/extra').write_text('extra')
        self.assertNotEqual(self.install().returncode,0); self.assertEqual(self.events(),[])

    def test_payload_symlink_and_special_file_rejected(self):
        extra=self.pkg/'payload/linked-directory'; extra.symlink_to(self.ks/'scripts',target_is_directory=True)
        result=self.install(); self.assertNotEqual(result.returncode,0)
        self.assertIn('Payload links and special files',result.stderr)
        extra.unlink(); os.mkfifo(extra)
        result=self.install(); self.assertNotEqual(result.returncode,0)
        self.assertIn('Payload links and special files',result.stderr)
        self.assertEqual(self.original,self.snapshot()); self.assertEqual(self.events(),[])

    def test_failed_staging_leaves_live_runtime_untouched(self):
        result=self.install(MO_FAIL='cp:res/ss-health.css'); self.assertNotEqual(result.returncode,0)
        self.assert_restored('1'); self.assertEqual(self.events(),[]); self.assertTrue((self.r/'running').exists())

    def test_failed_safe_dependency_commit_restores_original_enabled_state(self):
        result=self.install(MO_FAIL='mv:scripts/ss_dns_hooks.sh'); self.assertNotEqual(result.returncode,0)
        self.assert_restored('1'); self.assertEqual(self.events(),[]); self.assertTrue((self.r/'running').exists())

    def test_failed_later_commit_safely_stops_and_disables(self):
        result=self.install(MO_FAIL='mv:bin/anytls'); self.assertNotEqual(result.returncode,0)
        self.assert_restored(); self.assertEqual(self.events(),['new:stop','new:stop']); self.assertFalse((self.r/'running').exists())

    def test_failed_settings_application_restores_settings(self):
        result=self.install(MO_FAIL='dbus:ss_basic_anytls_handshake'); self.assertNotEqual(result.returncode,0)
        self.assert_restored(); self.assertEqual(self.events(),['new:stop','new:stop'])

    def test_failed_first_safe_stop_retries_before_restore(self):
        result=self.install(MO_FAIL='stop'); self.assertNotEqual(result.returncode,0)
        self.assert_restored(); self.assertEqual(self.events(),['new:stop','new:stop'])
        self.assertFalse((self.r/'running').exists())

    def test_failed_migration_restores_every_node_tls_flag(self):
        args=self.settings('ss_basic_allowinsecure=1\n')+['--migration=phone-insecure']
        result=self.install(args,MO_FAIL='start'); self.assertNotEqual(result.returncode,0)
        self.assert_restored(); self.assertNotIn('ssconf_basic_allowinsecure_2',self.state())

    def test_failed_start_and_absent_listeners_restore_without_old_start(self):
        for failure in ['start','listeners']:
            with self.subTest(failure=failure):
                # Each failure case needs a clean fixture after the first rollback.
                result=self.install(MO_FAIL=failure); self.assertNotEqual(result.returncode,0,result.stdout)
                self.assert_restored(); self.assertEqual(self.events()[-3:],['new:stop','new:start','new:stop'])
                self.data['ss_basic_enable']='1'; self.write_state(); (self.r/'running').touch(); (self.r/'failed').unlink(missing_ok=True)

    def test_self_disabled_start_is_failure(self):
        result=self.install(MO_DISABLE_ON_START='1'); self.assertNotEqual(result.returncode,0)
        self.assert_restored(); self.assertEqual(self.events(),['new:stop','new:start','new:stop'])

    def test_protected_direct_with_watchdog_accepts_absent_listeners(self):
        self.data['ss_basic_failover_enable']='1'; self.write_state()
        result=self.install(MO_RUNTIME_MODE='direct');self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('Protected direct path preserved',result.stdout)
        self.assertEqual(self.state()['ss_basic_enable'],'1')
        self.assertFalse((self.r/'running').exists())
        self.assertEqual(self.events(),['new:stop','new:start'])

    def test_protected_direct_missing_or_wrong_watchdog_rolls_back(self):
        self.data['ss_basic_failover_enable']='1';self.write_state()
        for watchdog in ['missing','wrong','duplicate']:
            with self.subTest(watchdog=watchdog):
                (self.r/'cron').unlink(missing_ok=True)
                result=self.install(MO_RUNTIME_MODE='direct',MO_WATCHDOG=watchdog)
                self.assertNotEqual(result.returncode,0);self.assertIn('watchdog',result.stderr)
                self.assert_restored();self.assertEqual(self.events()[-3:],['new:stop','new:start','new:stop'])
                self.data['ss_basic_enable']='1';self.write_state();(self.r/'running').touch()

    def test_protected_error_is_failure_even_with_listeners(self):
        self.data['ss_basic_failover_enable']='1';self.write_state()
        result=self.install(MO_RUNTIME_MODE='error',MO_KEEP_LISTENERS='1')
        self.assertNotEqual(result.returncode,0);self.assertIn('protected network path',result.stderr)
        self.assert_restored();self.assertEqual(self.events(),['new:stop','new:start','new:stop'])

    def test_protected_direct_requires_private_ram_state(self):
        self.data['ss_basic_failover_enable']='1';self.write_state()
        result=self.install(MO_RUNTIME_MODE='direct',MO_PUBLIC_RAM='1')
        self.assertNotEqual(result.returncode,0);self.assertIn('not private',result.stderr);self.assert_restored()

    def test_direct_without_failover_enabled_still_requires_listeners(self):
        result=self.install(MO_RUNTIME_MODE='direct')
        self.assertNotEqual(result.returncode,0);self.assertIn('listeners',result.stderr);self.assert_restored()

    def test_self_disabled_direct_is_failure(self):
        self.data['ss_basic_failover_enable']='1';self.write_state()
        result=self.install(MO_RUNTIME_MODE='direct',MO_DISABLE_ON_START='1')
        self.assertNotEqual(result.returncode,0);self.assertIn('disabled itself',result.stderr);self.assert_restored()

    def test_restore_refuses_running_service(self):
        result=self.install(); self.assertEqual(result.returncode,0,result.stderr)
        result=self.install(['--restore-files',str(self.backup())]); self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.events(),['new:stop','new:start'])

if __name__=='__main__': unittest.main()
