"""Steady scoped DNS filtering: reload, pinned flows and private keeper."""
import base64
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
SOURCE = Path(__file__).resolve().parents[1] / 'shadowsocks/scripts/ss_adblock.sh'
ROUTING = SOURCE.with_name('ss_routing.sh')
MOCK = r'''
import fcntl,json,os,pathlib,shlex,shutil,signal,sys,tempfile,time,stat
r=pathlib.Path(os.environ['AD_TEST_ROOT']);name=pathlib.Path(sys.argv[0]).name;a=sys.argv[1:]
with (r/'events').open('a') as log:log.write(json.dumps([name]+a)+'\n')
def state():return json.loads((r/'state.json').read_text())
def update(value):
 p=r/('state.'+str(os.getpid()));p.write_text(json.dumps(value));os.replace(p,r/'state.json')
def writejson(p,value):
 t=p.with_name(p.name+'.'+str(os.getpid()));t.write_text(json.dumps(value));os.replace(t,p)
def fakeproc(pid,comm,parent=0,token=1000,group=None,session=None,argv=None):
 p=r/'proc'/str(pid);p.mkdir(exist_ok=True)
 (p/'comm').write_text(comm+'\n')
 (p/'stat').write_text(' '.join(map(str,[pid,'('+comm+')','S',parent,group or os.getpgrp(),session or os.getsid(0)]+[0]*15+[token,0]))+'\n')
 if argv is not None:(p/'cmdline').write_bytes(b'\0'.join(x.encode() for x in argv)+b'\0')
 return p
s=state()
if name=='dbus':print(s.get('dbus',{}).get(a[1],''));sys.exit(0)
if name=='nvram':print(s.get('nvram',{}).get(a[1],''));sys.exit(0)
if name in ['cru','chown']:sys.exit(0)
if name=='ls':
 p=pathlib.Path(a[-1]);m=p.lstat().st_mode;owner=65534 if s.get('untrusted_path')==str(p) else 0
 print(stat.filemode(m),1,owner,0,p.stat().st_size,'Jan 1 00:00',p);sys.exit(0)
if name=='sleep':time.sleep(.3 if a==['1'] and s.get('hup_delay') else .08);sys.exit(0)
if name in ['ss-flock','ss-adblock-flock']:
 if a[0]=='mktemp':
  template=pathlib.Path(a[-1]);prefix=template.name.replace('XXXXXX','')
  if '-d' in a:print(tempfile.mkdtemp(prefix=prefix,dir=template.parent))
  else:fd,p=tempfile.mkstemp(prefix=prefix,dir=template.parent);os.close(fd);print(p)
 else:
  if a[-1]=='4':(r/'supervisors'/str(os.getppid())).touch()
  try:fcntl.flock(int(a[-1]),fcntl.LOCK_UN if '-u' in a else fcntl.LOCK_EX|(fcntl.LOCK_NB if '-n' in a else 0))
  except BlockingIOError:sys.exit(1)
 sys.exit(0)
if name=='netstat':
 if s.get('port_busy'):print('udp 0 0 0.0.0.0:530 0.0.0.0:* 999/foreign-dns')
 for p in (r/'listeners').iterdir():
  try:d=json.loads(p.read_text())
  except (FileNotFoundError,json.JSONDecodeError):continue
  pid=p.name;owner='-' if s.get('hidden_listener_owner') else '999/foreign-dns' if s.get('foreign_listener_owner') else pid+'/ss-adblock-dn'
  for proto in ['tcp','udp']:
   for ip in ['127.0.0.1',d['lan']]:print(proto,'0 0',ip+':530','0.0.0.0:*',('LISTEN ' if proto=='tcp' else '' )+owner)
 sys.exit(0)
if name=='ss-adblock-dns':
 if '--test' in a:sys.exit(1 if s.get('dns_test_fail') else 0)
 if s.get('dns_start_fail'):sys.exit(1)
 pid=os.getpid();parent=os.getppid();p=fakeproc(pid,'ss-adblock-dns',parent,1000,argv=sys.argv)
 (r/'supervisors'/str(parent)).touch();fakeproc(parent,'sh',token=500)
 if s.get('omit_comm'):(p/'comm').unlink()
 if not s.get('omit_exe'):(p/'exe').symlink_to(sys.argv[0] if not s.get('identity_mismatch') else '/another/program')
 conf=pathlib.Path(next(x.split('=',1)[1] for x in a if x.startswith('--conf-file=')));lines=conf.read_text().splitlines()
 lan=next(x.split('=',1)[1].split(',')[1] for x in lines if x.startswith('listen-address='))
 rules=pathlib.Path(next(x.split('=',1)[1] for x in lines if x.startswith('servers-file=')))
 listener=r/'listeners'/str(pid);effective={}
 def reload(*args):
  # Model the strongest old-vendor behavior: both LOCAL and real server
  # entries survive HUP unless the exact name is explicitly replaced.
  if args:time.sleep(state().get('hup_delay',0))
  for line in rules.read_text().splitlines():
   if line.startswith('server=/'):
    domain,value=line[8:].split('/',1);effective[domain]=(value=='')
  writejson(r/('effective.'+str(pid)),effective)
  if args:
   with (r/'events').open('a') as log:log.write(json.dumps(['HUP',str(pid)])+'\n')
 def stop(*args):
  listener.unlink(missing_ok=True);shutil.rmtree(p,ignore_errors=True);sys.exit(0)
 signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGHUP,reload);reload()
 writejson(listener,{'lan':lan})
 while True:time.sleep(.01)
if name=='iptables':
 if a[:2]!=['-t','nat']:sys.exit(2)
 a=a[2:];op=a[0];chain=a[1];t=s['nat']
 if s.get('detach_fail') and op in ['-D','-F','-X']:sys.exit(1)
 if op=='-S':
  if chain not in t:sys.exit(1)
  print(('-P '+chain+' ACCEPT') if chain in ['PREROUTING','OUTPUT'] else '-N '+chain)
  for rule in t[chain]:print(shlex.join(['-A',chain]+rule))
  sys.exit(0)
 if chain not in t:sys.exit(1)
 if op=='-D':
  if a[2:] not in t[chain]:sys.exit(1)
  t[chain].remove(a[2:])
 elif op=='-F':t[chain]=[]
 elif op=='-X':
  if t[chain] or any(x[-2:]==['-j',chain] for rules in t.values() for x in rules):sys.exit(1)
  del t[chain]
 else:sys.exit(2)
 update(s);sys.exit(0)
if name=='iptables-restore':
 text=sys.stdin.read()
 if s.get('firewall_fail'):sys.exit(1)
 t=json.loads(json.dumps(s['nat']))
 for line in text.splitlines():
  if line.startswith(':'):t.setdefault(line.split()[0][1:],[])
  elif line.startswith('-'):
   x=shlex.split(line);op,chain=x[:2]
   if chain not in t:sys.exit(1)
   if op=='-F':t[chain]=[]
   elif op=='-A':t[chain].append(x[2:])
   elif op=='-I':t[chain].insert(int(x[2])-1,x[3:])
   else:sys.exit(2)
 s['nat']=t;update(s);sys.exit(0)
sys.exit(2)
'''

def encoded(text):return base64.b64encode(text.encode()).decode()
class AdblockTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.r=Path(self.tmp.name)
        self.ks=self.r/'ks';self.runtime=self.r/'runtime';self.proc=self.r/'proc';self.rules=self.r/'rules'
        for p in [self.ks/'bin',self.ks/'scripts',self.ks/'res',self.proc/'net',self.r/'listeners',self.r/'supervisors']:p.mkdir(parents=True)
        (self.r/'events').touch();(self.r/'mode').write_text('proxy\n');(self.proc/'net/nf_conntrack').write_text('')
        (self.r/'passwd').write_text('nobody:x:65534:65534:nobody:/tmp:/bin/false\n')
        (self.r/'group').write_text('nogroup:x:65534:\n')
        mock='#!'+sys.executable+'\n'+MOCK
        for name in ['dbus','nvram','cru','chown','ls','sleep','ss-flock','netstat','iptables','iptables-restore','dnsmasq']:
            p=self.ks/'bin'/name;p.write_text(mock);p.chmod(0o755)
        (self.ks/'scripts/ss_routing.sh').write_bytes(ROUTING.read_bytes())
        self.script=self.ks/'scripts/ss_adblock.sh';self.script.chmod(0o755) if self.script.exists() else None
        code=SOURCE.read_text()
        for old,new in [('KS_ROOT=/koolshare',self.ks),('STATE_DIR=/tmp/ss_adblock',self.runtime),('RULE_DIR=/tmp/ss_adblock_dns-rules',self.rules),('PUBLIC_JSON=/tmp/ss_adblock.json',self.r/'status.json'),('PROC_ROOT=/proc',self.proc),('PASSWD_FILE=/etc/passwd',self.r/'passwd'),('GROUP_FILE=/etc/group',self.r/'group'),('LOCK_FILE=/var/lock/ss-adblock.lock',self.r/'adblock.lock')]:
            code=code.replace(old,old.split('=')[0]+'='+shlex.quote(str(new)))
        code=code.replace('/tmp/ss_failover/mode',str(self.r/'mode')).replace('/var/lock/koolss.lock',str(self.r/'service.lock'))
        self.script.write_text(code);self.script.chmod(0o755)
        self.data={'dbus':{'ss_basic_enable':'1','ss_basic_adblock_enable':'1','ss_basic_bypass_macs':'02:00:00:00:00:01','ss_basic_uu_macs':'02:00:00:00:00:02'},'nvram':{'lan_ipaddr':'198.51.100.1','lan_ifname':'br0'},'nat':{'PREROUTING':[['-s','198.51.100.2/32','-p','udp','--dport','53','-j','DNAT','--to-destination','192.0.2.1:53']],'OUTPUT':[['-j','UU_KEEP']]}}
        self.foreign=json.loads(json.dumps(self.data['nat']));self.save();self.workers=[]
        self.env=dict(os.environ,AD_TEST_ROOT=str(self.r),PATH=str(self.ks/'bin')+':'+os.environ['PATH'])
    def tearDown(self):
        # Kill only recorded fixture supervisors before children so their wait
        # restart loop cannot spawn new DNS processes during teardown.
        for _ in range(2):
            for p in list((self.r/'supervisors').iterdir()):
                try:os.kill(int(p.name),signal.SIGKILL)
                except ProcessLookupError:pass
            time.sleep(.04)
        for p in list((self.r/'listeners').iterdir()):
            try:os.kill(int(p.name),signal.SIGTERM)
            except ProcessLookupError:pass
        for p in self.workers:
            if p.poll() is None:p.kill()
            p.wait()
        time.sleep(.05);self.tmp.cleanup()
    def save(self):(self.r/'state.json').write_text(json.dumps(self.data))
    def current(self):return json.loads((self.r/'state.json').read_text())
    def setdb(self,**values):self.data=self.current();self.data['dbus'].update(values);self.save()
    def run_script(self,action='apply'):return subprocess.run(['/bin/sh',str(self.script),action],env=self.env,capture_output=True,text=True,timeout=15)
    def status(self):return json.loads((self.r/'status.json').read_text())
    def events(self):return [json.loads(x) for x in (self.r/'events').read_text().splitlines()]
    def generation(self):return self.runtime/(self.runtime/'current').read_text().strip()
    def pid(self):return int((self.generation()/'identity').read_text().split()[0])
    def normalize(self,raw,mode='block'):
        return subprocess.run(['/bin/sh','-c','. "$1";normalize_encoded "$2" "$3"','unit',str(self.script),raw,mode],env=dict(self.env,SS_ADBLOCK_LIBRARY='1'),capture_output=True,text=True,timeout=3)
    def waitfor(self,predicate,seconds=5):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            try:
                if predicate():return
            except (FileNotFoundError,KeyError,json.JSONDecodeError):pass
            time.sleep(.03)
        self.fail('condition not reached; status='+str(self.status() if (self.r/'status.json').exists() else None))
    def flows(self,text=None):
        if text is None:text='ipv4 2 udp 17 180 src=192.0.2.2 dst=192.0.2.53 sport=42000 dport=53 src=198.51.100.1 dst=192.0.2.2 sport=530 dport=42000 [ASSURED]\n'
        (self.proc/'net/nf_conntrack').write_text(text)
    def blocked(self,domain,pid=None):
        rows=json.loads((self.r/('effective.'+str(pid or self.pid()))).read_text())
        matches=[(len(k),v) for k,v in rows.items() if domain==k or domain.endswith('.'+k)]
        return max(matches)[1] if matches else False
    def start(self):
        result=self.run_script();self.assertEqual(result.returncode,0,result.stderr+str(self.status() if (self.r/'status.json').exists() else ''))
        self.assertEqual(self.status()['state'],'active');return self.pid()
    def worker(self,foreign=False):
        master=self.pid();g=self.generation();meta=(g/'ancestry').read_text().split();p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);self.workers.append(p)
        d=self.proc/str(p.pid);d.mkdir();(d/'comm').write_text('ss-adblock-dns\n');(d/'exe').symlink_to(self.runtime/'ss-adblock-dns')
        row=[p.pid,'(ss-adblock-dns)','S',master+999 if foreign else master,int(meta[2]),int(meta[3])]+[0]*15+[1001,0]
        (d/'stat').write_text(' '.join(map(str,row))+'\n');(d/'cmdline').write_bytes(b'\0'.join(str(x).encode() for x in [self.runtime/'ss-adblock-dns','--keep-in-foreground','--conf-file='+str(g/'dns.conf')])+b'\0')
        return p
    def test_pure_validate_works_without_runtime_dependencies_or_files(self):
        self.data['dbus']['ss_basic_adblock_enable']='0';self.save()
        before=set(self.r.rglob('*'));result=self.run_script('validate')
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,'')
        self.assertFalse(self.runtime.exists());self.assertFalse((self.r/'status.json').exists())
        self.assertFalse((self.ks/'res/ss-adblock-status.js').is_symlink())
        self.assertTrue(all(x[0]=='dbus' for x in self.events()))
        self.assertEqual(set(self.r.rglob('*')),before)

    def test_strict_base64_domain_normalization_and_budgets(self):
        good=self.normalize(encoded(' Ads.Example\r\n\tTRACK.example\t\n\nads.example\n'))
        self.assertEqual((good.returncode,good.stdout),(0,'ads.example\ntrack.example\n'))
        for raw in ['!','QQ=','AA==','YR==',encoded('ads.example\x00'),encoded('ads.example\x1f'),encoded('é.example'),
                    encoded('ads.example.\n'),encoded('*.ads.example'),encoded('https://ads.example'),encoded('192.0.2.1'),
                    encoded('one_label'),encoded('-ads.example'),encoded('ads..example'),encoded('ads.exa_mple'),
                    encoded('ads.example\n'*257),encoded(' '*8193)]:
            with self.subTest(raw=raw[:25]):
                result=self.normalize(raw);self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,'')
        marker=self.r/'must-not-exist'
        self.assertNotEqual(self.normalize(encoded('ads.example\n$(touch '+str(marker)+')')).returncode,0)
        self.assertFalse(marker.exists())

    def test_protected_roots_descendants_and_parents_are_rejected(self):
        for domain in ['youtube.com','ads.googlevideo.com','com','googleapis.com','doubleclick.net','ads.googlesyndication.com','google-analytics.com','home.arpa','router.asus.com','asus.com','163.com','ads.uu.163.com']:
            with self.subTest(domain=domain):self.assertNotEqual(self.normalize(encoded(domain)).returncode,0)
        self.assertEqual(self.normalize(encoded('youtube.com'),'allow').returncode,0)
        self.assertEqual(self.normalize(encoded('notyoutube.com')).returncode,0)

    def test_scoped_rules_private_permissions_and_whitelist(self):
        self.setdb(ss_basic_adblock_domains=encoded('ads.example\ntrack.ads.example'),ss_basic_adblock_allow=encoded('safe.ads.example\ncriteo.com'))
        self.start();conf=(self.generation()/'dns.conf').read_text();rules=(self.rules/'servers').read_text()
        for expected in ['user=nobody','group=nogroup','cache-size=0','server=127.0.0.1#53','servers-file='+str(self.rules/'servers')]:self.assertIn(expected,conf)
        self.assertIn('server=/ads.example/\n',rules);self.assertIn('server=/safe.ads.example/127.0.0.1#53',rules)
        self.assertNotIn('log-queries',conf);self.assertNotIn('dhcp-range',conf)
        self.assertEqual(self.rules.stat().st_mode&0o777,0o710);self.assertEqual((self.rules/'servers').stat().st_mode&0o777,0o640)
        chain=self.current()['nat']['SS_ADBLOCK']
        self.assertEqual(chain[:2],[['-m','mac','--mac-source','02:00:00:00:00:01','-j','RETURN'],['-m','mac','--mac-source','02:00:00:00:00:02','-j','RETURN']])
        self.assertEqual(self.current()['nat']['PREROUTING'][2:],self.foreign['PREROUTING']);self.assertEqual(self.current()['nat']['OUTPUT'],self.foreign['OUTPUT'])
        self.assertEqual(self.status()['excluded_devices'],2);self.assertGreaterEqual(self.status()['domains'],32)
        self.assertFalse(self.blocked('criteo.com'));self.assertTrue(self.blocked('ads.example'));self.assertFalse(self.blocked('safe.ads.example'))
    def test_unchanged_reconcile_and_firewall_repair_do_not_reload_dns(self):
        pid=self.start();(self.r/'events').write_text('');self.assertEqual(self.run_script('reconcile').returncode,0)
        self.assertEqual(pid,self.pid());self.assertFalse(any(x[0] in ['ss-adblock-dns','iptables-restore','HUP'] for x in self.events()))
        self.data=self.current();self.data['nat']['PREROUTING']=self.foreign['PREROUTING'];self.save()
        self.assertEqual(self.run_script('reconcile').returncode,0);self.assertEqual(self.pid(),pid)
        self.assertEqual(sum(x[0]=='iptables-restore' for x in self.events()),1);self.assertFalse(any(x[0]=='HUP' for x in self.events()))
    def test_off_on_and_removed_domains_override_vendor_retained_local_rules_same_pid(self):
        self.flows();self.setdb(ss_basic_adblock_domains=encoded('example.com\ntrack.example.com'))
        pid=self.start();self.assertTrue(self.blocked('www.example.com'))
        self.setdb(ss_basic_adblock_allow=encoded('www.example.com'));self.assertEqual(self.run_script().returncode,0)
        self.waitfor(lambda:not self.blocked('www.example.com'));self.assertEqual(self.pid(),pid)
        self.setdb(ss_basic_adblock_allow='');self.assertEqual(self.run_script().returncode,0);self.assertTrue(self.blocked('www.example.com'))
        self.assertIn('server=/www.example.com/\n',(self.rules/'servers').read_text())
        self.setdb(ss_basic_adblock_enable='0');self.assertEqual(self.run_script().returncode,0)
        self.waitfor(lambda:not self.blocked('www.example.com'));self.assertEqual(self.pid(),pid);self.assertEqual(self.current()['nat'],self.foreign)
        self.assertTrue(self.status()['running']);self.assertEqual(self.status()['state'],'off')
        self.setdb(ss_basic_adblock_enable='1',ss_basic_adblock_domains='');self.assertEqual(self.run_script().returncode,0)
        self.assertEqual(self.pid(),pid);self.assertFalse(self.blocked('www.example.com'));self.assertTrue(self.blocked('adnxs.com'))
        self.assertIn('server=/track.example.com/127.0.0.1#53',(self.rules/'servers').read_text())
    def test_async_hup_without_tcp_forks_finishes_before_success_is_reported(self):
        self.flows();self.data['hup_delay']=.2;self.save()
        self.setdb(ss_basic_adblock_domains=encoded('example.com'))
        pid=self.start();self.assertTrue(self.blocked('www.example.com'))
        self.setdb(ss_basic_adblock_allow=encoded('www.example.com'))
        self.assertEqual(self.run_script().returncode,0);self.assertFalse(self.blocked('www.example.com'))
        self.setdb(ss_basic_adblock_allow='');(self.r/'events').write_text('')
        self.assertEqual(self.run_script().returncode,0)
        # No wait-for-event helper: apply itself must cover this delayed HUP.
        self.assertTrue(self.blocked('www.example.com'));self.assertEqual(self.pid(),pid)
        self.assertTrue(any(x==['sleep','1'] for x in self.events()))
        self.assertEqual(len(list((self.r/'listeners').iterdir())),1)
    def test_membership_change_drains_pins_before_new_exclusion_applies(self):
        self.flows();pid=self.start();self.setdb(ss_basic_bypass_macs='02:00:00:00:00:03')
        self.assertEqual(self.run_script().returncode,0);self.assertEqual(self.status()['state'],'draining');self.assertEqual(self.pid(),pid)
        self.assertEqual(self.current()['nat'],self.foreign);self.waitfor(lambda:not self.blocked('adnxs.com'))
        self.flows('');self.waitfor(lambda: (self.runtime/'current').exists() and self.pid()!=pid and self.status()['state']=='active',8)
        self.assertTrue(any('02:00:00:00:00:03' in x for x in self.current()['nat']['SS_ADBLOCK']))
    def test_unknown_flow_state_and_persistent_pins_keep_passthrough_until_actual_zero(self):
        self.flows('udp broken\n');pid=self.start();self.setdb(ss_basic_adblock_enable='0');self.assertEqual(self.run_script().returncode,0)
        time.sleep(.5);self.assertEqual(self.pid(),pid);self.assertIsNone(self.status()['pending_flows'])
        self.flows();time.sleep(.5);self.assertEqual(self.pid(),pid)
        self.flows('');self.waitfor(lambda:not (self.runtime/'current').exists() and not self.status()['running'])
    def test_crash_recovers_same_port_passthrough_then_explicit_reconcile_filters(self):
        self.flows();pid=self.start();os.kill(pid,signal.SIGTERM)
        self.waitfor(lambda:self.pid()!=pid and self.status()['running'] and self.status()['mode']=='passthrough',8)
        self.assertEqual(self.current()['nat'],self.foreign);self.waitfor(lambda:not self.blocked('adnxs.com'))
        replacement=self.pid();self.assertEqual(self.run_script('reconcile').returncode,0)
        self.assertEqual(self.pid(),replacement);self.waitfor(lambda:self.blocked('adnxs.com'));self.assertEqual(self.status()['state'],'active')
    def test_private_uninstall_keeper_survives_removing_plugin_and_reclaims_only_zero_pins(self):
        self.flows();pid=self.start();self.assertEqual(self.run_script('uninstall').returncode,0)
        self.assertTrue(self.runtime.exists());self.assertEqual(self.current()['nat'],self.foreign);self.waitfor(lambda:not self.blocked('adnxs.com'))
        # Native OS commands remain, but no /koolshare runtime dependency is
        # available. The copied flock/DNS/keeper still rescue a failed master.
        import shutil
        shutil.rmtree(self.ks/'scripts');(self.ks/'bin/ss-flock').unlink();(self.ks/'bin/dnsmasq').unlink()
        os.kill(pid,signal.SIGTERM);self.waitfor(lambda:any(int(p.name)!=pid for p in (self.r/'listeners').iterdir()),8)
        self.flows('');self.waitfor(lambda:not self.runtime.exists() and not self.rules.exists(),8)
    def test_reload_cap_uses_passthrough_until_pins_zero_before_fresh_master(self):
        self.flows();pid=self.start();(self.generation()/'reloads').write_text('64\n')
        self.setdb(ss_basic_adblock_domains=encoded('new.example'))
        self.assertEqual(self.run_script().returncode,0);self.assertEqual(self.pid(),pid);self.assertEqual(self.status()['state'],'draining')
        self.assertFalse(self.blocked('adnxs.com'));self.flows('')
        self.waitfor(lambda:self.pid()!=pid and self.status()['state']=='active',8);self.assertTrue(self.blocked('new.example'))
    def test_hup_closes_only_verified_tcp_forks_not_master_or_foreign_worker(self):
        self.flows();pid=self.start();owned=self.worker();foreign=self.worker(True)
        self.setdb(ss_basic_adblock_domains=encoded('new.example'));self.assertEqual(self.run_script().returncode,0)
        self.waitfor(lambda:owned.poll() is not None);self.assertIsNone(foreign.poll());self.assertEqual(self.pid(),pid)
    def test_port_conflict_foreign_chain_and_invalid_settings_fail_open(self):
        self.data['port_busy']=True;self.save();self.assertNotEqual(self.run_script().returncode,0);self.assertEqual(self.current()['nat'],self.foreign)
        self.data=self.current();self.data.pop('port_busy');self.data['nat']['SS_ADBLOCK']=[['-j','FOREIGN_KEEP']];self.save()
        self.assertNotEqual(self.run_script().returncode,0);self.assertEqual(self.current()['nat']['SS_ADBLOCK'],[['-j','FOREIGN_KEEP']])
        self.assertEqual(self.current()['nat']['PREROUTING'],self.foreign['PREROUTING'])
    def test_old_kernel_identity_fallback_and_hidden_or_truncated_netstat_names(self):
        self.data.update(omit_comm=True,omit_exe=True,hidden_listener_owner=True);self.save();self.flows();pid=self.start()
        self.assertEqual(self.run_script('stop').returncode,0);self.assertEqual(self.pid(),pid);self.assertEqual(self.current()['nat'],self.foreign)
    def test_untrusted_ram_state_is_rejected_before_executing_private_flock(self):
        self.runtime.mkdir(mode=0o700);bad=self.runtime/'ss-adblock-flock';bad.write_text('#!/bin/sh\ntouch '+str(self.r/'pwned')+'\n');bad.chmod(0o700)
        self.data['untrusted_path']=str(self.runtime);self.save();(self.ks/'bin/ss-flock').unlink()
        self.assertNotEqual(self.run_script('web').returncode,0);self.assertFalse((self.r/'pwned').exists())
        self.assertEqual(self.current()['nat'],self.foreign)
    def test_failed_hook_detach_preserves_forwarder_even_with_zero_pins(self):
        pid=self.start();self.data=self.current();self.data['detach_fail']=True;self.save()
        self.setdb(ss_basic_adblock_enable='0');self.assertNotEqual(self.run_script().returncode,0)
        time.sleep(.6);self.assertEqual(self.pid(),pid);self.assertFalse(self.blocked('adnxs.com'))
        self.assertEqual(self.status()['state'],'error');self.assertTrue(self.status()['running'])
        self.data=self.current();self.data['detach_fail']=False;self.save()
        self.waitfor(lambda:not (self.runtime/'current').exists(),8);self.assertEqual(self.current()['nat'],self.foreign)
    def test_default_web_serializes_service_before_adblock_and_owns_only_its_cron(self):
        self.assertEqual(self.run_script('web').returncode,0);events=self.events();locks=[x for x in events if x[0] in ['ss-flock','ss-adblock-flock'] and x[1:2]==['-x']]
        self.assertEqual(locks[0][-1],'7');self.assertEqual(locks[1][-1],'5')
        self.assertTrue(any(x[:3]==['cru','a','ss_adblock'] for x in events));self.assertTrue(all(x[2]=='ss_adblock' for x in events if x[0]=='cru'))

if __name__=='__main__':unittest.main()
