"""Run the real latency shell with private local mocks; no router or network."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'plugin/overlay/shadowsocks/scripts/ss_latency.sh'
NONCE = '1' * 32
MOCK = r'''
import base64,fcntl,hashlib,json,os,pathlib,sys,time
r=pathlib.Path(os.environ['LATENCY_TEST_ROOT']);cmd=pathlib.Path(sys.argv[0]).name;a=sys.argv[1:]
def read(name):return json.loads((r/name).read_text())
def write(name,value):
 p=r/(name+'.'+str(os.getpid()));p.write_text(json.dumps(value));os.replace(p,r/name)
def event(**value):
 value['command']=cmd
 fd=os.open(r/'events',os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
 os.write(fd,(json.dumps(value)+'\n').encode());os.close(fd)
def live(pid):
 try:os.kill(pid,0);return True
 except OSError:return False
def blocked(phase):
 plan=read('plans.json');event(phase=phase,pid=os.getpid())
 if plan.get('hang_'+phase):time.sleep(30)
 if plan.get('gate_'+phase):
  until=time.monotonic()+20
  while not (r/('release_'+phase)).exists():
   if time.monotonic()>until:raise RuntimeError('test gate not released')
   time.sleep(.01)
 return plan
if cmd=='dbus':
 event(operation=a[0],key=a[1] if len(a)>1 else '')
 if len(a)!=2 or a[0]!='get':raise RuntimeError('DBus writes are forbidden')
 print(read('dbus.json').get(a[1],''))
elif cmd=='nvram':
 event(operation=a[0])
 if a!=['get','wan0_dns']:raise RuntimeError('unexpected NVRAM access')
 print('192.0.2.53 192.0.2.54')
elif cmd=='ss-flock':
 try:fcntl.flock(int(a[-1]),fcntl.LOCK_UN if a[0]=='-u' else fcntl.LOCK_EX|(fcntl.LOCK_NB if a[0]=='-n' else 0))
 except BlockingIOError:sys.exit(1)
elif cmd=='base64_decode':
 sys.stdout.buffer.write(base64.b64decode(b''.join(sys.stdin.buffer.read().split()),validate=True))
elif cmd=='md5sum':print(hashlib.md5(pathlib.Path(a[0]).read_bytes() if a else sys.stdin.buffer.read()).hexdigest()+'  -')
elif cmd=='sleep':time.sleep(read('plans.json').get('sleep_seconds',.03))
elif cmd=='mock-anytls':
 if a and a[0]=='map-host':
  event(phase='hosts',argument_count=len(a))
  if read('plans.json').get('invalid_hosts'):sys.exit(2)
  print(read('plans.json').get('mapped_host',a[1]),end='');sys.exit(0)
 event(forbidden=True);raise RuntimeError('temporary proxy client is forbidden')
elif cmd=='ss-https-probe':
 if '-resolve' in a:
  opt=dict(zip(a[::2],a[1::2]))
  if set(opt)!={'-resolve','-dns','-ca','-timeout'} or opt['-timeout']!='5s':raise RuntimeError('resolver contract')
  event(resolver=opt['-dns'])
  plan=blocked('dns')
  if plan.get('dns_rc'):sys.exit(plan['dns_rc'])
  print('192.0.2.2');sys.exit(0)
 event(forbidden=True);raise RuntimeError('HTTPS proxy request is forbidden')
elif cmd=='ss-tcp-probe':
 opt=dict(zip(a[::2],a[1::2]))
 if set(opt)!={'-address','-timeout','-samples'} or opt['-timeout']!='5s' or opt['-samples']!='3':raise RuntimeError('TCP contract')
 event(address_port=opt['-address'].rsplit(':',1)[1])
 for fd in (8,9):
  try:os.fstat(fd);raise RuntimeError('probe inherited job lock')
  except OSError:pass
 plan=blocked('probe')
 if plan.get('mutate'):
  data=read('dbus.json');data.update(plan['mutate']);write('dbus.json',data)
 state=plan.get('state','ok');reason=plan.get('reason','measured' if state=='ok' else state)
 values=plan.get('samples_ms',[123,100,145]) if state=='ok' else []
 if state=='ok':
  for i in range(len(values)):event(phase='sample',ordinal=i+1)
 output={'version':1,'method':'router_tcp','target':'entry','state':state,'reason':reason,
  'samples':3,'successes':plan.get('successes',3 if state=='ok' else 0),'samples_ms':values,
  'latency_ms':plan.get('latency_ms',sorted(values)[1] if len(values)==3 else None)}
 print(plan.get('raw',json.dumps(output,separators=(',',':'))))
 sys.exit(plan.get('rc',0 if state=='ok' else 2 if state=='path_unverified' else 1))

else:
 event(forbidden=True);raise RuntimeError('forbidden command '+cmd)
'''


class LatencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ss-latency-test-')
        self.r = Path(self.tmp.name)
        self.ks, self.state, self.public = self.r/'ks', self.r/'state', self.r/'public.json'
        for path in [self.ks/'bin',self.ks/'scripts',self.ks/'ss/rules',self.ks/'res',self.r/'listeners']:
            path.mkdir(parents=True)
        self.data = {'ssconf_basic_type_1':'4','ssconf_basic_trojan_binary_1':'AnyTLS',
                     'ssconf_basic_use_kcp_1':'0','ssconf_basic_server_1':'192.0.2.2',
                     'ssconf_basic_port_1':'443','ssconf_basic_trojan_sni_1':'sample.invalid',
                     'ssconf_basic_password_1':base64.b64encode(b'SYNTHETIC-PRIVATE-PASSWORD').decode(),
                     'ssconf_basic_allowinsecure_1':'0','ssconf_basic_node':'7',
                     'ss_basic_enable':'1','ss_basic_mode':'1','ss_basic_server_resolver':'12',
                     'ss_basic_server_resolver_user':'https://resolver.invalid/dns-query',
                     'ss_basic_anytls_hosts':'sample.invalid=192.0.2.2'}
        self.plans = {}
        self.save()
        (self.r/'events').touch()
        self.env = dict(os.environ,LATENCY_TEST_ROOT=str(self.r))
        for name in ['dbus','nvram','ss-flock','base64_decode','md5sum','sleep','netstat',
                     'mock-anytls','ss-https-probe','ss-tcp-probe','iptables','ipset','service','cru','killall','pkill']:
            path = self.ks/'bin'/name
            path.write_text('#!'+sys.executable+'\n'+MOCK)
            path.chmod(0o755)
        (self.ks/'scripts/ss_anytls.sh').write_text('#!/bin/sh\nexec "'+str(self.ks/'bin/mock-anytls')+'" "$@"\n')
        (self.ks/'scripts/ss_dns_hooks.sh').write_text((ROOT/'plugin/overlay/shadowsocks/scripts/ss_dns_hooks.sh').read_text())
        (self.ks/'ss/rules/cacert.pem').write_text('synthetic-ca')
        source = SOURCE.read_text()
        for key,old,value in [('KS_ROOT','/koolshare',self.ks),('STATE_DIR','/tmp/ss_latency',self.state),('PUBLIC_JSON','/tmp/ss_latency.json',self.public)]:
            source = source.replace(key+'='+old,key+"='"+str(value)+"'")
        source = source.replace('$3==0','$3=='+str(os.getuid()))
        # Darwin has no /proc. These processes are all test-owned, and every
        # cleanup test separately checks that unrelated processes survive.
        source = re.sub(r'(?m)^token\(\) \{.*?\}$', 'token() { kill -0 "$1" 2>/dev/null && printf "%s" "$1"; }',source)
        self.script = self.r/'ss_latency.sh'
        self.script.write_text(source)
        self.counter = 0

    def tearDown(self):
        for event in self.events():
            if event.get('phase') in ('client','dns','probe') and 'pid' in event:
                try: os.kill(event['pid'],signal.SIGKILL)
                except OSError: pass
        self.tmp.cleanup()

    def save(self):
        for name,data in [('dbus.json',self.data),('plans.json',self.plans)]:
            tmp=self.r/(name+'.tmp');tmp.write_text(json.dumps(data));tmp.replace(self.r/name)

    def events(self):
        return [json.loads(line) for line in (self.r/'events').read_text().splitlines()]

    def run_script(self,*args):
        return subprocess.run(['/bin/sh',str(self.script),*args],env=self.env,capture_output=True,text=True,timeout=8)

    def start(self,nonce=None):
        self.save();self.counter+=1
        nonce=nonce or format(self.counter,'032x')
        result=self.run_script('start','1',nonce)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,'')
        return nonce

    def await_event(self,phase,timeout=8):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            found=[event for event in self.events() if event.get('phase')==phase]
            if found:return found[-1]
            time.sleep(.02)
        self.fail('mock phase did not start: '+phase)

    def wait_done(self,nonce,timeout=10):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            try:
                data=json.loads(self.public.read_text())
                if data.get('job_id')==nonce and data.get('state')!='running':
                    with (self.state/'job.lock').open('a') as lock:
                        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        except BlockingIOError:time.sleep(.02);continue
                    self.assertNotIn('SYNTHETIC-PRIVATE-PASSWORD',self.public.read_text())
                    self.assertNotIn(self.data['ssconf_basic_password_1'],self.public.read_text())
                    for name in ['dns','metrics','snapshot','snapshot.next']:
                        self.assertFalse((self.state/name).exists(),name)
                    self.assertEqual(list(self.state.glob('request.claim.*')),[])
                    self.assertEqual(list(self.state.glob('request.data.*')),[])
                    return data
            except (FileNotFoundError,json.JSONDecodeError):pass
            time.sleep(.02)
        self.fail('latency job did not finish')

    def completed(self):
        nonce=self.start();return self.wait_done(nonce)

    def mailbox(self,content):
        self.save()
        self.assertEqual(self.run_script('status').returncode,0)
        (self.state/'request').write_bytes(content)
        # The firmware uploader need not inherit the measurement umask.
        (self.state/'request').chmod(0o666)
        return self.run_script()

    def test_success_is_three_guarded_entry_tcp_samples_and_preserves_all_config(self):
        before=dict(self.data);result=self.completed()
        self.assertEqual((result['state'],result['latency_ms'],result['method'],result['target']),('ok',123,'router_tcp','entry'))
        self.assertEqual(json.loads((self.r/'dbus.json').read_text()),before)
        self.assertEqual(len([x for x in self.events() if x.get('phase')=='probe']),1)
        self.assertEqual(len([x for x in self.events() if x.get('phase')=='hosts']),1)
        self.assertFalse(any(x.get('forbidden') for x in self.events()))
        self.assertTrue(all(x['operation']=='get' for x in self.events() if x['command'] in ('dbus','nvram')))
        self.assertEqual(len([x for x in self.events() if x.get('phase')=='sample']),3)
        self.assertFalse(any('password' in x.get('key','') for x in self.events()))
        self.assertFalse(any(x.get('phase')=='client' for x in self.events()))

    def test_domain_uses_existing_configured_resolver_without_writes(self):
        self.data['ssconf_basic_server_1']='entry.invalid'
        self.plans['mapped_host']='mapped.invalid'
        self.assertEqual(self.completed()['state'],'ok')
        self.assertEqual([x['resolver'] for x in self.events() if 'resolver' in x],[self.data['ss_basic_server_resolver_user']])

    def test_unsupported_protocol_or_kcp_never_launches_a_client(self):
        for key,value in [('ssconf_basic_type_1','0'),('ssconf_basic_trojan_binary_1','Trojan'),('ssconf_basic_use_kcp_1','1')]:
            with self.subTest(key=key):
                old=self.data[key];self.data[key]=value
                self.assertEqual(self.completed()['reason'],'unsupported_node')
                self.data[key]=old
        self.assertFalse(any(x.get('phase')=='client' for x in self.events()))

    def test_unverified_output_path_has_no_samples_and_preserves_foreign_process(self):
        foreign=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])
        try:
            self.plans.update(state='path_unverified',reason='output_redirect')
            result=self.completed()
            self.assertEqual((result['state'],result['latency_ms']),('path_unverified',None))
            self.assertIsNone(foreign.poll())
            self.assertFalse(any(x.get('phase')=='sample' for x in self.events()))
        finally:foreign.terminate();foreign.wait(timeout=3)

    def test_probe_failures_and_partial_samples_never_become_a_latency_value(self):
        for plan,state,reason in [({'state':'timeout'},'timeout','timeout'),
                                  ({'state':'failed','reason':'connect_failed'},'failed','connect_failed'),
                                  ({'state':'path_unverified','reason':'guard_changed'},'path_unverified','guard_changed'),
                                  ({'successes':2},'failed','invalid_metrics'),
                                  ({'latency_ms':999},'failed','invalid_metrics'),
                                  ({'samples_ms':[1,2]},'failed','invalid_metrics'),
                                  ({'samples_ms':[1,2,6000]},'failed','invalid_metrics'),
                                  ({'raw':'{}'},'failed','invalid_metrics')]:
            with self.subTest(plan=plan):
                self.plans=plan;result=self.completed()
                self.assertEqual((result['state'],result['reason'],result['latency_ms']),(state,reason,None))

    def test_hung_probe_is_bounded_and_its_child_is_reaped(self):
        self.plans['hang_probe']=True
        result=self.completed();self.assertEqual(result['state'],'timeout')
        pid=self.await_event('probe')['pid']
        with self.assertRaises(ProcessLookupError):os.kill(pid,0)

    def test_dns_failure_and_hang_never_launch_a_client(self):
        self.data['ssconf_basic_server_1']='entry.invalid'
        for plan in [{'dns_rc':1},{'hang_dns':True}]:
            with self.subTest(plan=plan):
                self.plans=plan;self.assertEqual(self.completed()['state'],'dns_failed')
        self.assertFalse(any(x.get('phase')=='client' for x in self.events()))

    def test_only_matching_nonce_cancels_and_single_instance_preserves_active_job(self):
        self.plans['gate_probe']=True
        nonce=self.start(NONCE);self.await_event('probe')
        self.assertEqual(self.run_script('cancel','2'*32).returncode,0)
        self.assertFalse((self.state/'cancel').exists())
        other=self.run_script('start','1','3'*32)
        self.assertEqual(other.returncode,3)
        self.assertEqual(json.loads(self.public.read_text())['job_id'],nonce)
        self.assertEqual(self.run_script('cancel',nonce).returncode,0)
        result=self.wait_done(nonce)
        self.assertEqual((result['state'],result['latency_ms']),('cancelled',None))

    def test_endpoint_or_hosts_change_invalidates_an_inflight_result(self):
        for change in [{'ssconf_basic_server_1':'192.0.2.9'},
                       {'ss_basic_anytls_hosts':'entry.invalid=192.0.2.3'}]:
            with self.subTest(key=next(iter(change))):
                self.plans={'mutate':change};result=self.completed()
                self.assertEqual((result['state'],result['latency_ms']),('changed',None))
                self.data=json.loads((self.r/'dbus.json').read_text())

    def test_public_identity_excludes_password_and_results_do_not_export_it(self):
        first=self.completed()['fingerprint']
        self.data['ssconf_basic_password_1']=base64.b64encode(b'another-private-password').decode()
        second=self.completed()['fingerprint']
        self.assertEqual(first,second)
        self.assertNotIn('another-private-password',self.public.read_text())

    def test_no_arguments_and_injected_ids_or_nonces_do_not_start_work(self):
        for args in [(),('start','0',NONCE),('start','01',NONCE),('start','1;touch',NONCE),
                     ('start','1','A'*32),('start','1','f'*31),('cancel','f'*33)]:
            with self.subTest(args=args):self.assertEqual(self.run_script(*args).returncode,2)
        self.assertFalse(self.state.exists());self.assertEqual(self.events(),[])

    def test_status_initializes_idle_json_without_network_or_config_changes(self):
        result=self.run_script('status');self.assertEqual(result.returncode,0,result.stderr)
        data=json.loads(result.stdout)
        self.assertEqual((data['state'],data['target'],data['checked_at'],data['reason']),('idle','entry',0,''))
        self.assertEqual(json.loads(self.public.read_text()),data)
        self.assertEqual(os.readlink(self.ks/'res/ss-latency-status.js'),str(self.public))
        self.assertEqual(self.events(),[])

    def test_status_migrates_only_inactive_legacy_measurement_ram(self):
        self.assertEqual(self.run_script('status').returncode,0)
        legacy='{"version":1,"method":"router_https","target":"google","state":"ok","latency_ms":615}'
        self.public.write_text(legacy)
        with (self.state/'job.lock').open('r') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            self.assertEqual(self.run_script('status').returncode,1)
            self.assertEqual(self.public.read_text(),legacy)
        migrated=self.run_script('status');self.assertEqual(migrated.returncode,0)
        value=json.loads(migrated.stdout)
        self.assertEqual((value['state'],value['method'],value['target']),('idle','router_tcp','entry'))
        self.assertEqual(value['transport'],'ram_mailbox_v1')
        self.assertEqual(json.loads((self.r/'dbus.json').read_text()),self.data)
        self.assertEqual(self.events(),[])

    def test_same_nonce_retry_does_not_repeat_a_completed_measurement(self):
        nonce=self.start();first=self.wait_done(nonce)
        self.assertEqual(self.run_script('start','1',nonce).returncode,0)
        self.assertEqual(json.loads(self.public.read_text()),first)
        self.assertEqual(len([x for x in self.events() if x.get('phase')=='probe']),1)

    def test_mailbox_start_and_duplicate_nonce_preserve_config_and_sample_once(self):
        before=dict(self.data)
        request=('start 1 '+NONCE+'\n').encode()
        self.assertEqual(self.mailbox(request).returncode,0)
        result=self.wait_done(NONCE)
        self.assertEqual((result['state'],result['latency_ms']),('ok',123))
        self.assertFalse((self.state/'request').exists())
        self.assertEqual(self.mailbox(request).returncode,0)
        self.assertEqual(json.loads(self.public.read_text()),result)
        self.assertEqual(len([x for x in self.events() if x.get('phase')=='probe']),1)
        self.assertEqual(json.loads((self.r/'dbus.json').read_text()),before)

    def test_mailbox_cancel_only_matches_its_nonce_and_busy_start_cannot_replace_job(self):
        before=dict(self.data);self.plans.update(gate_probe=True,sleep_seconds=.5)
        nonce=self.start(NONCE);self.await_event('probe')
        self.assertEqual(self.mailbox(('cancel '+'2'*32+'\n').encode()).returncode,0)
        self.assertFalse((self.state/'cancel').exists())
        self.assertEqual(self.mailbox(('start 1 '+'3'*32+'\n').encode()).returncode,3)
        self.assertEqual(json.loads(self.public.read_text())['job_id'],nonce)
        self.assertEqual(self.mailbox(('cancel '+nonce+'\n').encode()).returncode,0)
        self.assertEqual(self.wait_done(nonce)['state'],'cancelled')
        self.assertEqual(json.loads((self.r/'dbus.json').read_text()),before)
        self.assertEqual(len([x for x in self.events() if x.get('phase')=='probe']),1)
        self.assertFalse(any(x.get('phase')=='client' for x in self.events()))

    def test_mailbox_rejects_noncanonical_bytes_without_launching_work(self):
        good=('start 1 '+NONCE+'\n').encode()
        bad=[b'',good[:-1],good.replace(b'\n',b'\r\n'),good+b'\n',good+b'x',
             good.replace(b'start ',b'start  '),good.replace(b'start ',b'start\t'),
             good.replace(b' 1 ',b' 01 '),good.replace(b' 1 ',b' 0 '),
             good.replace(b' 1 ',b' 1000000 '),good.replace(NONCE.encode(),b'A'*32),
             good[:-1]+b'\0\n',good+b'\0',good+b'a'*129,b'cancel '+b'2'*31+b'\n',
             good[:-1]+b'\xff\n',b'start 1 '+NONCE.encode()+b' extra\n']
        before=dict(self.data)
        for payload in bad:
            with self.subTest(payload_length=len(payload)):
                self.assertEqual(self.mailbox(payload).returncode,2)
                self.assertEqual(json.loads(self.public.read_text())['state'],'idle')
                self.assertEqual(list(self.state.glob('request.claim.*')),[])
                self.assertEqual(list(self.state.glob('request.data.*')),[])
        self.assertEqual(self.events(),[])
        self.assertEqual(json.loads((self.r/'dbus.json').read_text()),before)

    def test_mailbox_rejects_symlink_fifo_unsafe_parent_and_foreign_owner(self):
        self.assertEqual(self.run_script('status').returncode,0)
        request=self.state/'request';foreign=self.r/'foreign.txt';foreign.write_bytes(b'keep-foreign')
        request.symlink_to(foreign)
        self.assertEqual(self.run_script().returncode,2)
        self.assertEqual(foreign.read_bytes(),b'keep-foreign');request.unlink()
        os.mkfifo(request);self.assertEqual(self.run_script().returncode,2);request.unlink()
        request.write_bytes(('start 1 '+NONCE+'\n').encode())
        self.state.chmod(0o755);self.assertEqual(self.run_script().returncode,1);self.state.chmod(0o700)
        ls=self.ks/'bin/ls'
        ls.write_text('#!'+sys.executable+'\nimport os,pathlib,sys\n'
            'if pathlib.Path(sys.argv[-1]).name=="request":print("-rw-r--r-- 1 "+str(os.getuid()+1)+" 0 44 request")\n'
            'else:os.execv("/bin/ls",["ls"]+sys.argv[1:])\n')
        ls.chmod(0o755)
        self.assertEqual(self.run_script().returncode,2)
        self.assertEqual(self.events(),[])

    def test_two_mailbox_consumers_can_start_only_one_job(self):
        self.save();self.assertEqual(self.run_script('status').returncode,0)
        (self.state/'request').write_bytes(('start 1 '+NONCE+'\n').encode())
        commands=[subprocess.Popen(['/bin/sh',str(self.script)],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for _ in range(2)]
        codes=[]
        for process in commands:
            process.communicate(timeout=8);codes.append(process.returncode)
        self.assertEqual(sorted(codes),[0,2])
        self.assertEqual(self.wait_done(NONCE)['state'],'ok')
        self.assertEqual(len([x for x in self.events() if x.get('phase')=='probe']),1)
        self.assertEqual(json.loads((self.r/'dbus.json').read_text()),self.data)

    def test_source_checks_pid_start_token_and_has_no_service_mutations(self):
        source=SOURCE.read_text()
        self.assertIn('awk \'{print $22}\' "$PROC_ROOT/$1/stat"',source)
        self.assertIn('[ "$(token "$1")" != "$2" ] || kill -KILL "$1"',source)
        self.assertNotRegex(source,r'\b(?:killall|pkill|iptables|ipset|cru)\b|dbus\s+(?:set|remove)|ssconfig\.sh|service\s+restart')
        self.assertEqual(json.loads((ROOT/'plugin/overlay/shadowsocks/res/ss-latency-capabilities.js').read_text())['max_parallel'],1)
        self.assertEqual(json.loads((ROOT/'plugin/overlay/shadowsocks/res/ss-latency-capabilities.js').read_text())['transport'],'ram_mailbox_v1')


if __name__=='__main__':unittest.main(verbosity=2)
