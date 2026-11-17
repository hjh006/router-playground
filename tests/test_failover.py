"""Exercise the real controller in private fake router roots, without networking."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MOCK = r'''
import base64,fcntl,json,os,pathlib,signal,sys,time
r=pathlib.Path(os.environ['FO_TEST_ROOT']);cmd=pathlib.Path(sys.argv[0]).name;a=sys.argv[1:]
def read(n):return json.loads((r/n).read_text())
def write(n,v):(r/n).write_text(json.dumps(v))
def event(v):
 with (r/'events').open('a') as f:f.write(json.dumps(v)+'\n')
def live():
 for p in (r/'listeners').iterdir():
  try:os.kill(int(p.name),0);yield int(p.name),json.loads(p.read_text())
  except (OSError,ValueError):pass
def clock(delta=0):
 value=int((r/'clock').read_text())+delta;(r/'clock').write_text(str(value));return value
if cmd=='dbus':
 d=read('dbus.json')
 if a[0]=='get':print(d.get(a[1],''))
 elif a[0]=='list':
  for k,v in sorted(d.items()):
   if k.startswith(a[1]):print(k+'='+v)
 else:sys.exit(2)
elif cmd=='ss-flock':
 try:fcntl.flock(int(a[-1]),fcntl.LOCK_UN if '-u' in a else fcntl.LOCK_EX|(fcntl.LOCK_NB if '-n' in a else 0))
 except (OSError,BlockingIOError):sys.exit(1)
elif cmd=='base64_decode':
 try:sys.stdout.buffer.write(base64.b64decode(sys.stdin.buffer.read(),validate=False))
 except Exception:sys.exit(1)
elif cmd=='date':print(clock())
elif cmd=='sleep':clock(int(a[0]));time.sleep(.04)
elif cmd=='nvram':print('192.0.2.53')
elif cmd=='nslookup':
 if read('plans.json').get('hang_dns'):
  event({'dns_pid':os.getpid()});time.sleep(30)
 print('Name: '+a[0]+'\nAddress 1: 192.0.2.2')
elif cmd=='netstat':
 if read('plans.json').get('occupied_port'):print('tcp 0 0 127.0.0.1:23457 0.0.0.0:* LISTEN 99999/foreign')
 for pid,x in live():print('tcp 0 0 '+x['address']+' 0.0.0.0:* LISTEN '+str(pid)+'/anytls')
elif cmd=='mock-anytls':
 address=a[a.index('-socks')+1];server=a[a.index('-s')+1]
 node=int(server.split(':')[0].split('.')[-1])
 (r/'listeners'/str(os.getpid())).write_text(json.dumps({'address':address,'node':node}))
 event({'started_node':node,'pid':os.getpid(),'nat':'-nat' in a})
 while True:time.sleep(1)
elif cmd=='ss-https-probe':
 if '-resolve' in a:
  event({'dns_endpoint_port':a[a.index('-dns')+1].split(':')[-1]})
  if read('plans.json').get('hang_dns'):
   event({'dns_pid':os.getpid()});time.sleep(30)
  print('192.0.2.2');sys.exit(0)
 proxy=a[a.index('-proxy')+1];target=a[a.index('-target')+1];d=read('dbus.json');plans=read('plans.json')
 node=int(d['ssconf_basic_node']) if proxy.endswith(':23456') else next((x['node'] for _,x in live() if x['address']==proxy),0)
 plan=plans.get('active',{}) if proxy.endswith(':23456') else plans.get('candidates',{}).get(str(node),{})
 event({'probe_node':node,'target':target,'active':proxy.endswith(':23456')})
 clock(plan.get('cost',1))
 if plans.get('invalidate')==target and not (r/'invalidated').exists():
  (r/'invalidated').touch();(r/'state/generation').write_text('new-generation\n')
 if plans.get('disable')==target and not (r/'disabled').exists():
  (r/'disabled').touch();d['ss_basic_enable']='0';write('dbus.json',d)
 if not plan.get('ok',False) or target in plan.get('failed_targets',[]):print('000|0');sys.exit(35)
 print(('200' if target=='telegram' else '204')+'|'+str(plan.get('ms',100)/1000))
elif cmd=='mock-service':
 d=read('dbus.json');g=(r/'state/generation').read_text().strip()
 action=a[0];target=a[1] if action=='failover-switch' else ''
 expected=a[2] if target else a[1];generation=a[3] if target else a[2]
 if d.get('ss_basic_enable')!='1' or d.get('ss_basic_failover_enable')!='1' or d['ssconf_basic_node']!=expected or g!=generation:sys.exit(75)
 if action=='failover-direct':
  event({'action':'direct'})
  if read('plans.json').get('direct_error'):(r/'state/mode').write_text('error\n');sys.exit(1)
  (r/'state/mode').write_text('direct\n')
 elif action=='failover-switch':
  event({'action':'switch','node':int(target)});d['ssconf_basic_node']=target;write('dbus.json',d)
  if read('plans.json').get('switch_error'):(r/'state/mode').write_text('error\n');sys.exit(20)
  (r/'state/mode').write_text('proxy\n')
 else:sys.exit(2)
else:sys.exit(2)
'''


class FailoverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ss-failover-test-')
        self.r = Path(self.tmp.name)
        self.ks = self.r/'ks';self.state = self.r/'state';self.public = self.r/'public.json'
        for p in [self.ks/'bin',self.ks/'scripts',self.ks/'ss/rules',self.ks/'res',self.r/'listeners',self.r/'proc']:
            p.mkdir(parents=True)
        self.status_link=self.ks/'res/ss-failover-status.js'
        self.data = {'ss_basic_enable':'1','ss_basic_type':'4','ss_basic_trojan_binary':'AnyTLS','ssconf_basic_node':'1',
                     'ss_basic_failover_enable':'1','ss_basic_failover_country':'HK','ss_basic_failover_failures':'1',
                     'ss_basic_failover_recoveries':'1','ss_basic_failover_budget':'120','ss_basic_server_resolver':'11'}
        self.node(1,'香港01');self.node(2,'香港02');self.node(3,'Japan');self.node(4,'Singapore')
        self.plans = {'active':{'ok':False},'candidates':{}}
        self.save()
        (self.r/'events').touch();(self.r/'clock').write_text('1000')
        self.env = dict(os.environ, FO_TEST_ROOT=str(self.r))
        for name in ['dbus','ss-flock','base64_decode','date','sleep','nvram','nslookup','netstat','mock-anytls','ss-https-probe','mock-service']:
            p=self.ks/'bin'/name;p.write_text('#!'+sys.executable+'\n'+MOCK);p.chmod(0o755)
        (self.ks/'scripts/ss_anytls.sh').write_text('#!/bin/sh\ncase "$1" in map-host) printf "%s" "$2"; exit;; esac\nexec "'+str(self.ks/'bin/mock-anytls')+'" "$@"\n')
        (self.ks/'ss/ssconfig.sh').write_text('#!/bin/sh\nexec "'+str(self.ks/'bin/mock-service')+'" "$@"\n')
        (self.ks/'ss/rules/cacert.pem').write_text('synthetic-ca')
        (self.ks/'scripts/ss_dns_hooks.sh').write_text((ROOT/'plugin/overlay/shadowsocks/scripts/ss_dns_hooks.sh').read_text())
        source=(ROOT/'plugin/overlay/shadowsocks/scripts/ss_failover.sh').read_text()
        for key,value in [('KS_ROOT',self.ks),('STATE_DIR',self.state),('PUBLIC_JSON',self.public),('PROC_ROOT',self.r/'proc')]:
            old={'KS_ROOT':'/koolshare','STATE_DIR':'/tmp/ss_failover','PUBLIC_JSON':'/tmp/ss_failover.json','PROC_ROOT':'/proc'}[key]
            source=source.replace(key+'='+old,key+"='"+str(value)+"'")
        self.script=self.r/'ss_failover.sh';self.script.write_text(source)

    def tearDown(self):
        for p in (self.r/'listeners').iterdir():
            try:os.kill(int(p.name),15)
            except OSError:pass
        self.tmp.cleanup()

    def node(self, identity, name):
        suffix=str(identity)
        for k,v in {'type':'4','trojan_binary':'AnyTLS','name':name,'server':'192.0.2.'+suffix,'port':'443',
                    'password':base64.b64encode(b'PRIVATE-SYNTHETIC-PASSWORD').decode(),'allowinsecure':'0'}.items():
            self.data['ssconf_basic_'+k+'_'+suffix]=v

    def save(self):
        (self.r/'dbus.json').write_text(json.dumps(self.data));(self.r/'plans.json').write_text(json.dumps(self.plans))

    def run_script(self,command='tick',allowed=(0,75)):
        self.save()
        result=subprocess.run(['/bin/sh',str(self.script),command],env=self.env,capture_output=True,text=True,timeout=30)
        self.assertIn(result.returncode,allowed,result.stderr)
        self.data=json.loads((self.r/'dbus.json').read_text())
        if self.public.exists():
            text=self.public.read_text();self.assertNotIn('PRIVATE-SYNTHETIC-PASSWORD',text);self.assertNotIn('192.0.2.',text)
        return result

    def status(self):return json.loads(self.public.read_text())
    def events(self):return [json.loads(x) for x in (self.r/'events').read_text().splitlines()]
    def switches(self):return [x['node'] for x in self.events() if x.get('action')=='switch']

    def test_validation_is_pure_and_rejects_injection_and_bad_budget(self):
        self.run_script('validate');self.assertFalse(self.state.exists())
        self.assertFalse(self.public.exists());self.assertFalse(self.status_link.is_symlink())
        self.assertEqual(list((self.ks/'res').iterdir()),[])
        for key,value in [('ss_basic_failover_countries','1=HK;touch /tmp/bad'),('ss_basic_failover_nodes','1;2'),
                          ('ss_basic_failover_country','HKG'),('ss_basic_failover_budget','20')]:
            old=self.data.get(key);self.data[key]=value
            if key=='ss_basic_failover_budget':self.data['ss_basic_failover_timeout']='8'
            self.save();p=subprocess.run(['/bin/sh',str(self.script),'validate'],env=self.env,capture_output=True)
            self.assertEqual(p.returncode,2);self.assertFalse(self.state.exists())
            self.assertFalse(self.public.exists());self.assertEqual(list((self.ks/'res').iterdir()),[])
            if old is None:self.data.pop(key,None)
            else:self.data[key]=old
            self.data.pop('ss_basic_failover_timeout',None)

    def test_status_link_is_created_and_same_target_is_idempotent(self):
        self.run_script('reset')
        self.assertTrue(self.status_link.is_symlink())
        self.assertEqual(os.readlink(self.status_link),str(self.public))
        self.assertEqual(self.status_link.read_bytes(),self.public.read_bytes())
        inode=self.status_link.lstat().st_ino
        self.run_script('reset')
        self.assertEqual(self.status_link.lstat().st_ino,inode)
        self.assertEqual(json.loads(self.status_link.read_text()),self.status())

    def test_validate_preserves_existing_state_and_foreign_status_path(self):
        self.state.mkdir();(self.state/'generation').write_text('original-generation\n')
        self.public.write_text('{"version":1,"state":"disabled"}\n')
        self.status_link.write_text('foreign-status-file')
        before={p:p.read_bytes() for p in [self.state/'generation',self.public,self.status_link]}
        self.run_script('validate')
        self.assertEqual({p:p.read_bytes() for p in before},before)
        self.assertEqual(list(self.state.iterdir()),[self.state/'generation'])
        self.assertEqual(self.events(),[])

    def test_foreign_status_destinations_are_rejected_without_overwrite(self):
        foreign=self.r/'foreign';foreign.write_text('foreign-content')
        for kind in ['regular','link','dangling','directory']:
            with self.subTest(kind=kind):
                if kind=='regular':self.status_link.write_text('foreign-content')
                elif kind=='directory':self.status_link.mkdir()
                else:self.status_link.symlink_to(foreign if kind=='link' else self.r/'missing')
                self.run_script('reset',allowed=(1,))
                self.assertFalse(self.state.exists());self.assertFalse(self.public.exists())
                self.assertEqual(foreign.read_text(),'foreign-content');self.assertEqual(self.events(),[])
                if kind=='regular':self.assertEqual(self.status_link.read_text(),'foreign-content')
                elif kind=='directory':self.assertTrue(self.status_link.is_dir());self.assertEqual(list(self.status_link.iterdir()),[])
                else:self.assertEqual(os.readlink(self.status_link),str(foreign if kind=='link' else self.r/'missing'))
                if kind=='directory':self.status_link.rmdir()
                else:self.status_link.unlink()

    def test_public_json_symlink_is_rejected_before_exposure(self):
        foreign=self.r/'foreign';foreign.write_text('foreign-content')
        self.public.symlink_to(foreign)
        self.run_script('reset',allowed=(1,))
        self.assertFalse(self.status_link.exists());self.assertFalse(self.status_link.is_symlink())
        self.assertFalse(self.state.exists());self.assertEqual(self.events(),[])
        self.assertEqual(os.readlink(self.public),str(foreign));self.assertEqual(foreign.read_text(),'foreign-content')

    def test_two_of_three_current_targets_avoid_single_site_failover(self):
        self.plans['active']={'ok':True,'failed_targets':['google']}
        self.run_script();self.assertEqual(self.status()['state'],'healthy');self.assertEqual(self.switches(),[])
        self.assertFalse(any('started_node' in x for x in self.events()))

    def test_same_country_wins_over_faster_foreign_node(self):
        self.node(3,'🇯🇵 日本经香港中转')
        self.plans['candidates']={'2':{'ok':True,'ms':300},'3':{'ok':True,'ms':20}}
        self.run_script();self.assertEqual(self.switches(),[2]);self.assertEqual(self.status()['state'],'switched')
        self.assertFalse(any(x.get('probe_node')==3 and not x['active'] for x in self.events() if 'probe_node' in x))
        self.assertTrue(all(not x['nat'] for x in self.events() if 'started_node' in x))

    def test_lowest_latency_within_same_country_is_selected(self):
        self.node(5,'Hong Kong');self.plans['candidates']={'2':{'ok':True,'ms':300},'5':{'ok':True,'ms':80},'3':{'ok':True,'ms':20}}
        self.run_script();self.assertEqual(self.switches(),[5])

    def test_other_countries_are_ranked_only_after_same_country_failure(self):
        self.plans['candidates']={'3':{'ok':True,'ms':200},'4':{'ok':True,'ms':50}}
        self.run_script();self.assertEqual(self.switches(),[4])
        order=[x['probe_node'] for x in self.events() if 'probe_node' in x and not x['active']]
        self.assertLess(order.index(2),order.index(3))

    def test_all_failed_enters_direct_and_keeps_user_intent(self):
        self.run_script();self.assertEqual(self.status()['state'],'direct');self.assertEqual(self.status()['reason'],'all_candidates_failed')
        self.assertEqual(self.data['ss_basic_enable'],'1');self.assertEqual(self.switches(),[])

    def test_custom_node_dns_port_is_used_by_candidate_bootstrap(self):
        self.data['ss_basic_server_resolver']='12'
        self.data['ss_basic_server_resolver_user']='192.0.2.53:7874'
        self.data['ssconf_basic_server_2']='candidate.example.test'
        self.plans['candidates']={'2':{'ok':True,'ms':80}}
        self.run_script()
        self.assertIn({'dns_endpoint_port':'7874'},self.events())
        self.assertEqual(self.switches(),[2])

    def test_direct_recovers_only_after_repeated_winner_confirmation(self):
        self.data['ss_basic_failover_recoveries']='2';self.run_script()
        self.plans['candidates']={'2':{'ok':True,'ms':50}}
        self.run_script();self.assertEqual(self.status()['state'],'recovering');self.assertEqual(self.switches(),[])
        self.run_script();self.assertEqual(self.switches(),[2])

    def test_failed_fastest_winner_preserves_same_country_backup_for_fresh_confirmations(self):
        self.node(5,'Hong Kong 03');self.data['ss_basic_failover_recoveries']='2'
        self.plans['candidates']={'2':{'ok':True,'ms':10},'5':{'ok':True,'ms':80},'3':{'ok':True,'ms':1}}
        self.run_script();self.assertEqual((self.state/'winner').read_text().split()[0],'2')
        self.plans['candidates']['2']['ok']=False
        self.run_script();self.assertEqual((self.state/'winner').read_text().split()[0],'5')
        self.assertEqual((self.state/'recover_count').read_text().strip(),'0')
        self.assertEqual([x.split()[0] for x in (self.state/'results').read_text().splitlines()],['5'])
        self.assertEqual((self.state/'phase').read_text().strip(),'same');self.assertEqual(self.switches(),[])
        self.run_script();self.assertEqual((self.state/'recover_count').read_text().strip(),'1');self.assertEqual(self.switches(),[])
        self.run_script();self.assertEqual(self.switches(),[5])
        started=[x['started_node'] for x in self.events() if 'started_node' in x]
        self.assertEqual(started.count(1),1);self.assertEqual(started.count(2),2);self.assertEqual(started.count(5),3)
        self.assertNotIn(3,started);self.assertNotIn(4,started)

    def test_exhausted_winner_pools_finish_direct_then_allow_later_recovery(self):
        self.node(5,'Hong Kong 03');self.data['ss_basic_failover_recoveries']='2'
        self.plans['candidates']={'2':{'ok':True,'ms':10},'5':{'ok':True,'ms':80},'3':{'ok':True,'ms':1}}
        self.run_script()
        self.plans['candidates']['2']['ok']=False;self.run_script()
        self.plans['candidates']['5']['ok']=False;self.run_script()
        self.assertEqual((self.state/'phase').read_text().strip(),'other')
        self.assertEqual((self.state/'winner').read_text().split()[0],'3')
        started=[x['started_node'] for x in self.events() if 'started_node' in x]
        self.assertEqual(started.count(1),1);self.assertEqual(started.count(2),2);self.assertEqual(started.count(5),2)
        self.assertLess(max(i for i,x in enumerate(started) if x==5),started.index(3))
        self.plans['candidates']['3']['ok']=False;self.run_script()
        self.assertEqual(self.status()['state'],'direct');self.assertEqual(self.status()['reason'],'all_candidates_failed')
        self.assertEqual(self.data['ss_basic_enable'],'1');self.assertEqual(self.switches(),[])
        self.plans['candidates']['2']['ok']=True;self.run_script();self.assertEqual(self.switches(),[])
        self.run_script();self.assertEqual(self.switches(),[2])

    def test_manual_disable_stops_recovery(self):
        self.run_script();self.data['ss_basic_enable']='0';self.plans['candidates']={'2':{'ok':True}}
        self.run_script();self.assertEqual(self.status()['state'],'disabled');self.assertEqual(self.switches(),[])

    def test_generation_change_discards_inflight_result(self):
        self.plans['active']={'ok':True};self.plans['invalidate']='google'
        result=self.run_script();self.assertEqual(result.returncode,75);self.assertEqual(self.switches(),[])
        self.assertFalse(any(x.get('action')=='direct' for x in self.events()))

    def test_country_mapping_and_explicit_candidates_override_names(self):
        self.data['ss_basic_failover_nodes']='3,2';self.data['ss_basic_failover_countries']='3=HK,2=JP'
        self.plans['candidates']={'3':{'ok':True,'ms':200},'2':{'ok':True,'ms':10}}
        self.run_script();self.assertEqual(self.switches(),[3])

    def test_budget_continues_same_group_before_scanning_other_countries(self):
        self.data.update(ss_basic_failover_timeout='3',ss_basic_failover_budget='20')
        self.plans['active']={'ok':False,'cost':3};self.plans['candidates']={
            '1':{'ok':False,'cost':3},'2':{'ok':False,'cost':3},'3':{'ok':True,'ms':200},'4':{'ok':True,'ms':50}}
        states=[]
        for _ in range(8):
            self.run_script();states.append(self.status()['state'])
            if self.switches():break
        self.assertIn('scanning_direct',states);self.assertEqual(self.switches(),[4])
        order=[x['probe_node'] for x in self.events() if 'probe_node' in x and not x['active']]
        self.assertLess(order.index(2),order.index(3))

    def test_probe_port_collision_never_measures_foreign_proxy(self):
        self.plans['occupied_port']=True;self.run_script(allowed=(1,))
        self.assertEqual(self.status()['reason'],'probe_port_busy');self.assertEqual(self.switches(),[])
        self.assertFalse(any('started_node' in x for x in self.events()))

    def test_controller_lock_is_released_after_switch(self):
        self.plans['candidates']={'2':{'ok':True}};self.run_script();self.assertEqual(self.switches(),[2])
        self.plans['active']={'ok':True};self.run_script();self.assertEqual(self.status()['state'],'healthy')

    def test_reset_while_disabled_stays_disabled(self):
        self.data['ss_basic_enable']='0';self.run_script('reset')
        self.assertEqual(self.status()['state'],'disabled');self.assertEqual(self.switches(),[])

    def test_failed_dns_route_restoration_is_not_reported_as_direct(self):
        self.plans['direct_error']=True;self.run_script()
        self.assertEqual(self.status()['mode'],'error');self.assertEqual(self.status()['state'],'error')

    def test_manual_disable_during_probe_never_switches_or_restores_intent(self):
        self.plans['disable']='google';self.run_script()
        self.assertEqual(self.data['ss_basic_enable'],'0');self.assertEqual(self.switches(),[])
        self.assertFalse(any(x.get('action')=='direct' for x in self.events()))

    def test_success_without_direct_mode_is_not_reported_as_direct(self):
        (self.ks/'ss/ssconfig.sh').write_text('#!/bin/sh\nexit 0\n')
        self.run_script();self.assertEqual(self.status()['state'],'error');self.assertEqual(self.status()['mode'],'proxy')

    def test_kcp_candidates_are_not_probed_or_committed(self):
        self.data['ssconf_basic_use_kcp_2']='1'
        self.plans['candidates']={'2':{'ok':True,'ms':10},'3':{'ok':True,'ms':200}}
        self.run_script();self.assertEqual(self.switches(),[3])
        self.assertFalse(any(x.get('started_node')==2 for x in self.events()))

    def test_invalid_settings_do_not_prevent_manual_reset(self):
        self.run_script('reset');previous=(self.state/'generation').read_text()
        self.data.update(ss_basic_enable='0',ss_basic_failover_country='bad;value')
        self.run_script('reset');self.assertNotEqual((self.state/'generation').read_text(),previous)
        self.assertEqual(self.status()['state'],'disabled')

    def test_switch_failure_after_selection_reports_actual_node(self):
        self.plans.update(switch_error=True,candidates={'2':{'ok':True}})
        self.run_script(allowed=(1,));self.assertEqual(self.status()['state'],'error')
        self.assertEqual(self.status()['current_node'],2);self.assertEqual(self.status()['reason'],'switch_failed')


if __name__=='__main__':unittest.main()
