"""Failover service commits, DNS protection and stale-request cancellation."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(os.environ.get('SS_FAILOVER_SERVICE_SOURCE', Path(__file__).resolve().parents[1] / 'shadowsocks/ss/ssconfig.sh'))

MOCK = r'''
import fcntl,json,os,pathlib,sys,tempfile
r=pathlib.Path(os.environ['FS_TEST_ROOT']);name=pathlib.Path(sys.argv[0]).name;a=sys.argv[1:]
if name=='dbus':
 d=json.loads((r/'dbus.json').read_text())
 if a[0]=='get':print(d.get(a[1],''))
 elif a[0]=='set':
  k,v=a[1].split('=',1)
  if k=='ss_basic_trojan_sni' and v=='new-sni' and (r/'fail-write').exists():sys.exit(1)
  d[k]=v
  if k=='ss_basic_port' and (r/'manual-change-on-write').exists():
   d.update(json.loads((r/'manual-change-on-write').read_text()));(r/'manual-change-on-write').unlink()
  (r/'dbus.json').write_text(json.dumps(d))
 else:sys.exit(2)
elif name=='ss-flock':
 if a[0]=='mktemp':
  template=a[1];fd,p=tempfile.mkstemp(prefix=pathlib.Path(template).name.replace('XXXXXX',''),dir=str(pathlib.Path(template).parent));os.close(fd);print(p)
 else:fcntl.flock(int(a[-1]),fcntl.LOCK_UN if '-u' in a else fcntl.LOCK_EX)
elif name=='iptables':
 if '-S' in a:print('-A PREROUTING -j UU_KEEP')
else:
 with (r/'events').open('a') as f:f.write(name+' '+ ' '.join(a)+'\n')
'''

@unittest.skipUnless(SOURCE.exists(), 'Run from a prepared plugin or set SS_FAILOVER_SERVICE_SOURCE')
class ServiceCommitTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.r=Path(self.tmp.name);self.ks=self.r/'ks';self.state=self.r/'state'
        (self.ks/'bin').mkdir(parents=True);self.state.mkdir();(self.r/'events').touch()
        for name in ['dbus','ss-flock','iptables','nvram','cru','logger']:
            p=self.ks/'bin'/name;p.write_text('#!'+sys.executable+'\n'+MOCK);p.chmod(0o755)
        self.data={'ss_basic_enable':'1','ss_basic_failover_enable':'1','ss_basic_type':'4','ss_basic_trojan_binary':'AnyTLS','ssconf_basic_node':'1'}
        for field,value in {'server':'old-host','port':'443','password':'old-secret','trojan_sni':'old-sni','allowinsecure':'0','use_kcp':'0'}.items():self.data['ss_basic_'+field]=value
        for field,value in {'server':'new-host','port':'8443','password':'new-secret','trojan_sni':'new-sni','allowinsecure':'1','use_kcp':'0','type':'4','trojan_binary':'AnyTLS'}.items():self.data['ssconf_basic_'+field+'_2']=value
        (self.state/'generation').write_text('123.456\n')
        self.source=SOURCE.read_text();self.functions='\n'.join(self.function(name) for name in ['ss_failover_guard','ss_failover_set_mode','ss_failover_select','ss_adblock_stop','ss_failover_enter_direct'])
        self.functions=self.functions.replace('/koolshare',str(self.ks))
        self.env=dict(os.environ,FS_TEST_ROOT=str(self.r),PATH=str(self.ks/'bin')+':'+os.environ['PATH'])
        self.prefix='SS_FAILOVER_STATE='+str(self.state)+'; SS_FAILOVER_EXPECTED=1; SS_FAILOVER_GENERATION=123.456\n'+self.functions+'\n'
        self.prefix+='ss_routing_remove_jumps(){ echo "remove-jump $*" >> "$FS_TEST_ROOT/events"; }; ss_routing_remove_output_rules(){ echo remove-output >> "$FS_TEST_ROOT/events"; }; ss_routing_remove_dns_rules(){ echo remove-dns >> "$FS_TEST_ROOT/events"; }; restore_conf(){ echo restore-dns >> "$FS_TEST_ROOT/events"; }; restart_dnsmasq(){ echo restart-dns >> "$FS_TEST_ROOT/events"; };\n'
    def tearDown(self):self.tmp.cleanup()
    def function(self,name):
        return re.search(r'(?ms)^'+name+r'\(\)\s*\{.*?^\}',self.source).group()
    def run_shell(self,body):
        (self.r/'dbus.json').write_text(json.dumps(self.data))
        result=subprocess.run(['/bin/bash','-c',self.prefix+body],env=self.env,capture_output=True,text=True,timeout=10)
        self.data=json.loads((self.r/'dbus.json').read_text());return result
    def test_selection_synchronizes_active_fields_before_id(self):
        result=self.run_shell('ss_failover_select 2');self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.data['ssconf_basic_node'],'2')
        for field in ['server','port','password','trojan_sni','allowinsecure','use_kcp','type','trojan_binary']:
            self.assertEqual(self.data['ss_basic_'+field],self.data['ssconf_basic_'+field+'_2'])
        self.assertEqual(list(self.state.glob('selection.*')),[])
    def test_stale_generation_node_or_manual_off_cannot_commit(self):
        for body in ['SS_FAILOVER_GENERATION=stale','SS_FAILOVER_EXPECTED=2','SS_FAILOVER_GENERATION="bad;token"']:
            before=dict(self.data);result=self.run_shell(body+'; ss_failover_select 2')
            self.assertEqual(result.returncode,75);self.assertEqual(self.data,before)
        self.data['ss_basic_enable']='0';before=dict(self.data)
        self.assertEqual(self.run_shell('ss_failover_select 2').returncode,75);self.assertEqual(self.data,before)
    def test_partial_settings_write_rolls_back_without_changing_selected_node(self):
        before=dict(self.data);(self.r/'fail-write').touch()
        self.assertEqual(self.run_shell('ss_failover_select 2').returncode,1)
        self.assertEqual(self.data,before);self.assertFalse(list(self.state.glob('selection.*')))
    def test_direct_protection_restores_dns_and_detaches_only_owned_hooks(self):
        result=self.run_shell('ss_failover_enter_direct');self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((self.state/'mode').read_text().strip(),'direct')
        events=(self.r/'events').read_text().splitlines()
        self.assertEqual([x for x in events if x.startswith(('remove-','restore-'))],['remove-jump nat PREROUTING SHADOWSOCKS','remove-jump mangle PREROUTING SHADOWSOCKS','remove-output','remove-dns','restore-dns'])
        self.assertIn('restart-dns',events);self.assertFalse(any('UU_KEEP' in s or 'kill' in s or 'flush' in s for s in events))
    def test_dns_restore_or_restart_failure_never_claims_direct(self):
        for function in ['restore_conf','restart_dnsmasq','ss_adblock_stop']:
            result=self.run_shell(function+'(){ return 1; }; ss_failover_enter_direct')
            self.assertEqual(result.returncode,1);self.assertEqual((self.state/'mode').read_text().strip(),'error')
    def test_remaining_proxy_hook_never_claims_direct(self):
        result=self.run_shell('iptables(){ echo "-A PREROUTING -j SHADOWSOCKS"; }; ss_failover_enter_direct')
        self.assertEqual(result.returncode,1);self.assertEqual((self.state/'mode').read_text().strip(),'error')

    def test_residual_owned_output_redirect_blocks_direct_without_matching_other_ports(self):
        for port,expected in [(3333,1),(3334,0)]:
            with self.subTest(port=port):
                body='iptables(){ case "$*" in *"-S OUTPUT"*) echo "-A OUTPUT -p tcp -m set --match-set router dst -j REDIRECT --to-ports '+str(port)+'" ;; *) echo "-A PREROUTING -j UU_KEEP" ;; esac; }; ss_failover_enter_direct'
                result=self.run_shell(body);self.assertEqual(result.returncode,expected,result.stderr)
                self.assertEqual((self.state/'mode').read_text().strip(),'error' if expected else 'direct')

    def test_manual_node_change_mid_selection_cancels_without_overwriting_manual_fields(self):
        manual={'ssconf_basic_node':'3','ss_basic_server':'manual-host','ss_basic_port':'2443',
                'ss_basic_password':'manual-secret','ss_basic_trojan_sni':'manual-sni','ss_basic_allowinsecure':'0',
                'ss_basic_use_kcp':'0','ss_basic_type':'4','ss_basic_trojan_binary':'AnyTLS'}
        expected=dict(self.data);expected.update(manual)
        (self.r/'manual-change-on-write').write_text(json.dumps(manual))
        result=self.run_shell('ss_failover_select 2');self.assertEqual(result.returncode,75,result.stderr)
        self.assertEqual(self.data,expected);self.assertFalse(list(self.state.glob('selection.*')))

    def run_action(self,action,anytls=True):
        # Execute the real dispatch, stubbing only operations that would mutate
        # router services. Keep the shell snapshot enabled to catch stale reads.
        dispatch='case $ACTION in\n'+self.source.rsplit('\ncase $ACTION in\n',1)[1]
        functions='\n'.join(name+'(){ echo '+name+' >> "$FS_TEST_ROOT/events"; };' for name in
                           ['set_lock','unset_lock','ss_failover_manual_reset','set_ulimit','apply_ss','write_numbers',
                            'disable_ss','ss_failover_enter_direct','ss_failover_watchdog','logger','echo_date'])
        body='ACTION='+action+'; ss_basic_enable=1; ss_basic_failover_enable=1; LOG_FILE="$FS_TEST_ROOT/action.log"\n'
        body+=functions+'\nss_routing_is_anytls(){ return '+('0' if anytls else '1')+'; };\n'+dispatch
        return self.run_shell(body)

    def test_restart_after_manual_disable_does_not_apply_stale_enabled_snapshot(self):
        self.data['ss_basic_enable']='0'
        result=self.run_action('restart');self.assertEqual(result.returncode,0,result.stderr)
        events=(self.r/'events').read_text().splitlines()
        self.assertIn('disable_ss',events);self.assertNotIn('apply_ss',events);self.assertNotIn('write_numbers',events)

    def test_start_and_default_apply_non_anytls_after_direct_fallback(self):
        self.data.update(ss_basic_type='0',ss_basic_trojan_binary='Trojan')
        for action in ['start','reload']:
            with self.subTest(action=action):
                (self.r/'events').write_text('');(self.state/'mode').write_text('direct\n')
                result=self.run_action(action,anytls=False);self.assertEqual(result.returncode,0,result.stderr)
                events=(self.r/'events').read_text().splitlines()
                self.assertIn('apply_ss',events);self.assertIn('write_numbers',events)
                self.assertNotIn('ss_failover_enter_direct',events)

    def test_post_start_and_pre_stop_hooks_preserve_exit_unlock_trap(self):
        hooks=self.ks/'ss/postscripts';hooks.mkdir(parents=True)
        hook=hooks/'P10-test';hook.write_text('#!/bin/sh\necho "hook-$1" >> "$FS_TEST_ROOT/events"\n');hook.chmod(0o755)
        for name,argument in [('ss_post_start','start'),('ss_pre_stop','stop')]:
            with self.subTest(hook=name):
                (self.r/'events').write_text('')
                actual='\n'.join(self.function(n) for n in ['set_lock','unset_lock',name]).replace('/koolshare',str(self.ks))
                body=actual+'\nLOCK_FILE="$FS_TEST_ROOT/service.lock"; SS_SERVICE_LOCKED=0\n'
                body+='echo_date(){ :; }; set_lock; trap \'unset_lock; echo exit-unlocked >> "$FS_TEST_ROOT/events"\' EXIT\n'+name
                result=self.run_shell(body);self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual((self.r/'events').read_text().splitlines(),['hook-'+argument,'exit-unlocked'])

    def test_ad_filter_apply_failure_leaves_core_and_uu_alone(self):
        scripts=self.ks/'scripts';scripts.mkdir()
        script=scripts/'ss_adblock.sh'
        script.write_text('#!/bin/sh\necho "ad-only $1" >> "$FS_TEST_ROOT/events"\nexit 1\n');script.chmod(0o755)
        self.data['ss_basic_adblock_enable']='1';(self.state/'mode').write_text('proxy\n')
        actual=self.function('ss_adblock_apply').replace('/koolshare',str(self.ks)).replace('/tmp/ss_failover',str(self.state))
        result=self.run_shell(actual+'\nss_adblock_apply')
        self.assertEqual(result.returncode,0,result.stderr)
        events=(self.r/'events').read_text()
        self.assertIn('ad-only apply',events);self.assertIn('cru a ss_adblock ',events)
        self.assertNotIn('kill',events);self.assertNotIn('restart',events)

    def test_ad_filter_child_closes_service_lock_but_parent_keeps_it(self):
        scripts=self.ks/'scripts';scripts.mkdir()
        script=scripts/'ss_adblock.sh'
        script.write_text('#!/bin/sh\nif ( : >&7 ) 2>/dev/null; then exit 9; fi\necho child-unlocked >> "$FS_TEST_ROOT/events"\n');script.chmod(0o755)
        actual=self.function('ss_adblock_apply').replace('/koolshare',str(self.ks)).replace('/tmp/ss_failover',str(self.state))
        result=self.run_shell(actual+'\nexec 7>"$FS_TEST_ROOT/parent.lock"; ss_adblock_apply; echo parent-locked >&7')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((self.r/'parent.lock').read_text(),'parent-locked\n')
        self.assertIn('child-unlocked',(self.r/'events').read_text())

    def test_direct_protection_detaches_ad_filter_before_dns_restore(self):
        result=self.run_shell('ss_failover_enter_direct');self.assertEqual(result.returncode,0,result.stderr)
        events=(self.r/'events').read_text().splitlines()
        self.assertLess(events.index('cru d ss_adblock'),events.index('restore-dns'))

    def test_invalid_optional_ads_cannot_block_stop_or_direct_protection(self):
        validation=next(m.group() for m in re.finditer(r'case "\$SS_FAILOVER_ACTION" in stop\|failover-direct\).*?\nesac',self.source,re.S) if 'ss_adblock.sh validate' in m.group())
        for action,expected in [('stop',0),('failover-direct',0),('start',1)]:
            with self.subTest(action=action):
                result=self.run_shell('SS_FAILOVER_ACTION='+action+'\nsh(){ return 1; };\n'+validation)
                self.assertEqual(result.returncode,expected,result.stderr)

if __name__=='__main__':unittest.main(verbosity=2)
