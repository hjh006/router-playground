package cn.simon.routercontrol;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Pure synthetic schema tests; no router, credentials, Android SDK or network needed. */
public final class PluginSettingsTest {
    private static int assertions;
    private static void check(boolean condition,String message){assertions++;if(!condition)throw new AssertionError(message);}
    private static Map<String,String> one(String key,String value){return Collections.singletonMap(key,value);}
    private static Map<String,String> defaults(){
        Map<String,String> config=new LinkedHashMap<>();
        for(String group:new String[]{"routing","devices","failover","adblock","health","anytls","dns"})
            for(PluginSettings.Field field:PluginSettings.fields(group,Collections.emptyMap()))
                config.put(field.key,field.encoded?Base64.getEncoder().encodeToString(field.defaultValue.getBytes(StandardCharsets.UTF_8)):field.defaultValue);
        config.put("ss_basic_type","4");config.put("ss_basic_trojan_binary","AnyTLS");
        config.put("ss_acl_ip_1","192.0.2.9");config.put("ss_acl_mode_1","1");config.put("ss_acl_port_1","80,443");
        config.put("ss_acl_default_mode","1");config.put("ss_acl_default_port","all");
        return config;
    }
    private static void fails(String group,Map<String,String> changes,Map<String,String> config)throws Exception{
        try{PluginSettings.normalize(group,changes,config);throw new AssertionError("Invalid settings were accepted");}
        catch(IOException expected){assertions++;}
    }
    private static String normalized(String group,String key,String value,Map<String,String> config)throws Exception{
        Map<String,String> out=PluginSettings.normalize(group,one(key,value),config);check(out.size()==1,"only changed field is emitted");return out.get(key);
    }
    public static void main(String[] ignored)throws Exception{
        Map<String,String> config=defaults();
        for(String group:new String[]{"routing","devices","failover","adblock","health","anytls","acl","dns"}){
            check(PluginSettings.supported(group,config),"group supported by capabilities");
            check(!PluginSettings.title(group).isEmpty()&&!PluginSettings.description(group).isEmpty(),"help supplied");
        }
        check(!PluginSettings.supported("unknown",config),"unknown group unsupported");
        check(PluginSettings.normalize("anytls",Collections.emptyMap(),config).isEmpty(),"empty patch writes nothing");
        Map<String,String> before=new LinkedHashMap<>(config);
        check("2".equals(normalized("routing","ss_basic_mode","2",config)),"route enum");
        check(before.equals(config),"normalization does not mutate current state");
        fails("routing",one("ss_basic_mode","0"),config);
        fails("routing",one("ss_basic_password","secret"),config);
        check("02:00:00:00:00:01".equals(normalized("devices","ss_basic_bypass_macs","02-00-00-00-00-01\n02:00:00:00:00:01",config)),"MAC case/separator normalization");
        fails("devices",one("ss_basic_bypass_macs","01:00:00:00:00:01"),config);
        fails("devices",one("ss_basic_bypass_macs","00:00:00:00:00:00"),config);
        Map<String,String> overlap=new LinkedHashMap<>();overlap.put("ss_basic_bypass_macs","02:00:00:00:00:01");overlap.put("ss_basic_uu_macs","02:00:00:00:00:01");fails("devices",overlap,config);
        fails("devices",one("ss_basic_uu_interval","1"),config);
        fails("devices",one("ss_basic_uu_tcp_policy","global"),config);
        check("direct".equals(normalized("devices","ss_basic_uu_tcp_policy","direct",config)),"UU direct is an explicit separate policy");
        check("1,2".equals(normalized("failover","ss_basic_failover_nodes","001\n2,1",config)),"candidate normalization");
        check("1=HK,2=JP".equals(normalized("failover","ss_basic_failover_countries","001=hk\n2=JP",config)),"country mapping normalization");
        fails("failover",one("ss_basic_failover_countries","1=HK,1=JP"),config);
        fails("failover",one("ss_basic_failover_nodes","0"),config);
        Map<String,String> smallBudget=new LinkedHashMap<>(config);smallBudget.put("ss_basic_failover_budget","20");fails("failover",one("ss_basic_failover_timeout","8"),smallBudget);
        check("30".equals(normalized("failover","ss_basic_failover_cooldown","030",config)),"bounded integer normalization");
        String encoded=normalized("adblock","ss_basic_adblock_domains"," ADS.EXAMPLE \nads.example",config);
        check("ads.example".equals(new String(Base64.getDecoder().decode(encoded),StandardCharsets.US_ASCII)),"adblock encoded exactly once");
        Map<String,String> loaded=new LinkedHashMap<>(config);loaded.put("ss_basic_adblock_domains",encoded);
        for(PluginSettings.Field field:PluginSettings.fields("adblock",loaded))if(field.key.endsWith("_domains"))check("ads.example".equals(PluginSettings.value(field,loaded)),"adblock display decoded");
        for(String bad:new String[]{"youtube.com","com","sub.googlevideo.com","*.ads.example","https://ads.example/","192.0.2.1","ads.example.","广告.example","ads.example\u0000"})fails("adblock",one("ss_basic_adblock_domains",bad),config);
        check(!normalized("adblock","ss_basic_adblock_allow","youtube.com",config).isEmpty(),"allow list accepts protected domains");
        Map<String,String> malformed=new LinkedHashMap<>(config);malformed.put("ss_basic_adblock_domains","YQ");fails("adblock",one("ss_basic_adblock_enable","1"),malformed);
        check("120".equals(normalized("health","ss_basic_health_interval","120",config)),"health enum");fails("health",one("ss_basic_health_interval","31"),config);
        check("auto".equals(normalized("anytls","ss_basic_anytls_alpn","",config)),"empty ALPN is auto");
        check("h2,http/1.1".equals(normalized("anytls","ss_basic_anytls_alpn","h2,http/1.1,h2",config)),"ALPN dedup");
        check("a.example=b.example,b.example=192.0.2.1".equals(normalized("anytls","ss_basic_anytls_hosts","A.EXAMPLE.=b.example\nb.example=192.0.2.1",config)),"Hosts canonicalization");
        fails("anytls",one("ss_basic_anytls_hosts","a.example=b.example,b.example=a.example"),config);
        fails("anytls",one("ss_basic_anytls_hosts","a.example=b.example,b.example=c.example,c.example=d.example,d.example=e.example,e.example=f.example"),config);
        fails("anytls",one("ss_basic_anytls_hosts","a.example=192.00.2.1"),config);
        check("80,443:444".equals(normalized("acl","ss_acl_port_1","080,443:444",config)),"existing ACL port normalization");
        Map<String,String> mixedDefaults=new LinkedHashMap<>(config);mixedDefaults.put("ss_basic_mode","2");mixedDefaults.put("ss_acl_default_mode","5");
        for(PluginSettings.Field field:PluginSettings.fields("acl",mixedDefaults))if("ss_acl_default_mode".equals(field.key))check(java.util.Arrays.asList(field.values).contains("5"),"preserve existing valid default outside new global mode");
        Map<String,String> rowOnly=PluginSettings.normalize("acl",one("ss_acl_port_1","443"),mixedDefaults);
        check(rowOnly.equals(one("ss_acl_port_1","443")),"unrelated ACL edit leaves old default untouched");
        check("5".equals(mixedDefaults.get("ss_acl_default_mode")),"default map is not mutated");
        Map<String,String> emptyDefaults=new LinkedHashMap<>(mixedDefaults);emptyDefaults.put("ss_acl_default_mode","");emptyDefaults.put("ss_acl_default_port","");
        for(PluginSettings.Field field:PluginSettings.fields("acl",emptyDefaults)) {
            if("ss_acl_default_mode".equals(field.key))check("2".equals(PluginSettings.value(field,emptyDefaults)),"empty default mode displays global mode");
            if("ss_acl_default_port".equals(field.key))check("all".equals(PluginSettings.value(field,emptyDefaults)),"empty default port displays unrestricted ports");
        }
        check(PluginSettings.normalize("acl",one("ss_acl_port_1","443"),emptyDefaults).equals(one("ss_acl_port_1","443")),"empty defaults do not block unrelated ACL edits");
        check("".equals(emptyDefaults.get("ss_acl_default_mode"))&&"".equals(emptyDefaults.get("ss_acl_default_port")),"fallback never writes implicit default values");
        fails("acl",one("ss_acl_default_port","80,443"),emptyDefaults);
        Map<String,String> explicitDefault=new LinkedHashMap<>();explicitDefault.put("ss_acl_default_mode","2");explicitDefault.put("ss_acl_default_port","80,443");
        check(PluginSettings.normalize("acl",explicitDefault,emptyDefaults).equals(explicitDefault),"restricted ports and initially unset mode submitted explicitly together");
        fails("acl",one("ss_acl_ip_1","192.0.2.8"),config);fails("acl",one("ss_acl_mode_2","0"),config);
        fails("acl",one("ss_acl_mode_1","0"),config);
        Map<String,String> direct=new LinkedHashMap<>();direct.put("ss_acl_mode_1","0");direct.put("ss_acl_port_1","all");check(PluginSettings.normalize("acl",direct,config).size()==2,"explicit direct+all patch");
        fails("acl",one("ss_acl_port_1","443; touch /tmp/not-run"),config);fails("acl",one("ss_acl_port_1","65536"),config);
        check("192.0.2.1:53,https://dns.example:853/custom?q=a+b&key=sample".equals(normalized("dns","ss_basic_server_resolver_user","192.0.2.1,https://DNS.Example:00853/custom?q=a+b&key=sample",config)),"complete resolver URLs and ports preserved");
        fails("dns",one("ss_basic_server_resolver","12"),config);
        Map<String,String> custom=new LinkedHashMap<>();custom.put("ss_basic_server_resolver","12");custom.put("ss_basic_server_resolver_user","https://dns.example/dns-query");check(PluginSettings.normalize("dns",custom,config).size()==2,"custom DNS explicit pair");
        for(String bad:new String[]{"192.0.2.1, 192.0.2.2","https://dns.example","HTTPS://dns.example/query","https://dns.example./query","https://user@dns.example/query","https://dns.example/q#fragment","https://dns.example/q?bad=%GG","http://dns.example/query","192.0.2.1:000053","[::1]:53","192.0.2.1,192.0.2.2,192.0.2.3,192.0.2.4,192.0.2.5"})fails("dns",one("ss_basic_server_resolver_user",bad),config);
        Map<String,String> noAcl=new LinkedHashMap<>(config);noAcl.remove("ss_acl_mode_1");check(!PluginSettings.supported("acl",noAcl),"no new ACL creation");
        Map<String,String> omittedEmpty=new LinkedHashMap<>(config);
        for(String key:new String[]{"ss_basic_adblock_domains","ss_basic_adblock_allow","ss_basic_failover_nodes","ss_basic_failover_countries","ss_basic_server_resolver_user","ss_basic_bypass_macs","ss_basic_uu_macs","ss_basic_anytls_hosts"})omittedEmpty.remove(key);
        for(String group:new String[]{"routing","devices","failover","adblock","health","anytls","acl","dns"})check(PluginSettings.supported(group,omittedEmpty),"omitted empty DBus defaults preserve group capability");
        check(PluginSettings.normalize("adblock",one("ss_basic_adblock_enable","1"),omittedEmpty).equals(one("ss_basic_adblock_enable","1")),"r5 adblock marker supports omitted empty lists without implicit list writes");
        check(PluginSettings.normalize("devices",one("ss_basic_uu_interval","10"),omittedEmpty).equals(one("ss_basic_uu_interval","10")),"omitted empty device profiles remain empty and are not written");
        check(PluginSettings.normalize("failover",one("ss_basic_failover_country","HK"),omittedEmpty).equals(one("ss_basic_failover_country","HK")),"omitted candidates and mapping remain default");
        check(PluginSettings.normalize("dns",one("ss_basic_server_resolver","2"),omittedEmpty).equals(one("ss_basic_server_resolver","2")),"unused empty custom resolver need not be exported");
        fails("dns",one("ss_basic_server_resolver","12"),omittedEmpty);
        check(PluginSettings.normalize("anytls",one("ss_basic_anytls_min_idle","1"),omittedEmpty).equals(one("ss_basic_anytls_min_idle","1")),"omitted empty Hosts are not written");
        Map<String,String> oldR4=new LinkedHashMap<>(omittedEmpty);oldR4.remove("ss_basic_adblock_enable");check(!PluginSettings.supported("adblock",oldR4),"r5 adblock requires its explicit feature marker");fails("adblock",one("ss_basic_adblock_enable","1"),oldR4);
        Map<String,String> oldR3=new LinkedHashMap<>(omittedEmpty);oldR3.remove("ss_basic_failover_enable");check(!PluginSettings.supported("failover",oldR3),"failover requires its own explicit capability marker");
        oldR3.remove("ss_basic_uu_tcp_policy");check(!PluginSettings.supported("devices",oldR3),"UU policy support cannot be inferred from empty device lists");
        Map<String,String> legacy=new LinkedHashMap<>(config);legacy.remove("ss_basic_anytls_handshake");check(!PluginSettings.supported("routing",legacy),"unrecognized enhancement rejected");
        Map<String,String> otherProtocol=new LinkedHashMap<>(config);otherProtocol.put("ss_basic_trojan_binary","Trojan");check(!PluginSettings.supported("anytls",otherProtocol),"protocol migration excluded");
        check("0".equals(normalized("routing","ss_basic_enable","0",otherProtocol)),"enhanced safe-stop remains available");fails("routing",one("ss_basic_mode","2"),otherProtocol);
        otherProtocol.put("ss_basic_mode","invalid-legacy-mode");
        check(PluginSettings.normalize("routing",one("ss_basic_enable","0"),otherProtocol).equals(one("ss_basic_enable","0")),"safe-stop bypasses unrelated invalid mode and never enables proxy");
        System.out.println("PluginSettings: "+assertions+" assertions passed (pure synthetic data; no network).");
    }
}
