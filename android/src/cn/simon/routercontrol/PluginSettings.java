package cn.simon.routercontrol;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Native settings schema for the maintained r5 plugin; no network or Android dependencies. */
public final class PluginSettings {
    public static final class Field {
        public final String key, label, help, defaultValue;
        public final String[] values, labels;
        public final boolean multiline, encoded;
        private Field(String key, String label, String help, String fallback, String[] values,
                      String[] labels, boolean multiline, boolean encoded) {
            this.key=key; this.label=label; this.help=help; this.defaultValue=fallback;
            this.values=values; this.labels=labels; this.multiline=multiline; this.encoded=encoded;
        }
    }
    private static final String[] MODES={"0","1","2","3","5","6"};
    private static final String[] MODE_LABELS={"直连","gfwlist 分流","大陆白名单分流","游戏模式","全局代理","回国模式"};
    private static final String RESTART="保存后使用插件原有应用流程，代理和 DNS 可能短暂重启。";
    private static final String[] PROTECTED=("youtube.com youtube-nocookie.com youtu.be googlevideo.com ytimg.com ggpht.com googleapis.com gvt1.com gvt2.com gstatic.com google.com doubleclick.net googlesyndication.com googleadservices.com googletagservices.com google-analytics.com googletagmanager.com playstation.com playstation.net sonyentertainmentnetwork.com sony.com sony.net 163.com 126.net netease.com uux.cn localhost local localdomain lan home home.arpa router.asus.com asusrouter.com routerlogin.net routerlogin.com").split(" ");

    private static Field text(String key,String label,String help,String fallback,boolean multiline,boolean encoded) {
        return new Field(key,label,help,fallback,null,null,multiline,encoded);
    }
    private static Field choice(String key,String label,String help,String fallback,String[] values,String[] labels) {
        return new Field(key,label,help,fallback,values,labels,false,false);
    }
    private static Field toggle(String key,String label,String help,String fallback) {
        return choice(key,label,help,fallback,new String[]{"0","1"},new String[]{"关闭","开启"});
    }
    private static Field number(String key,String label,String range,String fallback) {
        return text(key,label,range,fallback,false,false);
    }
    private static boolean known(String group) {
        return Arrays.asList("routing","devices","failover","adblock","health","anytls","acl","dns").contains(group);
    }
    public static String title(String group) {
        switch(group) {
            case "routing": return "路由与代理";
            case "devices": return "设备旁路与 UU";
            case "failover": return "自动故障切换";
            case "adblock": return "域名广告过滤";
            case "health": return "HTTPS 健康检测";
            case "anytls": return "AnyTLS 连接与 Hosts";
            case "acl": return "设备 IP 访问控制";
            case "dns": return "节点独立 DNS";
            default: return "插件设置";
        }
    }
    public static String description(String group) {
        switch(group) {
            case "routing": return "代理关闭表示跳过本插件；分流模式与自动故障切换是独立功能。已有 IP 规则和 MAC 策略优先，默认主机策略在访问控制中设置。"+RESTART;
            case "devices": return "旁路设备保留原有 TCP 和 DNS；UU 动态游戏目标优先，其他 TCP 可分流或直连。两组设备不能重复，不会关闭手机或电脑 VPN。"+RESTART;
            case "failover": return "同地区优先，再比较其他地区可用线路。故障直连保护只保障原本可直连的网络，并非立即直连按钮；手动关闭代理后不会自动复活。"+RESTART;
            case "adblock": return "仅保存这三个广告设置并热加载，不重启 AnyTLS 或 UU。只处理普通 IPv4 DNS，旁路与 UU 设备排除；不能过滤 YouTube 视频内广告。关闭时旧 DNS 连接可等待自然排空。";
            case "health": return "统计来自路由器三站 HTTPS，不是手机 TCP 延迟或长期保证。"+RESTART;
            case "anytls": return "Hosts 只改变 AnyTLS 入口连接目标，保留节点 SNI；不修改设备 VPN、全局 DNS 或 IPv6。"+RESTART;
            case "acl": return "仅编辑已有 IP 规则的策略与端口；无规则时全部主机跟随全局模式。新增、删除及 IP 修改请打开完整插件页。MAC 旁路和 UU 策略优先。"+RESTART;
            case "dns": return "只用于节点启动时独立解析，保留原 SNI。支持 IPv4:端口、HTTPS DNS 和最多 4 个逗号分隔上游；不是手机 DNS 或 Clash DNS 覆写。其它 DNS 功能请用完整插件页。"+RESTART;
            default: return "此设置组不可用。";
        }
    }

    public static List<Field> fields(String group,Map<String,String> config) {
        Map<String,String> current=config==null?Collections.emptyMap():config;
        List<Field> out=new ArrayList<>();
        switch(group) {
            case "routing":
                out.add(toggle("ss_basic_enable","路由器代理","关闭时保留 UU 和设备自身 VPN。","0"));
                out.add(choice("ss_basic_mode","全局分流模式","大陆白名单按境外 IPv4 TCP 分流；AnyTLS 的游戏模式仍不代理 UDP。","1",new String[]{"1","2","3","5","6"},Arrays.copyOfRange(MODE_LABELS,1,6))); break;
            case "devices":
                out.add(text("ss_basic_bypass_macs","自带 VPN 设备旁路","每行或逗号一个 MAC，最多 32 个；保留设备自身 VPN。","",true,false));
                out.add(text("ss_basic_uu_macs","UU 共存设备","最多 32 个，不能与旁路列表重复。","",true,false));
                out.add(choice("ss_basic_uu_tcp_policy","UU 设备的其他 TCP","动态游戏目标和 UDP 仍优先保留 UU。","gfwlist",new String[]{"gfwlist","foreign","direct"},new String[]{"gfwlist 分流（依赖路由器 DNS）","境外 IPv4 TCP 代理","直连（跳过本插件）"}));
                out.add(number("ss_basic_uu_interval","UU 动态规则检查间隔","2–30 秒，较短间隔增加路由器开销。","5")); break;
            case "failover":
                out.add(toggle("ss_basic_failover_enable","自动故障切换","后台每分钟检查，不需要 App 常驻。","0"));
                out.add(text("ss_basic_failover_country","优先国家/地区","auto 跟随当前线路，或两位代码，例如 HK、JP。","auto",false,false));
                out.add(text("ss_basic_failover_nodes","候选节点 ID","留空为全部有效 AnyTLS；最多 128 个，逗号或换行分隔。","",true,false));
                out.add(text("ss_basic_failover_countries","节点地区映射","节点ID=两位代码，每行一条，最多 128 条。","",true,false));
                out.add(number("ss_basic_failover_failures","连续失败次数","1–5 轮。","3"));
                out.add(number("ss_basic_failover_recoveries","候选连续成功次数","1–3 次。","2"));
                out.add(number("ss_basic_failover_cooldown","切换冷却时间","30–600 秒。","120"));
                out.add(number("ss_basic_failover_timeout","候选检测超时","3–8 秒。","5"));
                out.add(number("ss_basic_failover_budget","每轮检测预算","20–120 秒，至少 3 × 检测超时 + 8。","60"));
                out.add(toggle("ss_basic_failover_direct","故障直连保护","故障后撤回本插件转发，继续寻找可用线路。","1")); break;
            case "adblock":
                out.add(toggle("ss_basic_adblock_enable","域名广告过滤","无自动更新；关键播放、联机和本地域名受保护。","0"));
                out.add(text("ss_basic_adblock_domains","额外屏蔽域名","每行完整 ASCII 域名，最多 256 行、8192 字节；包含子域名。","",true,true));
                out.add(text("ss_basic_adblock_allow","放行域名","同样最多 256 行、8192 字节，优先于屏蔽。","",true,true)); break;
            case "health":
                out.add(choice("ss_basic_health_interval","检测间隔","两次采样之间的最小间隔。","30",new String[]{"30","60","120"},new String[]{"30 秒","60 秒","120 秒"}));
                out.add(choice("ss_basic_health_timeout","单目标超时","Google、YouTube、Telegram 请求的超时。","10",new String[]{"6","8","10"},new String[]{"6 秒","8 秒","10 秒"}));
                out.add(number("ss_basic_health_failures","连续失败判定次数","所有目标连续失败 1–5 次后判定连接失败。","3")); break;
            case "anytls":
                out.add(number("ss_basic_anytls_min_idle","最少空闲连接","0–20 个，0 减少常驻连接。","0"));
                out.add(number("ss_basic_anytls_idle_check","空闲检查间隔","5–300 秒。","30"));
                out.add(number("ss_basic_anytls_idle_timeout","空闲回收时间","5–600 秒。","30"));
                out.add(number("ss_basic_anytls_handshake","握手超时","3–20 秒。","8"));
                out.add(text("ss_basic_anytls_alpn","ALPN","h2、http/1.1，可逗号分隔；留空自动协商。","h2",false,false));
                out.add(choice("ss_basic_anytls_fingerprint","TLS 指纹","沿用节点自身的证书验证选项。","chrome",new String[]{"chrome","standard"},new String[]{"Chrome","标准 TLS"}));
                out.add(text("ss_basic_anytls_hosts","服务商 Hosts 映射","原域名=目标域名或 IPv4；最多 32 条、4 跳，不改变 SNI。","",true,false)); break;
            case "acl":
                List<String> ids=aclIds(current);
                if (!ids.isEmpty()) {
                    String mode=current.getOrDefault("ss_basic_mode","1");
                    Set<String> defaults=new LinkedHashSet<>(Arrays.asList("0",mode));
                    String existing=current.get("ss_acl_default_mode");
                    if(Arrays.asList(MODES).contains(existing)) defaults.add(existing);
                    List<String> defaultLabels=new ArrayList<>();for(String item:defaults)defaultLabels.add(modeLabel(item));
                    out.add(choice("ss_acl_default_mode","其他主机默认策略","已有规则可保留原模式；修改全局模式不会重写这里。",mode,defaults.toArray(new String[0]),defaultLabels.toArray(new String[0])));
                    out.add(text("ss_acl_default_port","其他主机默认端口","all 或逗号分隔端口；游戏模式必须 all。","all",false,false));
                }
                for(String id:ids) {
                    String label=current.get("ss_acl_ip_"+id);
                    out.add(choice("ss_acl_mode_"+id,label+" · 策略","规则按 IP 生效；DHCP 地址变化需在完整插件页调整。","0",MODES.clone(),MODE_LABELS.clone()));
                    out.add(text("ss_acl_port_"+id,label+" · 端口","all 或最多 15 个端口项（范围用冒号）；直连/游戏须 all。","all",false,false));
                } break;
            case "dns":
                out.add(choice("ss_basic_server_resolver","节点解析器","自定义时完整保留服务商 DNS URL、路径和查询参数。","1",new String[]{"1","2","3","4","5","6","7","8","9","10","11","12"},new String[]{"运营商自动获取","阿里 DNS 1","阿里 DNS 2","114 DNS 1","114 DNS 2","CNNIC DNS 1","CNNIC DNS 2","OneDNS 1","OneDNS 2","百度 DNS","DNSPod DNS","自定义"}));
                out.add(text("ss_basic_server_resolver_user","自定义节点 DNS","IPv4[:端口] 或 https://域名/路径；逗号分隔最多 4 个，不填手机客户端本地监听地址。","",false,false)); break;
            default: break;
        }
        return Collections.unmodifiableList(out);
    }

    private static String modeLabel(String mode) {
        for(int i=0;i<MODES.length;i++) if(MODES[i].equals(mode)) return MODE_LABELS[i];
        return "当前全局模式";
    }
    private static List<String> aclIds(Map<String,String> config) {
        Set<Integer> ids=new TreeSet<>();
        for(String key:config.keySet()) if(key.matches("ss_acl_mode_[1-9][0-9]{0,5}")) {
            String id=key.substring("ss_acl_mode_".length());
            if(config.containsKey("ss_acl_ip_"+id)&&config.containsKey("ss_acl_port_"+id)) ids.add(Integer.parseInt(id));
        }
        List<String> result=new ArrayList<>(); for(Integer id:ids) result.add(String.valueOf(id)); return result;
    }
    public static boolean supported(String group,Map<String,String> config) {
        if(!known(group)||config==null) return false;
        // dbconf omits keys whose DBus value is empty. Capability recognition
        // therefore uses nonempty enhanced defaults, never a device list/Hosts.
        for(String marker:new String[]{"ss_basic_anytls_min_idle","ss_basic_anytls_handshake","ss_basic_anytls_fingerprint","ss_basic_health_interval"})
            if(config.get(marker)==null||config.get(marker).isEmpty()) return false;
        if(!"routing".equals(group)&&(!"4".equals(config.get("ss_basic_type"))||!"AnyTLS".equals(config.get("ss_basic_trojan_binary")))) return false;
        List<Field> fields=fields(group,config);
        if(fields.isEmpty()) return false;
        for(Field field:fields) {
            if("acl".equals(group)&&field.key.startsWith("ss_acl_default_")) continue;
            if(field.defaultValue.isEmpty()) continue;
            if(!config.containsKey(field.key)) return false;
        }
        return true;
    }
    public static String value(Field field,Map<String,String> config) {
        String raw=config==null?field.defaultValue:config.getOrDefault(field.key,field.defaultValue);
        if(raw==null) raw=field.defaultValue;
        // Legacy empty port means no multiport restriction; an unset default mode
        // follows the global mode when its default port is all. Display that meaning
        // without adding either key to an unrelated patch.
        if((field.key.startsWith("ss_acl_default_")||field.key.matches("ss_acl_port_[1-9][0-9]{0,5}"))&&raw.trim().isEmpty()) raw=field.defaultValue;
        if(field.encoded) {
            try { raw=new String(Base64.getDecoder().decode(raw),StandardCharsets.UTF_8); }
            catch(IllegalArgumentException ignored) { /* Display invalid stored text instead of silently erasing it. */ }
        }
        if("ss_basic_anytls_alpn".equals(field.key)&&"auto".equals(raw)) return "";
        if(field.multiline&&Arrays.asList("ss_basic_bypass_macs","ss_basic_uu_macs","ss_basic_anytls_hosts","ss_basic_failover_nodes","ss_basic_failover_countries").contains(field.key)) return raw.replace(",","\n");
        return raw;
    }

    public static Map<String,String> normalize(String group,Map<String,String> changes,Map<String,String> current) throws IOException {
        if(!supported(group,current)) throw new IOException("当前插件版本或配置不支持此设置；请使用完整插件页。");
        if(changes==null) throw new IOException("没有有效的设置改动。");
        Map<String,Field> schema=new LinkedHashMap<>();
        Map<String,String> merged=new LinkedHashMap<>();
        for(Field field:fields(group,current)) {
            schema.put(field.key,field);
            if(field.encoded&&!changes.containsKey(field.key)) merged.put(field.key,decodeStored(current.getOrDefault(field.key,"")));
            else merged.put(field.key,value(field,current));
        }
        for(Map.Entry<String,String> entry:changes.entrySet()) {
            if(!schema.containsKey(entry.getKey())||entry.getValue()==null) throw new IOException("设置中包含不属于本分组的字段。");
            merged.put(entry.getKey(),entry.getValue());
        }
        if("routing".equals(group)&&changes.size()==1&&"0".equals(changes.get("ss_basic_enable"))) return Collections.singletonMap("ss_basic_enable","0");
        if(!"4".equals(current.get("ss_basic_type"))||!"AnyTLS".equals(current.get("ss_basic_trojan_binary"))) throw new IOException("当前并非 AnyTLS；请先在完整插件页完成协议配置。");
        Map<String,String> normalized=new LinkedHashMap<>();
        for(Field field:schema.values()) {
            if("ss_basic_server_resolver_user".equals(field.key)&&!changes.containsKey(field.key)&&!"12".equals(merged.get("ss_basic_server_resolver"))) normalized.put(field.key,merged.get(field.key));
            else normalized.put(field.key,normalizeField(group,field,merged.get(field.key)));
        }
        if("devices".equals(group)) {
            Set<String> bypass=new LinkedHashSet<>(Arrays.asList(normalized.get("ss_basic_bypass_macs").split(",")));
            for(String mac:normalized.get("ss_basic_uu_macs").split(",")) if(!mac.isEmpty()&&bypass.contains(mac)) throw new IOException("同一设备不能同时加入旁路和 UU 名单。");
        }
        if("failover".equals(group)&&Integer.parseInt(normalized.get("ss_basic_failover_budget"))<3*Integer.parseInt(normalized.get("ss_basic_failover_timeout"))+8) throw new IOException("检测预算至少为 3 × 候选超时 + 8 秒。");
        if("dns".equals(group)&&"12".equals(normalized.get("ss_basic_server_resolver"))&&normalized.get("ss_basic_server_resolver_user").isEmpty()) throw new IOException("选择自定义解析器时必须填写节点 DNS。");
        if("acl".equals(group)) {
            // The legacy backend only materializes an unset mode in its all-port
            // branch. A restricted default port therefore needs an explicit mode
            // in the same patch; never silently add one to a scoped write.
            if(changes.containsKey("ss_acl_default_port")&&!"all".equals(normalized.get("ss_acl_default_port"))
                    &&!changes.containsKey("ss_acl_default_mode")&&current.getOrDefault("ss_acl_default_mode","").trim().isEmpty())
                throw new IOException("自定义默认端口时，请同时明确选择其他主机默认策略。");
            for(String key:changes.keySet()) {
                String id=key.substring(key.lastIndexOf('_')+1);
                String modeKey="default".equals(id)?"ss_acl_default_mode":"ss_acl_mode_"+id;
                String portKey="default".equals(id)?"ss_acl_default_port":"ss_acl_port_"+id;
                if(key.startsWith("ss_acl_default_")) {modeKey="ss_acl_default_mode";portKey="ss_acl_default_port";}
                String mode=normalized.get(modeKey),ports=normalized.get(portKey);
                if(("3".equals(mode)||("0".equals(mode)&&!key.startsWith("ss_acl_default_")))&&!"all".equals(ports)) throw new IOException("直连或游戏策略需要 all 全端口；请一并修改端口字段。");
                if(!key.startsWith("ss_acl_default_")&&!ipv4(current.get("ss_acl_ip_"+id))) throw new IOException("已有规则的 IP 格式不受原生编辑支持，请使用完整插件页。");
            }
        }
        Map<String,String> result=new LinkedHashMap<>();
        for(String key:changes.keySet()) {
            String value=normalized.get(key);
            result.put(key,schema.get(key).encoded?Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.US_ASCII)):value);
        }
        return result;
    }

    private static String decodeStored(String raw) throws IOException {
        if(raw.length()%4!=0||!raw.matches("[A-Za-z0-9+/]*={0,2}")) throw new IOException("现有广告列表编码无效，请先在完整插件页修复。");
        try {
            byte[] bytes=Base64.getDecoder().decode(raw);
            if(!Base64.getEncoder().encodeToString(bytes).equals(raw)) throw new IllegalArgumentException();
            return new String(bytes,StandardCharsets.UTF_8);
        } catch(IllegalArgumentException ignored) {throw new IOException("现有广告列表编码无效，请先在完整插件页修复。");}
    }
    private static String normalizeField(String group,Field field,String input) throws IOException {
        String key=field.key,value=input==null?"":input.trim();
        if(field.values!=null) {
            if(!Arrays.asList(field.values).contains(value)) throw invalid(field);
            return value;
        }
        if("devices".equals(group)&&key.endsWith("_macs")) return normalizeMacs(input);
        if("ss_basic_anytls_hosts".equals(key)) return normalizeHosts(input);
        if("ss_basic_anytls_alpn".equals(key)) {
            if(value.isEmpty()||"auto".equals(value)) return "auto";
            Set<String> protocols=new LinkedHashSet<>(); for(String token:value.split(",",-1)) {
                token=token.trim(); if(!Arrays.asList("h2","http/1.1").contains(token)) throw invalid(field); protocols.add(token);
            } return String.join(",",protocols);
        }
        if("ss_basic_failover_country".equals(key)) {
            if("auto".equalsIgnoreCase(value)) return "auto";
            if(!value.matches("[A-Za-z]{2}")) throw invalid(field); return value.toUpperCase(Locale.ROOT);
        }
        if("ss_basic_failover_nodes".equals(key)) return normalizeIds(input);
        if("ss_basic_failover_countries".equals(key)) return normalizeCountries(input);
        if("adblock".equals(group)&&field.encoded) return domains(input,key.endsWith("_domains"));
        if("ss_basic_server_resolver_user".equals(key)) return input.isEmpty()?"":resolver(input);
        if("acl".equals(group)&&key.contains("_port")) return ports(value,field);
        int low=0,high=0;
        switch(key) {
            case "ss_basic_uu_interval": low=2;high=30;break;
            case "ss_basic_anytls_min_idle": low=0;high=20;break;
            case "ss_basic_anytls_idle_check": low=5;high=300;break;
            case "ss_basic_anytls_idle_timeout": low=5;high=600;break;
            case "ss_basic_anytls_handshake": low=3;high=20;break;
            case "ss_basic_health_failures": case "ss_basic_failover_failures": low=1;high=5;break;
            case "ss_basic_failover_recoveries": low=1;high=3;break;
            case "ss_basic_failover_cooldown": low=30;high=600;break;
            case "ss_basic_failover_timeout": low=3;high=8;break;
            case "ss_basic_failover_budget": low=20;high=120;break;
            default: throw invalid(field);
        }
        return integer(value,low,high,field.label);
    }
    private static IOException invalid(Field field) {return new IOException(field.label+"格式无效；"+field.help);}
    private static String integer(String value,int low,int high,String label) throws IOException {
        if(!value.matches("[0-9]{1,9}")) throw new IOException(label+"须为有效整数。");
        int number=Integer.parseInt(value); if(number<low||number>high) throw new IOException(label+"超出允许范围。"); return String.valueOf(number);
    }
    private static String normalizeMacs(String raw) throws IOException {
        Set<String> result=new LinkedHashSet<>();
        for(String part:raw.trim().split("[\\s,]+")) {
            if(part.isEmpty()) continue;
            String mac=part.replace('-',':').toUpperCase(Locale.ROOT);
            if(!mac.matches("(?:[0-9A-F]{2}:){5}[0-9A-F]{2}")||"00:00:00:00:00:00".equals(mac)||(Integer.parseInt(mac.substring(0,2),16)&1)!=0) throw new IOException("设备 MAC 格式无效。");
            result.add(mac); if(result.size()>32) throw new IOException("每组最多 32 个设备。");
        } return String.join(",",result);
    }
    private static boolean ipv4(String value) {
        if(value==null) return false; String[] parts=value.split("\\.",-1); if(parts.length!=4) return false;
        for(String part:parts) if(!part.matches("0|[1-9][0-9]{0,2}")||Integer.parseInt(part)>255) return false; return true;
    }
    private static String host(String value,boolean trailingDot) throws IOException {
        value=value.trim().toLowerCase(Locale.ROOT);
        if(value.matches("[0-9.]+")) {if(!ipv4(value)) throw new IOException("域名或 IPv4 格式无效。");return value;}
        if(trailingDot&&value.endsWith(".")) value=value.substring(0,value.length()-1);
        if(value.isEmpty()||value.length()>253||!value.matches("[a-z0-9.-]+")) throw new IOException("域名格式无效。");
        for(String label:value.split("\\.",-1)) if(label.length()>63||!label.matches("[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")) throw new IOException("域名格式无效。");return value;
    }
    private static String normalizeHosts(String raw) throws IOException {
        if(raw.length()>16384) throw new IOException("Hosts 内容过长。");
        Map<String,String> map=new LinkedHashMap<>();int count=0;
        for(String line:raw.split("[,\\r\\n]+",-1)) {
            if(line.trim().isEmpty()) continue; if(++count>32) throw new IOException("Hosts 最多 32 条。");
            String[] pair=line.split("=",-1); if(pair.length!=2) throw new IOException("Hosts 请填写 原域名=目标域名或IPv4。");
            String from=host(pair[0],true),to=host(pair[1],true),old=map.put(from,to);
            if(old!=null&&!old.equals(to)) throw new IOException("同一 Hosts 来源不能指向不同目标。");
        }
        List<String> output=new ArrayList<>();for(String from:map.keySet()) {
            String at=from;int hops=0;while(map.containsKey(at)) {if(++hops>4) throw new IOException("Hosts 映射存在循环或超过 4 跳。");at=map.get(at);}output.add(from+"="+map.get(from));
        }return String.join(",",output);
    }
    private static String normalizeIds(String raw) throws IOException {
        Set<String> ids=new LinkedHashSet<>();for(String value:raw.trim().split("[\\s,]+")) {
            if(value.isEmpty()) continue;if(!value.matches("[0-9]{1,6}")) throw new IOException("节点 ID 须为 1–999999。");ids.add(integer(value,1,999999,"节点 ID"));if(ids.size()>128) throw new IOException("最多 128 个候选节点。");
        }return String.join(",",ids);
    }
    private static String normalizeCountries(String raw) throws IOException {
        Map<String,String> map=new LinkedHashMap<>();int count=0;for(String line:raw.split("[,\\r\\n]+",-1)) {
            if(line.trim().isEmpty()) continue;if(++count>128) throw new IOException("最多 128 条节点地区映射。");
            String[] pair=line.trim().split("\\s*=\\s*",-1);if(pair.length!=2||!pair[0].matches("[0-9]{1,6}")||!pair[1].matches("[A-Za-z]{2}")) throw new IOException("地区映射请填写 节点ID=两位代码。");
            String id=integer(pair[0],1,999999,"节点 ID"),country=pair[1].toUpperCase(Locale.ROOT),old=map.put(id,country);if(old!=null&&!old.equals(country)) throw new IOException("同一节点不能映射到不同地区。");
        }List<String> result=new ArrayList<>();for(Map.Entry<String,String> entry:map.entrySet())result.add(entry.getKey()+"="+entry.getValue());return String.join(",",result);
    }
    private static String domains(String raw,boolean blocking) throws IOException {
        if(raw.length()>8192) throw new IOException("每个广告列表最多 8192 字节。");
        for(int i=0;i<raw.length();i++){char c=raw.charAt(i);if(c>126||(c<32&&c!='\n'&&c!='\r'&&c!='\t'))throw new IOException("广告列表只支持 ASCII 域名和普通换行。");}
        Set<String> result=new LinkedHashSet<>();int count=0;
        for(String line:raw.split("\n",-1)) {
            String name=line.trim();if(name.isEmpty())continue;if(++count>256)throw new IOException("每个广告列表最多 256 个非空行。");
            name=host(name,false);String[] labels=name.split("\\.");if(labels.length<2||!labels[labels.length-1].matches(".*[a-z].*"))throw new IOException("请填写完整域名，不接受 IP、网址或通配符。");
            if(blocking)for(String protectedName:PROTECTED)if(suffix(name,protectedName)||suffix(protectedName,name))throw new IOException("屏蔽列表涉及受保护的播放、联机或本地域名。");result.add(name);
        }return String.join("\n",result);
    }
    private static boolean suffix(String name,String parent){return name.equals(parent)||name.endsWith("."+parent);}
    private static String ports(String value,Field field) throws IOException {
        if("all".equals(value))return value;if(value.length()>50)throw invalid(field);int slots=0;List<String> out=new ArrayList<>();
        for(String item:value.split(",",-1)){String[] range=item.split(":",-1);if(range.length<1||range.length>2)throw invalid(field);String low=integer(range[0],1,65535,field.label);slots++;if(range.length==2){String high=integer(range[1],1,65535,field.label);if(Integer.parseInt(high)<Integer.parseInt(low))throw invalid(field);slots++;out.add(low+":"+high);}else out.add(low);}
        if(slots>15)throw invalid(field);return String.join(",",out);
    }
    private static String resolver(String input) throws IOException {
        String[] parts=input.split(",",-1);if(parts.length>4)throw new IOException("节点 DNS 最多 4 个上游。");List<String> output=new ArrayList<>();
        for(String part:parts) {
            if(part.startsWith("https://")) {
                String rest=part.substring(8);int slash=rest.indexOf('/');if(slash<1)throw new IOException("HTTPS DNS 必须包含完整路径。");String authority=rest.substring(0,slash),tail=rest.substring(slash);String[] endpoint=authority.split(":",-1);
                if(endpoint.length>2||authority.contains("@")||!tail.matches("/[A-Za-z0-9._~:/?%&=+@-]*"))throw new IOException("HTTPS DNS URL 格式无效。");
                for(int i=0;i<tail.length();i++)if(tail.charAt(i)=='%'){if(i+2>=tail.length()||!tail.substring(i+1,i+3).matches("[0-9A-Fa-f]{2}"))throw new IOException("HTTPS DNS URL 编码无效。");i+=2;}
                String domain=hostExact(endpoint[0]);String port=endpoint.length==2?":"+dnsPort(endpoint[1]):"";output.add("https://"+domain+port+tail);
            } else {
                String[] endpoint=part.split(":",-1);if(endpoint.length>2||!ipv4(endpoint[0]))throw new IOException("节点 DNS 须为 IPv4[:端口] 或 HTTPS URL。");output.add(endpoint[0]+":"+(endpoint.length==2?dnsPort(endpoint[1]):"53"));
            }
        }return String.join(",",output);
    }
    private static String hostExact(String value)throws IOException {
        if(value.isEmpty()||!value.equals(value.trim())||value.endsWith("."))throw new IOException("HTTPS DNS 主机名格式无效。");return host(value,false);
    }
    private static String dnsPort(String value)throws IOException {
        if(!value.matches("[0-9]{1,5}"))throw new IOException("DNS 端口格式无效。");return integer(value,1,65535,"DNS 端口");
    }
    private PluginSettings() {}
}
