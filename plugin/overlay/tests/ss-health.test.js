"use strict";

var assert = require("assert");
var fs = require("fs");
var vm = require("vm");
var health = require("../shadowsocks/res/ss-health.js");

var sample = {
    version: 1, enabled: true, node_id: "35", checked_at: 1000, interval_sec: 30,
    status: "healthy", total: 20, success: 19, last_latency_ms: 250,
    median_ms: 280, p95_ms: 900, jitter_ms: 120, consecutive_failures: 0,
    targets: [{ id: "google", state: "ok", latency_ms: 250, http_code: 204 }]
};
function view(changes, options) {
    var input = Object.assign({}, sample, changes || {});
    return health.makeView(input, Object.assign({ enabled: true, nodeId: "35", now: 1010 }, options || {}));
}

assert.strictEqual(view().kind, "healthy");
assert.strictEqual(view({ total: 1, success: 1 }).title, "已连通，采样中");
assert.strictEqual(view({ status: "degraded" }).kind, "degraded");
assert.strictEqual(view({ status: "down", consecutive_failures: 3 }).title, "连续检测失败");
assert.strictEqual(view({ status: "down", consecutive_failures: 2 }).title, "连续检测失败");
assert.strictEqual(view({ status: "down", consecutive_failures: 1 }).title, "连接检测未通过");
assert.strictEqual(view({ status: "down", consecutive_failures: 0, targets: [{ id: "proxy", state: "proxy_unavailable" }] }).title, "代理服务未就绪");
assert.strictEqual(view(null, { now: 1091 }).kind, "stale");
assert.strictEqual(view({ interval_sec: 120 }, { now: 1300 }).kind, "healthy");
assert.strictEqual(view({ interval_sec: 120 }, { now: 1361 }).kind, "stale");
assert.strictEqual(view(null, { now: 1091 }).historical, true);
assert.strictEqual(view(null, { now: 600 }).kind, "stale");
assert.strictEqual(view(null, { enabled: false }).kind, "disabled");
assert.strictEqual(view(null, { nodeId: "53" }).kind, "switching");
assert.strictEqual(view({ enabled: false }).kind, "checking");
assert.strictEqual(view({ checked_at: 0 }).kind, "checking");
assert.strictEqual(view({ version: 99 }).data, null);
assert.strictEqual(view({ success: 21 }).data.total, null);
assert.strictEqual(view({ last_latency_ms: NaN }).data.last_latency_ms, null);
assert.strictEqual(health.milliseconds(null), "—");
assert.strictEqual(health.milliseconds(19.6), "20 ms");

assert.deepStrictEqual(health.normalizeMacs("aa-bb-cc-dd-ee-00\nAA:BB:CC:DD:EE:00, 02:12:34:56:78:9a"), {
    valid: true, value: "AA:BB:CC:DD:EE:00,02:12:34:56:78:9A", count: 2
});
assert.deepStrictEqual(health.normalizeMacs(" \n,"), { valid: true, value: "", count: 0 });
assert.ok(health.normalizeMacs(" \n, bad").error.indexOf("第 1 项") === 0);
["00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "01:00:5E:00:00:01", "02:00:00:00:00", "02:00:00:00:00:00;reboot"].forEach(function (value) {
    assert.strictEqual(health.normalizeMacs(value).valid, false);
});
var tooMany = [];
for (var i = 0; i < 33; i++) { tooMany.push("02:00:00:00:00:" + (i < 16 ? "0" : "") + i.toString(16)); }
assert.strictEqual(health.normalizeMacs(tooMany.join(",")).valid, false);
assert.deepStrictEqual(health.normalizePolicies("02-00-00-00-00-01", "04:00:00:00:00:02"), {
    valid: true, bypass: "02:00:00:00:00:01", uu: "04:00:00:00:00:02"
});
assert.deepStrictEqual(health.normalizePolicies("", ""), { valid: true, bypass: "", uu: "" });
assert.strictEqual(health.normalizePolicies("02:00:00:00:00:01", "02-00-00-00-00-01").valid, false);
assert.strictEqual(health.normalizePolicies("02:00:00:00:00:01", "bad").field, "ss_basic_uu_macs");
assert.strictEqual(health.normalizePolicies("bad", "04:00:00:00:00:02").field, "ss_basic_bypass_macs");
assert.strictEqual(health.normalizePolicies("", tooMany.join(",")).valid, false);

assert.deepStrictEqual(health.normalizeAdvanced({}), { valid: true, values: health.advancedDefaults });
[
    ["ss_basic_anytls_min_idle", 0, 20],
    ["ss_basic_anytls_idle_check", 5, 300],
    ["ss_basic_anytls_idle_timeout", 5, 600],
    ["ss_basic_anytls_handshake", 3, 20],
    ["ss_basic_health_failures", 1, 5],
    ["ss_basic_uu_interval", 2, 30]
].forEach(function (rule) {
    [rule[1], rule[2], " " + rule[1] + " "].forEach(function (value) {
        var values = {}; values[rule[0]] = value;
        assert.strictEqual(health.normalizeAdvanced(values).valid, true);
    });
    [rule[1] - 1, rule[2] + 1, "", "1.5", "1e1", "8;reboot"].forEach(function (value) {
        var values = {}; values[rule[0]] = value;
        var result = health.normalizeAdvanced(values);
        assert.strictEqual(result.valid, false, rule[0] + " rejects " + value);
        assert.strictEqual(result.field, rule[0]);
    });
});
[["ss_basic_health_interval", ["30", "60", "120"]], ["ss_basic_health_timeout", ["6", "8", "10"]], ["ss_basic_anytls_fingerprint", ["chrome", "standard"]]].forEach(function (rule) {
    rule[1].forEach(function (value) { var values = {}; values[rule[0]] = value; assert.strictEqual(health.normalizeAdvanced(values).valid, true); });
    ["", "invalid", "30;reboot"].forEach(function (value) { var values = {}; values[rule[0]] = value; assert.strictEqual(health.normalizeAdvanced(values).valid, false); });
});
assert.strictEqual(health.normalizeAdvanced({ ss_basic_anytls_alpn: " h2, http/1.1,h2 " }).values.ss_basic_anytls_alpn, "h2,http/1.1");
assert.strictEqual(health.normalizeAdvanced({ ss_basic_anytls_alpn: "  " }).values.ss_basic_anytls_alpn, "auto");
["h3", "H2", "h2,", "h2,,http/1.1", "h2;reboot"].forEach(function (value) {
    assert.strictEqual(health.normalizeAdvanced({ ss_basic_anytls_alpn: value }).field, "ss_basic_anytls_alpn");
});

assert.deepStrictEqual(health.normalizeHosts(" \n,\r\n"), { valid: true, value: "", count: 0 });
assert.deepStrictEqual(health.normalizeHosts(" NODE.Example.com. = Connect.Example.com \n node.example.com=connect.example.com,edge.example.com=192.0.2.1"), { valid: true, value: "node.example.com=connect.example.com,edge.example.com=192.0.2.1", count: 2 });
assert.strictEqual(health.normalizeHosts("192.0.2.1=198.51.100.1").valid, true);
assert.strictEqual(health.normalizeHosts("constructor=constructor.example").valid, true);
assert.strictEqual(health.normalizeHosts("a=b\nb=c\nc=d\nd=e").valid, true);
assert.strictEqual(health.normalizeHosts("a=b,b=c,c=d,d=e,e=f").valid, false);
assert.strictEqual(health.normalizeHosts("a=b,b=a").valid, false);
assert.strictEqual(health.normalizeHosts("a=a").valid, false);
assert.strictEqual(health.normalizeHosts("a=b,a=c").valid, false);
assert.strictEqual(health.normalizeHosts("a=b,b=c,c=d,d=e,e=a").valid, false);
var hostEntries = [];
for (var h = 0; h < 32; h++) { hostEntries.push("node" + h + ".example.com=192.0.2.1"); }
assert.strictEqual(health.normalizeHosts(hostEntries.join("\n")).count, 32);
assert.strictEqual(health.normalizeHosts(hostEntries.concat("other.example.com=192.0.2.1").join("\n")).valid, false);
assert.strictEqual(health.normalizeHosts(Array(34).join("a=b\n")).valid, false);
[
    "a", "=b", "a=", "a=b=c", "a b=c", "a=b c", "a=http://example.com", "a=example.com:443", "a=::1", "a=256.1.2.3", "a=01.2.3.4", "a=1.2.3", "a=1.2.3.4.", "123=b", "a=例子.com", "_a=b", "-a=b", "a-=b", "a..b=c", "a.=b..", "a=*.example.com", "a=b;reboot", Array(65).join("a") + ".example=b"
].forEach(function (value) { assert.strictEqual(health.normalizeHosts(value).valid, false, "reject host mapping " + value); });
var longestHost = Array(64).join("a") + "." + Array(64).join("b") + "." + Array(64).join("c") + "." + Array(62).join("d");
assert.strictEqual(longestHost.length, 253);
assert.strictEqual(health.normalizeHosts(longestHost + ".=target.example").valid, true);
assert.strictEqual(health.normalizeHosts(longestHost + "d=target.example").valid, false);
assert.strictEqual(health.normalizeAdvanced({ ss_basic_anytls_hosts: "a=b\nb=192.0.2.1" }).values.ss_basic_anytls_hosts, "a=b,b=192.0.2.1");
assert.strictEqual(health.normalizeAdvanced({ ss_basic_anytls_hosts: "a=b,b=a" }).field, "ss_basic_anytls_hosts");

assert.strictEqual(health.buildVersion, "4.38.3-r7000.5");
assert.deepStrictEqual(health.normalizeAdblock({}), { valid: true, values: { ss_basic_adblock_enable: "0", ss_basic_adblock_domains: "", ss_basic_adblock_allow: "" } });
assert.deepStrictEqual(health.normalizeAdblockDomains(" ADS.Example.COM\t\r\n\n ads.example.com\nother.example", true), { valid: true, value: "ads.example.com\nother.example", count: 2 });
assert.deepStrictEqual(health.normalizeAdblockDomains(" \t\r\n", false), { valid: true, value: "", count: 0 });
["example.com.", "localhost", "192.0.2.1", "ad.123", "*.example.com", "https://ads.example.com/", "_ad.example", "-ad.example", "ad-.example", "a..example", "ads.例子", "ad\u0000.example", "ad\v.example", "ad\r.example", Array(65).join("a") + ".example"].forEach(function (value) { assert.strictEqual(health.normalizeAdblockDomains(value, false).valid, false, "reject advertising domain " + value); });
var adDomains = [];
for (i = 0; i < 256; i++) { adDomains.push("ad" + i + ".example"); }
assert.strictEqual(health.normalizeAdblockDomains(adDomains.join("\n"), true).count, 256);
assert.strictEqual(health.normalizeAdblockDomains(adDomains.concat("last.example").join("\n"), true).valid, false);
assert.strictEqual(health.normalizeAdblockDomains(Array(258).join("same.example\n"), true).valid, false, "line limit applies before deduplication");
assert.strictEqual(health.normalizeAdblockDomains(Array(8194).join(" "), true).valid, false);
var protectedDomains = ["doubleclick.net", "googlesyndication.com", "googleadservices.com", "googletagservices.com", "google-analytics.com", "googletagmanager.com", "youtube.com", "youtube-nocookie.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com", "googleapis.com", "gvt1.com", "gvt2.com", "gstatic.com", "google.com", "playstation.com", "playstation.net", "sonyentertainmentnetwork.com", "sony.com", "sony.net", "163.com", "126.net", "netease.com", "uux.cn", "localhost", "local", "localdomain", "lan", "home", "home.arpa", "router.asus.com", "asusrouter.com", "routerlogin.net", "routerlogin.com"];
protectedDomains.forEach(function (domain) {
    assert.strictEqual(health.normalizeAdblockDomains(domain, true).valid, false);
    assert.strictEqual(health.normalizeAdblockDomains("ads." + domain, true).valid, false);
    if (domain.indexOf(".") >= 0) { assert.strictEqual(health.normalizeAdblockDomains(domain, false).valid, true); }
});
assert.strictEqual(health.normalizeAdblockDomains("asus.com", true).valid, false, "protected parents are refused");
assert.strictEqual(health.normalizeAdblockDomains("notgooglevideo.com\ngooglevideo.com.example", true).valid, true, "protection uses domain boundaries");
assert.strictEqual(health.normalizeAdblock({ ss_basic_adblock_enable: "0", ss_basic_adblock_domains: "youtube.com" }).field, "ss_basic_adblock_domains", "disabled lists must still validate");
assert.strictEqual(health.normalizeAdblock({ ss_basic_adblock_enable: "1;reboot" }).field, "ss_basic_adblock_enable");
assert.strictEqual(health.normalizeAdblock({ ss_basic_adblock_domains: "ads.example", ss_basic_adblock_allow: "example.com." }).field, "ss_basic_adblock_allow");
assert.strictEqual(health.normalizeAdblock({ ss_basic_adblock_domains: "ads.example.com", ss_basic_adblock_allow: "example.com" }).valid, true);
assert.strictEqual(health.makeAdblockView(null).kind, "checking");
assert.strictEqual(health.makeAdblockView({ version: 1, enabled: false, running: false, state: "off" }).title, "域名广告过滤已关闭");
assert.strictEqual(health.makeAdblockView({ version: 1, enabled: true, running: false, state: "off" }).title, "设置已开启，等待代理运行");
var forwardingView = health.makeAdblockView({ version: 1, enabled: false, running: true, state: "off", domains: 32, excluded_devices: 2 });
assert.strictEqual(forwardingView.title, "广告过滤已关闭");
assert.strictEqual(forwardingView.kind, "disabled");
assert.strictEqual(forwardingView.note, "仅保留现有DNS连接的兼容转发，空闲后自动退出。");
assert.strictEqual(forwardingView.summary, "生效域名 0；排除设备 2");
var drainingView = health.makeAdblockView({ version: 1, enabled: true, running: true, state: "draining", domains: 32, excluded_devices: 3 });
assert.strictEqual(drainingView.title, "等待旧DNS连接释放");
assert.strictEqual(drainingView.kind, "checking");
assert.strictEqual(drainingView.note, "先保持直通，释放后应用新的设备排除策略。");
assert.strictEqual(drainingView.summary, "生效域名 0；排除设备 3");
var adView = health.makeAdblockView({ version: 1, enabled: true, running: true, state: "active", domains: 32, excluded_devices: 2, message: "PRIVATE-URL-MUST-NOT-RENDER" });
assert.strictEqual(adView.kind, "healthy");
assert.strictEqual(adView.summary, "生效域名 32；排除设备 2");
assert.ok(JSON.stringify(adView).indexOf("PRIVATE-URL") < 0);
assert.strictEqual(health.makeAdblockView({ version: 1, enabled: true, running: true, state: "error" }).kind, "down");
assert.strictEqual(health.makeAdblockView({ version: 1, enabled: "true", running: true, state: "active" }).kind, "checking");

[
    ["ss_basic_failover_failures", 1, 5], ["ss_basic_failover_recoveries", 1, 3],
    ["ss_basic_failover_cooldown", 30, 600], ["ss_basic_failover_timeout", 3, 8],
    ["ss_basic_failover_budget", 20, 120]
].forEach(function (rule) {
    [rule[1], rule[2], " " + rule[1] + " "].forEach(function (value) {
        var values = { ss_basic_failover_timeout: "3" }; values[rule[0]] = value;
        assert.strictEqual(health.normalizeAdvanced(values).valid, true, rule[0] + " accepts " + value);
    });
    [rule[1] - 1, rule[2] + 1, "", "1.5", "1e1", "5;reboot"].forEach(function (value) {
        var values = {}; values[rule[0]] = value;
        assert.strictEqual(health.normalizeAdvanced(values).field, rule[0], rule[0] + " rejects " + value);
    });
});
[
    ["ss_basic_uu_tcp_policy", ["gfwlist", "foreign", "direct"]],
    ["ss_basic_failover_enable", ["0", "1"]], ["ss_basic_failover_direct", ["0", "1"]]
].forEach(function (rule) {
    rule[1].forEach(function (value) { var values = {}; values[rule[0]] = value; assert.strictEqual(health.normalizeAdvanced(values).valid, true); });
    ["", "invalid", "1;reboot"].forEach(function (value) { var values = {}; values[rule[0]] = value; assert.strictEqual(health.normalizeAdvanced(values).field, rule[0]); });
});
assert.strictEqual(health.normalizeAdvanced({ ss_basic_failover_country: " hk " }).values.ss_basic_failover_country, "HK");
assert.strictEqual(health.normalizeAdvanced({ ss_basic_failover_country: " Auto " }).values.ss_basic_failover_country, "auto");
["", "Hong Kong", "香港", "HKG", "H1", "HK;reboot"].forEach(function (value) { assert.strictEqual(health.normalizeAdvanced({ ss_basic_failover_country: value }).field, "ss_basic_failover_country"); });
assert.strictEqual(health.normalizeAdvanced({ ss_basic_failover_budget: "20", ss_basic_failover_timeout: "8" }).field, "ss_basic_failover_budget");
assert.strictEqual(health.normalizeAdvanced({ ss_basic_failover_budget: "32", ss_basic_failover_timeout: "8" }).valid, true);
assert.strictEqual(health.normalizeAdvanced({ ss_basic_failover_budget: "31", ss_basic_failover_timeout: "8" }).valid, false);

assert.deepStrictEqual(health.normalizeNodeIds(" \n,"), { valid: true, value: "", count: 0 });
assert.deepStrictEqual(health.normalizeNodeIds("1, 003\n1 999999"), { valid: true, value: "1,3,999999", count: 3 });
["0", "1000000", "1.5", "-1", "2;reboot", "node.example:443", "1=HK"].forEach(function (value) { assert.strictEqual(health.normalizeNodeIds(value).valid, false); });
var candidateIds = [];
for (i = 1; i <= 129; i++) { candidateIds.push(String(i)); }
assert.strictEqual(health.normalizeNodeIds(candidateIds.slice(0, 128).join(",")).count, 128);
assert.strictEqual(health.normalizeNodeIds(candidateIds.join(",")).valid, false);
assert.strictEqual(health.normalizeNodeIds(Array(140).join("1,")).count, 1);
assert.deepStrictEqual(health.normalizeCountries(" \n,"), { valid: true, value: "", count: 0 });
assert.deepStrictEqual(health.normalizeCountries(" 001 = hk\n2=JP,1=HK"), { valid: true, value: "1=HK,2=JP", count: 2 });
["0=HK", "1000000=HK", "1=HongKong", "1=香港", "1=H1", "1=HK;reboot", "1=HK,1=JP", "constructor=HK"].forEach(function (value) { assert.strictEqual(health.normalizeCountries(value).valid, false, value); });
assert.strictEqual(health.normalizeCountries(candidateIds.slice(0, 128).join("=HK,") + "=HK").count, 128);
assert.strictEqual(health.normalizeCountries(candidateIds.join("=HK,") + "=HK").valid, false);
var normalizedFailover = health.normalizeAdvanced({ ss_basic_failover_nodes: "01\n2,1", ss_basic_failover_countries: "1=hk\n2=jp" });
assert.strictEqual(normalizedFailover.values.ss_basic_failover_nodes, "1,2");
assert.strictEqual(normalizedFailover.values.ss_basic_failover_countries, "1=HK,2=JP");

var failoverSample = { version: 1, state: "healthy", mode: "proxy", checked_at: 1000, current_node: "35", country: "HK", preferred_country: "HK", scanned: 2, total: 4, best_ms: 82, failures: 0 };
function failoverView(changes, options) {
    return health.makeFailoverView(Object.assign({}, failoverSample, changes || {}), Object.assign({ enabled: "1", configured: "1", now: 1010 }, options || {}));
}
assert.strictEqual(failoverView().kind, "healthy");
assert.ok(failoverView().summary.indexOf("当前节点 ID 35 · HK") >= 0);
assert.ok(failoverView().summary.indexOf("已检测 2 / 4") >= 0);
assert.ok(failoverView().summary.indexOf("82 ms") >= 0);
assert.strictEqual(failoverView(null, { enabled: "0" }).title, "代理已关闭");
assert.strictEqual(failoverView(null, { configured: "0" }).kind, "disabled");
assert.strictEqual(failoverView({ version: 2 }).kind, "checking");
assert.strictEqual(failoverView({ checked_at: 0 }).kind, "checking");
assert.strictEqual(failoverView({ checked_at: "1000" }).kind, "checking");
assert.strictEqual(failoverView(null, { now: 1241 }).kind, "stale");
assert.strictEqual(failoverView(null, { now: 699 }).kind, "stale");
assert.strictEqual(failoverView(null, { now: 1240 }).kind, "healthy");
[
    ["disabled", "disabled"], ["confirming", "degraded"], ["scanning_direct", "degraded"],
    ["scanning_proxy", "degraded"], ["recovering", "checking"], ["direct", "degraded"],
    ["switched", "healthy"], ["cooldown", "checking"], ["error", "down"]
].forEach(function (state) { assert.strictEqual(failoverView({ state: state[0] }).kind, state[1]); });
assert.strictEqual(failoverView({ mode: "error" }).kind, "down");
assert.strictEqual(failoverView({ mode: "direct" }).title, "直连保护中");
assert.strictEqual(failoverView({ state: "direct", mode: "direct" }).note.indexOf("只保障原本可直连的服务") >= 0, true);
assert.strictEqual(failoverView({ country: "XX", preferred_country: "XX" }).summary.indexOf("未识别") >= 0, true);
assert.strictEqual(failoverView({ current_node: "000035" }).currentNode, "35");
var hostileState = failoverView({ state: { toString: null }, current_node: { toString: null }, country: "<script>", preferred_country: "https://secret", reason: "private-host password=secret", best_ms: NaN, scanned: 129, total: 128, failures: 999 });
assert.strictEqual(hostileState.kind, "checking");
assert.strictEqual(hostileState.currentNode, null);
assert.ok(!/script|secret|129|999/.test(JSON.stringify(hostileState)));
assert.strictEqual(health.makeFailoverView(null, { enabled: true, configured: true }).kind, "checking");

var asp = fs.readFileSync(require.resolve("../shadowsocks/webs/Main_Ss_Content.asp"), "utf8");
assert.ok(asp.indexOf("4.38.3-r7000.5</span>") >= 0, "page shows current enhancement build");
assert.strictEqual((asp.match(/src="\/res\/ss-health\.js\?v=r7000\.5-ad2"/g) || []).length, 1, "health script bypasses the pre-draining browser cache");
assert.strictEqual((asp.match(/href="\/res\/ss-health\.css"/g) || []).length, 1, "legacy httpd requires a query-free health stylesheet URL");
["ss_health", "ss_health_title", "ss_health_latency", "ss_health_success", "ss_health_targets", "ss_health_legacy", "ss_state2", "ss_state3", "mode_state", "ss_basic_bypass_macs", "ss_basic_uu_macs", "ss_bypass_error", "ss_uu_error", "ss_anytls_advanced_body", "ss_health_advanced_body", "ss_anytls_advanced_toggle", "ss_health_advanced_toggle", "ss_anytls_advanced_error", "ss_health_advanced_error", "ss_failover_advanced_body", "ss_failover_advanced_toggle", "ss_failover_advanced_error", "ss_failover_status", "ss_failover_title", "ss_failover_time", "ss_failover_note", "ss_failover_summary", "ss_failover_node_catalog", "ss_adblock_advanced_body", "ss_adblock_advanced_toggle", "ss_adblock_advanced_error", "ss_adblock_status", "ss_adblock_title", "ss_adblock_note", "ss_adblock_summary", "ss_adblock_save", "ss_adblock_save_result"].concat(Object.keys(health.advancedDefaults)).forEach(function (id) {
    assert.strictEqual((asp.match(new RegExp('id="' + id + '"', "g")) || []).length, 1, id + " must be unique");
});
var scripts = asp.replace(/<%[\s\S]*?%>/g, "0").match(/<script\b[^>]*>[\s\S]*?<\/script>/gi) || [];
scripts.forEach(function (block, i) {
    var body = block.replace(/^<script\b[^>]*>/i, "").replace(/<\/script>$/i, "").replace(/<%[\s\S]*?%>/g, "0");
    new vm.Script(body, { filename: "Main_Ss_Content.asp:inline-" + i });
});

var elements = {}, focused = null, openedTab = null;
function fakeElement(id) {
    if (!elements[id]) {
        elements[id] = { value: "", style: { display: "none" }, attributes: {}, innerHTML: "", appendChild: function (value) { this.innerHTML += value; }, setAttribute: function (key, value) { this.attributes[key] = value; }, removeAttribute: function (key) { delete this.attributes[key]; }, focus: function () { focused = id; }, getElementsByTagName: function () { return []; } };
    }
    return elements[id];
}
var base64 = { encode: function (value) { return Buffer.from(value, "utf8").toString("base64"); }, decode: function (value) { return Buffer.from(value, "base64").toString("utf8"); } };
var context = { SsHealth: health, Base64: base64, E: fakeElement, window: { location: { protocol: "http:", host: "router.example" } }, document: { createTextNode: function (value) { return value; } }, $: function (selector) { return { trigger: function () { openedTab = selector; } }; } };
vm.createContext(context);
vm.runInContext(asp.slice(asp.indexOf("function loadAdvancedSettings("), asp.indexOf("function save()")), context);
context.loadAdvancedSettings({});
assert.strictEqual(elements.ss_basic_anytls_min_idle.value, "0");
assert.strictEqual(elements.ss_basic_anytls_alpn.value, "h2");
assert.strictEqual(elements.ss_basic_anytls_hosts.value, "");
assert.strictEqual(elements.ss_basic_failover_enable.value, "0");
assert.strictEqual(elements.ss_basic_failover_direct.value, "1");
assert.strictEqual(elements.ss_basic_uu_tcp_policy.value, "gfwlist");
assert.strictEqual(elements.ss_basic_uu_interval.value, "5");
assert.strictEqual(elements.ss_basic_adblock_enable.value, "0");
assert.strictEqual(elements.ss_basic_adblock_domains.value, "");
context.loadAdvancedSettings({ ss_basic_adblock_domains: base64.encode("Ads.Example.com\nother.example") });
assert.strictEqual(elements.ss_basic_adblock_domains.value, "Ads.Example.com\nother.example");
fakeElement("ssconf_basic_node").options = [{ value: "1", text: "Sample HK" }, { value: "2", text: "Other protocol" }];
context.loadAdvancedSettings({ ssconf_basic_type_1: "4", ssconf_basic_trojan_binary_1: "AnyTLS", ssconf_basic_type_2: "0", ss_basic_failover_countries: "1=HK,2=JP" });
assert.strictEqual(elements.ss_failover_node_catalog.value, "1 · Sample HK");
assert.strictEqual(elements.ss_basic_failover_countries.value, "1=HK\n2=JP");
assert.ok(asp.indexOf("loadAllConfigs();") < asp.indexOf("loadAdvancedSettings(db_ss);"), "node ID catalog loads after dropdown options");
context.loadAdvancedSettings({ ss_basic_anytls_alpn: "auto", ss_basic_health_interval: "120" });
assert.strictEqual(elements.ss_basic_anytls_alpn.value, "");
assert.strictEqual(elements.ss_basic_health_interval.value, "120");
var validated = context.validateAdvancedSettings();
assert.strictEqual(validated.ss_basic_anytls_alpn, "auto");
assert.strictEqual(validated.ss_basic_health_interval, "120");
elements.ss_basic_anytls_handshake.value = "2";
assert.strictEqual(context.validateAdvancedSettings(), null);
assert.strictEqual(openedTab, "#show_btn2");
assert.strictEqual(focused, "ss_basic_anytls_handshake");
assert.strictEqual(elements.ss_anytls_advanced_body.style.display, "");
assert.strictEqual(elements.ss_anytls_advanced_toggle.attributes["aria-expanded"], "true");
context.loadAdvancedSettings({});
elements.ss_basic_health_failures.value = "6";
assert.strictEqual(context.validateAdvancedSettings(), null);
assert.strictEqual(openedTab, "#show_btn6");
assert.strictEqual(focused, "ss_basic_health_failures");
context.loadAdvancedSettings({ ss_basic_failover_budget: "20", ss_basic_failover_timeout: "8" });
assert.strictEqual(context.validateAdvancedSettings(), null);
assert.strictEqual(openedTab, "#show_btn6");
assert.strictEqual(focused, "ss_basic_failover_budget");
assert.strictEqual(elements.ss_failover_advanced_body.style.display, "");
assert.strictEqual(elements.ss_failover_advanced_toggle.attributes["aria-expanded"], "true");
assert.ok(elements.ss_failover_advanced_error.innerHTML.indexOf("预算") >= 0);
context.loadAdvancedSettings({ ss_basic_uu_tcp_policy: "invalid" });
assert.strictEqual(context.validateAdvancedSettings(), null);
assert.strictEqual(openedTab, "#show_btn5");
assert.strictEqual(focused, "ss_basic_uu_tcp_policy");
assert.strictEqual(elements.ss_basic_uu_tcp_policy.attributes["aria-invalid"], "true");
context.loadAdvancedSettings({ ss_basic_uu_interval: "1" });
assert.strictEqual(context.validateAdvancedSettings(), null);
assert.strictEqual(openedTab, "#show_btn5");
assert.strictEqual(focused, "ss_basic_uu_interval");
assert.strictEqual(elements.ss_basic_uu_interval.attributes["aria-invalid"], "true");
assert.ok(elements.ss_uu_error.innerHTML.indexOf("2–30") >= 0);
vm.runInContext(asp.slice(asp.indexOf("function clearBypassError()"), asp.indexOf("function validateBypassDevices()")), context);
context.clearBypassError();
assert.strictEqual(elements.ss_basic_uu_interval.attributes["aria-invalid"], undefined);
context.loadAdvancedSettings({ ss_basic_adblock_enable: "0", ss_basic_adblock_domains: base64.encode("ads.googlevideo.com") });
assert.strictEqual(context.validateAdvancedSettings(), null);
assert.strictEqual(openedTab, "#show_btn6");
assert.strictEqual(focused, "ss_basic_adblock_domains");
assert.strictEqual(elements.ss_adblock_advanced_toggle.attributes["aria-expanded"], "true");
context.loadAdvancedSettings({ ss_basic_anytls_hosts: "a=b,b=a" });
elements.ss_anytls_advanced_body.getElementsByTagName = function (tag) { return tag === "textarea" ? [elements.ss_basic_anytls_hosts] : []; };
assert.strictEqual(context.validateAdvancedSettings(), null);
assert.strictEqual(focused, "ss_basic_anytls_hosts");
assert.strictEqual(openedTab, "#show_btn2");
assert.strictEqual(elements.ss_basic_anytls_hosts.attributes["aria-invalid"], "true");
context.clearAdvancedError("anytls");
assert.strictEqual(elements.ss_basic_anytls_hosts.attributes["aria-invalid"], undefined);
context.loadAdvancedSettings({ ss_basic_anytls_alpn: "auto", ss_basic_anytls_min_idle: "02", ss_basic_health_interval: "60", ss_basic_anytls_hosts: "NODE.example=alias.example,alias.example=192.0.2.1", ss_basic_uu_tcp_policy: "direct", ss_basic_uu_interval: "07", ss_basic_adblock_domains: base64.encode(" ADS.Example.COM\nads.example.com "), ss_basic_adblock_allow: base64.encode("Needed.Example.com"), ss_basic_failover_enable: "1", ss_basic_failover_country: "hk", ss_basic_failover_nodes: "01\n2", ss_basic_failover_countries: "1=hk\n2=jp" });
assert.strictEqual(elements.ss_basic_anytls_hosts.value, "NODE.example=alias.example\nalias.example=192.0.2.1");
context.advancedSettings = context.validateAdvancedSettings();
elements.ss_basic_bypass_macs = { value: "02:00:00:00:00:01" };
elements.ss_basic_uu_macs = { value: "04:00:00:00:00:02" };
var saveSource = asp.slice(asp.indexOf("function save()"));
vm.runInContext(saveSource.slice(saveSource.indexOf("var dbus = {}"), saveSource.indexOf("// collect data from checkbox")), context);
Object.keys(health.advancedDefaults).forEach(function (key) { assert.strictEqual(context.dbus[key], key === "ss_basic_adblock_domains" || key === "ss_basic_adblock_allow" ? base64.encode(context.advancedSettings[key]) : context.advancedSettings[key], key + " is serialized by save"); });
assert.strictEqual(context.dbus.ss_basic_anytls_min_idle, "2");
assert.strictEqual(context.dbus.ss_basic_anytls_alpn, "auto");
assert.strictEqual(context.dbus.ss_basic_anytls_hosts, "node.example=alias.example,alias.example=192.0.2.1");
assert.strictEqual(context.dbus.ss_basic_bypass_macs, "02:00:00:00:00:01");
assert.strictEqual(context.dbus.ss_basic_uu_macs, "04:00:00:00:00:02");
assert.strictEqual(context.dbus.ss_basic_uu_tcp_policy, "direct");
assert.strictEqual(context.dbus.ss_basic_uu_interval, "7");
assert.strictEqual(context.dbus.ss_basic_failover_enable, "1");
assert.strictEqual(context.dbus.ss_basic_failover_country, "HK");
assert.strictEqual(context.dbus.ss_basic_failover_nodes, "1,2");
assert.strictEqual(context.dbus.ss_basic_failover_countries, "1=HK,2=JP");
assert.strictEqual(context.dbus.ss_basic_adblock_enable, "0");
assert.strictEqual(context.dbus.ss_basic_adblock_domains, base64.encode("ads.example.com"));
assert.strictEqual(context.dbus.ss_basic_adblock_allow, base64.encode("needed.example.com"));

var adPosts = [], adRefreshes = 0;
context.SsHealth = Object.assign({}, health, { refreshAdblock: function () { adRefreshes++; } });
context.$.ajax = function (request) { adPosts.push(request); };
context.$.param = function (payload) { return payload; };
context.db_ss = { unrelated: "preserved" };
context.loadAdvancedSettings({ ss_basic_adblock_enable: "1", ss_basic_adblock_domains: base64.encode(" Ads.Example.COM "), ss_basic_adblock_allow: base64.encode("needed.example.com") });
elements.ss_basic_anytls_handshake.value = "999"; // Advertising-only save must ignore unrelated proxy inputs.
context.saveAdblockSettings();
assert.strictEqual(adPosts.length, 1);
assert.strictEqual(adPosts[0].type, "POST");
assert.strictEqual(adPosts[0].url, "/applydb.cgi?p=ss");
assert.strictEqual(adPosts[0].data.SystemCmd, "ss_adblock.sh");
assert.strictEqual(adPosts[0].data.current_page, "Main_Ss_Content.asp");
assert.strictEqual(adPosts[0].data.action_mode, " Refresh ");
assert.deepStrictEqual(Object.keys(adPosts[0].data).sort(), ["SystemCmd", "action_mode", "current_page", "ss_basic_adblock_allow", "ss_basic_adblock_domains", "ss_basic_adblock_enable"]);
assert.strictEqual(adPosts[0].data.ss_basic_adblock_domains, base64.encode("ads.example.com"));
assert.strictEqual(elements.ss_adblock_save.disabled, true);
adPosts[0].success("<!DOCTYPE html><html><form>Login</form></html>");
adPosts[0].complete();
assert.ok(elements.ss_adblock_save_result.innerHTML.indexOf("管理会话可能已过期") >= 0);
assert.strictEqual(context.db_ss.ss_basic_adblock_enable, undefined);
assert.strictEqual(adRefreshes, 0);
assert.strictEqual(elements.ss_adblock_save.disabled, false);
context.saveAdblockSettings();
adPosts[1].success(""); adPosts[1].complete();
assert.strictEqual(context.db_ss.ss_basic_adblock_domains, base64.encode("ads.example.com"));
assert.strictEqual(elements.ss_basic_adblock_domains.value, "ads.example.com");
assert.strictEqual(context.db_ss.unrelated, "preserved");
assert.strictEqual(adRefreshes, 1);
assert.ok(elements.ss_adblock_save_result.innerHTML.indexOf("已提交") >= 0);
context.saveAdblockSettings();adPosts[2].error();adPosts[2].complete();
assert.ok(elements.ss_adblock_save_result.innerHTML.indexOf("未能确认保存") >= 0);
context.saveAdblockSettings();
adPosts[3].success('<html><head>\r\n<meta http-equiv="refresh" content="0; url=http://router.example/Main_Ss_Content.asp">\r\n<meta http-equiv="Content-Type" content="text/html">\r\n</head></html>\r\n');adPosts[3].complete();
assert.ok(elements.ss_adblock_save_result.innerHTML.indexOf("已提交") >= 0, "legacy same-page redirect is a valid non-executed apply response");
assert.strictEqual(adRefreshes, 2);
context.saveAdblockSettings();adPosts[4].success('<html><head><meta http-equiv="refresh" content="0; url=http://other.example/Main_Ss_Content.asp"></head></html>');adPosts[4].complete();
assert.ok(elements.ss_adblock_save_result.innerHTML.indexOf("未能确认保存") >= 0, "a foreign redirect must not count as saved");
context.saveAdblockSettings();adPosts[5].success('<html><head><script>top.location.href="/Main_Login.asp";</script></head></html>');adPosts[5].complete();
assert.ok(elements.ss_adblock_save_result.innerHTML.indexOf("未能确认保存") >= 0, "login redirect must not count as saved");
assert.strictEqual(adRefreshes, 2);
context.saveAdblockSettings();adPosts[6].success("<script>parent.done_validating('', '');</script>\n");adPosts[6].complete();
assert.ok(elements.ss_adblock_save_result.innerHTML.indexOf("已提交") >= 0, "observed vendor completion reply is accepted without execution");
context.saveAdblockSettings();adPosts[7].success(" <script>\nparent.done_validating( \"\" , '' );\n</script>\n");adPosts[7].complete();
assert.ok(elements.ss_adblock_save_result.innerHTML.indexOf("已提交") >= 0, "empty completion arguments allow harmless whitespace");
assert.strictEqual(adRefreshes, 4);
context.saveAdblockSettings();adPosts[8].success("<script>parent.done_validating('unexpected', '');</script>\n");adPosts[8].complete();
assert.ok(elements.ss_adblock_save_result.innerHTML.indexOf("未能确认保存") >= 0, "nonempty completion arguments are not accepted");
context.saveAdblockSettings();adPosts[9].success("<script>parent.done_validating('', '');alert(1);</script>\n");adPosts[9].complete();
assert.ok(elements.ss_adblock_save_result.innerHTML.indexOf("未能确认保存") >= 0, "additional script is not accepted");
assert.strictEqual(adRefreshes, 4);
elements.ss_basic_adblock_allow.value = "https://bad.example/";
context.saveAdblockSettings();assert.strictEqual(adPosts.length, 10);
assert.strictEqual(focused, "ss_basic_adblock_allow");


// Real browser entrypoints must fetch JSON independently and follow a controller switch
// without changing the form's selected node or the Android health document schema.
var requests = [], runtimeElements = {}, expiryCallback = null;
var browser = {
    document: { getElementById: function (id) {
        if (!runtimeElements[id]) { runtimeElements[id] = { textContent: "", className: "", style: {}, firstChild: null, appendChild: function () {} }; }
        return runtimeElements[id];
    } },
    window: {
        jQuery: { ajax: function (request) { requests.push(request); } },
        setInterval: function (callback) { expiryCallback = callback; return 1; },
        clearInterval: function () {}
    }
};
vm.createContext(browser);
vm.runInContext(fs.readFileSync(require.resolve("../shadowsocks/res/ss-health.js"), "utf8"), browser);
browser.db_ss = { ss_basic_enable: "1", ss_basic_failover_enable: "1", ssconf_basic_node: "35" };
browser.E = browser.document.getElementById;
var nodeSelect = browser.E("ssconf_basic_node");
nodeSelect.selectedIndex = 0;
nodeSelect.options = [{ value: "35", text: "Original" }, { value: "36", text: "Alternate" }];
browser.menu_hook = {};
["show_menu", "update_ss_ui", "loadAllConfigs", "loadAdvancedSettings", "decode_show", "toggle_func", "version_show", "hook_event", "detect", "setTimeout"].forEach(function (name) { browser[name] = function () {}; });
var startOptions, nativeStart = browser.SsHealth.start;
browser.SsHealth.start = function (options) { startOptions = options; nativeStart(options); };
vm.runInContext(asp.slice(asp.indexOf("function init()"), asp.indexOf("function hide_elem()")), browser);
browser.init();
assert.strictEqual(startOptions.failoverEnabled, "1", "ASP initialization passes DBus failover flag to the new JS");
assert.strictEqual(startOptions.nodeId, "35");
assert.strictEqual(startOptions.nodeLabelForId("36"), "Alternate");
browser.SsHealth.refresh();
assert.strictEqual(requests.length, 3);
assert.strictEqual(requests[0].url, "/res/ss-failover-status.js");
assert.strictEqual(requests[1].url, "/res/ss-adblock-status.js");
assert.strictEqual(requests[2].url, "/res/ss-health-status.js");
requests.forEach(function (request) { assert.strictEqual(request.dataType, "json"); assert.strictEqual(request.cache, false); });
var liveNow = Date.now() / 1000;
requests[0].success(Object.assign({}, failoverSample, { current_node: "36", state: "switched", checked_at: liveNow }));
requests[0].complete();
requests[1].success({version:1,enabled:true,running:true,state:"active",domains:32,excluded_devices:2}); requests[1].complete();
requests[2].success(Object.assign({}, sample, { node_id: "36", targets: [], checked_at: liveNow }));
requests[2].complete();
assert.strictEqual(runtimeElements.ss_adblock_title.textContent,"域名广告过滤运行中");
assert.strictEqual(runtimeElements.ss_health_title.textContent, "连接正常");
assert.strictEqual(runtimeElements.ss_health_node.textContent, "当前节点 Alternate");
assert.strictEqual(runtimeElements.ss_failover_title.textContent, "已切换线路");
assert.ok(runtimeElements.ss_failover_summary.textContent.indexOf("当前节点 ID 36") >= 0);
assert.strictEqual(typeof expiryCallback, "function");
browser.SsHealth.refresh();
assert.strictEqual(requests.length, 6);
requests[3].error(); requests[3].complete();
assert.strictEqual(runtimeElements.ss_failover_title.textContent, "暂时无法读取自动切换状态");
requests[4].error(); requests[4].complete();
assert.strictEqual(runtimeElements.ss_adblock_title.textContent, "暂时无法读取广告过滤状态");
requests[5].error(); requests[5].complete();
browser.SsHealth.refresh("0");
assert.strictEqual(requests.length, 7, "adblock status remains readable when proxy is off");
requests[6].success({version:1,enabled:true,running:false,state:"off",domains:0,excluded_devices:2}); requests[6].complete();
assert.strictEqual(runtimeElements.ss_adblock_title.textContent,"设置已开启，等待代理运行");
assert.strictEqual(runtimeElements.ss_failover_title.textContent, "代理已关闭");
assert.strictEqual(runtimeElements.ss_health_title.textContent, "代理已关闭");
browser.SsHealth.start({ enabled: "1", failoverEnabled: "0", nodeId: "35" });
browser.SsHealth.refresh();
assert.strictEqual(requests.length, 9);
assert.strictEqual(requests[7].url, "/res/ss-adblock-status.js");
assert.strictEqual(requests[8].url, "/res/ss-health-status.js");
assert.strictEqual(runtimeElements.ss_failover_title.textContent, "自动故障切换未开启");
console.log("ss-health UI: health + failover states, safe JSON, stale data, device policies, settings, validation, save serialization and inline syntax passed");
