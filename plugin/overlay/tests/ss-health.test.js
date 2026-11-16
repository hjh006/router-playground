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
    ["ss_basic_health_failures", 1, 5]
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

var asp = fs.readFileSync(require.resolve("../shadowsocks/webs/Main_Ss_Content.asp"), "utf8");
["ss_health", "ss_health_title", "ss_health_latency", "ss_health_success", "ss_health_targets", "ss_health_legacy", "ss_state2", "ss_state3", "mode_state", "ss_basic_bypass_macs", "ss_basic_uu_macs", "ss_bypass_error", "ss_uu_error", "ss_anytls_advanced_body", "ss_health_advanced_body", "ss_anytls_advanced_toggle", "ss_health_advanced_toggle", "ss_anytls_advanced_error", "ss_health_advanced_error"].concat(Object.keys(health.advancedDefaults)).forEach(function (id) {
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
var context = { SsHealth: health, E: fakeElement, document: { createTextNode: function (value) { return value; } }, $: function (selector) { return { trigger: function () { openedTab = selector; } }; } };
vm.createContext(context);
vm.runInContext(asp.slice(asp.indexOf("function loadAdvancedSettings("), asp.indexOf("function save()")), context);
context.loadAdvancedSettings({});
assert.strictEqual(elements.ss_basic_anytls_min_idle.value, "0");
assert.strictEqual(elements.ss_basic_anytls_alpn.value, "h2");
assert.strictEqual(elements.ss_basic_anytls_hosts.value, "");
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
context.loadAdvancedSettings({ ss_basic_anytls_hosts: "a=b,b=a" });
elements.ss_anytls_advanced_body.getElementsByTagName = function (tag) { return tag === "textarea" ? [elements.ss_basic_anytls_hosts] : []; };
assert.strictEqual(context.validateAdvancedSettings(), null);
assert.strictEqual(focused, "ss_basic_anytls_hosts");
assert.strictEqual(openedTab, "#show_btn2");
assert.strictEqual(elements.ss_basic_anytls_hosts.attributes["aria-invalid"], "true");
context.clearAdvancedError("anytls");
assert.strictEqual(elements.ss_basic_anytls_hosts.attributes["aria-invalid"], undefined);
context.loadAdvancedSettings({ ss_basic_anytls_alpn: "auto", ss_basic_anytls_min_idle: "02", ss_basic_health_interval: "60", ss_basic_anytls_hosts: "NODE.example=alias.example,alias.example=192.0.2.1" });
assert.strictEqual(elements.ss_basic_anytls_hosts.value, "NODE.example=alias.example\nalias.example=192.0.2.1");
context.advancedSettings = context.validateAdvancedSettings();
elements.ss_basic_bypass_macs = { value: "02:00:00:00:00:01" };
elements.ss_basic_uu_macs = { value: "04:00:00:00:00:02" };
var saveSource = asp.slice(asp.indexOf("function save()"));
vm.runInContext(saveSource.slice(saveSource.indexOf("var dbus = {}"), saveSource.indexOf("// collect data from checkbox")), context);
Object.keys(health.advancedDefaults).forEach(function (key) { assert.strictEqual(context.dbus[key], context.advancedSettings[key], key + " is serialized by save"); });
assert.strictEqual(context.dbus.ss_basic_anytls_min_idle, "2");
assert.strictEqual(context.dbus.ss_basic_anytls_alpn, "auto");
assert.strictEqual(context.dbus.ss_basic_anytls_hosts, "node.example=alias.example,alias.example=192.0.2.1");
assert.strictEqual(context.dbus.ss_basic_bypass_macs, "02:00:00:00:00:01");
assert.strictEqual(context.dbus.ss_basic_uu_macs, "04:00:00:00:00:02");
console.log("ss-health UI: state, stale data, device policies, advanced ranges, save serialization and inline syntax passed");
