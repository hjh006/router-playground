(function (root, factory) {
    var api = factory();
    if (typeof module === "object" && module.exports) {
        module.exports = api;
    } else {
        root.SsHealth = api;
    }
}(this, function () {
    "use strict";

    var settings = {};
    var lastData = null;
    var busy = false;
    var expiryTimer = null;
    var runtimeEnabled = false;
    var failoverBusy = false;
    var lastFailoverData = null;
    var adblockBusy = false;
    var advancedDefaults = {
        ss_basic_anytls_min_idle: "0",
        ss_basic_anytls_idle_check: "30",
        ss_basic_anytls_idle_timeout: "30",
        ss_basic_anytls_handshake: "8",
        ss_basic_anytls_alpn: "h2",
        ss_basic_anytls_fingerprint: "chrome",
        ss_basic_anytls_hosts: "",
        ss_basic_health_interval: "30",
        ss_basic_health_timeout: "10",
        ss_basic_health_failures: "3",
        ss_basic_uu_tcp_policy: "gfwlist",
        ss_basic_uu_interval: "5",
        ss_basic_adblock_enable: "0",
        ss_basic_adblock_domains: "",
        ss_basic_adblock_allow: "",
        ss_basic_failover_enable: "0",
        ss_basic_failover_country: "auto",
        ss_basic_failover_nodes: "",
        ss_basic_failover_countries: "",
        ss_basic_failover_failures: "3",
        ss_basic_failover_recoveries: "2",
        ss_basic_failover_cooldown: "120",
        ss_basic_failover_timeout: "5",
        ss_basic_failover_budget: "60",
        ss_basic_failover_direct: "1"
    };

    function number(value) {
        return typeof value === "number" && isFinite(value) && value >= 0 ? value : null;
    }

    function count(value) {
        var result = number(value);
        return result !== null && Math.floor(result) === result ? result : null;
    }

    function milliseconds(value) {
        value = number(value);
        return value === null ? "—" : Math.round(value) + " ms";
    }

    function enabled(value) {
        return value === true || value === 1 || value === "1";
    }

    function makeView(data, options) {
        options = options || {};
        var now = number(options.now);
        var isEnabled = typeof options.enabled === "undefined" ? enabled(data && data.enabled) : enabled(options.enabled);
        var view = { kind: "checking", title: "等待检测", note: "首次采样完成后显示连接状态。", data: null, age: null, historical: false };
        if (!isEnabled) {
            view.kind = "disabled";
            view.title = "代理已关闭";
            view.note = "选择节点并开启代理后开始检测。";
            return view;
        }
        if (!data || typeof data !== "object" || data.version !== 1 || !enabled(data.enabled)) {
            return view;
        }
        var checkedAt = number(data.checked_at);
        if (checkedAt === null || checkedAt === 0) {
            return view;
        }
        if (typeof options.nodeId !== "undefined" && String(options.nodeId) !== String(data.node_id)) {
            view.kind = "switching";
            view.title = "节点切换中";
            view.note = "等待当前节点的检测结果。";
            return view;
        }
        var total = count(data.total);
        var success = count(data.success);
        var countsValid = total !== null && success !== null && success <= total;
        var targets = Object.prototype.toString.call(data.targets) === "[object Array]" ? data.targets.slice(0, 8) : [];
        view.data = {
            checked_at: checkedAt,
            total: countsValid ? total : null,
            success: countsValid ? success : null,
            last_latency_ms: number(data.last_latency_ms),
            median_ms: number(data.median_ms),
            p95_ms: number(data.p95_ms),
            jitter_ms: number(data.jitter_ms),
            consecutive_failures: count(data.consecutive_failures),
            targets: targets
        };
        var interval = number(data.interval_sec) || 30;
        var staleAfter = Math.max(90, interval * 3);
        view.age = now === null ? 0 : now - checkedAt;
        if (view.age < -300 || view.age > staleAfter) {
            view.kind = "stale";
            view.title = "检测数据已过期";
            view.note = view.age < -300 ? "路由器与浏览器的时间不同步，请检查系统时间。" : "连接状态未知，下面保留上次采样结果。";
            view.historical = true;
            return view;
        }
        if (data.status === "healthy") {
            view.kind = "healthy";
            view.title = total !== null && total < 5 ? "已连通，采样中" : "连接正常";
            view.note = total !== null && total < 5 ? "样本较少，继续观察成功率与延迟波动。" : "最近的 HTTPS 连通性检测已通过。";
        } else if (data.status === "degraded") {
            view.kind = "degraded";
            view.title = "连接有波动";
            view.note = "最近检测有未通过项，正在继续确认。可在节点管理中比较其他节点。";
        } else if (data.status === "down") {
            view.kind = "down";
            var proxyUnavailable = false;
            for (var i = 0; i < targets.length; i++) {
                if (targets[i] && targets[i].state === "proxy_unavailable") { proxyUnavailable = true; }
            }
            view.title = proxyUnavailable ? "代理服务未就绪" : (view.data.consecutive_failures > 1 ? "连续检测失败" : "连接检测未通过");
            view.note = proxyUnavailable ? "暂未取得代理连接，请检查代理开关与节点状态。" : "检测已达到设定的失败次数，请检查节点或网络。";
        } else {
            view.title = "检测中";
            view.note = "正在采集 HTTPS 连通性样本。";
        }
        return view;
    }

    function normalizeMacs(raw) {
        var parts = String(raw || "").split(/[\s,]+/);
        var seen = {};
        var macs = [];
        var itemNumber = 0;
        for (var i = 0; i < parts.length; i++) {
            if (!parts[i]) {
                continue;
            }
            itemNumber++;
            var mac = parts[i].replace(/-/g, ":").toUpperCase();
            if (!/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(mac) || mac === "00:00:00:00:00:00" || (parseInt(mac.slice(0, 2), 16) & 1)) {
                return { valid: false, error: "第 " + itemNumber + " 项不是有效的设备 MAC 地址。请使用 AA:BB:CC:DD:EE:FF 格式。" };
            }
            if (!seen[mac]) {
                seen[mac] = true;
                macs.push(mac);
            }
        }
        if (macs.length > 32) {
            return { valid: false, error: "最多可设置 32 个旁路设备。" };
        }
        return { valid: true, value: macs.join(","), count: macs.length };
    }

    function normalizePolicies(bypassRaw, uuRaw) {
        var bypass = normalizeMacs(bypassRaw);
        if (!bypass.valid) {
            return { valid: false, field: "ss_basic_bypass_macs", error: bypass.error };
        }
        var uu = normalizeMacs(uuRaw);
        if (!uu.valid) {
            return { valid: false, field: "ss_basic_uu_macs", error: uu.error };
        }
        var first = bypass.value ? bypass.value.split(",") : [];
        var second = uu.value ? uu.value.split(",") : [];
        var seen = {};
        var i;
        for (i = 0; i < first.length; i++) { seen[first[i]] = true; }
        for (i = 0; i < second.length; i++) {
            if (seen[second[i]]) {
                return { valid: false, field: "ss_basic_uu_macs", error: "有设备同时出现在两组列表中。请为每台设备只保留一种网络策略。" };
            }
        }
        return { valid: true, bypass: bypass.value, uu: uu.value };
    }

    function normalizeHosts(raw) {
        var entries = String(raw || "").split(/[,\r\n]+/);
        var mappings = {};
        var sources = [];
        var count = 0;
        function endpoint(value) {
            value = value.replace(/^\s+|\s+$/g, "").toLowerCase();
            if (!value || value.length > 254 || /[^a-z0-9.\-]/.test(value)) { return null; }
            if (/^[0-9.]+$/.test(value)) {
                var octets = value.split(".");
                if (octets.length !== 4) { return null; }
                for (var n = 0; n < octets.length; n++) {
                    if (!/^(0|[1-9][0-9]{0,2})$/.test(octets[n]) || Number(octets[n]) > 255) { return null; }
                }
                return value;
            }
            value = value.replace(/\.$/, "");
            if (value.length > 253) { return null; }
            var labels = value.split(".");
            for (var j = 0; j < labels.length; j++) {
                if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(labels[j])) { return null; }
            }
            return value;
        }
        for (var i = 0; i < entries.length; i++) {
            var entry = entries[i].replace(/^\s+|\s+$/g, "");
            if (!entry) { continue; }
            count++;
            if (count > 32) { return { valid: false, error: "Hosts 映射最多可填写 32 条。" }; }
            var pair = entry.split("=");
            var source = pair.length === 2 ? endpoint(pair[0]) : null;
            var target = pair.length === 2 ? endpoint(pair[1]) : null;
            if (source === null || target === null) {
                return { valid: false, error: "第 " + count + " 条 Hosts 映射格式有误。请填写 ASCII 域名或 IPv4，使用 原域名=目标域名或IPv4 格式。" };
            }
            if (Object.prototype.hasOwnProperty.call(mappings, "@" + source)) {
                if (mappings["@" + source] !== target) { return { valid: false, error: "同一来源有不同的 Hosts 映射目标，请保留一个目标。" }; }
            } else {
                sources.push(source);
                mappings["@" + source] = target;
            }
        }
        var canonical = [];
        for (i = 0; i < sources.length; i++) {
            var current = sources[i];
            var visited = {};
            var hops = 0;
            while (Object.prototype.hasOwnProperty.call(mappings, "@" + current)) {
                if (visited["@" + current]) { return { valid: false, error: "Hosts 映射存在循环，请移除指向自身或相互引用的条目。" }; }
                visited["@" + current] = true;
                current = mappings["@" + current];
                hops++;
                if (hops > 4) { return { valid: false, error: "Hosts 映射最多允许连续转换 4 次，请缩短映射链。" }; }
            }
            canonical.push(sources[i] + "=" + mappings["@" + sources[i]]);
        }
        return { valid: true, value: canonical.join(","), count: sources.length };
    }

    function normalizeAdvanced(values) {
        values = values || {};
        var result = {};
        var rules = [
            ["ss_basic_anytls_min_idle", 0, 20, "最少空闲连接"],
            ["ss_basic_anytls_idle_check", 5, 300, "空闲连接检查间隔"],
            ["ss_basic_anytls_idle_timeout", 5, 600, "空闲连接回收时间"],
            ["ss_basic_anytls_handshake", 3, 20, "握手超时"],
            ["ss_basic_health_failures", 1, 5, "连续失败判定次数"],
            ["ss_basic_uu_interval", 2, 30, "UU 规则检查间隔"],
            ["ss_basic_failover_failures", 1, 5, "线路连续失败次数"],
            ["ss_basic_failover_recoveries", 1, 3, "候选连续成功次数"],
            ["ss_basic_failover_cooldown", 30, 600, "切换冷却时间"],
            ["ss_basic_failover_timeout", 3, 8, "候选检测超时"],
            ["ss_basic_failover_budget", 20, 120, "每轮检测预算"]
        ];
        var i, key, value;
        for (i = 0; i < rules.length; i++) {
            key = rules[i][0];
            value = String(typeof values[key] === "undefined" ? advancedDefaults[key] : values[key]).replace(/^\s+|\s+$/g, "");
            if (!/^\d+$/.test(value) || Number(value) < rules[i][1] || Number(value) > rules[i][2]) {
                return { valid: false, field: key, error: rules[i][3] + "须为 " + rules[i][1] + "–" + rules[i][2] + " 之间的整数。" };
            }
            result[key] = String(Number(value));
        }
        var choices = [
            ["ss_basic_health_interval", ["30", "60", "120"], "检测间隔须选择 30、60 或 120 秒。"],
            ["ss_basic_health_timeout", ["6", "8", "10"], "单目标超时须选择 6、8 或 10 秒。"],
            ["ss_basic_anytls_fingerprint", ["chrome", "standard"], "请选择 Chrome 或标准 TLS 指纹。"],
            ["ss_basic_uu_tcp_policy", ["gfwlist", "foreign", "direct"], "请选择有效的 UU 设备 TCP 策略。"],
            ["ss_basic_failover_enable", ["0", "1"], "请选择是否启用自动故障切换。"],
            ["ss_basic_failover_direct", ["0", "1"], "请选择是否启用直连保护。"]
        ];
        for (i = 0; i < choices.length; i++) {
            key = choices[i][0];
            value = String(typeof values[key] === "undefined" ? advancedDefaults[key] : values[key]);
            var allowed = false;
            for (var j = 0; j < choices[i][1].length; j++) {
                if (value === choices[i][1][j]) { allowed = true; }
            }
            if (!allowed) { return { valid: false, field: key, error: choices[i][2] }; }
            result[key] = value;
        }
        key = "ss_basic_anytls_alpn";
        value = String(typeof values[key] === "undefined" ? advancedDefaults[key] : values[key]).replace(/^\s+|\s+$/g, "");
        var protocols = value ? value.split(",") : [];
        var normalized = [];
        var seen = {};
        for (i = 0; i < protocols.length; i++) {
            value = protocols[i].replace(/^\s+|\s+$/g, "");
            if (value !== "h2" && value !== "http/1.1") {
                return { valid: false, field: key, error: "ALPN 仅支持 h2、http/1.1，用逗号分隔；留空使用自动协商。" };
            }
            if (!seen[value]) { normalized.push(value); seen[value] = true; }
        }
        result[key] = normalized.length ? normalized.join(",") : "auto";
        key = "ss_basic_anytls_hosts";
        var hosts = normalizeHosts(typeof values[key] === "undefined" ? advancedDefaults[key] : values[key]);
        if (!hosts.valid) { return { valid: false, field: key, error: hosts.error }; }
        result[key] = hosts.value;
        key = "ss_basic_failover_country";
        value = String(typeof values[key] === "undefined" ? advancedDefaults[key] : values[key]).replace(/^\s+|\s+$/g, "");
        value = value.toLowerCase() === "auto" ? "auto" : value.toUpperCase();
        if (value !== "auto" && !/^[A-Z]{2}$/.test(value)) {
            return { valid: false, field: key, error: "优先国家/地区请填 auto 或两位代码，例如 HK、JP。" };
        }
        result[key] = value;
        key = "ss_basic_failover_nodes";
        var nodes = normalizeNodeIds(typeof values[key] === "undefined" ? advancedDefaults[key] : values[key]);
        if (!nodes.valid) { return { valid: false, field: key, error: nodes.error }; }
        result[key] = nodes.value;
        key = "ss_basic_failover_countries";
        var countries = normalizeCountries(typeof values[key] === "undefined" ? advancedDefaults[key] : values[key]);
        if (!countries.valid) { return { valid: false, field: key, error: countries.error }; }
        result[key] = countries.value;
        if (Number(result.ss_basic_failover_budget) < 3 * Number(result.ss_basic_failover_timeout) + 8) {
            return { valid: false, field: "ss_basic_failover_budget", error: "每轮预算须至少为 3 × 候选超时 + 8 秒，请增加预算或降低超时。" };
        }
        var advertising = normalizeAdblock(values);
        if (!advertising.valid) { return advertising; }
        for (key in advertising.values) {
            if (Object.prototype.hasOwnProperty.call(advertising.values, key)) { result[key] = advertising.values[key]; }
        }
        return { valid: true, values: result };
    }

    var adblockProtected = ["doubleclick.net", "googlesyndication.com", "googleadservices.com", "googletagservices.com", "google-analytics.com", "googletagmanager.com", "youtube.com", "youtube-nocookie.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com", "googleapis.com", "gvt1.com", "gvt2.com", "gstatic.com", "google.com", "playstation.com", "playstation.net", "sonyentertainmentnetwork.com", "sony.com", "sony.net", "163.com", "126.net", "netease.com", "uux.cn", "localhost", "local", "localdomain", "lan", "home", "home.arpa", "router.asus.com", "asusrouter.com", "routerlogin.net", "routerlogin.com"];

    function normalizeAdblockDomains(raw, blocking) {
        raw = String(typeof raw === "undefined" ? "" : raw);
        if (raw.length > 8192 || /[^\x00-\x7f]/.test(raw)) {
            return { valid: false, error: "列表仅支持 ASCII 域名，最多 8192 字节。" };
        }
        var lines = raw.split("\n"), domains = [], seen = {}, entries = 0;
        function suffix(child, parent) { return child === parent || child.slice(-(parent.length + 1)) === "." + parent; }
        for (var i = 0; i < lines.length; i++) {
            var domain = lines[i].replace(/\r$/, "").replace(/^[ \t]+|[ \t]+$/g, "").toLowerCase();
            if (!domain) { continue; }
            entries++;
            if (entries > 256) { return { valid: false, error: "每个列表最多 256 个非空行。" }; }
            var labels = domain.split("."), valid = labels.length >= 2 && domain.length <= 253 && /[a-z]/.test(labels[labels.length - 1]);
            for (var j = 0; j < labels.length; j++) {
                if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(labels[j])) { valid = false; }
            }
            if (!valid) { return { valid: false, error: "第 " + entries + " 行请填写完整 ASCII 域名；不支持 IP、网址、通配符或尾点。" }; }
            if (blocking) {
                for (j = 0; j < adblockProtected.length; j++) {
                    if (suffix(domain, adblockProtected[j]) || suffix(adblockProtected[j], domain)) {
                        return { valid: false, error: "第 " + entries + " 行覆盖了受保护的联网服务或本地域名，请从屏蔽列表移除。" };
                    }
                }
            }
            if (!Object.prototype.hasOwnProperty.call(seen, domain)) { seen[domain] = true; domains.push(domain); }
        }
        return { valid: true, value: domains.join("\n"), count: domains.length };
    }

    function normalizeAdblock(values) {
        values = values || {};
        var key = "ss_basic_adblock_enable", result = {};
        var value = String(typeof values[key] === "undefined" ? advancedDefaults[key] : values[key]);
        if (value !== "0" && value !== "1") { return { valid: false, field: key, error: "请选择是否启用域名广告过滤。" }; }
        result[key] = value;
        var keys = ["ss_basic_adblock_domains", "ss_basic_adblock_allow"];
        for (var i = 0; i < keys.length; i++) {
            key = keys[i];
            var list = normalizeAdblockDomains(typeof values[key] === "undefined" ? "" : values[key], i === 0);
            if (!list.valid) { return { valid: false, field: key, error: list.error }; }
            result[key] = list.value;
        }
        return { valid: true, values: result };
    }

    function makeAdblockView(data) {
        var view = { kind: "checking", title: "广告过滤状态待确认", note: "仅随路由器代理运行；直连保护或代理关闭时暂停。", summary: "" };
        if (!data || data.version !== 1 || typeof data.enabled !== "boolean" || typeof data.running !== "boolean") { return view; }
        if (data.state === "error") {
            view.kind = "down"; view.title = "广告过滤未成功应用"; view.note = "请检查列表或插件日志后重试。";
        } else if (data.state === "active" && data.enabled && data.running) {
            view.kind = "healthy"; view.title = "域名广告过滤运行中"; view.note = "覆盖普通 IPv4 DNS；自带 VPN 旁路和 UU 共存设备已排除。";
        } else if (data.state === "draining" && data.enabled && data.running) {
            view.title = "等待旧DNS连接释放"; view.note = "先保持直通，释放后应用新的设备排除策略。";
        } else if (data.state === "off" && data.running) {
            view.kind = "disabled"; view.title = "广告过滤已关闭"; view.note = "仅保留现有DNS连接的兼容转发，空闲后自动退出。";
        } else if (data.state === "off" && !data.running) {
            view.kind = "disabled"; view.title = data.enabled ? "设置已开启，等待代理运行" : "域名广告过滤已关闭";
        }
        var domains = count(data.domains), devices = count(data.excluded_devices), summary = [];
        if (data.state === "off" || data.state === "draining") { domains = 0; }
        if (domains !== null && domains <= 4096) { summary.push("生效域名 " + domains); }
        if (devices !== null && devices <= 64) { summary.push("排除设备 " + devices); }
        view.summary = summary.join("；");
        return view;
    }

    function renderAdblock(view) {
        var container = element("ss_adblock_status");
        if (!container) { return; }
        container.className = "ss-health ss-health-" + view.kind;
        text("ss_adblock_title", view.title); text("ss_adblock_note", view.note); text("ss_adblock_summary", view.summary);
    }

    function refreshAdblock() {
        if (!element("ss_adblock_status") || adblockBusy || typeof window === "undefined" || !window.jQuery) { return; }
        adblockBusy = true;
        window.jQuery.ajax({
            url: "/res/ss-adblock-status.js", dataType: "json", cache: false, timeout: 5000,
            success: function (data) { renderAdblock(makeAdblockView(data)); },
            error: function () { renderAdblock({ kind: "unavailable", title: "暂时无法读取广告过滤状态", note: "是否生效待确认，稍后自动重试。", summary: "" }); },
            complete: function () { adblockBusy = false; }
        });
    }

    function normalizeNodeIds(raw) {
        var parts = String(raw || "").split(/[\s,]+/);
        var ids = [], seen = {};
        for (var i = 0; i < parts.length; i++) {
            if (!parts[i]) { continue; }
            if (!/^[0-9]{1,6}$/.test(parts[i]) || Number(parts[i]) < 1) {
                return { valid: false, error: "候选节点请填写 1–999999 的节点 ID，用逗号或换行分隔；留空包含所有有效 AnyTLS 节点。" };
            }
            var id = String(Number(parts[i]));
            if (!seen[id]) { seen[id] = true; ids.push(id); }
            if (ids.length > 128) { return { valid: false, error: "候选节点最多 128 个。" }; }
        }
        return { valid: true, value: ids.join(","), count: ids.length };
    }

    function normalizeCountries(raw) {
        var lines = String(raw || "").split(/[,\r\n]+/);
        var values = {}, ids = [], entries = 0;
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].replace(/^\s+|\s+$/g, "");
            if (!line) { continue; }
            entries++;
            var pair = /^([0-9]{1,6})\s*=\s*([A-Za-z]{2})$/.exec(line);
            if (!pair || Number(pair[1]) < 1) {
                return { valid: false, error: "国家/地区映射请使用 节点ID=两位代码，例如 1=HK，每行一条。" };
            }
            if (entries > 128) { return { valid: false, error: "国家/地区映射最多 128 条。" }; }
            var id = String(Number(pair[1])), country = pair[2].toUpperCase();
            if (Object.prototype.hasOwnProperty.call(values, id)) {
                if (values[id] !== country) { return { valid: false, error: "同一个节点 ID 不能对应不同国家/地区。" }; }
            } else { ids.push(id); values[id] = country; }
        }
        var normalized = [];
        for (i = 0; i < ids.length; i++) { normalized.push(ids[i] + "=" + values[ids[i]]); }
        return { valid: true, value: normalized.join(","), count: ids.length };
    }

    function makeFailoverView(data, options) {
        options = options || {};
        var view = { kind: "checking", title: "等待自动切换状态", note: "后台每分钟检查；管理页面无需一直打开。", summary: "", checkedAt: null, currentNode: null };
        if (typeof options.enabled !== "undefined" && !enabled(options.enabled)) {
            view.kind = "disabled"; view.title = "代理已关闭";
            view.note = "自动切换不会重新开启手动关闭的代理。"; return view;
        }
        if (typeof options.configured !== "undefined" && !enabled(options.configured)) {
            view.kind = "disabled"; view.title = "自动故障切换未开启";
            view.note = "可在附加功能中配置同地区优先、候选节点及直连保护。"; return view;
        }
        if (!data || typeof data !== "object" || data.version !== 1) { return view; }
        var checkedAt = number(data.checked_at), now = number(options.now);
        if (checkedAt === null || checkedAt === 0) { return view; }
        view.checkedAt = checkedAt;
        if (now !== null && (now - checkedAt > 240 || checkedAt - now > 300)) {
            view.kind = "stale"; view.title = "自动切换状态已过期";
            view.note = "当前状态未知，请稍后刷新；不要据此判断网络已恢复。"; return view;
        }
        var states = {
            disabled: ["disabled", "自动故障切换已停止", "手动开启代理和自动切换后才会运行。"],
            healthy: ["healthy", "当前线路可用", "继续使用当前线路；故障时优先检测同国家/地区候选。"],
            confirming: ["degraded", "正在确认线路故障", "达到连续失败阈值后再切换，避免单次抖动触发换线。"],
            scanning_direct: ["degraded", "直连保护 · 检测候选中", "正在分批检测同国家/地区，再检测其他地区；未检测节点不算故障。"],
            scanning_proxy: ["degraded", "正在检测备用线路", "当前保留代理路径；先完成同国家/地区检测，再比较其他地区。"],
            recovering: ["checking", "候选线路恢复确认中", "候选需连续检测成功后才切回代理，避免反复切换。"],
            direct: ["degraded", "直连保护中", "暂无已确认可用线路，后台继续检测。只保障原本可直连的服务，受限网站仍需可用代理。"],
            switched: ["healthy", "已切换线路", "新的连接使用当前线路；已有连接可能需要重试。"],
            cooldown: ["checking", "切换冷却中", "等待冷却期结束后继续评估，避免频繁换线。"],
            error: ["down", "自动切换需要检查", "未能确认策略执行成功，请查看插件日志；不要把此状态当作网络已恢复。"]
        };
        if (typeof data.state === "string" && Object.prototype.hasOwnProperty.call(states, data.state)) {
            view.kind = states[data.state][0]; view.title = states[data.state][1]; view.note = states[data.state][2];
        }
        if (data.mode === "direct" && (data.state === "healthy" || data.state === "switched" || data.state === "cooldown")) {
            view.kind = states.direct[0]; view.title = states.direct[1]; view.note = states.direct[2];
        }
        if (data.mode === "error") {
            view.kind = "down"; view.title = "网络路径恢复待确认";
            view.note = "直连或代理路径尚未确认恢复，请查看插件日志并检查普通网站。";
        }
        var node = typeof data.current_node === "string" || typeof data.current_node === "number" ? String(data.current_node) : "";
        if (/^[0-9]{1,6}$/.test(node) && Number(node) > 0) { view.currentNode = String(Number(node)); }
        var country = typeof data.country === "string" && /^[A-Z]{2}$/.test(data.country) && data.country !== "XX" ? data.country : "未识别";
        var preferred = typeof data.preferred_country === "string" && /^[A-Z]{2}$/.test(data.preferred_country) && data.preferred_country !== "XX" ? data.preferred_country : "自动";
        var summary = [];
        if (data.mode === "proxy" || data.mode === "direct") { summary.push(data.mode === "direct" ? "当前路径 直连" : "当前路径 代理"); }
        if (view.currentNode !== null) { summary.push("当前节点 ID " + view.currentNode + " · " + country); }
        summary.push("优先地区 " + preferred);
        var scanned = count(data.scanned), total = count(data.total);
        if (scanned !== null && total !== null && scanned <= total && total <= 128) { summary.push("已检测 " + scanned + " / " + total + " 个候选"); }
        if (number(data.best_ms) !== null) { summary.push("候选 HTTPS " + milliseconds(data.best_ms)); }
        var failures = count(data.failures);
        if (failures !== null && failures <= 99) { summary.push("连续失败 " + failures + " 轮"); }
        view.summary = summary.join("；");
        return view;
    }

    function renderFailover(view) {
        var container = element("ss_failover_status");
        if (!container) { return; }
        container.className = "ss-health ss-health-" + view.kind;
        text("ss_failover_title", view.title);
        text("ss_failover_note", view.note);
        text("ss_failover_summary", view.summary);
        text("ss_failover_time", view.checkedAt ? "上次检查 " + timeLabel(view.checkedAt) : "");
    }

    function refreshFailover() {
        if (!runtimeEnabled || !enabled(settings.failoverEnabled)) {
            lastFailoverData = null;
            renderFailover(makeFailoverView(null, { enabled: runtimeEnabled, configured: settings.failoverEnabled }));
            return;
        }
        if (failoverBusy || typeof window === "undefined" || !window.jQuery) { return; }
        failoverBusy = true;
        window.jQuery.ajax({
            url: settings.failoverUrl || "/res/ss-failover-status.js", dataType: "json", cache: false, timeout: 5000,
            success: function (data) {
                lastFailoverData = data && data.version === 1 ? data : null;
                renderFailover(makeFailoverView(lastFailoverData, { enabled: runtimeEnabled, configured: settings.failoverEnabled, now: new Date().getTime() / 1000 }));
            },
            error: function () {
                lastFailoverData = null;
                renderFailover({ kind: "unavailable", title: "暂时无法读取自动切换状态", note: "后台状态未知，稍后自动重试。", summary: "", checkedAt: null });
            },
            complete: function () { failoverBusy = false; }
        });
    }

    function activeNode(data) {
        var current = makeFailoverView(lastFailoverData, { enabled: runtimeEnabled, configured: settings.failoverEnabled, now: new Date().getTime() / 1000 });
        if (enabled(settings.failoverEnabled) && current.currentNode !== null && data && (typeof data.node_id === "string" || typeof data.node_id === "number") && String(data.node_id) === current.currentNode) { return current.currentNode; }
        return settings.nodeId;
    }

    function activeNodeLabel(data) {
        var id = activeNode(data);
        if (String(id) === String(settings.nodeId)) { return settings.nodeLabel || ""; }
        var label = typeof settings.nodeLabelForId === "function" ? settings.nodeLabelForId(id) : "";
        return label || "节点 ID " + id;
    }

    function element(id) {
        return typeof document === "undefined" ? null : document.getElementById(id);
    }

    function text(id, value) {
        var el = element(id);
        if (el) {
            value = String(value);
            var current = typeof el.textContent !== "undefined" ? el.textContent : el.innerText;
            if (current === value) { return; }
            if (typeof el.textContent !== "undefined") {
                el.textContent = value;
            } else {
                el.innerText = value;
            }
        }
    }

    function timeLabel(checkedAt) {
        var date = new Date(checkedAt * 1000);
        if (isNaN(date.getTime())) { return "时间未知"; }
        function two(value) { return value < 10 ? "0" + value : String(value); }
        return two(date.getHours()) + ":" + two(date.getMinutes()) + ":" + two(date.getSeconds());
    }

    function targetLabel(target, index) {
        var labels = { google: "Google HTTPS", gstatic: "Gstatic HTTPS", youtube: "YouTube HTTPS", telegram: "Telegram HTTPS", domestic: "国内 HTTPS", proxy: "代理服务" };
        if (labels[target.id]) {
            return labels[target.id];
        }
        return typeof target.label === "string" && target.label.length <= 40 && !/[<>&@]|:\/\//.test(target.label) ? target.label : "检测目标 " + (index + 1);
    }

    function renderTargets(view) {
        var container = element("ss_health_targets");
        if (!container) {
            return;
        }
        while (container.firstChild) {
            container.removeChild(container.firstChild);
        }
        var states = { ok: "通过", timeout: "超时", tls_error: "TLS 连接失败", dns_error: "域名解析失败", network_error: "连接失败", http_error: "响应异常", local_error: "本地检测未就绪", proxy_unavailable: "代理服务未就绪", checking: "检测中" };
        var targets = view.data ? view.data.targets : [];
        for (var i = 0; i < targets.length; i++) {
            var target = targets[i];
            if (!target || typeof target !== "object") {
                continue;
            }
            var row = document.createElement("span");
            row.className = "ss-health-target";
            var label = document.createElement("span");
            label.className = "ss-health-target-name";
            label.appendChild(document.createTextNode(targetLabel(target, i)));
            row.appendChild(label);
            var state = states[target.state] || "状态未知";
            if (view.historical) {
                state = "上次" + state;
            }
            var latency = number(target.latency_ms);
            if (target.state === "ok" && latency !== null) {
                state += " · " + milliseconds(latency);
            } else if (target.state === "http_error" && count(target.http_code) >= 100 && target.http_code <= 599) {
                state += " · HTTP " + target.http_code;
            }
            row.appendChild(document.createTextNode(" " + state));
            container.appendChild(row);
        }
    }

    function render(view) {
        var container = element("ss_health");
        if (!container) {
            return;
        }
        container.className = "ss-health ss-health-" + view.kind;
        text("ss_health_title", view.title);
        text("ss_health_note", view.note);
        var nodeLabel = activeNodeLabel(lastData);
        text("ss_health_node", nodeLabel ? "当前节点 " + nodeLabel : "");
        text("ss_health_time", view.data ? "上次采样 " + timeLabel(view.data.checked_at) : "");
        var data = view.data;
        text("ss_health_latency", milliseconds(data && data.last_latency_ms));
        var total = data && data.total;
        var success = data && data.success;
        text("ss_health_success", total > 0 && success !== null ? Math.round(success * 1000 / total) / 10 + "%" : "—");
        text("ss_health_rate_label", total > 0 ? "最近 " + total + " 轮完整通过率" : "完整通过率");
        text("ss_health_sample_count", total > 0 && success !== null ? success + " / " + total + " 轮完整通过" : "等待采样");
        text("ss_health_p95", milliseconds(data && data.p95_ms));
        text("ss_health_jitter", milliseconds(data && data.jitter_ms));
        var median = data && data.median_ms;
        text("ss_health_median", median !== null && typeof median !== "undefined" ? "中位延迟 " + milliseconds(median) : "");
        renderTargets(view);
        var legacy = element("ss_health_legacy");
        var legacyForeign = element("ss_health_legacy_foreign");
        var legacyLabel = element("ss_health_legacy_label");
        if (legacy) { legacy.style.display = view.kind === "disabled" ? "none" : ""; }
        if (legacyForeign) { legacyForeign.style.display = data ? "none" : ""; }
        if (legacyLabel) { legacyLabel.style.display = data ? "none" : ""; }
    }

    function showUnavailable() {
        render({ kind: "unavailable", title: "暂时无法读取检测状态", note: "连接状态未知，稍后会自动重试。下方保留旧版检测供参考。", data: null, age: null, historical: false });
    }

    function refresh(isEnabled) {
        if (typeof isEnabled !== "undefined") {
            runtimeEnabled = enabled(isEnabled);
        }
        refreshFailover();
        refreshAdblock();
        if (!runtimeEnabled) {
            lastData = null;
            render(makeView(null, { enabled: false }));
            return;
        }
        if (busy || typeof window === "undefined" || !window.jQuery) {
            return;
        }
        busy = true;
        window.jQuery.ajax({
            url: settings.url || "/res/ss-health-status.js",
            dataType: "json",
            cache: false,
            timeout: 5000,
            success: function (data) {
                if (!data || data.version !== 1) {
                    lastData = null;
                    showUnavailable();
                    return;
                }
                lastData = data;
                render(makeView(data, { enabled: runtimeEnabled, nodeId: activeNode(data), now: new Date().getTime() / 1000 }));
            },
            error: function () {
                lastData = null;
                showUnavailable();
            },
            complete: function () { busy = false; }
        });
    }

    function start(options) {
        settings = options || {};
        runtimeEnabled = enabled(settings.enabled);
        lastData = null;
        lastFailoverData = null;
        render(makeView(null, { enabled: runtimeEnabled }));
        renderFailover(makeFailoverView(null, { enabled: runtimeEnabled, configured: settings.failoverEnabled }));
        renderAdblock(enabled(settings.adblockEnabled) ? makeAdblockView(null) : makeAdblockView({ version: 1, enabled: false, running: false, state: "off", domains: 0, excluded_devices: 0 }));
        if (expiryTimer !== null && typeof window !== "undefined") {
            window.clearInterval(expiryTimer);
        }
        if (typeof window !== "undefined") {
            expiryTimer = window.setInterval(function () {
                if (lastData && runtimeEnabled) {
                    render(makeView(lastData, { enabled: true, nodeId: activeNode(lastData), now: new Date().getTime() / 1000 }));
                }
                if (lastFailoverData) { renderFailover(makeFailoverView(lastFailoverData, { enabled: runtimeEnabled, configured: settings.failoverEnabled, now: new Date().getTime() / 1000 })); }
            }, 5000);
        }
    }

    return { buildVersion: "4.38.3-r7000.5", start: start, refresh: refresh, refreshAdblock: refreshAdblock, makeView: makeView, makeFailoverView: makeFailoverView, makeAdblockView: makeAdblockView, milliseconds: milliseconds, normalizeMacs: normalizeMacs, normalizePolicies: normalizePolicies, normalizeHosts: normalizeHosts, normalizeAdblock: normalizeAdblock, normalizeAdblockDomains: normalizeAdblockDomains, normalizeNodeIds: normalizeNodeIds, normalizeCountries: normalizeCountries, normalizeAdvanced: normalizeAdvanced, advancedDefaults: advancedDefaults };
}));
