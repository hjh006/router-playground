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
        ss_basic_health_failures: "3"
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
            ["ss_basic_health_failures", 1, 5, "连续失败判定次数"]
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
            ["ss_basic_anytls_fingerprint", ["chrome", "standard"], "请选择 Chrome 或标准 TLS 指纹。"]
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
        return { valid: true, values: result };
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
        text("ss_health_node", settings.nodeLabel ? "当前节点 " + settings.nodeLabel : "");
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
                render(makeView(data, { enabled: runtimeEnabled, nodeId: settings.nodeId, now: new Date().getTime() / 1000 }));
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
        render(makeView(null, { enabled: runtimeEnabled }));
        if (expiryTimer !== null && typeof window !== "undefined") {
            window.clearInterval(expiryTimer);
        }
        if (typeof window !== "undefined") {
            expiryTimer = window.setInterval(function () {
                if (lastData && runtimeEnabled) {
                    render(makeView(lastData, { enabled: true, nodeId: settings.nodeId, now: new Date().getTime() / 1000 }));
                }
            }, 5000);
        }
    }

    return { start: start, refresh: refresh, makeView: makeView, milliseconds: milliseconds, normalizeMacs: normalizeMacs, normalizePolicies: normalizePolicies, normalizeHosts: normalizeHosts, normalizeAdvanced: normalizeAdvanced, advancedDefaults: advancedDefaults };
}));
