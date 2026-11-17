package cn.simon.routercontrol;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;
import org.json.JSONObject;

/** Settings contracts against a loopback router with synthetic configuration only. */
public final class RouterSettingsApiTest {
    private static int assertions;
    private static volatile Map<String, String> config;
    private static volatile Map<String, String> submitted;
    private static volatile int writes;
    private static volatile int configReads;
    private static volatile int redirectedReads;
    private static volatile int optionalReads;
    private static volatile int backupReads;
    private static volatile String configFailure = "";
    private static volatile String postFailure = "";
    private static volatile String optionalFailure = "";
    private static volatile String backupFailure = "";
    private static volatile String backupBody = "";
    private static volatile String backupMethod;
    private static volatile String backupQuery;
    private static volatile String backupCookie;
    private static volatile String postMethod;
    private static volatile String postQuery;
    private static volatile String postCookie;
    private static volatile String postRawBody;
    private static volatile String postContentType;
    private static volatile String postRequestedWith;

    private interface Throwing { void run() throws Exception; }

    private static void check(boolean value, String message) {
        assertions++;
        if (!value) throw new AssertionError(message);
    }

    private static void refuses(Throwing action, String message) throws Exception {
        int before = writes;
        try { action.run(); throw new AssertionError(message); }
        catch (IOException expected) { assertions++; }
        check(writes == before, message + ": no POST");
    }

    private static Map<String, String> map(String... entries) {
        Map<String, String> result = new LinkedHashMap<>();
        for (int i = 0; i < entries.length; i += 2) result.put(entries[i], entries[i + 1]);
        return result;
    }

    private static Map<String, String> fixture() {
        return map("ss_basic_enable", "1", "ss_basic_version_local", "4.38.3",
            "ss_basic_type", "4", "ss_basic_trojan_binary", "AnyTLS", "ssconf_basic_node", "1",
            "ss_basic_mode", "2", "ss_basic_server", "entry.example.test", "ss_basic_port", "443",
            "ss_basic_password", "c2FtcGxl", "ss_basic_allowinsecure", "0",
            "ss_basic_anytls_min_idle", "0", "ss_basic_anytls_idle_check", "30",
            "ss_basic_anytls_idle_timeout", "30", "ss_basic_anytls_handshake", "8",
            "ss_basic_anytls_alpn", "h2", "ss_basic_anytls_fingerprint", "chrome",
            "ss_basic_anytls_hosts", "entry.example.test=192.0.2.1",
            "ss_basic_bypass_macs", "02:00:00:00:00:01", "ss_basic_uu_macs", "02:00:00:00:00:02",
            "ss_basic_uu_tcp_policy", "foreign", "ss_basic_uu_interval", "5",
            "ss_basic_health_interval", "30", "ss_basic_health_timeout", "10", "ss_basic_health_failures", "3",
            "ss_basic_rule_update", "0", "ss_basic_node_update", "0",
            "ss_basic_server_resolver", "1", "ss_basic_server_resolver_user", "",
            "ss_basic_failover_enable", "0", "ss_basic_failover_country", "HK",
            "ss_basic_failover_nodes", "", "ss_basic_failover_countries", "",
            "ss_basic_failover_failures", "3", "ss_basic_failover_recoveries", "2",
            "ss_basic_failover_cooldown", "120", "ss_basic_failover_timeout", "5",
            "ss_basic_failover_budget", "60", "ss_basic_failover_direct", "1",
            "ss_basic_adblock_enable", "0", "ss_basic_adblock_domains", "", "ss_basic_adblock_allow", "",
            "ssconf_basic_name_1", "合成线路", "ssconf_basic_type_1", "4",
            "ssconf_basic_trojan_binary_1", "AnyTLS", "ssconf_basic_server_1", "entry.example.test",
            "ssconf_basic_port_1", "443", "ssconf_basic_password_1", "c2FtcGxl");
    }

    private static void reply(HttpExchange exchange, int code, String text) throws IOException {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(code, bytes.length);
        try (java.io.OutputStream output = exchange.getResponseBody()) { output.write(bytes); }
    }

    private static Map<String, String> decode(String body) throws IOException {
        Map<String, String> result = new LinkedHashMap<>();
        for (String pair : body.split("&")) {
            String[] parts = pair.split("=", 2);
            String key = URLDecoder.decode(parts[0], "UTF-8");
            if (result.containsKey(key)) throw new IOException("Duplicate submitted field");
            result.put(key, URLDecoder.decode(parts.length == 2 ? parts[1] : "", "UTF-8"));
        }
        return result;
    }

    private static void metadata(String script) {
        check("POST".equals(postMethod) && "p=ss".equals(postQuery), "fixed POST settings endpoint");
        check("asus_token=synthetic".equals(postCookie), "reuse the supplied authenticated session");
        check(script.equals(submitted.get("SystemCmd")), "allowlisted apply script");
        check(" Refresh ".equals(submitted.get("action_mode")), "firmware refresh mode");
        check("Main_Ss_Content.asp".equals(submitted.get("current_page")), "fixed firmware return page");
        check(Arrays.asList(postRawBody.split("&")).contains("action_mode=%20Refresh%20"),
            "legacy firmware receives percent-encoded spaces in the raw refresh field");
        check("XMLHttpRequest".equals(postRequestedWith), "match the original plugin Ajax request header");
        check("application/x-www-form-urlencoded".equals(postContentType), "match the exact original plugin form content type");
    }

    public static void main(String[] ignored) throws Exception {
        config = fixture();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/dbconf", exchange -> {
            configReads++;
            if ("redirect".equals(configFailure)) {
                exchange.getResponseHeaders().set("Location", "/unexpected"); reply(exchange, 302, "redirect");
            } else if ("unauthorized".equals(configFailure)) reply(exchange, 401, "expired");
            else if ("login".equals(configFailure)) reply(exchange, 200, "<html><input name='login_authorization'></html>");
            else reply(exchange, 200, "var db_ss=" + new JSONObject(config).toString() + ";");
        });
        server.createContext("/unexpected", exchange -> { redirectedReads++; reply(exchange, 200, "unexpected"); });
        server.createContext("/ss_conf_backup.txt", exchange -> {
            backupReads++;
            backupMethod = exchange.getRequestMethod(); backupQuery = exchange.getRequestURI().getRawQuery();
            backupCookie = exchange.getRequestHeaders().getFirst("Cookie");
            if ("redirect".equals(backupFailure)) {
                exchange.getResponseHeaders().set("Location", "/unexpected"); reply(exchange, 302, "redirect");
            } else if ("login".equals(backupFailure)) reply(exchange, 200, "<html><input name='login_authorization'></html>");
            else if ("chunked".equals(backupFailure)) {
                exchange.sendResponseHeaders(200, 0);
                try (java.io.OutputStream output = exchange.getResponseBody()) { output.write(backupBody.getBytes(StandardCharsets.UTF_8)); }
            } else reply(exchange, 200, backupBody);
        });
        server.createContext("/ss_status", exchange -> reply(exchange, 200, "[\"checking\",\"checking\"]"));
        server.createContext("/res/ss-health-status.js", exchange -> reply(exchange, 200,
            "{\"version\":1,\"node_id\":1,\"checked_at\":123,\"status\":\"healthy\"}"));
        server.createContext("/res/ss-failover-status.js", exchange -> {
            optionalReads++;
            reply(exchange, "missing".equals(optionalFailure) ? 404 : 200,
                "invalid".equals(optionalFailure) ? "invalid" : "wrong-version".equals(optionalFailure)
                ? "{\"version\":2,\"state\":\"idle\",\"checked_at\":123}"
                : "{\"version\":1,\"state\":\"idle\",\"mode\":\"proxy\",\"checked_at\":123}");
        });
        server.createContext("/res/ss-adblock-status.js", exchange -> {
            optionalReads++;
            reply(exchange, "missing".equals(optionalFailure) ? 404 : 200,
                "invalid".equals(optionalFailure) ? "invalid" : "wrong-version".equals(optionalFailure)
                ? "{\"version\":2,\"state\":\"off\",\"enabled\":false}"
                : "{\"version\":1,\"state\":\"off\",\"enabled\":false,\"running\":false}");
        });
        server.createContext("/applydb.cgi", exchange -> {
            writes++;
            postMethod = exchange.getRequestMethod(); postQuery = exchange.getRequestURI().getRawQuery();
            postCookie = exchange.getRequestHeaders().getFirst("Cookie");
            postContentType = exchange.getRequestHeaders().getFirst("Content-Type");
            postRequestedWith = exchange.getRequestHeaders().getFirst("X-Requested-With");
            postRawBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            submitted = decode(postRawBody);
            if ("lost".equals(postFailure)) { exchange.close(); return; }
            if ("error".equals(postFailure)) reply(exchange, 500, "unconfirmed");
            else if ("login".equals(postFailure)) reply(exchange, 200, "<input name='login_authorization'>");
            else reply(exchange, 200, "<html>applied</html>");
        });
        server.start();
        try {
            RouterApi api = new RouterApi("http://127.0.0.1:" + server.getAddress().getPort(), "asus_token=synthetic", "");
            Map<String, String> expected = fixture();
            int before = writes;
            int reads = configReads;
            api.applySettings("health", map("ss_basic_health_interval", "60"), expected);
            check(writes == before + 1 && configReads == reads + 1, "fresh authenticated configuration before one settings POST");
            metadata("ss_config.sh");
            check(submitted.keySet().equals(new TreeSet<>(Arrays.asList("ss_basic_health_interval", "SystemCmd", "action_mode", "current_page"))),
                "non-advertising settings submit only their changed field and fixed metadata");
            check("60".equals(submitted.get("ss_basic_health_interval")), "submit the requested health value");
            check(!submitted.containsKey("ss_basic_password") && !submitted.containsKey("ss_basic_mode")
                && !submitted.containsKey("ssconf_basic_node"), "do not replay unrelated global or node settings");
            for (String[] change : new String[][]{
                {"routing", "ss_basic_mode", "5"}, {"devices", "ss_basic_uu_interval", "10"},
                {"failover", "ss_basic_failover_cooldown", "180"}, {"anytls", "ss_basic_anytls_handshake", "12"}}) {
                api.applySettings(change[0], map(change[1], change[2]), fixture());
                metadata("ss_config.sh");
                check(submitted.size() == 4 && change[2].equals(submitted.get(change[1])),
                    "each non-advertising group sends only its changed field");
            }
            String resolver = "https://dns.example.test/query?first=one&second=two";
            api.applySettings("dns", map("ss_basic_server_resolver", "12", "ss_basic_server_resolver_user", resolver), fixture());
            metadata("ss_config.sh");
            check(submitted.size() == 5 && resolver.equals(submitted.get("ss_basic_server_resolver_user")),
                "preserve complete DNS URL query parameters through form encoding");
            config = fixture(); config.putAll(map("ss_acl_ip_1", "192.0.2.10", "ss_acl_mode_1", "2", "ss_acl_port_1", "all",
                "ss_acl_default_mode", "2", "ss_acl_default_port", "all"));
            api.applySettings("acl", map("ss_acl_mode_1", "5"), new LinkedHashMap<>(config));
            metadata("ss_config.sh");
            check(submitted.size() == 4 && "5".equals(submitted.get("ss_acl_mode_1")) && !submitted.containsKey("ss_acl_ip_1"),
                "edit an existing ACL policy without replaying its IP or other rules");
            Map<String, String> aclBaseline = new LinkedHashMap<>(config);
            config = new LinkedHashMap<>(aclBaseline); config.put("ss_acl_ip_1", "192.0.2.11");
            refuses(() -> api.applySettings("acl", map("ss_acl_mode_1", "5"), aclBaseline),
                "stale ACL screen cannot apply a policy to a replaced device IP");
            config = new LinkedHashMap<>(aclBaseline);
            config.putAll(map("ss_acl_ip_2", "192.0.2.20", "ss_acl_mode_2", "2", "ss_acl_port_2", "all"));
            refuses(() -> api.applySettings("acl", map("ss_acl_mode_1", "5"), aclBaseline),
                "a newly added ACL rule invalidates the displayed baseline");
            Map<String, String> twoRuleBaseline = new LinkedHashMap<>(config);
            config = new LinkedHashMap<>(aclBaseline);
            refuses(() -> api.applySettings("acl", map("ss_acl_mode_1", "5"), twoRuleBaseline),
                "a deleted ACL rule invalidates the displayed baseline");
            config = new LinkedHashMap<>(aclBaseline); config.put("ss_basic_mode", "5");
            refuses(() -> api.applySettings("acl", map("ss_acl_mode_1", "5"), aclBaseline),
                "changed global routing mode invalidates ACL default-policy assumptions");
            config = fixture();

            String domains = "ads.example.test\ntracking.example.test";
            api.applySettings("adblock", map("ss_basic_adblock_enable", "1", "ss_basic_adblock_domains", domains,
                "ss_basic_adblock_allow", "allow.example.test"), expected);
            metadata("ss_adblock.sh");
            check(submitted.keySet().equals(new TreeSet<>(Arrays.asList("ss_basic_adblock_enable", "ss_basic_adblock_domains",
                "ss_basic_adblock_allow", "SystemCmd", "action_mode", "current_page"))), "exact three-field advertising hot-save contract");
            check("1".equals(submitted.get("ss_basic_adblock_enable")), "advertising switch is part of the hot save");
            check(domains.equals(new String(Base64.getDecoder().decode(submitted.get("ss_basic_adblock_domains")), StandardCharsets.UTF_8)),
                "advertising deny list is sent as Base64 UTF-8");
            check("allow.example.test".equals(new String(Base64.getDecoder().decode(submitted.get("ss_basic_adblock_allow")), StandardCharsets.UTF_8)),
                "advertising allow list is sent as Base64 UTF-8");
            config = fixture();
            config.put("ss_basic_adblock_domains", Base64.getEncoder().encodeToString(domains.getBytes(StandardCharsets.UTF_8)));
            config.put("ss_basic_adblock_allow", Base64.getEncoder().encodeToString("allow.example.test".getBytes(StandardCharsets.UTF_8)));
            api.applySettings("adblock", map("ss_basic_adblock_enable", "1"), new LinkedHashMap<>(config));
            check(submitted.size() == 6 && "ss_adblock.sh".equals(submitted.get("SystemCmd")), "an advertising-only toggle still uses the exact hot-save shape");
            check(config.get("ss_basic_adblock_domains").equals(submitted.get("ss_basic_adblock_domains"))
                && config.get("ss_basic_adblock_allow").equals(submitted.get("ss_basic_adblock_allow")),
                "partial advertising changes preserve untouched Base64 lists without double encoding");
            for (int missing = 1; missing <= 3; missing++) {
                config = fixture();
                if ((missing & 1) != 0) config.remove("ss_basic_adblock_domains");
                if ((missing & 2) != 0) config.remove("ss_basic_adblock_allow");
                api.applySettings("adblock", map("ss_basic_adblock_enable", "1"), new LinkedHashMap<>(config));
                check(submitted.size() == 6 && "ss_adblock.sh".equals(submitted.get("SystemCmd")),
                    "omitted empty advertising fields still permit the exact hot-save contract");
                check("".equals(submitted.get("ss_basic_adblock_domains")) && "".equals(submitted.get("ss_basic_adblock_allow")),
                    "advertising toggle explicitly supplies both omitted empty Base64 lists");
            }
            before = writes;
            api.applySettings("adblock", map("ss_basic_adblock_enable", "0"), new LinkedHashMap<>(config));
            check(writes == before, "unchanged advertising switch does not materialize omitted empty list keys");
            config = fixture();
            for (String key : new String[]{"ss_basic_bypass_macs", "ss_basic_uu_macs", "ss_basic_anytls_hosts"}) config.remove(key);
            Map<String, String> emptyListsBaseline = new LinkedHashMap<>(config);
            api.applySettings("devices", map("ss_basic_uu_interval", "10"), emptyListsBaseline);
            metadata("ss_config.sh");
            check(submitted.size() == 4 && "10".equals(submitted.get("ss_basic_uu_interval"))
                && !submitted.containsKey("ss_basic_bypass_macs") && !submitted.containsKey("ss_basic_uu_macs"),
                "empty omitted MAC lists permit saving another device setting without replaying the lists");
            api.applySettings("anytls", map("ss_basic_anytls_handshake", "12"), emptyListsBaseline);
            check(submitted.size() == 4 && "12".equals(submitted.get("ss_basic_anytls_handshake"))
                && !submitted.containsKey("ss_basic_anytls_hosts"),
                "empty omitted Hosts permit saving an unrelated AnyTLS setting");
            config = fixture();
            before = writes;
            api.applySettings("health", map("ss_basic_health_interval", "30"), expected);
            api.applySettings("adblock", map("ss_basic_adblock_enable", "0", "ss_basic_adblock_domains", "", "ss_basic_adblock_allow", ""), expected);
            check(writes == before, "unchanged values do not POST or restart services");

            for (String key : new String[]{"ss_basic_health_interval", "ss_basic_enable", "ss_basic_type", "ss_basic_trojan_binary", "ssconf_basic_node"}) {
                config = fixture(); config.put(key, "ss_basic_trojan_binary".equals(key) ? "Trojan" : "0");
                refuses(() -> api.applySettings("health", map("ss_basic_health_interval", "60"), fixture()), "refuse stale baseline for " + key);
            }
            config = fixture();
            for (String key : new String[]{"unknown", "SystemCmd", "ss_basic_rule_update", "ss_basic_node_update", "ss_basic_password", "ss_basic_anytls_hosts"}) {
                refuses(() -> api.applySettings("health", map(key, "1"), fixture()), "reject foreign/injected settings key " + key);
            }
            refuses(() -> api.applySettings("unsupported", map("ss_basic_health_interval", "60"), fixture()), "reject an unknown settings group");
            refuses(() -> api.applySettings("health", null, fixture()), "reject missing changes");
            refuses(() -> api.applySettings("health", map("ss_basic_health_interval", "60"), null), "reject missing expected baseline");
            config = fixture(); config.remove("ss_basic_anytls_handshake");
            refuses(() -> api.applySettings("health", map("ss_basic_health_interval", "60"), fixture()), "reject missing base enhancement capability");
            config = fixture(); config.remove("ss_basic_adblock_enable");
            refuses(() -> api.applySettings("adblock", map("ss_basic_adblock_enable", "1"), fixture()), "reject an older plugin missing an advertising capability");
            config = fixture();
            for (String failure : new String[]{"login", "unauthorized", "redirect"}) {
                configFailure = failure;
                refuses(() -> api.applySettings("health", map("ss_basic_health_interval", "60"), fixture()), "expired/redirected baseline does not write");
            }
            check(redirectedReads == 0, "authenticated configuration requests never follow redirects");
            configFailure = "";
            for (String failure : new String[]{"login", "error", "lost"}) {
                postFailure = failure; before = writes;
                try { api.applySettings("health", map("ss_basic_health_interval", "60"), fixture()); throw new AssertionError("POST failure must be reported"); }
                catch (IOException expectedFailure) { assertions++; }
                check(writes == before + 1, "failed/unknown POST response is never retried");
            }
            postFailure = "";
            RouterApi.Snapshot state = api.load();
            check(state.failover != null && "idle".equals(state.failover.optString("state")), "read optional failover status");
            check(state.adblock != null && !state.adblock.optBoolean("enabled", true), "read optional advertising status");
            for (String failure : new String[]{"missing", "invalid", "wrong-version"}) {
                optionalFailure = failure; state = api.load();
                check(state.enabled && state.nodes.size() == 1 && state.health != null, "optional status failure preserves authenticated configuration and health");
                check(state.failover == null && state.adblock == null, "missing, malformed or unsupported optional statuses remain unavailable");
            }
            optionalFailure = ""; config = fixture();
            config.remove("ss_basic_adblock_enable"); config.remove("ss_basic_failover_enable");
            int optionalBefore = optionalReads; state = api.load();
            check(state.failover == null && state.adblock == null && optionalReads == optionalBefore,
                "older plugin reads avoid unsupported optional status endpoints");

            config = fixture(); before = writes; reads = configReads;
            int backupsBefore = backupReads;
            backupBody = "ssconf_basic_name_1=合成线路\r\nss_basic_anytls_hosts=entry.example.test=192.0.2.1\r\n";
            byte[] backup = api.exportBackup();
            check(Arrays.equals(backupBody.getBytes(StandardCharsets.UTF_8), backup), "backup preserves original UTF-8 bytes and line endings");
            check(configReads == reads + 1 && backupReads == backupsBefore + 1, "backup revalidates authenticated configuration before its fixed GET");
            check("GET".equals(backupMethod) && backupQuery == null, "backup uses the fixed text endpoint without request parameters");
            check("asus_token=synthetic".equals(backupCookie), "backup reuses authenticated session headers");
            for (String failure : new String[]{"login", "redirect"}) {
                backupFailure = failure;
                refuses(api::exportBackup, "reject login HTML or redirects returned by the backup endpoint");
            }
            check(redirectedReads == 0, "backup never follows redirects with credentials");
            backupFailure = "";
            for (String failure : new String[]{"login", "unauthorized", "redirect"}) {
                configFailure = failure; backupsBefore = backupReads;
                refuses(api::exportBackup, "expired baseline prevents backup retrieval");
                check(backupReads == backupsBefore, "an invalid session cannot reach the backup endpoint");
            }
            configFailure = "";
            backupBody = "unexpected plain text";
            refuses(api::exportBackup, "reject non-plugin text instead of exporting an invalid backup");
            char[] oversized = new char[2 * 1024 * 1024]; Arrays.fill(oversized, 'x');
            backupBody = "ss_synthetic=" + new String(oversized);
            refuses(api::exportBackup, "reject backup exceeding the declared 2 MiB response limit");
            backupFailure = "chunked";
            refuses(api::exportBackup, "enforce the backup size limit when Content-Length is unavailable");
            check(writes == before, "all backup success and failure paths are read-only");
        } finally { server.stop(0); }
        System.out.println("RouterSettingsApi: " + assertions + " assertions passed (loopback only; no physical router writes).");
    }
}
