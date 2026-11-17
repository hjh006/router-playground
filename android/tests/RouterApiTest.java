package cn.simon.routercontrol;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONObject;

/** JVM contract tests against a loopback-only fake router, never the physical device. */
public final class RouterApiTest {
    private static int assertions;
    private static String config;
    private static String postBody;
    private static String cookie;
    private static String auth;
    private static int postCount;
    private static int statusCount;
    private static boolean statusMissing;
    private static boolean redirect;
    private static boolean healthMissing;
    private static boolean loginPost;

    private static void check(boolean passed, String message) {
        assertions++;
        if (!passed) throw new AssertionError(message);
    }

    private interface Throwing { void run() throws Exception; }
    private static void fails(Throwing action, String message) throws Exception {
        try { action.run(); throw new AssertionError(message); }
        catch (IOException expected) { assertions++; }
    }

    private static String fixture() {
        return "var db_ss = {"
                + "\"ss_basic_enable\":\"1\",\"ss_basic_version_local\":\"4.38.3\","
                + "\"ssconf_basic_node\":\"1\",\"ss_basic_mode\":\"2\","
                + "\"ss_basic_type\":\"4\",\"ss_basic_trojan_binary\":\"AnyTLS\","
                + "\"ss_basic_use_kcp\":\"1\",\"ss_basic_anytls_hosts\":\"preserve.example=10.1.2.3\","
                + "\"ss_basic_anytls_min_idle\":\"0\",\"ss_basic_anytls_idle_check\":\"30\","
                + "\"ss_basic_anytls_idle_timeout\":\"30\",\"ss_basic_anytls_handshake\":\"8\","
                + "\"ss_basic_anytls_alpn\":\"h2\",\"ss_basic_anytls_fingerprint\":\"chrome\","
                + "\"ss_basic_health_interval\":\"30\",\"ss_basic_health_timeout\":\"10\",\"ss_basic_health_failures\":\"3\","
                + "\"ss_basic_bypass_macs\":\"private\",\"ss_basic_uu_macs\":\"private\","
                + "\"ss_basic_rule_update\":\"0\",\"ss_basic_node_update\":\"0\","
                + "\"ssconf_basic_name_2\":\"备用线路\",\"ssconf_basic_type_2\":\"4\","
                + "\"ssconf_basic_trojan_binary_2\":\"AnyTLS\",\"ssconf_basic_server_2\":\"node.example.test\","
                + "\"ssconf_basic_port_2\":\"443\",\"ssconf_basic_password_2\":\"c2FtcGxl\","
                + "\"ssconf_basic_trojan_sni_2\":\"sni.example.test\",\"ssconf_basic_mode_2\":\"5\","
                + "\"ssconf_basic_allowinsecure_2\":\"0\","
                + "\"ssconf_basic_name_1\":\"主线路\",\"ssconf_basic_type_1\":\"4\","
                + "\"ssconf_basic_trojan_binary_1\":\"AnyTLS\",\"ssconf_basic_server_1\":\"main.example.test\","
                + "\"ssconf_basic_port_1\":\"443\",\"ssconf_basic_password_1\":\"c2FtcGxl\","
                + "\"ssconf_basic_name_3\":\"其他协议\",\"ssconf_basic_type_3\":\"4\","
                + "\"ssconf_basic_trojan_binary_3\":\"Trojan\"};";
    }

    private static String iifeFixture() throws Exception {
        StringBuilder text = new StringBuilder("var db_ss=(function() {\nvar o={};\n");
        for (Map.Entry<String, String> entry : RouterApi.parseConfig(fixture()).entrySet()) {
            text.append("o[").append(JSONObject.quote(entry.getKey())).append("]=")
                    .append(JSONObject.quote(entry.getValue())).append(";\n");
        }
        return text.append("return o;\n})();\n").toString();
    }

    private static void reply(HttpExchange exchange, int status, String text) throws IOException {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (java.io.OutputStream out = exchange.getResponseBody()) { out.write(bytes); }
    }

    private static Map<String, String> decode(String body) throws Exception {
        Map<String, String> fields = new LinkedHashMap<>();
        for (String pair : body.split("&")) {
            String[] kv = pair.split("=", 2);
            fields.put(URLDecoder.decode(kv[0], "UTF-8"), URLDecoder.decode(kv[1], "UTF-8"));
        }
        return fields;
    }

    public static void main(String[] ignored) throws Exception {
        check("http://192.168.1.1".equals(RouterApi.validateBaseUrl("http://192.168.1.1/")), "normalize root slash");
        check("http://192.168.1.1".equals(RouterApi.validateBaseUrl("192.168.1.1")), "accept bare LAN IPv4");
        check("http://192.168.1.1:8080".equals(RouterApi.validateBaseUrl("192.168.1.1:8080/")), "accept bare LAN IPv4 port");
        fails(() -> RouterApi.validateBaseUrl("8.8.8.8"), "bare public IPv4 remains blocked");
        check("https://router.example:8443".equals(RouterApi.validateBaseUrl("https://router.example:8443")), "HTTPS supported");
        for (String bad : new String[]{"http://example.com", "http://8.8.8.8", "http://192.168.1.1@evil.test", "http://user:pass@192.168.1.1", "http://192.168.1.1/path", "http://192.168.1.1?x=1", "http://192.168.1.1#x", "file:///tmp/x", "http://192.168.1.1:0", "http://192.168.1.1:65536", "http://192.168.1.01"}) {
            fails(() -> RouterApi.validateBaseUrl(bad), "reject unsafe address");
        }
        Map<String, String> parsed = RouterApi.parseConfig("\ufeff /* data */ var db_ss = {'ss_basic_enable':'1',name:'\\u9999\\u6e2f \\x30\\x31', escaped:'a\\\\b\\\'c\\n'}; // end");
        check("香港 01".equals(parsed.get("name")), "JS unicode and hex escape");
        check("a\\b'c\n".equals(parsed.get("escaped")), "JS escaped literal");
        check("1".equals(RouterApi.parseConfig("var db_ss=new Object();db_ss['ss_basic_enable']='1';").get("ss_basic_enable")), "legacy assignments");
        check("1".equals(RouterApi.parseConfig("db_ss={};db_ss.ss_basic_enable=\"1\";").get("ss_basic_enable")), "dot assignments");
        check("香港 01".equals(RouterApi.parseConfig("var db_ss=(function() {\nvar o={};\no['name']='\\u9999\\u6e2f 01';\nreturn o;\n})();").get("name")), "real firmware IIFE grammar");
        check(RouterApi.parseConfig(fixture()).equals(RouterApi.parseConfig(iifeFixture())), "IIFE preserves all synthetic fields");
        for (String bad : new String[]{"<html>login</html>", "var db_ss={a:alert(1)};", "var db_ss={a:'x'}; fetch('https://evil')", "var db_ss={a:'x',a:'y'};", "var db_ss={a:'unterminated};", "var db_ss={a:1};", "var db_ss={a:'\\q'};"}) {
            fails(() -> RouterApi.parseConfig(bad), "reject code/non-literals/duplicates");
        }
        for (String bad : new String[]{
                "var db_ss=(function(){var o={};o['a']=alert(1);return o;})();",
                "var db_ss=(function(){var o={};o['a']='x';fetch('https://evil');return o;})();",
                "var db_ss=(function(){var o={};o['a']='x';return other;})();",
                "var db_ss=(function(){var o={};o['a']='x';o['a']='y';return o;})();",
                "var db_ss=(function(){var o={};o['a']='x';return o;})();alert(1);",
                "var db_ss=(function(){var o={};o['a']='x';return o;}(evil));"}) {
            fails(() -> RouterApi.parseConfig(bad), "IIFE rejects executable/modified wrapper");
        }

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/dbconf", exchange -> {
            cookie = exchange.getRequestHeaders().getFirst("Cookie");
            auth = exchange.getRequestHeaders().getFirst("Authorization");
            if (redirect) {
                exchange.getResponseHeaders().set("Location", "http://example.com/");
                reply(exchange, 302, "redirect");
            } else reply(exchange, 200, config);
        });
        server.createContext("/res/ss-health-status.js", exchange -> reply(exchange, healthMissing ? 404 : 200,
                healthMissing ? "missing" : "{\"node_id\":1,\"checked_at\":123,\"status\":\"healthy\"}"));
        server.createContext("/ss_status", exchange -> {
            statusCount++;
            check("GET".equals(exchange.getRequestMethod()), "probe uses firmware GET endpoint");
            reply(exchange, statusMissing ? 404 : 200, statusMissing ? "missing" : "[\"checking\",\"checking\"]");
        });
        server.createContext("/applydb.cgi", exchange -> {
            postCount++;
            postBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            reply(exchange, 200, loginPost ? "<form action='login.cgi'><input name='login_authorization'></form>" : "<html>applied</html>");
        });
        server.start();
        try {
            String base = "http://127.0.0.1:" + server.getAddress().getPort();
            RouterApi api = new RouterApi(base, "asus_token=test-cookie", "Basic dGVzdDp0ZXN0");
            fails(() -> new RouterApi(base, "x\r\ny: z", ""), "reject header injection");
            config = iifeFixture();
            RouterApi.Snapshot snapshot = api.load();
            check(snapshot.nodes.size() == 2 && "1".equals(snapshot.nodes.get(0).id), "filter AnyTLS and numeric order");
            check("主线路".equals(snapshot.nodes.get(0).name), "UTF-8 labels");
            check(snapshot.enabled && "1".equals(snapshot.currentId), "current state");
            check(snapshot.health != null && "healthy".equals(snapshot.health.optString("status")), "health JSON");
            check("asus_token=test-cookie".equals(cookie) && "Basic dGVzdDp0ZXN0".equals(auth), "shared authentication");
            check(statusCount == 1 && postCount == 0, "enabled enhanced config schedules status without writes");
            statusMissing = true;
            check(api.load().nodes.size() == 2, "optional status failure preserves config read");
            statusMissing = false;
            int probes = statusCount;
            config = fixture().replace("\"ss_basic_enable\":\"1\"", "\"ss_basic_enable\":\"0\"");
            check(!api.load().enabled && statusCount == probes, "disabled proxy does not trigger probe");
            config = fixture().replace("ss_basic_anytls_handshake", "missing_r3_capability");
            api.load();
            check(statusCount == probes, "unrecognized enhanced config never triggers status");
            config = "var db_ss={ssconf_basic_node:'1'};";
            fails(api::load, "missing enable is not validated configuration");
            check(statusCount == probes, "invalid config does not trigger status");
            config = iifeFixture();
            healthMissing = true;
            check(api.load().health == null, "optional health endpoint");
            healthMissing = false;

            config = iifeFixture().replace("node.example.test", "fresh.example.test");
            api.switchNode("2");
            Map<String, String> fields = decode(postBody);
            check(fields.size() == 12, "exact minimal form whitelist");
            check("fresh.example.test".equals(fields.get("ss_basic_server")), "fresh config before mutation");
            check("0".equals(fields.get("ss_basic_use_kcp")), "clear stale KCP setting");
            check("c2FtcGxl".equals(fields.get("ss_basic_password")), "preserve Base64 password");
            check("2".equals(fields.get("ssconf_basic_node")) && "AnyTLS".equals(fields.get("ss_basic_trojan_binary")), "target selection");
            check("ss_config.sh".equals(fields.get("SystemCmd")) && " Refresh ".equals(fields.get("action_mode")), "firmware apply contract");
            check(!fields.containsKey("ss_basic_mode") && !fields.containsKey("ss_basic_enable"), "preserve mode and enable");
            for (String key : fields.keySet()) check(!key.contains("_uu_") && !key.contains("bypass") && !key.contains("dns") && !key.contains("hosts") && !key.contains("update"), "preserve global policies");
            int count = postCount;
            fails(() -> api.switchNode("3"), "reject other protocol");
            fails(() -> api.switchNode("4"), "reject missing node");
            fails(() -> api.switchNode("2&SystemCmd=bad"), "reject form injection");
            config = fixture().replace("\"ssconf_basic_port_2\":\"443\"", "\"ssconf_basic_port_2\":\"65536\"");
            fails(() -> api.switchNode("2"), "reject invalid node port");
            check(postCount == count, "invalid targets never write");
            config = fixture().replace("ss_basic_anytls_handshake", "missing_r3_capability");
            fails(() -> api.switchNode("2"), "reject unrecognized enhancement capabilities");
            config = fixture().replace("\"ss_basic_trojan_binary\":\"AnyTLS\"", "\"ss_basic_trojan_binary\":\"Trojan\"");
            fails(() -> api.switchNode("2"), "reject current non-AnyTLS protocol");
            config = fixture().replace("\"ss_basic_type\":\"4\"", "\"ss_basic_type\":\"3\"");
            fails(() -> api.switchNode("2"), "reject conflicting current protocol type");
            check(postCount == count, "capability/current-protocol guards never write");

            config = "<html><form><input name='login_authorization'></form></html>";
            probes = statusCount;
            fails(api::load, "200 login page is not configuration");
            check(statusCount == probes, "200 login response never triggers status");
            fails(() -> api.switchNode("2"), "expired session never writes");
            check(postCount == count, "auth failure no write");
            redirect = true;
            fails(api::load, "never follow redirect with credentials");
            redirect = false;
            config = fixture();
            loginPost = true;
            fails(() -> api.switchNode("2"), "200 login POST response rejected");
            check(postCount == count + 1, "write attempted once only");
        } finally { server.stop(0); }
        System.out.println("RouterApi: " + assertions + " assertions passed (loopback mock; no physical router writes).");
    }
}
