package cn.simon.routercontrol;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONObject;

/** Router measurement API against a loopback fixture. Never connects to real nodes. */
public final class RouterLatencyApiTest {
    private static int checks, posts, uploads;
    private static Map<String, String> config, submitted;
    private static String status, capability, cookie;
    private static boolean losePost;
    private static boolean loseUpload;
    private static String uploadBody, uploadContentType, uploadQuery, uploadCookie;
    private static String uploadResponse = "<script>parent.upload_ok(1);</script>";
    private static final String JOB = "0123456789abcdef0123456789abcdef";
    private interface Action { void run() throws Exception; }

    private static void check(boolean value, String message) {
        checks++; if (!value) throw new AssertionError(message);
    }
    private static void refuses(Action action, String message) throws Exception {
        int before = posts, uploadedBefore = uploads;
        try { action.run(); throw new AssertionError(message); }
        catch (IOException expected) { checks++; }
        check(posts == before && uploads == uploadedBefore, message + ": no upload or command");
    }
    private static JSONObject result(String state) {
        return new JSONObject().put("version", 1).put("method", "router_tcp").put("target", "entry").put("transport", "ram_mailbox_v1")
            .put("job_id", JOB).put("node_id", 1).put("state", state).put("checked_at", 1794900000)
            .put("latency_ms", "ok".equals(state) ? 153 : JSONObject.NULL)
            .put("reason", "path_unverified".equals(state) ? "routing_unknown" : "");
    }
    private static Map<String, String> decode(String body) throws Exception {
        Map<String, String> values = new LinkedHashMap<>();
        for (String pair : body.split("&")) {
            String[] parts = pair.split("=", 2);
            String key = URLDecoder.decode(parts[0], "UTF-8");
            if (values.put(key, URLDecoder.decode(parts.length == 2 ? parts[1] : "", "UTF-8")) != null) throw new IOException("duplicate key");
        }
        return values;
    }
    private static void metadata(String command) {
        check(submitted.size() == 3, "measurement posts exactly three metadata fields");
        check(command.equals(submitted.get("SystemCmd")), "fixed script with validated identifiers");
        check(" Refresh ".equals(submitted.get("action_mode")), "legacy refresh mode");
        check("Main_Ss_Content.asp".equals(submitted.get("current_page")), "fixed return page");
        check("asus_token=fixture".equals(cookie), "authenticated session reused");
        check(submitted.keySet().stream().noneMatch(k -> k.startsWith("ss")), "no router configuration submitted");
    }
    public static void main(String[] ignored) throws Exception {
        config = new LinkedHashMap<>();
        config.put("ss_basic_enable", "1"); config.put("ss_basic_mode", "2");
        config.put("ss_basic_anytls_hosts", "entry.example.test=192.0.2.1");
        config.put("ss_basic_server_resolver", "1");
        config.put("ssconf_basic_name_1", "Synthetic route"); config.put("ssconf_basic_type_1", "4");
        config.put("ssconf_basic_trojan_binary_1", "AnyTLS");
        config.put("ssconf_basic_server_1", "entry.example.test"); config.put("ssconf_basic_port_1", "443");
        config.put("ssconf_basic_password_1", "synthetic-base64");
        status = result("ok").toString();
        capability = "{\"version\":1,\"method\":\"router_tcp\",\"target\":\"entry\",\"max_parallel\":1,\"transport\":\"ram_mailbox_v1\"}";
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath(), response; int code = 200;
            cookie = exchange.getRequestHeaders().getFirst("Cookie");
            if ("/dbconf".equals(path)) response = "var db_ss=" + new JSONObject(config) + ";";
            else if ("/res/ss-latency-capabilities.js".equals(path)) response = capability;
            else if ("/res/ss-latency-status.js".equals(path)) response = status;
            else if ("/ssupload.cgi".equals(path)) {
                uploads++;
                uploadBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                uploadContentType = exchange.getRequestHeaders().getFirst("Content-Type");
                uploadQuery = exchange.getRequestURI().getRawQuery();
                uploadCookie = cookie;
                if (loseUpload) { code = 500; response = "upload response unavailable"; }
                else response = uploadResponse;
            }
            else if ("/applydb.cgi".equals(path)) {
                posts++;
                try { submitted = decode(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)); }
                catch (Exception error) { throw new IOException(error); }
                if (losePost) { code = 500; response = "response unavailable"; }
                else response = "ok";
            } else { code = 404; response = "unexpected path"; }
            byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(code, bytes.length);
            try (java.io.OutputStream output = exchange.getResponseBody()) { output.write(bytes); }
        });
        server.start();
        try {
            RouterApi api = new RouterApi("http://127.0.0.1:" + server.getAddress().getPort(), "asus_token=fixture", "");
            check(api.supportsRouterLatency() && posts == 0, "capability is a read-only fixed endpoint");
            Map<String, String> before = new LinkedHashMap<>(config);
            api.startLatency("1", JOB); metadata("ss_latency.sh");
            check(uploads == 1 && "a=/tmp/ss_latency/request".equals(uploadQuery), "fixed RAM mailbox upload endpoint");
            check(uploadContentType.startsWith("multipart/form-data; boundary="), "native multipart upload contract");
            check(uploadBody.contains("\r\n\r\nstart 1 " + JOB + "\n\r\n--"), "canonical ASCII start request");
            check(uploadBody.split("Content-Disposition:", -1).length == 2 && uploadBody.contains("name=\"file\"; filename=\"request\""), "one fixed file part only");
            check("asus_token=fixture".equals(uploadCookie) && !uploadBody.contains("synthetic-base64") && !uploadBody.contains("entry.example.test"), "upload contains identifiers only and reuses authentication");
            check(before.equals(config), "starting measurement preserves all configuration");
            api.cancelLatency(JOB); metadata("ss_latency.sh");
            check(uploads == 2 && uploadBody.contains("\r\n\r\ncancel " + JOB + "\n\r\n--"), "canonical nonce-specific cancel request");
            check(before.equals(config), "cancelling measurement preserves all configuration");
            for (String id : new String[]{"0", "01", "-1", "1000000", "1;reboot", "1 2", "1\n"}) refuses(() -> api.startLatency(id, JOB), "reject invalid node identifier");
            for (String nonce : new String[]{"", "a", JOB.toUpperCase(), JOB + ";reboot", JOB + "\n"}) {
                refuses(() -> api.startLatency("1", nonce), "reject invalid start job");
                refuses(() -> api.cancelLatency(nonce), "reject invalid cancellation job");
            }
            refuses(() -> api.startLatency("2", JOB), "missing saved route refused");
            config.put("ssconf_basic_trojan_binary_1", "Trojan");
            refuses(() -> api.startLatency("1", JOB), "non-AnyTLS route refused");
            config.put("ssconf_basic_trojan_binary_1", "AnyTLS");
            RouterApi.LatencyJob job = api.readLatency();
            check(job.isTerminal() && "ok".equals(job.state) && job.latencyMs == 153, "real result value parsed");
            check(job.jobId.equals(JOB) && job.nodeId.equals("1") && job.checkedAtMillis == 1794900000000L, "identity and sample time parsed");
            for (String state : new String[]{"running", "timeout", "failed", "dns_failed", "busy", "cancelled", "changed", "path_unverified"}) {
                job = RouterApi.parseLatency(result(state).toString());
                check(job.latencyMs == -1 && job.isTerminal() == !"running".equals(state), "failure never creates latency");
            }
            JSONObject idle = result("idle").put("job_id", "").put("node_id", 0).put("checked_at", 0);
            check(!RouterApi.parseLatency(idle.toString()).isTerminal(), "idle is not a completed node");
            check(RouterApi.parseLatency(result("ok").put("latency_ms", 5000).toString()).latencyMs == 5000, "median stays within one TCP timeout");
            check(RouterApi.parseLatency(result("ok").put("samples", 3).put("details", new JSONObject().put("median", true)).toString()).latencyMs == 153,
                    "optional backend sample details do not alter the metric");
            for (JSONObject bad : new JSONObject[]{result("ok").put("latency_ms", -1), result("ok").put("latency_ms", 5001),
                    result("ok").put("latency_ms", 1.5), result("ok").put("latency_ms", "153"),
                    result("timeout").put("latency_ms", 153), result("path_unverified").put("latency_ms", 1), result("ok").put("checked_at", 0),
                    result("ok").put("checked_at", -1), result("ok").put("node_id", "1;reboot"),
                    result("ok").put("job_id", "other"), result("ok").put("state", "<script>"),
                    result("ok").put("reason", "https://private.example.test/"), result("ok").put("method", "phone_tcp"),
                    result("ok").put("method", "router_https").put("target", "google"), result("ok").put("target", "google"),
                    result("ok").put("target", "https://unexpected.example.test/"), result("ok").put("transport", "other"),
                    result("ok").put("transport", JSONObject.NULL), result("ok").put("version", 2)}) {
                refuses(() -> RouterApi.parseLatency(bad.toString()), "malformed result rejected");
            }
            refuses(() -> RouterApi.parseLatency("<html>login_authorization</html>"), "login HTML is not a measurement");
            capability = "{\"version\":1,\"method\":\"phone_tcp\",\"target\":\"entry\",\"max_parallel\":1,\"transport\":\"ram_mailbox_v1\"}";
            check(!api.supportsRouterLatency(), "wrong measurement capability refused");
            capability = "{\"version\":1,\"method\":\"router_https\",\"target\":\"google\",\"max_parallel\":1,\"transport\":\"ram_mailbox_v1\"}";
            check(!api.supportsRouterLatency(), "old HTTPS capability cannot be shown as entry TCP");
            capability = "<html>login_authorization</html>";
            check(!api.supportsRouterLatency(), "login HTML is not a capability");
            capability = "{\"version\":1,\"method\":\"router_tcp\",\"target\":\"entry\",\"max_parallel\":1}";
            check(!api.supportsRouterLatency(), "component without the RAM mailbox contract is refused");
            for (String response : new String[]{"", "<script>parent.upload_ok(0);</script>", "<html>login_authorization</html>"}) {
                uploadResponse = response; int beforePosts = posts, beforeUploads = uploads;
                try { api.startLatency("1", JOB); throw new AssertionError("unconfirmed upload must fail"); }
                catch (IOException expected) { checks++; }
                check(posts == beforePosts && uploads == beforeUploads + 1, "unconfirmed upload never invokes or retries the script");
            }
            uploadResponse = "<script>parent.upload_ok(1);</script>";
            loseUpload = true; int beforePosts = posts, beforeUploads = uploads;
            try { api.startLatency("1", JOB); throw new AssertionError("lost upload must fail"); }
            catch (IOException expected) { checks++; }
            check(posts == beforePosts && uploads == beforeUploads + 1, "lost upload response never invokes or retries the script");
            loseUpload = false;
            losePost = true; int writes = posts;
            try { api.startLatency("1", JOB); throw new AssertionError("lost response must fail"); }
            catch (IOException expected) { checks++; }
            check(posts == writes + 1, "unknown POST result never retried");
            losePost = false;
            RouterApi.Node node = api.load().nodes.get(0);
            String identity = RouterApi.latencyFingerprint(node, config);
            check(identity.matches("[a-f0-9]{64}"), "local cache has a digest identity");
            for (String key : new String[]{"ssconf_basic_server_1", "ssconf_basic_port_1", "ss_basic_anytls_hosts", "ss_basic_server_resolver", "ss_basic_server_resolver_custom"}) {
                Map<String, String> changed = new LinkedHashMap<>(config); changed.put(key, "changed");
                check(!identity.equals(RouterApi.latencyFingerprint(node, changed)), "connection change invalidates cache");
            }
            Map<String, String> unrelated = new LinkedHashMap<>(config);
            unrelated.put("ss_basic_uu_macs", "synthetic-device"); unrelated.put("ssconf_basic_name_1", "Renamed");
            unrelated.put("ssconf_basic_password_1", "changed"); unrelated.put("ssconf_basic_trojan_sni_1", "changed.example.test");
            unrelated.put("ssconf_basic_allowinsecure_1", "1"); unrelated.put("ss_basic_anytls_handshake", "20");
            check(identity.equals(RouterApi.latencyFingerprint(node, unrelated)), "device/name/authentication/TLS changes do not alter the TCP entry identity");
            System.out.println("RouterLatencyApi: " + checks + " assertions passed (loopback only).");
        } finally { server.stop(0); }
    }
}
