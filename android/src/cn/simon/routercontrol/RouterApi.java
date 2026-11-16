package cn.simon.routercontrol;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The installed AM380 fancyss interface. Never logs or persists configuration. */
public final class RouterApi {
    private static final int CONFIG_LIMIT = 2 * 1024 * 1024;
    private static final String[] R3_CAPABILITIES = {"ss_basic_bypass_macs", "ss_basic_uu_macs",
            "ss_basic_anytls_min_idle", "ss_basic_anytls_idle_check", "ss_basic_anytls_idle_timeout",
            "ss_basic_anytls_handshake", "ss_basic_anytls_alpn", "ss_basic_anytls_fingerprint",
            "ss_basic_anytls_hosts", "ss_basic_health_interval", "ss_basic_health_timeout",
            "ss_basic_health_failures"};
    private final String baseUrl;
    private final String cookie;
    private final String basicAuth;

    /** basicAuth is the complete Authorization value, e.g. "Basic …". */
    public RouterApi(String baseUrl, String cookie, String basicAuth) throws IOException {
        this.baseUrl = validateBaseUrl(baseUrl);
        this.cookie = header(cookie);
        this.basicAuth = header(basicAuth);
        if (!this.basicAuth.isEmpty() && !this.basicAuth.matches("Basic [A-Za-z0-9+/]+=*")) {
            throw new IOException("登录凭证格式无效，请重新登录路由器");
        }
    }

    /** HTTP is restricted to literal LAN addresses; HTTPS uses system certificate validation. */
    public static String validateBaseUrl(String value) throws IOException {
        try {
            String address = value == null ? "" : value.trim();
            if (address.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}(:[0-9]{1,5})?/?")) address = "http://" + address;
            URI uri = new URI(address);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (!("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))
                    || host == null || uri.getUserInfo() != null || uri.getQuery() != null
                    || uri.getFragment() != null || uri.getPort() == 0 || uri.getPort() > 65535
                    || !(uri.getRawPath() == null || uri.getRawPath().isEmpty() || "/".equals(uri.getRawPath()))) {
                throw new IOException("请填写路由器管理地址，例如 http://192.168.1.1");
            }
            if ("http".equalsIgnoreCase(scheme) && !isLocalV4(host)) {
                throw new IOException("HTTP 仅支持局域网 IPv4 地址，域名和远程连接请使用 HTTPS");
            }
            return new URI(scheme.toLowerCase(java.util.Locale.ROOT), null, host, uri.getPort(), null, null, null).toASCIIString();
        } catch (URISyntaxException e) {
            throw new IOException("路由器地址格式无效");
        }
    }

    private static boolean isLocalV4(String host) {
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) return false;
        int[] octets = new int[4];
        for (int i = 0; i < 4; i++) {
            if (!parts[i].matches("0|[1-9][0-9]{0,2}")) return false;
            octets[i] = Integer.parseInt(parts[i]);
            if (octets[i] > 255) return false;
        }
        return octets[0] == 10 || octets[0] == 127
                || (octets[0] == 192 && octets[1] == 168)
                || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                || (octets[0] == 169 && octets[1] == 254);
    }

    private static String header(String value) throws IOException {
        if (value == null) return "";
        if (value.length() > 16384 || value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0
                || value.indexOf('\0') >= 0) throw new IOException("登录凭证格式无效，请重新登录路由器");
        return value;
    }

    public static final class Node {
        public final String id;
        public final String name;
        public final String server;
        public final String port;

        private Node(String id, Map<String, String> config) {
            this.id = id;
            this.name = config.getOrDefault("ssconf_basic_name_" + id, "线路 " + id);
            this.server = config.getOrDefault("ssconf_basic_server_" + id, "");
            this.port = config.getOrDefault("ssconf_basic_port_" + id, "");
        }
    }

    public static final class Snapshot {
        /** Contains private router data. Keep in memory only. */
        public final Map<String, String> config;
        public final List<Node> nodes;
        public final String currentId;
        public final boolean enabled;
        public final String version;
        /** Null when the optional health endpoint is unavailable or invalid. */
        public final JSONObject health;

        private Snapshot(Map<String, String> values, JSONObject health) throws IOException {
            validateConfig(values);
            this.config = Collections.unmodifiableMap(new LinkedHashMap<>(values));
            this.currentId = values.getOrDefault("ssconf_basic_node", "");
            this.enabled = "1".equals(values.get("ss_basic_enable"));
            this.version = values.getOrDefault("ss_basic_version_local", "未知版本");
            this.health = health;
            List<Node> found = new ArrayList<>();
            for (String key : values.keySet()) {
                if (key.matches("ssconf_basic_name_[1-9][0-9]{0,8}")) {
                    String id = key.substring("ssconf_basic_name_".length());
                    if (isAnyTls(values, id)) found.add(new Node(id, values));
                }
            }
            Collections.sort(found, Comparator.comparingLong(node -> Long.parseLong(node.id)));
            this.nodes = Collections.unmodifiableList(found);
        }
    }

    public Snapshot load() throws IOException {
        Map<String, String> config = loadConfig();
        validateConfig(config);
        if ("1".equals(config.get("ss_basic_enable")) && hasR3Capabilities(config)) {
            try {
                // The firmware status endpoint schedules its bounded asynchronous health probe.
                // It does not apply configuration or restart the proxy/UU services.
                request("/ss_status", null, 64 * 1024);
            } catch (IOException ignored) {
                // A missing/failed optional probe must not invalidate an authenticated config read.
            }
        }
        JSONObject health = null;
        try {
            String body = request("/res/ss-health-status.js", null, 64 * 1024);
            health = new JSONObject(body);
            if (!health.has("node_id") || !health.has("checked_at")) health = null;
        } catch (IOException | JSONException ignored) {
            // Health is optional; a successful configuration read still establishes the connection.
        }
        return new Snapshot(config, health);
    }

    private Map<String, String> loadConfig() throws IOException {
        return parseConfig(request("/dbconf?p=ss", null, CONFIG_LIMIT));
    }

    private static void validateConfig(Map<String, String> config) throws IOException {
        if (!("0".equals(config.get("ss_basic_enable")) || "1".equals(config.get("ss_basic_enable")))) {
            throw new IOException("未读取到插件配置，请确认已登录且安装了兼容的 AnyTLS 插件");
        }
    }

    private static boolean hasR3Capabilities(Map<String, String> config) {
        for (String capability : R3_CAPABILITIES) {
            if (!config.containsKey(capability)) return false;
        }
        return true;
    }

    private static boolean isAnyTls(Map<String, String> config, String id) {
        return "4".equals(config.get("ssconf_basic_type_" + id))
                && "AnyTLS".equals(config.get("ssconf_basic_trojan_binary_" + id));
    }

    /** Submits once. A lost response must be resolved by reading state, never by blind retry. */
    public void switchNode(String id) throws IOException {
        if (id == null || !id.matches("[1-9][0-9]{0,8}")) throw new IOException("线路编号无效");
        Map<String, String> config = loadConfig();
        if (!config.containsKey("ss_basic_enable") || !isAnyTls(config, id)
                || !config.containsKey("ssconf_basic_name_" + id)) {
            throw new IOException("该 AnyTLS 线路已不存在，请刷新线路列表");
        }
        if (!hasR3Capabilities(config)) {
            throw new IOException("未识别到 R7000 r3 增强配置，已取消切换，请先核对路由器版本");
        }
        if (!("0".equals(config.get("ss_basic_enable")) || "1".equals(config.get("ss_basic_enable")))
                || !"4".equals(config.get("ss_basic_type"))
                || !"AnyTLS".equals(config.get("ss_basic_trojan_binary"))) {
            throw new IOException("当前配置不是 AnyTLS，已取消切换；请先在路由器中完成协议配置");
        }
        String prefix = "ssconf_basic_";
        String suffix = "_" + id;
        String server = config.getOrDefault(prefix + "server" + suffix, "");
        String port = config.getOrDefault(prefix + "port" + suffix, "");
        String password = config.getOrDefault(prefix + "password" + suffix, "");
        if (server.isEmpty() || !port.matches("[0-9]{1,5}")
                || Integer.parseInt(port) < 1 || Integer.parseInt(port) > 65535 || password.isEmpty()) {
            throw new IOException("该线路配置不完整，请先在路由器中修复");
        }
        Map<String, String> form = new LinkedHashMap<>();
        form.put("ssconf_basic_node", id);
        form.put("ss_basic_type", "4");
        form.put("ss_basic_trojan_binary", "AnyTLS");
        for (String field : new String[]{"server", "port", "password", "trojan_sni", "allowinsecure", "use_kcp"}) {
            String fallback = ("allowinsecure".equals(field) || "use_kcp".equals(field)) ? "0" : "";
            String value = config.getOrDefault(prefix + field + suffix, fallback);
            if (value.length() > 16384) throw new IOException("线路参数过长，无法切换");
            if (("allowinsecure".equals(field) || "use_kcp".equals(field))
                    && !("0".equals(value) || "1".equals(value))) {
                throw new IOException("线路参数无效，请先在路由器中修复");
            }
            form.put("ss_basic_" + field, value);
        }
        // Preserve the active routing mode and enable state, as well as all global settings.
        // The firmware's node.mode is intentionally not copied: this app only changes the line.
        form.put("SystemCmd", "ss_config.sh");
        form.put("action_mode", " Refresh ");
        form.put("current_page", "Main_Ss_Content.asp");
        StringBuilder encoded = new StringBuilder();
        for (Map.Entry<String, String> entry : form.entrySet()) {
            if (encoded.length() > 0) encoded.append('&');
            encoded.append(URLEncoder.encode(entry.getKey(), "UTF-8"));
            encoded.append('=').append(URLEncoder.encode(entry.getValue(), "UTF-8"));
        }
        String response = request("/applydb.cgi?p=ss", encoded.toString().getBytes(StandardCharsets.UTF_8), 256 * 1024);
        String lower = response.toLowerCase(java.util.Locale.ROOT);
        if (lower.contains("main_login.asp") || lower.contains("login_authorization")
                || lower.contains("<title>login")) {
            throw new IOException("登录已过期，请重新登录后刷新状态");
        }
    }

    private String request(String path, byte[] form, int limit) throws IOException {
        // Every URL is constructed from a fixed relative endpoint, never from returned router data.
        URL target = new URL(baseUrl + path);
        HttpURLConnection connection = (HttpURLConnection) target.openConnection();
        connection.setInstanceFollowRedirects(false);
        connection.setConnectTimeout(10000);
        connection.setReadTimeout(20000);
        connection.setUseCaches(false);
        connection.setRequestProperty("Cache-Control", "no-store");
        connection.setRequestProperty("Accept", "text/plain, application/json, */*");
        connection.setRequestProperty("Referer", baseUrl + "/Main_Ss_Content.asp");
        connection.setRequestProperty("Origin", baseUrl);
        if (!cookie.isEmpty()) connection.setRequestProperty("Cookie", cookie);
        if (!basicAuth.isEmpty()) connection.setRequestProperty("Authorization", basicAuth);
        try {
            if (form != null) {
                connection.setRequestMethod("POST");
                connection.setDoOutput(true);
                connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
                connection.setFixedLengthStreamingMode(form.length);
                try (OutputStream out = connection.getOutputStream()) { out.write(form); }
            }
            int status = connection.getResponseCode();
            if (status == 401 || status == 403) throw new IOException("登录已过期或无权限，请重新登录路由器");
            if (status >= 300 && status < 400) throw new IOException("路由器要求跳转，请确认管理地址并重新登录");
            if (status < 200 || status >= 300) throw new IOException("路由器请求失败（HTTP " + status + "）");
            if (connection.getContentLengthLong() > limit) throw new IOException("路由器返回的数据过大");
            try (InputStream in = connection.getInputStream(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[8192];
                int count;
                while ((count = in.read(buffer)) != -1) {
                    if (out.size() + count > limit) throw new IOException("路由器返回的数据过大");
                    out.write(buffer, 0, count);
                }
                return new String(out.toByteArray(), StandardCharsets.UTF_8);
            }
        } finally {
            connection.disconnect();
        }
    }

    /** Parses a string-only db_ss object/assignments, without executing JavaScript. */
    static Map<String, String> parseConfig(String input) throws IOException {
        try { return new ConfigParser(input).parse(); }
        catch (IllegalArgumentException e) {
            throw new IOException("未读到有效插件配置，请确认路由器地址和登录状态");
        }
    }

    private static final class ConfigParser {
        private final String text;
        private int at;
        private final Map<String, String> values = new LinkedHashMap<>();

        ConfigParser(String text) { this.text = text; }

        Map<String, String> parse() {
            space();
            if (peek('\ufeff')) at++;
            space();
            if (word("var") || word("let") || word("const")) space();
            expectWord("db_ss");
            space();
            expect('=');
            space();
            if (peek('(')) return iife();
            if (word("new")) {
                space(); expectWord("Object"); space(); expect('('); space(); expect(')');
            } else {
                expect('{'); space();
                if (!peek('}')) {
                    while (true) {
                        String key = quotedOrIdentifier(); space(); expect(':'); space();
                        put(key, string()); space();
                        if (!peek(',')) break;
                        at++; space(); if (peek('}')) break;
                    }
                }
                expect('}');
            }
            space(); if (peek(';')) at++;
            while (true) {
                space(); if (at == text.length()) return values;
                expectWord("db_ss"); space();
                String key;
                if (peek('[')) { at++; space(); key = string(); space(); expect(']'); }
                else { expect('.'); key = identifier(); }
                space(); expect('='); space(); put(key, string()); space();
                if (peek(';')) at++; else if (at < text.length()) fail();
            }
        }

        /** AM380 emits a fixed object-building IIFE. Parse its grammar, never execute it. */
        private Map<String, String> iife() {
            expect('('); space(); expectWord("function"); space();
            expect('('); space(); expect(')'); space(); expect('{'); space();
            expectWord("var"); space(); expectWord("o"); space();
            expect('='); space(); expect('{'); space(); expect('}'); space(); expect(';');
            while (true) {
                space();
                if (word("return")) break;
                expectWord("o"); space(); expect('['); space();
                String key = string(); space(); expect(']'); space(); expect('='); space();
                put(key, string()); space(); expect(';');
            }
            space(); expectWord("o"); space(); expect(';'); space(); expect('}'); space();
            expect(')'); space(); expect('('); space(); expect(')'); space();
            if (peek(';')) at++;
            space();
            if (at != text.length()) fail();
            return values;
        }

        private void put(String key, String value) {
            if (!key.matches("[A-Za-z_][A-Za-z0-9_]*") || key.length() > 128
                    || value.length() > 65536 || values.size() > 20000) fail();
            if (values.put(key, value) != null) fail();
        }

        private String quotedOrIdentifier() {
            return peek('\'') || peek('"') ? string() : identifier();
        }

        private String identifier() {
            int start = at;
            if (at >= text.length() || !(Character.isLetter(text.charAt(at)) || text.charAt(at) == '_')) fail();
            at++;
            while (at < text.length() && (Character.isLetterOrDigit(text.charAt(at)) || text.charAt(at) == '_')) at++;
            return text.substring(start, at);
        }

        private String string() {
            if (!(peek('\'') || peek('"'))) { fail(); return ""; }
            char quote = text.charAt(at++);
            StringBuilder out = new StringBuilder();
            while (at < text.length()) {
                char c = text.charAt(at++);
                if (c == quote) return out.toString();
                if (c < 32) fail();
                if (c != '\\') { out.append(c); continue; }
                if (at == text.length()) fail();
                char escaped = text.charAt(at++);
                switch (escaped) {
                    case '\\': case '\'': case '"': case '/': out.append(escaped); break;
                    case 'n': out.append('\n'); break;
                    case 'r': out.append('\r'); break;
                    case 't': out.append('\t'); break;
                    case 'b': out.append('\b'); break;
                    case 'f': out.append('\f'); break;
                    case 'v': out.append('\u000b'); break;
                    case 'u': out.append(hex(4)); break;
                    case 'x': out.append(hex(2)); break;
                    default: fail();
                }
            }
            fail(); return "";
        }

        private char hex(int digits) {
            if (at + digits > text.length()) fail();
            int value = 0;
            for (int i = 0; i < digits; i++) {
                int digit = Character.digit(text.charAt(at++), 16);
                if (digit < 0) fail();
                value = value * 16 + digit;
            }
            return (char) value;
        }

        private void space() {
            while (at < text.length()) {
                if (Character.isWhitespace(text.charAt(at))) { at++; continue; }
                if (text.startsWith("//", at)) {
                    int end = text.indexOf('\n', at + 2); at = end < 0 ? text.length() : end + 1; continue;
                }
                if (text.startsWith("/*", at)) {
                    int end = text.indexOf("*/", at + 2); if (end < 0) fail(); at = end + 2; continue;
                }
                return;
            }
        }

        private boolean word(String word) {
            if (!text.startsWith(word, at)) return false;
            int end = at + word.length();
            if (end < text.length() && (Character.isLetterOrDigit(text.charAt(end)) || text.charAt(end) == '_')) return false;
            at = end; return true;
        }

        private void expectWord(String word) { if (!word(word)) fail(); }
        private boolean peek(char c) { return at < text.length() && text.charAt(at) == c; }
        private void expect(char c) { if (!peek(c)) fail(); at++; }
        private void fail() { throw new IllegalArgumentException("Invalid db_ss literal"); }
    }
}
