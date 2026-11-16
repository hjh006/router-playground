package cn.simon.routercontrol;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Phone-to-entry TCP timing only; never authenticates AnyTLS or changes network settings. */
public final class LatencyProbe {
    private static final int TIMEOUT_MS = 2000;
    // Native DNS resolution is not interruptible on every device. Keep at most two such
    // calls alive, with no queue or per-timeout replacement threads; saturated DNS fails fast.
    private static final ThreadPoolExecutor DNS = new ThreadPoolExecutor(2, 2, 30, TimeUnit.SECONDS,
            new SynchronousQueue<>(), task -> {
                Thread thread = new Thread(task, "router-tcp-dns");
                thread.setDaemon(true);
                return thread;
            }, new ThreadPoolExecutor.AbortPolicy());

    public static final class Result {
        public final String status;
        public final long latencyMs;
        public final long checkedAtMillis;
        public final String reason;
        public final String fingerprint;

        private Result(String status, long latencyMs, String reason, String fingerprint) {
            this.status = status;
            this.latencyMs = latencyMs;
            this.reason = reason;
            this.fingerprint = fingerprint;
            this.checkedAtMillis = System.currentTimeMillis();
        }
    }

    public static Result measure(RouterApi.Node node, Map<String, String> config) {
        if (node == null) return failure("failed", "invalid_endpoint", hash("invalid-node"));
        try {
            return measure(node.server, parsePort(node.port), config);
        } catch (IllegalArgumentException ignored) {
            return failure("failed", "invalid_endpoint", fingerprint(node, config));
        }
    }

    /** Identity contains effective entry + port + Hosts hash, never a password or raw endpoint. */
    public static String fingerprint(RouterApi.Node node, Map<String, String> config) {
        if (node == null) return hash("invalid-node");
        try {
            return endpoint(node.server, parsePort(node.port), config).fingerprint;
        } catch (IllegalArgumentException ignored) {
            String port = node.port;
            try { port = String.valueOf(parsePort(port)); } catch (IllegalArgumentException invalidPort) { }
            return hash("invalid\0" + node.server + "\0" + port + "\0" + hash(hosts(config)));
        }
    }

    // Package-visible entry point permits loopback-only tests without constructing private Nodes.
    static Result measure(String host, int port, Map<String, String> config) {
        String identity = hash("invalid\0" + host + "\0" + port + "\0" + hash(hosts(config)));
        final Endpoint entry;
        try {
            entry = endpoint(host, port, config);
            identity = entry.fingerprint;
        } catch (IllegalArgumentException ignored) {
            return failure("failed", "invalid_endpoint", identity);
        }
        if (Thread.currentThread().isInterrupted()) return failure("failed", "cancelled", identity);
        InetAddress address;
        if (entry.host.matches("[0-9.]+")) {
            String[] octets = entry.host.split("\\.");
            byte[] bytes = new byte[4];
            for (int i = 0; i < 4; i++) bytes[i] = (byte) Integer.parseInt(octets[i]);
            try { address = InetAddress.getByAddress(bytes); }
            catch (IOException ignored) { return failure("dns_failed", "dns_failed", identity); }
        } else {
            Future<InetAddress[]> pending;
            try { pending = DNS.submit(() -> InetAddress.getAllByName(entry.host)); }
            catch (RejectedExecutionException ignored) { return failure("dns_failed", "dns_busy", identity); }
            try {
                address = null;
                for (InetAddress candidate : pending.get(TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                    if (candidate instanceof Inet4Address) { address = candidate; break; }
                }
                // Match the maintained router's IPv4 node path, rather than ranking an IPv6-only path.
                if (address == null) return failure("dns_failed", "no_ipv4", identity);
            } catch (TimeoutException ignored) {
                pending.cancel(true);
                return failure("dns_failed", "dns_timeout", identity);
            } catch (InterruptedException ignored) {
                pending.cancel(true);
                Thread.currentThread().interrupt();
                return failure("failed", "cancelled", identity);
            } catch (ExecutionException ignored) {
                return failure("dns_failed", "dns_failed", identity);
            }
        }
        if (Thread.currentThread().isInterrupted()) return failure("failed", "cancelled", identity);
        try (Socket socket = new Socket()) {
            long started = System.nanoTime();
            socket.connect(new InetSocketAddress(address, port), TIMEOUT_MS);
            long elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
            if (Thread.currentThread().isInterrupted()) return failure("failed", "cancelled", identity);
            return new Result("ok", Math.max(0, elapsed), "", identity);
        } catch (SocketTimeoutException ignored) {
            return failure(Thread.currentThread().isInterrupted() ? "failed" : "timeout",
                    Thread.currentThread().isInterrupted() ? "cancelled" : "connect_timeout", identity);
        } catch (IOException | SecurityException ignored) {
            return failure("failed", Thread.currentThread().isInterrupted() ? "cancelled" : "connect_failed", identity);
        }
    }

    private static Result failure(String status, String reason, String identity) {
        return new Result(status, -1, reason, identity);
    }

    private static int parsePort(String text) {
        if (text == null || !text.matches("[0-9]{1,5}")) throw new IllegalArgumentException();
        int port = Integer.parseInt(text);
        if (port < 1 || port > 65535) throw new IllegalArgumentException();
        return port;
    }

    private static String hosts(Map<String, String> config) {
        if (config == null) return "";
        String value = config.get("ss_basic_anytls_hosts");
        return value == null ? "" : value;
    }

    private static final class Endpoint {
        final String host;
        final String fingerprint;
        Endpoint(String host, int port, String rawHosts) {
            this.host = host;
            this.fingerprint = hash("phone-tcp-v1\0" + host + "\0" + port + "\0" + hash(rawHosts));
        }
    }

    private static Endpoint endpoint(String original, int port, Map<String, String> config) {
        if (port < 1 || port > 65535) throw new IllegalArgumentException();
        String raw = hosts(config);
        if (raw.length() > 16384) throw new IllegalArgumentException();
        Map<String, String> mappings = new LinkedHashMap<>();
        int entries = 0;
        for (String item : raw.split("[,\n]", -1)) {
            item = trim(item);
            if (item.isEmpty()) continue;
            if (++entries > 32) throw new IllegalArgumentException();
            String[] pair = item.split("=", -1);
            if (pair.length != 2) throw new IllegalArgumentException();
            String key = normalizeHost(pair[0]);
            String value = normalizeHost(pair[1]);
            String prior = mappings.put(key, value);
            if (prior != null && !prior.equals(value)) throw new IllegalArgumentException();
        }
        // The router rejects any invalid chain, including one unrelated to this entry.
        for (String key : mappings.keySet()) mapped(key, mappings);
        return new Endpoint(mapped(normalizeHost(original), mappings), port, raw);
    }

    private static String mapped(String host, Map<String, String> mappings) {
        int hops = 0;
        while (mappings.containsKey(host)) {
            if (++hops > 4) throw new IllegalArgumentException();
            host = mappings.get(host);
        }
        return host;
    }

    private static String normalizeHost(String original) {
        if (original == null) throw new IllegalArgumentException();
        String host = trim(original).toLowerCase(Locale.ROOT);
        if (host.matches("[0-9.]+")) {
            String[] parts = host.split("\\.", -1);
            if (parts.length != 4) throw new IllegalArgumentException();
            for (String part : parts) {
                if (!part.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(part) > 255) throw new IllegalArgumentException();
            }
            return host;
        }
        if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        if (host.isEmpty() || host.length() > 253 || !host.matches("[a-z0-9.-]+")) throw new IllegalArgumentException();
        for (String label : host.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63 || !label.matches("[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")) throw new IllegalArgumentException();
        }
        return host;
    }

    private static String trim(String value) {
        return value.replaceAll("^[ \\t\\r]+|[ \\t\\r]+$", "");
    }

    private static String hash(String text) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(64);
            for (byte value : bytes) hex.append(String.format(Locale.ROOT, "%02x", value & 255));
            return hex.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable");
        }
    }

    private LatencyProbe() {}
}
