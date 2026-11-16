package cn.simon.routercontrol;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

/** Only loopback sockets and synthetic mappings; no DNS or real node traffic. */
public final class LatencyProbeTest {
    private static int assertions;
    private static void check(boolean value, String message) {
        assertions++;
        if (!value) throw new AssertionError(message);
    }
    private static Map<String, String> config(String mappings) {
        return new HashMap<String, String>() {
            @Override public String get(Object key) {
                if (!"ss_basic_anytls_hosts".equals(key)) throw new AssertionError("Probe must not read credentials");
                return mappings;
            }
        };
    }
    public static void main(String[] ignored) throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 8, java.net.InetAddress.getByAddress(new byte[]{127,0,0,1}))) {
            Thread accept = new Thread(() -> {
                try {
                    while (!listener.isClosed()) {
                        try (Socket socket = listener.accept()) { }
                    }
                } catch (java.io.IOException expectedOnClose) { }
            });
            accept.setDaemon(true); accept.start();
            int port = listener.getLocalPort();
            long before = System.currentTimeMillis();
            LatencyProbe.Result direct = LatencyProbe.measure("127.0.0.1", port, config(""));
            check("ok".equals(direct.status) && direct.latencyMs >= 0, "real loopback TCP timing");
            check(direct.checkedAtMillis >= before && direct.checkedAtMillis <= System.currentTimeMillis(), "actual measurement timestamp");
            check(direct.fingerprint.matches("[0-9a-f]{64}"), "digest only identity");
            LatencyProbe.Result mapped = LatencyProbe.measure("ENTRY.INVALID.", port, config(" entry.invalid = 127.0.0.1 "));
            check("ok".equals(mapped.status), "Hosts normalization before DNS");
            check(!mapped.fingerprint.equals(direct.fingerprint), "Hosts configuration changes identity");
            LatencyProbe.Result chain = LatencyProbe.measure("a.invalid", port,
                    config("a.invalid=b.invalid\nb.invalid=c.invalid,c.invalid=d.invalid,d.invalid=127.0.0.1"));
            check("ok".equals(chain.status), "four mapping hops permitted");
            for (String invalid : new String[]{"a.invalid=b.invalid,b.invalid=c.invalid,c.invalid=d.invalid,d.invalid=e.invalid,e.invalid=127.0.0.1",
                    "a.invalid=b.invalid,b.invalid=a.invalid", "a.invalid=127.0.0.1,a.invalid=127.0.0.2",
                    "a.invalid=127.00.0.1", "a.invalid=127.0.0.1=other", "bad_key=127.0.0.1",
                    "a.invalid=127.0.0.1\f",
                    "a.invalid=127.0.0.1,unrelated.invalid=unrelated.invalid"}) {
                LatencyProbe.Result result = LatencyProbe.measure("a.invalid", port, config(invalid));
                check("failed".equals(result.status) && "invalid_endpoint".equals(result.reason) && result.latencyMs == -1,
                        "invalid mapping fails before network");
            }
            check("ok".equals(LatencyProbe.measure("a.invalid", port,
                    config("a.invalid=127.0.0.1,A.INVALID.=127.0.0.1")).status), "identical duplicate mapping permitted");
            StringBuilder excessive = new StringBuilder();
            for (int i = 0; i < 33; i++) excessive.append("x").append(i).append(".invalid=127.0.0.1,");
            check("failed".equals(LatencyProbe.measure("127.0.0.1", port, config(excessive.toString())).status), "32-entry ceiling");
            Thread.currentThread().interrupt();
            LatencyProbe.Result cancelled = LatencyProbe.measure("127.0.0.1", port, config(""));
            check("failed".equals(cancelled.status) && "cancelled".equals(cancelled.reason), "interrupted caller cancels before network");
            check(Thread.interrupted(), "preserve interrupt signal");
            check("failed".equals(LatencyProbe.measure("127.0.0.1", 65536, config("")).status), "port validation");
            check("failed".equals(LatencyProbe.measure("127.0.0.1/private", port, config("")).status), "endpoint validation");
        }
        int closedPort;
        try (ServerSocket reserve = new ServerSocket(0, 1, java.net.InetAddress.getByAddress(new byte[]{127,0,0,1}))) {
            closedPort = reserve.getLocalPort();
        }
        LatencyProbe.Result refused = LatencyProbe.measure("127.0.0.1", closedPort, config(""));
        check("failed".equals(refused.status) && "connect_failed".equals(refused.reason) && refused.latencyMs == -1,
                "refused loopback does not fabricate latency");
        check(!refused.reason.contains("127.") && !refused.reason.contains(String.valueOf(closedPort)), "no endpoint in errors");
        System.out.println("LatencyProbe: " + assertions + " assertions passed (loopback only; no DNS or real-node probes).");
    }
}
