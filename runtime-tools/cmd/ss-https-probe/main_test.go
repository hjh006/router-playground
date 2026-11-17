package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifiedHTTPSViaRemoteDNSProxy(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			time.Sleep(150 * time.Millisecond)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	defer server.Close()
	proxy, hostnames := startTestSOCKS(t, server.Listener.Addr().String())
	caFile := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, address string
		untrusted     bool
		timeout       time.Duration
		wantRC        int
		wantClass     string
	}{
		{"trusted", "https://example.com/", false, time.Second, 0, ""},
		{"untrusted", "https://example.com/", true, time.Second, 3, "tls_verify"},
		{"hostname", "https://wrong.test/", false, time.Second, 3, "tls_verify"},
		{"deadline", "https://example.com/slow", false, 50 * time.Millisecond, 4, "timeout"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := newProbeClient(proxy, caFile, test.timeout)
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			if test.untrusted {
				client.Transport.(*http.Transport).TLSClientConfig.RootCAs = x509.NewCertPool()
			}
			got := probe(context.Background(), client, target{"test", test.address, 204})
			if got.RC != test.wantRC || got.ErrorClass != test.wantClass {
				t.Fatalf("result = %+v; want rc=%d class=%s", got, test.wantRC, test.wantClass)
			}
			if test.wantRC == 0 && (got.HTTP != 204 || got.TLSVersion != tls.VersionName(tls.VersionTLS13)) {
				t.Fatalf("unexpected successful result: %+v", got)
			}
			wantHost := "example.com"
			if test.name == "hostname" {
				wantHost = "wrong.test"
			}
			select {
			case host := <-hostnames:
				if host != wantHost {
					t.Fatalf("proxy got hostname %q, want %q", host, wantHost)
				}
			case <-time.After(time.Second):
				t.Fatal("proxy never received target hostname")
			}
		})
	}
}

func startTestSOCKS(t *testing.T, upstream string) (string, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	hosts := make(chan string, 8)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				reader := bufio.NewReader(conn)
				header := make([]byte, 2)
				if _, err := io.ReadFull(reader, header); err != nil || header[0] != 5 {
					return
				}
				if _, err := io.CopyN(io.Discard, reader, int64(header[1])); err != nil {
					return
				}
				conn.Write([]byte{5, 0})
				request := make([]byte, 4)
				if _, err := io.ReadFull(reader, request); err != nil || request[0] != 5 || request[1] != 1 || request[3] != 3 {
					return // Require a real SOCKS5 domain-name request, not local DNS.
				}
				length, err := reader.ReadByte()
				if err != nil {
					return
				}
				destination := make([]byte, int(length)+2)
				if _, err := io.ReadFull(reader, destination); err != nil || binary.BigEndian.Uint16(destination[length:]) != 443 {
					return
				}
				hosts <- string(destination[:length])
				outbound, err := net.DialTimeout("tcp", upstream, time.Second)
				if err != nil {
					return
				}
				defer outbound.Close()
				conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				go func() { io.Copy(outbound, reader); outbound.Close() }()
				io.Copy(conn, outbound)
			}()
		}
	}()
	return listener.Addr().String(), hosts
}

func TestProbeRejectsCredentials(t *testing.T) {
	r := probe(context.Background(), nil, target{"private", "https://user:password@example.com/", 200})
	if r.RC != 2 || r.ErrorClass != "invalid_url" {
		t.Fatalf("credential URL accepted: %+v", r)
	}
}

type testDNSPlan struct {
	addresses []string
	truncate  bool
	drop      bool
}

// Serve real DNS wire packets over a custom UDP port and its TCP fallback.
// Queries never leave loopback, and no external DNS library is needed.
func testDNSAnswer(query []byte, addresses []string, truncated bool) []byte {
	if len(query) < 12 {
		return nil
	}
	end := 12
	for {
		if end >= len(query) {
			return nil
		}
		length := int(query[end])
		end++
		if length == 0 {
			break
		}
		if length > 63 || end+length > len(query) {
			return nil
		}
		end += length
	}
	if end+4 > len(query) {
		return nil
	}
	isA := binary.BigEndian.Uint16(query[end:]) == 1
	end += 4
	result := make([]byte, 12)
	copy(result[:2], query[:2])
	flags := uint16(0x8180)
	if truncated {
		flags |= 0x0200
	}
	binary.BigEndian.PutUint16(result[2:], flags)
	binary.BigEndian.PutUint16(result[4:], 1)
	result = append(result, query[12:end]...)
	if isA && !truncated {
		binary.BigEndian.PutUint16(result[6:], uint16(len(addresses)))
		for _, address := range addresses {
			result = append(result, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
			result = append(result, net.ParseIP(address).To4()...)
		}
	}
	return result
}

func startTestDNS(t *testing.T, plan testDNSPlan) (string, <-chan string) {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	protocols := make(chan string, 32)
	response := func(query []byte, protocol string) []byte {
		protocols <- protocol
		if plan.drop {
			return nil
		}
		return testDNSAnswer(query, plan.addresses, plan.truncate && protocol == "udp")
	}
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, address, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			if answer := response(buffer[:n], "udp"); answer != nil {
				udp.WriteTo(answer, address)
			}
		}
	}()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				length := make([]byte, 2)
				if _, err := io.ReadFull(conn, length); err != nil {
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(length))
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				if answer := response(query, "tcp"); answer != nil {
					binary.BigEndian.PutUint16(length, uint16(len(answer)))
					conn.Write(append(length, answer...))
				}
			}()
		}
	}()
	return udp.LocalAddr().String(), protocols
}

func TestResolveIPv4CustomUDPAndTCPFallback(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		t.Run(map[bool]string{false: "udp", true: "tcp-fallback"}[fallback], func(t *testing.T) {
			server, protocols := startTestDNS(t, testDNSPlan{
				addresses: []string{"192.0.2.11", "192.0.2.12", "192.0.2.11"}, truncate: fallback,
			})
			got, err := resolveIPv4(context.Background(), "node.example.", server, "", time.Second)
			if err != nil || !reflect.DeepEqual(got, []string{"192.0.2.11", "192.0.2.12"}) {
				t.Fatalf("addresses = %v, err = %v", got, err)
			}
			seen := make(map[string]bool)
			for len(protocols) > 0 {
				seen[<-protocols] = true
			}
			if !seen["udp"] || seen["tcp"] != fallback {
				t.Fatalf("unexpected DNS protocols: %v", seen)
			}
		})
	}
}

func TestResolveIPv4DeadlineAndNoARecords(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		server, _ := startTestDNS(t, testDNSPlan{drop: true})
		start := time.Now()
		if got, err := resolveIPv4(context.Background(), "node.example.", server, "", 40*time.Millisecond); err == nil || len(got) != 0 {
			t.Fatalf("unresponsive DNS accepted: %v, %v", got, err)
		}
		if time.Since(start) > 500*time.Millisecond {
			t.Fatal("DNS lookup exceeded its deadline")
		}
	})
	t.Run("no-A-records", func(t *testing.T) {
		server, _ := startTestDNS(t, testDNSPlan{})
		if got, err := resolveIPv4(context.Background(), "node.example.", server, "", time.Second); err == nil || len(got) != 0 {
			t.Fatalf("empty answer accepted: %v, %v", got, err)
		}
	})
}

func TestResolveIPv4RejectsUnsafeParameters(t *testing.T) {
	for _, host := range []string{"", "https://node.example/", "user@node.example", "node.example?token=x", "node.example#x", "node.example\n", "node.example\x00", "节点.example", "bad..example", "-bad.example", "bad-.example", "999.0.0.1", "::1", strings.Repeat("a", 64) + ".example"} {
		if got, err := resolveIPv4(context.Background(), host, "127.0.0.1:53", "", time.Second); err == nil || len(got) != 0 {
			t.Errorf("unsafe hostname accepted: %q", host)
		}
	}
	for _, server := range []string{"", "dns.example:53", "udp://127.0.0.1:53", "user@127.0.0.1:53", "127.0.0.1:53?x", "127.0.0.1:53\n", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:+53", "[::1%lo0]:53"} {
		if got, err := resolveIPv4(context.Background(), "node.example.", server, "", time.Second); err == nil || len(got) != 0 {
			t.Errorf("unsafe DNS server accepted: %q", server)
		}
	}
	for _, host := range []string{"NODE.Example.", "xn--node-123.example", "192.0.2.11"} {
		if !validResolveHost(host) {
			t.Errorf("valid hostname rejected: %q", host)
		}
	}
	got, err := resolveIPv4(context.Background(), "192.0.2.11", "[::1]:53", "", time.Second)
	if err != nil || !reflect.DeepEqual(got, []string{"192.0.2.11"}) {
		t.Fatalf("IPv4 literal resolution = %v, %v", got, err)
	}
}

func TestResolveCLIProcess(t *testing.T) {
	if os.Getenv("SS_PROBE_TEST_CLI") != "1" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("SS_PROBE_TEST_ARGS")), &args); err != nil {
		os.Exit(99)
	}
	os.Args = append([]string{"ss-https-probe"}, args...)
	main()
	os.Exit(0)
}

func TestResolveCLIWithoutHTTPSCredentials(t *testing.T) {
	server, _ := startTestDNS(t, testDNSPlan{addresses: []string{"192.0.2.11", "192.0.2.12", "192.0.2.11"}})
	args, _ := json.Marshal([]string{"-resolve", "node.example.", "-dns", server, "-timeout", "1s", "-proxy", "invalid-proxy", "-ca", "missing-ca.pem"})
	cmd := exec.Command(os.Args[0], "-test.run=^TestResolveCLIProcess$")
	cmd.Env = append(os.Environ(), "SS_PROBE_TEST_CLI=1", "SS_PROBE_TEST_ARGS="+string(args))
	output, err := cmd.CombinedOutput()
	if err != nil || string(output) != "192.0.2.11\n192.0.2.12\n" {
		t.Fatalf("DNS CLI output = %q, err = %v", output, err)
	}
	args, _ = json.Marshal([]string{"-resolve", "user@node.example", "-dns", server, "-timeout", "1s"})
	cmd = exec.Command(os.Args[0], "-test.run=^TestResolveCLIProcess$")
	cmd.Env = append(os.Environ(), "SS_PROBE_TEST_CLI=1", "SS_PROBE_TEST_ARGS="+string(args))
	output, err = cmd.CombinedOutput()
	if err == nil || string(output) != "IPv4 DNS resolution failed\n" {
		t.Fatalf("invalid DNS CLI output = %q, err = %v", output, err)
	}
}

func testRoots(t *testing.T, server *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func startTestDoH(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" || r.Header.Get("Accept") != "application/dns-message" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		wire, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(testDNSAnswer(wire, []string{"192.0.2.11", "192.0.2.12", "192.0.2.11"}, false))
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	t.Cleanup(server.Close)
	return server
}

func TestResolveDoHVerifiedTLSAndHostname(t *testing.T) {
	server := startTestDoH(t)
	roots := testRoots(t, server)
	got, err := resolveIPv4(context.Background(), "node.example.", server.URL+"/private-path?token=synthetic", roots, time.Second)
	if err != nil || !reflect.DeepEqual(got, []string{"192.0.2.11", "192.0.2.12"}) {
		t.Fatalf("trusted DoH = %v, %v", got, err)
	}
	client, err := newDoHClient(roots, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("DoH transport must disable system proxies and verify TLS")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	untrusted := filepath.Join(t.TempDir(), "untrusted.pem")
	if err := os.WriteFile(untrusted, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct{ endpoint, ca string }{
		{server.URL, untrusted}, {strings.Replace(server.URL, "127.0.0.1", "localhost", 1), roots}, {server.URL, ""},
	} {
		if addresses, err := resolveIPv4(context.Background(), "node.example.", input.endpoint, input.ca, time.Second); err == nil || len(addresses) != 0 {
			t.Fatal("untrusted, hostname-mismatched or missing CA was accepted")
		}
	}
}

func TestDoHRedirectBodyLimitsAndCancellation(t *testing.T) {
	var redirected atomic.Int32
	started := make(chan struct{}, 4)
	cancelled := make(chan struct{}, 4)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/destination", http.StatusTemporaryRedirect)
			return
		}
		if r.URL.Path == "/destination" {
			redirected.Add(1)
		}
		if r.URL.Path == "/slow" {
			io.Copy(io.Discard, r.Body)
			started <- struct{}{}
			<-r.Context().Done()
			cancelled <- struct{}{}
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		switch r.URL.Path {
		case "/max":
			w.Write(make([]byte, 65535))
		case "/oversize":
			w.Write(make([]byte, 65536))
		}
	}))
	defer server.Close()
	client, err := newDoHClient(testRoots(t, server), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	for _, path := range []string{"/max", "/oversize", "/empty", "/redirect"} {
		t.Run(path, func(t *testing.T) {
			conn := dialDoH(context.Background(), client, server.URL+path)
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(time.Second))
			if _, err := conn.Write([]byte{0, 1, 1}); err != nil {
				t.Fatal(err)
			}
			length := make([]byte, 2)
			_, err := io.ReadFull(conn, length)
			if path != "/max" {
				if err == nil {
					t.Fatal("invalid DoH response accepted")
				}
				return
			}
			if err != nil || binary.BigEndian.Uint16(length) != 65535 {
				t.Fatalf("maximum DoH frame rejected: %v", err)
			}
			if n, err := io.CopyN(io.Discard, conn, 65535); err != nil || n != 65535 {
				t.Fatalf("maximum body truncated: %d, %v", n, err)
			}
		})
	}
	if redirected.Load() != 0 {
		t.Fatal("DoH followed a redirect")
	}
	for _, useDeadline := range []bool{false, true} {
		conn := dialDoH(context.Background(), client, server.URL+"/slow")
		if _, err := conn.Write([]byte{0, 1, 1}); err != nil {
			t.Fatal(err)
		}
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("DoH request did not start")
		}
		if useDeadline {
			conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			if _, err := conn.Read(make([]byte, 1)); err == nil {
				t.Fatal("DoH pipe ignored deadline")
			}
		}
		conn.Close()
		select {
		case <-cancelled:
		case <-time.After(time.Second):
			t.Fatal("closing DoH connection did not cancel HTTP")
		}
	}
}

func TestResolveDoHFallbackSharesDeadline(t *testing.T) {
	good := startTestDoH(t)
	var attempts atomic.Int32
	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		if r.URL.Path == "/slow" {
			io.Copy(io.Discard, r.Body)
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer bad.Close()
	roots := testRoots(t, good)
	got, err := resolveIPv4(context.Background(), "node.example.", bad.URL+","+good.URL, roots, time.Second)
	if err != nil || len(got) != 2 || attempts.Load() == 0 {
		t.Fatalf("DoH fallback failed: %v, %v", got, err)
	}
	start := time.Now()
	got, err = resolveIPv4(context.Background(), "node.example.", bad.URL+"/slow,"+good.URL, roots, 2400*time.Millisecond)
	if err != nil || len(got) != 2 || time.Since(start) > 2800*time.Millisecond {
		t.Fatalf("non-final upstream did not yield its budget: %v, %v, %s", got, err, time.Since(start))
	}
	start = time.Now()
	got, err = resolveIPv4(context.Background(), "node.example.", bad.URL+"/slow,"+bad.URL+"/slow,"+bad.URL+"/slow", roots, 80*time.Millisecond)
	if err == nil || len(got) != 0 || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("DNS upstreams reset shared deadline: %v, %v, %s", got, err, time.Since(start))
	}
	udp, _ := startTestDNS(t, testDNSPlan{addresses: []string{"192.0.2.21"}})
	got, err = resolveIPv4(context.Background(), "node.example.", bad.URL+","+udp, roots, time.Second)
	if err != nil || !reflect.DeepEqual(got, []string{"192.0.2.21"}) {
		t.Fatalf("DoH to UDP fallback failed: %v, %v", got, err)
	}
}

func TestDNSUpstreamValidationAndDoHCLI(t *testing.T) {
	for _, value := range []string{"https://user:secret@example.com/dns", "http://example.com/dns", "https://example.com/#", "https://example.com/dns#secret", "https://example.com:0/", "https://example.com:65536/", "https://example.com:/", "https://example.com/%0a", "https://example.com/?token=%00", "https://example.com/\n", "https://节点.example/", "https://example.com/,,127.0.0.1:53", "127.0.0.1:53,127.0.0.1:53,127.0.0.1:53,127.0.0.1:53,127.0.0.1:53"} {
		if _, err := parseDNSUpstreams(value); err == nil {
			t.Errorf("unsafe upstream accepted: %q", value)
		}
	}
	for _, value := range []string{"https://example.com/dns?token=synthetic%20value", "https://[::1]:443/dns", "https://example.com:8443/path,127.0.0.1:53"} {
		if _, err := parseDNSUpstreams(value); err != nil {
			t.Errorf("valid upstream rejected: %q", value)
		}
	}
	server := startTestDoH(t)
	args, _ := json.Marshal([]string{"-resolve", "node.example.", "-dns", server.URL + "/private-path?token=synthetic", "-ca", testRoots(t, server), "-timeout", "1s", "-proxy", "invalid-proxy"})
	cmd := exec.Command(os.Args[0], "-test.run=^TestResolveCLIProcess$")
	cmd.Env = append(os.Environ(), "SS_PROBE_TEST_CLI=1", "SS_PROBE_TEST_ARGS="+string(args))
	output, err := cmd.CombinedOutput()
	if err != nil || string(output) != "192.0.2.11\n192.0.2.12\n" {
		t.Fatalf("DoH CLI output = %q, err = %v", output, err)
	}
}
