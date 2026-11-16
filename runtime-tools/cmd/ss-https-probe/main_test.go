package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
