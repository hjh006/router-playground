package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type target struct {
	name, address string
	expect        int
}

var presets = []target{
	{"google", "https://www.google.com/generate_204", 204},
	{"youtube", "https://www.youtube.com/generate_204", 204},
	{"telegram", "https://telegram.org/", 200},
}

type result struct {
	Target     string `json:"target"`
	Host       string `json:"host"`
	RC         int    `json:"rc"`
	HTTP       int    `json:"http"`
	MS         int64  `json:"ms"`
	TCPMS      int64  `json:"tcp_ms,omitempty"`
	TLSMS      int64  `json:"tls_ms,omitempty"`
	FirstMS    int64  `json:"first_byte_ms,omitempty"`
	TLSVersion string `json:"tls_version,omitempty"`
	Phase      string `json:"phase"`
	ErrorClass string `json:"error_class,omitempty"`
	Error      string `json:"error,omitempty"`
}

// RC: 0 expected status, 1 unexpected HTTP status, 2 connection/protocol,
// 3 TLS certificate verification, 4 deadline. Process exits 1 if any probe fails.
func probe(ctx context.Context, client *http.Client, item target) result {
	started := time.Now()
	u, err := url.Parse(item.address)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return result{Target: item.name, RC: 2, Phase: "input", ErrorClass: "invalid_url", Error: "HTTPS URL without credentials required"}
	}
	r := result{Target: item.name, Host: u.Hostname(), Phase: "proxy_connect"}
	var lock sync.Mutex
	var tcpStart, tlsStart time.Time
	trace := &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) { lock.Lock(); tcpStart = time.Now(); lock.Unlock() },
		ConnectDone: func(_, _ string, _ error) {
			lock.Lock()
			r.TCPMS = time.Since(tcpStart).Milliseconds()
			lock.Unlock()
		},
		TLSHandshakeStart: func() { lock.Lock(); r.Phase = "tls_handshake"; tlsStart = time.Now(); lock.Unlock() },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			lock.Lock()
			r.TLSMS = time.Since(tlsStart).Milliseconds()
			if err == nil {
				r.Phase = "response"
			}
			lock.Unlock()
		},
		GotFirstResponseByte: func() { lock.Lock(); r.FirstMS = time.Since(started).Milliseconds(); lock.Unlock() },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, item.address, nil)
	if err != nil {
		r.RC, r.ErrorClass, r.Error = 2, "invalid_url", "invalid HTTPS request"
		return r
	}
	req.Header.Set("User-Agent", "ss-https-probe/1")
	response, requestErr := client.Do(req)
	lock.Lock()
	defer lock.Unlock()
	r.MS = time.Since(started).Milliseconds()
	if requestErr != nil {
		if wrapped, ok := requestErr.(*url.Error); ok {
			requestErr = wrapped.Err // Do not print URL query strings or credentials.
		}
		r.RC, r.ErrorClass = classifyError(requestErr, r.Phase)
		r.Error = requestErr.Error()
		return r
	}
	defer response.Body.Close()
	r.HTTP = response.StatusCode
	r.Phase = "complete"
	if response.TLS != nil {
		r.TLSVersion = tls.VersionName(response.TLS.Version)
	}
	if response.StatusCode != item.expect {
		r.RC, r.ErrorClass = 1, "unexpected_http_status"
		r.Error = fmt.Sprintf("expected HTTP %d", item.expect)
	}
	return r
}

func classifyError(err error, phase string) (int, string) {
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &unknown) || errors.As(err, &hostname) || errors.As(err, &invalid) {
		return 3, "tls_verify"
	}
	var networkError net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &networkError) && networkError.Timeout() {
		return 4, "timeout"
	}
	if phase == "tls_handshake" {
		return 2, "tls_protocol"
	}
	if phase == "proxy_connect" {
		return 2, "proxy_connect"
	}
	return 2, "http_protocol"
}

func newProbeClient(proxyAddress, caFile string, timeout time.Duration) (*http.Client, error) {
	if _, _, err := net.SplitHostPort(proxyAddress); err != nil || strings.ContainsAny(proxyAddress, "@/?#") {
		return nil, fmt.Errorf("proxy must be a host:port without credentials")
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA file contains no certificates")
	}
	// Go 1.23 net/http's SOCKS5h implementation sends domain names to the proxy
	// (src/net/http/transport.go and socks_bundle.go); no local target DNS lookup.
	proxyURL := &url.URL{Scheme: "socks5h", Host: proxyAddress}
	transport := &http.Transport{
		Proxy:                 http.ProxyURL(proxyURL),
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		TLSClientConfig:       &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
	}
	return &http.Client{
		Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func main() {
	proxyAddress := flag.String("proxy", "127.0.0.1:23459", "SOCKS5 host:port; target DNS is resolved by the proxy")
	caFile := flag.String("ca", "", "Required PEM CA bundle; destination TLS verification is always enabled")
	targetName := flag.String("target", "all", "all, google, youtube, or telegram; sequential requests")
	address := flag.String("url", "", "Optional single HTTPS URL instead of preset targets")
	expect := flag.Int("expect", 200, "Expected status for -url")
	format := flag.String("format", "json", "json or curl (single target only; http_code|seconds and curl-like exit status)")
	timeout := flag.Duration("timeout", 12*time.Second, "Total deadline per request (1s..60s)")
	flag.Parse()
	if *caFile == "" || *timeout < time.Second || *timeout > 60*time.Second || *expect < 100 || *expect > 599 || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "required: -ca FILE; timeout 1s..60s; expect 100..599; no positional arguments")
		os.Exit(2)
	}
	client, err := newProbeClient(*proxyAddress, *caFile, *timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	items := presets
	if *address != "" {
		items = []target{{"custom", *address, *expect}}
	} else if *targetName != "all" {
		items = nil
		for _, item := range presets {
			if item.name == *targetName {
				items = append(items, item)
			}
		}
		if len(items) == 0 {
			fmt.Fprintln(os.Stderr, "unknown target")
			os.Exit(2)
		}
	}
	if *format != "json" && *format != "curl" || *format == "curl" && len(items) != 1 {
		fmt.Fprintln(os.Stderr, "format must be json or curl; curl requires one -target or -url")
		os.Exit(2)
	}
	status := 0
	for _, item := range items {
		r := probe(context.Background(), client, item)
		if *format == "curl" {
			fmt.Printf("%03d|%.3f\n", r.HTTP, float64(r.MS)/1000)
			client.CloseIdleConnections()
			if r.HTTP != 0 {
				os.Exit(0) // Match curl without --fail: any HTTP status is a completed transfer.
			}
			switch r.RC {
			case 4:
				os.Exit(28)
			case 3:
				os.Exit(60)
			}
			if r.ErrorClass == "tls_protocol" {
				os.Exit(35)
			}
			os.Exit(7)
		}
		if r.RC != 0 {
			status = 1
		}
		if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
			fmt.Fprintln(os.Stderr, "write JSON result:", err)
			os.Exit(2)
		}
	}
	client.CloseIdleConnections()
	os.Exit(status)
}
