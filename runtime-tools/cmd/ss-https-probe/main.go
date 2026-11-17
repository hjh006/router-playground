package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strconv"
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

func loadRoots(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA file contains no certificates")
	}
	return roots, nil
}

func newProbeClient(proxyAddress, caFile string, timeout time.Duration) (*http.Client, error) {
	if _, _, err := net.SplitHostPort(proxyAddress); err != nil || strings.ContainsAny(proxyAddress, "@/?#") {
		return nil, fmt.Errorf("proxy must be a host:port without credentials")
	}
	roots, err := loadRoots(caFile)
	if err != nil {
		return nil, err
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

func validResolveHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.To4() != nil
	}
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	numeric := true
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' {
				numeric = false
			} else if c < '0' || c > '9' {
				return false
			}
		}
	}
	return !numeric // Reject malformed IPv4 literals instead of treating them as DNS names.
}

func validPort(port string) bool {
	if len(port) == 0 || len(port) > 5 {
		return false
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return false
	}
	return true
}

type dnsUpstream struct {
	address string
	doh     bool
}

func hasControl(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < ' ' || value[i] == 127 {
			return true
		}
	}
	return false
}

func parseDNSUpstreams(value string) ([]dnsUpstream, error) {
	parts := strings.Split(value, ",")
	if len(parts) > 4 {
		return nil, errors.New("at most four DNS upstreams are allowed")
	}
	var result []dnsUpstream
	for _, part := range parts {
		if part == "" || hasControl(part) || strings.Contains(part, " ") {
			return nil, errors.New("invalid DNS upstream")
		}
		if strings.HasPrefix(part, "https://") {
			u, err := url.Parse(part)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || strings.Contains(part, "#") || u.Opaque != "" || hasControl(u.Path) {
				return nil, errors.New("invalid HTTPS DNS endpoint")
			}
			query, err := url.QueryUnescape(u.RawQuery)
			if err != nil || hasControl(query) {
				return nil, errors.New("invalid HTTPS DNS query")
			}
			if !validResolveHost(u.Hostname()) && net.ParseIP(u.Hostname()) == nil {
				return nil, errors.New("invalid HTTPS DNS hostname")
			}
			if u.Port() != "" && !validPort(u.Port()) || strings.HasSuffix(u.Host, ":") {
				return nil, errors.New("invalid HTTPS DNS port")
			}
			result = append(result, dnsUpstream{u.String(), true})
		} else {
			ip, port, err := net.SplitHostPort(part)
			if err != nil || net.ParseIP(ip) == nil || !validPort(port) {
				return nil, errors.New("DNS server must be a literal IP and port")
			}
			number, _ := strconv.Atoi(port)
			result = append(result, dnsUpstream{net.JoinHostPort(net.ParseIP(ip).String(), strconv.Itoa(number)), false})
		}
	}
	return result, nil
}

func newDoHClient(caFile string, timeout time.Duration) (*http.Client, error) {
	roots, err := loadRoots(caFile)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:               nil, // DNS bootstrap must never follow system proxy environment variables.
		DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
		TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, DisableKeepAlives: true,
	}
	return &http.Client{Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

type dohConn struct {
	net.Conn
	cancel context.CancelFunc
}

func (conn *dohConn) Close() error {
	conn.cancel()
	return conn.Conn.Close()
}

// Resolver detects this as a stream, not PacketConn, so it supplies TCP DNS
// framing. Only the framing is adapted; Resolver validates the DNS response.
func dialDoH(ctx context.Context, client *http.Client, endpoint string) net.Conn {
	ctx, cancel := context.WithCancel(ctx)
	local, remote := net.Pipe()
	go func() {
		defer remote.Close()
		defer cancel()
		length := make([]byte, 2)
		if _, err := io.ReadFull(remote, length); err != nil {
			return
		}
		query := make([]byte, int(binary.BigEndian.Uint16(length)))
		if len(query) == 0 {
			return
		}
		if _, err := io.ReadFull(remote, query); err != nil {
			return
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		response, err := client.Do(req)
		if err != nil {
			return
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK || !strings.EqualFold(strings.TrimSpace(strings.SplitN(response.Header.Get("Content-Type"), ";", 2)[0]), "application/dns-message") {
			return
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 65536))
		if err != nil || len(body) == 0 || len(body) > 65535 {
			return
		}
		binary.BigEndian.PutUint16(length, uint16(len(body)))
		remote.Write(append(length, body...))
	}()
	return &dohConn{local, cancel}
}

func resolveIPv4(ctx context.Context, host, servers, caFile string, timeout time.Duration) ([]string, error) {
	if !validResolveHost(host) || timeout <= 0 {
		return nil, errors.New("invalid DNS lookup parameters")
	}
	upstreams, err := parseDNSUpstreams(servers)
	if err != nil {
		return nil, err
	}
	var client *http.Client
	for _, upstream := range upstreams {
		if upstream.doh {
			client, err = newDoHClient(caFile, timeout)
			if err != nil {
				return nil, errors.New("HTTPS DNS requires a valid CA bundle")
			}
			defer client.CloseIdleConnections()
			break
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for index, upstream := range upstreams {
		deadline, _ := ctx.Deadline()
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		if index < len(upstreams)-1 && remaining > 2*time.Second {
			remaining = 2 * time.Second
		}
		attempt, stop := context.WithTimeout(ctx, remaining)
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if upstream.doh {
				return dialDoH(ctx, client, upstream.address), nil
			}
			return (&net.Dialer{}).DialContext(ctx, network, upstream.address)
		}}
		ips, err := resolver.LookupIP(attempt, "ip4", host)
		stop()
		if err != nil {
			continue
		}
		var result []string
		seen := make(map[string]bool)
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				address := ipv4.String()
				if !seen[address] {
					result = append(result, address)
					seen[address] = true
				}
			}
		}
		if len(result) != 0 {
			return result, nil
		}
	}
	return nil, errors.New("IPv4 DNS lookup failed")
}

func main() {
	proxyAddress := flag.String("proxy", "127.0.0.1:23459", "SOCKS5 host:port; target DNS is resolved by the proxy")
	caFile := flag.String("ca", "", "Required PEM CA bundle; destination TLS verification is always enabled")
	targetName := flag.String("target", "all", "all, google, youtube, or telegram; sequential requests")
	address := flag.String("url", "", "Optional single HTTPS URL instead of preset targets")
	expect := flag.Int("expect", 200, "Expected status for -url")
	format := flag.String("format", "json", "json or curl (single target only; http_code|seconds and curl-like exit status)")
	timeout := flag.Duration("timeout", 12*time.Second, "Total deadline per request (1s..60s)")
	resolveHost := flag.String("resolve", "", "Resolve an ASCII hostname or IPv4 literal; print unique IPv4 addresses, one per line")
	dnsServer := flag.String("dns", "", "Up to four comma-separated literal IP:port or HTTPS DoH endpoints; HTTPS requires -ca")
	flag.Parse()
	if *resolveHost != "" || *dnsServer != "" {
		if *resolveHost == "" || *dnsServer == "" || *timeout < time.Second || *timeout > 60*time.Second || flag.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "required: -resolve HOST -dns UPSTREAMS; HTTPS requires -ca; timeout 1s..60s; no positional arguments")
			os.Exit(2)
		}
		addresses, err := resolveIPv4(context.Background(), *resolveHost, *dnsServer, *caFile, *timeout)
		if err != nil {
			fmt.Fprintln(os.Stderr, "IPv4 DNS resolution failed")
			os.Exit(1)
		}
		for _, address := range addresses {
			fmt.Println(address)
		}
		return
	}
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
