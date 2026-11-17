package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"
)

type result struct {
	Version   int     `json:"version"`
	Method    string  `json:"method"`
	Target    string  `json:"target"`
	Status    string  `json:"status"`
	State     string  `json:"state"`
	LatencyMS *int64  `json:"latency_ms"`
	Samples   int     `json:"samples"`
	Successes int     `json:"successes"`
	SamplesMS []int64 `json:"samples_ms"`
	Reason    string  `json:"reason"`
}

func newResult() result {
	return result{Version: 1, Method: "router_tcp", Target: "entry", Status: "failed", State: "failed", Samples: 3, SamplesMS: []int64{}, Reason: "connect_failed"}
}
func (r *result) state(state, reason string) {
	r.Status = state
	r.State = state
	r.Reason = reason
	r.LatencyMS = nil
	r.SamplesMS = []int64{}
}

type verifyPath func(context.Context) (string, string)
type dialTCP func(context.Context, string, string) (net.Conn, error)

// No SOCKS/HTTP proxy, resolver, TLS, payload, or socket mark is used here.
func measure(ctx context.Context, address string, timeout time.Duration, verify verifyPath, dial dialTCP) result {
	r := newResult()
	before, reason := verify(ctx)
	if reason != "" {
		r.state("path_unverified", reason)
		return r
	}
	values := make([]int64, 0, 3)
	failure := ""
	timedOut := false
	for i := 0; i < 3; i++ {
		if ctx.Err() != nil {
			timedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
			if timedOut {
				failure = "deadline_exceeded"
			} else {
				failure = "cancelled"
			}
			break
		}
		call, cancel := context.WithTimeout(ctx, timeout)
		started := time.Now()
		conn, err := dial(call, "tcp4", address)
		elapsed := time.Since(started).Milliseconds()
		cancel()
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			var network net.Error
			if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &network) && network.Timeout()) {
				timedOut = true
				failure = "connect_timeout"
			} else {
				failure = "connect_failed"
			}
			continue
		}
		if conn == nil {
			failure = "connect_failed"
			continue
		}
		if err = conn.Close(); err != nil {
			failure = "close_failed"
			continue
		}
		r.Successes++
		values = append(values, elapsed)
	}
	after, reason := verify(ctx)
	if reason != "" {
		r.state("path_unverified", "post_guard_failed")
		return r
	}
	if before != after {
		r.state("path_unverified", "path_changed")
		return r
	}
	if r.Successes != 3 {
		if timedOut {
			r.state("timeout", failure)
		} else {
			r.state("failed", failure)
		}
		return r
	}
	r.SamplesMS = values
	ordered := append([]int64(nil), values...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	r.LatencyMS = &ordered[1]
	r.Status = "ok"
	r.State = "ok"
	r.Reason = ""
	return r
}

func run(ctx context.Context, args []string, out io.Writer) int {
	flags := flag.NewFlagSet("ss-tcp-probe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}
	address := flags.String("address", "", "numeric IPv4:port; no DNS")
	timeout := flags.Duration("timeout", 5*time.Second, "per-connection timeout, at most 5s")
	samples := flags.Int("samples", 3, "exactly three fresh connections")
	version := flags.Bool("version", false, "print tool version without network access")
	checkOnly := flags.Bool("check-path", false, "only verify the path; never connect")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(out, "ss-tcp-probe -address IPv4:port -timeout 5s -samples 3 [-check-path]\nRead-only OUTPUT/WAN guard; unverified paths never produce latency.")
			return 0
		}
		r := newResult()
		r.state("failed", "invalid_arguments")
		_ = json.NewEncoder(out).Encode(r)
		return 2
	}
	if *version {
		fmt.Fprintln(out, "ss-tcp-probe/1.0.0")
		return 0
	}
	parsed, err := netip.ParseAddrPort(*address)
	if err != nil || !parsed.Addr().Is4() || parsed.Port() == 0 || parsed.Addr().IsUnspecified() || parsed.Addr().IsMulticast() || flags.NArg() != 0 || *samples != 3 || *timeout <= 0 || *timeout > 5*time.Second {
		r := newResult()
		r.state("failed", "invalid_arguments")
		_ = json.NewEncoder(out).Encode(r)
		return 2
	}
	bounded, cancel := context.WithTimeout(ctx, 19*time.Second)
	defer cancel()
	if *checkOnly {
		return reportPath(bounded, parsed.Addr(), systemRead, out)
	}
	verify := func(ctx context.Context) (string, string) { return verifySystemPath(ctx, parsed.Addr(), systemRead) }
	dialer := &net.Dialer{Timeout: *timeout}
	r := measure(bounded, parsed.String(), *timeout, verify, dialer.DialContext)
	_ = json.NewEncoder(out).Encode(r)
	if r.Status == "ok" {
		return 0
	}
	if r.Status == "path_unverified" {
		return 2
	}
	return 1
}

// This diagnostic schema intentionally has no measurement status or latency fields.
func reportPath(ctx context.Context, address netip.Addr, read commandRead, out io.Writer) int {
	_, reason := verifySystemPath(ctx, address, read)
	report := struct {
		Version  int    `json:"version"`
		Method   string `json:"method"`
		Target   string `json:"target"`
		Verified bool   `json:"path_verified"`
		Reason   string `json:"reason"`
	}{1, "router_tcp", "entry", reason == "", reason}
	_ = json.NewEncoder(out).Encode(report)
	if reason == "" {
		return 0
	}
	return 2
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout))
}
