package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"strings"
	"testing"
	"time"
)

func verified(context.Context) (string, string) { return "stable", "" }
func TestThreeRealLoopbackConnections(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan int, 1)
	go func() {
		n := 0
		for n < 3 {
			c, e := listener.Accept()
			if e != nil {
				break
			}
			n++
			_ = c.Close()
		}
		accepted <- n
	}()
	d := &net.Dialer{Timeout: time.Second}
	r := measure(context.Background(), listener.Addr().String(), time.Second, verified, d.DialContext)
	if r.Status != "ok" || r.State != "ok" || r.Successes != 3 || r.LatencyMS == nil || len(r.SamplesMS) != 3 {
		t.Fatalf("bad measured result: %+v", r)
	}
	if <-accepted != 3 {
		t.Fatal("did not create three independent TCP connections")
	}
	sorted := append([]int64(nil), r.SamplesMS...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	if *r.LatencyMS != sorted[1] {
		t.Fatal("result is not the actual median")
	}
	encoded, _ := json.Marshal(r)
	if strings.Contains(string(encoded), listener.Addr().String()) || strings.Contains(string(encoded), "127.0.0.1") {
		t.Fatal("endpoint leaked into result")
	}
}
func TestRefusedLoopbackHasNoLatency(t *testing.T) {
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	d := &net.Dialer{Timeout: 50 * time.Millisecond}
	r := measure(context.Background(), address, 50*time.Millisecond, verified, d.DialContext)
	if r.Status != "failed" || r.LatencyMS != nil || len(r.SamplesMS) != 0 || r.Successes != 0 || r.Reason != "connect_failed" {
		t.Fatalf("refusal became latency: %+v", r)
	}
}
func TestAnyFailedSampleDiscardsSuccessfulTimings(t *testing.T) {
	calls := 0
	dial := func(context.Context, string, string) (net.Conn, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("synthetic endpoint detail must never escape")
		}
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil
	}
	r := measure(context.Background(), "127.0.0.1:1", time.Second, verified, dial)
	if calls != 3 || r.Successes != 2 || r.Status != "failed" || r.LatencyMS != nil || len(r.SamplesMS) != 0 {
		t.Fatalf("partial success was accepted: %+v", r)
	}
	encoded, _ := json.Marshal(r)
	if strings.Contains(string(encoded), "synthetic") {
		t.Fatal("raw network error leaked")
	}
}
func TestTimeoutsAreNotFastFailures(t *testing.T) {
	calls := 0
	r := measure(context.Background(), "127.0.0.1:1", time.Second, verified, func(context.Context, string, string) (net.Conn, error) { calls++; return nil, context.DeadlineExceeded })
	if calls != 3 || r.Status != "timeout" || r.Reason != "connect_timeout" || r.LatencyMS != nil || len(r.SamplesMS) != 0 {
		t.Fatalf("bad timeout classification: %+v", r)
	}
}
func TestUnverifiedPathNeverDials(t *testing.T) {
	calls := 0
	r := measure(context.Background(), "127.0.0.1:1", time.Second, func(context.Context) (string, string) { return "", "output_redirect" }, func(context.Context, string, string) (net.Conn, error) { calls++; return nil, nil })
	if calls != 0 || r.Status != "path_unverified" || r.Reason != "output_redirect" || r.LatencyMS != nil {
		t.Fatalf("unverified path measured: %+v", r)
	}
}
func TestPostGuardFailureOrChangeDiscardsAllSamples(t *testing.T) {
	for _, post := range []string{"failure", "change"} {
		t.Run(post, func(t *testing.T) {
			checks := 0
			guard := func(context.Context) (string, string) {
				checks++
				if checks == 1 {
					return "before", ""
				}
				if post == "failure" {
					return "", "command_failed"
				}
				return "after", ""
			}
			r := measure(context.Background(), "127.0.0.1:1", time.Second, guard, func(context.Context, string, string) (net.Conn, error) {
				a, b := net.Pipe()
				_ = b.Close()
				return a, nil
			})
			if checks != 2 || r.Successes != 3 || r.Status != "path_unverified" || r.LatencyMS != nil || len(r.SamplesMS) != 0 {
				t.Fatalf("post-check did not revoke measurement: %+v", r)
			}
		})
	}
}
func TestDeadlineCancelsPendingDial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	r := measure(ctx, "127.0.0.1:1", time.Second, verified, func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() })
	if time.Since(started) > time.Second || r.Status != "timeout" || r.LatencyMS != nil {
		t.Fatalf("deadline did not bound work: %+v", r)
	}
}
func TestHelpVersionAndInvalidInputDoNotReadSystemOrNetwork(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"-version"}, {"-address", "example.test:443"}, {"-address", "127.0.0.1:80", "-samples", "2"}, {"-address", "127.0.0.1:0"}, {"-secret-endpoint"}} {
		var out bytes.Buffer
		code := run(context.Background(), args, &out)
		if args[0] == "-h" || args[0] == "-version" {
			if code != 0 {
				t.Fatal("help/version failed")
			}
			continue
		}
		if code != 2 {
			t.Fatal("invalid arguments accepted")
		}
		var r result
		if json.Unmarshal(out.Bytes(), &r) != nil || r.Reason != "invalid_arguments" {
			t.Fatal("invalid input must emit one sanitized JSON object")
		}
		if strings.Contains(out.String(), "example.test") || strings.Contains(out.String(), "secret-endpoint") {
			t.Fatal("invalid input leaked arguments")
		}
	}
}
