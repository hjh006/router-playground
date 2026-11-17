package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const rulesFixture = `*nat
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [10:456]
:POSTROUTING ACCEPT [0:0]
:SHADOWSOCKS_EXT - [0:0]
-A OUTPUT -p tcp -m set --match-set router dst -j REDIRECT --to-ports 3333
-A OUTPUT -p tcp -m mark --mark 0x3100/0xff00 -j SHADOWSOCKS_EXT
-A SHADOWSOCKS_EXT -m set --match-set white_list dst -j RETURN
COMMIT
*mangle
:OUTPUT ACCEPT [0:0]
COMMIT
*filter
:OUTPUT ACCEPT [0:0]
COMMIT
`
const setsFixture = `create router hash:ip family inet hashsize 1024 maxelem 65536
add router 198.51.100.99
create white_list hash:net family inet hashsize 1024 maxelem 65536
add white_list 0.0.0.0/0
`
const policyFixture = "0: from all lookup local\n100: from 192.0.2.7 lookup 163\n101: from all fwmark 0x3100/0xff00 lookup 310\n32766: from all lookup main\n32767: from all lookup default\n"

func fixture() snapshot {
	return snapshot{tables: rulesFixture, sets: setsFixture, rules: policyFixture, route: "198.51.100.8 via 203.0.113.1 dev vlan2 src 203.0.113.9\n    cache\n", wan: "vlan2"}
}
func TestKnownR5ZeroMarkWANPathIsProven(t *testing.T) {
	p, reason := provePath(fixture(), netip.MustParseAddr("198.51.100.8"))
	if reason != "" || p == "" {
		t.Fatalf("supported r5 path rejected: %s", reason)
	}
	updated := fixture()
	updated.tables = strings.ReplaceAll(updated.tables, "[10:456]", "[99:9999]")
	q, r := provePath(updated, netip.MustParseAddr("198.51.100.8"))
	if r != "" || p != q {
		t.Fatal("unrelated packet counters changed path evidence")
	}
}
func TestRouterSetRedirectWinsOverLaterWhiteReturn(t *testing.T) {
	s := fixture()
	s.sets += "add router 198.51.100.8\n"
	_, reason := provePath(s, netip.MustParseAddr("198.51.100.8"))
	if reason != "output_redirect" {
		t.Fatalf("white_list falsely bypassed first redirect: %s", reason)
	}
}
func TestNATAndMarkUnknownsFailClosed(t *testing.T) {
	cases := map[string]string{
		"mangle_output":      strings.Replace(rulesFixture, "*mangle\n:OUTPUT ACCEPT [0:0]", "*mangle\n:OUTPUT ACCEPT [0:0]\n-A OUTPUT -j MARK --set-mark 0x3100", 1),
		"zero_mark_jump":     strings.Replace(rulesFixture, "--mark 0x3100/0xff00", "--mark 0x0/0xff00", 1),
		"unconditional_jump": strings.Replace(rulesFixture, "-p tcp -m mark --mark 0x3100/0xff00 -j SHADOWSOCKS_EXT", "-j SHADOWSOCKS_EXT", 1),
		"dnat":               strings.Replace(rulesFixture, "-p tcp -m set --match-set router dst -j REDIRECT --to-ports 3333", "-p tcp -j DNAT --to-destination 127.0.0.1:3333", 1),
		"raw_notrack":        rulesFixture + "*raw\n:OUTPUT ACCEPT [0:0]\n-A OUTPUT -j NOTRACK\nCOMMIT\n",
		"filter_queue":       strings.Replace(rulesFixture, "*filter\n:OUTPUT ACCEPT [0:0]", "*filter\n:OUTPUT ACCEPT [0:0]\n-A OUTPUT -j NFQUEUE", 1),
		"inverted_set":       strings.Replace(rulesFixture, "--match-set router dst", "! --match-set router dst", 1),
	}
	for name, rules := range cases {
		t.Run(name, func(t *testing.T) {
			s := fixture()
			s.tables = rules
			_, reason := provePath(s, netip.MustParseAddr("198.51.100.8"))
			if reason == "" {
				t.Fatal("unknown interception profile accepted")
			}
		})
	}
}
func TestInvalidMissingAndUnsupportedSetsFailClosed(t *testing.T) {
	for _, sets := range []string{"", strings.Replace(setsFixture, "hash:ip", "list:set", 1), setsFixture + "add router 198.51.100.8 nomatch\n", strings.Replace(setsFixture, "family inet", "family inet6", 1), strings.Replace(setsFixture, "maxelem 65536", "maxelem 65536 timeout 30", 1)} {
		s := fixture()
		s.sets = sets
		_, reason := provePath(s, netip.MustParseAddr("198.51.100.8"))
		if reason != "unsupported_ipset" {
			t.Fatalf("unsupported set accepted: %s", reason)
		}
	}
}
func TestCIDRSetMembership(t *testing.T) {
	member, valid := setContains("create router hash:net family inet\nadd router 198.51.100.0/24\n", "router", netip.MustParseAddr("198.51.100.8"))
	if !valid || !member {
		t.Fatal("CIDR membership missed")
	}
}
func TestRouteAndPolicyCannotSilentlyUseTunnel(t *testing.T) {
	for _, edit := range []func(*snapshot){
		func(s *snapshot) { s.route = strings.Replace(s.route, "dev vlan2", "dev tun0", 1) },
		func(s *snapshot) { s.wan = "tun0"; s.route = strings.Replace(s.route, "dev vlan2", "dev tun0", 1) },
		func(s *snapshot) { s.rules = "1: from all lookup 163\n" + policyFixture },
		func(s *snapshot) { s.rules = "1: from 203.0.113.9 lookup 163\n" + policyFixture },
		func(s *snapshot) { s.rules = "1: from all fwmark 0x0/0xff00 lookup 310\n" + policyFixture },
		func(s *snapshot) { s.rules = "1: not from 192.0.2.7 lookup 163\n" + policyFixture },
		func(s *snapshot) { s.route = "local 198.51.100.8 dev lo src 127.0.0.1\n" },
	} {
		s := fixture()
		edit(&s)
		if _, reason := provePath(s, netip.MustParseAddr("198.51.100.8")); reason == "" {
			t.Fatal("ambiguous route/policy accepted")
		}
	}
}
func TestMalformedOrTruncatedRuleDumpRejected(t *testing.T) {
	for _, rules := range []string{"", strings.TrimSuffix(rulesFixture, "COMMIT\n"), strings.Replace(rulesFixture, ":OUTPUT ACCEPT", ":OUTPUT DROP", 1), "*nat\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n", rulesFixture + "garbage\n"} {
		s := fixture()
		s.tables = rules
		if _, reason := provePath(s, netip.MustParseAddr("198.51.100.8")); reason == "" {
			t.Fatal("invalid/incomplete rules accepted")
		}
	}
}
func TestCaptureExecutesOnlyBoundedReadOperations(t *testing.T) {
	calls := 0
	read := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls++
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		key := name + " " + strings.Join(args, " ")
		data := map[string]string{
			"iptables-save ": rulesFixture, "ipset save": setsFixture, "ip rule show": policyFixture,
			"ip route get 198.51.100.8": "198.51.100.8 via 203.0.113.1 dev vlan2 src 203.0.113.9\n",
			"nvram get wan0_proto":      "dhcp\n", "nvram get wan0_ifname": "vlan2\n",
		}
		value, ok := data[key]
		if !ok {
			t.Errorf("unexpected operation: %s", key)
			return nil, errors.New("not read-only")
		}
		return []byte(value), nil
	}
	if _, reason := verifySystemPath(context.Background(), netip.MustParseAddr("198.51.100.8"), read); reason != "" || calls != 6 {
		t.Fatalf("capture failed/count wrong: %s %d", reason, calls)
	}
}
func TestCommandFailureAndContextDeadlineAreNotProof(t *testing.T) {
	if _, reason := verifySystemPath(context.Background(), netip.MustParseAddr("198.51.100.8"), func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("private address must not escape")
	}); reason != "command_failed" {
		t.Fatal("failed command accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, reason := verifySystemPath(ctx, netip.MustParseAddr("198.51.100.8"), func(ctx context.Context, _ string, _ ...string) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() })
	if reason != "command_failed" || time.Since(started) > time.Second {
		t.Fatal("guard context did not bound commands")
	}
}
func TestBoundedSystemOutput(t *testing.T) {
	w := &boundedOutput{limit: 3}
	if _, e := w.Write([]byte("four")); e == nil || w.Len() != 0 {
		t.Fatal("oversized system snapshot not rejected")
	}
}

func TestCheckOnlyReportHasNoMeasurementNumbers(t *testing.T) {
	var output strings.Builder
	code := reportPath(context.Background(), netip.MustParseAddr("198.51.100.8"), func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("unavailable") }, &output)
	if code != 2 || !strings.Contains(output.String(), `"path_verified":false`) || strings.Contains(output.String(), "latency") || strings.Contains(output.String(), "198.51.") {
		t.Fatal("check-only diagnostic must contain no measurement or endpoint")
	}
}
