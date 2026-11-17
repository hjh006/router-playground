package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type commandRead func(context.Context, string, ...string) ([]byte, error)
type snapshot struct{ tables, sets, rules, route, wan string }
type chain struct {
	policy string
	rules  [][]string
}

var deviceName = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
var setName = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,31}$`)
var decimal = regexp.MustCompile(`^[0-9]+$`)

// Read only fixed system utilities, never a shell or caller-controlled executable.
func systemRead(ctx context.Context, name string, args ...string) ([]byte, error) {
	allowed := map[string][]string{
		"iptables-save": {"/usr/sbin/iptables-save", "/sbin/iptables-save", "/bin/iptables-save"},
		"ipset":         {"/usr/sbin/ipset", "/sbin/ipset", "/bin/ipset"},
		"ip":            {"/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip"},
		"nvram":         {"/usr/sbin/nvram", "/sbin/nvram", "/bin/nvram", "/usr/bin/nvram"},
	}
	path := ""
	for _, candidate := range allowed[name] {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0 {
			path = candidate
			break
		}
	}
	if path == "" {
		return nil, errors.New("system utility unavailable")
	}
	output := &boundedOutput{limit: 4 * 1024 * 1024}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 100 * time.Millisecond
	if err := cmd.Run(); err != nil {
		return nil, errors.New("system read failed")
	}
	return output.Bytes(), nil
}

type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	if w.Len()+len(p) > w.limit {
		return 0, errors.New("output limit")
	}
	return w.Buffer.Write(p)
}

func verifySystemPath(ctx context.Context, address netip.Addr, read commandRead) (string, string) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var state snapshot
	requests := []struct {
		name string
		args []string
		dest *string
	}{
		{"iptables-save", nil, &state.tables}, {"ipset", []string{"save"}, &state.sets},
		{"ip", []string{"rule", "show"}, &state.rules}, {"ip", []string{"route", "get", address.String()}, &state.route},
	}
	for _, request := range requests {
		body, err := read(ctx, request.name, request.args...)
		if err != nil {
			return "", "command_failed"
		}
		*request.dest = string(body)
	}
	proto, err := read(ctx, "nvram", "get", "wan0_proto")
	if err != nil {
		return "", "command_failed"
	}
	key := "wan0_ifname"
	switch strings.TrimSpace(string(proto)) {
	case "dhcp", "static":
	case "pppoe":
		key = "wan0_pppoe_ifname"
	default:
		return "", "unsupported_wan"
	}
	wan, err := read(ctx, "nvram", "get", key)
	if err != nil {
		return "", "command_failed"
	}
	state.wan = strings.TrimSpace(string(wan))
	return provePath(state, address)
}

// This deliberately supports a narrow, provable r5 OUTPUT profile. Unknown matches
// and targets fail closed; RemoteAddr would not reveal transparent REDIRECT/DNAT.
func provePath(state snapshot, address netip.Addr) (string, string) {
	tables, ok := outputChains(state.tables)
	if !ok {
		return "", "invalid_rules"
	}
	for _, name := range []string{"nat", "mangle", "filter"} {
		if _, found := tables[name]; !found {
			return "", "incomplete_rules"
		}
	}
	evidence := []string{}
	for name, c := range tables {
		if c.policy != "ACCEPT" {
			return "", "unsupported_output_policy"
		}
		if name != "nat" && len(c.rules) != 0 {
			return "", "unsupported_output_rule"
		}
	}
	nat := tables["nat"]
	for _, rule := range nat.rules {
		evidence = append(evidence, strings.Join(rule, " "))
		if len(rule) == 2 && (rule[0] == "-j") && (rule[1] == "ACCEPT" || rule[1] == "RETURN") {
			break
		}
		if len(rule) == 11 && strings.Join(rule[:5], " ") == "-p tcp -m set --match-set" && rule[6] == "dst" && rule[7] == "-j" && rule[8] == "REDIRECT" && rule[9] == "--to-ports" && decimal.MatchString(rule[10]) {
			member, valid := setContains(state.sets, rule[5], address)
			if !valid {
				return "", "unsupported_ipset"
			}
			if member {
				return "", "output_redirect"
			}
			continue
		}
		if len(rule) == 8 && strings.Join(rule[:5], " ") == "-p tcp -m mark --mark" && rule[6] == "-j" && rule[7] == "SHADOWSOCKS_EXT" {
			nonzero, valid := nonzeroMark(rule[5])
			if !valid || !nonzero {
				return "", "unsupported_output_rule"
			}
			continue
		}
		return "", "unsupported_output_rule"
	}
	source, route, ok := routeProof(state.route, state.wan, address)
	if !ok {
		return "", "route_unverified"
	}
	if !policyProof(state.rules, source) {
		return "", "policy_unverified"
	}
	evidence = append(evidence, route, strings.Join(strings.Fields(state.rules), " "))
	digest := sha256.Sum256([]byte(strings.Join(evidence, "\n")))
	return hex.EncodeToString(digest[:]), ""
}

func outputChains(text string) (map[string]chain, bool) {
	tables := map[string]chain{}
	table := ""
	declared := false
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 4096), 64*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "*") {
			if table != "" {
				return nil, false
			}
			table = line[1:]
			if _, exists := tables[table]; exists || table == "" {
				return nil, false
			}
			declared = false
			continue
		}
		if line == "COMMIT" {
			if table == "" || !declared {
				return nil, false
			}
			table = ""
			continue
		}
		if table == "" {
			return nil, false
		}
		fields := strings.Fields(line)
		if strings.HasPrefix(line, ":") {
			if len(fields) != 3 {
				return nil, false
			}
			if fields[0] == ":OUTPUT" {
				if declared {
					return nil, false
				}
				tables[table] = chain{policy: fields[1]}
				declared = true
			}
			continue
		}
		if len(fields) < 3 || fields[0] != "-A" {
			return nil, false
		}
		if fields[1] == "OUTPUT" {
			if !declared {
				return nil, false
			}
			c := tables[table]
			c.rules = append(c.rules, fields[2:])
			tables[table] = c
		}
	}
	return tables, scanner.Err() == nil && table == "" && len(tables) > 0
}

func setContains(text, name string, address netip.Addr) (bool, bool) {
	if !setName.MatchString(name) {
		return false, false
	}
	found, member := false, false
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 4096), 64*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[1] != name {
			continue
		}
		if fields[0] == "create" {
			if found || len(fields) < 3 || (fields[2] != "hash:ip" && fields[2] != "hash:net") {
				return false, false
			}
			found = true
			for i := 3; i < len(fields); i += 2 {
				if i+1 >= len(fields) {
					return false, false
				}
				switch fields[i] {
				case "family":
					if fields[i+1] != "inet" {
						return false, false
					}
				case "hashsize", "maxelem":
					if !decimal.MatchString(fields[i+1]) {
						return false, false
					}
				case "timeout":
					if fields[i+1] != "0" {
						return false, false
					}
				default:
					return false, false
				}
			}
		} else if fields[0] == "add" {
			if !found || len(fields) != 3 {
				return false, false
			}
			prefix, err := netip.ParsePrefix(fields[2])
			if err != nil {
				ip, e := netip.ParseAddr(fields[2])
				if e != nil || !ip.Is4() {
					return false, false
				}
				prefix = netip.PrefixFrom(ip, 32)
			}
			if !prefix.Addr().Is4() {
				return false, false
			}
			member = member || prefix.Contains(address)
		} else {
			return false, false
		}
	}
	return member, found && scanner.Err() == nil
}
func nonzeroMark(value string) (bool, bool) {
	pair := strings.Split(value, "/")
	if len(pair) > 2 {
		return false, false
	}
	mark, err := strconv.ParseUint(pair[0], 0, 32)
	if err != nil {
		return false, false
	}
	mask := uint64(0xffffffff)
	if len(pair) == 2 {
		mask, err = strconv.ParseUint(pair[1], 0, 32)
		if err != nil {
			return false, false
		}
	}
	if mark&^mask != 0 {
		return false, false
	}
	return mark&mask != 0, true
}
func routeProof(text, wan string, address netip.Addr) (netip.Addr, string, bool) {
	if !deviceName.MatchString(wan) || wan == "lo" || strings.HasPrefix(wan, "tun") || strings.HasPrefix(wan, "tap") || strings.HasPrefix(wan, "wg") || strings.HasPrefix(wan, "br") {
		return netip.Addr{}, "", false
	}
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) == 0 {
		return netip.Addr{}, "", false
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 3 || fields[0] != address.String() {
		return netip.Addr{}, "", false
	}
	source := netip.Addr{}
	dev := ""
	gateway := ""
	for i := 1; i < len(fields); i++ {
		if fields[i] == "cache" {
			continue
		}
		if i+1 >= len(fields) {
			return netip.Addr{}, "", false
		}
		key, value := fields[i], fields[i+1]
		i++
		switch key {
		case "dev":
			dev = value
		case "src":
			source, _ = netip.ParseAddr(value)
		case "via":
			if ip, e := netip.ParseAddr(value); e != nil || !ip.Is4() {
				return netip.Addr{}, "", false
			}
			gateway = value
		case "uid":
			if value != "0" {
				return netip.Addr{}, "", false
			}
		case "mtu", "advmss", "metric":
			if !decimal.MatchString(value) {
				return netip.Addr{}, "", false
			}
		case "scope":
			if value != "link" && value != "global" {
				return netip.Addr{}, "", false
			}
		case "table":
			if value != "main" && value != "254" {
				return netip.Addr{}, "", false
			}
		default:
			return netip.Addr{}, "", false
		}
	}
	if dev != wan || !source.Is4() || source.IsUnspecified() || source.IsLoopback() {
		return netip.Addr{}, "", false
	}
	return source, dev + " " + source.String() + " " + gateway, true
}
func policyProof(text string, source netip.Addr) bool {
	main := false
	lines := 0
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || !strings.HasSuffix(fields[0], ":") || !decimal.MatchString(strings.TrimSuffix(fields[0], ":")) || fields[1] != "from" {
			return false
		}
		lines++
		from := fields[2]
		rest := fields[3:]
		skip := false
		if from != "all" {
			prefix, err := netip.ParsePrefix(from)
			if err != nil {
				ip, e := netip.ParseAddr(from)
				if e != nil || !ip.Is4() {
					return false
				}
				prefix = netip.PrefixFrom(ip, 32)
			}
			if !prefix.Addr().Is4() {
				return false
			}
			skip = !prefix.Contains(source)
		}
		if len(rest) == 4 && rest[0] == "fwmark" {
			nonzero, valid := nonzeroMark(rest[1])
			if !valid {
				return false
			}
			skip = skip || nonzero
			rest = rest[2:]
		}
		if len(rest) != 2 || rest[0] != "lookup" {
			return false
		}
		if skip {
			if !decimal.MatchString(rest[1]) && rest[1] != "main" && rest[1] != "local" && rest[1] != "default" {
				return false
			}
			continue
		}
		if from != "all" {
			return false
		}
		switch rest[1] {
		case "main", "254":
			main = true
		case "local", "255", "default", "253":
		default:
			return false
		}
	}
	return lines > 0 && main
}
