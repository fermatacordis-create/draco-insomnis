// Package draco is Draco Insomnis for Go: the same firewall, block list, country filter, anti-copy
// pace, review requests and CrowdSec bridge as the PHP, JavaScript and Python editions, checked
// against the same shared test cases (tests/vectors). Standard library only, so it also runs as a
// Traefik plugin (Yaegi). Use it as net/http middleware, in Caddy (package caddy) or in Traefik.
package draco

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

var v4Part = regexp.MustCompile(`^(0|[1-9]\d{0,2})$`)

// toBytes returns the address as 4 or 16 bytes, or nil when it is not a valid IPv4 or IPv6 address.
// Like PHP's filter_var: decimal IPv4 without leading zeros, no IPv6 zone.
func toBytes(ip string) []byte {
	ip = strings.TrimSpace(ip)
	if strings.Contains(ip, "%") {
		return nil
	}
	if !strings.Contains(ip, ":") {
		parts := strings.Split(ip, ".")
		if len(parts) != 4 {
			return nil
		}
		out := make([]byte, 4)
		for i, p := range parts {
			if !v4Part.MatchString(p) {
				return nil
			}
			n, _ := strconv.Atoi(p)
			if n > 255 {
				return nil
			}
			out[i] = byte(n)
		}
		return out
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is6() {
		return nil
	}
	b := a.As16()
	return b[:]
}

// IsIP reports whether s is an IPv4 or IPv6 address.
func IsIP(s string) bool { return toBytes(s) != nil }

// fromBytes is dotted IPv4, or compressed lower-case IPv6 (like inet_ntop).
func fromBytes(b []byte) string {
	if len(b) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	}
	var w [8]int
	for i := 0; i < 8; i++ {
		w[i] = int(b[2*i])<<8 | int(b[2*i+1])
	}
	best, bestLen := -1, 0
	for i := 0; i < 8; {
		if w[i] != 0 {
			i++
			continue
		}
		j := i
		for j < 8 && w[j] == 0 {
			j++
		}
		if j-i > bestLen && j-i >= 2 {
			best, bestLen = i, j-i
		}
		i = j
	}
	hex := func(xs []int) string {
		s := make([]string, len(xs))
		for i, x := range xs {
			s[i] = strconv.FormatInt(int64(x), 16)
		}
		return strings.Join(s, ":")
	}
	if best < 0 {
		return hex(w[:])
	}
	return hex(w[:best]) + "::" + hex(w[best+bestLen:])
}

// InNet reports whether ip is inside the network ("10.0.0.0/8", "2001:db8::/32" or one address).
func InNet(cidr, ip string) bool {
	base, bitsText, hasBits := strings.Cut(strings.TrimSpace(cidr), "/")
	b, a := toBytes(base), toBytes(ip)
	if b == nil || a == nil || len(b) != len(a) {
		return false
	}
	max := len(b) * 8
	bits := max
	if hasBits {
		n, err := strconv.Atoi(bitsText)
		if err != nil || n < 0 {
			bits = max
		} else {
			bits = n
		}
	}
	if bits > max {
		return false
	}
	whole, rest := bits/8, bits%8
	for i := 0; i < whole; i++ {
		if b[i] != a[i] {
			return false
		}
	}
	if rest == 0 {
		return true
	}
	mask := byte(0xff << (8 - rest))
	return b[whole]&mask == a[whole]&mask
}

// Contains reports whether ip is in any of the networks.
func Contains(nets []string, ip string) bool {
	for _, n := range nets {
		if InNet(n, ip) {
			return true
		}
	}
	return false
}

var listSplit = regexp.MustCompile(`[\s,]+`)
var comment = regexp.MustCompile(`#.*`)

// ParseList reads networks and addresses: one per line or comma-separated; "#" starts a comment.
func ParseList(items ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, text := range items {
		for _, line := range strings.Split(strings.ReplaceAll(text, "\r", "\n"), "\n") {
			for _, item := range listSplit.Split(comment.ReplaceAllString(line, ""), -1) {
				host, _, _ := strings.Cut(item, "/")
				if item != "" && IsIP(host) && !seen[item] {
					seen[item] = true
					out = append(out, item)
				}
			}
		}
	}
	return out
}

// network is the /24 (IPv4) or /64 (IPv6) the address belongs to; "" when it is not an address.
func network(ip string) string {
	b := toBytes(ip)
	if b == nil {
		return ""
	}
	if len(b) == 4 {
		return fmt.Sprintf("%d.%d.%d.0/24", b[0], b[1], b[2])
	}
	keep := make([]byte, 16)
	copy(keep, b[:8])
	return fromBytes(keep) + "/64"
}

var mapped = regexp.MustCompile(`(?i)^::ffff:\d+\.\d+\.\d+\.\d+$`)

func unmap(ip string) string {
	if mapped.MatchString(ip) {
		return ip[7:]
	}
	return ip
}

// Cloudflare is Cloudflare's published ranges (https://www.cloudflare.com/ips/).
var Cloudflare = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
	"108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
	"162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
	"2a06:98c0::/29", "2c0f:f248::/32",
}

// LocalProxies are trusted when none are listed: this machine and networks unreachable from the internet.
var LocalProxies = []string{
	"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
	"::1/128", "fc00::/7", "fe80::/10",
}
