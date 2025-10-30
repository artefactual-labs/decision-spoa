package xforwarded

import (
	"net"
	"sort"
	"strings"
)

// Trusted encapsulates canonical trusted hop entries (IPs, CIDRs, or raw literals).
type Trusted struct {
	literals map[string]struct{}
	nets     map[string]*net.IPNet
}

// NewTrusted instantiates a Trusted set from canonical strings.
func NewTrusted(entries []string) Trusted {
	var t Trusted
	for _, entry := range entries {
		t.addEntry(entry)
	}
	return t
}

// CombineTrusted merges multiple Trusted sets into a new one without mutating inputs.
func CombineTrusted(lists ...Trusted) Trusted {
	var out Trusted
	for _, list := range lists {
		if list.Empty() {
			continue
		}
		for lit := range list.literals {
			out.addLiteral(lit)
		}
		for key, netw := range list.nets {
			out.addNet(key, netw)
		}
	}
	return out
}

// Entries returns all canonical entries (IPs, CIDRs, literals) stored in the Trusted set.
func (t Trusted) Entries() []string {
	if len(t.literals) == 0 {
		return nil
	}
	out := make([]string, 0, len(t.literals))
	for lit := range t.literals {
		out = append(out, lit)
	}
	sort.Strings(out)
	return out
}

// Empty returns true if no trusted entries are configured.
func (t Trusted) Empty() bool {
	return len(t.literals) == 0 && len(t.nets) == 0
}

func (t *Trusted) addEntry(entry string) {
	if entry == "" {
		return
	}
	if ip := net.ParseIP(entry); ip != nil {
		t.addLiteral(ip.String())
		return
	}
	if _, cidr, err := net.ParseCIDR(entry); err == nil {
		t.addNet(cidr.String(), cidr)
		return
	}
	t.addLiteral(entry)
}

func (t *Trusted) addLiteral(lit string) {
	if lit == "" {
		return
	}
	if t.literals == nil {
		t.literals = make(map[string]struct{})
	}
	t.literals[lit] = struct{}{}
}

func (t *Trusted) addNet(key string, cidr *net.IPNet) {
	if key == "" || cidr == nil {
		return
	}
	if t.nets == nil {
		t.nets = make(map[string]*net.IPNet)
	}
	if _, exists := t.nets[key]; exists {
		return
	}
	t.nets[key] = cidr
	t.addLiteral(key)
}

func (t Trusted) matchesLiteral(s string) bool {
	if len(t.literals) == 0 {
		return false
	}
	_, ok := t.literals[s]
	return ok
}

func (t Trusted) containsIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if t.matchesLiteral(ip.String()) {
		return true
	}
	for _, netw := range t.nets {
		if netw.Contains(ip) {
			return true
		}
	}
	return false
}

// Has reports whether the given literal IP/CIDR matches a trusted entry.
func (t Trusted) Has(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if t.matchesLiteral(value) {
		return true
	}
	if ip := net.ParseIP(value); ip != nil {
		return t.containsIP(ip)
	}
	return false
}

// FromXFF returns the client IP taking into account src, XFF and trusted proxies.
// The second return value is the number of trailing hops stripped from XFF.
func FromXFF(src, xff string, trusted Trusted) (net.IP, int) {
	srcTrim := strings.TrimSpace(src)
	srcIP := net.ParseIP(srcTrim)
	if xff == "" {
		return srcIP, 0
	}
	parts := strings.Split(xff, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}

	removed := 0

	// If the immediate peer is not trusted, ignore XFF entirely.
	if !trusted.Empty() {
		trustedSrc := false
		if srcTrim != "" && trusted.matchesLiteral(srcTrim) {
			trustedSrc = true
		} else if srcIP != nil && trusted.containsIP(srcIP) {
			trustedSrc = true
		}
		if !trustedSrc {
			return srcIP, 0
		}
	} else {
		// No trusted proxies configured; treat src as the client.
		return srcIP, 0
	}

	// remove trailing trusted proxies (closest to application)
	if !trusted.Empty() {
		for len(parts) > 0 {
			last := parts[len(parts)-1]
			if last == "" {
				parts = parts[:len(parts)-1]
				continue
			}
			if trusted.matchesLiteral(last) {
				parts = parts[:len(parts)-1]
				removed++
				continue
			}
			if ip := net.ParseIP(last); ip != nil {
				if trusted.containsIP(ip) {
					parts = parts[:len(parts)-1]
					removed++
					continue
				}
			}
			break
		}
	}

	// client is left-most remaining entry
	for _, candidate := range parts {
		if candidate == "" {
			continue
		}
		if ip := net.ParseIP(candidate); ip != nil {
			return ip, removed
		}
	}
	return srcIP, removed
}
