package policy

import (
	"reflect"
	"sort"
	"testing"

	"github.com/artefactual-labs/decision-spoa/internal/xforwarded"
)

func TestNormalizeTrusted(t *testing.T) {
	in := []string{"10.0.0.1", "10.0.0.1", " 203.0.113.0/24 ", "#comment", "2001:db8::1"}
	want := []string{"10.0.0.1", "203.0.113.0/24", "2001:db8::1"}
	got := normalizeTrusted(in)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeTrusted() = %#v, want %#v", got, want)
	}
}

func TestConfigTrustedFor(t *testing.T) {
	cfg := Config{
		Trusted: TrustedProxyConfig{
			Global: xforwarded.NewTrusted([]string{"g1", "g2"}),
			Frontends: map[string]xforwarded.Trusted{
				"fe_admin": xforwarded.NewTrusted([]string{"f1", "f2"}),
			},
			Backends: map[string]xforwarded.Trusted{
				"be_api": xforwarded.NewTrusted([]string{"b1"}),
			},
		},
	}

	tests := []struct {
		name     string
		backend  string
		frontend string
		want     []string
	}{
		{
			name:     "global only",
			backend:  "",
			frontend: "",
			want:     []string{"g1", "g2"},
		},
		{
			name:     "frontend + global",
			backend:  "",
			frontend: "fe_admin",
			want:     []string{"g1", "g2", "f1", "f2"},
		},
		{
			name:     "backend adds",
			backend:  "be_api",
			frontend: "fe_admin",
			want:     []string{"g1", "g2", "f1", "f2", "b1"},
		},
		{
			name:     "unknown scope",
			backend:  "unknown",
			frontend: "missing",
			want:     []string{"g1", "g2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cfg.TrustedFor(tt.backend, tt.frontend)
			gotEntries := got.Entries()
			sort.Strings(gotEntries)
			sort.Strings(tt.want)
			if !reflect.DeepEqual(gotEntries, tt.want) {
				t.Fatalf("TrustedFor(%q,%q) = %#v, want %#v", tt.backend, tt.frontend, gotEntries, tt.want)
			}
		})
	}
}

func TestCompileRules(t *testing.T) {
	raw := []RawRule{
		{
			Name:      "http-static",
			Protocols: []string{"http"},
			Match: RawRuleMatch{
				Path:    []string{`^/static/`},
				Method:  []string{"GET"},
				Country: []string{"CA"},
				Query:   []string{`foo=`},
				SNI:     []string{`^api\\.example\\.com$`},
				JA3:     []string{`^771,4865`},
				Host:    []string{"plain.example.com", `^regex\\.example\\.com$`},
			},
			Return: map[string]interface{}{
				"policy.bucket":      "static",
				"policy.use_varnish": true,
				"reason":             "static-hit",
				"policy.extra":       "1",
			},
		},
		{
			Name:     "fallback",
			Fallback: true,
			Return: map[string]interface{}{
				"reason": "fallback-reason",
			},
		},
	}

	rules, fallback, err := compileRules(raw)
	if err != nil {
		t.Fatalf("compileRules error: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("compileRules: rules len = %d, want 1", len(rules))
	}

	if fallback.Reason != "fallback-reason" {
		t.Fatalf("fallback reason = %q, want %q", fallback.Reason, "fallback-reason")
	}

	rule := rules[0]
	if _, ok := rule.Protocols["http"]; !ok {
		t.Fatalf("rule protocols missing http")
	}
	if len(rule.Match.PathRegex) != 1 {
		t.Fatalf("rule path regex count = %d, want 1", len(rule.Match.PathRegex))
	}
	if _, ok := rule.Match.Method["GET"]; !ok {
		t.Fatalf("rule method matcher missing GET")
	}
	if _, ok := rule.Match.HostExact["plain.example.com"]; !ok {
		t.Fatalf("rule host exact missing plain.example.com")
	}
	if len(rule.Match.HostRegex) != 1 {
		t.Fatalf("rule host regex count = %d, want 1", len(rule.Match.HostRegex))
	}
	if len(rule.Match.QueryRegex) != 1 {
		t.Fatalf("rule query regex count = %d, want 1", len(rule.Match.QueryRegex))
	}
	if len(rule.Match.SNIRegex) != 1 {
		t.Fatalf("rule sni regex count = %d, want 1", len(rule.Match.SNIRegex))
	}
	if len(rule.Match.JA3Regex) != 1 {
		t.Fatalf("rule ja3 regex count = %d, want 1", len(rule.Match.JA3Regex))
	}
	if rule.Return.Vars["policy.bucket"] != "static" {
		t.Fatalf("rule return bucket mismatch")
	}
	if rule.Return.Vars["policy.use_varnish"] != true {
		t.Fatalf("rule return use_varnish mismatch")
	}
	if rule.Return.Vars["policy.extra"] != "1" {
		t.Fatalf("rule return extra var missing")
	}
}
