package policy

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/artefactual-labs/decision-spoa/internal/xforwarded"
	"gopkg.in/yaml.v3"
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

func TestCompileExtendedMatchers(t *testing.T) {
	raw := []RawRule{
		{
			Name: "session+cookie",
			Match: RawRuleMatch{
				SessionPublic: &RawSessionPublicMatch{
					ReqCount:          RawNumberCond{GE: ptrFloat(1)},
					Rate:              RawNumberCond{GE: ptrFloat(0)},
					FirstPathRegex:    []string{`^/`},
					FirstPathDeep:     ptrBool(true),
					IdleSeconds:       RawNumberCond{LE: ptrFloat(3600)},
					SuspiciousScore:   RawNumberCond{GE: ptrFloat(5)},
					SuspiciousIgnored: ptrBool(false),
				},
				SessionSpecial: &RawSessionSpecialMatch{
					Role:        []string{"authenticated"},
					IdleSeconds: RawNumberCond{LT: ptrFloat(60)},
				},
				CookieGuard: &RawCookieGuardMatch{
					Valid:          ptrBool(true),
					AgeSeconds:     RawNumberCond{GT: ptrFloat(1.5)},
					ChallengeLevel: []string{"heavy"},
				},
				BotD: &RawBotdMatch{
					Verdict:    []string{"bad", "suspect"},
					Kind:       []string{"automation"},
					Confidence: RawNumberCond{GE: ptrFloat(0.8)},
					RequestID:  []string{"req-123"},
				},
			},
			Return: map[string]interface{}{"policy.bucket": "ok"},
		},
		{Name: "fallback", Fallback: true, Return: map[string]interface{}{"reason": "fb"}},
	}

	rules, _, err := compileRules(raw)
	if err != nil {
		t.Fatalf("compileRules error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 compiled rule, got %d", len(rules))
	}
	r := rules[0]
	if len(r.Match.SessionPublic.FirstPathRegex) != 1 {
		t.Fatalf("first_path_regex not compiled")
	}
	if r.Match.SessionPublic.FirstPathDeep == nil || *r.Match.SessionPublic.FirstPathDeep != true {
		t.Fatalf("first_path_deep missing")
	}
	if !r.Match.SessionPublic.SuspiciousScore.matches(5) {
		t.Fatalf("suspicious_score matcher missing")
	}
	if r.Match.SessionPublic.SuspiciousIgnored == nil || *r.Match.SessionPublic.SuspiciousIgnored != false {
		t.Fatalf("suspicious_ignored matcher missing")
	}
	if _, ok := r.Return.Vars["policy.bucket"]; !ok {
		t.Fatalf("return var missing")
	}
	if _, ok := r.Match.Botd.Verdict["bad"]; !ok {
		t.Fatalf("botd verdict matcher missing")
	}
	if _, ok := r.Match.Botd.Kind["automation"]; !ok {
		t.Fatalf("botd kind matcher missing")
	}
	if !r.Match.Botd.Confidence.matches(0.95) {
		t.Fatalf("botd confidence matcher missing")
	}
	if _, ok := r.Match.Botd.RequestID["req-123"]; !ok {
		t.Fatalf("botd request_id matcher missing")
	}
}

func TestNormalizeReturnSuspicion(t *testing.T) {
	ret, err := normalizeReturn(map[string]interface{}{
		"session.suspicious.increment": 3,
		"session.suspicious.reset":     true,
		"session.suspicious.ignore":    true,
		"stop":                         true,
		"policy.bucket":                "x",
	}, "rule")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ret.SuspicionDelta != 3 || !ret.SuspicionReset || !ret.SuspicionIgnoreSet || !ret.SuspicionIgnore || !ret.Terminal {
		t.Fatalf("unexpected suspicion fields: %+v", ret)
	}
	if ret.Vars["policy.bucket"] != "x" {
		t.Fatalf("vars missing")
	}
}

func TestRuleUnknownTopLevelKey(t *testing.T) {
	// Manually inject unknown key by decoding YAML snippet.
	yamlData := `
rules:
  - name: bad
    terminal: true
    return:
      policy.bucket: ok
`
	var rc RawConfig
	err := yaml.Unmarshal([]byte(yamlData), &rc)
	if err == nil {
		t.Fatalf("expected error for unknown top-level key")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func ptrFloat(v float64) *float64 { return &v }
func ptrBool(v bool) *bool        { return &v }
