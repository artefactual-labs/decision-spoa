package policy

import (
	"net"
	"regexp"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type promRuleCounter struct {
	vec *prometheus.CounterVec
}

func (p promRuleCounter) Inc(componentType, component, host, rule string) {
	p.vec.WithLabelValues(componentType, component, host, rule).Inc()
}

func TestEvaluateFirstMatch(t *testing.T) {
	cfg := Config{
		Defaults: Defaults{
			Global: Vars{
				"policy.bucket":      "default",
				"policy.challenge":   true,
				"policy.use_varnish": false,
			},
		},
		Rules: []Rule{
			{
				Name: "deny-eu",
				Protocols: map[string]struct{}{
					"http": {},
				},
				Match: RuleMatch{
					Country:   map[string]struct{}{"FR": {}, "DE": {}},
					HostExact: map[string]struct{}{"example.com": {}},
				},
				Return: RuleReturn{
					Vars: Vars{
						"policy.bucket":    "deny",
						"policy.challenge": false,
					},
					Reason: "block-eu",
				},
			},
			{
				Name: "allow-static",
				Protocols: map[string]struct{}{
					"http": {},
				},
				Match: RuleMatch{
					PathRegex: []*regexp.Regexp{regexp.MustCompile(`^/static/`)},
					Method:    map[string]struct{}{"GET": {}},
				},
				Return: RuleReturn{
					Vars: Vars{
						"policy.use_varnish": true,
					},
					Reason: "static",
				},
			},
		},
		Fallback: RuleReturn{
			Reason: "fallback",
			Vars:   Vars{},
		},
	}

	ruleHits := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hits",
		Help: "hits",
	}, []string{"component_type", "component", "host", "rule"})

	out := cfg.Evaluate(Input{
		Backend:          "be1",
		BackendLabel:     "be1",
		BackendLabelType: "backend",
		Frontend:         "fe1",
		Protocol:         "http",
		Host:             "example.com",
		Path:             "/static/app.js",
		Method:           "GET",
		Country:          "FR",
	}, promRuleCounter{vec: ruleHits}, false)

	if out.Reason != "block-eu" {
		t.Fatalf("reason = %q, want block-eu", out.Reason)
	}
	if out.Vars["policy.bucket"] != "deny" {
		t.Fatalf("bucket mismatch: %#v", out.Vars["policy.bucket"])
	}
	if out.Vars["policy.challenge"] != false {
		t.Fatalf("challenge mismatch: %#v", out.Vars["policy.challenge"])
	}
	if out.Vars["policy.use_varnish"] != true {
		t.Fatalf("use_varnish mismatch: %#v", out.Vars["policy.use_varnish"])
	}

	metric, err := ruleHits.GetMetricWithLabelValues("backend", "be1", "", "deny-eu")
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues: %v", err)
	}
	m := &dto.Metric{}
	if err := metric.Write(m); err != nil {
		t.Fatalf("metric write: %v", err)
	}
	if m.Counter.GetValue() != 1 {
		t.Fatalf("rule hits = %f, want 1", m.Counter.GetValue())
	}
}

func TestEvaluateFallback(t *testing.T) {
	cfg := Config{
		Defaults: Defaults{
			Global: Vars{
				"policy.bucket":      "default",
				"policy.challenge":   true,
				"policy.use_varnish": true,
			},
		},
		Rules: []Rule{},
		Fallback: RuleReturn{
			Reason: "fallback",
			Vars: Vars{
				"policy.extra": "fallback",
			},
		},
	}

	ruleHits := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hits",
		Help: "hits",
	}, []string{"component_type", "component", "host", "rule"})

	out := cfg.Evaluate(Input{
		Backend:          "be1",
		BackendLabel:     "be1",
		BackendLabelType: "backend",
		Frontend:         "fe1",
		Protocol:         "http",
		IP:               net.ParseIP("203.0.113.10"),
	}, promRuleCounter{vec: ruleHits}, false)

	if out.Vars["policy.bucket"] != "default" {
		t.Fatalf("bucket fallback mismatch: %#v", out.Vars["policy.bucket"])
	}
	if out.Vars["policy.challenge"] != true {
		t.Fatalf("challenge fallback mismatch: %#v", out.Vars["policy.challenge"])
	}
	if out.Vars["policy.use_varnish"] != true {
		t.Fatalf("use_varnish fallback mismatch: %#v", out.Vars["policy.use_varnish"])
	}
	if out.Reason != "fallback" {
		t.Fatalf("fallback reason = %q, want fallback", out.Reason)
	}
	if out.Vars["policy.extra"] != "fallback" {
		t.Fatalf("fallback extra var missing")
	}
}

func TestSkipRuleWhenNoVarsUnlocked(t *testing.T) {
	ruleHits := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "hits", Help: "hits"}, []string{"component_type", "component", "host", "rule"})

	cfg := Config{
		Defaults: Defaults{Global: Vars{"use_challenge": false}},
		Rules: []Rule{
			{
				Name:  "first",
				Match: RuleMatch{},
				Return: RuleReturn{
					Vars:   Vars{"use_challenge": true},
					Reason: "first",
				},
			},
			{
				Name:  "second",
				Match: RuleMatch{},
				Return: RuleReturn{
					Vars:   Vars{"use_challenge": true},
					Reason: "second",
				},
			},
		},
		Fallback: RuleReturn{Reason: "fallback", Vars: Vars{}},
	}

	out := cfg.Evaluate(Input{Backend: "b"}, promRuleCounter{vec: ruleHits}, false)

	if got := out.Reason; got != "first" {
		t.Fatalf("expected reason from first rule, got %q", got)
	}

	metric, err := ruleHits.GetMetricWithLabelValues("backend", "b", "", "second")
	if err == nil {
		m := &dto.Metric{}
		if err := metric.Write(m); err != nil {
			t.Fatalf("metric write: %v", err)
		}
		if m.Counter.GetValue() != 0 {
			t.Fatalf("second rule should not be counted, got %f", m.Counter.GetValue())
		}
	}
}

func TestEvaluateExtendedMatchers(t *testing.T) {
	cfg := Config{
		Defaults: Defaults{Global: Vars{"policy.bucket": "default", "policy.use_varnish": true, "policy.challenge": true}},
		Rules: []Rule{
			{
				Name: "extended",
				Match: RuleMatch{
					SessionPublic: SessionPublicMatch{
						ReqCount:      NumberCond{GE: ptrF(1)},
						Rate:          NumberCond{GE: ptrF(0)},
						FirstPathDeep: ptrB(true),
						IdleSeconds:   NumberCond{LE: ptrF(3600)},
					},
					SessionSpecial: SessionSpecialMatch{
						Role:        map[string]struct{}{"authenticated": {}},
						IdleSeconds: NumberCond{LT: ptrF(60)},
					},
					CookieGuard: CookieGuardMatch{
						Valid:          ptrB(true),
						AgeSeconds:     NumberCond{GT: ptrF(1.5)},
						ChallengeLevel: map[string]struct{}{"heavy": {}},
					},
				},
				Return: RuleReturn{Vars: Vars{"policy.bucket": "ok"}, Reason: "ext"},
			},
		},
		Fallback: RuleReturn{Reason: "fb", Vars: Vars{}},
	}

	in := Input{
		SessionPublicReqCount:      2,
		SessionPublicRate:          0.2,
		SessionPublicFirstPath:     "/index",
		SessionPublicFirstPathDeep: true,
		SessionPublicIdleSeconds:   10,
		SessionSpecialRole:         "authenticated",
		SessionSpecialIdleSeconds:  5,
		CookieGuardValid:           true,
		CookieAgeSeconds:           5,
		ChallengeLevel:             "heavy",
	}

	out := cfg.Evaluate(in, nil, false)
	if out.Vars["policy.bucket"] != "ok" || out.Reason != "ext" {
		t.Fatalf("extended match failed: out=%#v", out)
	}

	// Negative check: role mismatch
	in.SessionSpecialRole = "guest"
	out = cfg.Evaluate(in, nil, false)
	if out.Reason != "fb" {
		t.Fatalf("expected fallback on role mismatch, got: %#v", out)
	}
}

func ptrF(v float64) *float64 { return &v }
func ptrB(v bool) *bool       { return &v }
