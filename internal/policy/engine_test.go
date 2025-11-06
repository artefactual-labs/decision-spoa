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
