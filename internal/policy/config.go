package policy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/artefactual-labs/decision-spoa/internal/xforwarded"

	"gopkg.in/yaml.v3"
)

// Vars is a generic bag of variables the policy will return to HAProxy.
type Vars map[string]interface{}

// Defaults define base variables when no rule overrides them.
type Defaults struct {
	Global    Vars            `yaml:"global"`
	Frontends map[string]Vars `yaml:"frontends"`
	Backends  map[string]Vars `yaml:"backends"`
}

type RawConfig struct {
	Defaults Defaults         `yaml:"defaults"`
	Trusted  RawTrustedConfig `yaml:"trusted_proxy"`
	Rules    []RawRule        `yaml:"rules"`
}

type RawTrustedConfig struct {
	Global    []string            `yaml:"global"`
	Frontends map[string][]string `yaml:"frontends"`
	Backends  map[string][]string `yaml:"backends"`
}

// RawRule is the uncompiled rule definition shipped in YAML.
type RawRule struct {
	Name      string                 `yaml:"name"`
	Protocols []string               `yaml:"protocols"`
	Frontends []string               `yaml:"frontends"`
	Backends  []string               `yaml:"backends"`
	Match     RawRuleMatch           `yaml:"match"`
	Return    map[string]interface{} `yaml:"return"`
	Fallback  bool                   `yaml:"fallback"`
}

// RawRuleMatch captures optional match clauses. All slices are OR-ed.
type RawRuleMatch struct {
	XFF      []string `yaml:"xff"`
	Host     []string `yaml:"host"`
	Path     []string `yaml:"path"`
	Method   []string `yaml:"method"`
	Country  []string `yaml:"country"`
	CIDR     []string `yaml:"cidr"`
	ASN      []uint   `yaml:"asn"`
	UA       []string `yaml:"user_agent"`
	Query    []string `yaml:"query"`
	SNI      []string `yaml:"sni"`
	JA3      []string `yaml:"ja3"`
	Protocol []string `yaml:"protocol"` // shorthand when protocols only contains one value
}

// Rule encapsulates the compiled rule ready for evaluation.
type Rule struct {
	Name      string
	Protocols map[string]struct{}
	Frontends map[string]struct{}
	Backends  map[string]struct{}
	Match     RuleMatch
	Return    RuleReturn
	Fallback  bool
}

// RuleMatch holds compiled matchers.
type RuleMatch struct {
	HostExact  map[string]struct{}
	HostRegex  []*regexp.Regexp
	PathRegex  []*regexp.Regexp
	XFFRegex   []*regexp.Regexp
	UARegex    []*regexp.Regexp
	QueryRegex []*regexp.Regexp
	SNIRegex   []*regexp.Regexp
	JA3Regex   []*regexp.Regexp
	Country    map[string]struct{}
	CIDR       []*net.IPNet
	ASN        map[uint]struct{}
	Method     map[string]struct{}
}

// RuleReturn stores explicit overrides and extra vars.
type RuleReturn struct {
	Reason string
	Vars   Vars
}

// Config holds compiled rules, defaults, and trusted proxy settings.
type Config struct {
	Debug    bool
	Defaults Defaults
	Rules    []Rule
	Fallback RuleReturn
	Trusted  TrustedProxyConfig
}

type TrustedProxyConfig struct {
	Global    xforwarded.Trusted
	Frontends map[string]xforwarded.Trusted
	Backends  map[string]xforwarded.Trusted
}

// TrustedFor returns the trusted proxy list for a backend/frontend combination.
// Precedence: global → frontend → backend.
func (c Config) TrustedFor(backend, frontend string) xforwarded.Trusted {
	var lists []xforwarded.Trusted
	if !c.Trusted.Global.Empty() {
		lists = append(lists, c.Trusted.Global)
	}
	if frontend != "" {
		if t, ok := c.Trusted.Frontends[frontend]; ok && !t.Empty() {
			lists = append(lists, t)
		}
	}
	if backend != "" {
		if t, ok := c.Trusted.Backends[backend]; ok && !t.Empty() {
			lists = append(lists, t)
		}
	}
	return xforwarded.CombineTrusted(lists...)
}

// Compile transforms the raw config into match-ready structures.
func (r RawConfig) Compile() (Config, error) {
	var cfg Config
	cfg.Defaults = r.Defaults.withFallbacks()

	trusted, err := compileTrusted(r.Trusted)
	if err != nil {
		return cfg, err
	}
	cfg.Trusted = trusted

	compiledRules, fallback, err := compileRules(r.Rules)
	if err != nil {
		return cfg, err
	}

	cfg.Rules = compiledRules
	cfg.Fallback = fallback
	return cfg, nil
}

func compileTrusted(raw RawTrustedConfig) (TrustedProxyConfig, error) {
	cfg := TrustedProxyConfig{
		Frontends: make(map[string]xforwarded.Trusted),
		Backends:  make(map[string]xforwarded.Trusted),
	}

	cfg.Global = xforwarded.NewTrusted(normalizeTrusted(raw.Global))
	for k, entries := range raw.Frontends {
		cfg.Frontends[k] = xforwarded.NewTrusted(normalizeTrusted(entries))
	}
	for k, entries := range raw.Backends {
		cfg.Backends[k] = xforwarded.NewTrusted(normalizeTrusted(entries))
	}
	return cfg, nil
}

func normalizeTrusted(entries []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.HasPrefix(entry, "#") {
			continue
		}
		if idx := strings.Index(entry, "#"); idx >= 0 {
			entry = strings.TrimSpace(entry[:idx])
		}
		if entry == "" {
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			entry = ip.String()
		} else if _, cidr, err := net.ParseCIDR(entry); err == nil {
			entry = cidr.String()
		}
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		out = append(out, entry)
	}
	return out
}

func compileRules(raw []RawRule) ([]Rule, RuleReturn, error) {
	var compiled []Rule
	var fallback RuleReturn
	fallbackSet := false
	for i, rr := range raw {
		if rr.Fallback {
			if fallbackSet {
				return nil, RuleReturn{}, fmt.Errorf("multiple fallback rules defined (rule %d: %s)", i, rr.Name)
			}
			ret, err := normalizeReturn(rr.Return, "")
			if err != nil {
				return nil, RuleReturn{}, fmt.Errorf("fallback rule %q: %w", rr.Name, err)
			}
			if ret.Vars == nil {
				ret.Vars = make(Vars)
			}
			if ret.Reason == "" {
				ret.Reason = "fallback"
			}
			fallback = ret
			fallbackSet = true
			continue
		}

		rule, err := compileRule(rr)
		if err != nil {
			return nil, RuleReturn{}, err
		}
		compiled = append(compiled, rule)
	}

	if !fallbackSet {
		fallback = RuleReturn{
			Reason: "default-policy",
			Vars:   make(Vars),
		}
	}

	return compiled, fallback, nil
}

func compileRule(rr RawRule) (Rule, error) {
	if len(rr.Return) == 0 {
		return Rule{}, fmt.Errorf("rule %q must specify return", rr.Name)
	}

	protocols := make(map[string]struct{})
	for _, proto := range rr.Protocols {
		proto = strings.TrimSpace(strings.ToLower(proto))
		if proto == "" {
			continue
		}
		protocols[proto] = struct{}{}
	}
	for _, proto := range rr.Match.Protocol {
		proto = strings.TrimSpace(strings.ToLower(proto))
		if proto == "" {
			continue
		}
		protocols[proto] = struct{}{}
	}
	if len(protocols) == 0 {
		protocols["http"] = struct{}{}
	}

	frontends := asSet(rr.Frontends)
	backends := asSet(rr.Backends)

	match, err := compileRuleMatch(rr.Match)
	if err != nil {
		return Rule{}, fmt.Errorf("rule %q: %w", rr.Name, err)
	}

	ret, err := normalizeReturn(rr.Return, rr.Name)
	if err != nil {
		return Rule{}, err
	}

	return Rule{
		Name:      rr.Name,
		Protocols: protocols,
		Frontends: frontends,
		Backends:  backends,
		Match:     match,
		Return:    ret,
	}, nil
}

func compileRuleMatch(raw RawRuleMatch) (RuleMatch, error) {
	var match RuleMatch
	match.Country = asLowerSet(raw.Country)
	match.ASN = asUintSet(raw.ASN)
	match.Method = asUpperSet(raw.Method)

	for _, s := range raw.Host {
		if isRegexPattern(s) {
			re, err := regexp.Compile(s)
			if err != nil {
				return RuleMatch{}, fmt.Errorf("compile host regexp %q: %w", s, err)
			}
			match.HostRegex = append(match.HostRegex, re)
			continue
		}
		if match.HostExact == nil {
			match.HostExact = make(map[string]struct{})
		}
		match.HostExact[strings.ToLower(strings.TrimSpace(s))] = struct{}{}
	}
	for _, s := range raw.Query {
		re, err := regexp.Compile(s)
		if err != nil {
			return RuleMatch{}, fmt.Errorf("compile query regexp %q: %w", s, err)
		}
		match.QueryRegex = append(match.QueryRegex, re)
	}
	for _, s := range raw.SNI {
		re, err := regexp.Compile(s)
		if err != nil {
			return RuleMatch{}, fmt.Errorf("compile sni regexp %q: %w", s, err)
		}
		match.SNIRegex = append(match.SNIRegex, re)
	}
	for _, s := range raw.JA3 {
		re, err := regexp.Compile(s)
		if err != nil {
			return RuleMatch{}, fmt.Errorf("compile ja3 regexp %q: %w", s, err)
		}
		match.JA3Regex = append(match.JA3Regex, re)
	}
	for _, s := range raw.Path {
		re, err := regexp.Compile(s)
		if err != nil {
			return RuleMatch{}, fmt.Errorf("compile path regexp %q: %w", s, err)
		}
		match.PathRegex = append(match.PathRegex, re)
	}
	for _, s := range raw.XFF {
		re, err := regexp.Compile(s)
		if err != nil {
			return RuleMatch{}, fmt.Errorf("compile xff regexp %q: %w", s, err)
		}
		match.XFFRegex = append(match.XFFRegex, re)
	}
	for _, s := range raw.UA {
		re, err := regexp.Compile(s)
		if err != nil {
			return RuleMatch{}, fmt.Errorf("compile user_agent regexp %q: %w", s, err)
		}
		match.UARegex = append(match.UARegex, re)
	}
	for _, cidr := range raw.CIDR {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return RuleMatch{}, fmt.Errorf("parse cidr %q: %w", cidr, err)
		}
		match.CIDR = append(match.CIDR, network)
	}

	return match, nil
}

func normalizeReturn(raw map[string]interface{}, ruleName string) (RuleReturn, error) {
	ret := RuleReturn{
		Vars: make(Vars),
	}
	for k, v := range raw {
		if strings.EqualFold(k, "reason") {
			s, ok := v.(string)
			if !ok {
				return RuleReturn{}, fmt.Errorf("return reason must be string for rule %q", ruleName)
			}
			ret.Reason = s
			continue
		}
		ret.Vars[k] = v
	}
	return ret, nil
}

func (d Defaults) withFallbacks() Defaults {
	if d.Global == nil {
		d.Global = make(Vars)
	}
	if d.Frontends == nil {
		d.Frontends = make(map[string]Vars)
	}
	if d.Backends == nil {
		d.Backends = make(map[string]Vars)
	}
	return d
}

func asSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out[v] = struct{}{}
	}
	return out
}

func asLowerSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(values))
	for _, v := range values {
		v = strings.TrimSpace(strings.ToUpper(v))
		if v == "" {
			continue
		}
		out[v] = struct{}{}
	}
	return out
}

func asUintSet(values []uint) map[uint]struct{} {
	if len(values) == 0 {
		return nil
	}
	out := make(map[uint]struct{}, len(values))
	for _, v := range values {
		out[v] = struct{}{}
	}
	return out
}

func asUpperSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(values))
	for _, v := range values {
		v = strings.TrimSpace(strings.ToUpper(v))
		if v == "" {
			continue
		}
		out[v] = struct{}{}
	}
	return out
}

func cloneVars(src Vars) Vars {
	if len(src) == 0 {
		return make(Vars)
	}
	dst := make(Vars, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func mergeVars(dst Vars, src Vars) Vars {
	if len(src) == 0 {
		if dst == nil {
			dst = make(Vars)
		}
		return dst
	}
	if dst == nil {
		dst = make(Vars, len(src))
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func isRegexPattern(s string) bool {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return false
	}
	for _, r := range trimmed {
		switch r {
		case '^', '$', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|', '\\':
			return true
		}
	}
	return false
}

// loadRawConfig reads policy.yml if present, falling back to defaults.
func loadRawConfig(root string) (RawConfig, error) {
	path := filepath.Join(root, "policy.yml")
	var raw RawConfig
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return raw, fmt.Errorf("policy file %s not found: %w", path, err)
		}
		return raw, fmt.Errorf("read policy.yml: %w", err)
	}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return raw, fmt.Errorf("parse policy.yml: %w", err)
	}
	return raw, nil
}

func (c Config) RulesForProtocol(protocol string) []Rule {
	if protocol == "" {
		protocol = "http"
	}
	var result []Rule
	for _, r := range c.Rules {
		if _, ok := r.Protocols[protocol]; ok {
			result = append(result, r)
		}
	}
	return result
}

// Validate ensures defaults and fallback produce complete actions.
func (c Config) Validate() error {
	if c.Fallback.Vars == nil {
		return fmt.Errorf("fallback vars not initialized")
	}
	return nil
}

// For deterministic comparisons in tests.
func (c Config) SortedRuleNames() []string {
	names := make([]string, 0, len(c.Rules))
	for _, r := range c.Rules {
		names = append(names, r.Name)
	}
	sort.Strings(names)
	return names
}
