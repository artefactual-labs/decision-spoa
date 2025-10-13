package policy

import (
	"net"
	"strings"
)

type Input struct {
	Backend      string
	BackendLabel string
	Frontend     string
	Protocol     string
	XFF          string
	Method       string
	Query        string
	SNI          string
	JA3          string
	IP           net.IP
	ASN          uint
	Country      string
	UA           string
	Host         string
	Path         string
}

type Output struct {
	Vars   Vars
	Reason string
}

// RuleHitCounter records rule hits for observability.
type RuleHitCounter interface {
	Inc(backend, host, rule string)
}

func (c Config) baseVars(in Input) Vars {
	vars := cloneVars(c.Defaults.Global)
	if in.Frontend != "" {
		if v, ok := c.Defaults.Frontends[in.Frontend]; ok {
			vars = mergeVars(vars, v)
		}
	}
	if v, ok := c.Defaults.Backends[in.Backend]; ok {
		vars = mergeVars(vars, v)
	}
	return vars
}

func (c Config) Evaluate(in Input, ruleHits RuleHitCounter, withHostLabel bool) Output {
	out := Output{
		Vars: c.baseVars(in),
	}

	labelHost := ""
	if withHostLabel {
		labelHost = in.Host
	}

	labelBackend := in.Backend
	if in.BackendLabel != "" {
		labelBackend = in.BackendLabel
	}

	locked := make(map[string]struct{})

	hit := func(rule string) {
		if ruleHits != nil {
			ruleHits.Inc(labelBackend, labelHost, rule)
		}
	}

	rules := c.RulesForProtocol(strings.ToLower(in.Protocol))
	for _, rule := range rules {
		if !scopeMatches(rule, in) {
			continue
		}
		if !conditionsMatch(rule.Match, in) {
			continue
		}

		applyReturn(&out, rule.Return, locked, true)
		if out.Reason == "" && rule.Return.Reason != "" {
			out.Reason = rule.Return.Reason
		}
		hit(rule.Name)
	}

	// Fallback: apply explicit overrides
	applyReturn(&out, c.Fallback, locked, false)
	if out.Reason == "" {
		out.Reason = c.Fallback.Reason
		if out.Reason == "" {
			out.Reason = "default-policy"
		}
	}

	if out.Vars == nil {
		out.Vars = make(Vars)
	}

	return out
}

func scopeMatches(rule Rule, in Input) bool {
	if len(rule.Frontends) > 0 {
		if _, ok := rule.Frontends[in.Frontend]; !ok {
			return false
		}
	}
	if len(rule.Backends) > 0 {
		if _, ok := rule.Backends[in.Backend]; !ok {
			return false
		}
	}
	return true
}

func conditionsMatch(match RuleMatch, in Input) bool {
	if len(match.Country) > 0 {
		if _, ok := match.Country[strings.ToUpper(in.Country)]; !ok {
			return false
		}
	}
	if len(match.ASN) > 0 {
		if _, ok := match.ASN[in.ASN]; !ok {
			return false
		}
	}
	if len(match.Method) > 0 {
		m := strings.ToUpper(in.Method)
		if _, ok := match.Method[m]; !ok {
			return false
		}
	}
	if len(match.HostExact) > 0 || len(match.HostRegex) > 0 {
		if in.Host == "" {
			return false
		}
		matched := false
		h := strings.ToLower(in.Host)
		if len(match.HostExact) > 0 {
			if _, ok := match.HostExact[h]; ok {
				matched = true
			}
		}
		if !matched && len(match.HostRegex) > 0 {
			for _, re := range match.HostRegex {
				if re.MatchString(in.Host) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}
	if len(match.PathRegex) > 0 {
		ok := false
		for _, re := range match.PathRegex {
			if re.MatchString(in.Path) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(match.XFFRegex) > 0 {
		ok := false
		for _, re := range match.XFFRegex {
			if re.MatchString(in.XFF) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(match.UARegex) > 0 {
		ok := false
		for _, re := range match.UARegex {
			if re.MatchString(in.UA) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(match.QueryRegex) > 0 {
		ok := false
		for _, re := range match.QueryRegex {
			if re.MatchString(in.Query) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(match.SNIRegex) > 0 {
		ok := false
		sni := in.SNI
		for _, re := range match.SNIRegex {
			if re.MatchString(sni) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(match.JA3Regex) > 0 {
		ok := false
		for _, re := range match.JA3Regex {
			if re.MatchString(in.JA3) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(match.CIDR) > 0 {
		if in.IP == nil {
			return false
		}
		ok := false
		for _, network := range match.CIDR {
			if network.Contains(in.IP) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func applyReturn(out *Output, ret RuleReturn, locked map[string]struct{}, lock bool) {
	if len(ret.Vars) > 0 {
		if out.Vars == nil {
			out.Vars = make(Vars, len(ret.Vars))
		}
		for k, v := range ret.Vars {
			if lock {
				if _, exists := locked[k]; exists {
					continue
				}
				out.Vars[k] = v
				locked[k] = struct{}{}
				continue
			}
			if _, exists := out.Vars[k]; exists {
				continue
			}
			out.Vars[k] = v
		}
	}
	if ret.Reason != "" && out.Reason == "" {
		out.Reason = ret.Reason
	}
}
