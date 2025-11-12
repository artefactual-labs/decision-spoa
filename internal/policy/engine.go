package policy

import (
	"net"
	"strings"
)

type Input struct {
	Backend                        string
	BackendLabel                   string
	BackendLabelType               string
	Frontend                       string
	Protocol                       string
	XFF                            string
	Method                         string
	Query                          string
	SNI                            string
	JA3                            string
	IP                             net.IP
	ASN                            uint
	Country                        string
	UA                             string
	Host                           string
	Path                           string
	SessionPublicReqCount          uint64
	SessionPublicRate              float64
	SessionPublicFirstPath         string
	SessionPublicFirstPathDeep     bool
	SessionPublicIdleSeconds       float64
	SessionPublicSuspiciousScore   int
	SessionPublicSuspiciousIgnored bool
	SessionSpecialRole             string
	SessionSpecialIdleSeconds      float64
	CookieAgeSeconds               float64
	ChallengeLevel                 string
	CookieGuardValid               bool
}

type Output struct {
	Vars               Vars
	Reason             string
	SuspicionDelta     int
	SuspicionReset     bool
	SuspicionIgnoreSet bool
	SuspicionIgnore    bool
}

func ruleHasEffect(rule Rule, locked map[string]struct{}, reasonSet bool) bool {
	if rule.Return.Reason != "" && !reasonSet {
		return true
	}
	for k := range rule.Return.Vars {
		if _, ok := locked[k]; !ok {
			return true
		}
	}
	if rule.Return.SuspicionDelta != 0 {
		return true
	}
	if rule.Return.SuspicionReset {
		return true
	}
	if rule.Return.SuspicionIgnoreSet {
		return true
	}
	if rule.Return.Terminal {
		return true
	}
	return false
}

// RuleHitCounter records rule hits for observability.
type RuleHitCounter interface {
	Inc(componentType, component, host, rule string)
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

	componentType := "backend"
	if in.BackendLabelType != "" {
		componentType = in.BackendLabelType
	}
	component := in.Backend
	if in.BackendLabel != "" {
		component = in.BackendLabel
	}

	locked := make(map[string]struct{})

	hit := func(rule string) {
		if ruleHits != nil {
			ruleHits.Inc(componentType, component, labelHost, rule)
		}
	}

	stopped := false
	rules := c.RulesForProtocol(strings.ToLower(in.Protocol))
	for _, rule := range rules {
		if !ruleHasEffect(rule, locked, out.Reason != "") {
			continue
		}
		if !scopeMatches(rule, in) {
			continue
		}
		if !conditionsMatch(rule.Match, in) {
			continue
		}

		changed := applyReturn(&out, rule.Return, locked, true)
		if rule.Return.SuspicionReset {
			out.SuspicionReset = true
			changed = true
		}
		if rule.Return.SuspicionDelta != 0 {
			out.SuspicionDelta += rule.Return.SuspicionDelta
			changed = true
		}
		if rule.Return.SuspicionIgnoreSet {
			out.SuspicionIgnoreSet = true
			out.SuspicionIgnore = rule.Return.SuspicionIgnore
			changed = true
		}
		if !changed {
			continue
		}
		hit(rule.Name)
		if rule.Return.Terminal {
			stopped = true
			break
		}
	}

	// Fallback: apply explicit overrides (unless terminal rule already fired)
	if !stopped {
		applyReturn(&out, c.Fallback, locked, false)
		if out.Reason == "" {
			out.Reason = c.Fallback.Reason
			if out.Reason == "" {
				out.Reason = "default-policy"
			}
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
	// Extended session_public
	if len(match.SessionPublic.FirstPathRegex) > 0 {
		ok := false
		for _, re := range match.SessionPublic.FirstPathRegex {
			if re.MatchString(in.SessionPublicFirstPath) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if match.SessionPublic.FirstPathDeep != nil {
		if in.SessionPublicFirstPathDeep != *match.SessionPublic.FirstPathDeep {
			return false
		}
	}
	if !match.SessionPublic.ReqCount.matches(float64(in.SessionPublicReqCount)) {
		return false
	}
	if !match.SessionPublic.Rate.matches(in.SessionPublicRate) {
		return false
	}
	if !match.SessionPublic.IdleSeconds.matches(in.SessionPublicIdleSeconds) {
		return false
	}
	if !match.SessionPublic.SuspiciousScore.matches(float64(in.SessionPublicSuspiciousScore)) {
		return false
	}
	if match.SessionPublic.SuspiciousIgnored != nil {
		if in.SessionPublicSuspiciousIgnored != *match.SessionPublic.SuspiciousIgnored {
			return false
		}
	}

	// Extended session_special
	if len(match.SessionSpecial.Role) > 0 {
		role := strings.ToLower(strings.TrimSpace(in.SessionSpecialRole))
		if _, ok := match.SessionSpecial.Role[role]; !ok {
			return false
		}
	}
	if !match.SessionSpecial.IdleSeconds.matches(in.SessionSpecialIdleSeconds) {
		return false
	}

	// Extended cookie_guard
	if match.CookieGuard.Valid != nil {
		if in.CookieGuardValid != *match.CookieGuard.Valid {
			return false
		}
	}
	if !match.CookieGuard.AgeSeconds.matches(in.CookieAgeSeconds) {
		return false
	}
	if len(match.CookieGuard.ChallengeLevel) > 0 {
		lvl := strings.ToLower(strings.TrimSpace(in.ChallengeLevel))
		if _, ok := match.CookieGuard.ChallengeLevel[lvl]; !ok {
			return false
		}
	}
	return true
}

func applyReturn(out *Output, ret RuleReturn, locked map[string]struct{}, lock bool) (changed bool) {
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
				changed = true
				continue
			}
			if _, exists := out.Vars[k]; exists {
				continue
			}
			out.Vars[k] = v
			changed = true
		}
	}
	if ret.Reason != "" && out.Reason == "" {
		out.Reason = ret.Reason
		changed = true
	}
	return changed
}
