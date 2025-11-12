package main

import (
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/artefactual-labs/decision-spoa/internal/contextcfg"
	"github.com/artefactual-labs/decision-spoa/internal/session"
)

type trustRuntime struct {
	public  *session.PublicTable
	special *session.SpecialTable

	hashMu  sync.RWMutex
	hashers map[session.HashMode]session.Hasher
	secret  []byte

	publicHasher session.Hasher
}

func newTrustRuntime(pub *session.PublicTable, special *session.SpecialTable) *trustRuntime {
	h, _ := session.NewHasher(session.HashModeSHA256, nil)
	return &trustRuntime{
		public:       pub,
		special:      special,
		hashers:      make(map[session.HashMode]session.Hasher),
		publicHasher: h,
	}
}

func (t *trustRuntime) ConfigureHash(cfg contextcfg.HashingConfig) error {
	hasher, err := session.NewHasher(cfg.Mode, cfg.Secret)
	if err != nil {
		return err
	}
	t.hashMu.Lock()
	defer t.hashMu.Unlock()
	t.secret = append([]byte(nil), cfg.Secret...)
	t.hashers = map[session.HashMode]session.Hasher{
		cfg.Mode: hasher,
	}
	return nil
}

func (t *trustRuntime) hasherFor(mode session.HashMode) (session.Hasher, error) {
	if mode == "" {
		mode = session.HashModeSHA256
	}
	t.hashMu.RLock()
	if h, ok := t.hashers[mode]; ok {
		t.hashMu.RUnlock()
		return h, nil
	}
	secret := append([]byte(nil), t.secret...)
	t.hashMu.RUnlock()

	h, err := session.NewHasher(mode, secret)
	if err != nil {
		return session.Hasher{}, err
	}

	t.hashMu.Lock()
	defer t.hashMu.Unlock()
	if existing, ok := t.hashers[mode]; ok {
		return existing, nil
	}
	t.hashers[mode] = h
	return h, nil
}

func (t *trustRuntime) digestValue(mode session.HashMode, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	hasher, err := t.hasherFor(mode)
	if err != nil {
		return "", err
	}
	return hasher.Digest(value), nil
}

func parseHeaderBlock(block string) []headerPair {
	if block == "" {
		return nil
	}
	normalized := strings.ReplaceAll(block, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	out := make([]headerPair, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		if name == "" {
			continue
		}
		out = append(out, headerPair{Name: name, Value: value})
	}
	return out
}

type headerPair struct {
	Name  string
	Value string
}

func parseCookieHeader(headerValue string) map[string]string {
	if headerValue == "" {
		return nil
	}
	out := make(map[string]string)
	parts := strings.Split(headerValue, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.Index(part, "=")
		if idx <= 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(part[:idx]))
		value := strings.TrimSpace(part[idx+1:])
		if name == "" {
			continue
		}
		out[name] = value
	}
	return out
}

func parseSetCookie(line string) (string, string) {
	if line == "" {
		return "", ""
	}
	parts := strings.SplitN(line, ";", 2)
	kv := strings.TrimSpace(parts[0])
	idx := strings.Index(kv, "=")
	if idx <= 0 {
		return "", ""
	}
	name := strings.ToLower(strings.TrimSpace(kv[:idx]))
	value := strings.TrimSpace(kv[idx+1:])
	return name, value
}

func applySignalToSpecial(rule contextcfg.SignalRule, rawValue, digest string, rt *trustRuntime) {
	if digest == "" {
		return
	}
	rt.special.Update(digest, func(rec *session.SpecialRecord) {
		rec.SetHint("signal."+rule.Name, digest)
		applyRuleTags(rec, rule, rawValue, digest)
	})
}

func applyRuleTags(rec *session.SpecialRecord, rule contextcfg.SignalRule, rawValue, digest string) {
	for k, v := range rule.Tags {
		resolved := strings.ReplaceAll(v, "${value}", rawValue)
		resolved = strings.ReplaceAll(resolved, "${digest}", digest)
		switch strings.ToLower(k) {
		case "session.role", "session_special.role", "role":
			rec.SetRole(resolved)
			decisionTrustHintTotal.WithLabelValues("role=" + resolved).Inc()
		case "session.group", "session.groups", "group":
			for _, g := range strings.Split(resolved, ",") {
				if trimmed := strings.TrimSpace(g); trimmed != "" {
					rec.AddGroup(trimmed)
					decisionTrustHintTotal.WithLabelValues("group=" + trimmed).Inc()
				}
			}
		default:
			rec.SetTag(k, resolved)
		}
	}
}

func pathLooksDeep(path string) bool {
	if path == "" || path == "/" {
		return false
	}
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return false
	}
	segments := strings.Split(trimmed, "/")
	return len(segments) >= 2
}

func pickNewestSpecial(a, b session.SpecialSnapshot) session.SpecialSnapshot {
	if a.Key == "" {
		return b
	}
	if b.Key == "" {
		return a
	}
	if b.LastActivity.After(a.LastActivity) {
		return b
	}
	return a
}

func (t *trustRuntime) logMissingHasher(rule contextcfg.SignalRule, err error) {
	log.Printf("trust-runtime: skipping signal %s: %v", rule.Name, err)
}

func (t *trustRuntime) updateSpecialFromCookie(rule contextcfg.SignalRule, value string) {
	digest, err := t.digestValue(rule.HashMode, value)
	if err != nil {
		t.logMissingHasher(rule, err)
		return
	}
	applySignalToSpecial(rule, value, digest, t)
}

func (t *trustRuntime) addSuspicion(key string, delta int) (int, bool) {
	if t == nil || key == "" {
		return 0, false
	}
	return t.public.AddSuspicion(key, delta)
}

func (t *trustRuntime) resetSuspicion(key string) bool {
	if t == nil || key == "" {
		return false
	}
	return t.public.ResetSuspicion(key)
}

func (t *trustRuntime) setSuspicionIgnore(key string, ignore bool) bool {
	if t == nil || key == "" {
		return false
	}
	return t.public.SetSuspicionIgnore(key, ignore)
}

func specialIdleSeconds(now time.Time, snap session.SpecialSnapshot) float64 {
	if snap.Key == "" || snap.LastActivity.IsZero() {
		return 0
	}
	return now.Sub(snap.LastActivity).Seconds()
}

func (t *trustRuntime) publicSessionKey(cookieID string, ip net.IP, ua string) string {
	parts := []string{strings.TrimSpace(cookieID), strings.TrimSpace(ua)}
	if ip != nil {
		parts = append(parts, ip.String())
	} else {
		parts = append(parts, "")
	}
	compound := strings.Join(parts, "|")
	return t.publicHasher.Digest(compound)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
