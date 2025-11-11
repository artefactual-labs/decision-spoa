package contextcfg

import (
	"fmt"
	"strings"

	"github.com/artefactual-labs/decision-spoa/internal/session"
)

// ForwardMode describes how HAProxy response data is exposed to Decision.
type ForwardMode string

const (
	ForwardModeAllowlist ForwardMode = "allowlist"
	ForwardModeAll       ForwardMode = "all"
)

// TargetTable determines which in-memory store should receive a signal.
type TargetTable string

const (
	TargetTableSpecial TargetTable = "special"
	TargetTablePublic  TargetTable = "public"
)

// Config is the compiled response/context configuration consumed by Decision.
type Config struct {
	Response ResponseConfig
	Hash     HashingConfig
}

// ResponseConfig stores normalized allowlists for response forwarding.
type ResponseConfig struct {
	Mode    ForwardMode
	Headers map[string]SignalRule
	Cookies map[string]SignalRule
}

// SignalRule describes how to interpret an individual header/cookie.
type SignalRule struct {
	Name     string
	Table    TargetTable
	Tags     map[string]string
	HashMode session.HashMode
}

// HashingConfig controls optional digest overrides when storing trusted data.
type HashingConfig struct {
	Mode       session.HashMode `yaml:"-"`
	SecretFile string           `yaml:"secret_file"`
	Secret     []byte           `yaml:"-"`
}

// RawConfig mirrors the YAML layout from context.yml before compilation.
type RawConfig struct {
	Response RawResponseConfig `yaml:"response"`
	Hash     RawHashConfig     `yaml:"hash"`
}

type RawHashConfig struct {
	Mode       string `yaml:"mode"`
	SecretFile string `yaml:"secret_file"`
}

type RawResponseConfig struct {
	Mode    string          `yaml:"mode"`
	Headers []RawSignalRule `yaml:"headers"`
	Cookies []RawSignalRule `yaml:"cookies"`
}

type RawSignalRule struct {
	Name     string            `yaml:"name"`
	Table    string            `yaml:"table"`
	Tags     map[string]string `yaml:"tags"`
	HashMode string            `yaml:"hash_mode"`
}

// Compile builds the lookup maps and validates user friendly values.
func (r RawConfig) Compile() (Config, error) {
	resp, err := compileResponse(r.Response)
	if err != nil {
		return Config{}, err
	}
	hashCfg, err := compileHash(r.Hash)
	if err != nil {
		return Config{}, err
	}
	return Config{Response: resp, Hash: hashCfg}, nil
}

func compileResponse(raw RawResponseConfig) (ResponseConfig, error) {
	mode := ForwardModeAllowlist
	if raw.Mode != "" {
		switch ForwardMode(raw.Mode) {
		case ForwardModeAllowlist, ForwardModeAll:
			mode = ForwardMode(raw.Mode)
		default:
			return ResponseConfig{}, fmt.Errorf("contextcfg: unsupported response.mode %q", raw.Mode)
		}
	}
	headers, err := indexSignals(raw.Headers)
	if err != nil {
		return ResponseConfig{}, err
	}
	cookies, err := indexSignals(raw.Cookies)
	if err != nil {
		return ResponseConfig{}, err
	}
	return ResponseConfig{Mode: mode, Headers: headers, Cookies: cookies}, nil
}

func indexSignals(items []RawSignalRule) (map[string]SignalRule, error) {
	if len(items) == 0 {
		return map[string]SignalRule{}, nil
	}
	out := make(map[string]SignalRule, len(items))
	for _, item := range items {
		name := normalizeKey(item.Name)
		if name == "" {
			return nil, fmt.Errorf("contextcfg: signal missing name")
		}
		table := TargetTableSpecial
		if item.Table != "" {
			table = TargetTable(item.Table)
		}
		switch table {
		case TargetTableSpecial, TargetTablePublic:
		default:
			return nil, fmt.Errorf("contextcfg: unsupported table %q for %s", item.Table, item.Name)
		}
		if _, exists := out[name]; exists {
			return nil, fmt.Errorf("contextcfg: duplicate signal for %s", item.Name)
		}
		tags := make(map[string]string, len(item.Tags))
		for k, v := range item.Tags {
			if k == "" {
				continue
			}
			tags[k] = v
		}
		hashMode, err := parseHashMode(item.HashMode)
		if err != nil {
			return nil, err
		}
		out[name] = SignalRule{
			Name:     item.Name,
			Table:    table,
			Tags:     tags,
			HashMode: hashMode,
		}
	}
	return out, nil
}

func normalizeKey(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func compileHash(raw RawHashConfig) (HashingConfig, error) {
	mode, err := parseHashMode(raw.Mode)
	if err != nil {
		return HashingConfig{}, err
	}
	return HashingConfig{
		Mode:       mode,
		SecretFile: raw.SecretFile,
	}, nil
}

func parseHashMode(v string) (session.HashMode, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return session.HashModeSHA256, nil
	case "plain":
		return session.HashModePlain, nil
	case "sha256":
		return session.HashModeSHA256, nil
	case "sha512":
		return session.HashModeSHA512, nil
	case "hmac-sha256":
		return session.HashModeHMACSHA256, nil
	case "hmac-sha512":
		return session.HashModeHMACSHA512, nil
	default:
		return "", fmt.Errorf("contextcfg: unknown hash mode %q", v)
	}
}
