package contextcfg

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/artefactual-labs/decision-spoa/internal/session"
	"gopkg.in/yaml.v3"
)

func TestCompileResponse(t *testing.T) {
	yamlBody := []byte(`
response:
  mode: allowlist
  headers:
    - name: Atom-Authenticated
      table: special
      tags:
        session.role: editor
  cookies:
    - name: hb_v3
      table: public
      tags:
        challenge.level: heavy
hash:
  mode: hmac-sha256
  secret_file: secrets/hmac.key
`)
	var raw RawConfig
	if err := yaml.Unmarshal(yamlBody, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cfg, err := raw.Compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.Response.Mode != ForwardModeAllowlist {
		t.Fatalf("unexpected mode: %s", cfg.Response.Mode)
	}
	if len(cfg.Response.Headers) != 1 {
		t.Fatalf("expected 1 header rule")
	}
	if rule, ok := cfg.Response.Headers["atom-authenticated"]; !ok || rule.Tags["session.role"] != "editor" {
		t.Fatalf("missing header lookup: %v", cfg.Response.Headers)
	}
	if rule := cfg.Response.Headers["atom-authenticated"]; rule.HashMode != session.HashModeSHA256 {
		t.Fatalf("expected default hash mode sha256, got %s", rule.HashMode)
	}
}

func TestLoaderMissingFile(t *testing.T) {
	dir := t.TempDir()
	loader := Loader{Root: dir}
	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Response.Mode != ForwardModeAllowlist {
		t.Fatalf("expected default allowlist mode, got %s", cfg.Response.Mode)
	}

	secretDir := filepath.Join(dir, "secrets")
	if err := os.Mkdir(secretDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	secretPath := filepath.Join(secretDir, "hmac.key")
	if err := os.WriteFile(secretPath, []byte("abc123\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	body := []byte(`response: {mode: all}
hash: {mode: hmac-sha256, secret_file: secrets/hmac.key}`)
	if err := os.WriteFile(filepath.Join(dir, "context.yml"), body, 0o644); err != nil {
		t.Fatalf("write context: %v", err)
	}

	cfg, err = loader.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(cfg.Hash.Secret) != "abc123" {
		t.Fatalf("unexpected secret: %q", cfg.Hash.Secret)
	}
	if cfg.Response.Mode != ForwardModeAll {
		t.Fatalf("expected mode=all, got %s", cfg.Response.Mode)
	}
	if cfg.Hash.Mode != session.HashModeHMACSHA256 {
		t.Fatalf("expected hash mode hmac-sha256, got %s", cfg.Hash.Mode)
	}
}
