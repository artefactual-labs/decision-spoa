package contextcfg

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Loader reads context.yml plus any referenced secrets (e.g., HMAC keys).
type Loader struct {
	Root string
}

func (l Loader) Load() (Config, error) {
	path := filepath.Join(l.Root, "context.yml")
	data, err := os.ReadFile(path)
	var raw RawConfig
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return raw.Compile()
		}
		return Config{}, fmt.Errorf("contextcfg: read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return Config{}, fmt.Errorf("contextcfg: parse %s: %w", path, err)
	}
	cfg, err := raw.Compile()
	if err != nil {
		return Config{}, err
	}
	if cfg.Hash.SecretFile != "" {
		secretPath := cfg.Hash.SecretFile
		if !filepath.IsAbs(secretPath) {
			secretPath = filepath.Join(l.Root, secretPath)
		}
		secret, err := os.ReadFile(secretPath)
		if err != nil {
			return Config{}, fmt.Errorf("contextcfg: read secret %s: %w", secretPath, err)
		}
		cfg.Hash.Secret = bytes.TrimSpace(secret)
	}
	return cfg, nil
}
