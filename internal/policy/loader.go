package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Loader knows how to load a compiled policy configuration from disk.
type Loader struct {
	Root string
}

// LoadAll reads policy.yml and compiles it.
func (l Loader) LoadAll() (Config, error) {
	raw, err := loadRawConfig(l.Root)
	if err != nil {
		// Provide a clearer error when the new unified file is missing.
		var pathErr *os.PathError
		if errors.As(err, &pathErr) && errors.Is(pathErr, os.ErrNotExist) {
			return Config{}, fmt.Errorf("policy loader: expected %s but file does not exist", filepath.Join(l.Root, "policy.yml"))
		}
		return Config{}, err
	}

	cfg, err := raw.Compile()
	if err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
