package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
)

// HashMode controls how session identifiers are transformed before storage.
//
// The default for both public and special tables is HashModeSHA256 so operators
// do not accidentally retain raw cookie values unless explicitly configured.
type HashMode string

const (
	HashModePlain      HashMode = "plain"
	HashModeSHA256     HashMode = "sha256"
	HashModeSHA512     HashMode = "sha512"
	HashModeHMACSHA256 HashMode = "hmac-sha256"
	HashModeHMACSHA512 HashMode = "hmac-sha512"
)

// Hasher wraps the digest configuration used when storing session identifiers
// or backend-provided trust signals.
type Hasher struct {
	mode HashMode
	key  []byte
}

// NewHasher returns a Hasher ready for use. For HMAC-based modes the key must
// be non-empty, otherwise an error is returned.
func NewHasher(mode HashMode, key []byte) (Hasher, error) {
	if mode == "" {
		mode = HashModeSHA256
	}
	switch mode {
	case HashModePlain, HashModeSHA256, HashModeSHA512:
		return Hasher{mode: mode}, nil
	case HashModeHMACSHA256, HashModeHMACSHA512:
		if len(key) == 0 {
			return Hasher{}, errors.New("session: hmac mode requires a non-empty key")
		}
		return Hasher{mode: mode, key: append([]byte(nil), key...)}, nil
	default:
		return Hasher{}, errors.New("session: unsupported hash mode")
	}
}

// Digest returns the hashed representation of v according to the configured
// mode. For HashModePlain the input is returned unchanged.
func (h Hasher) Digest(v string) string {
	switch h.mode {
	case HashModePlain:
		return v
	case HashModeSHA256:
		sum := sha256.Sum256([]byte(v))
		return hex.EncodeToString(sum[:])
	case HashModeSHA512:
		sum := sha512.Sum512([]byte(v))
		return hex.EncodeToString(sum[:])
	case HashModeHMACSHA256:
		return h.hmac(sha256.New, v)
	case HashModeHMACSHA512:
		return h.hmac(sha512.New, v)
	default:
		// Default to SHA256 if mode is unset/unknown to keep behavior consistent.
		sum := sha256.Sum256([]byte(v))
		return hex.EncodeToString(sum[:])
	}
}

func (h Hasher) hmac(factory func() hash.Hash, v string) string {
	mac := hmac.New(factory, h.key)
	mac.Write([]byte(v))
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum)
}
