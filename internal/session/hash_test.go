package session

import "testing"

func TestHasher(t *testing.T) {
	h, err := NewHasher(HashModeSHA256, nil)
	if err != nil {
		t.Fatalf("new hasher: %v", err)
	}
	digest := h.Digest("abc")
	if len(digest) != 64 {
		t.Fatalf("expected sha256 hex length 64, got %d", len(digest))
	}

	if _, err := NewHasher(HashModeHMACSHA256, nil); err == nil {
		t.Fatal("expected error when hmac secret missing")
	}

	hmac, err := NewHasher(HashModeHMACSHA256, []byte("secret"))
	if err != nil {
		t.Fatalf("hmac hasher: %v", err)
	}
	if got := hmac.Digest("abc"); got == "abc" || got == digest {
		t.Fatalf("unexpected hmac digest reuse: %s", got)
	}
}
