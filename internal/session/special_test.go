package session

import (
	"testing"
	"time"
)

func TestSpecialTableUpdate(t *testing.T) {
	clock := fakeClock{t: time.Unix(1700000000, 0)}
	table := NewSpecialTable(1)
	table.now = clock.Now

	snap := table.Update("token", func(rec *SpecialRecord) {
		rec.SetRole("editor")
		rec.AddGroup("staff")
		rec.SetHint("source", "atom")
	})
	if snap.Role != "editor" {
		t.Fatalf("unexpected role: %s", snap.Role)
	}
	if len(snap.Groups) != 1 || snap.Groups[0] != "staff" {
		t.Fatalf("unexpected groups: %v", snap.Groups)
	}

	clock.Advance(time.Minute)
	table.Update("token", nil)
	if table.Len() != 1 {
		t.Fatalf("expected len=1, got %d", table.Len())
	}

	table.Update("other", nil) // should evict first entry because max=1
	if table.Evictions() != 1 {
		t.Fatalf("expected eviction counter increment, got %d", table.Evictions())
	}

	if _, ok := table.Touch("missing"); ok {
		t.Fatalf("expected missing touch to be false")
	}
}

func TestSpecialTableTouch(t *testing.T) {
	clock := fakeClock{t: time.Unix(1700000000, 0)}
	table := NewSpecialTable(2)
	table.now = clock.Now

	table.Update("token", func(rec *SpecialRecord) {
		rec.SetRole("viewer")
	})
	first, ok := table.Snapshot("token")
	if !ok {
		t.Fatalf("expected snapshot")
	}
	if first.Role != "viewer" {
		t.Fatalf("unexpected role: %s", first.Role)
	}

	clock.Advance(5 * time.Second)
	touched, ok := table.Touch("token")
	if !ok {
		t.Fatalf("touch should succeed")
	}
	if touched.LastActivity.Sub(first.LastActivity) != 5*time.Second {
		t.Fatalf("expected last activity to move forward")
	}
}
