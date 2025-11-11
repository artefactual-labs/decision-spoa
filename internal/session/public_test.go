package session

import (
	"testing"
	"time"
)

func TestPublicTableRecordAndEvict(t *testing.T) {
	clock := fakeClock{t: time.Unix(1700000000, 0)}
	table := NewPublicTable(2, time.Minute)
	table.now = clock.Now

	table.Record("a", "/", clock.Now())
	clock.Advance(10 * time.Second)
	table.Record("b", "/b", clock.Now())
	clock.Advance(10 * time.Second)
	table.Record("c", "/c", clock.Now()) // triggers eviction of "a"

	if table.Len() != 2 {
		t.Fatalf("expected len=2, got %d", table.Len())
	}
	if table.Evictions() != 1 {
		t.Fatalf("expected 1 eviction, got %d", table.Evictions())
	}
	if _, ok := table.Snapshot("a"); ok {
		t.Fatalf("expected 'a' to be evicted")
	}

	snapB, ok := table.Snapshot("b")
	if !ok {
		t.Fatalf("expected snapshot for 'b'")
	}
	if snapB.RecentHits != 1 {
		t.Fatalf("expected 1 hit in recent window, got %d", snapB.RecentHits)
	}
}

func TestPublicTableRateWindow(t *testing.T) {
	clock := fakeClock{t: time.Unix(1700000000, 0)}
	table := NewPublicTable(10, 30*time.Second)
	table.now = clock.Now

	table.Record("k", "/", clock.Now())
	clock.Advance(10 * time.Second)
	table.Record("k", "/", clock.Now())
	clock.Advance(25 * time.Second) // pushes the first hit outside the 30s window
	table.Record("k", "/", clock.Now())

	snap, ok := table.Snapshot("k")
	if !ok {
		t.Fatalf("missing snapshot")
	}
	if snap.RecentHits != 2 {
		t.Fatalf("expected 2 hits within last 30s, got %d", snap.RecentHits)
	}
}

type fakeClock struct {
	t time.Time
}

func (c *fakeClock) Now() time.Time {
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.t = c.t.Add(d)
}
