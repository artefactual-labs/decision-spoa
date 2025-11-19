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

func TestSuspicionScore(t *testing.T) {
	table := NewPublicTable(10, time.Minute)
	now := time.Unix(1700000000, 0)
	table.now = func() time.Time { return now }

	snap := table.Record("key", "/", now)
	if snap.SuspiciousScore != 0 {
		t.Fatalf("expected initial suspicious score 0, got %d", snap.SuspiciousScore)
	}

	if _, ok := table.AddSuspicion("missing", 5); ok {
		t.Fatalf("expected AddSuspicion false for missing key")
	}

	score, ok := table.AddSuspicion("key", 3)
	if !ok || score != 3 {
		t.Fatalf("expected updated score 3, got %d ok=%v", score, ok)
	}

	score, _ = table.AddSuspicion("key", -10)
	if score != 0 {
		t.Fatalf("score should clamp to 0, got %d", score)
	}

	if !table.ResetSuspicion("key") {
		t.Fatalf("expected reset success")
	}
	snap2, ok := table.Snapshot("key")
	if !ok || snap2.SuspiciousScore != 0 {
		t.Fatalf("expected snapshot score 0 after reset, got %d", snap2.SuspiciousScore)
	}

	if !table.SetSuspicionIgnore("key", true) {
		t.Fatalf("expected ignore set")
	}
	if snap3, _ := table.Snapshot("key"); !snap3.SuspiciousIgnored {
		t.Fatalf("snapshot should reflect ignore flag")
	}
	score, _ = table.AddSuspicion("key", 5)
	if score != 0 {
		t.Fatalf("score should remain 0 when ignored, got %d", score)
	}
	if !table.SetSuspicionIgnore("key", false) {
		t.Fatalf("expected ignore clear")
	}
	score, _ = table.AddSuspicion("key", 2)
	if score != 2 {
		t.Fatalf("score should increase after clearing ignore, got %d", score)
	}
}

func TestRecordWithBotd(t *testing.T) {
	table := NewPublicTable(10, time.Minute)
	now := time.Unix(1700000000, 0)
	table.now = func() time.Time { return now }

	botd := BotdTelemetry{
		Verdict:    "bad",
		Kind:       "automation",
		Confidence: 0.95,
		RequestID:  "req-1",
		SeenAt:     now,
	}
	snap := table.RecordWithBotd("key", "/", now, &botd)
	if snap.Botd.Verdict != "bad" || snap.Botd.Kind != "automation" {
		t.Fatalf("expected botd to persist, got %+v", snap.Botd)
	}

	// Subsequent record without telemetry should keep previous data.
	updated := table.RecordWithBotd("key", "/next", now.Add(10*time.Second), nil)
	if updated.Botd.Verdict != "bad" {
		t.Fatalf("botd verdict should remain, got %q", updated.Botd.Verdict)
	}
	if updated.Botd.SeenAt.IsZero() {
		t.Fatalf("botd seen timestamp should persist")
	}

	// Overwrite with new telemetry
	newBotd := BotdTelemetry{Verdict: "good", SeenAt: now.Add(20 * time.Second)}
	updated = table.RecordWithBotd("key", "/next", now.Add(20*time.Second), &newBotd)
	if updated.Botd.Verdict != "good" {
		t.Fatalf("botd verdict should update, got %q", updated.Botd.Verdict)
	}
	if !updated.Botd.SeenAt.Equal(newBotd.SeenAt) {
		t.Fatalf("expected seen timestamp to update")
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
