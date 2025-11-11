package session

import (
	"container/list"
	"sync"
	"time"
)

// PublicSnapshot captures the fields needed by the policy engine for the
// general-purpose (public) session table. All durations are expressed in
// seconds to keep the structure JSON/SPoe friendly when we eventually expose
// it to HAProxy.
type PublicSnapshot struct {
	Key             string
	FirstSeen       time.Time
	LastSeen        time.Time
	FirstPath       string
	RequestCount    uint64
	RecentWindowSec float64
	RecentHits      int
}

// PublicTable tracks short-lived public sessions derived from hashed
// (cookie, IP, UA) tuples. It keeps a rolling window of recent timestamps for
// rate calculations and evicts entries via LRU when the configured capacity is
// reached.
type PublicTable struct {
	maxEntries int
	rateWindow time.Duration
	now        func() time.Time

	mu        sync.Mutex
	order     *list.List
	entries   map[string]*list.Element
	evictions uint64
}

type publicEntry struct {
	Key    string
	Record *PublicRecord
}

// PublicRecord stores mutable state for a public session.
type PublicRecord struct {
	Key          string
	FirstSeen    time.Time
	LastSeen     time.Time
	FirstPath    string
	RequestCount uint64
	recent       []time.Time
}

// NewPublicTable creates a new LRU-backed public session table. rateWindow
// controls how far back timestamps are considered when computing recent hit
// counts.
func NewPublicTable(maxEntries int, rateWindow time.Duration) *PublicTable {
	return &PublicTable{
		maxEntries: maxEntries,
		rateWindow: rateWindow,
		now:        time.Now,
		order:      list.New(),
		entries:    make(map[string]*list.Element),
	}
}

// Record updates (or creates) the public session for key and returns a
// snapshot after the mutation.
func (t *PublicTable) Record(key, path string, ts time.Time) PublicSnapshot {
	if ts.IsZero() {
		ts = t.now()
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	entry := t.ensureLocked(key, ts)
	rec := entry.Record
	rec.RequestCount++
	rec.LastSeen = ts
	if rec.FirstPath == "" && path != "" {
		rec.FirstPath = path
	}
	rec.recent = append(rec.recent, ts)
	cutoff := ts.Add(-t.rateWindow)
	rec.recent = pruneRecent(rec.recent, cutoff)

	return snapshotFromRecord(rec, t.rateWindow)
}

// Snapshot returns the current view for a key without mutating it.
func (t *PublicTable) Snapshot(key string) (PublicSnapshot, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if el, ok := t.entries[key]; ok {
		t.order.MoveToFront(el)
		return snapshotFromRecord(el.Value.(*publicEntry).Record, t.rateWindow), true
	}
	return PublicSnapshot{}, false
}

// Len exposes the current number of tracked sessions.
func (t *PublicTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// Evictions returns the lifetime eviction counter.
func (t *PublicTable) Evictions() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.evictions
}

func (t *PublicTable) ensureLocked(key string, ts time.Time) *publicEntry {
	if el, ok := t.entries[key]; ok {
		t.order.MoveToFront(el)
		return el.Value.(*publicEntry)
	}
	rec := &PublicRecord{Key: key, FirstSeen: ts, LastSeen: ts}
	entry := &publicEntry{Key: key, Record: rec}
	el := t.order.PushFront(entry)
	t.entries[key] = el
	if t.maxEntries > 0 && len(t.entries) > t.maxEntries {
		t.evictOldest()
	}
	return entry
}

func (t *PublicTable) evictOldest() {
	oldest := t.order.Back()
	if oldest == nil {
		return
	}
	t.order.Remove(oldest)
	entry := oldest.Value.(*publicEntry)
	delete(t.entries, entry.Key)
	t.evictions++
}

func snapshotFromRecord(rec *PublicRecord, window time.Duration) PublicSnapshot {
	recent := pruneRecent(rec.recent, rec.LastSeen.Add(-window))
	rec.recent = recent
	return PublicSnapshot{
		Key:             rec.Key,
		FirstSeen:       rec.FirstSeen,
		LastSeen:        rec.LastSeen,
		FirstPath:       rec.FirstPath,
		RequestCount:    rec.RequestCount,
		RecentWindowSec: window.Seconds(),
		RecentHits:      len(recent),
	}
}

func pruneRecent(all []time.Time, cutoff time.Time) []time.Time {
	if len(all) == 0 {
		return nil
	}
	idx := 0
	for _, ts := range all {
		if ts.Before(cutoff) {
			continue
		}
		all[idx] = ts
		idx++
	}
	return all[:idx]
}
