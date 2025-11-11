package session

import (
	"container/list"
	"sort"
	"sync"
	"time"
)

// SpecialSnapshot represents the durable-trust view exposed to the policy
// engine. The struct intentionally keeps only immutable data so it can be
// shared safely with other components once captured under lock.
type SpecialSnapshot struct {
	Key          string
	Role         string
	Groups       []string
	Tags         map[string]string
	Hints        map[string]string
	FirstSeen    time.Time
	LastActivity time.Time
}

// SpecialTable stores trusted/privileged sessions keyed by backend signals or
// edge-issued tokens. Compared to PublicTable it retains data longer and avoids
// aggressive pruning.
type SpecialTable struct {
	maxEntries int
	now        func() time.Time

	mu        sync.Mutex
	order     *list.List
	entries   map[string]*list.Element
	evictions uint64
}

type specialEntry struct {
	Key    string
	Record *SpecialRecord
}

// SpecialRecord keeps mutable state; callers must hold SpecialTable's lock when
// mutating it.
type SpecialRecord struct {
	Key          string
	Role         string
	Groups       map[string]struct{}
	Tags         map[string]string
	Hints        map[string]string
	FirstSeen    time.Time
	LastActivity time.Time
}

// NewSpecialTable creates an LRU-backed table for trusted sessions.
func NewSpecialTable(maxEntries int) *SpecialTable {
	return &SpecialTable{
		maxEntries: maxEntries,
		now:        time.Now,
		order:      list.New(),
		entries:    make(map[string]*list.Element),
	}
}

// Update mutates (or creates) a special profile for key using the provided
// callback. The callback receives the record under lock so callers should keep
// work minimal.
func (t *SpecialTable) Update(key string, mutate func(*SpecialRecord)) SpecialSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.ensureLocked(key)
	rec := entry.Record
	rec.LastActivity = t.now()
	if mutate != nil {
		mutate(rec)
	}
	return snapshotSpecial(rec)
}

// Snapshot returns the current profile without mutating it.
func (t *SpecialTable) Snapshot(key string) (SpecialSnapshot, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	el, ok := t.entries[key]
	if !ok {
		return SpecialSnapshot{}, false
	}
	t.order.MoveToFront(el)
	return snapshotSpecial(el.Value.(*specialEntry).Record), true
}

// Touch updates LastActivity for an existing profile without creating a new
// record. It returns false when the key is unknown.
func (t *SpecialTable) Touch(key string) (SpecialSnapshot, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	el, ok := t.entries[key]
	if !ok {
		return SpecialSnapshot{}, false
	}
	rec := el.Value.(*specialEntry).Record
	rec.LastActivity = t.now()
	t.order.MoveToFront(el)
	return snapshotSpecial(rec), true
}

// Len reports the number of tracked trusted sessions.
func (t *SpecialTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// Evictions returns how many trusted sessions have been evicted.
func (t *SpecialTable) Evictions() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.evictions
}

func (t *SpecialTable) ensureLocked(key string) *specialEntry {
	if el, ok := t.entries[key]; ok {
		t.order.MoveToFront(el)
		return el.Value.(*specialEntry)
	}
	now := t.now()
	rec := &SpecialRecord{
		Key:          key,
		Groups:       make(map[string]struct{}),
		Tags:         make(map[string]string),
		Hints:        make(map[string]string),
		FirstSeen:    now,
		LastActivity: now,
	}
	entry := &specialEntry{Key: key, Record: rec}
	el := t.order.PushFront(entry)
	t.entries[key] = el
	if t.maxEntries > 0 && len(t.entries) > t.maxEntries {
		t.evictOldest()
	}
	return entry
}

func (t *SpecialTable) evictOldest() {
	oldest := t.order.Back()
	if oldest == nil {
		return
	}
	t.order.Remove(oldest)
	entry := oldest.Value.(*specialEntry)
	delete(t.entries, entry.Key)
	t.evictions++
}

func snapshotSpecial(rec *SpecialRecord) SpecialSnapshot {
	groups := make([]string, 0, len(rec.Groups))
	for g := range rec.Groups {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	tags := make(map[string]string, len(rec.Tags))
	for k, v := range rec.Tags {
		tags[k] = v
	}
	hints := make(map[string]string, len(rec.Hints))
	for k, v := range rec.Hints {
		hints[k] = v
	}
	return SpecialSnapshot{
		Key:          rec.Key,
		Role:         rec.Role,
		Groups:       groups,
		Tags:         tags,
		Hints:        hints,
		FirstSeen:    rec.FirstSeen,
		LastActivity: rec.LastActivity,
	}
}

// SetRole updates the profile role.
func (r *SpecialRecord) SetRole(role string) {
	r.Role = role
}

// AddGroup inserts the provided group label.
func (r *SpecialRecord) AddGroup(group string) {
	if group == "" {
		return
	}
	r.Groups[group] = struct{}{}
}

// SetTag stores/updates an arbitrary tag.
func (r *SpecialRecord) SetTag(key, value string) {
	if key == "" {
		return
	}
	if r.Tags == nil {
		r.Tags = make(map[string]string)
	}
	r.Tags[key] = value
}

// SetHint stores backend hints/metadata about the trusted session.
func (r *SpecialRecord) SetHint(key, value string) {
	if key == "" {
		return
	}
	if r.Hints == nil {
		r.Hints = make(map[string]string)
	}
	r.Hints[key] = value
}
