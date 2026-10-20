package workbuddy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"sync"
	"time"
)

type SessionRoute struct {
	Key      string
	Page     int
	PageSize int
}
type affinityEntry struct {
	account string
	until   time.Time
}
type affinityBinding struct {
	entries []affinityEntry
	touched time.Time
}
type Affinity struct {
	mu       sync.Mutex
	now      func() time.Time
	bindings map[string]affinityBinding
	cursors  map[string]int
}

func NewAffinity(now func() time.Time) *Affinity {
	if now == nil {
		now = time.Now
	}
	return &Affinity{now: now, bindings: make(map[string]affinityBinding), cursors: make(map[string]int)}
}

// SessionRouting hashes only a stable prefix and caller scope; no prompt text
// is retained. Explicit sessions keep ordinary affinity regardless of length.
func SessionRouting(caller, explicit string, payload []byte, prefix bool, maxMessages, pageSize int) SessionRoute {
	var source []byte
	count := 0
	if explicit != "" {
		source = []byte(explicit)
	} else if prefix {
		var body struct {
			Messages []json.RawMessage `json:"messages"`
		}
		if json.Unmarshal(payload, &body) != nil || len(body.Messages) == 0 {
			return SessionRoute{}
		}
		count = len(body.Messages)
		head := body.Messages
		if len(head) > 2 {
			head = head[:2]
		}
		// Canonical object key ordering makes equivalent JSON share a session.
		var value any
		raw, _ := json.Marshal(head)
		if json.Unmarshal(raw, &value) != nil {
			return SessionRoute{}
		}
		source, _ = json.Marshal(value)
	} else {
		return SessionRoute{}
	}
	digest := sha256.Sum256(append(append([]byte(caller), 0), source...))
	route := SessionRoute{Key: hex.EncodeToString(digest[:])}
	if explicit == "" && maxMessages > 0 && count > maxMessages {
		if pageSize == 0 {
			return SessionRoute{}
		}
		if pageSize > 1 {
			route.PageSize = pageSize
			route.Page = int(binary.BigEndian.Uint32(digest[:4])) % pageSize
		}
	}
	return route
}
func affinityKey(realm Realm, route SessionRoute) string {
	if route.Key == "" {
		return ""
	}
	return string(realm) + "\x00" + route.Key
}
func (a *Affinity) live(key string) affinityBinding {
	binding := a.bindings[key]
	now := a.now()
	live := binding.entries[:0]
	for _, entry := range binding.entries {
		if now.Before(entry.until) {
			live = append(live, entry)
		}
	}
	binding.entries = live
	if len(live) == 0 {
		delete(a.bindings, key)
	} else {
		a.bindings[key] = binding
	}
	return binding
}

// Pick accepts already eligible account keys. Page ranks use all enabled realm
// accounts so a temporary cooldown does not reshuffle the conversation's page.
func (a *Affinity) Pick(realm Realm, route SessionRoute, eligible, all []string) string {
	if len(eligible) == 0 {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	key := affinityKey(realm, route)
	set := make(map[string]bool, len(eligible))
	for _, id := range eligible {
		set[id] = true
	}
	group := eligible
	if route.PageSize > 1 {
		ranks := append([]string(nil), all...)
		sort.Strings(ranks)
		page := make(map[string]bool)
		if route.PageSize < len(ranks) {
			for i, id := range ranks {
				if i%route.PageSize == route.Page%route.PageSize {
					page[id] = true
				}
			}
		} else {
			for _, id := range ranks {
				page[id] = true
			}
		}
		narrowed := make([]string, 0, len(eligible))
		for _, id := range eligible {
			if page[id] {
				narrowed = append(narrowed, id)
			}
		}
		if len(narrowed) > 0 {
			group = narrowed
		}
	} else if key != "" {
		for _, entry := range a.live(key).entries {
			if set[entry.account] {
				a.bindLocked(key, entry.account)
				return entry.account
			}
		}
	}
	sort.Strings(group)
	cursorKey := string(realm)
	if route.PageSize > 1 {
		cursorKey = string(realm) + ":" + strconv.Itoa(route.Page) + "/" + strconv.Itoa(route.PageSize)
	}
	if len(a.cursors) >= 5000 {
		delete(a.cursors, cursorKey)
		if len(a.cursors) >= 5000 {
			for k := range a.cursors {
				delete(a.cursors, k)
				break
			}
		}
	}
	index := a.cursors[cursorKey] % len(group)
	selected := group[index]
	a.cursors[cursorKey] = (index + 1) % len(group)
	if key != "" {
		a.bindLocked(key, selected)
	}
	return selected
}
func (a *Affinity) bindLocked(key, id string) {
	now := a.now()
	binding := a.live(key)
	entries := []affinityEntry{{account: id, until: now.Add(2 * time.Hour)}}
	for _, entry := range binding.entries {
		if entry.account != id && len(entries) < 3 {
			entries = append(entries, entry)
		}
	}
	if _, exists := a.bindings[key]; !exists && len(a.bindings) >= 5000 {
		oldest := ""
		var stamp time.Time
		for k, b := range a.bindings {
			if oldest == "" || b.touched.Before(stamp) {
				oldest, stamp = k, b.touched
			}
		}
		delete(a.bindings, oldest)
	}
	a.bindings[key] = affinityBinding{entries: entries, touched: now}
}
func (a *Affinity) Demote(realm Realm, route SessionRoute, id string) {
	key := affinityKey(realm, route)
	if key == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	binding := a.live(key)
	kept := binding.entries[:0]
	for _, entry := range binding.entries {
		if entry.account != id {
			kept = append(kept, entry)
		}
	}
	binding.entries = kept
	if len(kept) == 0 {
		delete(a.bindings, key)
	} else {
		a.bindings[key] = binding
	}
}
