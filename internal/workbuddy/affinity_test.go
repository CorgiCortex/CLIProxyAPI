package workbuddy

import (
	"testing"
	"time"
)

func TestWorkBuddyPrefixRoutingScopeAndPaging(t *testing.T) {
	first := []byte(`{"messages":[{"role":"system","content":"rules"},{"role":"user","content":"first"}]}`)
	follow := []byte(`{"messages":[{"content":"rules","role":"system"},{"content":"first","role":"user"},{"role":"assistant","content":"reply"},{"role":"user","content":"next"}]}`)
	a := SessionRouting("caller-a", "", first, true, 2, 3)
	b := SessionRouting("caller-a", "", follow, true, 2, 3)
	if a.Key == "" || a.Key != b.Key || a.PageSize != 0 || b.PageSize != 3 {
		t.Fatalf("routes = %+v %+v", a, b)
	}
	if other := SessionRouting("caller-b", "", first, true, 2, 3); other.Key == a.Key {
		t.Fatal("caller scopes share affinity")
	}
	if explicit := SessionRouting("caller-a", "explicit", follow, true, 2, 3); explicit.PageSize != 0 || explicit.Key == a.Key {
		t.Fatal("explicit session paged or collided")
	}
	if off := SessionRouting("caller-a", "", follow, true, 2, 0); off.Key != "" {
		t.Fatal("legacy full rotation mode did not disable long affinity")
	}
}
func TestWorkBuddyAffinityHistoryAndExpiry(t *testing.T) {
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	a := NewAffinity(func() time.Time { return now })
	route := SessionRoute{Key: "conversation"}
	all := []string{"a", "b", "c"}
	if got := a.Pick(International, route, []string{"a"}, all); got != "a" {
		t.Fatal(got)
	}
	now = now.Add(time.Minute)
	if got := a.Pick(International, route, []string{"b"}, all); got != "b" {
		t.Fatal(got)
	}
	if got := a.Pick(International, route, []string{"a", "c"}, all); got != "a" {
		t.Fatal("warm history not preferred")
	}
	a.Demote(International, route, "a")
	if got := a.Pick(International, route, []string{"b", "c"}, all); got != "b" {
		t.Fatal("demotion discarded other warm accounts")
	}
	if got := a.Pick(China, route, []string{"c"}, all); got != "c" {
		t.Fatal("realm route corrupted")
	}
	now = now.Add(2*time.Hour + time.Second)
	a.mu.Lock()
	live := a.live(affinityKey(International, route))
	a.mu.Unlock()
	if len(live.entries) != 0 {
		t.Fatal("expired affinity survived")
	}
}
func TestWorkBuddyConversationPageRanksDoNotShiftWithCooldown(t *testing.T) {
	a := NewAffinity(nil)
	route := SessionRoute{Key: "long-conversation", Page: 1, PageSize: 3}
	all := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	seen := make(map[string]bool)
	for i := 0; i < 12; i++ {
		seen[a.Pick(International, route, append([]string(nil), all...), all)] = true
	}
	if len(seen) != 3 || !seen["b"] || !seen["e"] || !seen["h"] {
		t.Fatalf("page = %+v", seen)
	}
	for i := 0; i < 6; i++ {
		got := a.Pick(International, route, []string{"a", "c", "d", "e", "f", "g", "h"}, all)
		if got != "e" && got != "h" {
			t.Fatalf("cooldown shifted page: %s", got)
		}
	}
	if got := a.Pick(International, route, []string{"a", "c", "d"}, all); got != "a" && got != "c" && got != "d" {
		t.Fatal("empty page did not fall back")
	}
}
