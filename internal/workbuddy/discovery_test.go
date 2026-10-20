package workbuddy

import (
	"encoding/json"
	"testing"
)

func TestWorkBuddyRemoteCatalogPrefersCLIAndKeepsSnapshot(t *testing.T) {
	raw := json.RawMessage(`{"data":{"agents":{"desktop":{"models":["other-a","other-b"]},"cli":{"models":["fixture-new","auto","fixture-new"]}},"models":[{"id":"fixture-new","maxInputTokens":1234,"supportsToolCall":true}]}}`)
	models, err := ParseRemoteCatalog(raw, International)
	if err != nil {
		t.Fatal(err)
	}
	found, static := false, false
	for _, m := range models {
		switch m.ID {
		case "fixture-new":
			if found || m.Input != 1234 || !m.Tools || !m.Advertise {
				t.Fatal("bad remote model")
			}
			found = true
		case "deepseek-v4.1-flash":
			static = true
		case "other-a", "other-b", "auto":
			t.Fatal("non-CLI or virtual model advertised")
		}
	}
	if !found || !static {
		t.Fatal("remote merge lost models")
	}
}
func TestWorkBuddyRemoteCatalogEmptyCannotDeleteFallback(t *testing.T) {
	for _, raw := range []string{`{}`, `{"agents":[]}`, `{"agents":{"cli":{"models":[]}}}`, `{"agents":[{"name":"cli","models":["auto"]}]}`} {
		if _, err := ParseRemoteCatalog(json.RawMessage(raw), China); err == nil {
			t.Fatal("empty catalog accepted")
		}
	}
	models, err := ParseRemoteCatalog(json.RawMessage(`{"agents":[{"name":"other","models":["first"]},{"name":"long","models":["second","third"]}]}`), China)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, m := range models {
		if m.ID == "first" {
			t.Fatal("shorter list chosen")
		}
		if m.ID == "second" || m.ID == "third" {
			found++
		}
	}
	if found != 2 {
		t.Fatal("longest fallback list missing")
	}
}
