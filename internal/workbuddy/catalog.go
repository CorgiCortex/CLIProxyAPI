package workbuddy

import (
	_ "embed"
	"encoding/json"
	"strings"
)

// catalogSnapshot is a versioned offline fallback, not a claim of live access.
// Source: workbuddy2api-hub af706fc31e4a22cb2dea7442361b2b15185c3cee.
//
//go:embed catalog.json
var catalogSnapshot []byte

type Model struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Credits   string        `json:"credits"`
	Input     int           `json:"maxInputTokens"`
	Output    int           `json:"maxOutputTokens"`
	Context   int           `json:"maxAllowedSize"`
	Images    bool          `json:"supportsImages"`
	Tools     bool          `json:"supportsToolCall"`
	Reasoning bool          `json:"supportsReasoning"`
	Advertise bool          `json:"advertise"`
	Thinking  ModelThinking `json:"reasoning"`
}

type ModelThinking struct {
	Effort     string   `json:"effort"`
	Default    string   `json:"defaultEffort"`
	Levels     []string `json:"supportedEfforts"`
	CanDisable *bool    `json:"canDisableThinking"`
}

func Catalog(realm Realm) []Model {
	var catalogs map[Realm][]Model
	if json.Unmarshal(catalogSnapshot, &catalogs) != nil {
		return nil
	}
	return catalogs[realm]
}
func ModelFor(realm Realm, id string) (Model, bool) {
	for _, m := range Catalog(realm) {
		if m.ID == id {
			return m, true
		}
	}
	return Model{ID: id}, false
}
func IsFreeCapModel(realm Realm, model string) bool {
	return (realm == China || realm == International) && (model == "hy3" || model == "hy4-preview-f" || realm == International && model == "deepseek-v4.1-flash")
}
func IsPaidModel(realm Realm, model string) bool {
	m, ok := ModelFor(realm, model)
	if IsFreeCapModel(realm, model) {
		return false
	}
	return !ok || !strings.Contains(m.Credits, "x0.00")
}
