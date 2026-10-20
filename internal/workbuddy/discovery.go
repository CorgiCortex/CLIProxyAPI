package workbuddy

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ParseRemoteCatalog accepts the endpoint data or the equivalent desktop cache
// object. An empty agent list is not evidence that an account has no models.
func ParseRemoteCatalog(raw json.RawMessage, realm Realm) ([]Model, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil || root == nil {
		return nil, fmt.Errorf("workbuddy: invalid model catalog")
	}
	roots := []map[string]json.RawMessage{root}
	if data, ok := root["data"]; ok {
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(data, &nested); err != nil {
			return nil, fmt.Errorf("workbuddy: invalid catalog data")
		}
		if nested != nil {
			roots = append(roots, nested)
		}
	}
	var cli, other [][]string
	for _, r := range roots {
		agentsRaw := r["agents"]
		if len(agentsRaw) == 0 {
			continue
		}
		var agents []struct {
			Name   string   `json:"name"`
			Models []string `json:"models"`
		}
		if agentsRaw[0] == '[' {
			// Decode entries independently: non-chat agents may have a different
			// model configuration shape and cannot invalidate a valid chat list.
			var entries []json.RawMessage
			if err := json.Unmarshal(agentsRaw, &entries); err != nil {
				return nil, fmt.Errorf("workbuddy: invalid catalog agents")
			}
			for _, entry := range entries {
				var item struct {
					Name   string   `json:"name"`
					Models []string `json:"models"`
				}
				if json.Unmarshal(entry, &item) == nil {
					agents = append(agents, item)
				}
			}
		} else {
			var entries map[string]json.RawMessage
			if err := json.Unmarshal(agentsRaw, &entries); err != nil {
				return nil, fmt.Errorf("workbuddy: invalid catalog agents")
			}
			names := make([]string, 0, len(entries))
			for name := range entries {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				var item struct {
					Name   string   `json:"name"`
					Models []string `json:"models"`
				}
				if json.Unmarshal(entries[name], &item) == nil {
					item.Name = name
					agents = append(agents, item)
				}
			}
		}
		for _, agent := range agents {
			if len(agent.Models) == 0 {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(agent.Name), "cli") {
				cli = append(cli, agent.Models)
			} else {
				other = append(other, agent.Models)
			}
		}
	}
	pool := cli
	if len(pool) == 0 {
		pool = other
	}
	var ids []string
	for _, list := range pool {
		if len(list) > len(ids) {
			ids = list
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("workbuddy: empty remote model catalog")
	}
	metadata := make(map[string]json.RawMessage)
	var walk func(json.RawMessage, int)
	walk = func(node json.RawMessage, depth int) {
		if depth > 16 || len(node) == 0 {
			return
		}
		switch node[0] {
		case '{':
			var object map[string]json.RawMessage
			if json.Unmarshal(node, &object) != nil {
				return
			}
			if models, ok := object["models"]; ok {
				var entries []json.RawMessage
				if json.Unmarshal(models, &entries) == nil {
					for _, entry := range entries {
						var item struct {
							ID string `json:"id"`
						}
						if json.Unmarshal(entry, &item) == nil && validModelID(item.ID) {
							if _, exists := metadata[item.ID]; !exists {
								metadata[item.ID] = entry
							}
						}
					}
				}
			}
			names := make([]string, 0, len(object))
			for name := range object {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				walk(object[name], depth+1)
			}
		case '[':
			var entries []json.RawMessage
			if json.Unmarshal(node, &entries) == nil {
				for _, entry := range entries {
					walk(entry, depth+1)
				}
			}
		}
	}
	walk(raw, 0)
	models := Catalog(realm)
	byID := make(map[string]int, len(models))
	for i, m := range models {
		byID[m.ID] = i
	}
	seen := make(map[string]bool)
	valid := 0
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if !validModelID(id) || seen[id] {
			continue
		}
		seen[id] = true
		valid++
		m := Model{ID: id, Advertise: true}
		index, exists := byID[id]
		if exists {
			m = models[index]
		}
		if entry, ok := metadata[id]; ok {
			// Decode onto the snapshot so absent metadata never deletes known limits.
			if err := json.Unmarshal(entry, &m); err != nil {
				return nil, fmt.Errorf("workbuddy: malformed model metadata")
			}
			m.ID = id
		}
		if strings.HasSuffix(id, "-sg") || strings.HasSuffix(id, "-x") {
			sibling := strings.TrimSuffix(strings.TrimSuffix(id, "-sg"), "-x")
			if _, ok := byID[sibling]; ok {
				m.Advertise = false
			}
		}
		if exists {
			models[index] = m
		} else {
			byID[id] = len(models)
			models = append(models, m)
		}
	}
	if valid == 0 {
		return nil, fmt.Errorf("workbuddy: no usable models in remote catalog")
	}
	return models, nil
}
func validModelID(id string) bool {
	if len(id) == 0 || len(id) > 200 || strings.ContainsAny(id, "\r\n\t /\\") {
		return false
	}
	lower := strings.ToLower(id)
	return lower != "auto" && lower != "default" && !strings.HasPrefix(lower, "default-model") && !strings.Contains(lower, "completion")
}
func (a *ControlClient) DiscoverModels(ctx context.Context) ([]Model, error) {
	result, err := a.Call(ctx, ControlRequest{Operation: ControlModels})
	if err != nil {
		return nil, err
	}
	return ParseRemoteCatalog(result.Data, result.Credential.Realm)
}
