package workbuddy

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

type CreditPackage struct {
	ID         string   `json:"id,omitempty"`
	Code       string   `json:"code,omitempty"`
	Remaining  *float64 `json:"remaining,omitempty"`
	Used       *float64 `json:"used,omitempty"`
	Capacity   *float64 `json:"capacity,omitempty"`
	CycleStart string   `json:"cycle_start,omitempty"`
	CycleEnd   string   `json:"cycle_end,omitempty"`
}
type BalanceSnapshot struct {
	ObservedAt time.Time       `json:"observed_at"`
	Remaining  *float64        `json:"remaining,omitempty"`
	Used       *float64        `json:"used,omitempty"`
	Capacity   *float64        `json:"capacity,omitempty"`
	Packages   []CreditPackage `json:"packages"`
	Enterprise bool            `json:"enterprise"`
}

// observedNumber preserves absence and explicit zero. It never derives a
// missing field from another field and never treats malformed values as zero.
func observedNumber(fields map[string]json.RawMessage, keys ...string) (*float64, error) {
	for _, key := range keys {
		raw, exists := fields[key]
		if !exists || string(raw) == "null" || string(raw) == `""` {
			continue
		}
		var value float64
		if len(raw) > 0 && raw[0] == '"' {
			var text string
			if err := json.Unmarshal(raw, &text); err != nil {
				return nil, fmt.Errorf("workbuddy: malformed numeric field %s", key)
			}
			var err error
			value, err = strconv.ParseFloat(text, 64)
			if err != nil {
				return nil, fmt.Errorf("workbuddy: malformed numeric field %s", key)
			}
		} else if err := json.Unmarshal(raw, &value); err != nil {
			return nil, fmt.Errorf("workbuddy: malformed numeric field %s", key)
		}
		if !validCredit(value) {
			return nil, fmt.Errorf("workbuddy: invalid credit field %s", key)
		}
		return &value, nil
	}
	return nil, nil
}
func decodeCreditPackage(raw json.RawMessage) (CreditPackage, error) {
	var fields map[string]json.RawMessage
	var p CreditPackage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return p, fmt.Errorf("workbuddy: invalid credit package")
	}
	var err error
	p.Remaining, err = observedNumber(fields, "CycleCapacityRemainPrecise", "CycleCapacityRemain", "CapacityRemainPrecise", "CapacityRemain")
	if err != nil {
		return p, err
	}
	p.Used, err = observedNumber(fields, "CycleCapacityUsedPrecise", "CycleCapacityUsed", "CapacityUsedPrecise", "CapacityUsed")
	if err != nil {
		return p, err
	}
	p.Capacity, err = observedNumber(fields, "CycleCapacitySizePrecise", "CycleCapacitySize", "CapacitySizePrecise", "CapacitySize")
	if err != nil {
		return p, err
	}
	for key, target := range map[string]*string{"AccountId": &p.ID, "PackageCode": &p.Code, "CycleStartTime": &p.CycleStart, "CycleEndTime": &p.CycleEnd} {
		if value, ok := fields[key]; ok && string(value) != "null" {
			if err = json.Unmarshal(value, target); err != nil {
				return p, fmt.Errorf("workbuddy: invalid package metadata %s", key)
			}
		}
	}
	return p, nil
}

type resourcePage struct {
	Accounts   *[]json.RawMessage `json:"Accounts"`
	TotalCount *int               `json:"TotalCount"`
}

func decodeResourcePage(raw json.RawMessage, nested bool) (resourcePage, error) {
	var result resourcePage
	if nested {
		var data struct {
			Response struct {
				Data json.RawMessage `json:"Data"`
			} `json:"Response"`
		}
		if err := json.Unmarshal(raw, &data); err != nil {
			return result, fmt.Errorf("workbuddy: invalid resource response")
		}
		raw = data.Response.Data
	}
	if err := json.Unmarshal(raw, &result); err != nil || result.Accounts == nil || result.TotalCount != nil && *result.TotalCount < 0 {
		return result, fmt.Errorf("workbuddy: missing or invalid resource accounts")
	}
	return result, nil
}

func sumObserved(packages []CreditPackage, selectValue func(CreditPackage) *float64) *float64 {
	total := 0.0
	for _, p := range packages {
		v := selectValue(p)
		if v == nil {
			return nil
		}
		total += *v
		if !validCredit(total) {
			return nil
		}
	}
	return &total
}

// FetchBalance follows every reported page before publishing a total. Partial
// reads and duplicate package IDs are errors, not a lower balance observation.
func (a *ControlClient) FetchBalance(ctx context.Context) (BalanceSnapshot, error) {
	var snapshot BalanceSnapshot
	c, err := a.Load()
	if err != nil {
		return snapshot, err
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	var last ControlResult
	if c.EnterpriseID != "" {
		last, err = a.Call(ctx, ControlRequest{Operation: ControlEnterpriseUsage})
		if err != nil {
			return snapshot, err
		}
		var fields map[string]json.RawMessage
		if err = json.Unmarshal(last.Data, &fields); err != nil || fields == nil {
			return snapshot, fmt.Errorf("workbuddy: invalid enterprise balance")
		}
		p := CreditPackage{Code: "enterprise"}
		p.Used, err = observedNumber(fields, "credit")
		if err != nil {
			return snapshot, err
		}
		p.Capacity, err = observedNumber(fields, "limitNum")
		if err != nil {
			return snapshot, err
		}
		// The source exposes usage and a cycle limit, not an observed remainder.
		// Leave Remaining unknown instead of fabricating a reported balance.
		for key, target := range map[string]*string{"cycleStartTime": &p.CycleStart, "cycleEndTime": &p.CycleEnd} {
			if raw, ok := fields[key]; ok && string(raw) != "null" {
				if err = json.Unmarshal(raw, target); err != nil {
					return snapshot, fmt.Errorf("workbuddy: invalid enterprise cycle")
				}
			}
		}
		snapshot.Packages = []CreditPackage{p}
		snapshot.Enterprise = true
	} else {
		seen := make(map[string]bool)
		total := -1
		complete := false
		for page := 1; page <= 100; page++ {
			last, err = a.Call(ctx, ControlRequest{Operation: ControlResources, Page: page})
			if err != nil {
				return snapshot, err
			}
			data, errPage := decodeResourcePage(last.Data, true)
			if errPage != nil {
				return snapshot, errPage
			}
			if data.TotalCount != nil {
				if total >= 0 && total != *data.TotalCount {
					return snapshot, fmt.Errorf("workbuddy: balance pagination changed during observation")
				}
				total = *data.TotalCount
			}
			for _, raw := range *data.Accounts {
				p, errPackage := decodeCreditPackage(raw)
				if errPackage != nil {
					return snapshot, errPackage
				}
				if p.ID != "" {
					if seen[p.ID] {
						return snapshot, fmt.Errorf("workbuddy: duplicate package in balance pages")
					}
					seen[p.ID] = true
				}
				snapshot.Packages = append(snapshot.Packages, p)
			}
			count := len(snapshot.Packages)
			if total >= 0 && count > total {
				return snapshot, fmt.Errorf("workbuddy: balance exceeds reported package count")
			}
			if total >= 0 && count == total || total < 0 && len(*data.Accounts) < 100 {
				complete = true
				break
			}
			if len(*data.Accounts) == 0 {
				return snapshot, fmt.Errorf("workbuddy: incomplete balance pages")
			}
		}
		if !complete {
			return snapshot, fmt.Errorf("workbuddy: balance page limit exceeded")
		}
	}
	snapshot.ObservedAt = now()
	snapshot.Remaining = sumObserved(snapshot.Packages, func(p CreditPackage) *float64 { return p.Remaining })
	snapshot.Used = sumObserved(snapshot.Packages, func(p CreditPackage) *float64 { return p.Used })
	snapshot.Capacity = sumObserved(snapshot.Packages, func(p CreditPackage) *float64 { return p.Capacity })
	if snapshot.Remaining != nil {
		if err = a.Governor.ObserveBalance(last.Credential, last.Attempt, *snapshot.Remaining); err != nil {
			return snapshot, err
		}
	} else if err = a.Governor.ForgetBalance(last.Credential, last.Attempt); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}
