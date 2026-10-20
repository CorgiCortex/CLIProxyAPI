package workbuddy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"
)

// ControlOperation is a closed set: background work cannot use this client as
// an arbitrary authenticated HTTP tunnel.
type ControlOperation string

const (
	ControlModels          ControlOperation = "models"
	ControlResources       ControlOperation = "resources"
	ControlResourceSummary ControlOperation = "resource_summary"
	ControlFreePackages    ControlOperation = "free_packages"
	ControlPaidPackages    ControlOperation = "paid_packages"
	ControlEnterpriseUsage ControlOperation = "enterprise_usage"
	ControlCheckin         ControlOperation = "checkin"
	ControlCheckinStatus   ControlOperation = "checkin_status"
	ControlGrowthTasks     ControlOperation = "growth_tasks"
	ControlGrowthAccept    ControlOperation = "growth_accept"
	ControlGrowthClaim     ControlOperation = "growth_claim"
)

type ControlRequest struct {
	Operation    ControlOperation
	Page         int
	PackageCodes []string
	TaskCodes    []string
	TaskCode     string
}
type ControlResult struct {
	Data        json.RawMessage
	AlreadyDone bool
	Attempt     Attempt
	Credential  Credential
}
type controlSpec struct {
	method, path            string
	billing, observeBalance bool
	body                    any
}

var taskCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func (r ControlRequest) spec(c Credential, now time.Time) (controlSpec, error) {
	// These closed-set endpoints inspect metadata/balances or acquire rewards;
	// none performs paid inference. Credit parking must not prevent recovery.
	// The governor still checks every account, region and endpoint cooldown.
	s := controlSpec{method: http.MethodPost, body: struct{}{}, observeBalance: true}
	page := r.Page
	if page == 0 {
		page = 1
	}
	if page < 1 || page > 10000 {
		return s, fmt.Errorf("workbuddy: invalid resource page")
	}
	switch r.Operation {
	case ControlModels:
		s.method, s.path, s.body = http.MethodGet, "/v3/config", nil
	case ControlResources:
		s.billing, s.observeBalance, s.path = true, true, "/v2/billing/meter/get-user-resource"
		s.body = map[string]any{"PageNumber": page, "PageSize": 100, "ProductCode": "p_tcaca", "Status": []int{0, 3}, "PackageEndTimeRangeBegin": now.In(time.FixedZone("CST", 8*3600)).Format("2006-01-02 15:04:05"), "PackageEndTimeRangeEnd": "2036-01-01 00:00:00"}
	case ControlResourceSummary:
		s.billing, s.observeBalance, s.path = true, true, "/billing/meter/get-user-resource-summary"
	case ControlFreePackages, ControlPaidPackages:
		s.billing, s.observeBalance, s.path = true, true, "/billing/meter/get-user-resource-free-packages"
		if len(r.PackageCodes) == 0 || len(r.PackageCodes) > 200 {
			return s, fmt.Errorf("workbuddy: invalid package selection")
		}
		s.body = map[string]any{"PageNumber": page, "PageSize": 200, "PackageCodes": r.PackageCodes, "Status": []int{0}}
		if r.Operation == ControlPaidPackages {
			s.path = "/billing/meter/get-user-resource-paid-packages"
			s.body = map[string]any{"PageNumber": page, "PageSize": 200, "PackageCodes": r.PackageCodes, "Status": []int{0, 3}, "NeedRenewInfo": true}
		}
	case ControlEnterpriseUsage:
		if c.EnterpriseID == "" {
			return s, fmt.Errorf("workbuddy: enterprise usage requires an enterprise credential")
		}
		s.billing, s.observeBalance, s.path = true, true, "/billing/meter/get-enterprise-user-usage"
	case ControlCheckin, ControlCheckinStatus, ControlGrowthTasks, ControlGrowthAccept, ControlGrowthClaim:
		if c.Realm != China || c.EnterpriseID != "" {
			return s, fmt.Errorf("workbuddy: activity requires a personal CN credential")
		}
		switch r.Operation {
		case ControlCheckin:
			s.billing, s.path = true, "/v2/billing/meter/daily-checkin"
			// Acquiring credits must work while the account is parked for empty credit.
			s.observeBalance = true
		case ControlCheckinStatus:
			s.path, s.observeBalance = "/v2/billing/meter/checkin-activity-status", true
		case ControlGrowthTasks:
			s.method, s.path, s.body = http.MethodGet, "/v2/activity/growth/tasks", nil
		case ControlGrowthAccept:
			if len(r.TaskCodes) == 0 || len(r.TaskCodes) > 20 {
				return s, fmt.Errorf("workbuddy: growth accept requires 1 to 20 task codes")
			}
			for _, code := range r.TaskCodes {
				if !taskCodePattern.MatchString(code) {
					return s, fmt.Errorf("workbuddy: invalid task code")
				}
			}
			s.path, s.body = "/v2/activity/growth/tasks/accept", map[string]any{"task_codes": r.TaskCodes}
		case ControlGrowthClaim:
			if !taskCodePattern.MatchString(r.TaskCode) {
				return s, fmt.Errorf("workbuddy: invalid task code")
			}
			s.path = "/activity/growth/tasks/" + r.TaskCode + "/claim"
		}
	default:
		return s, fmt.Errorf("workbuddy: unsupported control operation")
	}
	return s, nil
}

// ControlClient shares chat's transports, limiter and governor. Load must read
// the authoritative credential; Refresh must persist rotation before returning.
// No upstream deadline is introduced and no mutating request is replayed after
// a connection failure with an uncertain result.
type ControlClient struct {
	Governor        *Governor
	Transports      *Transports
	Limiter         *Limiter
	Versions        IdentityVersions
	ProxyURL        string
	BaseURL         string // Offline fixture seam; never loaded from credential metadata.
	QueueWait       time.Duration
	Now             func() time.Time
	Load            func() (Credential, error)
	Refresh         func(context.Context) (Credential, error)
	MinimumInterval time.Duration
	Wait            func(context.Context, time.Duration) error
	paceMu          sync.Mutex
	nextCall        time.Time
}

func (a *ControlClient) Call(ctx context.Context, request ControlRequest) (ControlResult, error) {
	var result ControlResult
	if a.Governor == nil || a.Transports == nil || a.Limiter == nil || a.Load == nil {
		return result, fmt.Errorf("workbuddy: incomplete control client")
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	if a.MinimumInterval > 0 {
		a.paceMu.Lock()
		start := now()
		if a.nextCall.After(start) {
			start = a.nextCall
		}
		delay := start.Sub(now())
		a.nextCall = start.Add(a.MinimumInterval)
		a.paceMu.Unlock()
		wait := a.Wait
		if wait == nil {
			wait = waitBeforeConnect
		}
		if err := wait(ctx, delay); err != nil {
			return result, err
		}
	}
	c, err := a.Load()
	if err != nil {
		return result, err
	}
	if _, err = request.spec(c, now()); err != nil {
		return result, err
	}
	wait := a.QueueWait
	if wait == 0 {
		wait = 30 * time.Second
	}
	release, err := a.Limiter.Acquire(ctx, "background:"+RiskAccountKey(c), wait)
	if err != nil {
		return result, err
	}
	defer release()
	refreshed := false
	for {
		c, err = a.Load()
		if err != nil {
			return result, err
		}
		spec, errSpec := request.spec(c, now())
		if errSpec != nil {
			return result, errSpec
		}
		scope := "control:" + string(request.Operation)
		gate, attempt := a.Governor.Check(c, scope, false, spec.observeBalance)
		if gate.Reason == "credential_expired" && !refreshed && a.Refresh != nil {
			refreshed = true
			if _, err = a.Refresh(ctx); err != nil {
				return result, err
			}
			continue
		}
		if !gate.Allowed() {
			return result, &DispatchError{Reason: gate.Reason, Stop: gate.Stop, Until: gate.Until, Status: 429}
		}
		// Proactive acquisition is allowed only after restriction/cooldown checks.
		if c.Expiring(now()) && !refreshed && a.Refresh != nil {
			refreshed = true
			if _, err = a.Refresh(ctx); err != nil {
				return result, err
			}
			continue
		}
		base, _, errBase := Endpoint(c.Realm, Desktop)
		if errBase != nil {
			return result, errBase
		}
		headers, errHeaders := BillingHeaders(c, a.Versions)
		var order []string
		if !spec.billing {
			turn, errTurn := NewTurnID()
			if errTurn != nil {
				return result, errTurn
			}
			// These control endpoints belong to the desktop API regardless of the
			// product selected for inference.
			desktop := c
			desktop.Product = Desktop
			headers, order, errHeaders = IdentityHeaders(desktop, a.Versions, turn, turn, "", now())
		} else {
			base = "https://www.workbuddy.ai"
			if c.Realm == China {
				base = "https://www.codebuddy.cn"
			}
			headers.Set("X-Client-Platform", "web")
		}
		if errHeaders != nil {
			return result, errHeaders
		}
		if a.BaseURL != "" {
			if err = validateBaseURL(a.BaseURL); err != nil {
				return result, err
			}
			base = a.BaseURL
		}
		proxy := a.ProxyURL
		if c.ProxyURL != "" {
			proxy = c.ProxyURL
		}
		client, errClient := a.Transports.Client(c, base, proxy, order)
		if errClient != nil {
			return result, errClient
		}
		var body []byte
		if spec.body != nil {
			body, err = json.Marshal(spec.body)
			if err != nil {
				return result, err
			}
		}
		req, errReq := http.NewRequestWithContext(ctx, spec.method, base+spec.path, bytes.NewReader(body))
		if errReq != nil {
			return result, errReq
		}
		req.Header = headers
		response, errDo := client.Do(req)
		if errDo != nil {
			return result, a.failure(c, scope, ClassifyTransport(errDo))
		}
		raw, errRead := io.ReadAll(io.LimitReader(response.Body, 4<<20+1))
		errClose := response.Body.Close()
		if errRead != nil {
			return result, a.failure(c, scope, ClassifyTransport(errRead))
		}
		if errClose != nil {
			return result, a.failure(c, scope, ClassifyTransport(errClose))
		}
		if len(raw) > 4<<20 {
			return result, a.failure(c, scope, Fault{Kind: FaultUnknown, Status: 502})
		}
		var envelope authEnvelope
		errJSON := json.Unmarshal(raw, &envelope)
		already := request.Operation == ControlCheckin && (response.StatusCode == 200 || response.StatusCode == 400) && errJSON == nil && envelope.Code != nil && *envelope.Code == 10001
		success := response.StatusCode >= 200 && response.StatusCode < 300 && errJSON == nil && envelope.Code != nil && *envelope.Code == 0
		if success || already {
			return ControlResult{Data: envelope.Data, AlreadyDone: already, Attempt: attempt, Credential: c}, nil
		}
		status := response.StatusCode
		if status >= 200 && status < 300 {
			status = 400
			if envelope.Code != nil {
				switch *envelope.Code {
				case 401, 402, 403, 429:
					status = *envelope.Code
				case 11140:
					status = 403
				case 6004, 14003:
					status = 429
				}
			}
			if errJSON != nil || envelope.Code == nil {
				return result, a.failure(c, scope, Fault{Kind: FaultUnknown, Status: 502})
			}
		}
		fault := ClassifyHTTP(status, raw)
		if fault.Kind == FaultAuth && !refreshed && a.Refresh != nil {
			refreshed = true
			if _, err = a.Refresh(ctx); err == nil {
				continue
			}
		}
		return result, a.failure(c, scope, fault)
	}
}
func (a *ControlClient) failure(c Credential, scope string, fault Fault) error {
	gate, err := a.Governor.RecordFailure(c, scope, fault, FailureOptions{})
	if err != nil {
		return err
	}
	failure := ErrorForFault(fault)
	failure.Stop, failure.Until = gate.Stop, gate.Until
	return failure
}
