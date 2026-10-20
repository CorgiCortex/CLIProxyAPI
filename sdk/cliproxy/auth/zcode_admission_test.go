package auth

import (
	"context"
	"net/http"
	"testing"
)

// This fake avoids importing an executor helper back into its auth dependency.
type zcodeAdmissionError struct{}

func (zcodeAdmissionError) Error() string              { return "local account busy" }
func (zcodeAdmissionError) StatusCode() int            { return http.StatusTooManyRequests }
func (zcodeAdmissionError) IsRequestScoped() bool      { return true }
func (zcodeAdmissionError) RetryOtherCredential() bool { return true }

func TestZCodeAdmissionRotatesWithoutCoolingAccount(t *testing.T) {
	err := zcodeAdmissionError{}
	if isRequestInvalidError(err) {
		t.Fatal("admission pressure stopped account rotation")
	}
	result := resultErrorFromError(err)
	if !shouldSkipCredentialCooldown(result) {
		t.Fatal("admission pressure penalized credential")
	}
	auth := &Auth{ID: "zcode-admission", Provider: "zcode", Status: StatusActive}
	manager := NewManager(nil, nil, nil)
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	manager.MarkResult(context.Background(), Result{AuthID: auth.ID, Provider: "zcode", Model: "model", Error: result})
	current, ok := manager.GetByID(auth.ID)
	if !ok || current.Unavailable || !current.NextRetryAfter.IsZero() || current.Quota.Exceeded {
		t.Fatal("local pressure altered account availability")
	}
	if state := current.ModelStates["model"]; state != nil && (state.Unavailable || state.Quota.Exceeded || !state.NextRetryAfter.IsZero()) {
		t.Fatal("local pressure altered model availability")
	}
}
