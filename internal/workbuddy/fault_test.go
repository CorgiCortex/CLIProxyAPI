package workbuddy

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestFaultScopeAndResetClassification(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		kind   FaultKind
		soft   bool
		reset  string
	}{
		{"free_cap_en", 429, `{"code":6004,"msg":"your usage will reset at 2026-10-02 16:00:34 UTC+8"}`, FaultModelCap, false, "2026-10-02T08:00:34Z"},
		{"free_cap_cn", 429, `{"code":"6004","msg":"将在 2026-10-02T16:00:34 UTC+8 重置"}`, FaultModelCap, false, "2026-10-02T08:00:34Z"},
		{"escaped_cn", 429, `{"code":6004,"msg":"\u5c06\u5728 2026-10-02 16:00:34 UTC+05:30"}`, FaultModelCap, false, "2026-10-02T10:30:34Z"},
		{"negative_half_hour", 429, `{"code":6004,"msg":"reset at 2026-10-02 16:00:34 UTC-00:30"}`, FaultModelCap, false, "2026-10-02T16:30:34Z"},
		{"soft_clock_is_not_cap", 429, `{"code":14003,"msg":"your account usage will reset at 2026-10-02 16:00:34 UTC+8"}`, FaultModelRate, false, "2026-10-02T08:00:34Z"},
		{"cap_without_reset", 429, `{"code":6004}`, FaultModelRate, false, ""},
		{"account_phrase", 429, `{"msg":"your account is rate limited"}`, FaultAccountRate, false, ""},
		{"account_metadata_is_not_scope", 429, `{"accountId":"u","credentialId":"x","msg":"too many requests"}`, FaultModelRate, true, ""},
		{"account_cn", 429, `{"msg":"\u8d26\u53f7\u9650\u6d41"}`, FaultAccountRate, false, ""},
		{"soft_text", 429, "usage exceeds frequency limit", FaultModelRate, true, ""},
		{"unknown_shape", 429, "busy", FaultModelRate, false, ""},
		{"restricted_code", 403, `{"code":11140,"msg":"request illegal"}`, FaultRestricted, false, ""},
		{"restricted_phrase", 403, `{"msg":"Your account has been restricted due to unusual activity"}`, FaultRestricted, false, ""},
		{"request_id_is_not_code", 403, `{"requestId":"0011140abc","msg":"content rejected"}`, FaultContent, false, ""},
		{"auth", 401, "", FaultAuth, false, ""},
		{"credits", 402, "", FaultBalance, false, ""},
		{"retired", 500, `{"code":11102}`, FaultModelRetired, false, ""},
		{"provider_unavailable", 503, `{"code":11134}`, FaultProviderUnavailable, false, ""},
		{"entitlement", 400, `{"code":11158}`, FaultEntitlement, false, ""},
		{"gateway", 502, "", FaultGateway, false, ""},
		{"hard", 550, "", FaultHard, false, ""},
		{"request", 400, "unknown", FaultRequest, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyHTTP(tc.status, []byte(tc.body))
			if got.Kind != tc.kind || got.Soft != tc.soft {
				t.Fatalf("got kind=%s soft=%t", got.Kind, got.Soft)
			}
			if tc.reset == "" {
				if !got.ResetAt.IsZero() {
					t.Fatal("invented reset time")
				}
			} else if got.ResetAt.Format(time.RFC3339) != tc.reset {
				t.Fatalf("reset=%s want %s", got.ResetAt, tc.reset)
			}
		})
	}
}

func TestTransportFaultDoesNotBlameCredentialForLocalFailures(t *testing.T) {
	for _, tc := range []struct {
		err  error
		kind FaultKind
	}{
		{fmt.Errorf("wrapped: %w", context.Canceled), FaultCanceled},
		{fmt.Errorf("wrapped: %w", &net.DNSError{Err: "no such host", Name: "fixture.invalid"}), FaultLocalNetwork},
		{&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ENETUNREACH}, FaultLocalNetwork},
		{x509.UnknownAuthorityError{}, FaultTLS},
		{io.ErrUnexpectedEOF, FaultConnection},
		{fmt.Errorf("fixture unknown error"), FaultUnknown},
	} {
		if got := ClassifyTransport(tc.err); got.Kind != tc.kind {
			t.Fatalf("kind=%s want %s", got.Kind, tc.kind)
		}
	}
}
