package workbuddy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type FaultKind string

const (
	FaultAuth                FaultKind = "authentication"
	FaultBalance             FaultKind = "balance"
	FaultRestricted          FaultKind = "account_restricted"
	FaultContent             FaultKind = "content_rejected"
	FaultAccountRate         FaultKind = "account_rate"
	FaultModelRate           FaultKind = "model_rate"
	FaultModelCap            FaultKind = "model_cap"
	FaultModelRetired        FaultKind = "model_retired"
	FaultProviderUnavailable FaultKind = "provider_unavailable"
	FaultEntitlement         FaultKind = "model_entitlement"
	FaultGateway             FaultKind = "gateway"
	FaultHard                FaultKind = "hard_failure"
	FaultUnknown             FaultKind = "unknown_failure"
	FaultRequest             FaultKind = "request_rejected"
	FaultLocalNetwork        FaultKind = "local_network"
	FaultTLS                 FaultKind = "tls_verification"
	FaultCanceled            FaultKind = "canceled"
	FaultConnection          FaultKind = "connection"
)

// Fault contains only classification evidence. Upstream bodies can contain
// credentials or user content and must not enter persisted risk state.
type Fault struct {
	Kind    FaultKind
	Status  int
	Code    int
	ResetAt time.Time
	Soft    bool
}

var (
	codePattern         = regexp.MustCompile(`"code"\s*:\s*"?([0-9]+)"?`)
	resetPhrasePattern  = regexp.MustCompile(`(?:reset at|将在)\s*(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})`)
	resetClockPattern   = regexp.MustCompile(`(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s*UTC[+-]\d{1,2}`)
	offsetPattern       = regexp.MustCompile(`UTC([+-])(\d{1,2})(?::?(\d{2}))?`)
	accountScopePattern = regexp.MustCompile(`(?i)\b(?:account-level|account level|account-wide|account scope|account quota|account rate limit|account limit|per account|per-account|this account|your account|the account|an account|credential-level|credential level|credential scope|credential limit|per credential|this credential|the credential|your credential)\b`)
)

// faultText also exposes JSON-escaped localized display messages to the
// classifier. It never substitutes a default meaning for unknown responses.
func faultText(raw []byte) string {
	text := string(raw)
	var payload any
	if json.Unmarshal(raw, &payload) != nil {
		return text
	}
	var values []string
	var collect func(any, int)
	collect = func(value any, depth int) {
		if depth > 4 {
			return
		}
		switch v := value.(type) {
		case string:
			values = append(values, v)
		case map[string]any:
			for _, child := range v {
				collect(child, depth+1)
			}
		case []any:
			for _, child := range v {
				collect(child, depth+1)
			}
		}
	}
	collect(payload, 0)
	return text + "\n" + strings.Join(values, "\n")
}

func ParseResetTime(raw []byte) time.Time {
	text := faultText(raw)
	match := resetPhrasePattern.FindStringSubmatch(text)
	if len(match) == 0 {
		match = resetClockPattern.FindStringSubmatch(text)
	}
	if len(match) == 0 {
		return time.Time{}
	}
	offset := 0
	if zone := offsetPattern.FindStringSubmatch(text); len(zone) > 0 {
		hours, errHours := strconv.Atoi(zone[2])
		minutes := 0
		if zone[3] != "" {
			var errMinutes error
			minutes, errMinutes = strconv.Atoi(zone[3])
			if errMinutes != nil {
				return time.Time{}
			}
		}
		if errHours != nil || hours > 23 || minutes > 59 {
			return time.Time{}
		}
		offset = hours*3600 + minutes*60
		if zone[1] == "-" {
			offset = -offset
		}
	}
	stamp, errStamp := time.ParseInLocation("2006-01-02 15:04:05", strings.ReplaceAll(match[1], "T", " "), time.FixedZone("upstream", offset))
	if errStamp != nil {
		return time.Time{}
	}
	return stamp.UTC()
}

func ClassifyHTTP(status int, raw []byte) Fault {
	fault := Fault{Status: status}
	text := strings.ToLower(faultText(raw))
	// Capture the explicit code field, never a coincidental request ID.
	if match := codePattern.FindSubmatch(raw); len(match) > 0 {
		fault.Code, _ = strconv.Atoi(string(match[1]))
	}
	switch status {
	case 401:
		fault.Kind = FaultAuth
	case 402:
		fault.Kind = FaultBalance
	case 403:
		fault.Kind = FaultContent
		if fault.Code == 11140 || strings.Contains(text, "unusual activity") || strings.Contains(text, "账号存在异常行为") || strings.Contains(text, "已被限制") {
			fault.Kind = FaultRestricted
		}
	case 429:
		fault.Kind = FaultModelRate
		fault.ResetAt = ParseResetTime(raw)
		if !fault.ResetAt.IsZero() {
			if fault.Code == 6004 {
				fault.Kind = FaultModelCap
			}
			return fault
		}
		accountScoped := accountScopePattern.MatchString(text)
		for _, phrase := range []string{"账号级", "账户级", "该账号", "此账号", "该账户", "此账户", "账号限流", "账户限流", "凭证级", "该凭证"} {
			accountScoped = accountScoped || strings.Contains(text, phrase)
		}
		if accountScoped {
			fault.Kind = FaultAccountRate
			return fault
		}
		fault.Soft = fault.Code == 14003 || strings.Contains(text, "usage exceeds frequency limit") ||
			strings.Contains(text, "too many requests") || strings.Contains(text, "请求过于频繁")
	default:
		if status == 400 || status >= 500 {
			switch fault.Code {
			case 11102:
				fault.Kind = FaultModelRetired
				return fault
			case 11134:
				fault.Kind = FaultProviderUnavailable
				return fault
			case 11158:
				fault.Kind = FaultEntitlement
				return fault
			}
		}
		switch {
		case status == 502 || status == 503 || status == 504:
			fault.Kind = FaultGateway
		case status >= 500:
			fault.Kind = FaultHard
		default:
			fault.Kind = FaultRequest
		}
	}
	return fault
}

func ClassifyTransport(err error) Fault {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return Fault{Kind: FaultCanceled}
	}
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalidCertificate x509.CertificateInvalidError
	var verification *tls.CertificateVerificationError
	if errors.As(err, &unknownAuthority) || errors.As(err, &hostname) || errors.As(err, &invalidCertificate) || errors.As(err, &verification) {
		return Fault{Kind: FaultTLS}
	}
	var dns *net.DNSError
	if errors.As(err, &dns) || errors.Is(err, syscall.ENETDOWN) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return Fault{Kind: FaultLocalNetwork}
	}
	var operation *net.OpError
	if errors.As(err, &operation) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return Fault{Kind: FaultConnection}
	}
	return Fault{Kind: FaultUnknown}
}
