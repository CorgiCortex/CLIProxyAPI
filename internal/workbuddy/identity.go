package workbuddy

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
)

// IdentityVersions is versioned as one profile so headers never mix clients.
type IdentityVersions struct {
	DesktopIntl string
	DesktopCN   string
	CLI         string
	VSCode      string
	Extension   string
	Node        string
}

func DefaultVersions() IdentityVersions {
	return IdentityVersions{"5.8.4", "5.5.6", "2.168.2", "1.119.0", "4.12.39997873", "v22.21.1"}
}

func Endpoint(realm Realm, product Product) (base, domain string, err error) {
	if product != Desktop && product != VSCode && product != CLI {
		return "", "", fmt.Errorf("workbuddy: invalid product")
	}
	switch realm {
	case International:
		return "https://www.workbuddy.ai", "www.workbuddy.ai", nil
	case China:
		if product == VSCode {
			return "https://www.workbuddy.cn", "www.workbuddy.cn", nil
		}
		return "https://copilot.tencent.com", "copilot.tencent.com", nil
	default:
		return "", "", fmt.Errorf("workbuddy: invalid realm")
	}
}

func fixedUUID(digest []byte) string {
	var b uuid.UUID
	copy(b[:], digest[:16])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x0f) | 0xa0
	return b.String()
}

func DeviceID(uid, salt string) string {
	sum := md5.Sum([]byte(salt + ":" + uid))
	return fixedUUID(sum[:])
}

func ConversationID(uid, session string) string {
	if strings.TrimSpace(session) == "" {
		return ""
	}
	session = strings.TrimSpace(session)
	sum := sha256.Sum256([]byte(uid + "|" + session))
	return fixedUUID(sum[:])
}

func NewTurnID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("workbuddy: generate request id: %w", err)
	}
	return hex.EncodeToString(id[:]), nil
}

// IdentityHeaders returns both semantic headers and their wire ordering/casing.
func IdentityHeaders(c Credential, versions IdentityVersions, session, turn, model string, now time.Time) (http.Header, []string, error) {
	if err := c.Validate(); err != nil {
		return nil, nil, err
	}
	_, domain, err := Endpoint(c.Realm, c.Product)
	if err != nil {
		return nil, nil, err
	}
	conversationID, errConversation := uuid.NewV7()
	if errConversation != nil {
		return nil, nil, errConversation
	}
	message, errMessage := NewTurnID()
	if errMessage != nil {
		return nil, nil, errMessage
	}
	if turn == "" || c.Product != CLI {
		var errTurn error
		turn, errTurn = NewTurnID()
		if errTurn != nil {
			return nil, nil, errTurn
		}
	}
	requestTraceID, errTrace := uuid.NewRandom()
	if errTrace != nil {
		return nil, nil, errTrace
	}
	trace, errTrace := NewTurnID()
	if errTrace != nil {
		return nil, nil, errTrace
	}
	var spanID [16]byte
	_, errSpan := rand.Read(spanID[:])
	if errSpan != nil {
		return nil, nil, errSpan
	}
	span, parent := hex.EncodeToString(spanID[:8]), hex.EncodeToString(spanID[8:])
	h := make(http.Header)
	set := func(name, value string) { h.Set(name, value) }
	set("Accept-Encoding", "identity")
	set("Connection", "keep-alive")
	set("Content-Type", "application/json")
	if c.Product == CLI {
		set("Accept", "application/json")
	} else {
		set("Accept", "application/json, text/plain, */*")
		set("X-Requested-With", "XMLHttpRequest")
		origin, language := "https://www.workbuddy.ai", "en-US"
		if c.Realm == China {
			origin, language = "https://www.codebuddy.cn", "zh-CN"
		}
		set("Origin", origin)
		set("Referer", origin+"/")
		set("X-CodeBuddy-Request", "1")
		set("Accept-Language", language)
	}
	set("X-Agent-Intent", "craft")
	if c.Product != VSCode {
		set("X-Agent-Purpose", "conversation")
	}
	if c.Product == CLI {
		set("X-Agent-Runtime", "other")
	}
	set("X-Agent-Type", "main")
	switch c.Product {
	case Desktop:
		version, embedded := versions.DesktopIntl, "2.161.0"
		productName := "workbuddy-ai"
		if c.Realm == China {
			version, embedded, productName = versions.DesktopCN, "2.137.1", "WorkBuddy"
		}
		set("X-IDE-Name", "WorkBuddy")
		set("X-IDE-Type", "WorkBuddy")
		set("X-IDE-Version", version)
		set("X-Private-Data", "true")
		set("User-Agent", "WorkBuddy/"+version+" "+productName+"/"+version+" CLI/"+embedded)
	case VSCode:
		set("X-IDE-Type", "VSCode")
		set("X-IDE-Name", "VSCode")
		set("X-IDE-Version", versions.VSCode)
		set("X-Product-Version", versions.Extension)
		set("X-Env-ID", "production")
		set("User-Agent", "VSCode/"+versions.VSCode+" CodeBuddy/"+versions.Extension)
		set("X-Request-Trace-Id", requestTraceID.String())
		if c.Realm != China {
			set("X-Private-Data", "true")
		}
		if model != "" {
			set("X-Model-ID", model)
			stamp := fmt.Sprintf("%d", now.UnixMilli())
			set("monitor_promptPrepareStartTime", stamp)
			set("monitor_httpSendTime", stamp)
		}
	case CLI:
		set("X-IDE-Type", "CLI")
		set("X-IDE-Name", "CLI")
		set("X-IDE-Version", versions.CLI)
		set("User-Agent", "CLI/"+versions.CLI+" CodeBuddy/"+versions.CLI)
		private := "false"
		if c.EnterpriseID != "" {
			private = "true"
		}
		set("X-Private-Data", private)
		osName, arch := runtime.GOOS, runtime.GOARCH
		switch osName {
		case "linux":
			osName = "Linux"
		case "darwin":
			osName = "MacOS"
		case "windows":
			osName = "Windows"
		}
		if arch == "amd64" {
			arch = "x64"
		}
		if arch == "386" {
			arch = "ia32"
		}
		for _, pair := range [][2]string{
			{"x-stainless-lang", "js"}, {"x-stainless-package-version", "6.25.0"},
			{"x-stainless-os", osName}, {"x-stainless-arch", arch}, {"x-stainless-runtime", "node"},
			{"x-stainless-runtime-version", versions.Node}, {"x-stainless-retry-count", "0"}, {"x-stainless-timeout", "1200"},
		} {
			set(pair[0], pair[1])
		}
	}
	set("X-Product", "SaaS")
	set("X-Domain", domain)
	set("X-User-Id", c.UID)
	set("Authorization", "Bearer "+c.AccessToken)
	conversation := conversationID.String()
	if (c.Product == CLI || c.Product == Desktop) && ConversationID(c.UID, session) != "" {
		conversation = ConversationID(c.UID, session)
	}
	if c.Product == VSCode {
		// The caller's session key is already scoped to one upstream turn.
		// It is hashed with the account ID to avoid linking different accounts.
		if derived := ConversationID(c.UID, session); derived != "" {
			conversation = derived
		}
		conversation = strings.ReplaceAll(conversation, "-", "")
	}
	set("X-Conversation-ID", conversation)
	set("X-Conversation-Request-ID", turn)
	if c.Product != VSCode {
		set("X-Root-Request-ID", turn)
	}
	set("X-Conversation-Message-ID", message)
	requestID := message
	if c.Product == VSCode {
		requestID = turn
	}
	set("X-Request-ID", requestID)
	set("X-Trace-ID", trace)
	if c.Product != VSCode {
		set("traceparent", "00-"+trace+"-"+span+"-01")
	}
	b3 := trace + "-" + span + "-1"
	if c.Product != Desktop {
		set("X-B3-ParentSpanId", parent)
		b3 += "-" + parent
	}
	set("b3", b3)
	set("X-B3-TraceId", trace)
	set("X-B3-SpanId", span)
	set("X-B3-Sampled", "1")
	if c.EnterpriseID != "" {
		set("X-Enterprise-Id", c.EnterpriseID)
		set("X-Tenant-Id", c.EnterpriseID)
	}
	if c.PrivateData == "true" || c.PrivateData == "false" {
		h.Set("X-Private-Data", c.PrivateData)
	}
	if c.Realm == China && c.Product != CLI && c.DeviceToken != "" {
		set("X-Device-Token", c.DeviceToken)
	} else if c.Product == VSCode && c.EnterpriseID == "" {
		set("X-Device-Token-Error", "sdk_not_initialized")
	}
	order := identityHeaderOrder(c.Product)
	return h, order, nil
}

func identityHeaderOrder(product Product) []string {
	// The reference's pooled HTTP/1.1 writer emits framing headers first,
	// followed by the exact insertion order of the selected client profile.
	order := []string{"Accept-Encoding", "Content-Length", "Host", "Content-Type", "Accept"}
	if product != CLI {
		order = append(order, "X-Requested-With", "Origin", "Referer", "X-CodeBuddy-Request", "Accept-Language")
	}
	order = append(order, "X-Agent-Intent")
	if product != VSCode {
		order = append(order, "X-Agent-Purpose")
	}
	if product == CLI {
		order = append(order, "X-Agent-Runtime")
	}
	order = append(order, "X-Agent-Type")
	if product == Desktop {
		order = append(order, "X-IDE-Name", "X-IDE-Type", "X-IDE-Version", "X-Private-Data")
	} else {
		order = append(order, "X-IDE-Type", "X-IDE-Name", "X-IDE-Version")
	}
	if product == VSCode {
		order = append(order, "X-Product-Version", "X-Env-ID")
	}
	order = append(order, "X-Product", "X-Domain", "User-Agent", "X-User-Id", "Authorization")
	if product == VSCode {
		order = append(order, "X-Request-Trace-Id")
	}
	order = append(order, "X-Conversation-ID", "X-Conversation-Request-ID")
	if product != VSCode {
		order = append(order, "X-Root-Request-ID")
	}
	order = append(order, "X-Conversation-Message-ID", "X-Request-ID")
	if product == VSCode {
		order = append(order, "X-Model-ID", "monitor_promptPrepareStartTime", "monitor_httpSendTime", "X-Private-Data")
	}
	if product == CLI {
		order = append(order, "X-Private-Data", "x-stainless-lang", "x-stainless-package-version", "x-stainless-os",
			"x-stainless-arch", "x-stainless-runtime", "x-stainless-runtime-version", "x-stainless-retry-count", "x-stainless-timeout")
	}
	order = append(order, "X-Trace-ID")
	if product != VSCode {
		order = append(order, "traceparent")
	}
	order = append(order, "b3", "X-B3-TraceId")
	if product == VSCode {
		order = append(order, "X-B3-ParentSpanId")
	}
	order = append(order, "X-B3-SpanId", "X-B3-Sampled")
	if product == CLI {
		order = append(order, "X-B3-ParentSpanId")
	}
	return append(order, "X-Enterprise-Id", "X-Tenant-Id", "X-Device-Token", "X-Device-Token-Error", "Content-Encoding", "Connection")
}

func BillingHeaders(c Credential, versions IdentityVersions) (http.Header, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	requestID, errRequest := uuid.NewRandom()
	if errRequest != nil {
		return nil, errRequest
	}
	origin, language, version := "https://www.workbuddy.ai", "en-US", versions.DesktopIntl
	if c.Realm == China {
		origin, language, version = "https://www.codebuddy.cn", "zh-CN", versions.DesktopCN
	}
	h := http.Header{}
	for _, pair := range [][2]string{
		{"Content-Type", "application/json"}, {"Accept", "application/json, text/plain, */*"},
		{"X-Requested-With", "XMLHttpRequest"}, {"User-Agent", "WorkBuddy/" + version},
		{"Origin", origin}, {"Referer", origin + "/"}, {"Authorization", "Bearer " + c.AccessToken},
		{"X-User-Id", c.UID}, {"X-CodeBuddy-Request", "1"}, {"Accept-Language", language},
		{"X-Machine-ID", DeviceID(c.UID, "machine")}, {"X-Session-ID", DeviceID(c.UID, "session")},
		{"X-Request-ID", hex.EncodeToString(requestID[:])},
	} {
		h.Set(pair[0], pair[1])
	}
	domain := c.Domain
	if domain == "" {
		_, domain, _ = Endpoint(c.Realm, Desktop)
	}
	h.Set("X-Domain", domain)
	if c.Realm == China {
		h.Set("X-Product", "SaaS")
	}
	if c.EnterpriseID != "" {
		h.Set("X-Enterprise-Id", c.EnterpriseID)
		h.Set("X-Tenant-Id", c.EnterpriseID)
	} else {
		h.Set("X-No-Enterprise-Id", "1")
	}
	if c.Product != CLI && c.DeviceToken != "" {
		h.Set("X-Device-Token", c.DeviceToken)
	}
	return h, nil
}

// Frame applies transport encoding only, after the final payload configuration.
func Frame(product Product, data []byte) ([]byte, string, error) {
	if product == Desktop {
		return data, "", nil
	}
	if product != CLI && product != VSCode {
		return nil, "", fmt.Errorf("workbuddy: invalid product")
	}
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	if _, err := w.Write(data); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return out.Bytes(), "gzip", nil
}

func IdentityKey(c Credential, proxyURL string) string {
	sum := sha256.Sum256([]byte(string(c.Realm) + "\x00" + c.UID + "\x00" + string(c.Product) + "\x00" + proxyURL))
	return hex.EncodeToString(sum[:])
}
