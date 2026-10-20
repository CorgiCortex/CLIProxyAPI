package workbuddy

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIdentityRealmProductContracts(t *testing.T) {
	for _, realm := range []Realm{International, China} {
		for _, product := range []Product{Desktop, VSCode, CLI} {
			t.Run(string(realm)+"/"+string(product), func(t *testing.T) {
				credential := testCredential()
				credential.Realm, credential.Product, credential.DeviceToken = realm, product, "real-fixture-device-token"
				now := time.Unix(1800000000, 0)
				headers, _, err := IdentityHeaders(credential, DefaultVersions(), "session", "turn", "model", now)
				if err != nil {
					t.Fatal(err)
				}
				_, domain, errEndpoint := Endpoint(realm, product)
				if errEndpoint != nil {
					t.Fatal(errEndpoint)
				}
				if headers.Get("X-Domain") != domain || headers.Get("X-Machine-ID") != "" || headers.Get("X-Session-ID") != "" {
					t.Fatal("wrong chat domain or billing identifiers leaked into chat")
				}
				if headers.Get("X-User-Id") != credential.UID || headers.Get("Authorization") != "Bearer "+credential.AccessToken {
					t.Fatal("wrong account identity")
				}
				if (realm == China && product != CLI) != (headers.Get("X-Device-Token") != "") {
					t.Fatal("device token sent to wrong client or region")
				}
				b3 := strings.Split(headers.Get("b3"), "-")
				if b3[0] != headers.Get("X-Trace-ID") || b3[0] != headers.Get("X-B3-TraceId") || b3[1] != headers.Get("X-B3-SpanId") || b3[2] != "1" {
					t.Fatal("trace identifiers disagree")
				}
				if product == Desktop {
					if len(b3) != 3 || headers.Get("X-Root-Request-ID") == "" {
						t.Fatal("invalid desktop trace/request identifiers")
					}
					if headers.Get("X-Conversation-ID") != ConversationID(credential.UID, "session") {
						t.Fatal("desktop lost the account-scoped conversation identity")
					}
				} else if len(b3) != 4 || b3[3] != headers.Get("X-B3-ParentSpanId") {
					t.Fatal("invalid child trace")
				}
				if product == VSCode {
					if headers.Get("traceparent") != "" || headers.Get("X-Root-Request-ID") != "" || headers.Get("X-Model-ID") != "model" ||
						headers.Get("X-Request-ID") != headers.Get("X-Conversation-Request-ID") || len(headers.Get("X-Conversation-ID")) != 32 {
						t.Fatal("invalid VSCode header contract")
					}
					if (realm == China) != (headers.Get("X-Private-Data") == "") {
						t.Fatal("incorrect VSCode privacy default")
					}
				} else if headers.Get("X-Request-ID") != headers.Get("X-Conversation-Message-ID") {
					t.Fatal("message/request identifiers disagree")
				}
				if product == CLI {
					for _, absent := range []string{"Origin", "Referer", "X-Requested-With", "X-CodeBuddy-Request", "Accept-Language", "X-Device-Token"} {
						if headers.Get(absent) != "" {
							t.Fatalf("CLI sent browser header %s", absent)
						}
					}
					if headers.Get("X-Conversation-ID") != ConversationID(credential.UID, "session") ||
						headers.Get("X-Conversation-Request-ID") != "turn" || headers.Get("X-Root-Request-ID") != "turn" ||
						headers.Get("User-Agent") != "CLI/2.168.2 CodeBuddy/2.168.2" || headers.Get("X-Private-Data") != "false" {
						t.Fatal("invalid CLI identity contract")
					}
				}
				trace, errTrace := uuid.Parse(headers.Get("X-Trace-ID"))
				if errTrace != nil || trace.Version() != 7 {
					t.Fatal("trace ID is not UUIDv7")
				}
			})
		}
	}
}

func TestIdentityAccountIsolationPrivacyAndFraming(t *testing.T) {
	credential := testCredential()
	credential.Product, credential.Realm = VSCode, China
	credential.PrivateData = "false"
	h, _, err := IdentityHeaders(credential, DefaultVersions(), "one-turn", "", "model", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if h.Get("X-Device-Token-Error") != "sdk_not_initialized" || h.Get("X-Private-Data") != "false" {
		t.Fatal("explicit privacy/device failure contract lost")
	}
	first, errFirst := BillingHeaders(credential, DefaultVersions())
	if errFirst != nil {
		t.Fatal(errFirst)
	}
	credential.UID = "other-user"
	second, errSecond := BillingHeaders(credential, DefaultVersions())
	if errSecond != nil {
		t.Fatal(errSecond)
	}
	if first.Get("X-Machine-ID") == second.Get("X-Machine-ID") || first.Get("X-Session-ID") == second.Get("X-Session-ID") ||
		ConversationID("fixture-user", "session") == ConversationID("other-user", "session") {
		t.Fatal("identity correlates different accounts")
	}
	payload := []byte(`{"messages":[{"role":"user","content":"exact business payload"}],"metadata":{"literal":true}}`)
	for _, product := range []Product{Desktop, CLI, VSCode} {
		encoded, encoding, errFrame := Frame(product, payload)
		if errFrame != nil {
			t.Fatal(errFrame)
		}
		if product != Desktop {
			if encoding != "gzip" {
				t.Fatal("missing gzip encoding")
			}
			reader, errReader := gzip.NewReader(bytes.NewReader(encoded))
			if errReader != nil {
				t.Fatal(errReader)
			}
			encoded, err = io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if errClose := reader.Close(); errClose != nil {
				t.Fatal(errClose)
			}
		}
		if !bytes.Equal(encoded, payload) {
			t.Fatal("transport framing changed business semantics")
		}
	}
}
