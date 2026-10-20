package zcode

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSigningHandshakeAndBusinessSignature(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	aesKey, err := deriveSigningKey("secret", "ed25519_priv")
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, gcm.NonceSize())
	encrypted := gcm.Seal(iv, iv, []byte(base64.StdEncoding.EncodeToString(der)), []byte("key"))
	calls := 0
	client := &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Path != "/api/paas/c1f3a7e2/v2/client" || req.Header.Get("Authorization") != "key.secret" {
			t.Fatal("wrong handshake route or auth")
		}
		var body map[string]string
		if errDecode := json.NewDecoder(req.Body).Decode(&body); errDecode != nil {
			t.Fatal(errDecode)
		}
		key, errDerive := deriveSigningKey("secret", "getSignKey_hmac")
		if errDerive != nil {
			t.Fatal(errDerive)
		}
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte("get_sign_key\nkey\n" + body["ts"] + "\n" + body["nonce"]))
		if body["sig"] != base64.StdEncoding.EncodeToString(mac.Sum(nil)) || body["apiKey"] != "key.secret" {
			t.Fatal("invalid handshake HMAC")
		}
		data, errMarshal := json.Marshal(map[string]any{"code": 200, "data": map[string]string{"privateCipher": base64.StdEncoding.EncodeToString(encrypted)}})
		if errMarshal != nil {
			t.Fatal(errMarshal)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(data)))}, nil
	})}
	signer := NewSigner()
	signer.now = func() time.Time { return time.Unix(1234, 0) }
	for i := 0; i < 2; i++ {
		req, errRequest := http.NewRequest("POST", "https://api.z.ai/api/anthropic/v1/messages", nil)
		if errRequest != nil {
			t.Fatal(errRequest)
		}
		if errSign := signer.Sign(context.Background(), client, req, "account", "key.secret", "3.16.2", "session"); errSign != nil {
			t.Fatal(errSign)
		}
		h := req.Header
		signature, errDecode := base64.StdEncoding.DecodeString(h.Get("X-Client-Sig"))
		if errDecode != nil {
			t.Fatal(errDecode)
		}
		message := "key\n" + h.Get("X-Client-Ts") + "\n3.16.2\nsession\n" + h.Get("X-Client-Nonce")
		if !ed25519.Verify(public, []byte(message), signature) {
			t.Fatal("invalid business signature")
		}
		seed := sha256.Sum256([]byte("key\nzcode\nsession\n" + h.Get("X-Client-Ts")))
		digest := sha256.Sum256([]byte(hex.EncodeToString(seed[:])[:32] + "\n" + h.Get("X-Client-Pow")))
		if digest[0] != 0 {
			t.Fatal("invalid proof of work")
		}
	}
	if calls != 1 {
		t.Fatalf("handshake not cached: %d", calls)
	}
	signer.Invalidate("account", "https://api.z.ai", "key.secret")
	req, err := http.NewRequest("POST", "https://api.z.ai/api/anthropic/v1/messages", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = signer.Sign(context.Background(), client, req, "account", "key.secret", "3.16.2", "session"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal("invalidation did not renew key")
	}
}
