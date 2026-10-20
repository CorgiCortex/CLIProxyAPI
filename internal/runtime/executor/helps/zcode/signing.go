package zcode

import (
	"bytes"
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
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/sync/singleflight"
)

type signingKey struct {
	key     ed25519.PrivateKey
	expires time.Time
}

// Signer caches acquired keys by account, credential digest and upstream origin.
type Signer struct {
	mu    sync.Mutex
	keys  map[string]signingKey
	group singleflight.Group
	now   func() time.Time
}

func NewSigner() *Signer { return &Signer{keys: make(map[string]signingKey), now: time.Now} }

func signingCacheKey(account, origin, credential string) string {
	sum := sha256.Sum256([]byte(credential))
	return account + "\n" + origin + "\n" + hex.EncodeToString(sum[:])
}

func (s *Signer) Invalidate(account, origin, credential string) {
	s.mu.Lock()
	delete(s.keys, signingCacheKey(account, origin, credential))
	s.mu.Unlock()
}

func parseSigningCredential(value string) (id, secret, field string, err error) {
	parts := strings.Split(value, ".")
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return parts[0], parts[1], "apiKey", nil
	}
	if len(parts) == 3 {
		data, errDecode := base64.RawURLEncoding.DecodeString(parts[1])
		if errDecode != nil {
			return "", "", "", fmt.Errorf("zcode: invalid project signing token")
		}
		var claims struct {
			APIKey string `json:"api_key"`
			Use    string `json:"token_use"`
			Exp    int64  `json:"exp"`
		}
		if json.Unmarshal(data, &claims) == nil && claims.Use == "project_access" && claims.APIKey != "" && claims.Exp > time.Now().Unix() {
			return claims.APIKey, value, "accessToken", nil
		}
	}
	return "", "", "", fmt.Errorf("zcode: signing requires id.secret or a valid project_access token")
}

func deriveSigningKey(secret, info string) ([]byte, error) {
	key := make([]byte, 32)
	_, err := io.ReadFull(hkdf.New(sha256.New, []byte(secret), []byte("WD_CLIENT_SIGN_KDF_SALT"), []byte(info)), key)
	return key, err
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func closeBody(body io.Closer) {
	if err := body.Close(); err != nil {
		log.WithError(err).Warn("zcode: close upstream response")
	}
}

func (s *Signer) acquire(ctx context.Context, client *http.Client, origin, credential, id, secret, field string) (ed25519.PrivateKey, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ts := strconv.FormatInt(s.now().UnixMilli(), 10)
	nonce, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	key, err := deriveSigningKey(secret, "getSignKey_hmac")
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(strings.Join([]string{"get_sign_key", id, ts, nonce}, "\n")))
	clear(key)
	payload, err := json.Marshal(map[string]string{field: credential, "ts": ts, "nonce": nonce, "sig": base64.StdEncoding.EncodeToString(mac.Sum(nil))})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/api/paas/c1f3a7e2/v2/client", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	authValue := credential
	if field == "accessToken" {
		authValue = "Bearer " + credential
	}
	req.Header.Set("Authorization", authValue)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("zcode: signing handshake transport: %w", err)
	}
	defer closeBody(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("zcode: signing handshake HTTP %d", resp.StatusCode)
	}
	var envelope struct {
		Code int `json:"code"`
		Data struct {
			PrivateCipher string `json:"privateCipher"`
		} `json:"data"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("zcode: signing handshake response: %w", err)
	}
	if envelope.Code != 200 {
		return nil, fmt.Errorf("zcode: signing handshake code %d", envelope.Code)
	}
	encrypted, err := base64.StdEncoding.DecodeString(envelope.Data.PrivateCipher)
	if err != nil || len(encrypted) <= 28 {
		return nil, fmt.Errorf("zcode: invalid signing key envelope")
	}
	key, err = deriveSigningKey(secret, "ed25519_priv")
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, encrypted[:12], encrypted[12:], []byte(id))
	if err != nil {
		return nil, fmt.Errorf("zcode: decrypt signing key: %w", err)
	}
	defer clear(plain)
	der, err := base64.StdEncoding.DecodeString(string(plain))
	if err != nil {
		return nil, fmt.Errorf("zcode: decode signing key: %w", err)
	}
	defer clear(der)
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("zcode: parse signing key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("zcode: signing key must be Ed25519")
	}
	return privateKey, nil
}

func (s *Signer) Sign(ctx context.Context, client *http.Client, req *http.Request, account, credential, version, session string) error {
	id, secret, field, err := parseSigningCredential(credential)
	if err != nil {
		return err
	}
	if session == "" {
		return fmt.Errorf("zcode: signing session is required")
	}
	origin := req.URL.Scheme + "://" + req.URL.Host
	cacheKey := signingCacheKey(account, origin, credential)
	result := s.group.DoChan(cacheKey, func() (any, error) {
		s.mu.Lock()
		now := s.now()
		for k, entry := range s.keys {
			if !entry.expires.After(now) {
				delete(s.keys, k)
			}
		}
		entry, ok := s.keys[cacheKey]
		s.mu.Unlock()
		if ok {
			return entry.key, nil
		}
		key, errAcquire := s.acquire(ctx, client, origin, credential, id, secret, field)
		if errAcquire != nil {
			return nil, errAcquire
		}
		s.mu.Lock()
		s.keys[cacheKey] = signingKey{key: key, expires: now.Add(time.Hour)}
		s.mu.Unlock()
		return key, nil
	})
	var privateKey ed25519.PrivateKey
	select {
	case <-ctx.Done():
		return ctx.Err()
	case value := <-result:
		if value.Err != nil {
			return value.Err
		}
		privateKey = value.Val.(ed25519.PrivateKey)
	}
	ts := strconv.FormatInt(s.now().UnixMilli(), 10)
	nonce, err := randomHex(16)
	if err != nil {
		return err
	}
	seed := sha256.Sum256([]byte(strings.Join([]string{id, "zcode", session, ts}, "\n")))
	challenge := hex.EncodeToString(seed[:])[:32]
	prefix, err := randomHex(12)
	if err != nil {
		return err
	}
	var answer string
	for counter := uint64(0); counter <= 0xffffffff; counter++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		answer = fmt.Sprintf("%s%08x", prefix, counter)
		digest := sha256.Sum256([]byte(challenge + "\n" + answer))
		if digest[0] == 0 {
			break
		}
		if counter == 0xffffffff {
			return fmt.Errorf("zcode: proof of work exhausted")
		}
	}
	message := strings.Join([]string{id, ts, version, session, nonce}, "\n")
	req.Header.Set("X-Client-Ts", ts)
	req.Header.Set("X-Client-Version", version)
	req.Header.Set("X-Client-Sig", base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(message))))
	req.Header.Set("X-Session-Id", session)
	req.Header.Set("X-Client-Nonce", nonce)
	req.Header.Set("X-App-Id", "zcode")
	req.Header.Set("X-Client-Pow", answer)
	return nil
}
