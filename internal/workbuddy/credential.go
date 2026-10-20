// Package workbuddy implements the WorkBuddy upstream contract independently of
// client-facing API formats. Protocol behavior is derived from workbuddy2api-hub
// af706fc31e4a22cb2dea7442361b2b15185c3cee (MIT); see NOTICE.
package workbuddy

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Realm string
type Product string

const (
	International Realm   = "intl"
	China         Realm   = "cn"
	Desktop       Product = "workbuddy"
	VSCode        Product = "vscode"
	CLI           Product = "cli"
)

// Credential is the persisted native auth record. Secrets are never included in
// errors or diagnostic output.
type Credential struct {
	Type         string   `json:"type"`
	UID          string   `json:"uid"`
	Realm        Realm    `json:"realm"`
	Product      Product  `json:"product"`
	Domain       string   `json:"domain,omitempty"`
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	ExpiresAt    int64    `json:"expires_at,omitempty"`
	EnterpriseID string   `json:"enterprise_id,omitempty"`
	ProxyURL     string   `json:"proxy_url,omitempty"`
	DeviceToken  string   `json:"device_token,omitempty"`
	PrivateData  string   `json:"private_data,omitempty"`
	Disabled     bool     `json:"disabled,omitempty"`
	Prefix       string   `json:"prefix,omitempty"`
	Models       []string `json:"models,omitempty"`
}

func (c Credential) Validate() error {
	if c.Type != "workbuddy" {
		return fmt.Errorf("workbuddy: credential type must be workbuddy")
	}
	if strings.TrimSpace(c.UID) == "" || strings.TrimSpace(c.AccessToken) == "" {
		return fmt.Errorf("workbuddy: uid and access_token are required")
	}
	if c.Realm != International && c.Realm != China {
		return fmt.Errorf("workbuddy: realm must be intl or cn")
	}
	if c.Product != Desktop && c.Product != VSCode && c.Product != CLI {
		return fmt.Errorf("workbuddy: product must be workbuddy, vscode or cli")
	}
	if c.PrivateData != "" && c.PrivateData != "auto" && c.PrivateData != "true" && c.PrivateData != "false" {
		return fmt.Errorf("workbuddy: private_data must be auto, true or false")
	}
	if strings.ContainsAny(c.UID, "\r\n") || strings.ContainsAny(c.AccessToken, "\r\n") ||
		strings.ContainsAny(c.RefreshToken+c.Domain+c.EnterpriseID+c.DeviceToken, "\r\n") {
		return fmt.Errorf("workbuddy: invalid credential header value")
	}
	if c.Domain != "" && (strings.ContainsAny(c.Domain, "/:@") || strings.ContainsAny(c.Domain, " \t")) {
		return fmt.Errorf("workbuddy: domain must be a hostname")
	}
	return nil
}

func DecodeCredential(data []byte) (Credential, error) {
	var c Credential
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("workbuddy: invalid credential JSON")
	}
	return c, c.Validate()
}

// ImportHubCredential is an explicit import boundary, not a runtime fallback.
func ImportHubCredential(data []byte) (Credential, error) {
	var src struct {
		UID          string  `json:"uid"`
		Realm        Realm   `json:"realm"`
		Product      Product `json:"product"`
		Domain       string  `json:"domain"`
		AccessToken  string  `json:"accessToken"`
		RefreshToken string  `json:"refreshToken"`
		ExpiresAt    int64   `json:"expiresAt"`
		EnterpriseID string  `json:"enterpriseId"`
		Proxy        string  `json:"proxy"`
		Enabled      *bool   `json:"enabled"`
	}
	if err := json.Unmarshal(data, &src); err != nil {
		return Credential{}, fmt.Errorf("workbuddy: invalid hub credential JSON")
	}
	c := Credential{Type: "workbuddy", UID: src.UID, Realm: src.Realm, Product: src.Product,
		Domain: src.Domain, AccessToken: src.AccessToken, RefreshToken: src.RefreshToken,
		ExpiresAt: src.ExpiresAt, EnterpriseID: src.EnterpriseID, ProxyURL: src.Proxy}
	if c.Product == "" {
		c.Product = Desktop
	}
	if src.Enabled != nil {
		c.Disabled = !*src.Enabled
	}
	if c.ExpiresAt > 1e12 {
		c.ExpiresAt /= 1000
	}
	claims, errClaims := ParseTokenClaims(c.AccessToken)
	if errClaims != nil {
		return Credential{}, errClaims
	}
	if c.UID == "" {
		c.UID = claims.Subject
	} else if c.UID != claims.Subject {
		return Credential{}, fmt.Errorf("workbuddy: credential uid does not match token subject")
	}
	if c.ExpiresAt == 0 {
		c.ExpiresAt = claims.Expires
	}
	if c.EnterpriseID == "" {
		c.EnterpriseID = claims.EnterpriseID
	}
	return c, c.Validate()
}

type TokenClaims struct {
	Subject      string `json:"sub"`
	Expires      int64  `json:"exp"`
	EnterpriseID string `json:"enterprise_id"`
}

// ParseTokenClaims decodes identity and expiration. JWT contents are not treated as
// proof of authentication; only an upstream response can establish that.
func ParseTokenClaims(token string) (TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return TokenClaims{}, fmt.Errorf("workbuddy: access token is not a JWT")
	}
	raw, errDecode := base64.RawURLEncoding.DecodeString(parts[1])
	if errDecode != nil {
		return TokenClaims{}, fmt.Errorf("workbuddy: invalid JWT payload")
	}
	var claims TokenClaims
	if errDecode = json.Unmarshal(raw, &claims); errDecode != nil || claims.Subject == "" {
		return TokenClaims{}, fmt.Errorf("workbuddy: JWT has no valid subject")
	}
	return claims, nil
}

func (c Credential) Expiring(now time.Time) bool {
	return c.ExpiresAt > 0 && c.ExpiresAt <= now.Add(2*time.Minute).Unix()
}

// WriteJSON atomically replaces a private state file, including a directory
// fsync so credential rotation and risk state survive process restarts.
func WriteJSON(path string, value any) (err error) {
	raw, errMarshal := json.Marshal(value)
	if errMarshal != nil {
		return fmt.Errorf("workbuddy: encode state: %w", errMarshal)
	}
	dir := filepath.Dir(path)
	if errMkdir := os.MkdirAll(dir, 0700); errMkdir != nil {
		return errMkdir
	}
	f, errCreate := os.CreateTemp(dir, ".workbuddy-*")
	if errCreate != nil {
		return errCreate
	}
	name := f.Name()
	defer func() {
		if err != nil {
			if errRemove := os.Remove(name); errRemove != nil && !errors.Is(errRemove, os.ErrNotExist) {
				err = errors.Join(err, errRemove)
			}
		}
	}()
	if _, err = f.Write(raw); err != nil {
		return errors.Join(err, f.Close())
	}
	if err = f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	d, errOpen := os.Open(dir)
	if errOpen != nil {
		return errOpen
	}
	errSync := d.Sync()
	errClose := d.Close()
	if errSync != nil {
		return errSync
	}
	return errClose
}

func validateBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("workbuddy: invalid upstream base URL")
	}
	return nil
}
