package zcode

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CaptchaToken is a single-use verification parameter returned by the local worker.
type CaptchaToken struct {
	VerifyParam string `json:"verify_param"`
	Region      string `json:"region"`
	ExpiresAt   int64  `json:"expires_at"`
}

func TakeCaptcha(ctx context.Context, client *http.Client, endpoint, version string) (CaptchaToken, error) {
	var token CaptchaToken
	if endpoint == "" {
		return token, fmt.Errorf("zcode: captcha-url is required for start-plan")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	payload, err := json.Marshal(map[string]string{"app_version": version})
	if err != nil {
		return token, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(endpoint, "/")+"/v1/token", bytes.NewReader(payload))
	if err != nil {
		return token, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return token, fmt.Errorf("zcode: captcha worker unavailable: %w", err)
	}
	defer closeBody(resp.Body)
	if resp.StatusCode != 200 {
		return token, fmt.Errorf("zcode: captcha worker HTTP %d", resp.StatusCode)
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&token); err != nil {
		return token, fmt.Errorf("zcode: captcha worker response: %w", err)
	}
	if token.VerifyParam == "" || token.ExpiresAt <= time.Now().UnixMilli() {
		return token, fmt.Errorf("zcode: captcha worker returned empty or expired token")
	}
	return token, nil
}
