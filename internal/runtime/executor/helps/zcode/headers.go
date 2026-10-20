package zcode

import "net/http"

// ResponseHeaders excludes all account and verification material, even if echoed.
func ResponseHeaders(upstream http.Header) http.Header {
	out := make(http.Header)
	for _, name := range []string{"Content-Type", "Retry-After", "X-Request-Id"} {
		for _, value := range upstream.Values(name) {
			out.Add(name, value)
		}
	}
	return out
}
