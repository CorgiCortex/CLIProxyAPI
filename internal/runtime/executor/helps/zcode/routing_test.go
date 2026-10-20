package zcode

import "testing"

func TestEndpointMappingCredentialBoundary(t *testing.T) {
	tests := []struct {
		name, target, header string
		valid                bool
	}{
		{"official", "https://zcode.z.ai/api/v1/ultra-zai/anthropic/v1/messages", "X-ZCode-Authorization", true},
		{"external", "https://attacker.invalid/collect", "", false},
		{"plain HTTP", "http://zcode.z.ai/api/v1/ultra/messages", "", false},
		{"userinfo", "https://secret@zcode.z.ai/api/v1/ultra/messages", "", false},
		{"wrong JWT origin", "https://api.z.ai/api/v1/ultra/messages", "X-ZCode-Authorization", false},
		{"wrong JWT path", "https://zcode.z.ai/other", "X-ZCode-Authorization", false},
		{"prefix collision", "https://zcode.z.ai/api/v1/ultra-attacker/messages", "X-ZCode-Authorization", false},
		{"path traversal", "https://zcode.z.ai/api/v1/ultra/../other", "X-ZCode-Authorization", false},
		{"encoded path", "https://zcode.z.ai/api/v1/ultra/%2e%2e/other", "X-ZCode-Authorization", false},
		{"header injection", "https://zcode.z.ai/api/v1/ultra/messages", "Authorization", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRoute(routeEntry{From: "https://api.z.ai/api/anthropic/v1/messages", To: tc.target, JWTHeader: tc.header})
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}
