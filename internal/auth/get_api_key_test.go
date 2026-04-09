package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantKey    string
		wantErr    bool
		wantNoAuth bool
	}{
		{
			name:       "returns key for valid header",
			authHeader: "ApiKey abc123",
			wantKey:    "abc123",
		},
		{
			name:       "returns no auth error when header missing",
			authHeader: "",
			wantErr:    true,
			wantNoAuth: true,
		},
		{
			name:       "returns error for wrong scheme",
			authHeader: "Bearer abc123",
			wantErr:    true,
		},
		{
			name:       "returns error for missing key",
			authHeader: "ApiKey",
			wantErr:    true,
		},
		{
			name:       "returns error for malformed header",
			authHeader: "ApiKeyabc123",
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			if tc.authHeader != "" {
				headers.Set("Authorization", tc.authHeader)
			}

			gotKey, err := GetAPIKey(headers)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.wantNoAuth && err != ErrNoAuthHeaderIncluded {
					t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotKey != tc.wantKey {
				t.Fatalf("expected key %q, got %q", tc.wantKey, gotKey)
			}
		})
	}
}
