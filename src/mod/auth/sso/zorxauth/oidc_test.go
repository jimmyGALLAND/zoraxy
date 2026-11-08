package zorxauth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestValidOIDCCodeVerifier(t *testing.T) {
	valid := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	if !validOIDCCodeVerifier(valid) {
		t.Fatal("expected valid PKCE verifier to be accepted")
	}
	if validOIDCCodeVerifier(valid[:42]) {
		t.Fatal("expected verifier shorter than 43 characters to be rejected")
	}
	if validOIDCCodeVerifier(strings.Repeat("a", 129)) {
		t.Fatal("expected verifier longer than 128 characters to be rejected")
	}
	if validOIDCCodeVerifier(valid[:42] + "!") {
		t.Fatal("expected verifier containing a reserved character to be rejected")
	}
}

func TestValidOIDCCodeChallenge(t *testing.T) {
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	if !validOIDCCodeChallenge(challenge) {
		t.Fatal("expected valid S256 challenge to be accepted")
	}
	if validOIDCCodeChallenge(challenge[:42]) {
		t.Fatal("expected malformed challenge length to be rejected")
	}
	if validOIDCCodeChallenge("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!") {
		t.Fatal("expected invalid base64url challenge to be rejected")
	}
}

func TestIsOIDCAuthorizeRedirect(t *testing.T) {
	router := &AuthRouter{Options: &AuthRouterOptions{
		SSORedirectURL: "https://auth.example.test",
	}}
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"same issuer authorize endpoint", "https://auth.example.test/oidc/authorize?client_id=abc", true},
		{"different host", "https://other.example.test/oidc/authorize", false},
		{"different path", "https://auth.example.test/oidc/token", false},
		{"relative URL", "/oidc/authorize", false},
		{"invalid URL", "://invalid", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := router.isOIDCAuthorizeRedirect(test.url); got != test.want {
				t.Fatalf("isOIDCAuthorizeRedirect(%q) = %v, want %v", test.url, got, test.want)
			}
		})
	}
}

func TestValidOIDCScope(t *testing.T) {
	tests := []struct {
		scope string
		want  bool
	}{
		{"openid", true},
		{"openid profile", true},
		{"openid email profile", true},
		{"profile", false},
		{"openid admin", false},
		{"openid openid", false},
		{"", false},
	}
	for _, test := range tests {
		t.Run(test.scope, func(t *testing.T) {
			if got := validOIDCScope(test.scope); got != test.want {
				t.Fatalf("validOIDCScope(%q) = %v, want %v", test.scope, got, test.want)
			}
		})
	}
}
