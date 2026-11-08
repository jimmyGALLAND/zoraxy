package zorxauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSingleOIDCFormValue(t *testing.T) {
	tests := []struct {
		name   string
		values url.Values
		key    string
		want   string
		wantOK bool
	}{
		{name: "single value", values: url.Values{"code": {"authorization-code"}}, key: "code", want: "authorization-code", wantOK: true},
		{name: "missing value", values: url.Values{}, key: "code"},
		{name: "empty value", values: url.Values{"code": {""}}, key: "code"},
		{name: "duplicate values", values: url.Values{"code": {"first", "second"}}, key: "code"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := singleOIDCFormValue(test.values, test.key)
			if got != test.want || ok != test.wantOK {
				t.Fatalf("singleOIDCFormValue() = (%q, %v), want (%q, %v)", got, ok, test.want, test.wantOK)
			}
		})
	}
}

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


func TestVerifyOIDCClientSecret(t *testing.T) {
	secret := "a-long-random-client-secret"
	hash := sha256.Sum256([]byte(secret))
	client := &OIDCClient{
		SecretHash: base64.RawURLEncoding.EncodeToString(hash[:]),
	}
	if !verifyOIDCClientSecret(client, secret) {
		t.Fatal("expected the registered client secret to be accepted")
	}
	if verifyOIDCClientSecret(client, "wrong-secret") {
		t.Fatal("expected an incorrect client secret to be rejected")
	}
	if verifyOIDCClientSecret(client, "") {
		t.Fatal("expected an empty client secret to be rejected")
	}
	if verifyOIDCClientSecret(nil, secret) {
		t.Fatal("expected a nil client to be rejected")
	}
}

func TestVerifyOIDCJWTClaims(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	router := &AuthRouter{Options: &AuthRouterOptions{
		SSORedirectURL: "https://auth.example.test",
	}}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	fingerprint := sha256.Sum256(publicDER)
	provider := &oidcProvider{
		router: router,
		key: &oidcSigningMaterial{
			PrivateKey: privateKey,
			KeyID:      base64.RawURLEncoding.EncodeToString(fingerprint[:]),
		},
	}
	now := time.Now()
	tests := []struct {
		name   string
		claims map[string]interface{}
		wantOK bool
	}{
		{
			name: "valid issuer and lifetime",
			claims: map[string]interface{}{
				"iss": router.OIDCIssuer(), "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
			},
			wantOK: true,
		},
		{
			name: "expired token",
			claims: map[string]interface{}{
				"iss": router.OIDCIssuer(), "iat": now.Add(-2 * time.Minute).Unix(), "exp": now.Add(-time.Minute).Unix(),
			},
		},
		{
			name: "future issued token",
			claims: map[string]interface{}{
				"iss": router.OIDCIssuer(), "iat": now.Add(2 * time.Minute).Unix(), "exp": now.Add(3 * time.Minute).Unix(),
			},
		},
		{
			name: "wrong issuer",
			claims: map[string]interface{}{
				"iss": "https://attacker.example.test", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token, err := provider.signJWT(test.claims)
			if err != nil {
				t.Fatalf("sign JWT: %v", err)
			}
			_, err = provider.verifyJWT(token)
			if gotOK := err == nil; gotOK != test.wantOK {
				t.Fatalf("verifyJWT() error = %v, want success = %v", err, test.wantOK)
			}
		})
	}
}


func TestConsumeOIDCAuthorizationCode(t *testing.T) {
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])

	tests := []struct {
		name      string
		clientID  string
		redirect  string
		verifier  string
		expiresAt time.Time
		method    string
		wantOK    bool
	}{
		{
			name: "valid code", clientID: "client-1", redirect: "https://client.example.test/callback",
			verifier: verifier, expiresAt: time.Now().Add(time.Minute), method: "S256", wantOK: true,
		},
		{
			name: "expired code", clientID: "client-1", redirect: "https://client.example.test/callback",
			verifier: verifier, expiresAt: time.Now().Add(-time.Second), method: "S256",
		},
		{
			name: "wrong client", clientID: "client-2", redirect: "https://client.example.test/callback",
			verifier: verifier, expiresAt: time.Now().Add(time.Minute), method: "S256",
		},
		{
			name: "wrong redirect URI", clientID: "client-1", redirect: "https://attacker.example.test/callback",
			verifier: verifier, expiresAt: time.Now().Add(time.Minute), method: "S256",
		},
		{
			name: "wrong PKCE verifier", clientID: "client-1", redirect: "https://client.example.test/callback",
			verifier: strings.Repeat("z", 50), expiresAt: time.Now().Add(time.Minute), method: "S256",
		},
		{
			name: "unsupported PKCE method", clientID: "client-1", redirect: "https://client.example.test/callback",
			verifier: verifier, expiresAt: time.Now().Add(time.Minute), method: "plain",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := &oidcProvider{}
			provider.codes.Store("one-time-code", &oidcAuthorizationCode{
				ClientID: "client-1", RedirectURI: "https://client.example.test/callback",
				CodeChallenge: challenge, CodeChallengeMethod: test.method, ExpiresAt: test.expiresAt,
			})
			_, err := provider.consumeAuthorizationCode("one-time-code", test.clientID, test.redirect, test.verifier)
			if gotOK := err == nil; gotOK != test.wantOK {
				t.Fatalf("consumeAuthorizationCode() error = %v, want success = %v", err, test.wantOK)
			}
			if _, exists := provider.codes.Load("one-time-code"); exists {
				t.Fatal("authorization code must be consumed even when validation fails")
			}
		})
	}
}

func TestOIDCAuthorizationCodeCannotBeReused(t *testing.T) {
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	digest := sha256.Sum256([]byte(verifier))
	provider := &oidcProvider{}
	provider.codes.Store("one-time-code", &oidcAuthorizationCode{
		ClientID: "client-1", RedirectURI: "https://client.example.test/callback",
		CodeChallenge: base64.RawURLEncoding.EncodeToString(digest[:]),
		CodeChallengeMethod: "S256", ExpiresAt: time.Now().Add(time.Minute),
	})

	if _, err := provider.consumeAuthorizationCode("one-time-code", "client-1", "https://client.example.test/callback", verifier); err != nil {
		t.Fatalf("first authorization code exchange failed: %v", err)
	}
	if _, err := provider.consumeAuthorizationCode("one-time-code", "client-1", "https://client.example.test/callback", verifier); err == nil {
		t.Fatal("expected replayed authorization code to be rejected")
	}
}


func TestValidOIDCAccessTokenClaims(t *testing.T) {
	valid := map[string]interface{}{
		"aud": "client-1",
		"sub": "user-123",
		"token_use": "access",
		"scope": "openid profile",
	}
	tests := []struct {
		name   string
		claims map[string]interface{}
		client string
		want   bool
	}{
		{"valid access token", valid, "client-1", true},
		{"wrong audience", valid, "client-2", false},
		{"missing expected audience", valid, "", false},
		{"missing subject", map[string]interface{}{"aud": "client-1", "token_use": "access", "scope": "openid"}, "client-1", false},
		{"wrong token use", map[string]interface{}{"aud": "client-1", "sub": "user-123", "token_use": "id", "scope": "openid"}, "client-1", false},
		{"missing openid scope", map[string]interface{}{"aud": "client-1", "sub": "user-123", "token_use": "access", "scope": "profile"}, "client-1", false},
		{"unsupported scope", map[string]interface{}{"aud": "client-1", "sub": "user-123", "token_use": "access", "scope": "openid admin"}, "client-1", false},
		{"non-string audience", map[string]interface{}{"aud": []string{"client-1"}, "sub": "user-123", "token_use": "access", "scope": "openid"}, "client-1", false},
		{"nil claims", nil, "client-1", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validOIDCAccessTokenClaims(test.claims, test.client); got != test.want {
				t.Fatalf("validOIDCAccessTokenClaims() = %v, want %v", got, test.want)
			}
		})
	}
}


func TestVerifyOIDCJWTRejectsTampering(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	router := &AuthRouter{Options: &AuthRouterOptions{
		SSORedirectURL: "https://auth.example.test",
	}}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	fingerprint := sha256.Sum256(publicDER)
	provider := &oidcProvider{
		router: router,
		key: &oidcSigningMaterial{
			PrivateKey: privateKey,
			KeyID:      base64.RawURLEncoding.EncodeToString(fingerprint[:]),
		},
	}
	token, err := provider.signJWT(map[string]interface{}{
		"iss": router.OIDCIssuer(),
		"sub": "user-123",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("expected a three-part JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	payload = append(payload, ' ')
	tamperedPayload := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + parts[2]
	if _, err := provider.verifyJWT(tamperedPayload); err == nil {
		t.Fatal("expected a modified JWT payload to fail signature verification")
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode JWT signature: %v", err)
	}
	signature[0] ^= 0xff
	tamperedSignature := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(signature)
	if _, err := provider.verifyJWT(tamperedSignature); err == nil {
		t.Fatal("expected a modified JWT signature to be rejected")
	}
	if _, err := provider.verifyJWT("not-a-jwt"); err == nil {
		t.Fatal("expected malformed JWT to be rejected")
	}
}
