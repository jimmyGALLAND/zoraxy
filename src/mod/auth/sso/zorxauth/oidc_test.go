package zorxauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/database/dbinc"

)


func TestUpdateUserSerializesConcurrentMutations(t *testing.T) {
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "users.db"), dbinc.BackendBoltDB)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	defer db.Close()
	if err := db.NewTable(DB_USERS_TABLE); err != nil {
		t.Fatalf("create users table: %v", err)
	}

	router := &AuthRouter{Database: db}
	if err := router.saveUser(&User{
		Username:     "user-a",
		PasswordHash: hashPassword("initial-password"),
	}, ""); err != nil {
		t.Fatalf("create test user: %v", err)
	}

	updates := []func(*User) error{
		func(user *User) error {
			user.Email = "user@example.test"
			return nil
		},
		func(user *User) error {
			user.AllowedHosts = []string{"app.example.test"}
			return nil
		},
		func(user *User) error {
			user.Enable2FA = true
			user.TOTPSecret = "test-secret"
			return nil
		},
	}

	var waitGroup sync.WaitGroup
	errorsFound := make(chan error, len(updates))
	for _, update := range updates {
		waitGroup.Add(1)
		go func(update func(*User) error) {
			defer waitGroup.Done()
			_, err := router.updateUser("user-a", update)
			if err != nil {
				errorsFound <- err
			}
		}(update)
	}
	waitGroup.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Errorf("concurrent user update failed: %v", err)
	}

	user, err := router.getUserByUsername("user-a")
	if err != nil {
		t.Fatalf("reload test user: %v", err)
	}
	if user.Email != "user@example.test" {
		t.Errorf("email update was lost: got %q", user.Email)
	}
	if len(user.AllowedHosts) != 1 || user.AllowedHosts[0] != "app.example.test" {
		t.Errorf("allowed-host update was lost: got %#v", user.AllowedHosts)
	}
	if !user.Enable2FA || user.TOTPSecret != "test-secret" {
		t.Errorf("TOTP update was lost: enabled=%t", user.Enable2FA)
	}
}

func TestInvalidateUserSessions(t *testing.T) {
	router := &AuthRouter{}
	router.oidc = &oidcProvider{}
	router.gatewaySessionStore.Store("gateway-a", &GatewaySession{Username: "user-a"})
	router.gatewaySessionStore.Store("gateway-b", &GatewaySession{Username: "user-b"})
	router.cookieIdStore.Store("browser-a", &BrowserSession{Username: "user-a"})
	router.cookieIdStore.Store("browser-b", &BrowserSession{Username: "user-b"})
	router.pendingTOTPSessions.Store("totp-a", &PendingTOTPSession{Username: "user-a"})
	router.pendingTOTPSessions.Store("totp-b", &PendingTOTPSession{Username: "user-b"})
	router.pendingTOTPSetup.Store("user-a", &PendingTOTPSetup{Secret: "secret-a"})
	router.pendingTOTPSetup.Store("user-b", &PendingTOTPSetup{Secret: "secret-b"})
	router.pendingPasskeyReg.Store("passkey-reg-a", &PendingPasskeyRegistration{Username: "user-a"})
	router.pendingPasskeyReg.Store("passkey-reg-b", &PendingPasskeyRegistration{Username: "user-b"})
	router.sessionIdStore.Store("callback-a", "user-a")
	router.sessionIdStore.Store("callback-b", "user-b")
	router.oidc.codes.Store("oidc-a", &oidcAuthorizationCode{Username: "user-a"})
	router.oidc.codes.Store("oidc-b", &oidcAuthorizationCode{Username: "user-b"})

	router.invalidateUserSessions("user-a")

	for _, key := range []string{"gateway-a"} {
		if _, exists := router.gatewaySessionStore.Load(key); exists {
			t.Fatalf("expected gateway session %q to be invalidated", key)
		}
	}
	if _, exists := router.gatewaySessionStore.Load("gateway-b"); !exists {
		t.Fatal("expected another user's gateway session to remain")
	}
	if _, exists := router.cookieIdStore.Load("browser-a"); exists {
		t.Fatal("expected browser session to be invalidated")
	}
	if _, exists := router.cookieIdStore.Load("browser-b"); !exists {
		t.Fatal("expected another user's browser session to remain")
	}
	if _, exists := router.pendingTOTPSessions.Load("totp-a"); exists {
		t.Fatal("expected pending TOTP session to be invalidated")
	}
	if _, exists := router.pendingTOTPSessions.Load("totp-b"); !exists {
		t.Fatal("expected another user's pending TOTP session to remain")
	}
	if _, exists := router.pendingTOTPSetup.Load("user-a"); exists {
		t.Fatal("expected pending TOTP enrollment to be invalidated")
	}
	if _, exists := router.pendingTOTPSetup.Load("user-b"); !exists {
		t.Fatal("expected another user's pending TOTP enrollment to remain")
	}
	if _, exists := router.pendingPasskeyReg.Load("passkey-reg-a"); exists {
		t.Fatal("expected pending passkey registration to be invalidated")
	}
	if _, exists := router.pendingPasskeyReg.Load("passkey-reg-b"); !exists {
		t.Fatal("expected another user's pending passkey registration to remain")
	}
	if _, exists := router.sessionIdStore.Load("callback-a"); exists {
		t.Fatal("expected pending cross-domain callback to be invalidated")
	}
	if _, exists := router.sessionIdStore.Load("callback-b"); !exists {
		t.Fatal("expected another user's callback to remain")
	}
	if _, exists := router.oidc.codes.Load("oidc-a"); exists {
		t.Fatal("expected pending OIDC authorization code to be invalidated")
	}
	if _, exists := router.oidc.codes.Load("oidc-b"); !exists {
		t.Fatal("expected another user's OIDC authorization code to remain")
	}
}

func TestDeleteValidationCodesForUser(t *testing.T) {
	router := &AuthRouter{}
	router.sessionIdStore.Store("code-user-a-1", "user-a")
	router.sessionIdStore.Store("code-user-a-2", "user-a")
	router.sessionIdStore.Store("code-user-b", "user-b")

	router.deleteValidationCodesForUser("user-a")

	if _, exists := router.sessionIdStore.Load("code-user-a-1"); exists {
		t.Fatal("expected first pending validation code for user-a to be deleted")
	}
	if _, exists := router.sessionIdStore.Load("code-user-a-2"); exists {
		t.Fatal("expected second pending validation code for user-a to be deleted")
	}
	if value, exists := router.sessionIdStore.Load("code-user-b"); !exists || value != "user-b" {
		t.Fatal("expected validation code for user-b to remain")
	}
}

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

func TestIsOIDCProxyLogoutHostAllowed(t *testing.T) {
	resolveAliases := func(primary string) []string {
		if primary == "cloud.diagimm.fr" {
			return []string{"cloud.celjim.fr", "*.apps.celjim.fr"}
		}
		return nil
	}
	tests := []struct {
		name string
		host string
		primary string
		resolve func(string) []string
		want bool
	}{
		{name: "primary domain", host: "cloud.diagimm.fr", primary: "cloud.diagimm.fr", resolve: resolveAliases, want: true},
		{name: "configured alias", host: "cloud.celjim.fr", primary: "cloud.diagimm.fr", resolve: resolveAliases, want: true},
		{name: "wildcard alias", host: "files.apps.celjim.fr", primary: "cloud.diagimm.fr", resolve: resolveAliases, want: true},
		{name: "case insensitive", host: "CLOUD.CELJIM.FR.", primary: "cloud.diagimm.fr", resolve: resolveAliases, want: true},
		{name: "unrelated host", host: "attacker.example.test", primary: "cloud.diagimm.fr", resolve: resolveAliases, want: false},
		{name: "no resolver", host: "cloud.celjim.fr", primary: "cloud.diagimm.fr", want: false},
		{name: "empty host", host: "", primary: "cloud.diagimm.fr", resolve: resolveAliases, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isOIDCProxyLogoutHostAllowed(test.host, test.primary, test.resolve); got != test.want {
				t.Fatalf("isOIDCProxyLogoutHostAllowed(%q, %q) = %v, want %v", test.host, test.primary, got, test.want)
			}
		})
	}
}

func TestIsRegisteredOIDCLogoutRedirectURI(t *testing.T) {
	registered := []string{
		"https://portail.celjim.fr",
	}
	resolveAliases := func(primary string) []string {
		if primary == "cloud.diagimm.fr" {
			return []string{"cloud.celjim.fr", "*.apps.celjim.fr"}
		}
		return nil
	}
	tests := []struct {
		name string
		uri  string
		want bool
	}{
		{name: "registered portal landing page", uri: "https://portail.celjim.fr", want: true},
		{name: "primary proxy origin without registration", uri: "https://cloud.diagimm.fr", want: true},
		{name: "proxy alias origin without registration", uri: "https://cloud.celjim.fr", want: true},
		{name: "wildcard proxy alias origin", uri: "https://files.apps.celjim.fr/", want: true},
		{name: "registered callback URI", uri: "https://cloud.celjim.fr/apps/user_oidc/code", want: true},
		{name: "unregistered host", uri: "https://attacker.example.test", want: false},
		{name: "unregistered proxy path", uri: "https://cloud.celjim.fr/other", want: false},
		{name: "unregistered query", uri: "https://cloud.celjim.fr?next=attacker", want: false},
		{name: "non-standard port", uri: "https://cloud.celjim.fr:444", want: false},
		{name: "plain HTTP", uri: "http://cloud.celjim.fr", want: false},
		{name: "userinfo", uri: "https://user@cloud.celjim.fr", want: false},
		{name: "fragment", uri: "https://cloud.celjim.fr#section", want: false},
		{name: "malformed URI", uri: "://invalid", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isRegisteredOIDCLogoutRedirectURI(test.uri, registered, "cloud.diagimm.fr", resolveAliases); got != test.want {
				t.Fatalf("isRegisteredOIDCLogoutRedirectURI(%q) = %v, want %v", test.uri, got, test.want)
			}
		})
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

func TestValidOIDCIssuer(t *testing.T) {
	tests := []struct {
		name   string
		issuer string
		want   bool
	}{
		{"https issuer", "https://auth.example.test", true},
		{"https issuer with path", "https://auth.example.test/sso", true},
		{"http issuer", "http://auth.example.test", false},
		{"missing host", "https:///oidc", false},
		{"userinfo", "https://user:pass@auth.example.test", false},
		{"query string", "https://auth.example.test?tenant=one", false},
		{"fragment", "https://auth.example.test#issuer", false},
		{"relative issuer", "/auth", false},
		{"opaque issuer", "https:auth.example.test", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validOIDCIssuer(test.issuer); got != test.want {
				t.Fatalf("validOIDCIssuer(%q) = %v, want %v", test.issuer, got, test.want)
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

func TestNormalizeOIDCRedirectURIs(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		want bool
	}{
		{"Traccar Android callback", "org.traccar.manager://api/session/openid/callback", true},
		{"native callback with empty authority", "app.immich:///oauth-callback", true},
		{"HTTPS callback", "https://app.example.test/oidc/callback", true},
		{"reject plain HTTP callback", "http://app.example.test/callback", false},
		{"reject undotted custom scheme", "myapp://callback/path", false},
		{"reject opaque custom URI", "org.example:callback", false},
		{"reject userinfo", "org.example://user@callback/path", false},
		{"reject fragment", "org.example://callback/path#fragment", false},
		{"reject relative URI", "/oidc/callback", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeOIDCRedirectURIs([]string{test.uri})
			if (err == nil) != test.want {
				t.Fatalf("normalizeOIDCRedirectURIs(%q) = (%v, %v), want success = %v", test.uri, got, err, test.want)
			}
			if test.want && (len(got) != 1 || got[0] != test.uri) {
				t.Fatalf("redirect URI was not preserved exactly: got %#v, want %q", got, test.uri)
			}
		})
	}
}
