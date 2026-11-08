package zorxauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	oidcClientsTable = "zorxauth_oidc_clients"
	oidcSigningKey   = "oidc_signing_key"
	oidcIssuerOption = "oidc_issuer"
	oidcCodeLifetime = 2 * time.Minute
	oidcTokenLifetime = time.Hour
)

type OIDCClient struct {
	ID           string   `json:"client_id"`
	SecretHash   string   `json:"secret_hash"`
	Name         string   `json:"name"`
	ProxyDomain  string   `json:"proxy_domain,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	CreatedAt    time.Time `json:"created_at"`
}

type oidcAuthorizationCode struct {
	ClientID            string
	Username            string
	RedirectURI         string
	Nonce               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

type oidcSigningMaterial struct {
	PrivateKey *rsa.PrivateKey
	KeyID      string
}

type oidcProvider struct {
	router *AuthRouter
	key    *oidcSigningMaterial
	codes  sync.Map
}

func (ar *AuthRouter) initOIDCProvider() error {
	ar.Database.NewTable(oidcClientsTable)
	if !ar.Database.KeyExists(DB_NAME, oidcIssuerOption) {
		issuer := strings.TrimRight(ar.Options.SSORedirectURL, "/")
		if issuer != "" {
			if err := ar.Database.Write(DB_NAME, oidcIssuerOption, issuer); err != nil {
				return err
			}
		}
	}
	key := &oidcSigningMaterial{}
	if ar.Database.KeyExists(DB_NAME, oidcSigningKey) {
		var encoded string
		if err := ar.Database.Read(DB_NAME, oidcSigningKey, &encoded); err != nil {
			return err
		}
		block, _ := pem.Decode([]byte(encoded))
		if block == nil {
			return errors.New("invalid OIDC signing key PEM")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		privateKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return errors.New("OIDC signing key is not RSA")
		}
		if err := privateKey.Validate(); err != nil {
			return fmt.Errorf("invalid OIDC signing key: %w", err)
		}
		privateKey.Precompute()
		key.PrivateKey = privateKey
	} else {
		privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return err
		}
		encoded := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		if err := ar.Database.Write(DB_NAME, oidcSigningKey, encoded); err != nil {
			return err
		}
		key.PrivateKey = privateKey
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PrivateKey.PublicKey)
	if err != nil {
		return err
	}
	fingerprint := sha256.Sum256(publicDER)
	key.KeyID = base64.RawURLEncoding.EncodeToString(fingerprint[:])
	ar.oidc = &oidcProvider{router: ar, key: key}
	return nil
}

// isOIDCAuthorizeRedirect recognizes authorization requests that return to this SSO issuer.
func (ar *AuthRouter) isOIDCAuthorizeRedirect(rawURL string) bool {
	issuer, issuerErr := url.Parse(ar.OIDCIssuer())
	target, targetErr := url.Parse(rawURL)
	if issuerErr != nil || targetErr != nil || issuer.Host == "" || target.Host == "" {
		return false
	}
	return strings.EqualFold(issuer.Scheme, target.Scheme) &&
		strings.EqualFold(issuer.Host, target.Host) &&
		target.EscapedPath() == "/oidc/authorize"
}

func (ar *AuthRouter) OIDCIssuer() string {
	var issuer string
	if ar.Database != nil && ar.Database.KeyExists(DB_NAME, oidcIssuerOption) {
		_ = ar.Database.Read(DB_NAME, oidcIssuerOption, &issuer)
	}
	if issuer == "" && ar.Options != nil {
		issuer = strings.TrimRight(ar.Options.SSORedirectURL, "/")
	}
	return strings.TrimRight(issuer, "/")
}

// RegisterOIDCClient creates a client with an independently generated ID and secret.
// The plaintext secret is returned only once to the caller.
func (ar *AuthRouter) RegisterOIDCClient(name, proxyDomain string, redirectURIs []string) (*OIDCClient, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(redirectURIs) == 0 {
		return nil, "", errors.New("client name and at least one redirect URI are required")
	}
	normalizedRedirectURIs := make([]string, 0, len(redirectURIs))
	seenRedirectURIs := make(map[string]struct{}, len(redirectURIs))
	for _, rawURI := range redirectURIs {
		rawURI = strings.TrimSpace(rawURI)
		parsed, err := url.Parse(rawURI)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return nil, "", fmt.Errorf("invalid redirect URI: %s", rawURI)
		}
		if _, exists := seenRedirectURIs[rawURI]; exists {
			continue
		}
		seenRedirectURIs[rawURI] = struct{}{}
		normalizedRedirectURIs = append(normalizedRedirectURIs, rawURI)
	}
	if len(normalizedRedirectURIs) == 0 {
		return nil, "", errors.New("at least one valid redirect URI is required")
	}
	proxyDomain = strings.ToLower(strings.TrimSpace(proxyDomain))
	ar.oidcClientMutex.Lock()
	defer ar.oidcClientMutex.Unlock()
	if proxyDomain != "" {
		entries, err := ar.Database.ListTable(oidcClientsTable)
		if err != nil {
			return nil, "", err
		}
		for _, entry := range entries {
			if len(entry) == 0 {
				continue
			}
			existing := &OIDCClient{}
			if err := ar.Database.Read(oidcClientsTable, string(entry[0]), existing); err != nil {
				continue
			}
			if strings.EqualFold(existing.ProxyDomain, proxyDomain) {
				return nil, "", fmt.Errorf("reverse proxy %s already has an OIDC client", proxyDomain)
			}
		}
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	secretHash := sha256.Sum256([]byte(secret))
	client := &OIDCClient{
		ID: uuid.NewString(), SecretHash: base64.RawURLEncoding.EncodeToString(secretHash[:]),
		Name: name, ProxyDomain: strings.TrimSpace(proxyDomain),
		RedirectURIs: normalizedRedirectURIs, CreatedAt: time.Now().UTC(),
	}
	if err := ar.Database.Write(oidcClientsTable, client.ID, client); err != nil {
		return nil, "", err
	}
	// Never return the stored verifier hash to the management API caller.
	client.SecretHash = ""
	return client, secret, nil
}

func (ar *AuthRouter) GetOIDCClients() ([]*OIDCClient, error) {
	entries, err := ar.Database.ListTable(oidcClientsTable)
	if err != nil {
		return nil, err
	}
	clients := make([]*OIDCClient, 0, len(entries))
	for _, entry := range entries {
		if len(entry) == 0 {
			continue
		}
		client := &OIDCClient{}
		if err := ar.Database.Read(oidcClientsTable, string(entry[0]), client); err == nil {
			client.SecretHash = ""
			clients = append(clients, client)
		}
	}
	return clients, nil
}

func (ar *AuthRouter) DeleteOIDCClient(clientID string) error {
	ar.oidcClientMutex.Lock()
	defer ar.oidcClientMutex.Unlock()
	if !ar.Database.KeyExists(oidcClientsTable, clientID) {
		return errors.New("OIDC client not found")
	}
	return ar.Database.Delete(oidcClientsTable, clientID)
}

func (p *oidcProvider) loadClient(clientID string) (*OIDCClient, error) {
	client := &OIDCClient{}
	if !p.router.Database.KeyExists(oidcClientsTable, clientID) {
		return nil, errors.New("unknown client")
	}
	if err := p.router.Database.Read(oidcClientsTable, clientID, client); err != nil {
		return nil, err
	}
	return client, nil
}

func (p *oidcProvider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	issuer := p.router.OIDCIssuer()
	if issuer == "" {
		http.Error(w, "OIDC issuer is not configured", http.StatusServiceUnavailable)
		return
	}
	writeOIDCJSON(w, http.StatusOK, map[string]interface{}{
		"issuer": issuer, "authorization_endpoint": issuer + "/oidc/authorize",
		"token_endpoint": issuer + "/oidc/token", "userinfo_endpoint": issuer + "/oidc/userinfo",
		"jwks_uri": issuer + "/oidc/jwks", "response_types_supported": []string{"code"},
		"subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported": []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported": []string{"S256"},
		"grant_types_supported": []string{"authorization_code"},
	})
}

func (p *oidcProvider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := &p.key.PrivateKey.PublicKey
	writeOIDCJSON(w, http.StatusOK, map[string]interface{}{"keys": []interface{}{map[string]interface{}{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": p.key.KeyID,
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

func (p *oidcProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Do not allow an authorization request received on an arbitrary Host header
	// to be treated as a trusted redirect back to the configured issuer.
	issuer, err := url.Parse(p.router.OIDCIssuer())
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" ||
		!strings.EqualFold(issuer.Host, r.Host) || requestScheme(r) != "https" {
		http.Error(w, "request does not match the configured OIDC issuer", http.StatusMisdirectedRequest)
		return
	}
	q := r.URL.Query()
	client, err := p.loadClient(q.Get("client_id"))
	if err != nil {
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	}
	redirectURI := q.Get("redirect_uri")
	registered := false
	for _, candidate := range client.RedirectURIs {
		if candidate == redirectURI {
			registered = true
			break
		}
	}
	if !registered {
		http.Error(w, "redirect_uri mismatch", http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" || !validOIDCScope(q.Get("scope")) {
		http.Error(w, "unsupported authorization request", http.StatusBadRequest)
		return
	}
	if q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge_method") != "S256" || !validOIDCCodeChallenge(q.Get("code_challenge")) {
		http.Error(w, "state, nonce and a valid PKCE S256 challenge are required", http.StatusBadRequest)
		return
	}
	if p.router.OIDCIssuer() == "" {
		http.Error(w, "OIDC issuer is not configured", http.StatusServiceUnavailable)
		return
	}
	authenticated, username := p.router.RequestIsAuthenticatedInSSO(w, r)
	if !authenticated {
		loginURL := "/?redirect=" + url.QueryEscape(absoluteRequestURL(r))
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}
	user, err := p.router.getUserByUsername(username)
	if err != nil {
		http.Error(w, "user session is invalid", http.StatusUnauthorized)
		return
	}
	// Persist the user record before issuing a token so legacy records receive
	// a stable subject ID that can be resolved by the UserInfo endpoint.
	if err := p.router.saveUser(user, user.Username); err != nil {
		http.Error(w, "unable to persist user subject", http.StatusInternalServerError)
		return
	}
	if client.ProxyDomain != "" && !p.router.ValidateUserAccessToHost(username, client.ProxyDomain) {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		http.Error(w, "unable to create authorization code", http.StatusInternalServerError)
		return
	}
	code := base64.RawURLEncoding.EncodeToString(codeBytes)
	p.codes.Store(code, &oidcAuthorizationCode{
		ClientID: client.ID, Username: user.Username, RedirectURI: redirectURI, Nonce: q.Get("nonce"),
		Scope: q.Get("scope"), CodeChallenge: q.Get("code_challenge"),
		CodeChallengeMethod: "S256", ExpiresAt: time.Now().Add(oidcCodeLifetime),
	})
	time.AfterFunc(oidcCodeLifetime, func() { p.codes.Delete(code) })
	callback, _ := url.Parse(redirectURI)
	values := callback.Query()
	values.Set("code", code)
	values.Set("state", q.Get("state"))
	callback.RawQuery = values.Encode()
	http.Redirect(w, r, callback.String(), http.StatusFound)
}

func (p *oidcProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mediaType, _, mediaTypeErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaTypeErr != nil || mediaType != "application/x-www-form-urlencoded" {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	clientID, secret, hasBasicAuth := r.BasicAuth()
	if r.Header.Get("Authorization") != "" && !hasBasicAuth {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if !hasBasicAuth {
		clientID, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	} else if r.PostForm.Get("client_id") != "" || r.PostForm.Get("client_secret") != "" {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	client, err := p.loadClient(clientID)
	if err != nil || !verifyOIDCClientSecret(client, secret) {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		writeOIDCError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	code, err := p.consumeAuthorizationCode(
		r.PostForm.Get("code"),
		client.ID,
		r.PostForm.Get("redirect_uri"),
		r.PostForm.Get("code_verifier"),
	)
	if err != nil {
		writeOIDCError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	user, err := p.router.getUserByUsername(code.Username)
	if err != nil || (client.ProxyDomain != "" && !p.router.ValidateUserAccessToHost(user.Username, client.ProxyDomain)) {
		writeOIDCError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	now := time.Now()
	accessToken, err := p.signJWT(map[string]interface{}{
		"iss": p.router.OIDCIssuer(), "sub": stableOIDCSubject(user), "aud": client.ID,
		"iat": now.Unix(), "exp": now.Add(oidcTokenLifetime).Unix(), "scope": code.Scope,
		"token_use": "access",
	})
	if err != nil {
		writeOIDCError(w, http.StatusInternalServerError, "server_error")
		return
	}
	idClaims := map[string]interface{}{
		"iss": p.router.OIDCIssuer(), "sub": stableOIDCSubject(user), "aud": client.ID,
		"iat": now.Unix(), "exp": now.Add(oidcTokenLifetime).Unix(), "nonce": code.Nonce,
	}
	if hasOIDCScope(code.Scope, "profile") {
		idClaims["preferred_username"] = user.Username
	}
	if hasOIDCScope(code.Scope, "email") && user.Email != "" {
		idClaims["email"] = user.Email
		idClaims["email_verified"] = false
	}
	idToken, err := p.signJWT(idClaims)
	if err != nil {
		writeOIDCError(w, http.StatusInternalServerError, "server_error")
		return
	}
	writeOIDCJSON(w, http.StatusOK, map[string]interface{}{
		"access_token": accessToken, "token_type": "Bearer", "expires_in": int(oidcTokenLifetime.Seconds()),
		"id_token": idToken, "scope": code.Scope,
	})
}


func (p *oidcProvider) consumeAuthorizationCode(codeValue, clientID, redirectURI, verifier string) (*oidcAuthorizationCode, error) {
	value, exists := p.codes.LoadAndDelete(codeValue)
	if !exists {
		return nil, errors.New("authorization code not found or already used")
	}
	code, ok := value.(*oidcAuthorizationCode)
	if !ok || code == nil {
		return nil, errors.New("invalid authorization code")
	}
	if !time.Now().Before(code.ExpiresAt) || code.ClientID != clientID ||
		code.RedirectURI != redirectURI || code.CodeChallengeMethod != "S256" ||
		!validOIDCCodeVerifier(verifier) {
		return nil, errors.New("authorization code validation failed")
	}
	challenge := sha256.Sum256([]byte(verifier))
	actualChallenge := base64.RawURLEncoding.EncodeToString(challenge[:])
	if subtle.ConstantTimeCompare([]byte(actualChallenge), []byte(code.CodeChallenge)) != 1 {
		return nil, errors.New("PKCE verification failed")
	}
	return code, nil
}

func (p *oidcProvider) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeOIDCError(w, http.StatusMethodNotAllowed, "invalid_request")
		return
	}
	authorization := strings.Fields(r.Header.Get("Authorization"))
	if len(authorization) != 2 || !strings.EqualFold(authorization[0], "Bearer") {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	token := authorization[1]
	claims, err := p.verifyJWT(token)
	if err != nil {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	clientID, _ := claims["aud"].(string)
	if !validOIDCAccessTokenClaims(claims, clientID) {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	client, err := p.loadClient(clientID)
	if err != nil {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	if client == nil {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	sub, _ := claims["sub"].(string)
	user, err := p.router.getUserByID(sub)
	if err != nil {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	// Recheck the associated proxy authorization so access revocation takes
	// effect for UserInfo requests even while a previously issued token is valid.
	if client.ProxyDomain != "" && !p.router.ValidateUserAccessToHost(user.Username, client.ProxyDomain) {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	response := map[string]interface{}{"sub": stableOIDCSubject(user)}
	scope, _ := claims["scope"].(string)
	if hasOIDCScope(scope, "profile") {
		response["preferred_username"] = user.Username
	}
	if hasOIDCScope(scope, "email") && user.Email != "" {
		response["email"] = user.Email
		response["email_verified"] = false
	}
	writeOIDCJSON(w, http.StatusOK, response)
}

func (p *oidcProvider) signJWT(claims map[string]interface{}) (string, error) {
	header, _ := json.Marshal(map[string]interface{}{"alg": "RS256", "typ": "JWT", "kid": p.key.KeyID})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.key.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (p *oidcProvider) verifyJWT(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header["alg"] != "RS256" || header["kid"] != p.key.KeyID {
		return nil, errors.New("invalid JWT header")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&p.key.PrivateKey.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		return nil, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	exp, expOK := claims["exp"].(float64)
	iat, iatOK := claims["iat"].(float64)
	if !expOK || !iatOK || exp <= iat || now >= int64(exp) || int64(iat) > now+60 {
		return nil, errors.New("invalid JWT lifetime")
	}
	if claims["iss"] != p.router.OIDCIssuer() {
		return nil, errors.New("invalid JWT issuer")
	}
	return claims, nil
}

// validOIDCCodeChallenge validates the base64url-encoded SHA-256 challenge required by PKCE S256.
func validOIDCAccessTokenClaims(claims map[string]interface{}, expectedClientID string) bool {
	if claims == nil || expectedClientID == "" {
		return false
	}
	audience, ok := claims["aud"].(string)
	if !ok || audience == "" || audience != expectedClientID {
		return false
	}
	subject, ok := claims["sub"].(string)
	if !ok || subject == "" || claims["token_use"] != "access" {
		return false
	}
	scope, ok := claims["scope"].(string)
	return ok && validOIDCScope(scope)
}

func validOIDCCodeChallenge(challenge string) bool {
	if len(challenge) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil && len(decoded) == sha256.Size
}

// validOIDCCodeVerifier enforces the PKCE verifier length and unreserved character set.
func validOIDCCodeVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, char := range verifier {
		if !(char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' ||
			char >= '0' && char <= '9' || strings.ContainsRune("-._~", char)) {
			return false
		}
	}
	return true
}

func verifyOIDCClientSecret(client *OIDCClient, secret string) bool {
	if client == nil || secret == "" {
		return false
	}
	hash := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare([]byte(client.SecretHash), []byte(base64.RawURLEncoding.EncodeToString(hash[:]))) == 1
}

func stableOIDCSubject(user *User) string {
	return user.ID
}

func validOIDCScope(scope string) bool {
	scopes := strings.Fields(scope)
	if len(scopes) == 0 || !hasOIDCScope(scope, "openid") {
		return false
	}
	seen := make(map[string]bool, len(scopes))
	for _, item := range scopes {
		if item != "openid" && item != "profile" && item != "email" {
			return false
		}
		if seen[item] {
			return false
		}
		seen[item] = true
	}
	return true
}

func hasOIDCScope(scope, target string) bool {
	for _, item := range strings.Fields(scope) {
		if item == target {
			return true
		}
	}
	return false
}

func absoluteRequestURL(r *http.Request) string {
	scheme := requestScheme(r)
	return scheme + "://" + r.Host + r.URL.RequestURI()
}

func writeOIDCJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeOIDCError(w http.ResponseWriter, status int, code string) {
	writeOIDCJSON(w, status, map[string]string{"error": code})
}
