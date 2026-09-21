// Command church-oidc wraps a ChurchTools OAuth "social login" in a minimal
// OpenID Connect provider, so that OIDC-only tools can authenticate against
// ChurchTools. Port of the Java implementation in ../java.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	authCodeTTL     = 60 * time.Second
	loginStateTTL   = 5 * time.Minute
	accessTokenTTL  = 5 * time.Minute
	refreshTokenTTL = 30 * 24 * time.Hour
)

type appConfig struct {
	socialClientID    string
	socialSecret      string
	socialRedirectURI string
	socialAuthURI     string
	socialTokenURI    string
	socialUserInfoURI string
	subClaim          string
	issuer            string
	clientID          string
	clientSecret      string
	redirectURI       string
	port              string
}

var (
	cfg    appConfig
	signer *rsaSigner
)

func main() {
	cfg = loadConfig()

	var err error
	signer, err = newSigner()
	if err != nil {
		log.Fatalf("generating signing key: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", discoveryHandler)
	mux.HandleFunc("GET /oauth2/jwks", jwksHandler)
	mux.HandleFunc("GET /oauth2/authorize", authorizeHandler)
	mux.HandleFunc("GET /login/oauth2/code/custom-client", churchToolsCallbackHandler)
	mux.HandleFunc("POST /oauth2/token", tokenHandler)
	mux.HandleFunc("GET /userinfo", userinfoHandler)
	mux.HandleFunc("POST /userinfo", userinfoHandler)

	addr := ":" + cfg.port
	log.Printf("church-oidc listening on %s (issuer %s)", addr, cfg.issuer)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func loadConfig() appConfig {
	return appConfig{
		socialClientID:    mustEnv("OAUTH_SOCIAL_LOGIN_CLIENT_ID"),
		socialSecret:      mustEnv("OAUTH_SOCIAL_LOGIN_SECRET"),
		socialRedirectURI: mustEnv("OAUTH_SOCIAL_LOGIN_REDIRECTURI"),
		socialAuthURI:     mustEnv("OAUTH_SOCIAL_LOGIN_AUTHORIZATION_URI"),
		socialTokenURI:    mustEnv("OAUTH_SOCIAL_LOGIN_TOKEN_URI"),
		socialUserInfoURI: mustEnv("OAUTH_SOCIAL_LOGIN_USER_INFO_URI"),
		subClaim:          envOr("OPENID_SUB", "userName"),
		issuer:            strings.TrimSuffix(mustEnv("OPENID_ISSUER"), "/"),
		clientID:          mustEnv("OPENID_CLIENT_ID"),
		clientSecret:      mustEnv("OPENID_CLIENT_SECRET"),
		redirectURI:       mustEnv("OPENID_REDIRECT_URI"),
		port:              envOr("PORT", "8080"),
	}
}

func mustEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("missing required environment variable %s", name)
	}
	return v
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// ---- in-memory state -------------------------------------------------
//
// ponytail: single-process, in-memory maps with lazy TTL eviction via
// time.AfterFunc. Fine for a small proxy; swap for a shared store (Redis)
// if this ever needs to run with more than one replica.

var (
	mu                sync.Mutex
	pendingLogins     = map[string]*pendingLogin{} // keyed by state we send to ChurchTools
	issuedCodes       = map[string]*authGrant{}    // keyed by the code we hand back to the OIDC client
	accessTokens      = map[string]*activeToken{}  // keyed by access_token
	refreshTokenStore = map[string]*activeToken{}  // keyed by refresh_token
)

type pendingLogin struct {
	clientState   string
	codeChallenge string
	redirectURI   string
	scope         string
	nonce         string
}

type authGrant struct {
	subject       string
	claims        map[string]any
	scope         string
	nonce         string
	redirectURI   string
	codeChallenge string
}

type activeToken struct {
	subject string
	claims  map[string]any
	scope   string
}

func storeWithTTL[K comparable, V any](store map[K]V, key K, val V, ttl time.Duration) {
	mu.Lock()
	store[key] = val
	mu.Unlock()
	time.AfterFunc(ttl, func() {
		mu.Lock()
		delete(store, key)
		mu.Unlock()
	})
}

// ---- OIDC authorize / ChurchTools handoff -----------------------------

func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")

	if clientID != cfg.clientID || redirectURI != cfg.redirectURI {
		http.Error(w, "unknown client_id or redirect_uri", http.StatusBadRequest)
		return
	}

	state := q.Get("state")

	if rt := q.Get("response_type"); rt != "code" {
		redirectError(w, r, redirectURI, state, "unsupported_response_type")
		return
	}

	scope := q.Get("scope")
	if scope == "" {
		scope = "openid"
	}
	if !slices.Contains(strings.Fields(scope), "openid") {
		redirectError(w, r, redirectURI, state, "invalid_scope")
		return
	}

	challenge := q.Get("code_challenge")
	if challenge == "" || q.Get("code_challenge_method") != "S256" {
		redirectError(w, r, redirectURI, state, "invalid_request")
		return
	}

	loginState := randString(24)
	storeWithTTL(pendingLogins, loginState, &pendingLogin{
		clientState:   state,
		codeChallenge: challenge,
		redirectURI:   redirectURI,
		scope:         scope,
		nonce:         q.Get("nonce"),
	}, loginStateTTL)

	v := url.Values{}
	v.Set("client_id", cfg.socialClientID)
	v.Set("redirect_uri", cfg.socialRedirectURI)
	v.Set("response_type", "code")
	v.Set("state", loginState)
	http.Redirect(w, r, cfg.socialAuthURI+"?"+v.Encode(), http.StatusFound)
}

func redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode string) {
	v := url.Values{}
	v.Set("error", errCode)
	if state != "" {
		v.Set("state", state)
	}
	http.Redirect(w, r, redirectURI+"?"+v.Encode(), http.StatusFound)
}

func churchToolsCallbackHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	mu.Lock()
	p, ok := pendingLogins[state]
	if ok {
		delete(pendingLogins, state)
	}
	mu.Unlock()
	if !ok {
		http.Error(w, "unknown or expired login state", http.StatusBadRequest)
		return
	}

	socialToken, err := exchangeChurchToolsCode(code)
	if err != nil {
		http.Error(w, "ChurchTools token exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	top, err := fetchChurchToolsUserInfo(socialToken)
	if err != nil {
		http.Error(w, "ChurchTools userinfo failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	subVal, ok := top[cfg.subClaim]
	if !ok || subVal == nil {
		http.Error(w, "userinfo response has no "+cfg.subClaim+" attribute", http.StatusBadGateway)
		return
	}

	ourCode := randString(24)
	storeWithTTL(issuedCodes, ourCode, &authGrant{
		subject:       toString(subVal),
		claims:        extractClaims(top),
		scope:         p.scope,
		nonce:         p.nonce,
		redirectURI:   p.redirectURI,
		codeChallenge: p.codeChallenge,
	}, authCodeTTL)

	v := url.Values{}
	v.Set("code", ourCode)
	if p.clientState != "" {
		v.Set("state", p.clientState)
	}
	http.Redirect(w, r, p.redirectURI+"?"+v.Encode(), http.StatusFound)
}

func exchangeChurchToolsCode(code string) (string, error) {
	v := url.Values{}
	v.Set("grant_type", "authorization_code")
	v.Set("code", code)
	v.Set("redirect_uri", cfg.socialRedirectURI)
	v.Set("client_id", cfg.socialClientID)
	v.Set("client_secret", cfg.socialSecret)

	resp, err := http.PostForm(cfg.socialTokenURI, v)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK || body.AccessToken == "" {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	return body.AccessToken, nil
}

func fetchChurchToolsUserInfo(accessToken string) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, cfg.socialUserInfoURI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var top map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&top); err != nil {
		return nil, err
	}
	return top, nil
}

// extractClaims mirrors FederatedIdentityIdTokenCustomizer: profile fields
// come from the nested "data" object, email is top-level.
func extractClaims(top map[string]any) map[string]any {
	claims := map[string]any{}
	if data, ok := top["data"].(map[string]any); ok {
		copyIfPresent(claims, data, "userName", "preferred_username")
		copyIfPresent(claims, data, "firstName", "given_name")
		copyIfPresent(claims, data, "lastName", "family_name")
		copyIfPresent(claims, data, "displayName", "name")
		copyIfPresent(claims, data, "imageUrl", "profile")
	}
	if v, ok := top["email"]; ok && v != nil {
		claims["email"] = v
		// ChurchTools doesn't report a verification flag, but it's a login
		// provider vouching for its own users' emails — treat it as verified
		// (OIDC RPs like AFFiNE hard-require email_verified=true).
		claims["email_verified"] = true
	}
	return claims
}

func copyIfPresent(dst, src map[string]any, srcKey, dstKey string) {
	if v, ok := src[srcKey]; ok && v != nil {
		dst[dstKey] = v
	}
}

var profileClaimKeys = []string{"preferred_username", "given_name", "family_name", "name", "profile"}

func filterClaims(all map[string]any, scope string) map[string]any {
	scopes := strings.Fields(scope)
	out := map[string]any{}
	if slices.Contains(scopes, "profile") {
		for _, k := range profileClaimKeys {
			if v, ok := all[k]; ok {
				out[k] = v
			}
		}
	}
	if slices.Contains(scopes, "email") {
		if v, ok := all["email"]; ok {
			out["email"] = v
		}
		if v, ok := all["email_verified"]; ok {
			out["email_verified"] = v
		}
	}
	return out
}

// ---- OIDC token / userinfo ---------------------------------------------

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	clientID, clientSecret, ok := clientCredentials(r)
	if !ok || clientID != cfg.clientID || clientSecret != cfg.clientSecret {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		handleAuthCodeGrant(w, r)
	case "refresh_token":
		handleRefreshGrant(w, r)
	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

func clientCredentials(r *http.Request) (id, secret string, ok bool) {
	if id, secret, ok := r.BasicAuth(); ok {
		return id, secret, true
	}
	id = r.PostForm.Get("client_id")
	if id == "" {
		return "", "", false
	}
	return id, r.PostForm.Get("client_secret"), true
}

func handleAuthCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.PostForm.Get("code")

	mu.Lock()
	grant, ok := issuedCodes[code]
	if ok {
		delete(issuedCodes, code)
	}
	mu.Unlock()
	if !ok {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "unknown or expired code")
		return
	}

	if r.PostForm.Get("redirect_uri") != grant.redirectURI {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if verifier := r.PostForm.Get("code_verifier"); verifier == "" || !verifyPKCE(verifier, grant.codeChallenge) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	issueTokens(w, grant.subject, grant.claims, grant.scope, grant.nonce, "")
}

func handleRefreshGrant(w http.ResponseWriter, r *http.Request) {
	rt := r.PostForm.Get("refresh_token")

	mu.Lock()
	grant, ok := refreshTokenStore[rt]
	mu.Unlock()
	if !ok {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "unknown or expired refresh_token")
		return
	}

	issueTokens(w, grant.subject, grant.claims, grant.scope, "", rt)
}

// issueTokens mints an access token (always) and, unless one is being
// reused (refresh grant), a refresh token — matching the Java config's
// reuseRefreshTokens(true): no rotation on refresh.
func issueTokens(w http.ResponseWriter, subject string, claims map[string]any, scope, nonce, existingRefreshToken string) {
	accessToken := randString(24)
	storeWithTTL(accessTokens, accessToken, &activeToken{subject: subject, claims: claims, scope: scope}, accessTokenTTL)

	refreshToken := existingRefreshToken
	if refreshToken == "" {
		refreshToken = randString(24)
		storeWithTTL(refreshTokenStore, refreshToken, &activeToken{subject: subject, claims: claims, scope: scope}, refreshTokenTTL)
	}

	now := time.Now()
	idClaims := map[string]any{
		"iss": cfg.issuer,
		"sub": subject,
		"aud": cfg.clientID,
		"iat": now.Unix(),
		"exp": now.Add(accessTokenTTL).Unix(),
	}
	if nonce != "" {
		idClaims["nonce"] = nonce
	}
	for k, v := range filterClaims(claims, scope) {
		idClaims[k] = v
	}

	idToken, err := signer.sign(idClaims)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	writeJSON(w, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(accessTokenTTL.Seconds()),
		"id_token":      idToken,
		"refresh_token": refreshToken,
		"scope":         scope,
	})
}

func userinfoHandler(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}

	mu.Lock()
	at, ok := accessTokens[token]
	mu.Unlock()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}

	out := map[string]any{"sub": at.subject}
	for k, v := range filterClaims(at.claims, at.scope) {
		out[k] = v
	}
	writeJSON(w, out)
}

// ---- discovery / JWKS ---------------------------------------------------

func discoveryHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                cfg.issuer,
		"authorization_endpoint":                cfg.issuer + "/oauth2/authorize",
		"token_endpoint":                        cfg.issuer + "/oauth2/token",
		"userinfo_endpoint":                     cfg.issuer + "/userinfo",
		"jwks_uri":                              cfg.issuer + "/oauth2/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "preferred_username", "given_name", "family_name", "name", "profile", "email", "email_verified"},
		"code_challenge_methods_supported":      []string{"S256"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
	})
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	pub := signer.key.PublicKey
	jwk := map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": signer.kid,
		"n":   b64(pub.N.Bytes()),
		"e":   b64(big.NewInt(int64(pub.E)).Bytes()),
	}
	writeJSON(w, map[string]any{"keys": []any{jwk}})
}

// ---- JWT signing ---------------------------------------------------------
//
// A hand-rolled RS256 signer: a JWT is just two base64url JSON segments and
// an RSA signature over them, so stdlib crypto covers it without a JOSE
// dependency.

type rsaSigner struct {
	key *rsa.PrivateKey
	kid string
}

func newSigner() (*rsaSigner, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &rsaSigner{key: key, kid: randString(8)}, nil
}

func (s *rsaSigner) sign(claims map[string]any) (string, error) {
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": s.kid}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	signingInput := b64(headerJSON) + "." + b64(claimsJSON)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64(sig), nil
}

// ---- small helpers --------------------------------------------------------

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func randString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing means the OS RNG is broken
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func verifyPKCE(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	return b64(sum[:]) == challenge
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func writeTokenError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}
