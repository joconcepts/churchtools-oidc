package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestPKCE(t *testing.T) {
	verifier := "test-verifier-abc123"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	if !verifyPKCE(verifier, challenge) {
		t.Fatal("expected matching verifier/challenge to pass")
	}
	if verifyPKCE("wrong-verifier", challenge) {
		t.Fatal("expected mismatched verifier to fail")
	}
}

func TestSignAndVerify(t *testing.T) {
	s, err := newSigner()
	if err != nil {
		t.Fatalf("newSigner: %v", err)
	}

	jwt, err := s.sign(map[string]any{"sub": "alice", "iss": "https://example.test"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}

	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	sum := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(&s.key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if claims["sub"] != "alice" {
		t.Fatalf("expected sub=alice, got %v", claims["sub"])
	}
}

func TestExtractAndFilterClaims(t *testing.T) {
	top := map[string]any{
		"id":       float64(42),
		"userName": "jdoe",
		"email":    "jdoe@example.test",
		"data": map[string]any{
			"userName":    "jdoe",
			"firstName":   "Jane",
			"lastName":    "Doe",
			"displayName": "Jane Doe",
			"imageUrl":    "https://example.test/avatar.png",
		},
	}

	claims := extractClaims(top)
	want := map[string]string{
		"preferred_username": "jdoe",
		"given_name":         "Jane",
		"family_name":        "Doe",
		"name":               "Jane Doe",
		"profile":            "https://example.test/avatar.png",
		"email":              "jdoe@example.test",
	}
	for k, v := range want {
		if claims[k] != v {
			t.Fatalf("claims[%q] = %v, want %v", k, claims[k], v)
		}
	}

	onlyEmail := filterClaims(claims, "openid email")
	if _, ok := onlyEmail["given_name"]; ok {
		t.Fatal("email-only scope should not include profile claims")
	}
	if onlyEmail["email"] != "jdoe@example.test" {
		t.Fatal("email-only scope should include email claim")
	}
	if onlyEmail["email_verified"] != true {
		t.Fatal("email-only scope should include email_verified=true")
	}
}
