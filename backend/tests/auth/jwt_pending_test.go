package auth

import (
	"encoding/base64"
	"strings"
	"testing"

	"noaddx/internal/auth"
	"noaddx/tests/testutil"
)

func setupPendingJWTEnv(t *testing.T) {
	t.Helper()
	testutil.SetupTestEnv(t)
	t.Cleanup(func() {
		testutil.TeardownTestEnv(t)
	})
}

func TestSignPendingRegistrationToken_ContainsPendingID(t *testing.T) {
	setupPendingJWTEnv(t)

	// Generate pending ID
	pendingID, err := auth.GeneratePendingID()
	if err != nil {
		t.Fatalf("GeneratePendingID() failed: %v", err)
	}

	// Store the derived identity server-side (never the AccountNumber itself)
	pending := testutil.NewPendingIdentity(t)
	if err := auth.StorePendingRegistration(pendingID, pending); err != nil {
		t.Fatalf("StorePendingRegistration() failed: %v", err)
	}

	// Sign token with pending ID (not AccountNumber)
	token, err := auth.SignPendingRegistrationToken(pendingID)
	if err != nil {
		t.Fatalf("SignPendingRegistrationToken() failed: %v", err)
	}

	if token == "" {
		t.Error("SignPendingRegistrationToken() returned empty token")
	}

	// Verify token and retrieve the pending identity
	retrieved, err := auth.VerifyPendingRegistrationToken(token)
	if err != nil {
		t.Fatalf("VerifyPendingRegistrationToken() failed: %v", err)
	}

	if retrieved != pending {
		t.Errorf("VerifyPendingRegistrationToken() = %+v, want %+v", retrieved, pending)
	}

	// Verify token was deleted (one-time use)
	_, err = auth.VerifyPendingRegistrationToken(token)
	if err == nil {
		t.Error("VerifyPendingRegistrationToken() should fail on second use (one-time use)")
	}
}

func TestSignPendingRegistrationToken_NoAccountNumberInToken(t *testing.T) {
	setupPendingJWTEnv(t)

	pendingID, err := auth.GeneratePendingID()
	if err != nil {
		t.Fatalf("GeneratePendingID() failed: %v", err)
	}

	pending := testutil.NewPendingIdentity(t)
	if err := auth.StorePendingRegistration(pendingID, pending); err != nil {
		t.Fatalf("StorePendingRegistration() failed: %v", err)
	}

	token, err := auth.SignPendingRegistrationToken(pendingID)
	if err != nil {
		t.Fatalf("SignPendingRegistrationToken() failed: %v", err)
	}

	// The token is public to the client: it must carry neither the auth key nor the public key
	for name, secret := range map[string]string{"auth key": pending.AuthKey, "public key": pending.PublicKey} {
		if strings.Contains(token, secret) || strings.Contains(token, base64.RawURLEncoding.EncodeToString([]byte(secret))) {
			t.Errorf("pending token contains the %s", name)
		}
	}

	retrieved, err := auth.VerifyPendingRegistrationToken(token)
	if err != nil {
		t.Fatalf("VerifyPendingRegistrationToken() failed: %v", err)
	}
	if retrieved != pending {
		t.Errorf("VerifyPendingRegistrationToken() = %+v, want %+v", retrieved, pending)
	}
}

func TestVerifyPendingRegistrationToken_Expired(t *testing.T) {
	setupPendingJWTEnv(t)

	// This test would require manipulating JWT expiration or waiting for configured TTL
	// For now, we test that invalid tokens are rejected
	invalidToken := "invalid.token.here"

	_, err := auth.VerifyPendingRegistrationToken(invalidToken)
	if err == nil {
		t.Error("VerifyPendingRegistrationToken() with invalid token should have failed")
	}
}

func TestVerifyPendingRegistrationToken_InvalidPendingID(t *testing.T) {
	setupPendingJWTEnv(t)

	// Create token with pending ID that doesn't exist in store
	nonExistentPendingID, err := auth.GeneratePendingID()
	if err != nil {
		t.Fatalf("GeneratePendingID() failed: %v", err)
	}

	// Don't store it in the store
	token, err := auth.SignPendingRegistrationToken(nonExistentPendingID)
	if err != nil {
		t.Fatalf("SignPendingRegistrationToken() failed: %v", err)
	}

	// Verify should fail because pending ID doesn't exist in store
	_, err = auth.VerifyPendingRegistrationToken(token)
	if err == nil {
		t.Error("VerifyPendingRegistrationToken() with non-existent pending ID should have failed")
	}
}
