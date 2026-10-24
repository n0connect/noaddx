package auth

import (
	"testing"

	"noaddx/internal/auth"
	"noaddx/internal/identity"
	"noaddx/tests/testutil"
)

// The AccountNumber of the shared Go/JS interop vector (backend/tests/identity,
// frontend/tests): the fuzz worker must derive the same key as the coordinator that
// produced the seed hashes, so this one is fixed rather than drawn from the CSPRNG.
const vectorAccountNumber = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

// Stored hashes are parsed before Argon2id runs: no encoding may panic the server, and a
// hash verifies only for the key it was made from.
func FuzzVerifyAccountNumberHash(f *testing.F) {
	testutil.SetupTestEnv(f)
	f.Cleanup(func() { testutil.TeardownTestEnv(f) })

	authKey, err := identity.DeriveAuthKey(vectorAccountNumber)
	if err != nil {
		f.Fatalf("DeriveAuthKey: %v", err)
	}
	genuine, err := auth.HashAccountNumber(authKey)
	if err != nil {
		f.Fatalf("HashAccountNumber: %v", err)
	}
	other := testutil.NewAuthKey(f)
	f.Add(genuine, authKey)
	f.Add(genuine, other)
	f.Add("argon2id$m=8192$t=1$p=1$$", authKey)
	f.Add("argon2id$m=4294967296$t=1$p=1$00$00", authKey)
	f.Add("", "")

	f.Fuzz(func(t *testing.T, encodedHash, key string) {
		err := auth.VerifyAccountNumberHash(encodedHash, key)
		if err == nil && key != authKey {
			t.Fatalf("hash %q verified for a different key", encodedHash)
		}
	})
}
