package auth

import (
	"strings"
	"testing"

	"noaddx/internal/auth"
	"noaddx/tests/testutil"
)

func setupAuthTestEnv(t *testing.T) {
	t.Helper()
	testutil.SetupTestEnv(t)
	t.Cleanup(func() {
		testutil.TeardownTestEnv(t)
	})
}

// TestComputeAccountLookup_Deterministic tests that the same auth key under the
// configured pepper always produces the same lookup value, and different keys differ
func TestComputeAccountLookup_Deterministic(t *testing.T) {
	setupAuthTestEnv(t)

	authKey := testutil.NewAuthKey(t)
	lookup1, err := auth.ComputeAccountLookup(authKey)
	if err != nil {
		t.Fatalf("ComputeAccountLookup() failed: %v", err)
	}
	lookup2, err := auth.ComputeAccountLookup(authKey)
	if err != nil {
		t.Fatalf("ComputeAccountLookup() failed: %v", err)
	}
	if lookup1 != lookup2 {
		t.Errorf("ComputeAccountLookup() is not deterministic: got %q and %q", lookup1, lookup2)
	}
	if len(lookup1) != 64 {
		t.Errorf("ComputeAccountLookup() length = %d, want 64 (hex-encoded SHA256)", len(lookup1))
	}

	other, err := auth.ComputeAccountLookup(testutil.NewAuthKey(t))
	if err != nil || other == lookup1 {
		t.Fatalf("distinct auth keys produced the same lookup (err=%v)", err)
	}
}

// TestHashAndVerifyAccountNumber tests Argon2id hashing and verification
func TestHashAndVerifyAccountNumber(t *testing.T) {
	setupAuthTestEnv(t)

	authKey := testutil.NewAuthKey(t)
	hash, err := auth.HashAccountNumber(authKey)
	if err != nil {
		t.Fatalf("HashAccountNumber() failed: %v", err)
	}
	if !strings.HasPrefix(hash, "argon2id$") || len(strings.Split(hash, "$")) != 6 {
		t.Fatalf("HashAccountNumber() returned malformed hash %q", hash)
	}
	if err := auth.VerifyAccountNumberHash(hash, authKey); err != nil {
		t.Errorf("VerifyAccountNumberHash() with the correct key failed: %v", err)
	}
	if err := auth.VerifyAccountNumberHash(hash, testutil.NewAuthKey(t)); err == nil {
		t.Error("VerifyAccountNumberHash() accepted a different key")
	}
}

// TestHashAndVerifyAccountNumber_DifferentSalts tests that the same key produces
// different hashes (random salt) that both verify
func TestHashAndVerifyAccountNumber_DifferentSalts(t *testing.T) {
	setupAuthTestEnv(t)

	authKey := testutil.NewAuthKey(t)
	hash1, err := auth.HashAccountNumber(authKey)
	if err != nil {
		t.Fatalf("HashAccountNumber() failed: %v", err)
	}
	hash2, err := auth.HashAccountNumber(authKey)
	if err != nil {
		t.Fatalf("HashAccountNumber() failed: %v", err)
	}
	if hash1 == hash2 {
		t.Error("HashAccountNumber() produced identical hashes (should have different salts)")
	}
	for i, hash := range []string{hash1, hash2} {
		if err := auth.VerifyAccountNumberHash(hash, authKey); err != nil {
			t.Errorf("VerifyAccountNumberHash() with hash%d failed: %v", i+1, err)
		}
	}
}

// TestVerifyAccountNumberHash_InvalidFormat_ShouldFail corrupts a real stored hash in every
// way the parser must reject, and checks it fails closed without panicking
func TestVerifyAccountNumberHash_InvalidFormat_ShouldFail(t *testing.T) {
	setupAuthTestEnv(t)

	authKey := testutil.NewAuthKey(t)
	real, err := auth.HashAccountNumber(authKey)
	if err != nil {
		t.Fatalf("HashAccountNumber() failed: %v", err)
	}
	parts := strings.Split(real, "$") // argon2id, m=, t=, p=, salt, hash
	join := func(p ...string) string { return strings.Join(p, "$") }

	corrupted := map[string]string{
		"empty string":         "",
		"missing parts":        join(parts[:3]...),
		"wrong prefix":         join(append([]string{"bcrypt"}, parts[1:]...)...),
		"invalid memory":       join(parts[0], "m=x", parts[2], parts[3], parts[4], parts[5]),
		"invalid time":         join(parts[0], parts[1], "t=x", parts[3], parts[4], parts[5]),
		"invalid parallelism":  join(parts[0], parts[1], parts[2], "p=x", parts[4], parts[5]),
		"empty salt":           join(parts[0], parts[1], parts[2], parts[3], "", parts[5]),
		"empty hash":           join(parts[0], parts[1], parts[2], parts[3], parts[4], ""),
		"non-hex salt":         join(parts[0], parts[1], parts[2], parts[3], "zz"+parts[4][2:], parts[5]),
		"non-hex hash":         join(parts[0], parts[1], parts[2], parts[3], parts[4], "zz"+parts[5][2:]),
		"too many parts":       join(append(parts, parts[5])...),
		"missing delimiters":   strings.ReplaceAll(real, "$", ""),
		"truncated hash value": join(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5][:len(parts[5])-2]),
	}
	for name, encoded := range corrupted {
		t.Run(name, func(t *testing.T) {
			err := auth.VerifyAccountNumberHash(encoded, authKey)
			if err == nil || err.Error() == "" {
				t.Errorf("corrupted hash (%s) was not rejected with an error", name)
			}
		})
	}
}

// TestVerifyAccountNumberHash_Empty_ShouldFail tests that empty inputs fail gracefully
func TestVerifyAccountNumberHash_Empty_ShouldFail(t *testing.T) {
	setupAuthTestEnv(t)

	authKey := testutil.NewAuthKey(t)
	if err := auth.VerifyAccountNumberHash("", authKey); err == nil {
		t.Error("VerifyAccountNumberHash() with empty hash should have failed")
	}

	real, err := auth.HashAccountNumber(authKey)
	if err != nil {
		t.Fatalf("HashAccountNumber() failed: %v", err)
	}
	if err := auth.VerifyAccountNumberHash(real, ""); err == nil {
		t.Error("VerifyAccountNumberHash() with an empty key should have failed")
	}
}

// Stored parameters are bounded before any work is done: a corrupted or planted record can
// neither crash the server (parallelism 0 or > 255 used to panic inside argon2) nor make it
// allocate unbounded memory, and only canonical decimal fields parse.
func TestVerifyAccountNumberHash_RejectsOutOfRangeParameters(t *testing.T) {
	setupAuthTestEnv(t)

	authKey := testutil.NewAuthKey(t)
	real, err := auth.HashAccountNumber(authKey)
	if err != nil {
		t.Fatalf("HashAccountNumber() failed: %v", err)
	}
	parts := strings.Split(real, "$")
	join := func(p ...string) string { return strings.Join(p, "$") }

	corrupted := map[string]string{
		"parallelism 0":     join(parts[0], parts[1], parts[2], "p=0", parts[4], parts[5]),
		"parallelism 256":   join(parts[0], parts[1], parts[2], "p=256", parts[4], parts[5]),
		"time 0":            join(parts[0], parts[1], "t=0", parts[3], parts[4], parts[5]),
		"memory 0":          join(parts[0], "m=0", parts[2], parts[3], parts[4], parts[5]),
		"memory over bound": join(parts[0], "m=4294967295", parts[2], parts[3], parts[4], parts[5]),
		"trailing garbage":  join(parts[0], parts[1]+"abc", parts[2], parts[3], parts[4], parts[5]),
		"signed number":     join(parts[0], "m=+"+strings.TrimPrefix(parts[1], "m="), parts[2], parts[3], parts[4], parts[5]),
		"short salt":        join(parts[0], parts[1], parts[2], parts[3], parts[4][:16], parts[5]),
		"short hash":        join(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5][:16]),
	}
	for name, encoded := range corrupted {
		t.Run(name, func(t *testing.T) {
			if err := auth.VerifyAccountNumberHash(encoded, authKey); err == nil {
				t.Errorf("corrupted hash (%s) verified", name)
			}
		})
	}
	if err := auth.VerifyAccountNumberHash(real, authKey); err != nil {
		t.Fatalf("the genuine hash no longer verifies: %v", err)
	}
}
