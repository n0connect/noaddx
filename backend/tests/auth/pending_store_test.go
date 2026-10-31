package auth

import (
	"errors"
	"testing"
	"time"

	"noaddx/internal/auth"
	"noaddx/internal/config"
	"noaddx/tests/testutil"
)

func setupPendingStoreEnv(t *testing.T) {
	t.Helper()
	testutil.SetupTestEnv(t)
	t.Cleanup(func() {
		testutil.TeardownTestEnv(t)
	})
}

func TestGeneratePendingID(t *testing.T) {
	setupPendingStoreEnv(t)

	// Test that pending ID is generated and has correct format (32 hex chars = 128 bits)
	pendingID1, err := auth.GeneratePendingID()
	if err != nil {
		t.Fatalf("GeneratePendingID() failed: %v", err)
	}

	pendingBytes := config.GetPendingIDBytes()
	if pendingBytes <= 0 {
		t.Fatal("PENDING_ID_BYTES not configured in test env")
	}
	expectedLen := pendingBytes * 2
	if len(pendingID1) != expectedLen {
		t.Errorf("GeneratePendingID() length = %d, want %d (hex-encoded)", len(pendingID1), expectedLen)
	}

	// Test uniqueness
	pendingID2, err := auth.GeneratePendingID()
	if err != nil {
		t.Fatalf("GeneratePendingID() failed: %v", err)
	}

	if pendingID1 == pendingID2 {
		t.Error("GeneratePendingID() produced duplicate IDs")
	}

	// Test multiple generations
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := auth.GeneratePendingID()
		if err != nil {
			t.Fatalf("GeneratePendingID() failed: %v", err)
		}
		if ids[id] {
			t.Errorf("GeneratePendingID() produced duplicate ID: %s", id)
		}
		ids[id] = true
	}
}

func TestStoreAndPendingRegistration(t *testing.T) {
	setupPendingStoreEnv(t)

	pending := testutil.NewPendingIdentity(t)

	// Generate pending ID
	pendingID, err := auth.GeneratePendingID()
	if err != nil {
		t.Fatalf("GeneratePendingID() failed: %v", err)
	}

	// Store pending registration
	if err := auth.StorePendingRegistration(pendingID, pending); err != nil {
		t.Fatalf("StorePendingRegistration() failed: %v", err)
	}

	// Retrieve it
	retrieved, err := auth.PendingRegistration(pendingID)
	if err != nil {
		t.Fatalf("PendingRegistration() failed: %v", err)
	}

	if retrieved != pending {
		t.Errorf("PendingRegistration() = %+v, want %+v", retrieved, pending)
	}
}

func TestPendingRegistration_NotFound(t *testing.T) {
	setupPendingStoreEnv(t)

	// A freshly generated id that was never stored: exactly what a forged token would carry
	nonExistentID, err := auth.GeneratePendingID()
	if err != nil {
		t.Fatalf("GeneratePendingID: %v", err)
	}

	_, err = auth.PendingRegistration(nonExistentID)
	if err == nil {
		t.Error("PendingRegistration() with non-existent ID should have failed")
	}
	if err != nil && err.Error() != "invalid token" {
		t.Errorf("PendingRegistration() returned unexpected error: %v", err)
	}
}

// Reading does not use an entry up: a phase 2 that fails for a passing reason is retried
func TestPendingRegistration_ReadDoesNotUseItUp(t *testing.T) {
	setupPendingStoreEnv(t)

	pending := testutil.NewPendingIdentity(t)
	pendingID, err := auth.GeneratePendingID()
	if err != nil {
		t.Fatalf("GeneratePendingID() failed: %v", err)
	}
	if err := auth.StorePendingRegistration(pendingID, pending); err != nil {
		t.Fatalf("StorePendingRegistration() failed: %v", err)
	}

	for attempt := 1; attempt <= 2; attempt++ {
		if retrieved, err := auth.PendingRegistration(pendingID); err != nil || retrieved != pending {
			t.Fatalf("read %d = %+v, %v; want the stored identity", attempt, retrieved, err)
		}
	}
}

func TestPendingRegistration_Expiration(t *testing.T) {
	setupPendingStoreEnv(t)
	t.Setenv("PENDING_TOKEN_TTL_SEC", "1")

	pendingID, err := auth.GeneratePendingID()
	if err != nil {
		t.Fatalf("GeneratePendingID() failed: %v", err)
	}
	if err := auth.StorePendingRegistration(pendingID, testutil.NewPendingIdentity(t)); err != nil {
		t.Fatalf("StorePendingRegistration() failed: %v", err)
	}

	time.Sleep(1100 * time.Millisecond)
	if _, err := auth.PendingRegistration(pendingID); !errors.Is(err, auth.ErrExpiredToken) {
		t.Fatalf("PendingRegistration() after the TTL = %v, want ErrExpiredToken", err)
	}
	if _, err := auth.PendingRegistration(pendingID); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("expired entry was not removed: second read = %v", err)
	}
}

// Completing an entry (its account exists) makes it single use
func TestPendingRegistration_OneTimeUse(t *testing.T) {
	setupPendingStoreEnv(t)

	pendingID, err := auth.GeneratePendingID()
	if err != nil {
		t.Fatalf("GeneratePendingID() failed: %v", err)
	}
	if err := auth.StorePendingRegistration(pendingID, testutil.NewPendingIdentity(t)); err != nil {
		t.Fatalf("StorePendingRegistration() failed: %v", err)
	}

	auth.CompletePendingRegistration(pendingID)
	if _, err := auth.PendingRegistration(pendingID); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("read after completion = %v, want ErrInvalidToken", err)
	}
}

// The pending-registration store is bounded: once full it refuses (fail closed) instead of
// growing without limit, and frees capacity as entries are completed.
func TestStorePendingRegistration_IsBounded(t *testing.T) {
	setupPendingStoreEnv(t)
	auth.ResetPendingStoreForTesting()
	t.Cleanup(auth.ResetPendingStoreForTesting)

	account := testutil.NewPendingIdentity(t)
	var last string
	for i := 0; i < auth.MaxPendingRegistrations; i++ {
		id, err := auth.GeneratePendingID()
		if err != nil {
			t.Fatalf("GeneratePendingID: %v", err)
		}
		if err := auth.StorePendingRegistration(id, account); err != nil {
			t.Fatalf("entry %d refused below the cap: %v", i, err)
		}
		last = id
	}
	overflow, _ := auth.GeneratePendingID()
	if err := auth.StorePendingRegistration(overflow, account); !errors.Is(err, auth.ErrPendingStoreFull) {
		t.Fatalf("entry beyond the cap = %v, want ErrPendingStoreFull", err)
	}
	auth.CompletePendingRegistration(last)
	if err := auth.StorePendingRegistration(overflow, account); err != nil {
		t.Fatalf("freed capacity not reusable: %v", err)
	}
}
