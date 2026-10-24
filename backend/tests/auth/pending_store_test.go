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

func TestStoreAndGetPendingRegistration(t *testing.T) {
	setupPendingStoreEnv(t)

	accountNumber := testutil.NewAccountNumber(t)

	// Generate pending ID
	pendingID, err := auth.GeneratePendingID()
	if err != nil {
		t.Fatalf("GeneratePendingID() failed: %v", err)
	}

	// Store pending registration
	if err := auth.StorePendingRegistration(pendingID, accountNumber); err != nil {
		t.Fatalf("StorePendingRegistration() failed: %v", err)
	}

	// Retrieve it
	retrieved, err := auth.GetPendingRegistration(pendingID)
	if err != nil {
		t.Fatalf("GetPendingRegistration() failed: %v", err)
	}

	if retrieved != accountNumber {
		t.Errorf("GetPendingRegistration() = %q, want %q", retrieved, accountNumber)
	}
}

func TestGetPendingRegistration_NotFound(t *testing.T) {
	setupPendingStoreEnv(t)

	// A freshly generated id that was never stored: exactly what a forged token would carry
	nonExistentID, err := auth.GeneratePendingID()
	if err != nil {
		t.Fatalf("GeneratePendingID: %v", err)
	}

	_, err = auth.GetPendingRegistration(nonExistentID)
	if err == nil {
		t.Error("GetPendingRegistration() with non-existent ID should have failed")
	}
	if err != nil && err.Error() != "invalid token" {
		t.Errorf("GetPendingRegistration() returned unexpected error: %v", err)
	}
}

func TestPendingRegistration_ConsumedOnRead(t *testing.T) {
	setupPendingStoreEnv(t)

	accountNumber := testutil.NewAccountNumber(t)

	// Generate and store
	pendingID, err := auth.GeneratePendingID()
	if err != nil {
		t.Fatalf("GeneratePendingID() failed: %v", err)
	}

	if err := auth.StorePendingRegistration(pendingID, accountNumber); err != nil {
		t.Fatalf("StorePendingRegistration() failed: %v", err)
	}

	// Verify it exists
	_, err = auth.GetPendingRegistration(pendingID)
	if err != nil {
		t.Fatalf("GetPendingRegistration() failed before delete: %v", err)
	}

	// Verify it's gone: retrieval is one-time use
	_, err = auth.GetPendingRegistration(pendingID)
	if err == nil {
		t.Error("GetPendingRegistration() after delete should have failed")
	}
}

func TestPendingRegistration_Expiration(t *testing.T) {
	setupPendingStoreEnv(t)
	t.Setenv("PENDING_TOKEN_TTL_SEC", "1")

	pendingID, err := auth.GeneratePendingID()
	if err != nil {
		t.Fatalf("GeneratePendingID() failed: %v", err)
	}
	if err := auth.StorePendingRegistration(pendingID, testutil.NewAccountNumber(t)); err != nil {
		t.Fatalf("StorePendingRegistration() failed: %v", err)
	}

	time.Sleep(1100 * time.Millisecond)
	if _, err := auth.GetPendingRegistration(pendingID); !errors.Is(err, auth.ErrExpiredToken) {
		t.Fatalf("GetPendingRegistration() after the TTL = %v, want ErrExpiredToken", err)
	}
	if _, err := auth.GetPendingRegistration(pendingID); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("expired entry was not removed: second read = %v", err)
	}
}

func TestPendingRegistration_OneTimeUse(t *testing.T) {
	setupPendingStoreEnv(t)

	accountNumber := testutil.NewAccountNumber(t)

	pendingID, err := auth.GeneratePendingID()
	if err != nil {
		t.Fatalf("GeneratePendingID() failed: %v", err)
	}

	if err := auth.StorePendingRegistration(pendingID, accountNumber); err != nil {
		t.Fatalf("StorePendingRegistration() failed: %v", err)
	}

	// First retrieval should work
	retrieved1, err := auth.GetPendingRegistration(pendingID)
	if err != nil {
		t.Fatalf("GetPendingRegistration() first call failed: %v", err)
	}
	if retrieved1 != accountNumber {
		t.Errorf("GetPendingRegistration() = %q, want %q", retrieved1, accountNumber)
	}

	// Second retrieval must fail (one-time use)
	_, err = auth.GetPendingRegistration(pendingID)
	if err == nil {
		t.Error("GetPendingRegistration() after delete should have failed (one-time use)")
	}
}

// The pending-registration store is bounded: once full it refuses (fail closed) instead of
// growing without limit, and frees capacity as entries are consumed.
func TestStorePendingRegistration_IsBounded(t *testing.T) {
	setupPendingStoreEnv(t)
	auth.ResetPendingStoreForTesting()
	t.Cleanup(auth.ResetPendingStoreForTesting)

	account := testutil.NewAccountNumber(t)
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
	if _, err := auth.GetPendingRegistration(last); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := auth.StorePendingRegistration(overflow, account); err != nil {
		t.Fatalf("freed capacity not reusable: %v", err)
	}
}
