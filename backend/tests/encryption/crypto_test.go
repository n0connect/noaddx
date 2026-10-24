package encryption

import (
	"encoding/hex"
	"strings"
	"testing"

	"noaddress/internal/encryption"
	"noaddress/tests/testutil"
)

func TestEncryptWithAAD_Basic(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	// Generate user key
	userKey, err := encryption.GenerateUserAESKey()
	if err != nil {
		t.Fatalf("GenerateUserAESKey() failed: %v", err)
	}

	if len(userKey) != 32 {
		t.Errorf("GenerateUserAESKey() length = %d, want 32", len(userKey))
	}

	// Test data
	plaintext := "Y7KAl2oV4VL5Ox6nNgvQIcD4jXZK4scXV2k7WwsA2ms"
	userUUID := testutil.NewInternalID(t)
	recordID := testutil.NewRecordID(t)
	field := encryption.FieldPeerPublicKey
	purpose := encryption.PurposeStoredRecord

	// Build AAD
	aad := encryption.BuildAAD(userUUID, recordID, field, purpose)

	// Encrypt
	ciphertext, err := encryption.EncryptWithAAD(plaintext, userKey, aad)
	if err != nil {
		t.Fatalf("EncryptWithAAD() failed: %v", err)
	}

	if ciphertext == "" {
		t.Error("EncryptWithAAD() returned empty ciphertext")
	}

	// Decrypt
	decrypted, err := encryption.DecryptWithAAD(ciphertext, userKey, aad)
	if err != nil {
		t.Fatalf("DecryptWithAAD() failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("DecryptWithAAD() = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptWithAAD_InvalidAADLength(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	userKey, err := encryption.GenerateUserAESKey()
	if err != nil {
		t.Fatalf("GenerateUserAESKey() failed: %v", err)
	}

	badAAD := make([]byte, encryption.AADLength-1)
	_, err = encryption.EncryptWithAAD("data", userKey, badAAD)
	if err == nil {
		t.Error("EncryptWithAAD() with invalid AAD length should fail")
	}
}

func TestEncryptWithAAD_CrossUserSwap_ShouldFail(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	// Generate two different user keys
	userKey1, err := encryption.GenerateUserAESKey()
	if err != nil {
		t.Fatalf("GenerateUserAESKey() failed: %v", err)
	}

	userKey2, err := encryption.GenerateUserAESKey()
	if err != nil {
		t.Fatalf("GenerateUserAESKey() failed: %v", err)
	}

	// Test data
	plaintext := "user1 peer key"
	userUUID1 := "user1-uuid-123456789012"
	userUUID2 := "user2-uuid-987654321098"
	recordID := testutil.NewRecordID(t)
	field := encryption.FieldPeerPublicKey
	purpose := encryption.PurposeStoredRecord

	// Build AAD for user1
	aad1 := encryption.BuildAAD(userUUID1, recordID, field, purpose)

	// Encrypt with user1's key and AAD
	ciphertext, err := encryption.EncryptWithAAD(plaintext, userKey1, aad1)
	if err != nil {
		t.Fatalf("EncryptWithAAD() failed: %v", err)
	}

	// Try to decrypt with user2's key (should fail)
	aad2 := encryption.BuildAAD(userUUID2, recordID, field, purpose)
	_, err = encryption.DecryptWithAAD(ciphertext, userKey2, aad2)
	if err == nil {
		t.Error("DecryptWithAAD() with different user's key should have failed (AAD mismatch)")
	}

	// Try to decrypt with user1's key but user2's AAD (should fail)
	_, err = encryption.DecryptWithAAD(ciphertext, userKey1, aad2)
	if err == nil {
		t.Error("DecryptWithAAD() with different AAD should have failed (cross-user data swap protection)")
	}

	// Try to decrypt with user2's key and user1's AAD (should fail)
	_, err = encryption.DecryptWithAAD(ciphertext, userKey2, aad1)
	if err == nil {
		t.Error("DecryptWithAAD() with wrong key should have failed")
	}
}

func TestEncryptWithAAD_DifferentFields_ShouldFail(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	userKey, err := encryption.GenerateUserAESKey()
	if err != nil {
		t.Fatalf("GenerateUserAESKey() failed: %v", err)
	}

	plaintext := "Test data"
	userUUID := testutil.NewInternalID(t)
	recordID := testutil.NewRecordID(t)
	purpose := encryption.PurposeStoredRecord

	// Encrypt with FieldTitle
	aadTitle := encryption.BuildAAD(userUUID, recordID, encryption.FieldPeerPublicKey, purpose)
	ciphertext, err := encryption.EncryptWithAAD(plaintext, userKey, aadTitle)
	if err != nil {
		t.Fatalf("EncryptWithAAD() failed: %v", err)
	}

	// Try to decrypt with FieldTags AAD (should fail)
	aadTags := encryption.BuildAAD(userUUID, recordID, encryption.FieldInviteCreator, purpose)
	_, err = encryption.DecryptWithAAD(ciphertext, userKey, aadTags)
	if err == nil {
		t.Error("DecryptWithAAD() with different field AAD should have failed")
	}
}

func TestEncryptWithAAD_DifferentRecordIDs_ShouldFail(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	userKey, err := encryption.GenerateUserAESKey()
	if err != nil {
		t.Fatalf("GenerateUserAESKey() failed: %v", err)
	}

	plaintext := "Test data"
	userUUID := testutil.NewInternalID(t)
	recordID1 := testutil.NewRecordID(t)
	recordID2 := testutil.NewRecordID(t)
	field := encryption.FieldPeerPublicKey
	purpose := encryption.PurposeStoredRecord

	// Encrypt with recordID1
	aad1 := encryption.BuildAAD(userUUID, recordID1, field, purpose)
	ciphertext, err := encryption.EncryptWithAAD(plaintext, userKey, aad1)
	if err != nil {
		t.Fatalf("EncryptWithAAD() failed: %v", err)
	}

	// Try to decrypt with recordID2 AAD (should fail)
	aad2 := encryption.BuildAAD(userUUID, recordID2, field, purpose)
	_, err = encryption.DecryptWithAAD(ciphertext, userKey, aad2)
	if err == nil {
		t.Error("DecryptWithAAD() with different record ID AAD should have failed")
	}
}

func TestEncryptWithMasterKey(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	// The master key comes from the environment SetupTestEnv generated; no database involved
	encryption.ResetMasterKeysForTesting()
	defer encryption.ResetMasterKeysForTesting()

	userKey, err := encryption.GenerateUserAESKey()
	if err != nil {
		t.Fatalf("GenerateUserAESKey() failed: %v", err)
	}
	userKeyHex := hex.EncodeToString(userKey)

	encrypted, err := encryption.EncryptWithMasterKey(userKeyHex)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey() failed: %v", err)
	}
	if encrypted == "" || strings.Contains(encrypted, userKeyHex) {
		t.Fatal("EncryptWithMasterKey() returned an empty or plaintext-bearing result")
	}

	decryptedBytes, err := encryption.DecryptUserKey(encrypted, encryption.ActiveMasterKeyID())
	if err != nil {
		t.Fatalf("DecryptUserKey() failed: %v", err)
	}
	if hex.EncodeToString(decryptedBytes) != userKeyHex {
		t.Error("DecryptUserKey() did not return the wrapped key")
	}
	if _, err := encryption.DecryptUserKey(encrypted, "unknown-key-id"); err == nil {
		t.Error("DecryptUserKey() accepted an unknown master key id")
	}
}

func TestEncryptWithAAD_EmptyPlaintext(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	userKey, err := encryption.GenerateUserAESKey()
	if err != nil {
		t.Fatalf("GenerateUserAESKey() failed: %v", err)
	}

	plaintext := ""
	userUUID := testutil.NewInternalID(t)
	recordID := testutil.NewRecordID(t)
	aad := encryption.BuildAAD(userUUID, recordID, encryption.FieldPeerPublicKey, encryption.PurposeStoredRecord)

	// Encrypt empty string
	ciphertext, err := encryption.EncryptWithAAD(plaintext, userKey, aad)
	if err != nil {
		t.Fatalf("EncryptWithAAD() with empty plaintext failed: %v", err)
	}

	// Decrypt
	decrypted, err := encryption.DecryptWithAAD(ciphertext, userKey, aad)
	if err != nil {
		t.Fatalf("DecryptWithAAD() failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("DecryptWithAAD() = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptWithAAD_LongPlaintext(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	userKey, err := encryption.GenerateUserAESKey()
	if err != nil {
		t.Fatalf("GenerateUserAESKey() failed: %v", err)
	}

	// Create a long plaintext (1000 characters)
	plaintext := ""
	for i := 0; i < 1000; i++ {
		plaintext += "A"
	}

	userUUID := testutil.NewInternalID(t)
	recordID := testutil.NewRecordID(t)
	aad := encryption.BuildAAD(userUUID, recordID, encryption.FieldPeerPublicKey, encryption.PurposeStoredRecord)

	// Encrypt
	ciphertext, err := encryption.EncryptWithAAD(plaintext, userKey, aad)
	if err != nil {
		t.Fatalf("EncryptWithAAD() with long plaintext failed: %v", err)
	}

	// Decrypt
	decrypted, err := encryption.DecryptWithAAD(ciphertext, userKey, aad)
	if err != nil {
		t.Fatalf("DecryptWithAAD() failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("DecryptWithAAD() length = %d, want %d", len(decrypted), len(plaintext))
	}
}
