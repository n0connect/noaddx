package encryption

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"noaddx/internal/encryption"
	"noaddx/tests/testutil"
)

// masterKeyHex draws a fresh 256-bit master key from the CSPRNG, as `make setup` does.
func masterKeyHex(t *testing.T) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(testutil.NewAuthKey(t))
	if err != nil || len(raw) != 32 {
		t.Fatalf("key material: %v", err)
	}
	return hex.EncodeToString(raw)
}

func initKeys(t *testing.T, activeID, active, old string) error {
	t.Helper()
	t.Setenv("MASTER_KEY_ACTIVE_ID", activeID)
	t.Setenv("MASTER_KEY_ACTIVE", active)
	t.Setenv("MASTER_KEY_OLD", old)
	encryption.ResetMasterKeysForTesting()
	t.Cleanup(encryption.ResetMasterKeysForTesting)
	return encryption.InitMasterKeys()
}

// Rotation decrypts by the key id stored next to each record; nothing is trial-decrypted.
func TestMasterKeyRotation_DecryptsByStoredKeyID(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	oldKey, newKey := masterKeyHex(t), masterKeyHex(t)
	if err := initKeys(t, "k1", oldKey, ""); err != nil {
		t.Fatalf("InitMasterKeys: %v", err)
	}
	ciphertext, err := encryption.EncryptWithMasterKey("rotation-test")
	if err != nil {
		t.Fatalf("EncryptWithMasterKey: %v", err)
	}

	if err := initKeys(t, "k2", newKey, "k1:"+oldKey); err != nil {
		t.Fatalf("InitMasterKeys after rotation: %v", err)
	}
	plaintext, err := encryption.DecryptWithMasterKey(ciphertext, "k1")
	if err != nil || plaintext != "rotation-test" {
		t.Fatalf("decrypt by old key id = %q, %v", plaintext, err)
	}
	for _, id := range []string{"", "k2", "k3"} {
		if _, err := encryption.DecryptWithMasterKey(ciphertext, id); err == nil {
			t.Errorf("record decrypted under key id %q", id)
		}
	}
}

// Only full-entropy key material is accepted: 32 bytes as hex or base64, never raw text.
func TestInitMasterKeys_RejectsLowEntropyOrMalformedKeys(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	good := masterKeyHex(t)
	cases := map[string][3]string{
		"32-character passphrase": {"k1", "correct horse battery staple!!!!", ""},
		"short hex":               {"k1", good[:62], ""},
		"long hex":                {"k1", good + "00", ""},
		"old entry without id":    {"k1", good, masterKeyHex(t)},
		"old entry with bad key":  {"k1", good, "k0:" + good[:40]},
		"old id equals active id": {"k1", good, "k1:" + masterKeyHex(t)},
		"duplicate old ids":       {"k3", good, "k1:" + masterKeyHex(t) + ",k1:" + masterKeyHex(t)},
		"old key equals active":   {"k2", good, "k1:" + good},
		"key id with separator":   {"k:1", good, ""},
		"oversized key id":        {strings.Repeat("k", 33), good, ""},
	}
	for name, c := range cases {
		if err := initKeys(t, c[0], c[1], c[2]); err == nil {
			t.Errorf("%s: InitMasterKeys accepted it", name)
		}
	}

	raw, _ := hex.DecodeString(good)
	if err := initKeys(t, "k1", base64.StdEncoding.EncodeToString(raw), "k0:"+masterKeyHex(t)); err != nil {
		t.Fatalf("base64 active key with a valid old key rejected: %v", err)
	}
}
