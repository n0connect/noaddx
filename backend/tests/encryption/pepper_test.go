package encryption

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"noaddx/internal/config"
	"noaddx/tests/testutil"
)

// The lookup pepper must be real key material (hex or base64 of >= 32 bytes); a long
// human-chosen string is not accepted as raw bytes.
func TestAccountLookupPepper_OnlyFullEntropyEncodings(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	raw, err := base64.RawURLEncoding.DecodeString(testutil.NewAuthKey(t))
	if err != nil {
		t.Fatalf("key material: %v", err)
	}
	for name, value := range map[string]string{
		"hex":    hex.EncodeToString(raw),
		"base64": base64.StdEncoding.EncodeToString(raw),
	} {
		t.Setenv("ACCOUNT_LOOKUP_PEPPER", value)
		if got := config.GetAccountLookupPepper(); len(got) != 32 {
			t.Errorf("%s pepper decoded to %d bytes, want 32", name, len(got))
		}
	}
	for _, value := range []string{"this is a long but guessable pepper phrase!", hex.EncodeToString(raw[:16])} {
		t.Setenv("ACCOUNT_LOOKUP_PEPPER", value)
		if got := config.GetAccountLookupPepper(); got != nil {
			t.Errorf("pepper %q accepted as %d bytes", value, len(got))
		}
	}
}
