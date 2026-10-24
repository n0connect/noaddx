package identity

import (
	"encoding/hex"
	"testing"

	"noaddress/internal/cryptoengine"
	"noaddress/internal/identity"
	"noaddress/tests/testutil"

	"github.com/google/uuid"
)

// Fixed vector shared with frontend/tests/crypto.test.mjs (cross-implementation check).
const (
	vectorAccountNumber = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// RFC 5869 Appendix A.1
func TestHKDFSHA256_RFC5869_Case1(t *testing.T) {
	ikm := mustHex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustHex(t, "000102030405060708090a0b0c")
	info := mustHex(t, "f0f1f2f3f4f5f6f7f8f9")
	want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	got, err := cryptoengine.HKDFSHA256(ikm, salt, info, 42)
	if err != nil || hex.EncodeToString(got) != want {
		t.Fatalf("HKDF mismatch: got %x err=%v", got, err)
	}
}

// RFC 7748 §6.1 (Alice)
func TestX25519PublicKey_RFC7748(t *testing.T) {
	priv := mustHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	want := "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	got, err := cryptoengine.X25519PublicKey(priv)
	if err != nil || hex.EncodeToString(got) != want {
		t.Fatalf("X25519 mismatch: got %x err=%v", got, err)
	}
}

func TestDerivations_DeterministicAndSeparated(t *testing.T) {
	authKey, err := identity.DeriveAuthKey(vectorAccountNumber)
	if err != nil {
		t.Fatalf("DeriveAuthKey: %v", err)
	}
	authKey2, _ := identity.DeriveAuthKey(vectorAccountNumber)
	publicKey, err := identity.DerivePublicKey(vectorAccountNumber)
	if err != nil {
		t.Fatalf("DerivePublicKey: %v", err)
	}
	if authKey != authKey2 {
		t.Fatal("auth key derivation is not deterministic")
	}
	if authKey == vectorAccountNumber || authKey == publicKey {
		t.Fatal("derived values are not domain separated")
	}
	if !identity.ValidateEncodedKey(authKey) || !identity.ValidateEncodedKey(publicKey) {
		t.Fatal("derived values are not 32-byte base64url")
	}
	// Logged so the frontend vector can be refreshed if the scheme is ever versioned
	t.Logf("vector auth_key=%s public_key=%s", authKey, publicKey)
}

func TestDerivations_RejectMalformedAccountNumber(t *testing.T) {
	for _, bad := range []string{
		"",
		vectorAccountNumber[:42],
		vectorAccountNumber + "A",
		"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh+", // '+' outside base64url
		"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9", // non-canonical trailing bits
	} {
		if _, err := identity.DeriveAuthKey(bad); err == nil {
			t.Errorf("DeriveAuthKey accepted %q", bad)
		}
		if identity.ValidateEncodedKey(bad) {
			t.Errorf("ValidateEncodedKey accepted %q", bad)
		}
	}
}

func TestTags_PepperKeyedStableAndContextSeparated(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	user, other := testutil.NewInternalID(t), testutil.NewInternalID(t)
	conv1, conv2 := testutil.NewRecordID(t), testutil.NewRecordID(t)

	stream1, err := identity.StreamTag(user)
	if err != nil {
		t.Fatalf("StreamTag: %v", err)
	}
	stream2, _ := identity.StreamTag(user)
	streamOther, _ := identity.StreamTag(other)
	inviteTag, _ := identity.InviteCreatorTag(user)
	convTag1, _ := identity.ConversationTag(user, conv1)
	convTag1Again, _ := identity.ConversationTag(user, conv1)
	convTag2, _ := identity.ConversationTag(user, conv2)
	otherConvTag1, _ := identity.ConversationTag(other, conv1)

	if stream1 != stream2 || convTag1 != convTag1Again {
		t.Fatal("tags are not deterministic")
	}
	// Every pair below must differ: no tag can be joined with another context
	all := map[string]string{"stream": stream1, "streamOther": streamOther, "invite": inviteTag,
		"conv1": convTag1, "conv2": convTag2, "otherConv1": otherConvTag1}
	seen := map[string]string{}
	for name, tag := range all {
		if len(tag) != 64 {
			t.Fatalf("%s tag has length %d", name, len(tag))
		}
		if prev, dup := seen[tag]; dup {
			t.Fatalf("%s and %s share a tag", name, prev)
		}
		seen[tag] = name
	}

	if _, err := identity.StreamTag("not-a-valid-uuid"); err == nil {
		t.Fatal("StreamTag accepted malformed UUID")
	}
	if _, err := identity.ConversationTag(user, uuid.Nil); err == nil {
		t.Fatal("ConversationTag accepted the nil conversation id")
	}

	lookup, err := identity.InviteLookup(make([]byte, 16))
	if err != nil || len(lookup) != 64 || lookup == inviteTag {
		t.Fatalf("InviteLookup unexpected: %s err=%v", lookup, err)
	}
}
