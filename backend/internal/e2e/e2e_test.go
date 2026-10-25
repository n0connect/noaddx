package e2e

import (
	"bytes"
	"encoding/base64"
	"testing"

	"noaddx/internal/identity"

	"github.com/google/uuid"
)

// Interop vectors: the same accounts, conversation and message as frontend/tests/crypto.test.mjs.
const (
	accountA      = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	accountB      = "HxwdHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA"
	vectorText    = "noaddx. interop ✓ <b>&"
	vectorSentAt  = int64(1729700000000)
	vectorCounter = int64(3)
	// Produced by frontend/js/crypto.js (A → B); Go must open it.
	browserCiphertext = "Fz7HARBe7PC_zNbd8K7FNWBckeuw0twbXi-lqQ9lUo0AvZW8tvWkJ7SMb5DnEUg5j_RD1BEcxRrkhPYOJbTK4W6cFHHb39CzI8aBMPd1vVwDzH_qpVIDC24Fq3_QLN23-miHnf9sS9GGKalP6ZCYrXIq6pNe_MheEsIAuHYfC5tZ9MW6r7-lrYJ-txuhgp2mFpwZ3BnPUysgMB96U2cnMFt7dgR_wKT-wUGEhept8tLZK9nkfOJCvnBqnp0rdU_GFtoqoL24iutPmRpuzo7mOrMI0fspRGhG2DaET59MM0XS-3W1hjf6XmFMgFUuwxHQNnJpv5vKTm2xxMaeKC9KkKjuV1K_MgxhsjgCyl9iZh_iKUXqLk5L-j3XsA8"
)

var (
	vectorConversation = uuid.MustParse("3b241101-e2bb-4255-8caf-4136c566a962")
	vectorMessage      = uuid.MustParse("a3f1c2d4-5b6e-4f70-8a91-b2c3d4e5f607")
)

type party struct {
	private []byte
	public  string
}

func load(t testing.TB, account string) party {
	t.Helper()
	priv, err := identity.DeriveIdentityPrivateKey(account)
	if err != nil {
		t.Fatalf("DeriveIdentityPrivateKey: %v", err)
	}
	pub, err := identity.DerivePublicKey(account)
	if err != nil {
		t.Fatalf("DerivePublicKey: %v", err)
	}
	return party{private: priv, public: pub}
}

func keys(t *testing.T) (party, party, []byte, []byte) {
	t.Helper()
	a, b := load(t, accountA), load(t, accountB)
	ab, err := ConversationKey(a.private, b.public, vectorConversation)
	if err != nil {
		t.Fatalf("ConversationKey(a,b): %v", err)
	}
	ba, err := ConversationKey(b.private, a.public, vectorConversation)
	if err != nil {
		t.Fatalf("ConversationKey(b,a): %v", err)
	}
	return a, b, ab, ba
}

func TestDecrypt_OpensBrowserCiphertext(t *testing.T) {
	a, _, _, ba := keys(t)
	msg, err := Decrypt(ba, vectorConversation, vectorMessage, a.public, browserCiphertext)
	if err != nil {
		t.Fatalf("Go could not open the browser's ciphertext: %v", err)
	}
	if msg.Text != vectorText || msg.SentAt != vectorSentAt || msg.Counter != vectorCounter {
		t.Fatalf("decrypted %+v", msg)
	}
}

func TestEncrypt_ProducesBrowserCompatibleCiphertext(t *testing.T) {
	a, _, ab, ba := keys(t)
	ct, err := Encrypt(ab, vectorConversation, vectorMessage, a.public, vectorText, vectorSentAt, vectorCounter)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(ct)
	if len(raw) != 12+256+16 {
		t.Fatalf("ciphertext is %d bytes, want one 256-byte padded block", len(raw))
	}
	msg, err := Decrypt(ba, vectorConversation, vectorMessage, a.public, ct)
	if err != nil || msg.Text != vectorText {
		t.Fatalf("round trip failed: %v %+v", err, msg)
	}
	t.Logf("go vector (paste into frontend/tests/crypto.test.mjs when the format changes): %s", ct)
}

func TestDecrypt_RejectsEveryBinding(t *testing.T) {
	a, b, _, ba := keys(t)
	other := uuid.MustParse("4c352212-f3cc-4366-9dbf-5247d677b073")
	cases := map[string]func() error{
		"wrong message id": func() error {
			_, err := Decrypt(ba, vectorConversation, other, a.public, browserCiphertext)
			return err
		},
		"reflected sender": func() error {
			_, err := Decrypt(ba, vectorConversation, vectorMessage, b.public, browserCiphertext)
			return err
		},
		"wrong conversation": func() error {
			key, err := ConversationKey(b.private, a.public, other)
			if err != nil {
				return nil
			}
			_, err = Decrypt(key, other, vectorMessage, a.public, browserCiphertext)
			return err
		},
		"flipped bit": func() error {
			raw, _ := base64.RawURLEncoding.DecodeString(browserCiphertext)
			raw[20] ^= 1
			_, err := Decrypt(ba, vectorConversation, vectorMessage, a.public, base64.RawURLEncoding.EncodeToString(raw))
			return err
		},
		"truncated": func() error {
			_, err := Decrypt(ba, vectorConversation, vectorMessage, a.public, browserCiphertext[:60])
			return err
		},
	}
	for name, attempt := range cases {
		if attempt() == nil {
			t.Errorf("%s: tampered message was accepted", name)
		}
	}
}

func TestEncrypt_RejectsInvalidArguments(t *testing.T) {
	a, _, ab, _ := keys(t)
	big := make([]byte, maxPayloadBytes)
	for i := range big {
		big[i] = 'x'
	}
	if _, err := Encrypt(ab, vectorConversation, vectorMessage, a.public, string(big), vectorSentAt, 1); err == nil {
		t.Error("payload above the limit was encrypted")
	}
	if _, err := Encrypt(ab, vectorConversation, vectorMessage, a.public, "hi", vectorSentAt, 0); err == nil {
		t.Error("counter 0 was accepted")
	}
	v1 := uuid.Must(uuid.NewUUID()) // time-based: not the random v4 the protocol requires
	if _, err := Encrypt(ab, vectorConversation, v1, a.public, "hi", vectorSentAt, 1); err == nil {
		t.Error("a non-v4 message id was accepted")
	}
}

// Ciphertext length reveals only a power-of-two size class: 256, 512, 1024, 2048 or 4096
// bytes of framed plaintext. A larger payload is refused rather than given a sixth class.
func TestFrame_PowerOfTwoBuckets(t *testing.T) {
	cases := map[int]int{1: 256, 254: 256, 255: 512, 510: 512, 511: 1024, 2046: 2048, 2047: 4096, 4094: 4096}
	for payload, want := range cases {
		framed, err := frame(bytes.Repeat([]byte{'x'}, payload))
		if err != nil || len(framed) != want {
			t.Errorf("payload %d: frame of %d bytes (err %v), want %d", payload, len(framed), err, want)
		}
	}
	if _, err := frame(bytes.Repeat([]byte{'x'}, 4095)); err == nil {
		t.Error("a 4095-byte payload was framed")
	}
}

// Reading stays lenient: frames written before the buckets (any multiple of 256, payloads up
// to 6000 bytes) still open, so stored messages survive the change.
func TestUnframe_ReadsFramesFromBeforeTheBuckets(t *testing.T) {
	body := bytes.Repeat([]byte{'x'}, 5000)
	framed := make([]byte, 20*256)
	framed[0], framed[1] = byte(len(body)>>8), byte(len(body))
	copy(framed[2:], body)
	got, err := unframe(framed)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("legacy frame did not open: %v", err)
	}
}
