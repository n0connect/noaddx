package e2e

import (
	"testing"

	"noaddx/internal/utils"

	"github.com/google/uuid"
)

// Decrypt never panics, and whatever it accepts for this key and AAD is a genuine sealing of
// the vector message: a fuzzer cannot forge GCM, and non-canonical encodings are refused.
func FuzzDecrypt(f *testing.F) {
	a, b := load(f, accountA), load(f, accountB)
	key, err := ConversationKey(a.private, b.public, vectorConversation)
	if err != nil {
		f.Fatalf("ConversationKey: %v", err)
	}
	genuine, err := Encrypt(key, vectorConversation, vectorMessage, a.public, vectorText, vectorSentAt, vectorCounter)
	if err != nil {
		f.Fatalf("Encrypt: %v", err)
	}
	f.Add(genuine)
	f.Add(browserCiphertext)
	f.Add("")
	f.Add(genuine[:len(genuine)-1])
	f.Add(genuine + "A")

	f.Fuzz(func(t *testing.T, ciphertext string) {
		msg, err := Decrypt(key, vectorConversation, vectorMessage, a.public, ciphertext)
		if err != nil {
			return
		}
		if *msg != (Message{Text: vectorText, SentAt: vectorSentAt, Counter: vectorCounter}) {
			t.Fatalf("ciphertext %q decrypted to %+v", ciphertext, msg)
		}
		if !utils.IsBase64URL(ciphertext) {
			t.Fatalf("non-canonical ciphertext %q accepted", ciphertext)
		}
	})
}

// Mutating the message id or sender must fail authentication (they are bound by the AAD).
func FuzzDecryptBindings(f *testing.F) {
	a, b := load(f, accountA), load(f, accountB)
	key, err := ConversationKey(a.private, b.public, vectorConversation)
	if err != nil {
		f.Fatalf("ConversationKey: %v", err)
	}
	genuine, err := Encrypt(key, vectorConversation, vectorMessage, a.public, vectorText, vectorSentAt, vectorCounter)
	if err != nil {
		f.Fatalf("Encrypt: %v", err)
	}
	f.Add(vectorMessage.String(), a.public)
	f.Add(vectorMessage.String(), b.public)
	f.Add(uuid.New().String(), a.public)

	f.Fuzz(func(t *testing.T, messageID, sender string) {
		id, err := uuid.Parse(messageID)
		if err != nil {
			return
		}
		_, err = Decrypt(key, vectorConversation, id, sender, genuine)
		if err == nil && (id != vectorMessage || sender != a.public) {
			// the same bytes in a non-canonical spelling (e.g. an embedded CR) must not pass either
			t.Fatalf("ciphertext accepted under message %s sender %q", id, sender)
		}
	})
}
