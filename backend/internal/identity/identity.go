// Package identity derives every account-scoped value noaddx needs from a single
// AccountNumber, with strict domain separation. The browser runs the same
// derivations (frontend/js/crypto.js); both sides MUST stay byte-for-byte equal.
package identity

import (
	"encoding/base64"
	"encoding/hex"
	"errors"

	"noaddx/internal/config"
	"noaddx/internal/cryptoengine"
	"noaddx/internal/utils"

	"github.com/google/uuid"
)

const (
	// KeySize is the size of every derived secret and of X25519 public keys.
	KeySize = 32
	// EncodedKeyLength is the base64url (no padding) length of a 32-byte value.
	EncodedKeyLength = 43

	derivationSalt      = "noaddx.v1"
	infoAuthKey         = "noaddx/auth"
	infoIdentityKey     = "noaddx/identity/x25519"
	infoStreamTag       = "noaddx/stream-tag"
	infoConversationTag = "noaddx/conversation-tag"
	infoInviteCreator   = "noaddx/invite-creator"
	infoInviteLookup    = "noaddx/invite-lookup"
)

var (
	ErrInvalidAccountNumber = errors.New("invalid account number")
	ErrInvalidKey           = errors.New("invalid key")
	ErrPepperNotConfigured  = errors.New("ACCOUNT_LOOKUP_PEPPER not configured")
)

func decodeKey(encoded string) ([]byte, error) {
	if len(encoded) != EncodedKeyLength || !utils.IsBase64URL(encoded) {
		return nil, ErrInvalidKey
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != KeySize {
		return nil, ErrInvalidKey
	}
	return raw, nil
}

func deriveFromAccount(accountNumber, info string) ([]byte, error) {
	if !utils.ValidateAccountNumber(accountNumber) {
		return nil, ErrInvalidAccountNumber
	}
	raw, err := decodeKey(accountNumber)
	if err != nil {
		return nil, ErrInvalidAccountNumber
	}
	return cryptoengine.HKDFSHA256(raw, []byte(derivationSalt), []byte(info), KeySize)
}

// DeriveAuthKey returns the login secret the browser sends instead of the AccountNumber.
// The server stores only HMAC/Argon2id of this value, so the AccountNumber itself
// (and the E2E identity derived from it) never reaches the server after signup.
func DeriveAuthKey(accountNumber string) (string, error) {
	key, err := deriveFromAccount(accountNumber, infoAuthKey)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(key), nil
}

// DeriveIdentityPrivateKey returns the account's 32-byte X25519 private scalar.
// The server calls it only inside DerivePublicKey at signup and never stores the result;
// clients (the browser, internal/e2e) use it to talk.
func DeriveIdentityPrivateKey(accountNumber string) ([]byte, error) {
	return deriveFromAccount(accountNumber, infoIdentityKey)
}

// DerivePublicKey returns the account's X25519 identity public key (base64url).
func DerivePublicKey(accountNumber string) (string, error) {
	seed, err := DeriveIdentityPrivateKey(accountNumber)
	if err != nil {
		return "", err
	}
	defer zero(seed)
	pub, err := cryptoengine.X25519PublicKey(seed)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(pub), nil
}

// zero wipes key material once it is no longer needed (RULES.md §1.2)
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ValidateEncodedKey whitelists a base64url-encoded 32-byte value (public key or auth key).
func ValidateEncodedKey(encoded string) bool {
	_, err := decodeKey(encoded)
	return err == nil
}

func pepperSubkey(info string) ([]byte, error) {
	pepper := config.GetAccountLookupPepper()
	if len(pepper) < KeySize {
		return nil, ErrPepperNotConfigured
	}
	return cryptoengine.HKDFSHA256(pepper, []byte(derivationSalt), []byte(info), KeySize)
}

func keyedTag(info string, data []byte) (string, error) {
	key, err := pepperSubkey(info)
	if err != nil {
		return "", err
	}
	mac, err := cryptoengine.HMACSHA256(key, data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(mac), nil
}

// Every pseudonym below is keyed by its own HKDF subkey of the pepper, so tags from
// different contexts can never be joined against each other.

// StreamTag addresses a user's live event streams. It exists only in memory, never on disk.
func StreamTag(userUUID string) (string, error) {
	if !utils.ValidateUUID(userUUID) {
		return "", ErrInvalidKey
	}
	return keyedTag(infoStreamTag, []byte(userUUID))
}

// ConversationTag is the pseudonym a user carries inside ONE conversation. It differs per
// conversation, so a database dump cannot tell that two conversations share a member.
func ConversationTag(userUUID string, conversationID uuid.UUID) (string, error) {
	if !utils.ValidateUUID(userUUID) || conversationID == uuid.Nil {
		return "", ErrInvalidKey
	}
	data := make([]byte, 0, len(userUUID)+len(conversationID))
	data = append(data, userUUID...)
	data = append(data, conversationID[:]...)
	return keyedTag(infoConversationTag, data)
}

// InviteCreatorTag groups a user's pending invites (for the active-invite cap) without
// being joinable with conversation or stream tags.
func InviteCreatorTag(userUUID string) (string, error) {
	if !utils.ValidateUUID(userUUID) {
		return "", ErrInvalidKey
	}
	return keyedTag(infoInviteCreator, []byte(userUUID))
}

// InviteLookup maps a raw invite token to its storage key; tokens are never stored.
func InviteLookup(rawToken []byte) (string, error) {
	if len(rawToken) == 0 {
		return "", ErrInvalidKey
	}
	return keyedTag(infoInviteLookup, rawToken)
}
