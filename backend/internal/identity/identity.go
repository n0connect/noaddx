// Package identity derives every account-scoped value noaddress needs from a single
// AccountNumber, with strict domain separation. The browser runs the same
// derivations (frontend/js/crypto.js); both sides MUST stay byte-for-byte equal.
package identity

import (
	"encoding/base64"
	"encoding/hex"
	"errors"

	"noaddress/internal/config"
	"noaddress/internal/cryptoengine"
	"noaddress/internal/utils"
)

const (
	// KeySize is the size of every derived secret and of X25519 public keys.
	KeySize = 32
	// EncodedKeyLength is the base64url (no padding) length of a 32-byte value.
	EncodedKeyLength = 43

	derivationSalt   = "noaddress.v1"
	infoAuthKey      = "noaddress/auth"
	infoIdentityKey  = "noaddress/identity/x25519"
	infoMemberTag    = "noaddress/member-tag"
	infoInviteLookup = "noaddress/invite-lookup"
)

var (
	ErrInvalidAccountNumber = errors.New("invalid account number")
	ErrInvalidKey           = errors.New("invalid key")
	ErrPepperNotConfigured  = errors.New("ACCOUNT_LOOKUP_PEPPER not configured")
)

func decodeKey(encoded string) ([]byte, error) {
	if len(encoded) != EncodedKeyLength {
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

// DerivePublicKey returns the account's X25519 identity public key (base64url).
// The matching private scalar is re-derived client-side and never stored anywhere.
func DerivePublicKey(accountNumber string) (string, error) {
	seed, err := deriveFromAccount(accountNumber, infoIdentityKey)
	if err != nil {
		return "", err
	}
	pub, err := cryptoengine.X25519PublicKey(seed)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(pub), nil
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

// MemberTag is the pseudonym a user carries inside conversations, invites and events.
// Without the pepper, a database dump cannot link conversation rows back to users.
func MemberTag(userUUID string) (string, error) {
	if !utils.ValidateUUID(userUUID) {
		return "", ErrInvalidKey
	}
	return keyedTag(infoMemberTag, []byte(userUUID))
}

// InviteLookup maps a raw invite token to its storage key; tokens are never stored.
func InviteLookup(rawToken []byte) (string, error) {
	if len(rawToken) == 0 {
		return "", ErrInvalidKey
	}
	return keyedTag(infoInviteLookup, rawToken)
}
