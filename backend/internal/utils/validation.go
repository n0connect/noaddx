package utils

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"noaddress/internal/config"
	"noaddress/internal/cryptoengine"

	"github.com/google/uuid"
)

var validationLogger = NewLogger("VALIDATION")

// ========================================
// INPUT VALIDATION - WHITELIST APPROACH
// ========================================
// Security Strategy: the server never sees message plaintext (E2E), so every
// client field is a fixed-shape token (UUID, base64url key, ciphertext) and is
// whitelisted by exact format before use. Frontend renders text via textContent.

var (
	// AccountNumber: Base64URL (no padding) - length derived from byte size
	// Base64URL uses A-Z, a-z, 0-9, _, - (RFC 4648 Section 5)
	accountNumberBytes   = 32
	accountNumberLength  = base64.RawURLEncoding.EncodedLen(accountNumberBytes)
	accountNumberPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

const (
	// Invite tokens carry 128 bits of CSPRNG output
	InviteTokenBytes = 16
	// AES-256-GCM framing: nonce(12) || ciphertext(>=1) || tag(16)
	minCiphertextBytes = cryptoengine.GCMNonceSize + 1 + cryptoengine.GCMTagSize
)

func internalIDLength() (int, error) {
	length := config.GetInternalIDLength()
	if length <= 0 {
		return 0, fmt.Errorf("INTERNAL_ID_LENGTH not configured")
	}
	return length, nil
}

func ValidateUUID(uuid string) bool {
	length, err := internalIDLength()
	if err != nil {
		validationLogger.LogError("ValidateUUID", err)
		return false
	}
	if len(uuid) != length {
		return false
	}
	for i := 0; i < len(uuid); i++ {
		if !isAlphaNumeric(uuid[i]) {
			return false
		}
	}
	return true
}

func GenerateInternalID() (string, error) {
	length, err := internalIDLength()
	if err != nil {
		return "", err
	}

	randomBytes, err := cryptoengine.RandomBytes(length)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// 62 characters: A-Z, a-z, 0-9
	alphanumeric := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)

	for i := 0; i < length; i++ {
		// Rejection sampling for uniform distribution
		// 256 % 62 = 8, reject values >= 248 to avoid bias
		b := randomBytes[i]
		for b >= 248 {
			extraByte, err := cryptoengine.RandomBytes(1)
			if err != nil {
				return "", fmt.Errorf("failed to generate random bytes: %w", err)
			}
			b = extraByte[0]
		}
		result[i] = alphanumeric[b%62]
	}

	validationLogger.Debug("GenerateInternalID: generated alphanumeric UUID with CSPRNG, length=%d", length)
	return string(result), nil
}

// GenerateAccountNumber generates a 256-bit (32 bytes) CSPRNG account number
// Returns base64url-encoded string (43 characters, no padding)
func GenerateAccountNumber() (string, error) {
	// Generate exactly 32 bytes (256 bits) of CSPRNG
	randomBytes, err := cryptoengine.RandomBytes(accountNumberBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Base64URL encoding (RFC 4648 Section 5, no padding)
	encoded := base64.RawURLEncoding.EncodeToString(randomBytes)

	validationLogger.Debug("GenerateAccountNumber: generated 43-char base64url account number (256-bit CSPRNG)")
	return encoded, nil
}

// ValidateAccountNumber validates account number format
// Must be exactly 43 base64url characters (A-Z, a-z, 0-9, _, -)
func ValidateAccountNumber(accountNumber string) bool {
	if len(accountNumber) != accountNumberLength {
		return false
	}
	return accountNumberPattern.MatchString(accountNumber)
}

// MaskAccountNumber masks account number for logging (shows only last 4 characters)
// Example: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" -> "****************************567"
func MaskAccountNumber(accountNumber string) string {
	if len(accountNumber) <= 4 {
		return "****"
	}
	return strings.Repeat("*", len(accountNumber)-4) + accountNumber[len(accountNumber)-4:]
}

// ParseCanonicalUUIDv4 accepts only lowercase, hyphenated, version-4 UUIDs.
// Rejecting alternate spellings keeps AAD binding and DB keys unambiguous.
func ParseCanonicalUUIDv4(raw string) (uuid.UUID, bool) {
	if len(raw) != 36 {
		return uuid.Nil, false
	}
	parsed, err := uuid.Parse(raw)
	if err != nil || parsed.Version() != 4 || parsed.Variant() != uuid.RFC4122 || parsed.String() != raw {
		return uuid.Nil, false
	}
	return parsed, true
}

// ValidateInviteToken whitelists a base64url (no padding) 16-byte invite token.
func ValidateInviteToken(token string) ([]byte, bool) {
	if len(token) != base64.RawURLEncoding.EncodedLen(InviteTokenBytes) || !accountNumberPattern.MatchString(token) {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != InviteTokenBytes {
		return nil, false
	}
	return raw, true
}

// ValidateCiphertext whitelists an opaque base64url E2E ciphertext within size bounds.
func ValidateCiphertext(encoded string) bool {
	maxBytes := config.GetMaxMessageBytes()
	if maxBytes <= 0 {
		validationLogger.Error("ValidateCiphertext: MAX_MESSAGE_BYTES not configured")
		return false
	}
	if len(encoded) < base64.RawURLEncoding.EncodedLen(minCiphertextBytes) ||
		len(encoded) > base64.RawURLEncoding.EncodedLen(maxBytes) ||
		!accountNumberPattern.MatchString(encoded) {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	return err == nil && len(raw) >= minCiphertextBytes && len(raw) <= maxBytes
}

func isAlphaNumeric(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}
