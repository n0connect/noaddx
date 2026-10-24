package cryptoengine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// RandomBytes generates cryptographically secure random bytes using crypto/rand.
// Complies with RULES.md §1.3 (uses platform CSPRNG).
func RandomBytes(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("invalid size")
	}
	out := make([]byte, size)
	_, err := rand.Read(out)
	if err != nil {
		return nil, fmt.Errorf("rand.Read failed: %w", err)
	}
	return out, nil
}

// SHA256 computes SHA-256 hash of data using crypto/sha256.
// Complies with RULES.md §1.4 (SHA-256 hashing).
func SHA256(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return hash[:], nil
}

// HMACSHA256 computes HMAC-SHA256 of data with given key.
// Complies with RULES.md §1.4 (SHA-256 for HMAC).
func HMACSHA256(key, data []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("empty key")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// ConstantTimeEqual performs constant-time comparison of two byte slices.
// Complies with RULES.md §16.2 (constant-time operations on secrets).
func ConstantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Argon2idKey derives a key using Argon2id algorithm.
// Complies with RULES.md §1.2 (Argon2id for key derivation).
//
// Parameters:
//   - password: Input password/passphrase
//   - salt: Cryptographic salt (should be random, minimum 16 bytes)
//   - iterations: Time cost (number of iterations)
//   - memory: Memory cost in KiB
//   - lanes: Parallelism degree (threads)
//   - keyLen: Desired output key length in bytes
//
// Uses Argon2id version 1.3 (RFC 9106).
func Argon2idKey(password, salt []byte, iterations, memory, lanes, keyLen uint32) ([]byte, error) {
	if len(password) == 0 || len(salt) == 0 {
		return nil, fmt.Errorf("invalid input")
	}
	if keyLen == 0 {
		return nil, fmt.Errorf("invalid key length")
	}

	// golang.org/x/crypto/argon2 signature:
	// IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte
	// Note: lanes parameter maps to threads parameter
	key := argon2.IDKey(password, salt, iterations, memory, uint8(lanes), keyLen)
	return key, nil
}

// EncryptAES256GCM encrypts plaintext using AES-256-GCM with optional AAD.
// Complies with RULES.md §1.4 (AES-256-GCM for symmetric encryption).
//
// Output format: nonce(12 bytes) || ciphertext || tag(16 bytes)
//
// Parameters:
//   - key: 32-byte AES-256 key
//   - plaintext: Data to encrypt (can be empty)
//   - aad: Additional Authenticated Data (can be empty/nil)
//
// Returns encrypted data or error.
func EncryptAES256GCM(key, plaintext, aad []byte) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, fmt.Errorf("invalid key length")
	}

	// Generate random 12-byte nonce (RULES.md §1.3)
	nonce, err := RandomBytes(GCMNonceSize)
	if err != nil {
		return nil, err
	}

	// Create AES-256 cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher failed: %w", err)
	}

	// Create GCM mode (default tag size is 16 bytes)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM failed: %w", err)
	}

	// Encrypt: gcm.Seal returns ciphertext+tag appended
	ciphertextWithTag := gcm.Seal(nil, nonce, plaintext, aad)

	// Build output: nonce || ciphertext || tag
	// Note: gcm.Seal already appends tag, so ciphertextWithTag = ciphertext+tag
	out := make([]byte, 0, len(nonce)+len(ciphertextWithTag))
	out = append(out, nonce...)
	out = append(out, ciphertextWithTag...)
	return out, nil
}

// DecryptAES256GCM decrypts AES-256-GCM ciphertext with optional AAD verification.
// Complies with RULES.md §1.4 (AES-256-GCM for symmetric encryption).
//
// Input format: nonce(12 bytes) || ciphertext || tag(16 bytes)
//
// Parameters:
//   - key: 32-byte AES-256 key
//   - data: Encrypted data (nonce+ciphertext+tag)
//   - aad: Additional Authenticated Data (must match encryption AAD)
//
// Returns decrypted plaintext or error on authentication failure.
func DecryptAES256GCM(key, data, aad []byte) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, fmt.Errorf("invalid key length")
	}
	if len(data) < GCMNonceSize+GCMTagSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Parse input: nonce || ciphertext+tag
	nonce := data[:GCMNonceSize]
	ciphertextWithTag := data[GCMNonceSize:]

	// Create AES-256 cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher failed: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM failed: %w", err)
	}

	// Decrypt and verify: gcm.Open verifies tag automatically
	plaintext, err := gcm.Open(nil, nonce, ciphertextWithTag, aad)
	if err != nil {
		// Generic error message to prevent information leakage (RULES.md §16.1)
		return nil, fmt.Errorf("decryption failed")
	}

	return plaintext, nil
}

// HKDFSHA256 derives outLen bytes with HKDF-SHA256 (RFC 5869).
// Complies with RULES.md §1.4 (SHA-256 based KDF for domain-separated subkeys).
func HKDFSHA256(ikm, salt, info []byte, outLen int) ([]byte, error) {
	if len(ikm) == 0 {
		return nil, fmt.Errorf("invalid input")
	}
	if outLen <= 0 || outLen > HKDFMaxOutput {
		return nil, fmt.Errorf("invalid output length")
	}
	out := make([]byte, outLen)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, salt, info), out); err != nil {
		return nil, fmt.Errorf("hkdf failed: %w", err)
	}
	return out, nil
}

// X25519PublicKey returns the X25519 public key for a 32-byte private scalar.
// Clamping is applied by crypto/ecdh per RFC 7748, matching WebCrypto's behaviour.
// Complies with RULES.md §1.4 (X25519 key exchange).
func X25519PublicKey(privateKey []byte) ([]byte, error) {
	if len(privateKey) != X25519KeySize {
		return nil, fmt.Errorf("invalid key length")
	}
	priv, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("x25519 key failed: %w", err)
	}
	return priv.PublicKey().Bytes(), nil
}
