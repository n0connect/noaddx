// Package cryptoengine is the single entry point for every cryptographic primitive the
// backend uses. Two interchangeable engines implement it:
//
//   - openssl: libcrypto >= 3.2 through cgo  (build tag `openssl`, CGO_ENABLED=1)
//   - native:  the Go standard library       (default build, CGO_ENABLED=0)
//
// Both produce byte-identical results and accept and refuse exactly the same inputs: input
// validation lives here, once, and the equivalence package compares the engines directly.
package cryptoengine

import "errors"

// engine is what both implementations provide. Inputs are validated before they get here.
type engine interface {
	Name() string
	Version() string
	Check() error
	Random(out []byte) error
	SHA256(data []byte) ([]byte, error)
	HMACSHA256(key, data []byte) ([]byte, error)
	Equal(a, b []byte) bool
	Argon2id(password, salt []byte, timeCost, memoryKiB, lanes, keyLen uint32) ([]byte, error)
	HKDFSHA256(ikm, salt, info []byte, length int) ([]byte, error)
	SealAES256GCM(key, nonce, plaintext, aad []byte) ([]byte, error)
	OpenAES256GCM(key, nonce, sealed, aad []byte) ([]byte, error)
	X25519PublicKey(privateKey []byte) ([]byte, error)
	X25519(privateKey, peerPublicKey []byte) ([]byte, error)
}

var (
	errInvalidInput = errors.New("cryptoengine: invalid input")
	errDecrypt      = errors.New("decryption failed")
)

// Argon2id limits (RFC 9106): at least 8 KiB of memory per lane, 1-255 lanes, 4+ byte tags.
const (
	minArgon2Lanes    = 1
	maxArgon2Lanes    = 255
	minArgon2KeyBytes = 4
)

// EngineName reports the engine compiled into this binary ("openssl" or "native").
func EngineName() string { return active.Name() }

// EngineVersion reports the engine's library version (OpenSSL release or Go toolchain).
func EngineVersion() string { return active.Version() }

// RandomBytes returns size bytes from the engine's CSPRNG (RULES.md §1.3).
func RandomBytes(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errInvalidInput
	}
	out := make([]byte, size)
	if err := active.Random(out); err != nil {
		return nil, err
	}
	return out, nil
}

// SHA256 computes the SHA-256 digest of data.
func SHA256(data []byte) ([]byte, error) {
	return active.SHA256(data)
}

// HMACSHA256 computes HMAC-SHA256 of data under a non-empty key.
func HMACSHA256(key, data []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errInvalidInput
	}
	return active.HMACSHA256(key, data)
}

// ConstantTimeEqual compares two byte slices in constant time (RULES.md §16.2).
func ConstantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	return active.Equal(a, b)
}

// Argon2idKey derives keyLen bytes with Argon2id v1.3 (RFC 9106). Out-of-range parameters
// are refused rather than adjusted, so both engines always run the same computation.
func Argon2idKey(password, salt []byte, iterations, memory, lanes, keyLen uint32) ([]byte, error) {
	if len(password) == 0 || len(salt) == 0 || iterations == 0 || keyLen < minArgon2KeyBytes ||
		lanes < minArgon2Lanes || lanes > maxArgon2Lanes || memory < 8*lanes {
		return nil, errInvalidInput
	}
	return active.Argon2id(password, salt, iterations, memory, lanes, keyLen)
}

// HKDFSHA256 derives outLen bytes with HKDF-SHA256 (RFC 5869).
func HKDFSHA256(ikm, salt, info []byte, outLen int) ([]byte, error) {
	if len(ikm) == 0 || outLen <= 0 || outLen > HKDFMaxOutput {
		return nil, errInvalidInput
	}
	return active.HKDFSHA256(ikm, salt, info, outLen)
}

// SealAES256GCM encrypts under an explicit 12-byte nonce and returns ciphertext || tag.
// Nonces must never repeat under a key: use EncryptAES256GCM unless the nonce is managed.
func SealAES256GCM(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(key) != AES256KeySize || len(nonce) != GCMNonceSize {
		return nil, errInvalidInput
	}
	return active.SealAES256GCM(key, nonce, plaintext, aad)
}

// EncryptAES256GCM encrypts with a fresh random nonce: nonce(12) || ciphertext || tag(16).
func EncryptAES256GCM(key, plaintext, aad []byte) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, errInvalidInput
	}
	nonce, err := RandomBytes(GCMNonceSize)
	if err != nil {
		return nil, err
	}
	sealed, err := active.SealAES256GCM(key, nonce, plaintext, aad)
	if err != nil {
		return nil, err
	}
	return append(nonce, sealed...), nil
}

// DecryptAES256GCM authenticates and decrypts nonce(12) || ciphertext || tag(16).
// Every failure reads the same, so callers cannot learn why (RULES.md §16.1).
func DecryptAES256GCM(key, data, aad []byte) ([]byte, error) {
	if len(key) != AES256KeySize || len(data) < GCMNonceSize+GCMTagSize {
		return nil, errInvalidInput
	}
	plaintext, err := active.OpenAES256GCM(key, data[:GCMNonceSize], data[GCMNonceSize:], aad)
	if err != nil {
		return nil, errDecrypt
	}
	return plaintext, nil
}

// X25519PublicKey returns the X25519 public key for a 32-byte private scalar.
func X25519PublicKey(privateKey []byte) ([]byte, error) {
	if len(privateKey) != X25519KeySize {
		return nil, errInvalidInput
	}
	return active.X25519PublicKey(privateKey)
}

// X25519SharedSecret computes the X25519 shared secret; a low-order peer point (all-zero
// result) is refused by both engines.
func X25519SharedSecret(privateKey, peerPublicKey []byte) ([]byte, error) {
	if len(privateKey) != X25519KeySize || len(peerPublicKey) != X25519KeySize {
		return nil, errInvalidInput
	}
	return active.X25519(privateKey, peerPublicKey)
}
