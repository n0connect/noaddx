// Package native is the pure-Go crypto engine: the Go standard library (crypto/*) plus
// golang.org/x/crypto/argon2, CGO disabled. It is byte-for-byte interchangeable with the
// OpenSSL engine (noaddx/internal/cryptoengine/openssl); the equivalence package proves it.
//
// Inputs are validated by the engine-independent layer (noaddx/internal/cryptoengine)
// before they reach an engine, so both engines see exactly the same well-formed calls.
package native

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"runtime"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Engine implements the primitives with the Go standard library.
type Engine struct{}

var errFailed = errors.New("native: operation failed")

// Name identifies the engine.
func (Engine) Name() string { return "native" }

// Version reports the Go release whose crypto/* the binary was built with.
func (Engine) Version() string { return runtime.Version() }

// Check has nothing to verify at runtime: the implementation is compiled in.
func (Engine) Check() error { return nil }

// Random fills out from the platform CSPRNG.
func (Engine) Random(out []byte) error {
	if _, err := rand.Read(out); err != nil {
		return errFailed
	}
	return nil
}

// SHA256 returns the SHA-256 digest of data.
func (Engine) SHA256(data []byte) ([]byte, error) {
	sum := sha256.Sum256(data)
	return sum[:], nil
}

// HMACSHA256 returns HMAC-SHA256(key, data).
func (Engine) HMACSHA256(key, data []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// Equal compares two equal-length slices in constant time.
func (Engine) Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Argon2id derives keyLen bytes with Argon2id v1.3 (RFC 9106). memoryKiB >= 8*lanes and
// 1 <= lanes <= 255 are guaranteed by the caller.
func (Engine) Argon2id(password, salt []byte, timeCost, memoryKiB, lanes, keyLen uint32) ([]byte, error) {
	return argon2.IDKey(password, salt, timeCost, memoryKiB, uint8(lanes), keyLen), nil
}

// HKDFSHA256 derives length bytes with HKDF-SHA256 (RFC 5869).
func (Engine) HKDFSHA256(ikm, salt, info []byte, length int) ([]byte, error) {
	out := make([]byte, length)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, salt, info), out); err != nil {
		return nil, errFailed
	}
	return out, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errFailed
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errFailed
	}
	return gcm, nil
}

// SealAES256GCM returns ciphertext || 16-byte tag for the given 12-byte nonce.
func (Engine) SealAES256GCM(key, nonce, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

// OpenAES256GCM authenticates and decrypts ciphertext || tag.
func (Engine) OpenAES256GCM(key, nonce, sealed, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, errFailed
	}
	return plaintext, nil
}

// X25519PublicKey returns the public key of a 32-byte private scalar (clamped per RFC 7748).
func (Engine) X25519PublicKey(privateKey []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, errFailed
	}
	return priv.PublicKey().Bytes(), nil
}

// X25519 returns the shared secret; the all-zero result of a low-order peer is refused.
func (Engine) X25519(privateKey, peerPublicKey []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, errFailed
	}
	peer, err := ecdh.X25519().NewPublicKey(peerPublicKey)
	if err != nil {
		return nil, errFailed
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return nil, errFailed
	}
	return shared, nil
}
