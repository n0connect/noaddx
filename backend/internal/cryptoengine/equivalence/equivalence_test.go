//go:build openssl

package equivalence

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"noaddx/internal/cryptoengine/native"
	"noaddx/internal/cryptoengine/openssl"
)

// Differential tests: every deterministic primitive is fed the same inputs through both
// engines (native Go and OpenSSL) and must produce the same bytes, or both must refuse.

var (
	goEngine  native.Engine
	sslEngine openssl.Engine
)

func random(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return b
}

func randomInt(t *testing.T, max int) int {
	t.Helper()
	return int(binary.BigEndian.Uint32(random(t, 4)) % uint32(max))
}

func same(t *testing.T, what string, a []byte, aErr error, b []byte, bErr error) {
	t.Helper()
	if (aErr == nil) != (bErr == nil) {
		t.Fatalf("%s: engines disagree on acceptance (native err=%v, openssl err=%v)", what, aErr, bErr)
	}
	if aErr == nil && !bytes.Equal(a, b) {
		t.Fatalf("%s: outputs differ\nnative  %x\nopenssl %x", what, a, b)
	}
}

func TestEquivalence_SHA256(t *testing.T) {
	for n := 0; n <= 300; n++ {
		data := random(t, n)
		a, aErr := goEngine.SHA256(data)
		b, bErr := sslEngine.SHA256(data)
		same(t, "SHA256", a, aErr, b, bErr)
	}
}

func TestEquivalence_HMACSHA256(t *testing.T) {
	for i := 0; i < 1000; i++ {
		key, data := random(t, 1+randomInt(t, 200)), random(t, randomInt(t, 300))
		a, aErr := goEngine.HMACSHA256(key, data)
		b, bErr := sslEngine.HMACSHA256(key, data)
		same(t, "HMAC-SHA256", a, aErr, b, bErr)
	}
}

func TestEquivalence_HKDFSHA256(t *testing.T) {
	for i := 0; i < 1000; i++ {
		ikm, salt, info := random(t, 1+randomInt(t, 80)), random(t, randomInt(t, 80)), random(t, randomInt(t, 80))
		length := 1 + randomInt(t, 255*32)
		a, aErr := goEngine.HKDFSHA256(ikm, salt, info, length)
		b, bErr := sslEngine.HKDFSHA256(ikm, salt, info, length)
		same(t, "HKDF-SHA256", a, aErr, b, bErr)
	}
}

// Small memory keeps this fast; odd sizes exercise the RFC 9106 rounding to 4*lanes blocks.
func TestEquivalence_Argon2id(t *testing.T) {
	for i := 0; i < 60; i++ {
		lanes := uint32(1 + randomInt(t, 4))
		memory := 8*lanes + uint32(randomInt(t, 200))
		timeCost := uint32(1 + randomInt(t, 3))
		keyLen := uint32(4 + randomInt(t, 61))
		password, salt := random(t, 1+randomInt(t, 64)), random(t, 8+randomInt(t, 32))
		a, aErr := goEngine.Argon2id(password, salt, timeCost, memory, lanes, keyLen)
		b, bErr := sslEngine.Argon2id(password, salt, timeCost, memory, lanes, keyLen)
		same(t, "Argon2id", a, aErr, b, bErr)
	}
}

func TestEquivalence_AES256GCM(t *testing.T) {
	for i := 0; i < 500; i++ {
		key, nonce := random(t, 32), random(t, 12)
		plaintext, aad := random(t, randomInt(t, 600)), random(t, randomInt(t, 80))
		a, aErr := goEngine.SealAES256GCM(key, nonce, plaintext, aad)
		b, bErr := sslEngine.SealAES256GCM(key, nonce, plaintext, aad)
		same(t, "AES-256-GCM seal", a, aErr, b, bErr)

		// Each engine opens what the other sealed, and both reject the same tampering
		pa, paErr := goEngine.OpenAES256GCM(key, nonce, b, aad)
		pb, pbErr := sslEngine.OpenAES256GCM(key, nonce, a, aad)
		same(t, "AES-256-GCM open (crossed)", pa, paErr, pb, pbErr)
		if paErr != nil || !bytes.Equal(pa, plaintext) {
			t.Fatalf("cross-engine open failed: %v", paErr)
		}
		tampered := append([]byte{}, a...)
		tampered[randomInt(t, len(tampered))] ^= byte(1 + randomInt(t, 255))
		_, taErr := goEngine.OpenAES256GCM(key, nonce, tampered, aad)
		_, tbErr := sslEngine.OpenAES256GCM(key, nonce, tampered, aad)
		if taErr == nil || tbErr == nil {
			t.Fatalf("tampered ciphertext accepted (native err=%v, openssl err=%v)", taErr, tbErr)
		}
	}
}

func TestEquivalence_X25519(t *testing.T) {
	for i := 0; i < 500; i++ {
		priv, peer := random(t, 32), random(t, 32) // peer: arbitrary u, top bit and non-canonical values included
		a, aErr := goEngine.X25519PublicKey(priv)
		b, bErr := sslEngine.X25519PublicKey(priv)
		same(t, "X25519 public key", a, aErr, b, bErr)
		sa, saErr := goEngine.X25519(priv, peer)
		sb, sbErr := sslEngine.X25519(priv, peer)
		same(t, "X25519 shared secret", sa, saErr, sb, sbErr)
	}
}

// Points of small order give an all-zero shared secret: both engines must refuse every one,
// in canonical and in non-canonical (top bit set, u >= p) encodings.
func TestEquivalence_X25519RejectsLowOrderPoints(t *testing.T) {
	lowOrder := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
		"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}
	priv := random(t, 32)
	for _, h := range lowOrder {
		peer := make([]byte, 32)
		for i := range peer {
			var v byte
			for _, c := range h[2*i : 2*i+2] {
				v <<= 4
				switch {
				case c >= '0' && c <= '9':
					v |= byte(c - '0')
				default:
					v |= byte(c-'a') + 10
				}
			}
			peer[i] = v
		}
		_, aErr := goEngine.X25519(priv, peer)
		_, bErr := sslEngine.X25519(priv, peer)
		if aErr == nil || bErr == nil {
			t.Errorf("low-order point %s accepted (native err=%v, openssl err=%v)", h, aErr, bErr)
		}
	}
}

func TestEquivalence_ConstantTimeEqual(t *testing.T) {
	for i := 0; i < 300; i++ {
		a := random(t, 1+randomInt(t, 64))
		b := append([]byte{}, a...)
		if randomInt(t, 2) == 1 {
			b[randomInt(t, len(b))] ^= 0x80
		}
		if goEngine.Equal(a, b) != sslEngine.Equal(a, b) || goEngine.Equal(a, b) != bytes.Equal(a, b) {
			t.Fatalf("Equal disagrees for %x / %x", a, b)
		}
	}
}

func TestEquivalence_RandomBytesAreFilled(t *testing.T) {
	for _, engine := range []interface{ Random([]byte) error }{goEngine, sslEngine} {
		a, b := make([]byte, 64), make([]byte, 64)
		if engine.Random(a) != nil || engine.Random(b) != nil || bytes.Equal(a, b) || bytes.Equal(a, make([]byte, 64)) {
			t.Fatalf("%T: CSPRNG output missing or repeated", engine)
		}
	}
}
