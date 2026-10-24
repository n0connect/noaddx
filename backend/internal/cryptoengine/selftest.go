package cryptoengine

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrSelfTest means the engine produced a wrong answer for a published test vector.
var ErrSelfTest = errors.New("cryptoengine: known-answer self-test failed")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("cryptoengine: bad self-test vector")
	}
	return b
}

// SelfTest runs known-answer tests for every primitive on the active engine. The server
// calls it at startup and refuses to run on a mismatch (a broken or swapped library must
// never touch user data). Vectors: FIPS 180-4, RFC 4231, RFC 5869, the Argon2 reference
// implementation, GCM spec test case 16, RFC 7748 §6.1.
func SelfTest() error {
	if err := active.Check(); err != nil {
		return err
	}
	checks := []struct {
		name string
		run  func() ([]byte, error)
		want string
	}{
		{"SHA-256", func() ([]byte, error) { return SHA256([]byte("abc")) },
			"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"HMAC-SHA256", func() ([]byte, error) {
			return HMACSHA256([]byte("Jefe"), []byte("what do ya want for nothing?"))
		}, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"},
		{"HKDF-SHA256", func() ([]byte, error) {
			return HKDFSHA256(bytes.Repeat([]byte{0x0b}, 22), mustHex("000102030405060708090a0b0c"), mustHex("f0f1f2f3f4f5f6f7f8f9"), 42)
		}, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"},
		{"Argon2id", func() ([]byte, error) {
			return Argon2idKey(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 16), 3, 32, 4, 32)
		}, "03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e"},
		{"AES-256-GCM", func() ([]byte, error) {
			return SealAES256GCM(mustHex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),
				mustHex("cafebabefacedbaddecaf888"),
				mustHex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
				mustHex("feedfacedeadbeeffeedfacedeadbeefabaddad2"))
		}, "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662" +
			"76fc6ece0f4e1768cddf8853bb2d551b"},
		{"X25519", func() ([]byte, error) {
			return X25519SharedSecret(mustHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
				mustHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
		}, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"},
	}
	for _, c := range checks {
		got, err := c.run()
		if err != nil || !bytes.Equal(got, mustHex(c.want)) {
			return fmt.Errorf("%w: %s (%s engine)", ErrSelfTest, c.name, active.Name())
		}
	}
	if _, err := X25519SharedSecret(mustHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"), make([]byte, X25519KeySize)); err == nil {
		return fmt.Errorf("%w: low-order X25519 point accepted (%s engine)", ErrSelfTest, active.Name())
	}
	return nil
}
