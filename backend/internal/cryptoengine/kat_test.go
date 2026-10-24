package cryptoengine_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"noaddx/internal/cryptoengine"
)

// Known-answer tests run against whichever engine this binary was built with
// (native by default, OpenSSL with -tags openssl). Every expected value comes from a
// published specification or an independent reference implementation:
//   SHA-256: FIPS 180-4 examples · HMAC: RFC 4231 · HKDF: RFC 5869
//   Argon2id: the phc-winner-argon2 reference CLI · AES-256-GCM: GCM spec test case 16
//   X25519: RFC 7748 §5.2 and §6.1

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex in test vector: %v", err)
	}
	return b
}

func expectHex(t *testing.T, what string, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != strings.ReplaceAll(want, " ", "") {
		t.Errorf("%s (%s engine)\n got %x\nwant %s", what, cryptoengine.EngineName(), got, want)
	}
}

func TestKAT_SHA256(t *testing.T) {
	for msg, want := range map[string]string{
		"":    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq": "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
	} {
		got, err := cryptoengine.SHA256([]byte(msg))
		if err != nil {
			t.Fatalf("SHA256: %v", err)
		}
		expectHex(t, "SHA-256("+msg+")", got, want)
	}
}

func TestKAT_HMACSHA256(t *testing.T) {
	cases := []struct{ key, data, want string }{
		{hex.EncodeToString(bytes.Repeat([]byte{0x0b}, 20)), hex.EncodeToString([]byte("Hi There")),
			"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"},
		{hex.EncodeToString([]byte("Jefe")), hex.EncodeToString([]byte("what do ya want for nothing?")),
			"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"},
		{hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 131)), hex.EncodeToString([]byte("Test Using Larger Than Block-Size Key - Hash Key First")),
			"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"},
	}
	for i, c := range cases {
		got, err := cryptoengine.HMACSHA256(unhex(t, c.key), unhex(t, c.data))
		if err != nil {
			t.Fatalf("case %d: %v", i+1, err)
		}
		expectHex(t, "HMAC-SHA256 RFC 4231", got, c.want)
	}
}

func TestKAT_HKDFSHA256(t *testing.T) {
	cases := []struct {
		ikm, salt, info string
		length          int
		want            string
	}{
		{"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42,
			"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"},
		{"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "", 42,
			"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"},
	}
	for i, c := range cases {
		got, err := cryptoengine.HKDFSHA256(unhex(t, c.ikm), unhex(t, c.salt), unhex(t, c.info), c.length)
		if err != nil {
			t.Fatalf("case %d: %v", i+1, err)
		}
		expectHex(t, "HKDF-SHA256 RFC 5869", got, c.want)
	}
}

func TestKAT_Argon2id(t *testing.T) {
	got, err := cryptoengine.Argon2idKey([]byte("password"), []byte("somesalt"), 2, 1<<16, 1, 32)
	if err != nil {
		t.Fatalf("Argon2idKey: %v", err)
	}
	expectHex(t, "Argon2id t=2 m=64MiB p=1", got, "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7")

	got, err = cryptoengine.Argon2idKey(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 16), 3, 32, 4, 32)
	if err != nil {
		t.Fatalf("Argon2idKey (4 lanes): %v", err)
	}
	expectHex(t, "Argon2id t=3 m=32KiB p=4", got, "03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e")
}

func TestKAT_AES256GCM(t *testing.T) {
	key := unhex(t, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	nonce := unhex(t, "cafebabefacedbaddecaf888")
	plaintext := unhex(t, "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
	aad := unhex(t, "feedfacedeadbeeffeedfacedeadbeefabaddad2")
	want := "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662" +
		"76fc6ece0f4e1768cddf8853bb2d551b"

	sealed, err := cryptoengine.SealAES256GCM(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("SealAES256GCM: %v", err)
	}
	expectHex(t, "AES-256-GCM test case 16", sealed, want)

	opened, err := cryptoengine.DecryptAES256GCM(key, append(append([]byte{}, nonce...), sealed...), aad)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("DecryptAES256GCM of the vector: %v", err)
	}
	for i := range sealed {
		tampered := append([]byte{}, sealed...)
		tampered[i] ^= 0x01
		if _, err := cryptoengine.DecryptAES256GCM(key, append(append([]byte{}, nonce...), tampered...), aad); err == nil {
			t.Fatalf("a flipped bit at offset %d was accepted", i)
		}
	}
}

func TestKAT_X25519(t *testing.T) {
	shared, err := cryptoengine.X25519SharedSecret(
		unhex(t, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
		unhex(t, "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))
	if err != nil {
		t.Fatalf("X25519 RFC 7748 §5.2: %v", err)
	}
	expectHex(t, "X25519 RFC 7748 §5.2", shared, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")

	alice := unhex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	bob := unhex(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	alicePub, err := cryptoengine.X25519PublicKey(alice)
	if err != nil {
		t.Fatalf("X25519PublicKey: %v", err)
	}
	expectHex(t, "X25519 Alice public", alicePub, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	bobPub, err := cryptoengine.X25519PublicKey(bob)
	if err != nil {
		t.Fatalf("X25519PublicKey: %v", err)
	}
	expectHex(t, "X25519 Bob public", bobPub, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	shared, err = cryptoengine.X25519SharedSecret(alice, bobPub)
	if err != nil {
		t.Fatalf("X25519SharedSecret: %v", err)
	}
	expectHex(t, "X25519 shared secret", shared, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	// The all-zero output of a low-order peer point is rejected (RFC 7748 §6.1)
	if _, err := cryptoengine.X25519SharedSecret(alice, make([]byte, 32)); err == nil {
		t.Fatal("the zero point was accepted as a peer key")
	}
}

// Invalid input is refused identically by both engines because the checks run once, in
// the engine-independent layer.
func TestInputValidation(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	checks := map[string]error{}
	_, checks["RandomBytes(0)"] = cryptoengine.RandomBytes(0)
	_, checks["HMAC empty key"] = cryptoengine.HMACSHA256(nil, []byte("x"))
	_, checks["HKDF empty ikm"] = cryptoengine.HKDFSHA256(nil, nil, nil, 32)
	_, checks["HKDF length 0"] = cryptoengine.HKDFSHA256(key, nil, nil, 0)
	_, checks["HKDF length too long"] = cryptoengine.HKDFSHA256(key, nil, nil, 255*32+1)
	_, checks["Argon2 empty password"] = cryptoengine.Argon2idKey(nil, key, 1, 64, 1, 32)
	_, checks["Argon2 empty salt"] = cryptoengine.Argon2idKey(key, nil, 1, 64, 1, 32)
	_, checks["Argon2 zero lanes"] = cryptoengine.Argon2idKey(key, key, 1, 64, 0, 32)
	_, checks["Argon2 256 lanes"] = cryptoengine.Argon2idKey(key, key, 1, 1<<16, 256, 32)
	_, checks["Argon2 memory below 8 per lane"] = cryptoengine.Argon2idKey(key, key, 1, 31, 4, 32)
	_, checks["Argon2 zero time"] = cryptoengine.Argon2idKey(key, key, 0, 64, 1, 32)
	_, checks["Argon2 short output"] = cryptoengine.Argon2idKey(key, key, 1, 64, 1, 3)
	_, checks["GCM short key"] = cryptoengine.EncryptAES256GCM(key[:16], []byte("x"), nil)
	_, checks["GCM short nonce"] = cryptoengine.SealAES256GCM(key, key[:8], []byte("x"), nil)
	_, checks["GCM truncated input"] = cryptoengine.DecryptAES256GCM(key, key[:27], nil)
	_, checks["X25519 short scalar"] = cryptoengine.X25519PublicKey(key[:31])
	_, checks["X25519 short peer"] = cryptoengine.X25519SharedSecret(key, key[:31])
	for name, err := range checks {
		if err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestStartupSelfTestPasses(t *testing.T) {
	if err := cryptoengine.SelfTest(); err != nil {
		t.Fatalf("SelfTest (%s engine): %v", cryptoengine.EngineName(), err)
	}
}
