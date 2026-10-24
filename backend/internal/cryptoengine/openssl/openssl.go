//go:build openssl && cgo

package openssl

/*
#cgo pkg-config: libcrypto
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x30200000L
#error "noaddx: the OpenSSL engine needs OpenSSL >= 3.2 (EVP_KDF ARGON2ID)"
#endif
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/thread.h>
#include <stdint.h>

static int nx_random(unsigned char *out, int len) {
	return RAND_bytes(out, len) == 1;
}

static int nx_sha256(const unsigned char *in, size_t inlen, unsigned char *out) {
	unsigned int outlen = 0;
	return EVP_Digest(in, inlen, out, &outlen, EVP_sha256(), NULL) == 1 && outlen == 32;
}

static int nx_hmac_sha256(const unsigned char *key, size_t keylen,
                          const unsigned char *in, size_t inlen, unsigned char *out) {
	size_t outlen = 0;
	return EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, key, keylen, in, inlen, out, 32, &outlen) != NULL
		&& outlen == 32;
}

static int nx_hkdf_sha256(const unsigned char *ikm, size_t ikmlen, const unsigned char *salt, size_t saltlen,
                          const unsigned char *info, size_t infolen, unsigned char *out, size_t outlen) {
	EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
	if (kdf == NULL) {
		return 0;
	}
	EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
	EVP_KDF_free(kdf);
	if (ctx == NULL) {
		return 0;
	}
	OSSL_PARAM params[5], *p = params;
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)"SHA256", 0);
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ikm, ikmlen);
	if (saltlen > 0) {
		*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, saltlen);
	}
	if (infolen > 0) {
		*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, infolen);
	}
	*p = OSSL_PARAM_construct_end();
	int ok = EVP_KDF_derive(ctx, out, outlen, params) == 1;
	EVP_KDF_CTX_free(ctx);
	return ok;
}

static int nx_argon2id(const unsigned char *pwd, size_t pwdlen, const unsigned char *salt, size_t saltlen,
                       uint32_t iter, uint32_t memcost, uint32_t lanes, uint32_t threads,
                       unsigned char *out, uint32_t outlen) {
	EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
	if (kdf == NULL) {
		return 0;
	}
	EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
	EVP_KDF_free(kdf);
	if (ctx == NULL) {
		return 0;
	}
	uint32_t version = 0x13;
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)pwd, pwdlen),
		OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, saltlen),
		OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter),
		OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memcost),
		OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
		OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads),
		OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_VERSION, &version),
		OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SIZE, &outlen),
		OSSL_PARAM_construct_end(),
	};
	int ok = EVP_KDF_derive(ctx, out, outlen, params) == 1;
	EVP_KDF_CTX_free(ctx);
	return ok;
}

// out receives ptlen bytes of ciphertext followed by the 16-byte tag
static int nx_gcm_seal(const unsigned char *key, const unsigned char *nonce,
                       const unsigned char *pt, int ptlen, const unsigned char *aad, int aadlen,
                       unsigned char *out) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int ok = 0, len = 0, total = 0;
	if (ctx == NULL) {
		return 0;
	}
	if (EVP_EncryptInit_ex2(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
	    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
	    EVP_EncryptInit_ex2(ctx, NULL, key, nonce, NULL) != 1) {
		goto done;
	}
	if (aadlen > 0 && EVP_EncryptUpdate(ctx, NULL, &len, aad, aadlen) != 1) {
		goto done;
	}
	if (ptlen > 0) {
		if (EVP_EncryptUpdate(ctx, out, &len, pt, ptlen) != 1) {
			goto done;
		}
		total = len;
	}
	if (EVP_EncryptFinal_ex(ctx, out + total, &len) != 1) {
		goto done;
	}
	total += len;
	if (total != ptlen || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out + ptlen) != 1) {
		goto done;
	}
	ok = 1;
done:
	EVP_CIPHER_CTX_free(ctx);
	return ok;
}

// in is ctlen bytes of ciphertext followed by the 16-byte tag; out receives ctlen bytes
static int nx_gcm_open(const unsigned char *key, const unsigned char *nonce,
                       const unsigned char *in, int ctlen, const unsigned char *aad, int aadlen,
                       unsigned char *out) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int ok = 0, len = 0, total = 0;
	if (ctx == NULL) {
		return 0;
	}
	if (EVP_DecryptInit_ex2(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
	    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
	    EVP_DecryptInit_ex2(ctx, NULL, key, nonce, NULL) != 1) {
		goto done;
	}
	if (aadlen > 0 && EVP_DecryptUpdate(ctx, NULL, &len, aad, aadlen) != 1) {
		goto done;
	}
	if (ctlen > 0) {
		if (EVP_DecryptUpdate(ctx, out, &len, in, ctlen) != 1) {
			goto done;
		}
		total = len;
	}
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)(in + ctlen)) != 1) {
		goto done;
	}
	if (EVP_DecryptFinal_ex(ctx, out + total, &len) != 1) {
		goto done; // authentication failed
	}
	total += len;
	ok = total == ctlen;
done:
	EVP_CIPHER_CTX_free(ctx);
	return ok;
}

static int nx_x25519_public(const unsigned char *priv, unsigned char *pub) {
	EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
	size_t len = 32;
	if (key == NULL) {
		return 0;
	}
	int ok = EVP_PKEY_get_raw_public_key(key, pub, &len) == 1 && len == 32;
	EVP_PKEY_free(key);
	return ok;
}

// Fails for the all-zero result of a low-order peer point (RFC 7748 §6.1), as Go does
static int nx_x25519(const unsigned char *priv, const unsigned char *peer, unsigned char *out) {
	EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
	EVP_PKEY *peerkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer, 32);
	EVP_PKEY_CTX *ctx = NULL;
	size_t len = 32;
	int ok = 0;
	if (key == NULL || peerkey == NULL) {
		goto done;
	}
	ctx = EVP_PKEY_CTX_new(key, NULL);
	if (ctx == NULL || EVP_PKEY_derive_init(ctx) != 1 || EVP_PKEY_derive_set_peer_ex(ctx, peerkey, 0) != 1) {
		goto done;
	}
	ok = EVP_PKEY_derive(ctx, out, &len) == 1 && len == 32;
done:
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(peerkey);
	EVP_PKEY_free(key);
	return ok;
}

static int nx_equal(const unsigned char *a, const unsigned char *b, size_t len) {
	return CRYPTO_memcmp(a, b, len) == 0;
}

static unsigned long nx_version_num(void) {
	return OpenSSL_version_num();
}

static const char *nx_version(void) {
	return OpenSSL_version(OPENSSL_VERSION);
}

// Lets Argon2id compute its lanes in parallel; returns how many threads are allowed
static uint64_t nx_enable_threads(uint64_t wanted) {
	if (OSSL_set_max_threads(NULL, wanted) != 1) {
		return 1;
	}
	return OSSL_get_max_threads(NULL);
}
*/
import "C"

import (
	"errors"
	"sync"
	"unsafe"
)

// minVersion is OpenSSL 3.2.0: the first release with the ARGON2ID KDF.
const minVersion = 0x30200000

// maxArgon2Threads bounds the worker threads OpenSSL may start for one Argon2id call.
const maxArgon2Threads = 8

var (
	errFailed     = errors.New("openssl: operation failed")
	errOldOpenSSL = errors.New("openssl: the linked libcrypto is older than 3.2.0")
	threadsOnce   sync.Once
	argon2Threads uint32 = 1
)

// Engine implements the primitives with OpenSSL's EVP interfaces (libcrypto >= 3.2).
type Engine struct{}

// ptr returns a C pointer to b's data, or nil for an empty slice (never indexes b[0]).
func ptr(b []byte) *C.uchar {
	if len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

// done turns an OpenSSL status into an error, emptying the thread's error queue either way
// so no failure detail lingers into a later call.
func done(ok C.int) error {
	C.ERR_clear_error()
	if ok != 1 {
		return errFailed
	}
	return nil
}

// Name identifies the engine.
func (Engine) Name() string { return "openssl" }

// Version reports the libcrypto the process actually runs against.
func (Engine) Version() string { return C.GoString(C.nx_version()) }

// Check refuses a runtime libcrypto older than 3.2.0 (the headers were checked at build time).
func (Engine) Check() error {
	if C.nx_version_num() < minVersion {
		return errOldOpenSSL
	}
	return nil
}

// Random fills out with RAND_bytes.
func (Engine) Random(out []byte) error {
	if len(out) == 0 {
		return nil
	}
	return done(C.nx_random(ptr(out), C.int(len(out))))
}

// SHA256 returns the SHA-256 digest of data.
func (Engine) SHA256(data []byte) ([]byte, error) {
	out := make([]byte, 32)
	if err := done(C.nx_sha256(ptr(data), C.size_t(len(data)), ptr(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// HMACSHA256 returns HMAC-SHA256(key, data).
func (Engine) HMACSHA256(key, data []byte) ([]byte, error) {
	out := make([]byte, 32)
	if err := done(C.nx_hmac_sha256(ptr(key), C.size_t(len(key)), ptr(data), C.size_t(len(data)), ptr(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// Equal compares two equal-length slices with CRYPTO_memcmp (constant time).
func (Engine) Equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	return C.nx_equal(ptr(a), ptr(b), C.size_t(len(a))) == 1
}

// Argon2id derives keyLen bytes with the ARGON2ID KDF (v1.3, RFC 9106).
func (Engine) Argon2id(password, salt []byte, timeCost, memoryKiB, lanes, keyLen uint32) ([]byte, error) {
	threadsOnce.Do(func() {
		argon2Threads = uint32(C.nx_enable_threads(maxArgon2Threads))
		if argon2Threads == 0 {
			argon2Threads = 1
		}
	})
	threads := lanes
	if threads > argon2Threads {
		threads = argon2Threads
	}
	out := make([]byte, keyLen)
	ok := C.nx_argon2id(ptr(password), C.size_t(len(password)), ptr(salt), C.size_t(len(salt)),
		C.uint32_t(timeCost), C.uint32_t(memoryKiB), C.uint32_t(lanes), C.uint32_t(threads),
		ptr(out), C.uint32_t(keyLen))
	if err := done(ok); err != nil {
		return nil, err
	}
	return out, nil
}

// HKDFSHA256 derives length bytes with the HKDF KDF over SHA-256 (RFC 5869).
func (Engine) HKDFSHA256(ikm, salt, info []byte, length int) ([]byte, error) {
	out := make([]byte, length)
	ok := C.nx_hkdf_sha256(ptr(ikm), C.size_t(len(ikm)), ptr(salt), C.size_t(len(salt)),
		ptr(info), C.size_t(len(info)), ptr(out), C.size_t(length))
	if err := done(ok); err != nil {
		return nil, err
	}
	return out, nil
}

// SealAES256GCM returns ciphertext || 16-byte tag for the given 12-byte nonce.
func (Engine) SealAES256GCM(key, nonce, plaintext, aad []byte) ([]byte, error) {
	out := make([]byte, len(plaintext)+16)
	ok := C.nx_gcm_seal(ptr(key), ptr(nonce), ptr(plaintext), C.int(len(plaintext)), ptr(aad), C.int(len(aad)), ptr(out))
	if err := done(ok); err != nil {
		return nil, err
	}
	return out, nil
}

// OpenAES256GCM authenticates and decrypts ciphertext || tag.
func (Engine) OpenAES256GCM(key, nonce, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < 16 {
		return nil, errFailed
	}
	ctLen := len(sealed) - 16
	out := make([]byte, ctLen)
	ok := C.nx_gcm_open(ptr(key), ptr(nonce), ptr(sealed), C.int(ctLen), ptr(aad), C.int(len(aad)), ptr(out))
	if err := done(ok); err != nil {
		return nil, err
	}
	return out, nil
}

// X25519PublicKey returns the public key of a 32-byte private scalar (clamped per RFC 7748).
func (Engine) X25519PublicKey(privateKey []byte) ([]byte, error) {
	out := make([]byte, 32)
	if err := done(C.nx_x25519_public(ptr(privateKey), ptr(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// X25519 returns the shared secret; the all-zero result of a low-order peer is refused.
func (Engine) X25519(privateKey, peerPublicKey []byte) ([]byte, error) {
	out := make([]byte, 32)
	if err := done(C.nx_x25519(ptr(privateKey), ptr(peerPublicKey), ptr(out))); err != nil {
		return nil, err
	}
	return out, nil
}
