// Package openssl is the OpenSSL crypto engine: libcrypto >= 3.2 through cgo (EVP digests,
// EVP_Q_mac, EVP_KDF HKDF and ARGON2ID, EVP AES-256-GCM, EVP_PKEY X25519, RAND_bytes,
// CRYPTO_memcmp). It is byte-for-byte interchangeable with the native engine; the
// equivalence package proves it. Built only with `-tags openssl` and CGO_ENABLED=1.
package openssl
