//go:build openssl && !cgo

package cryptoengine

// The OpenSSL engine needs cgo: this undefined name turns a CGO_ENABLED=0 build with
// -tags openssl into a compile error that says what is wrong.
var active engine = openSSLEngineRequiresCGO_ENABLED_1
