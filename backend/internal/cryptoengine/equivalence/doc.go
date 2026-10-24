// Package equivalence proves that the two crypto engines are interchangeable: the same
// inputs give byte-identical outputs and the same accept/reject decisions. Its tests link
// both engines into one binary, so they run only with the OpenSSL engine available:
//
//	go test -tags openssl ./internal/cryptoengine/equivalence/   (or: make test-equivalence)
package equivalence
