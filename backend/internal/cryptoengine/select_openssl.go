//go:build openssl && cgo

package cryptoengine

import "noaddx/internal/cryptoengine/openssl"

// Built with -tags openssl: every primitive runs on libcrypto.
var active engine = openssl.Engine{}
