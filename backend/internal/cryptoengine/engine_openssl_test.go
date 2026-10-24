//go:build openssl

package cryptoengine_test

import (
	"strings"
	"testing"

	"noaddx/internal/cryptoengine"
)

func TestOpenSSLBuildUsesTheOpenSSLEngine(t *testing.T) {
	if cryptoengine.EngineName() != "openssl" || !strings.HasPrefix(cryptoengine.EngineVersion(), "OpenSSL ") {
		t.Fatalf("engine = %q (%s), want openssl", cryptoengine.EngineName(), cryptoengine.EngineVersion())
	}
}
