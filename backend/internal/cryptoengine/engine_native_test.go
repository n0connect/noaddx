//go:build !openssl

package cryptoengine_test

import (
	"testing"

	"noaddx/internal/cryptoengine"
)

func TestDefaultBuildUsesTheNativeEngine(t *testing.T) {
	if cryptoengine.EngineName() != "native" {
		t.Fatalf("engine = %q, want native", cryptoengine.EngineName())
	}
}
