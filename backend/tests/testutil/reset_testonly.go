//go:build test
// +build test

package testutil

import (
	"noaddx/internal/auth"
	"noaddx/internal/middleware"
)

// resetRateLimiterForTesting calls the test-only reset function
// This code is ONLY compiled when building with -tags test
func resetRateLimiterForTesting() {
	middleware.ResetRateLimiterForTesting()
}

// resetPendingStoreForTesting calls the test-only reset function
// This code is ONLY compiled when building with -tags test
func resetPendingStoreForTesting() {
	auth.ResetPendingStoreForTesting()
}
