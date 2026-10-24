//go:build test
// +build test

package middleware

import "sync"

// ResetTrustedProxiesForTesting clears cached trusted proxy configuration.
func ResetTrustedProxiesForTesting() {
	trustedProxyOnce = sync.Once{}
	trustedProxyNets = nil
	trustedProxyIPs = nil
}

// ResetAllowedOriginsForTesting forces ALLOWED_ORIGINS to be re-read.
func ResetAllowedOriginsForTesting() {
	corsOnce = sync.Once{}
	allowedOrigins = nil
}
