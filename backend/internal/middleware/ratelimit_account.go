package middleware

// AllowAccountLookup applies rate limiting for a specific account lookup hash.
func AllowAccountLookup(lookup string) bool {
	if lookup == "" {
		return true
	}
	return AllowKey("acct:" + lookup)
}

// AllowKey applies the shared token-bucket limiter to an arbitrary namespaced key
// (e.g. "msg:<member tag>"). Fails closed when the limiter is misconfigured.
func AllowKey(key string) bool {
	if err := globalRateLimiter.loadConfig(); err != nil {
		rateLimitLogger.LogError("RateLimitConfig", err)
		return false
	}
	if key == "" {
		return false
	}
	return globalRateLimiter.getBucket(key).Allow()
}
