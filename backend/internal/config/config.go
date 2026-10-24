package config

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultJWTSecretMinLen         = 32
	defaultJWTIssuer               = "noaddx-backend"
	defaultJWTAudience             = "noaddx-web"
	defaultJWTExpirationMinutes    = 15
	defaultAllowedOrigins          = "http://localhost"
	defaultAppEnv                  = "development"
	defaultLogLevel                = "info"
	defaultDBHost                  = "postgres"
	defaultDBPort                  = "5432"
	defaultDBUser                  = "postgres"
	defaultDBName                  = "noaddx"
	defaultDBSSLMode               = "disable"
	defaultBackendPort             = "8080"
	defaultMaxRequestBodyBytes     = 1048576
	defaultMaxJSONDepth            = 2
	defaultInviteTTLSeconds        = 86400 // Pairing tickets die after 24h
	defaultMaxActiveInvites        = 5
	defaultMaxConversationsPerUser = 256
	defaultMaxMessageBytes         = 8192 // Raw E2E ciphertext (nonce + payload + tag)
	defaultMessagePageLimit        = 200
	defaultMessageTTLDays          = 7 // Messages vanish after TTL..TTL+1 days (day-granular)
	maxMessageTTLDays              = 365
	// Argon2id parameters follow OWASP recommendations (2023)
	// Memory: 64MiB (65536 KiB) - recommended for password hashing
	// Time: 3 iterations - balance between security and performance
	// Parallelism: 4 - utilize multi-core CPUs effectively
	// Note: These defaults are tuned for production with 100-200 concurrent users
	// High-traffic scenarios (1000+ concurrent) may need adjustment or queueing
	defaultArgon2MemoryKiB   = 65536
	defaultArgon2Time        = 3
	defaultArgon2Parallelism = 4 // Increased from 2 for better CPU utilization
	defaultArgon2SaltLength  = 16
	defaultArgon2HashLength  = 32
	// At most this many Argon2id computations at once (each takes ARGON2_MEMORY_KIB)
	defaultArgon2MaxConcurrent     = 4
	defaultPendingTokenTTLSeconds  = 300
	defaultPendingCleanupSeconds   = 60
	defaultPendingIDBytes          = 16
	defaultInternalIDLength        = 24
	defaultRateLimitMaxTokens      = 20
	defaultRateLimitRefillSeconds  = 3
	defaultRateLimitCleanupSeconds = 300
	defaultRateLimitMaxBuckets     = 10000
	defaultServerReadHeaderTimeout = 5
	defaultServerReadTimeout       = 15
	defaultServerWriteTimeout      = 15
	defaultServerIdleTimeout       = 60
	defaultServerMaxHeaderBytes    = 8192
	defaultPoWDifficulty           = 20  // Strong security with acceptable browser performance (~20-40 sec)
	minPoWDifficulty               = 18  // Minimum difficulty (low load)
	maxPoWDifficulty               = 24  // Maximum difficulty (high load, DoS protection)
	defaultPoWChallengeTTLSeconds  = 300 // A challenge must be solved and used within 5 minutes
	maxPoWChallengeTTLSeconds      = 3600
	minPepperBytes                 = 32
)

// Argon2id bounds (RULES.md §5.1 range checks). They apply to configuration at startup and
// to every stored hash before verification, so no record can request unbounded work.
const (
	MinArgon2MemoryKiB           = 8192    // 8 MiB: test floor; production requires ProductionMinArgon2MemoryKiB
	MaxArgon2MemoryKiB           = 1 << 20 // 1 GiB
	MinArgon2Time                = 1
	MaxArgon2Time                = 16
	MinArgon2Parallelism         = 1
	MaxArgon2Parallelism         = 255 // argon2 takes uint8 lanes
	MinArgon2SaltBytes           = 16
	MaxArgon2SaltBytes           = 64
	MinArgon2HashBytes           = 16
	MaxArgon2HashBytes           = 64
	ProductionMinArgon2MemoryKiB = 19456 // OWASP minimum for Argon2id (19 MiB, t=2)
)

// ========================================
// ENVIRONMENT VARIABLE HELPERS
// ========================================

func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string) int {
	value := strings.TrimSpace(GetEnv(key, ""))
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0
	}
	return parsed
}

func getEnvIntDefault(key string, defaultValue int) int {
	value := strings.TrimSpace(GetEnv(key, ""))
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0
	}
	return parsed
}

func getEnvBool(key string) bool {
	value := strings.ToLower(strings.TrimSpace(GetEnv(key, "")))
	if value == "" {
		return false
	}
	return value == "true" || value == "1" || value == "yes"
}

// ========================================
// JWT CONFIGURATION
// ========================================

// GetJWTSecret returns JWT secret key from environment
func GetJWTSecret() string {
	return GetEnv("JWT_SECRET", "")
}

// GetJWTSecretMinLength returns minimum JWT secret length in characters
func GetJWTSecretMinLength() int {
	return getEnvIntDefault("JWT_SECRET_MIN_LEN", defaultJWTSecretMinLen)
}

// GetJWTIssuer returns JWT issuer value
func GetJWTIssuer() string {
	return strings.TrimSpace(GetEnv("JWT_ISSUER", defaultJWTIssuer))
}

// GetJWTAudience returns JWT audience value
func GetJWTAudience() string {
	return strings.TrimSpace(GetEnv("JWT_AUDIENCE", defaultJWTAudience))
}

// GetJWTExpiration returns JWT token expiration duration
func GetJWTExpiration() time.Duration {
	minutes := getEnvIntDefault("JWT_EXPIRATION_MINUTES", defaultJWTExpirationMinutes)
	if minutes <= 0 {
		return 0
	}
	return time.Duration(minutes) * time.Minute
}

// ========================================
// REQUEST AND VALIDATION LIMITS
// ========================================

// GetMaxRequestBodyBytes returns max request body size in bytes
func GetMaxRequestBodyBytes() int {
	return getEnvIntDefault("MAX_REQUEST_BODY_BYTES", defaultMaxRequestBodyBytes)
}

// GetMaxJSONDepth returns max JSON nesting depth
func GetMaxJSONDepth() int {
	return getEnvIntDefault("MAX_JSON_DEPTH", defaultMaxJSONDepth)
}

// ========================================
// MESSAGING CONFIGURATION
// ========================================

// GetInviteTTL returns how long an unredeemed invite stays valid
func GetInviteTTL() time.Duration {
	seconds := getEnvIntDefault("INVITE_TTL_SEC", defaultInviteTTLSeconds)
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// GetMaxActiveInvites returns the cap on unredeemed invites per user
func GetMaxActiveInvites() int {
	return getEnvIntDefault("MAX_ACTIVE_INVITES", defaultMaxActiveInvites)
}

// GetMaxConversationsPerUser returns the cap on conversations per user
func GetMaxConversationsPerUser() int {
	return getEnvIntDefault("MAX_CONVERSATIONS_PER_USER", defaultMaxConversationsPerUser)
}

// GetMaxMessageBytes returns the max raw ciphertext size of one message
func GetMaxMessageBytes() int {
	return getEnvIntDefault("MAX_MESSAGE_BYTES", defaultMaxMessageBytes)
}

// GetMessagePageLimit returns the max number of messages returned per request
func GetMessagePageLimit() int {
	return getEnvIntDefault("MESSAGE_PAGE_LIMIT", defaultMessagePageLimit)
}

// GetMessageTTLDays returns how many days ciphertext is kept before deletion
func GetMessageTTLDays() int {
	return getEnvIntDefault("MESSAGE_TTL_DAYS", defaultMessageTTLDays)
}

// MaxMessageTTLDays is the upper bound accepted for MESSAGE_TTL_DAYS
func MaxMessageTTLDays() int {
	return maxMessageTTLDays
}

// ========================================
// SECURITY CONFIGURATION
// ========================================

// GetAllowedOrigins returns CORS allowed origins (comma-separated)
func GetAllowedOrigins() string {
	return GetEnv("ALLOWED_ORIGINS", defaultAllowedOrigins)
}

// IsProductionMode returns true if running in production
func IsProductionMode() bool {
	env := strings.ToLower(strings.TrimSpace(GetEnv("APP_ENV", defaultAppEnv)))
	return env == "production" || env == "prod"
}

// GetLogLevel returns logging level
// Values: debug, info, warn, error
func GetLogLevel() string {
	return strings.ToLower(strings.TrimSpace(GetEnv("LOG_LEVEL", defaultLogLevel)))
}

// GetTrustedProxies returns comma-separated trusted proxy IPs/CIDRs
func GetTrustedProxies() string {
	return strings.TrimSpace(GetEnv("TRUSTED_PROXIES", ""))
}

// GetHSTSMaxAge returns HSTS max-age in seconds
func GetHSTSMaxAge() int {
	return getEnvInt("HSTS_MAX_AGE")
}

// GetHSTSIncludeSubDomains returns whether HSTS includeSubDomains is enabled
func GetHSTSIncludeSubDomains() bool {
	return getEnvBool("HSTS_INCLUDE_SUBDOMAINS")
}

// GetHSTSPreload returns whether HSTS preload is enabled
func GetHSTSPreload() bool {
	return getEnvBool("HSTS_PRELOAD")
}

// GetSecurityHeaderCOOP returns Cross-Origin-Opener-Policy (default same-origin; "off" disables)
func GetSecurityHeaderCOOP() string {
	value := strings.TrimSpace(GetEnv("SEC_HEADER_COOP", "same-origin"))
	if strings.EqualFold(value, "off") || strings.EqualFold(value, "disabled") {
		return ""
	}
	return value
}

// GetSecurityHeaderCORP returns Cross-Origin-Resource-Policy (default same-origin; "off" disables)
func GetSecurityHeaderCORP() string {
	value := strings.TrimSpace(GetEnv("SEC_HEADER_CORP", "same-origin"))
	if strings.EqualFold(value, "off") || strings.EqualFold(value, "disabled") {
		return ""
	}
	return value
}

// GetSecurityHeaderCOEP returns Cross-Origin-Embedder-Policy (default require-corp; "off" disables)
func GetSecurityHeaderCOEP() string {
	value := strings.TrimSpace(GetEnv("SEC_HEADER_COEP", "require-corp"))
	if strings.EqualFold(value, "off") || strings.EqualFold(value, "disabled") {
		return ""
	}
	return value
}

// ========================================
// RATE LIMITING
// ========================================

// GetRateLimitMaxTokens returns max tokens per bucket
func GetRateLimitMaxTokens() int {
	return getEnvIntDefault("RATE_LIMIT_MAX_TOKENS", defaultRateLimitMaxTokens)
}

// GetRateLimitRefillIntervalSeconds returns refill interval in seconds
func GetRateLimitRefillIntervalSeconds() int {
	return getEnvIntDefault("RATE_LIMIT_REFILL_INTERVAL_SEC", defaultRateLimitRefillSeconds)
}

// GetRateLimitCleanupIntervalSeconds returns cleanup interval in seconds
func GetRateLimitCleanupIntervalSeconds() int {
	return getEnvIntDefault("RATE_LIMIT_CLEANUP_INTERVAL_SEC", defaultRateLimitCleanupSeconds)
}

// GetRateLimitMaxBuckets returns max bucket count before cleanup
func GetRateLimitMaxBuckets() int {
	return getEnvIntDefault("RATE_LIMIT_MAX_BUCKETS", defaultRateLimitMaxBuckets)
}

// ========================================
// DATABASE CONFIGURATION
// ========================================

// GetDBHost returns database host
func GetDBHost() string {
	return strings.TrimSpace(GetEnv("DB_HOST", defaultDBHost))
}

// GetDBPort returns database port
func GetDBPort() string {
	return strings.TrimSpace(GetEnv("DB_PORT", defaultDBPort))
}

// GetDBUser returns database user
func GetDBUser() string {
	return strings.TrimSpace(GetEnv("DB_USER", defaultDBUser))
}

// GetDBPassword returns the database password; there is no default (make setup generates one)
func GetDBPassword() string {
	return GetEnv("DB_PASSWORD", "")
}

// GetDBName returns database name
func GetDBName() string {
	return strings.TrimSpace(GetEnv("DB_NAME", defaultDBName))
}

// GetDBSSLMode returns database SSL mode
// Values: disable, require, verify-ca, verify-full
func GetDBSSLMode() string {
	// Note: Logging is handled in database.connection.go ValidateStartupConfig
	return strings.TrimSpace(GetEnv("DB_SSL_MODE", defaultDBSSLMode))
}

// ========================================
// ENCRYPTION CONFIGURATION
// ========================================

// GetArgon2MemoryKiB returns Argon2 memory in KiB
func GetArgon2MemoryKiB() int {
	return getEnvIntDefault("ARGON2_MEMORY_KIB", defaultArgon2MemoryKiB)
}

// GetArgon2Time returns Argon2 time cost
func GetArgon2Time() int {
	return getEnvIntDefault("ARGON2_TIME", defaultArgon2Time)
}

// GetArgon2Parallelism returns Argon2 parallelism
func GetArgon2Parallelism() int {
	return getEnvIntDefault("ARGON2_PARALLELISM", defaultArgon2Parallelism)
}

// GetArgon2MaxConcurrent returns how many Argon2id computations may run at once
func GetArgon2MaxConcurrent() int {
	return getEnvIntDefault("ARGON2_MAX_CONCURRENT", defaultArgon2MaxConcurrent)
}

// GetArgon2SaltLength returns Argon2 salt length in bytes
func GetArgon2SaltLength() int {
	return getEnvIntDefault("ARGON2_SALT_LENGTH", defaultArgon2SaltLength)
}

// GetArgon2HashLength returns Argon2 hash length in bytes
func GetArgon2HashLength() int {
	return getEnvIntDefault("ARGON2_HASH_LENGTH", defaultArgon2HashLength)
}

// GetAccountLookupPepper returns the pepper for account lookup HMAC: at least 32 bytes of
// key material encoded as hex or base64. Raw text is rejected (nil), never used as bytes.
func GetAccountLookupPepper() []byte {
	pepperStr := strings.TrimSpace(GetEnv("ACCOUNT_LOOKUP_PEPPER", ""))
	if pepperStr == "" {
		return nil
	}
	if decoded, err := hex.DecodeString(pepperStr); err == nil && len(decoded) >= minPepperBytes {
		return decoded
	}
	if decoded, err := base64.StdEncoding.Strict().DecodeString(pepperStr); err == nil && len(decoded) >= minPepperBytes {
		return decoded
	}
	return nil
}

// ========================================
// PENDING REGISTRATION CONFIGURATION
// ========================================

// GetPendingTokenTTL returns pending token TTL
func GetPendingTokenTTL() time.Duration {
	seconds := getEnvIntDefault("PENDING_TOKEN_TTL_SEC", defaultPendingTokenTTLSeconds)
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// GetPendingCleanupInterval returns pending store cleanup interval
func GetPendingCleanupInterval() time.Duration {
	seconds := getEnvIntDefault("PENDING_CLEANUP_INTERVAL_SEC", defaultPendingCleanupSeconds)
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// GetPendingIDBytes returns pending ID length in bytes
func GetPendingIDBytes() int {
	return getEnvIntDefault("PENDING_ID_BYTES", defaultPendingIDBytes)
}

// ========================================
// IDENTIFIER CONFIGURATION
// ========================================

// GetInternalIDLength returns internal UUID length
func GetInternalIDLength() int {
	return getEnvIntDefault("INTERNAL_ID_LENGTH", defaultInternalIDLength)
}

// ========================================
// SERVER CONFIGURATION
// ========================================

// GetBackendPort returns backend server port
func GetBackendPort() string {
	return strings.TrimSpace(GetEnv("BACKEND_PORT", defaultBackendPort))
}

// GetServerReadHeaderTimeout returns read header timeout
func GetServerReadHeaderTimeout() time.Duration {
	seconds := getEnvIntDefault("SERVER_READ_HEADER_TIMEOUT_SEC", defaultServerReadHeaderTimeout)
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// GetServerReadTimeout returns read timeout
func GetServerReadTimeout() time.Duration {
	seconds := getEnvIntDefault("SERVER_READ_TIMEOUT_SEC", defaultServerReadTimeout)
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// GetServerWriteTimeout returns write timeout
func GetServerWriteTimeout() time.Duration {
	seconds := getEnvIntDefault("SERVER_WRITE_TIMEOUT_SEC", defaultServerWriteTimeout)
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// GetServerIdleTimeout returns idle timeout
func GetServerIdleTimeout() time.Duration {
	seconds := getEnvIntDefault("SERVER_IDLE_TIMEOUT_SEC", defaultServerIdleTimeout)
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// GetServerMaxHeaderBytes returns max header bytes
func GetServerMaxHeaderBytes() int {
	return getEnvIntDefault("SERVER_MAX_HEADER_BYTES", defaultServerMaxHeaderBytes)
}

// ========================================
// PROOF OF WORK CONFIGURATION
// ========================================

// GetPoWDifficulty returns the PoW difficulty level
func GetPoWDifficulty() int {
	return getEnvIntDefault("POW_DIFFICULTY", defaultPoWDifficulty)
}

// GetPoWChallengeTTL returns how long an issued PoW challenge stays valid
func GetPoWChallengeTTL() time.Duration {
	seconds := getEnvIntDefault("POW_CHALLENGE_TTL_SEC", defaultPoWChallengeTTLSeconds)
	if seconds <= 0 || seconds > maxPoWChallengeTTLSeconds {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// DefaultPoWDifficulty returns the default PoW difficulty level
func DefaultPoWDifficulty() int {
	return defaultPoWDifficulty
}

// MinPoWDifficulty returns the minimum PoW difficulty level
func MinPoWDifficulty() int {
	return minPoWDifficulty
}

// MaxPoWDifficulty returns the maximum PoW difficulty level
func MaxPoWDifficulty() int {
	return maxPoWDifficulty
}
