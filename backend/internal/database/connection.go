package database

import (
	"fmt"
	"log"
	"strings"

	"noaddress/internal/config"
	"noaddress/internal/encryption"
	"noaddress/internal/models"
	"noaddress/internal/utils"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var dbLogger = utils.NewLogger("DATABASE")

var (
	DB *gorm.DB
)

// gormLogLevel keeps SQL (and the pseudonyms/lookups bound into it) out of logs
// unless LOG_LEVEL=debug is explicitly requested.
func gormLogLevel() logger.LogLevel {
	if config.GetLogLevel() == "debug" && !config.IsProductionMode() {
		return logger.Info
	}
	return logger.Silent
}

func Init() {
	dbLogger.Info("Initializing database connection...")

	// Be careful special information passed to dns
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=UTC",
		config.GetDBHost(), config.GetDBUser(), config.GetDBPassword(), config.GetDBName(), config.GetDBPort(), config.GetDBSSLMode())

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger:         logger.Default.LogMode(gormLogLevel()),
		TranslateError: true, // Surfaces unique violations as gorm.ErrDuplicatedKey
	})
	if err != nil {
		dbLogger.LogError("Database connection", err)
		log.Fatal("Failed to connect to database")
	}
	dbLogger.Info("Connected to PostgreSQL")

	if err := encryption.InitMasterKeys(); err != nil {
		dbLogger.LogError("Master key initialization", err)
		log.Fatal("Failed to initialize master keys")
	}

	// Note: models.Requests is not a database model (only for HTTP request/response DTOs)
	err = DB.AutoMigrate(&models.User{}, &models.Invite{}, &models.Conversation{}, &models.ConversationMember{}, &models.Message{})
	if err != nil {
		dbLogger.LogError("Database migration", err)
		log.Fatal("Failed to migrate database")
	}
	dbLogger.Info("Database migrations completed")
}

// ValidateStartupConfig validates all required configuration at startup
func ValidateStartupConfig() error {
	dbLogger.Info("Validation not guarantee your [JWT_SECRET] is created by secure source!")
	dbLogger.Info("Recommendation use openssl with isolated system for high entropy clean source.")
	// Validate JWT secret
	jwtSecret := config.GetJWTSecret()
	if jwtSecret == "" {
		return fmt.Errorf("JWT_SECRET is required please check .env file")
	}
	minJWTLen := config.GetJWTSecretMinLength()
	if minJWTLen <= 0 {
		return fmt.Errorf("JWT_SECRET_MIN_LEN is required")
	}
	if len(jwtSecret) < minJWTLen {
		return fmt.Errorf("JWT_SECRET must be at least %d characters. If you dont have key plese use openssl for create high entropy CSPRNG for create JWT_SECRET", minJWTLen)
	}

	if config.GetJWTIssuer() == "" {
		return fmt.Errorf("JWT_ISSUER is required")
	}
	if config.GetJWTAudience() == "" {
		return fmt.Errorf("JWT_AUDIENCE is required")
	}
	if config.GetJWTExpiration() <= 0 {
		return fmt.Errorf("JWT_EXPIRATION_MINUTES is required and must be > 0")
	}

	// Validate encryption key
	dbLogger.Info("Validation not guarantee your [MASTER_KEY_ACTIVE] is created by secure source!")
	dbLogger.Info("Recommendation use openssl with isolated system for high entropy clean source.")
	if err := encryption.InitMasterKeys(); err != nil {
		return err
	}

	// Validate ACCOUNT_LOOKUP_PEPPER
	dbLogger.Info("Validation not guarantee your [ACCOUNT_LOOKUP_PEPPER] is created by secure source!")
	dbLogger.Info("Recommendation use openssl with isolated system for high entropy clean source.")
	pepper := config.GetAccountLookupPepper()
	if pepper == nil || len(pepper) < 32 {
		return fmt.Errorf("ACCOUNT_LOOKUP_PEPPER is required and must be at least 32 bytes (can be hex or base64 encoded). Use: openssl rand -hex 32")
	}
	dbLogger.Info("ACCOUNT_LOOKUP_PEPPER validated: length=%d bytes", len(pepper))

	// Validate request limits
	if config.GetMaxRequestBodyBytes() <= 0 {
		return fmt.Errorf("MAX_REQUEST_BODY_BYTES is required and must be > 0")
	}
	if config.GetMaxJSONDepth() <= 0 {
		return fmt.Errorf("MAX_JSON_DEPTH is required and must be > 0")
	}
	// Validate messaging limits
	if config.GetInviteTTL() <= 0 || config.GetMaxActiveInvites() <= 0 || config.GetMaxConversationsPerUser() <= 0 {
		return fmt.Errorf("INVITE_TTL_SEC, MAX_ACTIVE_INVITES and MAX_CONVERSATIONS_PER_USER must be > 0")
	}
	if config.GetMaxMessageBytes() <= 0 || config.GetMaxMessageBytes() > config.GetMaxRequestBodyBytes()/2 {
		return fmt.Errorf("MAX_MESSAGE_BYTES must be > 0 and fit (base64) inside MAX_REQUEST_BODY_BYTES")
	}
	if config.GetMessagePageLimit() <= 0 || config.GetMessagePageLimit() > 1000 {
		return fmt.Errorf("MESSAGE_PAGE_LIMIT must be between 1 and 1000")
	}
	if config.GetPoWChallengeTTL() <= 0 {
		return fmt.Errorf("POW_CHALLENGE_TTL_SEC must be between 1 and 3600")
	}
	if config.GetMessageTTLDays() <= 0 || config.GetMessageTTLDays() > config.MaxMessageTTLDays() {
		return fmt.Errorf("MESSAGE_TTL_DAYS must be between 1 and %d", config.MaxMessageTTLDays())
	}
	if config.GetInternalIDLength() <= 0 {
		return fmt.Errorf("INTERNAL_ID_LENGTH is required and must be > 0")
	}

	// Validate Argon2id parameters
	if config.GetArgon2MemoryKiB() <= 0 || config.GetArgon2Time() <= 0 || config.GetArgon2Parallelism() <= 0 ||
		config.GetArgon2SaltLength() <= 0 || config.GetArgon2HashLength() <= 0 {
		return fmt.Errorf("ARGON2_* parameters are required and must be > 0")
	}

	// Validate pending registration config
	if config.GetPendingTokenTTL() <= 0 {
		return fmt.Errorf("PENDING_TOKEN_TTL_SEC is required and must be > 0")
	}
	if config.GetPendingCleanupInterval() <= 0 {
		return fmt.Errorf("PENDING_CLEANUP_INTERVAL_SEC is required and must be > 0")
	}
	if config.GetPendingIDBytes() <= 0 {
		return fmt.Errorf("PENDING_ID_BYTES is required and must be > 0")
	}

	// Validate rate limiting config
	if config.GetRateLimitMaxTokens() <= 0 || config.GetRateLimitRefillIntervalSeconds() <= 0 ||
		config.GetRateLimitCleanupIntervalSeconds() <= 0 || config.GetRateLimitMaxBuckets() <= 0 {
		return fmt.Errorf("RATE_LIMIT_* configuration is required and must be > 0")
	}

	// Validate server configuration
	if config.GetBackendPort() == "" {
		return fmt.Errorf("BACKEND_PORT is required")
	}
	if config.GetServerReadHeaderTimeout() <= 0 || config.GetServerReadTimeout() <= 0 ||
		config.GetServerWriteTimeout() <= 0 || config.GetServerIdleTimeout() <= 0 {
		return fmt.Errorf("SERVER_*_TIMEOUT_SEC values are required and must be > 0")
	}
	if config.GetServerMaxHeaderBytes() <= 0 {
		return fmt.Errorf("SERVER_MAX_HEADER_BYTES is required and must be > 0")
	}

	// Validate database config
	if config.GetDBHost() == "" || config.GetDBPort() == "" || config.GetDBUser() == "" ||
		config.GetDBPassword() == "" || config.GetDBName() == "" || config.GetDBSSLMode() == "" {
		return fmt.Errorf("DB_* configuration is required")
	}

	// Validate CORS config
	if strings.TrimSpace(config.GetAllowedOrigins()) == "" {
		return fmt.Errorf("ALLOWED_ORIGINS is required")
	}

	// SECURITY: In production, validate stricter settings
	if config.IsProductionMode() {
		// Validate CORS is not wildcard
		if config.GetAllowedOrigins() == "*" {
			return fmt.Errorf("ALLOWED_ORIGINS cannot be '*' in production mode")
		}

		// Validate SSL mode
		if config.GetDBSSLMode() == "disable" {
			return fmt.Errorf("DB_SSL_MODE cannot be 'disable' in production mode")
		}

		// SECURITY: Production behind reverse proxy must configure trusted proxies
		// Without this, X-Forwarded-For headers are ignored and IP-based security fails
		if strings.TrimSpace(config.GetTrustedProxies()) == "" {
			dbLogger.Warn("TRUSTED_PROXIES not configured in production mode")
			dbLogger.Warn("If running behind reverse proxy (nginx/cloudflare), rate limiting and IP-based security will use proxy IP instead of client IP")
			dbLogger.Warn("Set TRUSTED_PROXIES to comma-separated list of proxy IPs/CIDRs (e.g., '10.0.0.0/8,172.16.0.0/12')")
		}

		// Validate log level (not debug in production)
		if config.GetLogLevel() == "debug" {
			dbLogger.Warn("LOG_LEVEL is set to 'debug' in production mode - consider using 'info' or higher")
		}

		dbLogger.Info("Production mode validation passed")
	}

	return nil
}
