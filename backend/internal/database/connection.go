package database

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"noaddx/internal/config"
	"noaddx/internal/encryption"
	"noaddx/internal/models"
	"noaddx/internal/utils"

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

// Connection pool bounds: a flood of requests queues for a connection instead of exhausting
// PostgreSQL's max_connections (default 100)
const (
	maxOpenConns    = 20
	maxIdleConns    = 10
	connMaxLifetime = 30 * time.Minute
)

// ConnectionURL builds the PostgreSQL URL with every component escaped, so credentials can
// contain any character without altering the connection parameters (no DSN injection).
func ConnectionURL() string {
	query := url.Values{}
	query.Set("sslmode", config.GetDBSSLMode())
	query.Set("TimeZone", "UTC")
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(config.GetDBUser(), config.GetDBPassword()),
		Host:     net.JoinHostPort(config.GetDBHost(), config.GetDBPort()),
		Path:     "/" + config.GetDBName(),
		RawQuery: query.Encode(),
	}
	return u.String()
}

func Init() {
	dbLogger.Info("Initializing database connection...")

	var err error
	DB, err = gorm.Open(postgres.Open(ConnectionURL()), &gorm.Config{
		Logger:         logger.Default.LogMode(gormLogLevel()),
		TranslateError: true, // Surfaces unique violations as gorm.ErrDuplicatedKey
	})
	if err != nil {
		dbLogger.LogError("Database connection", err)
		log.Fatal("Failed to connect to database")
	}
	sqlDB, err := DB.DB()
	if err != nil {
		dbLogger.LogError("Database pool", err)
		log.Fatal("Failed to configure database pool")
	}
	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetMaxIdleConns(maxIdleConns)
	sqlDB.SetConnMaxLifetime(connMaxLifetime)
	dbLogger.Info("Connected to PostgreSQL")

	if err := encryption.InitMasterKeys(); err != nil {
		dbLogger.LogError("Master key initialization", err)
		log.Fatal("Failed to initialize master keys")
	}

	err = DB.AutoMigrate(&models.User{}, &models.Invite{}, &models.Conversation{}, &models.ConversationMember{}, &models.Message{})
	if err != nil {
		dbLogger.LogError("Database migration", err)
		log.Fatal("Failed to migrate database")
	}
	dbLogger.Info("Database migrations completed")
}

// bounded is one numeric setting with its inclusive range (RULES.md §5.1: type, range,
// whitelist). Unparseable values read as 0 and fail the range check.
type bounded struct {
	key      string
	value    int
	min, max int
}

func checkBounds(settings []bounded) error {
	for _, s := range settings {
		if s.value < s.min || s.value > s.max {
			return fmt.Errorf("%s must be an integer between %d and %d", s.key, s.min, s.max)
		}
	}
	return nil
}

func seconds(d time.Duration) int { return int(d / time.Second) }

var (
	allowedAppEnvs   = map[string]struct{}{"development": {}, "test": {}, "production": {}, "prod": {}}
	allowedLogLevels = map[string]struct{}{"debug": {}, "info": {}, "warn": {}, "error": {}}
	allowedSSLModes  = map[string]struct{}{"disable": {}, "allow": {}, "prefer": {}, "require": {}, "verify-ca": {}, "verify-full": {}}
	// Production must authenticate the database server, not just encrypt to whoever answers
	productionSSLModes = map[string]struct{}{"verify-ca": {}, "verify-full": {}}
)

// minProductionDBPasswordLen rejects well-known defaults such as "postgres" in production
const minProductionDBPasswordLen = 16

// ValidateStartupConfig validates all configuration at startup; the server refuses to start
// on any value outside its whitelist or range.
func ValidateStartupConfig() error {
	if _, ok := allowedAppEnvs[strings.ToLower(strings.TrimSpace(config.GetEnv("APP_ENV", "development")))]; !ok {
		return fmt.Errorf("APP_ENV must be one of development, test, production")
	}
	if _, ok := allowedLogLevels[config.GetLogLevel()]; !ok {
		return fmt.Errorf("LOG_LEVEL must be one of debug, info, warn, error")
	}

	minJWTLen := config.GetJWTSecretMinLength()
	argon2Floor := config.MinArgon2MemoryKiB
	if config.IsProductionMode() {
		argon2Floor = config.ProductionMinArgon2MemoryKiB
	}
	port, _ := strconv.Atoi(config.GetBackendPort())
	if err := checkBounds([]bounded{
		{"JWT_SECRET_MIN_LEN", minJWTLen, 32, 1024},
		{"JWT_EXPIRATION_MINUTES", int(config.GetJWTExpiration() / time.Minute), 1, 1440},
		{"MAX_REQUEST_BODY_BYTES", config.GetMaxRequestBodyBytes(), 1024, 16 << 20},
		{"MAX_JSON_DEPTH", config.GetMaxJSONDepth(), 1, 8},
		{"INVITE_TTL_SEC", seconds(config.GetInviteTTL()), 60, 7 * 24 * 3600},
		{"MAX_ACTIVE_INVITES", config.GetMaxActiveInvites(), 1, 100},
		{"MAX_CONVERSATIONS_PER_USER", config.GetMaxConversationsPerUser(), 1, 4096},
		{"MAX_MESSAGE_BYTES", config.GetMaxMessageBytes(), 512, 65536},
		{"MESSAGE_PAGE_LIMIT", config.GetMessagePageLimit(), 1, 1000},
		{"MESSAGE_TTL_DAYS", config.GetMessageTTLDays(), 1, config.MaxMessageTTLDays()},
		{"POW_CHALLENGE_TTL_SEC", seconds(config.GetPoWChallengeTTL()), 1, 3600},
		{"POW_DIFFICULTY", config.GetPoWDifficulty(), config.MinPoWDifficulty(), config.MaxPoWDifficulty()},
		{"INTERNAL_ID_LENGTH", config.GetInternalIDLength(), 16, 24}, // users.uuid is size:24
		{"ARGON2_MEMORY_KIB", config.GetArgon2MemoryKiB(), argon2Floor, config.MaxArgon2MemoryKiB},
		{"ARGON2_TIME", config.GetArgon2Time(), config.MinArgon2Time, config.MaxArgon2Time},
		{"ARGON2_PARALLELISM", config.GetArgon2Parallelism(), config.MinArgon2Parallelism, config.MaxArgon2Parallelism},
		{"ARGON2_SALT_LENGTH", config.GetArgon2SaltLength(), config.MinArgon2SaltBytes, config.MaxArgon2SaltBytes},
		{"ARGON2_HASH_LENGTH", config.GetArgon2HashLength(), config.MinArgon2HashBytes, config.MaxArgon2HashBytes},
		{"ARGON2_MAX_CONCURRENT", config.GetArgon2MaxConcurrent(), 1, 64},
		{"PENDING_TOKEN_TTL_SEC", seconds(config.GetPendingTokenTTL()), 30, 3600},
		{"PENDING_CLEANUP_INTERVAL_SEC", seconds(config.GetPendingCleanupInterval()), 1, 3600},
		{"PENDING_ID_BYTES", config.GetPendingIDBytes(), 16, 64},
		{"RATE_LIMIT_MAX_TOKENS", config.GetRateLimitMaxTokens(), 1, 10000},
		{"RATE_LIMIT_REFILL_INTERVAL_SEC", config.GetRateLimitRefillIntervalSeconds(), 1, 3600},
		{"RATE_LIMIT_CLEANUP_INTERVAL_SEC", config.GetRateLimitCleanupIntervalSeconds(), 1, 86400},
		{"RATE_LIMIT_MAX_BUCKETS", config.GetRateLimitMaxBuckets(), 100, 1000000},
		{"BACKEND_PORT", port, 1, 65535},
		{"SERVER_READ_HEADER_TIMEOUT_SEC", seconds(config.GetServerReadHeaderTimeout()), 1, 60},
		{"SERVER_READ_TIMEOUT_SEC", seconds(config.GetServerReadTimeout()), 1, 300},
		{"SERVER_WRITE_TIMEOUT_SEC", seconds(config.GetServerWriteTimeout()), 1, 300},
		{"SERVER_IDLE_TIMEOUT_SEC", seconds(config.GetServerIdleTimeout()), 1, 600},
		{"SERVER_MAX_HEADER_BYTES", config.GetServerMaxHeaderBytes(), 1024, 1 << 20},
	}); err != nil {
		return err
	}

	if len(config.GetJWTSecret()) < minJWTLen {
		return fmt.Errorf("JWT_SECRET must be at least %d characters (generate it: openssl rand -hex 32)", minJWTLen)
	}
	if config.GetJWTIssuer() == "" || config.GetJWTAudience() == "" {
		return fmt.Errorf("JWT_ISSUER and JWT_AUDIENCE are required")
	}
	if err := encryption.InitMasterKeys(); err != nil {
		return err
	}
	if config.GetAccountLookupPepper() == nil {
		return fmt.Errorf("ACCOUNT_LOOKUP_PEPPER must be at least 32 bytes as hex or base64 (generate it: openssl rand -hex 32)")
	}
	if config.GetMaxMessageBytes() > config.GetMaxRequestBodyBytes()/2 {
		return fmt.Errorf("MAX_MESSAGE_BYTES must fit (base64) inside MAX_REQUEST_BODY_BYTES")
	}

	if config.GetDBHost() == "" || config.GetDBPort() == "" || config.GetDBUser() == "" ||
		config.GetDBPassword() == "" || config.GetDBName() == "" {
		return fmt.Errorf("DB_HOST, DB_PORT, DB_USER, DB_PASSWORD and DB_NAME are required")
	}
	if _, ok := allowedSSLModes[config.GetDBSSLMode()]; !ok {
		return fmt.Errorf("DB_SSL_MODE must be a libpq sslmode (disable, require, verify-ca, verify-full, ...)")
	}
	if strings.TrimSpace(config.GetAllowedOrigins()) == "" || config.GetAllowedOrigins() == "*" {
		return fmt.Errorf("ALLOWED_ORIGINS must list exact origins (no wildcard)")
	}

	if config.IsProductionMode() {
		if _, ok := productionSSLModes[config.GetDBSSLMode()]; !ok {
			return fmt.Errorf("DB_SSL_MODE must be verify-ca or verify-full in production")
		}
		if len(config.GetDBPassword()) < minProductionDBPasswordLen {
			return fmt.Errorf("DB_PASSWORD must be at least %d characters in production", minProductionDBPasswordLen)
		}
		if strings.TrimSpace(config.GetTrustedProxies()) == "" {
			dbLogger.Warn("TRUSTED_PROXIES is empty: behind a reverse proxy every client shares one rate-limit bucket")
		}
		if config.GetLogLevel() == "debug" {
			return fmt.Errorf("LOG_LEVEL=debug is not allowed in production")
		}
		dbLogger.Info("Production mode validation passed")
	}
	return nil
}
