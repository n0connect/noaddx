package database

import (
	"net/url"
	"testing"

	"noaddx/internal/config"
	"noaddx/internal/database"
	"noaddx/internal/encryption"
	"noaddx/tests/testutil"
)

func validate(t *testing.T) error {
	t.Helper()
	encryption.ResetMasterKeysForTesting()
	t.Cleanup(encryption.ResetMasterKeysForTesting)
	return database.ValidateStartupConfig()
}

// Every numeric knob has a minimum and a maximum (RULES.md §5.1): a value outside the range
// stops startup instead of being silently clamped, truncated or overflowed.
func TestValidateStartupConfig_RejectsOutOfRangeValues(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	if err := validate(t); err != nil {
		t.Fatalf("baseline test configuration rejected: %v", err)
	}

	cases := map[string][2]string{
		"argon2 lanes overflow uint8":   {"ARGON2_PARALLELISM", "256"},
		"argon2 memory over 1 GiB":      {"ARGON2_MEMORY_KIB", "2097152"},
		"argon2 memory below floor":     {"ARGON2_MEMORY_KIB", "64"},
		"argon2 time over bound":        {"ARGON2_TIME", "1000"},
		"argon2 salt too short":         {"ARGON2_SALT_LENGTH", "8"},
		"argon2 hash too short":         {"ARGON2_HASH_LENGTH", "8"},
		"jwt min length below 32":       {"JWT_SECRET_MIN_LEN", "8"},
		"jwt secret below 32 bytes":     {"JWT_SECRET", "0123456789abcdef"},
		"internal id beyond column":     {"INTERNAL_ID_LENGTH", "40"},
		"internal id too short":         {"INTERNAL_ID_LENGTH", "8"},
		"pending id below 128 bits":     {"PENDING_ID_BYTES", "4"},
		"pow difficulty out of range":   {"POW_DIFFICULTY", "40"},
		"pow difficulty below floor":    {"POW_DIFFICULTY", "4"},
		"unknown sslmode":               {"DB_SSL_MODE", "sometimes"},
		"rate limit buckets unbounded":  {"RATE_LIMIT_MAX_BUCKETS", "100000000"},
		"body limit over 16 MiB":        {"MAX_REQUEST_BODY_BYTES", "99999999"},
		"json depth too deep":           {"MAX_JSON_DEPTH", "64"},
		"invite ttl over 7 days":        {"INVITE_TTL_SEC", "9999999"},
		"session lifetime over a day":   {"JWT_EXPIRATION_MINUTES", "100000"},
		"conversations per user absurd": {"MAX_CONVERSATIONS_PER_USER", "1000000"},
		"non-numeric value":             {"MAX_ACTIVE_INVITES", "five"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv(c[0], c[1])
			if err := validate(t); err == nil {
				t.Errorf("%s=%s accepted", c[0], c[1])
			}
		})
	}
}

// Production mode raises the floors: verified TLS to the database and OWASP Argon2 memory.
func TestValidateStartupConfig_ProductionFloors(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("DB_SSL_MODE", "verify-full")
	t.Setenv("ARGON2_MEMORY_KIB", "65536")
	t.Setenv("ARGON2_TIME", "3")
	t.Setenv("DB_PASSWORD", testutil.NewAuthKey(t))
	if err := validate(t); err != nil {
		t.Fatalf("hardened production configuration rejected: %v", err)
	}

	for name, c := range map[string][2]string{
		"plaintext database link":    {"DB_SSL_MODE", "disable"},
		"unauthenticated tls":        {"DB_SSL_MODE", "require"},
		"argon2 below owasp minimum": {"ARGON2_MEMORY_KIB", "16384"},
		"default database password":  {"DB_PASSWORD", "postgres"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(c[0], c[1])
			if err := validate(t); err == nil {
				t.Errorf("production accepted %s=%s", c[0], c[1])
			}
		})
	}
}

// Credentials can contain any character without changing the connection parameters
// (a password like "x sslmode=disable" must stay a password).
func TestConnectionURL_EscapesCredentials(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	password := testutil.NewAuthKey(t) + " sslmode=disable host=evil.example '\\"
	user := "app user@x"
	t.Setenv("DB_PASSWORD", password)
	t.Setenv("DB_USER", user)
	t.Setenv("DB_SSL_MODE", "verify-full")

	parsed, err := url.Parse(database.ConnectionURL())
	if err != nil {
		t.Fatalf("connection URL does not parse: %v", err)
	}
	gotPassword, _ := parsed.User.Password()
	if parsed.User.Username() != user || gotPassword != password {
		t.Fatalf("credentials changed in transit: user=%q", parsed.User.Username())
	}
	query := parsed.Query()
	if parsed.Hostname() != config.GetDBHost() || query.Get("sslmode") != "verify-full" || len(query["sslmode"]) != 1 || query.Get("host") != "" {
		t.Fatalf("connection parameters were altered: %s", parsed.Redacted())
	}
}
