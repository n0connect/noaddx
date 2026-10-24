package database

import (
	"encoding/hex"
	"noaddx/internal/auth"
	"noaddx/internal/identity"
	"testing"

	"noaddx/internal/database"
	"noaddx/internal/encryption"
	"noaddx/internal/models"
	"noaddx/tests/testutil"
)

// TestDatabaseMigration tests that database migrations run successfully
// This test should run BEFORE backend starts to ensure database is properly set up
func TestDatabaseMigration(t *testing.T) {
	// Setup test environment (includes encryption keys)
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	// Setup database environment variables
	// These should be set before database.Init() is called
	testutil.SetupTestDatabaseEnv()

	// Initialize database (this runs migrations)
	// This is what backend does on startup
	database.Init()

	// Verify database connection is established
	if database.DB == nil {
		t.Fatal("database.DB should not be nil after Init()")
	}

	// Verify tables exist
	if !database.DB.Migrator().HasTable(&models.User{}) {
		t.Error("users table should exist after migration")
	}

	for _, table := range []interface{}{&models.Invite{}, &models.Conversation{}, &models.ConversationMember{}, &models.Message{}} {
		if !database.DB.Migrator().HasTable(table) {
			t.Errorf("%T table should exist after migration", table)
		}
	}
}

// TestUserTableSchema tests that User table has correct schema
func TestUserTableSchema(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	// Setup database environment variables
	testutil.SetupTestDatabaseEnv()

	database.Init()

	// Check required columns exist
	hasUUID := database.DB.Migrator().HasColumn(&models.User{}, "uuid")
	if !hasUUID {
		t.Error("users table should have 'uuid' column")
	}

	hasAccountLookup := database.DB.Migrator().HasColumn(&models.User{}, "account_lookup")
	if !hasAccountLookup {
		t.Error("users table should have 'account_lookup' column")
	}

	hasAccountHash := database.DB.Migrator().HasColumn(&models.User{}, "account_hash")
	if !hasAccountHash {
		t.Error("users table should have 'account_hash' column")
	}

	for _, column := range []string{"public_key", "session_epoch", "conv_index_enc"} {
		if !database.DB.Migrator().HasColumn(&models.User{}, column) {
			t.Errorf("users table should have '%s' column", column)
		}
	}

	hasEncryptedKey := database.DB.Migrator().HasColumn(&models.User{}, "encrypted_key")
	if !hasEncryptedKey {
		t.Error("users table should have 'encrypted_key' column")
	}

	hasMasterKeyID := database.DB.Migrator().HasColumn(&models.User{}, "master_key_id")
	if !hasMasterKeyID {
		t.Error("users table should have 'master_key_id' column")
	}

	// Zero-identifier schema: when an identity was created or touched is never stored
	for _, forbidden := range []string{"created_at", "updated_at"} {
		if database.DB.Migrator().HasColumn(&models.User{}, forbidden) {
			t.Errorf("users table must not have '%s' column", forbidden)
		}
	}
}

// TestChatTableSchema tests that messaging tables store no plaintext-linkable columns
func TestChatTableSchema(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	// Setup database environment variables
	testutil.SetupTestDatabaseEnv()

	database.Init()

	expected := map[interface{}][]string{
		&models.Invite{}:             {"id", "lookup", "creator_tag", "creator_ref_enc", "master_key_id", "expires_at"},
		&models.Conversation{}:       {"id", "last_seq"},
		&models.ConversationMember{}: {"conversation_id", "member_tag", "member_ref_enc", "master_key_id", "peer_key_enc", "read_seq"},
		&models.Message{}:            {"conversation_id", "seq", "id", "sender_tag", "ciphertext", "expires_on"},
	}
	for model, columns := range expected {
		for _, column := range columns {
			if !database.DB.Migrator().HasColumn(model, column) {
				t.Errorf("%T should have column %q", model, column)
			}
		}
	}

	// Zero-identifier schema: no user UUID or timestamp columns on messaging tables
	for _, model := range []interface{}{&models.ConversationMember{}, &models.Message{}, &models.Conversation{}} {
		for _, forbidden := range []string{"user_uuid", "created_at", "updated_at"} {
			if database.DB.Migrator().HasColumn(model, forbidden) {
				t.Errorf("%T must not have column %q", model, forbidden)
			}
		}
	}
}

// TestUserTableIndexes tests that User table has correct indexes
func TestUserTableIndexes(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	// Setup database environment variables
	testutil.SetupTestDatabaseEnv()

	database.Init()

	if !database.DB.Migrator().HasIndex(&models.User{}, "idx_users_uuid") {
		t.Error("users table should have unique index 'idx_users_uuid' on 'uuid'")
	}

	if !database.DB.Migrator().HasIndex(&models.User{}, "idx_users_account_lookup") {
		t.Error("users table should have unique index 'idx_users_account_lookup' on 'account_lookup'")
	}

	if !database.DB.Migrator().HasIndex(&models.Message{}, "idx_messages_expires_on") {
		t.Error("messages table should index 'expires_on' for retention purges")
	}
	if !database.DB.Migrator().HasIndex(&models.Invite{}, "idx_invites_lookup") {
		t.Error("invites table should have unique index 'idx_invites_lookup'")
	}
}

// TestDatabaseConnection tests that database connection is working
func TestDatabaseConnection(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	// Setup database environment variables
	testutil.SetupTestDatabaseEnv()

	database.Init()

	// Test connection by executing a simple query
	var count int64
	if err := database.DB.Model(&models.User{}).Count(&count).Error; err != nil {
		t.Fatalf("Failed to query database: %v", err)
	}

	// Connection is working if query succeeds
	t.Logf("Database connection verified. Current user count: %d", count)
}

// TestDatabaseConstraints tests that database constraints are properly set
func TestDatabaseConstraints(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	// Setup database environment variables
	testutil.SetupTestDatabaseEnv()

	database.Init()

	// A complete row built by the real registration primitives, then each required
	// column nulled in turn: only the NOT NULL constraint can reject it
	realRow := func() map[string]interface{} {
		account := testutil.NewAccountNumber(t)
		authKey, err := identity.DeriveAuthKey(account)
		if err != nil {
			t.Fatalf("DeriveAuthKey: %v", err)
		}
		publicKey, err := identity.DerivePublicKey(account)
		if err != nil {
			t.Fatalf("DerivePublicKey: %v", err)
		}
		lookup, err := auth.ComputeAccountLookup(authKey)
		if err != nil {
			t.Fatalf("ComputeAccountLookup: %v", err)
		}
		hash, err := auth.HashAccountNumber(authKey)
		if err != nil {
			t.Fatalf("HashAccountNumber: %v", err)
		}
		userKey, err := encryption.GenerateUserAESKey()
		if err != nil {
			t.Fatalf("GenerateUserAESKey: %v", err)
		}
		wrapped, err := encryption.EncryptWithMasterKey(hex.EncodeToString(userKey))
		if err != nil {
			t.Fatalf("EncryptWithMasterKey: %v", err)
		}
		return map[string]interface{}{
			"uuid":           testutil.NewInternalID(t),
			"account_lookup": lookup,
			"account_hash":   hash,
			"public_key":     publicKey,
			"encrypted_key":  wrapped,
			"master_key_id":  encryption.ActiveMasterKeyID(),
		}
	}

	complete := realRow()
	if err := database.DB.Model(&models.User{}).Create(complete).Error; err != nil {
		t.Fatalf("a complete real row was rejected: %v", err)
	}
	database.DB.Where("uuid = ?", complete["uuid"]).Delete(&models.User{})

	for _, column := range []string{"uuid", "account_lookup", "account_hash", "encrypted_key"} {
		row := realRow()
		row[column] = nil
		if err := database.DB.Model(&models.User{}).Create(row).Error; err == nil {
			t.Errorf("a row with NULL %s was accepted (NOT NULL constraint missing)", column)
			database.DB.Where("account_lookup = ?", row["account_lookup"]).Delete(&models.User{})
		}
	}
}

// TestDatabaseMasterKey tests that master key is initialized
func TestDatabaseMasterKey(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	// Setup database environment variables
	testutil.SetupTestDatabaseEnv()

	database.Init()

	if encryption.ActiveMasterKeyID() == "" {
		t.Fatal("ActiveMasterKeyID should not be empty after Init()")
	}
	if len(encryption.ActiveMasterKey()) != 32 {
		t.Errorf("ActiveMasterKey length = %d, want 32", len(encryption.ActiveMasterKey()))
	}
}
