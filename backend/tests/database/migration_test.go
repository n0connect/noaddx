package database

import (
	"testing"

	"noaddress/internal/database"
	"noaddress/internal/encryption"
	"noaddress/internal/models"
	"noaddress/tests/testutil"
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

	for _, column := range []string{"public_key", "session_epoch"} {
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

	hasCreatedAt := database.DB.Migrator().HasColumn(&models.User{}, "created_at")
	if !hasCreatedAt {
		t.Error("users table should have 'created_at' column")
	}

	hasUpdatedAt := database.DB.Migrator().HasColumn(&models.User{}, "updated_at")
	if !hasUpdatedAt {
		t.Error("users table should have 'updated_at' column")
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
		&models.Invite{}:             {"id", "lookup", "creator_tag", "creator_enc", "master_key_id", "expires_at"},
		&models.Conversation{}:       {"id"},
		&models.ConversationMember{}: {"conversation_id", "member_tag", "peer_key_enc", "read_seq"},
		&models.Message{}:            {"seq", "id", "conversation_id", "sender_tag", "ciphertext"},
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

	if !database.DB.Migrator().HasIndex(&models.Message{}, "idx_messages_conversation_seq") {
		t.Error("messages table should have composite index 'idx_messages_conversation_seq'")
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

	// Test NOT NULL constraint on account_lookup
	accountLookupUUID := "test-uuid-123456789012"
	err := database.DB.Model(&models.User{}).Create(map[string]interface{}{
		"uuid":           accountLookupUUID,
		"account_lookup": nil,
		"account_hash":   "test-hash",
		"encrypted_key":  "test-key",
		"master_key_id":  "test-key-id",
	}).Error
	if err == nil {
		t.Error("Creating user with NULL account_lookup should fail (NOT NULL constraint)")
		database.DB.Where("uuid = ?", accountLookupUUID).Delete(&models.User{})
	} else {
		t.Logf("Expected error when creating user with NULL account_lookup: %v", err)
	}

	// Test NOT NULL constraint on account_hash
	accountHashUUID := "test-uuid-987654321098"
	err = database.DB.Model(&models.User{}).Create(map[string]interface{}{
		"uuid":           accountHashUUID,
		"account_lookup": "test-lookup",
		"account_hash":   nil,
		"encrypted_key":  "test-key",
		"master_key_id":  "test-key-id",
	}).Error
	if err == nil {
		t.Error("Creating user with NULL account_hash should fail (NOT NULL constraint)")
		database.DB.Where("uuid = ?", accountHashUUID).Delete(&models.User{})
	} else {
		t.Logf("Expected error when creating user with NULL account_hash: %v", err)
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
