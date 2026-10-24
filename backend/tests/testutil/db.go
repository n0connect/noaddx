//go:build test
// +build test

package testutil

import (
	"testing"

	"noaddx/internal/database"
	"noaddx/internal/models"

	"gorm.io/gorm"
)

// InitializeTestDatabase initializes the global database connection for tests
// This should be called once before running tests that require database
// It also resets global state (rate limiter, pending store) for test isolation
func InitializeTestDatabase(t *testing.T) {
	t.Helper()

	// Setup test environment
	SetupTestEnv(t)

	// Initialize database (this sets database.DB)
	database.Init()

	// Reset global state for test isolation
	// This ensures each test starts with a clean state
	resetGlobalStateForTesting(t)
}

// resetGlobalStateForTesting resets all global state that could affect test isolation
// SECURITY: This function calls test-only reset functions that are only available
// when compiled with -tags test. In production builds, these functions don't exist.
func resetGlobalStateForTesting(t *testing.T) {
	t.Helper()

	// Reset rate limiter (prevents rate limit state from affecting tests)
	// SECURITY: ResetRateLimiterForTesting is only available in test builds
	// It will NOT be compiled into production binaries
	resetRateLimiterForTesting()

	// Reset pending store (prevents pending registrations from affecting tests)
	// SECURITY: ResetPendingStoreForTesting is only available in test builds
	// It will NOT be compiled into production binaries
	resetPendingStoreForTesting()
}

// allModels lists every table, children before parents
func allModels() []interface{} {
	return []interface{}{&models.Message{}, &models.ConversationMember{}, &models.Conversation{}, &models.Invite{}, &models.User{}}
}

// CleanupTestData removes all test data created during tests
// This should be called in defer after each test that creates data
func CleanupTestData(t *testing.T) {
	t.Helper()

	if database.DB == nil {
		return
	}

	for _, model := range allModels() {
		if err := database.DB.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(model).Error; err != nil {
			t.Logf("Failed to cleanup %T: %v", model, err)
		}
	}
}
