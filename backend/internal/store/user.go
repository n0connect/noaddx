package store

import (
	"errors"

	"noaddress/internal/database"
	"noaddress/internal/models"
	"noaddress/internal/utils"

	"gorm.io/gorm"
)

var userRepoLogger = utils.NewLogger("USER_REPOSITORY")

// UserRepository defines the interface for user data access
type UserRepository interface {
	FindByUUID(uuid string) (*models.User, error)
	FindByAccountLookup(lookup string) (*models.User, error)
	Create(user *models.User) error
	ExistsByAccountLookup(lookup string) (bool, error)
	BumpSessionEpoch(uuid string) error
}

// userRepository implements UserRepository
type userRepository struct{}

// NewUserRepository creates a new UserRepository instance
func NewUserRepository() UserRepository {
	return &userRepository{}
}

// FindByUUID finds a user by UUID
func (r *userRepository) FindByUUID(uuid string) (*models.User, error) {
	var user models.User
	result := database.DB.Where("uuid = ?", uuid).First(&user)
	if result.Error != nil {
		userRepoLogger.LogError("UserRepository.FindByUUID", result.Error)
		// Wrap GORM's ErrRecordNotFound as ErrNotFound for consistent error handling
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, result.Error
	}
	return &user, nil
}

// Create creates a new user
func (r *userRepository) Create(user *models.User) error {
	err := database.DB.Create(user).Error
	if err != nil {
		userRepoLogger.LogError("UserRepository.Create", err)
		return err
	}
	return nil
}

// FindByAccountLookup finds a user by account lookup (HMAC)
func (r *userRepository) FindByAccountLookup(lookup string) (*models.User, error) {
	var user models.User
	result := database.DB.Where("account_lookup = ?", lookup).First(&user)
	if result.Error != nil {
		userRepoLogger.LogError("UserRepository.FindByAccountLookup", result.Error)
		// Wrap GORM's ErrRecordNotFound as ErrNotFound for consistent error handling
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, result.Error
	}
	return &user, nil
}

// ExistsByAccountLookup checks if a user exists with the given account lookup
func (r *userRepository) ExistsByAccountLookup(lookup string) (bool, error) {
	var count int64
	result := database.DB.Model(&models.User{}).Where("account_lookup = ?", lookup).Count(&count)
	if result.Error != nil {
		userRepoLogger.LogError("UserRepository.ExistsByAccountLookup", result.Error)
		return false, result.Error
	}
	exists := count > 0
	return exists, nil
}

// BumpSessionEpoch invalidates every JWT issued to the user (logout = revoke all sessions)
func (r *userRepository) BumpSessionEpoch(uuid string) error {
	result := database.DB.Model(&models.User{}).Where("uuid = ?", uuid).
		UpdateColumn("session_epoch", gorm.Expr("session_epoch + 1"))
	if result.Error != nil {
		userRepoLogger.LogError("UserRepository.BumpSessionEpoch", result.Error)
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}
