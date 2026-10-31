package store

import (
	"errors"

	"noaddx/internal/database"
	"noaddx/internal/models"
	"noaddx/internal/utils"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var keyRepoLogger = utils.NewLogger("KEY_REPOSITORY")

// KeyRepository finds and re-wraps records by the master key that encrypts them, and keeps
// the commitments the startup key check compares against. Three tables hold master-key
// encrypted values: users.encrypted_key, conversation_members.member_ref_enc and
// invites.creator_ref_enc, each next to the id of the key that wrote it.
type KeyRepository interface {
	MasterKeyIDsInUse() (map[string]struct{}, error)
	HasUsers() (bool, error)

	// Rows under keyID in primary-key order, after a cursor (the zero value starts at the top)
	UsersUnderKey(keyID string, afterID uint, limit int) ([]models.User, error)
	MembersUnderKey(keyID string, after models.ConversationMember, limit int) ([]models.ConversationMember, error)
	InvitesUnderKey(keyID string, after uuid.UUID, limit int) ([]models.Invite, error)

	// Replace one encrypted value, only if the row still names fromKeyID (no lost updates)
	RewrapUser(id uint, fromKeyID, toKeyID, enc string) error
	RewrapMember(member *models.ConversationMember, fromKeyID, toKeyID, enc string) error
	RewrapInvite(id uuid.UUID, fromKeyID, toKeyID, enc string) error

	KeyCheck(name string) (string, bool, error)
	PinKeyCheck(name, value string) error
}

type keyRepository struct{}

// NewKeyRepository creates a new KeyRepository instance
func NewKeyRepository() KeyRepository {
	return &keyRepository{}
}

func (r *keyRepository) MasterKeyIDsInUse() (map[string]struct{}, error) {
	inUse := make(map[string]struct{})
	for _, model := range []interface{}{&models.User{}, &models.ConversationMember{}, &models.Invite{}} {
		var ids []string
		if err := database.DB.Model(model).Distinct().Pluck("master_key_id", &ids).Error; err != nil {
			keyRepoLogger.LogError("KeyRepository.MasterKeyIDsInUse", err)
			return nil, err
		}
		for _, id := range ids {
			inUse[id] = struct{}{}
		}
	}
	return inUse, nil
}

func (r *keyRepository) HasUsers() (bool, error) {
	var ids []uint
	if err := database.DB.Model(&models.User{}).Limit(1).Pluck("id", &ids).Error; err != nil {
		keyRepoLogger.LogError("KeyRepository.HasUsers", err)
		return false, err
	}
	return len(ids) > 0, nil
}

func (r *keyRepository) UsersUnderKey(keyID string, afterID uint, limit int) ([]models.User, error) {
	var users []models.User
	err := database.DB.Where("master_key_id = ? AND id > ?", keyID, afterID).Order("id").Limit(limit).Find(&users).Error
	if err != nil {
		keyRepoLogger.LogError("KeyRepository.UsersUnderKey", err)
	}
	return users, err
}

func (r *keyRepository) MembersUnderKey(keyID string, after models.ConversationMember, limit int) ([]models.ConversationMember, error) {
	var members []models.ConversationMember
	err := database.DB.Where("master_key_id = ? AND (conversation_id, member_tag) > (?, ?)", keyID, after.ConversationID, after.MemberTag).
		Order("conversation_id, member_tag").Limit(limit).Find(&members).Error
	if err != nil {
		keyRepoLogger.LogError("KeyRepository.MembersUnderKey", err)
	}
	return members, err
}

func (r *keyRepository) InvitesUnderKey(keyID string, after uuid.UUID, limit int) ([]models.Invite, error) {
	var invites []models.Invite
	err := database.DB.Where("master_key_id = ? AND id > ?", keyID, after).Order("id").Limit(limit).Find(&invites).Error
	if err != nil {
		keyRepoLogger.LogError("KeyRepository.InvitesUnderKey", err)
	}
	return invites, err
}

func rewrap(model interface{}, column, fromKeyID, toKeyID, enc, where string, args ...interface{}) error {
	err := database.DB.Model(model).Where(where+" AND master_key_id = ?", append(args, fromKeyID)...).
		UpdateColumns(map[string]interface{}{column: enc, "master_key_id": toKeyID}).Error
	if err != nil {
		keyRepoLogger.LogError("KeyRepository.rewrap", err)
	}
	return err
}

func (r *keyRepository) RewrapUser(id uint, fromKeyID, toKeyID, enc string) error {
	return rewrap(&models.User{}, "encrypted_key", fromKeyID, toKeyID, enc, "id = ?", id)
}

func (r *keyRepository) RewrapMember(member *models.ConversationMember, fromKeyID, toKeyID, enc string) error {
	return rewrap(&models.ConversationMember{}, "member_ref_enc", fromKeyID, toKeyID, enc,
		"conversation_id = ? AND member_tag = ?", member.ConversationID, member.MemberTag)
}

func (r *keyRepository) RewrapInvite(id uuid.UUID, fromKeyID, toKeyID, enc string) error {
	return rewrap(&models.Invite{}, "creator_ref_enc", fromKeyID, toKeyID, enc, "id = ?", id)
}

func (r *keyRepository) KeyCheck(name string) (string, bool, error) {
	var check models.KeyCheck
	err := database.DB.Where("name = ?", name).First(&check).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", false, nil
	}
	if err != nil {
		keyRepoLogger.LogError("KeyRepository.KeyCheck", err)
		return "", false, err
	}
	return check.Value, true, nil
}

// PinKeyCheck stores a commitment once; an existing one is never overwritten
func (r *keyRepository) PinKeyCheck(name, value string) error {
	err := database.DB.Clauses(clause.OnConflict{DoNothing: true}).Create(&models.KeyCheck{Name: name, Value: value}).Error
	if err != nil {
		keyRepoLogger.LogError("KeyRepository.PinKeyCheck", err)
	}
	return err
}
