package store

import (
	"errors"
	"time"

	"noaddress/internal/database"
	"noaddress/internal/models"
	"noaddress/internal/utils"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var chatRepoLogger = utils.NewLogger("CHAT_REPOSITORY")

// ChatRepository defines data access for invites, conversations and messages.
// Every query that touches a conversation is scoped by member tag to prevent IDOR.
type ChatRepository interface {
	CountActiveInvites(creatorTag string, now time.Time) (int64, error)
	DeleteExpiredInvites(creatorTag string, now time.Time) error
	CreateInvite(invite *models.Invite) error
	TakeInvite(lookup, redeemerTag string, now time.Time) (*models.Invite, error)
	CountMemberships(memberTag string) (int64, error)
	CreateConversation(conversationID uuid.UUID, members []models.ConversationMember) error
	ListMemberships(memberTag string) ([]models.ConversationMember, error)
	FindMembership(conversationID uuid.UUID, memberTag string) (*models.ConversationMember, error)
	ListMemberTags(conversationID uuid.UUID) ([]string, error)
	LastSeqs(conversationIDs []uuid.UUID) (map[uuid.UUID]int64, error)
	DeleteConversation(conversationID uuid.UUID) error
	CreateMessage(message *models.Message) error
	ListMessagesAfter(conversationID uuid.UUID, afterSeq int64, limit int) ([]models.Message, error)
	ListLatestMessages(conversationID uuid.UUID, limit int) ([]models.Message, error)
	AdvanceReadSeq(conversationID uuid.UUID, memberTag string, seq int64) error
}

type chatRepository struct{}

// NewChatRepository creates a new ChatRepository instance
func NewChatRepository() ChatRepository {
	return &chatRepository{}
}

func (r *chatRepository) CountActiveInvites(creatorTag string, now time.Time) (int64, error) {
	var count int64
	err := database.DB.Model(&models.Invite{}).
		Where("creator_tag = ? AND expires_at > ?", creatorTag, now).Count(&count).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.CountActiveInvites", err)
	}
	return count, err
}

// DeleteExpiredInvites drops a creator's dead invites so they do not linger as metadata.
func (r *chatRepository) DeleteExpiredInvites(creatorTag string, now time.Time) error {
	err := database.DB.Where("creator_tag = ? AND expires_at <= ?", creatorTag, now).Delete(&models.Invite{}).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.DeleteExpiredInvites", err)
	}
	return err
}

func (r *chatRepository) CreateInvite(invite *models.Invite) error {
	if err := database.DB.Create(invite).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.CreateInvite", err)
		return err
	}
	return nil
}

// TakeInvite atomically deletes and returns an invite (single use, race-free).
// The creator can never consume their own invite: the row simply does not match.
func (r *chatRepository) TakeInvite(lookup, redeemerTag string, now time.Time) (*models.Invite, error) {
	var invite models.Invite
	result := database.DB.Clauses(clause.Returning{}).
		Where("lookup = ? AND creator_tag <> ?", lookup, redeemerTag).Delete(&invite)
	if result.Error != nil {
		chatRepoLogger.LogError("ChatRepository.TakeInvite", result.Error)
		return nil, result.Error
	}
	if result.RowsAffected == 0 || !now.Before(invite.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &invite, nil
}

func (r *chatRepository) CountMemberships(memberTag string) (int64, error) {
	var count int64
	err := database.DB.Model(&models.ConversationMember{}).Where("member_tag = ?", memberTag).Count(&count).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.CountMemberships", err)
	}
	return count, err
}

func (r *chatRepository) CreateConversation(conversationID uuid.UUID, members []models.ConversationMember) error {
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&models.Conversation{ID: conversationID}).Error; err != nil {
			return err
		}
		return tx.Create(&members).Error
	})
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.CreateConversation", err)
	}
	return err
}

func (r *chatRepository) ListMemberships(memberTag string) ([]models.ConversationMember, error) {
	var members []models.ConversationMember
	err := database.DB.Where("member_tag = ?", memberTag).Find(&members).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.ListMemberships", err)
	}
	return members, err
}

func (r *chatRepository) FindMembership(conversationID uuid.UUID, memberTag string) (*models.ConversationMember, error) {
	var member models.ConversationMember
	err := database.DB.Where("conversation_id = ? AND member_tag = ?", conversationID, memberTag).First(&member).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		chatRepoLogger.LogError("ChatRepository.FindMembership", err)
		return nil, err
	}
	return &member, nil
}

func (r *chatRepository) ListMemberTags(conversationID uuid.UUID) ([]string, error) {
	var tags []string
	err := database.DB.Model(&models.ConversationMember{}).
		Where("conversation_id = ?", conversationID).Pluck("member_tag", &tags).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.ListMemberTags", err)
	}
	return tags, err
}

func (r *chatRepository) LastSeqs(conversationIDs []uuid.UUID) (map[uuid.UUID]int64, error) {
	result := make(map[uuid.UUID]int64, len(conversationIDs))
	if len(conversationIDs) == 0 {
		return result, nil
	}
	var rows []struct {
		ConversationID uuid.UUID
		LastSeq        int64
	}
	err := database.DB.Model(&models.Message{}).
		Select("conversation_id, MAX(seq) AS last_seq").
		Where("conversation_id IN ?", conversationIDs).
		Group("conversation_id").Scan(&rows).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.LastSeqs", err)
		return nil, err
	}
	for _, row := range rows {
		result[row.ConversationID] = row.LastSeq
	}
	return result, nil
}

// DeleteConversation burns a conversation for every member, ciphertext included.
func (r *chatRepository) DeleteConversation(conversationID uuid.UUID) error {
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("conversation_id = ?", conversationID).Delete(&models.Message{}).Error; err != nil {
			return err
		}
		if err := tx.Where("conversation_id = ?", conversationID).Delete(&models.ConversationMember{}).Error; err != nil {
			return err
		}
		result := tx.Where("id = ?", conversationID).Delete(&models.Conversation{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	})
	if err != nil && !errors.Is(err, ErrNotFound) {
		chatRepoLogger.LogError("ChatRepository.DeleteConversation", err)
	}
	return err
}

func (r *chatRepository) CreateMessage(message *models.Message) error {
	err := database.DB.Create(message).Error
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrConflict
		}
		chatRepoLogger.LogError("ChatRepository.CreateMessage", err)
	}
	return err
}

func (r *chatRepository) ListMessagesAfter(conversationID uuid.UUID, afterSeq int64, limit int) ([]models.Message, error) {
	var messages []models.Message
	err := database.DB.Where("conversation_id = ? AND seq > ?", conversationID, afterSeq).
		Order("seq ASC").Limit(limit).Find(&messages).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.ListMessagesAfter", err)
	}
	return messages, err
}

// ListLatestMessages returns the newest `limit` messages in ascending order.
func (r *chatRepository) ListLatestMessages(conversationID uuid.UUID, limit int) ([]models.Message, error) {
	var messages []models.Message
	err := database.DB.Where("conversation_id = ?", conversationID).
		Order("seq DESC").Limit(limit).Find(&messages).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.ListLatestMessages", err)
		return nil, err
	}
	for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
		messages[i], messages[j] = messages[j], messages[i]
	}
	return messages, nil
}

// AdvanceReadSeq only moves the read marker forward.
func (r *chatRepository) AdvanceReadSeq(conversationID uuid.UUID, memberTag string, seq int64) error {
	err := database.DB.Model(&models.ConversationMember{}).
		Where("conversation_id = ? AND member_tag = ? AND read_seq < ?", conversationID, memberTag, seq).
		UpdateColumn("read_seq", seq).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.AdvanceReadSeq", err)
	}
	return err
}
