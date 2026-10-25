package store

import (
	"errors"
	"time"

	"noaddx/internal/database"
	"noaddx/internal/models"
	"noaddx/internal/utils"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var chatRepoLogger = utils.NewLogger("CHAT_REPOSITORY")

// ChatRepository defines data access for invites, conversations and messages.
// Conversation-scoped reads are always keyed by (conversation, per-conversation tag).
type ChatRepository interface {
	// Transaction runs fn on a repository bound to one database transaction.
	Transaction(fn func(tx ChatRepository) error) error

	CountActiveInvites(creatorTag string, now time.Time) (int64, error)
	DeleteExpiredInvites(creatorTag string, now time.Time) error
	DeleteInvites(creatorTag string) error
	CreateInvite(invite *models.Invite) error
	TakeInvite(lookup, redeemerTag string, now time.Time) (*models.Invite, error)

	LockUsers(userUUIDs []string) (map[string]*models.User, error)
	SaveConvIndex(userUUID, enc string) error
	DeleteUser(userUUID string) error

	CreateConversation(conversationID uuid.UUID, members []models.ConversationMember) error
	FindMembership(conversationID uuid.UUID, memberTag string) (*models.ConversationMember, error)
	FindMembershipsByTags(memberTags []string) (map[uuid.UUID]models.ConversationMember, error)
	ListMembers(conversationID uuid.UUID) ([]models.ConversationMember, error)
	LastSeqs(conversationIDs []uuid.UUID) (map[uuid.UUID]int64, error)
	DeleteConversation(conversationID uuid.UUID) error

	NextSeq(conversationID uuid.UUID) (int64, error)
	CreateMessage(message *models.Message) error
	ListMessagesAfter(conversationID uuid.UUID, afterSeq int64, limit int) ([]models.Message, error)
	ListLatestMessages(conversationID uuid.UUID, limit int) ([]models.Message, error)
	AdvanceReadSeq(conversationID uuid.UUID, memberTag string, seq int64) error

	PurgeExpired(today, now time.Time) (int64, int64, error)
}

type chatRepository struct {
	tx *gorm.DB // nil outside a transaction
}

// NewChatRepository creates a new ChatRepository instance
func NewChatRepository() ChatRepository {
	return &chatRepository{}
}

// db resolves the connection lazily: repositories are built before database.Init runs
func (r *chatRepository) db() *gorm.DB {
	if r.tx != nil {
		return r.tx
	}
	return database.DB
}

func (r *chatRepository) Transaction(fn func(tx ChatRepository) error) error {
	return r.db().Transaction(func(tx *gorm.DB) error {
		return fn(&chatRepository{tx: tx})
	})
}

// ---------- invites ----------

func (r *chatRepository) CountActiveInvites(creatorTag string, now time.Time) (int64, error) {
	var count int64
	err := r.db().Model(&models.Invite{}).
		Where("creator_tag = ? AND expires_at > ?", creatorTag, now).Count(&count).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.CountActiveInvites", err)
	}
	return count, err
}

// DeleteExpiredInvites drops a creator's dead invites so they do not linger as metadata.
func (r *chatRepository) DeleteExpiredInvites(creatorTag string, now time.Time) error {
	err := r.db().Where("creator_tag = ? AND expires_at <= ?", creatorTag, now).Delete(&models.Invite{}).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.DeleteExpiredInvites", err)
	}
	return err
}

// DeleteInvites removes every invite of one creator, pending or expired.
func (r *chatRepository) DeleteInvites(creatorTag string) error {
	err := r.db().Where("creator_tag = ?", creatorTag).Delete(&models.Invite{}).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.DeleteInvites", err)
	}
	return err
}

func (r *chatRepository) CreateInvite(invite *models.Invite) error {
	if err := r.db().Create(invite).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.CreateInvite", err)
		return err
	}
	return nil
}

// TakeInvite atomically deletes and returns an invite (single use, race-free).
// The creator can never consume their own invite: the row simply does not match.
func (r *chatRepository) TakeInvite(lookup, redeemerTag string, now time.Time) (*models.Invite, error) {
	var invite models.Invite
	result := r.db().Clauses(clause.Returning{}).
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

// ---------- users: encrypted conversation index ----------

// LockUsers loads and row-locks users in UUID order (a global order prevents deadlocks).
// Must run inside Transaction.
func (r *chatRepository) LockUsers(userUUIDs []string) (map[string]*models.User, error) {
	var users []models.User
	err := r.db().Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("uuid IN ?", userUUIDs).Order("uuid").Find(&users).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.LockUsers", err)
		return nil, err
	}
	result := make(map[string]*models.User, len(users))
	for i := range users {
		result[users[i].UUID] = &users[i]
	}
	return result, nil
}

func (r *chatRepository) SaveConvIndex(userUUID, enc string) error {
	result := r.db().Model(&models.User{}).Where("uuid = ?", userUUID).UpdateColumn("conv_index_enc", enc)
	if result.Error != nil {
		chatRepoLogger.LogError("ChatRepository.SaveConvIndex", result.Error)
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteUser removes the account row (its credentials, keys and conversation index).
func (r *chatRepository) DeleteUser(userUUID string) error {
	result := r.db().Where("uuid = ?", userUUID).Delete(&models.User{})
	if result.Error != nil {
		chatRepoLogger.LogError("ChatRepository.DeleteUser", result.Error)
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- conversations ----------

func (r *chatRepository) CreateConversation(conversationID uuid.UUID, members []models.ConversationMember) error {
	err := r.db().Transaction(func(tx *gorm.DB) error {
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

func (r *chatRepository) FindMembership(conversationID uuid.UUID, memberTag string) (*models.ConversationMember, error) {
	var member models.ConversationMember
	err := r.db().Where("conversation_id = ? AND member_tag = ?", conversationID, memberTag).First(&member).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		chatRepoLogger.LogError("ChatRepository.FindMembership", err)
		return nil, err
	}
	return &member, nil
}

// FindMembershipsByTags resolves many per-conversation tags in one query.
func (r *chatRepository) FindMembershipsByTags(memberTags []string) (map[uuid.UUID]models.ConversationMember, error) {
	result := make(map[uuid.UUID]models.ConversationMember, len(memberTags))
	if len(memberTags) == 0 {
		return result, nil
	}
	var members []models.ConversationMember
	if err := r.db().Where("member_tag IN ?", memberTags).Find(&members).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.FindMembershipsByTags", err)
		return nil, err
	}
	for _, m := range members {
		result[m.ConversationID] = m
	}
	return result, nil
}

func (r *chatRepository) ListMembers(conversationID uuid.UUID) ([]models.ConversationMember, error) {
	var members []models.ConversationMember
	err := r.db().Where("conversation_id = ?", conversationID).Find(&members).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.ListMembers", err)
	}
	return members, err
}

func (r *chatRepository) LastSeqs(conversationIDs []uuid.UUID) (map[uuid.UUID]int64, error) {
	result := make(map[uuid.UUID]int64, len(conversationIDs))
	if len(conversationIDs) == 0 {
		return result, nil
	}
	var conversations []models.Conversation
	if err := r.db().Where("id IN ?", conversationIDs).Find(&conversations).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.LastSeqs", err)
		return nil, err
	}
	for _, c := range conversations {
		result[c.ID] = c.LastSeq
	}
	return result, nil
}

// DeleteConversation burns a conversation for every member, ciphertext included.
func (r *chatRepository) DeleteConversation(conversationID uuid.UUID) error {
	err := r.db().Transaction(func(tx *gorm.DB) error {
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

// ---------- messages ----------

// NextSeq bumps the conversation's own counter; the row lock it takes serialises
// concurrent senders until the surrounding transaction ends.
func (r *chatRepository) NextSeq(conversationID uuid.UUID) (int64, error) {
	var rows []struct{ LastSeq int64 }
	err := r.db().Raw("UPDATE conversations SET last_seq = last_seq + 1 WHERE id = ? RETURNING last_seq", conversationID).
		Scan(&rows).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.NextSeq", err)
		return 0, err
	}
	if len(rows) != 1 {
		return 0, ErrNotFound
	}
	return rows[0].LastSeq, nil
}

func (r *chatRepository) CreateMessage(message *models.Message) error {
	err := r.db().Create(message).Error
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
	err := r.db().Where("conversation_id = ? AND seq > ?", conversationID, afterSeq).
		Order("seq ASC").Limit(limit).Find(&messages).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.ListMessagesAfter", err)
	}
	return messages, err
}

// ListLatestMessages returns the newest `limit` messages in ascending order.
func (r *chatRepository) ListLatestMessages(conversationID uuid.UUID, limit int) ([]models.Message, error) {
	var messages []models.Message
	err := r.db().Where("conversation_id = ?", conversationID).
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
	err := r.db().Model(&models.ConversationMember{}).
		Where("conversation_id = ? AND member_tag = ? AND read_seq < ?", conversationID, memberTag, seq).
		UpdateColumn("read_seq", seq).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.AdvanceReadSeq", err)
	}
	return err
}

// ---------- retention ----------

// PurgeExpired deletes ciphertext past its deletion day and invites past expiry.
func (r *chatRepository) PurgeExpired(today, now time.Time) (int64, int64, error) {
	messages := r.db().Where("expires_on < ?", today).Delete(&models.Message{})
	if messages.Error != nil {
		chatRepoLogger.LogError("ChatRepository.PurgeExpired (messages)", messages.Error)
		return 0, 0, messages.Error
	}
	invites := r.db().Where("expires_at <= ?", now).Delete(&models.Invite{})
	if invites.Error != nil {
		chatRepoLogger.LogError("ChatRepository.PurgeExpired (invites)", invites.Error)
		return messages.RowsAffected, 0, invites.Error
	}
	return messages.RowsAffected, invites.RowsAffected, nil
}
