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
	ListLatestMessages(conversationID uuid.UUID, floorSeq int64, limit int) ([]models.Message, error)
	AdvanceReadSeq(conversationID uuid.UUID, memberTag string, seq int64) error

	CreateRoom(room *models.Room, creator *models.ConversationMember) error
	FindRoom(roomID uuid.UUID) (*models.Room, error)
	FindRooms(roomIDs []uuid.UUID) (map[uuid.UUID]models.Room, error)
	LockRoom(roomID uuid.UUID) (*models.Room, error)
	LockConversation(conversationID uuid.UUID) (int64, error)
	AddMember(member *models.ConversationMember) error
	UpdateVault(conversationID uuid.UUID, memberTag, vault string) error
	DeleteMember(conversationID uuid.UUID, memberTag string) error
	CountMembers(conversationIDs []uuid.UUID) (map[uuid.UUID]int, error)

	CreateNote(note *models.RoomNote) error
	CountNotesFor(recipientTags []string, now time.Time) (map[uuid.UUID]int, error)
	ListNotes(conversationID uuid.UUID, recipientTag string, now time.Time) ([]models.RoomNote, error)
	DeleteNote(conversationID, noteID uuid.UUID, recipientTag string) error

	PurgeExpired(today, latest, now time.Time) (PurgeCounts, error)
}

// PurgeCounts reports what one retention pass removed.
type PurgeCounts struct {
	Messages, Invites, Rooms, Notes int64
}

// roomPurgeBatch bounds how many expired rooms one retention pass deletes; the rest go next pass
const roomPurgeBatch = 1000

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

// DeleteConversation burns a conversation for every member, ciphertext included. A room's row
// goes first: lock order is rooms before conversations (LOCK_HIERARCHY.md).
func (r *chatRepository) DeleteConversation(conversationID uuid.UUID) error {
	err := r.db().Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ?", conversationID).Delete(&models.Room{}).Error; err != nil {
			return err
		}
		if err := tx.Where("conversation_id = ?", conversationID).Delete(&models.Message{}).Error; err != nil {
			return err
		}
		if err := tx.Where("conversation_id = ?", conversationID).Delete(&models.ConversationMember{}).Error; err != nil {
			return err
		}
		if err := tx.Where("conversation_id = ?", conversationID).Delete(&models.RoomNote{}).Error; err != nil {
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

// ListLatestMessages returns the newest `limit` messages after floorSeq in ascending order.
func (r *chatRepository) ListLatestMessages(conversationID uuid.UUID, floorSeq int64, limit int) ([]models.Message, error) {
	var messages []models.Message
	err := r.db().Where("conversation_id = ? AND seq > ?", conversationID, floorSeq).
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

// PurgeExpired deletes ciphertext past its deletion day, invites and notes past expiry, and
// expired rooms with everything in them. Nothing is kept past latest either: a lowered
// MESSAGE_TTL_DAYS also shortens what is already stored.
func (r *chatRepository) PurgeExpired(today, latest, now time.Time) (PurgeCounts, error) {
	var counts PurgeCounts
	capped := r.db().Model(&models.Message{}).Where("expires_on > ?", latest).UpdateColumn("expires_on", latest)
	if capped.Error != nil {
		chatRepoLogger.LogError("ChatRepository.PurgeExpired (cap)", capped.Error)
		return counts, capped.Error
	}
	messages := r.db().Where("expires_on < ?", today).Delete(&models.Message{})
	if messages.Error != nil {
		chatRepoLogger.LogError("ChatRepository.PurgeExpired (messages)", messages.Error)
		return counts, messages.Error
	}
	counts.Messages = messages.RowsAffected
	invites := r.db().Where("expires_at <= ?", now).Delete(&models.Invite{})
	if invites.Error != nil {
		chatRepoLogger.LogError("ChatRepository.PurgeExpired (invites)", invites.Error)
		return counts, invites.Error
	}
	counts.Invites = invites.RowsAffected
	notes := r.db().Where("expires_at <= ?", now).Delete(&models.RoomNote{})
	if notes.Error != nil {
		chatRepoLogger.LogError("ChatRepository.PurgeExpired (notes)", notes.Error)
		return counts, notes.Error
	}
	counts.Notes = notes.RowsAffected
	var expired []uuid.UUID
	if err := r.db().Model(&models.Room{}).Where("expires_at <= ?", now).Limit(roomPurgeBatch).Pluck("id", &expired).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.PurgeExpired (rooms)", err)
		return counts, err
	}
	for _, id := range expired {
		if err := r.DeleteConversation(id); err != nil && !errors.Is(err, ErrNotFound) {
			return counts, err
		}
		counts.Rooms++
	}
	return counts, nil
}

// ---------- rooms ----------

// CreateRoom stores a new room, its conversation and its creator's membership together.
func (r *chatRepository) CreateRoom(room *models.Room, creator *models.ConversationMember) error {
	err := r.db().Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&models.Conversation{ID: room.ID}).Error; err != nil {
			return err
		}
		if err := tx.Create(room).Error; err != nil {
			return err
		}
		return tx.Create(creator).Error
	})
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return ErrConflict
	}
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.CreateRoom", err)
	}
	return err
}

func (r *chatRepository) FindRoom(roomID uuid.UUID) (*models.Room, error) {
	var room models.Room
	if err := r.db().Where("id = ?", roomID).First(&room).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		chatRepoLogger.LogError("ChatRepository.FindRoom", err)
		return nil, err
	}
	return &room, nil
}

// FindRooms returns the rooms among roomIDs (one-to-one conversations are simply absent).
func (r *chatRepository) FindRooms(roomIDs []uuid.UUID) (map[uuid.UUID]models.Room, error) {
	result := make(map[uuid.UUID]models.Room, len(roomIDs))
	if len(roomIDs) == 0 {
		return result, nil
	}
	var rooms []models.Room
	if err := r.db().Where("id IN ?", roomIDs).Find(&rooms).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.FindRooms", err)
		return nil, err
	}
	for _, room := range rooms {
		result[room.ID] = room
	}
	return result, nil
}

// LockRoom loads and row-locks a room; joins of one room are serialised by it. Must run
// inside Transaction, after any users row lock and before the conversation row lock.
func (r *chatRepository) LockRoom(roomID uuid.UUID) (*models.Room, error) {
	var rooms []models.Room
	if err := r.db().Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", roomID).Find(&rooms).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.LockRoom", err)
		return nil, err
	}
	if len(rooms) != 1 {
		return nil, ErrNotFound
	}
	return &rooms[0], nil
}

// LockConversation row-locks a conversation and returns its last sequence number. Joins,
// leaves and sends all take this lock, so a message is checked against the roster it is
// stored under.
func (r *chatRepository) LockConversation(conversationID uuid.UUID) (int64, error) {
	var conversations []models.Conversation
	if err := r.db().Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", conversationID).Find(&conversations).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.LockConversation", err)
		return 0, err
	}
	if len(conversations) != 1 {
		return 0, ErrNotFound
	}
	return conversations[0].LastSeq, nil
}

func (r *chatRepository) AddMember(member *models.ConversationMember) error {
	if err := r.db().Create(member).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrConflict
		}
		chatRepoLogger.LogError("ChatRepository.AddMember", err)
		return err
	}
	return nil
}

func (r *chatRepository) UpdateVault(conversationID uuid.UUID, memberTag, vault string) error {
	err := r.db().Model(&models.ConversationMember{}).
		Where("conversation_id = ? AND member_tag = ?", conversationID, memberTag).UpdateColumn("vault", vault).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.UpdateVault", err)
	}
	return err
}

// DeleteMember removes one membership and every note to or from it in that room.
func (r *chatRepository) DeleteMember(conversationID uuid.UUID, memberTag string) error {
	err := r.db().Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("conversation_id = ? AND (sender_tag = ? OR recipient_tag = ?)", conversationID, memberTag, memberTag).
			Delete(&models.RoomNote{}).Error; err != nil {
			return err
		}
		result := tx.Where("conversation_id = ? AND member_tag = ?", conversationID, memberTag).Delete(&models.ConversationMember{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	})
	if err != nil && !errors.Is(err, ErrNotFound) {
		chatRepoLogger.LogError("ChatRepository.DeleteMember", err)
	}
	return err
}

func (r *chatRepository) CountMembers(conversationIDs []uuid.UUID) (map[uuid.UUID]int, error) {
	result := make(map[uuid.UUID]int, len(conversationIDs))
	if len(conversationIDs) == 0 {
		return result, nil
	}
	var rows []struct {
		ConversationID uuid.UUID
		Count          int
	}
	err := r.db().Model(&models.ConversationMember{}).Select("conversation_id, count(*) AS count").
		Where("conversation_id IN ?", conversationIDs).Group("conversation_id").Scan(&rows).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.CountMembers", err)
		return nil, err
	}
	for _, row := range rows {
		result[row.ConversationID] = row.Count
	}
	return result, nil
}

// ---------- room notes ----------

// CreateNote stores a note; an expired note between the same two members makes way for it.
func (r *chatRepository) CreateNote(note *models.RoomNote) error {
	err := r.db().Where("conversation_id = ? AND sender_tag = ? AND recipient_tag = ? AND expires_at <= ?",
		note.ConversationID, note.SenderTag, note.RecipientTag, time.Now().UTC()).Delete(&models.RoomNote{}).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.CreateNote (expired)", err)
		return err
	}
	if err := r.db().Create(note).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrConflict
		}
		chatRepoLogger.LogError("ChatRepository.CreateNote", err)
		return err
	}
	return nil
}

// CountNotesFor counts live notes per room for the caller's per-room tags.
func (r *chatRepository) CountNotesFor(recipientTags []string, now time.Time) (map[uuid.UUID]int, error) {
	result := make(map[uuid.UUID]int, len(recipientTags))
	if len(recipientTags) == 0 {
		return result, nil
	}
	var rows []struct {
		ConversationID uuid.UUID
		Count          int
	}
	err := r.db().Model(&models.RoomNote{}).Select("conversation_id, count(*) AS count").
		Where("recipient_tag IN ? AND expires_at > ?", recipientTags, now).Group("conversation_id").Scan(&rows).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.CountNotesFor", err)
		return nil, err
	}
	for _, row := range rows {
		result[row.ConversationID] = row.Count
	}
	return result, nil
}

func (r *chatRepository) ListNotes(conversationID uuid.UUID, recipientTag string, now time.Time) ([]models.RoomNote, error) {
	var notes []models.RoomNote
	err := r.db().Where("conversation_id = ? AND recipient_tag = ? AND expires_at > ?", conversationID, recipientTag, now).
		Order("id").Find(&notes).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.ListNotes", err)
	}
	return notes, err
}

// DeleteNote removes a note addressed to recipientTag; nobody else can delete it.
func (r *chatRepository) DeleteNote(conversationID, noteID uuid.UUID, recipientTag string) error {
	result := r.db().Where("id = ? AND conversation_id = ? AND recipient_tag = ?", noteID, conversationID, recipientTag).
		Delete(&models.RoomNote{})
	if result.Error != nil {
		chatRepoLogger.LogError("ChatRepository.DeleteNote", result.Error)
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}
