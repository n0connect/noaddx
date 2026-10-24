package models

import (
	"time"

	"github.com/google/uuid"
)

// Invite is a single-use pairing ticket. The raw token is never stored, and the
// creator is only reachable through a master-key encrypted blob bound by AAD.
type Invite struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey"`
	Lookup      string    `gorm:"size:64;uniqueIndex;not null"` // HMAC(pepper-subkey, token)
	CreatorTag  string    `gorm:"size:64;index;not null"`       // Member tag of the creator (pseudonym)
	CreatorEnc  string    `gorm:"type:text;not null"`           // AES-256-GCM(master key, creator UUID)
	MasterKeyID string    `gorm:"size:32;not null"`
	ExpiresAt   time.Time `gorm:"index;not null"`
}

func (Invite) TableName() string {
	return "invites"
}

// Conversation is intentionally empty: membership lives in pseudonymous rows.
type Conversation struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey"`
}

func (Conversation) TableName() string {
	return "conversations"
}

// ConversationMember links a member tag to a conversation. The peer's public key
// is encrypted with the member's own server key so a DB dump reveals no graph.
type ConversationMember struct {
	ConversationID uuid.UUID `gorm:"type:uuid;primaryKey"`
	MemberTag      string    `gorm:"size:64;primaryKey;index"`
	PeerKeyEnc     string    `gorm:"type:text;not null"`
	ReadSeq        int64     `gorm:"not null;default:0"`
}

func (ConversationMember) TableName() string {
	return "conversation_members"
}

// Message stores only end-to-end ciphertext. Timestamps live inside the ciphertext.
type Message struct {
	Seq            int64     `gorm:"primaryKey;autoIncrement;index:idx_messages_conversation_seq,priority:2"`
	ID             uuid.UUID `gorm:"type:uuid;uniqueIndex;not null"` // Client-generated, bound into the E2E AAD
	ConversationID uuid.UUID `gorm:"type:uuid;not null;index:idx_messages_conversation_seq,priority:1"`
	SenderTag      string    `gorm:"size:64;not null"`
	Ciphertext     string    `gorm:"type:text;not null"`
}

func (Message) TableName() string {
	return "messages"
}
