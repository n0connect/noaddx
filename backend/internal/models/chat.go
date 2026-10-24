package models

import (
	"time"

	"github.com/google/uuid"
)

// Invite is a single-use pairing ticket. The raw token is never stored, and the
// creator is only reachable through a master-key encrypted blob bound by AAD.
type Invite struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey"`
	Lookup        string    `gorm:"size:64;uniqueIndex;not null"` // HMAC(invite-lookup subkey, token)
	CreatorTag    string    `gorm:"size:64;index;not null"`       // HMAC(invite-creator subkey, uuid)
	CreatorRefEnc string    `gorm:"type:text;not null"`           // AES-256-GCM(master key, creator UUID)
	MasterKeyID   string    `gorm:"size:32;not null"`
	ExpiresAt     time.Time `gorm:"index;not null"`
}

func (Invite) TableName() string {
	return "invites"
}

// Conversation keeps only its own message counter: sequence numbers are per
// conversation, so storage reveals no ordering across conversations.
type Conversation struct {
	ID      uuid.UUID `gorm:"type:uuid;primaryKey"`
	LastSeq int64     `gorm:"not null;default:0"`
}

func (Conversation) TableName() string {
	return "conversations"
}

// ConversationMember is one side of a conversation under a per-conversation pseudonym.
// Who that is lives only in MemberRefEnc (master key) and the peer key in PeerKeyEnc
// (the member's own server key); neither is readable from a database dump.
type ConversationMember struct {
	ConversationID uuid.UUID `gorm:"type:uuid;primaryKey"`
	MemberTag      string    `gorm:"size:64;primaryKey"` // HMAC(conversation-tag subkey, uuid || conversation)
	MemberRefEnc   string    `gorm:"type:text;not null"` // AES-256-GCM(master key, member UUID)
	MasterKeyID    string    `gorm:"size:32;not null"`
	PeerKeyEnc     string    `gorm:"type:text;not null"` // AES-256-GCM(member's server key, peer public key)
	ReadSeq        int64     `gorm:"not null;default:0"`
}

func (ConversationMember) TableName() string {
	return "conversation_members"
}

// Message stores only end-to-end ciphertext. The send time lives inside the ciphertext;
// the server keeps a day-granular deletion date and nothing finer.
type Message struct {
	ConversationID uuid.UUID `gorm:"type:uuid;primaryKey"`
	Seq            int64     `gorm:"primaryKey;autoIncrement:false"`
	ID             uuid.UUID `gorm:"type:uuid;uniqueIndex;not null"` // Client-generated, bound into the E2E AAD
	SenderTag      string    `gorm:"size:64;not null"`
	Ciphertext     string    `gorm:"type:text;not null"`
	ExpiresOn      time.Time `gorm:"type:date;index;not null"`
}

func (Message) TableName() string {
	return "messages"
}
