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
// In a room PeerKeyEnc is empty: the member's card announces their room key to the others.
type ConversationMember struct {
	ConversationID uuid.UUID `gorm:"type:uuid;primaryKey"`
	MemberTag      string    `gorm:"size:64;primaryKey"` // HMAC(conversation-tag subkey, uuid || conversation)
	MemberRefEnc   string    `gorm:"type:text;not null"` // AES-256-GCM(master key, member UUID)
	MasterKeyID    string    `gorm:"size:32;not null"`
	PeerKeyEnc     string    `gorm:"type:text;not null"` // AES-256-GCM(member's server key, peer public key)
	ReadSeq        int64     `gorm:"not null;default:0"`
	Card           string    `gorm:"type:text;not null;default:''"` // rooms: sealed by a code-derived key the server never sees
	Vault          string    `gorm:"type:text;not null;default:''"` // rooms: the room code sealed for this member's account
	JoinedSeq      int64     `gorm:"not null;default:0"`            // rooms: messages up to this seq predate the member
}

func (ConversationMember) TableName() string {
	return "conversation_members"
}

// Room is the server's side of a code-based group conversation (same id as its Conversation).
// The code never reaches the server; Lookup is a keyed hash of a value derived from it.
type Room struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey"`
	Lookup     string    `gorm:"size:64;not null"` // HMAC(room-lookup subkey, lookup derived from the code)
	MaxMembers int       `gorm:"not null"`
	ExpiresAt  time.Time `gorm:"index;not null"`   // hour-aligned; the room is deleted then
	OwnerTag   string    `gorm:"size:64;not null"` // the creator's member tag in this room only
}

func (Room) TableName() string {
	return "rooms"
}

// RoomNote is a sealed note from one room member to another (a friend request). Only the
// addressee can open it; the server sees two per-room pseudonyms and ciphertext.
type RoomNote struct {
	ID             uuid.UUID `gorm:"type:uuid;primaryKey"`
	ConversationID uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_room_notes_pair,priority:1;index:idx_room_notes_to,priority:1"`
	SenderTag      string    `gorm:"size:64;not null;uniqueIndex:idx_room_notes_pair,priority:2"`
	RecipientTag   string    `gorm:"size:64;not null;uniqueIndex:idx_room_notes_pair,priority:3;index:idx_room_notes_to,priority:2"`
	Blob           string    `gorm:"type:text;not null"`
	ExpiresAt      time.Time `gorm:"index;not null"`
}

func (RoomNote) TableName() string {
	return "room_notes"
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
