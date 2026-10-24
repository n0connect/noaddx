package models

import "time"

type User struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	UUID          string    `gorm:"uniqueIndex;size:24;not null" json:"uuid"` // Internal user ID (never exposed to peers)
	AccountLookup string    `gorm:"uniqueIndex;not null" json:"-"`            // HMAC(pepper, authKey) for fast lookup
	AccountHash   string    `gorm:"not null" json:"-"`                        // Argon2id hash of authKey
	PublicKey     string    `gorm:"size:43;not null;default:''" json:"-"`     // X25519 identity public key (base64url)
	SessionEpoch  int       `gorm:"not null;default:0" json:"-"`              // Bumped on logout: revokes every issued JWT
	EncryptedKey  string    `gorm:"type:text;not null" json:"-"`              // Per-user server key, wrapped by master key
	MasterKeyID   string    `gorm:"size:32;not null;default:''" json:"-"`
	CreatedAt     time.Time `gorm:"autoCreateTime;not null" json:"created_at"`
	UpdatedAt     time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

// TableName returns the table name for GORM
func (User) TableName() string {
	return "users"
}
