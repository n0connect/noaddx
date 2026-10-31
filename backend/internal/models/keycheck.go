package models

// KeyCheck commits to a secret the database depends on, so startup can refuse a different
// one (a regenerated .env) instead of answering every account with errors. Value is an HMAC
// under a subkey of that secret: it reveals nothing about the secret itself.
type KeyCheck struct {
	Name  string `gorm:"size:32;primaryKey"`
	Value string `gorm:"size:64;not null"`
}

func (KeyCheck) TableName() string {
	return "key_checks"
}
