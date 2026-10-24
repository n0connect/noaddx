//go:build test
// +build test

package testutil

import (
	"testing"

	"noaddress/internal/cryptoengine"
	"noaddress/internal/identity"
	"noaddress/internal/utils"

	"github.com/google/uuid"
)

// Every value a test needs is produced by the same generator production uses;
// tests never hand-write account numbers, ids or keys.

// NewAccountNumber returns a fresh AccountNumber from the production generator.
func NewAccountNumber(t *testing.T) string {
	t.Helper()
	account, err := utils.GenerateAccountNumber()
	if err != nil {
		t.Fatalf("GenerateAccountNumber: %v", err)
	}
	return account
}

// NewAuthKey returns the login key the browser would derive for a fresh AccountNumber.
func NewAuthKey(t *testing.T) string {
	t.Helper()
	authKey, err := identity.DeriveAuthKey(NewAccountNumber(t))
	if err != nil {
		t.Fatalf("DeriveAuthKey: %v", err)
	}
	return authKey
}

// NewInternalID returns a fresh internal user id from the production generator.
func NewInternalID(t *testing.T) string {
	t.Helper()
	id, err := utils.GenerateInternalID()
	if err != nil {
		t.Fatalf("GenerateInternalID: %v", err)
	}
	return id
}

// NewRecordID returns a fresh UUIDv4 drawn from the engine CSPRNG, as stored records use.
func NewRecordID(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewRandomFromReader(cryptoengine.RandReader)
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}
	return id
}
