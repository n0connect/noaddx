package auth

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"noaddx/internal/config"
	"noaddx/internal/cryptoengine"
	"noaddx/internal/utils"
)

var (
	pendingStoreLogger = utils.NewLogger("PENDING_STORE")
	pendingStore       = &pendingRegistrationStore{
		store: make(map[string]*pendingRegistration),
	}
	cleanupOnce   sync.Once
	cleanupTicker *time.Ticker
)

// MaxPendingRegistrations bounds phase-1 registrations awaiting confirmation (each costs the
// client a proof of work; the bound caps memory even under a distributed flood).
const MaxPendingRegistrations = 50000

// ErrPendingStoreFull: the store is at its bound; the client retries later
var ErrPendingStoreFull = errors.New("pending registration store full")

// PendingIdentity is what phase 1 of registration keeps for phase 2: the values derived
// from the AccountNumber, never the AccountNumber itself. The AccountNumber also seeds the
// user's E2E identity, so it exists in server memory only for the duration of the phase-1
// request; what waits here cannot be turned back into it.
type PendingIdentity struct {
	AuthKey   string // HKDF(AccountNumber, "noaddx/auth"): the login secret (stored hashed at phase 2)
	PublicKey string // X25519 identity public key (base64url)
}

type pendingRegistration struct {
	identity  PendingIdentity
	ExpiresAt time.Time
}

type pendingRegistrationStore struct {
	mu    sync.RWMutex
	store map[string]*pendingRegistration
}

func pendingConfig() (time.Duration, time.Duration, int, error) {
	ttl := config.GetPendingTokenTTL()
	cleanup := config.GetPendingCleanupInterval()
	idBytes := config.GetPendingIDBytes()
	if ttl <= 0 || cleanup <= 0 || idBytes <= 0 {
		return 0, 0, 0, fmt.Errorf("pending registration config not set")
	}
	return ttl, cleanup, idBytes, nil
}

// GeneratePendingID generates a unique pending ID
func GeneratePendingID() (string, error) {
	_, _, idBytes, err := pendingConfig()
	if err != nil {
		return "", err
	}
	randomBytes, err := cryptoengine.RandomBytes(idBytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(randomBytes), nil
}

// initCleanup starts the background cleanup goroutine (only once)
// SECURITY: Prevents goroutine leak by starting cleanup only once
func initCleanup() error {
	_, cleanupInterval, _, err := pendingConfig()
	if err != nil {
		return err
	}

	cleanupOnce.Do(func() {
		cleanupTicker = time.NewTicker(cleanupInterval)
		go func() {
			for range cleanupTicker.C {
				cleanupExpiredPending()
			}
		}()
		pendingStoreLogger.Debug("Started background cleanup goroutine")
	})
	return nil
}

// StorePendingRegistration keeps a derived identity under a pending ID (config-driven TTL)
func StorePendingRegistration(pendingID string, pending PendingIdentity) error {
	ttl, _, _, err := pendingConfig()
	if err != nil {
		return err
	}

	pendingStore.mu.Lock()
	defer pendingStore.mu.Unlock()

	// Start cleanup goroutine if not started (only once)
	if err := initCleanup(); err != nil {
		return err
	}

	now := time.Now()
	if len(pendingStore.store) >= MaxPendingRegistrations {
		removeExpiredPendingLocked(now)
	}
	if len(pendingStore.store) >= MaxPendingRegistrations {
		pendingStoreLogger.Warn("Pending registration store at capacity")
		return ErrPendingStoreFull
	}
	pendingStore.store[pendingID] = &pendingRegistration{
		identity:  pending,
		ExpiresAt: now.Add(ttl),
	}

	return nil
}

// GetPendingRegistration retrieves the pending identity by pending ID
// SECURITY: Uses write lock from start to prevent race conditions
// One-time use: deletes entry after retrieval
func GetPendingRegistration(pendingID string) (PendingIdentity, error) {
	pendingStore.mu.Lock() // Write lock (we will delete)
	defer pendingStore.mu.Unlock()

	pending, exists := pendingStore.store[pendingID]
	if !exists {
		return PendingIdentity{}, ErrInvalidToken
	}

	if time.Now().After(pending.ExpiresAt) {
		// Expired - remove it
		delete(pendingStore.store, pendingID)
		return PendingIdentity{}, ErrExpiredToken
	}

	// One-time use: delete immediately after retrieval
	identity := pending.identity
	delete(pendingStore.store, pendingID)
	return identity, nil
}

// cleanupExpiredPending removes expired entries (runs in background)
func cleanupExpiredPending() {
	pendingStore.mu.Lock()
	defer pendingStore.mu.Unlock()
	removeExpiredPendingLocked(time.Now())
}

// removeExpiredPendingLocked deletes expired entries. Caller holds pendingStore.mu.
func removeExpiredPendingLocked(now time.Time) {
	for id, pending := range pendingStore.store {
		if now.After(pending.ExpiresAt) {
			delete(pendingStore.store, id)
		}
	}
}

// StopCleanup stops the background cleanup goroutine gracefully
// This should be called during application shutdown to prevent resource leaks
func StopCleanup() {
	if cleanupTicker != nil {
		cleanupTicker.Stop()
		pendingStoreLogger.Debug("Stopped background cleanup goroutine")
	}
}
