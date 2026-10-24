package encryption

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"unsafe"

	"noaddx/internal/config"
	"noaddx/internal/utils"
)

var masterKeyLogger = utils.NewLogger("MASTER_KEY")

const masterKeyBytes = 32

type masterKeySet struct {
	activeID string
	active   []byte
	old      map[string][]byte
}

var (
	masterKeys     masterKeySet
	masterKeyOnce  sync.Once
	masterKeyError error
)

// keyIDPattern whitelists master key ids: they are stored next to every record (size:32)
var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

// InitMasterKeys loads MASTER_KEY_ACTIVE(_ID) and MASTER_KEY_OLD ("id:key,id:key").
// Fails closed: any malformed entry stops startup, because a silently dropped old key would
// make every record it protects unreadable.
func InitMasterKeys() error {
	masterKeyOnce.Do(func() {
		masterKeys, masterKeyError = loadMasterKeys()
		if masterKeyError == nil {
			masterKeyLogger.Info("Master keys initialized: active_id=%s old_keys=%d", masterKeys.activeID, len(masterKeys.old))
		}
	})
	return masterKeyError
}

func loadMasterKeys() (masterKeySet, error) {
	activeID := strings.TrimSpace(config.GetEnv("MASTER_KEY_ACTIVE_ID", ""))
	activeKeyRaw := strings.TrimSpace(config.GetEnv("MASTER_KEY_ACTIVE", ""))
	if activeKeyRaw == "" {
		return masterKeySet{}, fmt.Errorf("MASTER_KEY_ACTIVE is required")
	}
	if !keyIDPattern.MatchString(activeID) {
		return masterKeySet{}, fmt.Errorf("MASTER_KEY_ACTIVE_ID must match %s", keyIDPattern)
	}
	activeKey, err := decodeKeyMaterial(activeKeyRaw)
	if err != nil {
		return masterKeySet{}, fmt.Errorf("invalid active master key: %w", err)
	}

	oldKeys := make(map[string][]byte)
	oldRaw := strings.TrimSpace(config.GetEnv("MASTER_KEY_OLD", ""))
	if oldRaw != "" {
		for _, entry := range strings.Split(oldRaw, ",") {
			parts := strings.SplitN(strings.TrimSpace(entry), ":", 2)
			if len(parts) != 2 {
				return masterKeySet{}, fmt.Errorf("MASTER_KEY_OLD entries must be id:key")
			}
			kid := strings.TrimSpace(parts[0])
			if !keyIDPattern.MatchString(kid) || kid == activeID {
				return masterKeySet{}, fmt.Errorf("MASTER_KEY_OLD has an invalid or active key id")
			}
			if _, dup := oldKeys[kid]; dup {
				return masterKeySet{}, fmt.Errorf("MASTER_KEY_OLD repeats a key id")
			}
			key, err := decodeKeyMaterial(strings.TrimSpace(parts[1]))
			if err != nil {
				return masterKeySet{}, fmt.Errorf("MASTER_KEY_OLD has invalid key material")
			}
			if subtle.ConstantTimeCompare(key, activeKey) == 1 {
				return masterKeySet{}, fmt.Errorf("MASTER_KEY_OLD repeats the active key")
			}
			oldKeys[kid] = key
		}
	}
	return masterKeySet{activeID: activeID, active: activeKey, old: oldKeys}, nil
}

func ActiveMasterKey() []byte {
	if err := InitMasterKeys(); err != nil {
		panic(err)
	}
	return masterKeys.active
}

func ActiveMasterKeyID() string {
	if err := InitMasterKeys(); err != nil {
		panic(err)
	}
	return masterKeys.activeID
}

func MasterKeyByID(id string) ([]byte, bool) {
	if err := InitMasterKeys(); err != nil {
		return nil, false
	}
	if id == masterKeys.activeID {
		return masterKeys.active, true
	}
	key, ok := masterKeys.old[id]
	return key, ok
}

// decodeKeyMaterial accepts exactly 32 bytes of key material encoded as hex or base64.
// Raw text is never a key: a 32-character passphrase has a fraction of 256 bits of entropy.
func decodeKeyMaterial(keyRaw string) ([]byte, error) {
	if decoded, err := hex.DecodeString(keyRaw); err == nil && len(decoded) == masterKeyBytes {
		return decoded, nil
	}
	if decoded, err := base64.StdEncoding.Strict().DecodeString(keyRaw); err == nil && len(decoded) == masterKeyBytes {
		return decoded, nil
	}
	return nil, fmt.Errorf("must be 32 bytes as hex (64 chars) or base64")
}

// zeroizeKey securely zeros key material in memory (RULES.md §1.2)
func zeroizeKey(key []byte) {
	if len(key) == 0 {
		return
	}
	// Zero out the slice
	for i := range key {
		key[i] = 0
	}
	// Ensure compiler doesn't optimize away the zeroing
	if len(key) > 0 {
		ptr := unsafe.Pointer(&key[0])
		for i := 0; i < len(key); i++ {
			*(*byte)(unsafe.Add(ptr, i)) = 0
		}
	}
}

// ZeroizeAllKeys explicitly zeros all master keys (call on shutdown)
func ZeroizeAllKeys() {
	if masterKeys.active != nil {
		zeroizeKey(masterKeys.active)
	}
	for _, key := range masterKeys.old {
		if key != nil {
			zeroizeKey(key)
		}
	}
}
