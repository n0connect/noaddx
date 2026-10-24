package auth

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"noaddx/internal/config"
	"noaddx/internal/cryptoengine"
	"noaddx/internal/utils"
)

var accountLogger = utils.NewLogger("ACCOUNT")

type argon2Params struct {
	memoryKiB  uint32
	time       uint32
	parallel   uint32
	saltLength uint32
	hashLength uint32
}

// decoyHash is a genuine Argon2id hash of a random secret nobody knows. Logins for unknown
// accounts verify against it so they cost exactly what a real verification costs.
var (
	decoyHashOnce sync.Once
	decoyHash     string
	decoyHashErr  error
)

func getArgon2Params() (argon2Params, error) {
	memory := config.GetArgon2MemoryKiB()
	timeCost := config.GetArgon2Time()
	parallel := config.GetArgon2Parallelism()
	saltLen := config.GetArgon2SaltLength()
	hashLen := config.GetArgon2HashLength()

	if memory <= 0 || timeCost <= 0 || parallel <= 0 || saltLen <= 0 || hashLen <= 0 {
		return argon2Params{}, fmt.Errorf("argon2 parameters not configured")
	}

	return argon2Params{
		memoryKiB:  uint32(memory),
		time:       uint32(timeCost),
		parallel:   uint32(parallel),
		saltLength: uint32(saltLen),
		hashLength: uint32(hashLen),
	}, nil
}

// ComputeAccountLookup computes HMAC-SHA256(pepper, accountNumber) for fast database lookup
// Returns hex-encoded string
func ComputeAccountLookup(accountNumber string) (string, error) {
	pepper := config.GetAccountLookupPepper()
	if len(pepper) == 0 {
		return "", errors.New("ACCOUNT_LOOKUP_PEPPER not configured")
	}
	if len(pepper) < 32 {
		return "", errors.New("ACCOUNT_LOOKUP_PEPPER too short")
	}
	mac, err := cryptoengine.HMACSHA256(pepper, []byte(accountNumber))
	if err != nil {
		return "", err
	}
	lookup := hex.EncodeToString(mac)

	accountLogger.Debug("ComputeAccountLookup: computed lookup for account number (masked)")
	return lookup, nil
}

// HashAccountNumber hashes account number using Argon2id
// Returns encoded hash string with parameters
func HashAccountNumber(accountNumber string) (string, error) {
	params, err := getArgon2Params()
	if err != nil {
		return "", err
	}

	// Generate random salt
	salt, err := cryptoengine.RandomBytes(int(params.saltLength))
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash with Argon2id
	hash, err := cryptoengine.Argon2idKey([]byte(accountNumber), salt, params.time, params.memoryKiB, params.parallel, params.hashLength)
	if err != nil {
		return "", fmt.Errorf("argon2id failed: %w", err)
	}

	// Encode: format = "argon2id$m=memory$t=time$p=parallelism$salt$hash"
	// Using hex encoding for both salt and hash
	encoded := fmt.Sprintf("argon2id$m=%d$t=%d$p=%d$%s$%s",
		params.memoryKiB,
		params.time,
		params.parallel,
		hex.EncodeToString(salt),
		hex.EncodeToString(hash))

	accountLogger.Debug("HashAccountNumber: hashed account number (masked)")
	return encoded, nil
}

// parseParam reads one "<name>=<canonical decimal>" field within [min, max].
func parseParam(field, name string, min, max uint64) (uint32, error) {
	digits := strings.TrimPrefix(field, name+"=")
	if digits == field || digits == "" {
		return 0, fmt.Errorf("invalid %s parameter", name)
	}
	value, err := strconv.ParseUint(digits, 10, 32)
	if err != nil || strconv.FormatUint(value, 10) != digits || value < min || value > max {
		return 0, fmt.Errorf("invalid %s parameter", name)
	}
	return uint32(value), nil
}

// VerifyAccountNumberHash verifies an auth key against a stored Argon2id hash
// ("argon2id$m=<KiB>$t=<n>$p=<n>$<salt hex>$<hash hex>"). Every parameter is range-checked
// before Argon2 runs, so a corrupted record can neither crash nor exhaust the server.
func VerifyAccountNumberHash(encodedHash, accountNumber string) error {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "argon2id" {
		return fmt.Errorf("invalid hash format: expected 6 parts starting with 'argon2id'")
	}
	memory, err := parseParam(parts[1], "m", config.MinArgon2MemoryKiB, config.MaxArgon2MemoryKiB)
	if err != nil {
		return err
	}
	timeCost, err := parseParam(parts[2], "t", config.MinArgon2Time, config.MaxArgon2Time)
	if err != nil {
		return err
	}
	parallelism, err := parseParam(parts[3], "p", config.MinArgon2Parallelism, config.MaxArgon2Parallelism)
	if err != nil {
		return err
	}

	salt, err := hex.DecodeString(parts[4])
	if err != nil || len(salt) < config.MinArgon2SaltBytes || len(salt) > config.MaxArgon2SaltBytes {
		return fmt.Errorf("invalid salt")
	}
	expectedHash, err := hex.DecodeString(parts[5])
	if err != nil || len(expectedHash) < config.MinArgon2HashBytes || len(expectedHash) > config.MaxArgon2HashBytes {
		return fmt.Errorf("invalid hash")
	}

	computedHash, err := cryptoengine.Argon2idKey([]byte(accountNumber), salt, timeCost, memory, parallelism, uint32(len(expectedHash)))
	if err != nil {
		return fmt.Errorf("argon2id failed: %w", err)
	}

	// Constant-time comparison
	if !cryptoengine.ConstantTimeEqual(computedHash, expectedHash) {
		return errors.New("account number hash mismatch")
	}
	return nil
}

func getDecoyHash() (string, error) {
	decoyHashOnce.Do(func() {
		secret, err := cryptoengine.RandomBytes(32)
		if err != nil {
			decoyHashErr = err
			return
		}
		decoyHash, decoyHashErr = HashAccountNumber(hex.EncodeToString(secret))
	})
	return decoyHash, decoyHashErr
}

// EqualizeVerificationTiming runs a full Argon2id verification against the decoy hash,
// so a login for a non-existent account takes as long as one for a real account
// (no user-enumeration timing side channel). The result is meaningless by design.
func EqualizeVerificationTiming(authKey string) {
	hash, err := getDecoyHash()
	if err != nil {
		accountLogger.LogError("EqualizeVerificationTiming", err)
		return
	}
	_ = VerifyAccountNumberHash(hash, authKey)
}
