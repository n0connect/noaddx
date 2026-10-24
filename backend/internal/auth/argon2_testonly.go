//go:build test
// +build test

package auth

import "noaddx/internal/config"

// HoldArgon2SlotsForTesting takes every Argon2id slot so tests can observe a saturated
// server; the returned function gives them back. Test builds only.
func HoldArgon2SlotsForTesting() (release func()) {
	n := config.GetArgon2MaxConcurrent()
	for i := 0; i < n; i++ {
		if err := argon2Slots().Acquire(0); err != nil {
			panic("HoldArgon2SlotsForTesting: slot already held")
		}
	}
	return func() {
		for i := 0; i < n; i++ {
			argon2Slots().Release()
		}
	}
}
