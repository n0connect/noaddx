package utils

import (
	"errors"
	"time"
)

// DefaultLockTimeout bounds every SafeMutex acquisition (RULES.md §4.1).
const DefaultLockTimeout = 5 * time.Second

// ErrLockTimeout is returned when a SafeMutex cannot be acquired in time.
var ErrLockTimeout = errors.New("mutex lock timeout")

// SafeMutex is a mutual-exclusion lock whose acquisition can time out.
// It is a one-slot channel, so a timed-out Lock leaves no goroutine behind that could
// later grab the lock with nobody to release it.
type SafeMutex struct {
	slot    chan struct{}
	timeout time.Duration
}

// NewSafeMutex creates a mutex with DefaultLockTimeout.
func NewSafeMutex() *SafeMutex {
	return NewSafeMutexWithTimeout(DefaultLockTimeout)
}

// NewSafeMutexWithTimeout creates a mutex with a custom timeout.
func NewSafeMutexWithTimeout(timeout time.Duration) *SafeMutex {
	return &SafeMutex{slot: make(chan struct{}, 1), timeout: timeout}
}

// Lock acquires the mutex or returns ErrLockTimeout.
func (m *SafeMutex) Lock() error {
	timer := time.NewTimer(m.timeout)
	defer timer.Stop()
	select {
	case m.slot <- struct{}{}:
		return nil
	case <-timer.C:
		return ErrLockTimeout
	}
}

// Unlock releases the mutex. Unlocking an unlocked mutex is a logic error and aborts
// (RULES.md §4.1: poisoned lock state must not be tolerated).
func (m *SafeMutex) Unlock() {
	select {
	case <-m.slot:
	default:
		panic("utils: unlock of unlocked SafeMutex")
	}
}
