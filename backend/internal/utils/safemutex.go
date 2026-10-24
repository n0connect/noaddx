package utils

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// SafeMutex wraps sync.Mutex with timeout support (RULES.md §4.1)
type SafeMutex struct {
	mu      sync.Mutex
	timeout time.Duration
}

// NewSafeMutex creates a mutex with default 5s timeout
func NewSafeMutex() *SafeMutex {
	return &SafeMutex{timeout: 5 * time.Second}
}

// NewSafeMutexWithTimeout creates a mutex with custom timeout
func NewSafeMutexWithTimeout(timeout time.Duration) *SafeMutex {
	return &SafeMutex{timeout: timeout}
}

// Lock attempts to acquire the lock with timeout, returns error on timeout
func (sm *SafeMutex) Lock() error {
	ctx, cancel := context.WithTimeout(context.Background(), sm.timeout)
	defer cancel()

	locked := make(chan struct{})
	go func() {
		sm.mu.Lock()
		close(locked)
	}()

	select {
	case <-locked:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("mutex lock timeout after %v", sm.timeout)
	}
}

// Unlock releases the lock
func (sm *SafeMutex) Unlock() {
	sm.mu.Unlock()
}

// SafeRWMutex wraps sync.RWMutex with timeout support
type SafeRWMutex struct {
	mu      sync.RWMutex
	timeout time.Duration
}

// NewSafeRWMutex creates an RWMutex with default 5s timeout
func NewSafeRWMutex() *SafeRWMutex {
	return &SafeRWMutex{timeout: 5 * time.Second}
}

// Lock acquires write lock with timeout
func (sm *SafeRWMutex) Lock() error {
	ctx, cancel := context.WithTimeout(context.Background(), sm.timeout)
	defer cancel()

	locked := make(chan struct{})
	go func() {
		sm.mu.Lock()
		close(locked)
	}()

	select {
	case <-locked:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("RWMutex write lock timeout after %v", sm.timeout)
	}
}

// Unlock releases write lock
func (sm *SafeRWMutex) Unlock() {
	sm.mu.Unlock()
}

// RLock acquires read lock with timeout
func (sm *SafeRWMutex) RLock() error {
	ctx, cancel := context.WithTimeout(context.Background(), sm.timeout)
	defer cancel()

	locked := make(chan struct{})
	go func() {
		sm.mu.RLock()
		close(locked)
	}()

	select {
	case <-locked:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("RWMutex read lock timeout after %v", sm.timeout)
	}
}

// RUnlock releases read lock
func (sm *SafeRWMutex) RUnlock() {
	sm.mu.RUnlock()
}
