package utils

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"noaddress/internal/utils"
)

func TestSafeMutex_TimesOutWithoutLeakingTheLock(t *testing.T) {
	m := utils.NewSafeMutexWithTimeout(50 * time.Millisecond)
	if err := m.Lock(); err != nil {
		t.Fatalf("first Lock: %v", err)
	}
	if err := m.Lock(); !errors.Is(err, utils.ErrLockTimeout) {
		t.Fatalf("second Lock = %v, want ErrLockTimeout", err)
	}
	m.Unlock()
	// The timed-out attempt must not have left a waiter that steals the lock later
	time.Sleep(20 * time.Millisecond)
	if err := m.Lock(); err != nil {
		t.Fatalf("Lock after Unlock: %v", err)
	}
	m.Unlock()
}

func TestSafeMutex_UnlockOfUnlockedPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Unlock of an unlocked SafeMutex did not panic")
		}
	}()
	utils.NewSafeMutex().Unlock()
}

func TestSafeGoSupervised_RestartsAfterPanicAndStopsOnReturn(t *testing.T) {
	var calls int32
	done := make(chan struct{})
	utils.SafeGoSupervised(context.Background(), "test", func(ctx context.Context) {
		if atomic.AddInt32(&calls, 1) == 1 {
			panic("boom")
		}
		close(done)
	})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("supervised goroutine was not restarted after a panic")
	}
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("fn ran %d times, want 2 (normal return must not restart)", got)
	}
}

func TestSafeGoSupervised_NoRestartAfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls int32
	utils.SafeGoSupervised(ctx, "test", func(ctx context.Context) {
		atomic.AddInt32(&calls, 1)
		cancel()
		panic("boom")
	})
	time.Sleep(1500 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("fn ran %d times after cancellation, want 1", got)
	}
}

func captureLog(t *testing.T, level string, fn func()) string {
	t.Helper()
	t.Setenv("LOG_LEVEL", level)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	fn()
	return buf.String()
}

func TestLogger_LevelFilterAndNewlineEscaping(t *testing.T) {
	logger := utils.NewLogger("TEST")

	out := captureLog(t, "warn", func() {
		logger.Debug("debug line")
		logger.Info("info line")
		logger.Warn("warn %s", "line\nforged [ERROR] entry")
	})
	if strings.Contains(out, "debug line") || strings.Contains(out, "info line") {
		t.Fatalf("lines below LOG_LEVEL=warn were emitted: %q", out)
	}
	if strings.Count(out, "\n") != 1 || !strings.Contains(out, `line\nforged`) {
		t.Fatalf("user-controlled newline was not escaped: %q", out)
	}

	out = captureLog(t, "debug", func() { logger.Debug("debug line") })
	if !strings.Contains(out, "debug line") {
		t.Fatalf("LOG_LEVEL=debug suppressed debug output: %q", out)
	}
}
