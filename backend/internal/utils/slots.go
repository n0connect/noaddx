package utils

import (
	"errors"
	"time"
)

// ErrSlotsBusy means no slot freed up within the wait allowed.
var ErrSlotsBusy = errors.New("all slots busy")

// Slots bounds how many callers may run a memory-hungry operation at once (RULES.md §17.1:
// resource exhaustion degrades gracefully). A caller waits at most `wait` for a slot and
// otherwise gets ErrSlotsBusy, so a flood is refused instead of exhausting memory.
type Slots struct {
	free chan struct{}
}

// NewSlots creates a bound of n concurrent holders (n >= 1).
func NewSlots(n int) *Slots {
	if n < 1 {
		n = 1
	}
	s := &Slots{free: make(chan struct{}, n)}
	for i := 0; i < n; i++ {
		s.free <- struct{}{}
	}
	return s
}

// Acquire takes a slot, waiting at most `wait`.
func (s *Slots) Acquire(wait time.Duration) error {
	select {
	case <-s.free:
		return nil
	default:
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-s.free:
		return nil
	case <-timer.C:
		return ErrSlotsBusy
	}
}

// Release returns a slot taken with Acquire.
func (s *Slots) Release() {
	select {
	case s.free <- struct{}{}:
	default:
		panic("utils.Slots: Release without Acquire")
	}
}
