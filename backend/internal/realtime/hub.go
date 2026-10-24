// Package realtime fans out content-free "pokes" to connected clients over SSE.
// Events never carry ciphertext: clients refetch through the authorized REST path,
// so there is exactly one code path that decides who may read what.
package realtime

import (
	"errors"
	"sync"

	"noaddress/internal/utils"
)

const (
	// MaxSubscribersPerMember bounds open tabs/devices per identity.
	MaxSubscribersPerMember = 4
	// MaxSubscribersTotal bounds goroutines and sockets held by event streams.
	MaxSubscribersTotal = 4096
	// subscriberBuffer absorbs bursts; a full buffer drops pokes (clients resync on reconnect).
	subscriberBuffer = 32
)

// Event kinds (whitelist): the SSE handler only ever writes these names.
const (
	KindMessage      = "msg"  // new message in conversation ConversationID
	KindConversation = "conv" // conversation list changed (created / burned)
)

var (
	ErrTooManySubscribers = errors.New("too many subscribers")
	hubLogger             = utils.NewLogger("REALTIME")
)

// Event is a content-free notification.
type Event struct {
	Kind           string
	ConversationID string
}

// Hub maps member tags to live subscriber channels.
// Lock order: Hub.mu is a leaf lock (Priority Level 1); nothing is acquired while holding it.
type Hub struct {
	mu    sync.Mutex
	subs  map[string]map[chan Event]struct{}
	total int
}

// NewHub creates an empty hub.
func NewHub() *Hub {
	return &Hub{subs: make(map[string]map[chan Event]struct{})}
}

// Default is the process-wide hub used by handlers.
var Default = NewHub()

// Subscribe registers a channel for memberTag. The returned cancel func is idempotent.
func (h *Hub) Subscribe(memberTag string) (<-chan Event, func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.total >= MaxSubscribersTotal || len(h.subs[memberTag]) >= MaxSubscribersPerMember {
		return nil, nil, ErrTooManySubscribers
	}
	ch := make(chan Event, subscriberBuffer)
	if h.subs[memberTag] == nil {
		h.subs[memberTag] = make(map[chan Event]struct{})
	}
	h.subs[memberTag][ch] = struct{}{}
	h.total++

	cancel := func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.removeLocked(memberTag, ch)
	}
	return ch, cancel, nil
}

// removeLocked closes and forgets ch if still registered. Caller holds h.mu.
func (h *Hub) removeLocked(memberTag string, ch chan Event) {
	set, ok := h.subs[memberTag]
	if !ok {
		return
	}
	if _, ok := set[ch]; !ok {
		return
	}
	delete(set, ch)
	close(ch)
	h.total--
	if len(set) == 0 {
		delete(h.subs, memberTag)
	}
}

// Publish delivers ev to every subscriber of each tag without blocking.
// Sends happen under h.mu, so a channel can never be closed mid-send.
func (h *Hub) Publish(memberTags []string, ev Event) {
	h.mu.Lock()
	defer h.mu.Unlock()

	dropped := 0
	for _, tag := range memberTags {
		for ch := range h.subs[tag] {
			select {
			case ch <- ev:
			default:
				dropped++
			}
		}
	}
	if dropped > 0 {
		hubLogger.Warn("Publish: dropped %d pokes on full subscriber buffers", dropped)
	}
}

// Kick closes every stream of memberTag (used when sessions are revoked).
func (h *Hub) Kick(memberTag string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for ch := range h.subs[memberTag] {
		h.removeLocked(memberTag, ch)
	}
}
