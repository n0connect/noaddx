package handlers

import (
	"errors"
	"io"
	"net/http"
	"time"

	"noaddress/internal/realtime"
)

const (
	// sseWriteTimeout bounds every individual write so a stalled client cannot pin a goroutine
	sseWriteTimeout = 10 * time.Second
	// sseKeepAlive keeps proxies from reaping idle streams
	sseKeepAlive = 25 * time.Second
	// sseMaxLifetime forces periodic reconnects, which re-run JWT + session-epoch checks
	sseMaxLifetime = 10 * time.Minute
	// sseMaxIterations bounds the event loop (RULES.md §8.1); lifetime normally ends it first
	sseMaxIterations = 100000
	sseRetryPreamble = "retry: 3000\n: ready\n\n"
	ssePing          = ": ping\n\n"
)

// formatEvent renders whitelisted event kinds only; payloads are server-generated IDs.
func formatEvent(ev realtime.Event) string {
	switch ev.Kind {
	case realtime.KindMessage:
		return "event: msg\ndata: {\"c\":\"" + ev.ConversationID + "\"}\n\n"
	case realtime.KindConversation:
		return "event: conv\ndata: {}\n\n"
	default:
		return ""
	}
}

// EventsHandler streams content-free change notifications (GET /api/v2/events).
func EventsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	me, ok := resolveMe(w, r)
	if !ok || rejectQuery(w, r) {
		return
	}

	events, cancel, err := realtime.Default.Subscribe(me.StreamTag)
	if err != nil {
		chatLogger.Warn("EventsHandler: subscriber limit reached")
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}
	defer cancel()

	rc := http.NewResponseController(w)
	write := func(payload string) bool {
		if err := rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return false
		}
		if _, err := io.WriteString(w, payload); err != nil {
			return false
		}
		return rc.Flush() == nil
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no") // nginx: do not buffer the stream
	w.WriteHeader(http.StatusOK)
	if !write(sseRetryPreamble) {
		return
	}

	keepAlive := time.NewTicker(sseKeepAlive)
	defer keepAlive.Stop()
	lifetime := time.NewTimer(sseMaxLifetime)
	defer lifetime.Stop()

	for i := 0; i < sseMaxIterations; i++ {
		select {
		case <-r.Context().Done():
			return
		case <-lifetime.C:
			return
		case <-keepAlive.C:
			if !write(ssePing) {
				return
			}
		case ev, open := <-events:
			if !open {
				return // session revoked (Kick) — client reconnect will fail auth
			}
			if payload := formatEvent(ev); payload != "" && !write(payload) {
				return
			}
		}
	}
}
