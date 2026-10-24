package realtime

import "testing"

func TestHub_PublishReachesOnlyTargetTags(t *testing.T) {
	h := NewHub()
	a, cancelA, err := h.Subscribe("a")
	if err != nil {
		t.Fatal(err)
	}
	defer cancelA()
	b, cancelB, _ := h.Subscribe("b")
	defer cancelB()

	h.Publish([]string{"a"}, Event{Kind: KindMessage, ConversationID: "c1"})
	select {
	case ev := <-a:
		if ev.ConversationID != "c1" {
			t.Fatalf("unexpected event %+v", ev)
		}
	default:
		t.Fatal("subscriber a did not receive event")
	}
	select {
	case ev := <-b:
		t.Fatalf("subscriber b received foreign event %+v", ev)
	default:
	}
}

func TestHub_LimitsAndKick(t *testing.T) {
	h := NewHub()
	cancels := []func(){}
	for i := 0; i < MaxSubscribersPerMember; i++ {
		_, cancel, err := h.Subscribe("a")
		if err != nil {
			t.Fatalf("subscribe %d: %v", i, err)
		}
		cancels = append(cancels, cancel)
	}
	if _, _, err := h.Subscribe("a"); err != ErrTooManySubscribers {
		t.Fatalf("expected per-member limit, got %v", err)
	}

	h.Kick("a")
	if h.total != 0 || len(h.subs) != 0 {
		t.Fatalf("kick left state behind: total=%d subs=%d", h.total, len(h.subs))
	}
	// Cancels after kick must be harmless (idempotent, no double close)
	for _, cancel := range cancels {
		cancel()
	}
	// Publishing to a kicked tag must not panic
	h.Publish([]string{"a"}, Event{Kind: KindConversation})
}

func TestHub_FullBufferDropsInsteadOfBlocking(t *testing.T) {
	h := NewHub()
	_, cancel, _ := h.Subscribe("a")
	defer cancel()
	for i := 0; i < subscriberBuffer*3; i++ {
		h.Publish([]string{"a"}, Event{Kind: KindConversation})
	}
}
