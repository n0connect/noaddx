package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"noaddx/internal/auth"
	"noaddx/internal/chat"
	"noaddx/internal/config"
	"noaddx/internal/middleware"
	"noaddx/internal/models"
	"noaddx/internal/realtime"
	"noaddx/internal/store"
	"noaddx/internal/utils"
)

const (
	conversationsPath = "/api/v2/conversations"
	// "after" is the only accepted query parameter; seq values are positive int64
	maxSeqDigits = 19
)

var (
	chatLogger  = utils.NewLogger("CHAT")
	chatService = chat.NewService()
)

// resolveMe turns the JWT-authenticated user into a chat member or writes the error.
func resolveMe(w http.ResponseWriter, r *http.Request) (*chat.Member, bool) {
	w.Header().Set("Cache-Control", "no-store")
	userUUID, ok := auth.GetUserUUID(r.Context())
	if !ok {
		chatLogger.Error("resolveMe: user UUID not found in context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	me, err := chatService.ResolveMember(userUUID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return nil, false
		}
		writeChatError(w, err, "ResolveMember")
		return nil, false
	}
	return me, true
}

// writeChatError maps service errors to generic client messages; details stay in logs.
func writeChatError(w http.ResponseWriter, err error, op string) {
	switch {
	case errors.Is(err, chat.ErrInvalidInput):
		chatLogger.Warn("%s: rejected input: %v", op, err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
	case errors.Is(err, chat.ErrNotFound):
		http.Error(w, "Not found", http.StatusNotFound)
	case errors.Is(err, chat.ErrLimitReached):
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
	case errors.Is(err, chat.ErrConflict):
		http.Error(w, "Conflict", http.StatusConflict)
	case errors.Is(err, chat.ErrIdentityUnset):
		http.Error(w, "Forbidden", http.StatusForbidden)
	default:
		chatLogger.LogError(op, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func rejectQuery(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.RawQuery != "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return true
	}
	return false
}

func allowOrTooMany(w http.ResponseWriter, bucket string, me *chat.Member) bool {
	if middleware.AllowKey(bucket + ":" + me.StreamTag) {
		return true
	}
	chatLogger.Warn("rate limit exceeded: bucket=%s", bucket)
	http.Error(w, "Too many requests", http.StatusTooManyRequests)
	return false
}

// MeHandler returns the caller's identity public key so the client can detect
// a server that swapped it (client compares against its own derivation).
func MeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	me, ok := resolveMe(w, r)
	if !ok || rejectQuery(w, r) {
		return
	}
	utils.EncodeJSONResponse(w, models.MeResponse{PublicKey: me.PublicKey, MessageTTLDays: config.GetMessageTTLDays()}, http.StatusOK)
}

// CreateInviteHandler issues a single-use pairing token (POST /api/v2/invites).
func CreateInviteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	me, ok := resolveMe(w, r)
	if !ok || rejectQuery(w, r) || !allowOrTooMany(w, "invite", me) {
		return
	}
	token, expiresAt, err := chatService.CreateInvite(me)
	if err != nil {
		writeChatError(w, err, "CreateInvite")
		return
	}
	utils.EncodeJSONResponse(w, models.InviteResponse{Token: token, ExpiresAt: expiresAt.Unix()}, http.StatusCreated)
}

// RedeemInviteHandler pairs the caller with the invite creator (POST /api/v2/invites/redeem).
func RedeemInviteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	me, ok := resolveMe(w, r)
	if !ok || rejectQuery(w, r) || !allowOrTooMany(w, "redeem", me) {
		return
	}
	var req models.RedeemInviteRequest
	if err := utils.DecodeJSONRequest(r, &req); err != nil {
		chatLogger.LogError("DecodeJSONRequest", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	conversation, creatorStream, err := chatService.RedeemInvite(me, req.Token)
	if err != nil {
		writeChatError(w, err, "RedeemInvite")
		return
	}
	realtime.Default.Publish([]string{creatorStream}, realtime.Event{Kind: realtime.KindConversation})
	utils.EncodeJSONResponse(w, models.ConversationResponse{Conversation: *conversation}, http.StatusCreated)
}

// parseConversationRoute whitelists: "", "/{id}", "/{id}/messages", "/{id}/read".
func parseConversationRoute(path string) (uuid.UUID, string, bool) {
	rest := strings.TrimPrefix(path, conversationsPath)
	if rest == "" {
		return uuid.Nil, "", true
	}
	parts := strings.Split(strings.TrimPrefix(rest, "/"), "/")
	if !strings.HasPrefix(rest, "/") || len(parts) > 2 {
		return uuid.Nil, "", false
	}
	id, ok := utils.ParseCanonicalUUIDv4(parts[0])
	if !ok {
		return uuid.Nil, "", false
	}
	if len(parts) == 1 {
		return id, "", true
	}
	switch parts[1] {
	case "messages", "read":
		return id, parts[1], true
	default:
		return uuid.Nil, "", false
	}
}

// ConversationsHandler routes every /api/v2/conversations[/...] request.
func ConversationsHandler(w http.ResponseWriter, r *http.Request) {
	id, sub, ok := parseConversationRoute(r.URL.Path)
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	me, ok := resolveMe(w, r)
	if !ok {
		return
	}

	switch {
	case id == uuid.Nil && r.Method == http.MethodGet:
		listConversations(w, r, me)
	case id != uuid.Nil && sub == "" && r.Method == http.MethodDelete:
		burnConversation(w, r, me, id)
	case sub == "messages" && r.Method == http.MethodGet:
		listMessages(w, r, me, id)
	case sub == "messages" && r.Method == http.MethodPost:
		sendMessage(w, r, me, id)
	case sub == "read" && r.Method == http.MethodPost:
		markRead(w, r, me, id)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func listConversations(w http.ResponseWriter, r *http.Request, me *chat.Member) {
	if rejectQuery(w, r) {
		return
	}
	conversations, err := chatService.ListConversations(me)
	if err != nil {
		writeChatError(w, err, "ListConversations")
		return
	}
	utils.EncodeJSONResponse(w, models.ConversationsResponse{Conversations: conversations}, http.StatusOK)
}

func burnConversation(w http.ResponseWriter, r *http.Request, me *chat.Member, id uuid.UUID) {
	if rejectQuery(w, r) {
		return
	}
	peers, err := chatService.BurnConversation(me, id)
	if err != nil {
		writeChatError(w, err, "BurnConversation")
		return
	}
	realtime.Default.Publish(peers, realtime.Event{Kind: realtime.KindConversation})
	w.WriteHeader(http.StatusNoContent)
}

// parseAfter accepts either no query at all or exactly "after=<positive-or-zero int64>".
func parseAfter(r *http.Request) (*int64, bool) {
	if r.URL.RawQuery == "" {
		return nil, true
	}
	values := r.URL.Query()
	raw, present := values["after"]
	if len(values) != 1 || !present || len(raw) != 1 || len(raw[0]) == 0 || len(raw[0]) > maxSeqDigits {
		return nil, false
	}
	for i := 0; i < len(raw[0]); i++ {
		if raw[0][i] < '0' || raw[0][i] > '9' {
			return nil, false
		}
	}
	after, err := strconv.ParseInt(raw[0], 10, 64)
	if err != nil {
		return nil, false
	}
	return &after, true
}

func listMessages(w http.ResponseWriter, r *http.Request, me *chat.Member, id uuid.UUID) {
	after, ok := parseAfter(r)
	if !ok {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	messages, err := chatService.ListMessages(me, id, after)
	if err != nil {
		writeChatError(w, err, "ListMessages")
		return
	}
	utils.EncodeJSONResponse(w, models.MessagesResponse{Messages: messages}, http.StatusOK)
}

func sendMessage(w http.ResponseWriter, r *http.Request, me *chat.Member, id uuid.UUID) {
	if rejectQuery(w, r) || !allowOrTooMany(w, "msg", me) {
		return
	}
	var req models.SendMessageRequest
	if err := utils.DecodeJSONRequest(r, &req); err != nil {
		chatLogger.LogError("DecodeJSONRequest", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	seq, peers, err := chatService.SendMessage(me, id, req.ID, req.Ciphertext)
	if err != nil {
		writeChatError(w, err, "SendMessage")
		return
	}
	realtime.Default.Publish(peers, realtime.Event{Kind: realtime.KindMessage, ConversationID: id.String()})
	utils.EncodeJSONResponse(w, models.SendMessageResponse{Seq: seq}, http.StatusCreated)
}

func markRead(w http.ResponseWriter, r *http.Request, me *chat.Member, id uuid.UUID) {
	if rejectQuery(w, r) {
		return
	}
	var req models.MarkReadRequest
	if err := utils.DecodeJSONRequest(r, &req); err != nil {
		chatLogger.LogError("DecodeJSONRequest", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if err := chatService.MarkRead(me, id, req.Seq); err != nil {
		writeChatError(w, err, "MarkRead")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
