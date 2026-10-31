package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"noaddx/internal/auth"
	"noaddx/internal/chat"
	"noaddx/internal/config"
	"noaddx/internal/identity"
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
	case errors.Is(err, chat.ErrRoomFull):
		http.Error(w, "Room full", http.StatusConflict)
	case errors.Is(err, chat.ErrStale):
		// The roster changed since the sender fetched it: fetch it again and re-encrypt
		http.Error(w, "Roster changed", http.StatusPreconditionFailed)
	case errors.Is(err, chat.ErrIdentityUnset):
		http.Error(w, "Forbidden", http.StatusForbidden)
	case errors.Is(err, chat.ErrForbidden):
		chatLogger.Warn("%s: refused", op)
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

// MeHandler: GET returns the caller's identity public key so the client can detect a server
// that swapped it (client compares against its own derivation); DELETE erases the account.
func MeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	me, ok := resolveMe(w, r)
	if !ok || rejectQuery(w, r) {
		return
	}
	if r.Method == http.MethodDelete {
		deleteAccount(w, r, me)
		return
	}
	utils.EncodeJSONResponse(w, models.MeResponse{
		PublicKey:       me.PublicKey,
		MessageTTLDays:  config.GetMessageTTLDays(),
		RoomMaxMembers:  config.GetRoomMaxMembers(),
		RoomMaxTTLHours: config.GetRoomMaxTTLHours(),
	}, http.StatusOK)
}

// deleteAccount erases the caller once the request re-proves the account number (as its auth
// key): a live session alone, or a request riding on one, cannot erase an identity.
func deleteAccount(w http.ResponseWriter, r *http.Request, me *chat.Member) {
	if !allowOrTooMany(w, "delete", me) {
		return
	}
	var req models.DeleteAccountRequest
	if err := utils.DecodeJSONRequest(r, &req); err != nil || !identity.ValidateEncodedKey(req.AuthKey) {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	streams, err := chatService.DeleteAccount(me, req.AuthKey)
	if err != nil {
		writeChatError(w, err, "DeleteAccount")
		return
	}
	realtime.Default.Publish(streams, realtime.Event{Kind: realtime.KindConversation})
	realtime.Default.Kick(me.StreamTag) // this account's other devices
	auth.ClearAuthCookie(w)
	utils.EncodeJSONResponse(w, models.LoginResponse{Success: true, Message: "Account deleted"}, http.StatusOK)
}

// CreateInviteHandler issues a single-use pairing token (POST /api/v2/invites).
// Each invite costs a fresh proof of work, like each registration phase.
func CreateInviteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	me, ok := resolveMe(w, r)
	if !ok || rejectQuery(w, r) || !allowOrTooMany(w, "invite", me) {
		return
	}
	var req models.CreateInviteRequest
	if err := utils.DecodeJSONRequest(r, &req); err != nil {
		chatLogger.LogError("DecodeJSONRequest", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if !requireProofOfWork(w, req.PoW, "invite") {
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

// conversationRoute is a whitelisted /api/v2/conversations path: id, sub-resource, item id.
type conversationRoute struct {
	id   uuid.UUID
	sub  string
	item uuid.UUID
}

// parseConversationRoute whitelists: "", "/{id}", "/{id}/messages", "/{id}/read",
// "/{id}/members", "/{id}/notes", "/{id}/notes/{note id}".
func parseConversationRoute(path string) (conversationRoute, bool) {
	rest := strings.TrimPrefix(path, conversationsPath)
	if rest == "" {
		return conversationRoute{}, true
	}
	parts := strings.Split(strings.TrimPrefix(rest, "/"), "/")
	if !strings.HasPrefix(rest, "/") || len(parts) > 3 {
		return conversationRoute{}, false
	}
	id, ok := utils.ParseCanonicalUUIDv4(parts[0])
	if !ok {
		return conversationRoute{}, false
	}
	if len(parts) == 1 {
		return conversationRoute{id: id}, true
	}
	switch {
	case len(parts) == 2 && (parts[1] == "messages" || parts[1] == "read" || parts[1] == "members" || parts[1] == "notes"):
		return conversationRoute{id: id, sub: parts[1]}, true
	case len(parts) == 3 && parts[1] == "notes":
		item, ok := utils.ParseCanonicalUUIDv4(parts[2])
		if !ok {
			return conversationRoute{}, false
		}
		return conversationRoute{id: id, sub: "notes", item: item}, true
	default:
		return conversationRoute{}, false
	}
}

// ConversationsHandler routes every /api/v2/conversations[/...] request.
func ConversationsHandler(w http.ResponseWriter, r *http.Request) {
	route, ok := parseConversationRoute(r.URL.Path)
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	me, ok := resolveMe(w, r)
	if !ok {
		return
	}

	id, sub := route.id, route.sub
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
	case sub == "members" && r.Method == http.MethodGet:
		roomMembers(w, r, me, id)
	case sub == "notes" && route.item == uuid.Nil && r.Method == http.MethodGet:
		listNotes(w, r, me, id)
	case sub == "notes" && route.item == uuid.Nil && r.Method == http.MethodPost:
		sendNote(w, r, me, id)
	case sub == "notes" && route.item != uuid.Nil && r.Method == http.MethodDelete:
		deleteNote(w, r, me, id, route.item)
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

// ---------- rooms ----------

// CreateRoomHandler stores a room the client derived from a fresh room code (POST /api/v2/rooms).
// Each room costs a proof of work, like each invite.
func CreateRoomHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	me, ok := resolveMe(w, r)
	if !ok || rejectQuery(w, r) || !allowOrTooMany(w, "room", me) {
		return
	}
	var req models.CreateRoomRequest
	if err := utils.DecodeJSONRequest(r, &req); err != nil {
		chatLogger.LogError("DecodeJSONRequest", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	in, err := chat.ParseRoomInput(req.ID, req.Lookup, req.Card, req.Vault)
	if err != nil {
		writeChatError(w, err, "CreateRoom")
		return
	}
	in.MaxMembers = req.MaxMembers
	in.ExpiresAt = time.Unix(req.ExpiresAt, 0)
	if !requireProofOfWork(w, req.PoW, "room") {
		return
	}
	conversation, err := chatService.CreateRoom(me, in)
	if err != nil {
		writeChatError(w, err, "CreateRoom")
		return
	}
	realtime.Default.Publish([]string{me.StreamTag}, realtime.Event{Kind: realtime.KindConversation})
	utils.EncodeJSONResponse(w, models.ConversationResponse{Conversation: *conversation}, http.StatusCreated)
}

// JoinRoomHandler takes a seat in a room whose code the caller holds (POST /api/v2/rooms/join):
// 201 for a new seat, 200 when the caller was already a member.
func JoinRoomHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	me, ok := resolveMe(w, r)
	if !ok || rejectQuery(w, r) || !allowOrTooMany(w, "join", me) {
		return
	}
	var req models.JoinRoomRequest
	if err := utils.DecodeJSONRequest(r, &req); err != nil {
		chatLogger.LogError("DecodeJSONRequest", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	in, err := chat.ParseRoomInput(req.ID, req.Lookup, req.Card, req.Vault)
	if err != nil {
		writeChatError(w, err, "JoinRoom")
		return
	}
	conversation, created, peers, err := chatService.JoinRoom(me, in)
	if err != nil {
		writeChatError(w, err, "JoinRoom")
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		realtime.Default.Publish(append(peers, me.StreamTag), realtime.Event{Kind: realtime.KindConversation})
	}
	utils.EncodeJSONResponse(w, models.ConversationResponse{Conversation: *conversation}, status)
}

func roomMembers(w http.ResponseWriter, r *http.Request, me *chat.Member, id uuid.UUID) {
	if rejectQuery(w, r) {
		return
	}
	members, err := chatService.RoomMembers(me, id)
	if err != nil {
		writeChatError(w, err, "RoomMembers")
		return
	}
	utils.EncodeJSONResponse(w, models.RoomMembersResponse{Members: members}, http.StatusOK)
}

func listNotes(w http.ResponseWriter, r *http.Request, me *chat.Member, id uuid.UUID) {
	if rejectQuery(w, r) {
		return
	}
	notes, err := chatService.ListNotes(me, id)
	if err != nil {
		writeChatError(w, err, "ListNotes")
		return
	}
	utils.EncodeJSONResponse(w, models.NotesResponse{Notes: notes}, http.StatusOK)
}

func sendNote(w http.ResponseWriter, r *http.Request, me *chat.Member, id uuid.UUID) {
	if rejectQuery(w, r) || !allowOrTooMany(w, "note", me) {
		return
	}
	var req models.SendNoteRequest
	if err := utils.DecodeJSONRequest(r, &req); err != nil {
		chatLogger.LogError("DecodeJSONRequest", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	recipient, err := chatService.SendNote(me, id, req.ID, req.To, req.Blob)
	if err != nil {
		writeChatError(w, err, "SendNote")
		return
	}
	realtime.Default.Publish([]string{recipient}, realtime.Event{Kind: realtime.KindConversation})
	w.WriteHeader(http.StatusCreated)
}

func deleteNote(w http.ResponseWriter, r *http.Request, me *chat.Member, id, noteID uuid.UUID) {
	if rejectQuery(w, r) {
		return
	}
	if err := chatService.DeleteNote(me, id, noteID); err != nil {
		writeChatError(w, err, "DeleteNote")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
