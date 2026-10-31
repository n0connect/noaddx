package integration

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"noaddx/internal/chat"
	"noaddx/internal/database"
	"noaddx/internal/e2e"
	"noaddx/internal/models"

	"github.com/google/uuid"
)

// roomSide is one user's place in one room: the room derived from the code, and their key in it.
// Everything here is the real client protocol (internal/e2e), so messages are genuine E2E ciphertext.
type roomSide struct {
	u      *user
	code   *e2e.RoomCode
	room   *e2e.Room
	member *e2e.RoomMember
	root   []byte
}

func (s *roomSide) path(suffix string) string {
	return "/api/v2/conversations/" + s.room.ID.String() + suffix
}

func newCode(t *testing.T, maxMembers, ttlHours int) *e2e.RoomCode {
	t.Helper()
	code, err := e2e.NewRoomCode(maxMembers, uint32(time.Now().Unix()/3600)+uint32(ttlHours)+1)
	if err != nil {
		t.Fatalf("NewRoomCode: %v", err)
	}
	return code
}

func sideOf(t *testing.T, u *user, code *e2e.RoomCode) *roomSide {
	t.Helper()
	room, err := e2e.DeriveRoom(code.Secret)
	if err != nil {
		t.Fatalf("DeriveRoom: %v", err)
	}
	root, err := e2e.RoomsRoot(u.accountNumber)
	if err != nil {
		t.Fatalf("RoomsRoot: %v", err)
	}
	member, err := room.Member(root)
	if err != nil {
		t.Fatalf("Member: %v", err)
	}
	return &roomSide{u: u, code: code, room: room, member: member, root: root}
}

func (s *roomSide) vault(t *testing.T) string {
	t.Helper()
	vault, err := e2e.SealVault(s.root, s.room.ID, s.code)
	if err != nil {
		t.Fatalf("SealVault: %v", err)
	}
	return vault
}

func (s *roomSide) createRequest(t *testing.T) models.CreateRoomRequest {
	t.Helper()
	return models.CreateRoomRequest{
		ID:         s.room.ID.String(),
		Lookup:     s.room.Lookup,
		MaxMembers: s.code.MaxMembers,
		ExpiresAt:  int64(s.code.ExpiresHour) * 3600,
		Card:       s.member.Card,
		Vault:      s.vault(t),
	}
}

func (s *roomSide) joinRequest(t *testing.T) models.JoinRoomRequest {
	t.Helper()
	return models.JoinRoomRequest{ID: s.room.ID.String(), Lookup: s.room.Lookup, Card: s.member.Card, Vault: s.vault(t)}
}

func createRoom(t *testing.T, u *user, maxMembers, ttlHours int) *roomSide {
	t.Helper()
	s := sideOf(t, u, newCode(t, maxMembers, ttlHours))
	req := s.createRequest(t)
	req.PoW = u.freshPoW()
	rr := u.do("POST", "/api/v2/rooms", req)
	expectStatus(t, rr, http.StatusCreated, "create room")
	var resp models.ConversationResponse
	decode(t, rr, &resp)
	if resp.Conversation.ID != s.room.ID.String() || resp.Conversation.Room == nil || !resp.Conversation.Room.Owner {
		t.Fatalf("create returned %+v", resp.Conversation)
	}
	return s
}

func joinRoom(t *testing.T, u *user, code *e2e.RoomCode) *roomSide {
	t.Helper()
	s := sideOf(t, u, code)
	expectStatus(t, u.do("POST", "/api/v2/rooms/join", s.joinRequest(t)), http.StatusCreated, "join room")
	return s
}

func (s *roomSide) members(t *testing.T) []models.RoomMemberDTO {
	t.Helper()
	rr := s.u.do("GET", s.path("/members"), nil)
	expectStatus(t, rr, http.StatusOK, "room members")
	var resp models.RoomMembersResponse
	decode(t, rr, &resp)
	return resp.Members
}

func (s *roomSide) roster(t *testing.T) []string {
	t.Helper()
	members := s.members(t)
	cards := make([]string, len(members))
	for i, m := range members {
		cards[i] = m.Card
	}
	return cards
}

// sealTo encrypts text for exactly the given roster (as a client that fetched it would).
func (s *roomSide) sealTo(t *testing.T, roster []string, id, text string, counter int64) string {
	t.Helper()
	recipients, digest, err := s.room.Recipients(s.member, roster)
	if err != nil {
		t.Fatalf("Recipients: %v", err)
	}
	blob, err := s.room.SealMessage(s.member, uuid.MustParse(id), recipients, digest, text, time.Now().UnixMilli(), counter)
	if err != nil {
		t.Fatalf("SealMessage: %v", err)
	}
	return blob
}

func (s *roomSide) post(id, blob string) *httptest.ResponseRecorder {
	return s.u.do("POST", s.path("/messages"), models.SendMessageRequest{ID: id, Ciphertext: blob})
}

func (s *roomSide) say(t *testing.T, text string, counter int64) {
	t.Helper()
	id := newMessageID()
	expectStatus(t, s.post(id, s.sealTo(t, s.roster(t), id, text, counter)), http.StatusCreated, "room send")
}

type heard struct {
	text   string
	sender []byte
	mine   bool
}

func (s *roomSide) read(t *testing.T) []heard {
	t.Helper()
	rr := s.u.do("GET", s.path("/messages"), nil)
	expectStatus(t, rr, http.StatusOK, "room read")
	var resp models.MessagesResponse
	decode(t, rr, &resp)
	out := make([]heard, 0, len(resp.Messages))
	for _, m := range resp.Messages {
		msg, err := s.room.OpenMessage(s.member, uuid.MustParse(m.ID), m.Ciphertext)
		if err != nil {
			t.Fatalf("OpenMessage seq %d: %v", m.Seq, err)
		}
		if m.Mine != bytes.Equal(msg.Sender, s.member.Public) {
			t.Fatalf("server says mine=%v for a message from %x", m.Mine, msg.Sender)
		}
		out = append(out, heard{text: msg.Text, sender: msg.Sender, mine: m.Mine})
	}
	return out
}

func listOf(t *testing.T, u *user) []models.ConversationDTO {
	t.Helper()
	rr := u.do("GET", "/api/v2/conversations", nil)
	expectStatus(t, rr, http.StatusOK, "list conversations")
	var list models.ConversationsResponse
	decode(t, rr, &list)
	return list.Conversations
}

func findConversation(list []models.ConversationDTO, id string) *models.ConversationDTO {
	for i := range list {
		if list[i].ID == id {
			return &list[i]
		}
	}
	return nil
}

func TestRooms_CreateJoinAndTalk(t *testing.T) {
	mux := setup(t)
	alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)
	a := createRoom(t, alice, 3, 24)
	b := joinRoom(t, bob, a.code)
	c := joinRoom(t, carol, a.code)

	a.say(t, "merhaba oda", 1)
	b.say(t, "selam", 1)
	c.say(t, "ben de buradayım", 1)

	for name, s := range map[string]*roomSide{"alice": a, "bob": b, "carol": c} {
		got := s.read(t)
		if len(got) != 3 || got[0].text != "merhaba oda" || got[1].text != "selam" || got[2].text != "ben de buradayım" {
			t.Fatalf("%s read %+v", name, got)
		}
		for i, sender := range []*roomSide{a, b, c} {
			if !bytes.Equal(got[i].sender, sender.member.Public) {
				t.Fatalf("%s: message %d attributed to the wrong member", name, i)
			}
		}
	}

	members := b.members(t)
	if len(members) != 3 {
		t.Fatalf("bob sees %d members", len(members))
	}
	owners, mine := 0, 0
	for _, m := range members {
		if m.Owner {
			owners++
			if m.Card != a.member.Card {
				t.Fatal("the owner flag is not on the creator's card")
			}
		}
		if m.Mine {
			mine++
			if m.Card != b.member.Card {
				t.Fatal("the mine flag is not on bob's card")
			}
		}
	}
	if owners != 1 || mine != 1 {
		t.Fatalf("owner=%d mine=%d flags", owners, mine)
	}

	// Every member's listing carries a vault that opens, for that member only, to the code
	for name, s := range map[string]*roomSide{"alice": a, "bob": b} {
		conv := findConversation(listOf(t, s.u), s.room.ID.String())
		if conv == nil || conv.Room == nil || conv.PeerPublicKey != "" {
			t.Fatalf("%s's listing lacks the room: %+v", name, conv)
		}
		code, err := e2e.OpenVault(s.root, s.room.ID, conv.Room.Vault)
		if err != nil || !bytes.Equal(code.Secret, a.code.Secret) {
			t.Fatalf("%s's vault: %v", name, err)
		}
		if conv.Room.MaxMembers != 3 || conv.Room.ExpiresAt != int64(a.code.ExpiresHour)*3600 || conv.Room.Members != 3 || conv.Room.Owner != (s == a) {
			t.Fatalf("%s's room view %+v", name, conv.Room)
		}
		if conv.LastSeq != 3 {
			t.Fatalf("%s's last_seq = %d", name, conv.LastSeq)
		}
	}
	if _, err := e2e.OpenVault(b.root, a.room.ID, findConversation(listOf(t, alice), a.room.ID.String()).Room.Vault); err == nil {
		t.Fatal("bob opened alice's vault")
	}
}

func TestRooms_JoinNeedsTheCode(t *testing.T) {
	mux := setup(t)
	alice, mallory := register(t, mux), register(t, mux)
	a := createRoom(t, alice, 4, 24)

	// The room id alone (it appears in every URL) does not let anyone in
	m := sideOf(t, mallory, newCode(t, 4, 24))
	req := m.joinRequest(t)
	req.ID = a.room.ID.String()
	expectStatus(t, mallory.do("POST", "/api/v2/rooms/join", req), http.StatusNotFound, "join with the id only")
	unknown := sideOf(t, mallory, newCode(t, 4, 24))
	expectStatus(t, mallory.do("POST", "/api/v2/rooms/join", unknown.joinRequest(t)), http.StatusNotFound, "join an unknown room")

	base := a.path("")
	expectStatus(t, mallory.do("GET", base+"/members", nil), http.StatusNotFound, "outsider reads the roster")
	expectStatus(t, mallory.do("GET", base+"/messages", nil), http.StatusNotFound, "outsider reads messages")
	expectStatus(t, mallory.do("DELETE", base, nil), http.StatusNotFound, "outsider burns")

	var stored models.Room
	database.DB.First(&stored, "id = ?", a.room.ID)
	if stored.Lookup == "" || strings.Contains(stored.Lookup, a.room.Lookup) || stored.Lookup == hexOf(t, a.room.Lookup) {
		t.Fatal("the server stores the room lookup itself instead of its keyed hash")
	}
}

func hexOf(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(raw))
	for _, b := range raw {
		out = append(out, digits[b>>4], digits[b&15])
	}
	return string(out)
}

func TestRooms_FullRoomRefusesAndRejoinIsHarmless(t *testing.T) {
	mux := setup(t)
	alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)
	a := createRoom(t, alice, 2, 24)
	b := joinRoom(t, bob, a.code)
	expectStatus(t, carol.do("POST", "/api/v2/rooms/join", sideOf(t, carol, a.code).joinRequest(t)), http.StatusConflict, "join a full room")

	// Joining again refreshes the vault and changes nothing else
	expectStatus(t, bob.do("POST", "/api/v2/rooms/join", b.joinRequest(t)), http.StatusOK, "rejoin")
	expectStatus(t, alice.do("POST", "/api/v2/rooms/join", a.joinRequest(t)), http.StatusOK, "owner rejoins")
	if n := len(a.members(t)); n != 2 {
		t.Fatalf("rejoining changed the roster to %d members", n)
	}
	if len(listOf(t, bob)) != 1 {
		t.Fatal("rejoining added the room to bob's list twice")
	}
}

func TestRooms_LateJoinerReadsOnlyLaterMessages(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	a := createRoom(t, alice, 4, 24)
	a.say(t, "before bob", 1)
	b := joinRoom(t, bob, a.code)
	a.say(t, "after bob", 2)

	got := b.read(t)
	if len(got) != 1 || got[0].text != "after bob" {
		t.Fatalf("bob read %+v, want only the message sent after he joined", got)
	}
	if got := a.read(t); len(got) != 2 {
		t.Fatalf("alice reads %d messages", len(got))
	}
	rr := bob.do("GET", a.path("/messages?after=0"), nil)
	var page models.MessagesResponse
	decode(t, rr, &page)
	if len(page.Messages) != 1 {
		t.Fatalf("after=0 gave bob %d messages", len(page.Messages))
	}
}

func TestRooms_StaleRosterIsRefused(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	a := createRoom(t, alice, 4, 24)
	before := a.roster(t)
	joinRoom(t, bob, a.code)

	id := newMessageID()
	expectStatus(t, a.post(id, a.sealTo(t, before, id, "bob would miss this", 1)), http.StatusPreconditionFailed, "send to a stale roster")
	// Fetching the roster again and re-encrypting works, under the same message id
	expectStatus(t, a.post(id, a.sealTo(t, a.roster(t), id, "now bob reads it", 1)), http.StatusCreated, "send to the current roster")
}

func TestRooms_MessageStructureIsWhitelisted(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	a := createRoom(t, alice, 2, 24)
	b := joinRoom(t, bob, a.code)
	conv := pair(t, alice, bob)

	id := newMessageID()
	good := a.sealTo(t, a.roster(t), id, "x", 1)
	raw, _ := base64.RawURLEncoding.DecodeString(good)
	pairCiphertext := seal(t, alice, bob, conv, id, "one-to-one", 1)
	note, err := a.room.SealNote(a.member, uuid.MustParse(id), b.member.Card, "noaddx:x", time.Now().UnixMilli())
	if err != nil {
		t.Fatalf("SealNote: %v", err)
	}
	cut := func(n int) string { return base64.RawURLEncoding.EncodeToString(raw[:len(raw)-n]) }
	for name, bad := range map[string]string{
		"one-to-one format": pairCiphertext,
		"a note":            note,
		"truncated frame":   cut(16),
		"no wraps":          base64.RawURLEncoding.EncodeToString(raw[:162]),
		"not base64url":     good[:len(good)-1] + "*",
		"empty":             "",
	} {
		expectStatus(t, a.post(id, bad), http.StatusBadRequest, name)
	}
	// More wraps than the room has seats
	recipients, digest, _ := a.room.Recipients(a.member, a.roster(t))
	many := append(append([][]byte{}, recipients...), recipients...)
	tooMany, err := a.room.SealMessage(a.member, uuid.MustParse(id), many, digest, "x", time.Now().UnixMilli(), 1)
	if err != nil {
		t.Fatalf("SealMessage: %v", err)
	}
	expectStatus(t, a.post(id, tooMany), http.StatusBadRequest, "more wraps than seats")
	// A room message is refused in a one-to-one conversation
	expectStatus(t, alice.do("POST", "/api/v2/conversations/"+conv+"/messages", models.SendMessageRequest{ID: id, Ciphertext: good}),
		http.StatusBadRequest, "room format in a pair")
	expectStatus(t, a.post(id, good), http.StatusCreated, "the genuine message")
}

func TestRooms_LeaveKeepsTheRoomAndBurnEndsIt(t *testing.T) {
	mux := setup(t)
	alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)
	a := createRoom(t, alice, 4, 24)
	b := joinRoom(t, bob, a.code)
	c := joinRoom(t, carol, a.code)
	c.say(t, "bye", 1)

	expectStatus(t, carol.do("DELETE", c.path(""), nil), http.StatusNoContent, "carol leaves")
	if findConversation(listOf(t, carol), a.room.ID.String()) != nil {
		t.Fatal("the room is still in carol's list")
	}
	expectStatus(t, carol.do("GET", c.path("/messages"), nil), http.StatusNotFound, "carol reads after leaving")
	if n := len(b.members(t)); n != 2 {
		t.Fatalf("after carol left bob sees %d members", n)
	}
	if got := b.read(t); len(got) != 1 || got[0].text != "bye" {
		t.Fatalf("carol's message should stay readable: %+v", got)
	}

	expectStatus(t, alice.do("DELETE", a.path(""), nil), http.StatusNoContent, "owner burns")
	expectStatus(t, bob.do("GET", b.path("/messages"), nil), http.StatusNotFound, "bob reads a burned room")
	if findConversation(listOf(t, bob), a.room.ID.String()) != nil {
		t.Fatal("the burned room is still in bob's list")
	}
	for _, model := range []interface{}{&models.Room{}, &models.Conversation{}} {
		var n int64
		database.DB.Model(model).Where("id = ?", a.room.ID).Count(&n)
		if n != 0 {
			t.Fatalf("%T row survived the burn", model)
		}
	}
	for _, model := range []interface{}{&models.ConversationMember{}, &models.Message{}, &models.RoomNote{}} {
		var n int64
		database.DB.Model(model).Where("conversation_id = ?", a.room.ID).Count(&n)
		if n != 0 {
			t.Fatalf("%T rows survived the burn", model)
		}
	}
}

func TestRooms_ExpiredRoomStopsAnsweringAndIsPurged(t *testing.T) {
	mux := setup(t)
	alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)
	a := createRoom(t, alice, 4, 1)
	b := joinRoom(t, bob, a.code)
	a.say(t, "short-lived", 1)

	database.DB.Model(&models.Room{}).Where("id = ?", a.room.ID).UpdateColumn("expires_at", time.Now().UTC().Add(-time.Second))
	expectStatus(t, bob.do("GET", b.path("/messages"), nil), http.StatusNotFound, "read an expired room")
	expectStatus(t, bob.do("GET", b.path("/members"), nil), http.StatusNotFound, "roster of an expired room")
	id := newMessageID()
	expectStatus(t, b.post(id, b.sealTo(t, []string{a.member.Card, b.member.Card}, id, "late", 1)), http.StatusNotFound, "send to an expired room")
	expectStatus(t, carol.do("POST", "/api/v2/rooms/join", sideOf(t, carol, a.code).joinRequest(t)), http.StatusNotFound, "join an expired room")
	if findConversation(listOf(t, bob), a.room.ID.String()) != nil {
		t.Fatal("an expired room is still listed")
	}

	if err := chat.NewService().PurgeExpired(time.Now()); err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	var rooms, members, messages int64
	database.DB.Model(&models.Room{}).Where("id = ?", a.room.ID).Count(&rooms)
	database.DB.Model(&models.ConversationMember{}).Where("conversation_id = ?", a.room.ID).Count(&members)
	database.DB.Model(&models.Message{}).Where("conversation_id = ?", a.room.ID).Count(&messages)
	if rooms+members+messages != 0 {
		t.Fatalf("purge left rooms=%d members=%d messages=%d", rooms, members, messages)
	}
}

func TestRooms_CreateValidatesEveryField(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)
	nowHour := time.Now().Unix() / 3600
	cases := map[string]func(*models.CreateRoomRequest){
		"one member":          func(r *models.CreateRoomRequest) { r.MaxMembers = 1 },
		"above the bound":     func(r *models.CreateRoomRequest) { r.MaxMembers = e2e.MaxRoomMembers + 1 },
		"above the config":    func(r *models.CreateRoomRequest) { r.MaxMembers = 17 },
		"expiry off the hour": func(r *models.CreateRoomRequest) { r.ExpiresAt++ },
		"expiry now":          func(r *models.CreateRoomRequest) { r.ExpiresAt = nowHour * 3600 },
		"expiry too far":      func(r *models.CreateRoomRequest) { r.ExpiresAt = (nowHour + 168 + 3) * 3600 },
		"uppercase id":        func(r *models.CreateRoomRequest) { r.ID = strings.ToUpper(r.ID) },
		"short lookup":        func(r *models.CreateRoomRequest) { r.Lookup = r.Lookup[1:] },
		"short card":          func(r *models.CreateRoomRequest) { r.Card = r.Card[1:] },
		"long vault":          func(r *models.CreateRoomRequest) { r.Vault += "A" },
	}
	for name, mutate := range cases {
		s := sideOf(t, alice, newCode(t, 4, 24))
		req := s.createRequest(t)
		mutate(&req)
		req.PoW = alice.freshPoW()
		expectStatus(t, alice.do("POST", "/api/v2/rooms", req), http.StatusBadRequest, name)
	}

	s := sideOf(t, alice, newCode(t, 4, 24))
	expectStatus(t, alice.do("POST", "/api/v2/rooms", s.createRequest(t)), http.StatusPreconditionFailed, "create without proof of work")
	req := s.createRequest(t)
	req.PoW = alice.freshPoW()
	expectStatus(t, alice.do("POST", "/api/v2/rooms", req), http.StatusCreated, "create")
	req.PoW = alice.freshPoW()
	expectStatus(t, alice.do("POST", "/api/v2/rooms", req), http.StatusConflict, "create the same room again")

	expectStatus(t, alice.do("POST", "/api/v2/rooms/join", models.JoinRoomRequest{ID: s.room.ID.String()}), http.StatusBadRequest, "join without fields")
	if len(listOf(t, alice)) != 1 {
		t.Fatal("refused requests left rooms behind")
	}
}

func TestRooms_StorageHoldsNoJoinableIdentifiers(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	r1 := createRoom(t, alice, 4, 24)
	r2 := createRoom(t, alice, 4, 24)
	b1 := joinRoom(t, bob, r1.code)
	b2 := joinRoom(t, bob, r2.code)
	r1.say(t, "one", 1)
	b2.say(t, "two", 1)

	if bytes.Equal(r1.member.Public, r2.member.Public) || bytes.Equal(b1.member.Public, b2.member.Public) {
		t.Fatal("an account carries the same member key in two rooms")
	}
	var rooms []models.Room
	database.DB.Find(&rooms)
	var members []models.ConversationMember
	database.DB.Find(&members)
	var users []models.User
	database.DB.Find(&users)

	tags := map[string]string{}
	for _, m := range members {
		if _, seen := tags[m.MemberTag]; seen {
			t.Fatal("a member tag repeats across rooms")
		}
		tags[m.MemberTag] = m.ConversationID.String()
		if m.PeerKeyEnc != "" || m.Card == "" || m.Vault == "" {
			t.Fatalf("room membership row has the wrong shape: %+v", m)
		}
	}
	for _, r := range rooms {
		if tags[r.OwnerTag] != r.ID.String() {
			t.Fatal("a room's owner tag is not a member tag of that same room")
		}
	}
	for _, u := range users {
		for _, m := range members {
			row := m.MemberTag + m.MemberRefEnc + m.Card + m.Vault
			if strings.Contains(row, u.UUID) || strings.Contains(row, u.PublicKey) {
				t.Fatal("a room membership row links to an account in plaintext")
			}
		}
		for _, r := range rooms {
			if strings.Contains(r.Lookup+r.OwnerTag, u.UUID) {
				t.Fatal("a rooms row links to an account in plaintext")
			}
		}
	}
}

func TestRooms_DeleteAccountBurnsOwnedRoomsAndLeavesJoinedOnes(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	owned := createRoom(t, alice, 4, 24)
	joinRoom(t, bob, owned.code)
	theirs := createRoom(t, bob, 4, 24)
	aliceInTheirs := joinRoom(t, alice, theirs.code)
	aliceInTheirs.say(t, "i was here", 1)

	expectStatus(t, alice.do("DELETE", "/api/v2/me", models.DeleteAccountRequest{AuthKey: alice.authKey}), http.StatusOK, "delete alice")

	list := listOf(t, bob)
	if findConversation(list, owned.room.ID.String()) != nil {
		t.Fatal("the room alice owned survived her account")
	}
	if findConversation(list, theirs.room.ID.String()) == nil {
		t.Fatal("bob's own room vanished when alice deleted her account")
	}
	if n := len(theirs.members(t)); n != 1 {
		t.Fatalf("bob's room still has %d members", n)
	}
	if got := theirs.read(t); len(got) != 1 || got[0].text != "i was here" {
		t.Fatalf("alice's message in bob's room: %+v", got)
	}
}

func TestRooms_EventsPokeTheOtherMembers(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	a := createRoom(t, alice, 4, 24)

	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/api/v2/events", nil)
	req.AddCookie(alice.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("events connect: %v", err)
	}
	defer resp.Body.Close()
	lines := make(chan string, 32)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	waitFor(t, lines, "retry: 3000")

	b := joinRoom(t, bob, a.code)
	waitFor(t, lines, "event: conv")
	b.say(t, "poke", 1)
	waitFor(t, lines, `data: {"c":"`+a.room.ID.String()+`"}`)
}

func (s *roomSide) note(t *testing.T, to *roomSide, text string) (string, string) {
	t.Helper()
	id := newMessageID()
	blob, err := s.room.SealNote(s.member, uuid.MustParse(id), to.member.Card, text, time.Now().UnixMilli())
	if err != nil {
		t.Fatalf("SealNote: %v", err)
	}
	return id, blob
}

func (s *roomSide) postNote(id, to, blob string) *httptest.ResponseRecorder {
	return s.u.do("POST", s.path("/notes"), models.SendNoteRequest{ID: id, To: to, Blob: blob})
}

func (s *roomSide) notes(t *testing.T) []models.NoteDTO {
	t.Helper()
	rr := s.u.do("GET", s.path("/notes"), nil)
	expectStatus(t, rr, http.StatusOK, "list notes")
	var resp models.NotesResponse
	decode(t, rr, &resp)
	return resp.Notes
}

func TestRoomNotes_AFriendRequestReachesOnlyItsAddressee(t *testing.T) {
	mux := setup(t)
	alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)
	a := createRoom(t, alice, 4, 24)
	b := joinRoom(t, bob, a.code)
	c := joinRoom(t, carol, a.code)

	// The request carries an ordinary single-use invite, end to end
	rr := alice.createInvite()
	expectStatus(t, rr, http.StatusCreated, "invite for the request")
	var invite models.InviteResponse
	decode(t, rr, &invite)
	noteID, blob := a.note(t, b, invite.Token)
	expectStatus(t, a.postNote(noteID, b.member.Card, blob), http.StatusCreated, "send the request")
	expectStatus(t, a.postNote(noteID, b.member.Card, blob), http.StatusConflict, "send it again")

	for side, want := range map[*roomSide]int{a: 0, b: 1, c: 0} {
		if conv := findConversation(listOf(t, side.u), a.room.ID.String()); conv == nil || conv.Room.Notes != want {
			t.Fatalf("a member sees %+v waiting notes, want %d", conv.Room, want)
		}
	}
	if len(c.notes(t)) != 0 || len(a.notes(t)) != 0 {
		t.Fatal("a note reached someone other than its addressee")
	}
	waiting := b.notes(t)
	if len(waiting) != 1 || waiting[0].ID != noteID {
		t.Fatalf("bob's notes: %+v", waiting)
	}
	opened, err := b.room.OpenNote(b.member, uuid.MustParse(noteID), waiting[0].Blob)
	if err != nil || opened.Text != invite.Token || !bytes.Equal(opened.Sender, a.member.Public) {
		t.Fatalf("OpenNote: %v", err)
	}
	expectStatus(t, carol.do("DELETE", c.path("/notes/"+noteID), nil), http.StatusNotFound, "carol deletes bob's note")

	// Accepting redeems the invite: the new one-to-one conversation carries alice's account key
	rr = bob.do("POST", "/api/v2/invites/redeem", models.RedeemInviteRequest{Token: opened.Text})
	expectStatus(t, rr, http.StatusCreated, "accept")
	var friends models.ConversationResponse
	decode(t, rr, &friends)
	if friends.Conversation.PeerPublicKey != alice.publicKey {
		t.Fatal("the friendship is not with the account that sent the request")
	}
	expectStatus(t, bob.do("DELETE", b.path("/notes/"+noteID), nil), http.StatusNoContent, "bob clears the note")
	expectStatus(t, bob.do("DELETE", b.path("/notes/"+noteID), nil), http.StatusNotFound, "clear it twice")
	if len(b.notes(t)) != 0 {
		t.Fatal("the note survived its deletion")
	}
	againID, again := a.note(t, b, "noaddx:again")
	expectStatus(t, a.postNote(againID, b.member.Card, again), http.StatusCreated, "a new request once the old one is gone")
}

func TestRoomNotes_AreAddressedStrictly(t *testing.T) {
	mux := setup(t)
	alice, bob, carol, dave := register(t, mux), register(t, mux), register(t, mux), register(t, mux)
	a := createRoom(t, alice, 4, 24)
	b := joinRoom(t, bob, a.code)
	c := joinRoom(t, carol, a.code)

	forCarol, toCarol := a.note(t, c, "noaddx:x")
	expectStatus(t, a.postNote(forCarol, b.member.Card, toCarol), http.StatusBadRequest, "sealed for carol, sent to bob")
	selfID, toSelf := a.note(t, a, "noaddx:x")
	expectStatus(t, a.postNote(selfID, a.member.Card, toSelf), http.StatusBadRequest, "a note to oneself")
	strangerSide := sideOf(t, dave, a.code)
	strangerID, toStranger := a.note(t, strangerSide, "noaddx:x")
	expectStatus(t, a.postNote(strangerID, strangerSide.member.Card, toStranger), http.StatusNotFound, "a card nobody in the room has")
	msgID := newMessageID()
	expectStatus(t, a.postNote(msgID, b.member.Card, a.sealTo(t, a.roster(t), msgID, "x", 1)), http.StatusBadRequest, "a room message as a note")
	bobID, toBob := a.note(t, b, "noaddx:x")
	expectStatus(t, dave.do("POST", a.path("/notes"), models.SendNoteRequest{ID: bobID, To: b.member.Card, Blob: toBob}), http.StatusNotFound, "a non-member sends")
	expectStatus(t, dave.do("GET", a.path("/notes"), nil), http.StatusNotFound, "a non-member lists")

	// A pending note goes when either side leaves the room
	expectStatus(t, a.postNote(bobID, b.member.Card, toBob), http.StatusCreated, "alice asks bob")
	expectStatus(t, bob.do("DELETE", b.path(""), nil), http.StatusNoContent, "bob leaves")
	var n int64
	database.DB.Model(&models.RoomNote{}).Where("conversation_id = ?", a.room.ID).Count(&n)
	if n != 0 {
		t.Fatalf("%d notes survived their addressee leaving", n)
	}
}
