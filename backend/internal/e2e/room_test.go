package e2e

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"noaddx/internal/cryptoengine"

	"github.com/google/uuid"
)

const roomVectorText = "oda ✓ <b>&"

// accountC completes the room vector trio (bytes 0x20..0x3f), next to accountA and accountB.
var accountC = base64.RawURLEncoding.EncodeToString([]byte(" !\"#$%&'()*+,-./0123456789:;<=>?"))

type roomParty struct {
	root   []byte
	member *RoomMember
}

func roomFixture(t *testing.T, maxMembers int) (*RoomCode, *Room) {
	t.Helper()
	code, err := NewRoomCode(maxMembers, 500000)
	if err != nil {
		t.Fatalf("NewRoomCode: %v", err)
	}
	room, err := DeriveRoom(code.Secret)
	if err != nil {
		t.Fatalf("DeriveRoom: %v", err)
	}
	return code, room
}

func joinAs(t *testing.T, room *Room, account string) roomParty {
	t.Helper()
	root, err := RoomsRoot(account)
	if err != nil {
		t.Fatalf("RoomsRoot: %v", err)
	}
	member, err := room.Member(root)
	if err != nil {
		t.Fatalf("Member: %v", err)
	}
	return roomParty{root: root, member: member}
}

func rosterOf(parties ...roomParty) []string {
	cards := make([]string, len(parties))
	for i, p := range parties {
		cards[i] = p.member.Card
	}
	return cards
}

func sealFor(t *testing.T, room *Room, from roomParty, roster []string, id uuid.UUID, counter int64) string {
	t.Helper()
	recipients, digest, err := room.Recipients(from.member, roster)
	if err != nil {
		t.Fatalf("Recipients: %v", err)
	}
	blob, err := room.SealMessage(from.member, id, recipients, digest, roomVectorText, vectorSentAt, counter)
	if err != nil {
		t.Fatalf("SealMessage: %v", err)
	}
	return blob
}

func flip(t *testing.T, blob string, index int) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(blob)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw[index] ^= 0x01
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestRoomCode_RoundTripAndStrictParsing(t *testing.T) {
	code, _ := roomFixture(t, 8)
	text := code.String()
	if !strings.HasPrefix(text, RoomCodePrefix) || len(text) != len(RoomCodePrefix)+50 {
		t.Fatalf("room code %q has the wrong shape", text)
	}
	parsed, err := ParseRoomCode(text)
	if err != nil {
		t.Fatalf("ParseRoomCode: %v", err)
	}
	if !bytes.Equal(parsed.Secret, code.Secret) || parsed.MaxMembers != 8 || parsed.ExpiresHour != 500000 {
		t.Fatalf("round trip changed the code: %+v", parsed)
	}

	body := text[len(RoomCodePrefix):]
	raw, _ := base64.RawURLEncoding.DecodeString(body)
	withMax := func(max byte) string {
		b := append([]byte(nil), raw...)
		b[RoomSecretSize] = max
		return RoomCodePrefix + base64.RawURLEncoding.EncodeToString(b)
	}
	withHour := func(hour byte) string {
		b := append([]byte(nil), raw...)
		copy(b[RoomSecretSize+1:], []byte{0, 0, 0, hour})
		return RoomCodePrefix + base64.RawURLEncoding.EncodeToString(b)
	}
	for name, bad := range map[string]string{
		"invite prefix":     "noaddx:" + body,
		"no prefix":         body,
		"short":             text[:len(text)-1],
		"long":              text + "A",
		"non-canonical end": text[:len(text)-1] + "B",
		"bad alphabet":      text[:len(text)-1] + "+",
		"one member":        withMax(1),
		"too many members":  withMax(MaxRoomMembers + 1),
		"no expiry":         withHour(0),
	} {
		if _, err := ParseRoomCode(bad); err == nil {
			t.Errorf("%s: ParseRoomCode accepted %q", name, bad)
		}
	}
	if _, err := NewRoomCode(MinRoomMembers-1, 1); err == nil {
		t.Error("NewRoomCode accepted a one-member room")
	}
}

func TestDeriveRoom_UUIDv4AndDomainSeparation(t *testing.T) {
	code, room := roomFixture(t, 4)
	if room.ID.Version() != 4 || room.ID.Variant() != uuid.RFC4122 {
		t.Fatalf("room id %s is not a UUIDv4", room.ID)
	}
	again, err := DeriveRoom(code.Secret)
	if err != nil || again.ID != room.ID || again.Lookup != room.Lookup {
		t.Fatal("room derivation is not deterministic")
	}
	lookup, err := base64.RawURLEncoding.DecodeString(room.Lookup)
	if err != nil || len(lookup) != 32 {
		t.Fatalf("lookup %q is not 32 bytes of base64url", room.Lookup)
	}
	if bytes.Equal(lookup, room.cardKey) || bytes.Equal(lookup, code.Secret) || bytes.Contains(lookup, room.ID[:]) {
		t.Fatal("derived room values are not domain separated")
	}
	if _, err := DeriveRoom(code.Secret[:31]); err == nil {
		t.Fatal("DeriveRoom accepted a short secret")
	}
}

func TestRoomMember_KeyDiffersPerRoomAndAccount(t *testing.T) {
	_, room1 := roomFixture(t, 4)
	_, room2 := roomFixture(t, 4)
	a1, a2, b1 := joinAs(t, room1, accountA), joinAs(t, room2, accountA), joinAs(t, room1, accountB)
	if bytes.Equal(a1.member.Public, a2.member.Public) {
		t.Fatal("an account has the same member key in two rooms")
	}
	if bytes.Equal(a1.member.Public, b1.member.Public) {
		t.Fatal("two accounts share a member key")
	}
	identityKey := load(t, accountA).public
	if base64.RawURLEncoding.EncodeToString(a1.member.Public) == identityKey {
		t.Fatal("the member key is the account's identity key")
	}
	again := joinAs(t, room1, accountA)
	if !bytes.Equal(again.member.Public, a1.member.Public) {
		t.Fatal("the member key is not deterministic")
	}
}

func TestRoomCard_OpensOnlyInItsRoom(t *testing.T) {
	_, room := roomFixture(t, 4)
	_, other := roomFixture(t, 4)
	a := joinAs(t, room, accountA)
	public, err := room.OpenCard(a.member.Card)
	if err != nil || !bytes.Equal(public, a.member.Public) {
		t.Fatalf("OpenCard: %v", err)
	}
	if _, err := other.OpenCard(a.member.Card); err == nil {
		t.Fatal("a card opened in another room")
	}
	for name, bad := range map[string]string{
		"tampered": flip(t, a.member.Card, 30),
		"short":    a.member.Card[:len(a.member.Card)-1],
		"empty":    "",
	} {
		if _, err := room.OpenCard(bad); err == nil {
			t.Errorf("%s card opened", name)
		}
	}
}

func TestRoomVault_OpensOnlyForItsAccountAndRoom(t *testing.T) {
	code, room := roomFixture(t, 6)
	_, other := roomFixture(t, 6)
	a, b := joinAs(t, room, accountA), joinAs(t, room, accountB)
	vault, err := SealVault(a.root, room.ID, code)
	if err != nil {
		t.Fatalf("SealVault: %v", err)
	}
	opened, err := OpenVault(a.root, room.ID, vault)
	if err != nil || !bytes.Equal(opened.Secret, code.Secret) || opened.MaxMembers != 6 || opened.ExpiresHour != code.ExpiresHour {
		t.Fatalf("OpenVault: %v %+v", err, opened)
	}
	if _, err := OpenVault(b.root, room.ID, vault); err == nil {
		t.Fatal("another account opened the vault")
	}
	if _, err := OpenVault(a.root, other.ID, vault); err == nil {
		t.Fatal("the vault opened under another room id")
	}
	// A vault sealed under the wrong room id holds a secret whose room is not that id
	misfiled, err := SealVault(a.root, other.ID, code)
	if err != nil {
		t.Fatalf("SealVault: %v", err)
	}
	if _, err := OpenVault(a.root, other.ID, misfiled); err == nil {
		t.Fatal("OpenVault accepted a secret that derives another room id")
	}
}

func TestRosterDigest_IgnoresOrderButNotMembership(t *testing.T) {
	_, room := roomFixture(t, 4)
	a, b, c := joinAs(t, room, accountA), joinAs(t, room, accountB), joinAs(t, room, accountC)
	d1, err := RosterDigest(rosterOf(a, b, c))
	if err != nil {
		t.Fatalf("RosterDigest: %v", err)
	}
	d2, _ := RosterDigest(rosterOf(c, a, b))
	d3, _ := RosterDigest(rosterOf(a, b))
	if !bytes.Equal(d1, d2) {
		t.Fatal("roster digest depends on order")
	}
	if bytes.Equal(d1, d3) {
		t.Fatal("roster digest ignores a member")
	}
	if _, err := RosterDigest(nil); err == nil {
		t.Fatal("RosterDigest accepted an empty roster")
	}
}

func TestRoomMessage_EveryRecipientOpensItAndSeesTheSender(t *testing.T) {
	_, room := roomFixture(t, 4)
	a, b, c := joinAs(t, room, accountA), joinAs(t, room, accountB), joinAs(t, room, accountC)
	id := uuid.New()
	blob := sealFor(t, room, a, rosterOf(a, b, c), id, 5)
	for name, p := range map[string]roomParty{"sender": a, "b": b, "c": c} {
		msg, err := room.OpenMessage(p.member, id, blob)
		if err != nil {
			t.Fatalf("%s: OpenMessage: %v", name, err)
		}
		if msg.Text != roomVectorText || msg.SentAt != vectorSentAt || msg.Counter != 5 || !bytes.Equal(msg.Sender, a.member.Public) {
			t.Fatalf("%s opened %+v", name, msg)
		}
	}
}

func TestRoomMessage_MembersOutsideTheRosterCannotOpenIt(t *testing.T) {
	_, room := roomFixture(t, 4)
	a, b, c := joinAs(t, room, accountA), joinAs(t, room, accountB), joinAs(t, room, accountC)
	id := uuid.New()
	blob := sealFor(t, room, a, rosterOf(a, b), id, 1)
	if _, err := room.OpenMessage(c.member, id, blob); err == nil {
		t.Fatal("a member who joined after the message was sent opened it")
	}
}

func TestRoomMessage_AMemberCannotImpersonateAnother(t *testing.T) {
	_, room := roomFixture(t, 4)
	a, b, c := joinAs(t, room, accountA), joinAs(t, room, accountB), joinAs(t, room, accountC)
	// C holds the code and A's public card, but not A's member key
	forger := &RoomMember{private: c.member.private, Public: a.member.Public, Card: a.member.Card}
	recipients, digest, err := room.Recipients(c.member, rosterOf(a, b, c))
	if err != nil {
		t.Fatalf("Recipients: %v", err)
	}
	id := uuid.New()
	forged, err := room.SealMessage(forger, id, recipients, digest, "i am a", vectorSentAt, 1)
	if err != nil {
		t.Fatalf("SealMessage: %v", err)
	}
	if _, err := room.OpenMessage(b.member, id, forged); err == nil {
		t.Fatal("B accepted a message forged under A's card")
	}
}

func TestRoomMessage_RejectsEveryBinding(t *testing.T) {
	_, room := roomFixture(t, 4)
	_, other := roomFixture(t, 4)
	a, b := joinAs(t, room, accountA), joinAs(t, room, accountB)
	id := uuid.New()
	blob := sealFor(t, room, a, rosterOf(a, b), id, 1)
	raw, _ := base64.RawURLEncoding.DecodeString(blob)
	bodyStart := roomHeaderSize + 2*roomWrapSize

	cases := map[string]func() (*RoomMessage, error){
		"other message id": func() (*RoomMessage, error) { return room.OpenMessage(b.member, uuid.New(), blob) },
		"other room": func() (*RoomMessage, error) {
			bInOther := joinAs(t, other, accountB)
			return other.OpenMessage(bInOther.member, id, blob)
		},
		"card":          func() (*RoomMessage, error) { return room.OpenMessage(b.member, id, flip(t, blob, 20)) },
		"ephemeral key": func() (*RoomMessage, error) { return room.OpenMessage(b.member, id, flip(t, blob, 70)) },
		"commitment":    func() (*RoomMessage, error) { return room.OpenMessage(b.member, id, flip(t, blob, 100)) },
		"roster digest": func() (*RoomMessage, error) { return room.OpenMessage(b.member, id, flip(t, blob, 140)) },
		// Wraps are shuffled and say nothing about their recipient: break both to break B's
		"every wrap": func() (*RoomMessage, error) {
			return room.OpenMessage(b.member, id, flip(t, flip(t, blob, roomHeaderSize+1), roomHeaderSize+roomWrapSize+1))
		},
		"body":          func() (*RoomMessage, error) { return room.OpenMessage(b.member, id, flip(t, blob, bodyStart+3)) },
		"magic":         func() (*RoomMessage, error) { return room.OpenMessage(b.member, id, flip(t, blob, 0)) },
		"wrap count":    func() (*RoomMessage, error) { return room.OpenMessage(b.member, id, flip(t, blob, roomHeaderSize-1)) },
		"truncated":     func() (*RoomMessage, error) { return room.OpenMessage(b.member, id, blob[:len(blob)-4]) },
		"not canonical": func() (*RoomMessage, error) { return room.OpenMessage(b.member, id, blob+"\n") },
		"note magic":    func() (*RoomMessage, error) { return room.OpenNote(b.member, id, blob) },
		"base64 standard": func() (*RoomMessage, error) {
			return room.OpenMessage(b.member, id, base64.StdEncoding.EncodeToString(raw))
		},
	}
	for name, open := range cases {
		if _, err := open(); err == nil {
			t.Errorf("%s: tampered message opened", name)
		}
	}
}

func TestRoomMessage_WrapOrderDoesNotMatter(t *testing.T) {
	_, room := roomFixture(t, 4)
	a, b, c := joinAs(t, room, accountA), joinAs(t, room, accountB), joinAs(t, room, accountC)
	id := uuid.New()
	raw, _ := base64.RawURLEncoding.DecodeString(sealFor(t, room, a, rosterOf(a, b, c), id, 1))
	first := append([]byte(nil), raw[roomHeaderSize:roomHeaderSize+roomWrapSize]...)
	copy(raw[roomHeaderSize:], raw[roomHeaderSize+2*roomWrapSize:roomHeaderSize+3*roomWrapSize])
	copy(raw[roomHeaderSize+2*roomWrapSize:], first)
	if _, err := room.OpenMessage(b.member, id, base64.RawURLEncoding.EncodeToString(raw)); err != nil {
		t.Fatalf("reordered wraps: %v", err)
	}
}

// A malicious sender commits to one message key and wraps another: every recipient refuses it,
// so nobody can be shown a body that decrypts differently for someone else.
func TestRoomMessage_CommitmentMustMatchTheWrappedKey(t *testing.T) {
	_, room := roomFixture(t, 4)
	a, b := joinAs(t, room, accountA), joinAs(t, room, accountB)
	recipients, digest, err := room.Recipients(a.member, rosterOf(a, b))
	if err != nil {
		t.Fatalf("Recipients: %v", err)
	}
	framed, err := encodePayload(roomVectorText, vectorSentAt, 1)
	if err != nil {
		t.Fatalf("encodePayload: %v", err)
	}
	mk, _ := cryptoengine.RandomBytes(32)
	wrongCommit, _ := cryptoengine.RandomBytes(32)
	id := uuid.New()
	raw, err := room.assemble(a.member, roomMessageMagic, id, recipients, digest, mk, wrongCommit, framed)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if _, err := room.OpenMessage(b.member, id, base64.RawURLEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("a message whose commitment does not match its key opened")
	}
}

func TestRoomMessage_SizeIsHeaderWrapsAndAPaddedClass(t *testing.T) {
	_, room := roomFixture(t, 4)
	a, b, c := joinAs(t, room, accountA), joinAs(t, room, accountB), joinAs(t, room, accountC)
	recipients, digest, _ := room.Recipients(a.member, rosterOf(a, b, c))
	for _, tc := range []struct {
		textLen int
		frame   int
	}{{1, 256}, {300, 512}, {3000, 4096}} {
		blob, err := room.SealMessage(a.member, uuid.New(), recipients, digest, strings.Repeat("x", tc.textLen), vectorSentAt, 1)
		if err != nil {
			t.Fatalf("SealMessage(%d): %v", tc.textLen, err)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(blob)
		if want := roomHeaderSize + 3*roomWrapSize + tc.frame + cryptoengine.GCMTagSize; len(raw) != want {
			t.Fatalf("text of %d bytes: blob is %d bytes, want %d", tc.textLen, len(raw), want)
		}
	}
	if _, err := room.SealMessage(a.member, uuid.New(), recipients, digest, strings.Repeat("x", maxPayloadBytes), vectorSentAt, 1); err == nil {
		t.Fatal("SealMessage accepted a payload larger than the largest frame")
	}
}

func TestRoomRecipients_SkipBrokenCardsButCountThem(t *testing.T) {
	_, room := roomFixture(t, 8)
	a, b := joinAs(t, room, accountA), joinAs(t, room, accountB)
	garbage := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, roomCardSize))
	lowOrder, err := room.sealCard(make([]byte, 32)) // the all-zero point: X25519 with it is refused
	if err != nil {
		t.Fatalf("sealCard: %v", err)
	}
	roster := []string{a.member.Card, b.member.Card, garbage, lowOrder, b.member.Card}
	recipients, digest, err := room.Recipients(a.member, roster)
	if err != nil {
		t.Fatalf("Recipients: %v", err)
	}
	if len(recipients) != 2 {
		t.Fatalf("got %d recipients, want A and B once each", len(recipients))
	}
	want, _ := RosterDigest(roster)
	if !bytes.Equal(digest, want) {
		t.Fatal("the digest does not cover the roster as served")
	}
	if _, _, err := room.Recipients(a.member, []string{b.member.Card}); err == nil {
		t.Fatal("Recipients accepted a roster without the sender")
	}
}

func TestRoomNote_OnlyTheAddresseeOpensIt(t *testing.T) {
	_, room := roomFixture(t, 4)
	a, b, c := joinAs(t, room, accountA), joinAs(t, room, accountB), joinAs(t, room, accountC)
	id := uuid.New()
	note, err := room.SealNote(a.member, id, b.member.Card, "noaddx:invite", vectorSentAt)
	if err != nil {
		t.Fatalf("SealNote: %v", err)
	}
	msg, err := room.OpenNote(b.member, id, note)
	if err != nil || msg.Text != "noaddx:invite" || !bytes.Equal(msg.Sender, a.member.Public) {
		t.Fatalf("OpenNote: %v %+v", err, msg)
	}
	for name, p := range map[string]roomParty{"sender": a, "bystander": c} {
		if _, err := room.OpenNote(p.member, id, note); err == nil {
			t.Errorf("%s opened a note addressed to B", name)
		}
	}
	if _, err := room.OpenMessage(b.member, id, note); err == nil {
		t.Fatal("a note opened as a room message")
	}
}

// Produced by frontend/js/room-crypto.js (A → A, B): Go must open all of it.
const (
	roomVectorCode    = "noaddx#QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8FAAdTAA"
	roomVectorID      = "bcde36b2-87a3-43c6-8748-ee62ca2f2939"
	roomVectorLookup  = "Twh6cxJTOdj3qtOn-Nt1_ADT-RWFAifUus6kjV14vd4"
	roomVectorPublicA = "W8eS0mxpk64t2ikVSK_TjuuAtndUpH1_XgsDi0ObJm8"
	roomVectorPublicB = "Rr1i9oWfcZMTHT3ZWyOfTo8I7bdpM2f2TPQD1r13qks"
	roomVectorMessage = "5f0c2a1e-7b3d-4c8e-9a6f-1d2e3f4a5b6c"
	roomVectorNote    = "8e7d6c5b-4a39-4281-9f0e-0d1c2b3a4958"
	roomInteropText   = "noaddx. room interop ✓ <b>&"
	browserCardA      = "uJ3NyU9nViUzChYyFBB8Yzu4n7M9hlkXxleAREpT0j5ou6v6kYJO7WXHgdleq8w8JpWhGvhgwzAan-6n"
	browserCardB      = "tJ2XEYRYXgzKx2Ya5ylCuLQ2_0yhQ-SgYUY0nNlYYTtXyj8AysfLsC3z-hUufz2Cc1ZbaPRcYrtRfklI"
	browserVaultA     = "8p0yn5IH8Eh21IfmLhAwQLnE5n4vtRh_9lnOelaiwyT6PPiyzAU40SlhfEFXnbZWUsW6crTSplDXIyNbwllpBG4"
	browserDigest     = "EXqEOQ7529OBHGHwqW1TJuzHuGdAHqn2EIZO8X3tQhg"
	browserRoomBlob   = "TkFEUgG4nc3JT2dWJTMKFjIUEHxjO7ifsz2GWRfGV4BESlPSPmi7q_qRgk7tZceB2V6rzDwmlaEa-GDDMBqf7qfMWLmu8HxKmeoLXv10v5OReaRzUUCztkyDelyXXhCDeiSMyjlyZ4da0IKaaV3M-dU1DEMDuUwtkTOUhE8puQ3pEXqEOQ7529OBHGHwqW1TJuzHuGdAHqn2EIZO8X3tQhgCh-pztczNhOUGvyDSHdUyh3jmZZkppMWdDPZ7HGIuQYwvhhXOXbLt670KMOSe9AswFvftRzm11QNZxZGlGTWEWoffTNFV9Fg2VR2WQhBo8zHQ7BJfLanLyYHTsy1kJZMB_bKbtTuTmN-MxzSjtOm60YILE_vfKSARlbaqzooe1YtuuV5hy7K4495WLUazj5hewsxui53zPhDhdQx7EV6IJTasxaMb49P-3vs2h6_uKQvh93kLqResRCgSzwDDKekP0OhPyDd3pvmFP2yeZnST9yz7cLmMgdBqR3uMQSWvoDaxV7j1sRqJn-j57jC6_Dam2OByFtphyrcE74i_vdJb66jG3b2XecbqrPxvuPUFDqtwvqH2xofiLEU5AOZLuOlhgoYEtz3mNa1B-4DaNA1io_bxQG8UCR91OKQiFeb2EBI-pKwc6hR032DRK9O9agJVmD4EvYQ9K5fDqsvbhRxjQGZY9xMJ7LwTqV_MGAym0Fg"
	browserRoomNote   = "TkFETgG4nc3JT2dWJTMKFjIUEHxjO7ifsz2GWRfGV4BESlPSPmi7q_qRgk7tZceB2V6rzDwmlaEa-GDDMBqf7qexIfbPMMfXRnd9UcAHV1zEHv4NzTe-Sm-6kQ9V_LDdPVsQ2UfL5a1_l7ipoizLmaGoFtfeWw4r305XRjeYG8j8JefGFGXZHamruEIKh94qb0oNIoTeFsU0sQrA_WpIGKwBZcPj6dpK0GMFoLyVCZtsgz2KKPSMZEsFBYKR_KczmEx0NaSqCSSRBfvV1ddTTZO1XSQ3w5HwgsYU7PAc6QJj3IJsj7uThpQBP00nmWCMalzT_tUeehwX1y2dPMbNgE-ChWtV-oiC-9nKHcLCm0pbGn260JhyX_p2C339hspaxbWidSKKXHMlMBdtrwj9vdmDPXhhY7hYvBEgy6F8wVzQ9vVbJ7S7KrQgz7h-9RG5Iuv1OZg8lpooOLqLtCG6oxJxwFEjmtl1rc1w1oNN8FoTuXQ7vDyNBttuTu0zn3zcBQOHwrMncJmlsMhAftL_P0451dyXiQgNq8O-dGUTy_AxPT9vG8GxssQsJco-sDKGjIM8Q1q2VddNyg0d3MYx-dYWvDDa-Pxm00UIkFSSNDOYAz8SYXpFckSkRwRf1cnAXiE"
)

func TestRoomInterop_OpensWhatTheBrowserSealed(t *testing.T) {
	code, err := ParseRoomCode(roomVectorCode)
	if err != nil || code.String() != roomVectorCode || code.MaxMembers != 5 || code.ExpiresHour != 480000 {
		t.Fatalf("ParseRoomCode: %v %+v", err, code)
	}
	for i, b := range code.Secret {
		if b != byte(0x40+i) {
			t.Fatal("the vector secret is not 0x40..0x5f")
		}
	}
	room, err := DeriveRoom(code.Secret)
	if err != nil || room.ID.String() != roomVectorID || room.Lookup != roomVectorLookup {
		t.Fatalf("DeriveRoom: %v %s %s", err, room.ID, room.Lookup)
	}
	a, b := joinAs(t, room, accountA), joinAs(t, room, accountB)
	if encode(a.member.Public) != roomVectorPublicA || encode(b.member.Public) != roomVectorPublicB {
		t.Fatal("member keys differ from the browser's")
	}
	for card, want := range map[string]string{browserCardA: roomVectorPublicA, browserCardB: roomVectorPublicB} {
		public, err := room.OpenCard(card)
		if err != nil || encode(public) != want {
			t.Fatalf("OpenCard(browser card): %v", err)
		}
	}
	vault, err := OpenVault(a.root, room.ID, browserVaultA)
	if err != nil || vault.MaxMembers != 5 || vault.ExpiresHour != 480000 {
		t.Fatalf("OpenVault(browser vault): %v", err)
	}
	digest, err := RosterDigest([]string{browserCardA, browserCardB})
	if err != nil || encode(digest) != browserDigest {
		t.Fatalf("RosterDigest differs from the browser's: %v", err)
	}
	for name, reader := range map[string]roomParty{"a": a, "b": b} {
		msg, err := room.OpenMessage(reader.member, uuid.MustParse(roomVectorMessage), browserRoomBlob)
		if err != nil || msg.Text != roomInteropText || msg.SentAt != vectorSentAt || msg.Counter != 4 || encode(msg.Sender) != roomVectorPublicA {
			t.Fatalf("%s: OpenMessage(browser blob): %v %+v", name, err, msg)
		}
	}
	// The note was sealed for B's browser card, whose bytes differ from the card B derives here
	bWithBrowserCard := &RoomMember{private: b.member.private, Public: b.member.Public, Card: browserCardB}
	note, err := room.OpenNote(bWithBrowserCard, uuid.MustParse(roomVectorNote), browserRoomNote)
	if err != nil || note.Text != "noaddx:invite-vector" || encode(note.Sender) != roomVectorPublicA {
		t.Fatalf("OpenNote(browser note): %v", err)
	}
}
