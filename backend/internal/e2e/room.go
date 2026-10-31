package e2e

// Room protocol (docs/architecture/rooms.md), the twin of frontend/js/room-crypto.js:
//
//	code    = "noaddx#" || base64url(S(32) || max members(1) || expiry hour(4, big-endian))
//	room id = UUIDv4 bits over HKDF(S, "noaddx/room/id", 16); lookup = HKDF(S, "noaddx/room/lookup")
//	card    = nonce || AES-GCM(HKDF(S, "noaddx/room/card"), member key, AAD "NADC" 1 room id)
//	member  = X25519 key from HKDF(rooms root, salt = room id, "noaddx/rooms/member/x25519")
//	message = header(162) || wraps(48 each) || body; each recipient unwraps the message key with
//	          X25519(eph, R) || X25519(sender, R), which also authenticates the sender

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"sort"
	"strings"

	"noaddx/internal/cryptoengine"
	"noaddx/internal/utils"

	"github.com/google/uuid"
)

const (
	RoomCodePrefix = "noaddx#"
	RoomSecretSize = 32
	MinRoomMembers = 2
	MaxRoomMembers = 32

	roomCodeBytes  = RoomSecretSize + 1 + 4
	roomCardSize   = cryptoengine.GCMNonceSize + keySize + cryptoengine.GCMTagSize
	roomVaultSize  = cryptoengine.GCMNonceSize + roomCodeBytes + cryptoengine.GCMTagSize
	roomWrapSize   = keySize + cryptoengine.GCMTagSize
	roomHeaderSize = 4 + 1 + roomCardSize + 3*keySize + 1
	roomVersion    = 0x01
	roomIDSize     = 16

	// Header offsets: magic(4) version(1) card(60) ephemeral key(32) commitment(32) digest(32) n(1)
	offsetCard   = 5
	offsetEph    = offsetCard + roomCardSize
	offsetCommit = offsetEph + keySize
	offsetDigest = offsetCommit + keySize

	derivationSalt   = "noaddx.v1"
	infoRoomID       = "noaddx/room/id"
	infoRoomLookup   = "noaddx/room/lookup"
	infoRoomCard     = "noaddx/room/card"
	infoRoomsRoot    = "noaddx/rooms"
	infoRoomsVault   = "noaddx/rooms/vault"
	infoRoomMember   = "noaddx/rooms/member/x25519"
	infoRoomWrap     = "noaddx/room/wrap/v1"
	roomCommitPrefix = "noaddx/room/commit/v1"
	roomRosterPrefix = "noaddx/room/roster/v1"
	// maxShuffleDraws bounds the rejection sampling of one shuffle index (RULES.md §8.1);
	// a draw is rejected with probability < 1/8, so the bound is never reached in practice
	maxShuffleDraws = 64
)

var (
	roomMessageMagic = []byte("NADR")
	roomNoteMagic    = []byte("NADN")
	roomCardMagic    = []byte("NADC")
	roomVaultMagic   = []byte("NADV")
	zeroNonce        = make([]byte, cryptoengine.GCMNonceSize)

	ErrNotInRoster = errors.New("e2e: the sender is not in the roster")
)

func concat(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeExact mirrors crypto.js b64urlDecode for a value of exactly size bytes.
func decodeExact(encoded string, size int) ([]byte, error) {
	if len(encoded) != base64.RawURLEncoding.EncodedLen(size) || !utils.IsBase64URL(encoded) {
		return nil, ErrInvalidInput
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != size {
		return nil, ErrInvalidInput
	}
	return raw, nil
}

func deriveFrom(secret []byte, info string, size int) ([]byte, error) {
	return cryptoengine.HKDFSHA256(secret, []byte(derivationSalt), []byte(info), size)
}

// ---------- the code ----------

// RoomCode is everything a room code carries: the secret and the creator's limits.
type RoomCode struct {
	Secret      []byte
	MaxMembers  int
	ExpiresHour uint32 // deletion time, in hours since the Unix epoch
}

func (c *RoomCode) valid() bool {
	return len(c.Secret) == RoomSecretSize && c.MaxMembers >= MinRoomMembers && c.MaxMembers <= MaxRoomMembers && c.ExpiresHour > 0
}

// NewRoomCode draws a fresh room secret.
func NewRoomCode(maxMembers int, expiresHour uint32) (*RoomCode, error) {
	secret, err := cryptoengine.RandomBytes(RoomSecretSize)
	if err != nil {
		return nil, err
	}
	code := &RoomCode{Secret: secret, MaxMembers: maxMembers, ExpiresHour: expiresHour}
	if !code.valid() {
		return nil, ErrInvalidInput
	}
	return code, nil
}

func (c *RoomCode) bytes() []byte {
	out := make([]byte, 0, roomCodeBytes)
	out = append(out, c.Secret...)
	out = append(out, byte(c.MaxMembers))
	return binary.BigEndian.AppendUint32(out, c.ExpiresHour)
}

// String renders the code a member shares.
func (c *RoomCode) String() string {
	return RoomCodePrefix + encode(c.bytes())
}

func parseRoomCodeBytes(raw []byte) (*RoomCode, error) {
	if len(raw) != roomCodeBytes {
		return nil, ErrInvalidInput
	}
	code := &RoomCode{
		Secret:      append([]byte(nil), raw[:RoomSecretSize]...),
		MaxMembers:  int(raw[RoomSecretSize]),
		ExpiresHour: binary.BigEndian.Uint32(raw[RoomSecretSize+1:]),
	}
	if !code.valid() {
		return nil, ErrInvalidInput
	}
	return code, nil
}

// ParseRoomCode accepts exactly the canonical form String produces.
func ParseRoomCode(code string) (*RoomCode, error) {
	if !strings.HasPrefix(code, RoomCodePrefix) {
		return nil, ErrInvalidInput
	}
	raw, err := decodeExact(code[len(RoomCodePrefix):], roomCodeBytes)
	if err != nil {
		return nil, err
	}
	return parseRoomCodeBytes(raw)
}

// ---------- the room ----------

// Room holds what every code holder derives from the secret.
type Room struct {
	ID      uuid.UUID
	Lookup  string // base64url; the only derived value the server is shown
	cardKey []byte
}

// DeriveRoom computes the room id, the lookup and the card key from the room secret.
func DeriveRoom(secret []byte) (*Room, error) {
	if len(secret) != RoomSecretSize {
		return nil, ErrInvalidInput
	}
	idBytes, err := deriveFrom(secret, infoRoomID, roomIDSize)
	if err != nil {
		return nil, err
	}
	idBytes[6] = idBytes[6]&0x0f | 0x40 // version 4
	idBytes[8] = idBytes[8]&0x3f | 0x80 // RFC 4122 variant
	var id uuid.UUID
	copy(id[:], idBytes)
	lookup, err := deriveFrom(secret, infoRoomLookup, keySize)
	if err != nil {
		return nil, err
	}
	cardKey, err := deriveFrom(secret, infoRoomCard, keySize)
	if err != nil {
		return nil, err
	}
	return &Room{ID: id, Lookup: encode(lookup), cardKey: cardKey}, nil
}

// RoomsRoot is the per-account root of every room key (the browser keeps it non-extractable).
func RoomsRoot(accountNumber string) ([]byte, error) {
	raw, err := decodeKey(accountNumber)
	if err != nil {
		return nil, err
	}
	defer zero(raw)
	return deriveFrom(raw, infoRoomsRoot, keySize)
}

// RoomMember is one account's key in one room, and the card that announces it.
type RoomMember struct {
	private []byte
	Public  []byte
	Card    string
}

// Member derives the caller's key in this room; it differs in every room.
func (r *Room) Member(root []byte) (*RoomMember, error) {
	if len(root) != keySize {
		return nil, ErrInvalidInput
	}
	private, err := cryptoengine.HKDFSHA256(root, r.ID[:], []byte(infoRoomMember), keySize)
	if err != nil {
		return nil, err
	}
	public, err := cryptoengine.X25519PublicKey(private)
	if err != nil {
		return nil, err
	}
	card, err := r.sealCard(public)
	if err != nil {
		return nil, err
	}
	return &RoomMember{private: private, Public: public, Card: card}, nil
}

func (r *Room) cardAAD() []byte {
	return concat(roomCardMagic, []byte{roomVersion}, r.ID[:])
}

func (r *Room) sealCard(public []byte) (string, error) {
	if len(public) != keySize {
		return "", ErrInvalidInput
	}
	sealed, err := cryptoengine.EncryptAES256GCM(r.cardKey, public, r.cardAAD())
	if err != nil {
		return "", err
	}
	return encode(sealed), nil
}

func (r *Room) openCardRaw(raw []byte) ([]byte, error) {
	public, err := cryptoengine.DecryptAES256GCM(r.cardKey, raw, r.cardAAD())
	if err != nil || len(public) != keySize {
		return nil, ErrBadMessage
	}
	return public, nil
}

// OpenCard returns the member key a card announces; only a code holder can make a card.
func (r *Room) OpenCard(card string) ([]byte, error) {
	raw, err := decodeExact(card, roomCardSize)
	if err != nil {
		return nil, ErrBadMessage
	}
	return r.openCardRaw(raw)
}

// ---------- the vault ----------

func vaultAAD(roomID uuid.UUID) []byte {
	return concat(roomVaultMagic, []byte{roomVersion}, roomID[:])
}

func vaultKey(root []byte) ([]byte, error) {
	if len(root) != keySize {
		return nil, ErrInvalidInput
	}
	return deriveFrom(root, infoRoomsVault, keySize)
}

// SealVault seals the room code for the account that owns root, bound to the room id.
func SealVault(root []byte, roomID uuid.UUID, code *RoomCode) (string, error) {
	if !code.valid() || roomID == uuid.Nil {
		return "", ErrInvalidInput
	}
	key, err := vaultKey(root)
	if err != nil {
		return "", err
	}
	defer zero(key)
	sealed, err := cryptoengine.EncryptAES256GCM(key, code.bytes(), vaultAAD(roomID))
	if err != nil {
		return "", err
	}
	return encode(sealed), nil
}

// OpenVault recovers the room code and checks that its secret derives roomID.
func OpenVault(root []byte, roomID uuid.UUID, vault string) (*RoomCode, error) {
	raw, err := decodeExact(vault, roomVaultSize)
	if err != nil {
		return nil, ErrBadMessage
	}
	key, err := vaultKey(root)
	if err != nil {
		return nil, err
	}
	defer zero(key)
	plain, err := cryptoengine.DecryptAES256GCM(key, raw, vaultAAD(roomID))
	if err != nil {
		return nil, ErrBadMessage
	}
	defer zero(plain)
	code, err := parseRoomCodeBytes(plain)
	if err != nil {
		return nil, ErrBadMessage
	}
	room, err := DeriveRoom(code.Secret)
	if err != nil || room.ID != roomID {
		return nil, ErrBadMessage
	}
	return code, nil
}

// ---------- the roster ----------

// RosterDigest commits to a roster as served: the cards, sorted by their bytes.
func RosterDigest(cards []string) ([]byte, error) {
	if len(cards) == 0 || len(cards) > MaxRoomMembers {
		return nil, ErrInvalidInput
	}
	raws := make([][]byte, len(cards))
	for i, card := range cards {
		raw, err := decodeExact(card, roomCardSize)
		if err != nil {
			return nil, err
		}
		raws[i] = raw
	}
	sort.Slice(raws, func(i, j int) bool { return bytes.Compare(raws[i], raws[j]) < 0 })
	return cryptoengine.SHA256(concat(append([][]byte{[]byte(roomRosterPrefix)}, raws...)...))
}

// Recipients returns the member keys a message to this roster is wrapped for, and the
// roster digest. A card that does not open, or carries a key X25519 refuses, gets no wrap
// but still counts in the digest, so it cannot stop the room from working.
func (r *Room) Recipients(me *RoomMember, roster []string) ([][]byte, []byte, error) {
	digest, err := RosterDigest(roster)
	if err != nil {
		return nil, nil, err
	}
	recipients := make([][]byte, 0, len(roster))
	seen := make(map[string]struct{}, len(roster))
	self := false
	for _, card := range roster {
		public, err := r.OpenCard(card)
		if err != nil {
			continue
		}
		if _, dup := seen[string(public)]; dup {
			continue
		}
		shared, err := cryptoengine.X25519SharedSecret(me.private, public)
		if err != nil {
			continue
		}
		zero(shared)
		seen[string(public)] = struct{}{}
		recipients = append(recipients, public)
		self = self || bytes.Equal(public, me.Public)
	}
	if !self {
		return nil, nil, ErrNotInRoster
	}
	return recipients, digest, nil
}

// ---------- messages and notes ----------

// RoomMessage is a decrypted room message or note.
type RoomMessage struct {
	Message
	Sender []byte // the sender's member key in this room
	Digest []byte // the roster digest the sender encrypted for
}

func commitment(mk []byte) ([]byte, error) {
	return cryptoengine.SHA256(concat([]byte(roomCommitPrefix), mk))
}

func (r *Room) bodyAAD(id uuid.UUID, header []byte) []byte {
	return concat(r.ID[:], id[:], header)
}

func (r *Room) wrapAAD(id uuid.UUID, header, body []byte) ([]byte, error) {
	return cryptoengine.SHA256(concat(r.ID[:], id[:], header, body))
}

// wrapKey derives one recipient's key-encryption key from dh1 || dh2 (sender: X25519(e, R),
// X25519(a, R); recipient: X25519(r, E), X25519(r, A)), bound to everyone involved.
func (r *Room) wrapKey(id uuid.UUID, dh1, dh2, ephPublic, senderPublic, recipientPublic []byte) ([]byte, error) {
	ikm := concat(dh1, dh2)
	defer zero(ikm)
	info := concat([]byte(infoRoomWrap), r.ID[:], ephPublic, senderPublic, recipientPublic)
	return cryptoengine.HKDFSHA256(ikm, id[:], info, keySize)
}

// randomIndex draws uniformly from [0, n) for n <= 256, by rejection sampling.
func randomIndex(n int) (int, error) {
	limit := 256 - 256%n
	for draw := 0; draw < maxShuffleDraws; draw++ {
		b, err := cryptoengine.RandomBytes(1)
		if err != nil {
			return 0, err
		}
		if int(b[0]) < limit {
			return int(b[0]) % n, nil
		}
	}
	return 0, errors.New("e2e: shuffle draw bound reached")
}

// wrapFor computes one recipient's wrap of mk, as the sender.
func (r *Room) wrapFor(id uuid.UUID, me *RoomMember, eph, ephPublic, recipient, mk, wrapAAD []byte) ([]byte, error) {
	dh1, err := cryptoengine.X25519SharedSecret(eph, recipient)
	if err != nil {
		return nil, err
	}
	defer zero(dh1)
	dh2, err := cryptoengine.X25519SharedSecret(me.private, recipient)
	if err != nil {
		return nil, err
	}
	defer zero(dh2)
	kek, err := r.wrapKey(id, dh1, dh2, ephPublic, me.Public, recipient)
	if err != nil {
		return nil, err
	}
	defer zero(kek)
	return cryptoengine.SealAES256GCM(kek, zeroNonce, mk, wrapAAD)
}

// assemble builds header || shuffled wraps || body. Every AES-GCM key in it seals exactly one
// plaintext (mk is fresh, each KEK mixes a fresh ephemeral key and the message id), hence the
// zero nonces.
func (r *Room) assemble(me *RoomMember, magic []byte, id uuid.UUID, recipients [][]byte, digest, mk, commit, framed []byte) ([]byte, error) {
	if id.Version() != 4 || len(recipients) == 0 || len(recipients) > MaxRoomMembers ||
		len(digest) != keySize || len(mk) != keySize || len(commit) != keySize {
		return nil, ErrInvalidInput
	}
	card, err := decodeExact(me.Card, roomCardSize)
	if err != nil {
		return nil, err
	}
	eph, err := cryptoengine.RandomBytes(keySize)
	if err != nil {
		return nil, err
	}
	defer zero(eph)
	ephPublic, err := cryptoengine.X25519PublicKey(eph)
	if err != nil {
		return nil, err
	}
	header := concat(magic, []byte{roomVersion}, card, ephPublic, commit, digest, []byte{byte(len(recipients))})
	body, err := cryptoengine.SealAES256GCM(mk, zeroNonce, framed, r.bodyAAD(id, header))
	if err != nil {
		return nil, err
	}
	wrapAAD, err := r.wrapAAD(id, header, body)
	if err != nil {
		return nil, err
	}
	wraps := make([][]byte, len(recipients))
	for i, recipient := range recipients {
		if len(recipient) != keySize {
			return nil, ErrInvalidInput
		}
		if wraps[i], err = r.wrapFor(id, me, eph, ephPublic, recipient, mk, wrapAAD); err != nil {
			return nil, err
		}
	}
	// No wrap says whom it is for, and the order does not either
	for i := len(wraps) - 1; i > 0; i-- {
		j, err := randomIndex(i + 1)
		if err != nil {
			return nil, err
		}
		wraps[i], wraps[j] = wraps[j], wraps[i]
	}
	return concat(append(append([][]byte{header}, wraps...), body)...), nil
}

func (r *Room) seal(me *RoomMember, magic []byte, id uuid.UUID, recipients [][]byte, digest, framed []byte) (string, error) {
	mk, err := cryptoengine.RandomBytes(keySize)
	if err != nil {
		return "", err
	}
	defer zero(mk)
	commit, err := commitment(mk)
	if err != nil {
		return "", err
	}
	raw, err := r.assemble(me, magic, id, recipients, digest, mk, commit, framed)
	if err != nil {
		return "", err
	}
	return encode(raw), nil
}

// SealMessage encrypts one room message for recipients (from Recipients, which includes the sender).
func (r *Room) SealMessage(me *RoomMember, messageID uuid.UUID, recipients [][]byte, digest []byte, text string, sentAt, counter int64) (string, error) {
	framed, err := encodePayload(text, sentAt, counter)
	if err != nil {
		return "", err
	}
	return r.seal(me, roomMessageMagic, messageID, recipients, digest, framed)
}

// SealNote encrypts a note for the one member whose card is `to`.
func (r *Room) SealNote(me *RoomMember, noteID uuid.UUID, to, text string, sentAt int64) (string, error) {
	recipient, err := r.OpenCard(to)
	if err != nil {
		return "", ErrInvalidInput
	}
	digest, err := RosterDigest([]string{to})
	if err != nil {
		return "", err
	}
	framed, err := encodePayload(text, sentAt, 1)
	if err != nil {
		return "", err
	}
	return r.seal(me, roomNoteMagic, noteID, [][]byte{recipient}, digest, framed)
}

// splitRoomBlob checks the structure: magic, version, 1..32 wraps (exactly one in a note) and
// a body that is one of the five padded frame sizes.
func splitRoomBlob(raw, magic []byte) ([]byte, [][]byte, []byte, error) {
	if len(raw) < roomHeaderSize || !bytes.Equal(raw[:len(magic)], magic) || raw[len(magic)] != roomVersion {
		return nil, nil, nil, ErrBadMessage
	}
	n := int(raw[roomHeaderSize-1])
	if n < 1 || n > MaxRoomMembers || (bytes.Equal(magic, roomNoteMagic) && n != 1) {
		return nil, nil, nil, ErrBadMessage
	}
	bodyStart := roomHeaderSize + n*roomWrapSize
	frameLen := len(raw) - bodyStart - cryptoengine.GCMTagSize
	if frameLen < padBlock || frameLen > maxFrameBytes || frameLen&(frameLen-1) != 0 {
		return nil, nil, nil, ErrBadMessage
	}
	wraps := make([][]byte, n)
	for i := range wraps {
		wraps[i] = raw[roomHeaderSize+i*roomWrapSize : roomHeaderSize+(i+1)*roomWrapSize]
	}
	return raw[:roomHeaderSize], wraps, raw[bodyStart:], nil
}

func (r *Room) open(me *RoomMember, magic []byte, id uuid.UUID, blob string) (*RoomMessage, error) {
	if id.Version() != 4 || !utils.IsBase64URL(blob) {
		return nil, ErrBadMessage
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(blob)
	if err != nil {
		return nil, ErrBadMessage
	}
	header, wraps, body, err := splitRoomBlob(raw, magic)
	if err != nil {
		return nil, err
	}
	sender, err := r.openCardRaw(header[offsetCard:offsetEph])
	if err != nil {
		return nil, err
	}
	ephPublic := header[offsetEph:offsetCommit]
	dh1, err := cryptoengine.X25519SharedSecret(me.private, ephPublic)
	if err != nil {
		return nil, ErrBadMessage
	}
	defer zero(dh1)
	dh2, err := cryptoengine.X25519SharedSecret(me.private, sender)
	if err != nil {
		return nil, ErrBadMessage
	}
	defer zero(dh2)
	kek, err := r.wrapKey(id, dh1, dh2, ephPublic, sender, me.Public)
	if err != nil {
		return nil, err
	}
	defer zero(kek)
	wrapAAD, err := r.wrapAAD(id, header, body)
	if err != nil {
		return nil, err
	}
	var mk []byte
	for _, wrap := range wraps {
		if key, err := cryptoengine.DecryptAES256GCM(kek, concat(zeroNonce, wrap), wrapAAD); err == nil {
			mk = key
			break
		}
	}
	if len(mk) != keySize {
		return nil, ErrBadMessage
	}
	defer zero(mk)
	commit, err := commitment(mk)
	if err != nil || !cryptoengine.ConstantTimeEqual(commit, header[offsetCommit:offsetDigest]) {
		return nil, ErrBadMessage
	}
	framed, err := cryptoengine.DecryptAES256GCM(mk, concat(zeroNonce, body), r.bodyAAD(id, header))
	if err != nil {
		return nil, ErrBadMessage
	}
	msg, err := decodePayload(framed)
	if err != nil {
		return nil, ErrBadMessage
	}
	digest := append([]byte(nil), header[offsetDigest:roomHeaderSize-1]...)
	return &RoomMessage{Message: *msg, Sender: sender, Digest: digest}, nil
}

// OpenMessage verifies and decrypts a room message addressed (among others) to me.
func (r *Room) OpenMessage(me *RoomMember, messageID uuid.UUID, blob string) (*RoomMessage, error) {
	return r.open(me, roomMessageMagic, messageID, blob)
}

// OpenNote verifies and decrypts a note, and checks it was addressed to me alone.
func (r *Room) OpenNote(me *RoomMember, noteID uuid.UUID, blob string) (*RoomMessage, error) {
	msg, err := r.open(me, roomNoteMagic, noteID, blob)
	if err != nil {
		return nil, err
	}
	want, err := RosterDigest([]string{me.Card})
	if err != nil || !cryptoengine.ConstantTimeEqual(want, msg.Digest) {
		return nil, ErrBadMessage
	}
	return msg, nil
}
