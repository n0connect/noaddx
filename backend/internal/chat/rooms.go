package chat

// Rooms (docs/architecture/rooms.md): code-based group conversations. Every value the server
// receives is derived from a room secret it never sees, so it can enforce the member limit,
// the lifetime and the order of messages, and cannot join, read or forge anything.

import (
	"bytes"
	"errors"
	"sort"
	"time"

	"noaddx/internal/config"
	"noaddx/internal/cryptoengine"
	"noaddx/internal/encryption"
	"noaddx/internal/identity"
	"noaddx/internal/models"
	"noaddx/internal/store"
	"noaddx/internal/utils"

	"github.com/google/uuid"
)

var (
	ErrRoomFull = errors.New("room full")
	ErrStale    = errors.New("roster changed")
)

const (
	roomRosterPrefix = "noaddx/room/roster/v1"
	// expirySkew tolerates a client clock this far off when it proposes a room's expiry
	expirySkew = 10 * time.Minute
)

// RoomInput is a create or join request whose fields passed ParseRoomInput.
type RoomInput struct {
	ID         uuid.UUID
	Lookup     []byte
	Card       string
	Vault      string
	MaxMembers int       // create only
	ExpiresAt  time.Time // create only
}

// ParseRoomInput whitelists the client-derived room fields by type, exact length and alphabet.
func ParseRoomInput(id, lookup, card, vault string) (*RoomInput, error) {
	roomID, okID := utils.ParseCanonicalUUIDv4(id)
	rawLookup, okLookup := utils.DecodeExact(lookup, utils.RoomLookupBytes)
	_, okCard := utils.DecodeExact(card, utils.RoomCardBytes)
	_, okVault := utils.DecodeExact(vault, utils.RoomVaultBytes)
	if !okID || !okLookup || !okCard || !okVault {
		return nil, ErrInvalidInput
	}
	return &RoomInput{ID: roomID, Lookup: rawLookup, Card: card, Vault: vault}, nil
}

// checkLimits validates what only a creator sends: the member limit and an hour-aligned expiry
// one hour to ROOM_MAX_TTL_HOURS (+1, the rounding) ahead.
func checkLimits(in *RoomInput, now time.Time) error {
	if in.MaxMembers < config.MinRoomMembers || in.MaxMembers > config.GetRoomMaxMembers() || in.ExpiresAt.Unix()%3600 != 0 {
		return ErrInvalidInput
	}
	earliest := now.Add(time.Hour - expirySkew)
	latest := now.Add(time.Duration(config.GetRoomMaxTTLHours()+1)*time.Hour + expirySkew)
	if in.ExpiresAt.Before(earliest) || in.ExpiresAt.After(latest) {
		return ErrInvalidInput
	}
	return nil
}

func roomAlive(room *models.Room, now time.Time) bool {
	return now.Before(room.ExpiresAt)
}

// liveRoom returns the room behind id, nil for a one-to-one conversation, and ErrNotFound for
// a room past its expiry: an expired room stops answering at once, before it is purged.
func (s *Service) liveRoom(repo store.ChatRepository, id uuid.UUID) (*models.Room, error) {
	room, err := repo.FindRoom(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !roomAlive(room, time.Now()) {
		return nil, ErrNotFound
	}
	return room, nil
}

func (s *Service) requireRoom(repo store.ChatRepository, id uuid.UUID) (*models.Room, error) {
	room, err := s.liveRoom(repo, id)
	if err == nil && room == nil {
		return nil, ErrNotFound
	}
	return room, err
}

// lockSelf row-locks the caller's account (the first lock in every room transaction).
func lockSelf(tx store.ChatRepository, me *Member) (*Member, *models.User, error) {
	rows, err := tx.LockUsers([]string{me.UserUUID})
	if err != nil {
		return nil, nil, err
	}
	row := rows[me.UserUUID]
	if row == nil {
		return nil, nil, ErrNotFound
	}
	self, err := memberFromUser(row)
	if err != nil {
		return nil, nil, err
	}
	return self, row, nil
}

func roomMembership(owner *Member, in *RoomInput, joinedSeq int64) (models.ConversationMember, error) {
	tag, err := owner.tag(in.ID)
	if err != nil {
		return models.ConversationMember{}, err
	}
	refEnc, err := encryption.EncryptWithAAD(owner.UserUUID, encryption.ActiveMasterKey(), memberRefAAD(tag, in.ID))
	if err != nil {
		return models.ConversationMember{}, err
	}
	return models.ConversationMember{
		ConversationID: in.ID,
		MemberTag:      tag,
		MemberRefEnc:   refEnc,
		MasterKeyID:    encryption.ActiveMasterKeyID(),
		Card:           in.Card,
		Vault:          in.Vault,
		JoinedSeq:      joinedSeq,
	}, nil
}

func roomDTO(room *models.Room, member *models.ConversationMember, members, notes int, lastSeq int64) models.ConversationDTO {
	return models.ConversationDTO{
		ID:      room.ID.String(),
		LastSeq: lastSeq,
		ReadSeq: member.ReadSeq,
		Room: &models.RoomDTO{
			Vault:      member.Vault,
			MaxMembers: room.MaxMembers,
			ExpiresAt:  room.ExpiresAt.Unix(),
			Owner:      member.MemberTag == room.OwnerTag,
			Members:    members,
			Notes:      notes,
		},
	}
}

// rosterDigest is SHA-256("noaddx/room/roster/v1" || cards sorted by their bytes), exactly as
// clients compute it over the roster they were served.
func rosterDigest(cards []string) ([]byte, error) {
	raws := make([][]byte, 0, len(cards)+1)
	raws = append(raws, []byte(roomRosterPrefix))
	for _, card := range cards {
		raw, ok := utils.DecodeExact(card, utils.RoomCardBytes)
		if !ok {
			return nil, errCorrupt
		}
		raws = append(raws, raw)
	}
	sort.Slice(raws[1:], func(i, j int) bool { return bytes.Compare(raws[1+i], raws[1+j]) < 0 })
	return cryptoengine.SHA256(bytes.Join(raws, nil))
}

func cardsOf(members []models.ConversationMember) []string {
	cards := make([]string, len(members))
	for i := range members {
		cards[i] = members[i].Card
	}
	return cards
}

// CreateRoom stores a room whose id, lookup, card and vault the creator derived from its code.
func (s *Service) CreateRoom(me *Member, in *RoomInput) (*models.ConversationDTO, error) {
	if err := checkLimits(in, time.Now()); err != nil {
		return nil, err
	}
	lookup, err := identity.RoomLookup(in.Lookup)
	if err != nil {
		return nil, err
	}
	var dto models.ConversationDTO
	err = s.chats.Transaction(func(tx store.ChatRepository) error {
		self, row, err := lockSelf(tx, me)
		if err != nil {
			return err
		}
		index, err := openIndex(self, row.ConvIndexEnc)
		if err != nil {
			return err
		}
		if len(index) >= config.GetMaxConversationsPerUser() {
			return ErrLimitReached
		}
		member, err := roomMembership(self, in, 0)
		if err != nil {
			return err
		}
		room := models.Room{ID: in.ID, Lookup: lookup, MaxMembers: in.MaxMembers, ExpiresAt: in.ExpiresAt.UTC(), OwnerTag: member.MemberTag}
		if err := tx.CreateRoom(&room, &member); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return ErrConflict
			}
			return err
		}
		if err := s.saveIndex(tx, self, append([]uuid.UUID{in.ID}, index...)); err != nil {
			return err
		}
		dto = roomDTO(&room, &member, 1, 0, 0)
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.logger.Debug("CreateRoom: room created")
	return &dto, nil
}

// JoinRoom adds the caller to a room whose code they hold. Joining a room the caller is
// already in only refreshes their vault. Returns the caller's view, whether a seat was taken,
// and the other members' live-event addresses. Lock order: users, rooms, conversations.
func (s *Service) JoinRoom(me *Member, in *RoomInput) (*models.ConversationDTO, bool, []string, error) {
	lookup, err := identity.RoomLookup(in.Lookup)
	if err != nil {
		return nil, false, nil, err
	}
	var (
		dto     models.ConversationDTO
		created bool
		streams []string
	)
	err = s.chats.Transaction(func(tx store.ChatRepository) error {
		self, row, err := lockSelf(tx, me)
		if err != nil {
			return err
		}
		room, err := tx.LockRoom(in.ID)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		// A wrong code and a missing room answer alike
		if !roomAlive(room, time.Now()) || !cryptoengine.ConstantTimeEqual([]byte(lookup), []byte(room.Lookup)) {
			return ErrNotFound
		}
		lastSeq, err := tx.LockConversation(in.ID)
		if err != nil {
			return err
		}
		members, err := tx.ListMembers(in.ID)
		if err != nil {
			return err
		}
		tag, err := self.tag(in.ID)
		if err != nil {
			return err
		}
		for i := range members {
			if members[i].MemberTag == tag {
				if err := tx.UpdateVault(in.ID, tag, in.Vault); err != nil {
					return err
				}
				members[i].Vault = in.Vault
				dto = roomDTO(room, &members[i], len(members), 0, lastSeq)
				return nil
			}
		}
		if len(members) >= room.MaxMembers {
			return ErrRoomFull
		}
		for i := range members {
			if members[i].Card == in.Card {
				return ErrInvalidInput // a copy of someone's card announces nobody new
			}
		}
		index, err := openIndex(self, row.ConvIndexEnc)
		if err != nil {
			return err
		}
		if len(index) >= config.GetMaxConversationsPerUser() {
			return ErrLimitReached
		}
		member, err := roomMembership(self, in, lastSeq)
		if err != nil {
			return err
		}
		if err := tx.AddMember(&member); err != nil {
			return err
		}
		if err := s.saveIndex(tx, self, append([]uuid.UUID{in.ID}, index...)); err != nil {
			return err
		}
		for i := range members {
			userUUID, err := openMemberRef(&members[i])
			if err != nil {
				return err
			}
			stream, err := identity.StreamTag(userUUID)
			if err != nil {
				return err
			}
			streams = append(streams, stream)
		}
		created = true
		dto = roomDTO(room, &member, len(members)+1, 0, lastSeq)
		return nil
	})
	if err != nil {
		return nil, false, nil, err
	}
	s.logger.Debug("JoinRoom: joined=%v", created)
	return &dto, created, streams, nil
}

// RoomMembers returns the roster as cards, sorted so the order says nothing about who came first.
func (s *Service) RoomMembers(me *Member, id uuid.UUID) ([]models.RoomMemberDTO, error) {
	room, err := s.requireRoom(s.chats, id)
	if err != nil {
		return nil, err
	}
	mine, err := s.requireMembership(s.chats, me, id)
	if err != nil {
		return nil, err
	}
	members, err := s.chats.ListMembers(id)
	if err != nil {
		return nil, err
	}
	result := make([]models.RoomMemberDTO, len(members))
	for i, m := range members {
		result[i] = models.RoomMemberDTO{Card: m.Card, Mine: m.MemberTag == mine.MemberTag, Owner: m.MemberTag == room.OwnerTag}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Card < result[j].Card })
	return result, nil
}

// leaveRoom removes the caller from a room they do not own; their messages stay readable to
// the others. Lock order: users, then the conversation row (which serialises it with sends).
func (s *Service) leaveRoom(me *Member, id uuid.UUID) ([]string, error) {
	var streams []string
	err := s.chats.Transaction(func(tx store.ChatRepository) error {
		self, row, err := lockSelf(tx, me)
		if err != nil {
			return err
		}
		if _, err := tx.LockConversation(id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrNotFound
			}
			return err
		}
		member, err := s.requireMembership(tx, self, id)
		if err != nil {
			return err
		}
		_, peers, err := s.peerStreams(tx, self, id)
		if err != nil {
			return err
		}
		if err := tx.DeleteMember(id, member.MemberTag); err != nil {
			return err
		}
		index, err := openIndex(self, row.ConvIndexEnc)
		if err != nil {
			return err
		}
		if err := s.saveIndex(tx, self, withoutID(index, map[uuid.UUID]struct{}{id: {}})); err != nil {
			return err
		}
		streams = peers
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.logger.Debug("leaveRoom: member left")
	return streams, nil
}

// checkRoomMessage refuses a message wrapped for more members than the room has, or for a
// roster other than the current one (the sender then fetches it again and re-encrypts).
// Runs under the conversation row lock taken by NextSeq.
func checkRoomMessage(tx store.ChatRepository, id uuid.UUID, blob *utils.RoomBlob) error {
	members, err := tx.ListMembers(id)
	if err != nil {
		return err
	}
	if blob.Wraps > len(members) {
		return ErrInvalidInput
	}
	digest, err := rosterDigest(cardsOf(members))
	if err != nil {
		return err
	}
	if !cryptoengine.ConstantTimeEqual(digest, blob.Digest) {
		return ErrStale
	}
	return nil
}

// ---------- notes ----------

// SendNote delivers a sealed note (a friend request) to the one member whose card is `to`.
// At most one note waits per sender and addressee, so a member never has more waiting than
// the room has other members. Returns the addressee's live-event address.
func (s *Service) SendNote(me *Member, id uuid.UUID, rawNoteID, to, blob string) (string, error) {
	noteID, okID := utils.ParseCanonicalUUIDv4(rawNoteID)
	_, okTo := utils.DecodeExact(to, utils.RoomCardBytes)
	parsed, okBlob := utils.ParseRoomBlob(blob, utils.RoomNoteMagic, 1)
	if !okID || !okTo || !okBlob {
		return "", ErrInvalidInput
	}
	// A note's digest covers exactly its addressee's card
	digest, err := rosterDigest([]string{to})
	if err != nil {
		return "", err
	}
	if !cryptoengine.ConstantTimeEqual(digest, parsed.Digest) {
		return "", ErrInvalidInput
	}
	room, err := s.requireRoom(s.chats, id)
	if err != nil {
		return "", err
	}
	var stream string
	err = s.chats.Transaction(func(tx store.ChatRepository) error {
		if _, err := tx.LockConversation(id); err != nil {
			return err
		}
		sender, err := s.requireMembership(tx, me, id)
		if err != nil {
			return err
		}
		members, err := tx.ListMembers(id)
		if err != nil {
			return err
		}
		var recipient *models.ConversationMember
		for i := range members {
			if members[i].Card == to {
				recipient = &members[i]
			}
		}
		if recipient == nil {
			return ErrNotFound
		}
		if recipient.MemberTag == sender.MemberTag {
			return ErrInvalidInput
		}
		expiresAt := time.Now().UTC().Add(config.GetInviteTTL())
		if room.ExpiresAt.Before(expiresAt) {
			expiresAt = room.ExpiresAt
		}
		note := models.RoomNote{ID: noteID, ConversationID: id, SenderTag: sender.MemberTag, RecipientTag: recipient.MemberTag, Blob: blob, ExpiresAt: expiresAt}
		if err := tx.CreateNote(&note); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return ErrConflict
			}
			return err
		}
		userUUID, err := openMemberRef(recipient)
		if err != nil {
			return err
		}
		stream, err = identity.StreamTag(userUUID)
		return err
	})
	if err != nil {
		return "", err
	}
	s.logger.Debug("SendNote: note delivered")
	return stream, nil
}

// ListNotes returns the live notes addressed to the caller in one room.
func (s *Service) ListNotes(me *Member, id uuid.UUID) ([]models.NoteDTO, error) {
	if _, err := s.requireRoom(s.chats, id); err != nil {
		return nil, err
	}
	member, err := s.requireMembership(s.chats, me, id)
	if err != nil {
		return nil, err
	}
	notes, err := s.chats.ListNotes(id, member.MemberTag, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	result := make([]models.NoteDTO, len(notes))
	for i, n := range notes {
		result[i] = models.NoteDTO{ID: n.ID.String(), Blob: n.Blob}
	}
	return result, nil
}

// DeleteNote removes a note addressed to the caller (accepted or ignored).
func (s *Service) DeleteNote(me *Member, id, noteID uuid.UUID) error {
	if _, err := s.requireRoom(s.chats, id); err != nil {
		return err
	}
	member, err := s.requireMembership(s.chats, me, id)
	if err != nil {
		return err
	}
	if err := s.chats.DeleteNote(id, noteID, member.MemberTag); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	return nil
}
