// Package chat implements pairing and the message relay. The server only ever handles
// opaque E2E ciphertext, and storage alone does not reveal who talks to whom:
//   - a member appears under a different HMAC pseudonym in every conversation,
//   - who that member is lives only in master-key-encrypted references,
//   - a user's conversation list is a padded blob encrypted with their own server key,
//   - sequence numbers are per conversation, and ciphertext is deleted after MESSAGE_TTL_DAYS.
package chat

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
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

const (
	// The conversation index is padded to this block so its size only reveals a coarse bucket
	indexPadBlock = 1024
	day           = 24 * time.Hour
)

var (
	ErrNotFound      = errors.New("not found")
	ErrInvalidInput  = errors.New("invalid input")
	ErrLimitReached  = errors.New("limit reached")
	ErrConflict      = errors.New("conflict")
	ErrIdentityUnset = errors.New("identity not initialised")
	errCorrupt       = errors.New("stored record failed authentication")
)

// Member is the authenticated caller, resolved once per request.
type Member struct {
	UserUUID  string
	PublicKey string
	StreamTag string // in-memory address for live events; never stored
	inviteTag string
	key       []byte // per-user server key (wraps peer keys and the conversation index)
}

// Service holds chat business logic.
type Service struct {
	users  store.UserRepository
	chats  store.ChatRepository
	logger *utils.Logger
}

// NewService creates a new chat Service instance
func NewService() *Service {
	return &Service{
		users:  store.NewUserRepository(),
		chats:  store.NewChatRepository(),
		logger: utils.NewLogger("CHAT_SERVICE"),
	}
}

func memberFromUser(user *models.User) (*Member, error) {
	if !identity.ValidateEncodedKey(user.PublicKey) {
		return nil, ErrIdentityUnset
	}
	streamTag, err := identity.StreamTag(user.UUID)
	if err != nil {
		return nil, err
	}
	inviteTag, err := identity.InviteCreatorTag(user.UUID)
	if err != nil {
		return nil, err
	}
	key, err := encryption.DecryptUserKey(user.EncryptedKey, user.MasterKeyID)
	if err != nil {
		return nil, err
	}
	return &Member{UserUUID: user.UUID, PublicKey: user.PublicKey, StreamTag: streamTag, inviteTag: inviteTag, key: key}, nil
}

// ResolveMember loads the caller's identity and unwrapped server key.
func (s *Service) ResolveMember(userUUID string) (*Member, error) {
	user, err := s.users.FindByUUID(userUUID)
	if err != nil {
		return nil, err
	}
	return memberFromUser(user)
}

func (m *Member) tag(conversationID uuid.UUID) (string, error) {
	return identity.ConversationTag(m.UserUUID, conversationID)
}

// ---------- encrypted conversation index ----------

func indexAAD(m *Member) []byte {
	return encryption.BuildAAD(m.UserUUID, uuid.Nil, encryption.FieldConversationIndex, encryption.PurposeStoredRecord)
}

// openIndex returns the caller's conversation ids, newest first.
func openIndex(m *Member, enc string) ([]uuid.UUID, error) {
	if enc == "" {
		return nil, nil
	}
	plain, err := encryption.DecryptWithAAD(enc, m.key, indexAAD(m))
	if err != nil {
		return nil, errCorrupt
	}
	var raw []string
	if err := json.Unmarshal([]byte(plain), &raw); err != nil || len(raw) > config.GetMaxConversationsPerUser() {
		return nil, errCorrupt
	}
	ids := make([]uuid.UUID, 0, len(raw))
	seen := make(map[uuid.UUID]struct{}, len(raw))
	for _, r := range raw {
		id, ok := utils.ParseCanonicalUUIDv4(r)
		if !ok {
			return nil, errCorrupt
		}
		if _, dup := seen[id]; !dup {
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func sealIndex(m *Member, ids []uuid.UUID) (string, error) {
	if len(ids) == 0 {
		return "", nil
	}
	raw := make([]string, len(ids))
	for i, id := range ids {
		raw[i] = id.String()
	}
	plain, err := json.Marshal(raw)
	if err != nil {
		return "", err
	}
	// Trailing spaces are valid JSON whitespace; they hide the exact conversation count
	padded := len(plain) + (indexPadBlock-len(plain)%indexPadBlock)%indexPadBlock
	return encryption.EncryptWithAAD(string(plain)+strings.Repeat(" ", padded-len(plain)), m.key, indexAAD(m))
}

func withoutID(ids []uuid.UUID, drop map[uuid.UUID]struct{}) []uuid.UUID {
	kept := ids[:0:0]
	for _, id := range ids {
		if _, gone := drop[id]; !gone {
			kept = append(kept, id)
		}
	}
	return kept
}

// ---------- membership records ----------

func sealMembership(owner *Member, conversationID uuid.UUID, peerPublicKey string) (models.ConversationMember, error) {
	tag, err := owner.tag(conversationID)
	if err != nil {
		return models.ConversationMember{}, err
	}
	refAAD := encryption.BuildAAD(tag, conversationID, encryption.FieldMemberRef, encryption.PurposeStoredRecord)
	refEnc, err := encryption.EncryptWithAAD(owner.UserUUID, encryption.ActiveMasterKey(), refAAD)
	if err != nil {
		return models.ConversationMember{}, err
	}
	peerAAD := encryption.BuildAAD(tag, conversationID, encryption.FieldPeerPublicKey, encryption.PurposeStoredRecord)
	peerEnc, err := encryption.EncryptWithAAD(peerPublicKey, owner.key, peerAAD)
	if err != nil {
		return models.ConversationMember{}, err
	}
	return models.ConversationMember{
		ConversationID: conversationID,
		MemberTag:      tag,
		MemberRefEnc:   refEnc,
		MasterKeyID:    encryption.ActiveMasterKeyID(),
		PeerKeyEnc:     peerEnc,
	}, nil
}

// openMemberRef recovers who a membership row belongs to, and cross-checks the tag.
func openMemberRef(member *models.ConversationMember) (string, error) {
	masterKey, ok := encryption.MasterKeyByID(member.MasterKeyID)
	if !ok {
		return "", errCorrupt
	}
	aad := encryption.BuildAAD(member.MemberTag, member.ConversationID, encryption.FieldMemberRef, encryption.PurposeStoredRecord)
	userUUID, err := encryption.DecryptWithAAD(member.MemberRefEnc, masterKey, aad)
	if err != nil || !utils.ValidateUUID(userUUID) {
		return "", errCorrupt
	}
	expected, err := identity.ConversationTag(userUUID, member.ConversationID)
	if err != nil || expected != member.MemberTag {
		return "", errCorrupt
	}
	return userUUID, nil
}

func (s *Service) openPeerKey(me *Member, member *models.ConversationMember) (string, error) {
	aad := encryption.BuildAAD(member.MemberTag, member.ConversationID, encryption.FieldPeerPublicKey, encryption.PurposeStoredRecord)
	peerKey, err := encryption.DecryptWithAAD(member.PeerKeyEnc, me.key, aad)
	if err != nil || !identity.ValidateEncodedKey(peerKey) {
		return "", errCorrupt
	}
	return peerKey, nil
}

// requireMembership is the single authorization gate for conversation-scoped calls.
func (s *Service) requireMembership(repo store.ChatRepository, me *Member, conversationID uuid.UUID) (*models.ConversationMember, error) {
	tag, err := me.tag(conversationID)
	if err != nil {
		return nil, err
	}
	member, err := repo.FindMembership(conversationID, tag)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return member, nil
}

// peerStreams returns live-event addresses of the other members (for notifications).
func (s *Service) peerStreams(repo store.ChatRepository, me *Member, conversationID uuid.UUID) ([]string, []string, error) {
	members, err := repo.ListMembers(conversationID)
	if err != nil {
		return nil, nil, err
	}
	var uuids, streams []string
	for i := range members {
		userUUID, err := openMemberRef(&members[i])
		if err != nil {
			return nil, nil, err
		}
		uuids = append(uuids, userUUID)
		if userUUID == me.UserUUID {
			continue
		}
		stream, err := identity.StreamTag(userUUID)
		if err != nil {
			return nil, nil, err
		}
		streams = append(streams, stream)
	}
	return uuids, streams, nil
}

// ---------- invites ----------

// CreateInvite issues a single-use token. Only its HMAC is stored.
func (s *Service) CreateInvite(me *Member) (string, time.Time, error) {
	now := time.Now().UTC()
	if err := s.chats.DeleteExpiredInvites(me.inviteTag, now); err != nil {
		return "", time.Time{}, err
	}
	active, err := s.chats.CountActiveInvites(me.inviteTag, now)
	if err != nil {
		return "", time.Time{}, err
	}
	if active >= int64(config.GetMaxActiveInvites()) {
		return "", time.Time{}, ErrLimitReached
	}

	rawToken, err := cryptoengine.RandomBytes(utils.InviteTokenBytes)
	if err != nil {
		return "", time.Time{}, err
	}
	lookup, err := identity.InviteLookup(rawToken)
	if err != nil {
		return "", time.Time{}, err
	}
	inviteID, err := uuid.NewRandomFromReader(cryptoengine.RandReader)
	if err != nil {
		return "", time.Time{}, err
	}

	aad := encryption.BuildAAD(lookup, inviteID, encryption.FieldInviteCreator, encryption.PurposeStoredRecord)
	creatorEnc, err := encryption.EncryptWithAAD(me.UserUUID, encryption.ActiveMasterKey(), aad)
	if err != nil {
		return "", time.Time{}, err
	}

	expiresAt := now.Add(config.GetInviteTTL())
	invite := models.Invite{
		ID:            inviteID,
		Lookup:        lookup,
		CreatorTag:    me.inviteTag,
		CreatorRefEnc: creatorEnc,
		MasterKeyID:   encryption.ActiveMasterKeyID(),
		ExpiresAt:     expiresAt,
	}
	if err := s.chats.CreateInvite(&invite); err != nil {
		return "", time.Time{}, err
	}
	return base64.RawURLEncoding.EncodeToString(rawToken), expiresAt, nil
}

func openInviteCreator(invite *models.Invite) (string, error) {
	masterKey, ok := encryption.MasterKeyByID(invite.MasterKeyID)
	if !ok {
		return "", errCorrupt
	}
	aad := encryption.BuildAAD(invite.Lookup, invite.ID, encryption.FieldInviteCreator, encryption.PurposeStoredRecord)
	creatorUUID, err := encryption.DecryptWithAAD(invite.CreatorRefEnc, masterKey, aad)
	if err != nil || !utils.ValidateUUID(creatorUUID) {
		return "", errCorrupt
	}
	return creatorUUID, nil
}

// RedeemInvite consumes a token and opens a conversation between creator and caller.
// Everything happens in one transaction: on any failure the invite is restored.
// Returns the caller's view plus the creator's stream address (to notify).
func (s *Service) RedeemInvite(me *Member, token string) (*models.ConversationDTO, string, error) {
	rawToken, ok := utils.ValidateInviteToken(token)
	if !ok {
		return nil, "", ErrInvalidInput
	}
	lookup, err := identity.InviteLookup(rawToken)
	if err != nil {
		return nil, "", err
	}

	var (
		dto           *models.ConversationDTO
		creatorStream string
	)
	err = s.chats.Transaction(func(tx store.ChatRepository) error {
		invite, err := tx.TakeInvite(lookup, me.inviteTag, time.Now().UTC())
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrNotFound
			}
			return err
		}
		creatorUUID, err := openInviteCreator(invite)
		if err != nil {
			return err
		}

		rows, err := tx.LockUsers([]string{me.UserUUID, creatorUUID})
		if err != nil {
			return err
		}
		if rows[me.UserUUID] == nil || rows[creatorUUID] == nil {
			return ErrNotFound
		}
		self, err := memberFromUser(rows[me.UserUUID])
		if err != nil {
			return err
		}
		creator, err := memberFromUser(rows[creatorUUID])
		if err != nil {
			return err
		}
		if creator.inviteTag != invite.CreatorTag {
			return errCorrupt
		}

		myIndex, err := openIndex(self, rows[self.UserUUID].ConvIndexEnc)
		if err != nil {
			return err
		}
		theirIndex, err := openIndex(creator, rows[creator.UserUUID].ConvIndexEnc)
		if err != nil {
			return err
		}
		limit := config.GetMaxConversationsPerUser()
		if len(myIndex) >= limit || len(theirIndex) >= limit {
			return ErrLimitReached
		}

		conversationID, err := uuid.NewRandomFromReader(cryptoengine.RandReader)
		if err != nil {
			return err
		}
		mine, err := sealMembership(self, conversationID, creator.PublicKey)
		if err != nil {
			return err
		}
		theirs, err := sealMembership(creator, conversationID, self.PublicKey)
		if err != nil {
			return err
		}
		if err := tx.CreateConversation(conversationID, []models.ConversationMember{mine, theirs}); err != nil {
			return err
		}
		if err := s.saveIndex(tx, self, append([]uuid.UUID{conversationID}, myIndex...)); err != nil {
			return err
		}
		if err := s.saveIndex(tx, creator, append([]uuid.UUID{conversationID}, theirIndex...)); err != nil {
			return err
		}

		dto = &models.ConversationDTO{ID: conversationID.String(), PeerPublicKey: creator.PublicKey}
		creatorStream = creator.StreamTag
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	s.logger.Debug("RedeemInvite: conversation opened")
	return dto, creatorStream, nil
}

func (s *Service) saveIndex(repo store.ChatRepository, m *Member, ids []uuid.UUID) error {
	enc, err := sealIndex(m, ids)
	if err != nil {
		return err
	}
	return repo.SaveConvIndex(m.UserUUID, enc)
}

// ---------- conversations ----------

// ListConversations returns the caller's conversations in index order (newest first).
// Recency across conversations is deliberately not tracked server-side.
func (s *Service) ListConversations(me *Member) ([]models.ConversationDTO, error) {
	user, err := s.users.FindByUUID(me.UserUUID)
	if err != nil {
		return nil, err
	}
	ids, err := openIndex(me, user.ConvIndexEnc)
	if err != nil {
		return nil, err
	}

	tags := make([]string, len(ids))
	for i, id := range ids {
		if tags[i], err = me.tag(id); err != nil {
			return nil, err
		}
	}
	memberships, err := s.chats.FindMembershipsByTags(tags)
	if err != nil {
		return nil, err
	}
	lastSeqs, err := s.chats.LastSeqs(ids)
	if err != nil {
		return nil, err
	}

	result := make([]models.ConversationDTO, 0, len(ids))
	stale := make(map[uuid.UUID]struct{})
	for i, id := range ids {
		member, ok := memberships[id]
		if !ok || member.MemberTag != tags[i] {
			stale[id] = struct{}{}
			continue
		}
		peerKey, err := s.openPeerKey(me, &member)
		if err != nil {
			s.logger.Error("SECURITY: a stored peer key failed authentication")
			continue
		}
		result = append(result, models.ConversationDTO{
			ID:            id.String(),
			PeerPublicKey: peerKey,
			LastSeq:       lastSeqs[id],
			ReadSeq:       member.ReadSeq,
		})
	}
	if len(stale) > 0 {
		s.pruneIndex(me, stale)
	}
	return result, nil
}

// pruneIndex drops ids whose conversation no longer exists (burned by the peer elsewhere).
func (s *Service) pruneIndex(me *Member, stale map[uuid.UUID]struct{}) {
	err := s.chats.Transaction(func(tx store.ChatRepository) error {
		rows, err := tx.LockUsers([]string{me.UserUUID})
		if err != nil || rows[me.UserUUID] == nil {
			return err
		}
		ids, err := openIndex(me, rows[me.UserUUID].ConvIndexEnc)
		if err != nil {
			return err
		}
		return s.saveIndex(tx, me, withoutID(ids, stale))
	})
	if err != nil {
		s.logger.LogError("pruneIndex", err)
	}
}

// BurnConversation deletes a conversation and all its ciphertext for every member,
// and removes it from every member's encrypted index.
func (s *Service) BurnConversation(me *Member, conversationID uuid.UUID) ([]string, error) {
	var streams []string
	err := s.chats.Transaction(func(tx store.ChatRepository) error {
		if _, err := s.requireMembership(tx, me, conversationID); err != nil {
			return err
		}
		uuids, peerStreams, err := s.peerStreams(tx, me, conversationID)
		if err != nil {
			return err
		}
		rows, err := tx.LockUsers(uuids)
		if err != nil {
			return err
		}
		if err := tx.DeleteConversation(conversationID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrNotFound
			}
			return err
		}
		drop := map[uuid.UUID]struct{}{conversationID: {}}
		for _, row := range rows {
			member, err := memberFromUser(row)
			if err != nil {
				return err
			}
			ids, err := openIndex(member, row.ConvIndexEnc)
			if err != nil {
				return err
			}
			if err := s.saveIndex(tx, member, withoutID(ids, drop)); err != nil {
				return err
			}
		}
		streams = peerStreams
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.logger.Debug("BurnConversation: conversation burned")
	return streams, nil
}

// DeleteAccount erases the caller: its invites, every conversation it is in (all ciphertext,
// for both sides) and the account row. Returns the peers' live-event addresses.
// Lock order is RedeemInvite's (invites, then users). Peers' rows are left unlocked: their
// encrypted indexes drop the vanished conversations at their next listing (pruneIndex).
func (s *Service) DeleteAccount(me *Member) ([]string, error) {
	var streams []string
	err := s.chats.Transaction(func(tx store.ChatRepository) error {
		if err := tx.DeleteInvites(me.inviteTag); err != nil {
			return err
		}
		rows, err := tx.LockUsers([]string{me.UserUUID})
		if err != nil {
			return err
		}
		row := rows[me.UserUUID]
		if row == nil {
			return ErrNotFound
		}
		ids, err := openIndex(me, row.ConvIndexEnc)
		if err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := s.requireMembership(tx, me, id); errors.Is(err, ErrNotFound) {
				continue // the peer burned it already
			} else if err != nil {
				return err
			}
			_, peers, err := s.peerStreams(tx, me, id)
			if err != nil {
				return err
			}
			if err := tx.DeleteConversation(id); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			streams = append(streams, peers...)
		}
		if err := tx.DeleteUser(me.UserUUID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrNotFound
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.logger.Debug("DeleteAccount: account erased")
	return streams, nil
}

// ---------- messages ----------

// ListMessages returns messages after `after`, or the latest page when after is nil.
func (s *Service) ListMessages(me *Member, conversationID uuid.UUID, after *int64) ([]models.MessageDTO, error) {
	member, err := s.requireMembership(s.chats, me, conversationID)
	if err != nil {
		return nil, err
	}
	limit := config.GetMessagePageLimit()
	var messages []models.Message
	if after == nil {
		messages, err = s.chats.ListLatestMessages(conversationID, limit)
	} else {
		messages, err = s.chats.ListMessagesAfter(conversationID, *after, limit)
	}
	if err != nil {
		return nil, err
	}
	result := make([]models.MessageDTO, 0, len(messages))
	for _, m := range messages {
		result = append(result, models.MessageDTO{
			ID:         m.ID.String(),
			Seq:        m.Seq,
			Mine:       m.SenderTag == member.MemberTag,
			Ciphertext: m.Ciphertext,
		})
	}
	return result, nil
}

// expiryDay returns the day-granular deletion date for ciphertext stored now.
func expiryDay(now time.Time) time.Time {
	return now.UTC().Truncate(day).Add(time.Duration(config.GetMessageTTLDays()) * day)
}

// SendMessage stores one opaque ciphertext under the conversation's next sequence number.
func (s *Service) SendMessage(me *Member, conversationID uuid.UUID, rawID, ciphertext string) (int64, []string, error) {
	messageID, ok := utils.ParseCanonicalUUIDv4(rawID)
	if !ok || !utils.ValidateCiphertext(ciphertext) {
		return 0, nil, ErrInvalidInput
	}
	var seq int64
	err := s.chats.Transaction(func(tx store.ChatRepository) error {
		member, err := s.requireMembership(tx, me, conversationID)
		if err != nil {
			return err
		}
		if seq, err = tx.NextSeq(conversationID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrNotFound
			}
			return err
		}
		err = tx.CreateMessage(&models.Message{
			ConversationID: conversationID,
			Seq:            seq,
			ID:             messageID,
			SenderTag:      member.MemberTag,
			Ciphertext:     ciphertext,
			ExpiresOn:      expiryDay(time.Now()),
		})
		if errors.Is(err, store.ErrConflict) {
			return ErrConflict
		}
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	_, streams, err := s.peerStreams(s.chats, me, conversationID)
	if err != nil {
		// The message is stored; the peer sees it on its next sync
		s.logger.LogError("peerStreams", err)
		return seq, nil, nil
	}
	return seq, streams, nil
}

// MarkRead advances the caller's read marker (never backwards, never past the end).
func (s *Service) MarkRead(me *Member, conversationID uuid.UUID, seq int64) error {
	if seq <= 0 {
		return ErrInvalidInput
	}
	member, err := s.requireMembership(s.chats, me, conversationID)
	if err != nil {
		return err
	}
	lastSeqs, err := s.chats.LastSeqs([]uuid.UUID{conversationID})
	if err != nil {
		return err
	}
	if seq > lastSeqs[conversationID] {
		return ErrInvalidInput
	}
	return s.chats.AdvanceReadSeq(conversationID, member.MemberTag, seq)
}

// ---------- retention ----------

// PurgeExpired deletes ciphertext past its deletion day and expired invites.
func (s *Service) PurgeExpired(now time.Time) error {
	messages, invites, err := s.chats.PurgeExpired(now.UTC().Truncate(day), now.UTC())
	if err != nil {
		return err
	}
	s.logger.Debug("PurgeExpired: removed %d messages, %d invites", messages, invites)
	return nil
}

const (
	retentionInterval = time.Hour
	// maxRetentionCycles bounds the loop (RULES.md §8.1); hourly, it outlives any deployment
	maxRetentionCycles = 1 << 20
)

// RunRetention purges expired ciphertext and invites now and then hourly until ctx ends.
func (s *Service) RunRetention(ctx context.Context) {
	ticker := time.NewTicker(retentionInterval)
	defer ticker.Stop()
	for cycle := 0; cycle < maxRetentionCycles; cycle++ {
		if err := s.PurgeExpired(time.Now()); err != nil {
			s.logger.LogError("PurgeExpired", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
