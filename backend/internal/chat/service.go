// Package chat implements noaddress's pairing and message relay. The server only ever
// handles opaque E2E ciphertext; it learns neither plaintext nor who talks to whom
// from storage alone (members are HMAC pseudonyms, peer keys are encrypted).
package chat

import (
	"encoding/base64"
	"errors"
	"time"

	"noaddress/internal/config"
	"noaddress/internal/cryptoengine"
	"noaddress/internal/encryption"
	"noaddress/internal/identity"
	"noaddress/internal/models"
	"noaddress/internal/store"
	"noaddress/internal/utils"

	"github.com/google/uuid"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrInvalidInput  = errors.New("invalid input")
	ErrLimitReached  = errors.New("limit reached")
	ErrConflict      = errors.New("conflict")
	ErrIdentityUnset = errors.New("identity not initialised")
)

// Member is the authenticated caller, resolved once per request.
type Member struct {
	UserUUID  string
	Tag       string
	PublicKey string
	key       []byte // per-user server key (wraps peer public keys at rest)
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

// ResolveMember loads the caller's tag, public key and unwrapped server key.
func (s *Service) ResolveMember(userUUID string) (*Member, error) {
	user, err := s.users.FindByUUID(userUUID)
	if err != nil {
		return nil, err
	}
	if !identity.ValidateEncodedKey(user.PublicKey) {
		return nil, ErrIdentityUnset
	}
	tag, err := identity.MemberTag(user.UUID)
	if err != nil {
		return nil, err
	}
	key, err := encryption.DecryptUserKey(user.EncryptedKey, user.MasterKeyID)
	if err != nil {
		return nil, err
	}
	return &Member{UserUUID: user.UUID, Tag: tag, PublicKey: user.PublicKey, key: key}, nil
}

// CreateInvite issues a single-use token. Only its HMAC is stored.
func (s *Service) CreateInvite(me *Member) (string, time.Time, error) {
	now := time.Now().UTC()
	if err := s.chats.DeleteExpiredInvites(me.Tag, now); err != nil {
		return "", time.Time{}, err
	}
	active, err := s.chats.CountActiveInvites(me.Tag, now)
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
		ID:          inviteID,
		Lookup:      lookup,
		CreatorTag:  me.Tag,
		CreatorEnc:  creatorEnc,
		MasterKeyID: encryption.ActiveMasterKeyID(),
		ExpiresAt:   expiresAt,
	}
	if err := s.chats.CreateInvite(&invite); err != nil {
		return "", time.Time{}, err
	}
	s.logger.Info("CreateInvite: invite issued")
	return base64.RawURLEncoding.EncodeToString(rawToken), expiresAt, nil
}

// RedeemInvite consumes a token and opens a conversation between creator and caller.
// Returns the caller's view plus the creator's tag (to notify).
func (s *Service) RedeemInvite(me *Member, token string) (*models.ConversationDTO, string, error) {
	rawToken, ok := utils.ValidateInviteToken(token)
	if !ok {
		return nil, "", ErrInvalidInput
	}
	lookup, err := identity.InviteLookup(rawToken)
	if err != nil {
		return nil, "", err
	}
	if err := s.ensureCapacity(me.Tag); err != nil {
		return nil, "", err
	}

	// Single use: the row is deleted atomically before anything else happens.
	// Own invites never match, so a self-redeem leaves the invite intact (404).
	invite, err := s.chats.TakeInvite(lookup, me.Tag, time.Now().UTC())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, "", ErrNotFound
		}
		return nil, "", err
	}

	creator, err := s.resolveInviteCreator(invite)
	if err != nil {
		return nil, "", err
	}
	if err := s.ensureCapacity(creator.Tag); err != nil {
		return nil, "", err
	}

	conversationID, err := uuid.NewRandomFromReader(cryptoengine.RandReader)
	if err != nil {
		return nil, "", err
	}
	mine, err := sealPeerKey(me, conversationID, creator.PublicKey)
	if err != nil {
		return nil, "", err
	}
	theirs, err := sealPeerKey(creator, conversationID, me.PublicKey)
	if err != nil {
		return nil, "", err
	}
	if err := s.chats.CreateConversation(conversationID, []models.ConversationMember{mine, theirs}); err != nil {
		return nil, "", err
	}

	s.logger.Info("RedeemInvite: conversation opened")
	return &models.ConversationDTO{ID: conversationID.String(), PeerPublicKey: creator.PublicKey}, creator.Tag, nil
}

func (s *Service) ensureCapacity(memberTag string) error {
	count, err := s.chats.CountMemberships(memberTag)
	if err != nil {
		return err
	}
	if count >= int64(config.GetMaxConversationsPerUser()) {
		return ErrLimitReached
	}
	return nil
}

func (s *Service) resolveInviteCreator(invite *models.Invite) (*Member, error) {
	masterKey, ok := encryption.MasterKeyByID(invite.MasterKeyID)
	if !ok {
		return nil, errors.New("unknown master key id")
	}
	aad := encryption.BuildAAD(invite.Lookup, invite.ID, encryption.FieldInviteCreator, encryption.PurposeStoredRecord)
	creatorUUID, err := encryption.DecryptWithAAD(invite.CreatorEnc, masterKey, aad)
	if err != nil {
		return nil, err
	}
	creator, err := s.ResolveMember(creatorUUID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	// Defence in depth: the decrypted creator must match the tag the invite was filed under
	if creator.Tag != invite.CreatorTag {
		return nil, errors.New("invite creator mismatch")
	}
	return creator, nil
}

func sealPeerKey(owner *Member, conversationID uuid.UUID, peerPublicKey string) (models.ConversationMember, error) {
	aad := encryption.BuildAAD(owner.Tag, conversationID, encryption.FieldPeerPublicKey, encryption.PurposeStoredRecord)
	enc, err := encryption.EncryptWithAAD(peerPublicKey, owner.key, aad)
	if err != nil {
		return models.ConversationMember{}, err
	}
	return models.ConversationMember{ConversationID: conversationID, MemberTag: owner.Tag, PeerKeyEnc: enc}, nil
}

func (s *Service) openPeerKey(me *Member, member *models.ConversationMember) (string, error) {
	aad := encryption.BuildAAD(me.Tag, member.ConversationID, encryption.FieldPeerPublicKey, encryption.PurposeStoredRecord)
	peerKey, err := encryption.DecryptWithAAD(member.PeerKeyEnc, me.key, aad)
	if err != nil {
		return "", err
	}
	if !identity.ValidateEncodedKey(peerKey) {
		return "", errors.New("stored peer key malformed")
	}
	return peerKey, nil
}

// ListConversations returns the caller's conversations, most recently active first.
func (s *Service) ListConversations(me *Member) ([]models.ConversationDTO, error) {
	members, err := s.chats.ListMemberships(me.Tag)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, 0, len(members))
	for _, m := range members {
		ids = append(ids, m.ConversationID)
	}
	lastSeqs, err := s.chats.LastSeqs(ids)
	if err != nil {
		return nil, err
	}

	result := make([]models.ConversationDTO, 0, len(members))
	for i := range members {
		peerKey, err := s.openPeerKey(me, &members[i])
		if err != nil {
			s.logger.LogError("openPeerKey", err)
			s.logger.Error("SECURITY: peer key failed authentication for conversation=%s", members[i].ConversationID.String())
			continue
		}
		result = append(result, models.ConversationDTO{
			ID:            members[i].ConversationID.String(),
			PeerPublicKey: peerKey,
			LastSeq:       lastSeqs[members[i].ConversationID],
			ReadSeq:       members[i].ReadSeq,
		})
	}
	sortByActivity(result)
	return result, nil
}

func sortByActivity(list []models.ConversationDTO) {
	// Insertion sort: list is bounded by MAX_CONVERSATIONS_PER_USER
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j].LastSeq > list[j-1].LastSeq; j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
}

// requireMembership is the single authorization gate for conversation-scoped calls.
func (s *Service) requireMembership(me *Member, conversationID uuid.UUID) (*models.ConversationMember, error) {
	member, err := s.chats.FindMembership(conversationID, me.Tag)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return member, nil
}

// PeerTags returns the other members of a conversation (for notifications).
func (s *Service) peerTags(me *Member, conversationID uuid.UUID) ([]string, error) {
	tags, err := s.chats.ListMemberTags(conversationID)
	if err != nil {
		return nil, err
	}
	peers := make([]string, 0, len(tags))
	for _, tag := range tags {
		if tag != me.Tag {
			peers = append(peers, tag)
		}
	}
	return peers, nil
}

// BurnConversation deletes a conversation and all its ciphertext for every member.
func (s *Service) BurnConversation(me *Member, conversationID uuid.UUID) ([]string, error) {
	if _, err := s.requireMembership(me, conversationID); err != nil {
		return nil, err
	}
	peers, err := s.peerTags(me, conversationID)
	if err != nil {
		return nil, err
	}
	if err := s.chats.DeleteConversation(conversationID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	s.logger.Info("BurnConversation: conversation burned")
	return peers, nil
}

// ListMessages returns messages after `after`, or the latest page when after is nil.
func (s *Service) ListMessages(me *Member, conversationID uuid.UUID, after *int64) ([]models.MessageDTO, error) {
	if _, err := s.requireMembership(me, conversationID); err != nil {
		return nil, err
	}
	limit := config.GetMessagePageLimit()
	var (
		messages []models.Message
		err      error
	)
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
			Mine:       m.SenderTag == me.Tag,
			Ciphertext: m.Ciphertext,
		})
	}
	return result, nil
}

// SendMessage stores one opaque ciphertext and returns its sequence number.
func (s *Service) SendMessage(me *Member, conversationID uuid.UUID, rawID, ciphertext string) (int64, []string, error) {
	messageID, ok := utils.ParseCanonicalUUIDv4(rawID)
	if !ok || !utils.ValidateCiphertext(ciphertext) {
		return 0, nil, ErrInvalidInput
	}
	if _, err := s.requireMembership(me, conversationID); err != nil {
		return 0, nil, err
	}
	message := models.Message{
		ID:             messageID,
		ConversationID: conversationID,
		SenderTag:      me.Tag,
		Ciphertext:     ciphertext,
	}
	if err := s.chats.CreateMessage(&message); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return 0, nil, ErrConflict
		}
		return 0, nil, err
	}
	peers, err := s.peerTags(me, conversationID)
	if err != nil {
		// Message is stored; the peer will see it on its next sync
		s.logger.LogError("peerTags", err)
		return message.Seq, nil, nil
	}
	return message.Seq, peers, nil
}

// MarkRead advances the caller's read marker (never backwards, never past the end).
func (s *Service) MarkRead(me *Member, conversationID uuid.UUID, seq int64) error {
	if seq <= 0 {
		return ErrInvalidInput
	}
	if _, err := s.requireMembership(me, conversationID); err != nil {
		return err
	}
	lastSeqs, err := s.chats.LastSeqs([]uuid.UUID{conversationID})
	if err != nil {
		return err
	}
	if seq > lastSeqs[conversationID] {
		return ErrInvalidInput
	}
	return s.chats.AdvanceReadSeq(conversationID, me.Tag, seq)
}
