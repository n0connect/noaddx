package chat

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"noaddx/internal/cryptoengine"
	"noaddx/internal/encryption"
	"noaddx/internal/identity"
	"noaddx/internal/models"

	"github.com/google/uuid"
)

// The database is useless without the keys in .env, and the keys are useless without the
// database: VerifyKeys stops them from drifting apart unnoticed, RunRewrap completes a
// master key rotation so the old key can actually be retired.

const (
	pepperCheckName = "pepper"
	// keySampleSize rows per table are tried: one corrupt row must not stop the server,
	// while a wrong key opens none of them
	keySampleSize = 3
	rewrapBatch   = 100
	// maxRewrapBatches bounds the loop (RULES.md §8.1); 100 rows each, it covers any table
	maxRewrapBatches = 1 << 20
)

func sortedIDs(set map[string]struct{}) []string {
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// VerifyKeys refuses keys that cannot open what the database holds. A regenerated .env, or a
// master key dropped from MASTER_KEY_OLD while records still need it, would otherwise start a
// server that answers every account with errors. Every master key id in use must be
// configured and open sample records, and the pepper must be the one the database runs with.
func (s *Service) VerifyKeys() error {
	inUse, err := s.keys.MasterKeyIDsInUse()
	if err != nil {
		return err
	}
	delete(inUse, "") // rows from before key ids existed: no key and no code path opens them
	for _, id := range sortedIDs(inUse) {
		if _, ok := encryption.MasterKeyByID(id); !ok {
			return fmt.Errorf("records are encrypted under master key %q, which is not configured: restore it as MASTER_KEY_ACTIVE or in MASTER_KEY_OLD", id)
		}
		opens, err := s.opensSample(id)
		if err != nil {
			return err
		}
		if !opens {
			return fmt.Errorf("the key configured as master key %q does not open the records stored under that id", id)
		}
	}
	for _, id := range encryption.OldMasterKeyIDs() {
		if _, used := inUse[id]; !used {
			s.logger.Info("Old master key %s encrypts nothing any more: remove it from MASTER_KEY_OLD", id)
		}
	}
	return s.verifyPepper(inUse)
}

// opensSample reports whether keyID decrypts any of a few records stored under it.
func (s *Service) opensSample(keyID string) (bool, error) {
	users, err := s.keys.UsersUnderKey(keyID, 0, keySampleSize)
	if err != nil {
		return false, err
	}
	members, err := s.keys.MembersUnderKey(keyID, models.ConversationMember{}, keySampleSize)
	if err != nil {
		return false, err
	}
	invites, err := s.keys.InvitesUnderKey(keyID, uuid.Nil, keySampleSize)
	if err != nil {
		return false, err
	}
	for i := range users {
		if _, err := encryption.DecryptUserKey(users[i].EncryptedKey, keyID); err == nil {
			return true, nil
		}
	}
	for i := range members {
		if _, err := memberRefUUID(&members[i]); err == nil {
			return true, nil
		}
	}
	for i := range invites {
		if _, err := openInviteCreator(&invites[i]); err == nil {
			return true, nil
		}
	}
	return len(users)+len(members)+len(invites) == 0, nil
}

var errPepperChanged = errors.New("ACCOUNT_LOOKUP_PEPPER is not the pepper this database was created with: restore the original (it can never change, every account is keyed by it)")

// verifyPepper compares the pepper with the commitment pinned at the first run. A database
// that predates the check gets the commitment only once stored pseudonyms prove the pepper,
// so a wrong pepper is never pinned (which would then lock the right one out).
func (s *Service) verifyPepper(inUse map[string]struct{}) error {
	check, err := identity.PepperCheck()
	if err != nil {
		return err
	}
	pinned, ok, err := s.keys.KeyCheck(pepperCheckName)
	if err != nil {
		return err
	}
	if ok {
		if !cryptoengine.ConstantTimeEqual([]byte(pinned), []byte(check)) {
			return errPepperChanged
		}
		return nil
	}
	proven, err := s.pepperProven(inUse)
	if err != nil {
		return err
	}
	if !proven {
		s.logger.Warn("ACCOUNT_LOOKUP_PEPPER is not verified yet: no stored conversation can prove it")
		return nil
	}
	return s.keys.PinKeyCheck(pepperCheckName, check)
}

// pepperProven: an empty database (the first run) takes any pepper; otherwise a membership
// pseudonym recomputed with the pepper must match the stored one. A mismatch is an error.
func (s *Service) pepperProven(inUse map[string]struct{}) (bool, error) {
	hasUsers, err := s.keys.HasUsers()
	if err != nil || !hasUsers {
		return !hasUsers, err
	}
	for _, id := range sortedIDs(inUse) {
		members, err := s.keys.MembersUnderKey(id, models.ConversationMember{}, keySampleSize)
		if err != nil {
			return false, err
		}
		for i := range members {
			userUUID, err := memberRefUUID(&members[i])
			if err != nil {
				continue
			}
			tag, err := identity.ConversationTag(userUUID, members[i].ConversationID)
			if err != nil {
				return false, err
			}
			if tag != members[i].MemberTag {
				return false, errPepperChanged
			}
			return true, nil
		}
	}
	return false, nil
}

// RunRewrap moves every record still under an old master key to the active one, a batch at
// a time, so a rotated-out (possibly exposed) key stops protecting anything and can leave
// MASTER_KEY_OLD. Rows written meanwhile already use the active key, and each update applies
// only while the row still names the old key. Rows that do not open keep their old key.
func (s *Service) RunRewrap(ctx context.Context) {
	active := encryption.ActiveMasterKeyID()
	inUse, err := s.keys.MasterKeyIDsInUse()
	if err != nil {
		s.logger.LogError("RunRewrap", err)
		return
	}
	moved, stuck := 0, 0
	for _, id := range sortedIDs(inUse) {
		if id != active && id != "" {
			m, st := s.rewrapKey(ctx, id, active)
			moved, stuck = moved+m, stuck+st
		}
	}
	switch {
	case stuck > 0:
		s.logger.Warn("Master key rotation: %d records re-wrapped, %d do not open and keep their old key", moved, stuck)
	case moved > 0:
		s.logger.Info("Master key rotation: %d records re-wrapped; no record uses an old key any more, MASTER_KEY_OLD can be emptied", moved)
	}
}

// rewrapKey walks the three tables in primary-key order; the cursors move past every row,
// re-wrapped or not, so a row that cannot be opened is visited once.
func (s *Service) rewrapKey(ctx context.Context, from, to string) (moved, stuck int) {
	count := func(err error) {
		if err == nil {
			moved++
		} else {
			stuck++
		}
	}
	var (
		afterUser   uint
		afterMember models.ConversationMember
		afterInvite uuid.UUID
	)
	for batch := 0; batch < maxRewrapBatches && ctx.Err() == nil; batch++ {
		users, errUsers := s.keys.UsersUnderKey(from, afterUser, rewrapBatch)
		members, errMembers := s.keys.MembersUnderKey(from, afterMember, rewrapBatch)
		invites, errInvites := s.keys.InvitesUnderKey(from, afterInvite, rewrapBatch)
		if err := errors.Join(errUsers, errMembers, errInvites); err != nil {
			s.logger.LogError("rewrapKey", err)
			return moved, stuck
		}
		if len(users)+len(members)+len(invites) == 0 {
			return moved, stuck
		}
		for i := range users {
			afterUser = users[i].ID
			count(s.rewrapUser(&users[i], from, to))
		}
		for i := range members {
			afterMember = members[i]
			count(s.rewrapMember(&members[i], from, to))
		}
		for i := range invites {
			afterInvite = invites[i].ID
			count(s.rewrapInvite(&invites[i], from, to))
		}
	}
	return moved, stuck
}

func (s *Service) rewrapUser(user *models.User, from, to string) error {
	key, err := encryption.DecryptUserKey(user.EncryptedKey, from)
	if err != nil {
		return err
	}
	enc, err := encryption.EncryptWithMasterKey(hex.EncodeToString(key))
	if err != nil {
		return err
	}
	return s.keys.RewrapUser(user.ID, from, to, enc)
}

// Re-wrapping first verifies the record (tag included): nothing unauthenticated is re-sealed
func (s *Service) rewrapMember(member *models.ConversationMember, from, to string) error {
	userUUID, err := openMemberRef(member)
	if err != nil {
		return err
	}
	enc, err := encryption.EncryptWithAAD(userUUID, encryption.ActiveMasterKey(), memberRefAAD(member.MemberTag, member.ConversationID))
	if err != nil {
		return err
	}
	return s.keys.RewrapMember(member, from, to, enc)
}

func (s *Service) rewrapInvite(invite *models.Invite, from, to string) error {
	creatorUUID, err := openInviteCreator(invite)
	if err != nil {
		return err
	}
	enc, err := encryption.EncryptWithAAD(creatorUUID, encryption.ActiveMasterKey(), inviteCreatorAAD(invite.Lookup, invite.ID))
	if err != nil {
		return err
	}
	return s.keys.RewrapInvite(invite.ID, from, to, enc)
}
