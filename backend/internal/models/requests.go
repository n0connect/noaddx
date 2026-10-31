// Package models/requests contains HTTP request/response DTOs only.
// These models are NOT database entities and are NOT imported in database migrations.
// They are only used for API request/response serialization.

package models

type LoginRequest struct {
	AuthKey string `json:"auth_key"` // HKDF(AccountNumber, "noaddx/auth") — never the AccountNumber itself
}

type RegisterRequest struct {
	Confirm      bool         `json:"confirm"`       // false = generate AccountNumber only, true = create account
	PendingToken string       `json:"pending_token"` // required when confirm=true (references the AccountNumber)
	PoW          *PoWSolution `json:"pow,omitempty"` // Proof of work solution, required in both phases
}

type PoWSolution struct {
	Challenge  string `json:"challenge"`
	Solution   string `json:"solution"`
	Timestamp  int64  `json:"timestamp"`
	TTL        int64  `json:"ttl"`
	Difficulty int    `json:"difficulty"` // Informational only; the server uses its own issued value
	Salt       string `json:"salt"`
}

type PoWChallengeResponse struct {
	Success   bool          `json:"success"`
	Message   string        `json:"message"`
	Challenge *PoWChallenge `json:"challenge,omitempty"`
}

type PoWChallenge struct {
	Challenge  string `json:"challenge"`
	Timestamp  int64  `json:"timestamp"`
	Difficulty int    `json:"difficulty"`
	TTL        int64  `json:"ttl"`
	Salt       string `json:"salt"`
}

// DeleteAccountRequest re-proves the account: a live session alone cannot erase it
type DeleteAccountRequest struct {
	AuthKey string `json:"auth_key"` // HKDF(AccountNumber, "noaddx/auth"), as at login
}

// LoginResponse never carries the session token: it travels only in the HttpOnly cookie
type LoginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// RegisterResponse: phase 1 shows the AccountNumber once; phase 2 sets the session cookie only
type RegisterResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	AccountNumber string `json:"account_number,omitempty"` // Only sent when confirm=false
	PendingToken  string `json:"pending_token,omitempty"`  // Only sent when confirm=false
	Confirmed     bool   `json:"confirmed"`                // true if account was created
}

// ---- messaging ----

type MeResponse struct {
	PublicKey       string `json:"public_key"`
	MessageTTLDays  int    `json:"message_ttl_days"`   // ciphertext is deleted after this many days
	RoomMaxMembers  int    `json:"room_max_members"`   // largest room a member may create
	RoomMaxTTLHours int    `json:"room_max_ttl_hours"` // longest room lifetime, in hours
}

type CreateInviteRequest struct {
	PoW *PoWSolution `json:"pow"` // Proof of work solution, required for every invite
}

type InviteResponse struct {
	Token     string `json:"token"`      // 16 random bytes, base64url; shown to the user once
	ExpiresAt int64  `json:"expires_at"` // Unix seconds
}

type RedeemInviteRequest struct {
	Token string `json:"token"`
}

type ConversationDTO struct {
	ID            string   `json:"id"`
	PeerPublicKey string   `json:"peer_public_key"` // empty in a room
	LastSeq       int64    `json:"last_seq"`
	ReadSeq       int64    `json:"read_seq"`
	Room          *RoomDTO `json:"room,omitempty"` // present for rooms only
}

// RoomDTO is the caller's view of a room; the vault is theirs alone (sealed for their account)
type RoomDTO struct {
	Vault      string `json:"vault"`
	MaxMembers int    `json:"max_members"`
	ExpiresAt  int64  `json:"expires_at"` // Unix seconds, on the hour
	Owner      bool   `json:"owner"`
	Members    int    `json:"members"`
	Notes      int    `json:"notes"` // sealed notes waiting for the caller
}

// CreateRoomRequest: every value is derived on the client from a room secret the server never sees
type CreateRoomRequest struct {
	ID         string       `json:"id"`          // UUIDv4 derived from the secret
	Lookup     string       `json:"lookup"`      // 32 bytes derived from the secret, base64url
	MaxMembers int          `json:"max_members"` // 2..ROOM_MAX_MEMBERS
	ExpiresAt  int64        `json:"expires_at"`  // Unix seconds on the hour, 1h..ROOM_MAX_TTL_HOURS ahead
	Card       string       `json:"card"`        // the creator's member card
	Vault      string       `json:"vault"`       // the code, sealed for the creator's account
	PoW        *PoWSolution `json:"pow"`
}

type JoinRoomRequest struct {
	ID     string `json:"id"`
	Lookup string `json:"lookup"`
	Card   string `json:"card"`
	Vault  string `json:"vault"`
}

type RoomMemberDTO struct {
	Card  string `json:"card"`
	Mine  bool   `json:"mine"`
	Owner bool   `json:"owner"`
}

type RoomMembersResponse struct {
	Members []RoomMemberDTO `json:"members"`
}

type SendNoteRequest struct {
	ID   string `json:"id"`   // Client-generated UUIDv4, bound into the note's encryption
	To   string `json:"to"`   // the addressee's card
	Blob string `json:"blob"` // base64url sealed note
}

type NoteDTO struct {
	ID   string `json:"id"`
	Blob string `json:"blob"`
}

type NotesResponse struct {
	Notes []NoteDTO `json:"notes"`
}

type ConversationResponse struct {
	Conversation ConversationDTO `json:"conversation"`
}

type ConversationsResponse struct {
	Conversations []ConversationDTO `json:"conversations"`
}

type SendMessageRequest struct {
	ID         string `json:"id"`         // Client-generated UUIDv4, bound into the E2E AAD
	Ciphertext string `json:"ciphertext"` // base64url(nonce || ciphertext || tag)
}

type SendMessageResponse struct {
	Seq int64 `json:"seq"`
}

type MessageDTO struct {
	ID         string `json:"id"`
	Seq        int64  `json:"seq"`
	Mine       bool   `json:"mine"`
	Ciphertext string `json:"ciphertext"`
}

type MessagesResponse struct {
	Messages []MessageDTO `json:"messages"`
}

type MarkReadRequest struct {
	Seq int64 `json:"seq"`
}
