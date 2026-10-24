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

type LoginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"` // JWT token
}

type RegisterResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	AccountNumber string `json:"account_number"`
	Token         string `json:"token,omitempty"`         // Only sent when confirm=true
	PendingToken  string `json:"pending_token,omitempty"` // Only sent when confirm=false
	Confirmed     bool   `json:"confirmed"`               // true if account was created
}

// ---- messaging ----

type MeResponse struct {
	PublicKey      string `json:"public_key"`
	MessageTTLDays int    `json:"message_ttl_days"` // ciphertext is deleted after this many days
}

type InviteResponse struct {
	Token     string `json:"token"`      // 16 random bytes, base64url; shown to the user once
	ExpiresAt int64  `json:"expires_at"` // Unix seconds
}

type RedeemInviteRequest struct {
	Token string `json:"token"`
}

type ConversationDTO struct {
	ID            string `json:"id"`
	PeerPublicKey string `json:"peer_public_key"`
	LastSeq       int64  `json:"last_seq"`
	ReadSeq       int64  `json:"read_seq"`
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
