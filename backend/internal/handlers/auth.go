package handlers

import (
	"encoding/hex"
	"net/http"
	"strings"

	"noaddx/internal/auth"
	"noaddx/internal/encryption"
	"noaddx/internal/identity"
	"noaddx/internal/middleware"
	"noaddx/internal/models"
	"noaddx/internal/pow"
	"noaddx/internal/store"
	"noaddx/internal/utils"
)

var (
	authLogger     = utils.NewLogger("AUTH")
	userRepository = store.NewUserRepository()
)

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	authLogger.LogRequest(r.Method)
	authLogger.Debug("Starting RegisterHandler")

	// Handle HEAD requests (used by browsers/tools for link previews, health checks, etc.)
	if r.Method == http.MethodHead {
		authLogger.Debug("Handling HEAD request for registration endpoint")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.Method != http.MethodPost {
		authLogger.Warn("Invalid method for registration: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Prevent caching of sensitive responses
	w.Header().Set("Cache-Control", "no-store")

	// Parse request body
	var req models.RegisterRequest
	if err := utils.DecodeJSONRequest(r, &req); err != nil {
		// Empty body is OK - treat as generate AccountNumber only (confirm=false)
		authLogger.Debug("Empty or invalid body, treating as AccountNumber generation request")
		req.Confirm = false
	}

	// SECURITY: PoW is validated here and only here, for both phases, on the exact struct
	// the handler acts on (no second parser that could disagree about the body)
	if req.PoW == nil {
		authLogger.Warn("PoW solution missing for registration (confirm=%v)", req.Confirm)
		http.Error(w, "Proof of work required", http.StatusPreconditionFailed)
		return
	}
	if !pow.ValidateSolution(req.PoW) {
		authLogger.Warn("Invalid PoW solution for registration (confirm=%v)", req.Confirm)
		http.Error(w, "Invalid proof of work", http.StatusForbidden)
		return
	}

	// PHASE 1: Generate AccountNumber only (confirm=false)
	// Returns a pending registration token that must be used to confirm
	if !req.Confirm {
		authLogger.Debug("Phase 1: Generating AccountNumber preview (no account creation)")

		// Generate AccountNumber (256-bit CSPRNG, base64url encoded)
		accountNumber, err := utils.GenerateAccountNumber()
		if err != nil {
			authLogger.LogError("GenerateAccountNumber", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Compute lookup for collision check (almost impossible)
		previewAuthKey, err := identity.DeriveAuthKey(accountNumber)
		if err != nil {
			authLogger.LogError("DeriveAuthKey", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		lookup, err := auth.ComputeAccountLookup(previewAuthKey)
		if err != nil {
			authLogger.LogError("ComputeAccountLookup", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Check for collision - regenerate if needed (very unlikely but safe)
		exists, err := userRepository.ExistsByAccountLookup(lookup)
		if err != nil {
			authLogger.LogError("ExistsByAccountLookup", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if exists {
			// thanks user for almost impossible situation
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Generate pending ID and store AccountNumber server-side
		pendingID, err := auth.GeneratePendingID()
		if err != nil {
			authLogger.LogError("GeneratePendingID", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Store AccountNumber server-side with pending ID
		if err := auth.StorePendingRegistration(pendingID, accountNumber); err != nil {
			authLogger.LogError("StorePendingRegistration", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Generate pending registration token (contains pending ID, not AccountNumber)
		pendingToken, err := auth.SignPendingRegistrationToken(pendingID)
		if err != nil {
			authLogger.LogError("SignPendingRegistrationToken", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		responseData := models.RegisterResponse{
			Success:       true,
			Message:       "Account number generated - click continue to create account",
			AccountNumber: accountNumber,
			PendingToken:  pendingToken,
			Confirmed:     false,
		}
		utils.EncodeJSONResponse(w, responseData, http.StatusOK)
		authLogger.LogResponse(http.StatusOK, "AccountNumber preview generated with pending token")
		return
	}

	// PHASE 2: Create account (confirm=true)
	// ZERO-TRUST: Verify pending token and extract AccountNumber from it
	authLogger.Debug("Phase 2: Confirming account creation")

	// SECURITY: Phase 2 PoW was validated above with a fresh, single-use challenge
	// This prevents Phase 1 PoW replay and ensures fresh proof-of-work for expensive Argon2id

	if req.PendingToken == "" {
		authLogger.Warn("No pending token provided for account confirmation")
		http.Error(w, "Pending token required", http.StatusBadRequest)
		return
	}

	// Verify pending token and extract the AccountNumber from server-side store
	// Note: VerifyPendingRegistrationToken automatically deletes the pending registration (one-time use)
	pendingAccountNumber, err := auth.VerifyPendingRegistrationToken(req.PendingToken)
	if err != nil {
		// SECURITY: Generic error message to prevent information leakage
		// Don't distinguish between expired and invalid tokens
		authLogger.Warn("Invalid or expired pending registration token")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// ZERO-TRUST: AccountNumber comes from verified token, NOT from user input

	// ZERO-KNOWLEDGE LOGIN: the server keys the account by a derived auth key, so after this
	// request it never needs (or sees) the AccountNumber that also seeds the E2E identity
	authKey, err := identity.DeriveAuthKey(pendingAccountNumber)
	if err != nil {
		authLogger.LogError("DeriveAuthKey", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	publicKey, err := identity.DerivePublicKey(pendingAccountNumber)
	if err != nil {
		authLogger.LogError("DerivePublicKey", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Compute lookup and hash
	lookup, err := auth.ComputeAccountLookup(authKey)
	if err != nil {
		authLogger.LogError("ComputeAccountLookup", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Check if account already exists (race condition or replay attack)
	exists, err := userRepository.ExistsByAccountLookup(lookup)
	if err != nil {
		authLogger.LogError("ExistsByAccountLookup", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if exists {
		// SECURITY: Generic error message to prevent enumeration
		// Don't reveal that account exists - use same message as invalid token
		authLogger.Warn("Account already exists (possible replay)")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Hash auth key with Argon2id
	accountHash, err := auth.HashAccountNumber(authKey)
	if err != nil {
		authLogger.LogError("HashAccountNumber", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Generate internal user UUID (for backward compatibility and JWT subject)
	internalUUID, err := utils.GenerateInternalID()
	if err != nil {
		authLogger.LogError("GenerateInternalID", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Generate encryption key for user
	userAESKey, err := encryption.GenerateUserAESKey()
	if err != nil {
		authLogger.LogError("GenerateUserAESKey", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	userKeyHex := hex.EncodeToString(userAESKey)
	encryptedUserKey, err := encryption.EncryptWithMasterKey(userKeyHex)
	if err != nil {
		authLogger.LogError("EncryptWithMasterKey", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	masterKeyID := encryption.ActiveMasterKeyID()

	// ZERO-TRUST: identity public key is derived server-side from the verified AccountNumber,
	// never accepted from the client
	user := models.User{
		UUID:          internalUUID,
		AccountLookup: lookup,
		AccountHash:   accountHash,
		PublicKey:     publicKey,
		EncryptedKey:  encryptedUserKey,
		MasterKeyID:   masterKeyID,
	}

	if err := userRepository.Create(&user); err != nil {
		authLogger.LogError("UserRepository.Create", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	authLogger.Debug("New identity registered")

	// Generate JWT token for immediate login (using internal UUID as subject)
	token, err := auth.SignToken(internalUUID, user.SessionEpoch)
	if err != nil {
		authLogger.LogError("SignToken", err)
		// Account created but token failed - user can still login manually
		// SECURITY: Don't return AccountNumber in response
		responseData := models.RegisterResponse{
			Success:   true,
			Message:   "Account created successfully",
			Confirmed: true,
		}
		utils.EncodeJSONResponse(w, responseData, http.StatusCreated)
		return
	}

	// SECURITY: Set HttpOnly cookie (primary auth method for browsers - XSS protection)
	// Token also returned in response for API client compatibility
	auth.SetAuthCookie(w, token)

	// SECURITY: Don't return AccountNumber in response (already shown to user in Phase 1)
	// Prevents network sniffing and reduces information leakage
	responseData := models.RegisterResponse{
		Success:   true,
		Message:   "Account created successfully",
		Token:     token,
		Confirmed: true,
	}
	utils.EncodeJSONResponse(w, responseData, http.StatusCreated)
	authLogger.LogResponse(http.StatusCreated, "Account created successfully")
}

func PoWChallengeHandler(w http.ResponseWriter, r *http.Request) {
	authLogger.LogRequest(r.Method)
	authLogger.Debug("Starting PoWChallengeHandler")

	// Handle HEAD requests
	if r.Method == http.MethodHead {
		authLogger.Debug("Handling HEAD request for PoW challenge endpoint")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.Method != http.MethodGet {
		authLogger.Warn("Invalid method for PoW challenge: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Prevent caching of sensitive responses
	w.Header().Set("Cache-Control", "no-store")

	// Rate-limit key: HMAC(client IP) with a per-boot secret (forwarded headers trusted only from TRUSTED_PROXIES)
	challenge, err := pow.GenerateChallenge(middleware.ClientKey(r))
	if err != nil {
		authLogger.LogError("GenerateChallenge", err)
		if strings.Contains(err.Error(), "rate limit exceeded") {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	authLogger.Debug("Generated PoW challenge with difficulty: %d", challenge.Difficulty)

	responseData := models.PoWChallengeResponse{
		Success:   true,
		Message:   "PoW challenge generated successfully",
		Challenge: challenge,
	}

	utils.EncodeJSONResponse(w, responseData, http.StatusOK)
	authLogger.LogResponse(http.StatusOK, "PoW challenge generated successfully")
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	authLogger.LogRequest(r.Method)
	authLogger.Debug("Starting LoginHandler")

	// Handle HEAD requests (used by browsers/tools for link previews, health checks, etc.)
	if r.Method == http.MethodHead {
		authLogger.Debug("Handling HEAD request for login endpoint")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.Method != http.MethodPost {
		authLogger.Warn("Invalid method for login: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Prevent caching of sensitive responses
	w.Header().Set("Cache-Control", "no-store")

	var req models.LoginRequest
	if err := utils.DecodeJSONRequest(r, &req); err != nil {
		authLogger.LogError("DecodeJSONRequest", err)
		authLogger.Warn("Invalid JSON request for login")
		utils.EncodeJSONResponse(w, models.LoginResponse{Success: false, Message: "Invalid request"}, http.StatusBadRequest)
		return
	}
	// SECURITY: Validate auth key format (exactly 32 bytes, base64url) before any database operations
	// The client sends HKDF(AccountNumber, "noaddx/auth"); the AccountNumber itself never leaves the browser
	if !identity.ValidateEncodedKey(req.AuthKey) {
		authLogger.Warn("Invalid auth key format in login request")
		utils.EncodeJSONResponse(w, models.LoginResponse{Success: false, Message: "Invalid credentials"}, http.StatusUnauthorized)
		return
	}

	// Compute lookup for database query (only reached if format is valid)
	lookup, err := auth.ComputeAccountLookup(req.AuthKey)
	if err != nil {
		authLogger.LogError("ComputeAccountLookup", err)
		authLogger.Warn("Login failed: lookup computation error")
		utils.EncodeJSONResponse(w, models.LoginResponse{Success: false, Message: "Invalid credentials"}, http.StatusUnauthorized)
		return
	}

	// Apply per-account rate limit using lookup hash
	if !middleware.AllowAccountLookup(lookup) {
		authLogger.Warn("Login rate limit exceeded for account lookup")
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	// Find user by lookup
	user, err := userRepository.FindByAccountLookup(lookup)
	if err != nil {
		authLogger.LogError("UserRepository.FindByAccountLookup", err)
		authLogger.Warn("Login failed: user not found")
		// SECURITY: Spend a full Argon2id verification anyway to prevent a timing attack
		// This ensures user existence cannot be determined by response time
		// Even though OpenSSL Argon2id is constant-time within verification,
		// the absence of verification creates a timing side-channel
		auth.EqualizeVerificationTiming(req.AuthKey)
		utils.EncodeJSONResponse(w, models.LoginResponse{Success: false, Message: "Invalid credentials"}, http.StatusUnauthorized)
		return
	}

	// Verify auth key hash
	if err := auth.VerifyAccountNumberHash(user.AccountHash, req.AuthKey); err != nil {
		authLogger.Warn("Login failed: auth key hash verification failed")
		utils.EncodeJSONResponse(w, models.LoginResponse{Success: false, Message: "Invalid credentials"}, http.StatusUnauthorized)
		return
	}

	// Accounts created before the E2E identity existed cannot chat: treat as invalid
	if !identity.ValidateEncodedKey(user.PublicKey) {
		authLogger.Warn("Login failed: account has no identity key (legacy record)")
		utils.EncodeJSONResponse(w, models.LoginResponse{Success: false, Message: "Invalid credentials"}, http.StatusUnauthorized)
		return
	}

	authLogger.Debug("Successful login")

	// Generate JWT token (using internal UUID as subject)
	token, err := auth.SignToken(user.UUID, user.SessionEpoch)
	if err != nil {
		authLogger.LogError("SignToken", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// SECURITY: Set HttpOnly cookie (primary auth method for browsers - XSS protection)
	// Token also returned in response for API client compatibility
	auth.SetAuthCookie(w, token)

	responseData := models.LoginResponse{
		Success: true,
		Message: "Login successful",
		Token:   token,
	}
	utils.EncodeJSONResponse(w, responseData, http.StatusOK)
	authLogger.LogResponse(http.StatusOK, "LoginHandler completed successfully")
}
