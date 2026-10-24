// ========================================
// PROOF OF WORK HELPER FUNCTIONS
// ========================================

// Trusted Types: the CSP allows exactly one policy, and it whitelists exactly one URL
const POW_WORKER_PATH = 'js/pow-worker.js';
const powWorkerPolicy = window.trustedTypes
    ? window.trustedTypes.createPolicy('noaddx-worker', {
        createScriptURL: (url) => {
            if (url !== POW_WORKER_PATH) {
                throw new TypeError('script URL not whitelisted');
            }
            return url;
        }
    })
    : null;

function powWorkerURL() {
    return powWorkerPolicy ? powWorkerPolicy.createScriptURL(POW_WORKER_PATH) : POW_WORKER_PATH;
}

// Get PoW challenge from backend
async function getPowChallenge() {
    try {
        const response = await fetchWithErrorHandling(`${API_BASE_URL}/pow/challenge`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            }
        });

        if (!response) {
            return null;
        }

        const data = await response.json();
        if (!data || !data.success || !data.challenge) {
            console.error('Invalid PoW challenge response');
            return null;
        }

        return data.challenge;
    } catch (error) {
        console.error('Error getting PoW challenge:', error);
        return null;
    }
}

// Solve PoW challenge using Web Worker
function solvePowChallenge(challenge) {
    return new Promise((resolve, reject) => {
        const worker = new Worker(powWorkerURL());

        worker.postMessage({
            challenge: challenge.challenge,
            difficulty: challenge.difficulty,
            salt: challenge.salt
        });

        worker.onmessage = function(e) {
            // Ignore progress updates, only process success/failure
            if (e.data.progress) {
                return;  // Continue computing
            }

            if (e.data.success === true) {
                resolve({
                    challenge: challenge.challenge,
                    solution: e.data.solution,
                    timestamp: challenge.timestamp,
                    ttl: challenge.ttl,
                    difficulty: challenge.difficulty,
                    salt: challenge.salt
                });
                worker.terminate();
            } else if (e.data.success === false) {
                reject(new Error('Processing failed'));
                worker.terminate();
            }
        };

        worker.onerror = function(error) {
            reject(error);
            worker.terminate();
        };
    });
}

// ========================================
// AUTHENTICATION FUNCTIONS
// ========================================

// Verifies the server holds the same public key this device derived, then opens the app.
// A mismatch means the server (or something in between) swapped the identity key.
async function enterApp(identity, persist) {
    const check = await apiCall('GET', '/me');
    const ttlDays = check.data && Number.isSafeInteger(check.data.message_ttl_days) ? check.data.message_ttl_days : 0;
    if (!check.ok || !check.data || check.data.public_key !== identity.publicKey || ttlDays < 1 || ttlDays > 365) {
        await Keystore.wipe();
        if (check.ok) {
            showError('identity mismatch — the server returned a different public key');
            await apiCall('POST', '/logout');
        }
        showMainMenu();
        return false;
    }
    if (persist) {
        await Keystore.save(identity);
    }
    await Chat.start(identity, ttlDays);
    return true;
}

async function login() {
    const accountNumberInputElement = document.getElementById('accountNumberInput');
    const errorElement = document.getElementById('loginError');
    const successElement = document.getElementById('loginSuccess');
    const loginBtn = document.getElementById('loginBtn');

    errorElement.textContent = '';
    successElement.textContent = '';

    // Check if eye animation is active and mask smoothly if needed
    if (window.eyeAnimation && window.eyeAnimation.currentZone !== 'none') {
        // Stop animation and get original value
        const originalValue = window.eyeAnimation.originalValue || accountNumberInputElement.value;
        window.eyeAnimation.stopAnimation();
        window.eyeAnimation.currentZone = 'none';
        window.eyeAnimation.resetToMasked();

        // Smoothly mask the input using existing animation
        await animateInputToMask(accountNumberInputElement, originalValue);

        // Restore original value after masking
        accountNumberInputElement.value = originalValue;
        accountNumberInputElement.type = 'password';
    }

    const accountNumberInput = accountNumberInputElement.value.trim();

    if (!accountNumberInput) {
        errorElement.textContent = 'please enter account number';
        return;
    }

    // Normalize & validate account number format safely
    const normalizedAccountNumber = String(accountNumberInput)
        .normalize('NFKC')   // Unicode look-alike cleanup
        .trim();             // Remove leading/trailing hidden whitespace

    if (normalizedAccountNumber.startsWith(NoaddxCrypto.INVITE_PREFIX)) {
        errorElement.textContent = 'that is an invite — log in first, then use join';
        return;
    }

    if (
        normalizedAccountNumber.length !== ACCOUNT_NUMBER_LEN ||
        !ACCOUNT_NUMBER_REGEX.test(normalizedAccountNumber)
    ) {
        errorElement.textContent = 'invalid format';
        return;
    }

    loginBtn.disabled = true;
    try {
        // ZERO-KNOWLEDGE: only HKDF(AccountNumber, "noaddx/auth") goes over the wire
        const authKey = await NoaddxCrypto.deriveAuthKey(normalizedAccountNumber);
        const response = await fetchWithErrorHandling(`${API_BASE_URL}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ auth_key: authKey })
        });

        // If fetchWithErrorHandling returned null, it means error was handled and redirected
        if (!response) {
            return;
        }

        const data = await response.json();

        if (!data) {
            errorElement.textContent = getUserFriendlyError(null, response.status);
            return;
        }

        if (data.success) {
            successElement.textContent = 'deriving your keys…';
            const identity = await NoaddxCrypto.deriveIdentity(normalizedAccountNumber);
            accountNumberInputElement.value = '';
            errorElement.textContent = '';
            successElement.textContent = '';
            await enterApp(identity, true);
        } else {
            // SECURITY: Map API error message to generic user-facing message
            const userMsg = getUserFriendlyError(data.message, response.status);
            errorElement.textContent = userMsg.toLowerCase();
        }
    } catch (error) {
        errorElement.textContent = 'request failed';
        console.error('Login error:', error && error.name);
    } finally {
        loginBtn.disabled = false;
    }
}

// Global variables for registration state
let scrambleInterval = null;
let pendingRegistrationAccountNumber = null;
let pendingRegistrationToken = null;  // Zero-trust: token from backend
let pendingRegistrationPoW = null;    // PoW solution from Phase 1

// Scramble animation: random characters cycle until the real AccountNumber arrives (visual only)
function startAccountNumberScramble(accountNumberElement, successElement, accountNumberDisplay) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    
    // Safety checks
    if (!accountNumberElement || !successElement || !accountNumberDisplay) {
        console.error('startAccountNumberScramble: missing required elements');
        return;
    }
    
    // Show the account number display area first
    accountNumberDisplay.style.display = 'block';
    const accountNumberBox = accountNumberDisplay.querySelector('.account-number-box');
    if (accountNumberBox) accountNumberBox.classList.add('show');
    
    successElement.textContent = 'Generating your special Account Number';
    accountNumberElement.classList.add('generating');
    
    // Clear any existing interval
    if (scrambleInterval) {
        clearInterval(scrambleInterval);
    }
    
    // Cycle base64url characters (A-Z, a-z, 0-9, _, -) until the real value arrives
    const base64urlChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
    scrambleInterval = setInterval(() => {
        let scrambled = '';
        for (let i = 0; i < ACCOUNT_NUMBER_LEN; i++) {
            // Mix of base64url characters and occasional * for visual interest
            if (Math.random() < 0.08) {
                scrambled += '*';
            } else {
                scrambled += base64urlChars.charAt(Math.floor(Math.random() * base64urlChars.length));
            }
        }
        accountNumberElement.textContent = scrambled;
    }, 120); // Fast scramble animation
}

// Stop the scramble animation
function stopAccountNumberScramble() {
    if (scrambleInterval) {
        clearInterval(scrambleInterval);
        scrambleInterval = null;
    }
}

// Copy button - get real Account Number from backend (but don't create account yet)
// Zero-trust: Backend returns a pending_token that we must use to confirm
async function copyAccountNumber() {
    const accountNumberElement = document.getElementById('generatedAccountNumber');
    const successElement = document.getElementById('registerSuccess');
    const errorElement = document.getElementById('registerError');
    const continueBtn = document.getElementById('continueBtn');
    const copyBtn = document.getElementById('copyBtn');
    
    // Disable copy button immediately to prevent multiple clicks
    if (copyBtn) {
        copyBtn.disabled = true;
    }
    
    // Stop the scramble animation
    stopAccountNumberScramble();
    
    // Show masking animation
    accountNumberElement.classList.remove('generating');
    accountNumberElement.classList.add('masking');
    successElement.textContent = 'securing your identifier...';
    
    // Animate to all asterisks
    await animateToMask(accountNumberElement);
    
    // First, get PoW challenge from backend
    successElement.textContent = 'Preparing security challenge...';

    try {
        const challenge = await getPowChallenge();
        if (!challenge) {
            throw new Error('Failed to get PoW challenge');
        }

        successElement.textContent = 'Securing your account...';

        // Solve the PoW challenge
        const powSolution = await solvePowChallenge(challenge);

        successElement.textContent = 'Generating your special Account Number';

        // Get Account Number from backend (Phase 1 - no account creation)
        const response = await fetchWithErrorHandling(`${API_BASE_URL}/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                confirm: false,
                pow: powSolution
            })
        });

        // If fetchWithErrorHandling returned null, it means error was handled and redirected
        if (!response) {
            // Re-enable copy button on error
            if (copyBtn) {
                copyBtn.disabled = false;
            }
            return;
        }

        const data = await response.json();
        
        if (!data || !data.success) {
            // SECURITY: Map API error message to generic user-facing message
            const userMsg = getUserFriendlyError(data?.message, response.status);
            errorElement.textContent = userMsg.toLowerCase();
            accountNumberElement.textContent = 'error - try again';
            // Re-enable copy button on error
            if (copyBtn) {
                copyBtn.disabled = false;
            }
            return;
        }

        const realAccountNumber = data.account_number;
        const pendingToken = data.pending_token;
        
        if (!realAccountNumber || realAccountNumber.length !== ACCOUNT_NUMBER_LEN || !pendingToken) {
            // SECURITY: Generic error message
            errorElement.textContent = getUserFriendlyError(null, response.status).toLowerCase();
            // Re-enable copy button on error
            if (copyBtn) {
                copyBtn.disabled = false;
            }
            return;
        }
        
        // Store pending AccountNumber and token for account creation on continue
        pendingRegistrationAccountNumber = realAccountNumber;
        pendingRegistrationToken = pendingToken;
        // Also store the PoW solution for the confirmation step
        pendingRegistrationPoW = powSolution;
        
        // Reveal the real AccountNumber with animation
        await revealRealAccountNumber(accountNumberElement, realAccountNumber);
        
        accountNumberElement.classList.remove('masking');
        accountNumberElement.classList.add('revealed');
        successElement.textContent = 'your account number is ready! click continue to create account.';
        
        // Copy to clipboard
        try {
            await copyToClipboard(realAccountNumber);
            showSuccess('Account number copied to clipboard!');
        } catch (e) {
            showWarning('Could not copy automatically. Please copy manually.');
        }
        
        // Enable continue button
        continueBtn.disabled = false;
        
    } catch (error) {
        // SECURITY: Generic error message, detailed error only in console
        errorElement.textContent = getUserFriendlyError(null, 500).toLowerCase();
        console.error('AccountNumber generation error:', error && error.name);
        accountNumberElement.textContent = 'error - try again';
        // Re-enable copy button on error
        if (copyBtn) {
            copyBtn.disabled = false;
        }
    }
}

// Animate AccountNumber to all asterisks (for display elements)
function animateToMask(accountNumberElement) {
    return new Promise((resolve) => {
        const currentText = accountNumberElement.textContent;
        const maskLength = currentText.length || ACCOUNT_NUMBER_LEN;
        let masked = currentText.split('');
        let step = 0;
        
        const maskInterval = setInterval(() => {
            // Mask 2-3 random characters per step
            for (let i = 0; i < 3; i++) {
                const randomIndex = Math.floor(Math.random() * maskLength);
                if (masked[randomIndex] !== undefined) {
                    masked[randomIndex] = '*';
                }
            }
            accountNumberElement.textContent = masked.join('');
            step++;
            
            // Check if all masked
            if (masked.every(c => c === '*') || step > 20) {
                clearInterval(maskInterval);
                accountNumberElement.textContent = '*'.repeat(maskLength);
                resolve();
            }
        }, 50);
    });
}

// Animate input field to all asterisks (for input elements)
function animateInputToMask(inputElement, originalValue) {
    return new Promise((resolve) => {
        const currentValue = inputElement.value || originalValue;
        let masked = currentValue.split('');
        let step = 0;
        
        // Show as text during animation
        inputElement.type = 'text';
        
        const maskInterval = setInterval(() => {
            // Mask 2-3 random characters per step
            for (let i = 0; i < 3; i++) {
                const randomIndex = Math.floor(Math.random() * masked.length);
                masked[randomIndex] = '*';
            }
            inputElement.value = masked.join('');
            step++;
            
            // Check if all masked
            if (masked.every(c => c === '*') || step > 20) {
                clearInterval(maskInterval);
                inputElement.value = '*'.repeat(masked.length);
                resolve();
            }
        }, 50);
    });
}

// Reveal the real AccountNumber character by character
function revealRealAccountNumber(accountNumberElement, realAccountNumber) {
    return new Promise((resolve) => {
        const totalLength = realAccountNumber.length;
        let revealed = '*'.repeat(totalLength).split('');
        let revealOrder = [];
        
        // Create random reveal order
        for (let i = 0; i < totalLength; i++) {
            revealOrder.push(i);
        }
        // Shuffle
        for (let i = revealOrder.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [revealOrder[i], revealOrder[j]] = [revealOrder[j], revealOrder[i]];
        }
        
        let step = 0;
        const revealInterval = setInterval(() => {
            // Reveal 2-3 characters per step
            for (let i = 0; i < 3 && step < totalLength; i++, step++) {
                const idx = revealOrder[step];
                revealed[idx] = realAccountNumber[idx];
            }
            accountNumberElement.textContent = revealed.join('');
            
            if (step >= totalLength) {
                clearInterval(revealInterval);
                accountNumberElement.textContent = realAccountNumber;
                resolve();
            }
        }, 40);
    });
}

async function continueWithAccountNumber() {
    const generatedAccountNumber = document.getElementById('generatedAccountNumber').textContent;
    const successElement = document.getElementById('registerSuccess');
    const errorElement = document.getElementById('registerError');

    // Validate that we have a real AccountNumber (not masked)
    if (!generatedAccountNumber || generatedAccountNumber.includes('*') || generatedAccountNumber.length !== ACCOUNT_NUMBER_LEN) {
        showError('Please generate your account number first');
        return;
    }

    // Zero-trust: We need the pending token from Phase 1
    if (!pendingRegistrationToken) {
        showError('Session expired. Please try again.');
        cancelRegistration();
        return;
    }

    successElement.textContent = 'preparing security challenge...';
    errorElement.textContent = '';

    try {
        // SECURITY: Phase 2 requires separate PoW (prevents Phase 1 replay)
        const challenge = await getPowChallenge();
        if (!challenge) {
            throw new Error('Failed to get PoW challenge for Phase 2');
        }

        successElement.textContent = 'securing your account...';
        const powSolution = await solvePowChallenge(challenge);

        successElement.textContent = 'creating your account...';

        // Phase 2: Create account using pending token (not Account Number from frontend)
        const response = await fetch(`${API_BASE_URL}/register`, {
            method: 'POST',
            credentials: 'include', // Send cookies (HttpOnly cookie will be set)
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                confirm: true,
                pending_token: pendingRegistrationToken,
                pow: powSolution
            })
        });

        if (!response.ok) {
            // Handle 409 Conflict specially (no status page for this)
            if (response.status === 409) {
                const data = await response.json().catch(() => ({}));
                // SECURITY: Generic error message
                const userMsg = getUserFriendlyError(data?.message || 'Unauthorized', response.status);
                errorElement.textContent = userMsg.toLowerCase();
                showError('Please try logging in instead.');
                return;
            }
            // For other errors, use error handler (will redirect to status pages)
            await handleErrorResponse(response, 'register');
            return;
        }

        const data = await response.json();

        if (!data.success) {
            // SECURITY: Map API error message to generic user-facing message
            const userMsg = getUserFriendlyError(data?.message, response.status);
            errorElement.textContent = userMsg.toLowerCase();
            showError('Please try again.');
            return;
        }

        // Account created: derive the E2E identity locally from the account number we hold
        successElement.textContent = 'deriving your keys…';
        const identity = await NoaddxCrypto.deriveIdentity(pendingRegistrationAccountNumber);

        // The account number was copied for the user to save; do not leave it in the clipboard
        // (clipboard histories and cross-device sync would keep it). Best effort only.
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText('').catch(() => {});
        }

        // Clear pending state
        pendingRegistrationAccountNumber = null;
        pendingRegistrationToken = null;
        pendingRegistrationPoW = null;
        document.getElementById('generatedAccountNumber').textContent = '';

        if (await enterApp(identity, true)) {
            showSuccess('welcome to noaddx.');
        }

    } catch (error) {
        // SECURITY: Generic error message, detailed error only in console
        console.error('Account creation error:', error && error.name);
        errorElement.textContent = getUserFriendlyError(null, 500).toLowerCase();
        showError('Please try again.');
    }
}

async function logout() {
    // Forget local key material first, then revoke every server session
    Chat.stop();
    await Keystore.wipe();
    await apiCall('POST', '/logout');
    showMainMenu();
    document.getElementById('accountNumberInput').value = '';
}

// Cancel registration - just go back (no account was created yet)
function cancelRegistration() {
    // Stop the scramble animation
    stopAccountNumberScramble();
    
    // Clear any pending state
    pendingRegistrationAccountNumber = null;
    pendingRegistrationToken = null;
    pendingRegistrationPoW = null;
    
    // Return to main menu
    showMainMenu();
}
