// ========================================
// MAIN APPLICATION INITIALIZATION
// ========================================

// Check if current URL is a valid frontend route
function isValidFrontendRoute() {
    const path = window.location.pathname;

    // Allow root path
    if (path === '/' || path === '') {
        return true;
    }

    // Allow status pages (UUID HTML files) - these are handled by nginx
    const statusPagePattern = /^\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.html$/i;
    if (statusPagePattern.test(path)) {
        return true;
    }

    // Reject any other paths (including /api/*) - they don't exist in this SPA
    return false;
}

// Resume a session: needs both the stored (non-extractable) identity key and a live cookie
async function resumeSession() {
    const identity = await Keystore.load();
    if (!identity) {
        showMainMenu();
        return;
    }
    if (!(await enterApp(identity, false))) {
        showMainMenu();
    }
}

// Initialize event listeners when DOM is ready
document.addEventListener('DOMContentLoaded', async function() {
    // Check if current URL is valid for frontend
    if (!isValidFrontendRoute()) {
        // Redirect to 404 page for invalid routes
        window.location.replace('/e0ab670f-6801-4475-b337-c08d5adb9e73.html');
        return;
    }

    setupEventListeners();

    // WebCrypto X25519 + secure context are hard requirements (no JS crypto fallbacks)
    if (!window.isSecureContext || !(await NoaddxCrypto.isSupported())) {
        showMainMenu();
        document.getElementById('unsupportedNotice').textContent =
            'this browser cannot run noaddx. securely (needs https and WebCrypto X25519). update your browser.';
        document.getElementById('showLoginBtn').disabled = true;
        document.getElementById('showRegisterFormBtn').disabled = true;
        return;
    }

    await resumeSession();
});

function setupEventListeners() {
    // Main menu event listeners
    document.getElementById('showLoginBtn').addEventListener('click', showLogin);
    document.getElementById('showRegisterFormBtn').addEventListener('click', showRegisterForm);
    document.getElementById('backToMenuFromLogin').addEventListener('click', showMainMenu);

    // Brand title click - go back to main menu
    const loginBrandTitle = document.getElementById('loginBrandTitle');
    const registerBrandTitle = document.getElementById('registerBrandTitle');
    if (loginBrandTitle) {
        loginBrandTitle.addEventListener('click', showMainMenu);
    }
    if (registerBrandTitle) {
        registerBrandTitle.addEventListener('click', function() {
            // Cancel any pending registration first
            cancelRegistration();
        });
    }

    // Login page event listeners
    document.getElementById('loginBtn').addEventListener('click', login);
    document.getElementById('accountNumberInput').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') login();
    });

    // Register page event listeners
    document.getElementById('copyBtn').addEventListener('click', copyAccountNumber);
    document.getElementById('continueBtn').addEventListener('click', continueWithAccountNumber);
    document.getElementById('cancelRegistration').addEventListener('click', cancelRegistration);

    // App: header
    document.getElementById('logoutBtn').addEventListener('click', logout);
    document.getElementById('deleteIdentityBtn').addEventListener('click', () => {
        Chat.backToList();
        togglePairPanel('deletePanel');
        document.getElementById('deleteAccountInput').focus();
    });
    document.getElementById('closeDeleteBtn').addEventListener('click', () => {
        document.getElementById('deleteAccountInput').value = '';
        togglePairPanel(null);
    });
    document.getElementById('deleteConfirmBtn').addEventListener('click', deleteIdentity);
    document.getElementById('deleteAccountInput').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') deleteIdentity();
    });

    // App: pairing
    document.getElementById('newInviteBtn').addEventListener('click', () => Chat.createInvite());
    document.getElementById('showJoinBtn').addEventListener('click', () => {
        togglePairPanel('joinPanel');
        document.getElementById('inviteInput').focus();
    });
    document.getElementById('closeJoinBtn').addEventListener('click', () => togglePairPanel(null));
    document.getElementById('copyInviteBtn').addEventListener('click', async () => {
        const code = document.getElementById('inviteCode').textContent;
        if (!code) return;
        try {
            await copyToClipboard(code);
            showSuccess('invite copied');
        } catch (e) {
            showWarning('copy it manually');
        }
    });
    document.getElementById('joinBtn').addEventListener('click', () => Chat.join());
    document.getElementById('inviteInput').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') Chat.join();
    });

    // App: conversation
    document.getElementById('backToListBtn').addEventListener('click', () => Chat.backToList());
    document.getElementById('verifyBtn').addEventListener('click', () => Chat.showSafety());
    document.getElementById('markVerifiedBtn').addEventListener('click', () => Chat.toggleVerified());
    document.getElementById('burnBtn').addEventListener('click', () => Chat.askBurn(true));
    document.getElementById('burnNoBtn').addEventListener('click', () => Chat.askBurn(false));
    document.getElementById('burnYesBtn').addEventListener('click', () => Chat.burn());
    document.getElementById('sendBtn').addEventListener('click', () => Chat.send());

    // Composer: Enter to send, Shift+Enter for a new line
    const messageInput = document.getElementById('messageInput');
    messageInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
            e.preventDefault();
            Chat.send();
        }
    });
    messageInput.addEventListener('input', updateComposerMeta);

    // Escape leaves a conversation
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && document.getElementById('chatView').style.display !== 'none') {
            Chat.backToList();
        }
    });

    // Catch up after the tab was hidden or the machine slept
    document.addEventListener('visibilitychange', () => Chat.onVisible());
}
