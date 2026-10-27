// ========================================
// UI FUNCTIONS
// ========================================
// Rendering only: no network, no crypto. Every user- or server-supplied string
// reaches the DOM through textContent (never innerHTML).

const VIEW_IDS = ['mainMenu', 'loginContainer', 'registerContainer', 'appContainer'];

// Elements marked data-hidden start hidden through the stylesheet; the view code reads and
// toggles element.style.display, so mirror that state into it once (CSSOM, CSP-safe).
document.querySelectorAll('[data-hidden]').forEach(element => {
    element.style.display = 'none';
});

function setView(activeId) {
    VIEW_IDS.forEach(id => {
        document.getElementById(id).style.display = id === activeId ? 'block' : 'none';
    });
}

function showMainMenu() {
    setView('mainMenu');
}

function showLogin() {
    setView('loginContainer');
    document.getElementById('accountNumberInput').value = '';
    document.getElementById('loginError').textContent = '';
    document.getElementById('loginSuccess').textContent = '';

    // Re-initialize eye animation when login page is shown
    // This ensures animation works even if login page is dynamically displayed
    setTimeout(() => {
        if (typeof initEyeAnimation === 'function') {
            initEyeAnimation();
        }
        document.getElementById('accountNumberInput').focus();
    }, 100);
}

function showRegisterForm() {
    setView('registerContainer');
    document.getElementById('registerError').textContent = '';
    document.getElementById('registerSuccess').textContent = '';

    // Reset Account Number display state
    const accountNumberElement = document.getElementById('generatedAccountNumber');
    const continueBtn = document.getElementById('continueBtn');
    const copyBtn = document.getElementById('copyBtn');
    const accountNumberBox = document.querySelector('.account-number-box');

    accountNumberElement.textContent = '';
    accountNumberElement.classList.remove('generating', 'masking', 'revealed');
    continueBtn.disabled = true;
    if (copyBtn) {
        copyBtn.disabled = false;
    }
    if (accountNumberBox) accountNumberBox.classList.add('show');

    // Start the scramble animation immediately
    startAccountNumberScramble(
        accountNumberElement,
        document.getElementById('registerSuccess'),
        document.getElementById('accountNumberDisplay')
    );
}

function showApp() {
    setView('appContainer');
}

function clearChildren(element) {
    while (element.firstChild) {
        element.removeChild(element.firstChild);
    }
}

// ---------- scramble ----------
// Visual only: the noise is Math.random and never key material, and the real value is
// written only after it has arrived. A fixed prefix (the invite's "noaddx:") stays readable.

const SCRAMBLE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';

// Cycles random base64url characters (and an occasional '*') until the returned function is called
function startScramble(element, length, prefix = '') {
    const draw = () => {
        let scrambled = prefix;
        for (let i = 0; i < length; i++) {
            scrambled += Math.random() < 0.08 ? '*' : SCRAMBLE_CHARS.charAt(Math.floor(Math.random() * SCRAMBLE_CHARS.length));
        }
        element.textContent = scrambled;
    };
    draw();
    const timer = setInterval(draw, 120);
    return () => clearInterval(timer);
}

// Turns the characters after the prefix into '*', a few per step
function animateToMask(element, prefix = '') {
    return new Promise((resolve) => {
        const masked = element.textContent.slice(prefix.length).split('');
        let step = 0;
        const timer = setInterval(() => {
            for (let i = 0; i < 3; i++) {
                const index = Math.floor(Math.random() * masked.length);
                if (masked[index] !== undefined) {
                    masked[index] = '*';
                }
            }
            element.textContent = prefix + masked.join('');
            step++;
            if (masked.every(c => c === '*') || step > 20) {
                clearInterval(timer);
                element.textContent = prefix + '*'.repeat(masked.length);
                resolve();
            }
        }, 50);
    });
}

// Replaces the mask with the real value in a random order, a few characters per step
function revealText(element, value, prefix = '') {
    return new Promise((resolve) => {
        const body = value.slice(prefix.length);
        const shown = '*'.repeat(body.length).split('');
        const order = Array.from(shown.keys());
        for (let i = order.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [order[i], order[j]] = [order[j], order[i]];
        }
        let step = 0;
        const timer = setInterval(() => {
            for (let i = 0; i < 3 && step < order.length; i++, step++) {
                shown[order[step]] = body[order[step]];
            }
            element.textContent = prefix + shown.join('');
            if (step >= order.length) {
                clearInterval(timer);
                element.textContent = value;
                resolve();
            }
        }, 40);
    });
}

// ---------- aura ----------

// Draws a mirrored 5x5 pixel glyph; CSS scales it up with image-rendering: pixelated
function drawGlyph(canvas, grid) {
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.clearRect(0, 0, 5, 5);
    ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--fg').trim() || '#000';
    for (let row = 0; row < 5; row++) {
        for (let col = 0; col < 5; col++) {
            if (grid[row][col]) {
                ctx.fillRect(col, row, 1, 1);
            }
        }
    }
}

function createGlyph(grid) {
    const canvas = document.createElement('canvas');
    canvas.width = 5;
    canvas.height = 5;
    canvas.className = 'aura-glyph';
    drawGlyph(canvas, grid);
    return canvas;
}

function renderMe(aura) {
    drawGlyph(document.getElementById('meGlyph'), aura.grid);
    document.getElementById('meName').textContent = aura.name;
    document.getElementById('meBadge').title = 'you are ' + aura.name + ' · ' + aura.code;
}

// ---------- home ----------

function showHome() {
    document.getElementById('chatView').style.display = 'none';
    document.getElementById('homeView').style.display = 'block';
}

const PAIR_PANELS = ['invitePanel', 'joinPanel', 'deletePanel'];

// Opens panelId alone, or closes every pair panel when it is already open (or null)
function togglePairPanel(panelId) {
    PAIR_PANELS.forEach(id => {
        const panel = document.getElementById(id);
        panel.style.display = id === panelId && panel.style.display === 'none' ? 'block' : 'none';
    });
}

// Opens panelId and closes the others, whatever was open
function showPairPanel(panelId) {
    PAIR_PANELS.forEach(id => {
        document.getElementById(id).style.display = id === panelId ? 'block' : 'none';
    });
}

// While the proof of work runs, the invite scrambles exactly like a new account number does.
// Returns the function that stops the scramble.
function showInviteGenerating() {
    const codeElement = document.getElementById('inviteCode');
    codeElement.classList.remove('masking', 'revealed');
    codeElement.classList.add('generating');
    document.getElementById('inviteBox').classList.add('show');
    document.getElementById('newInviteBtn').disabled = true;
    document.getElementById('copyInviteBtn').disabled = true;
    document.getElementById('inviteHint').style.display = 'none';
    document.getElementById('inviteStatus').style.display = 'block';
    showPairPanel('invitePanel');
    return startScramble(codeElement, NoaddxCrypto.INVITE_BODY_CHARS, NoaddxCrypto.INVITE_PREFIX);
}

// Masks the noise, then reveals the real code (the account number's sequence)
async function revealInvite(code, expiresAtSeconds) {
    const codeElement = document.getElementById('inviteCode');
    codeElement.classList.remove('generating');
    codeElement.classList.add('masking');
    await animateToMask(codeElement, NoaddxCrypto.INVITE_PREFIX);
    await revealText(codeElement, code, NoaddxCrypto.INVITE_PREFIX);
    codeElement.classList.remove('masking');
    codeElement.classList.add('revealed');
    document.getElementById('inviteExpiry').textContent = formatExpiry(expiresAtSeconds);
    document.getElementById('inviteStatus').style.display = 'none';
    document.getElementById('inviteHint').style.display = 'block';
    document.getElementById('copyInviteBtn').disabled = false;
    document.getElementById('newInviteBtn').disabled = false;
}

// Puts the invite panel away and forgets the code it showed
function resetInvitePanel() {
    const codeElement = document.getElementById('inviteCode');
    codeElement.classList.remove('generating', 'masking', 'revealed');
    codeElement.textContent = '';
    document.getElementById('invitePanel').style.display = 'none';
    document.getElementById('inviteStatus').style.display = 'none';
    document.getElementById('inviteHint').style.display = 'block';
    document.getElementById('copyInviteBtn').disabled = false;
    document.getElementById('newInviteBtn').disabled = false;
}

// items: [{ id, aura, unread, verified }] in display order
function renderConversationList(items, onOpen) {
    const list = document.getElementById('conversationList');
    clearChildren(list);

    if (items.length === 0) {
        const empty = document.createElement('li');
        empty.className = 'empty-message';
        empty.textContent = 'no conversations yet — create an invite and send it to someone you trust';
        list.appendChild(empty);
        return;
    }

    items.forEach(item => {
        const row = document.createElement('li');
        row.className = 'conversation-item' + (item.unread ? ' unread' : '');
        row.tabIndex = 0;
        row.dataset.id = item.id;

        const name = document.createElement('span');
        name.className = 'aura-name';
        name.textContent = item.aura.name;

        const code = document.createElement('span');
        code.className = 'aura-code';
        code.textContent = '·' + item.aura.code;

        const marker = document.createElement('span');
        marker.className = 'unread-marker';
        marker.textContent = item.unread ? 'new' : '›';

        row.appendChild(createGlyph(item.aura.grid));
        row.appendChild(name);
        row.appendChild(code);
        if (item.verified) {
            const verified = document.createElement('span');
            verified.className = 'verified-mark';
            verified.title = 'safety number verified on this device';
            verified.textContent = '✓';
            row.appendChild(verified);
        }
        row.appendChild(marker);
        row.addEventListener('click', () => onOpen(item.id));
        row.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') onOpen(item.id);
        });
        list.appendChild(row);
    });
}

// ---------- chat ----------

function showChatView(aura) {
    drawGlyph(document.getElementById('peerGlyph'), aura.grid);
    document.getElementById('peerName').textContent = aura.name;
    document.getElementById('peerCode').textContent = '·' + aura.code;
    document.getElementById('safetyPanel').style.display = 'none';
    document.getElementById('burnConfirm').style.display = 'none';
    clearChildren(document.getElementById('messageList'));
    document.getElementById('homeView').style.display = 'none';
    document.getElementById('chatView').style.display = 'block';
}

function setVerifiedState(verified) {
    document.getElementById('peerVerified').style.display = verified ? 'inline' : 'none';
    const button = document.getElementById('markVerifiedBtn');
    button.textContent = verified ? '✓ verified — unmark' : 'mark as verified';
    button.classList.toggle('active', verified);
}

function renderSafetyNumber(groups) {
    const box = document.getElementById('safetyNumber');
    clearChildren(box);
    groups.forEach(group => {
        const cell = document.createElement('span');
        cell.textContent = group;
        box.appendChild(cell);
    });
}

// A gap in the peer's counter: the server withheld, delayed or deleted their messages
function createGapElement(missing) {
    const item = document.createElement('li');
    item.className = 'msg-gap';
    // The count comes from the peer's own counter; cap what we repeat back
    item.textContent = missing === 1
        ? '⚠ 1 message from them never arrived'
        : missing <= 999 ? `⚠ ${missing} messages from them never arrived` : '⚠ messages from them never arrived';
    return item;
}

function createMessageElement(message) {
    const item = document.createElement('li');
    item.className = 'msg ' + (message.mine ? 'mine' : 'theirs') + (message.broken ? ' broken' : '');
    item.dataset.seq = String(message.seq);

    const text = document.createElement('div');
    text.className = 'msg-text';
    text.textContent = message.broken ? '⚠ unreadable — integrity check failed' : neutralizeReceivedText(message.text);
    item.appendChild(text);

    if (!message.broken) {
        const time = document.createElement('div');
        time.className = 'msg-time';
        time.textContent = formatTime(message.sentAt);
        item.appendChild(time);
    }
    return item;
}

// Appends messages (already sorted by seq) and keeps the view pinned to the bottom
function appendMessages(messages) {
    const list = document.getElementById('messageList');
    const pinned = list.scrollHeight - list.scrollTop - list.clientHeight < 48;
    const empty = list.querySelector('.empty-message');
    if (empty && messages.length > 0) {
        empty.remove();
    }
    messages.forEach(message => list.appendChild(
        message.gap ? createGapElement(message.gap) : createMessageElement(message)));
    if (pinned || messages.some(m => m.mine)) {
        list.scrollTop = list.scrollHeight;
    }
}

function renderEmptyConversation(ttlDays) {
    const list = document.getElementById('messageList');
    if (list.children.length === 0) {
        const empty = document.createElement('li');
        empty.className = 'empty-message';
        empty.textContent = `end-to-end encrypted. messages vanish after ${ttlDays} days. say hello.`;
        list.appendChild(empty);
    }
}

function setComposerHint(ttlDays) {
    document.getElementById('composerHint').textContent =
        `vanishes after ${ttlDays} days · enter to send · shift+enter for a new line`;
}

function updateComposerMeta() {
    const input = document.getElementById('messageInput');
    document.getElementById('charCount').textContent = `${[...input.value].length}/${MAX_MESSAGE_CHARS}`;
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 140) + 'px';
}

// ---------- formatting ----------

function formatTime(ms) {
    const date = new Date(ms);
    const now = new Date();
    const hhmm = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
    if (date.toDateString() === now.toDateString()) {
        return hhmm;
    }
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + ' ' + hhmm;
}

function formatExpiry(expiresAtSeconds) {
    const hours = Math.max(0, Math.round((expiresAtSeconds * 1000 - Date.now()) / 3600000));
    return hours >= 1 ? `in ${hours}h` : 'within the hour';
}
