// ========================================
// UI FUNCTIONS
// ========================================
// Rendering only: no network, no crypto. Every user- or server-supplied string
// reaches the DOM through textContent (never innerHTML).

const VIEW_IDS = ['mainMenu', 'loginContainer', 'registerContainer', 'appContainer'];

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

    // Start fake Account Number animation immediately
    startFakeAccountNumberGeneration(
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

function togglePairPanel(panelId) {
    ['invitePanel', 'joinPanel'].forEach(id => {
        const panel = document.getElementById(id);
        panel.style.display = id === panelId && panel.style.display === 'none' ? 'block' : 'none';
    });
}

function renderInvite(code, expiresAtSeconds) {
    const box = document.getElementById('inviteBox');
    const codeElement = document.getElementById('inviteCode');
    box.classList.remove('show');
    codeElement.classList.remove('revealed');
    codeElement.textContent = code;
    // Restart the same reveal transition the account number uses
    requestAnimationFrame(() => {
        box.classList.add('show');
        codeElement.classList.add('revealed');
    });
    document.getElementById('inviteExpiry').textContent = formatExpiry(expiresAtSeconds);
    document.getElementById('joinPanel').style.display = 'none';
    document.getElementById('invitePanel').style.display = 'block';
}

// items: [{ id, aura, unread }] in display order
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

function renderSafetyNumber(groups) {
    const box = document.getElementById('safetyNumber');
    clearChildren(box);
    groups.forEach(group => {
        const cell = document.createElement('span');
        cell.textContent = group;
        box.appendChild(cell);
    });
}

function createMessageElement(message) {
    const item = document.createElement('li');
    item.className = 'msg ' + (message.mine ? 'mine' : 'theirs') + (message.broken ? ' broken' : '');
    item.dataset.seq = String(message.seq);

    const text = document.createElement('div');
    text.className = 'msg-text';
    text.textContent = message.broken ? '⚠ unreadable — integrity check failed' : message.text;
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
    messages.forEach(message => list.appendChild(createMessageElement(message)));
    if (pinned || messages.some(m => m.mine)) {
        list.scrollTop = list.scrollHeight;
    }
}

function renderEmptyConversation() {
    const list = document.getElementById('messageList');
    if (list.children.length === 0) {
        const empty = document.createElement('li');
        empty.className = 'empty-message';
        empty.textContent = 'end-to-end encrypted. say hello.';
        list.appendChild(empty);
    }
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
