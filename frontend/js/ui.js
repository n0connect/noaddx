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

const PAIR_PANELS = ['invitePanel', 'roomPanel', 'joinPanel', 'deletePanel'];

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

// items: [{ id, aura, unread, verified, room }] in display order
function renderConversationList(items, onOpen) {
    const list = document.getElementById('conversationList');
    clearChildren(list);

    if (items.length === 0) {
        const empty = document.createElement('li');
        empty.className = 'empty-message';
        empty.textContent = 'no conversations yet — invite someone you trust, or open a room and share its code';
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
        name.textContent = item.room ? roomName(item.aura) : item.aura.name;

        const code = document.createElement('span');
        code.className = 'aura-code';
        code.textContent = item.room ? roomMeta(item.room) : '·' + item.aura.code;

        const marker = document.createElement('span');
        marker.className = 'unread-marker';
        marker.textContent = item.unread ? 'new' : (item.room && item.room.notes > 0 ? 'request' : '›');

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

function showChatView(aura, room) {
    drawGlyph(document.getElementById('peerGlyph'), aura.grid);
    document.getElementById('peerName').textContent = room ? roomName(aura) : aura.name;
    document.getElementById('peerCode').textContent = room ? '' : '·' + aura.code;
    document.getElementById('safetyPanel').style.display = 'none';
    document.getElementById('burnConfirm').style.display = 'none';
    hideRoomPanels();
    // A room has members, a code and a member list; a pair has a safety number
    ['roomMeta', 'membersBtn', 'roomCodeBtn'].forEach(id => {
        document.getElementById(id).style.display = room ? 'inline' : 'none';
    });
    document.getElementById('verifyBtn').style.display = room ? 'none' : 'inline';
    document.getElementById('peerVerified').style.display = 'none';
    const burnButton = document.getElementById('burnBtn');
    burnButton.textContent = room && !room.owner ? 'leave' : 'burn';
    burnButton.title = room && !room.owner ? 'Leave room' : (room ? 'Burn room for everyone' : 'Burn conversation');
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

// A gap in a sender's counter: the server withheld, delayed or deleted their messages
function createGapElement(missing, from) {
    const item = document.createElement('li');
    item.className = 'msg-gap';
    const who = from || 'them';
    // The count comes from the sender's own counter; cap what we repeat back
    item.textContent = missing === 1
        ? `⚠ 1 message from ${who} never arrived`
        : missing <= 999 ? `⚠ ${missing} messages from ${who} never arrived` : `⚠ messages from ${who} never arrived`;
    return item;
}

function createMessageElement(message) {
    const item = document.createElement('li');
    item.className = 'msg ' + (message.mine ? 'mine' : 'theirs') + (message.broken ? ' broken' : '');
    item.dataset.seq = String(message.seq);

    // In a room, every message from someone else says who (their name in this room only)
    if (message.from && !message.broken) {
        const sender = document.createElement('div');
        sender.className = 'msg-sender';
        sender.textContent = message.left ? message.from + ' · left' : message.from;
        item.appendChild(sender);
    }

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
        message.gap ? createGapElement(message.gap, message.from) : createMessageElement(message)));
    if (pinned || messages.some(m => m.mine)) {
        list.scrollTop = list.scrollHeight;
    }
}

function renderEmptyConversation(ttlDays, room) {
    const list = document.getElementById('messageList');
    if (list.children.length === 0) {
        const empty = document.createElement('li');
        empty.className = 'empty-message';
        empty.textContent = room
            ? `encrypted for exactly the members listed. you only see what was sent after you joined. the room vanishes ${formatTimeLeft(room.expiresAt)}.`
            : `end-to-end encrypted. messages vanish after ${ttlDays} days. say hello.`;
        list.appendChild(empty);
    }
}

function setComposerHint(ttlDays) {
    document.getElementById('composerHint').textContent =
        `vanishes after ${ttlDays} days · enter to send · shift+enter for a new line`;
}

// Messages go with the room, or after the usual retention if that comes first
function setRoomComposerHint(expiresAt, ttlDays) {
    const vanish = Math.min(expiresAt, Date.now() + ttlDays * 86400000);
    document.getElementById('composerHint').textContent =
        `vanishes ${formatTimeLeft(vanish)} · enter to send · shift+enter for a new line`;
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

// "in 5h", "in 3d", "within the hour", "now"
function formatTimeLeft(atMs) {
    const left = atMs - Date.now();
    if (left <= 0) return 'now';
    const hours = Math.floor(left / 3600000);
    if (hours >= 48) return `in ${Math.floor(hours / 24)}d`;
    return hours >= 1 ? `in ${hours}h` : 'within the hour';
}

function formatExpiry(expiresAtSeconds) {
    const hours = Math.max(0, Math.round((expiresAtSeconds * 1000 - Date.now()) / 3600000));
    return hours >= 1 ? `in ${hours}h` : 'within the hour';
}

// ---------- rooms ----------
// A room's name comes from its id (the same for every member); people in it have their own
// per-room auras, which link to nothing outside the room.

function roomName(aura) {
    return '#' + aura.name;
}

function roomMeta(room) {
    return `${room.members}/${room.maxMembers} · ${formatTimeLeft(room.expiresAt)}`;
}

const ROOM_PANELS = ['membersPanel', 'notesPanel', 'roomCodePanel'];

function hideRoomPanels() {
    ROOM_PANELS.forEach(id => {
        document.getElementById(id).style.display = 'none';
    });
}

// Opens panelId alone (the notes panel stays as it is); returns whether it is now open
function toggleRoomPanel(panelId) {
    const panel = document.getElementById(panelId);
    const opening = panel.style.display === 'none';
    ['membersPanel', 'roomCodePanel', 'safetyPanel', 'burnConfirm'].forEach(id => {
        document.getElementById(id).style.display = 'none';
    });
    panel.style.display = opening ? 'block' : 'none';
    return opening;
}

function renderRoomHeader(room) {
    document.getElementById('roomMeta').textContent = roomMeta(room);
    const burnButton = document.getElementById('burnBtn');
    burnButton.textContent = room.owner ? 'burn' : 'leave';
}

function setBurnConfirm(room) {
    document.getElementById('burnConfirmText').textContent = !room
        ? 'burn for both sides? this cannot be undone.'
        : room.owner
            ? 'burn this room for everyone? this cannot be undone.'
            : 'leave this room? you can come back with the code while a seat is free.';
    document.getElementById('burnYesBtn').textContent = room && !room.owner ? 'leave' : 'burn';
}

// The creator's choices, within what this server allows
function setRoomLimits(maxMembers, ttlChoices) {
    const members = document.getElementById('roomMembersSelect');
    clearChildren(members);
    for (let n = NoaddxRoomCrypto.MIN_MEMBERS; n <= maxMembers; n++) {
        const option = document.createElement('option');
        option.value = String(n);
        option.textContent = `${n} people`;
        option.selected = n === Math.min(8, maxMembers);
        members.appendChild(option);
    }
    const ttl = document.getElementById('roomTtlSelect');
    clearChildren(ttl);
    ttlChoices.forEach(hours => {
        const option = document.createElement('option');
        option.value = String(hours);
        option.textContent = hours === 1 ? '1 hour' : hours % 24 === 0 ? `${hours / 24} day${hours === 24 ? '' : 's'}` : `${hours} hours`;
        option.selected = hours === 24 || ttlChoices.length === 1;
        ttl.appendChild(option);
    });
}

// While the proof of work runs the room code scrambles, as invites and account numbers do
function showRoomGenerating() {
    const codeElement = document.getElementById('roomCode');
    codeElement.classList.remove('masking', 'revealed');
    codeElement.classList.add('generating');
    document.getElementById('roomBox').style.display = 'flex';
    document.getElementById('roomBox').classList.add('show');
    document.getElementById('roomForm').style.display = 'none';
    document.getElementById('newRoomBtn').disabled = true;
    document.getElementById('copyRoomBtn').disabled = true;
    document.getElementById('roomHint').style.display = 'none';
    document.getElementById('roomStatus').style.display = 'block';
    showPairPanel('roomPanel');
    return startScramble(codeElement, NoaddxRoomCrypto.CODE_CHARS - NoaddxRoomCrypto.CODE_PREFIX.length, NoaddxRoomCrypto.CODE_PREFIX);
}

async function revealRoomCode(code, expiresAtSeconds) {
    const codeElement = document.getElementById('roomCode');
    codeElement.classList.remove('generating');
    codeElement.classList.add('masking');
    await animateToMask(codeElement, NoaddxRoomCrypto.CODE_PREFIX);
    await revealText(codeElement, code, NoaddxRoomCrypto.CODE_PREFIX);
    codeElement.classList.remove('masking');
    codeElement.classList.add('revealed');
    document.getElementById('roomExpiry').textContent = formatTimeLeft(expiresAtSeconds * 1000);
    document.getElementById('roomStatus').style.display = 'none';
    document.getElementById('roomHint').style.display = 'block';
    document.getElementById('copyRoomBtn').disabled = false;
    document.getElementById('newRoomBtn').disabled = false;
}

// Puts the room panel away and forgets the code it showed
function resetRoomPanel() {
    const codeElement = document.getElementById('roomCode');
    codeElement.classList.remove('generating', 'masking', 'revealed');
    codeElement.textContent = '';
    document.getElementById('roomPanel').style.display = 'none';
    document.getElementById('roomBox').style.display = 'none';
    document.getElementById('roomForm').style.display = 'flex';
    document.getElementById('roomStatus').style.display = 'none';
    document.getElementById('roomHint').style.display = 'block';
    document.getElementById('roomExpiry').textContent = 'when its time is up';
    document.getElementById('copyRoomBtn').disabled = false;
    document.getElementById('newRoomBtn').disabled = false;
}

function showRoomCode(code, expiresAt) {
    document.getElementById('roomCodeShown').textContent = code;
    document.getElementById('roomCodeHint').textContent =
        `anyone holding this code can join while a seat is free · the room vanishes ${formatTimeLeft(expiresAt)} · share it only over a channel you trust`;
}

function memberRow(entry) {
    const row = document.createElement('li');
    row.className = 'member-item';
    row.appendChild(createGlyph(entry.aura.grid));
    const name = document.createElement('span');
    name.className = 'aura-name';
    name.textContent = entry.aura.name;
    row.appendChild(name);
    const code = document.createElement('span');
    code.className = 'aura-code';
    code.textContent = '·' + entry.aura.code;
    row.appendChild(code);
    return row;
}

function memberTag(text) {
    const tag = document.createElement('span');
    tag.className = 'member-tag';
    tag.textContent = text;
    return tag;
}

// entries: verified roster; skipped: cards that failed to open (shown, never written to)
function renderMembers(entries, skipped, requested, onBefriend) {
    const list = document.getElementById('memberList');
    clearChildren(list);
    entries.forEach(entry => {
        const row = memberRow(entry);
        if (entry.mine) row.appendChild(memberTag('you'));
        if (entry.owner) row.appendChild(memberTag('owner'));
        if (!entry.mine) {
            const button = document.createElement('button');
            button.className = 'menu-opt member-action';
            const asked = requested.has(entry.publicKey);
            button.textContent = asked ? 'request sent' : 'befriend';
            button.disabled = asked;
            button.title = 'send them an invite only they can open';
            button.addEventListener('click', () => onBefriend(entry));
            row.appendChild(button);
        }
        list.appendChild(row);
    });
    if (skipped > 0) {
        const row = document.createElement('li');
        row.className = 'member-item member-broken';
        row.textContent = skipped === 1
            ? '⚠ 1 member card failed verification — nothing is encrypted for it'
            : `⚠ ${skipped} member cards failed verification — nothing is encrypted for them`;
        list.appendChild(row);
    }
}

function renderRoomSafety(groups) {
    const box = document.getElementById('roomSafetyNumber');
    clearChildren(box);
    groups.forEach(group => {
        const cell = document.createElement('span');
        cell.textContent = group;
        box.appendChild(cell);
    });
}

// notes: [{ id, aura, from }] friend requests addressed to this member
function renderNotes(notes, onAccept, onIgnore) {
    const panel = document.getElementById('notesPanel');
    const list = document.getElementById('noteList');
    clearChildren(list);
    panel.style.display = notes.length > 0 ? 'block' : 'none';
    notes.forEach(note => {
        const row = memberRow({ aura: note.aura });
        row.appendChild(memberTag(note.from ? 'wants to be friends' : 'left · wants to be friends'));
        const accept = document.createElement('button');
        accept.className = 'menu-opt member-action';
        accept.textContent = 'accept';
        accept.addEventListener('click', () => onAccept(note));
        const ignore = document.createElement('button');
        ignore.className = 'menu-opt';
        ignore.textContent = 'ignore';
        ignore.addEventListener('click', () => onIgnore(note));
        row.appendChild(accept);
        row.appendChild(ignore);
        list.appendChild(row);
    });
}
