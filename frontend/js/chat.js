// ========================================
// CHAT (state, sync, realtime)
// ========================================
// The server is treated as an untrusted relay: every response is shape-checked,
// every message is authenticated by AES-GCM + AAD, peer keys from invites are
// verified against the fingerprint embedded in the invite code, and gaps in the
// peer's encrypted message counter expose messages the server withheld.

const Chat = (() => {
    'use strict';

    const MAX_RECONNECT_ATTEMPTS = 8;
    const RECONNECT_BASE_MS = 1000;
    const RECONNECT_MAX_MS = 30000;
    const MAX_CIPHERTEXT_CHARS = 11000;

    let me = null;                    // { privateKey, publicKey, aura, ttlDays }
    const conversations = new Map();  // id -> conversation state
    let order = [];                   // server order: newest conversation first
    let recent = [];                  // ids with activity this session, most recent first (memory only)
    let activeId = null;
    let events = null;
    let reconnectAttempts = 0;
    let reconnectTimer = null;
    let refreshTimer = null;
    let listLoaded = false;           // distinguishes the first load from live additions

    // ---------- plumbing ----------

    async function api(method, path, body) {
        const result = await apiCall(method, path, body);
        if (result.status === 401) {
            sessionLost();
        }
        return result;
    }

    function sessionLost() {
        if (!me) return;
        stop();
        Keystore.wipe();
        showWarning('session ended — log in again');
        showLogin();
    }

    function isSeq(value) {
        return Number.isSafeInteger(value) && value >= 0;
    }

    function isPublicKey(value) {
        try {
            NoaddressCrypto.b64urlDecode(value, 32);
            return true;
        } catch (e) {
            return false;
        }
    }

    function conversationKey(conv) {
        if (!conv.key) {
            conv.key = NoaddressCrypto.conversationKey(me.privateKey, conv.peerPublicKey, conv.id);
        }
        return conv.key;
    }

    function updateTitle() {
        let unread = 0;
        conversations.forEach(conv => {
            if (conv.id !== activeId && conv.lastSeq > conv.readSeq) unread++;
        });
        document.title = unread > 0 ? `(${unread}) noaddress.` : 'noaddress.';
    }

    // The server keeps no cross-conversation recency, so ordering is decided here:
    // unread first, then activity seen during this session, then newest conversation
    function renderList() {
        const rank = id => {
            const r = recent.indexOf(id);
            return r === -1 ? recent.length + order.indexOf(id) : r;
        };
        const items = order.filter(id => conversations.has(id)).map(id => {
            const conv = conversations.get(id);
            return { id: conv.id, aura: conv.aura, unread: conv.lastSeq > conv.readSeq, verified: conv.verified };
        });
        items.sort((a, b) => (b.unread - a.unread) || (rank(a.id) - rank(b.id)));
        renderConversationList(items, open);
        updateTitle();
    }

    function bump(id) {
        recent = [id].concat(recent.filter(other => other !== id));
    }

    // ---------- lifecycle ----------

    async function start(identity, ttlDays) {
        me = {
            privateKey: identity.privateKey,
            publicKey: identity.publicKey,
            aura: await NoaddressCrypto.aura(identity.publicKey),
            ttlDays: ttlDays
        };
        renderMe(me.aura);
        setComposerHint(ttlDays);
        showHome();
        showApp();
        await refreshConversations();
        connectEvents();
    }

    function stop() {
        closeEvents();
        clearTimeout(refreshTimer);
        conversations.clear();
        order = [];
        recent = [];
        activeId = null;
        listLoaded = false;
        me = null;
        clearChildren(document.getElementById('conversationList'));
        clearChildren(document.getElementById('messageList'));
        document.getElementById('inviteCode').textContent = '';
        document.getElementById('inviteInput').value = '';
        document.getElementById('messageInput').value = '';
        document.title = 'noaddress.';
    }

    // ---------- conversations ----------

    async function refreshConversations() {
        const result = await api('GET', '/conversations');
        if (!me) return;
        if (!result.ok || !result.data || !Array.isArray(result.data.conversations)) {
            if (result.status !== 401) showError('could not load conversations');
            return;
        }

        const seen = new Set();
        const nextOrder = [];
        let joined = false;
        for (const item of result.data.conversations) {
            if (!item || !validateConversationId(item.id) || !isPublicKey(item.peer_public_key) ||
                !isSeq(item.last_seq) || !isSeq(item.read_seq) || seen.has(item.id)) {
                continue;
            }
            seen.add(item.id);
            nextOrder.push(item.id);
            const existing = conversations.get(item.id);
            if (existing) {
                if (existing.peerPublicKey !== item.peer_public_key) {
                    // A conversation's key can never change; treat as tampering
                    showError('peer key changed unexpectedly — conversation hidden');
                    conversations.delete(item.id);
                    continue;
                }
                existing.lastSeq = Math.max(existing.lastSeq, item.last_seq);
                existing.readSeq = Math.max(existing.readSeq, item.read_seq);
            } else {
                joined = joined || listLoaded;
                conversations.set(item.id, {
                    id: item.id,
                    peerPublicKey: item.peer_public_key,
                    aura: await NoaddressCrypto.aura(item.peer_public_key),
                    verified: await Keystore.isVerified(item.id, item.peer_public_key),
                    myMaxN: 0,
                    peerLastN: 0,
                    lastSeq: item.last_seq,
                    readSeq: item.read_seq,
                    maxSeq: 0,
                    seqs: new Set(),
                    ids: new Set(),
                    loaded: false,
                    key: null,
                    syncChain: Promise.resolve()
                });
            }
        }

        for (const id of Array.from(conversations.keys())) {
            if (!seen.has(id)) {
                conversations.delete(id);
                if (activeId === id) {
                    activeId = null;
                    showHome();
                    showWarning('this conversation was burned');
                }
            }
        }
        order = nextOrder;
        listLoaded = true;
        renderList();

        // Someone redeemed an invite: the code on screen is spent, so put it away
        if (joined && document.getElementById('invitePanel').style.display !== 'none') {
            togglePairPanel(null);
            showSuccess('someone joined with your invite');
        }
    }

    function scheduleRefresh() {
        clearTimeout(refreshTimer);
        refreshTimer = setTimeout(refreshConversations, 250);
    }

    async function open(id) {
        const conv = conversations.get(id);
        if (!conv) return;
        activeId = id;
        showChatView(conv.aura);
        conv.seqs = new Set();
        conv.ids = new Set();
        conv.maxSeq = 0;
        conv.myMaxN = 0;
        conv.peerLastN = 0;
        conv.loaded = false;
        setVerifiedState(conv.verified);
        await sync(conv);
        if (activeId === id) {
            renderEmptyConversation(me.ttlDays);
            document.getElementById('messageInput').focus();
        }
    }

    function backToList() {
        activeId = null;
        showHome();
        renderList();
    }

    // ---------- messages ----------

    // Serialised per conversation so SSE pokes and manual opens never interleave
    function sync(conv) {
        conv.syncChain = conv.syncChain.then(() => syncNow(conv)).catch(() => {});
        return conv.syncChain;
    }

    async function syncNow(conv) {
        const path = conv.loaded
            ? `/conversations/${conv.id}/messages?after=${conv.maxSeq}`
            : `/conversations/${conv.id}/messages`;
        const result = await api('GET', path);
        if (!me || activeId !== conv.id) return;
        if (result.status === 404) {
            scheduleRefresh();
            return;
        }
        if (!result.ok || !result.data || !Array.isArray(result.data.messages)) {
            showError('could not load messages');
            return;
        }
        conv.loaded = true;

        const key = await conversationKey(conv);
        const fresh = [];
        for (const raw of result.data.messages) {
            if (!raw || !NoaddressCrypto.isUuidV4(raw.id) || !isSeq(raw.seq) || raw.seq === 0 ||
                typeof raw.mine !== 'boolean' || typeof raw.ciphertext !== 'string' ||
                raw.ciphertext.length > MAX_CIPHERTEXT_CHARS || conv.seqs.has(raw.seq) || raw.seq <= conv.maxSeq ||
                conv.ids.has(raw.id)) {
                // Unknown shape, or a message id seen before (a server re-serving an old ciphertext)
                continue;
            }
            const sender = raw.mine ? me.publicKey : conv.peerPublicKey;
            let message;
            try {
                const plain = await NoaddressCrypto.decryptMessage(key, conv.id, raw.id, sender, raw.ciphertext);
                message = { seq: raw.seq, mine: raw.mine, text: plain.text, sentAt: plain.sentAt };
                if (raw.mine) {
                    conv.myMaxN = Math.max(conv.myMaxN, plain.counter);
                } else {
                    // The first visible peer message is the baseline (older ones may have expired)
                    if (conv.peerLastN > 0 && plain.counter > conv.peerLastN + 1) {
                        fresh.push({ gap: plain.counter - conv.peerLastN - 1 });
                    }
                    conv.peerLastN = Math.max(conv.peerLastN, plain.counter);
                }
            } catch (e) {
                message = { seq: raw.seq, mine: raw.mine, broken: true };
            }
            conv.seqs.add(raw.seq);
            conv.ids.add(raw.id);
            conv.maxSeq = raw.seq;
            fresh.push(message);
        }
        if (activeId !== conv.id) return;

        appendMessages(fresh);
        conv.lastSeq = Math.max(conv.lastSeq, conv.maxSeq);
        await markRead(conv);
    }

    async function markRead(conv) {
        if (conv.maxSeq > conv.readSeq) {
            conv.readSeq = conv.maxSeq;
            await api('POST', `/conversations/${conv.id}/read`, { seq: conv.maxSeq });
        }
        updateTitle();
    }

    async function send() {
        const conv = conversations.get(activeId);
        const input = document.getElementById('messageInput');
        const sendBtn = document.getElementById('sendBtn');
        if (!conv || sendBtn.disabled) return;

        const validation = validateMessageText(input.value);
        if (!validation.valid) {
            if (input.value.trim() !== '') showError(validation.error);
            return;
        }

        sendBtn.disabled = true;
        try {
            const id = NoaddressCrypto.newMessageId();
            const sentAt = Date.now();
            const key = await conversationKey(conv);
            const ciphertext = await NoaddressCrypto.encryptMessage(key, conv.id, id, me.publicKey, validation.sanitized, sentAt, conv.myMaxN + 1);
            const result = await api('POST', `/conversations/${conv.id}/messages`, { id: id, ciphertext: ciphertext });

            if (result.ok && result.data && isSeq(result.data.seq) && result.data.seq > 0) {
                input.value = '';
                updateComposerMeta();
                bump(conv.id);
                await sync(conv);
            } else if (result.status === 429) {
                showWarning('slow down — too many messages');
            } else if (result.status === 404) {
                scheduleRefresh();
            } else if (result.status !== 401) {
                showError('message not sent');
            }
        } catch (e) {
            showError('message not sent');
        } finally {
            sendBtn.disabled = false;
            input.focus();
        }
    }

    // ---------- pairing ----------

    async function createInvite() {
        const result = await api('POST', '/invites');
        if (result.status === 429) {
            showWarning('invite limit reached — wait for one to be used or expire');
            return;
        }
        if (!result.ok || !result.data || typeof result.data.token !== 'string' || !Number.isSafeInteger(result.data.expires_at)) {
            if (result.status !== 401) showError('could not create invite');
            return;
        }
        let code;
        try {
            code = await NoaddressCrypto.buildInviteCode(result.data.token, me.publicKey);
        } catch (e) {
            showError('server returned a malformed invite');
            return;
        }
        renderInvite(code, result.data.expires_at);
        try {
            await copyToClipboard(code);
            showSuccess('invite copied');
        } catch (e) {
            showWarning('copy it manually');
        }
    }

    async function join() {
        const input = document.getElementById('inviteInput');
        const validation = validateInviteCode(input.value);
        if (!validation.valid) {
            showError(validation.error);
            return;
        }
        const invite = validation.sanitized;
        if (await NoaddressCrypto.fingerprintMatches(invite, me.publicKey)) {
            showWarning('that is your own invite — send it to someone else');
            return;
        }

        const result = await api('POST', '/invites/redeem', { token: invite.token });
        if (result.status === 404) {
            showError('invite expired or already used');
            return;
        }
        if (result.status === 429) {
            showWarning('too many attempts — wait a moment');
            return;
        }
        const conv = result.data && result.data.conversation;
        if (!result.ok || !conv || !validateConversationId(conv.id) || !isPublicKey(conv.peer_public_key)) {
            if (result.status !== 401) showError('could not join');
            return;
        }

        // The server chose which key we got; the invite code says which key we should get
        if (!(await NoaddressCrypto.fingerprintMatches(invite, conv.peer_public_key))) {
            await api('DELETE', `/conversations/${conv.id}`);
            showError('verification FAILED: the server substituted the peer key. conversation burned.');
            return;
        }

        input.value = '';
        togglePairPanel(null);
        await refreshConversations();
        showSuccess('connected');
        await open(conv.id);
    }

    // ---------- conversation actions ----------

    async function toggleVerified() {
        const conv = conversations.get(activeId);
        if (!conv) return;
        const next = !conv.verified;
        if (!(await Keystore.setVerified(conv.id, conv.peerPublicKey, next))) {
            showWarning('could not save verification on this device');
            return;
        }
        conv.verified = next;
        setVerifiedState(next);
        if (next) showSuccess('marked as verified on this device');
    }

    async function showSafety() {
        const conv = conversations.get(activeId);
        const panel = document.getElementById('safetyPanel');
        if (!conv) return;
        if (panel.style.display !== 'none') {
            panel.style.display = 'none';
            return;
        }
        renderSafetyNumber(await NoaddressCrypto.safetyNumber(me.publicKey, conv.peerPublicKey));
        panel.style.display = 'block';
    }

    function askBurn(show) {
        document.getElementById('burnConfirm').style.display = show ? 'flex' : 'none';
    }

    async function burn() {
        const id = activeId;
        askBurn(false);
        if (!id) return;
        const result = await api('DELETE', `/conversations/${id}`);
        if (result.status === 204 || result.status === 404) {
            conversations.delete(id);
            backToList();
            showSuccess('burned');
            scheduleRefresh();
        } else if (result.status !== 401) {
            showError('could not burn conversation');
        }
    }

    // ---------- realtime ----------

    function closeEvents() {
        clearTimeout(reconnectTimer);
        if (events) {
            events.close();
            events = null;
        }
    }

    function connectEvents() {
        closeEvents();
        if (!me) return;
        events = new EventSource(`${API_BASE_URL}/events`);
        events.addEventListener('open', () => {
            reconnectAttempts = 0;
            resync();
        });
        events.addEventListener('msg', onMessageEvent);
        events.addEventListener('conv', scheduleRefresh);
        // Never rely on the browser's built-in retry (fixed interval, unlimited attempts):
        // every drop goes through our bounded exponential backoff (RULES.md §17.1)
        events.onerror = () => {
            scheduleReconnect();
        };
    }

    function scheduleReconnect() {
        closeEvents();
        if (!me) return;
        const delay = Math.min(RECONNECT_MAX_MS, RECONNECT_BASE_MS * 2 ** reconnectAttempts);
        if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
            showWarning('live updates paused — reload to resume');
            return;
        }
        reconnectAttempts++;
        reconnectTimer = setTimeout(reconnect, delay);
    }

    // Only reconnect while the session is still valid (a 401 ends the session instead)
    async function reconnect() {
        if (!me) return;
        const check = await api('GET', '/me');
        if (!me || check.status === 401) return;
        if (!check.ok) {
            scheduleReconnect();
            return;
        }
        connectEvents();
    }

    function onMessageEvent(event) {
        let data;
        try {
            data = JSON.parse(event.data);
        } catch (e) {
            return;
        }
        if (!data || Object.keys(data).length !== 1 || !validateConversationId(data.c)) return;
        const conv = conversations.get(data.c);
        if (!conv) {
            scheduleRefresh();
            return;
        }
        bump(conv.id);
        if (activeId === conv.id && document.visibilityState === 'visible') {
            sync(conv);
        } else {
            scheduleRefresh();
        }
    }

    function resync() {
        if (!me) return;
        scheduleRefresh();
        const conv = conversations.get(activeId);
        if (conv) sync(conv);
    }

    function onVisible() {
        if (!me || document.visibilityState !== 'visible') return;
        if (!events) {
            reconnectAttempts = 0;
            connectEvents();
        } else {
            resync();
        }
    }

    return Object.freeze({
        start, stop, open, backToList, send, createInvite, join,
        showSafety, toggleVerified, askBurn, burn, onVisible,
        isActive: () => me !== null
    });
})();
