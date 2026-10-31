// ========================================
// CHAT (state, sync, realtime)
// ========================================
// The server is treated as an untrusted relay: every response is shape-checked,
// every message is authenticated by AES-GCM + AAD, peer keys from invites are
// verified against the fingerprint embedded in the invite code, and gaps in the
// peer's encrypted message counter expose messages the server withheld.
// Rooms (rooms.js) are conversations too: a room conversation carries `room` and no peer key.

const Chat = (() => {
    'use strict';

    const MAX_RECONNECT_ATTEMPTS = 8;
    const RECONNECT_BASE_MS = 1000;
    const RECONNECT_MAX_MS = 30000;
    const MAX_CIPHERTEXT_CHARS = 11000;
    // A roster can change between fetching it and sending (412): fetch, re-encrypt, retry, bounded
    const MAX_ROSTER_RETRIES = 2;

    let me = null;                    // { privateKey, publicKey, roomsRoot, aura, ttlDays, limits }
    const conversations = new Map();  // id -> conversation state
    let order = [];                   // server order: newest conversation first
    let recent = [];                  // ids with activity this session, most recent first (memory only)
    let activeId = null;
    let events = null;
    let reconnectAttempts = 0;
    let reconnectTimer = null;
    let refreshTimer = null;
    let listLoaded = false;           // distinguishes the first load from live additions
    let inviteRun = null;             // { stopScramble } while an invite is paid for and revealed
    let unsent = null;                // a send whose answer never came: { convId, text, id, counter, ciphertext }
    let roomRun = null;               // { stopScramble } while a room is paid for and revealed
    let friendRun = false;            // one friend request (a proof of work) at a time
    const rejectedRooms = new Set();  // "id vault" pairs that failed verification: warned about once

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
            NoaddxCrypto.b64urlDecode(value, 32);
            return true;
        } catch (e) {
            return false;
        }
    }

    function conversationKey(conv) {
        if (!conv.key) {
            conv.key = NoaddxCrypto.conversationKey(me.privateKey, conv.peerPublicKey, conv.id);
        }
        return conv.key;
    }

    function updateTitle() {
        let unread = 0;
        conversations.forEach(conv => {
            if (conv.id !== activeId && conv.lastSeq > conv.readSeq) unread++;
        });
        document.title = unread > 0 ? `(${unread}) noaddx.` : 'noaddx.';
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
            return { id: conv.id, aura: conv.aura, unread: conv.lastSeq > conv.readSeq, verified: conv.verified, room: conv.room };
        });
        items.sort((a, b) => (b.unread - a.unread) || (rank(a.id) - rank(b.id)));
        renderConversationList(items, open);
        updateTitle();
    }

    function bump(id) {
        recent = [id].concat(recent.filter(other => other !== id));
    }

    // ---------- lifecycle ----------

    async function start(identity, ttlDays, limits) {
        me = {
            privateKey: identity.privateKey,
            publicKey: identity.publicKey,
            roomsRoot: identity.roomsRoot,
            aura: await NoaddxCrypto.aura(identity.publicKey),
            ttlDays: ttlDays,
            limits: limits
        };
        renderMe(me.aura);
        setComposerHint(ttlDays);
        setRoomLimits(limits.maxMembers, Rooms.ttlChoices(limits.maxTTLHours));
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
        unsent = null;
        rejectedRooms.clear();
        me = null;
        clearChildren(document.getElementById('conversationList'));
        clearChildren(document.getElementById('messageList'));
        if (inviteRun) {
            inviteRun.stopScramble();
            inviteRun = null;
        }
        if (roomRun) {
            roomRun.stopScramble();
            roomRun = null;
        }
        friendRun = false;
        resetInvitePanel();
        resetRoomPanel();
        hideRoomPanels();
        togglePairPanel(null);
        document.getElementById('inviteInput').value = '';
        document.getElementById('deleteAccountInput').value = '';
        document.getElementById('messageInput').value = '';
        document.title = 'noaddx.';
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
            const isRoom = Boolean(item && item.room);
            if (!item || !validateConversationId(item.id) || (!isRoom && !isPublicKey(item.peer_public_key)) ||
                !isSeq(item.last_seq) || !isSeq(item.read_seq) || seen.has(item.id)) {
                continue;
            }
            seen.add(item.id);
            nextOrder.push(item.id);
            const existing = conversations.get(item.id);
            if (existing) {
                // A conversation's kind, peer key and room code can never change; treat as tampering
                if (isRoom !== Boolean(existing.room) ||
                    (isRoom ? !Rooms.refreshView(existing.room, item) : existing.peerPublicKey !== item.peer_public_key)) {
                    showError(isRoom ? 'room data changed unexpectedly — room hidden' : 'peer key changed unexpectedly — conversation hidden');
                    conversations.delete(item.id);
                    continue;
                }
                existing.lastSeq = Math.max(existing.lastSeq, item.last_seq);
                existing.readSeq = Math.max(existing.readSeq, item.read_seq);
                continue;
            }
            const state = await newConversationState(item, isRoom);
            if (!me) return;
            if (!state) continue;
            joined = joined || (listLoaded && !isRoom);
            conversations.set(item.id, state);
        }

        for (const id of Array.from(conversations.keys())) {
            if (!seen.has(id)) {
                const gone = conversations.get(id);
                conversations.delete(id);
                if (activeId === id) {
                    activeId = null;
                    showHome();
                    showWarning(gone.room ? 'this room is gone — burned or expired' : 'this conversation was burned');
                }
            }
        }
        order = nextOrder;
        listLoaded = true;
        renderList();
        const active = conversations.get(activeId);
        if (active && active.room) {
            refreshActiveRoom(active);
        }

        // Someone redeemed an invite: the code on screen is spent, so put it away
        // (unless a new one is being made, which nobody can have redeemed yet)
        if (joined && !inviteRun && document.getElementById('invitePanel').style.display !== 'none') {
            togglePairPanel(null);
            showSuccess('someone joined with your invite');
        }
    }

    // Verifies a listed conversation once (a room against the code in its vault); null hides it
    async function newConversationState(item, isRoom) {
        const state = {
            id: item.id,
            peerPublicKey: null,
            room: null,
            aura: null,
            verified: false,
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
        };
        if (!isRoom) {
            state.peerPublicKey = item.peer_public_key;
            state.aura = await NoaddxCrypto.aura(item.peer_public_key);
            state.verified = await Keystore.isVerified(item.id, item.peer_public_key);
            return state;
        }
        try {
            state.room = await Rooms.adopt(me.roomsRoot, item);
        } catch (e) {
            const seen = item.id + ' ' + (item.room && item.room.vault);
            if (!rejectedRooms.has(seen)) {
                rejectedRooms.add(seen);
                showError('a room failed verification against its code — hidden');
            }
            return null;
        }
        state.aura = await Rooms.aura(item.id);
        state.peerLastN = new Map();  // per sender: their counter in this room
        return state;
    }

    function scheduleRefresh() {
        clearTimeout(refreshTimer);
        refreshTimer = setTimeout(refreshConversations, 250);
    }

    async function open(id) {
        const conv = conversations.get(id);
        if (!conv) return;
        activeId = id;
        showChatView(conv.aura, conv.room);
        conv.seqs = new Set();
        conv.ids = new Set();
        conv.maxSeq = 0;
        // myMaxN is kept: within a session this device's counter only ever grows
        conv.peerLastN = conv.room ? new Map() : 0;
        conv.loaded = false;
        if (conv.room) {
            renderRoomHeader(conv.room);
            setRoomComposerHint(conv.room.expiresAt, me.ttlDays);
            if (!(await loadRoster(conv))) return;
            await refreshRoomPanels(conv);
        } else {
            setComposerHint(me.ttlDays);
            setVerifiedState(conv.verified);
        }
        await sync(conv);
        if (activeId === id) {
            renderEmptyConversation(me.ttlDays, conv.room);
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

        const key = conv.room ? null : await conversationKey(conv);
        const fresh = [];
        for (const raw of result.data.messages) {
            if (!raw || !NoaddxCrypto.isUuidV4(raw.id) || !isSeq(raw.seq) || raw.seq === 0 ||
                typeof raw.mine !== 'boolean' || typeof raw.ciphertext !== 'string' ||
                raw.ciphertext.length > MAX_CIPHERTEXT_CHARS || conv.seqs.has(raw.seq) || raw.seq <= conv.maxSeq ||
                conv.ids.has(raw.id)) {
                // Unknown shape, or a message id seen before (a server re-serving an old ciphertext)
                continue;
            }
            let message;
            try {
                if (conv.room) {
                    message = await openRoomMessage(conv, raw, fresh);
                    conv.seqs.add(raw.seq);
                    conv.ids.add(raw.id);
                    conv.maxSeq = raw.seq;
                    fresh.push(message);
                    continue;
                }
                const sender = raw.mine ? me.publicKey : conv.peerPublicKey;
                const plain = await NoaddxCrypto.decryptMessage(key, conv.id, raw.id, sender, raw.ciphertext);
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

    // Verifies a room message's sender and counter; gaps are tracked per sender
    async function openRoomMessage(conv, raw, fresh) {
        let plain;
        try {
            plain = await Rooms.open(conv, raw);
        } catch (e) {
            return { seq: raw.seq, mine: raw.mine, broken: true };
        }
        const mine = plain.sender === conv.room.member.publicKey;
        if (mine !== raw.mine) {
            return { seq: raw.seq, mine: raw.mine, broken: true };
        }
        if (mine) {
            conv.myMaxN = Math.max(conv.myMaxN, plain.counter);
            return { seq: raw.seq, mine: true, text: plain.text, sentAt: plain.sentAt };
        }
        const entry = Rooms.senderOf(conv.room, plain.sender);
        const aura = entry ? entry.aura : await NoaddxCrypto.aura(plain.sender);
        const last = conv.peerLastN.get(plain.sender) || 0;
        if (last > 0 && plain.counter > last + 1) {
            fresh.push({ gap: plain.counter - last - 1, from: aura.name });
        }
        conv.peerLastN.set(plain.sender, Math.max(last, plain.counter));
        return { seq: raw.seq, mine: false, text: plain.text, sentAt: plain.sentAt, from: aura.name, left: !entry };
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

        if (conv.room && Rooms.expired(conv.room)) {
            showWarning('this room has expired');
            return;
        }
        if (conv.room && !conv.room.roster && !(await loadRoster(conv))) return;

        sendBtn.disabled = true;
        try {
            // Retrying a send whose answer was lost resends the same id and ciphertext: if the
            // first attempt was stored, the server refuses the duplicate id (409) instead of
            // delivering the message twice
            const text = validation.sanitized;
            let attempt = unsent && unsent.convId === conv.id && unsent.text === text ? unsent : null;
            if (!attempt) {
                const id = NoaddxCrypto.newMessageId();
                attempt = { convId: conv.id, text: text, id: id, counter: conv.myMaxN + 1, ciphertext: null };
                attempt.ciphertext = await sealAttempt(conv, attempt);
            }
            let result = await api('POST', `/conversations/${conv.id}/messages`, { id: attempt.id, ciphertext: attempt.ciphertext });
            // Someone joined or left since the roster was fetched: encrypt for the new one
            for (let retry = 0; conv.room && result.status === 412 && retry < MAX_ROSTER_RETRIES; retry++) {
                if (!(await loadRoster(conv))) return;
                attempt.ciphertext = await sealAttempt(conv, attempt);
                result = await api('POST', `/conversations/${conv.id}/messages`, { id: attempt.id, ciphertext: attempt.ciphertext });
            }
            const stored = (result.ok && result.data && isSeq(result.data.seq) && result.data.seq > 0) || result.status === 409;
            // Only a lost answer leaves the outcome open; any other answer settles it
            unsent = !stored && (result.status === 0 || result.status >= 500) ? attempt : null;

            if (stored) {
                // The counter never repeats, even if the server withholds this message from the
                // next sync: the peer then sees the gap instead of a reused counter
                conv.myMaxN = Math.max(conv.myMaxN, attempt.counter);
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

    function sealAttempt(conv, attempt) {
        if (conv.room) {
            return Rooms.seal(conv, attempt.id, attempt.text, attempt.counter);
        }
        return conversationKey(conv).then(key =>
            NoaddxCrypto.encryptMessage(key, conv.id, attempt.id, me.publicKey, attempt.text, Date.now(), attempt.counter));
    }

    // ---------- pairing ----------

    // Pays for an invite with a proof of work (as registration does) and builds its code.
    // Returns { code, expiresAt }, or null once the reason has been shown.
    async function requestInvite(owner) {
        const issued = await api('GET', '/pow/challenge');
        if (me !== owner) return null;
        if (!issued.ok || !issued.data || !issued.data.challenge) {
            if (issued.status === 429) showWarning('too many attempts — wait a minute');
            else if (issued.status !== 401) showError('could not create invite');
            return null;
        }
        const pow = await solvePowChallenge(issued.data.challenge);
        if (me !== owner) return null;

        const result = await api('POST', '/invites', { pow: pow });
        if (me !== owner) return null;
        if (result.status === 429) {
            showWarning('invite limit reached — wait for one to be used or expire');
            return null;
        }
        if (!result.ok || !result.data || typeof result.data.token !== 'string' || !Number.isSafeInteger(result.data.expires_at)) {
            if (result.status !== 401) showError('could not create invite');
            return null;
        }
        try {
            return {
                code: await NoaddxCrypto.buildInviteCode(result.data.token, owner.publicKey),
                expiresAt: result.data.expires_at
            };
        } catch (e) {
            showError('server returned a malformed invite');
            return null;
        }
    }

    async function createInvite() {
        if (inviteRun || !me) return;  // one proof of work at a time
        const owner = me;
        const run = { stopScramble: showInviteGenerating() };
        inviteRun = run;

        let invite = null;
        try {
            invite = await requestInvite(owner);
        } catch (e) {
            // The worker refused the challenge or found no solution within its budget
            if (me === owner) showError('could not create invite');
        }
        if (me !== owner) return;  // stop() ended this run and put the panel away
        run.stopScramble();
        if (!invite) {
            inviteRun = null;
            resetInvitePanel();
            return;
        }

        await revealInvite(invite.code, invite.expiresAt);
        if (me !== owner) {
            // Logged out mid-reveal: the last animation frame wrote the code back
            document.getElementById('inviteCode').textContent = '';
            return;
        }
        inviteRun = null;
        try {
            await copyToClipboard(invite.code);
            showSuccess('invite copied');
        } catch (e) {
            showWarning('copy it manually');
        }
    }

    // The join field takes an invite code or a room code
    async function join() {
        const input = document.getElementById('inviteInput');
        const validation = validateJoinCode(input.value);
        if (!validation.valid) {
            showError(validation.error);
            return;
        }
        const id = validation.kind === 'room' ? await joinRoom(validation.sanitized) : await redeemInvite(validation.sanitized);
        if (!id || !me) return;
        input.value = '';
        togglePairPanel(null);
        await refreshConversations();
        await open(id);
    }

    // Redeems an invite and checks the peer key against its fingerprint. Returns the new
    // conversation id, or null once the reason has been shown.
    async function redeemInvite(invite) {
        if (await NoaddxCrypto.fingerprintMatches(invite, me.publicKey)) {
            showWarning('that is your own invite — send it to someone else');
            return null;
        }
        const result = await api('POST', '/invites/redeem', { token: invite.token });
        if (result.status === 404) {
            showError('invite expired or already used');
            return null;
        }
        if (result.status === 429) {
            showWarning('too many attempts — wait a moment');
            return null;
        }
        const conv = result.data && result.data.conversation;
        if (!result.ok || !conv || !validateConversationId(conv.id) || !isPublicKey(conv.peer_public_key)) {
            if (result.status !== 401) showError('could not join');
            return null;
        }
        // The server chose which key we got; the invite code says which key we should get
        if (!(await NoaddxCrypto.fingerprintMatches(invite, conv.peer_public_key))) {
            await api('DELETE', `/conversations/${conv.id}`);
            showError('verification FAILED: the server substituted the peer key. conversation burned.');
            return null;
        }
        showSuccess('connected');
        return conv.id;
    }

    // ---------- rooms ----------

    // Fetches and verifies the active room's member list. Returns false once the reason was shown.
    async function loadRoster(conv) {
        try {
            await Rooms.loadRoster(api, conv);
        } catch (e) {
            if (!me) return false;
            if (e.status === 404) {
                scheduleRefresh();
            } else if (e.status !== 401) {
                showError('the member list failed verification — not sending to it');
            }
            return false;
        }
        if (activeId === conv.id) {
            renderRoomHeader(conv.room);
        }
        return true;
    }

    // Someone joined, left or sent a note: refresh what the open room shows
    async function refreshActiveRoom(conv) {
        if (await loadRoster(conv) && activeId === conv.id) {
            await refreshRoomPanels(conv);
        }
    }

    async function refreshRoomPanels(conv) {
        if (!conv.room.roster || activeId !== conv.id) return;
        if (document.getElementById('membersPanel').style.display !== 'none') {
            renderMembers(conv.room.roster, conv.room.skipped, conv.room.requested, entry => befriend(conv, entry));
            renderRoomSafety(await Rooms.safetyNumber(conv));
        }
        const notes = conv.room.notes > 0 ? await Rooms.notes(api, conv) : [];
        if (activeId !== conv.id) return;
        renderNotes(notes, note => acceptNote(conv, note), note => ignoreNote(conv, note));
    }

    async function joinRoom(code) {
        if (Date.now() >= code.expiresHour * 3600000) {
            showError('this room has expired');
            return null;
        }
        const result = await Rooms.join(api, me.roomsRoot, code);
        if (result.id) {
            showSuccess(result.status === 201 ? 'you joined the room' : 'you are already in this room');
            return result.id;
        }
        if (result.status === 404) {
            showError('no such room — the code is wrong, or the room expired or was burned');
        } else if (result.status === 409) {
            showWarning('this room is full');
        } else if (result.status === 429) {
            showWarning('too many attempts or too many conversations — wait a moment');
        } else if (result.status !== 401) {
            showError('could not join the room');
        }
        return null;
    }

    async function createRoom() {
        if (roomRun || !me) return;  // one proof of work at a time
        const owner = me;
        const maxMembers = Number(document.getElementById('roomMembersSelect').value);
        const ttlHours = Number(document.getElementById('roomTtlSelect').value);
        const run = { stopScramble: showRoomGenerating() };
        roomRun = run;
        const solve = async () => {
            const issued = await api('GET', '/pow/challenge');
            if (me !== owner || !issued.ok || !issued.data || !issued.data.challenge) return null;
            return solvePowChallenge(issued.data.challenge);
        };
        let created = { status: 0 };
        try {
            created = await Rooms.create(api, owner.roomsRoot, maxMembers, ttlHours, solve);
        } catch (e) {
            created = { status: 0 };
        }
        if (me !== owner) return;  // stop() ended this run and put the panel away
        run.stopScramble();
        if (!created.code) {
            roomRun = null;
            resetRoomPanel();
            if (created.status === 429) showWarning('too many rooms or attempts — wait a moment');
            else if (created.status === 400) showError('the server refused the room — check your device clock');
            else if (created.status !== 401) showError('could not create room');
            return;
        }
        await revealRoomCode(created.code, NoaddxRoomCrypto.parseRoomCode(created.code).expiresHour * 3600);
        if (me !== owner) {
            document.getElementById('roomCode').textContent = '';
            return;
        }
        roomRun = null;
        scheduleRefresh();
        try {
            await copyToClipboard(created.code);
            showSuccess('room code copied');
        } catch (e) {
            showWarning('copy it manually');
        }
    }

    function activeRoom() {
        const conv = conversations.get(activeId);
        return conv && conv.room ? conv : null;
    }

    async function toggleMembers() {
        const conv = activeRoom();
        if (!conv) return;
        if (toggleRoomPanel('membersPanel')) {
            await refreshRoomPanels(conv);
        }
    }

    function toggleRoomCode() {
        const conv = activeRoom();
        if (!conv) return;
        if (toggleRoomPanel('roomCodePanel')) {
            showRoomCode(Rooms.codeText(conv), conv.room.expiresAt);
        }
    }

    async function copyRoomCode() {
        const conv = activeRoom();
        if (!conv) return;
        try {
            await copyToClipboard(Rooms.codeText(conv));
            showSuccess('room code copied');
        } catch (e) {
            showWarning('copy it manually');
        }
    }

    // Sends a member an invite inside the room, sealed for them alone (a proof of work, as any invite)
    async function befriend(conv, entry) {
        if (friendRun || !me) return;
        friendRun = true;
        const owner = me;
        showSuccess('preparing a friend request · solving a proof of work');
        try {
            const invite = await requestInvite(owner);
            if (!invite || me !== owner) return;
            const result = await Rooms.befriend(api, conv, entry, invite.code);
            if (result.status === 201) {
                conv.room.requested.add(entry.publicKey);
                showSuccess(`friend request sent to ${entry.aura.name}`);
            } else if (result.status === 409) {
                showWarning('you already have a request waiting with them');
            } else if (result.status === 404) {
                showWarning('they are no longer in this room');
            } else if (result.status !== 401) {
                showError('friend request not sent');
            }
        } catch (e) {
            if (me === owner) showError('friend request not sent');
        } finally {
            friendRun = false;
            if (me === owner) await refreshRoomPanels(conv);
        }
    }

    // Accepting redeems the invite inside the note, with the usual fingerprint check
    async function acceptNote(conv, note) {
        const validation = validateInviteCode(note.invite);
        if (!validation.valid) {
            showError('that friend request is malformed — ignored');
            await ignoreNote(conv, note);
            return;
        }
        const id = await redeemInvite(validation.sanitized);
        if (!id || !me) return;
        await Rooms.dismissNote(api, conv, note.id);
        showSuccess('you are now friends — a private conversation opened');
        await refreshConversations();
        await open(id);
    }

    async function ignoreNote(conv, note) {
        await Rooms.dismissNote(api, conv, note.id);
        conv.room.notes = Math.max(0, conv.room.notes - 1);
        await refreshRoomPanels(conv);
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
        renderSafetyNumber(await NoaddxCrypto.safetyNumber(me.publicKey, conv.peerPublicKey));
        panel.style.display = 'block';
    }

    function askBurn(show) {
        const conv = conversations.get(activeId);
        setBurnConfirm(conv ? conv.room : null);
        document.getElementById('burnConfirm').style.display = show ? 'flex' : 'none';
    }

    // A pair is burned for both sides; a room is burned by its owner and left by anyone else
    async function burn() {
        const id = activeId;
        const conv = conversations.get(id);
        const leaving = Boolean(conv && conv.room && !conv.room.owner);
        askBurn(false);
        if (!id) return;
        const result = await api('DELETE', `/conversations/${id}`);
        if (result.status === 204 || result.status === 404) {
            conversations.delete(id);
            backToList();
            showSuccess(leaving ? 'you left the room' : 'burned');
            scheduleRefresh();
        } else if (result.status !== 401) {
            showError(leaving ? 'could not leave the room' : 'could not burn conversation');
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
        start, stop, open, backToList, send, createInvite, join, createRoom,
        toggleMembers, toggleRoomCode, copyRoomCode,
        showSafety, toggleVerified, askBurn, burn, onVisible,
        isActive: () => me !== null,
        publicKey: () => (me ? me.publicKey : null)
    });
})();
