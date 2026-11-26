/**
 * Notifications for new messages (private chats and groups) and group invitations.
 *
 * - Unread counts per conversation come from the server (so they survive a reload and work across
 *   devices) and go up live as messages arrive.
 * - A short list of recent notifications powers the bell in the header.
 * - Optional sound, and optional system (desktop / phone browser) notifications when Zyphra is in the
 *   background. Notifications never show message text: messages are end-to-end encrypted, and a
 *   lock screen is not private. They say who wrote and where.
 *
 * Scope keys: `dm:<other member's user_id>` and `group:<group_id>`.
 */
import { useSyncExternalStore } from 'react';
import {
  fetchUnreadCounts,
  markConversationReadOnServer,
  resolveE2EEPeer,
  fetchMyServerMlsGroups,
} from './e2eeApi.ts';
import { subscribeE2EERealtime, type E2EERealtimeEvent } from './e2eeRealtime.ts';

export type ScopeKey = string;

export interface NotificationItem {
  id: string;
  kind: 'dm' | 'group' | 'invite' | 'mention' | 'reminder';
  scope: ScopeKey;
  title: string;
  body: string;
  at: number;
  read: boolean;
}

export interface NotificationPrefs {
  sound: boolean;
  desktop: boolean;
}

export interface NotificationState {
  ready: boolean;
  unread: Record<ScopeKey, number>;
  totalUnread: number;
  items: NotificationItem[];
  unseenItems: number;
  prefs: NotificationPrefs;
  permission: 'default' | 'granted' | 'denied' | 'unsupported';
  /** Latest in-app pop-up (new message while you are elsewhere in the app). */
  toast: NotificationItem | null;
}

const MAX_ITEMS = 30;
const DEFAULT_PREFS: NotificationPrefs = { sound: true, desktop: false };

function currentPermission(): NotificationState['permission'] {
  if (typeof window === 'undefined' || !('Notification' in window)) return 'unsupported';
  return Notification.permission as NotificationState['permission'];
}

let state: NotificationState = {
  ready: false,
  unread: {},
  totalUnread: 0,
  items: [],
  unseenItems: 0,
  prefs: DEFAULT_PREFS,
  permission: currentPermission(),
  toast: null,
};

const subscribers = new Set<() => void>();
function emit(next: Partial<NotificationState>) {
  const merged = { ...state, ...next };
  merged.totalUnread = Object.values(merged.unread).reduce((a, b) => a + (b > 0 ? b : 0), 0);
  merged.unseenItems = merged.items.filter((i) => !i.read).length;
  state = merged;
  for (const fn of Array.from(subscribers)) fn();
}

// ---------------------------------------------------------------------------- session
let myUserId: string | null = null;
let activeScope: ScopeKey | null = null;
let stopRealtime: (() => void) | null = null;
let stopFocus: (() => void) | null = null;
const lastSeq: Record<ScopeKey, number> = {};
const userNames = new Map<string, string>();
const groupNames = new Map<string, string>();
const pendingUserLookups = new Map<string, Promise<string>>();
let groupsLoaded: Promise<void> | null = null;
const markTimers = new Map<ScopeKey, ReturnType<typeof setTimeout>>();
/** Muted chats ('dm:<user>', 'group:<id>', 'room'): still counted, but no pop-up, sound or system notice. */
let mutedScopes = new Set<ScopeKey>();

/** The chat screen tells the store which chats are muted (synced from the server). */
export function setNotificationMutedScopes(scopes: Iterable<ScopeKey>): void {
  mutedScopes = new Set(scopes);
}

function reminderSeenKey(uid: string) {
  return `zyphra_reminders_seen:${uid}`;
}

/** Renewal reminder in the bell, once per stage (7 days / 1 day / ended). */
export function pushReminder(rem: { key: string; title: string; body: string }): void {
  const uid = myUserId;
  if (!uid) return;
  let seen: string[] = [];
  try {
    seen = JSON.parse(localStorage.getItem(reminderSeenKey(uid)) || '[]');
  } catch {
    seen = [];
  }
  if (seen.includes(rem.key)) return;
  try {
    localStorage.setItem(reminderSeenKey(uid), JSON.stringify([...seen, rem.key].slice(-40)));
  } catch {
    /* storage unavailable */
  }
  pushItem({ id: `reminder:${rem.key}`, kind: 'reminder', scope: `reminder:${rem.key}`, title: rem.title, body: rem.body, at: Date.now(), read: false }, true);
}
const markSeqs = new Map<ScopeKey, number>();

function prefsKey(uid: string) {
  return `zyphra_notify_prefs:${uid}`;
}

function loadPrefs(uid: string): NotificationPrefs {
  try {
    const raw = localStorage.getItem(prefsKey(uid));
    if (raw) {
      const p = JSON.parse(raw);
      return { sound: p.sound !== false, desktop: p.desktop === true };
    }
  } catch {
    /* storage unavailable */
  }
  return DEFAULT_PREFS;
}

export function startNotifications(userId: string): () => void {
  if (myUserId === userId && stopRealtime) return stopNotifications;
  stopNotifications();
  myUserId = userId;
  emit({ prefs: loadPrefs(userId), permission: currentPermission(), ready: false, unread: {}, items: [], toast: null });

  void refreshUnreadCounts();
  stopRealtime = subscribeE2EERealtime(handleEvent);

  // Coming back to the tab while a conversation is open clears it; refresh counts after sleep.
  const onFocus = () => {
    if (isViewing(activeScope)) markActiveRead();
    if (document.visibilityState === 'visible') void refreshUnreadCounts();
  };
  window.addEventListener('focus', onFocus);
  document.addEventListener('visibilitychange', onFocus);
  stopFocus = () => {
    window.removeEventListener('focus', onFocus);
    document.removeEventListener('visibilitychange', onFocus);
  };
  return stopNotifications;
}

export function stopNotifications(): void {
  stopRealtime?.();
  stopRealtime = null;
  stopFocus?.();
  stopFocus = null;
  for (const t of markTimers.values()) clearTimeout(t);
  markTimers.clear();
  markSeqs.clear();
  myUserId = null;
  activeScope = null;
  for (const k of Object.keys(lastSeq)) delete lastSeq[k];
  userNames.clear();
  groupNames.clear();
  pendingUserLookups.clear();
  groupsLoaded = null;
  updateTitle(0);
  emit({ ready: false, unread: {}, items: [], toast: null });
}

export async function refreshUnreadCounts(): Promise<void> {
  if (!myUserId) return;
  const uid = myUserId;
  try {
    const res = await fetchUnreadCounts();
    if (myUserId !== uid) return;
    const unread: Record<ScopeKey, number> = {};
    for (const d of res.dm) {
      const key = `dm:${d.peer_user_id}`;
      if (d.peer_username) userNames.set(d.peer_user_id, `@${d.peer_username}`);
      lastSeq[key] = Math.max(lastSeq[key] || 0, d.last_seq);
      if (!isViewing(key)) unread[key] = d.unread;
    }
    for (const g of res.groups) {
      const key = `group:${g.group_id}`;
      groupNames.set(g.group_id, g.name);
      lastSeq[key] = Math.max(lastSeq[key] || 0, g.last_seq);
      if (!isViewing(key)) unread[key] = g.unread;
    }
    emit({ unread, ready: true });
    updateTitle(state.totalUnread);
  } catch {
    /* offline or signed out: keep what we have */
  }
}

// ---------------------------------------------------------------------------- chat screen hooks
/** The conversation the chat screen is showing right now (null when none). */
export function setActiveConversation(scope: ScopeKey | null): void {
  activeScope = scope;
  if (isViewing(scope)) markActiveRead();
}

/** Called by the chat screen once it has shown messages up to `seq` in `scope`. */
export function markConversationRead(scope: ScopeKey, seq?: number): void {
  if (seq && seq > 0) lastSeq[scope] = Math.max(lastSeq[scope] || 0, seq);
  const target = lastSeq[scope] || seq || 0;
  const hadUnread = (state.unread[scope] || 0) > 0;
  const hasUnreadItems = state.items.some((i) => i.scope === scope && !i.read);
  if (hadUnread || hasUnreadItems) {
    const unread = { ...state.unread };
    delete unread[scope];
    emit({
      unread,
      items: state.items.map((i) => (i.scope === scope ? { ...i, read: true } : i)),
      toast: state.toast?.scope === scope ? null : state.toast,
    });
    updateTitle(state.totalUnread);
  }
  if (target > 0) scheduleServerMark(scope, target);
}

/**
 * The chat screen has messages up to `seq` for `scope`. It counts as read only when the person can
 * actually see it (this tab visible and focused); otherwise it is read when they come back.
 */
export function conversationShown(scope: ScopeKey, seq: number): void {
  if (seq > 0) lastSeq[scope] = Math.max(lastSeq[scope] || 0, seq);
  if (isViewing(scope)) markConversationRead(scope);
}

/** Names the chat screen already knows, so notifications can say "@name" without a lookup. */
export function rememberNames(names: { users?: Record<string, string>; groups?: Record<string, string> }): void {
  for (const [id, label] of Object.entries(names.users || {})) if (label) userNames.set(id, label);
  for (const [id, label] of Object.entries(names.groups || {})) if (label) groupNames.set(id, label);
}

function markActiveRead() {
  if (activeScope) markConversationRead(activeScope);
}

function isViewing(scope: ScopeKey | null): boolean {
  if (!scope || scope !== activeScope) return false;
  if (typeof document === 'undefined') return false;
  return document.visibilityState === 'visible' && document.hasFocus();
}

function scheduleServerMark(scope: ScopeKey, seq: number) {
  markSeqs.set(scope, Math.max(markSeqs.get(scope) || 0, seq));
  if (markTimers.has(scope)) return;
  markTimers.set(
    scope,
    setTimeout(() => {
      markTimers.delete(scope);
      const s = markSeqs.get(scope) || 0;
      markSeqs.delete(scope);
      const [type, id] = splitScope(scope);
      if (!id || s <= 0) return;
      const target =
        type === 'dm'
          ? ({ scope_type: 'dm', peer_user_id: id } as const)
          : ({ scope_type: 'group', group_id: id } as const);
      markConversationReadOnServer(target, s).catch(() => {
        /* best effort: the next read marks it again */
      });
    }, 800)
  );
}

function splitScope(scope: ScopeKey): ['dm' | 'group', string] {
  const i = scope.indexOf(':');
  const type = scope.slice(0, i) === 'group' ? 'group' : 'dm';
  return [type, scope.slice(i + 1)];
}

// ---------------------------------------------------------------------------- bell + settings
export function markAllNotificationsSeen(): void {
  if (state.unseenItems === 0) return;
  emit({ items: state.items.map((i) => ({ ...i, read: true })) });
}

/** Clears every unread badge (and tells the server), like "Mark all as read". */
export function markEverythingRead(): void {
  for (const scope of Object.keys(state.unread)) {
    const s = lastSeq[scope];
    if (s) scheduleServerMark(scope, s);
  }
  emit({ unread: {}, items: state.items.map((i) => ({ ...i, read: true })), toast: null });
  updateTitle(0);
}

export function clearNotificationList(): void {
  emit({ items: [] });
}

export function dismissToast(): void {
  if (state.toast) emit({ toast: null });
}

export function setNotificationPrefs(next: Partial<NotificationPrefs>): void {
  const prefs = { ...state.prefs, ...next };
  if (myUserId) {
    try {
      localStorage.setItem(prefsKey(myUserId), JSON.stringify(prefs));
    } catch {
      /* storage unavailable */
    }
  }
  emit({ prefs });
}

/** Asks the browser for permission to show system notifications. Must be called from a click. */
export async function enableDesktopNotifications(): Promise<NotificationState['permission']> {
  if (!('Notification' in window)) {
    emit({ permission: 'unsupported' });
    return 'unsupported';
  }
  let perm = Notification.permission as NotificationState['permission'];
  if (perm === 'default') {
    try {
      perm = (await Notification.requestPermission()) as NotificationState['permission'];
    } catch {
      perm = Notification.permission as NotificationState['permission'];
    }
  }
  unlockSound();
  emit({ permission: perm });
  setNotificationPrefs({ desktop: perm === 'granted' });
  return perm;
}

/** Opens the conversation behind a notification (App switches to it). */
export function openNotification(item: Pick<NotificationItem, 'kind' | 'scope'>): void {
  const [type, id] = splitScope(item.scope);
  window.dispatchEvent(
    new CustomEvent('zyphra:open-conversation', {
      detail:
        item.kind === 'invite'
          ? { type: 'invites' }
          : item.kind === 'reminder'
            ? { type: 'payments' }
            : item.scope === 'room'
              ? { type: 'room' }
              : { type, id },
    })
  );
  if (state.toast && state.toast.scope === item.scope) emit({ toast: null });
}

// ---------------------------------------------------------------------------- incoming events
function handleEvent(evt: E2EERealtimeEvent) {
  if (!myUserId) return;
  if (evt.type === 'dm_ciphertext') {
    const sender = String(evt.sender_user_id || '');
    if (!sender || sender === myUserId) return; // my own message (from another device)
    if (evt.event_kind === 'control') return; // an encrypted reaction / edit / vote: never unread
    const scope = `dm:${sender}`;
    if (evt.seq) lastSeq[scope] = Math.max(lastSeq[scope] || 0, Number(evt.seq));
    void notifyMessage(scope, 'dm', sender, null, String(evt.message_id || ''));
  } else if (evt.type === 'group_ciphertext') {
    const sender = String(evt.sender_user_id || '');
    const gid = String(evt.group_id || '');
    if (!gid || !sender || sender === myUserId) return;
    if (evt.event_kind === 'control') return;
    const scope = `group:${gid}`;
    if (evt.seq) lastSeq[scope] = Math.max(lastSeq[scope] || 0, Number(evt.seq));
    void notifyMessage(scope, 'group', sender, gid, String(evt.message_id || ''));
  } else if (evt.type === 'group_invitation') {
    const gid = String(evt.group_id || '');
    if (!gid) return;
    const groupName = String(evt.group_name || '') || 'a group';
    const by = evt.invited_by_username ? `@${evt.invited_by_username}` : 'Someone';
    pushItem({
      id: `inv:${gid}:${Date.now()}`,
      kind: 'invite',
      scope: `invite:${gid}`,
      title: groupName,
      body: `${by} added you. Accept or reject in Groups.`,
      at: Date.now(),
      read: false,
    }, true);
  } else if (evt.type === 'mention') {
    // "@you": shown even when the chat is muted (like WhatsApp), unless it is on screen.
    const sender = String(evt.sender_user_id || '');
    const isRoom = evt.scope_type === 'room';
    const scope = isRoom ? 'room' : `group:${evt.group_id}`;
    if (!sender || sender === myUserId || isViewing(scope)) return;
    void (async () => {
      const uid = myUserId;
      const [who, groupName] = await Promise.all([
        nameForUser(sender),
        isRoom ? Promise.resolve(null) : nameForGroup(String(evt.group_id || '')),
      ]);
      if (myUserId !== uid) return;
      pushItem(
        {
          id: `mention:${evt.message_id || Date.now()}`,
          kind: 'mention',
          scope,
          title: `${who} mentioned you`,
          body: isRoom ? "In the Members' room" : `In ${groupName}`,
          at: Date.now(),
          read: false,
        },
        true
      );
    })();
  } else if (evt.type === 'group_deleted' && evt.group_id) {
    const scope = `group:${evt.group_id}`;
    const unread = { ...state.unread };
    delete unread[scope];
    emit({ unread, items: state.items.filter((i) => i.scope !== scope) });
    updateTitle(state.totalUnread);
  }
}

async function notifyMessage(
  scope: ScopeKey,
  kind: 'dm' | 'group',
  senderId: string,
  groupId: string | null,
  messageId: string
) {
  if (isViewing(scope)) return; // already on screen: the chat screen marks it read
  const uid = myUserId;
  const unread = { ...state.unread, [scope]: (state.unread[scope] || 0) + 1 };
  emit({ unread });
  updateTitle(state.totalUnread);
  if (mutedScopes.has(scope)) return; // muted: counted, but no pop-up or sound

  const [who, groupName] = await Promise.all([
    nameForUser(senderId),
    groupId ? nameForGroup(groupId) : Promise.resolve(null),
  ]);
  if (myUserId !== uid) return;
  const count = state.unread[scope] || 1;
  const body = count > 1 ? `${count} new messages` : 'New message';
  pushItem(
    {
      id: `${scope}:${messageId || Date.now()}`,
      kind,
      scope,
      title: kind === 'group' ? `${who} in ${groupName}` : who,
      body,
      at: Date.now(),
      read: false,
    },
    false
  );
}

function pushItem(item: NotificationItem, isInvite: boolean) {
  // One entry per conversation in the list: a new message replaces the older entry for it.
  // A mention keeps its own entry, so a plain "new message" cannot hide it.
  const keyOf = (i: NotificationItem) => (i.kind === 'mention' ? `mention|${i.scope}` : i.scope);
  const rest = state.items.filter((i) => keyOf(i) !== keyOf(item));
  const items = [item, ...rest].slice(0, MAX_ITEMS);
  const inApp = typeof document !== 'undefined' && document.visibilityState === 'visible' && document.hasFocus();
  emit({ items, toast: inApp ? item : state.toast });
  if (state.prefs.sound) playPing(isInvite);
  if (!inApp) showSystemNotification(item);
}

async function nameForUser(uid: string): Promise<string> {
  const known = userNames.get(uid);
  if (known) return known;
  let p = pendingUserLookups.get(uid);
  if (!p) {
    p = resolveE2EEPeer(uid)
      .then((peer) => {
        const label = peer.username ? `@${peer.username}` : 'A member';
        userNames.set(uid, label);
        return label;
      })
      .catch(() => 'A member')
      .finally(() => pendingUserLookups.delete(uid));
    pendingUserLookups.set(uid, p);
  }
  return p;
}

async function nameForGroup(gid: string): Promise<string> {
  if (!groupNames.has(gid)) {
    if (!groupsLoaded) {
      groupsLoaded = fetchMyServerMlsGroups()
        .then((res) => {
          for (const g of res.groups) groupNames.set(g.group_id, g.name);
        })
        .catch(() => {
          groupsLoaded = null;
        });
    }
    await groupsLoaded;
  }
  return groupNames.get(gid) || 'a group';
}

// ---------------------------------------------------------------------------- outputs
const BASE_TITLE = typeof document !== 'undefined' ? document.title.replace(/^\(\d+\+?\)\s*/, '') : 'Zyphra';
function updateTitle(total: number) {
  if (typeof document === 'undefined') return;
  document.title = total > 0 ? `(${total > 99 ? '99+' : total}) ${BASE_TITLE}` : BASE_TITLE;
}

function showSystemNotification(item: NotificationItem) {
  if (!state.prefs.desktop || currentPermission() !== 'granted') return;
  try {
    const n = new Notification(item.title, {
      body: item.body,
      tag: item.scope,
      icon: '/favicon.svg',
      silent: true,
    });
    n.onclick = () => {
      window.focus();
      openNotification(item);
      n.close();
    };
  } catch {
    /* some mobile browsers only allow notifications from a service worker */
  }
}

let audioCtx: AudioContext | null = null;
function unlockSound() {
  try {
    const Ctx = window.AudioContext || (window as any).webkitAudioContext;
    if (!Ctx) return;
    if (!audioCtx) audioCtx = new Ctx();
    if (audioCtx.state === 'suspended') void audioCtx.resume();
  } catch {
    /* no audio */
  }
}
if (typeof window !== 'undefined') {
  // Browsers only allow sound after the person has interacted with the page once.
  const once = () => {
    unlockSound();
    window.removeEventListener('pointerdown', once);
    window.removeEventListener('keydown', once);
  };
  window.addEventListener('pointerdown', once);
  window.addEventListener('keydown', once);
}

let lastPingAt = 0;
function playPing(isInvite: boolean) {
  const now = Date.now();
  if (now - lastPingAt < 1500) return; // a burst of messages makes one sound
  lastPingAt = now;
  try {
    if (!audioCtx || audioCtx.state !== 'running') return;
    const t = audioCtx.currentTime;
    const tones = isInvite ? [660, 880] : [880, 1175];
    tones.forEach((freq, i) => {
      const osc = audioCtx!.createOscillator();
      const gain = audioCtx!.createGain();
      osc.type = 'sine';
      osc.frequency.value = freq;
      const start = t + i * 0.12;
      gain.gain.setValueAtTime(0.0001, start);
      gain.gain.exponentialRampToValueAtTime(0.12, start + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.18);
      osc.connect(gain).connect(audioCtx!.destination);
      osc.start(start);
      osc.stop(start + 0.2);
    });
  } catch {
    /* no audio */
  }
}

// ---------------------------------------------------------------------------- React hook
function subscribe(fn: () => void) {
  subscribers.add(fn);
  return () => {
    subscribers.delete(fn);
  };
}
function getSnapshot() {
  return state;
}

/** Current state, outside React (tests, event handlers). */
export function getNotificationState(): NotificationState {
  return state;
}

export function useNotifications(): NotificationState {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}