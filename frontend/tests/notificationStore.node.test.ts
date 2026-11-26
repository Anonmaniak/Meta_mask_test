/**
 * Notification logic: unread counts, ignoring your own messages, not notifying for the chat you are
 * looking at, clearing when a chat is opened, and telling the server how far you have read.
 * Runs in Node with a fake browser (window, document, fetch, WebSocket).
 */
import { describe, it, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// ---------------------------------------------------------------- fake browser
const listeners: Record<string, Array<() => void>> = {};
const fakeDoc = {
  title: 'Zyphra',
  visibilityState: 'visible' as 'visible' | 'hidden',
  focused: true,
  hasFocus() {
    return this.focused;
  },
  addEventListener(type: string, fn: () => void) {
    (listeners[type] ||= []).push(fn);
  },
  removeEventListener(type: string, fn: () => void) {
    listeners[type] = (listeners[type] || []).filter((f) => f !== fn);
  },
};
const store: Record<string, string> = {};
(globalThis as any).document = fakeDoc;
(globalThis as any).localStorage = {
  getItem: (k: string) => (k in store ? store[k] : null),
  setItem: (k: string, v: string) => {
    store[k] = String(v);
  },
  removeItem: (k: string) => {
    delete store[k];
  },
};
(globalThis as any).window = Object.assign(globalThis as any, {
  location: { hostname: 'localhost', origin: 'http://localhost:5173', protocol: 'http:', host: 'localhost:5173' },
  addEventListener: fakeDoc.addEventListener.bind(fakeDoc),
  removeEventListener: fakeDoc.removeEventListener.bind(fakeDoc),
  dispatchEvent: () => true,
});

let socket: { onmessage?: (ev: { data: string }) => void } | null = null;
class FakeWebSocket {
  static OPEN = 1;
  static CONNECTING = 0;
  readyState = 0;
  onmessage?: (ev: { data: string }) => void;
  onopen?: () => void;
  onclose?: () => void;
  onerror?: () => void;
  constructor() {
    socket = this;
  }
  send() { }
  close() { }
}
(globalThis as any).WebSocket = FakeWebSocket;

const marks: Array<Record<string, unknown>> = [];
let unreadReply: any = { dm: [], groups: [], total: 0 };
(globalThis as any).fetch = async (url: string, init: any = {}) => {
  const json = (body: unknown) =>
    new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
  if (url.endsWith('/e2ee/unread')) return json(unreadReply);
  if (url.endsWith('/e2ee/read-markers')) {
    marks.push(JSON.parse(init.body));
    return json({ success: true });
  }
  if (url.includes('/e2ee/peers/') || url.includes('resolve')) {
    return json({ user_id: 'usr_bob', username: 'bob', primary_wallet: null, identity_version: 1, devices: [] });
  }
  if (url.endsWith('/e2ee/groups')) return json({ groups: [{ group_id: 'grp_1', name: 'Team', members: [] }] });
  return json({});
};

const ME = 'usr_me';
let N: typeof import('../src/services/notificationStore.ts');

function push(evt: Record<string, unknown>) {
  assert.ok(socket?.onmessage, 'live connection is open');
  socket!.onmessage!({ data: JSON.stringify(evt) });
}
const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));

describe('notifications', () => {
  before(async () => {
    N = await import('../src/services/notificationStore.ts');
  });

  beforeEach(async () => {
    N.stopNotifications();
    marks.length = 0;
    unreadReply = { dm: [], groups: [], total: 0 };
    fakeDoc.visibilityState = 'visible';
    fakeDoc.focused = true;
  });

  it('loads unread counts from the server and shows them in the tab title', async () => {
    unreadReply = {
      dm: [{ conversation_id: 'c1', peer_user_id: 'usr_bob', peer_username: 'bob', unread: 2, last_seq: 10 }],
      groups: [{ group_id: 'grp_1', name: 'Team', unread: 3, last_seq: 20 }],
      total: 5,
    };
    N.startNotifications(ME);
    await tick(20);
    const s = N.getNotificationState();
    assert.equal(s.unread['dm:usr_bob'], 2);
    assert.equal(s.unread['group:grp_1'], 3);
    assert.equal(s.totalUnread, 5);
    assert.equal(fakeDoc.title, '(5) Zyphra');
  });

  it('counts a new private message, names the sender, and ignores my own messages', async () => {
    N.startNotifications(ME);
    await tick(20);
    push({ type: 'dm_ciphertext', sender_user_id: 'usr_bob', recipient_user_id: ME, seq: 11, message_id: 'm1' });
    push({ type: 'dm_ciphertext', sender_user_id: ME, recipient_user_id: 'usr_bob', seq: 12, message_id: 'm2' });
    await tick(20);
    const s = N.getNotificationState();
    assert.equal(s.unread['dm:usr_bob'], 1);
    assert.equal(s.items.length, 1);
    assert.equal(s.items[0].title, '@bob');
    assert.equal(s.items[0].body, 'New message');
    assert.ok(!JSON.stringify(s.items).includes('ciphertext'));
  });

  it('group messages say who wrote and where, and never count my own', async () => {
    N.startNotifications(ME);
    await tick(20);
    N.rememberNames({ users: { usr_ann: '@ann' }, groups: { grp_1: 'Team' } });
    push({ type: 'group_ciphertext', group_id: 'grp_1', sender_user_id: 'usr_ann', seq: 21, message_id: 'g1' });
    push({ type: 'group_ciphertext', group_id: 'grp_1', sender_user_id: 'usr_ann', seq: 22, message_id: 'g2' });
    push({ type: 'group_ciphertext', group_id: 'grp_1', sender_user_id: ME, seq: 23, message_id: 'g3' });
    await tick(20);
    const s = N.getNotificationState();
    assert.equal(s.unread['group:grp_1'], 2);
    assert.equal(s.items.length, 1, 'one list entry per conversation');
    assert.equal(s.items[0].title, '@ann in Team');
    assert.equal(s.items[0].body, '2 new messages');
  });

  it('does not notify for the conversation on screen, and clears it when opened', async () => {
    N.startNotifications(ME);
    await tick(20);
    push({ type: 'dm_ciphertext', sender_user_id: 'usr_bob', recipient_user_id: ME, seq: 30, message_id: 'a' });
    await tick(20);
    assert.equal(N.getNotificationState().unread['dm:usr_bob'], 1);

    // Opening the chat clears the badge and tells the server how far I read
    N.setActiveConversation('dm:usr_bob');
    N.conversationShown('dm:usr_bob', 30);
    await tick(900);
    assert.equal(N.getNotificationState().unread['dm:usr_bob'], undefined);
    assert.deepEqual(marks.at(-1), { scope_type: 'dm', peer_user_id: 'usr_bob', last_read_seq: 30 });

    // While I'm looking at it, new messages are not counted
    push({ type: 'dm_ciphertext', sender_user_id: 'usr_bob', recipient_user_id: ME, seq: 31, message_id: 'b' });
    await tick(20);
    assert.equal(N.getNotificationState().unread['dm:usr_bob'], undefined);
  });

  it('counts messages for the open chat while the tab is in the background, then clears on return', async () => {
    N.startNotifications(ME);
    await tick(20);
    N.setActiveConversation('group:grp_1');
    fakeDoc.visibilityState = 'hidden';
    fakeDoc.focused = false;
    push({ type: 'group_ciphertext', group_id: 'grp_1', sender_user_id: 'usr_ann', seq: 40, message_id: 'x' });
    await tick(20);
    // The chat screen polls while hidden: that must NOT count as read
    N.conversationShown('group:grp_1', 40);
    assert.equal(N.getNotificationState().unread['group:grp_1'], 1);

    fakeDoc.visibilityState = 'visible';
    fakeDoc.focused = true;
    for (const fn of listeners['focus'] || []) fn();
    await tick(900);
    assert.equal(N.getNotificationState().unread['group:grp_1'], undefined);
    assert.deepEqual(marks.at(-1), { scope_type: 'group', group_id: 'grp_1', last_read_seq: 40 });
  });

  it('group invitations appear in the list; "Mark all as read" clears everything', async () => {
    N.startNotifications(ME);
    await tick(20);
    push({ type: 'group_invitation', group_id: 'grp_9', group_name: 'Book club', invited_by_username: 'zara' });
    push({ type: 'dm_ciphertext', sender_user_id: 'usr_bob', recipient_user_id: ME, seq: 50, message_id: 'c' });
    await tick(20);
    let s = N.getNotificationState();
    assert.equal(s.items.length, 2);
    assert.equal(s.items.find((i) => i.kind === 'invite')?.title, 'Book club');
    assert.equal(s.unseenItems, 2);

    N.markEverythingRead();
    await tick(900);
    s = N.getNotificationState();
    assert.equal(s.totalUnread, 0);
    assert.equal(s.unseenItems, 0);
    assert.equal(fakeDoc.title, 'Zyphra');
    assert.ok(marks.some((m) => m.peer_user_id === 'usr_bob' && m.last_read_seq === 50));
  });

  it('remembers sound / background settings per member', async () => {
    N.startNotifications(ME);
    N.setNotificationPrefs({ sound: false });
    N.stopNotifications();
    N.startNotifications(ME);
    assert.equal(N.getNotificationState().prefs.sound, false);
    N.startNotifications('usr_other');
    assert.equal(N.getNotificationState().prefs.sound, true);
  });

  it('signing out clears everything', async () => {
    N.startNotifications(ME);
    push({ type: 'dm_ciphertext', sender_user_id: 'usr_bob', recipient_user_id: ME, seq: 60, message_id: 'd' });
    await tick(20);
    N.stopNotifications();
    const s = N.getNotificationState();
    assert.equal(s.totalUnread, 0);
    assert.equal(s.items.length, 0);
    assert.equal(fakeDoc.title, 'Zyphra');
  });
});