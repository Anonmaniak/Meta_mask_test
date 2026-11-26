import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  foldChatEvents,
  canEditMessage,
  canDeleteForEveryone,
  findMentionedIds,
  searchMessages,
  cleanEmoji,
  describeTimer,
  type FoldInput,
} from '../src/services/chatEvents.ts';

const T0 = Date.parse('2026-11-25T10:00:00Z');
const at = (min: number) => new Date(T0 + min * 60_000).toISOString();
const msg = (id: string, sender: string, min: number, text: string, extra: Partial<FoldInput> = {}): FoldInput => ({
  id, sender, timestamp: at(min), message: text, canDecrypt: true, env: { kind: 'message', text }, ...extra,
});
const ev = (id: string, sender: string, min: number, env: FoldInput['env']): FoldInput => ({
  id, sender, timestamp: at(min), message: '', canDecrypt: true, env,
});
const opts = { myUserId: 'me', nowMs: T0 + 60 * 60_000 };

describe('reactions', () => {
  it('keeps one reaction per person, the latest wins, empty removes', () => {
    const out = foldChatEvents([
      msg('m1', 'a', 0, 'hi'),
      ev('e1', 'b', 1, { kind: 'reaction', target_id: 'm1', emoji: '👍' }),
      ev('e2', 'c', 1, { kind: 'reaction', target_id: 'm1', emoji: '👍' }),
      ev('e3', 'b', 2, { kind: 'reaction', target_id: 'm1', emoji: '❤️' }),
      ev('e4', 'c', 3, { kind: 'reaction', target_id: 'm1', emoji: '' }),
    ], opts);
    assert.equal(out.length, 1); // events are never shown as bubbles
    assert.deepEqual(out[0].reactions, { '❤️': ['b'] });
  });
  it('ignores reactions to unknown or deleted messages and bad emoji', () => {
    const out = foldChatEvents([
      msg('m1', 'a', 0, 'hi', { deleted: true }),
      ev('e1', 'b', 1, { kind: 'reaction', target_id: 'm1', emoji: '👍' }),
      ev('e2', 'b', 1, { kind: 'reaction', target_id: 'nope', emoji: '👍' }),
      msg('m2', 'a', 2, 'yo'),
      ev('e3', 'b', 3, { kind: 'reaction', target_id: 'm2', emoji: '<script>' }),
    ], opts);
    assert.deepEqual(out.map((m) => m.reactions), [{}, {}]);
    assert.equal(cleanEmoji('abc'), '');
    assert.equal(cleanEmoji('👍🏽'), '👍🏽');
  });
});

describe('edits', () => {
  it('applies the author\u2019s latest edit within 15 minutes', () => {
    const out = foldChatEvents([
      msg('m1', 'a', 0, 'helo'),
      ev('e1', 'a', 2, { kind: 'edit', target_id: 'm1', text: 'hello' }),
      ev('e2', 'a', 5, { kind: 'edit', target_id: 'm1', text: 'hello!' }),
    ], opts);
    assert.equal(out[0].message, 'hello!');
    assert.equal(out[0].edited, true);
  });
  it('refuses edits by someone else, after the window, on polls, or empty', () => {
    const out = foldChatEvents([
      msg('m1', 'a', 0, 'original'),
      ev('e1', 'b', 1, { kind: 'edit', target_id: 'm1', text: 'hijack' }),
      ev('e2', 'a', 17, { kind: 'edit', target_id: 'm1', text: 'too late' }),
      ev('e3', 'a', 2, { kind: 'edit', target_id: 'm1', text: '   ' }),
      msg('p1', 'a', 3, '', { env: { kind: 'message', text: '', poll: { question: 'Q?', options: ['x', 'y'] } } }),
      ev('e4', 'a', 4, { kind: 'edit', target_id: 'p1', text: 'changed' }),
    ], opts);
    assert.equal(out[0].message, 'original');
    assert.equal(out[0].edited, false);
    assert.equal(out[1].edited, false);
  });
  it('allows the minute of server rounding at the window edge', () => {
    const out = foldChatEvents([msg('m1', 'a', 0, 'x'), ev('e1', 'a', 16, { kind: 'edit', target_id: 'm1', text: 'y' })], opts);
    assert.equal(out[0].message, 'y');
  });
});

describe('polls', () => {
  const poll = (multi = false) => msg('p1', 'a', 0, '', { env: { kind: 'message', text: '', poll: { question: 'Lunch?', options: ['Pizza', 'Sushi', 'Tacos'], multi } } });
  it('counts the latest vote per person and shows mine', () => {
    const out = foldChatEvents([
      poll(),
      ev('v1', 'b', 1, { kind: 'poll_vote', target_id: 'p1', vote: [0] }),
      ev('v2', 'me', 1, { kind: 'poll_vote', target_id: 'p1', vote: [1] }),
      ev('v3', 'b', 2, { kind: 'poll_vote', target_id: 'p1', vote: [2] }),
      ev('v4', 'c', 2, { kind: 'poll_vote', target_id: 'p1', vote: [0, 1] }), // single choice: first only
      ev('v5', 'd', 2, { kind: 'poll_vote', target_id: 'p1', vote: [9] }), // no such option
    ], opts);
    const p = out[0].poll!;
    assert.deepEqual(p.votes, [['c'], ['me'], ['b']]);
    assert.equal(p.totalVoters, 3);
    assert.deepEqual(p.myVote, [1]);
  });
  it('multi-choice keeps several; an empty vote withdraws', () => {
    const out = foldChatEvents([
      poll(true),
      ev('v1', 'b', 1, { kind: 'poll_vote', target_id: 'p1', vote: [0, 2, 2] }),
      ev('v2', 'c', 1, { kind: 'poll_vote', target_id: 'p1', vote: [1] }),
      ev('v3', 'c', 2, { kind: 'poll_vote', target_id: 'p1', vote: [] }),
    ], opts);
    assert.deepEqual(out[0].poll!.votes, [['b'], [], ['b']]);
    assert.equal(out[0].poll!.totalVoters, 1);
  });
  it('rejects malformed polls', () => {
    const out = foldChatEvents([msg('p1', 'a', 0, 'text', { env: { kind: 'message', text: 'text', poll: { question: 'Q', options: ['only one'] } } })], opts);
    assert.equal(out[0].poll, undefined);
  });
});

describe('deleted, expired and announcement groups', () => {
  it('shows deleted as empty, hides expired', () => {
    const out = foldChatEvents([
      msg('m1', 'a', 0, 'secret', { deleted: true }),
      msg('m2', 'a', 1, 'gone', { expired: true }),
      msg('m3', 'a', 2, 'timed', { expiresAt: at(30) }), // already past at opts.nowMs
      msg('m4', 'a', 3, 'stays', { expiresAt: at(999) }),
    ], opts);
    assert.deepEqual(out.map((m) => [m.id, m.message, m.deleted]), [['m1', '', true], ['m4', 'stays', false]]);
  });
  it('hides non-admin messages in an announcement group, keeps my unsent ones', () => {
    const out = foldChatEvents([
      msg('m1', 'admin', 0, 'news'),
      msg('m2', 'member', 1, 'sneaky'),
      { ...msg('m3', 'me', 2, 'pending'), sendStatus: 'sending' as const },
    ], { ...opts, adminsOnly: true, adminIds: new Set(['admin']) });
    assert.deepEqual(out.map((m) => m.id), ['m1', 'm3']);
  });
});

describe('helpers', () => {
  it('edit and delete windows', () => {
    const m = { sender: 'me', timestamp: at(0) };
    assert.equal(canEditMessage(m, 'me', T0 + 14 * 60_000), true);
    assert.equal(canEditMessage(m, 'me', T0 + 16 * 60_000), false);
    assert.equal(canEditMessage(m, 'other', T0), false);
    assert.equal(canDeleteForEveryone(m, 'me', T0 + 47 * 3_600_000, false), true);
    assert.equal(canDeleteForEveryone(m, 'me', T0 + 49 * 3_600_000, false), false);
    assert.equal(canDeleteForEveryone(m, 'other', T0 + 99 * 3_600_000, true), true); // group admin
  });
  it('finds mentions case-insensitively and not inside emails', () => {
    const members = [{ user_id: 'u1', username: 'Alice' }, { user_id: 'u2', username: 'bob_99' }, { user_id: 'u3', username: null }];
    assert.deepEqual(findMentionedIds('hi @alice and @BOB_99, mail x@alice.com', members), ['u1', 'u2']);
    assert.deepEqual(findMentionedIds('@alice', members, 'u1'), []);
  });
  it('searches text and poll questions, skips deleted', () => {
    const items = [
      { id: 'a', message: 'Meeting at noon' },
      { id: 'b', message: 'meeting moved', deleted: true },
      { id: 'c', message: '', poll: { question: 'Which meeting room?', options: [], multi: false, votes: [], totalVoters: 0, myVote: [] } },
    ];
    assert.deepEqual(searchMessages(items, 'MEETING'), ['a', 'c']);
    assert.deepEqual(searchMessages(items, 'm'), []);
  });
  it('describes timers', () => {
    assert.deepEqual([0, 86400, 604800, 7776000].map(describeTimer), ['Off', '24 hours', '7 days', '90 days']);
  });
});
