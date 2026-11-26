import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildTimeline,
  formatDayLabel,
  formatSessionLabel,
  isEmojiOnly,
  formatBytes,
  type TimelineEntry,
} from '../src/services/chatFormat.ts';
import { attachmentKind, checkFilesForMessage, isRiskyFileName } from '../src/services/attachmentLimits.ts';

const NOW = new Date(2026, 10, 23, 16, 30); // Mon 23 Nov 2026, 4:30 PM local
const at = (y: number, mo: number, d: number, h: number, mi = 0) => new Date(y, mo, d, h, mi).toISOString();

describe('Instagram-style day labels', () => {
  it('uses Today / Yesterday / weekday / date / date with year', () => {
    assert.equal(formatDayLabel(at(2026, 10, 23, 9), NOW, 'en-GB'), 'Today');
    assert.equal(formatDayLabel(at(2026, 10, 22, 23, 59), NOW, 'en-GB'), 'Yesterday');
    assert.equal(formatDayLabel(at(2026, 10, 18, 10), NOW, 'en-GB'), 'Wed');
    assert.equal(formatDayLabel(at(2026, 10, 12, 10), NOW, 'en-GB'), '12 Nov');
    assert.equal(formatDayLabel(at(2025, 10, 12, 10), NOW, 'en-GB'), '12 Nov 2025');
  });
  it('adds the time to session labels', () => {
    assert.match(formatSessionLabel(at(2026, 10, 23, 16, 10), NOW, 'en-US'), /^Today 4:10\sPM$/);
    assert.match(formatSessionLabel(at(2026, 10, 12, 16, 10), NOW, 'en-GB'), /^12 Nov, 16:10$/);
  });
});

describe('timeline: labels and runs', () => {
  type M = { id: string; t: string; s: string };
  const build = (ms: M[]) =>
    buildTimeline(ms, { getKey: (m) => m.id, getTime: (m) => m.t, getSender: (m) => m.s, now: NOW, locale: 'en-GB' });
  const shape = (out: TimelineEntry<M>[]) =>
    out.map((e) => (e.kind === 'label' ? `[${e.text}]` : `${e.item.id}:${e.position}`));

  it('starts a label per day and after a 1-hour gap, and groups same-sender runs', () => {
    const out = build([
      { id: 'a', t: at(2026, 10, 22, 10, 0), s: 'u1' },
      { id: 'b', t: at(2026, 10, 22, 10, 1), s: 'u1' },
      { id: 'c', t: at(2026, 10, 22, 10, 2), s: 'u1' },
      { id: 'd', t: at(2026, 10, 22, 10, 3), s: 'u2' },
      { id: 'e', t: at(2026, 10, 22, 12, 0), s: 'u2' }, // > 1 h gap: new label, new run
      { id: 'f', t: at(2026, 10, 23, 9, 0), s: 'u2' }, // new day
      { id: 'g', t: at(2026, 10, 23, 9, 20), s: 'u2' }, // > 5 min: separate run, same session
    ]);
    assert.deepEqual(shape(out), [
      '[Yesterday 10:00]', 'a:first', 'b:middle', 'c:last', 'd:single',
      '[Yesterday 12:00]', 'e:single',
      '[Today 9:00]', 'f:single', 'g:single',
    ]);
    const a = out[1] as any;
    const c = out[3] as any;
    assert.equal(a.showName, true);
    assert.equal(a.showAvatar, false);
    assert.equal(c.showName, false);
    assert.equal(c.showAvatar, true);
  });

  it('survives an invalid time without crashing or starting a label', () => {
    const out = build([
      { id: 'a', t: at(2026, 10, 23, 9), s: 'u1' },
      { id: 'b', t: 'not a date', s: 'u1' },
    ]);
    assert.deepEqual(shape(out), ['[Today 9:00]', 'a:first', 'b:last']);
  });
});

describe('emoji-only messages', () => {
  it('detects 1 to 3 emoji, including joined and flag emoji', () => {
    assert.equal(isEmojiOnly('😂'), true);
    assert.equal(isEmojiOnly('❤️🔥'), true);
    assert.equal(isEmojiOnly('👨‍👩‍👧 👍🏽'), true);
    assert.equal(isEmojiOnly('🇮🇳'), true);
  });
  it('rejects text, numbers and 4+ emoji', () => {
    assert.equal(isEmojiOnly('ok 👍'), false);
    assert.equal(isEmojiOnly('123'), false);
    assert.equal(isEmojiOnly('😂😂😂😂'), false);
    assert.equal(isEmojiOnly(''), false);
  });
});

describe('file limits', () => {
  const file = (name: string, size: number, lastModified = 1) => ({ name, size, lastModified }) as unknown as File;
  it('refuses empty, too large, duplicate and over-count files with clear messages', () => {
    const r = checkFilesForMessage(
      [file('a.pdf', 10), file('a.pdf', 10), file('empty.txt', 0), file('big.mov', 9 * 1024 * 1024), file('b.png', 5), file('c', 1), file('d', 1), file('e', 1), file('f', 1)],
      [],
      5 * 1024 * 1024,
      5
    );
    assert.deepEqual(r.accepted.map((f) => f.name), ['a.pdf', 'b.png', 'c', 'd', 'e']);
    assert.equal(r.errors.length, 3);
    assert.match(r.errors[0], /empty/);
    assert.match(r.errors[1], /at most 5\.0 MB/);
    assert.match(r.errors[2], /up to 5 files/);
  });
  it('classifies kinds; SVG is a file; flags executables', () => {
    assert.equal(attachmentKind('image/jpeg', 'x.jpg'), 'image');
    assert.equal(attachmentKind('image/svg+xml', 'x.svg'), 'file');
    assert.equal(attachmentKind('video/mp4', 'x.mp4'), 'video');
    assert.equal(attachmentKind('', 'song.mp3'), 'audio');
    assert.equal(attachmentKind('application/pdf', 'x.pdf'), 'file');
    assert.equal(isRiskyFileName('setup.EXE'), true);
    assert.equal(isRiskyFileName('notes.pdf'), false);
    assert.equal(formatBytes(1536), '2 KB');
    assert.equal(formatBytes(2.5 * 1024 * 1024), '2.5 MB');
  });
});
