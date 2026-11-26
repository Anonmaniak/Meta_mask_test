/**
 * Instagram-style chat timeline helpers (pure functions, unit-tested in tests/chatFormat.node.test.ts).
 *
 * - A centered label starts every "session": the first message of a day, or one sent more than
 *   SESSION_GAP_MS after the previous message. It reads like Instagram:
 *   "Today 4:10 PM", "Yesterday 12:23 AM", "Mon 9:15 AM" (last 7 days), "12 Nov, 4:10 PM" (this year),
 *   "12 Nov 2025, 4:10 PM" (older).
 * - Consecutive messages from the same person (same session, within RUN_GAP_MS) form a "run":
 *   bubbles get tighter corners on the sender's side, the name shows once on the first bubble and the
 *   avatar once next to the last one.
 */

export const SESSION_GAP_MS = 60 * 60 * 1000; // 1 hour without messages starts a new time label
export const RUN_GAP_MS = 5 * 60 * 1000; // same sender within 5 minutes stays in one run

export type RunPosition = 'single' | 'first' | 'middle' | 'last';

export interface TimelineMessage<T> {
  kind: 'message';
  key: string;
  item: T;
  position: RunPosition;
  /** First message of a run: show the sender's name (groups / members' room). */
  showName: boolean;
  /** Last message of a run: show the avatar (other people) / delivery state (own). */
  showAvatar: boolean;
}

export interface TimelineLabel {
  kind: 'label';
  key: string;
  text: string;
  /** Full date for screen readers and the tooltip, e.g. "Monday, 23 November 2026, 4:10 PM". */
  title: string;
}

export type TimelineEntry<T> = TimelineMessage<T> | TimelineLabel;

function toDate(v: string | number | Date): Date {
  return v instanceof Date ? v : new Date(v);
}

function startOfDay(d: Date): number {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
}

export function isSameDay(a: Date, b: Date): boolean {
  return startOfDay(a) === startOfDay(b);
}

/** Whole calendar days between two dates (local time), ignoring the clock. */
export function calendarDaysBetween(earlier: Date, later: Date): number {
  return Math.round((startOfDay(later) - startOfDay(earlier)) / 86_400_000);
}

export function formatClock(d: Date, locale?: string): string {
  return d.toLocaleTimeString(locale, { hour: 'numeric', minute: '2-digit' });
}

/** "Today", "Yesterday", "Mon", "12 Nov", "12 Nov 2025". */
export function formatDayLabel(value: string | number | Date, now: Date = new Date(), locale?: string): string {
  const d = toDate(value);
  if (Number.isNaN(d.getTime())) return '';
  const days = calendarDaysBetween(d, now);
  if (days <= 0) return 'Today';
  if (days === 1) return 'Yesterday';
  if (days < 7) return d.toLocaleDateString(locale, { weekday: 'short' });
  if (d.getFullYear() === now.getFullYear()) return d.toLocaleDateString(locale, { day: 'numeric', month: 'short' });
  return d.toLocaleDateString(locale, { day: 'numeric', month: 'short', year: 'numeric' });
}

/** Label text for the start of a session: "Today 4:10 PM", "12 Nov, 4:10 PM", ... */
export function formatSessionLabel(value: string | number | Date, now: Date = new Date(), locale?: string): string {
  const d = toDate(value);
  if (Number.isNaN(d.getTime())) return '';
  const day = formatDayLabel(d, now, locale);
  const clock = formatClock(d, locale);
  const days = calendarDaysBetween(d, now);
  return days < 7 ? `${day} ${clock}` : `${day}, ${clock}`;
}

export function formatFullTimestamp(value: string | number | Date, locale?: string): string {
  const d = toDate(value);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleString(locale, {
    weekday: 'long',
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

/**
 * Turns a time-ordered message list into labels + messages with their run position.
 * `getTime` must return something `new Date()` understands; invalid times never start a session.
 */
export function buildTimeline<T>(
  items: readonly T[],
  opts: {
    getKey: (item: T, index: number) => string;
    getTime: (item: T) => string | number | Date;
    getSender: (item: T) => string;
    now?: Date;
    locale?: string;
  }
): TimelineEntry<T>[] {
  const now = opts.now ?? new Date();
  const out: TimelineEntry<T>[] = [];
  type Pending = { item: T; key: string; sender: string; time: Date; sessionStart: boolean };
  const rows: Pending[] = [];

  let prevTime: Date | null = null;
  items.forEach((item, i) => {
    const t = toDate(opts.getTime(item));
    const valid = !Number.isNaN(t.getTime());
    let sessionStart = false;
    if (valid) {
      sessionStart =
        prevTime === null || !isSameDay(prevTime, t) || t.getTime() - prevTime.getTime() > SESSION_GAP_MS;
      prevTime = t;
    }
    rows.push({ item, key: opts.getKey(item, i), sender: opts.getSender(item), time: valid ? t : (prevTime ?? now), sessionStart });
  });

  const continuesRun = (a: Pending | undefined, b: Pending | undefined): boolean =>
    Boolean(
      a &&
        b &&
        !b.sessionStart &&
        a.sender === b.sender &&
        Math.abs(b.time.getTime() - a.time.getTime()) <= RUN_GAP_MS
    );

  rows.forEach((row, i) => {
    if (row.sessionStart) {
      out.push({
        kind: 'label',
        key: `label_${row.key}`,
        text: formatSessionLabel(row.time, now, opts.locale),
        title: formatFullTimestamp(row.time, opts.locale),
      });
    }
    const joinsPrev = continuesRun(rows[i - 1], row);
    const joinsNext = continuesRun(row, rows[i + 1]);
    const position: RunPosition = joinsPrev ? (joinsNext ? 'middle' : 'last') : joinsNext ? 'first' : 'single';
    out.push({
      kind: 'message',
      key: row.key,
      item: row.item,
      position,
      showName: !joinsPrev,
      showAvatar: !joinsNext,
    });
  });
  return out;
}

// Emoji-only messages (1 to 3 emoji, nothing else) are shown large and without a bubble, like Instagram.
const EMOJI_ONLY_RE =
  /^(?:\p{Extended_Pictographic}(?:\uFE0F|\u20E3)?(?:\p{Emoji_Modifier})?(?:\u200D\p{Extended_Pictographic}(?:\uFE0F)?(?:\p{Emoji_Modifier})?)*|\p{Regional_Indicator}{2}|\s){1,12}$/u;

export function countEmoji(text: string): number {
  const seg =
    typeof Intl !== 'undefined' && (Intl as any).Segmenter
      ? Array.from(new (Intl as any).Segmenter(undefined, { granularity: 'grapheme' }).segment(text), (s: any) => s.segment as string)
      : Array.from(text);
  return seg.filter((g: string) => g.trim().length > 0).length;
}

export function isEmojiOnly(text: string | null | undefined): boolean {
  const t = (text || '').trim();
  if (!t || /[0-9#*]/.test(t.replace(/[0-9#*]\uFE0F?\u20E3/gu, ''))) return false;
  if (!EMOJI_ONLY_RE.test(t)) return false;
  const n = countEmoji(t);
  return n >= 1 && n <= 3;
}

/** "1.2 MB", "340 KB", "12 B". */
export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${Math.max(1, Math.round(n / 1024))} KB`;
  return `${(n / (1024 * 1024)).toFixed(n < 10 * 1024 * 1024 ? 1 : 0)} MB`;
}
