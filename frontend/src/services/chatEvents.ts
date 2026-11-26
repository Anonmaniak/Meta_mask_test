/**
 * Encrypted chat events, applied on the device.
 *
 * In private chats and groups the server cannot read messages, so reactions, edits and poll votes travel
 * as small ENCRYPTED events that point at an earlier message (`target_id`). The server only knows such an
 * event is a "control" event (so it is never counted unread or notified). This module folds the events
 * into what a member sees, and enforces the rules every device must agree on:
 *
 * - reaction:  one per person per message; the latest wins; '' removes it.
 * - edit:      only the author, within 15 minutes of the original, never on a deleted message or a poll.
 * - poll vote: the latest vote per person wins; option numbers must exist; single-choice polls keep one.
 * - deleted / expired messages: deleted shows "This message was deleted"; expired is hidden.
 * - announcement groups: messages from non-admins are hidden (the server refuses them too).
 *
 * Pure functions only (no React, no network), so they are unit-tested in tests/chatEvents.node.test.ts.
 */

export const EDIT_WINDOW_MS = 15 * 60 * 1000;
/** Server times are rounded down to the minute: allow that minute on top of each window. */
export const SERVER_TIME_SLACK_MS = 60 * 1000;
export const DELETE_WINDOW_MS = 48 * 60 * 60 * 1000;
export const MAX_POLL_OPTIONS = 10;
export const QUICK_REACTIONS = ['❤️', '👍', '😂', '😮', '😢', '🙏'] as const;

export type ChatEventKind = 'message' | 'reaction' | 'edit' | 'poll_vote';

export interface PollDefinition {
  question: string;
  options: string[];
  /** true = members may tick several options */
  multi?: boolean;
}

/** The parts of a decrypted envelope this module reads (see E2EEPlaintextEnvelope). */
export interface EventEnvelopeFields {
  kind?: ChatEventKind;
  target_id?: string;
  emoji?: string;
  text?: string;
  poll?: PollDefinition;
  vote?: number[];
  mentions?: string[];
}

/** One record as the chat screen holds it, before folding. */
export interface FoldInput {
  id: string;
  sender: string;
  /** Server time (ISO). */
  timestamp: string;
  message: string;
  canDecrypt?: boolean;
  /** Decrypted fields (undefined when the record could not be decrypted). */
  env?: EventEnvelopeFields;
  deleted?: boolean;
  expired?: boolean;
  expiresAt?: string | null;
  /** Local optimistic / failed entries are passed through untouched. */
  sendStatus?: 'sending' | 'delivered' | 'failed';
}

export interface PollTally {
  question: string;
  options: string[];
  multi: boolean;
  /** votes[i] = user ids who picked option i */
  votes: string[][];
  totalVoters: number;
  myVote: number[];
}

export interface FoldedFields {
  /** emoji -> user ids, in the order they reacted */
  reactions: Record<string, string[]>;
  edited: boolean;
  deleted: boolean;
  poll?: PollTally;
  mentions: string[];
}

export interface FoldOptions {
  myUserId: string;
  nowMs: number;
  /** Announcement group: only these people may post messages. */
  adminsOnly?: boolean;
  adminIds?: ReadonlySet<string>;
}

const timeOf = (iso: string): number => {
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : 0;
};

export function cleanPoll(raw: unknown): PollDefinition | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const p = raw as Record<string, unknown>;
  const question = typeof p.question === 'string' ? p.question.trim().slice(0, 300) : '';
  const options = Array.isArray(p.options)
    ? p.options.filter((o): o is string => typeof o === 'string').map((o) => o.trim().slice(0, 100)).filter(Boolean)
    : [];
  if (!question || options.length < 2 || options.length > MAX_POLL_OPTIONS) return undefined;
  return { question, options, multi: p.multi === true };
}

/** Reaction text from someone else's encrypted event: a short emoji, never letters or markup. */
export function cleanEmoji(raw: unknown): string {
  if (typeof raw !== 'string') return '';
  const e = raw.trim();
  if (!e || e.length > 16 || /[\x00-\x7f]/.test(e)) return '';
  return e;
}

/**
 * Folds events into messages. Returns only displayable messages, in their original order, each
 * extended with reactions / edited / deleted / poll / mentions.
 */
export function foldChatEvents<T extends FoldInput>(records: readonly T[], opts: FoldOptions): Array<T & FoldedFields> {
  const byId = new Map<string, T>();
  for (const r of records) byId.set(r.id, r);

  const reactions = new Map<string, Map<string, string>>(); // target -> user -> emoji
  const edits = new Map<string, { text: string; at: number }>();
  const votes = new Map<string, Map<string, number[]>>(); // poll id -> user -> options

  const isEvent = (r: T) => Boolean(r.env?.kind && r.env.kind !== 'message');

  for (const r of records) {
    if (!isEvent(r) || !r.canDecrypt || r.deleted || r.expired) continue;
    const env = r.env!;
    const target = typeof env.target_id === 'string' ? byId.get(env.target_id) : undefined;
    if (!target || isEvent(target) || target.deleted) continue;
    if (env.kind === 'reaction') {
      const map = reactions.get(target.id) || new Map<string, string>();
      const emoji = cleanEmoji(env.emoji);
      map.delete(r.sender); // re-insert so order follows the latest reaction
      if (emoji) map.set(r.sender, emoji);
      reactions.set(target.id, map);
    } else if (env.kind === 'edit') {
      if (r.sender !== target.sender || target.env?.poll) continue;
      const delta = timeOf(r.timestamp) - timeOf(target.timestamp);
      if (delta < -SERVER_TIME_SLACK_MS || delta > EDIT_WINDOW_MS + SERVER_TIME_SLACK_MS) continue;
      const text = typeof env.text === 'string' ? env.text.slice(0, 4000) : '';
      if (!text.trim()) continue;
      const prev = edits.get(target.id);
      const at = timeOf(r.timestamp);
      if (!prev || at >= prev.at) edits.set(target.id, { text, at });
    } else if (env.kind === 'poll_vote') {
      const poll = cleanPoll(target.env?.poll);
      if (!poll) continue;
      const picked = Array.isArray(env.vote)
        ? Array.from(new Set(env.vote.filter((i) => Number.isInteger(i) && i >= 0 && i < poll.options.length)))
        : [];
      const chosen = poll.multi ? picked : picked.slice(0, 1);
      const map = votes.get(target.id) || new Map<string, number[]>();
      map.set(r.sender, chosen);
      votes.set(target.id, map);
    }
  }

  const out: Array<T & FoldedFields> = [];
  for (const r of records) {
    if (isEvent(r)) continue; // events are never bubbles
    if (r.expired) continue;
    if (r.expiresAt && timeOf(r.expiresAt) && timeOf(r.expiresAt) <= opts.nowMs && r.sendStatus === undefined) continue;
    if (
      opts.adminsOnly &&
      opts.adminIds &&
      r.sendStatus === undefined &&
      !r.deleted &&
      !opts.adminIds.has(r.sender)
    ) {
      continue;
    }
    const reactMap = reactions.get(r.id);
    const grouped: Record<string, string[]> = {};
    if (reactMap && !r.deleted) {
      for (const [uid, emoji] of reactMap) (grouped[emoji] ||= []).push(uid);
    }
    const edit = !r.deleted ? edits.get(r.id) : undefined;
    const pollDef = !r.deleted && r.canDecrypt ? cleanPoll(r.env?.poll) : undefined;
    let poll: PollTally | undefined;
    if (pollDef) {
      const tally: string[][] = pollDef.options.map(() => []);
      const voteMap = votes.get(r.id);
      let myVote: number[] = [];
      let voters = 0;
      if (voteMap) {
        for (const [uid, picked] of voteMap) {
          if (picked.length) voters++;
          for (const i of picked) tally[i].push(uid);
          if (uid === opts.myUserId) myVote = picked;
        }
      }
      poll = { question: pollDef.question, options: pollDef.options, multi: Boolean(pollDef.multi), votes: tally, totalVoters: voters, myVote };
    }
    const mentions = Array.isArray(r.env?.mentions) ? r.env!.mentions!.filter((m) => typeof m === 'string').slice(0, 50) : [];
    out.push({
      ...r,
      message: r.deleted ? '' : edit ? edit.text : r.message,
      reactions: grouped,
      edited: Boolean(edit),
      deleted: Boolean(r.deleted),
      poll,
      mentions,
    });
  }
  return out;
}

/** Whether `me` may still edit / delete a message they sent (server times, with the minute of slack). */
export function canEditMessage(msg: { sender: string; timestamp: string; deleted?: boolean; poll?: unknown }, me: string, nowMs: number): boolean {
  if (msg.sender !== me || msg.deleted || msg.poll) return false;
  return nowMs - timeOf(msg.timestamp) <= EDIT_WINDOW_MS;
}

export function canDeleteForEveryone(msg: { sender: string; timestamp: string; deleted?: boolean }, me: string, nowMs: number, isGroupAdmin: boolean): boolean {
  if (msg.deleted) return false;
  if (isGroupAdmin) return true;
  return msg.sender === me && nowMs - timeOf(msg.timestamp) <= DELETE_WINDOW_MS;
}

/** @mentions in text: returns the ids of members whose @username appears (case-insensitive). */
export function findMentionedIds(text: string, members: ReadonlyArray<{ user_id: string; username?: string | null }>, exclude?: string): string[] {
  const names = new Set(Array.from(text.matchAll(/(?<![A-Za-z0-9_])@([A-Za-z0-9_]{3,32})/g), (m) => m[1].toLowerCase()));
  if (!names.size) return [];
  const out: string[] = [];
  for (const m of members) {
    if (m.username && names.has(m.username.toLowerCase()) && m.user_id !== exclude && !out.includes(m.user_id)) out.push(m.user_id);
  }
  return out;
}

/** Case-insensitive search over displayed messages; returns ids in order. */
export function searchMessages(items: ReadonlyArray<{ id: string; message: string; deleted?: boolean; poll?: PollTally }>, query: string): string[] {
  const q = query.trim().toLowerCase();
  if (q.length < 2) return [];
  return items
    .filter((m) => !m.deleted && ((m.message || '').toLowerCase().includes(q) || (m.poll && m.poll.question.toLowerCase().includes(q))))
    .map((m) => m.id);
}

/** "24 hours" / "7 days" / "90 days" for a disappearing timer (0 = off). */
export function describeTimer(ttlSeconds: number): string {
  if (!ttlSeconds) return 'Off';
  if (ttlSeconds === 86400) return '24 hours';
  if (ttlSeconds % 86400 === 0) return `${ttlSeconds / 86400} days`;
  return `${Math.round(ttlSeconds / 3600)} hours`;
}
