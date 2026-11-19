/**
 * Pure helpers for the chat view's incremental sync and instant ("optimistic") sending.
 * Kept free of React / browser APIs so they can be unit-tested with the Node runner.
 */

export type LocalSendStatus = 'sending' | 'delivered' | 'failed';

export interface LocalEntryLike {
  id: string;
  localScope?: string;
  sendStatus?: LocalSendStatus;
}

/**
 * Combine the messages the server returned with this browser's own not-yet-confirmed entries.
 *
 * - Local entries (sending / just delivered / failed) of the SAME conversation stay visible.
 * - An entry disappears from the local list as soon as the server list contains its id
 *   (the real message replaces the optimistic one, no duplicate).
 * - Entries that belong to another conversation never leak into this one.
 */
export function mergeLocalEntries<T extends LocalEntryLike>(
  server: T[],
  prev: T[],
  scope: string
): T[] {
  const ids = new Set(server.map((m) => m.id));
  const locals = prev.filter(
    (m) =>
      m.localScope === scope &&
      (m.sendStatus === 'sending' || m.sendStatus === 'delivered' || m.sendStatus === 'failed') &&
      !ids.has(m.id)
  );
  return locals.length ? [...server, ...locals] : server;
}
