/**
 * Resilient networking helpers for Zyphra.
 *
 * Why this exists
 * ---------------
 * After the site has been idle, the first request can hit a backend that is still
 * waking up (Render cold start) or a database connection that Neon already closed.
 * The browser then reports a bare "Failed to fetch" even though the very next
 * request works. `resilientFetch` hides that window: safe (GET/HEAD) requests are
 * retried with backoff, so the user just sees the page load a little later instead
 * of an error followed by a manual refresh.
 *
 * Non-idempotent requests (POST/PUT/PATCH/DELETE) are never retried automatically,
 * so a chat message can never be sent twice by the retry layer.
 */

const IDEMPOTENT_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const RETRYABLE_STATUS = new Set([500, 502, 503, 504]);
/** A plain 500 is usually a real bug, so it only gets a couple of quick retries. */
const MAX_RETRIES_FOR_500 = 2;

export interface ResilientFetchOptions {
  /** Total time (ms) to keep retrying before giving up. Default 30 000. */
  budgetMs?: number;
  /** Abort a single attempt after this many ms. Default 20 000. */
  attemptTimeoutMs?: number;
  /** Force retrying on/off. Default: only for GET/HEAD/OPTIONS. */
  retry?: boolean;
}

/** Thrown when the server could not be reached at all (after all retries). */
export class NetworkUnreachableError extends Error {
  constructor(cause?: unknown) {
    super('Cannot reach the Zyphra server right now. It may be waking up, so please try again in a moment.');
    this.name = 'NetworkUnreachableError';
    (this as { cause?: unknown }).cause = cause;
  }
}

/** Extra random wait (0 to 2 s) so thousands of browsers do not all reconnect in the same instant after a restart. */
export function reconnectJitterMs(): number {
  return Math.random() * 2000;
}

/** When the server says it is full (close code 4503): try again in 20 to 60 seconds, not every second. */
export function serverFullDelayMs(): number {
  return 20000 + Math.random() * 40000;
}

/** Exponential backoff with jitter: ~0.4s, 0.8s, 1.6s, 3.2s, 5s, 5s ... */
export function backoffDelay(attempt: number, capMs = 5000): number {
  const base = Math.min(400 * 2 ** Math.max(0, attempt), capMs);
  return Math.round(base * (0.8 + Math.random() * 0.4));
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

function retryAfterMs(res: Response): number | null {
  const raw = res.headers.get('retry-after');
  if (!raw) return null;
  const secs = Number(raw);
  if (!Number.isFinite(secs) || secs < 0) return null;
  return Math.min(secs * 1000, 5000);
}

export async function resilientFetch(
  url: string,
  init: RequestInit = {},
  opts: ResilientFetchOptions = {}
): Promise<Response> {
  const method = (init.method || 'GET').toUpperCase();
  const canRetry = opts.retry ?? IDEMPOTENT_METHODS.has(method);
  const budgetMs = opts.budgetMs ?? 30000;
  const attemptTimeoutMs = opts.attemptTimeoutMs ?? 20000;
  const startedAt = Date.now();
  const callerSignal = init.signal ?? null;

  let attempt = 0;
  let count500 = 0;

  for (; ;) {
    const controller = new AbortController();
    const forwardAbort = () => controller.abort();
    if (callerSignal) {
      if (callerSignal.aborted) controller.abort();
      else callerSignal.addEventListener('abort', forwardAbort, { once: true });
    }
    const timeout = canRetry ? setTimeout(() => controller.abort(), attemptTimeoutMs) : null;

    try {
      const res = await fetch(url, { ...init, signal: controller.signal });
      if (!canRetry || !RETRYABLE_STATUS.has(res.status)) return res;

      if (res.status === 500 && ++count500 > MAX_RETRIES_FOR_500) return res;
      const delay = retryAfterMs(res) ?? backoffDelay(attempt);
      if (Date.now() - startedAt + delay > budgetMs) return res; // out of budget: surface the real response
      attempt += 1;
      await sleep(delay);
    } catch (err) {
      if (callerSignal?.aborted) throw err; // the caller cancelled on purpose
      const delay = backoffDelay(attempt);
      if (!canRetry) throw new NetworkUnreachableError(err);
      if (Date.now() - startedAt + delay > budgetMs) throw new NetworkUnreachableError(err);
      attempt += 1;
      await sleep(delay);
    } finally {
      if (timeout) clearTimeout(timeout);
      if (callerSignal) callerSignal.removeEventListener('abort', forwardAbort);
    }
  }
}

/**
 * Calls `cb` when the browser comes back online or the tab becomes visible again
 * (laptop wake, phone unlock, switching tabs). Returns an unsubscribe function.
 * Used so WebSockets reconnect immediately instead of waiting out a backoff timer.
 */
export function onWake(cb: () => void): () => void {
  if (typeof window === 'undefined' || typeof document === 'undefined') return () => { };
  const onVisible = () => {
    if (document.visibilityState === 'visible') cb();
  };
  window.addEventListener('online', cb);
  document.addEventListener('visibilitychange', onVisible);
  return () => {
    window.removeEventListener('online', cb);
    document.removeEventListener('visibilitychange', onVisible);
  };
}