/**
 * Chat Platform REST + Public WebSocket Client (`/api/platform/*` & `/ws/public-chat`).
 *
 * Covers:
 * - Open Public Chat (readable feed, cursor pagination, edit/delete, real-time `/ws/public-chat`)
 * - Username Search Directory, Extended Profile, Identity/Wallet/Level History, User Blocks,
 *   DM Read Receipts & Abuse Reporting
 * - Wallet-Based Levels (starting at Level 7) & Server-Side Ethereum RPC Balance Verification
 * - Group Access Policies (`min_eth_balance_eth`, `visibility`, paid/free), Invite Links,
 *   Public Group Discovery, Policy-Gated Join Requests & Leave Group
 * - RBAC Admin Console (`superadmin` / `moderator` / break-glass `X-Admin-Token`) & Audit Logs
 */

import { getBaseApiUrl } from './api.ts';
import { resilientFetch, backoffDelay, onWake, reconnectJitterMs, serverFullDelayMs } from './resilientFetch.ts';
import { getE2EESessionId, getE2EESessionToken, type E2EEAccountProfile, type E2EEGroupAccessPolicy } from './e2eeApi.ts';

export interface PublicChatMessageRecord {
  seq: number;
  message_id: string;
  author_user_id: string | null;
  guest_id: string | null;
  display_name: string;
  author_level: number;
  is_guest: boolean;
  content: string;
  edited_at: string | null;
  deleted_at?: string | null;
  created_at: string;
  /** Files and images posted with the message (Members' room files are not end-to-end encrypted). */
  attachments?: PublicChatAttachmentRecord[];
  /** emoji -> user ids (one reaction per member) */
  reactions?: Record<string, string[]>;
  /** The message this one replies to (id), and the quote the server built from it. */
  reply_to_message_id?: string | null;
  reply_to?: PublicChatReplyQuote | null;
}

/** Quote on top of a Members' room reply. `available` is false when the original was deleted or blocked. */
export interface PublicChatReplyQuote {
  message_id: string;
  author_user_id: string | null;
  display_name: string | null;
  preview: string | null;
  available: boolean;
}

export interface PublicChatAttachmentRecord {
  attachment_id: string;
  file_name: string;
  mime_type: string;
  kind: 'image' | 'video' | 'audio' | 'file';
  size_bytes: number;
}

export interface PublicChatFeedResponse {
  room: string;
  security_notice: string;
  messages: PublicChatMessageRecord[];
  next_before_seq: number | null;
  /** Pinned Members' room messages (newest first, up to 3) */
  pins?: Array<{ message_id: string; pinned_by: string; pinned_at: string | null }>;
  online: {
    watching?: number;
    active_live?: number;
    authenticated_users?: number;
    public_viewers: number;
  };
  policy: {
    guest_read_enabled: boolean;
    guest_posting_enabled: boolean;
    max_length: number;
    edit_window_seconds: number;
    retention_days?: number;
    max_file_bytes?: number;
    max_files_per_message?: number;
  };
}

export interface DirectoryUserRecord {
  user_id: string;
  username: string | null;
  display_name: string | null;
  bio: string | null;
  current_level: number;
  highest_level: number;
  primary_wallet: string | null;
  online: boolean;
  created_at: string;
}

export interface BalanceSnapshotRecord {
  snapshot_id: string;
  user_id: string;
  wallet_address: string;
  chain_id: number;
  balance_wei: string;
  balance_eth?: string;
  block_number: number;
  rpc_source: string;
  qualified_level: number;
  verified_at: string;
}

export interface PaymentRecord {
  payment_id: string;
  user_id: string;
  wallet_address: string | null;
  amount_atomic: string;
  amount_formatted: string;
  currency: string;
  network: string;
  chain_id: number | null;
  status: 'pending' | 'verified' | 'failed' | 'cancelled' | 'reversed';
  transaction_reference: string;
  block_number: number | null;
  verification_source: string;
  verified_at: string | null;
  error_message: string | null;
  retry_count: number;
  metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface DiscoverableGroupRecord {
  group_id: string;
  name: string;
  creator_user_id: string;
  current_epoch: number;
  ciphersuite: string;
  description: string;
  visibility: 'public' | 'invite_only';
  min_eth_balance_wei: string;
  min_eth_balance_eth: string;
  require_invitation: boolean;
  is_paid?: boolean;
  entry_fee_eth?: string;
  entry_fee_wei?: string;
  /** Price set by the admin, in US dollars (the ETH amount is converted at payment time). */
  /** Monthly price in USD. */
  entry_fee_usd?: number | string;
  /** Yearly price in USD ('0' = automatic, 12 x monthly). */
  entry_fee_yearly_usd?: number | string;
  eth_usd_price?: number;
  has_paid?: boolean;
  active_member_count: number;
  is_member: boolean;
  created_at: string;
}

/** "$20.00/month · $240.00/year" for a paid group (yearly is 12 x monthly unless the admin set one). */
export function formatGroupFee(g: {
  entry_fee_usd?: number | string;
  entry_fee_yearly_usd?: number | string;
  entry_fee_eth?: string;
}): string {
  const monthly = Number(g.entry_fee_usd || 0);
  if (monthly <= 0) return `${g.entry_fee_eth || '0'} ETH / month`;
  const yearlyCfg = Number(g.entry_fee_yearly_usd || 0);
  const yearly = yearlyCfg > 0 ? yearlyCfg : monthly * 12;
  return `$${monthly.toFixed(2)}/month · $${yearly.toFixed(2)}/year`;
}

/** One billing plan: what to pay (USD + ETH) and how many days of access it buys. */
export interface BillingPlan {
  usd: number;
  eth: string;
  wei: string;
  days: number;
}

export type BillingPeriod = 'monthly' | 'yearly';

export interface BillingPlans {
  monthly: BillingPlan;
  yearly: BillingPlan;
}

export interface PlatformPricing {
  platform_entry_fee_eth: string;
  platform_entry_fee_wei: string;
  eth_usd_price: number;
  /** Monthly price (kept under the old name). */
  platform_entry_fee_usd: number;
  platform_monthly_fee_usd: number;
  platform_yearly_fee_usd: number;
  /** True when the admin left the yearly price empty (it is then 12 x monthly). */
  yearly_is_auto: boolean;
  plans: BillingPlans;
  /** 'live' | 'live_cached' | 'live_stale' | 'admin_fixed' */
  rate_source?: string;
  quoted_at?: string;
  authorized_payment_destination: string | null;
  allowed_payment_chain_ids: number[];
}

export interface SubscriptionRecord {
  scope_type: 'platform' | 'group';
  scope_id: string;
  paid_until: string | null;
  last_period: BillingPeriod;
  active: boolean;
}

export interface GroupSubscriptionRecord extends SubscriptionRecord {
  group_id: string;
  group_name: string;
}

export interface PlatformMembershipStatus {
  user_id: string;
  wallet_address: string | null;
  is_platform_paid: boolean;
  platform_paid_at: string | null;
  /** When the current membership period ends (null = never paid). */
  platform_paid_until: string | null;
  platform_period: BillingPeriod | null;
  /** The admin set the monthly price to $0: nothing to pay. */
  membership_is_free: boolean;
  total_verified_wei?: string;
  total_verified_eth?: string;
  group_subscriptions: GroupSubscriptionRecord[];
  /** Free membership given by an admin (null = none). Absent on older servers. */
  platform_free_access?: FreeAccessPeriod | null;
  /** Groups an admin gave this member free access to. Absent on older servers. */
  group_free_access?: Array<FreeAccessPeriod & { group_id: string; group_name: string }>;
  pricing: PlatformPricing;
}

/** How long a free-access grant lasts: until a date, or with no end date. */
export interface FreeAccessPeriod {
  expires_at: string | null;
  lifetime: boolean;
}

/** One free-access grant, as the admin console sees it. */
export interface AccessGrant extends FreeAccessPeriod {
  user_id: string;
  username: string | null;
  scope_type: 'platform' | 'group';
  /** 'platform' or the group id */
  scope_id: string;
  group_name: string | null;
  granted_by: string;
  note: string;
  created_at: string | null;
  revoked_at: string | null;
  revoked_by: string | null;
  active: boolean;
}

/** "Mar 3, 2027" for a date, or "—". */
export function formatDate(iso?: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? '—'
    : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

/** Whole days left until `iso` (0 when passed). */
export function daysLeft(iso?: string | null): number {
  if (!iso) return 0;
  const ms = new Date(iso).getTime() - Date.now();
  return ms > 0 ? Math.ceil(ms / 86400000) : 0;
}

export interface GroupPricing {
  group_id: string;
  name: string;
  is_paid: boolean;
  entry_fee_eth: string;
  entry_fee_wei: string;
  /** Monthly price in USD. */
  entry_fee_usd: number;
  entry_fee_yearly_usd?: number;
  plans: BillingPlans;
  eth_usd_price: number;
  rate_source?: string;
  has_paid: boolean;
  authorized_payment_destination: string | null;
  allowed_payment_chain_ids: number[];
}

export interface GroupJoinRequestRecord {
  request_id: string;
  group_id: string;
  user_id: string;
  username: string | null;
  current_level: number;
  qualifying_balance_wei: string;
  invite_code: string | null;
  status: string;
  created_at: string;
}

function buildPlatformHeaders(adminToken?: string | null): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  const sessionTok = getE2EESessionToken();
  if (sessionTok) {
    headers['Authorization'] = `Bearer ${sessionTok}`;
  }
  const sessionId = getE2EESessionId();
  if (sessionId) {
    headers['X-Session-Id'] = sessionId;
  }
  if (adminToken && adminToken.trim()) {
    headers['X-Admin-Token'] = adminToken.trim();
  }
  return headers;
}

/** Tells the app that a request was refused because a subscription is missing or expired. */
/** A join attempt refused because the group is paid and the member has no subscription yet. */
export interface GroupPaymentRequiredDetail {
  code: 'group_payment_required';
  message: string;
  group_id: string;
  group_name: string;
}

export function isGroupPaymentRequired(err: unknown): err is Error & { status: 402; detail: GroupPaymentRequiredDetail } {
  const e = err as any;
  return Boolean(e && e.status === 402 && e.detail && e.detail.code === 'group_payment_required' && e.detail.group_id);
}

export function announcePaymentRequired(message: string): void {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('zyphra:payment-required', { detail: { message } }));
  }
}

async function platformFetch<T>(
  path: string,
  init?: RequestInit,
  adminToken?: string | null
): Promise<T> {
  const base = getBaseApiUrl();
  const res = await resilientFetch(`${base}/platform${path}`, {
    ...init,
    credentials: 'include',
    headers: {
      ...buildPlatformHeaders(adminToken),
      ...((init?.headers as Record<string, string>) || {}),
    },
  });
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('text/html')) {
    throw new Error(
      `Expected JSON response from backend but received HTML (HTTP ${res.status}). Verify API proxy or backend URL.`
    );
  }
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg =
      typeof json.detail === 'string'
        ? json.detail
        : typeof json.detail?.message === 'string'
          ? json.detail.message
          : Array.isArray(json.summary) && json.summary.length > 0
            ? json.summary.join('; ')
            : json.error || `HTTP ${res.status}`;
    const err: any = new Error(msg);
    err.status = res.status;
    err.detail = json.detail;
    // 402 = membership / group subscription expired: let the app send the member to Payments to renew.
    // Exception: joining a paid group they have never paid for. The caller opens that group's payment
    // window instead (see isGroupPaymentRequired), so do not navigate away.
    if (res.status === 402 && !adminToken && !isGroupPaymentRequired(err)) announcePaymentRequired(msg);
    throw err;
  }
  return json as T;
}

let inMemoryGuestToken: string | null = null;

// ----------------------------------------------------------------------------
// Admin Console login (/Admin456). The session token lives in sessionStorage only
// (cleared when the tab closes) and is sent as X-Admin-Token.
// ----------------------------------------------------------------------------
const ADMIN_SESSION_KEY = 'zyphra_admin_session';

export function getStoredAdminSession(): string | null {
  try {
    return sessionStorage.getItem(ADMIN_SESSION_KEY);
  } catch {
    return null;
  }
}

function storeAdminSession(token: string | null): void {
  try {
    if (token) sessionStorage.setItem(ADMIN_SESSION_KEY, token);
    else sessionStorage.removeItem(ADMIN_SESSION_KEY);
  } catch {
    // ignore storage failures
  }
}

export async function adminLogin(loginId: string, password: string): Promise<string> {
  const res = await platformFetch<{ token: string }>('/admin/login', {
    method: 'POST',
    body: JSON.stringify({ login_id: loginId, password }),
  });
  storeAdminSession(res.token);
  return res.token;
}

export async function adminSessionValid(token: string): Promise<boolean> {
  try {
    await platformFetch('/admin/session', undefined, token);
    return true;
  } catch {
    return false;
  }
}

export async function adminLogout(token: string | null): Promise<void> {
  try {
    if (token) await platformFetch('/admin/logout', { method: 'POST' }, token);
  } catch {
    // best effort
  } finally {
    storeAdminSession(null);
  }
}

export function getOrCreateGuestSessionToken(): string {
  if (!inMemoryGuestToken) {
    const rand = new Uint8Array(12);
    crypto.getRandomValues(rand);
    inMemoryGuestToken = Array.from(rand)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
  return inMemoryGuestToken;
}

// ============================================================================
// 1. OPEN PUBLIC CHAT + REAL-TIME WEBSOCKET
// ============================================================================

export async function fetchPublicChatFeed(
  beforeSeq?: number | null,
  limit = 50,
  walletAddress?: string | null
): Promise<PublicChatFeedResponse> {
  const qs = new URLSearchParams({ limit: String(limit) });
  if (beforeSeq && beforeSeq > 0) {
    qs.set('before_seq', String(beforeSeq));
  }
  const extraHeaders: Record<string, string> = {};
  if (walletAddress && walletAddress.trim()) {
    extraHeaders['X-Wallet-Address'] = walletAddress.trim();
  }
  return platformFetch(`/public-chat/messages?${qs.toString()}`, {
    headers: extraHeaders,
  });
}

export async function postPublicChatMessage(
  content: string,
  forceAuthed = false,
  attachmentIds: string[] = [],
  replyToMessageId: string | null = null
): Promise<{
  success: boolean;
  message: PublicChatMessageRecord;
}> {
  const isAuthed = forceAuthed || Boolean(getE2EESessionToken());
  return platformFetch('/public-chat/messages', {
    method: 'POST',
    body: JSON.stringify({
      content,
      guest_token: isAuthed ? undefined : getOrCreateGuestSessionToken(),
      attachment_ids: attachmentIds.length ? attachmentIds : undefined,
      reply_to_message_id: replyToMessageId || undefined,
    }),
  });
}

function fileToBase64(file: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => {
      const res = String(r.result || '');
      resolve(res.slice(res.indexOf(',') + 1));
    };
    r.onerror = () => reject(new Error('Could not read the file.'));
    r.readAsDataURL(file);
  });
}

/** Uploads one file for the Members' room; attach the returned id when posting the message. */
export async function uploadPublicChatAttachment(file: File): Promise<{ success: boolean; attachment: PublicChatAttachmentRecord }> {
  const data_b64 = await fileToBase64(file);
  return platformFetch('/public-chat/attachments', {
    method: 'POST',
    body: JSON.stringify({ file_name: file.name || 'file', mime_type: file.type || 'application/octet-stream', data_b64 }),
  });
}

/** Downloads a Members' room file (with the member's session) as a Blob of the right type. */
export async function fetchPublicChatAttachmentBlob(attachmentId: string, mimeType?: string): Promise<Blob> {
  const base = getBaseApiUrl();
  const headers = buildPlatformHeaders();
  delete headers['Content-Type'];
  const res = await resilientFetch(`${base}/platform/public-chat/attachments/${encodeURIComponent(attachmentId)}`, {
    credentials: 'include',
    headers,
  });
  if (!res.ok) {
    const json = await res.json().catch(() => ({}) as any);
    const err: any = new Error(typeof json.detail === 'string' ? json.detail : `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  const buf = await res.arrayBuffer();
  // The server sends non-images as application/octet-stream; restore the real type for playback/saving.
  return new Blob([buf], { type: mimeType || res.headers.get('X-Zyphra-File-Type') || 'application/octet-stream' });
}

export async function editPublicChatMessage(
  messageId: string,
  content: string
): Promise<{ success: boolean; message_id: string; content: string; edited_at: string }> {
  return platformFetch(`/public-chat/messages/${encodeURIComponent(messageId)}`, {
    method: 'PATCH',
    body: JSON.stringify({ content }),
  });
}

export async function deletePublicChatMessage(
  messageId: string,
  reason = '',
  adminToken?: string | null
): Promise<{ success: boolean; message_id: string }> {
  const qs = reason ? `?reason=${encodeURIComponent(reason)}` : '';
  return platformFetch(
    `/public-chat/messages/${encodeURIComponent(messageId)}${qs}`,
    { method: 'DELETE' },
    adminToken
  );
}



function resolveWsBaseUrl(wsPath: string): string {
  const apiBase = getBaseApiUrl().replace(/\/api\/?$/, '');
  if (apiBase.startsWith('https://')) {
    return `wss://${apiBase.slice('https://'.length)}${wsPath}`;
  }
  if (apiBase.startsWith('http://')) {
    return `ws://${apiBase.slice('http://'.length)}${wsPath}`;
  }
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}${wsPath}`;
}

function closeWebSocketSafely(target: WebSocket | null): void {
  if (!target) return;
  target.onmessage = null;
  target.onclose = null;
  target.onerror = null;
  if (target.readyState === WebSocket.CONNECTING) {
    target.onopen = () => {
      try {
        target.close();
      } catch {
        // ignore
      }
    };
    return;
  }
  target.onopen = null;
  if (target.readyState === WebSocket.OPEN) {
    try {
      target.close();
    } catch {
      // ignore
    }
  }
}

export function connectPublicChatWebSocket(
  onEvent: (evt: Record<string, any>) => void,
  initialWalletAddress?: string | null
): { close: () => void; setMemberWallet: (walletAddress: string | null) => void } {
  if (typeof WebSocket === 'undefined') {
    return { close: () => { }, setMemberWallet: () => { } };
  }

  let closed = false;
  let currentWallet: string | null = initialWalletAddress ? initialWalletAddress.trim() : null;
  let ws: WebSocket | null = null;
  let pingTimer: ReturnType<typeof setInterval> | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let hasConnectedBefore = false;

  let reconnectAttempts = 0;
  const scheduleReconnect = (delayMs?: number) => {
    if (closed) return;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(openSocket, delayMs ?? backoffDelay(reconnectAttempts++, 15000) + reconnectJitterMs());
  };
  // Laptop woke up / network is back / tab visible again: reconnect right away.
  const stopWake = onWake(() => {
    if (closed) return;
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
    reconnectAttempts = 0;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    openSocket();
  });

  const getWsUrl = (): string => {
    const connectedFlag = currentWallet ? '1' : '0';
    return `${resolveWsBaseUrl('/ws/public-chat')}?connected=${connectedFlag}`;
  };

  const openSocket = () => {
    if (closed) return;
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
    try {
      ws = new WebSocket(getWsUrl());
      ws.onopen = () => {
        // Members-only stream: the first frame must authenticate a paid session.
        const sessionToken = getE2EESessionToken();
        if (sessionToken && ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'auth', token: sessionToken }));
        }
        reconnectAttempts = 0;
        if (hasConnectedBefore) {
          // Messages may have been missed while offline: tell the UI to re-sync the feed.
          onEvent({ type: 'ws_reconnected' });
        }
        hasConnectedBefore = true;
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(
            JSON.stringify({
              type: 'presence_status',
              wallet_address: currentWallet,
            })
          );
        }
        pingTimer = setInterval(() => {
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
          }
        }, 20000);
      };
      ws.onmessage = (ev) => {
        try {
          const parsed = JSON.parse(String(ev.data));
          if (parsed && parsed.type) {
            onEvent(parsed);
          }
        } catch {
          // ignore malformed frames
        }
      };
      ws.onclose = (ev) => {
        if (pingTimer) clearInterval(pingTimer);
        // 4401 = not signed in, 4402 = membership not paid: retrying cannot help.
        if (ev.code === 4401 || ev.code === 4402) {
          onEvent({ type: 'ws_unauthorized', code: ev.code });
          return;
        }
        if (ev.code === 4503) {
          // The server is full right now: tell the page (it falls back to refreshing) and retry slowly.
          onEvent({ type: 'ws_capacity' });
          scheduleReconnect(serverFullDelayMs());
          return;
        }
        scheduleReconnect();
      };
    } catch {
      scheduleReconnect();
    }
  };

  openSocket();

  return {
    setMemberWallet(walletAddress: string | null) {
      const next = walletAddress && walletAddress.trim() ? walletAddress.trim() : null;
      if (next === currentWallet) return;
      currentWallet = next;
      if (ws && ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(
            JSON.stringify({
              type: 'presence_status',
              wallet_address: currentWallet,
            })
          );
        } catch {
          // ignore send errors on closing socket
        }
      }
    },
    close() {
      closed = true;
      stopWake();
      if (pingTimer) clearInterval(pingTimer);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      closeWebSocketSafely(ws);
      ws = null;
    },
  };
}

export function connectMemberPresenceWebSocket(
  walletAddress: string
): { close: () => void; updateWallet: (nextWallet: string) => void } {
  if (typeof WebSocket === 'undefined' || !walletAddress.trim()) {
    return { close: () => { }, updateWallet: () => { } };
  }

  let closed = false;
  let currentWallet = walletAddress.trim();
  let ws: WebSocket | null = null;
  let pingTimer: ReturnType<typeof setInterval> | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  let reconnectAttempts = 0;
  const scheduleReconnect = (delayMs?: number) => {
    if (closed) return;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(openSocket, delayMs ?? backoffDelay(reconnectAttempts++, 15000) + reconnectJitterMs());
  };
  // Laptop woke up / network is back / tab visible again: reconnect right away.
  const stopWake = onWake(() => {
    if (closed) return;
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
    reconnectAttempts = 0;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    openSocket();
  });

  const openSocket = () => {
    if (closed) return;
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
    try {
      ws = new WebSocket(resolveWsBaseUrl('/ws/member-presence'));
      ws.onopen = () => {
        reconnectAttempts = 0;
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(
            JSON.stringify({
              type: 'member_online',
              wallet_address: currentWallet,
            })
          );
        }
        pingTimer = setInterval(() => {
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
          }
        }, 20000);
      };
      ws.onclose = (ev) => {
        if (pingTimer) clearInterval(pingTimer);
        if (ev.code === 4503) scheduleReconnect(serverFullDelayMs());
        else if (ev.code !== 4401) scheduleReconnect();
      };
    } catch {
      scheduleReconnect();
    }
  };

  openSocket();

  return {
    updateWallet(nextWallet: string) {
      const cleaned = nextWallet.trim();
      if (!cleaned) return;
      currentWallet = cleaned;
      if (ws && ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(
            JSON.stringify({
              type: 'member_online',
              wallet_address: currentWallet,
            })
          );
        } catch {
          // ignore
        }
      }
    },
    close() {
      closed = true;
      stopWake();
      if (pingTimer) clearInterval(pingTimer);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      closeWebSocketSafely(ws);
      ws = null;
    },
  };
}

// ============================================================================
// 2. SEARCH, PROFILE, HISTORY, BLOCKS, READ RECEIPTS & ABUSE REPORTS
// ============================================================================

export async function searchUsers(query = '', limit = 25): Promise<{ users: DirectoryUserRecord[] }> {
  const qs = new URLSearchParams({ q: query, limit: String(limit) });
  return platformFetch(`/users/search?${qs.toString()}`);
}

export async function updateMyProfile(payload: {
  display_name?: string | null;
  bio?: string | null;
  show_online_presence?: boolean;
  send_read_receipts?: boolean;
}): Promise<{ success: boolean; user: E2EEAccountProfile }> {
  return platformFetch('/profile', {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });
}

export async function fetchMyIdentityHistory(): Promise<{
  user_id: string;
  username_history: Array<{
    history_id: string;
    old_username: string | null;
    new_username: string;
    reserved_until: string | null;
    changed_at: string;
  }>;
  wallets: Array<{
    wallet_address: string;
    is_primary: boolean;
    status: string;
    linked_at: string;
    revoked_at?: string | null;
  }>;
  wallet_history: Array<{
    history_id: string;
    action: string;
    old_wallet_address: string | null;
    new_wallet_address: string;
    created_at: string;
  }>;
  balance_snapshots: BalanceSnapshotRecord[];
  level_history: Array<{
    history_id: string;
    previous_level: number;
    new_level: number;
    reason: string;
    balance_wei: string;
    chain_id: number;
    created_at: string;
  }>;
}> {
  return platformFetch('/profile/history');
}

export async function fetchBlockedUsers(): Promise<{
  blocked_users: Array<{
    blocked_user_id: string;
    username: string | null;
    display_name: string | null;
    reason: string;
    created_at: string;
  }>;
}> {
  return platformFetch('/blocks');
}

export async function blockUser(targetUserId: string, reason = ''): Promise<{ success: boolean }> {
  return platformFetch('/blocks', {
    method: 'POST',
    body: JSON.stringify({ target_user_id: targetUserId, reason }),
  });
}

export async function unblockUser(targetUserId: string): Promise<{ success: boolean }> {
  return platformFetch(`/blocks/${encodeURIComponent(targetUserId)}`, {
    method: 'DELETE',
  });
}

export async function sendDmReadReceipt(
  peerUserId: string,
  lastReadSeq: number
): Promise<{ success: boolean; receipt: any }> {
  return platformFetch('/dm/read-receipt', {
    method: 'POST',
    body: JSON.stringify({ peer_user_id: peerUserId, last_read_seq: lastReadSeq }),
  });
}

export async function fetchDmReadReceipts(peerUserId: string): Promise<{
  receipts: Record<string, { last_read_seq: number; updated_at: string }>;
}> {
  return platformFetch(`/dm/read-receipts/${encodeURIComponent(peerUserId)}`);
}

export async function submitAbuseReport(payload: {
  scope_type: 'public_chat' | 'dm' | 'group' | 'user';
  scope_id: string;
  reason: string;
  details?: string;
  target_user_id?: string | null;
  message_id?: string | null;
}): Promise<{ success: boolean; report: any }> {
  return platformFetch('/reports', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

// ============================================================================
// 3. WALLET-BASED LEVELS (LEVEL 7+) & SERVER-SIDE ETH BALANCE VERIFICATION
// ============================================================================

export async function verifyMyWalletBalance(chainId?: number): Promise<{
  success: boolean;
  snapshot: BalanceSnapshotRecord;
  user: E2EEAccountProfile;
}> {
  return platformFetch('/wallet/verify-balance', {
    method: 'POST',
    body: JSON.stringify(chainId ? { chain_id: chainId } : {}),
  });
}

export async function submitPaymentForVerification(
  transactionReference: string,
  chainId?: number,
  purpose: 'platform_entry' | 'group_entry' = 'platform_entry',
  groupId?: string,
  billingPeriod: BillingPeriod = 'monthly'
): Promise<{
  success: boolean;
  status: string;
  payment: PaymentRecord;
  already_verified?: boolean;
  user?: E2EEAccountProfile;
  is_platform_paid?: boolean;
  billing_period?: BillingPeriod;
  subscription?: SubscriptionRecord | null;
  reason?: string;
}> {
  return platformFetch('/payments/verify', {
    method: 'POST',
    body: JSON.stringify({
      transaction_reference: transactionReference,
      chain_id: chainId,
      purpose,
      group_id: groupId,
      billing_period: billingPeriod,
    }),
  });
}

export async function fetchPlatformPricing(): Promise<PlatformPricing> {
  return platformFetch('/pricing');
}

export async function fetchMembershipStatus(): Promise<PlatformMembershipStatus> {
  return platformFetch('/membership/status');
}

export async function fetchGroupPricing(groupId: string): Promise<GroupPricing> {
  return platformFetch(`/groups/${encodeURIComponent(groupId)}/pricing`);
}

export async function fetchMyPaymentHistory(limit = 50): Promise<{
  user_id: string;
  total_verified_wei: string;
  total_verified_eth: string;
  payments: PaymentRecord[];
}> {
  return platformFetch(`/payments/history?limit=${encodeURIComponent(limit)}`);
}

// ============================================================================
// 4. GROUP ACCESS POLICIES, DISCOVERY, INVITE LINKS & LEAVE GROUP
// ============================================================================

export async function discoverPublicGroups(): Promise<{ groups: DiscoverableGroupRecord[] }> {
  return platformFetch('/groups/discover');
}

export async function fetchGroupPolicy(groupId: string): Promise<{
  group_id: string;
  name: string;
  policy: E2EEGroupAccessPolicy;
}> {
  return platformFetch(`/groups/${encodeURIComponent(groupId)}/policy`);
}

export async function updateGroupPolicy(
  groupId: string,
  payload: {
    description: string;
    visibility: 'public' | 'invite_only';
    min_eth_balance_eth?: string;
    require_invitation: boolean;
    is_paid?: boolean;
    /** Platform superadmin only. MONTHLY price in US dollars. */
    entry_fee_usd?: number;
    /** Platform superadmin only. YEARLY price in US dollars (0 = automatic, 12 x monthly). */
    entry_fee_yearly_usd?: number;
    entry_fee_eth?: string;
  },
  adminToken?: string | null
): Promise<{ success: boolean; policy: E2EEGroupAccessPolicy }> {
  return platformFetch(
    `/groups/${encodeURIComponent(groupId)}/policy`,
    {
      method: 'PUT',
      body: JSON.stringify(payload),
    },
    adminToken
  );
}



export async function requestJoinPublicGroup(groupId: string): Promise<{
  success: boolean;
  request_id: string;
  group_id: string;
  status: string;
}> {
  return platformFetch(`/groups/${encodeURIComponent(groupId)}/join-request`, {
    method: 'POST',
  });
}

export async function fetchGroupJoinRequests(groupId: string): Promise<{
  requests: GroupJoinRequestRecord[];
}> {
  return platformFetch(`/groups/${encodeURIComponent(groupId)}/join-requests`);
}

/** Group admins: turn down a pending join request. */
export async function declineGroupJoinRequest(
  groupId: string,
  requestId: string
): Promise<{ success: boolean; request_id: string; status: 'declined' }> {
  return platformFetch(
    `/groups/${encodeURIComponent(groupId)}/join-requests/${encodeURIComponent(requestId)}/decline`,
    { method: 'POST' }
  );
}

export async function leaveEncryptedGroup(groupId: string): Promise<{
  success: boolean;
  left_group_id: string;
}> {
  return platformFetch(`/groups/${encodeURIComponent(groupId)}/leave`, {
    method: 'POST',
  });
}

/** A group admin deletes their group for good (paid groups: platform admin only). */
export async function deleteGroup(groupId: string): Promise<{
  success: boolean;
  group_id: string;
  name: string;
  removed_messages: number;
  removed_files: number;
}> {
  return platformFetch(`/groups/${encodeURIComponent(groupId)}`, { method: 'DELETE' });
}

/** Admin456: delete any group. */
export async function adminDeleteGroup(
  groupId: string,
  adminToken?: string | null
): Promise<{ success: boolean; group_id: string; name: string; removed_messages: number; removed_files: number }> {
  return platformFetch(`/admin/groups/${encodeURIComponent(groupId)}`, { method: 'DELETE' }, adminToken);
}

export async function setGroupMemberRole(
  groupId: string,
  targetUserId: string,
  role: 'admin' | 'member'
): Promise<{ success: boolean }> {
  return platformFetch(
    `/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(targetUserId)}/role`,
    {
      method: 'POST',
      body: JSON.stringify({ role }),
    }
  );
}

// ============================================================================
// 5. ADMIN CONSOLE, RBAC & AUDIT LOGS
// ============================================================================

export async function fetchAdminOverview(adminToken?: string | null): Promise<{
  role: string;
  actor_user_id: string;
  stats: {
    /** Every wallet that has signed in (registered), paying or not. */
    total_users: number;
    /** People whose platform subscription is active right now. */
    paid_members?: number;
    /** True while the monthly price is $0 (everyone has access). */
    membership_free?: boolean;
    /** DISTINCT people with a valid login (a login lasts 24 h). */
    active_sessions: number;
    /** Groups that exist and still have at least one member. */
    total_groups: number;
    /** Room messages members can still see (inside the retention window). */
    public_messages: number;
    encrypted_dm_messages: number;
    encrypted_group_messages: number;
    open_reports: number;
    generated_at?: string;
  };
  online: { authenticated_users: number; public_viewers: number; admins_online?: number };
  networks: Record<string, any>;
}> {
  return platformFetch('/admin/overview', undefined, adminToken);
}

export async function fetchAdminUsers(
  query = '',
  adminToken?: string | null
): Promise<{ users: any[] }> {
  return platformFetch(
    `/admin/users?q=${encodeURIComponent(query)}&limit=100`,
    undefined,
    adminToken
  );
}



export async function inspectAdminUser(
  targetUserId: string,
  adminToken?: string | null
): Promise<any> {
  return platformFetch(
    `/admin/users/${encodeURIComponent(targetUserId)}/inspect`,
    undefined,
    adminToken
  );
}



export async function moderateAdminUser(
  targetUserId: string,
  payload: {
    action_type: 'suspend' | 'mute' | 'restore';
    reason: string;
    duration_hours?: number;
  },
  adminToken?: string | null
): Promise<{ success: boolean; user: any }> {
  return platformFetch(
    `/admin/users/${encodeURIComponent(targetUserId)}/moderate`,
    {
      method: 'POST',
      body: JSON.stringify(payload),
    },
    adminToken
  );
}



export async function triggerAdminUserBalanceVerify(
  targetUserId: string,
  chainId?: number,
  adminToken?: string | null
): Promise<{ success: boolean; snapshot: BalanceSnapshotRecord; user: any }> {
  return platformFetch(
    `/admin/users/${encodeURIComponent(targetUserId)}/verify-balance`,
    {
      method: 'POST',
      body: JSON.stringify(chainId ? { chain_id: chainId } : {}),
    },
    adminToken
  );
}



export async function setAdminUserRole(
  targetUserId: string,
  role: 'superadmin' | 'moderator' | null,
  adminToken?: string | null
): Promise<{ success: boolean; user: any }> {
  return platformFetch(
    `/admin/users/${encodeURIComponent(targetUserId)}/role`,
    {
      method: 'POST',
      body: JSON.stringify({ role }),
    },
    adminToken
  );
}





/** Admin456: members who were given free access (no payment needed). */
export async function fetchAdminAccessGrants(
  opts: { includeInactive?: boolean; userId?: string; scopeType?: 'platform' | 'group'; groupId?: string } = {},
  adminToken?: string | null
): Promise<{ grants: AccessGrant[] }> {
  const qs = new URLSearchParams();
  if (opts.includeInactive) qs.set('include_inactive', 'true');
  if (opts.userId) qs.set('user_id', opts.userId);
  if (opts.scopeType) qs.set('scope_type', opts.scopeType);
  if (opts.groupId) qs.set('group_id', opts.groupId);
  const q = qs.toString();
  return platformFetch(`/admin/access-grants${q ? `?${q}` : ''}`, undefined, adminToken);
}

/** Admin456 (superadmin only): let a member in without paying. `days` null = no end date. */
export async function adminGrantAccess(
  body: { user_id: string; scope_type: 'platform' | 'group'; group_id?: string; days: number | null; note?: string },
  adminToken?: string | null
): Promise<{ success: boolean; grant: AccessGrant }> {
  return platformFetch('/admin/access-grants', { method: 'POST', body: JSON.stringify(body) }, adminToken);
}

/** Admin456 (superadmin only): switch a free-access grant off. */
export async function adminRevokeAccess(
  body: { user_id: string; scope_type: 'platform' | 'group'; group_id?: string },
  adminToken?: string | null
): Promise<{ success: boolean }> {
  return platformFetch('/admin/access-grants/revoke', { method: 'POST', body: JSON.stringify(body) }, adminToken);
}

// ============================================================================
// MEMBERS' ROOM REACTIONS / TYPING / PINS, BANNER, RENEWAL REMINDERS
// ============================================================================

/** emoji -> user ids who reacted with it */
export type ReactionMap = Record<string, string[]>;

/** One reaction per member per message; null removes mine. */
export async function reactToRoomMessage(messageId: string, emoji: string | null): Promise<{ success: boolean; reactions: ReactionMap }> {
  return platformFetch(`/public-chat/messages/${encodeURIComponent(messageId)}/reaction`, {
    method: 'POST',
    body: JSON.stringify({ emoji }),
  });
}

export async function sendRoomTyping(): Promise<{ success: boolean; sent: boolean }> {
  return platformFetch('/public-chat/typing', { method: 'POST' });
}

export interface RoomPin {
  message_id: string;
  pinned_by: string;
  pinned_at: string | null;
}

/** Moderators / admins only. */
export async function setRoomMessagePinned(messageId: string, pinned: boolean): Promise<{ success: boolean; pins: RoomPin[] }> {
  return platformFetch('/public-chat/pins', { method: 'POST', body: JSON.stringify({ message_id: messageId, pinned }) });
}

export interface PlatformAnnouncement {
  id: string;
  text: string;
  level: 'info' | 'warning';
  ends_at: string | null;
}

export async function fetchAnnouncement(): Promise<{ announcement: PlatformAnnouncement | null }> {
  return platformFetch('/announcement');
}

export interface RenewalReminder {
  scope_type: 'platform' | 'group';
  scope_id: string;
  name: string;
  expires_at: string;
  /** '7d' = ends within a week, '1d' = within a day, 'expired' = ended in the last 14 days */
  stage: '7d' | '1d' | 'expired';
  free_access: boolean;
  /** Changes per stage, so each stage is announced once. */
  key: string;
}

export async function fetchRenewalReminders(): Promise<{ reminders: RenewalReminder[] }> {
  return platformFetch('/reminders');
}

export async function fetchAdminGroups(adminToken?: string | null): Promise<{ groups: any[] }> {
  return platformFetch('/admin/groups?limit=150', undefined, adminToken);
}

export async function fetchAdminReports(
  statusFilter = '',
  adminToken?: string | null
): Promise<{ reports: any[] }> {
  const qs = statusFilter ? `?status=${encodeURIComponent(statusFilter)}` : '';
  return platformFetch(`/admin/reports${qs}`, undefined, adminToken);
}

export async function resolveAdminReport(
  reportId: string,
  status: 'resolved' | 'dismissed',
  resolutionNote = '',
  adminToken?: string | null
): Promise<{ success: boolean; report: any }> {
  return platformFetch(
    `/admin/reports/${encodeURIComponent(reportId)}/resolve`,
    {
      method: 'POST',
      body: JSON.stringify({ status, resolution_note: resolutionNote }),
    },
    adminToken
  );
}



export async function fetchAdminSettings(
  adminToken?: string | null
): Promise<{ settings: Record<string, any> }> {
  return platformFetch('/admin/settings', undefined, adminToken);
}

export async function updateAdminSettings(
  updates: Record<string, any>,
  adminToken?: string | null
): Promise<{ success: boolean; settings: Record<string, any> }> {
  return platformFetch(
    '/admin/settings',
    {
      method: 'PUT',
      body: JSON.stringify(updates),
    },
    adminToken
  );
}



export async function fetchAdminAuditLogs(
  adminToken?: string | null
): Promise<{ audit_logs: any[] }> {
  return platformFetch('/admin/audit-logs?limit=150', undefined, adminToken);
}

export async function fetchAdminPayments(
  limit = 100,
  status?: string,
  adminToken?: string | null
): Promise<{ payments: PaymentRecord[]; count: number }> {
  const query = new URLSearchParams({ limit: String(limit) });
  if (status) query.set('status', status);
  return platformFetch(`/admin/payments?${query.toString()}`, undefined, adminToken);
}

export async function retryAdminPayment(
  paymentId: string,
  adminToken?: string | null
): Promise<{ success: boolean; status: string; payment: PaymentRecord }> {
  return platformFetch(
    `/admin/payments/${encodeURIComponent(paymentId)}/retry`,
    { method: 'POST' },
    adminToken
  );
}




// ============================================================================
// TALK TO ADMIN (support conversations)
// ============================================================================

export interface SupportThread {
  thread_id: string;
  subject: string;
  status: 'open' | 'closed';
  created_at: string;
  last_message_at: string;
  last_sender_role: 'user' | 'admin';
  /** Messages the viewer has not read yet. */
  unread: number;
  /** Admin inbox only */
  user_id?: string;
  username?: string | null;
  wallet_address?: string | null;
}

export interface SupportMessage {
  message_id: string;
  thread_id: string;
  sender_role: 'user' | 'admin';
  content: string;
  created_at: string;
}

export async function createSupportThread(
  subject: string,
  message: string
): Promise<{ success: boolean; thread: SupportThread }> {
  return platformFetch('/support/threads', {
    method: 'POST',
    body: JSON.stringify({ subject, message }),
  });
}

export async function fetchMySupportThreads(): Promise<{ threads: SupportThread[]; unread_total: number }> {
  return platformFetch('/support/threads');
}

export async function fetchSupportUnread(): Promise<{ unread_total: number }> {
  return platformFetch('/support/unread');
}

export async function fetchSupportThread(
  threadId: string
): Promise<{ thread: SupportThread; messages: SupportMessage[] }> {
  return platformFetch(`/support/threads/${encodeURIComponent(threadId)}`);
}

export async function sendSupportMessage(threadId: string, content: string): Promise<{ success: boolean }> {
  return platformFetch(`/support/threads/${encodeURIComponent(threadId)}/messages`, {
    method: 'POST',
    body: JSON.stringify({ content }),
  });
}

export async function adminListSupportThreads(
  status: 'open' | 'closed' | null,
  adminToken?: string | null
): Promise<{ threads: SupportThread[]; unread_total: number }> {
  const qs = status ? `?status=${status}` : '';
  return platformFetch(`/admin/support/threads${qs}`, undefined, adminToken);
}

export async function adminGetSupportThread(
  threadId: string,
  adminToken?: string | null
): Promise<{ thread: SupportThread; messages: SupportMessage[] }> {
  return platformFetch(`/admin/support/threads/${encodeURIComponent(threadId)}`, undefined, adminToken);
}

export async function adminReplySupportThread(
  threadId: string,
  content: string,
  adminToken?: string | null
): Promise<{ success: boolean }> {
  return platformFetch(
    `/admin/support/threads/${encodeURIComponent(threadId)}/reply`,
    { method: 'POST', body: JSON.stringify({ content }) },
    adminToken
  );
}

export async function adminSetSupportThreadStatus(
  threadId: string,
  status: 'open' | 'closed',
  adminToken?: string | null
): Promise<{ success: boolean }> {
  return platformFetch(
    `/admin/support/threads/${encodeURIComponent(threadId)}/status`,
    { method: 'POST', body: JSON.stringify({ status }) },
    adminToken
  );
}