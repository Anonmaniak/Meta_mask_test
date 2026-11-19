/**
 * Chat Platform REST + Public WebSocket Client (`/api/platform/*` & `/ws/public-chat`).
 *
 * Covers:
 * - Open Public Chat (readable feed, cursor pagination, edit/delete, real-time `/ws/public-chat`)
 * - Username Search Directory, Extended Profile, Identity/Wallet/Level History, User Blocks,
 *   DM Read Receipts & Abuse Reporting
 * - Wallet-Based Levels (starting at Level 7) & Server-Side Ethereum RPC Balance Verification
 * - Group Access Policies (`min_level`, `min_eth_balance_eth`, `visibility`), Invite Links,
 *   Public Group Discovery, Policy-Gated Join Requests & Leave Group
 * - RBAC Admin Console (`superadmin` / `moderator` / break-glass `X-Admin-Token`) & Audit Logs
 */

import { getBaseApiUrl } from './api.ts';
import { resilientFetch, backoffDelay, onWake } from './resilientFetch.ts';
import { getE2EESessionToken, type E2EEAccountProfile, type E2EEGroupAccessPolicy } from './e2eeApi.ts';

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
}

export interface PublicChatFeedResponse {
  room: string;
  security_notice: string;
  messages: PublicChatMessageRecord[];
  next_before_seq: number | null;
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
  };
}

export interface DirectoryUserRecord {
  user_id: string;
  username: string | null;
  display_name: string | null;
  bio: string | null;
  avatar_url: string | null;
  current_level: number;
  highest_level: number;
  primary_wallet: string | null;
  online: boolean;
  created_at: string;
}

export interface LevelDefinitionRecord {
  level: number;
  name: string;
  description: string;
  min_balance_wei: string;
  min_balance_eth: string;
  min_payment_wei?: string;
  min_payment_eth?: string;
  max_balance_wei: string | null;
  enabled: boolean;
  privileges: Record<string, any>;
  updated_at?: string;
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
  avatar_url: string | null;
  visibility: 'public' | 'invite_only';
  min_level: number;
  min_eth_balance_wei: string;
  min_eth_balance_eth: string;
  require_invitation: boolean;
  is_paid?: boolean;
  entry_fee_eth?: string;
  entry_fee_wei?: string;
  /** Price set by the admin, in US dollars (the ETH amount is converted at payment time). */
  entry_fee_usd?: number;
  eth_usd_price?: number;
  has_paid?: boolean;
  active_member_count: number;
  is_member: boolean;
  created_at: string;
}

/** "$20.00 (0.01 ETH)" for a paid group; falls back to ETH only for old fixed-ETH groups. */
export function formatGroupFee(g: { entry_fee_usd?: number | string; entry_fee_eth?: string }): string {
  const usd = Number(g.entry_fee_usd || 0);
  const eth = g.entry_fee_eth || '0';
  return usd > 0 ? `$${usd.toFixed(2)} (${eth} ETH)` : `${eth} ETH`;
}

export interface PlatformPricing {
  platform_entry_fee_eth: string;
  platform_entry_fee_wei: string;
  eth_usd_price: number;
  platform_entry_fee_usd: number;
  /** 'live' | 'live_cached' | 'live_stale' | 'admin_fixed' */
  rate_source?: string;
  quoted_at?: string;
  authorized_payment_destination: string | null;
  allowed_payment_chain_ids: number[];
}

export interface PlatformMembershipStatus {
  user_id: string;
  wallet_address: string | null;
  is_platform_paid: boolean;
  platform_paid_at: string | null;
  pricing: PlatformPricing;
}

export interface GroupPricing {
  group_id: string;
  name: string;
  is_paid: boolean;
  entry_fee_eth: string;
  entry_fee_wei: string;
  entry_fee_usd: number;
  eth_usd_price: number;
  rate_source?: string;
  has_paid: boolean;
  authorized_payment_destination: string | null;
  allowed_payment_chain_ids: number[];
}

export interface GroupInviteRecord {
  invite_code: string;
  group_id: string;
  creator_user_id: string;
  expires_at: string | null;
  max_uses: number;
  uses_count: number;
  revoked: boolean;
  created_at: string;
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
  if (adminToken && adminToken.trim()) {
    headers['X-Admin-Token'] = adminToken.trim();
  }
  return headers;
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
        : Array.isArray(json.summary) && json.summary.length > 0
          ? json.summary.join('; ')
          : json.error || `HTTP ${res.status}`;
    const err: any = new Error(msg);
    err.status = res.status;
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

export async function postPublicChatMessage(content: string, forceAuthed = false): Promise<{
  success: boolean;
  message: PublicChatMessageRecord;
}> {
  const isAuthed = forceAuthed || Boolean(getE2EESessionToken());
  return platformFetch('/public-chat/messages', {
    method: 'POST',
    body: JSON.stringify({
      content,
      guest_token: isAuthed ? undefined : getOrCreateGuestSessionToken(),
    }),
  });
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
  const scheduleReconnect = () => {
    if (closed) return;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(openSocket, backoffDelay(reconnectAttempts++, 15000));
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
      if (ws) {
        try {
          ws.close();
        } catch {
          // ignore
        }
      }
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
  const scheduleReconnect = () => {
    if (closed) return;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(openSocket, backoffDelay(reconnectAttempts++, 15000));
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
        if (ev.code !== 4401) scheduleReconnect();
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
      if (ws) {
        try {
          ws.close();
        } catch {
          // ignore
        }
      }
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
  avatar_url?: string | null;
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

export async function fetchLevelDefinitions(): Promise<{
  starting_level: number;
  levels: LevelDefinitionRecord[];
  policy: {
    level_downgrade_enabled: boolean;
    level_downgrade_grace_hours: number;
    balance_reeval_minutes: number;
    default_balance_chain_id: number;
  };
}> {
  return platformFetch('/levels');
}

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
  groupId?: string
): Promise<{
  success: boolean;
  status: string;
  payment: PaymentRecord;
  already_verified?: boolean;
  user?: E2EEAccountProfile;
  is_platform_paid?: boolean;
  reason?: string;
}> {
  return platformFetch('/payments/verify', {
    method: 'POST',
    body: JSON.stringify({
      transaction_reference: transactionReference,
      chain_id: chainId,
      purpose,
      group_id: groupId,
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

export async function updateAdminPricing(
  payload: {
    /** The membership price the admin sets, in US dollars (converted to ETH at payment time). */
    platform_entry_fee_usd?: number;
    use_live_eth_price?: boolean;
    /** Fixed ETH/USD rate, used when live pricing is off or unavailable. */
    eth_usd_price?: number;
    authorized_payment_destination?: string;
  },
  adminToken?: string | null
): Promise<{ success: boolean; pricing: PlatformPricing }> {
  return platformFetch(
    '/admin/pricing',
    {
      method: 'PUT',
      body: JSON.stringify(payload),
    },
    adminToken
  );
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
    min_level: number;
    min_eth_balance_eth?: string;
    require_invitation: boolean;
    is_paid?: boolean;
    /** Platform superadmin only. Price in US dollars. */
    entry_fee_usd?: number;
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



export async function createGroupInvite(
  groupId: string,
  expiresHours = 72,
  maxUses = 25
): Promise<{ success: boolean; invite: GroupInviteRecord }> {
  return platformFetch(`/groups/${encodeURIComponent(groupId)}/invites`, {
    method: 'POST',
    body: JSON.stringify({ expires_hours: expiresHours, max_uses: maxUses }),
  });
}

export async function fetchGroupInvites(groupId: string): Promise<{ invites: GroupInviteRecord[] }> {
  return platformFetch(`/groups/${encodeURIComponent(groupId)}/invites`);
}

export async function revokeGroupInvite(
  groupId: string,
  inviteCode: string
): Promise<{ success: boolean }> {
  return platformFetch(
    `/groups/${encodeURIComponent(groupId)}/invites/${encodeURIComponent(inviteCode)}`,
    { method: 'DELETE' }
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

export async function joinGroupByInviteCode(inviteCode: string): Promise<{
  success: boolean;
  request_id: string;
  group_id: string;
  status: string;
}> {
  return platformFetch(`/groups/join-by-invite/${encodeURIComponent(inviteCode)}`, {
    method: 'POST',
  });
}

export async function fetchGroupJoinRequests(groupId: string): Promise<{
  requests: GroupJoinRequestRecord[];
}> {
  return platformFetch(`/groups/${encodeURIComponent(groupId)}/join-requests`);
}

export async function leaveEncryptedGroup(groupId: string): Promise<{
  success: boolean;
  left_group_id: string;
}> {
  return platformFetch(`/groups/${encodeURIComponent(groupId)}/leave`, {
    method: 'POST',
  });
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
    total_users: number;
    active_sessions: number;
    total_groups: number;
    public_messages: number;
    encrypted_dm_messages: number;
    encrypted_group_messages: number;
    open_reports: number;
  };
  online: { authenticated_users: number; public_viewers: number };
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



export async function upsertAdminLevel(
  level: number,
  payload: {
    name: string;
    description: string;
    min_balance_eth: string;
    min_payment_eth?: string;
    min_balance_wei?: string;
    min_payment_wei?: string;
    enabled: boolean;
    privileges?: Record<string, any>;
  },
  adminToken?: string | null
): Promise<{ success: boolean; level: LevelDefinitionRecord }> {
  return platformFetch(
    `/admin/levels/${level}`,
    {
      method: 'PUT',
      body: JSON.stringify(payload),
    },
    adminToken
  );
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

export async function adminReevaluateUserLevel(
  targetUserId: string,
  adminToken?: string | null
): Promise<{ success: boolean; result: any; user: any }> {
  return platformFetch(
    `/admin/users/${encodeURIComponent(targetUserId)}/re-evaluate-level`,
    { method: 'POST' },
    adminToken
  );
}

export async function adminBatchReevaluateLevels(
  adminToken?: string | null
): Promise<{ success: boolean; re_evaluation: any }> {
  return platformFetch(
    '/admin/levels/re-evaluate',
    { method: 'POST' },
    adminToken
  );
}

export async function fetchAdminUserQualificationStatus(
  targetUserId: string,
  adminToken?: string | null
): Promise<any> {
  return platformFetch(
    `/admin/users/${encodeURIComponent(targetUserId)}/qualification-status`,
    undefined,
    adminToken
  );
}

export async function fetchMyQualificationStatus(): Promise<any> {
  return platformFetch('/wallet/qualification-status');
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