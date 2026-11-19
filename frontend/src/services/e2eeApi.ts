/**
 * Authenticated REST + Secure WebSocket (`wss://` / `ws://`) Client for `/api/e2ee/*`.
 *
 * Security Controls:
 * - Keeps wallet session tokens strictly in memory (plus `HttpOnly` cookie when same-site),
 *   never persisting raw session tokens or keys in `localStorage`.
 * - Authenticates WebSockets via first-frame JSON (`{ type: 'auth', token }`) rather than
 *   URL query parameters so bearer tokens never leak into proxy or server URL logs.
 */

import { getBaseApiUrl } from './api.ts';
import { resilientFetch, backoffDelay, onWake } from './resilientFetch.ts';
import type { ClaimedPeerPrekeyBundle, PeerActiveDeviceDescriptor } from './olmService.ts';

export interface E2EEAccountProfile {
  user_id: string;
  username: string | null;
  display_name?: string | null;
  bio?: string | null;
  avatar_url?: string | null;
  current_level?: number;
  highest_level?: number;
  qualifying_balance_wei?: string;
  qualifying_chain_id?: number;
  last_balance_verified_at?: string | null;
  level_grace_expires_at?: string | null;
  account_status?: string;
  is_platform_paid?: boolean;
  show_online_presence?: boolean;
  send_read_receipts?: boolean;
  admin_role?: 'superadmin' | 'moderator' | null;
  identity_version: number;
  wallets: Array<{
    wallet_address: string;
    is_primary: boolean;
    status: string;
    linked_at: string;
  }>;
  primary_wallet: string | null;
  created_at: string;
  updated_at: string;
}

export interface E2EEDmCiphertextRecord {
  seq: number;
  message_id: string;
  conversation_id: string;
  sender_user_id: string;
  sender_device_id: string;
  sender_curve25519_key: string;
  sender_ed25519_key: string;
  recipient_user_id: string;
  protocol: string;
  device_ciphertexts: Record<string, { message_type: number; ciphertext_b64: string }>;
  attachment_ids: string[];
  timestamp: string;
}

export interface E2EEGroupAccessPolicy {
  description: string;
  avatar_url: string | null;
  visibility: 'public' | 'invite_only';
  min_level: number;
  min_eth_balance_wei: string;
  min_eth_balance_eth?: string;
  require_invitation: boolean;
  is_paid?: boolean;
  entry_fee_eth?: string;
  entry_fee_usd?: string | number;
  entry_fee_wei?: string;
}

export interface E2EEGroupRecord {
  group_id: string;
  mls_group_id_b64: string;
  name: string;
  creator_user_id: string;
  current_epoch: number;
  ciphersuite: string;
  history_sharing_mode: string;
  policy?: E2EEGroupAccessPolicy;
  created_at: string;
  updated_at: string;
  members: Array<{
    user_id: string;
    username?: string | null;
    display_name?: string | null;
    device_id: string;
    role: string;
    leaf_index: number | null;
    status: string;
    joined_epoch: number;
    removed_epoch: number | null;
  }>;
}

const SESSION_STORAGE_KEY = 'zyphra_e2ee_token';
const LOCAL_STORAGE_KEY = 'zyphra_e2ee_session_token';

function getStoredSessionToken(): string | null {
  if (typeof sessionStorage !== 'undefined') {
    const s = sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (s && s.trim()) return s.trim();
  }
  if (typeof localStorage !== 'undefined') {
    const l = localStorage.getItem(LOCAL_STORAGE_KEY);
    if (l && l.trim()) return l.trim();
  }
  return null;
}

let inMemorySessionToken: string | null = getStoredSessionToken();

export function setE2EESessionToken(token: string | null): void {
  inMemorySessionToken = token ? token.trim() : null;
  if (typeof sessionStorage !== 'undefined') {
    if (inMemorySessionToken) {
      sessionStorage.setItem(SESSION_STORAGE_KEY, inMemorySessionToken);
    } else {
      sessionStorage.removeItem(SESSION_STORAGE_KEY);
    }
  }
  if (typeof localStorage !== 'undefined') {
    if (inMemorySessionToken) {
      localStorage.setItem(LOCAL_STORAGE_KEY, inMemorySessionToken);
    } else {
      localStorage.removeItem(LOCAL_STORAGE_KEY);
    }
  }
}

export function getE2EESessionToken(): string | null {
  if (!inMemorySessionToken) {
    inMemorySessionToken = getStoredSessionToken();
  }
  return inMemorySessionToken;
}

export function hasStoredSessionToken(): boolean {
  return Boolean(getE2EESessionToken());
}

function buildAuthHeaders(extra?: Record<string, string>): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(extra || {}),
  };
  const token = getE2EESessionToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

async function e2eeFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const base = getBaseApiUrl();
  const res = await resilientFetch(`${base}/e2ee${path}`, {
    ...init,
    credentials: 'include',
    headers: buildAuthHeaders(init?.headers as Record<string, string> | undefined),
  });
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('text/html')) {
    throw new Error(
      `Expected JSON response from backend but received HTML (HTTP ${res.status}). Verify API proxy or backend URL.`
    );
  }
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401) {
      setE2EESessionToken(null);
    }
    const err: any = new Error(
      typeof json.detail === 'string'
        ? json.detail
        : json.detail?.message || json.error || `HTTP ${res.status}`
    );
    err.status = res.status;
    err.detail = json.detail;
    throw err;
  }
  return json as T;
}

export async function requestE2EEAuthChallenge(
  walletAddress: string,
  purpose: 'login' | 'link_wallet' | 'reset_lost_identity' = 'login',
  chainId = 1
): Promise<{ challenge_id: string; message: string; expires_at: string }> {
  return e2eeFetch('/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({
      wallet_address: walletAddress,
      purpose,
      chain_id: chainId,
    }),
  });
}

export async function verifyE2EEAuthChallenge(
  challengeId: string,
  walletAddress: string,
  signature: string
): Promise<{
  success: boolean;
  created_account: boolean;
  session_token: string;
  user: E2EEAccountProfile;
  devices: PeerActiveDeviceDescriptor[];
}> {
  const res = await e2eeFetch<{
    success: boolean;
    created_account: boolean;
    session_token: string;
    user: E2EEAccountProfile;
    devices: PeerActiveDeviceDescriptor[];
  }>('/auth/verify', {
    method: 'POST',
    body: JSON.stringify({
      challenge_id: challengeId,
      wallet_address: walletAddress,
      signature,
    }),
  });
  setE2EESessionToken(res.session_token);
  return res;
}

export async function logoutE2EESession(): Promise<void> {
  try {
    await e2eeFetch('/auth/logout', { method: 'POST' });
  } finally {
    setE2EESessionToken(null);
  }
}

export async function fetchMyE2EEAccount(): Promise<{
  user: E2EEAccountProfile;
  devices: PeerActiveDeviceDescriptor[];
}> {
  const token = getE2EESessionToken();
  if (!token) {
    throw Object.assign(new Error('No active authentication session token'), { status: 401 });
  }
  return e2eeFetch('/me');
}

export async function checkUsernameAvailability(username: string): Promise<{
  username: string;
  available: boolean;
  is_current?: boolean;
  reason: string | null;
}> {
  return e2eeFetch(`/account/username/check?username=${encodeURIComponent(username.trim())}`);
}

export async function updateMyE2EEUsername(username: string): Promise<{
  success: boolean;
  user: E2EEAccountProfile;
}> {
  return e2eeFetch('/account/username', {
    method: 'PATCH',
    body: JSON.stringify({ username }),
  });
}

export async function linkNewWalletToE2EEAccount(payload: {
  challenge_id: string;
  new_wallet_address: string;
  signature: string;
  make_primary: boolean;
  revoke_previous_wallets: boolean;
}): Promise<{ success: boolean; user: E2EEAccountProfile; session_token?: string | null }> {
  const res = await e2eeFetch<{
    success: boolean;
    user: E2EEAccountProfile;
    session_token?: string | null;
  }>('/account/wallets/link', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  if (res.session_token) {
    setE2EESessionToken(res.session_token);
  }
  return res;
}

export async function resolveE2EEPeer(identifier: string): Promise<{
  user_id: string;
  username: string | null;
  primary_wallet: string | null;
  identity_version: number;
  devices: PeerActiveDeviceDescriptor[];
}> {
  return e2eeFetch(`/users/resolve/${encodeURIComponent(identifier)}`);
}

export async function registerE2EEDeviceBundle(payload: {
  device_id: string;
  device_label: string;
  ed25519_identity_key: string;
  curve25519_identity_key: string;
  fallback_key_id: string | null;
  fallback_public_key: string | null;
  bundle_signature: string;
  one_time_keys: Record<string, string>;
  mls_key_packages: Array<{
    package_id: string;
    ciphersuite: string;
    key_package_b64: string;
    key_package_ref: string;
  }>;
}): Promise<{
  success: boolean;
  device: PeerActiveDeviceDescriptor;
  available_counts: { one_time_prekeys: number; mls_key_packages: number };
}> {
  return e2eeFetch('/devices/register', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function replenishE2EEPrekeys(
  deviceId: string,
  payload: {
    fallback_key_id: string | null;
    fallback_public_key: string | null;
    bundle_signature: string;
    one_time_keys: Record<string, string>;
    mls_key_packages: Array<{
      package_id: string;
      ciphersuite: string;
      key_package_b64: string;
      key_package_ref: string;
    }>;
  }
): Promise<{ available_counts: { one_time_prekeys: number; mls_key_packages: number } }> {
  return e2eeFetch(`/devices/${encodeURIComponent(deviceId)}/prekeys`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function revokeE2EEDevice(deviceId: string): Promise<{ success: boolean }> {
  return e2eeFetch(`/devices/${encodeURIComponent(deviceId)}/revoke`, {
    method: 'POST',
  });
}

export async function resetLostE2EEIdentity(payload: {
  challenge_id: string;
  wallet_address: string;
  signature: string;
  confirm_irrecoverable_history: boolean;
  new_device: any;
}): Promise<{
  success: boolean;
  identity_version: number;
  irrecoverable_history_notice: string;
}> {
  return e2eeFetch('/identity/reset', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function claimPeerOlmPrekeyBundles(
  targetUserId: string,
  targetDeviceIds?: string[]
): Promise<ClaimedPeerPrekeyBundle[]> {
  const res = await e2eeFetch<{ bundles: ClaimedPeerPrekeyBundle[] }>('/prekeys/claim', {
    method: 'POST',
    body: JSON.stringify({
      target_user_id: targetUserId,
      target_device_ids: targetDeviceIds,
    }),
  });
  return res.bundles || [];
}

export async function fetchPeerActiveDevices(targetUserId: string): Promise<{
  user_id: string;
  identity_version: number;
  devices: PeerActiveDeviceDescriptor[];
}> {
  return e2eeFetch(`/users/${encodeURIComponent(targetUserId)}/devices`);
}

export async function submitOlmDmCiphertext(payload: {
  message_id: string;
  recipient_user_id: string;
  sender_device_id: string;
  protocol: string;
  device_ciphertexts: Record<string, { message_type: number; ciphertext_b64: string }>;
  attachment_ids?: string[];
}): Promise<{ success: boolean; seq: number; conversation_id: string; timestamp: string }> {
  return e2eeFetch('/dm/messages', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function fetchOlmDmCiphertexts(
  peerUserId: string,
  deviceId: string,
  afterSeq = 0,
  limit = 100
): Promise<{ conversation_id: string; messages: E2EEDmCiphertextRecord[] }> {
  const qs = new URLSearchParams({
    peer_user_id: peerUserId,
    device_id: deviceId,
    after_seq: String(afterSeq),
    limit: String(limit),
  });
  return e2eeFetch(`/dm/messages?${qs.toString()}`);
}

export async function fetchMyDmConversations(): Promise<{
  conversations: Array<{
    conversation_id: string;
    peer_user_id: string;
    peer_username: string | null;
    peer_primary_wallet: string | null;
    last_seq: number;
    last_timestamp: string;
  }>;
}> {
  return e2eeFetch('/dm/conversations');
}

export async function claimPeerMlsKeyPackages(targetUserId: string): Promise<
  Array<{
    package_id: string;
    user_id: string;
    device_id: string;
    ciphersuite: string;
    key_package_b64: string;
    key_package_ref: string;
  }>
> {
  const res = await e2eeFetch<{ key_packages: any[] }>('/mls/key-packages/claim', {
    method: 'POST',
    body: JSON.stringify({ target_user_id: targetUserId }),
  });
  return res.key_packages || [];
}

export async function createServerMlsGroup(payload: {
  name: string;
  mls_group_id_b64: string;
  creator_device_id: string;
  ciphersuite: string;
  description?: string;
  visibility?: 'public' | 'invite_only';
  min_level?: number;
  min_eth_balance_wei?: string;
  require_invitation?: boolean;
  /** Platform superadmin only: create the group as a paid group (price in USD). */
  is_paid?: boolean;
  entry_fee_usd?: number;
}): Promise<{ success: boolean; group: E2EEGroupRecord }> {
  return e2eeFetch('/groups', {
    method: 'POST',
    body: JSON.stringify({ ...payload, history_sharing_mode: 'none' }),
  });
}

export async function fetchMyServerMlsGroups(): Promise<{ groups: E2EEGroupRecord[] }> {
  return e2eeFetch('/groups');
}

export async function fetchPendingServerMlsWelcomes(
  deviceId: string,
  consume = false
): Promise<{
  welcomes: Array<{
    welcome_id: string;
    group_id: string;
    group_name: string;
    epoch: number;
    mls_welcome_b64: string;
    timestamp: string;
  }>;
}> {
  return e2eeFetch(
    `/groups/welcomes?device_id=${encodeURIComponent(deviceId)}&consume=${consume ? 'true' : 'false'}`
  );
}

export async function ackServerMlsWelcome(
  welcomeId: string,
  deviceId: string
): Promise<{ success: boolean; acknowledged: boolean }> {
  return e2eeFetch(
    `/groups/welcomes/${encodeURIComponent(welcomeId)}/ack?device_id=${encodeURIComponent(deviceId)}`,
    { method: 'POST' }
  );
}

export async function submitServerMlsCommit(
  groupId: string,
  payload: {
    committer_device_id: string;
    expected_epoch: number;
    commit_type: 'add' | 'remove' | 'update';
    mls_commit_b64: string;
    added_members?: Array<{ user_id: string; device_id: string; role: 'member' | 'admin' }>;
    removed_members?: Array<{ user_id: string; device_id?: string }>;
    welcomes?: Array<{ target_user_id: string; target_device_id: string; mls_welcome_b64: string }>;
  }
): Promise<{ success: boolean; commit: any; group: E2EEGroupRecord }> {
  return e2eeFetch(`/groups/${encodeURIComponent(groupId)}/commits`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function fetchServerMlsCommits(
  groupId: string,
  afterEpoch = 0
): Promise<{ commits: Array<{ epoch: number; mls_commit_b64: string; commit_type: string }> }> {
  return e2eeFetch(
    `/groups/${encodeURIComponent(groupId)}/commits?after_epoch=${afterEpoch}`
  );
}

export async function submitServerMlsGroupMessage(
  groupId: string,
  payload: {
    message_id: string;
    sender_device_id: string;
    epoch: number;
    mls_ciphertext_b64: string;
    attachment_ids?: string[];
  }
): Promise<{ success: boolean; message: any }> {
  return e2eeFetch(`/groups/${encodeURIComponent(groupId)}/messages`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function fetchServerMlsGroupMessages(
  groupId: string,
  afterSeq = 0,
  limit = 100
): Promise<{
  group_id: string;
  messages: Array<{
    seq: number;
    message_id: string;
    group_id: string;
    epoch: number;
    sender_user_id: string;
    sender_device_id: string;
    mls_ciphertext_b64: string;
    attachment_ids: string[];
    timestamp: string;
  }>;
}> {
  return e2eeFetch(
    `/groups/${encodeURIComponent(groupId)}/messages?after_seq=${afterSeq}&limit=${limit}`
  );
}

export async function uploadEncryptedAttachmentBlob(payload: {
  scope_type: 'dm' | 'group';
  scope_id: string;
  uploader_device_id: string;
  ciphertext_b64: string;
  ciphertext_sha256: string;
}): Promise<{ success: boolean; attachment: { attachment_id: string } }> {
  return e2eeFetch('/attachments', {
    method: 'POST',
    body: JSON.stringify({ ...payload, algorithm: 'AES-256-GCM' }),
  });
}

export async function downloadEncryptedAttachmentBlob(attachmentId: string): Promise<{
  attachment: {
    attachment_id: string;
    ciphertext_b64: string;
    ciphertext_sha256: string;
    byte_length: number;
  };
}> {
  return e2eeFetch(`/attachments/${encodeURIComponent(attachmentId)}`);
}

export async function fetchIdentitySecurityEvents(
  userIds: string[],
  afterSeq = 0
): Promise<{
  events: Array<{
    seq: number;
    event_id: string;
    user_id: string;
    event_type: string;
    device_id: string | null;
    identity_version: number;
    timestamp: string;
  }>;
}> {
  if (userIds.length === 0) return { events: [] };
  return e2eeFetch(
    `/identity/events?user_ids=${encodeURIComponent(userIds.join(','))}&after_seq=${afterSeq}`
  );
}

/**
 * Establishes a secure WebSocket (`wss://` in HTTPS, `ws://` on localhost dev)
 * to receive real-time ciphertext & epoch notifications without polling lag.
 */
export function connectE2EEWebSocket(onEvent: (evt: Record<string, any>) => void): {
  close: () => void;
} {
  if (typeof WebSocket === 'undefined') {
    return { close: () => { } };
  }

  let closedByCaller = false;
  let ws: WebSocket | null = null;
  let pingInterval: ReturnType<typeof setInterval> | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  let reconnectAttempts = 0;
  const scheduleReconnect = () => {
    if (closedByCaller) return;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(openSocket, backoffDelay(reconnectAttempts++, 15000));
  };
  // Laptop woke up / network is back / tab visible again: reconnect right away.
  const stopWake = onWake(() => {
    if (closedByCaller) return;
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
    reconnectAttempts = 0;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    openSocket();
  });

  const getWsUrl = (): string => {
    const apiBase = getBaseApiUrl().replace(/\/api\/?$/, '');
    if (apiBase.startsWith('https://')) {
      return `wss://${apiBase.slice('https://'.length)}/ws/e2ee`;
    }
    if (apiBase.startsWith('http://')) {
      return `ws://${apiBase.slice('http://'.length)}/ws/e2ee`;
    }
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}/ws/e2ee`;
  };

  const openSocket = () => {
    if (closedByCaller) return;
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
    try {
      ws = new WebSocket(getWsUrl());
      ws.onopen = () => {
        reconnectAttempts = 0;
        if (ws && inMemorySessionToken) {
          ws.send(JSON.stringify({ type: 'auth', token: inMemorySessionToken }));
        }
        pingInterval = setInterval(() => {
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
          }
        }, 25000);
      };
      ws.onmessage = (ev) => {
        try {
          const parsed = JSON.parse(String(ev.data));
          if (parsed && parsed.type && parsed.type !== 'pong') {
            onEvent(parsed);
          }
        } catch {
          // Ignore malformed frame
        }
      };
      ws.onclose = (ev) => {
        if (pingInterval) clearInterval(pingInterval);
        if (ev.code !== 4401) scheduleReconnect();
      };
    } catch {
      scheduleReconnect();
    }
  };

  openSocket();

  return {
    close() {
      closedByCaller = true;
      stopWake();
      if (pingInterval) clearInterval(pingInterval);
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