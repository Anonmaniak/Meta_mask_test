import type {
  HealthResponse,
  EncryptedChatMessage,
  EncryptedMessageSendPayload,
  RoomRecipientsResponse,
  ChatKeyChallengeResponse,
  ChatKeyRegisterPayload,
  ChatKeyRegisterResponse,
  ChatKeyLookupResponse,
} from '../types';
import { resilientFetch } from './resilientFetch.ts';

const envBackend =
  typeof import.meta !== 'undefined'
    ? (import.meta as any).env?.VITE_BACKEND_URL || (import.meta as any).env?.VITE_API_URL
    : '';

const DEFAULT_BACKEND_URL =
  (envBackend && (envBackend.endsWith('/api') ? envBackend : `${envBackend.replace(/\/+$/, '')}/api`)) ||
  (typeof window !== 'undefined'
    ? window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
      ? 'http://localhost:10000/api'
      : `${window.location.origin}/api`
    : 'http://localhost:10000/api');

export function getBaseApiUrl(): string {
  if (typeof localStorage !== 'undefined') {
    const custom = localStorage.getItem('backend_url');
    if (custom && custom.trim()) {
      return custom.trim().replace(/\/+$/, '');
    }
  }
  return DEFAULT_BACKEND_URL;
}

export function setBaseApiUrl(url: string) {
  if (url && url.trim()) {
    localStorage.setItem('backend_url', url.trim().replace(/\/+$/, ''));
  } else {
    localStorage.removeItem('backend_url');
  }
}

export async function fetchHealth(): Promise<HealthResponse> {
  const base = getBaseApiUrl();
  const res = await fetch(`${base}/health`, { cache: 'no-store' });
  if (!res.ok) throw new Error(`Health check failed: HTTP ${res.status}`);
  return res.json();
}

/**
 * Fire-and-forget wake-up call, made once when the app loads. `deep=1` makes the
 * backend touch the database too, so a sleeping Render instance / Neon compute is
 * already awake (and pooled connections are fresh) by the time the first real
 * request is sent. Never throws.
 */
export function warmUpBackend(): void {
  const base = getBaseApiUrl();
  resilientFetch(`${base}/health?deep=1`, { cache: 'no-store' }, { budgetMs: 45000 }).catch(() => { });
}

export class ChatSendError extends Error {
  readonly status: number;
  readonly payload?: EncryptedMessageSendPayload;
  readonly isRetryable: boolean;

  constructor(status: number, message: string, payload?: EncryptedMessageSendPayload) {
    super(message);
    this.name = 'ChatSendError';
    this.status = status;
    this.payload = payload;
    this.isRetryable = status === 409 || status >= 500;
  }
}

export async function fetchChatMessages(
  channel = 'global',
  recipient?: string | null,
  limit = 50
): Promise<EncryptedChatMessage[]> {
  const base = getBaseApiUrl();
  try {
    const params = new URLSearchParams({
      channel,
      limit: String(limit),
    });
    if (recipient && recipient.trim()) {
      params.set('recipient', recipient.trim());
    }
    const url = `${base}/chat/messages?${params.toString()}`;
    const res = await resilientFetch(url, { cache: 'no-store' });
    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data) ? data : [];
  } catch (err) {
    console.warn('fetchChatMessages failed:', err);
    return [];
  }
}

export async function sendEncryptedChatMessage(
  payload: EncryptedMessageSendPayload
): Promise<{ success: boolean; message_id: string; duplicate?: boolean }> {
  const base = getBaseApiUrl();
  const res = await fetch(`${base}/chat/messages`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    const errMsg = json.detail || json.error || `HTTP ${res.status}: Encrypted transmit failed`;
    throw new ChatSendError(res.status, errMsg, payload);
  }
  return json;
}

export async function fetchRoomRecipients(roomId = 'global'): Promise<RoomRecipientsResponse> {
  const base = getBaseApiUrl();
  const res = await resilientFetch(`${base}/chat/rooms/${encodeURIComponent(roomId)}/recipients`, {
    cache: 'no-store',
  });
  if (!res.ok) {
    const json = await res.json().catch(() => ({}));
    throw new Error(json.detail || `Failed to fetch recipients for room ${roomId}`);
  }
  return res.json();
}

export async function requestChatKeyChallenge(
  address: string,
  fingerprint: string,
  chainId = 1
): Promise<ChatKeyChallengeResponse> {
  const base = getBaseApiUrl();
  const res = await fetch(`${base}/chat/keys/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      address,
      public_key_fingerprint: fingerprint,
      chain_id: chainId,
    }),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(json.detail || json.error || `HTTP ${res.status}: Failed to request challenge`);
  }
  return json as ChatKeyChallengeResponse;
}

export async function registerChatPublicKey(
  payload: ChatKeyRegisterPayload
): Promise<ChatKeyRegisterResponse> {
  const base = getBaseApiUrl();
  const res = await fetch(`${base}/chat/keys/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(json.detail || json.error || `HTTP ${res.status}: Failed to register chat key`);
  }
  return json as ChatKeyRegisterResponse;
}

export async function fetchChatPublicKey(
  address: string
): Promise<ChatKeyLookupResponse | null> {
  const base = getBaseApiUrl();
  const res = await resilientFetch(`${base}/chat/keys/${encodeURIComponent(address)}`, {
    cache: 'no-store',
  });
  if (res.status === 404) {
    return { address, registered: false };
  }
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(json.detail || json.error || `HTTP ${res.status}: Failed to lookup chat key`);
  }
  return json as ChatKeyLookupResponse;
}

export async function batchFetchChatPublicKeys(
  addresses: string[]
): Promise<Record<string, ChatKeyLookupResponse>> {
  const base = getBaseApiUrl();
  const res = await fetch(`${base}/chat/keys/lookup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ addresses }),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(json.detail || json.error || `HTTP ${res.status}: Failed to lookup chat keys`);
  }
  return json?.keys || {};
}