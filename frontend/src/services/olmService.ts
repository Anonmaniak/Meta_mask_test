/**
 * Olm v2 (Signal 3DH + Double Ratchet) Service via Audited Vodozemac WASM.
 *
 * Implements:
 * - On-device Curve25519 identity + Ed25519 signing key generation (`Vodozemac.Account`).
 * - Single-use One-Time Prekey (OTK) batch generation & signed Fallback Key management.
 * - Canonical Ed25519 self-signed device key bundles (`account.sign(...)`).
 * - Outbound & Inbound Olm v2 (`SessionConfigVersion.V2`) Double Ratchet sessions
 *   across multiple recipient and sender devices, encrypted at rest in `e2eeVault.ts`.
 * - Deterministic 60-digit Safety Numbers for key verification.
 * - Peer identity-key change & device addition/revocation/reset detection.
 */

import * as Vodozemac from '@towns-protocol/vodozemac';
import {
  base64ToBytes,
  bytesToBase64,
  loadDeviceVaultRecord,
  saveDeviceVaultRecord,
  loadOlmSessions,
  saveOlmSessions,
  loadPeerTrustRecord,
  savePeerTrustRecord,
  type StoredDeviceVaultRecord,
  type PeerTrustRecord,
} from './e2eeVault.ts';

export const OLM_PROTOCOL_ID = 'OLM_V2_DOUBLE_RATCHET';
const DEFAULT_OTK_BATCH = 15;
const MAX_STORED_SESSIONS_PER_PEER_DEVICE = 5;

export interface DeviceBundleRegistrationData {
  device_id: string;
  device_label: string;
  ed25519_identity_key: string;
  curve25519_identity_key: string;
  fallback_key_id: string | null;
  fallback_public_key: string | null;
  bundle_signature: string;
  one_time_keys: Record<string, string>;
}

export interface ClaimedPeerPrekeyBundle {
  device_id: string;
  user_id: string;
  ed25519_identity_key: string;
  curve25519_identity_key: string;
  prekey_id: string;
  prekey_public: string;
  is_fallback: boolean;
  bundle_signature: string;
  signed_payload?: string;
}

export interface PeerActiveDeviceDescriptor {
  device_id: string;
  user_id: string;
  device_label: string;
  ed25519_identity_key: string;
  curve25519_identity_key: string;
  status: string;
}

export interface E2EEPlaintextEnvelope {
  v: 1;
  text: string;
  attachments?: Array<{
    attachment_id: string;
    key_b64: string;
    iv_b64: string;
    sha256_hex: string;
    file_name: string;
    mime_type: string;
    size_bytes: number;
  }>;
  /** Reply to an earlier message (WhatsApp / Instagram style). Encrypted like the rest of the message. */
  reply_to?: {
    message_id: string;
    sender_user_id: string;
    /** Short excerpt of the original, so the quote shows even if the original is not loaded. */
    preview: string;
    has_files?: boolean;
  };
  sent_at: string;
  /**
   * Chat events, encrypted like everything else (see services/chatEvents.ts):
   * 'message' (default) or 'reaction' | 'edit' | 'poll_vote', which point at `target_id`.
   */
  kind?: 'message' | 'reaction' | 'edit' | 'poll_vote';
  target_id?: string;
  /** reaction: the emoji ('' removes it) */
  emoji?: string;
  /** A poll message: question + 2..10 options */
  poll?: { question: string; options: string[]; multi?: boolean };
  /** poll_vote: chosen option numbers ([] withdraws) */
  vote?: number[];
  /** @mentioned member ids */
  mentions?: string[];
}

let wasmInitPromise: Promise<void> | null = null;

export async function ensureVodozemacReady(): Promise<void> {
  if (!wasmInitPromise) {
    wasmInitPromise = Vodozemac.initAsync();
  }
  await wasmInitPromise;
}

function mapToRecord(mapOrObj: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!mapOrObj) return out;
  if (mapOrObj instanceof Map) {
    for (const [k, v] of mapOrObj.entries()) {
      out[String(k)] = String(v);
    }
    return out;
  }
  if (typeof mapOrObj === 'object') {
    for (const [k, v] of Object.entries(mapOrObj as Record<string, unknown>)) {
      out[k] = String(v);
    }
  }
  return out;
}

function generateRandomDeviceId(): string {
  const rnd = crypto.getRandomValues(new Uint8Array(12));
  let hex = '';
  for (const b of rnd) {
    hex += b.toString(16).padStart(2, '0');
  }
  return `dev_${hex}`;
}

export function buildCanonicalDeviceBundleString(
  userId: string,
  deviceId: string,
  ed25519IdentityKey: string,
  curve25519IdentityKey: string,
  fallbackKeyId: string | null,
  fallbackPublicKey: string | null
): string {
  return (
    `zyphra-e2ee-device-v1|${userId}|${deviceId}|` +
    `${ed25519IdentityKey}|${curve25519IdentityKey}|` +
    `${fallbackKeyId || ''}|${fallbackPublicKey || ''}`
  );
}

const deviceInflightPromises = new Map<
  string,
  Promise<{
    record: StoredDeviceVaultRecord;
    isNewDevice: boolean;
    registrationBundle: DeviceBundleRegistrationData;
  }>
>();

/** Generates a brand-new local Olm device identity; optionally persists it to the vault. */
export async function generateFreshLocalOlmDevice(
  userId: string,
  deviceLabel = 'Browser E2EE Vault',
  persist = false
): Promise<{
  record: StoredDeviceVaultRecord;
  isNewDevice: boolean;
  registrationBundle: DeviceBundleRegistrationData;
}> {
  await ensureVodozemacReady();
  const pickleKey = crypto.getRandomValues(new Uint8Array(32));
  const account = new Vodozemac.Account();
  try {
    const deviceId = generateRandomDeviceId();
    account.generate_one_time_keys(DEFAULT_OTK_BATCH);
    account.generate_fallback_key();

    const otks = mapToRecord(account.one_time_keys);
    const fallbackMap = mapToRecord(account.fallback_key);
    const fallbackEntries = Object.entries(fallbackMap);
    const fallbackKeyId = fallbackEntries.length > 0 ? fallbackEntries[0][0] : null;
    const fallbackPublicKey = fallbackEntries.length > 0 ? fallbackEntries[0][1] : null;

    const ed25519Key = account.ed25519_key;
    const curve25519Key = account.curve25519_key;
    const canonical = buildCanonicalDeviceBundleString(
      userId,
      deviceId,
      ed25519Key,
      curve25519Key,
      fallbackKeyId,
      fallbackPublicKey
    );
    const bundleSignature = account.sign(canonical);

    const record: StoredDeviceVaultRecord = {
      userId,
      deviceId,
      deviceLabel,
      pickleKeyB64: bytesToBase64(pickleKey),
      accountPickle: account.pickle(pickleKey),
      ed25519Key,
      curve25519Key,
      fallbackKeyId,
      fallbackPublicKey,
      createdAt: new Date().toISOString(),
    };
    if (persist) {
      await saveDeviceVaultRecord(record);
    }

    return {
      record,
      isNewDevice: true,
      registrationBundle: {
        device_id: deviceId,
        device_label: deviceLabel,
        ed25519_identity_key: ed25519Key,
        curve25519_identity_key: curve25519Key,
        fallback_key_id: fallbackKeyId,
        fallback_public_key: fallbackPublicKey,
        bundle_signature: bundleSignature,
        one_time_keys: otks,
      },
    };
  } finally {
    pickleKey.fill(0);
    account.free();
  }
}

/**
 * Loads an existing device identity for `userId` from the encrypted vault, or
 * generates a brand-new on-device `Vodozemac.Account` using WebCrypto CSPRNG.
 * Never derives any key material from wallet addresses, balances, or signatures.
 */
export async function getOrCreateLocalOlmDevice(
  userId: string,
  deviceLabel = 'Browser E2EE Vault'
): Promise<{
  record: StoredDeviceVaultRecord;
  isNewDevice: boolean;
  registrationBundle: DeviceBundleRegistrationData;
}> {
  const inflight = deviceInflightPromises.get(userId);
  if (inflight) {
    return inflight;
  }

  const p = (async () => {
    try {
      await ensureVodozemacReady();
      const existing = await loadDeviceVaultRecord(userId);

      if (existing) {
        const pickleKey = base64ToBytes(existing.pickleKeyB64);
        const account = Vodozemac.Account.from_pickle(existing.accountPickle, pickleKey);
        try {
          const otks = mapToRecord(account.one_time_keys);
          const canonical = buildCanonicalDeviceBundleString(
            userId,
            existing.deviceId,
            existing.ed25519Key,
            existing.curve25519Key,
            existing.fallbackKeyId,
            existing.fallbackPublicKey
          );
          const sig = account.sign(canonical);
          return {
            record: existing,
            isNewDevice: false,
            registrationBundle: {
              device_id: existing.deviceId,
              device_label: existing.deviceLabel,
              ed25519_identity_key: existing.ed25519Key,
              curve25519_identity_key: existing.curve25519Key,
              fallback_key_id: existing.fallbackKeyId,
              fallback_public_key: existing.fallbackPublicKey,
              bundle_signature: sig,
              one_time_keys: otks,
            },
          };
        } finally {
          pickleKey.fill(0);
          account.free();
        }
      }

      return await generateFreshLocalOlmDevice(userId, deviceLabel, true);
    } finally {
      deviceInflightPromises.delete(userId);
    }
  })();

  deviceInflightPromises.set(userId, p);
  return p;
}

export async function markLocalPrekeysPublished(userId: string): Promise<void> {
  await ensureVodozemacReady();
  const rec = await loadDeviceVaultRecord(userId);
  if (!rec) return;
  const pickleKey = base64ToBytes(rec.pickleKeyB64);
  const account = Vodozemac.Account.from_pickle(rec.accountPickle, pickleKey);
  try {
    account.mark_keys_as_published();
    rec.accountPickle = account.pickle(pickleKey);
    await saveDeviceVaultRecord(rec);
  } finally {
    pickleKey.fill(0);
    account.free();
  }
}

/**
 * Generates fresh One-Time Prekeys and optionally rotates the signed Fallback Key.
 */
export async function generateMoreOlmPrekeys(
  userId: string,
  count = DEFAULT_OTK_BATCH,
  rotateFallback = false
): Promise<{
  device_id: string;
  fallback_key_id: string | null;
  fallback_public_key: string | null;
  bundle_signature: string;
  one_time_keys: Record<string, string>;
}> {
  await ensureVodozemacReady();
  const rec = await loadDeviceVaultRecord(userId);
  if (!rec) {
    throw new Error('No local E2EE device identity found');
  }

  const pickleKey = base64ToBytes(rec.pickleKeyB64);
  const account = Vodozemac.Account.from_pickle(rec.accountPickle, pickleKey);
  try {
    account.generate_one_time_keys(count);
    if (rotateFallback) {
      account.generate_fallback_key();
      const fbMap = mapToRecord(account.fallback_key);
      const entries = Object.entries(fbMap);
      if (entries.length > 0) {
        rec.fallbackKeyId = entries[0][0];
        rec.fallbackPublicKey = entries[0][1];
      }
    }
    const otks = mapToRecord(account.one_time_keys);
    const canonical = buildCanonicalDeviceBundleString(
      userId,
      rec.deviceId,
      rec.ed25519Key,
      rec.curve25519Key,
      rec.fallbackKeyId,
      rec.fallbackPublicKey
    );
    const sig = account.sign(canonical);

    rec.accountPickle = account.pickle(pickleKey);
    await saveDeviceVaultRecord(rec);

    return {
      device_id: rec.deviceId,
      fallback_key_id: rec.fallbackKeyId,
      fallback_public_key: rec.fallbackPublicKey,
      bundle_signature: sig,
      one_time_keys: otks,
    };
  } finally {
    pickleKey.fill(0);
    account.free();
  }
}

const olmVaultLocks = new Map<string, Promise<unknown>>();

function withOlmVaultLock<T>(userId: string, fn: () => Promise<T>): Promise<T> {
  const prev = olmVaultLocks.get(userId) ?? Promise.resolve();
  const next = prev.catch(() => { }).then(fn);
  const cleanup = () => {
    if (olmVaultLocks.get(userId) === tracked) {
      olmVaultLocks.delete(userId);
    }
  };
  const tracked = next.then(cleanup, cleanup);
  olmVaultLocks.set(userId, tracked);
  return next;
}

/**
 * Encrypts a structured plaintext envelope for a list of target devices using
 * Olm v2 Double Ratchet sessions. Automatically establishes a new 3DH outbound
 * session via `claimPrekeysFn` for any target device without an active session.
 */
export async function encryptOlmMultiDevicePayload(
  senderUserId: string,
  envelope: E2EEPlaintextEnvelope,
  targetDevices: PeerActiveDeviceDescriptor[],
  claimPrekeysFn: (userId: string, deviceIds: string[]) => Promise<ClaimedPeerPrekeyBundle[]>
): Promise<{
  senderDeviceId: string;
  deviceCiphertexts: Record<string, { message_type: number; ciphertext_b64: string }>;
}> {
  return withOlmVaultLock(senderUserId, async () => {
    await ensureVodozemacReady();
    const rec = await loadDeviceVaultRecord(senderUserId);
    if (!rec) {
      throw new Error('Local E2EE device vault not initialized');
    }

    const serializedPlaintext = JSON.stringify(envelope);
    const pickleKey = base64ToBytes(rec.pickleKeyB64);
    const account = Vodozemac.Account.from_pickle(rec.accountPickle, pickleKey);

    try {
      // Exclude the sending device itself; include all peer devices + sender's other devices
      const filteredTargets = targetDevices.filter(
        (d) => d.status === 'active' && d.device_id !== rec.deviceId
      );

      // Identify devices missing an active Olm session
      const missingByUser = new Map<string, PeerActiveDeviceDescriptor[]>();
      for (const dev of filteredTargets) {
        const storedSessions = await loadOlmSessions(senderUserId, dev.curve25519_identity_key);
        if (storedSessions.length === 0) {
          const arr = missingByUser.get(dev.user_id) || [];
          arr.push(dev);
          missingByUser.set(dev.user_id, arr);
        }
      }

      // Claim single-use prekeys and establish 3DH outbound sessions
      for (const [targetUid, devs] of missingByUser.entries()) {
        const bundles = await claimPrekeysFn(
          targetUid,
          devs.map((d) => d.device_id)
        );
        for (const b of bundles) {
          // Verify claimed bundle keys match the expected active device identity
          const expectedDev = devs.find((d) => d.device_id === b.device_id);
          if (
            !expectedDev ||
            expectedDev.curve25519_identity_key !== b.curve25519_identity_key ||
            expectedDev.ed25519_identity_key !== b.ed25519_identity_key
          ) {
            throw new Error(
              `Security alert: Prekey bundle key substitution detected for device ${b.device_id}`
            );
          }

          const session = account.create_outbound_session(
            b.curve25519_identity_key,
            b.prekey_public,
            Vodozemac.SessionConfigVersion.V2
          );
          try {
            await saveOlmSessions(senderUserId, b.curve25519_identity_key, [
              {
                sessionId: session.session_id,
                pickle: session.pickle(pickleKey),
                updatedAt: new Date().toISOString(),
              },
            ]);
          } finally {
            session.free();
          }
        }
      }

      const deviceCiphertexts: Record<string, { message_type: number; ciphertext_b64: string }> = {};

      // Also encrypt a self-ratchet copy or self-vault record? No: sender's own sending device
      // stores decrypted message in local session cache or encrypts to a local loopback session!
      // Even better: create/maintain a local self-loopback Olm session for `rec.deviceId` so
      // the sending device itself can also decrypt historical messages from server ciphertext
      // across page reloads without storing unencrypted plaintext!
      let selfSessions = await loadOlmSessions(senderUserId, rec.curve25519Key);
      if (selfSessions.length === 0) {
        account.generate_one_time_keys(1);
        const selfOtks = mapToRecord(account.one_time_keys);
        const selfOtkPub = Object.values(selfOtks)[0];
        const outSelf = account.create_outbound_session(
          rec.curve25519Key,
          selfOtkPub,
          Vodozemac.SessionConfigVersion.V2
        );
        try {
          const initMsg = outSelf.encrypt(JSON.stringify({ v: 1, text: '__self_init__', sent_at: '' }));
          const wireInit = new Vodozemac.OlmMessage(initMsg.message_type, initMsg.ciphertext);
          const inboundSelf = account.create_inbound_session(rec.curve25519Key, wireInit);
          const inSession = inboundSelf.session;
          // Save inbound session first for receiving, outbound second? Actually in Olm Double Ratchet,
          // `outSelf` encrypts and `inSession` decrypts! Let's store `outSelf` under `self_out` and `inSession` under `rec.curve25519Key`!
          await saveOlmSessions(senderUserId, `self_out:${rec.curve25519Key}`, [
            {
              sessionId: outSelf.session_id,
              pickle: outSelf.pickle(pickleKey),
              updatedAt: new Date().toISOString(),
            },
          ]);
          selfSessions = [
            {
              sessionId: inSession.session_id,
              pickle: inSession.pickle(pickleKey),
              updatedAt: new Date().toISOString(),
            },
          ];
          await saveOlmSessions(senderUserId, rec.curve25519Key, selfSessions);
          inSession.free();
          inboundSelf.free();
          wireInit.free();
          initMsg.free();
        } finally {
          outSelf.free();
        }
        rec.accountPickle = account.pickle(pickleKey);
        await saveDeviceVaultRecord(rec);
      }

      // Encrypt copy for sender's own active device via `self_out` Olm v2 ratchet
      const selfOutList = await loadOlmSessions(senderUserId, `self_out:${rec.curve25519Key}`);
      if (selfOutList.length > 0) {
        const selfOutSess = Vodozemac.Session.from_pickle(selfOutList[0].pickle, pickleKey);
        try {
          const olmMsg = selfOutSess.encrypt(serializedPlaintext);
          deviceCiphertexts[rec.deviceId] = {
            message_type: olmMsg.message_type,
            ciphertext_b64: bytesToBase64(olmMsg.ciphertext),
          };
          selfOutList[0] = {
            sessionId: selfOutSess.session_id,
            pickle: selfOutSess.pickle(pickleKey),
            updatedAt: new Date().toISOString(),
          };
          await saveOlmSessions(senderUserId, `self_out:${rec.curve25519Key}`, selfOutList);
          olmMsg.free();
        } finally {
          selfOutSess.free();
        }
      }

      // Encrypt distinct Olm v2 ratchet ciphertext for each recipient/sibling device
      for (const dev of filteredTargets) {
        const sessions = await loadOlmSessions(senderUserId, dev.curve25519_identity_key);
        if (sessions.length === 0) continue;
        const primary = Vodozemac.Session.from_pickle(sessions[0].pickle, pickleKey);
        try {
          const olmMsg = primary.encrypt(serializedPlaintext);
          deviceCiphertexts[dev.device_id] = {
            message_type: olmMsg.message_type,
            ciphertext_b64: bytesToBase64(olmMsg.ciphertext),
          };
          sessions[0] = {
            sessionId: primary.session_id,
            pickle: primary.pickle(pickleKey),
            updatedAt: new Date().toISOString(),
          };
          await saveOlmSessions(senderUserId, dev.curve25519_identity_key, sessions);
          olmMsg.free();
        } finally {
          primary.free();
        }
      }

      return {
        senderDeviceId: rec.deviceId,
        deviceCiphertexts,
      };
    } finally {
      pickleKey.fill(0);
      account.free();
    }
  });
}

/**
 * Decrypts an inbound Olm v2 message (`PreKey` type 0 or `Normal` type 1) addressed
 * to this device, advancing and persisting the Double Ratchet state in `e2eeVault.ts`.
 */
export async function decryptOlmDeviceCiphertext(
  receiverUserId: string,
  senderCurve25519Key: string,
  messageType: number,
  ciphertextB64: string
): Promise<E2EEPlaintextEnvelope> {
  return withOlmVaultLock(receiverUserId, async () => {
    await ensureVodozemacReady();
    const rec = await loadDeviceVaultRecord(receiverUserId);
    if (!rec) {
      throw new Error('Local E2EE device vault not initialized');
    }

    const pickleKey = base64ToBytes(rec.pickleKeyB64);
    const account = Vodozemac.Account.from_pickle(rec.accountPickle, pickleKey);
    const rawCt = base64ToBytes(ciphertextB64);
    const wireMsg = new Vodozemac.OlmMessage(messageType, rawCt);

    try {
      const sessions = await loadOlmSessions(receiverUserId, senderCurve25519Key);

      // 1. Try existing sessions first
      for (let i = 0; i < sessions.length; i++) {
        const sess = Vodozemac.Session.from_pickle(sessions[i].pickle, pickleKey);
        try {
          if (messageType === 0 && !sess.session_matches(wireMsg)) {
            continue;
          }
          const plaintextStr = sess.decrypt(wireMsg);
          const updatedEntry = {
            sessionId: sess.session_id,
            pickle: sess.pickle(pickleKey),
            updatedAt: new Date().toISOString(),
          };
          const reordered = [updatedEntry, ...sessions.filter((_, idx) => idx !== i)].slice(
            0,
            MAX_STORED_SESSIONS_PER_PEER_DEVICE
          );
          await saveOlmSessions(receiverUserId, senderCurve25519Key, reordered);
          return JSON.parse(plaintextStr) as E2EEPlaintextEnvelope;
        } catch {
          // Try next session or inbound prekey creation below
        } finally {
          sess.free();
        }
      }

      // 2. If PreKey message (type === 0), create new inbound session from Account OTK/Fallback
      if (messageType === 0) {
        let inbound: Vodozemac.InboundCreationResult;
        try {
          inbound = account.create_inbound_session(senderCurve25519Key, wireMsg);
        } catch {
          throw new Error(
            'Unable to decrypt Olm message: one-time prekey already consumed or replay detected'
          );
        }
        const newSess = inbound.session;
        try {
          const plaintextStr = inbound.plaintext;
          const newEntry = {
            sessionId: newSess.session_id,
            pickle: newSess.pickle(pickleKey),
            updatedAt: new Date().toISOString(),
          };
          // Persist updated Account (removes consumed OTK from local memory!)
          rec.accountPickle = account.pickle(pickleKey);
          await saveDeviceVaultRecord(rec);
          await saveOlmSessions(
            receiverUserId,
            senderCurve25519Key,
            [newEntry, ...sessions].slice(0, MAX_STORED_SESSIONS_PER_PEER_DEVICE)
          );
          return JSON.parse(plaintextStr) as E2EEPlaintextEnvelope;
        } finally {
          newSess.free();
          inbound.free();
        }
      }

      throw new Error('Unable to decrypt Olm message: no matching ratchet session or replay detected');
    } finally {
      wireMsg.free();
      pickleKey.fill(0);
      account.free();
    }
  });
}

/**
 * Forces session re-establishment with a peer device by clearing cached outbound
 * ratchet sessions so the next message performs a fresh 3DH prekey handshake.
 */
export async function resetOlmSessionWithPeerDevice(
  userId: string,
  peerCurve25519Key: string
): Promise<void> {
  await saveOlmSessions(userId, peerCurve25519Key, []);
}

// ============================================================================
// Key Verification: 60-Digit Safety Numbers
// ============================================================================

async function computeHalfFingerprintDigits(
  userId: string,
  ed25519Key: string,
  curve25519Key: string
): Promise<string> {
  const canonical = new TextEncoder().encode(
    `zyphra-safety-number-v1|${userId}|${ed25519Key}|${curve25519Key}`
  );
  let buf = new Uint8Array(canonical.byteLength);
  buf.set(canonical);
  // 64 rounds of SHA-512 commitment
  for (let i = 0; i < 64; i++) {
    const hash = await crypto.subtle.digest('SHA-512', buf);
    buf = new Uint8Array(hash);
  }
  // Extract 6 chunks of 5 decimal digits = 30 digits per participant
  let digits = '';
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  for (let offset = 0; offset < 30; offset += 5) {
    const chunkVal =
      ((BigInt(view.getUint8(offset)) << 32n) |
        (BigInt(view.getUint8(offset + 1)) << 24n) |
        (BigInt(view.getUint8(offset + 2)) << 16n) |
        (BigInt(view.getUint8(offset + 3)) << 8n) |
        BigInt(view.getUint8(offset + 4))) %
      100000n;
    digits += chunkVal.toString().padStart(5, '0');
  }
  return digits;
}

/**
 * Computes a deterministic, symmetric 60-digit Safety Number (12 blocks of 5 digits)
 * over two users' cryptographic device identities. Both sides compute the exact
 * same string regardless of who initiates verification.
 */
export async function computeSafetyNumber(
  partyA: { userId: string; ed25519Key: string; curve25519Key: string },
  partyB: { userId: string; ed25519Key: string; curve25519Key: string }
): Promise<string> {
  const [first, second] =
    `${partyA.userId}:${partyA.ed25519Key}` <= `${partyB.userId}:${partyB.ed25519Key}`
      ? [partyA, partyB]
      : [partyB, partyA];

  const [d1, d2] = await Promise.all([
    computeHalfFingerprintDigits(first.userId, first.ed25519Key, first.curve25519Key),
    computeHalfFingerprintDigits(second.userId, second.ed25519Key, second.curve25519Key),
  ]);
  const combined = d1 + d2;
  const groups: string[] = [];
  for (let i = 0; i < 60; i += 5) {
    groups.push(combined.slice(i, i + 5));
  }
  return groups.join(' ');
}

// ============================================================================
// Peer Identity Change Detection & Verification State
// ============================================================================

export async function evaluateAndRecordPeerTrust(
  localUserId: string,
  peerUserId: string,
  serverIdentityVersion: number,
  activeDevices: PeerActiveDeviceDescriptor[]
): Promise<PeerTrustRecord> {
  const existing = await loadPeerTrustRecord(localUserId, peerUserId);
  const now = new Date().toISOString();

  if (!existing) {
    const devicesMap: PeerTrustRecord['devices'] = {};
    for (const d of activeDevices) {
      devicesMap[d.device_id] = {
        deviceId: d.device_id,
        ed25519Key: d.ed25519_identity_key,
        curve25519Key: d.curve25519_identity_key,
        verified: false,
        firstSeenAt: now,
      };
    }
    const initial: PeerTrustRecord = {
      peerUserId,
      identityVersion: serverIdentityVersion,
      devices: devicesMap,
      securityWarnings: [],
      updatedAt: now,
    };
    await savePeerTrustRecord(localUserId, initial);
    return initial;
  }

  const warnings = [...existing.securityWarnings];
  const updatedDevices: PeerTrustRecord['devices'] = { ...existing.devices };

  if (serverIdentityVersion > existing.identityVersion) {
    warnings.push(
      `Security Notice: Peer ${peerUserId.slice(0, 12)}... reset their encryption identity (v${existing.identityVersion} -> v${serverIdentityVersion}). Re-verify safety numbers before sharing sensitive data.`
    );
  }

  for (const d of activeDevices) {
    const known = updatedDevices[d.device_id];
    if (!known) {
      warnings.push(
        `New device added by peer (${d.device_label || d.device_id.slice(0, 12)}). Safety number verification recommended.`
      );
      updatedDevices[d.device_id] = {
        deviceId: d.device_id,
        ed25519Key: d.ed25519_identity_key,
        curve25519Key: d.curve25519_identity_key,
        verified: false,
        firstSeenAt: now,
      };
    } else if (
      known.ed25519Key !== d.ed25519_identity_key ||
      known.curve25519Key !== d.curve25519_identity_key
    ) {
      warnings.push(
        `CRITICAL: Identity key changed on peer device ${d.device_id}! Marked unverified.`
      );
      updatedDevices[d.device_id] = {
        ...known,
        ed25519Key: d.ed25519_identity_key,
        curve25519Key: d.curve25519_identity_key,
        verified: false,
      };
    }
  }

  const updated: PeerTrustRecord = {
    peerUserId,
    identityVersion: serverIdentityVersion,
    devices: updatedDevices,
    securityWarnings: warnings.slice(-8),
    updatedAt: now,
  };
  await savePeerTrustRecord(localUserId, updated);
  return updated;
}

export async function markPeerDevicesVerified(
  localUserId: string,
  peerUserId: string
): Promise<PeerTrustRecord | null> {
  const existing = await loadPeerTrustRecord(localUserId, peerUserId);
  if (!existing) return null;
  const now = new Date().toISOString();
  for (const k of Object.keys(existing.devices)) {
    existing.devices[k].verified = true;
    existing.devices[k].verifiedAt = now;
  }
  existing.securityWarnings = [];
  existing.updatedAt = now;
  await savePeerTrustRecord(localUserId, existing);
  return existing;
}