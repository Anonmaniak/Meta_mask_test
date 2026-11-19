/**
 * Encrypted At-Rest Local Key Vault (`zyphra_e2ee_vault_v2`).
 *
 * Security Properties:
 * 1. Generates a non-extractable WebCrypto `AES-256-GCM` master wrapping key
 *    (`extractable: false`) persisted in IndexedDB via structured clone.
 * 2. Encrypts every sensitive E2EE state record (Vodozemac pickle keys, Account
 *    pickles, Olm ratchet Session pickles, MLS PrivateKeyPackages, MLS GroupState
 *    snapshots, and peer identity trust records) with a unique 96-bit CSPRNG IV
 *    and AAD binding the record ID (`zyphra-vault-v2|<recordId>`).
 * 3. Never stores private keys, session keys, or decrypted messages in
 *    `localStorage` or `sessionStorage`.
 * 4. Supports deterministic in-memory IndexedDB backing in Node.js (`>=20`) test
 *    runners while still enforcing real WebCrypto non-extractable AES-256-GCM wrapping.
 */

const VAULT_DB_NAME = 'zyphra_e2ee_vault_v2';
const VAULT_DB_VERSION = 1;
const MASTER_KEY_STORE = 'master_keys';
const RECORD_STORE = 'encrypted_records';
const MASTER_KEY_ID = 'vault_master_aes_gcm_v2';

interface EncryptedRecordRow {
  id: string;
  ivB64: string;
  ciphertextB64: string;
  updatedAt: string;
}

export interface StoredDeviceVaultRecord {
  userId: string;
  deviceId: string;
  deviceLabel: string;
  pickleKeyB64: string;
  accountPickle: string;
  ed25519Key: string;
  curve25519Key: string;
  fallbackKeyId: string | null;
  fallbackPublicKey: string | null;
  createdAt: string;
}

export interface StoredOlmSessionEntry {
  sessionId: string;
  pickle: string;
  updatedAt: string;
}

export interface StoredMlsKeyPackageSecret {
  packageId: string;
  keyPackageRef: string;
  ciphersuite: string;
  publicPackageB64: string;
  initPrivateKeyB64: string;
  hpkePrivateKeyB64: string;
  signaturePrivateKeyB64: string;
  createdAt: string;
}

export interface StoredMlsGroupVaultState {
  groupId: string;
  mlsGroupIdB64: string;
  epoch: number;
  encodedGroupStateB64: string;
  updatedAt: string;
}

export interface PeerDeviceTrustEntry {
  deviceId: string;
  ed25519Key: string;
  curve25519Key: string;
  verified: boolean;
  verifiedAt?: string;
  firstSeenAt: string;
}

export interface PeerTrustRecord {
  peerUserId: string;
  identityVersion: number;
  devices: Record<string, PeerDeviceTrustEntry>;
  securityWarnings: string[];
  updatedAt: string;
}

// Fallback encrypted store for headless Node.js unit tests without browser IndexedDB
const memoryMasterKeys = new Map<string, CryptoKey>();
const memoryEncryptedRecords = new Map<string, EncryptedRecordRow>();

function getWebCrypto(): Crypto {
  if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle) {
    return globalThis.crypto;
  }
  throw new Error('Secure WebCrypto CSPRNG and SubtleCrypto are required for E2EE');
}

export function bytesToBase64(bytes: Uint8Array): string {
  const nodeBuf = (globalThis as any).Buffer;
  if (typeof nodeBuf !== 'undefined') {
    return nodeBuf.from(bytes).toString('base64');
  }
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
  const pad = '='.repeat((4 - (normalized.length % 4)) % 4);
  const padded = normalized + pad;
  const nodeBuf = (globalThis as any).Buffer;
  if (typeof nodeBuf !== 'undefined') {
    return new Uint8Array(nodeBuf.from(padded, 'base64'));
  }
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function hasIndexedDB(): boolean {
  return typeof indexedDB !== 'undefined' && indexedDB !== null;
}

function openVaultDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(VAULT_DB_NAME, VAULT_DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(MASTER_KEY_STORE)) {
        db.createObjectStore(MASTER_KEY_STORE, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(RECORD_STORE)) {
        db.createObjectStore(RECORD_STORE, { keyPath: 'id' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('Failed to open E2EE IndexedDB vault'));
  });
}

let masterKeyInflightPromise: Promise<CryptoKey> | null = null;

async function getOrCreateMasterWrappingKey(): Promise<CryptoKey> {
  if (masterKeyInflightPromise) {
    return masterKeyInflightPromise;
  }
  masterKeyInflightPromise = (async () => {
    try {
      const wc = getWebCrypto();

      if (!hasIndexedDB()) {
        const existing = memoryMasterKeys.get(MASTER_KEY_ID);
        if (existing) return existing;
        const generated = await wc.subtle.generateKey(
          { name: 'AES-GCM', length: 256 },
          false, // MUST be non-extractable
          ['encrypt', 'decrypt']
        );
        memoryMasterKeys.set(MASTER_KEY_ID, generated);
        return generated;
      }

      const db = await openVaultDB();
      try {
        const existingKey = await new Promise<CryptoKey | null>((resolve, reject) => {
          const tx = db.transaction(MASTER_KEY_STORE, 'readonly');
          const req = tx.objectStore(MASTER_KEY_STORE).get(MASTER_KEY_ID);
          req.onsuccess = () => resolve(req.result?.key || null);
          req.onerror = () => reject(req.error);
        });
        if (existingKey) {
          return existingKey;
        }

        const generated = await wc.subtle.generateKey(
          { name: 'AES-GCM', length: 256 },
          false, // Non-extractable hardware/browser-protected CryptoKey
          ['encrypt', 'decrypt']
        );

        await new Promise<void>((resolve, reject) => {
          const tx = db.transaction(MASTER_KEY_STORE, 'readwrite');
          tx.objectStore(MASTER_KEY_STORE).put({
            id: MASTER_KEY_ID,
            key: generated,
            createdAt: new Date().toISOString(),
          });
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);
        });
        return generated;
      } finally {
        db.close();
      }
    } finally {
      masterKeyInflightPromise = null;
    }
  })();
  return masterKeyInflightPromise;
}

function buildRecordAad(recordId: string): ArrayBuffer {
  return toArrayBuffer(new TextEncoder().encode(`zyphra-vault-v2|${recordId}`));
}

export async function putVaultRecord<T>(recordId: string, value: T): Promise<void> {
  const wc = getWebCrypto();
  const masterKey = await getOrCreateMasterWrappingKey();
  const iv = wc.getRandomValues(new Uint8Array(12));
  const plaintextBytes = new TextEncoder().encode(JSON.stringify(value));

  const ciphertextBuf = await wc.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(iv),
      additionalData: buildRecordAad(recordId),
    },
    masterKey,
    toArrayBuffer(plaintextBytes)
  );

  // Zeroize transient plaintext buffer
  plaintextBytes.fill(0);

  const row: EncryptedRecordRow = {
    id: recordId,
    ivB64: bytesToBase64(iv),
    ciphertextB64: bytesToBase64(new Uint8Array(ciphertextBuf)),
    updatedAt: new Date().toISOString(),
  };

  if (!hasIndexedDB()) {
    memoryEncryptedRecords.set(recordId, row);
    return;
  }

  const db = await openVaultDB();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(RECORD_STORE, 'readwrite');
      tx.objectStore(RECORD_STORE).put(row);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

export async function getVaultRecord<T>(recordId: string): Promise<T | null> {
  const wc = getWebCrypto();
  let row: EncryptedRecordRow | null = null;

  if (!hasIndexedDB()) {
    row = memoryEncryptedRecords.get(recordId) || null;
  } else {
    const db = await openVaultDB();
    try {
      row = await new Promise<EncryptedRecordRow | null>((resolve, reject) => {
        const tx = db.transaction(RECORD_STORE, 'readonly');
        const req = tx.objectStore(RECORD_STORE).get(recordId);
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error);
      });
    } finally {
      db.close();
    }
  }

  if (!row) return null;

  const masterKey = await getOrCreateMasterWrappingKey();
  const iv = base64ToBytes(row.ivB64);
  const ct = base64ToBytes(row.ciphertextB64);

  const plainBuf = await wc.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(iv),
      additionalData: buildRecordAad(recordId),
    },
    masterKey,
    toArrayBuffer(ct)
  );

  const plainBytes = new Uint8Array(plainBuf);
  try {
    const jsonText = new TextDecoder().decode(plainBytes);
    return JSON.parse(jsonText) as T;
  } finally {
    plainBytes.fill(0);
  }
}

export async function deleteVaultRecord(recordId: string): Promise<void> {
  if (!hasIndexedDB()) {
    memoryEncryptedRecords.delete(recordId);
    return;
  }

  const db = await openVaultDB();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(RECORD_STORE, 'readwrite');
      tx.objectStore(RECORD_STORE).delete(recordId);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

export async function listRawEncryptedVaultRowsForAudit(): Promise<EncryptedRecordRow[]> {
  if (!hasIndexedDB()) {
    return Array.from(memoryEncryptedRecords.values());
  }
  const db = await openVaultDB();
  try {
    return await new Promise<EncryptedRecordRow[]>((resolve, reject) => {
      const tx = db.transaction(RECORD_STORE, 'readonly');
      const req = tx.objectStore(RECORD_STORE).getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error);
    });
  } finally {
    db.close();
  }
}

export async function wipeUserDeviceVault(userId: string): Promise<void> {
  const prefixTargets = [
    `device:${userId}`,
    `olm_index:${userId}`,
    `mls_kp_index:${userId}`,
    `mls_grp_index:${userId}`,
  ];
  const olmIdx = (await getVaultRecord<string[]>(`olm_index:${userId}`)) || [];
  const kpIdx = (await getVaultRecord<string[]>(`mls_kp_index:${userId}`)) || [];
  const grpIdx = (await getVaultRecord<string[]>(`mls_grp_index:${userId}`)) || [];

  for (const peerKey of olmIdx) {
    await deleteVaultRecord(`olm_sess:${userId}:${peerKey}`);
  }
  for (const kpRef of kpIdx) {
    await deleteVaultRecord(`mls_kp:${userId}:${kpRef}`);
  }
  for (const gid of grpIdx) {
    await deleteVaultRecord(`mls_grp:${userId}:${gid}`);
  }
  for (const k of prefixTargets) {
    await deleteVaultRecord(k);
  }
  // Thorough cleanup for cached decryptions and safety number trust states (LOW-4)
  try {
    const allRows = await listRawEncryptedVaultRowsForAudit();
    for (const r of allRows) {
      if (r.id.startsWith(`dec_msg:${userId}`) || r.id.startsWith(`trust:${userId}`)) {
        await deleteVaultRecord(r.id);
      }
    }
  } catch {
    // Non-fatal if raw scan fails
  }
}

// ============================================================================
// Typed Vault Accessors
// ============================================================================

export async function loadDeviceVaultRecord(userId: string): Promise<StoredDeviceVaultRecord | null> {
  return getVaultRecord<StoredDeviceVaultRecord>(`device:${userId}`);
}

export async function saveDeviceVaultRecord(rec: StoredDeviceVaultRecord): Promise<void> {
  await putVaultRecord(`device:${rec.userId}`, rec);
}

export async function loadOlmSessions(
  userId: string,
  peerCurve25519Key: string
): Promise<StoredOlmSessionEntry[]> {
  return (await getVaultRecord<StoredOlmSessionEntry[]>(`olm_sess:${userId}:${peerCurve25519Key}`)) || [];
}

export async function saveOlmSessions(
  userId: string,
  peerCurve25519Key: string,
  sessions: StoredOlmSessionEntry[]
): Promise<void> {
  await putVaultRecord(`olm_sess:${userId}:${peerCurve25519Key}`, sessions);
  const idx = new Set((await getVaultRecord<string[]>(`olm_index:${userId}`)) || []);
  idx.add(peerCurve25519Key);
  await putVaultRecord(`olm_index:${userId}`, Array.from(idx));
}

export async function saveMlsKeyPackageSecret(
  userId: string,
  secret: StoredMlsKeyPackageSecret
): Promise<void> {
  await putVaultRecord(`mls_kp:${userId}:${secret.keyPackageRef}`, secret);
  const idx = new Set((await getVaultRecord<string[]>(`mls_kp_index:${userId}`)) || []);
  idx.add(secret.keyPackageRef);
  await putVaultRecord(`mls_kp_index:${userId}`, Array.from(idx));
}

export async function listMlsKeyPackageSecrets(
  userId: string
): Promise<StoredMlsKeyPackageSecret[]> {
  const idx = (await getVaultRecord<string[]>(`mls_kp_index:${userId}`)) || [];
  const results: StoredMlsKeyPackageSecret[] = [];
  for (const ref of idx) {
    const rec = await getVaultRecord<StoredMlsKeyPackageSecret>(`mls_kp:${userId}:${ref}`);
    if (rec) results.push(rec);
  }
  return results;
}

export async function consumeMlsKeyPackageSecret(
  userId: string,
  keyPackageRef: string
): Promise<void> {
  await deleteVaultRecord(`mls_kp:${userId}:${keyPackageRef}`);
  const idx = ((await getVaultRecord<string[]>(`mls_kp_index:${userId}`)) || []).filter(
    (r) => r !== keyPackageRef
  );
  await putVaultRecord(`mls_kp_index:${userId}`, idx);
}

export async function saveMlsGroupVaultState(
  userId: string,
  state: StoredMlsGroupVaultState
): Promise<void> {
  await putVaultRecord(`mls_grp:${userId}:${state.groupId}`, state);
  const idx = new Set((await getVaultRecord<string[]>(`mls_grp_index:${userId}`)) || []);
  idx.add(state.groupId);
  await putVaultRecord(`mls_grp_index:${userId}`, Array.from(idx));
}

export async function loadMlsGroupVaultState(
  userId: string,
  groupId: string
): Promise<StoredMlsGroupVaultState | null> {
  return getVaultRecord<StoredMlsGroupVaultState>(`mls_grp:${userId}:${groupId}`);
}

export async function deleteMlsGroupVaultState(
  userId: string,
  groupId: string
): Promise<void> {
  await deleteVaultRecord(`mls_grp:${userId}:${groupId}`);
}

export async function loadPeerTrustRecord(
  userId: string,
  peerUserId: string
): Promise<PeerTrustRecord | null> {
  return getVaultRecord<PeerTrustRecord>(`trust:${userId}:${peerUserId}`);
}

export async function savePeerTrustRecord(
  userId: string,
  record: PeerTrustRecord
): Promise<void> {
  await putVaultRecord(`trust:${userId}:${record.peerUserId}`, record);
}

export async function loadVaultDecryptedMessage<T>(
  userId: string,
  messageId: string
): Promise<T | null> {
  return getVaultRecord<T>(`dec_msg:${userId}:${messageId}`);
}

export async function saveVaultDecryptedMessage<T>(
  userId: string,
  messageId: string,
  decryptedPayload: T
): Promise<void> {
  await putVaultRecord(`dec_msg:${userId}:${messageId}`, decryptedPayload);
}
