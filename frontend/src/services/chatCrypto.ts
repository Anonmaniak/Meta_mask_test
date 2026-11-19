/**
 * Browser-side End-to-End Encryption (E2EE) Cryptographic Foundation
 * for MetaMask-branded chat application.
 *
 * Implements:
 * - ECDH key generation on NIST P-256 curve with non-extractable private key.
 * - IndexedDB structured-clone persistence for local key pairs.
 * - HKDF-SHA-256 domain-separated 256-bit AES key derivation.
 * - AES-256-GCM authenticated message encryption and decryption.
 * - Fresh 96-bit random IVs and authenticated additional data (AAD) envelope binding.
 * - Strict error classification and zero-leakage security posture.
 */

// ============================================================================
// Types and Error Definitions
// ============================================================================

export type ChatCryptoErrorCode =
  | 'CRYPTO_UNSUPPORTED'
  | 'STORAGE_UNAVAILABLE'
  | 'STORAGE_BLOCKED'
  | 'STORAGE_CORRUPTED'
  | 'IDENTITY_NOT_FOUND'
  | 'PRIVATE_KEY_MISSING'
  | 'KEY_GENERATION_FAILED'
  | 'KEY_IMPORT_FAILED'
  | 'KEY_DERIVATION_FAILED'
  | 'INVALID_PUBLIC_KEY'
  | 'INVALID_ENVELOPE'
  | 'ENCRYPTION_FAILED'
  | 'DECRYPTION_FAILED'
  | 'AUTH_TAG_MISMATCH'
  | 'INCOMPATIBLE_VERSION';

/**
 * Actionable, typed error class safe for displaying UI messages
 * without leaking sensitive cryptographic material, keys, or plaintext.
 */
export class ChatCryptoError extends Error {
  readonly code: ChatCryptoErrorCode;
  readonly safeMessage: string;

  constructor(code: ChatCryptoErrorCode, safeMessage: string, details?: unknown) {
    super(`[${code}] ${safeMessage}`);
    this.name = 'ChatCryptoError';
    this.code = code;
    this.safeMessage = safeMessage;

    if (details !== undefined && typeof details === 'object' && details !== null && 'message' in details) {
      this.cause = (details as { message: unknown }).message;
    }
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Standardized exportable public key representation suitable for
 * backend registration, identity verification, and on-wire exchange.
 */
export interface ExportedPublicKey {
  version: 1;
  curve: 'P-256';
  format: 'raw+jwk';
  /** 65-byte uncompressed EC point (0x04 || X || Y) encoded as base64url */
  rawBase64Url: string;
  /** RFC 7517 compliant JSON Web Key representation */
  jwk: JsonWebKey;
  /** SHA-256 digest of raw public key bytes in base64url format */
  fingerprint: string;
}

/**
 * Local chat identity encapsulating the active user's key pair
 * and public identity metadata.
 */
export interface ChatIdentity {
  version: 1;
  id: string;
  keyPair: {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
  };
  exportedPublicKey: ExportedPublicKey;
  createdAt: number;
}

/**
 * Record structure stored inside browser IndexedDB.
 */
export interface StoredIdentityRecord {
  id: string;
  version: 1;
  keyVersion: number;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  exportedPublicKey: ExportedPublicKey;
  createdAt: number;
  updatedAt: number;
}

/**
 * Options to bind shared-secret derivation to conversation and participants.
 */
export interface KeyDerivationOptions {
  /** Domain separation protocol context string (default: metamask-chat-e2ee:v1) */
  protocolContext?: string;
  /** Unique conversation identifier */
  conversationId?: string;
  /** Sender EVM address */
  senderAddress?: string;
  /** Recipient EVM address */
  recipientAddress?: string;
  /** Optional custom salt buffer */
  salt?: Uint8Array;
}

/**
 * Envelope metadata accompanying encrypted payload.
 */
export interface EnvelopeMetadata {
  conversationId?: string;
  sender?: string;
  recipient?: string;
  timestamp?: number;
}

/**
 * Options for message encryption.
 */
export interface EncryptOptions {
  /** Explicit Authenticated Additional Data buffer or string */
  additionalData?: Uint8Array | string;
  /** Contextual conversation metadata automatically bound via AAD */
  metadata?: EnvelopeMetadata;
  /** Protocol key version indicator */
  keyVersion?: number;
  /** Optional sender public key to attach to the envelope */
  senderPublicKey?: ExportedPublicKey;
}

/**
 * Options for message decryption.
 */
export interface DecryptOptions {
  /** Explicit expected AAD buffer or string to verify against envelope */
  expectedAdditionalData?: Uint8Array | string;
  /** Expected sender EVM address to verify against envelope metadata */
  expectedSender?: string;
  /** Expected recipient EVM address to verify against envelope metadata */
  expectedRecipient?: string;
  /** Expected conversation ID to verify against envelope metadata */
  expectedConversationId?: string;
}

/**
 * Versioned transport-safe encrypted message envelope.
 * Plaintext is strictly excluded.
 */
export interface EncryptedMessageEnvelope {
  version: 1;
  algorithm: 'ECDH-P256-HKDF-SHA256-AES-GCM-256';
  keyVersion: number;
  /** 12-byte (96-bit) random IV encoded in base64url */
  iv: string;
  /** Ciphertext and 128-bit authentication tag encoded in base64url */
  ciphertext: string;
  /** Optional authenticated additional data encoded in base64url */
  aad?: string;
  /** Optional sender public key */
  senderPublicKey?: ExportedPublicKey;
  /** Optional envelope metadata authenticated via AAD */
  metadata?: EnvelopeMetadata;
}

// ============================================================================
// Constants & Configuration
// ============================================================================

export const PROTOCOL_VERSION = 1;
export const PROTOCOL_ALGORITHM = 'ECDH-P256-HKDF-SHA256-AES-GCM-256';
export const DEFAULT_PROTOCOL_CONTEXT = 'metamask-chat-e2ee:v1';
export const DEFAULT_HKDF_SALT = new TextEncoder().encode('metamask-chat-e2ee-v1:hkdf-salt');

export const IDB_DATABASE_NAME = 'metamask_chat_keystore';
export const IDB_STORE_NAME = 'identities';
export const IDB_SCHEMA_VERSION = 1;

// ============================================================================
// Base64url Utility Functions
// ============================================================================

/**
 * Encodes a Uint8Array into a URL-safe base64 string without padding.
 */
export function uint8ArrayToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decodes a URL-safe base64 string into a Uint8Array.
 * Strictly validates characters and handles padding.
 */
export function base64UrlToUint8Array(base64url: string): Uint8Array {
  if (typeof base64url !== 'string' || base64url.length === 0) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Base64url input must be a non-empty string.');
  }

  // Reject invalid characters
  if (!/^[A-Za-z0-9_-]+$/.test(base64url)) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Base64url string contains illegal characters.');
  }

  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const remainder = base64.length % 4;
  if (remainder === 1) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Illegal base64url string length.');
  }
  if (remainder > 0) {
    base64 += '='.repeat(4 - remainder);
  }

  try {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch (err) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Failed to decode base64url string.', err);
  }
}

/**
 * Helper to satisfy strict TypeScript DOM BufferSource typings
 * where Uint8Array defaults to Uint8Array<ArrayBufferLike>.
 */
function toBufferSource(data: Uint8Array | ArrayBuffer): BufferSource {
  return data as unknown as BufferSource;
}

// ============================================================================
// Environment & Capability Probing
// ============================================================================

/**
 * Checks whether the current runtime supports required Web Crypto APIs.
 */
export function isWebCryptoSupported(): boolean {
  const g = typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : null);
  if (!g || !g.crypto || !g.crypto.subtle) return false;
  const subtle = g.crypto.subtle;
  return (
    typeof subtle.generateKey === 'function' &&
    typeof subtle.deriveBits === 'function' &&
    typeof subtle.deriveKey === 'function' &&
    typeof subtle.importKey === 'function' &&
    typeof subtle.exportKey === 'function' &&
    typeof subtle.encrypt === 'function' &&
    typeof subtle.decrypt === 'function' &&
    typeof subtle.digest === 'function'
  );
}

/**
 * Checks whether IndexedDB is available in the current environment.
 */
export function isIndexedDBSupported(): boolean {
  if (typeof window !== 'undefined' && 'indexedDB' in window && !!window.indexedDB) {
    return true;
  }
  if (typeof globalThis !== 'undefined' && 'indexedDB' in globalThis && !!(globalThis as any).indexedDB) {
    return true;
  }
  return false;
}

/**
 * Enforces presence of Web Crypto API or throws ChatCryptoError.
 */
export function assertCryptoSupported(): void {
  if (!isWebCryptoSupported()) {
    throw new ChatCryptoError(
      'CRYPTO_UNSUPPORTED',
      'Native Web Crypto API is not supported in this browser environment.'
    );
  }
}

// ============================================================================
// Part A: Key Generation and Export
// ============================================================================

/**
 * Generates an ECDH key pair on the NIST P-256 curve.
 * The private key is strictly marked non-extractable (extractable: false).
 */
export async function generateChatKeyPair(): Promise<CryptoKeyPair> {
  assertCryptoSupported();

  try {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      false, // Private key MUST NOT be extractable into raw bytes
      ['deriveKey', 'deriveBits']
    );

    return keyPair;
  } catch (err) {
    throw new ChatCryptoError('KEY_GENERATION_FAILED', 'Failed to generate ECDH P-256 key pair.', err);
  }
}

/**
 * Exports a public CryptoKey into both raw uncompressed base64url and JWK formats,
 * including a cryptographic fingerprint.
 */
export async function exportChatPublicKey(publicKey: CryptoKey): Promise<ExportedPublicKey> {
  assertCryptoSupported();

  if (!publicKey || publicKey.type !== 'public' || publicKey.algorithm.name !== 'ECDH') {
    throw new ChatCryptoError('INVALID_PUBLIC_KEY', 'Invalid public key provided for export.');
  }

  try {
    const rawBuffer = await crypto.subtle.exportKey('raw', publicKey);
    const rawBytes = new Uint8Array(rawBuffer);
    const rawBase64Url = uint8ArrayToBase64Url(rawBytes);

    const jwk = await crypto.subtle.exportKey('jwk', publicKey);

    const hashBuffer = await crypto.subtle.digest('SHA-256', toBufferSource(rawBytes));
    const fingerprint = uint8ArrayToBase64Url(new Uint8Array(hashBuffer));

    return {
      version: 1,
      curve: 'P-256',
      format: 'raw+jwk',
      rawBase64Url,
      jwk,
      fingerprint,
    };
  } catch (err) {
    if (err instanceof ChatCryptoError) throw err;
    throw new ChatCryptoError('KEY_GENERATION_FAILED', 'Failed to export public key.', err);
  }
}

/**
 * Validates and imports an external participant's P-256 public key.
 * Supports ExportedPublicKey objects, raw 65-byte uncompressed point base64url strings,
 * raw Uint8Array buffers, or JWK objects.
 */
export async function importChatPublicKey(
  keyInput: ExportedPublicKey | JsonWebKey | string | Uint8Array
): Promise<CryptoKey> {
  assertCryptoSupported();

  if (!keyInput) {
    throw new ChatCryptoError('INVALID_PUBLIC_KEY', 'No public key provided to import.');
  }

  try {
    // 1. ExportedPublicKey structure
    if (typeof keyInput === 'object' && keyInput !== null && 'curve' in keyInput) {
      const exp = keyInput as ExportedPublicKey;
      if (exp.curve !== 'P-256') {
        throw new ChatCryptoError('INVALID_PUBLIC_KEY', `Unsupported curve: ${exp.curve}. Expected P-256.`);
      }
      if (exp.rawBase64Url) {
        let rawBytes: Uint8Array;
        try {
          rawBytes = base64UrlToUint8Array(exp.rawBase64Url);
        } catch (err) {
          throw new ChatCryptoError('INVALID_PUBLIC_KEY', 'Invalid base64url encoding in rawBase64Url.', err);
        }
        return await importRawPublicKeyBytes(rawBytes);
      }
      if (exp.jwk) {
        return await crypto.subtle.importKey('jwk', exp.jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
      }
    }

    // 2. Raw byte buffer
    if (keyInput instanceof Uint8Array) {
      return await importRawPublicKeyBytes(keyInput);
    }

    // 3. String (base64url raw point or JSON JWK string)
    if (typeof keyInput === 'string') {
      const trimmed = keyInput.trim();
      if (trimmed.startsWith('{')) {
        let parsed: unknown;
        try {
          parsed = JSON.parse(trimmed);
        } catch (err) {
          throw new ChatCryptoError('INVALID_PUBLIC_KEY', 'Invalid JSON in public key string.', err);
        }
        return await importChatPublicKey(parsed as any);
      }
      let rawBytes: Uint8Array;
      try {
        rawBytes = base64UrlToUint8Array(trimmed);
      } catch (err) {
        throw new ChatCryptoError('INVALID_PUBLIC_KEY', 'Invalid base64url encoding in public key string.', err);
      }
      return await importRawPublicKeyBytes(rawBytes);
    }

    // 4. JWK object
    if (typeof keyInput === 'object' && keyInput !== null && 'kty' in keyInput) {
      const jwk = keyInput as JsonWebKey;
      if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
        throw new ChatCryptoError('INVALID_PUBLIC_KEY', 'Invalid JWK: must be EC curve P-256.');
      }
      return await crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
    }

    throw new ChatCryptoError('INVALID_PUBLIC_KEY', 'Unrecognized public key format.');
  } catch (err) {
    if (err instanceof ChatCryptoError) {
      if (err.code === 'INVALID_PUBLIC_KEY') throw err;
      throw new ChatCryptoError('INVALID_PUBLIC_KEY', err.safeMessage, err);
    }
    throw new ChatCryptoError('INVALID_PUBLIC_KEY', 'Failed to import public encryption key.', err);
  }
}

/**
 * Validates and imports a raw 65-byte uncompressed P-256 point (0x04 || X || Y).
 */
async function importRawPublicKeyBytes(bytes: Uint8Array): Promise<CryptoKey> {
  if (bytes.byteLength !== 65 || bytes[0] !== 0x04) {
    throw new ChatCryptoError(
      'INVALID_PUBLIC_KEY',
      `Invalid raw P-256 public key. Expected 65-byte uncompressed point starting with 0x04, got ${bytes.byteLength} bytes.`
    );
  }
  return await crypto.subtle.importKey(
    'raw',
    toBufferSource(bytes),
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );
}

/**
 * Generates a full in-memory ChatIdentity with a non-extractable private key.
 */
export async function generateChatIdentity(id = 'default'): Promise<ChatIdentity> {
  const keyPair = await generateChatKeyPair();
  const exportedPublic = await exportChatPublicKey(keyPair.publicKey);

  return {
    version: 1,
    id,
    keyPair: {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
    },
    exportedPublicKey: exportedPublic,
    createdAt: Date.now(),
  };
}

// ============================================================================
// Part B: IndexedDB Key Persistence & Recovery
// ============================================================================

function getIndexedDB(): IDBFactory {
  if (typeof window !== 'undefined' && window.indexedDB) {
    return window.indexedDB;
  }
  if (typeof globalThis !== 'undefined' && (globalThis as any).indexedDB) {
    return (globalThis as any).indexedDB;
  }
  throw new ChatCryptoError(
    'STORAGE_UNAVAILABLE',
    'IndexedDB storage is not supported or accessible in this environment.'
  );
}

/**
 * Opens the IndexedDB keystore with schema creation and error handling.
 */
function openCryptoDatabase(): Promise<IDBDatabase> {
  const idb = getIndexedDB();

  return new Promise((resolve, reject) => {
    let request: IDBOpenDBRequest;
    try {
      request = idb.open(IDB_DATABASE_NAME, IDB_SCHEMA_VERSION);
    } catch (err) {
      return reject(
        new ChatCryptoError(
          'STORAGE_BLOCKED',
          'IndexedDB database open call threw an access error. Storage may be blocked.',
          err
        )
      );
    }

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(IDB_STORE_NAME)) {
        db.createObjectStore(IDB_STORE_NAME, { keyPath: 'id' });
      }
    };

    request.onsuccess = () => {
      resolve(request.result);
    };

    request.onerror = () => {
      reject(
        new ChatCryptoError(
          'STORAGE_BLOCKED',
          'Failed to open cryptographic identity database.',
          request.error
        )
      );
    };

    request.onblocked = () => {
      reject(
        new ChatCryptoError(
          'STORAGE_BLOCKED',
          'Database open request blocked by concurrent connection.'
        )
      );
    };
  });
}

/**
 * Executes an operation inside an IndexedDB transaction.
 */
async function withIdentityStore<T>(
  mode: IDBTransactionMode,
  operation: (store: IDBObjectStore) => IDBRequest<any>
): Promise<T> {
  const db = await openCryptoDatabase();
  return new Promise<T>((resolve, reject) => {
    let tx: IDBTransaction;
    try {
      tx = db.transaction(IDB_STORE_NAME, mode);
    } catch (err) {
      db.close();
      return reject(new ChatCryptoError('STORAGE_CORRUPTED', 'Failed to create database transaction.', err));
    }

    let request: IDBRequest<any>;
    try {
      const store = tx.objectStore(IDB_STORE_NAME);
      request = operation(store);
    } catch (err) {
      db.close();
      return reject(new ChatCryptoError('STORAGE_CORRUPTED', 'Database operation threw an error.', err));
    }

    request.onerror = () => {
      // Handled by tx.onerror
    };

    tx.oncomplete = () => {
      db.close();
      resolve(request.result);
    };

    tx.onerror = () => {
      db.close();
      reject(new ChatCryptoError('STORAGE_CORRUPTED', 'Database transaction failed.', tx.error));
    };

    tx.onabort = () => {
      db.close();
      reject(new ChatCryptoError('STORAGE_CORRUPTED', 'Database transaction aborted.', tx.error));
    };
  });
}

/**
 * Persists an identity into IndexedDB using structured cloning of the CryptoKey.
 */
export async function saveChatIdentity(identity: ChatIdentity): Promise<void> {
  if (
    !identity ||
    !identity.id ||
    !identity.keyPair ||
    !identity.keyPair.privateKey ||
    !identity.keyPair.publicKey ||
    !identity.exportedPublicKey
  ) {
    throw new ChatCryptoError('KEY_GENERATION_FAILED', 'Invalid chat identity provided for persistence.');
  }

  const record: StoredIdentityRecord = {
    id: identity.id,
    version: identity.version,
    keyVersion: identity.exportedPublicKey.version,
    privateKey: identity.keyPair.privateKey,
    publicKey: identity.keyPair.publicKey,
    exportedPublicKey: identity.exportedPublicKey,
    createdAt: identity.createdAt,
    updatedAt: Date.now(),
  };

  try {
    await withIdentityStore('readwrite', (store) => store.put(record));
  } catch (err) {
    if (err instanceof ChatCryptoError) throw err;
    throw new ChatCryptoError('STORAGE_CORRUPTED', 'Failed to save chat identity to local storage.', err);
  }
}

/**
 * Loads an existing identity from IndexedDB.
 * Returns null if not found. Throws explicit typed errors if storage is corrupted or private key is missing.
 */
export async function loadChatIdentity(id = 'default'): Promise<ChatIdentity | null> {
  let record: StoredIdentityRecord | undefined;
  try {
    record = await withIdentityStore<StoredIdentityRecord | undefined>('readonly', (store) => store.get(id));
  } catch (err) {
    if (err instanceof ChatCryptoError) throw err;
    throw new ChatCryptoError('STORAGE_CORRUPTED', `Failed to read chat identity '${id}' from storage.`, err);
  }

  if (!record) {
    return null;
  }

  // Validate private key presence and type
  if (!record.privateKey || !(record.privateKey instanceof CryptoKey) || record.privateKey.type !== 'private') {
    throw new ChatCryptoError(
      'PRIVATE_KEY_MISSING',
      'The private encryption key for this identity is missing or corrupted in local storage. Historical encrypted messages cannot be decrypted.'
    );
  }

  if (!record.publicKey || !(record.publicKey instanceof CryptoKey) || record.publicKey.type !== 'public') {
    throw new ChatCryptoError(
      'STORAGE_CORRUPTED',
      'The public encryption key for this identity is corrupted in local storage.'
    );
  }

  if (!record.exportedPublicKey || !record.exportedPublicKey.rawBase64Url) {
    throw new ChatCryptoError(
      'STORAGE_CORRUPTED',
      'Exported public key metadata is corrupted in local storage.'
    );
  }

  return {
    version: record.version || 1,
    id: record.id,
    keyPair: {
      publicKey: record.publicKey,
      privateKey: record.privateKey,
    },
    exportedPublicKey: record.exportedPublicKey,
    createdAt: record.createdAt,
  };
}

/**
 * Checks whether an identity record already exists in IndexedDB.
 */
export async function checkIdentityExists(id = 'default'): Promise<boolean> {
  try {
    const record = await withIdentityStore<StoredIdentityRecord | undefined>('readonly', (store) => store.get(id));
    return !!record;
  } catch (err) {
    if (err instanceof ChatCryptoError) throw err;
    throw new ChatCryptoError('STORAGE_CORRUPTED', `Failed to check existence for identity '${id}'.`, err);
  }
}

/**
 * Initializes or loads the current browser's encryption identity.
 * If an existing identity is found, it is loaded and returned.
 * If no identity exists, a fresh one is generated, persisted, and returned.
 * IMPORTANT: If storage or loading fails with an error, this function FAILS CLOSED
 * and does NOT silently replace or generate an ephemeral unpersisted key.
 */
export async function initializeChatIdentity(id = 'default'): Promise<ChatIdentity> {
  // 1. Attempt to load existing identity
  const existing = await loadChatIdentity(id);
  if (existing) {
    return existing;
  }

  // 2. Generate new identity only if clean non-existence was confirmed
  const fresh = await generateChatIdentity(id);

  // 3. Persist before returning
  await saveChatIdentity(fresh);

  return fresh;
}

/**
 * Deletes a stored chat identity from IndexedDB.
 */
export async function deleteChatIdentity(id = 'default'): Promise<void> {
  try {
    await withIdentityStore('readwrite', (store) => store.delete(id));
  } catch (err) {
    if (err instanceof ChatCryptoError) throw err;
    throw new ChatCryptoError('STORAGE_CORRUPTED', `Failed to delete identity '${id}'.`, err);
  }
}

/**
 * Clears all identities from the keystore.
 */
export async function clearAllChatIdentities(): Promise<void> {
  try {
    await withIdentityStore('readwrite', (store) => store.clear());
  } catch (err) {
    if (err instanceof ChatCryptoError) throw err;
    throw new ChatCryptoError('STORAGE_CORRUPTED', 'Failed to clear identities keystore.', err);
  }
}

// ============================================================================
// Part C: Shared-Secret Derivation (ECDH + HKDF-SHA256)
// ============================================================================

/**
 * Builds a deterministic, domain-separated HKDF info string binding
 * protocol version, conversation, and sorted participant identities.
 */
export function buildDerivationInfo(options?: KeyDerivationOptions): Uint8Array {
  const protocol = options?.protocolContext || DEFAULT_PROTOCOL_CONTEXT;
  const conv = options?.conversationId ? `conv=${options.conversationId};` : '';

  let participants = '';
  if (options?.senderAddress && options?.recipientAddress) {
    const s = options.senderAddress.trim().toLowerCase();
    const r = options.recipientAddress.trim().toLowerCase();
    const sorted = [s, r].sort();
    participants = `participants=${sorted[0]}<->${sorted[1]};`;
  } else if (options?.senderAddress) {
    participants = `sender=${options.senderAddress.trim().toLowerCase()};`;
  } else if (options?.recipientAddress) {
    participants = `recipient=${options.recipientAddress.trim().toLowerCase()};`;
  }

  const infoString = `${protocol}:aes-gcm-256;${conv}${participants}`;
  return new TextEncoder().encode(infoString);
}

/**
 * Derives a 256-bit AES-GCM symmetric key from the local ECDH private key
 * and a validated peer public key using HKDF-SHA-256.
 */
export async function deriveSharedKey(
  privateKey: CryptoKey,
  peerPublicKeyInput: CryptoKey | ExportedPublicKey | JsonWebKey | string | Uint8Array,
  options?: KeyDerivationOptions
): Promise<CryptoKey> {
  assertCryptoSupported();

  if (!privateKey || privateKey.type !== 'private' || privateKey.algorithm.name !== 'ECDH') {
    throw new ChatCryptoError('KEY_DERIVATION_FAILED', 'Invalid private key provided for key derivation.');
  }

  let peerPublicKey: CryptoKey;
  if (peerPublicKeyInput instanceof CryptoKey) {
    if (peerPublicKeyInput.type !== 'public' || peerPublicKeyInput.algorithm.name !== 'ECDH') {
      throw new ChatCryptoError('INVALID_PUBLIC_KEY', 'Invalid peer public key CryptoKey.');
    }
    peerPublicKey = peerPublicKeyInput;
  } else {
    peerPublicKey = await importChatPublicKey(peerPublicKeyInput);
  }

  try {
    // 1. ECDH derivation of 256 bits (32 bytes) of shared secret
    const sharedSecretBuffer = await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: peerPublicKey,
      },
      privateKey,
      256
    );

    // 2. HKDF extract and expand with SHA-256
    const salt = options?.salt || DEFAULT_HKDF_SALT;
    const info = buildDerivationInfo(options);

    const hkdfKey = await crypto.subtle.importKey(
      'raw',
      sharedSecretBuffer,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );

    const derivedAesKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: toBufferSource(salt),
        info: toBufferSource(info),
      },
      hkdfKey,
      {
        name: 'AES-GCM',
        length: 256,
      },
      false, // AES key is kept non-extractable
      ['encrypt', 'decrypt']
    );

    return derivedAesKey;
  } catch (err) {
    if (err instanceof ChatCryptoError) throw err;
    throw new ChatCryptoError('KEY_DERIVATION_FAILED', 'Shared secret derivation failed.', err);
  }
}

// ============================================================================
// Part D: Message Encryption & Decryption (AES-256-GCM)
// ============================================================================

/**
 * Builds canonical Authenticated Additional Data (AAD) bytes.
 */
function buildAadBytes(
  optionsAad?: Uint8Array | string,
  metadata?: EnvelopeMetadata
): Uint8Array | undefined {
  if (optionsAad) {
    return typeof optionsAad === 'string' ? new TextEncoder().encode(optionsAad) : optionsAad;
  }
  if (metadata) {
    const conv = metadata.conversationId || '';
    const s = metadata.sender ? metadata.sender.toLowerCase() : '';
    const r = metadata.recipient ? metadata.recipient.toLowerCase() : '';
    const canonical = `metamask-chat-aad:v1;conv=${conv};s=${s};r=${r}`;
    return new TextEncoder().encode(canonical);
  }
  return undefined;
}

/**
 * Encrypts a plaintext message using AES-256-GCM with a fresh 96-bit random IV.
 * Plaintext is strictly kept out of the returned envelope.
 */
export async function encryptMessage(
  plaintext: string,
  key: CryptoKey,
  options?: EncryptOptions
): Promise<EncryptedMessageEnvelope> {
  assertCryptoSupported();

  if (typeof plaintext !== 'string') {
    throw new ChatCryptoError('ENCRYPTION_FAILED', 'Plaintext message must be a string.');
  }

  if (!key || key.type !== 'secret' || key.algorithm.name !== 'AES-GCM') {
    throw new ChatCryptoError('ENCRYPTION_FAILED', 'Invalid AES-GCM encryption key.');
  }

  try {
    // Fresh 96-bit (12 bytes) IV per operation
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const aadBytes = buildAadBytes(options?.additionalData, options?.metadata);
    const plaintextBytes = new TextEncoder().encode(plaintext);

    const encryptParams: AesGcmParams = {
      name: 'AES-GCM',
      iv: toBufferSource(iv),
      tagLength: 128,
    };
    if (aadBytes) {
      encryptParams.additionalData = toBufferSource(aadBytes);
    }

    const ciphertextBuffer = await crypto.subtle.encrypt(
      encryptParams,
      key,
      toBufferSource(plaintextBytes)
    );

    const ciphertextBytes = new Uint8Array(ciphertextBuffer);

    const envelope: EncryptedMessageEnvelope = {
      version: 1,
      algorithm: PROTOCOL_ALGORITHM,
      keyVersion: options?.keyVersion || 1,
      iv: uint8ArrayToBase64Url(iv),
      ciphertext: uint8ArrayToBase64Url(ciphertextBytes),
    };

    if (aadBytes) {
      envelope.aad = uint8ArrayToBase64Url(aadBytes);
    }
    if (options?.metadata) {
      envelope.metadata = { ...options.metadata };
    }
    if (options?.senderPublicKey) {
      envelope.senderPublicKey = options.senderPublicKey;
    }

    return envelope;
  } catch (err) {
    if (err instanceof ChatCryptoError) throw err;
    throw new ChatCryptoError('ENCRYPTION_FAILED', 'Message encryption failed.', err);
  }
}

/**
 * Validates the encrypted envelope and decrypts the ciphertext using AES-256-GCM.
 * Fails closed if authentication tag, IV, or AAD validation fails.
 */
export async function decryptMessage(
  envelopeInput: EncryptedMessageEnvelope | string,
  key: CryptoKey,
  options?: DecryptOptions
): Promise<string> {
  assertCryptoSupported();

  if (!key || key.type !== 'secret' || key.algorithm.name !== 'AES-GCM') {
    throw new ChatCryptoError('DECRYPTION_FAILED', 'Invalid AES-GCM decryption key.');
  }

  let envelope: EncryptedMessageEnvelope;
  if (typeof envelopeInput === 'string') {
    envelope = deserializeEnvelope(envelopeInput);
  } else {
    envelope = envelopeInput;
    validateEnvelope(envelope);
  }

  // Validate contextual bindings if expected by caller
  if (options?.expectedConversationId && envelope.metadata?.conversationId) {
    if (options.expectedConversationId !== envelope.metadata.conversationId) {
      throw new ChatCryptoError('INVALID_ENVELOPE', 'Message conversation ID does not match expected conversation.');
    }
  }
  if (options?.expectedSender && envelope.metadata?.sender) {
    if (options.expectedSender.toLowerCase() !== envelope.metadata.sender.toLowerCase()) {
      throw new ChatCryptoError('INVALID_ENVELOPE', 'Message sender does not match expected sender.');
    }
  }
  if (options?.expectedRecipient && envelope.metadata?.recipient) {
    if (options.expectedRecipient.toLowerCase() !== envelope.metadata.recipient.toLowerCase()) {
      throw new ChatCryptoError('INVALID_ENVELOPE', 'Message recipient does not match expected recipient.');
    }
  }

  // Decode and strictly check IV length (12 bytes = 96 bits)
  const ivBytes = base64UrlToUint8Array(envelope.iv);
  if (ivBytes.byteLength !== 12) {
    throw new ChatCryptoError(
      'INVALID_ENVELOPE',
      `Invalid IV length: expected 12 bytes, got ${ivBytes.byteLength}.`
    );
  }

  // Decode and check ciphertext length (minimum 16 bytes for 128-bit GCM tag)
  const ciphertextBytes = base64UrlToUint8Array(envelope.ciphertext);
  if (ciphertextBytes.byteLength < 16) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Ciphertext is too short to contain a valid authentication tag.');
  }

  // Determine and verify AAD
  let aadBytes: Uint8Array | undefined;
  if (options?.expectedAdditionalData) {
    aadBytes = typeof options.expectedAdditionalData === 'string'
      ? new TextEncoder().encode(options.expectedAdditionalData)
      : options.expectedAdditionalData;
  } else if (envelope.metadata) {
    const metaAad = buildAadBytes(undefined, envelope.metadata);
    if (envelope.aad && metaAad) {
      const expectedAadB64 = uint8ArrayToBase64Url(metaAad);
      if (envelope.aad !== expectedAadB64) {
        throw new ChatCryptoError(
          'AUTH_TAG_MISMATCH',
          'Envelope metadata does not match authenticated additional data (AAD). Tampering detected.'
        );
      }
    }
    aadBytes = metaAad;
  } else if (envelope.aad) {
    aadBytes = base64UrlToUint8Array(envelope.aad);
  }

  const decryptParams: AesGcmParams = {
    name: 'AES-GCM',
    iv: toBufferSource(ivBytes),
    tagLength: 128,
  };
  if (aadBytes) {
    decryptParams.additionalData = toBufferSource(aadBytes);
  }

  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      decryptParams,
      key,
      toBufferSource(ciphertextBytes)
    );

    return new TextDecoder().decode(decryptedBuffer);
  } catch (err) {
    // Fail closed: never return corrupt or unauthenticated plaintext
    throw new ChatCryptoError(
      'AUTH_TAG_MISMATCH',
      'Message decryption or authentication tag verification failed. Ciphertext, IV, or metadata was tampered with.',
      err
    );
  }
}

// ============================================================================
// Part E: Envelope Serialization & Strict Validation
// ============================================================================

/**
 * Validates the structure and integrity constraints of an envelope.
 */
export function validateEnvelope(envelope: unknown): asserts envelope is EncryptedMessageEnvelope {
  if (!envelope || typeof envelope !== 'object') {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Message envelope must be a valid object.');
  }

  const env = envelope as Record<string, any>;

  // Check version
  if (env.version !== PROTOCOL_VERSION) {
    throw new ChatCryptoError(
      'INCOMPATIBLE_VERSION',
      `Unsupported envelope version: ${env.version}. Expected version ${PROTOCOL_VERSION}.`
    );
  }

  // Check algorithm
  if (env.algorithm !== PROTOCOL_ALGORITHM && env.algorithm !== 'AES-256-GCM') {
    throw new ChatCryptoError('INVALID_ENVELOPE', `Unsupported algorithm: ${env.algorithm}.`);
  }

  // Check keyVersion
  if (typeof env.keyVersion !== 'number' || env.keyVersion <= 0) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Envelope missing valid keyVersion number.');
  }

  // Check IV
  if (typeof env.iv !== 'string' || env.iv.length === 0) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Envelope missing required IV string.');
  }

  // Check ciphertext
  if (typeof env.ciphertext !== 'string' || env.ciphertext.length === 0) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Envelope missing required ciphertext string.');
  }

  // Enforce zero plaintext leak rule
  if ('plaintext' in env || 'message' in env || 'text' in env || 'content' in env) {
    throw new ChatCryptoError(
      'INVALID_ENVELOPE',
      'Security violation: plaintext detected inside encrypted message envelope.'
    );
  }
}

/**
 * Serializes an envelope into a JSON string.
 */
export function serializeEnvelope(envelope: EncryptedMessageEnvelope): string {
  validateEnvelope(envelope);
  return JSON.stringify(envelope);
}

/**
 * Deserializes an envelope from a JSON string or base64url-encoded JSON string.
 */
export function deserializeEnvelope(input: string): EncryptedMessageEnvelope {
  if (typeof input !== 'string' || !input.trim()) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Envelope payload must be a non-empty string.');
  }

  const trimmed = input.trim();
  let parsed: unknown;

  if (trimmed.startsWith('{')) {
    try {
      parsed = JSON.parse(trimmed);
    } catch (err) {
      throw new ChatCryptoError('INVALID_ENVELOPE', 'Failed to parse JSON envelope.', err);
    }
  } else {
    try {
      const bytes = base64UrlToUint8Array(trimmed);
      const jsonStr = new TextDecoder().decode(bytes);
      parsed = JSON.parse(jsonStr);
    } catch (err) {
      throw new ChatCryptoError('INVALID_ENVELOPE', 'Failed to decode base64url envelope string.', err);
    }
  }

  validateEnvelope(parsed);
  return parsed;
}

// ============================================================================
// Part F: Multi-Recipient Room / Group Encryption (Key Encapsulation Mechanism)
// ============================================================================

/**
 * Recipient-specific encrypted content-key wrapper.
 * Enables 1-to-many room encryption without redundant plaintext encryption.
 */
export interface RecipientKeyWrapper {
  /** EVM address of recipient */
  recipient: string;
  /** Public key fingerprint of recipient */
  keyFingerprint: string;
  /** 12-byte random IV for wrappedKey encoded as base64url */
  iv: string;
  /** 256-bit content key encrypted with pairwise shared key, encoded as base64url */
  wrappedKey: string;
}

/**
 * Versioned transport envelope for multi-recipient room messages (e.g. Global Chat).
 * Strictly excludes message plaintext.
 */
export interface EncryptedRoomMessageEnvelope {
  version: 1;
  messageId: string;
  roomId: string;
  sender: string;
  algorithm: 'ECDH-P256-HKDF-AES-GCM-256' | 'ECDH-P256-HKDF-SHA256-AES-GCM-256';
  keyVersion: number;
  /** 12-byte random IV for message content, encoded as base64url */
  contentIv: string;
  /** Content ciphertext with 128-bit GCM tag, encoded as base64url */
  contentCiphertext: string;
  /** Array of recipient-specific encrypted content-key wrappers */
  recipients: RecipientKeyWrapper[];
  /** Sender public key metadata to allow recipients to derive shared key */
  senderPublicKey: ExportedPublicKey;
  /** Optional EIP-191 wallet signature over message envelope metadata */
  signature?: string;
  /** Creation timestamp in ISO 8601 UTC */
  timestamp: string;
}

export interface MultiRecipientEncryptOptions {
  roomId?: string;
  messageId?: string;
  keyVersion?: number;
}

/**
 * Encrypts a message for a set of recipients using a single random content key (K_msg),
 * wrapping K_msg individually for each recipient using pairwise ECDH + HKDF.
 * Ensures the sender can also decrypt their own message.
 */
export async function encryptMultiRecipientMessage(
  plaintext: string,
  senderIdentity: ChatIdentity,
  recipientPublicKeys: Record<string, ExportedPublicKey | CryptoKey>,
  options?: MultiRecipientEncryptOptions
): Promise<EncryptedRoomMessageEnvelope> {
  assertCryptoSupported();

  if (typeof plaintext !== 'string' || plaintext.length === 0) {
    throw new ChatCryptoError('ENCRYPTION_FAILED', 'Plaintext message cannot be empty.');
  }

  const roomId = options?.roomId || 'global';
  const messageId = options?.messageId || `msg_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
  const senderAddress = senderIdentity.id.trim().toLowerCase();
  const keyVersion = options?.keyVersion || 1;

  // 1. Generate a fresh, random 256-bit (32 bytes) content encryption key K_msg
  const rawContentKey = crypto.getRandomValues(new Uint8Array(32));
  const contentKey = await crypto.subtle.importKey(
    'raw',
    rawContentKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  // 2. Encrypt the plaintext with K_msg using a fresh 96-bit IV
  const contentIv = crypto.getRandomValues(new Uint8Array(12));
  const contentAad = new TextEncoder().encode(
    `metamask-chat-e2ee:v1:content;room=${roomId};msgId=${messageId};sender=${senderAddress}`
  );

  const ciphertextBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: toBufferSource(contentIv),
      additionalData: toBufferSource(contentAad),
      tagLength: 128,
    },
    contentKey,
    toBufferSource(new TextEncoder().encode(plaintext))
  );

  const contentCiphertext = uint8ArrayToBase64Url(new Uint8Array(ciphertextBuffer));

  // 3. Ensure sender is included in recipient map so sender can decrypt their own message
  const fullRecipientMap = { ...recipientPublicKeys };
  if (!fullRecipientMap[senderAddress] && senderIdentity.exportedPublicKey) {
    fullRecipientMap[senderAddress] = senderIdentity.exportedPublicKey;
  }

  // 4. Wrap K_msg for each recipient
  const recipientWrappers: RecipientKeyWrapper[] = [];

  for (const [address, peerPubKeyInput] of Object.entries(fullRecipientMap)) {
    const normalizedRecipient = address.trim().toLowerCase();
    try {
      // Derive pairwise key with domain-separated HKDF info
      const wrapInfo = new TextEncoder().encode(
        `metamask-chat-e2ee:v1:key-wrap;room=${roomId};recipient=${normalizedRecipient}`
      );

      let peerPublicKey: CryptoKey;
      let fingerprint: string;

      if (peerPubKeyInput instanceof CryptoKey) {
        peerPublicKey = peerPubKeyInput;
        fingerprint = 'unknown';
      } else {
        peerPublicKey = await importChatPublicKey(peerPubKeyInput);
        fingerprint = peerPubKeyInput.fingerprint;
      }

      // ECDH derivation
      const sharedSecretBuffer = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: peerPublicKey },
        senderIdentity.keyPair.privateKey,
        256
      );

      const hkdfKey = await crypto.subtle.importKey(
        'raw',
        sharedSecretBuffer,
        { name: 'HKDF' },
        false,
        ['deriveKey']
      );

      const pairwiseWrapKey = await crypto.subtle.deriveKey(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          salt: toBufferSource(DEFAULT_HKDF_SALT),
          info: toBufferSource(wrapInfo),
        },
        hkdfKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
      );

      // Encrypt the 32-byte content key with fresh 96-bit IV
      const wrapIv = crypto.getRandomValues(new Uint8Array(12));
      const wrappedKeyBuffer = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: toBufferSource(wrapIv),
          tagLength: 128,
        },
        pairwiseWrapKey,
        toBufferSource(rawContentKey)
      );

      recipientWrappers.push({
        recipient: normalizedRecipient,
        keyFingerprint: fingerprint,
        iv: uint8ArrayToBase64Url(wrapIv),
        wrappedKey: uint8ArrayToBase64Url(new Uint8Array(wrappedKeyBuffer)),
      });
    } catch (wrapErr) {
      console.warn(`Failed to wrap key for recipient ${normalizedRecipient}:`, wrapErr);
    }
  }

  if (recipientWrappers.length === 0) {
    throw new ChatCryptoError('ENCRYPTION_FAILED', 'Failed to wrap encryption key for any recipient.');
  }

  const envelope: EncryptedRoomMessageEnvelope = {
    version: 1,
    messageId,
    roomId,
    sender: senderAddress,
    algorithm: PROTOCOL_ALGORITHM,
    keyVersion,
    contentIv: uint8ArrayToBase64Url(contentIv),
    contentCiphertext,
    recipients: recipientWrappers,
    senderPublicKey: senderIdentity.exportedPublicKey,
    timestamp: new Date().toISOString(),
  };

  validateRoomEnvelope(envelope);
  return envelope;
}

/**
 * Decrypts a multi-recipient room message envelope using the recipient's private key.
 */
export async function decryptMultiRecipientMessage(
  envelopeInput: EncryptedRoomMessageEnvelope | string,
  myAddress: string,
  myPrivateKey: CryptoKey,
  senderPublicKeyInput?: ExportedPublicKey | CryptoKey
): Promise<string> {
  assertCryptoSupported();

  let envelope: EncryptedRoomMessageEnvelope;
  if (typeof envelopeInput === 'string') {
    envelope = deserializeRoomEnvelope(envelopeInput);
  } else {
    envelope = envelopeInput;
    validateRoomEnvelope(envelope);
  }

  const normalizedMyAddress = myAddress.trim().toLowerCase();

  // 1. Locate recipient wrapper
  const wrapper = envelope.recipients.find(
    (r) => r.recipient.trim().toLowerCase() === normalizedMyAddress
  );

  if (!wrapper) {
    throw new ChatCryptoError(
      'DECRYPTION_FAILED',
      'Current wallet is not an authorized recipient of this message envelope.'
    );
  }

  // 2. Resolve sender public key
  const peerPubKeySource = senderPublicKeyInput || envelope.senderPublicKey;
  if (!peerPubKeySource) {
    throw new ChatCryptoError('INVALID_PUBLIC_KEY', 'Sender public key missing for message decryption.');
  }

  let senderPublicKey: CryptoKey;
  if (peerPubKeySource instanceof CryptoKey) {
    senderPublicKey = peerPubKeySource;
  } else {
    senderPublicKey = await importChatPublicKey(peerPubKeySource);
  }

  // 3. Derive pairwise key used to unwrap K_msg
  const wrapInfo = new TextEncoder().encode(
    `metamask-chat-e2ee:v1:key-wrap;room=${envelope.roomId};recipient=${normalizedMyAddress}`
  );

  const sharedSecretBuffer = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: senderPublicKey },
    myPrivateKey,
    256
  );

  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    sharedSecretBuffer,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );

  const pairwiseWrapKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: toBufferSource(DEFAULT_HKDF_SALT),
      info: toBufferSource(wrapInfo),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  // 4. Unwrap the 32-byte content key K_msg
  const wrapIv = base64UrlToUint8Array(wrapper.iv);
  const wrappedKeyBytes = base64UrlToUint8Array(wrapper.wrappedKey);

  let rawContentKeyBuffer: ArrayBuffer;
  try {
    rawContentKeyBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toBufferSource(wrapIv),
        tagLength: 128,
      },
      pairwiseWrapKey,
      toBufferSource(wrappedKeyBytes)
    );
  } catch (unwrapErr) {
    throw new ChatCryptoError(
      'AUTH_TAG_MISMATCH',
      'Failed to unwrap message encryption key: key wrapper tag mismatch or invalid key.',
      unwrapErr
    );
  }

  const contentKey = await crypto.subtle.importKey(
    'raw',
    rawContentKeyBuffer,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  // 5. Decrypt content ciphertext with K_msg and content AAD
  const contentIv = base64UrlToUint8Array(envelope.contentIv);
  const contentCiphertextBytes = base64UrlToUint8Array(envelope.contentCiphertext);
  const contentAad = new TextEncoder().encode(
    `metamask-chat-e2ee:v1:content;room=${envelope.roomId};msgId=${envelope.messageId};sender=${envelope.sender.trim().toLowerCase()}`
  );

  try {
    const plaintextBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toBufferSource(contentIv),
        additionalData: toBufferSource(contentAad),
        tagLength: 128,
      },
      contentKey,
      toBufferSource(contentCiphertextBytes)
    );

    return new TextDecoder().decode(plaintextBuffer);
  } catch (contentDecryptErr) {
    throw new ChatCryptoError(
      'AUTH_TAG_MISMATCH',
      'Message content decryption failed: ciphertext, IV, or authenticated metadata was tampered with.',
      contentDecryptErr
    );
  }
}

/**
 * Validates the structure and field types of an EncryptedRoomMessageEnvelope.
 */
export function validateRoomEnvelope(envelope: unknown): asserts envelope is EncryptedRoomMessageEnvelope {
  if (!envelope || typeof envelope !== 'object') {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Room message envelope must be a non-null object.');
  }

  const env = envelope as Record<string, any>;

  if (env.version !== 1) {
    throw new ChatCryptoError('INCOMPATIBLE_VERSION', `Unsupported envelope version: ${env.version}. Expected 1.`);
  }

  if (typeof env.messageId !== 'string' || !env.messageId.trim()) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Envelope missing valid messageId.');
  }

  if (typeof env.roomId !== 'string' || !env.roomId.trim()) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Envelope missing valid roomId.');
  }

  if (typeof env.sender !== 'string' || !/^0x[a-fA-F0-9]{40}$/.test(env.sender)) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Envelope missing valid sender EVM address.');
  }

  if (typeof env.contentIv !== 'string' || env.contentIv.length === 0) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Envelope missing valid contentIv.');
  }

  if (typeof env.contentCiphertext !== 'string' || env.contentCiphertext.length === 0) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Envelope missing valid contentCiphertext.');
  }

  if (!Array.isArray(env.recipients) || env.recipients.length === 0) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Envelope must contain at least one recipient wrapper.');
  }

  // Strict check: zero plaintext permitted
  if ('plaintext' in env || 'message' in env || 'text' in env) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Security violation: plaintext detected inside room envelope.');
  }
}

export function serializeRoomEnvelope(envelope: EncryptedRoomMessageEnvelope): string {
  validateRoomEnvelope(envelope);
  return JSON.stringify(envelope);
}

export function deserializeRoomEnvelope(input: string): EncryptedRoomMessageEnvelope {
  if (typeof input !== 'string' || !input.trim()) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Room envelope payload must be a non-empty string.');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(input.trim());
  } catch (err) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Failed to parse JSON room envelope.', err);
  }
  validateRoomEnvelope(parsed);
  return parsed;
}

/**
 * Deterministically serializes an arbitrary object to a canonical JSON string
 * with recursively sorted keys and zero extraneous whitespace, matching RFC 8785 (JCS).
 */
export function canonicalJsonStringify(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJsonStringify).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  const pairs = keys.map((key) => JSON.stringify(key) + ':' + canonicalJsonStringify(obj[key]));
  return '{' + pairs.join(',') + '}';
}

export interface CanonicalEnvelopeResult {
  canonicalJson: string;
  envelopeHash: string;
  signMessage: string;
  recipients: RecipientKeyWrapper[];
}

/**
 * Constructs the canonical representation of an encrypted room message envelope,
 * enforces duplicate recipient rejection and deterministic lexicographical recipient ordering,
 * computes the SHA-256 integrity hash, and formats the exact EIP-191 signing message.
 */
export async function buildCanonicalEnvelopeHash(envelope: {
  messageId?: string;
  message_id?: string;
  roomId?: string;
  channel?: string;
  room?: string;
  sender: string;
  algorithm?: string;
  keyVersion?: number;
  key_version?: number;
  contentIv?: string;
  content_iv?: string;
  contentCiphertext?: string;
  content_ciphertext?: string;
  recipients: RecipientKeyWrapper[];
  timestamp: string;
  version?: number;
}): Promise<CanonicalEnvelopeResult> {
  assertCryptoSupported();

  const messageId = String(envelope.messageId || envelope.message_id || '').trim();
  const room = String(envelope.roomId || envelope.channel || envelope.room || 'global').trim();
  const senderRaw = String(envelope.sender || '').trim();
  const senderNorm = senderRaw.toLowerCase();
  const version = Number(envelope.version ?? 1);
  const algorithm = String(envelope.algorithm || PROTOCOL_ALGORITHM).trim();
  const keyVersion = Number(envelope.keyVersion ?? envelope.key_version ?? 1);
  const contentIv = String(envelope.contentIv || envelope.content_iv || '').trim();
  const contentCiphertext = String(envelope.contentCiphertext || envelope.content_ciphertext || '').trim();

  if (!messageId) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Message ID is required for canonical envelope.');
  }
  if (!senderNorm || !/^0x[a-fA-F0-9]{40}$/.test(senderNorm)) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Valid EVM sender address required.');
  }
  if (!contentIv) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Content IV is required.');
  }
  if (!contentCiphertext) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Content ciphertext is required.');
  }
  if (!Array.isArray(envelope.recipients) || envelope.recipients.length === 0) {
    throw new ChatCryptoError('INVALID_ENVELOPE', 'Recipients list cannot be empty.');
  }

  // Reject duplicate recipients
  const seen = new Set<string>();
  for (const r of envelope.recipients) {
    const addr = String(r.recipient || '').trim().toLowerCase();
    if (!addr) {
      throw new ChatCryptoError('INVALID_ENVELOPE', 'Recipient address cannot be empty.');
    }
    if (seen.has(addr)) {
      throw new ChatCryptoError('INVALID_ENVELOPE', `Duplicate recipient address in envelope: ${r.recipient}`);
    }
    seen.add(addr);
  }

  // Deterministic lexicographical sorting by recipient address
  const sortedRecipients: RecipientKeyWrapper[] = envelope.recipients
    .map((r) => ({
      iv: String(r.iv || '').trim(),
      keyFingerprint: String(r.keyFingerprint || '').trim(),
      recipient: String(r.recipient || '').trim().toLowerCase(),
      wrappedKey: String(r.wrappedKey || '').trim(),
    }))
    .sort((a, b) => a.recipient.localeCompare(b.recipient));

  const canonicalDict = {
    algorithm,
    channel: room,
    content_ciphertext: contentCiphertext,
    content_iv: contentIv,
    key_version: keyVersion,
    message_id: messageId,
    recipients: sortedRecipients,
    room,
    sender: senderNorm,
    timestamp: String(envelope.timestamp).trim(),
    version,
  };

  const canonicalJson = canonicalJsonStringify(canonicalDict);

  // SHA-256 hash using Web Cryptography API
  const encodedBytes = new TextEncoder().encode(canonicalJson);
  const digestBuffer = await crypto.subtle.digest('SHA-256', toBufferSource(encodedBytes));
  const hashArray = Array.from(new Uint8Array(digestBuffer));
  const envelopeHash = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

  // Format exact EIP-191 human-readable message binding both room metadata and envelope hash
  const signMessage =
    `zyphra.in Chat Message\n` +
    `Sender: ${senderRaw}\n` +
    `Message ID: ${messageId}\n` +
    `Room: ${room}\n` +
    `Timestamp: ${String(envelope.timestamp).trim()}\n` +
    `Envelope Hash: ${envelopeHash}`;

  return {
    canonicalJson,
    envelopeHash,
    signMessage,
    recipients: sortedRecipients,
  };
}

/**
 * Signs an encrypted room envelope using a wallet provider function,
 * binding the canonical SHA-256 envelope hash.
 */
export async function createSignedRoomMessageEnvelope(
  envelope: EncryptedRoomMessageEnvelope,
  signMessageFn: (message: string) => Promise<string>
): Promise<EncryptedRoomMessageEnvelope> {
  const { signMessage, recipients } = await buildCanonicalEnvelopeHash(envelope);
  const signature = await signMessageFn(signMessage);
  return {
    ...envelope,
    recipients,
    signature,
  };
}


