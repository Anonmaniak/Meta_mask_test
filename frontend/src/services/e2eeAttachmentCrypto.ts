/**
 * Client-Side E2EE File Attachment Encryption & Integrity Verification (Section I).
 *
 * Architecture:
 * 1. Generates a unique ephemeral 256-bit `AES-256-GCM` key + 96-bit IV per file
 *    using WebCrypto CSPRNG (`crypto.getRandomValues` / `crypto.subtle.generateKey`).
 * 2. Binds `(scopeType, scopeId, fileName, mimeType)` as Additional Authenticated Data (AAD).
 * 3. Encrypts file bytes on-device BEFORE upload; server receives only opaque ciphertext
 *    and its SHA-256 integrity digest.
 * 4. The ephemeral decryption key + IV + SHA-256 digest + file metadata are transmitted
 *    exclusively inside the E2EE Olm v2 Double Ratchet or MLS RFC 9420 PrivateMessage!
 * 5. Before decrypting a downloaded ciphertext blob, verifies SHA-256(ciphertext)
 *    matches the expected digest from the E2EE message envelope.
 */

import { base64ToBytes, bytesToBase64 } from './e2eeVault.ts';

export interface EncryptedAttachmentKeyDescriptor {
  attachment_id: string;
  key_b64: string;
  iv_b64: string;
  sha256_hex: string;
  file_name: string;
  mime_type: string;
  size_bytes: number;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, '0');
  }
  return hex;
}

function constantTimeHexEqual(a: string, b: string): boolean {
  const normA = a.trim().toLowerCase();
  const normB = b.trim().toLowerCase();
  if (normA.length !== normB.length) return false;
  let diff = 0;
  for (let i = 0; i < normA.length; i++) {
    diff |= normA.charCodeAt(i) ^ normB.charCodeAt(i);
  }
  return diff === 0;
}

function buildAttachmentAad(scopeType: 'dm' | 'group', fileName: string, mimeType: string): ArrayBuffer {
  return toArrayBuffer(
    new TextEncoder().encode(`zyphra-e2ee-attachment-v1|${scopeType}|${fileName}|${mimeType}`)
  );
}

export async function encryptAttachmentOnDevice(
  plaintextBytes: Uint8Array,
  metadata: { scopeType: 'dm' | 'group'; fileName: string; mimeType: string }
): Promise<{
  ciphertextB64: string;
  ciphertextSha256Hex: string;
  ephemeralKeyB64: string;
  ivB64: string;
  sizeBytes: number;
}> {
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  try {
    const aesKey = await crypto.subtle.importKey(
      'raw',
      toArrayBuffer(rawKey),
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    const ctBuf = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(iv),
        additionalData: buildAttachmentAad(
          metadata.scopeType,
          metadata.fileName,
          metadata.mimeType
        ),
      },
      aesKey,
      toArrayBuffer(plaintextBytes)
    );

    const ctBytes = new Uint8Array(ctBuf);
    const sha256Buf = await crypto.subtle.digest('SHA-256', toArrayBuffer(ctBytes));

    return {
      ciphertextB64: bytesToBase64(ctBytes),
      ciphertextSha256Hex: bytesToHex(new Uint8Array(sha256Buf)),
      ephemeralKeyB64: bytesToBase64(rawKey),
      ivB64: bytesToBase64(iv),
      sizeBytes: plaintextBytes.byteLength,
    };
  } finally {
    rawKey.fill(0);
  }
}

export async function decryptAttachmentOnDevice(
  ciphertextB64: string,
  descriptor: EncryptedAttachmentKeyDescriptor,
  scopeType: 'dm' | 'group'
): Promise<Uint8Array> {
  const ctBytes = base64ToBytes(ciphertextB64);
  const sha256Buf = await crypto.subtle.digest('SHA-256', toArrayBuffer(ctBytes));
  const actualSha256Hex = bytesToHex(new Uint8Array(sha256Buf));

  if (!constantTimeHexEqual(actualSha256Hex, descriptor.sha256_hex)) {
    throw new Error('Attachment integrity check failed: SHA-256 ciphertext digest mismatch');
  }

  const rawKey = base64ToBytes(descriptor.key_b64);
  const iv = base64ToBytes(descriptor.iv_b64);
  try {
    const aesKey = await crypto.subtle.importKey(
      'raw',
      toArrayBuffer(rawKey),
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    const plainBuf = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(iv),
        additionalData: buildAttachmentAad(scopeType, descriptor.file_name, descriptor.mime_type),
      },
      aesKey,
      toArrayBuffer(ctBytes)
    );

    return new Uint8Array(plainBuf);
  } finally {
    rawKey.fill(0);
  }
}
