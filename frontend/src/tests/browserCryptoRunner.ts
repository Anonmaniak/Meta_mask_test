import {
  generateChatIdentity,
  saveChatIdentity,
  loadChatIdentity,
  initializeChatIdentity,
  deleteChatIdentity,
  clearAllChatIdentities,
  importChatPublicKey,
  deriveSharedKey,
  encryptMessage,
  decryptMessage,
  validateEnvelope,
  serializeEnvelope,
  deserializeEnvelope,
  uint8ArrayToBase64Url,
  base64UrlToUint8Array,
  ChatCryptoError,
  IDB_DATABASE_NAME,
  IDB_STORE_NAME,
  IDB_SCHEMA_VERSION,
} from '../services/chatCrypto';

export interface TestResult {
  id: number;
  name: string;
  passed: boolean;
  durationMs: number;
  error?: string;
  details?: string;
}

export async function runAllBrowserCryptoTests(): Promise<TestResult[]> {
  const results: TestResult[] = [];

  async function executeTest(id: number, name: string, fn: () => Promise<string | void>) {
    const t0 = performance.now();
    try {
      const details = await fn();
      const durationMs = Math.round((performance.now() - t0) * 100) / 100;
      results.push({ id, name, passed: true, durationMs, details: details || 'OK' });
    } catch (err: any) {
      const durationMs = Math.round((performance.now() - t0) * 100) / 100;
      results.push({
        id,
        name,
        passed: false,
        durationMs,
        error: err?.message || String(err),
      });
    }
  }

  // Ensure clean IndexedDB state before starting
  try {
    await clearAllChatIdentities();
  } catch {
    // initial clear if store doesn't exist yet is ok
  }

  // --------------------------------------------------------------------------
  // Test 1: Generate key pair and export public key in agreed format
  // --------------------------------------------------------------------------
  await executeTest(1, 'Generate key pair and export public key in agreed format', async () => {
    const identity = await generateChatIdentity('test_alice');

    if (!identity.keyPair || !identity.keyPair.privateKey || !identity.keyPair.publicKey) {
      throw new Error('Keypair missing from generated identity');
    }
    if (identity.keyPair.privateKey.extractable !== false) {
      throw new Error('Private key MUST be non-extractable');
    }
    if (identity.keyPair.privateKey.algorithm.name !== 'ECDH') {
      throw new Error('Private key algorithm must be ECDH');
    }

    const exp = identity.exportedPublicKey;
    if (exp.version !== 1 || exp.curve !== 'P-256') {
      throw new Error('Invalid export version or curve');
    }

    const raw = base64UrlToUint8Array(exp.rawBase64Url);
    if (raw.byteLength !== 65 || raw[0] !== 0x04) {
      throw new Error('Exported raw public key must be 65-byte uncompressed point starting with 0x04');
    }
    if (exp.jwk.kty !== 'EC' || exp.jwk.crv !== 'P-256') {
      throw new Error('Exported JWK is invalid');
    }

    // Verify importability
    const imported = await importChatPublicKey(exp.rawBase64Url);
    if (imported.type !== 'public') {
      throw new Error('Re-imported key is not a public key');
    }

    return `Fingerprint: ${exp.fingerprint.slice(0, 16)}... (Raw 65 bytes, JWK EC P-256)`;
  });

  // --------------------------------------------------------------------------
  // Test 2: Save and reload identity through IndexedDB in browser environment
  // --------------------------------------------------------------------------
  await executeTest(2, 'Save and reload identity through IndexedDB in browser test environment', async () => {
    const originalIdentity = await generateChatIdentity('user_reload_test');
    await saveChatIdentity(originalIdentity);

    // Reload from IndexedDB
    const reloaded = await loadChatIdentity('user_reload_test');
    if (!reloaded) {
      throw new Error('Failed to load saved identity from IndexedDB');
    }

    if (reloaded.id !== 'user_reload_test') {
      throw new Error('Loaded identity ID mismatch');
    }
    if (reloaded.keyPair.privateKey.extractable !== false) {
      throw new Error('Reloaded private key must remain non-extractable');
    }

    // Test that the reloaded non-extractable private key can derive shared keys
    const peer = await generateChatIdentity('peer');
    const sharedKey = await deriveSharedKey(reloaded.keyPair.privateKey, peer.exportedPublicKey);
    if (!sharedKey) {
      throw new Error('Failed to derive shared key using reloaded private key');
    }

    // Encrypt & decrypt roundtrip with reloaded key
    const envelope = await encryptMessage('Message via reloaded IndexedDB key', sharedKey);
    const decrypted = await decryptMessage(envelope, sharedKey);
    if (decrypted !== 'Message via reloaded IndexedDB key') {
      throw new Error('Decryption failed with reloaded key');
    }

    return 'Successfully persisted and reloaded non-extractable CryptoKey via IndexedDB structured cloning';
  });

  // --------------------------------------------------------------------------
  // Test 3: Derive same shared secret/key from both sides of ECDH test exchange
  // --------------------------------------------------------------------------
  await executeTest(3, 'Derive same shared secret/key from both sides of ECDH test exchange', async () => {
    const alice = await generateChatIdentity('alice');
    const bob = await generateChatIdentity('bob');

    const conversationId = 'conv-browser-exchange-42';
    const aliceAddr = '0x1111111111111111111111111111111111111111';
    const bobAddr = '0x2222222222222222222222222222222222222222';

    // Alice derives key for (Alice -> Bob)
    const aliceKey = await deriveSharedKey(alice.keyPair.privateKey, bob.exportedPublicKey, {
      conversationId,
      senderAddress: aliceAddr,
      recipientAddress: bobAddr,
    });

    // Bob derives key for (Bob -> Alice)
    const bobKey = await deriveSharedKey(bob.keyPair.privateKey, alice.exportedPublicKey, {
      conversationId,
      senderAddress: bobAddr,
      recipientAddress: aliceAddr,
    });

    // Test bidirectional communication
    const msg1 = 'Hello Bob, this is Alice!';
    const env1 = await encryptMessage(msg1, aliceKey, {
      metadata: { conversationId, sender: aliceAddr, recipient: bobAddr },
    });
    const dec1 = await decryptMessage(env1, bobKey, { expectedConversationId: conversationId });
    if (dec1 !== msg1) throw new Error('Bob failed to decrypt Alice message');

    const msg2 = 'Hello Alice, Bob acknowledges!';
    const env2 = await encryptMessage(msg2, bobKey, {
      metadata: { conversationId, sender: bobAddr, recipient: aliceAddr },
    });
    const dec2 = await decryptMessage(env2, aliceKey, { expectedConversationId: conversationId });
    if (dec2 !== msg2) throw new Error('Alice failed to decrypt Bob message');

    return 'Both sides derived identical 256-bit AES-GCM keys with domain separation';
  });

  // --------------------------------------------------------------------------
  // Test 4: Encrypt and decrypt a valid message successfully
  // --------------------------------------------------------------------------
  await executeTest(4, 'Encrypt and decrypt a valid message successfully', async () => {
    const alice = await generateChatIdentity('alice4');
    const bob = await generateChatIdentity('bob4');
    const key = await deriveSharedKey(alice.keyPair.privateKey, bob.exportedPublicKey);

    const testStrings = [
      'Simple ASCII text',
      'Unicode: 🦊 MetaMask Escrow 🔐 ⚡ 🚀',
      'JSON payload: {"type":"trade","amount":"1.5 ETH","to":"0x123"}',
      'Line1\nLine2\r\nLine3 with tabs\t\t!',
    ];

    for (const str of testStrings) {
      const envelope = await encryptMessage(str, key);
      const dec = await decryptMessage(envelope, key);
      if (dec !== str) throw new Error(`Decryption mismatch for: ${str}`);
    }

    return 'All Unicode, JSON, and multiline strings decrypted accurately';
  });

  // --------------------------------------------------------------------------
  // Test 5: Confirm that encrypting the same plaintext twice produces different IVs and ciphertexts
  // --------------------------------------------------------------------------
  await executeTest(5, 'Confirm encrypting same plaintext twice produces different IVs and ciphertexts', async () => {
    const identity = await generateChatIdentity('iv_test');
    const key = await deriveSharedKey(identity.keyPair.privateKey, identity.exportedPublicKey);

    const plaintext = 'Identical plaintext message for entropy check';
    const ivs = new Set<string>();
    const ciphertexts = new Set<string>();

    for (let i = 0; i < 25; i++) {
      const envelope = await encryptMessage(plaintext, key);
      const ivBytes = base64UrlToUint8Array(envelope.iv);
      if (ivBytes.byteLength !== 12) {
        throw new Error('IV must be strictly 12 bytes');
      }
      ivs.add(envelope.iv);
      ciphertexts.add(envelope.ciphertext);
    }

    if (ivs.size !== 25) throw new Error(`IV collision detected! Unique: ${ivs.size}/25`);
    if (ciphertexts.size !== 25) throw new Error(`Ciphertext collision! Unique: ${ciphertexts.size}/25`);

    return '25 distinct 96-bit random IVs and ciphertexts generated for identical plaintext';
  });

  // --------------------------------------------------------------------------
  // Test 6: Confirm that a modified ciphertext fails authentication
  // --------------------------------------------------------------------------
  await executeTest(6, 'Confirm that a modified ciphertext fails authentication', async () => {
    const identity = await generateChatIdentity('tamper_ct');
    const key = await deriveSharedKey(identity.keyPair.privateKey, identity.exportedPublicKey);

    const envelope = await encryptMessage('Original uncorrupted message', key);

    const ctBytes = base64UrlToUint8Array(envelope.ciphertext);
    ctBytes[ctBytes.byteLength - 1] ^= 0x01; // flip last bit in auth tag

    const tampered = { ...envelope, ciphertext: uint8ArrayToBase64Url(ctBytes) };

    let threwExpected = false;
    try {
      await decryptMessage(tampered, key);
    } catch (err: any) {
      if (err instanceof ChatCryptoError && err.code === 'AUTH_TAG_MISMATCH') {
        threwExpected = true;
      }
    }

    if (!threwExpected) throw new Error('Modified ciphertext was NOT rejected by authentication tag check');
    return '1-bit ciphertext modification rejected with AUTH_TAG_MISMATCH';
  });

  // --------------------------------------------------------------------------
  // Test 7: Confirm that a modified IV fails authentication
  // --------------------------------------------------------------------------
  await executeTest(7, 'Confirm that a modified IV fails authentication', async () => {
    const identity = await generateChatIdentity('tamper_iv');
    const key = await deriveSharedKey(identity.keyPair.privateKey, identity.exportedPublicKey);

    const envelope = await encryptMessage('Message for IV tamper test', key);

    const ivBytes = base64UrlToUint8Array(envelope.iv);
    ivBytes[0] ^= 0x01; // flip 1 bit in IV

    const tampered = { ...envelope, iv: uint8ArrayToBase64Url(ivBytes) };

    let threwExpected = false;
    try {
      await decryptMessage(tampered, key);
    } catch (err: any) {
      if (err instanceof ChatCryptoError && err.code === 'AUTH_TAG_MISMATCH') {
        threwExpected = true;
      }
    }

    if (!threwExpected) throw new Error('Modified IV was NOT rejected by authentication tag check');
    return '1-bit IV modification rejected with AUTH_TAG_MISMATCH';
  });

  // --------------------------------------------------------------------------
  // Test 8: Confirm that an incorrect key cannot decrypt the message
  // --------------------------------------------------------------------------
  await executeTest(8, 'Confirm that an incorrect key cannot decrypt the message', async () => {
    const alice = await generateChatIdentity('alice8');
    const bob = await generateChatIdentity('bob8');
    const eve = await generateChatIdentity('eve8');

    const aliceBobKey = await deriveSharedKey(alice.keyPair.privateKey, bob.exportedPublicKey);
    const eveKey = await deriveSharedKey(eve.keyPair.privateKey, bob.exportedPublicKey);

    const envelope = await encryptMessage('Confidential for Bob only', aliceBobKey);

    let threwExpected = false;
    try {
      await decryptMessage(envelope, eveKey);
    } catch (err: any) {
      if (err instanceof ChatCryptoError && err.code === 'AUTH_TAG_MISMATCH') {
        threwExpected = true;
      }
    }

    if (!threwExpected) throw new Error('Eve was able to decrypt Alice-Bob message with wrong key');
    return 'Decryption with unauthorized key failed closed with AUTH_TAG_MISMATCH';
  });

  // --------------------------------------------------------------------------
  // Test 9: Confirm that malformed or unsupported envelope versions are rejected
  // --------------------------------------------------------------------------
  await executeTest(9, 'Confirm that malformed or unsupported envelope versions are rejected', async () => {
    const identity = await generateChatIdentity('env_test');
    const key = await deriveSharedKey(identity.keyPair.privateKey, identity.exportedPublicKey);

    const validEnvelope = await encryptMessage('Test payload', key);

    // 1. Unsupported version
    let threwVersion = false;
    try {
      validateEnvelope({ ...validEnvelope, version: 99 });
    } catch (err: any) {
      if (err instanceof ChatCryptoError && err.code === 'INCOMPATIBLE_VERSION') {
        threwVersion = true;
      }
    }
    if (!threwVersion) throw new Error('Version 99 was not rejected with INCOMPATIBLE_VERSION');

    // 2. Plaintext leak
    let threwLeak = false;
    try {
      validateEnvelope({ ...validEnvelope, plaintext: 'forbidden plaintext leak' });
    } catch (err: any) {
      if (err instanceof ChatCryptoError && err.code === 'INVALID_ENVELOPE') {
        threwLeak = true;
      }
    }
    if (!threwLeak) throw new Error('Envelope with plaintext leak was not rejected');

    // 3. Serialization roundtrip
    const serialized = serializeEnvelope(validEnvelope);
    const deserialized = deserializeEnvelope(serialized);
    if (deserialized.ciphertext !== validEnvelope.ciphertext) {
      throw new Error('Serialization roundtrip failed');
    }

    return 'Version mismatches, invalid envelopes, and plaintext leaks strictly rejected';
  });

  // --------------------------------------------------------------------------
  // Test 10: Confirm that IndexedDB failures produce explicit errors and do not silently generate a replacement identity
  // --------------------------------------------------------------------------
  await executeTest(10, 'Confirm IndexedDB failures produce explicit errors and do not silently generate replacement identity', async () => {
    const corruptedId = 'corrupted_identity_case';

    // Inject a corrupted record into IndexedDB directly (missing privateKey)
    const openReq = indexedDB.open(IDB_DATABASE_NAME, IDB_SCHEMA_VERSION);
    await new Promise<void>((resolve, reject) => {
      openReq.onsuccess = () => {
        const db = openReq.result;
        const tx = db.transaction(IDB_STORE_NAME, 'readwrite');
        const store = tx.objectStore(IDB_STORE_NAME);
        store.put({
          id: corruptedId,
          version: 1,
          keyVersion: 1,
          // Intentionally omitting privateKey or providing null to simulate corruption
          privateKey: null,
          publicKey: null,
          exportedPublicKey: null,
          createdAt: Date.now(),
        });
        tx.oncomplete = () => {
          db.close();
          resolve();
        };
        tx.onerror = () => {
          db.close();
          reject(tx.error);
        };
      };
      openReq.onerror = () => reject(openReq.error);
    });

    // 1. loadChatIdentity on corrupted record MUST throw PRIVATE_KEY_MISSING
    let threwMissing = false;
    try {
      await loadChatIdentity(corruptedId);
    } catch (err: any) {
      if (err instanceof ChatCryptoError && err.code === 'PRIVATE_KEY_MISSING') {
        threwMissing = true;
      }
    }
    if (!threwMissing) {
      throw new Error('loadChatIdentity did not throw PRIVATE_KEY_MISSING for corrupted record');
    }

    // 2. initializeChatIdentity on corrupted record MUST FAIL CLOSED
    // It must NOT silently overwrite or generate a fresh replacement identity!
    let threwInit = false;
    try {
      await initializeChatIdentity(corruptedId);
    } catch (err: any) {
      if (err instanceof ChatCryptoError && err.code === 'PRIVATE_KEY_MISSING') {
        threwInit = true;
      }
    }
    if (!threwInit) {
      throw new Error('initializeChatIdentity silently replaced or bypassed corrupted identity!');
    }

    // Clean up corrupted test entry
    await deleteChatIdentity(corruptedId);

    return 'Corrupted keystore record threw PRIVATE_KEY_MISSING; failed closed without silent replacement';
  });

  // --------------------------------------------------------------------------
  // Test 11: Confirm that no private key or plaintext is written to application logs
  // --------------------------------------------------------------------------
  await executeTest(11, 'Confirm that no private key or plaintext is written to application logs', async () => {
    const interceptedLogs: string[] = [];
    const origLog = console.log;
    const origWarn = console.warn;
    const origError = console.error;

    console.log = (...args: any[]) => interceptedLogs.push(args.map(String).join(' '));
    console.warn = (...args: any[]) => interceptedLogs.push(args.map(String).join(' '));
    console.error = (...args: any[]) => interceptedLogs.push(args.map(String).join(' '));

    try {
      const topSecret = 'CRITICAL_SECRET_ESCROW_SEED_VALUE_999';
      const alice = await generateChatIdentity('audit_alice');
      const bob = await generateChatIdentity('audit_bob');

      const sharedKey = await deriveSharedKey(alice.keyPair.privateKey, bob.exportedPublicKey);
      const envelope = await encryptMessage(topSecret, sharedKey);
      const decrypted = await decryptMessage(envelope, sharedKey);

      if (decrypted !== topSecret) throw new Error('Decryption check failed');

      const allLogs = interceptedLogs.join('\n');
      if (allLogs.includes(topSecret)) {
        throw new Error('Plaintext leaked into console logs!');
      }
      if (allLogs.includes('privateKey') || allLogs.includes('CryptoKey')) {
        throw new Error('Private key or CryptoKey object reference leaked into console logs!');
      }
    } finally {
      console.log = origLog;
      console.warn = origWarn;
      console.error = origError;
    }

    return 'Zero plaintext or private key references emitted across entire encryption/decryption lifecycle';
  });

  return results;
}
