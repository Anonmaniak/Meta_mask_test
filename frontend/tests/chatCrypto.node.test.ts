import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateChatKeyPair,
  exportChatPublicKey,
  importChatPublicKey,
  deriveSharedKey,
  encryptMessage,
  decryptMessage,
  serializeEnvelope,
  deserializeEnvelope,
  validateEnvelope,
  uint8ArrayToBase64Url,
  base64UrlToUint8Array,
  ChatCryptoError,
  type EncryptedMessageEnvelope,
} from '../src/services/chatCrypto.ts';

describe('MetaMask Chat E2EE Cryptography Foundation (chatCrypto.ts)', () => {

  // --------------------------------------------------------------------------
  // Test 1: Key Generation and Public Key Export Format
  // --------------------------------------------------------------------------
  it('1. Generates P-256 ECDH keypair with non-extractable private key and exports agreed formats', async () => {
    const keyPair = await generateChatKeyPair();

    // Verify key algorithms and types
    assert.equal(keyPair.privateKey.type, 'private');
    assert.equal(keyPair.privateKey.algorithm.name, 'ECDH');
    assert.equal((keyPair.privateKey.algorithm as EcKeyAlgorithm).namedCurve, 'P-256');

    // Crucial security requirement: private key MUST NOT be extractable into JS
    assert.equal(keyPair.privateKey.extractable, false);

    assert.equal(keyPair.publicKey.type, 'public');
    assert.equal(keyPair.publicKey.algorithm.name, 'ECDH');

    // Export public key
    const exported = await exportChatPublicKey(keyPair.publicKey);

    // Verify export structure
    assert.equal(exported.version, 1);
    assert.equal(exported.curve, 'P-256');
    assert.equal(exported.format, 'raw+jwk');
    assert.ok(typeof exported.rawBase64Url === 'string' && exported.rawBase64Url.length > 0);
    assert.ok(typeof exported.fingerprint === 'string' && exported.fingerprint.length > 0);

    // Verify raw uncompressed point: 65 bytes starting with 0x04
    const rawBytes = base64UrlToUint8Array(exported.rawBase64Url);
    assert.equal(rawBytes.byteLength, 65);
    assert.equal(rawBytes[0], 0x04);

    // Verify JWK structure
    assert.equal(exported.jwk.kty, 'EC');
    assert.equal(exported.jwk.crv, 'P-256');
    assert.ok(typeof exported.jwk.x === 'string');
    assert.ok(typeof exported.jwk.y === 'string');

    // Verify public key can be re-imported from raw base64url
    const reimportedFromRaw = await importChatPublicKey(exported.rawBase64Url);
    assert.equal(reimportedFromRaw.type, 'public');
    assert.equal((reimportedFromRaw.algorithm as EcKeyAlgorithm).namedCurve, 'P-256');

    // Verify public key can be re-imported from JWK
    const reimportedFromJwk = await importChatPublicKey(exported.jwk);
    assert.equal(reimportedFromJwk.type, 'public');
  });

  // --------------------------------------------------------------------------
  // Test 2: Symmetric ECDH Shared-Secret & HKDF-SHA256 Derivation
  // --------------------------------------------------------------------------
  it('2. Derives identical AES-256-GCM symmetric key on both sides of ECDH exchange', async () => {
    const alice = await generateChatKeyPair();
    const bob = await generateChatKeyPair();

    const alicePublic = await exportChatPublicKey(alice.publicKey);
    const bobPublic = await exportChatPublicKey(bob.publicKey);

    const aliceAddress = '0x1111111111111111111111111111111111111111';
    const bobAddress = '0x2222222222222222222222222222222222222222';
    const conversationId = 'conv-metamask-alice-bob-001';

    // Alice derives key for conversation with Bob
    const aliceDerivedAesKey = await deriveSharedKey(alice.privateKey, bobPublic, {
      conversationId,
      senderAddress: aliceAddress,
      recipientAddress: bobAddress,
    });

    // Bob derives key for conversation with Alice (symmetrical participant ordering)
    const bobDerivedAesKey = await deriveSharedKey(bob.privateKey, alicePublic, {
      conversationId,
      senderAddress: bobAddress,
      recipientAddress: aliceAddress,
    });

    assert.equal(aliceDerivedAesKey.algorithm.name, 'AES-GCM');
    assert.equal((aliceDerivedAesKey.algorithm as AesKeyAlgorithm).length, 256);
    assert.equal(bobDerivedAesKey.algorithm.name, 'AES-GCM');
    assert.equal((bobDerivedAesKey.algorithm as AesKeyAlgorithm).length, 256);

    // Verify both derived keys produce cross-compatible encryption and decryption
    const testPlaintext = 'Secret handshake between Alice and Bob';
    const encryptedByAlice = await encryptMessage(testPlaintext, aliceDerivedAesKey, {
      metadata: { conversationId, sender: aliceAddress, recipient: bobAddress },
    });

    const decryptedByBob = await decryptMessage(encryptedByAlice, bobDerivedAesKey, {
      expectedConversationId: conversationId,
    });

    assert.equal(decryptedByBob, testPlaintext);

    // Reverse test: Bob encrypts, Alice decrypts
    const encryptedByBob = await encryptMessage('Reply from Bob to Alice', bobDerivedAesKey, {
      metadata: { conversationId, sender: bobAddress, recipient: aliceAddress },
    });

    const decryptedByAlice = await decryptMessage(encryptedByBob, aliceDerivedAesKey, {
      expectedConversationId: conversationId,
    });

    assert.equal(decryptedByAlice, 'Reply from Bob to Alice');
  });

  // --------------------------------------------------------------------------
  // Test 3: Domain Separation in Key Derivation
  // --------------------------------------------------------------------------
  it('3. Guarantees keys are distinct across different conversations or protocol contexts', async () => {
    const alice = await generateChatKeyPair();
    const bob = await generateChatKeyPair();

    const bobPublic = await exportChatPublicKey(bob.publicKey);

    // Key for Conversation A
    const keyConvA = await deriveSharedKey(alice.privateKey, bobPublic, {
      conversationId: 'conversation-A',
    });

    // Key for Conversation B
    const keyConvB = await deriveSharedKey(alice.privateKey, bobPublic, {
      conversationId: 'conversation-B',
    });

    const plaintext = 'Domain separation verification message';
    const envelopeA = await encryptMessage(plaintext, keyConvA);

    // Decrypting envelopeA with keyConvB must fail authentication
    await assert.rejects(
      async () => {
        await decryptMessage(envelopeA, keyConvB);
      },
      (err: any) => {
        assert.ok(err instanceof ChatCryptoError);
        assert.equal(err.code, 'AUTH_TAG_MISMATCH');
        return true;
      }
    );
  });

  // --------------------------------------------------------------------------
  // Test 4: End-to-End Encryption and Decryption Workflow
  // --------------------------------------------------------------------------
  it('4. Successfully encrypts and decrypts valid messages with UTF-8 and special characters', async () => {
    const keyPair = await generateChatKeyPair();
    const aesKey = await deriveSharedKey(keyPair.privateKey, keyPair.publicKey);

    const testMessages = [
      'Hello Web3 World!',
      '🔐 MetaMask End-to-End Encryption with Emojis 🦊🚀',
      'Multi-line message:\nLine 1: 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B\nLine 2: 0.5 ETH transferred',
      JSON.stringify({ type: 'tx_notification', hash: '0x123', amount: '1.25' }),
      'A'.repeat(5000), // Larger payload
    ];

    for (const msg of testMessages) {
      const envelope = await encryptMessage(msg, aesKey);
      const decrypted = await decryptMessage(envelope, aesKey);
      assert.equal(decrypted, msg);
    }
  });

  // --------------------------------------------------------------------------
  // Test 5: Fresh 96-bit IV on Every Operation
  // --------------------------------------------------------------------------
  it('5. Confirms that encrypting the same plaintext twice produces different IVs and ciphertexts', async () => {
    const keyPair = await generateChatKeyPair();
    const aesKey = await deriveSharedKey(keyPair.privateKey, keyPair.publicKey);

    const plaintext = 'Repeatable test message for IV uniqueness check';
    const ivs = new Set<string>();
    const ciphertexts = new Set<string>();

    const iterations = 20;
    for (let i = 0; i < iterations; i++) {
      const envelope = await encryptMessage(plaintext, aesKey);

      // Verify IV is valid 12 bytes
      const ivBytes = base64UrlToUint8Array(envelope.iv);
      assert.equal(ivBytes.byteLength, 12);

      ivs.add(envelope.iv);
      ciphertexts.add(envelope.ciphertext);

      // Decrypt to confirm validity
      const dec = await decryptMessage(envelope, aesKey);
      assert.equal(dec, plaintext);
    }

    // Every single encryption must generate a unique IV and unique ciphertext
    assert.equal(ivs.size, iterations, 'All IVs must be strictly unique');
    assert.equal(ciphertexts.size, iterations, 'All ciphertexts must be strictly unique');
  });

  // --------------------------------------------------------------------------
  // Test 6: Tampered Ciphertext Fails Authentication
  // --------------------------------------------------------------------------
  it('6. Confirms that a modified ciphertext fails AES-GCM authentication', async () => {
    const keyPair = await generateChatKeyPair();
    const aesKey = await deriveSharedKey(keyPair.privateKey, keyPair.publicKey);

    const envelope = await encryptMessage('Sensitive escrow trade instruction', aesKey);

    // Tamper with the ciphertext by flipping one bit
    const ctBytes = base64UrlToUint8Array(envelope.ciphertext);
    ctBytes[ctBytes.byteLength - 1] ^= 0x01; // flip last byte

    const tamperedEnvelope: EncryptedMessageEnvelope = {
      ...envelope,
      ciphertext: uint8ArrayToBase64Url(ctBytes),
    };

    await assert.rejects(
      async () => {
        await decryptMessage(tamperedEnvelope, aesKey);
      },
      (err: any) => {
        assert.ok(err instanceof ChatCryptoError);
        assert.equal(err.code, 'AUTH_TAG_MISMATCH');
        return true;
      }
    );
  });

  // --------------------------------------------------------------------------
  // Test 7: Tampered IV Fails Authentication
  // --------------------------------------------------------------------------
  it('7. Confirms that a modified IV fails AES-GCM authentication', async () => {
    const keyPair = await generateChatKeyPair();
    const aesKey = await deriveSharedKey(keyPair.privateKey, keyPair.publicKey);

    const envelope = await encryptMessage('Integrity verification payload', aesKey);

    // Tamper with IV by flipping one bit
    const ivBytes = base64UrlToUint8Array(envelope.iv);
    ivBytes[0] ^= 0x01;

    const tamperedEnvelope: EncryptedMessageEnvelope = {
      ...envelope,
      iv: uint8ArrayToBase64Url(ivBytes),
    };

    await assert.rejects(
      async () => {
        await decryptMessage(tamperedEnvelope, aesKey);
      },
      (err: any) => {
        assert.ok(err instanceof ChatCryptoError);
        assert.equal(err.code, 'AUTH_TAG_MISMATCH');
        return true;
      }
    );
  });

  // --------------------------------------------------------------------------
  // Test 8: Tampered AAD / Metadata Fails Authentication
  // --------------------------------------------------------------------------
  it('8. Confirms that modified Authenticated Additional Data (AAD) fails authentication', async () => {
    const keyPair = await generateChatKeyPair();
    const aesKey = await deriveSharedKey(keyPair.privateKey, keyPair.publicKey);

    const originalSender = '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const hackerSender = '0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

    const envelope = await encryptMessage('Authorized payment confirmation', aesKey, {
      metadata: { sender: originalSender, conversationId: 'conv-1' },
    });

    // An attacker attempts to forge the sender in the metadata envelope
    const forgedEnvelope: EncryptedMessageEnvelope = {
      ...envelope,
      metadata: { sender: hackerSender, conversationId: 'conv-1' },
    };

    await assert.rejects(
      async () => {
        await decryptMessage(forgedEnvelope, aesKey);
      },
      (err: any) => {
        assert.ok(err instanceof ChatCryptoError);
        assert.equal(err.code, 'AUTH_TAG_MISMATCH');
        return true;
      }
    );
  });

  // --------------------------------------------------------------------------
  // Test 9: Incorrect Key Cannot Decrypt
  // --------------------------------------------------------------------------
  it('9. Confirms that an incorrect key cannot decrypt the message', async () => {
    const alice = await generateChatKeyPair();
    const bob = await generateChatKeyPair();
    const charlie = await generateChatKeyPair();

    const aliceBobKey = await deriveSharedKey(alice.privateKey, bob.publicKey);
    const charlieKey = await deriveSharedKey(charlie.privateKey, bob.publicKey);

    const envelope = await encryptMessage('Private message from Alice to Bob', aliceBobKey);

    // Charlie tries to decrypt
    await assert.rejects(
      async () => {
        await decryptMessage(envelope, charlieKey);
      },
      (err: any) => {
        assert.ok(err instanceof ChatCryptoError);
        assert.equal(err.code, 'AUTH_TAG_MISMATCH');
        return true;
      }
    );
  });

  // --------------------------------------------------------------------------
  // Test 10: Strict Envelope Validation & Version Checks
  // --------------------------------------------------------------------------
  it('10. Confirms that malformed, invalid, or unsupported envelope versions are rejected', async () => {
    const keyPair = await generateChatKeyPair();
    const aesKey = await deriveSharedKey(keyPair.privateKey, keyPair.publicKey);

    const validEnvelope = await encryptMessage('Test payload', aesKey);

    // A. Unsupported version
    const invalidVersion = { ...validEnvelope, version: 99 };
    assert.throws(
      () => validateEnvelope(invalidVersion),
      (err: any) => {
        assert.ok(err instanceof ChatCryptoError);
        assert.equal(err.code, 'INCOMPATIBLE_VERSION');
        return true;
      }
    );

    // B. Plaintext leakage security violation
    const leakedPlaintext = { ...validEnvelope, plaintext: 'leaked text' };
    assert.throws(
      () => validateEnvelope(leakedPlaintext),
      (err: any) => {
        assert.ok(err instanceof ChatCryptoError);
        assert.equal(err.code, 'INVALID_ENVELOPE');
        return true;
      }
    );

    // C. Invalid IV length (16 bytes instead of 12)
    const badIvEnvelope: EncryptedMessageEnvelope = {
      ...validEnvelope,
      iv: uint8ArrayToBase64Url(new Uint8Array(16)),
    };
    await assert.rejects(
      async () => {
        await decryptMessage(badIvEnvelope, aesKey);
      },
      (err: any) => {
        assert.ok(err instanceof ChatCryptoError);
        assert.equal(err.code, 'INVALID_ENVELOPE');
        return true;
      }
    );

    // D. Truncated ciphertext (< 16 bytes auth tag)
    const truncatedEnvelope: EncryptedMessageEnvelope = {
      ...validEnvelope,
      ciphertext: uint8ArrayToBase64Url(new Uint8Array(8)),
    };
    await assert.rejects(
      async () => {
        await decryptMessage(truncatedEnvelope, aesKey);
      },
      (err: any) => {
        assert.ok(err instanceof ChatCryptoError);
        assert.equal(err.code, 'INVALID_ENVELOPE');
        return true;
      }
    );

    // E. Serialization and deserialization roundtrip
    const serialized = serializeEnvelope(validEnvelope);
    const deserialized = deserializeEnvelope(serialized);
    assert.deepEqual(deserialized, validEnvelope);
  });

  // --------------------------------------------------------------------------
  // Test 11: Invalid Public Key Input Handling
  // --------------------------------------------------------------------------
  it('11. Confirms that invalid public keys fail closed with typed errors', async () => {
    // Invalid curve / key input
    await assert.rejects(
      async () => {
        await importChatPublicKey('invalid-base64url-garbage');
      },
      (err: any) => {
        assert.ok(err instanceof ChatCryptoError);
        assert.equal(err.code, 'INVALID_PUBLIC_KEY');
        return true;
      }
    );

    // Invalid point length (32 bytes instead of 65)
    await assert.rejects(
      async () => {
        await importChatPublicKey(uint8ArrayToBase64Url(new Uint8Array(32)));
      },
      (err: any) => {
        assert.ok(err instanceof ChatCryptoError);
        assert.equal(err.code, 'INVALID_PUBLIC_KEY');
        return true;
      }
    );

    // Invalid JWK curve
    await assert.rejects(
      async () => {
        await importChatPublicKey({ kty: 'EC', crv: 'P-521' } as any);
      },
      (err: any) => {
        assert.ok(err instanceof ChatCryptoError);
        assert.equal(err.code, 'INVALID_PUBLIC_KEY');
        return true;
      }
    );
  });

  // --------------------------------------------------------------------------
  // Test 12: Zero Logging Verification
  // --------------------------------------------------------------------------
  it('12. Confirms that no private keys, shared secrets, or plaintext are written to logs', async () => {
    const logs: string[] = [];
    const origLog = console.log;
    const origWarn = console.warn;
    const origError = console.error;

    console.log = (...args: any[]) => logs.push(args.map(String).join(' '));
    console.warn = (...args: any[]) => logs.push(args.map(String).join(' '));
    console.error = (...args: any[]) => logs.push(args.map(String).join(' '));

    try {
      const secretSecret = 'Ultra-Confidential-Plaintext-98765';
      const alice = await generateChatKeyPair();
      const bob = await generateChatKeyPair();
      const sharedKey = await deriveSharedKey(alice.privateKey, bob.publicKey);

      const envelope = await encryptMessage(secretSecret, sharedKey);
      const decrypted = await decryptMessage(envelope, sharedKey);
      assert.equal(decrypted, secretSecret);

      // Verify nothing sensitive appears in captured logs
      const combined = logs.join('\n');
      assert.ok(!combined.includes(secretSecret), 'Plaintext MUST NOT be logged');
      assert.ok(!combined.includes('privateKey'), 'Private key references MUST NOT be logged');
      assert.ok(!combined.includes('sharedSecret'), 'Shared secrets MUST NOT be logged');
    } finally {
      console.log = origLog;
      console.warn = origWarn;
      console.error = origError;
    }
  });

});
