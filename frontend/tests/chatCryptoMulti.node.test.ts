/**
 * Node test suite for Multi-Recipient Room Message Encryption / Decryption.
 * Verifies key encapsulation, pairwise secret derivation, and fail-closed security.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  generateChatIdentity,
  encryptMultiRecipientMessage,
  decryptMultiRecipientMessage,
  validateRoomEnvelope,
  buildCanonicalEnvelopeHash,
  canonicalJsonStringify,
  createSignedRoomMessageEnvelope,
  ChatCryptoError,
} from '../src/services/chatCrypto.ts';

describe('Multi-Recipient Room E2EE (chatCrypto.ts)', () => {
  test('1. Sender can encrypt and decrypt their own message in a room', async () => {
    const senderIdentity = await generateChatIdentity('0x1111111111111111111111111111111111111111');
    const plaintext = 'Hello to Global Chat E2EE!';

    // Encrypt for sender only (e.g. empty peer list)
    const envelope = await encryptMultiRecipientMessage(
      plaintext,
      senderIdentity,
      {},
      { roomId: 'global' }
    );

    assert.equal(envelope.version, 1);
    assert.equal(envelope.roomId, 'global');
    assert.equal(envelope.sender, '0x1111111111111111111111111111111111111111');
    assert.ok(envelope.contentCiphertext.length > 0);
    assert.ok(envelope.contentIv.length > 0);
    assert.equal(envelope.recipients.length, 1);
    assert.equal(envelope.recipients[0].recipient, '0x1111111111111111111111111111111111111111');

    // Decrypt
    const decrypted = await decryptMultiRecipientMessage(
      envelope,
      '0x1111111111111111111111111111111111111111',
      senderIdentity.keyPair.privateKey
    );

    assert.equal(decrypted, plaintext);
  });

  test('2. Two authorized recipients can independently decrypt their respective payloads', async () => {
    const sender = await generateChatIdentity('0x1111111111111111111111111111111111111111');
    const recipientA = await generateChatIdentity('0x2222222222222222222222222222222222222222');
    const recipientB = await generateChatIdentity('0x3333333333333333333333333333333333333333');

    const plaintext = 'Secret global transmission for Alice and Bob';

    const envelope = await encryptMultiRecipientMessage(
      plaintext,
      sender,
      {
        '0x2222222222222222222222222222222222222222': recipientA.exportedPublicKey,
        '0x3333333333333333333333333333333333333333': recipientB.exportedPublicKey,
      },
      { roomId: 'global' }
    );

    // Should contain 3 wrappers: sender + recipientA + recipientB
    assert.equal(envelope.recipients.length, 3);

    // Recipient A decrypts
    const decryptedA = await decryptMultiRecipientMessage(
      envelope,
      '0x2222222222222222222222222222222222222222',
      recipientA.keyPair.privateKey
    );
    assert.equal(decryptedA, plaintext);

    // Recipient B decrypts
    const decryptedB = await decryptMultiRecipientMessage(
      envelope,
      '0x3333333333333333333333333333333333333333',
      recipientB.keyPair.privateKey
    );
    assert.equal(decryptedB, plaintext);

    // Sender also decrypts
    const decryptedSender = await decryptMultiRecipientMessage(
      envelope,
      '0x1111111111111111111111111111111111111111',
      sender.keyPair.privateKey
    );
    assert.equal(decryptedSender, plaintext);
  });

  test('3. Non-recipient cannot decrypt the message (fails closed)', async () => {
    const sender = await generateChatIdentity('0x1111111111111111111111111111111111111111');
    const recipientA = await generateChatIdentity('0x2222222222222222222222222222222222222222');
    const eve = await generateChatIdentity('0x9999999999999999999999999999999999999999');

    const envelope = await encryptMultiRecipientMessage(
      'Classified Room Data',
      sender,
      {
        '0x2222222222222222222222222222222222222222': recipientA.exportedPublicKey,
      },
      { roomId: 'global' }
    );

    await assert.rejects(
      async () => {
        await decryptMultiRecipientMessage(
          envelope,
          '0x9999999999999999999999999999999999999999',
          eve.keyPair.privateKey
        );
      },
      (err: any) => {
        assert.ok(err instanceof ChatCryptoError);
        assert.equal(err.code, 'DECRYPTION_FAILED');
        return true;
      }
    );
  });

  test('4. Tampered content ciphertext fails authentication tag check', async () => {
    const sender = await generateChatIdentity('0x1111111111111111111111111111111111111111');
    const recipientA = await generateChatIdentity('0x2222222222222222222222222222222222222222');

    const envelope = await encryptMultiRecipientMessage(
      'Original Plaintext',
      sender,
      {
        '0x2222222222222222222222222222222222222222': recipientA.exportedPublicKey,
      },
      { roomId: 'global' }
    );

    // Tamper with the ciphertext by flipping characters
    const tampered = { ...envelope };
    const chars = tampered.contentCiphertext.split('');
    chars[0] = chars[0] === 'A' ? 'B' : 'A';
    tampered.contentCiphertext = chars.join('');

    await assert.rejects(
      async () => {
        await decryptMultiRecipientMessage(
          tampered,
          '0x2222222222222222222222222222222222222222',
          recipientA.keyPair.privateKey
        );
      },
      (err: any) => {
        assert.ok(err instanceof ChatCryptoError);
        assert.equal(err.code, 'AUTH_TAG_MISMATCH');
        return true;
      }
    );
  });

  test('5. Tampered metadata / AAD fails decryption', async () => {
    const sender = await generateChatIdentity('0x1111111111111111111111111111111111111111');
    const recipientA = await generateChatIdentity('0x2222222222222222222222222222222222222222');

    const envelope = await encryptMultiRecipientMessage(
      'Original Message',
      sender,
      {
        '0x2222222222222222222222222222222222222222': recipientA.exportedPublicKey,
      },
      { roomId: 'global' }
    );

    // Tamper with sender address in envelope metadata
    const tampered = {
      ...envelope,
      sender: '0x8888888888888888888888888888888888888888',
    };

    await assert.rejects(
      async () => {
        await decryptMultiRecipientMessage(
          tampered,
          '0x2222222222222222222222222222222222222222',
          recipientA.keyPair.privateKey
        );
      },
      (err: any) => {
        assert.ok(err instanceof ChatCryptoError);
        assert.equal(err.code, 'AUTH_TAG_MISMATCH');
        return true;
      }
    );
  });

  test('6. Plaintext field inside envelope fails strict validation', () => {
    const badEnvelope = {
      version: 1,
      messageId: 'msg_123',
      roomId: 'global',
      sender: '0x1111111111111111111111111111111111111111',
      algorithm: 'ECDH-P256-HKDF-AES-GCM-256',
      keyVersion: 1,
      contentIv: 'test',
      contentCiphertext: 'test',
      recipients: [{ recipient: '0x1', keyFingerprint: 'x', iv: 'y', wrappedKey: 'z' }],
      message: 'LEAKED PLAINTEXT',
      timestamp: new Date().toISOString(),
    };

    assert.throws(
      () => validateRoomEnvelope(badEnvelope),
      (err: any) => {
        assert.ok(err instanceof ChatCryptoError);
        assert.equal(err.code, 'INVALID_ENVELOPE');
        return true;
      }
    );
  });

  test('7. Canonical envelope hash is deterministic and cryptographically binds all envelope fields', async () => {
    assert.equal(canonicalJsonStringify({ b: 2, a: 1 }), '{"a":1,"b":2}');

    const envelope = {
      messageId: 'msg_test_det_1',
      roomId: 'global',
      sender: '0x1111111111111111111111111111111111111111',
      algorithm: 'ECDH-P256-HKDF-AES-GCM-256',
      keyVersion: 1,
      contentIv: 'dGVzdF9pdl8xMmJ5dGVz',
      contentCiphertext: 'dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw',
      recipients: [
        {
          recipient: '0x1111111111111111111111111111111111111111',
          keyFingerprint: 'fp_abc',
          iv: 'iv_1',
          wrappedKey: 'key_1',
        },
      ],
      timestamp: '2026-11-10T00:00:00.000Z',
      version: 1,
    };

    const res1 = await buildCanonicalEnvelopeHash(envelope);
    const res2 = await buildCanonicalEnvelopeHash(envelope);

    assert.equal(res1.envelopeHash, res2.envelopeHash);
    assert.equal(res1.canonicalJson, res2.canonicalJson);
    assert.ok(res1.signMessage.includes(`Envelope Hash: ${res1.envelopeHash}`));
    assert.ok(res1.signMessage.includes(`Message ID: msg_test_det_1`));
  });

  test('8. Recipient order invariance: different recipient array ordering produces identical canonical hash', async () => {
    const rAlice = {
      recipient: '0x1111111111111111111111111111111111111111',
      keyFingerprint: 'fp_alice',
      iv: 'iv_alice',
      wrappedKey: 'key_alice',
    };
    const rBob = {
      recipient: '0x2222222222222222222222222222222222222222',
      keyFingerprint: 'fp_bob',
      iv: 'iv_bob',
      wrappedKey: 'key_bob',
    };

    const envOrderA = {
      messageId: 'msg_order_test',
      roomId: 'global',
      sender: '0x1111111111111111111111111111111111111111',
      contentIv: 'iv_common',
      contentCiphertext: 'ct_common',
      recipients: [rAlice, rBob],
      timestamp: '2026-11-10T00:00:00.000Z',
    };

    const envOrderB = {
      ...envOrderA,
      recipients: [rBob, rAlice], // Swapped order!
    };

    const hashA = await buildCanonicalEnvelopeHash(envOrderA);
    const hashB = await buildCanonicalEnvelopeHash(envOrderB);

    assert.equal(hashA.envelopeHash, hashB.envelopeHash);
    assert.equal(hashA.canonicalJson, hashB.canonicalJson);
  });

  test('9. Duplicate recipients are strictly rejected by canonical builder', async () => {
    const dupEnvelope = {
      messageId: 'msg_dup_test',
      roomId: 'global',
      sender: '0x1111111111111111111111111111111111111111',
      contentIv: 'iv_common',
      contentCiphertext: 'ct_common',
      recipients: [
        {
          recipient: '0x1111111111111111111111111111111111111111',
          keyFingerprint: 'fp1',
          iv: 'iv1',
          wrappedKey: 'k1',
        },
        {
          recipient: '0x1111111111111111111111111111111111111111', // Duplicate!
          keyFingerprint: 'fp2',
          iv: 'iv2',
          wrappedKey: 'k2',
        },
      ],
      timestamp: '2026-11-10T00:00:00.000Z',
    };

    await assert.rejects(
      async () => {
        await buildCanonicalEnvelopeHash(dupEnvelope);
      },
      (err: any) => {
        assert.ok(err instanceof ChatCryptoError);
        assert.equal(err.code, 'INVALID_ENVELOPE');
        assert.ok(err.message.includes('Duplicate recipient'));
        return true;
      }
    );
  });

  test('10. Tampering with ciphertext, IV, or recipient wrappers alters envelope hash', async () => {
    const baseEnvelope = {
      messageId: 'msg_tamper_check',
      roomId: 'global',
      sender: '0x1111111111111111111111111111111111111111',
      contentIv: 'iv_original',
      contentCiphertext: 'ct_original',
      recipients: [
        {
          recipient: '0x1111111111111111111111111111111111111111',
          keyFingerprint: 'fp1',
          iv: 'iv1',
          wrappedKey: 'k1',
        },
      ],
      timestamp: '2026-11-10T00:00:00.000Z',
    };

    const baseResult = await buildCanonicalEnvelopeHash(baseEnvelope);

    // Tamper ciphertext
    const tamperedCt = await buildCanonicalEnvelopeHash({
      ...baseEnvelope,
      contentCiphertext: 'ct_tampered',
    });
    assert.notEqual(baseResult.envelopeHash, tamperedCt.envelopeHash);

    // Tamper IV
    const tamperedIv = await buildCanonicalEnvelopeHash({
      ...baseEnvelope,
      contentIv: 'iv_tampered',
    });
    assert.notEqual(baseResult.envelopeHash, tamperedIv.envelopeHash);

    // Tamper recipient wrapper
    const tamperedWrap = await buildCanonicalEnvelopeHash({
      ...baseEnvelope,
      recipients: [
        {
          recipient: '0x1111111111111111111111111111111111111111',
          keyFingerprint: 'fp1',
          iv: 'iv1',
          wrappedKey: 'k_tampered',
        },
      ],
    });
    assert.notEqual(baseResult.envelopeHash, tamperedWrap.envelopeHash);
  });

  test('11. createSignedRoomMessageEnvelope attaches valid signature binding canonical hash', async () => {
    const senderIdentity = await generateChatIdentity('0x1111111111111111111111111111111111111111');
    const envelope = await encryptMultiRecipientMessage(
      'Signed Room Message Payload',
      senderIdentity,
      {},
      { roomId: 'global' }
    );

    let recordedSignMessage = '';
    const signed = await createSignedRoomMessageEnvelope(envelope, async (msg) => {
      recordedSignMessage = msg;
      return '0x' + 'bb'.repeat(65);
    });

    assert.ok(signed.signature);
    assert.equal(signed.signature, '0x' + 'bb'.repeat(65));
    assert.ok(recordedSignMessage.includes('Envelope Hash:'));
    assert.ok(recordedSignMessage.includes('zyphra.in Chat Message'));
  });
});
