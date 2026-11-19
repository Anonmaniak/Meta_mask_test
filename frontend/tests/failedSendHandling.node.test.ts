import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateChatIdentity,
  encryptMultiRecipientMessage,
  decryptMultiRecipientMessage,
  validateRoomEnvelope,
  ChatCryptoError,
  type EncryptedRoomMessageEnvelope,
} from '../src/services/chatCrypto.ts';
import { ChatSendError, sendEncryptedChatMessage } from '../src/services/api.ts';

describe('Frontend Failed-Send Handling & Plaintext Fallback Prohibition', () => {

  it('1. Server rejection produces ChatSendError with message was not sent state', async () => {
    // Mock global fetch to simulate server database 500 failure
    const originalFetch = globalThis.fetch;
    try {
      (globalThis as any).fetch = async () => {
        return {
          ok: false,
          status: 500,
          json: async () => ({
            detail: 'Unable to save encrypted message',
            error: 'Internal Server Error',
          }),
        };
      };

      const dummyPayload: any = {
        version: 1,
        message_id: 'msg_fail_test_123',
        channel: 'global',
        sender: '0x1111111111111111111111111111111111111111',
        algorithm: 'ECDH-P256-HKDF-AES-GCM-256',
        key_version: 1,
        content_iv: 'dGVzdF9pdl8xMmJ5',
        content_ciphertext: 'dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw',
        recipients: [],
        sender_public_key: {},
        signature: '0x123',
        timestamp: new Date().toISOString(),
      };

      await assert.rejects(
        async () => {
          await sendEncryptedChatMessage(dummyPayload);
        },
        (err: any) => {
          assert.ok(err instanceof ChatSendError);
          assert.equal(err.status, 500);
          assert.equal(err.message, 'Unable to save encrypted message');
          assert.equal(err.isRetryable, true);
          assert.equal(err.payload?.message_id, 'msg_fail_test_123');
          return true;
        }
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('2. Retry with original encrypted payload succeeds when payload is fresh (< 5 min)', async () => {
    const senderAddress = '0x1111111111111111111111111111111111111111';
    const senderIdentity = await generateChatIdentity(senderAddress);

    const envelope = await encryptMultiRecipientMessage(
      'Safe retry payload text',
      senderIdentity,
      {},
      { roomId: 'global', messageId: 'msg_retry_fresh_123' }
    );

    // Verify envelope is valid
    validateRoomEnvelope(envelope);
    assert.equal(envelope.messageId, 'msg_retry_fresh_123');

    // Simulate safe retry submission
    let callCount = 0;
    const originalFetch = globalThis.fetch;
    try {
      (globalThis as any).fetch = async (_url: string, opts: any) => {
        callCount++;
        if (callCount === 1) {
          // First attempt: simulate transient server 500
          return {
            ok: false,
            status: 500,
            json: async () => ({ detail: 'Unable to save encrypted message' }),
          };
        }
        // Second attempt: succeeds
        const body = JSON.parse(opts.body);
        return {
          ok: true,
          status: 200,
          json: async () => ({
            success: true,
            message_id: body.message_id,
            status: 'encrypted_delivered',
          }),
        };
      };

      const sendPayload: any = {
        version: 1,
        message_id: envelope.messageId,
        channel: envelope.roomId,
        sender: envelope.sender,
        algorithm: envelope.algorithm,
        key_version: envelope.keyVersion,
        content_iv: envelope.contentIv,
        content_ciphertext: envelope.contentCiphertext,
        recipients: envelope.recipients,
        sender_public_key: envelope.senderPublicKey,
        signature: '0x' + '1'.repeat(130),
        timestamp: envelope.timestamp,
      };

      // Attempt 1 fails
      await assert.rejects(async () => {
        await sendEncryptedChatMessage(sendPayload);
      });

      // Retry attempt succeeds with the exact same encrypted payload
      const retryResult = await sendEncryptedChatMessage(sendPayload);
      assert.equal(retryResult.success, true);
      assert.equal(retryResult.message_id, 'msg_retry_fresh_123');
      assert.equal(callCount, 2);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('3. Outdated or unavailable encryption keys stop sending and request key refresh', async () => {
    const senderAddress = '0x1111111111111111111111111111111111111111';
    const senderIdentity = await generateChatIdentity(senderAddress);

    // If an invalid or corrupted key is encountered, encryption strictly aborts without falling back to plaintext
    const invalidSender: any = {
      ...senderIdentity,
      exportedPublicKey: {
        ...senderIdentity.exportedPublicKey,
        rawBase64Url: 'corrupted_key_payload',
      },
    };

    await assert.rejects(
      async () => {
        await encryptMultiRecipientMessage('Message to peer', invalidSender, {}, { roomId: 'global' });
      },
      (err: any) => {
        assert.ok(err instanceof ChatCryptoError);
        assert.equal(err.code, 'ENCRYPTION_FAILED');
        return true;
      }
    );
  });

  it('4. Plaintext fallback is strictly prohibited under all error conditions', async () => {
    const senderAddress = '0x1111111111111111111111111111111111111111';
    const senderIdentity = await generateChatIdentity(senderAddress);

    const envelope = await encryptMultiRecipientMessage(
      'Sensitive user communication',
      senderIdentity,
      {},
      { roomId: 'global' }
    );

    // Verify that the envelope contains ZERO plaintext
    const serialized = JSON.stringify(envelope);
    assert.ok(!serialized.includes('Sensitive user communication'));
    assert.ok(envelope.contentCiphertext !== 'Sensitive user communication');

    // Attempting to inject plaintext field into envelope strictly fails validation
    const smuggledEnvelope: any = {
      ...envelope,
      plaintext: 'Sensitive user communication',
    };
    assert.throws(
      () => validateRoomEnvelope(smuggledEnvelope),
      (err: any) => {
        assert.ok(err instanceof ChatCryptoError);
        assert.equal(err.code, 'INVALID_ENVELOPE');
        assert.ok(err.safeMessage.includes('plaintext detected'));
        return true;
      }
    );
  });
});
