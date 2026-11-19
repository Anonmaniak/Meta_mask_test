import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  registerWalletChatKey,
  getWalletChatPublicKey,
  isWalletChatKeyRegistered,
  ChatKeyServiceError,
} from '../src/services/chatKeyService.ts';

describe('Frontend Chat Key Registration Service (chatKeyService.ts)', () => {

  it('1. Rejects invalid wallet address formats in key lookup and registration', async () => {
    await assert.rejects(
      async () => {
        await getWalletChatPublicKey('invalid-eth-address');
      },
      (err: any) => {
        assert.ok(err instanceof ChatKeyServiceError);
        assert.equal(err.code, 'INVALID_ADDRESS');
        return true;
      }
    );

    await assert.rejects(
      async () => {
        await registerWalletChatKey('not-an-address');
      },
      (err: any) => {
        assert.ok(err instanceof ChatKeyServiceError);
        assert.equal(err.code, 'INVALID_ACCOUNT');
        return true;
      }
    );
  });

  it('2. isWalletChatKeyRegistered returns false for invalid address without throwing', async () => {
    const isReg = await isWalletChatKeyRegistered('bad-address');
    assert.equal(isReg, false);
  });

  it('3. Fails cleanly when MetaMask (window.ethereum) is unavailable', async () => {
    // In Node test environment, window is undefined
    await assert.rejects(
      async () => {
        await registerWalletChatKey('0x1111111111111111111111111111111111111111');
      },
      (err: any) => {
        assert.ok(err instanceof ChatKeyServiceError);
        assert.equal(err.code, 'WALLET_NOT_FOUND');
        return true;
      }
    );
  });

  it('4. Aborts registration if wallet account switches during signing', async () => {
    // Mock window and window.ethereum
    const testAccount1 = '0x1111111111111111111111111111111111111111';
    const testAccount2 = '0x2222222222222222222222222222222222222222';

    // Mock fetch for challenge
    const origFetch = globalThis.fetch;
    const origWindow = (globalThis as any).window;

    try {
      (globalThis as any).window = {
        ethereum: {
          request: async ({ method }: { method: string; params?: any[] }) => {
            if (method === 'personal_sign') {
              return '0x' + '22'.repeat(65);
            }
            if (method === 'eth_accounts') {
              // Account switched to Account 2!
              return [testAccount2];
            }
            return [];
          },
        },
      };

      globalThis.fetch = async (url: any) => {
        if (String(url).includes('/chat/keys/challenge')) {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              challenge_id: 'mock-nonce-12345',
              address: testAccount1,
              message: 'Mock challenge message',
              expires_at: new Date(Date.now() + 300000).toISOString(),
              public_key_fingerprint: 'mock-fp-12345',
            }),
          } as any;
        }
        return { ok: false, status: 500 } as any;
      };

      const { generateChatIdentity } = await import('../src/services/chatCrypto.ts');
      const identity = await generateChatIdentity(testAccount1);

      await assert.rejects(
        async () => {
          await registerWalletChatKey(testAccount1, false, identity);
        },
        (err: any) => {
          assert.ok(err instanceof ChatKeyServiceError);
          assert.equal(err.code, 'ACCOUNT_CHANGED');
          return true;
        }
      );
    } finally {
      globalThis.fetch = origFetch;
      (globalThis as any).window = origWindow;
    }
  });

  it('5. Handles user rejection (EIP-1193 error 4001) cleanly', async () => {
    const testAccount = '0x1111111111111111111111111111111111111111';
    const origFetch = globalThis.fetch;
    const origWindow = (globalThis as any).window;

    try {
      (globalThis as any).window = {
        ethereum: {
          request: async ({ method }: { method: string }) => {
            if (method === 'personal_sign') {
              const err: any = new Error('User rejected action');
              err.code = 4001;
              throw err;
            }
            return [];
          },
        },
      };

      globalThis.fetch = async (url: any) => {
        if (String(url).includes('/chat/keys/challenge')) {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              challenge_id: 'mock-nonce',
              address: testAccount,
              message: 'Mock challenge',
              expires_at: new Date().toISOString(),
              public_key_fingerprint: 'mock-fp',
            }),
          } as any;
        }
        return { ok: false, status: 500 } as any;
      };

      const { generateChatIdentity } = await import('../src/services/chatCrypto.ts');
      const identity = await generateChatIdentity(testAccount);

      await assert.rejects(
        async () => {
          await registerWalletChatKey(testAccount, false, identity);
        },
        (err: any) => {
          assert.ok(err instanceof ChatKeyServiceError);
          assert.equal(err.code, 'SIGNATURE_REJECTED');
          return true;
        }
      );
    } finally {
      globalThis.fetch = origFetch;
      (globalThis as any).window = origWindow;
    }
  });

});
