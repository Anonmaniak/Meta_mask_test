/**
 * Wallet-Bound Public Encryption Key Registration Service.
 * Coordinates local identity initialization, server challenge retrieval,
 * MetaMask wallet signature (EIP-191 personal_sign), and backend registration.
 */

import { initializeChatIdentity, loadChatIdentity, ChatCryptoError } from './chatCrypto.ts';
import {
  requestChatKeyChallenge,
  registerChatPublicKey,
  fetchChatPublicKey,
} from './api.ts';
import type {
  ChatKeyRegisterResponse,
  ChatKeyLookupResponse,
} from '../types';

export class ChatKeyServiceError extends Error {
  readonly code: string;
  readonly safeMessage: string;

  constructor(code: string, safeMessage: string, details?: unknown) {
    super(`[${code}] ${safeMessage}`);
    this.name = 'ChatKeyServiceError';
    this.code = code;
    this.safeMessage = safeMessage;
    if (details !== undefined && typeof details === 'object' && details !== null && 'message' in details) {
      this.cause = (details as { message: unknown }).message;
    }
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Checks whether the current browser has a registered public key on the backend
 * for the specified wallet address.
 */
export async function isWalletChatKeyRegistered(account: string): Promise<boolean> {
  if (!account || !/^0x[a-fA-F0-9]{40}$/i.test(account)) {
    return false;
  }
  try {
    const res = await fetchChatPublicKey(account);
    return Boolean(res && res.registered);
  } catch {
    return false;
  }
}

/**
 * Retrieves the registered public key metadata for a given address.
 */
export async function getWalletChatPublicKey(account: string): Promise<ChatKeyLookupResponse | null> {
  if (!account || !/^0x[a-fA-F0-9]{40}$/i.test(account)) {
    throw new ChatKeyServiceError('INVALID_ADDRESS', 'Invalid Ethereum wallet address format');
  }
  return await fetchChatPublicKey(account);
}

/**
 * Registers the active browser's chat public encryption key bound to the connected wallet.
 * 
 * Process:
 * 1. Verifies that MetaMask is connected with the expected account.
 * 2. Loads or generates the browser's local ChatIdentity (P-256 ECDH).
 * 3. Requests a server-issued challenge bound to the wallet address and public key fingerprint.
 * 4. Requests an EIP-191 personal_sign from MetaMask for the exact challenge message.
 * 5. Verifies account has not changed during signing.
 * 6. Submits the public key and signature to the backend for verification and storage.
 * 
 * Security:
 * - The private key is never transmitted or exposed to the network.
 * - The signature binds to the public key fingerprint and single-use challenge nonce.
 */
export async function registerWalletChatKey(
  account: string,
  rotate = false,
  existingIdentity?: import('./chatCrypto.ts').ChatIdentity
): Promise<ChatKeyRegisterResponse> {
  if (!account || !/^0x[a-fA-F0-9]{40}$/i.test(account)) {
    throw new ChatKeyServiceError('INVALID_ACCOUNT', 'A valid EVM wallet address is required for key registration.');
  }

  // 1. Verify MetaMask window.ethereum availability
  if (typeof window === 'undefined' || !window.ethereum) {
    throw new ChatKeyServiceError('WALLET_NOT_FOUND', 'MetaMask is not available. Please connect your wallet.');
  }

  // 2. Load or initialize local browser chat identity
  let identity;
  if (existingIdentity) {
    identity = existingIdentity;
  } else {
    try {
      identity = await initializeChatIdentity(account.toLowerCase());
    } catch (err: any) {
      if (err instanceof ChatCryptoError) {
        throw new ChatKeyServiceError(err.code, err.safeMessage, err);
      }
      throw new ChatKeyServiceError('CRYPTO_INIT_FAILED', 'Failed to initialize local chat identity.', err);
    }
  }

  const exportedPub = identity.exportedPublicKey;

  // 3. Request challenge from backend
  let challenge;
  try {
    challenge = await requestChatKeyChallenge(account, exportedPub.fingerprint);
  } catch (err: any) {
    throw new ChatKeyServiceError('CHALLENGE_FAILED', err?.message || 'Failed to obtain challenge from server.', err);
  }

  // 4. Prompt user to sign the challenge via MetaMask personal_sign
  let signature: string;
  try {
    signature = await window.ethereum.request({
      method: 'personal_sign',
      params: [challenge.message, account],
    });
  } catch (err: any) {
    if (err?.code === 4001) {
      throw new ChatKeyServiceError('SIGNATURE_REJECTED', 'User rejected the chat key registration signature request.');
    }
    throw new ChatKeyServiceError('SIGNATURE_FAILED', 'Failed to obtain wallet signature from MetaMask.', err);
  }

  // 5. Verify account has not changed during signature process
  const currentAccounts: string[] = await window.ethereum.request({ method: 'eth_accounts' }).catch(() => []);
  if (currentAccounts.length > 0 && currentAccounts[0].toLowerCase() !== account.toLowerCase()) {
    throw new ChatKeyServiceError(
      'ACCOUNT_CHANGED',
      'Wallet account changed during signing. Key registration aborted.'
    );
  }

  // 6. Submit registration to backend
  try {
    const regResult = await registerChatPublicKey({
      address: account,
      challenge_id: challenge.challenge_id,
      signature,
      public_key: {
        version: exportedPub.version,
        curve: exportedPub.curve,
        format: exportedPub.format,
        rawBase64Url: exportedPub.rawBase64Url,
        jwk: exportedPub.jwk,
        fingerprint: exportedPub.fingerprint,
      },
      key_version: 1,
      rotate,
    });

    return regResult;
  } catch (err: any) {
    throw new ChatKeyServiceError('REGISTRATION_FAILED', err?.message || 'Server rejected key registration.', err);
  }
}

/**
 * Ensures that the connected wallet has registered its local chat public key.
 * If already registered with the current local key fingerprint, returns existing info.
 * If not registered, initiates registration flow.
 */
export async function ensureWalletChatKeyRegistered(
  account: string
): Promise<{ registered: boolean; fingerprint: string }> {
  const localIdentity = await loadChatIdentity(account.toLowerCase());
  if (localIdentity) {
    const remote = await fetchChatPublicKey(account);
    if (remote && remote.registered && remote.fingerprint === localIdentity.exportedPublicKey.fingerprint) {
      return { registered: true, fingerprint: remote.fingerprint };
    }
  }

  const result = await registerWalletChatKey(account, false);
  return { registered: result.success, fingerprint: result.fingerprint };
}
