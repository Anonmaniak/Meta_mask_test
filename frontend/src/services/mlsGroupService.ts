/**
 * IETF RFC 9420 Messaging Layer Security (MLS) Group Encryption Service.
 *
 * Uses `ts-mls` (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`) to provide:
 * - TreeKEM O(log N) group key management with forward secrecy & post-compromise healing.
 * - Single-use signed `KeyPackage` generation, verification, and post-Welcome deletion.
 * - Secure member addition (`ProposalAdd` + `Commit` + `Welcome`): new members join at
 *   `epoch = E+1` and CANNOT decrypt messages sent in prior epochs `< E+1`.
 * - Secure member removal (`ProposalRemove` + `Commit`): TreeKEM path secrets are
 *   rotated so removed members CANNOT decrypt any messages in epochs `>= E+1`.
 * - Self key-rotation (`Commit` update path) & epoch authenticator verification.
 */

import { getCiphersuiteFromName, type CiphersuiteImpl } from 'ts-mls/crypto/ciphersuite.js';
import { getCiphersuiteImpl } from 'ts-mls/crypto/getCiphersuiteImpl.js';
import {
  generateKeyPackage,
  encodeKeyPackage,
  decodeKeyPackage,
  verifyKeyPackage,
  makeKeyPackageRef,
} from 'ts-mls/keyPackage.js';
import { defaultCapabilities } from 'ts-mls/defaultCapabilities.js';
import { defaultLifetime } from 'ts-mls/lifetime.js';
import {
  createGroup,
  joinGroup,
  encodeGroupState,
  decodeGroupState,
  type ClientState,
} from 'ts-mls/clientState.js';
import { defaultClientConfig } from 'ts-mls/clientConfig.js';
import { createCommit } from 'ts-mls/createCommit.js';
import { createApplicationMessage } from 'ts-mls/createMessage.js';
import { processMessage } from 'ts-mls/processMessages.js';
import { acceptAll } from 'ts-mls/incomingMessageAction.js';
import { emptyPskIndex } from 'ts-mls/pskIndex.js';
import { encodeMlsMessage, decodeMlsMessage } from 'ts-mls/message.js';
import { encodeWelcome, decodeWelcome } from 'ts-mls/welcome.js';
import { mlsExporter } from 'ts-mls/keySchedule.js';
import { getCredentialFromLeafIndex } from 'ts-mls/ratchetTree.js';
import { toLeafIndex, nodeToLeafIndex, isLeaf, toNodeIndex } from 'ts-mls/treemath.js';

import {
  base64ToBytes,
  bytesToBase64,
  saveMlsKeyPackageSecret,
  listMlsKeyPackageSecrets,
  consumeMlsKeyPackageSecret,
  saveMlsGroupVaultState,
  loadMlsGroupVaultState,
  deleteMlsGroupVaultState,
} from './e2eeVault.ts';
import type { E2EEPlaintextEnvelope } from './olmService.ts';

export const MLS_CIPHERSUITE_NAME = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519' as const;

let ciphersuitePromise: Promise<CiphersuiteImpl> | null = null;

export async function getMlsCiphersuite(): Promise<CiphersuiteImpl> {
  if (!ciphersuitePromise) {
    ciphersuitePromise = getCiphersuiteImpl(getCiphersuiteFromName(MLS_CIPHERSUITE_NAME));
  }
  return ciphersuitePromise;
}

export function encodeMlsCredentialIdentity(userId: string, deviceId: string): Uint8Array {
  return new TextEncoder().encode(`${userId}|${deviceId}`);
}

export function decodeMlsCredentialIdentity(bytes: Uint8Array): {
  userId: string;
  deviceId: string;
} {
  const str = new TextDecoder().decode(bytes);
  const idx = str.indexOf('|');
  if (idx === -1) {
    return { userId: str, deviceId: '' };
  }
  return {
    userId: str.slice(0, idx),
    deviceId: str.slice(idx + 1),
  };
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) {
    out += b.toString(16).padStart(2, '0');
  }
  return out;
}

async function persistClientState(
  userId: string,
  groupId: string,
  mlsGroupIdB64: string,
  state: ClientState
): Promise<void> {
  const encoded = encodeGroupState(state);
  await saveMlsGroupVaultState(userId, {
    groupId,
    mlsGroupIdB64,
    epoch: Number(state.groupContext.epoch),
    encodedGroupStateB64: bytesToBase64(encoded),
    updatedAt: new Date().toISOString(),
  });
}

async function restoreClientState(userId: string, groupId: string): Promise<ClientState> {
  const stored = await loadMlsGroupVaultState(userId, groupId);
  if (!stored) {
    throw new Error(`No local MLS group state found for group ${groupId}`);
  }
  const bytes = base64ToBytes(stored.encodedGroupStateB64);
  const decoded = decodeGroupState(bytes, 0);
  if (!decoded) {
    throw new Error(`Corrupted local MLS group state for group ${groupId}`);
  }
  const [groupState] = decoded;
  return {
    ...groupState,
    clientConfig: defaultClientConfig,
  };
}

/**
 * Generates a batch of single-use MLS KeyPackages for `(userId, deviceId)`,
 * storing private keys encrypted at rest in `e2eeVault.ts` and returning
 * public KeyPackages for server upload.
 */
export async function generateMlsKeyPackagesForDevice(
  userId: string,
  deviceId: string,
  count = 6
): Promise<
  Array<{
    package_id: string;
    ciphersuite: string;
    key_package_b64: string;
    key_package_ref: string;
  }>
> {
  const cs = await getMlsCiphersuite();
  const credential = {
    credentialType: 'basic' as const,
    identity: encodeMlsCredentialIdentity(userId, deviceId),
  };

  const uploads: Array<{
    package_id: string;
    ciphersuite: string;
    key_package_b64: string;
    key_package_ref: string;
  }> = [];

  for (let i = 0; i < count; i++) {
    const kp = await generateKeyPackage(
      credential,
      defaultCapabilities(),
      defaultLifetime,
      [],
      cs
    );
    const pubBytes = encodeKeyPackage(kp.publicPackage);
    const pubB64 = bytesToBase64(pubBytes);
    const refBytes = await makeKeyPackageRef(kp.publicPackage, cs.hash);
    const refHex = bytesToHex(refBytes);
    const packageId = `mkp_${refHex.slice(0, 24)}`;

    await saveMlsKeyPackageSecret(userId, {
      packageId,
      keyPackageRef: refHex,
      ciphersuite: MLS_CIPHERSUITE_NAME,
      publicPackageB64: pubB64,
      initPrivateKeyB64: bytesToBase64(kp.privatePackage.initPrivateKey),
      hpkePrivateKeyB64: bytesToBase64(kp.privatePackage.hpkePrivateKey),
      signaturePrivateKeyB64: bytesToBase64(kp.privatePackage.signaturePrivateKey),
      createdAt: new Date().toISOString(),
    });

    uploads.push({
      package_id: packageId,
      ciphersuite: MLS_CIPHERSUITE_NAME,
      key_package_b64: pubB64,
      key_package_ref: refHex,
    });
  }

  return uploads;
}

/**
 * Creates a brand-new RFC 9420 MLS group at epoch 0 on the creator's device.
 */
export async function initializeNewMlsGroupLocal(
  userId: string,
  deviceId: string
): Promise<{
  mlsGroupIdB64: string;
  finalizeWithServerGroupId: (serverGroupId: string) => Promise<void>;
}> {
  const cs = await getMlsCiphersuite();
  const rawGroupId = crypto.getRandomValues(new Uint8Array(24));
  const mlsGroupIdB64 = bytesToBase64(rawGroupId);

  const kp = await generateKeyPackage(
    {
      credentialType: 'basic',
      identity: encodeMlsCredentialIdentity(userId, deviceId),
    },
    defaultCapabilities(),
    defaultLifetime,
    [],
    cs
  );

  const initialState = await createGroup(
    rawGroupId,
    kp.publicPackage,
    kp.privatePackage,
    [],
    cs
  );

  return {
    mlsGroupIdB64,
    async finalizeWithServerGroupId(serverGroupId: string) {
      await withMlsGroupLock(`${userId}:${serverGroupId}`, async () => {
        await persistClientState(userId, serverGroupId, mlsGroupIdB64, initialState);
      });
    },
  };
}

const mlsGroupLocks = new Map<string, Promise<unknown>>();

function withMlsGroupLock<T>(lockKey: string, fn: () => Promise<T>): Promise<T> {
  const prev = mlsGroupLocks.get(lockKey) ?? Promise.resolve();
  const next = prev.catch(() => {}).then(fn);
  const cleanup = () => {
    if (mlsGroupLocks.get(lockKey) === tracked) {
      mlsGroupLocks.delete(lockKey);
    }
  };
  const tracked = next.then(cleanup, cleanup);
  mlsGroupLocks.set(lockKey, tracked);
  return next;
}

export async function clearLocalMlsGroupState(
  userId: string,
  serverGroupId: string
): Promise<void> {
  await withMlsGroupLock(`${userId}:${serverGroupId}`, async () => {
    await deleteMlsGroupVaultState(userId, serverGroupId);
  });
}

/**
 * Creates an MLS `Add` Commit + `Welcome` for claimed peer KeyPackages.
 * Verifies each KeyPackage signature and credential binding before adding.
 */
export async function buildMlsAddMembersCommit(
  committerUserId: string,
  serverGroupId: string,
  claimedKeyPackages: Array<{
    user_id: string;
    device_id: string;
    key_package_b64: string;
  }>
): Promise<{
  expectedEpoch: number;
  mlsCommitB64: string;
  mlsWelcomeB64: string;
  addedMembers: Array<{ user_id: string; device_id: string; leaf_index?: number; role: 'member' }>;
  applyLocalCommit: () => Promise<number>;
}> {
  return withMlsGroupLock(`${committerUserId}:${serverGroupId}`, async () => {
    const cs = await getMlsCiphersuite();
    const state = await restoreClientState(committerUserId, serverGroupId);
    const expectedEpoch = Number(state.groupContext.epoch);

    const addProposals = [];
    const addedMembers: Array<{
      user_id: string;
      device_id: string;
      leaf_index?: number;
      role: 'member';
    }> = [];

    for (const item of claimedKeyPackages) {
      const decodedKpRes = decodeKeyPackage(base64ToBytes(item.key_package_b64), 0);
      if (!decodedKpRes) {
        throw new Error(`Malformed MLS KeyPackage bytes for device ${item.device_id}`);
      }
      const [decodedKp] = decodedKpRes;
      const validSig = await verifyKeyPackage(decodedKp, cs.signature);
      if (!validSig) {
        throw new Error(`Invalid signature on MLS KeyPackage for device ${item.device_id}`);
      }
      if (decodedKp.leafNode.credential.credentialType === 'basic') {
        const cred = decodeMlsCredentialIdentity(decodedKp.leafNode.credential.identity);
        if (cred.userId !== item.user_id || cred.deviceId !== item.device_id) {
          throw new Error(
            `MLS KeyPackage credential mismatch: expected ${item.user_id}|${item.device_id}`
          );
        }
      }
      addProposals.push({
        proposalType: 'add' as const,
        add: { keyPackage: decodedKp },
      });
      addedMembers.push({
        user_id: item.user_id,
        device_id: item.device_id,
        role: 'member',
      });
    }

    const commitRes = await createCommit(
      { state, cipherSuite: cs },
      {
        extraProposals: addProposals,
        ratchetTreeExtension: true,
      }
    );

    if (!commitRes.welcome) {
      throw new Error('MLS Commit did not produce a Welcome message for added members');
    }

    const mlsCommitB64 = bytesToBase64(encodeMlsMessage(commitRes.commit));
    const mlsWelcomeB64 = bytesToBase64(encodeWelcome(commitRes.welcome));
    const mlsGroupIdB64 = bytesToBase64(commitRes.newState.groupContext.groupId);

    return {
      expectedEpoch,
      mlsCommitB64,
      mlsWelcomeB64,
      addedMembers,
      async applyLocalCommit() {
        return withMlsGroupLock(`${committerUserId}:${serverGroupId}`, async () => {
          await persistClientState(committerUserId, serverGroupId, mlsGroupIdB64, commitRes.newState);
          return Number(commitRes.newState.groupContext.epoch);
        });
      },
    };
  });
}

/**
 * Finds all leaf indices belonging to `targetUserId` (or a specific `targetDeviceId`)
 * in the group's RatchetTree and generates an MLS `Remove` Commit that rotates
 * TreeKEM path secrets so the removed member cannot decrypt future epochs.
 */
export async function buildMlsRemoveMemberCommit(
  committerUserId: string,
  serverGroupId: string,
  targetUserId: string,
  targetDeviceId?: string
): Promise<{
  expectedEpoch: number;
  mlsCommitB64: string;
  removedMembers: Array<{ user_id: string; device_id?: string }>;
  applyLocalCommit: () => Promise<number>;
}> {
  return withMlsGroupLock(`${committerUserId}:${serverGroupId}`, async () => {
    const cs = await getMlsCiphersuite();
    const state = await restoreClientState(committerUserId, serverGroupId);
    const expectedEpoch = Number(state.groupContext.epoch);

    const removeProposals: Array<{ proposalType: 'remove'; remove: { removed: number } }> = [];

    for (let nodeIdx = 0; nodeIdx < state.ratchetTree.length; nodeIdx++) {
      const nIdx = toNodeIndex(nodeIdx);
      if (!isLeaf(nIdx)) continue;
      const node = state.ratchetTree[nodeIdx];
      if (!node || node.nodeType !== 'leaf') continue;
      const leafIdx = nodeToLeafIndex(nIdx);
      const cred = getCredentialFromLeafIndex(state.ratchetTree, leafIdx);
      if (cred.credentialType === 'basic') {
        const parsed = decodeMlsCredentialIdentity(cred.identity);
        const matchesUser = parsed.userId === targetUserId;
        const matchesDev = !targetDeviceId || parsed.deviceId === targetDeviceId;
        if (matchesUser && matchesDev) {
          removeProposals.push({
            proposalType: 'remove',
            remove: { removed: Number(leafIdx) },
          });
        }
      }
    }

    if (removeProposals.length === 0) {
      throw new Error(`Target member ${targetUserId} not found in MLS ratchet tree`);
    }

    const commitRes = await createCommit(
      { state, cipherSuite: cs },
      {
        extraProposals: removeProposals.map((p) => ({
          proposalType: 'remove' as const,
          remove: { removed: toLeafIndex(p.remove.removed) },
        })),
        ratchetTreeExtension: true,
      }
    );

    const mlsCommitB64 = bytesToBase64(encodeMlsMessage(commitRes.commit));
    const mlsGroupIdB64 = bytesToBase64(commitRes.newState.groupContext.groupId);

    return {
      expectedEpoch,
      mlsCommitB64,
      removedMembers: [{ user_id: targetUserId, device_id: targetDeviceId }],
      async applyLocalCommit() {
        return withMlsGroupLock(`${committerUserId}:${serverGroupId}`, async () => {
          await persistClientState(committerUserId, serverGroupId, mlsGroupIdB64, commitRes.newState);
          return Number(commitRes.newState.groupContext.epoch);
        });
      },
    };
  });
}

/**
 * Rotates the member's own leaf HPKE key & TreeKEM direct path secrets (`Update` Commit)
 * for post-compromise healing.
 */
export async function buildMlsSelfKeyRotationCommit(
  committerUserId: string,
  serverGroupId: string
): Promise<{
  expectedEpoch: number;
  mlsCommitB64: string;
  applyLocalCommit: () => Promise<number>;
}> {
  return withMlsGroupLock(`${committerUserId}:${serverGroupId}`, async () => {
    const cs = await getMlsCiphersuite();
    const state = await restoreClientState(committerUserId, serverGroupId);
    const expectedEpoch = Number(state.groupContext.epoch);

    const commitRes = await createCommit(
      { state, cipherSuite: cs },
      {
        extraProposals: [],
        ratchetTreeExtension: true,
      }
    );

    const mlsCommitB64 = bytesToBase64(encodeMlsMessage(commitRes.commit));
    const mlsGroupIdB64 = bytesToBase64(commitRes.newState.groupContext.groupId);

    return {
      expectedEpoch,
      mlsCommitB64,
      async applyLocalCommit() {
        return withMlsGroupLock(`${committerUserId}:${serverGroupId}`, async () => {
          await persistClientState(committerUserId, serverGroupId, mlsGroupIdB64, commitRes.newState);
          return Number(commitRes.newState.groupContext.epoch);
        });
      },
    };
  });
}

/**
 * Joins an encrypted MLS group from a server-delivered `Welcome` message, matching
 * against local encrypted `PrivateKeyPackage`s and immediately deleting the consumed
 * `PrivateKeyPackage` for forward secrecy.
 */
export async function joinMlsGroupFromWelcomeB64(
  userId: string,
  serverGroupId: string,
  welcomeB64: string
): Promise<{ epoch: number; mlsGroupIdB64: string }> {
  return withMlsGroupLock(`${userId}:${serverGroupId}`, async () => {
    const cs = await getMlsCiphersuite();
    const decodedWelcomeRes = decodeWelcome(base64ToBytes(welcomeB64), 0);
    if (!decodedWelcomeRes) {
      throw new Error('Malformed MLS Welcome message bytes');
    }
    const [welcome] = decodedWelcomeRes;
    const storedSecrets = await listMlsKeyPackageSecrets(userId);

    for (const sec of storedSecrets) {
      const decodedPubRes = decodeKeyPackage(base64ToBytes(sec.publicPackageB64), 0);
      if (!decodedPubRes) continue;
      const [pubPkg] = decodedPubRes;
      const privPkg = {
        initPrivateKey: base64ToBytes(sec.initPrivateKeyB64),
        hpkePrivateKey: base64ToBytes(sec.hpkePrivateKeyB64),
        signaturePrivateKey: base64ToBytes(sec.signaturePrivateKeyB64),
      };
      try {
        const joinedState = await joinGroup(welcome, pubPkg, privPkg, emptyPskIndex, cs);
        const mlsGroupIdB64 = bytesToBase64(joinedState.groupContext.groupId);
        await persistClientState(userId, serverGroupId, mlsGroupIdB64, joinedState);
        await consumeMlsKeyPackageSecret(userId, sec.keyPackageRef);
        return {
          epoch: Number(joinedState.groupContext.epoch),
          mlsGroupIdB64,
        };
      } catch {
        // Not the KeyPackage targeted by this Welcome; try next stored KeyPackage
      } finally {
        privPkg.initPrivateKey.fill(0);
        privPkg.hpkePrivateKey.fill(0);
        privPkg.signaturePrivateKey.fill(0);
      }
    }

    // Idempotent recovery: if Welcome was already imported locally prior to server ACK
    try {
      const existingState = await restoreClientState(userId, serverGroupId);
      return {
        epoch: Number(existingState.groupContext.epoch),
        mlsGroupIdB64: bytesToBase64(existingState.groupContext.groupId),
      };
    } catch {
      // Fall through to explicit error
    }

    throw new Error('Unable to join MLS group: no matching local KeyPackage secret found for Welcome');
  });
}

/**
 * Applies ordered MLS Commit messages so an online or returning-offline member
 * advances cleanly to the group's latest epoch.
 */
export async function processIncomingMlsCommits(
  userId: string,
  serverGroupId: string,
  commits: Array<{ epoch: number; mls_commit_b64: string }>
): Promise<{ epoch: number; selfRemoved: boolean }> {
  return withMlsGroupLock(`${userId}:${serverGroupId}`, async () => {
    const cs = await getMlsCiphersuite();
    let state: ClientState;
    try {
      state = await restoreClientState(userId, serverGroupId);
    } catch {
      return { epoch: 0, selfRemoved: false };
    }

    const sorted = [...commits].sort((a, b) => a.epoch - b.epoch);
    let selfRemoved = false;

    for (const c of sorted) {
      const currentEpoch = Number(state.groupContext.epoch);
      // Commit at server `epoch = E+1` was created in `currentEpoch = E`
      if (c.epoch <= currentEpoch) {
        continue;
      }
      const decodedMsgRes = decodeMlsMessage(base64ToBytes(c.mls_commit_b64), 0);
      if (!decodedMsgRes) {
        throw new Error(`Malformed MLS Commit message at epoch ${c.epoch}`);
      }
      const [decodedMsg] = decodedMsgRes;
      if (
        decodedMsg.wireformat !== 'mls_private_message' &&
        decodedMsg.wireformat !== 'mls_public_message'
      ) {
        throw new Error(`Unexpected MLS wireformat '${decodedMsg.wireformat}' for Commit`);
      }
      const res = await processMessage(decodedMsg, state, emptyPskIndex, acceptAll, cs);
      if (res.kind === 'newState') {
        state = res.newState;
        if (state.groupActiveState.kind === 'removedFromGroup') {
          selfRemoved = true;
          await deleteMlsGroupVaultState(userId, serverGroupId);
          return { epoch: Number(state.groupContext.epoch), selfRemoved: true };
        }
        await persistClientState(
          userId,
          serverGroupId,
          bytesToBase64(state.groupContext.groupId),
          state
        );
      }
    }

    return { epoch: Number(state.groupContext.epoch), selfRemoved };
  });
}

/**
 * Encrypts an application message into an MLS RFC 9420 `PrivateMessage`.
 */
export async function encryptMlsGroupMessage(
  userId: string,
  serverGroupId: string,
  envelope: E2EEPlaintextEnvelope
): Promise<{ epoch: number; mlsCiphertextB64: string }> {
  return withMlsGroupLock(`${userId}:${serverGroupId}`, async () => {
    const cs = await getMlsCiphersuite();
    const state = await restoreClientState(userId, serverGroupId);
    const epoch = Number(state.groupContext.epoch);
    const plainBytes = new TextEncoder().encode(JSON.stringify(envelope));

    const appRes = await createApplicationMessage(state, plainBytes, cs);
    plainBytes.fill(0);

    const wireBytes = encodeMlsMessage({
      version: 'mls10',
      wireformat: 'mls_private_message',
      privateMessage: appRes.privateMessage,
    });

    await persistClientState(
      userId,
      serverGroupId,
      bytesToBase64(appRes.newState.groupContext.groupId),
      appRes.newState
    );

    return {
      epoch,
      mlsCiphertextB64: bytesToBase64(wireBytes),
    };
  });
}

/**
 * Decrypts an MLS RFC 9420 `PrivateMessage` and advances the sender secret tree ratchet.
 */
export async function decryptMlsGroupMessage(
  userId: string,
  serverGroupId: string,
  mlsCiphertextB64: string
): Promise<E2EEPlaintextEnvelope> {
  return withMlsGroupLock(`${userId}:${serverGroupId}`, async () => {
    const cs = await getMlsCiphersuite();
    const state = await restoreClientState(userId, serverGroupId);
    const decodedMsgRes = decodeMlsMessage(base64ToBytes(mlsCiphertextB64), 0);
    if (!decodedMsgRes) {
      throw new Error('Malformed MLS PrivateMessage wire bytes');
    }
    const [decodedMsg] = decodedMsgRes;
    if (decodedMsg.wireformat !== 'mls_private_message') {
      throw new Error('Downgrade rejected: MLS application messages must use mls_private_message');
    }

    const res = await processMessage(decodedMsg, state, emptyPskIndex, acceptAll, cs);
    if (res.kind !== 'applicationMessage') {
      throw new Error('Expected MLS applicationMessage payload');
    }

    await persistClientState(
      userId,
      serverGroupId,
      bytesToBase64(res.newState.groupContext.groupId),
      res.newState
    );

    const decodedText = new TextDecoder().decode(res.message);
    return JSON.parse(decodedText) as E2EEPlaintextEnvelope;
  });
}

/**
 * Exports the RFC 9420 Epoch Authenticator fingerprint and local epoch number so
 * group participants can verify cryptographic state equivalence.
 */
export async function getMlsGroupSecurityInfo(
  userId: string,
  serverGroupId: string
): Promise<{
  epoch: number;
  epochAuthenticatorHex: string;
  exportedContextVerifyCode: string;
} | null> {
  const stored = await loadMlsGroupVaultState(userId, serverGroupId);
  if (!stored) return null;
  const cs = await getMlsCiphersuite();
  const state = await restoreClientState(userId, serverGroupId);
  const authHex = bytesToHex(state.keySchedule.epochAuthenticator);
  const exported = await mlsExporter(
    state.keySchedule.exporterSecret,
    'zyphra-mls-group-verify-v1',
    new Uint8Array(0),
    16,
    cs
  );
  return {
    epoch: Number(state.groupContext.epoch),
    epochAuthenticatorHex: authHex,
    exportedContextVerifyCode: bytesToHex(exported).toUpperCase().match(/.{1,4}/g)?.join('-') || '',
  };
}
