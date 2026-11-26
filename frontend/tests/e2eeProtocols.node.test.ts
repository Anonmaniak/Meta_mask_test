import test from 'node:test';
import assert from 'node:assert/strict';

import {
  putVaultRecord,
  getVaultRecord,
  listRawEncryptedVaultRowsForAudit,
  wipeUserDeviceVault,
  listMlsKeyPackageSecrets,
  loadMlsGroupVaultState,
  saveMlsGroupVaultState,
} from '../src/services/e2eeVault.ts';

import {
  getOrCreateLocalOlmDevice,
  markLocalPrekeysPublished,
  generateMoreOlmPrekeys,
  encryptOlmMultiDevicePayload,
  decryptOlmDeviceCiphertext,
  resetOlmSessionWithPeerDevice,
  computeSafetyNumber,
  evaluateAndRecordPeerTrust,
  markPeerDevicesVerified,
  type ClaimedPeerPrekeyBundle,
  type PeerActiveDeviceDescriptor,
} from '../src/services/olmService.ts';

import {
  generateMlsKeyPackagesForDevice,
  initializeNewMlsGroupLocal,
  buildMlsAddMembersCommit,
  buildMlsRemoveMemberCommit,
  buildMlsSelfKeyRotationCommit,
  joinMlsGroupFromWelcomeB64,
  processIncomingMlsCommits,
  encryptMlsGroupMessage,
  decryptMlsGroupMessage,
  getMlsGroupSecurityInfo,
} from '../src/services/mlsGroupService.ts';

import {
  encryptAttachmentOnDevice,
  decryptAttachmentOnDevice,
} from '../src/services/e2eeAttachmentCrypto.ts';

test('Encrypted At-Rest Vault wraps records with non-extractable AES-256-GCM and leaks zero plaintext', async () => {
  const secretCanary = 'ULTRA_SENSITIVE_PICKLE_CANARY_998877';
  await putVaultRecord('test:canary_record', {
    secret: secretCanary,
    nested: { keyMaterial: 'PRIVATE_CURVE25519_SCALAR_DATA' },
  });

  const rawRows = await listRawEncryptedVaultRowsForAudit();
  const canaryRow = rawRows.find((r) => r.id === 'test:canary_record');
  assert.ok(canaryRow, 'Encrypted vault row should exist');
  assert.ok(canaryRow.ivB64.length >= 16);
  assert.ok(canaryRow.ciphertextB64.length >= 32);

  const serializedRow = JSON.stringify(canaryRow);
  assert.equal(
    serializedRow.includes(secretCanary),
    false,
    'Raw vault storage MUST NOT contain plaintext canary'
  );
  assert.equal(
    serializedRow.includes('PRIVATE_CURVE25519_SCALAR_DATA'),
    false,
    'Raw vault storage MUST NOT contain nested key material'
  );

  const decrypted = await getVaultRecord<{ secret: string; nested: { keyMaterial: string } }>(
    'test:canary_record'
  );
  assert.ok(decrypted);
  assert.equal(decrypted.secret, secretCanary);
  assert.equal(decrypted.nested.keyMaterial, 'PRIVATE_CURVE25519_SCALAR_DATA');
});

test('Olm v2 (Vodozemac) 3DH + Double Ratchet multi-device E2EE, replay rejection & Safety Numbers', async () => {
  const aliceUserId = 'usr_alice_permanent_01';
  const aliceSiblingVaultId = 'usr_alice_permanent_01__tablet';
  const bobUserId = 'usr_bob_permanent_02';

  const aliceDev1 = await getOrCreateLocalOlmDevice(aliceUserId, 'Alice Laptop');
  const aliceDev2 = await getOrCreateLocalOlmDevice(aliceSiblingVaultId, 'Alice Tablet');
  const bobDev1 = await getOrCreateLocalOlmDevice(bobUserId, 'Bob Phone');

  assert.equal(aliceDev1.isNewDevice, true);
  assert.equal(bobDev1.isNewDevice, true);
  assert.notEqual(aliceDev1.record.curve25519Key, bobDev1.record.curve25519Key);
  assert.notEqual(aliceDev1.record.ed25519Key, bobDev1.record.ed25519Key);

  // Verify idempotent reload from encrypted vault preserves permanent device identity
  const aliceReloaded = await getOrCreateLocalOlmDevice(aliceUserId, 'Alice Laptop');
  assert.equal(aliceReloaded.isNewDevice, false);
  assert.equal(aliceReloaded.record.deviceId, aliceDev1.record.deviceId);
  assert.equal(aliceReloaded.record.ed25519Key, aliceDev1.record.ed25519Key);

  await markLocalPrekeysPublished(aliceUserId);
  await markLocalPrekeysPublished(aliceSiblingVaultId);
  await markLocalPrekeysPublished(bobUserId);

  // Build in-memory prekey directory simulating server public key bundles
  const otkPools = new Map<string, Array<[string, string]>>([
    [aliceDev1.record.deviceId, Object.entries(aliceDev1.registrationBundle.one_time_keys)],
    [aliceDev2.record.deviceId, Object.entries(aliceDev2.registrationBundle.one_time_keys)],
    [bobDev1.record.deviceId, Object.entries(bobDev1.registrationBundle.one_time_keys)],
  ]);

  const bundleMap = new Map([
    [aliceDev1.record.deviceId, { uid: aliceUserId, b: aliceDev1.registrationBundle }],
    [aliceDev2.record.deviceId, { uid: aliceUserId, b: aliceDev2.registrationBundle }],
    [bobDev1.record.deviceId, { uid: bobUserId, b: bobDev1.registrationBundle }],
  ]);

  const claimPrekeys = async (_targetUid: string, deviceIds: string[]): Promise<ClaimedPeerPrekeyBundle[]> => {
    return deviceIds.map((did) => {
      const entry = bundleMap.get(did);
      assert.ok(entry, `Unknown device ${did}`);
      const pool = otkPools.get(did) || [];
      const otk = pool.shift();
      const [prekeyId, prekeyPublic] = otk
        ? otk
        : [entry.b.fallback_key_id!, entry.b.fallback_public_key!];
      return {
        device_id: did,
        user_id: entry.uid,
        ed25519_identity_key: entry.b.ed25519_identity_key,
        curve25519_identity_key: entry.b.curve25519_identity_key,
        prekey_id: prekeyId,
        prekey_public: prekeyPublic,
        is_fallback: !otk,
        bundle_signature: entry.b.bundle_signature,
      };
    });
  };

  const targetDevicesForAliceSend: PeerActiveDeviceDescriptor[] = [
    {
      device_id: aliceDev1.record.deviceId,
      user_id: aliceUserId,
      device_label: 'Alice Laptop',
      ed25519_identity_key: aliceDev1.record.ed25519Key,
      curve25519_identity_key: aliceDev1.record.curve25519Key,
      status: 'active',
    },
    {
      device_id: aliceDev2.record.deviceId,
      user_id: aliceUserId,
      device_label: 'Alice Tablet',
      ed25519_identity_key: aliceDev2.record.ed25519Key,
      curve25519_identity_key: aliceDev2.record.curve25519Key,
      status: 'active',
    },
    {
      device_id: bobDev1.record.deviceId,
      user_id: bobUserId,
      device_label: 'Bob Phone',
      ed25519_identity_key: bobDev1.record.ed25519Key,
      curve25519_identity_key: bobDev1.record.curve25519Key,
      status: 'active',
    },
  ];

  // 1. Key substitution attack during prekey claim MUST be rejected
  await assert.rejects(
    () =>
      encryptOlmMultiDevicePayload(
        aliceUserId,
        { v: 1, text: 'Should never encrypt under substituted key', sent_at: new Date().toISOString() },
        [targetDevicesForAliceSend[2]],
        async () => [
          {
            device_id: bobDev1.record.deviceId,
            user_id: bobUserId,
            ed25519_identity_key: bobDev1.record.ed25519Key,
            curve25519_identity_key: aliceDev2.record.curve25519Key, // Substituted Curve25519 key!
            prekey_id: 'forged_otk',
            prekey_public: aliceDev2.record.curve25519Key,
            is_fallback: false,
            bundle_signature: 'forged',
          },
        ]
      ),
    /Prekey bundle key substitution detected/
  );

  // 2. Legitimate multi-device Olm v2 encryption
  const secretDm1 = 'Confidential wire transfer details: alpha-bravo-7741';
  const encrypted1 = await encryptOlmMultiDevicePayload(
    aliceUserId,
    { v: 1, text: secretDm1, sent_at: '2026-10-30T01:00:00.000Z' },
    targetDevicesForAliceSend,
    claimPrekeys
  );

  assert.ok(encrypted1.deviceCiphertexts[bobDev1.record.deviceId]);
  assert.ok(encrypted1.deviceCiphertexts[aliceDev2.record.deviceId]);
  assert.ok(encrypted1.deviceCiphertexts[aliceDev1.record.deviceId]);
  assert.notEqual(
    encrypted1.deviceCiphertexts[bobDev1.record.deviceId].ciphertext_b64,
    encrypted1.deviceCiphertexts[aliceDev2.record.deviceId].ciphertext_b64,
    'Each device MUST receive an independent Olm ratchet ciphertext'
  );
  assert.equal(
    JSON.stringify(encrypted1).includes(secretDm1),
    false,
    'Ciphertext bundle MUST NOT contain plaintext'
  );

  // 3. Decrypt on Bob Phone, Alice Tablet, and Alice Laptop self-ratchet
  const bobCt1 = encrypted1.deviceCiphertexts[bobDev1.record.deviceId];
  assert.equal(bobCt1.message_type, 0, 'Initial 3DH message must be Olm PreKey type 0');

  const bobDec1 = await decryptOlmDeviceCiphertext(
    bobUserId,
    aliceDev1.record.curve25519Key,
    bobCt1.message_type,
    bobCt1.ciphertext_b64
  );
  assert.equal(bobDec1.text, secretDm1);

  const aliceTabCt1 = encrypted1.deviceCiphertexts[aliceDev2.record.deviceId];
  const aliceTabDec1 = await decryptOlmDeviceCiphertext(
    aliceSiblingVaultId,
    aliceDev1.record.curve25519Key,
    aliceTabCt1.message_type,
    aliceTabCt1.ciphertext_b64
  );
  assert.equal(aliceTabDec1.text, secretDm1);

  const aliceSelfCt1 = encrypted1.deviceCiphertexts[aliceDev1.record.deviceId];
  const aliceSelfDec1 = await decryptOlmDeviceCiphertext(
    aliceUserId,
    aliceDev1.record.curve25519Key,
    aliceSelfCt1.message_type,
    aliceSelfCt1.ciphertext_b64
  );
  assert.equal(aliceSelfDec1.text, secretDm1);

  // 4. Replay attack with already-decrypted Olm PreKey message MUST fail
  await assert.rejects(
    () =>
      decryptOlmDeviceCiphertext(
        bobUserId,
        aliceDev1.record.curve25519Key,
        bobCt1.message_type,
        bobCt1.ciphertext_b64
      ),
    /Unable to decrypt Olm message/
  );

  // 5. Bob replies to Alice -> Double Ratchet advances to Normal message (type 1)
  const secretReply = 'Confirmed receipt over Double Ratchet type-1';
  const bobReply = await encryptOlmMultiDevicePayload(
    bobUserId,
    { v: 1, text: secretReply, sent_at: '2026-10-30T01:01:00.000Z' },
    [targetDevicesForAliceSend[0]],
    claimPrekeys
  );
  const toAliceCt = bobReply.deviceCiphertexts[aliceDev1.record.deviceId];
  assert.equal(toAliceCt.message_type, 1, 'Reply over established session uses Normal ratchet message type 1');

  const aliceDecReply = await decryptOlmDeviceCiphertext(
    aliceUserId,
    bobDev1.record.curve25519Key,
    toAliceCt.message_type,
    toAliceCt.ciphertext_b64
  );
  assert.equal(aliceDecReply.text, secretReply);

  // Replay of Normal ratchet message (type 1) MUST also fail
  await assert.rejects(
    () =>
      decryptOlmDeviceCiphertext(
        aliceUserId,
        bobDev1.record.curve25519Key,
        toAliceCt.message_type,
        toAliceCt.ciphertext_b64
      ),
    /Unable to decrypt Olm message/
  );

  // 6. Prekey replenishment + Fallback key rotation + Session re-establishment
  const rotated = await generateMoreOlmPrekeys(bobUserId, 5, true);
  assert.equal(Object.keys(rotated.one_time_keys).length >= 5, true);
  assert.ok(rotated.fallback_public_key);
  otkPools.set(bobDev1.record.deviceId, Object.entries(rotated.one_time_keys));

  await resetOlmSessionWithPeerDevice(aliceUserId, bobDev1.record.curve25519Key);
  const reestablished = await encryptOlmMultiDevicePayload(
    aliceUserId,
    { v: 1, text: 'Fresh 3DH session after manual reset', sent_at: '2026-10-30T01:02:00.000Z' },
    [targetDevicesForAliceSend[2]],
    claimPrekeys
  );
  assert.equal(reestablished.deviceCiphertexts[bobDev1.record.deviceId].message_type, 0);
  const bobDecReest = await decryptOlmDeviceCiphertext(
    bobUserId,
    aliceDev1.record.curve25519Key,
    reestablished.deviceCiphertexts[bobDev1.record.deviceId].message_type,
    reestablished.deviceCiphertexts[bobDev1.record.deviceId].ciphertext_b64
  );
  assert.equal(bobDecReest.text, 'Fresh 3DH session after manual reset');

  // 7. Symmetric 60-digit Safety Numbers
  const snAlice = await computeSafetyNumber(
    {
      userId: aliceUserId,
      ed25519Key: aliceDev1.record.ed25519Key,
      curve25519Key: aliceDev1.record.curve25519Key,
    },
    {
      userId: bobUserId,
      ed25519Key: bobDev1.record.ed25519Key,
      curve25519Key: bobDev1.record.curve25519Key,
    }
  );
  const snBob = await computeSafetyNumber(
    {
      userId: bobUserId,
      ed25519Key: bobDev1.record.ed25519Key,
      curve25519Key: bobDev1.record.curve25519Key,
    },
    {
      userId: aliceUserId,
      ed25519Key: aliceDev1.record.ed25519Key,
      curve25519Key: aliceDev1.record.curve25519Key,
    }
  );
  assert.equal(snAlice, snBob, 'Safety number MUST be symmetric across both peers');
  assert.equal(snAlice.replace(/\s+/g, '').length, 60, 'Safety number MUST contain 60 decimal digits');

  const snTampered = await computeSafetyNumber(
    {
      userId: aliceUserId,
      ed25519Key: aliceDev1.record.ed25519Key,
      curve25519Key: aliceDev1.record.curve25519Key,
    },
    {
      userId: bobUserId,
      ed25519Key: aliceDev2.record.ed25519Key, // MITM key
      curve25519Key: bobDev1.record.curve25519Key,
    }
  );
  assert.notEqual(snAlice, snTampered, 'Safety number MUST change on MITM identity substitution');

  // 8. Identity-key change, new device & lost-key reset warning detection
  const trustInitial = await evaluateAndRecordPeerTrust(aliceUserId, bobUserId, 1, [
    targetDevicesForAliceSend[2],
  ]);
  assert.equal(trustInitial.securityWarnings.length, 0);
  await markPeerDevicesVerified(aliceUserId, bobUserId);

  // Peer adds a new device + increments identity_version after lost-key reset
  const trustAfterReset = await evaluateAndRecordPeerTrust(aliceUserId, bobUserId, 2, [
    {
      ...targetDevicesForAliceSend[2],
      ed25519_identity_key: aliceDev2.record.ed25519Key, // Mutated key on device ID
    },
    {
      device_id: 'dev_bob_new_phone',
      user_id: bobUserId,
      device_label: 'Bob New Phone',
      ed25519_identity_key: aliceDev2.record.ed25519Key,
      curve25519_identity_key: aliceDev2.record.curve25519Key,
      status: 'active',
    },
  ]);
  assert.equal(trustAfterReset.devices[bobDev1.record.deviceId].verified, false);
  assert.ok(
    trustAfterReset.securityWarnings.some((w) => w.includes('reset their encryption identity'))
  );
  assert.ok(trustAfterReset.securityWarnings.some((w) => w.includes('CRITICAL: Identity key changed')));
  assert.ok(trustAfterReset.securityWarnings.some((w) => w.includes('New device added by peer')));
});

test('RFC 9420 MLS Group E2EE: pre-join secrecy, Remove rekeying, post-removal secrecy & epoch authenticators', async () => {
  const aliceUid = 'usr_mls_alice';
  const bobUid = 'usr_mls_bob';
  const charlieUid = 'usr_mls_charlie';
  const groupId = 'grp_mls_security_test_01';

  // 1. Alice creates group at epoch 0
  const initRes = await initializeNewMlsGroupLocal(aliceUid, 'dev_alice_1');
  await initRes.finalizeWithServerGroupId(groupId);
  const info0 = await getMlsGroupSecurityInfo(aliceUid, groupId);
  assert.ok(info0);
  assert.equal(info0.epoch, 0);

  // 2. Bob publishes KeyPackages; credential-mismatch attack is rejected first
  const bobKps = await generateMlsKeyPackagesForDevice(bobUid, 'dev_bob_1', 2);
  assert.equal((await listMlsKeyPackageSecrets(bobUid)).length, 2);

  await assert.rejects(
    () =>
      buildMlsAddMembersCommit(aliceUid, groupId, [
        {
          user_id: 'usr_attacker_impersonator',
          device_id: 'dev_bob_1',
          key_package_b64: bobKps[0].key_package_b64,
        },
      ]),
    /MLS KeyPackage credential mismatch/
  );

  // 3. Alice legitimately adds Bob -> epoch 1
  const addBob = await buildMlsAddMembersCommit(aliceUid, groupId, [
    {
      user_id: bobUid,
      device_id: 'dev_bob_1',
      key_package_b64: bobKps[0].key_package_b64,
    },
  ]);
  assert.equal(addBob.expectedEpoch, 0);
  const aliceEpoch1 = await addBob.applyLocalCommit();
  assert.equal(aliceEpoch1, 1);

  const bobJoin = await joinMlsGroupFromWelcomeB64(bobUid, groupId, addBob.mlsWelcomeB64);
  assert.equal(bobJoin.epoch, 1);
  // Consumed KeyPackage private secret MUST be deleted for forward secrecy
  assert.equal((await listMlsKeyPackageSecrets(bobUid)).length, 1);

  // 4. Alice sends Epoch-1 message (before Charlie joins)
  const preCharlieSecret = 'Epoch-1 secret strictly before Charlie joined';
  const msgEpoch1 = await encryptMlsGroupMessage(aliceUid, groupId, {
    v: 1,
    text: preCharlieSecret,
    sent_at: '2026-10-30T01:05:00.000Z',
  });
  assert.equal(msgEpoch1.epoch, 1);
  assert.equal(msgEpoch1.mlsCiphertextB64.includes(preCharlieSecret), false);

  const bobDecEpoch1 = await decryptMlsGroupMessage(bobUid, groupId, msgEpoch1.mlsCiphertextB64);
  assert.equal(bobDecEpoch1.text, preCharlieSecret);

  // 5. Add Charlie at Epoch 2 -> Charlie MUST NOT be able to decrypt Epoch-1 message!
  const charlieKps = await generateMlsKeyPackagesForDevice(charlieUid, 'dev_charlie_1', 1);
  const addCharlie = await buildMlsAddMembersCommit(aliceUid, groupId, [
    {
      user_id: charlieUid,
      device_id: 'dev_charlie_1',
      key_package_b64: charlieKps[0].key_package_b64,
    },
  ]);
  assert.equal(addCharlie.expectedEpoch, 1);
  await addCharlie.applyLocalCommit();

  // Bob processes Commit to advance from epoch 1 -> 2
  const bobSync2 = await processIncomingMlsCommits(bobUid, groupId, [
    { epoch: 2, mls_commit_b64: addCharlie.mlsCommitB64 },
  ]);
  assert.equal(bobSync2.epoch, 2);
  assert.equal(bobSync2.selfRemoved, false);

  // Charlie joins via Welcome at epoch 2
  const charlieJoin = await joinMlsGroupFromWelcomeB64(
    charlieUid,
    groupId,
    addCharlie.mlsWelcomeB64
  );
  assert.equal(charlieJoin.epoch, 2);

  // PRE-JOIN SECRECY PROOF: Charlie cannot decrypt Epoch-1 message
  await assert.rejects(() =>
    decryptMlsGroupMessage(charlieUid, groupId, msgEpoch1.mlsCiphertextB64)
  );

  // Snapshot Bob's epoch-2 vault state to simulate a malicious removed member retaining local keys
  const bobStolenEpoch2Snapshot = await loadMlsGroupVaultState(bobUid, groupId);
  assert.ok(bobStolenEpoch2Snapshot);

  // 6. Remove Bob at Epoch 3 -> TreeKEM path secrets rotate; Bob CANNOT decrypt Epoch-3 messages!
  const removeBob = await buildMlsRemoveMemberCommit(aliceUid, groupId, bobUid);
  assert.equal(removeBob.expectedEpoch, 2);
  const aliceEpoch3 = await removeBob.applyLocalCommit();
  assert.equal(aliceEpoch3, 3);

  const charlieSync3 = await processIncomingMlsCommits(charlieUid, groupId, [
    { epoch: 3, mls_commit_b64: removeBob.mlsCommitB64 },
  ]);
  assert.equal(charlieSync3.epoch, 3);
  assert.equal(charlieSync3.selfRemoved, false);

  const bobSync3 = await processIncomingMlsCommits(bobUid, groupId, [
    { epoch: 3, mls_commit_b64: removeBob.mlsCommitB64 },
  ]);
  assert.equal(bobSync3.selfRemoved, true);
  assert.equal(await loadMlsGroupVaultState(bobUid, groupId), null);

  // Charlie sends a post-removal message in Epoch 3
  const postBobRemovalSecret = 'Epoch-3 secret after Bob was removed and TreeKEM rekeyed';
  const msgEpoch3 = await encryptMlsGroupMessage(charlieUid, groupId, {
    v: 1,
    text: postBobRemovalSecret,
    sent_at: '2026-10-30T01:06:00.000Z',
  });
  assert.equal(msgEpoch3.epoch, 3);

  const aliceDecEpoch3 = await decryptMlsGroupMessage(aliceUid, groupId, msgEpoch3.mlsCiphertextB64);
  assert.equal(aliceDecEpoch3.text, postBobRemovalSecret);

  // POST-REMOVAL SECRECY PROOF: Even if Bob restores his stolen epoch-2 state, he cannot decrypt Epoch 3
  await saveMlsGroupVaultState(bobUid, bobStolenEpoch2Snapshot);
  await assert.rejects(() =>
    decryptMlsGroupMessage(bobUid, groupId, msgEpoch3.mlsCiphertextB64)
  );

  // 7. Self Key Rotation (Update Commit -> Epoch 4) & Epoch Authenticator Equivalence
  const rotateAlice = await buildMlsSelfKeyRotationCommit(aliceUid, groupId);
  assert.equal(rotateAlice.expectedEpoch, 3);
  await rotateAlice.applyLocalCommit();
  await processIncomingMlsCommits(charlieUid, groupId, [
    { epoch: 4, mls_commit_b64: rotateAlice.mlsCommitB64 },
  ]);

  const aliceSec4 = await getMlsGroupSecurityInfo(aliceUid, groupId);
  const charlieSec4 = await getMlsGroupSecurityInfo(charlieUid, groupId);
  assert.ok(aliceSec4 && charlieSec4);
  assert.equal(aliceSec4.epoch, 4);
  assert.equal(charlieSec4.epoch, 4);
  assert.equal(aliceSec4.epochAuthenticatorHex, charlieSec4.epochAuthenticatorHex);
  assert.equal(aliceSec4.exportedContextVerifyCode, charlieSec4.exportedContextVerifyCode);

  // 8. Lost-all-devices simulation: wiping Charlie's local vault makes group ciphertexts irrecoverable
  await wipeUserDeviceVault(charlieUid);
  await assert.rejects(() =>
    decryptMlsGroupMessage(charlieUid, groupId, msgEpoch3.mlsCiphertextB64)
  );
});

test('E2EE File Attachment Crypto encrypts on-device, verifies SHA-256 integrity, and rejects tampering', async () => {
  const rawFile = new TextEncoder().encode(
    'CONFIDENTIAL ESCROW CONTRACT PDF PAYLOAD - DO NOT EXPOSE TO STORAGE BUCKET'
  );
  const enc = await encryptAttachmentOnDevice(rawFile, {
    scopeType: 'dm',
    fileName: 'contract.pdf',
    mimeType: 'application/pdf',
  });

  assert.equal(enc.ciphertextB64.includes('CONFIDENTIAL ESCROW'), false);
  assert.equal(enc.ciphertextSha256Hex.length, 64);

  const descriptor = {
    attachment_id: 'att_test_001',
    key_b64: enc.ephemeralKeyB64,
    iv_b64: enc.ivB64,
    sha256_hex: enc.ciphertextSha256Hex,
    file_name: 'contract.pdf',
    mime_type: 'application/pdf',
    size_bytes: enc.sizeBytes,
  };

  // Valid decryption succeeds
  const decBytes = await decryptAttachmentOnDevice(enc.ciphertextB64, descriptor, 'dm');
  assert.equal(
    new TextDecoder().decode(decBytes),
    'CONFIDENTIAL ESCROW CONTRACT PDF PAYLOAD - DO NOT EXPOSE TO STORAGE BUCKET'
  );

  // Tampered ciphertext bytes MUST fail SHA-256 integrity check before AES-GCM decryption
  const tamperedBytes = Buffer.from(enc.ciphertextB64, 'base64');
  tamperedBytes[0] ^= 0xff;
  await assert.rejects(
    () => decryptAttachmentOnDevice(tamperedBytes.toString('base64'), descriptor, 'dm'),
    /SHA-256 ciphertext digest mismatch/
  );

  // Cross-scope replay (DM blob replayed into a Group context) MUST fail AES-GCM AAD verification
  await assert.rejects(() => decryptAttachmentOnDevice(enc.ciphertextB64, descriptor, 'group'));
});

