/**
 * One place that makes sure this browser's E2EE device is registered with the server.
 *
 * Both the sign-in flow (App.tsx) and the chat screen (Chat.tsx) need the device ready. They used to
 * run their own copies of this code at the same moment right after login, which registered the
 * device bundle twice and published two batches of MLS KeyPackages. Now both call
 * `ensureLocalDeviceRegistered`, and a call made while one is already running for the same user
 * simply waits for that run and receives the same result.
 */
import {
  fetchMyE2EEAccount,
  registerE2EEDeviceBundle,
  replenishE2EEPrekeys,
} from './e2eeApi.ts';
import { wipeUserDeviceVault } from './e2eeVault.ts';
import {
  getOrCreateLocalOlmDevice,
  markLocalPrekeysPublished,
  generateMoreOlmPrekeys,
} from './olmService.ts';
import { generateMlsKeyPackagesForDevice } from './mlsGroupService.ts';
import { shouldWipeLocalDevice } from './deviceRevocation.ts';

const DEVICE_LABEL = 'Web browser';

export interface ProvisionedDevice {
  deviceId: string;
  availableCounts: { one_time_prekeys: number; mls_key_packages: number };
}

const inflight = new Map<string, Promise<ProvisionedDevice>>();

async function provision(userId: string): Promise<ProvisionedDevice> {
  let localDev = await getOrCreateLocalOlmDevice(userId, DEVICE_LABEL);
  let mlsPackages = localDev.isNewDevice
    ? await generateMlsKeyPackagesForDevice(userId, localDev.record.deviceId, 8)
    : [];

  let regRes;
  try {
    regRes = await registerE2EEDeviceBundle({
      ...localDev.registrationBundle,
      mls_key_packages: mlsPackages,
    });
  } catch (regErr: any) {
    // Only a CONFIRMED revocation of this device may wipe the vault. A suspended account, for
    // example, also gets 403 and must keep its keys and history for when it is restored.
    const revoked = await shouldWipeLocalDevice(regErr, localDev.record.deviceId, fetchMyE2EEAccount);
    if (!revoked) throw regErr;
    await wipeUserDeviceVault(userId);
    localDev = await getOrCreateLocalOlmDevice(userId, DEVICE_LABEL);
    mlsPackages = await generateMlsKeyPackagesForDevice(userId, localDev.record.deviceId, 8);
    regRes = await registerE2EEDeviceBundle({
      ...localDev.registrationBundle,
      mls_key_packages: mlsPackages,
    });
  }
  await markLocalPrekeysPublished(userId);

  let counts = regRes.available_counts;
  if (counts.one_time_prekeys < 5 || counts.mls_key_packages < 3) {
    const moreOlm = await generateMoreOlmPrekeys(userId, 12, false);
    const moreMls = await generateMlsKeyPackagesForDevice(userId, localDev.record.deviceId, 6);
    const rep = await replenishE2EEPrekeys(localDev.record.deviceId, {
      ...moreOlm,
      mls_key_packages: moreMls,
    });
    await markLocalPrekeysPublished(userId);
    counts = rep?.available_counts || counts;
  }
  return { deviceId: localDev.record.deviceId, availableCounts: counts };
}

/** Registers (or re-confirms) this browser's device for `userId`. Concurrent calls share one run. */
export function ensureLocalDeviceRegistered(userId: string): Promise<ProvisionedDevice> {
  const running = inflight.get(userId);
  if (running) return running;
  const p = provision(userId).finally(() => {
    if (inflight.get(userId) === p) inflight.delete(userId);
  });
  inflight.set(userId, p);
  return p;
}
