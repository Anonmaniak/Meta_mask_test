/**
 * When is it safe to wipe this browser's E2EE device vault?
 *
 * Wiping destroys the Olm identity, Double Ratchet sessions, MLS group state and the local message
 * cache. It is irreversible, so it must ONLY happen when the server has positively said that THIS
 * device is revoked. A plain HTTP 403 is not enough: the backend also answers 403 for a suspended or
 * muted account, a block between users, "you are not in this group", admin-only actions, and more.
 *
 * Pure functions (no browser APIs) so they run in the Node unit tests.
 */

export interface ApiErrorLike {
  status?: number;
  message?: string;
  detail?: unknown;
}

export interface DeviceStatusLike {
  device_id: string;
  status: string;
}

function errorText(err: ApiErrorLike | null | undefined): string {
  if (!err) return '';
  const d = err.detail as { message?: unknown } | string | undefined;
  const fromDetail = typeof d === 'string' ? d : typeof d?.message === 'string' ? d.message : '';
  return `${err.message || ''} ${fromDetail}`.trim();
}

/** 403 because of moderation (suspension / mute): never a reason to touch the device vault. */
export function isAccountRestrictionError(err: ApiErrorLike | null | undefined): boolean {
  if (!err || err.status !== 403) return false;
  return /account (is )?(currently )?(suspended|muted)|muted by moderation/i.test(errorText(err));
}

/**
 * The device-registration endpoint's explicit "this device id can never be used again" answers
 * (backend e2ee_db.upsert_device_and_keys). These are definitive on their own.
 */
export function isDeviceRevokedRegistrationError(err: ApiErrorLike | null | undefined): boolean {
  if (!err || err.status !== 403 || isAccountRestrictionError(err)) return false;
  return /revoked device cannot be re-?activated|device id belongs to another user/i.test(errorText(err));
}

/** True only when the server's own device list marks `deviceId` as revoked. */
export function isDeviceRevokedInList(
  devices: readonly DeviceStatusLike[] | null | undefined,
  deviceId: string | null | undefined
): boolean {
  if (!deviceId || !Array.isArray(devices)) return false;
  const mine = devices.find((d) => d && d.device_id === deviceId);
  return Boolean(mine && String(mine.status).toLowerCase() === 'revoked');
}

/**
 * Decides whether a failed request means "this device was revoked, wipe and re-provision".
 * Anything other than a 403 → no. Moderation 403 → no. Explicit registration revocation → yes.
 * Otherwise ask the server (GET /e2ee/me lists every device with its status) and wipe only if it
 * confirms this device is revoked. If that check itself fails, keep the vault (fail safe).
 */
export async function shouldWipeLocalDevice(
  err: ApiErrorLike | null | undefined,
  deviceId: string | null | undefined,
  fetchMyDevices: () => Promise<{ devices: readonly DeviceStatusLike[] }>
): Promise<boolean> {
  if (!err || err.status !== 403) return false;
  if (isAccountRestrictionError(err)) return false;
  if (isDeviceRevokedRegistrationError(err)) return true;
  if (!deviceId) return false;
  try {
    const me = await fetchMyDevices();
    return isDeviceRevokedInList(me?.devices, deviceId);
  } catch {
    return false;
  }
}
