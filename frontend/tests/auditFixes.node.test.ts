import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  isAccountRestrictionError,
  isDeviceRevokedRegistrationError,
  isDeviceRevokedInList,
  shouldWipeLocalDevice,
} from '../src/services/deviceRevocation.ts';
import { cleanEmoji, isSingleEmoji } from '../src/services/chatEvents.ts';

const err = (status: number, message: string) => ({ status, message, detail: message });
const me = (devices: Array<{ device_id: string; status: string }>) => async () => ({ devices });
const failingMe = async (): Promise<{ devices: Array<{ device_id: string; status: string }> }> => {
  throw Object.assign(new Error('Account suspended: spam'), { status: 403 });
};

describe('vault wipe only on confirmed device revocation', () => {
  it('never wipes for a suspended or muted account', async () => {
    const suspended = err(403, 'Account suspended: Contact platform administrator');
    assert.equal(isAccountRestrictionError(suspended), true);
    assert.equal(await shouldWipeLocalDevice(suspended, 'dev_1', me([{ device_id: 'dev_1', status: 'revoked' }])), false);
    const muted = err(403, 'Your account is currently muted by moderation');
    assert.equal(await shouldWipeLocalDevice(muted, 'dev_1', me([])), false);
  });

  it('never wipes for ordinary permission 403s when the device is still active', async () => {
    for (const msg of [
      'You are not in this group',
      'Cannot exchange attachments with blocked user',
      'Only group admins can pin messages',
      'Forbidden or revoked device_id',
    ]) {
      assert.equal(await shouldWipeLocalDevice(err(403, msg), 'dev_1', me([{ device_id: 'dev_1', status: 'active' }])), false, msg);
    }
  });

  it('never wipes for non-403 errors', async () => {
    for (const s of [400, 401, 402, 404, 409, 500]) {
      assert.equal(await shouldWipeLocalDevice(err(s, 'x'), 'dev_1', me([{ device_id: 'dev_1', status: 'revoked' }])), false);
    }
    assert.equal(await shouldWipeLocalDevice(null, 'dev_1', me([])), false);
  });

  it('wipes on the explicit registration revocation answers', async () => {
    const revoked = err(403, 'Revoked device cannot be re-activated; generate a new device identity');
    assert.equal(isDeviceRevokedRegistrationError(revoked), true);
    assert.equal(await shouldWipeLocalDevice(revoked, 'dev_1', failingMe), true);
    assert.equal(await shouldWipeLocalDevice(err(403, 'Device ID belongs to another user'), 'dev_1', failingMe), true);
  });

  it('wipes when the server device list confirms this device is revoked', async () => {
    const generic = err(403, 'Forbidden or revoked device_id');
    assert.equal(await shouldWipeLocalDevice(generic, 'dev_1', me([{ device_id: 'dev_1', status: 'revoked' }])), true);
    // a different device being revoked does not count
    assert.equal(await shouldWipeLocalDevice(generic, 'dev_1', me([{ device_id: 'dev_2', status: 'revoked' }])), false);
  });

  it('keeps the vault when confirmation is impossible', async () => {
    const generic = err(403, 'Forbidden or revoked device_id');
    assert.equal(await shouldWipeLocalDevice(generic, 'dev_1', failingMe), false);
    assert.equal(await shouldWipeLocalDevice(generic, null, me([{ device_id: 'dev_1', status: 'revoked' }])), false);
    assert.equal(isDeviceRevokedInList(undefined, 'dev_1'), false);
  });
});

describe('reaction emoji validation (mirrors backend)', () => {
  it('accepts keycaps, flags, ZWJ sequences and skin tones', () => {
    for (const e of ['👍', '👍🏽', '❤️', '1️⃣', '#️⃣', '*️⃣', '🇺🇬', '👨‍👩‍👧‍👦', '👩🏽‍💻', '🏴󠁧󠁢󠁥󠁮󠁧󠁿']) {
      assert.equal(cleanEmoji(e), e, e);
    }
  });

  it('rejects text in any script, multiple emoji and broken sequences', () => {
    for (const e of ['abc', '1', 'Привет', 'ж', '中文', 'αβ', '👍👍', '<b>', '👍a', '🇺', '1️', '👍\u200d']) {
      assert.equal(isSingleEmoji(e), false, e);
      assert.equal(cleanEmoji(e), '', e);
    }
    assert.equal(cleanEmoji(42), '');
  });
});
