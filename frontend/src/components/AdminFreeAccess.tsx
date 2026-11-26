import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Gift, Search, X, Loader2, RefreshCw } from 'lucide-react';
import { formatAddress } from '../services/web3';
import {
  fetchAdminUsers,
  fetchAdminGroups,
  fetchAdminAccessGrants,
  adminGrantAccess,
  adminRevokeAccess,
  formatDate,
  type AccessGrant,
} from '../services/platformApi';

/**
 * Admin456 "Free access": let a member in without paying, for the whole membership or one group.
 * A group grant also waives that group's minimum-balance rule. Only a superadmin can give or revoke;
 * moderators see the list. Members are still added to encrypted groups by a group admin (the server
 * cannot add anyone to an encrypted group), and the member still accepts the invitation.
 */

interface AdminFreeAccessProps {
  adminToken: string;
  /** 'superadmin' | 'moderator' (from the overview) */
  role: string;
  onUnauthorized?: () => void;
}

interface PickedMember {
  user_id: string;
  username: string | null;
  primary_wallet: string | null;
}

type Duration = '30' | '90' | '365' | 'none' | 'custom';

const DURATIONS: Array<[Duration, string]> = [
  ['30', '30 days'],
  ['90', '90 days'],
  ['365', '1 year'],
  ['none', 'No end date'],
  ['custom', 'Custom number of days'],
];

const memberLabel = (m: { username?: string | null; user_id: string }) => (m.username ? `@${m.username}` : m.user_id);

export const AdminFreeAccess: React.FC<AdminFreeAccessProps> = ({ adminToken, role, onUnauthorized }) => {
  const canEdit = role === 'superadmin';

  // --- form ---
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<PickedMember[]>([]);
  const [searching, setSearching] = useState(false);
  const [member, setMember] = useState<PickedMember | null>(null);
  const [scope, setScope] = useState<string>('platform'); // 'platform' or a group id
  const [duration, setDuration] = useState<Duration>('none');
  const [customDays, setCustomDays] = useState('60');
  const [note, setNote] = useState('');
  const [saving, setSaving] = useState(false);

  // --- data ---
  const [groups, setGroups] = useState<Array<{ group_id: string; name: string; is_paid: boolean }>>([]);
  const [grants, setGrants] = useState<AccessGrant[]>([]);
  const [showEnded, setShowEnded] = useState(false);
  const [loading, setLoading] = useState(false);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const searchSeq = useRef(0);

  const fail = useCallback(
    (err: any, fallback: string) => {
      if (err?.status === 401 && onUnauthorized) onUnauthorized();
      setNotice(null);
      setError(err?.message || fallback);
    },
    [onUnauthorized]
  );

  const loadGrants = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchAdminAccessGrants({ includeInactive: showEnded }, adminToken);
      setGrants(res.grants);
    } catch (err: any) {
      fail(err, 'Could not load the free-access list.');
    } finally {
      setLoading(false);
    }
  }, [adminToken, showEnded, fail]);

  useEffect(() => {
    void loadGrants();
  }, [loadGrants]);

  useEffect(() => {
    fetchAdminGroups(adminToken)
      .then((res) =>
        setGroups(
          (res.groups || [])
            .map((g: any) => ({ group_id: g.group_id, name: g.name, is_paid: Boolean(g.policy?.is_paid) }))
            .sort((a: any, b: any) => Number(b.is_paid) - Number(a.is_paid) || a.name.localeCompare(b.name))
        )
      )
      .catch((err) => fail(err, 'Could not load the groups.'));
  }, [adminToken, fail]);

  // Member search (debounced; only the latest answer is shown)
  useEffect(() => {
    if (member) return;
    const q = query.trim();
    if (q.length < 2) {
      searchSeq.current += 1; // ignore any answer still on its way (the list is hidden below 2 letters)
      return;
    }
    const seq = ++searchSeq.current;
    const t = window.setTimeout(() => {
      setSearching(true);
      fetchAdminUsers(q, adminToken)
        .then((res) => {
          if (seq === searchSeq.current) setResults((res.users || []).slice(0, 8));
        })
        .catch((err) => {
          if (seq === searchSeq.current) fail(err, 'Member search failed.');
        })
        .finally(() => {
          if (seq === searchSeq.current) setSearching(false);
        });
    }, 250);
    return () => window.clearTimeout(t);
  }, [query, member, adminToken, fail]);

  const days: number | null | 'invalid' = useMemo(() => {
    if (duration === 'none') return null;
    if (duration !== 'custom') return Number(duration);
    const n = Number(customDays);
    return Number.isInteger(n) && n >= 1 && n <= 3650 ? n : 'invalid';
  }, [duration, customDays]);

  const scopeName = scope === 'platform' ? 'the membership' : `"${groups.find((g) => g.group_id === scope)?.name || 'this group'}"`;

  const give = async () => {
    if (!member || days === 'invalid' || saving) return;
    setSaving(true);
    setError(null);
    try {
      const res = await adminGrantAccess(
        {
          user_id: member.user_id,
          scope_type: scope === 'platform' ? 'platform' : 'group',
          ...(scope === 'platform' ? {} : { group_id: scope }),
          days,
          note: note.trim(),
        },
        adminToken
      );
      const ends = res.grant.lifetime ? 'with no end date' : `until ${formatDate(res.grant.expires_at)}`;
      setNotice(
        scope === 'platform'
          ? `${memberLabel(member)} now has free membership ${ends}.`
          : `${memberLabel(member)} now has free access to ${scopeName} ${ends}. A group admin can add them; they accept the invitation as usual.`
      );
      setMember(null);
      setQuery('');
      setNote('');
      await loadGrants();
    } catch (err: any) {
      fail(err, 'Free access was not given.');
    } finally {
      setSaving(false);
    }
  };

  const revoke = async (g: AccessGrant) => {
    const what = g.scope_type === 'platform' ? 'free membership' : `free access to "${g.group_name || 'the group'}"`;
    if (!confirm(`Revoke ${what} for ${memberLabel(g)}? They will need to pay unless they already have a paid period.`)) return;
    const key = `${g.user_id}:${g.scope_type}:${g.scope_id}`;
    setBusyKey(key);
    setError(null);
    try {
      await adminRevokeAccess(
        { user_id: g.user_id, scope_type: g.scope_type, ...(g.scope_type === 'group' ? { group_id: g.scope_id } : {}) },
        adminToken
      );
      setNotice(`Revoked ${what} for ${memberLabel(g)}.`);
      await loadGrants();
    } catch (err: any) {
      fail(err, 'Free access was not revoked.');
    } finally {
      setBusyKey(null);
    }
  };

  const grantStatus = (g: AccessGrant): { tone: 'ok' | 'warn' | 'bad'; label: string } => {
    if (g.revoked_at) return { tone: 'bad', label: 'Revoked' };
    if (!g.active) return { tone: 'bad', label: 'Ended' };
    if (g.lifetime) return { tone: 'ok', label: 'No end date' };
    return { tone: 'ok', label: `Until ${formatDate(g.expires_at)}` };
  };

  const cell: React.CSSProperties = { padding: '10px 8px', verticalAlign: 'top' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {(error || notice) && (
        <div className="deck-card" role={error ? 'alert' : 'status'} style={{ padding: '12px 16px', fontSize: '0.92rem' }}>
          {error || notice}
        </div>
      )}

      {/* Give free access */}
      <div className="deck-card">
        <div className="deck-title">
          <Gift size={18} /> Give free access
        </div>
        <div className="deck-subtitle" style={{ maxWidth: '72ch' }}>
          Let a member in without paying. Membership opens the app. A group grant opens one group and also skips its
          minimum-balance rule. Suspended accounts stay blocked.
        </div>

        {!canEdit ? (
          <p className="deck-subtitle" style={{ marginTop: 14 }}>
            Only a superadmin can give or revoke free access. You can see who has it below.
          </p>
        ) : (
          <div className="admin-settings-grid admin-settings-grid--two" style={{ marginTop: 16 }}>
            <div className="admin-settings-field" style={{ gridColumn: '1 / -1' }}>
              <label className="admin-settings-label" htmlFor="fa-member">
                Member
              </label>
              {member ? (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 10,
                    padding: '8px 12px',
                    border: '1px solid var(--border-strong)',
                    borderRadius: 10,
                    background: 'var(--bg-input)',
                  }}
                >
                  <span>
                    <strong>{memberLabel(member)}</strong>
                    {member.primary_wallet ? ` (${formatAddress(member.primary_wallet, 4)})` : ''}
                  </span>
                  <button
                    type="button"
                    className="btn-outline"
                    style={{ padding: '3px 10px', fontSize: '0.88rem' }}
                    onClick={() => {
                      setMember(null);
                      setResults([]);
                    }}
                  >
                    <X size={14} /> Change
                  </button>
                </div>
              ) : (
                <>
                  <div style={{ position: 'relative' }}>
                    <Search size={15} style={{ position: 'absolute', left: 12, top: 13, color: 'var(--text-muted)' }} />
                    <input
                      id="fa-member"
                      className="admin-settings-input"
                      style={{ paddingLeft: 34 }}
                      placeholder="Search @username, member ID or 0x wallet"
                      value={query}
                      onChange={(e) => setQuery(e.target.value)}
                      autoComplete="off"
                    />
                  </div>
                  {query.trim().length >= 2 && (
                    <div style={{ marginTop: 6, border: '1px solid var(--border-subtle)', borderRadius: 10, overflow: 'hidden' }}>
                      {searching && results.length === 0 ? (
                        <div className="admin-settings-hint" style={{ padding: '10px 12px' }}>Searching…</div>
                      ) : results.length === 0 ? (
                        <div className="admin-settings-hint" style={{ padding: '10px 12px' }}>No member matches.</div>
                      ) : (
                        results.map((u) => (
                          <button
                            key={u.user_id}
                            type="button"
                            onClick={() => setMember(u)}
                            style={{
                              display: 'flex',
                              width: '100%',
                              justifyContent: 'space-between',
                              gap: 10,
                              padding: '9px 12px',
                              background: 'transparent',
                              border: 0,
                              borderTop: '1px solid var(--border-subtle)',
                              color: 'var(--text-main)',
                              font: 'inherit',
                              textAlign: 'left',
                              cursor: 'pointer',
                            }}
                          >
                            <span>{memberLabel(u)}</span>
                            <span style={{ color: 'var(--text-muted)' }}>
                              {u.primary_wallet ? formatAddress(u.primary_wallet, 4) : u.user_id.slice(0, 14)}
                            </span>
                          </button>
                        ))
                      )}
                    </div>
                  )}
                </>
              )}
            </div>

            <div className="admin-settings-field">
              <label className="admin-settings-label" htmlFor="fa-scope">
                Access to
              </label>
              <select id="fa-scope" className="admin-settings-input" value={scope} onChange={(e) => setScope(e.target.value)}>
                <option value="platform">Membership (the whole app)</option>
                {groups.map((g) => (
                  <option key={g.group_id} value={g.group_id}>
                    {g.name}
                    {g.is_paid ? ' (paid group)' : ''}
                  </option>
                ))}
              </select>
              <div className="admin-settings-hint">
                A group grant does not include the membership. If membership is paid, give both.
              </div>
            </div>

            <div className="admin-settings-field">
              <label className="admin-settings-label" htmlFor="fa-duration">
                How long
              </label>
              <select
                id="fa-duration"
                className="admin-settings-input"
                value={duration}
                onChange={(e) => setDuration(e.target.value as Duration)}
              >
                {DURATIONS.map(([id, label]) => (
                  <option key={id} value={id}>
                    {label}
                  </option>
                ))}
              </select>
              {duration === 'custom' && (
                <input
                  className="admin-settings-input"
                  style={{ marginTop: 8 }}
                  type="number"
                  min={1}
                  max={3650}
                  aria-label="Number of days"
                  value={customDays}
                  onChange={(e) => setCustomDays(e.target.value)}
                />
              )}
              <div className="admin-settings-hint">
                {days === 'invalid' ? 'Enter whole days from 1 to 3650.' : 'Giving access again replaces the old length.'}
              </div>
            </div>

            <div className="admin-settings-field" style={{ gridColumn: '1 / -1' }}>
              <label className="admin-settings-label" htmlFor="fa-note">
                Note (only admins see it)
              </label>
              <input
                id="fa-note"
                className="admin-settings-input"
                maxLength={200}
                placeholder="Why, for the activity log"
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
            </div>

            <div style={{ gridColumn: '1 / -1' }}>
              <button type="button" className="btn-solid" disabled={!member || days === 'invalid' || saving} onClick={() => void give()}>
                {saving ? <Loader2 size={15} className="wg__spin" /> : <Gift size={15} />}
                <span>Give free access</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Who has it */}
      <div className="deck-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <div className="deck-title">Members with free access ({grants.length})</div>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <label style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: '0.9rem' }}>
              <input type="checkbox" checked={showEnded} onChange={(e) => setShowEnded(e.target.checked)} />
              Show ended and revoked
            </label>
            <button type="button" className="btn-outline" onClick={() => void loadGrants()} disabled={loading}>
              {loading ? <Loader2 size={14} className="wg__spin" /> : <RefreshCw size={14} />}
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {grants.length === 0 ? (
          <p className="deck-subtitle" style={{ marginTop: 10 }}>
            {loading ? 'Loading…' : 'Nobody has free access yet.'}
          </p>
        ) : (
          <div style={{ overflowX: 'auto', marginTop: 10 }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.9rem', textAlign: 'left' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                  <th style={cell}>Member</th>
                  <th style={cell}>Access to</th>
                  <th style={cell}>Status</th>
                  <th style={cell}>Given</th>
                  <th style={cell}>Note</th>
                  {canEdit && <th style={cell} />}
                </tr>
              </thead>
              <tbody>
                {grants.map((g) => {
                  const st = grantStatus(g);
                  const key = `${g.user_id}:${g.scope_type}:${g.scope_id}`;
                  return (
                    <tr key={key} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                      <td style={cell}>{memberLabel(g)}</td>
                      <td style={cell}>{g.scope_type === 'platform' ? 'Membership' : g.group_name || 'Deleted group'}</td>
                      <td style={cell}>
                        <span className={`chip chip--${st.tone}`}>{st.label}</span>
                      </td>
                      <td style={cell}>{formatDate(g.created_at)}</td>
                      <td style={{ ...cell, maxWidth: 260, overflowWrap: 'anywhere' }}>{g.note || '–'}</td>
                      {canEdit && (
                        <td style={{ ...cell, textAlign: 'right' }}>
                          {g.active && (
                            <button
                              type="button"
                              className="btn-outline"
                              style={{ padding: '3px 10px', fontSize: '0.88rem' }}
                              disabled={busyKey === key}
                              onClick={() => void revoke(g)}
                            >
                              Revoke
                            </button>
                          )}
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
