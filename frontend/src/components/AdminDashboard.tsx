import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import {
  Shield,
  ShieldCheck,
  Users,
  Flag,
  Settings,
  FileText,
  Search,
  Key,
  Trash2,
  X,
  Megaphone,
} from 'lucide-react';
import { formatAddress, formatEth } from '../services/web3';
import { AdminSupportInbox } from './AdminSupportInbox';
import { AdminFreeAccess } from './AdminFreeAccess';
import { AdminDashboardSkeleton } from './Skeleton';
import type { E2EEAccountProfile } from '../services/e2eeApi';
import {
  fetchAdminOverview,
  fetchAdminUsers,
  inspectAdminUser,
  moderateAdminUser,
  triggerAdminUserBalanceVerify,
  setAdminUserRole,
  fetchAdminGroups,
  updateGroupPolicy,
  adminDeleteGroup,
  fetchAdminReports,
  resolveAdminReport,
  deletePublicChatMessage,
  fetchAdminSettings,
  updateAdminSettings,
  fetchAdminAuditLogs,
  fetchAdminPayments,
  retryAdminPayment,
  formatDate,
  type PaymentRecord,
} from '../services/platformApi';

interface AdminDashboardProps {
  e2eeProfile?: E2EEAccountProfile | null;
  adminToken: string;
  onLogout?: () => void;
}

type AdminTab = 'overview' | 'users' | 'groups' | 'payments' | 'access' | 'reports' | 'support' | 'settings' | 'audit';

/**
 * Asks the admin why and for how long (empty = until restored). Returns null when cancelled.
 * Previously Mute had no duration (so it was permanent) and Suspend had no confirmation or reason.
 */
function askModeration(action: 'mute' | 'suspend', who: string): { reason: string; duration_hours?: number } | null {
  const verb = action === 'mute' ? 'Mute' : 'Suspend';
  const reason = prompt(
    `${verb} ${who}: reason (shown in the activity log)${action === 'suspend' ? '. Suspending signs them out everywhere.' : ''}`,
    action === 'mute' ? 'Spam or abuse in the members\u2019 room' : 'Breach of the club rules'
  );
  if (reason === null) return null;
  const clean = reason.trim();
  if (clean.length < 2) {
    alert('Please give a reason (at least 2 characters).');
    return null;
  }
  const hours = prompt(`${verb} for how many hours? Leave empty to keep it until you restore them. (Max 8760 = 1 year)`, action === 'mute' ? '24' : '');
  if (hours === null) return null;
  const h = hours.trim();
  if (!h) return { reason: clean };
  const n = Math.floor(Number(h));
  if (!(n >= 1 && n <= 8760)) {
    alert('Hours must be a whole number from 1 to 8760, or empty.');
    return null;
  }
  return { reason: clean, duration_hours: n };
}

/** Number field for Platform Settings (empty input keeps the old value instead of sending 0). */
const SettingNumber: React.FC<{
  label: string;
  hint?: string;
  value: number | undefined;
  fallback: number;
  min: number;
  max: number;
  onChange: (n: number) => void;
}> = ({ label, hint, value, fallback, min, max, onChange }) => (
  <div className="admin-settings-field">
    <label className="admin-settings-label">{label}</label>
    <input
      type="number"
      className="admin-settings-input"
      min={min}
      max={max}
      value={value ?? fallback}
      onChange={(e) => {
        if (e.target.value === '') return;
        const n = Math.round(Number(e.target.value));
        if (Number.isFinite(n)) onChange(Math.min(max, Math.max(min, n)));
      }}
    />
    {hint && <div className="admin-settings-hint">{hint}</div>}
  </div>
);

export const AdminDashboard: React.FC<AdminDashboardProps> = ({ e2eeProfile, adminToken, onLogout }) => {
  const [activeTab, setActiveTab] = useState<AdminTab>('overview');
  const [overview, setOverview] = useState<any>(null);
  const [users, setUsers] = useState<any[]>([]);
  const [userQuery, setUserQuery] = useState('');
  const [inspectedUser, setInspectedUser] = useState<any>(null);
  const [groups, setGroups] = useState<any[]>([]);
  const [reports, setReports] = useState<any[]>([]);
  const [settings, setSettings] = useState<Record<string, any>>({});
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [payments, setPayments] = useState<PaymentRecord[]>([]);

  const [error, setError] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  // When the last refresh worked, and whether the latest one failed (so old numbers never look live).
  const [lastOkAt, setLastOkAt] = useState<number | null>(null);
  const [refreshFailing, setRefreshFailing] = useState(false);
  const pollBusyRef = useRef(false);
  const userQueryRef = useRef(userQuery);
  userQueryRef.current = userQuery;
  const userSearchSeqRef = useRef(0);

  const runUserSearch = useCallback(async (q: string) => {
    const seq = ++userSearchSeqRef.current;
    try {
      const u = await fetchAdminUsers(q, adminToken);
      if (seq === userSearchSeqRef.current) {
        setUsers(u.users);
      }
    } catch (err: any) {
      if (seq === userSearchSeqRef.current) {
        setError(err?.message || 'User search failed.');
      }
      if (err?.status === 401 && onLogout) onLogout();
    }
  }, [adminToken, onLogout]);

  const loadAdminData = useCallback(async (isPoll = false) => {
    if (isPoll && pollBusyRef.current) return;
    pollBusyRef.current = true;
    if (!isPoll) setError(null);
    try {
      const ov = await fetchAdminOverview(adminToken);
      setOverview(ov);
      setLastOkAt(Date.now());
      setRefreshFailing(false);

      if (activeTab === 'users') {
        const seq = ++userSearchSeqRef.current;
        const u = await fetchAdminUsers(userQueryRef.current, adminToken);
        if (seq === userSearchSeqRef.current) {
          setUsers(u.users);
        }
      } else if (activeTab === 'groups') {
        const g = await fetchAdminGroups(adminToken);
        setGroups(g.groups);
      } else if (activeTab === 'payments') {
        const p = await fetchAdminPayments(150, undefined, adminToken);
        setPayments(p.payments);
      } else if (activeTab === 'reports') {
        const r = await fetchAdminReports('', adminToken);
        setReports(r.reports);
      } else if (activeTab === 'settings' && !isPoll) {
        const s = await fetchAdminSettings(adminToken);
        setSettings(s.settings);
      } else if (activeTab === 'audit') {
        const a = await fetchAdminAuditLogs(adminToken);
        setAuditLogs(a.audit_logs);
      }
    } catch (err: any) {
      if (!isPoll) setError(err?.message || 'Admin request failed.');
      setRefreshFailing(true);
      if (err?.status === 401 && onLogout) onLogout();
    } finally {
      pollBusyRef.current = false;
    }
  }, [activeTab, adminToken, onLogout]);

  useEffect(() => {
    if (activeTab !== 'users') return;
    const timer = window.setTimeout(() => {
      void runUserSearch(userQuery);
    }, 180);
    return () => window.clearTimeout(timer);
  }, [activeTab, userQuery, runUserSearch]);

  const filteredUsers = useMemo(() => {
    const q = userQuery.trim().replace(/^@+/, '').toLowerCase();
    if (!q) return users;
    return users.filter((u) => {
      const uid = String(u.user_id || '').toLowerCase();
      const uname = String(u.username || '').toLowerCase();
      const wallet = String(u.primary_wallet || '').toLowerCase();
      return uid.includes(q) || uname.includes(q) || wallet.includes(q);
    });
  }, [users, userQuery]);

  useEffect(() => {
    void loadAdminData(false);
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        void loadAdminData(true);
      }
    }, 5000);
    const onVisible = () => {
      if (document.visibilityState === 'visible') {
        void loadAdminData(true);
      }
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      window.clearInterval(id);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [loadAdminData]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top RBAC Header */}
      <div className="deck-card">
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '12px',
          }}
        >
          <div>
            <div className="deck-title">
              <Shield size={20} /> Administration
            </div>
            <div className="deck-subtitle">
              Signed in as:{' '}
              <strong>
                {overview
                  ? `${overview.actor_user_id} (${overview.role})`
                  : e2eeProfile?.admin_role
                    ? `${e2eeProfile.username || e2eeProfile.user_id} (${e2eeProfile.admin_role})`
                    : 'Admin Console session'}
              </strong>{' '}
              · Private chats and groups are encrypted: admins cannot read them.
            </div>
          </div>

          <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
            {onLogout && (
              <button type="button" className="btn-outline" onClick={onLogout}>
                <Key size={13} />
                <span>Sign Out</span>
              </button>
            )}
          </div>
        </div>

        {/* Sub-tabs */}
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '16px' }}>
          {(
            [
              ['overview', 'Overview'],
              ['users', 'Users & Wallets'],
              ['groups', 'Groups & Policies'],
              ['payments', 'Payments'],
              ['access', 'Free access'],
              ['reports', 'Moderation & Reports'],
              ['support', 'Support Inbox'],
              ['settings', 'Platform Settings'],
              ['audit', 'Activity log'],
            ] as Array<[AdminTab, string]>
          ).map(([id, label]) => (
            <button
              key={id}
              type="button"
              className={activeTab === id ? 'btn-solid' : 'btn-outline'}
              style={{ padding: '6px 12px', fontSize: '0.86rem' }}
              onClick={() => setActiveTab(id)}
            >
              {label}
            </button>
          ))}
        </div>

        {error && (
          <div style={{ marginTop: '12px', fontSize: '0.9rem', fontWeight: 600 }}>{error}</div>
        )}
        {statusMsg && (
          <div
            style={{
              marginTop: '12px',
              padding: '8px 12px',
              background: 'var(--bg-input)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              fontSize: '0.9rem',
            }}
          >
            {statusMsg}
          </div>
        )}
      </div>

      {/* 1. OVERVIEW */}
      {!overview && !error && activeTab === 'overview' && <AdminDashboardSkeleton />}
      {overview && activeTab === 'overview' && (
        <>
          {refreshFailing && (
            <div
              role="alert"
              style={{
                marginBottom: '12px',
                padding: '10px 14px',
                borderRadius: '12px',
                border: '1px solid var(--warn)',
                background: 'var(--warn-soft)',
                color: 'var(--text-main)',
                fontSize: '0.9rem',
              }}
            >
              Live updates are paused: the server is not answering. The numbers below may be out of date. Retrying every 5 seconds.
            </div>
          )}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))',
              gap: '14px',
            }}
          >
            {([
              ['Registered wallets', overview.stats.total_users ?? 0, 'Everyone who has signed in with a wallet'],
              [
                'Paid members',
                overview.stats.paid_members ?? 0,
                overview.stats.membership_free ? 'Membership is free right now' : 'Active subscription',
              ],
              ['Signed in (last 24 h)', overview.stats.active_sessions ?? 0, 'People with a valid login'],
              ['Groups', overview.stats.total_groups ?? overview.stats.encrypted_groups ?? 0, 'Existing groups that have members'],
              ['Members\u2019 room messages', overview.stats.public_messages ?? 0, 'Messages members can still see'],
              ['Private messages (encrypted)', overview.stats.encrypted_dm_messages ?? 0, ''],
              ['Group messages (encrypted)', overview.stats.encrypted_group_messages ?? 0, ''],
              ['Open reports', overview.stats.open_reports ?? 0, ''],
              [
                'Online now',
                (overview.online?.authenticated_users ?? 0) + (overview.online?.public_viewers ?? 0),
                (overview.online?.admins_online ?? 0) > 0
                  ? `Includes ${overview.online?.admins_online} admin${overview.online?.admins_online === 1 ? '' : 's'}`
                  : 'Connected right now',
              ],
            ] as Array<[string, number, string]>).map(([label, val, hint]) => (
              <div key={label} className="deck-card" style={{ padding: '18px' }}>
                <div style={{ fontSize: '0.92rem', color: 'var(--text-secondary)', fontWeight: 500 }}>{label}</div>
                <div style={{ fontFamily: 'var(--font-display)', fontSize: '2.3rem', fontWeight: 500, marginTop: '4px', lineHeight: 1.1, fontVariantNumeric: 'lining-nums' }}>{val ?? 0}</div>
                {hint && <div style={{ marginTop: '6px', fontSize: '0.78rem', color: 'var(--text-muted)' }}>{hint}</div>}
              </div>
            ))}
          </div>
          {lastOkAt && (
            <div style={{ marginTop: '10px', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Updated {new Date(lastOkAt).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', second: '2-digit' })}
            </div>
          )}
        </>
      )}

      {/* 2. USERS & MODERATION */}
      {overview && activeTab === 'users' && (
        <div className="deck-card">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void runUserSearch(userQuery);
            }}
            style={{ display: 'flex', gap: '8px', marginBottom: '14px' }}
          >
            <Search size={16} style={{ marginTop: '10px' }} />
            <input
              type="text"
              placeholder="Search user_id, @username, or 0x wallet..."
              value={userQuery}
              onChange={(e) => setUserQuery(e.target.value)}
              style={{
                flex: 1,
                background: 'var(--bg-input)',
                border: '1px solid var(--border-strong)',
                borderRadius: '8px',
                padding: '8px 12px',
                color: 'var(--text-main)',
                fontSize: '0.9rem',
              }}
            />
            <button type="submit" className="btn-solid">
              Search
            </button>
          </form>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.9rem', textAlign: 'left' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '8px' }}>Member ID</th>
                  <th style={{ padding: '8px' }}>@Username</th>
                  <th style={{ padding: '8px' }}>Primary Wallet</th>
                  <th style={{ padding: '8px' }}>Balance</th>
                  <th style={{ padding: '8px' }}>Status</th>
                  <th style={{ padding: '8px' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.map((u) => (
                  <tr key={u.user_id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '8px', fontFamily: 'ui-monospace, monospace' }}>
                      {u.user_id.slice(0, 14)}...
                    </td>
                    <td style={{ padding: '8px', fontFamily: 'ui-monospace, monospace' }}>
                      {u.username ? `@${u.username}` : '—'}
                    </td>
                    <td style={{ padding: '8px', fontFamily: 'ui-monospace, monospace' }}>
                      {u.primary_wallet ? formatAddress(u.primary_wallet, 4) : '—'}
                    </td>
                    <td style={{ padding: '8px', fontWeight: 700 }}>
                      {formatEth(u.qualifying_balance_wei || '0', 3)} ETH
                    </td>
                    <td style={{ padding: '8px' }}>
                      <span className="audit-status" title={u.suspension_reason || ''}>
                        {u.account_status}
                        {u.account_status !== 'active' && u.suspended_until ? ` until ${formatDate(u.suspended_until)}` : ''}
                      </span>
                      {u.admin_role && (
                        <span className="audit-status" style={{ marginLeft: '4px' }}>
                          {u.admin_role}
                        </span>
                      )}
                    </td>
                    <td style={{ padding: '8px', display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                      <button
                        type="button"
                        className="btn-outline"
                        style={{ padding: '3px 8px', fontSize: '0.9rem' }}
                        onClick={async () => {
                          try {
                            const detail = await inspectAdminUser(u.user_id, adminToken);
                            setInspectedUser(detail);
                          } catch (err: any) {
                            setError(err?.message || 'Inspect user failed');
                          }
                        }}
                      >
                        Inspect
                      </button>
                      <button
                        type="button"
                        className="btn-outline"
                        style={{ padding: '3px 8px', fontSize: '0.9rem' }}
                        onClick={async () => {
                          try {
                            const res = await triggerAdminUserBalanceVerify(u.user_id, undefined, adminToken);
                            setStatusMsg(
                              `Verified balance for ${u.user_id.slice(0, 10)}: ${formatEth(res.user.qualifying_balance_wei || '0', 3)} ETH`
                            );
                            loadAdminData();
                          } catch (err: any) {
                            setError(err?.message || 'RPC balance verify failed');
                          }
                        }}
                      >
                        Check balance
                      </button>
                      <button
                        type="button"
                        className="btn-outline"
                        style={{ padding: '3px 8px', fontSize: '0.9rem' }}
                        onClick={async () => {
                          try {
                            const who = u.username ? `@${u.username}` : u.user_id;
                            if (u.account_status === 'active') {
                              const ask = askModeration('mute', who);
                              if (!ask) return;
                              await moderateAdminUser(u.user_id, { action_type: 'mute', ...ask }, adminToken);
                              setStatusMsg(`${who} muted${ask.duration_hours ? ` for ${ask.duration_hours} h` : ' until restored'}.`);
                            } else {
                              if (!confirm(`Restore ${who} to full access?`)) return;
                              await moderateAdminUser(u.user_id, { action_type: 'restore', reason: 'Restored by admin' }, adminToken);
                              setStatusMsg(`${who} restored.`);
                            }
                            setError(null);
                            loadAdminData();
                          } catch (err: any) {
                            setError(err?.message || 'User moderation failed');
                          }
                        }}
                      >
                        {u.account_status === 'active' ? 'Mute' : 'Restore'}
                      </button>
                      <button
                        type="button"
                        className="btn-outline"
                        style={{ padding: '3px 8px', fontSize: '0.9rem' }}
                        onClick={async () => {
                          try {
                            const who = u.username ? `@${u.username}` : u.user_id;
                            const ask = askModeration('suspend', who);
                            if (!ask) return;
                            await moderateAdminUser(u.user_id, { action_type: 'suspend', ...ask }, adminToken);
                            setStatusMsg(`${who} suspended${ask.duration_hours ? ` for ${ask.duration_hours} h` : ' until restored'}.`);
                            setError(null);
                            loadAdminData();
                          } catch (err: any) {
                            setError(err?.message || 'User suspension failed');
                          }
                        }}
                      >
                        Suspend
                      </button>
                      {overview.role === 'superadmin' && (
                        <button
                          type="button"
                          className="btn-outline"
                          style={{ padding: '3px 8px', fontSize: '0.9rem' }}
                          onClick={async () => {
                            try {
                              const nextRole = u.admin_role ? null : 'moderator';
                              await setAdminUserRole(u.user_id, nextRole, adminToken);
                              loadAdminData();
                            } catch (err: any) {
                              setError(err?.message || 'Role change failed');
                            }
                          }}
                        >
                          {u.admin_role ? 'Remove role' : 'Make moderator'}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 3. GROUPS & ACCESS POLICIES */}
      {overview && activeTab === 'groups' && (
        <div className="deck-card" style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div className="deck-title">
            <Users size={18} /> Groups and who can join ({groups.length})
          </div>
          {groups.map((g) => (
            <div
              key={g.group_id}
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '12px',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '10px',
                fontSize: '0.9rem',
                flexWrap: 'wrap',
                gap: '8px',
              }}
            >
              <div>
                <strong>{g.name}</strong> (<code>{g.group_id}</code>) &bull; Created by{' '}
                <strong>
                  {g.creator_username
                    ? `@${g.creator_username}`
                    : g.creator_wallet
                      ? formatAddress(g.creator_wallet, 4)
                      : g.creator_user_id}
                </strong>
                {g.creator_username && g.creator_wallet ? ` (${formatAddress(g.creator_wallet, 4)})` : ''}{' '}
                &bull; Epoch #{g.current_epoch} &bull;{' '}
                {g.active_member_count} members &bull; Visibility: <strong>{g.policy.visibility}</strong>{' '}
                &bull; Status:{' '}
                <strong style={{ color: g.policy.is_paid ? 'var(--accent)' : 'var(--ok)' }}>
                  {g.policy.is_paid
                    ? `Paid group (${Number(g.policy.entry_fee_usd || 0) > 0
                      ? `$${Number(g.policy.entry_fee_usd).toFixed(2)}/month · $${(Number(g.policy.entry_fee_yearly_usd || 0) > 0 ? Number(g.policy.entry_fee_yearly_usd) : Number(g.policy.entry_fee_usd) * 12).toFixed(2)}/year`
                      : `${g.policy.entry_fee_eth || '0'} ETH`})`
                    : 'Free group'}
                </strong>
                {g.empty && <span style={{ color: 'var(--warn)' }}> &bull; No members left (not counted)</span>}
              </div>
              <div style={{ display: 'flex', gap: '6px' }}>
                <button
                  type="button"
                  className="btn-outline"
                  style={{
                    padding: '4px 10px',
                    fontSize: '0.9rem',
                    borderColor: g.policy.is_paid ? 'var(--accent)' : undefined,
                    color: g.policy.is_paid ? 'var(--accent)' : undefined,
                  }}
                  onClick={async () => {
                    const isPaid = confirm(`Make "${g.name}" a PAID group (monthly / yearly subscription)? (Cancel = free group)`);
                    let fee = String(Number(g.policy.entry_fee_usd || 0) > 0 ? g.policy.entry_fee_usd : '10');
                    let yearlyFee = String(Number(g.policy.entry_fee_yearly_usd || 0));
                    if (isPaid) {
                      const promptFee = prompt('MONTHLY price in US dollars (e.g. 10). Members pay the ETH equivalent for 30 days:', fee);
                      if (promptFee === null) return;
                      fee = promptFee;
                      if (!(Number(fee) > 0)) {
                        setError('Enter a monthly price greater than 0 for a paid group.');
                        return;
                      }
                      const promptYearly = prompt(
                        `YEARLY price in US dollars for 365 days. Leave 0 for automatic (12 x monthly = $${(Number(fee) * 12).toFixed(2)}):`,
                        yearlyFee
                      );
                      if (promptYearly === null) return;
                      yearlyFee = promptYearly;
                      if (!(Number(yearlyFee) >= 0)) {
                        setError('The yearly price must be 0 (automatic) or more.');
                        return;
                      }
                    }
                    try {
                      await updateGroupPolicy(
                        g.group_id,
                        {
                          description: g.policy.description || '',
                          visibility: g.policy.visibility,
                          min_eth_balance_eth: g.policy.min_eth_balance_eth || '0',
                          require_invitation: g.policy.require_invitation,
                          is_paid: isPaid,
                          entry_fee_usd: isPaid ? Number(fee) : 0,
                          entry_fee_yearly_usd: isPaid ? Number(yearlyFee) : 0,
                        },
                        adminToken
                      );
                      loadAdminData();
                      setStatusMsg(`Group "${g.name}" policy updated.`);
                    } catch (err: any) {
                      setError(err?.message || 'Update group policy failed');
                    }
                  }}
                >
                  {g.policy.is_paid ? `Edit Prices ($${Number(g.policy.entry_fee_usd || 0).toFixed(2)}/mo)` : 'Set as Paid Group'}
                </button>
                {overview?.role === 'superadmin' && (
                  <button
                    type="button"
                    className="btn-outline"
                    style={{ padding: '4px 10px', fontSize: '0.9rem', borderColor: 'var(--danger)', color: 'var(--danger)' }}
                    onClick={async () => {
                      const typed = prompt(
                        `Delete "${g.name}" for good? This removes its ${g.active_member_count ?? 0} members, all messages and files. It cannot be undone.\n\nType the group name to confirm:`
                      );
                      if (typed === null) return;
                      if (typed.trim() !== g.name) {
                        setError('The name did not match, so nothing was deleted.');
                        return;
                      }
                      try {
                        const res = await adminDeleteGroup(g.group_id, adminToken);
                        setError(null);
                        setStatusMsg(`Group "${res.name}" deleted (${res.removed_messages} messages, ${res.removed_files} files removed).`);
                        loadAdminData();
                      } catch (err: any) {
                        setError(err?.message || 'Could not delete the group');
                      }
                    }}
                  >
                    Delete group
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* PAYMENTS: every payment, with the period it bought and a retry for ones stuck pending */}
      {overview && activeTab === 'payments' && (
        <div className="deck-card" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div className="deck-title">Payments &amp; subscriptions</div>
          {payments.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No payments yet.</div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.9rem' }}>
                <thead>
                  <tr style={{ textAlign: 'left', color: 'var(--text-muted)' }}>
                    <th style={{ padding: '6px' }}>Date</th>
                    <th style={{ padding: '6px' }}>Wallet</th>
                    <th style={{ padding: '6px' }}>For</th>
                    <th style={{ padding: '6px' }}>Period</th>
                    <th style={{ padding: '6px' }}>Amount</th>
                    <th style={{ padding: '6px' }}>Status</th>
                    <th style={{ padding: '6px' }} />
                  </tr>
                </thead>
                <tbody>
                  {payments.map((p) => (
                    <tr key={p.payment_id} style={{ borderTop: '1px solid var(--border-subtle)' }}>
                      <td style={{ padding: '6px' }}>{formatDate(p.verified_at || p.created_at)}</td>
                      <td style={{ padding: '6px', fontFamily: 'ui-monospace, monospace' }}>
                        {p.wallet_address ? formatAddress(p.wallet_address) : '—'}
                      </td>
                      <td style={{ padding: '6px' }}>
                        {(p.metadata?.purpose || 'platform_entry') === 'group_entry'
                          ? `Group ${p.metadata?.target_id || ''}`
                          : 'Membership'}
                      </td>
                      <td style={{ padding: '6px' }}>{p.metadata?.billing_period || 'monthly'}</td>
                      <td style={{ padding: '6px', fontFamily: 'ui-monospace, monospace' }}>
                        {p.status === 'verified' ? `${p.amount_formatted} ${p.currency}` : '—'}
                      </td>
                      <td style={{ padding: '6px' }} title={p.error_message || ''}>{p.status}</td>
                      <td style={{ padding: '6px' }}>
                        {p.status !== 'verified' && (
                          <button
                            type="button"
                            className="btn-outline"
                            style={{ padding: '3px 9px', fontSize: '0.9rem' }}
                            onClick={async () => {
                              try {
                                const r = await retryAdminPayment(p.payment_id, adminToken);
                                setStatusMsg(
                                  r.success
                                    ? 'Payment verified and access extended.'
                                    : `Payment not credited (${r.status}).`
                                );
                                loadAdminData();
                              } catch (err: any) {
                                setError(err?.message || 'Retry failed');
                              }
                            }}
                          >
                            Retry
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Support inbox (talk to admin) */}
      {activeTab === 'support' && <AdminSupportInbox adminToken={adminToken} />}

      {/* FREE ACCESS (no payment): membership or one group */}
      {overview && activeTab === 'access' && (
        <AdminFreeAccess adminToken={adminToken} role={overview.role} onUnauthorized={onLogout} />
      )}

      {/* 5. MODERATION & ABUSE REPORTS */}
      {overview && activeTab === 'reports' && (
        <div className="deck-card" style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div className="deck-title">
            <Flag size={18} /> Abuse &amp; Public Chat Moderation Queue ({reports.length})
          </div>
          {reports.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>No reports filed.</div>
          ) : (
            reports.map((r) => (
              <div
                key={r.report_id}
                style={{
                  padding: '12px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '10px',
                  fontSize: '0.9rem',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '10px',
                }}
              >
                <div>
                  <div>
                    <strong>[{r.status.toUpperCase()}]</strong> Scope: <code>{r.scope_type}</code> •
                    Reason: <strong>{r.reason}</strong>
                  </div>
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
                    Reporter: {r.reporter_user_id} • Target: {r.target_user_id || '—'} • Message:{' '}
                    {r.message_id || '—'} • {formatDate(r.created_at)}
                  </div>
                  {r.details && (
                    <div style={{ marginTop: '6px', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                      &ldquo;{r.details}&rdquo;
                    </div>
                  )}
                  {r.status !== 'open' && r.resolution_note && (
                    <div style={{ marginTop: '4px', color: 'var(--text-secondary)', fontSize: '0.86rem' }}>
                      Outcome: {r.resolution_note}
                    </div>
                  )}
                </div>
                <div style={{ display: 'flex', gap: '6px' }}>
                  {r.scope_type === 'public_chat' && r.message_id && (
                    <button
                      type="button"
                      className="btn-outline"
                      style={{ padding: '4px 10px', fontSize: '0.9rem' }}
                      onClick={async () => {
                        try {
                          await deletePublicChatMessage(
                            r.message_id,
                            'Removed via moderation queue',
                            adminToken
                          );
                          setStatusMsg(`Deleted public message ${r.message_id}`);
                        } catch (err: any) {
                          setError(err?.message || 'Delete message failed');
                        }
                      }}
                    >
                      <Trash2 size={12} />
                      <span>Delete Public Msg</span>
                    </button>
                  )}
                  {r.status === 'open' && (
                    <>
                      <button
                        type="button"
                        className="btn-solid"
                        style={{ padding: '4px 10px', fontSize: '0.9rem' }}
                        onClick={async () => {
                          try {
                            const note = prompt('What was done? (saved with the report)', 'Action taken');
                            if (note === null) return;
                            await resolveAdminReport(r.report_id, 'resolved', note.trim() || 'Action taken', adminToken);
                            loadAdminData();
                          } catch (err: any) {
                            setError(err?.message || 'Resolve report failed');
                          }
                        }}
                      >
                        Resolve
                      </button>
                      <button
                        type="button"
                        className="btn-outline"
                        style={{ padding: '4px 10px', fontSize: '0.9rem' }}
                        onClick={async () => {
                          try {
                            await resolveAdminReport(r.report_id, 'dismissed', 'Dismissed', adminToken);
                            loadAdminData();
                          } catch (err: any) {
                            setError(err?.message || 'Dismiss report failed');
                          }
                        }}
                      >
                        Dismiss
                      </button>
                    </>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* 6. PLATFORM SETTINGS */}
      {overview && activeTab === 'settings' && (
        <div className="deck-card admin-settings-card">
          <div className="deck-header" style={{ marginBottom: 0 }}>
            <div>
              <div className="deck-title">
                <Settings size={18} /> Platform settings
              </div>
              <div className="deck-subtitle" style={{ marginTop: '4px' }}>
                Manage username rules, members&apos; room moderation limits, and payment configuration.
              </div>
            </div>
          </div>

          <section className="admin-settings-section">
            <div className="admin-settings-section-head">
              <Megaphone size={16} /> Banner for everyone
            </div>
            <div className="admin-settings-grid">
              <div className="admin-settings-field">
                <label className="admin-settings-label" htmlFor="ann-text">
                  Message at the top of the app
                </label>
                <textarea
                  id="ann-text"
                  className="admin-settings-input"
                  style={{ height: 'auto', minHeight: 64, padding: '10px 12px', resize: 'vertical' }}
                  maxLength={280}
                  placeholder="e.g. Maintenance Sunday 10 pm, chats may be slow for 20 minutes"
                  value={settings.announcement_text || ''}
                  onChange={(e) => setSettings({ ...settings, announcement_text: e.target.value })}
                />
                <div className="admin-settings-hint">
                  Empty = no banner. Members can close it; changing the text shows it again. {(settings.announcement_text || '').length}/280
                </div>
              </div>
              <div className="admin-settings-grid admin-settings-grid--two">
                <div className="admin-settings-field">
                  <label className="admin-settings-label" htmlFor="ann-level">Style</label>
                  <select
                    id="ann-level"
                    className="admin-settings-input"
                    value={settings.announcement_level === 'warning' ? 'warning' : 'info'}
                    onChange={(e) => setSettings({ ...settings, announcement_level: e.target.value })}
                  >
                    <option value="info">Information</option>
                    <option value="warning">Warning</option>
                  </select>
                </div>
                <div className="admin-settings-field">
                  <label className="admin-settings-label" htmlFor="ann-end">Hide after (optional)</label>
                  <input
                    id="ann-end"
                    type="datetime-local"
                    className="admin-settings-input"
                    value={(() => {
                      const d = settings.announcement_ends_at ? new Date(settings.announcement_ends_at) : null;
                      if (!d || Number.isNaN(d.getTime())) return '';
                      const local = new Date(d.getTime() - d.getTimezoneOffset() * 60000);
                      return local.toISOString().slice(0, 16);
                    })()}
                    onChange={(e) =>
                      setSettings({
                        ...settings,
                        announcement_ends_at: e.target.value ? new Date(e.target.value).toISOString() : '',
                      })
                    }
                  />
                  <div className="admin-settings-hint">Empty = until you remove the text.</div>
                </div>
              </div>
            </div>
          </section>

          <section className="admin-settings-section">
            <div className="admin-settings-section-head">
              <Users size={16} /> Usernames &amp; Identity
            </div>
            <div className="admin-settings-grid admin-settings-grid--two">
              <SettingNumber
                label="Hours between username changes"
                hint="0 = members can change their username anytime."
                value={settings.username_cooldown_hours}
                fallback={24}
                min={0}
                max={720}
                onChange={(n) => setSettings({ ...settings, username_cooldown_hours: n })}
              />

              <SettingNumber
                label="Days an old username stays reserved"
                hint="After a rename, nobody else can take the old name for this long (stops impersonation)."
                value={settings.username_reservation_days}
                fallback={30}
                min={0}
                max={365}
                onChange={(n) => setSettings({ ...settings, username_reservation_days: n })}
              />
            </div>
          </section>

          <section className="admin-settings-section">
            <div className="admin-settings-section-head">
              <FileText size={16} /> Members&apos; Room
            </div>
            <div className="admin-settings-grid">
              <SettingNumber
                label="Longest message (characters)"
                hint="Maximum length allowed per message (50–4000)."
                value={settings.public_chat_max_length}
                fallback={1000}
                min={50}
                max={4000}
                onChange={(n) => setSettings({ ...settings, public_chat_max_length: n })}
              />

              <SettingNumber
                label="Minutes a message can be edited"
                hint="0 = messages cannot be edited."
                value={
                  settings.public_chat_edit_window_seconds !== undefined
                    ? Math.round(Number(settings.public_chat_edit_window_seconds) / 60)
                    : undefined
                }
                fallback={15}
                min={0}
                max={1440}
                onChange={(n) => setSettings({ ...settings, public_chat_edit_window_seconds: n * 60 })}
              />

              <SettingNumber
                label="Keep messages for (days)"
                hint="Older messages are no longer shown."
                value={settings.public_chat_retention_days}
                fallback={90}
                min={1}
                max={3650}
                onChange={(n) => setSettings({ ...settings, public_chat_retention_days: n })}
              />
            </div>
          </section>

          {/* Direct Platform Admission Paywall & ETH USD Valuation */}
          <section className="admin-settings-panel">
            <div className="admin-settings-section-head" style={{ borderBottomColor: 'var(--border-subtle)' }}>
              <ShieldCheck size={16} /> Membership, Pricing &amp; Payments
            </div>

            <div className="admin-settings-grid admin-settings-grid--two">
              <div className="admin-settings-field">
                <label className="admin-settings-label">Payment network</label>
                <div className="dropdown-theme-toggle admin-network-toggle">
                  <button
                    type="button"
                    className={`dropdown-theme-btn ${Number(settings.default_balance_chain_id ?? 11155111) === 1 ? 'active' : ''}`}
                    onClick={() => setSettings({ ...settings, default_balance_chain_id: 1 })}
                  >
                    Ethereum Mainnet (1)
                  </button>
                  <button
                    type="button"
                    className={`dropdown-theme-btn ${Number(settings.default_balance_chain_id ?? 11155111) === 11155111 ? 'active' : ''}`}
                    onClick={() => setSettings({ ...settings, default_balance_chain_id: 11155111 })}
                  >
                    Sepolia Testnet (11155111)
                  </button>
                </div>
                <div className="admin-settings-hint">
                  Payments are accepted only on this network. Use Sepolia for testing and Mainnet for real money.
                </div>
              </div>

              <div className="admin-settings-field">
                <label className="admin-settings-label">Payment wallet (treasury address)</label>
                <input
                  type="text"
                  className="admin-settings-input admin-settings-input--mono"
                  value={settings.authorized_payment_destination ?? ''}
                  placeholder="0x... (required before anyone can pay)"
                  spellCheck={false}
                  autoComplete="off"
                  onChange={(e) => setSettings({ ...settings, authorized_payment_destination: e.target.value.trim() })}
                />
                <div className="admin-settings-hint">
                  All membership and paid-group ETH transfers must be sent to this address.
                </div>
              </div>
            </div>

            <div className="admin-settings-grid admin-settings-grid--two">
              <div className="admin-settings-field">
                <label className="admin-settings-label">Monthly price (USD $)</label>
                <input
                  type="number"
                  className="admin-settings-input"
                  min={0}
                  step="0.5"
                  value={settings.platform_entry_fee_usd ?? 0}
                  onChange={(e) => setSettings({ ...settings, platform_entry_fee_usd: Number(e.target.value) })}
                />
                <div className="admin-settings-hint">0 = free for everyone.</div>
              </div>

              <div className="admin-settings-field">
                <label className="admin-settings-label">Yearly price (USD $)</label>
                <input
                  type="number"
                  className="admin-settings-input"
                  min={0}
                  step="0.5"
                  value={settings.platform_yearly_fee_usd ?? 0}
                  onChange={(e) => setSettings({ ...settings, platform_yearly_fee_usd: Number(e.target.value) })}
                />
                <div className="admin-settings-hint">0 = automatic (12 &times; monthly).</div>
              </div>

              <div className="admin-settings-field">
                <label className="admin-settings-label">ETH price source</label>
                <select
                  className="admin-settings-input"
                  value={(settings.use_live_eth_price ?? true) ? 'live' : 'fixed'}
                  onChange={(e) => setSettings({ ...settings, use_live_eth_price: e.target.value === 'live' })}
                >
                  <option value="live">Live market rate (recommended)</option>
                  <option value="fixed">Fixed rate below</option>
                </select>
                <div className="admin-settings-hint">How USD prices are quoted in ETH.</div>
              </div>

              <div className="admin-settings-field">
                <label className="admin-settings-label">
                  {(settings.use_live_eth_price ?? true) ? 'Backup price of 1 ETH (USD)' : 'Price of 1 ETH (USD)'}
                </label>
                <input
                  type="number"
                  className="admin-settings-input"
                  value={settings.eth_usd_price ?? 2500}
                  onChange={(e) => setSettings({ ...settings, eth_usd_price: Number(e.target.value) })}
                />
                <div className="admin-settings-hint">
                  {(settings.use_live_eth_price ?? true)
                    ? 'Used if the live price feed is unavailable.'
                    : 'Fixed conversion rate for all quotes.'}
                </div>
              </div>
            </div>

            <div className="admin-settings-summary">
              Members pay ${Number(settings.platform_entry_fee_usd ?? 0).toFixed(2)}/month or $
              {(Number(settings.platform_yearly_fee_usd ?? 0) > 0
                ? Number(settings.platform_yearly_fee_usd)
                : Number(settings.platform_entry_fee_usd ?? 0) * 12
              ).toFixed(2)}
              /year (their choice), converted to ETH at payment time
              {(settings.use_live_eth_price ?? true)
                ? ' using the live market rate.'
                : ` at a fixed $${Number(settings.eth_usd_price ?? 2500).toFixed(0)} per ETH (~${(
                  (Number(settings.platform_entry_fee_usd ?? 0) || 0) / (Number(settings.eth_usd_price ?? 2500) || 1)
                ).toFixed(5)} ETH).`}
            </div>
          </section>

          <div className="admin-settings-footer">
            <span className="admin-settings-hint">
              Changes take effect immediately and are recorded in the activity log.
            </span>
            <button
              type="button"
              className="btn-solid"
              onClick={async () => {
                try {
                  const saved = await updateAdminSettings(settings, adminToken);
                  if (saved?.settings) setSettings(saved.settings);
                  setError(null);
                  setStatusMsg('Platform settings saved (recorded in the activity log).');
                } catch (err: any) {
                  setError(err?.message || 'Settings save failed');
                }
              }}
            >
              Save Platform Settings
            </button>
          </div>
        </div>
      )}

      {/* 7. AUDIT LOGS */}
      {overview && activeTab === 'audit' && (
        <div className="deck-card" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div className="deck-title">
            <FileText size={18} /> Activity log
          </div>
          {auditLogs.map((log) => (
            <div
              key={log.audit_id || log.log_id}
              style={{
                padding: '8px 12px',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                fontSize: '0.86rem',
                fontFamily: 'ui-monospace, monospace',
              }}
            >
              <div>
                [{new Date(log.created_at).toLocaleString()}] <strong>{log.event_type || log.action}</strong> •
                actor={log.actor_user_id} • target={log.target_type || log.entity_type}:{log.target_id || log.entity_id}
              </div>
              {log.details && (
                <div style={{ color: 'var(--text-muted)', marginTop: '4px', fontSize: '0.9rem', wordBreak: 'break-all' }}>
                  {JSON.stringify(log.details)}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* USER INSPECTOR MODAL */}
      {inspectedUser && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 350,
            background: 'rgba(0,0,0,0.78)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '16px',
          }}
          onClick={() => setInspectedUser(null)}
        >
          <div
            className="deck-card"
            style={{ maxWidth: '680px', width: '100%', maxHeight: '85vh', overflowY: 'auto' }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ fontWeight: 700 }}>
                Account History Inspector — {inspectedUser.user.user_id}
              </h3>
              <button className="btn-outline" style={{ padding: '4px 8px' }} onClick={() => setInspectedUser(null)}>
                <X size={15} />
              </button>
            </div>

            {/* WALLET & PAYMENT DIAGNOSTIC VIEW */}
            {inspectedUser.qualification_status && (
              <div
                style={{
                  marginTop: '12px',
                  padding: '12px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '10px',
                }}
              >
                <div style={{ fontWeight: 600, fontSize: '0.85rem', marginBottom: '8px' }}>
                  Wallet &amp; Payment Diagnostics
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '8px', fontSize: '0.86rem' }}>
                  <div style={{ padding: '6px 8px', background: 'var(--bg-main)', borderRadius: '6px' }}>
                    <div style={{ color: 'var(--text-muted)' }}>Verified Balance</div>
                    <div style={{ fontWeight: 700 }}>{inspectedUser.qualification_status.wallet_balance_eth} ETH</div>
                  </div>
                  <div style={{ padding: '6px 8px', background: 'var(--bg-main)', borderRadius: '6px' }}>
                    <div style={{ color: 'var(--text-muted)' }}>Verified Payments</div>
                    <div style={{ fontWeight: 700 }}>{inspectedUser.qualification_status.verified_payments_eth} ETH</div>
                  </div>
                  <div style={{ padding: '6px 8px', background: 'var(--bg-main)', borderRadius: '6px' }}>
                    <div style={{ color: 'var(--text-muted)' }}>Pending Payments</div>
                    <div style={{ fontWeight: 700 }}>{inspectedUser.qualification_status.pending_payments_count}</div>
                  </div>
                </div>
              </div>
            )}

            <pre
              style={{
                marginTop: '12px',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '10px',
                padding: '12px',
                fontSize: '0.9rem',
                overflowX: 'auto',
              }}
            >
              {JSON.stringify(inspectedUser, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};