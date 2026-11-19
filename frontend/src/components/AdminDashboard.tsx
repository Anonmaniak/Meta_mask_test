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
} from 'lucide-react';
import { formatAddress, formatEth } from '../services/web3';
import { AdminSupportInbox } from './AdminSupportInbox';
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
  fetchAdminReports,
  resolveAdminReport,
  deletePublicChatMessage,
  fetchAdminSettings,
  updateAdminSettings,
  fetchAdminAuditLogs,
} from '../services/platformApi';

interface AdminDashboardProps {
  e2eeProfile?: E2EEAccountProfile | null;
  adminToken: string;
  onLogout?: () => void;
}

type AdminTab = 'overview' | 'users' | 'groups' | 'reports' | 'support' | 'settings' | 'audit';

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

  const [error, setError] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
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

      if (activeTab === 'users') {
        const seq = ++userSearchSeqRef.current;
        const u = await fetchAdminUsers(userQueryRef.current, adminToken);
        if (seq === userSearchSeqRef.current) {
          setUsers(u.users);
        }
      } else if (activeTab === 'groups') {
        const g = await fetchAdminGroups(adminToken);
        setGroups(g.groups);
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
              <Shield size={20} /> Platform Governance &amp; RBAC Admin Console
            </div>
            <div className="deck-subtitle">
              Signed in as:{' '}
              <strong>
                {overview
                  ? `${overview.actor_user_id} (${overview.role.toUpperCase()})`
                  : e2eeProfile?.admin_role
                    ? `${e2eeProfile.username || e2eeProfile.user_id} (${e2eeProfile.admin_role.toUpperCase()})`
                    : 'Admin Console session'}
              </strong>{' '}
              &bull; Private E2EE ciphertexts are never readable by admins.
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
              ['reports', 'Moderation & Reports'],
              ['support', 'Support Inbox'],
              ['settings', 'Platform Settings'],
              ['audit', 'Audit Logs'],
            ] as Array<[AdminTab, string]>
          ).map(([id, label]) => (
            <button
              key={id}
              type="button"
              className={activeTab === id ? 'btn-solid' : 'btn-outline'}
              style={{ padding: '6px 12px', fontSize: '0.78rem' }}
              onClick={() => setActiveTab(id)}
            >
              {label}
            </button>
          ))}
        </div>

        {error && (
          <div style={{ marginTop: '12px', fontSize: '0.82rem', fontWeight: 600 }}>{error}</div>
        )}
        {statusMsg && (
          <div
            style={{
              marginTop: '12px',
              padding: '8px 12px',
              background: 'var(--bg-input)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              fontSize: '0.8rem',
            }}
          >
            {statusMsg}
          </div>
        )}
      </div>

      {/* 1. OVERVIEW */}
      {overview && activeTab === 'overview' && (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))',
            gap: '14px',
          }}
        >
          {[
            ['Total Accounts', overview.stats.total_users ?? 0],
            ['Active SIWE Sessions', overview.stats.active_sessions ?? 0],
            ['Encrypted Groups', overview.stats.total_groups ?? overview.stats.encrypted_groups ?? 0],
            ['Open Public Messages', overview.stats.public_messages ?? 0],
            ['E2EE DM Envelopes', overview.stats.encrypted_dm_messages ?? 0],
            ['E2EE Group Envelopes', overview.stats.encrypted_group_messages ?? 0],
            ['Open Abuse Reports', overview.stats.open_reports ?? 0],
            ['Online Right Now', (overview.online?.authenticated_users ?? 0) + (overview.online?.public_viewers ?? 0)],
          ].map(([label, val]) => (
            <div key={String(label)} className="deck-card" style={{ padding: '18px' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 700 }}>
                {String(label).toUpperCase()}
              </div>
              <div style={{ fontSize: '1.6rem', fontWeight: 800, marginTop: '4px' }}>{val ?? 0}</div>
            </div>
          ))}
        </div>
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
                fontSize: '0.84rem',
              }}
            />
            <button type="submit" className="btn-solid">
              Search
            </button>
          </form>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem', textAlign: 'left' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '8px' }}>Permanent ID</th>
                  <th style={{ padding: '8px' }}>@Username</th>
                  <th style={{ padding: '8px' }}>Primary Wallet</th>
                  <th style={{ padding: '8px' }}>Verified Balance</th>
                  <th style={{ padding: '8px' }}>Status / Role</th>
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
                      <span className="audit-status">{u.account_status}</span>
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
                        style={{ padding: '3px 8px', fontSize: '0.7rem' }}
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
                        style={{ padding: '3px 8px', fontSize: '0.7rem' }}
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
                        RPC Verify
                      </button>
                      <button
                        type="button"
                        className="btn-outline"
                        style={{ padding: '3px 8px', fontSize: '0.7rem' }}
                        onClick={async () => {
                          try {
                            const nextAct = u.account_status === 'active' ? 'mute' : 'restore';
                            await moderateAdminUser(
                              u.user_id,
                              { action_type: nextAct, reason: `Admin ${nextAct}` },
                              adminToken
                            );
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
                        style={{ padding: '3px 8px', fontSize: '0.7rem' }}
                        onClick={async () => {
                          try {
                            await moderateAdminUser(
                              u.user_id,
                              { action_type: 'suspend', reason: 'Admin suspension' },
                              adminToken
                            );
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
                          style={{ padding: '3px 8px', fontSize: '0.7rem' }}
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
                          {u.admin_role ? 'Revoke Role' : 'Make Mod'}
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
            <Users size={18} /> Encrypted Groups &amp; Access Rules ({groups.length})
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
                fontSize: '0.82rem',
                flexWrap: 'wrap',
                gap: '8px',
              }}
            >
              <div>
                <strong>{g.name}</strong> (<code>{g.group_id}</code>) &bull; Epoch #{g.current_epoch} &bull;{' '}
                {g.active_member_count} members &bull; Visibility: <strong>{g.policy.visibility}</strong>{' '}
                &bull; Status:{' '}
                <strong style={{ color: g.policy.is_paid ? '#eab308' : '#10b981' }}>
                  {g.policy.is_paid ? `PAID GROUP (${Number(g.policy.entry_fee_usd || 0) > 0 ? '$' + Number(g.policy.entry_fee_usd).toFixed(2) : (g.policy.entry_fee_eth || '0') + ' ETH'})` : 'FREE GROUP'}
                </strong>
              </div>
              <div style={{ display: 'flex', gap: '6px' }}>
                <button
                  type="button"
                  className="btn-outline"
                  style={{
                    padding: '4px 10px',
                    fontSize: '0.74rem',
                    borderColor: g.policy.is_paid ? '#eab308' : undefined,
                    color: g.policy.is_paid ? '#eab308' : undefined,
                  }}
                  onClick={async () => {
                    const isPaid = confirm(`Tag "${g.name}" as Paid Members Only? (Cancel for Free)`);
                    let fee = String(Number(g.policy.entry_fee_usd || 0) > 0 ? g.policy.entry_fee_usd : '10');
                    if (isPaid) {
                      const promptFee = prompt('Enter the group entry fee in US dollars (e.g. 10). Members pay the ETH equivalent:', fee);
                      if (promptFee === null) return;
                      fee = promptFee;
                      if (!(Number(fee) > 0)) {
                        setError('Enter an entry fee greater than 0 for a paid group.');
                        return;
                      }
                    }
                    try {
                      await updateGroupPolicy(
                        g.group_id,
                        {
                          description: g.policy.description || '',
                          visibility: g.policy.visibility,
                          min_level: g.policy.min_level,
                          min_eth_balance_eth: g.policy.min_eth_balance_eth || '0',
                          require_invitation: g.policy.require_invitation,
                          is_paid: isPaid,
                          entry_fee_usd: isPaid ? Number(fee) : 0,
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
                  {g.policy.is_paid ? `Edit Price ($${Number(g.policy.entry_fee_usd || 0).toFixed(2)})` : 'Set as Paid Group'}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Support inbox (talk to admin) */}
      {activeTab === 'support' && <AdminSupportInbox adminToken={adminToken} />}

      {/* 5. MODERATION & ABUSE REPORTS */}
      {overview && activeTab === 'reports' && (
        <div className="deck-card" style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div className="deck-title">
            <Flag size={18} /> Abuse &amp; Public Chat Moderation Queue ({reports.length})
          </div>
          {reports.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.82rem' }}>No reports filed.</div>
          ) : (
            reports.map((r) => (
              <div
                key={r.report_id}
                style={{
                  padding: '12px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '10px',
                  fontSize: '0.8rem',
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
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.74rem' }}>
                    Reporter: {r.reporter_user_id} • Target: {r.target_user_id || '—'} • Message:{' '}
                    {r.message_id || '—'}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '6px' }}>
                  {r.scope_type === 'public_chat' && r.message_id && (
                    <button
                      type="button"
                      className="btn-outline"
                      style={{ padding: '4px 10px', fontSize: '0.72rem' }}
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
                        style={{ padding: '4px 10px', fontSize: '0.72rem' }}
                        onClick={async () => {
                          try {
                            await resolveAdminReport(r.report_id, 'resolved', 'Action taken', adminToken);
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
                        style={{ padding: '4px 10px', fontSize: '0.72rem' }}
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
        <div className="deck-card" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div className="deck-title">
            <Settings size={18} /> Live Platform Policy Configuration
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
              gap: '14px',
              fontSize: '0.82rem',
              alignItems: 'end',
            }}
          >
            <div>
              <div style={{ marginBottom: '6px', color: 'var(--text-muted)', fontSize: '0.78rem' }}>
                Username change Hrs
              </div>
              <input
                type="number"
                min={0}
                max={720}
                value={settings.username_cooldown_hours ?? 24}
                onChange={(e) =>
                  setSettings({ ...settings, username_cooldown_hours: Number(e.target.value) })
                }
                style={{
                  width: '100%',
                  maxWidth: '180px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-strong)',
                  borderRadius: '8px',
                  padding: '8px 12px',
                  color: 'var(--text-main)',
                  fontSize: '0.84rem',
                }}
              />
            </div>

            <div>
              <div style={{ marginBottom: '6px', color: 'var(--text-muted)', fontSize: '0.78rem' }}>
                Active Ethereum Network
              </div>
              <div className="dropdown-theme-toggle" style={{ maxWidth: '380px' }}>
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
            </div>

            {/* Direct Platform Admission Paywall & ETH USD Valuation */}
            <div
              style={{
                gridColumn: '1 / -1',
                padding: '14px 16px',
                background: 'rgba(59, 130, 246, 0.08)',
                border: '1px solid rgba(59, 130, 246, 0.25)',
                borderRadius: '10px',
                display: 'flex',
                flexDirection: 'column',
                gap: '10px',
              }}
            >
              <div style={{ fontWeight: 600, color: '#60a5fa', display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.88rem' }}>
                <ShieldCheck size={16} /> Membership Price &amp; ETH Conversion
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '10px' }}>
                <div>
                  <div style={{ marginBottom: '4px', color: 'var(--text-muted)' }}>Membership Price (USD $, 0 = free):</div>
                  <input
                    type="number"
                    min={0}
                    step="0.5"
                    value={settings.platform_entry_fee_usd ?? 10}
                    onChange={(e) => setSettings({ ...settings, platform_entry_fee_usd: Number(e.target.value) })}
                    style={{
                      width: '100%',
                      background: 'var(--bg-input)',
                      border: '1px solid var(--border-strong)',
                      borderRadius: '6px',
                      padding: '6px 10px',
                      color: 'var(--text-main)',
                    }}
                  />
                </div>

                <div>
                  <div style={{ marginBottom: '4px', color: 'var(--text-muted)' }}>ETH Rate Source:</div>
                  <select
                    value={(settings.use_live_eth_price ?? true) ? 'live' : 'fixed'}
                    onChange={(e) => setSettings({ ...settings, use_live_eth_price: e.target.value === 'live' })}
                    style={{
                      width: '100%',
                      background: 'var(--bg-input)',
                      border: '1px solid var(--border-strong)',
                      borderRadius: '6px',
                      padding: '6px 10px',
                      color: 'var(--text-main)',
                    }}
                  >
                    <option value="live">Live market rate (recommended)</option>
                    <option value="fixed">Fixed rate below</option>
                  </select>
                </div>

                <div>
                  <div style={{ marginBottom: '4px', color: 'var(--text-muted)' }}>
                    {(settings.use_live_eth_price ?? true) ? 'Fallback 1 ETH (USD $) if live rate is down:' : 'Fixed 1 ETH (USD $):'}
                  </div>
                  <input
                    type="number"
                    value={settings.eth_usd_price ?? 2500}
                    onChange={(e) => setSettings({ ...settings, eth_usd_price: Number(e.target.value) })}
                    style={{
                      width: '100%',
                      background: 'var(--bg-input)',
                      border: '1px solid var(--border-strong)',
                      borderRadius: '6px',
                      padding: '6px 10px',
                      color: 'var(--text-main)',
                    }}
                  />
                </div>

                <div>
                  <div style={{ marginBottom: '4px', color: 'var(--text-muted)' }}>Treasury Destination Address:</div>
                  <input
                    type="text"
                    value={settings.authorized_payment_destination ?? ''}
                    onChange={(e) => setSettings({ ...settings, authorized_payment_destination: e.target.value })}
                    style={{
                      width: '100%',
                      background: 'var(--bg-input)',
                      border: '1px solid var(--border-strong)',
                      borderRadius: '6px',
                      padding: '6px 10px',
                      color: 'var(--text-main)',
                      fontFamily: 'ui-monospace, monospace',
                      fontSize: '0.78rem',
                    }}
                  />
                </div>
              </div>

              <div style={{ fontSize: '0.82rem', color: '#10b981', fontWeight: 600 }}>
                Members pay ${Number(settings.platform_entry_fee_usd ?? 10).toFixed(2)} USD, converted to ETH at payment time
                {(settings.use_live_eth_price ?? true)
                  ? ' using the live market rate.'
                  : ` at a fixed $${Number(settings.eth_usd_price ?? 2500).toFixed(0)} per ETH (~${(
                    (Number(settings.platform_entry_fee_usd ?? 10) || 0) / (Number(settings.eth_usd_price ?? 2500) || 1)
                  ).toFixed(5)} ETH).`}
              </div>
            </div>
          </div>

          <button
            type="button"
            className="btn-solid"
            style={{ alignSelf: 'flex-start' }}
            onClick={async () => {
              try {
                await updateAdminSettings(settings, adminToken);
                setStatusMsg('Platform settings persisted & audit logged.');
              } catch (err: any) {
                setError(err?.message || 'Settings save failed');
              }
            }}
          >
            Save Platform Settings
          </button>
        </div>
      )}

      {/* 7. AUDIT LOGS */}
      {overview && activeTab === 'audit' && (
        <div className="deck-card" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div className="deck-title">
            <FileText size={18} /> Immutable Security &amp; Governance Audit Logs
          </div>
          {auditLogs.map((log) => (
            <div
              key={log.audit_id || log.log_id}
              style={{
                padding: '8px 12px',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                fontSize: '0.76rem',
                fontFamily: 'ui-monospace, monospace',
              }}
            >
              <div>
                [{new Date(log.created_at).toLocaleString()}] <strong>{log.event_type || log.action}</strong> •
                actor={log.actor_user_id} • target={log.target_type || log.entity_type}:{log.target_id || log.entity_id}
              </div>
              {log.details && (
                <div style={{ color: 'var(--text-muted)', marginTop: '4px', fontSize: '0.72rem', wordBreak: 'break-all' }}>
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

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '8px', fontSize: '0.76rem' }}>
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
                fontSize: '0.74rem',
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