import React, { useState, useEffect } from 'react';
import { friendlyError } from '../services/friendlyError';
import {
  Users,
  UserCog,
  Smartphone,
  Wallet,
  Trash2,
  UserPlus,
  UserMinus,
  AlertTriangle,
  X,
  Link2,
  LogOut,
  Award,
} from 'lucide-react';
import { fetchIdentitySecurityEvents } from '../services/e2eeApi.ts';
import { ListRowsSkeleton } from './Skeleton';
import type { E2EEAccountProfile, E2EEGroupRecord } from '../services/e2eeApi.ts';
import type { PeerActiveDeviceDescriptor } from '../services/olmService.ts';
import {
  fetchGroupPolicy,
  updateGroupPolicy,
  fetchGroupJoinRequests,
  declineGroupJoinRequest,
  setGroupMemberRole,
  type GroupJoinRequestRecord,
} from '../services/platformApi.ts';
import { formatAddress, formatEth } from '../services/web3.ts';

const modalBackdropStyle: React.CSSProperties = {
  position: 'fixed',
  inset: 0,
  zIndex: 1300,
  background: 'var(--backdrop)',
  backdropFilter: 'blur(6px)',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  padding: '16px',
};

const modalCardStyle: React.CSSProperties = {
  width: '100%',
  maxWidth: '620px',
  maxHeight: '88vh',
  overflowY: 'auto',
  background: 'var(--bg-card)',
  border: '1px solid var(--border-strong)',
  borderRadius: '18px',
  padding: '24px',
  boxShadow: 'var(--shadow-console)',
  display: 'flex',
  flexDirection: 'column',
  gap: '16px',
};

interface MlsGroupSecurityModalProps {
  open: boolean;
  onClose: () => void;
  group: E2EEGroupRecord | null;
  currentUserId: string;
  /** Resolves to 'invited' when the person must still Accept, 'active' when they joined directly. */
  onAddMember: (identifier: string) => Promise<'active' | 'invited' | void>;
  onRemoveMember: (targetUserId: string) => Promise<void>;
  onLeaveGroup?: () => Promise<void>;
  /** Group admins: delete the whole group (members, messages and files). */
  onDeleteGroup?: () => Promise<void>;
  onGroupUpdated?: () => Promise<void>;
  /** Tab to show when the window opens ("invites" = the join requests tab, e.g. from a new join request alert). */
  initialTab?: 'members' | 'policy' | 'invites';
}

export const MlsGroupSecurityModal: React.FC<MlsGroupSecurityModalProps> = ({
  open,
  onClose,
  group,
  currentUserId,
  onAddMember,
  onRemoveMember,
  onLeaveGroup,
  onDeleteGroup,
  onGroupUpdated,
  initialTab,
}) => {
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteText, setDeleteText] = useState('');
  const [tab, setTab] = useState<'members' | 'policy' | 'invites'>('members');
  // Paid status is shown read-only here (only the platform admin sets prices, in /Admin456).
  const [paidInfo, setPaidInfo] = useState<{ isPaid: boolean; monthlyUsd: number } | null>(null);
  const [memberInput, setMemberInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [infoMsg, setInfoMsg] = useState<string | null>(null);

  // Access Policy form state
  const [desc, setDesc] = useState('');
  const [visibility, setVisibility] = useState<'public' | 'invite_only'>('invite_only');
  const [minEth, setMinEth] = useState('0');
  const [requireInvite, setRequireInvite] = useState(true);

  // Join requests (invite links were removed: admins add people, who Accept or Reject)
  const [joinRequests, setJoinRequests] = useState<GroupJoinRequestRecord[]>([]);

  const activeMembers = group ? group.members.filter((m) => m.status === 'active') : [];
  const isGroupAdmin = activeMembers.some(
    (m) => m.user_id === currentUserId && m.role === 'admin'
  );

  useEffect(() => {
    if (open) setTab(initialTab && (initialTab !== 'invites' || isGroupAdmin) ? initialTab : 'members');
  }, [open, initialTab, isGroupAdmin]);

  useEffect(() => {
    if (!open || !group) return;
    setErrorMsg(null);
    setInfoMsg(null);
    fetchGroupPolicy(group.group_id)
      .then((res) => {
        setPaidInfo({
          isPaid: Boolean((res.policy as any).is_paid),
          monthlyUsd: Number((res.policy as any).entry_fee_usd || 0),
        });
        setDesc(res.policy.description || '');
        setVisibility(res.policy.visibility || 'invite_only');
        setMinEth(res.policy.min_eth_balance_eth || '0');
        setRequireInvite(Boolean(res.policy.require_invitation));
      })
      .catch(() => { });

    if (isGroupAdmin) {
      fetchGroupJoinRequests(group.group_id)
        .then((r) => setJoinRequests(r.requests || []))
        .catch(() => { });
    }
  }, [open, group?.group_id, isGroupAdmin]);

  if (!open || !group) return null;

  const uniqueUsers = Array.from(new Set(activeMembers.map((m) => m.user_id)));
  // People an admin added who have not pressed Accept yet
  const invitedUsers = Array.from(
    new Map(
      group.members
        .filter((m) => m.status === 'invited' && !uniqueUsers.includes(m.user_id))
        .map((m) => [m.user_id, m.username || null] as const)
    ).entries()
  );

  const handleSavePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErrorMsg(null);
    setInfoMsg(null);
    try {
      await updateGroupPolicy(group.group_id, {
        description: desc,
        visibility,
        min_eth_balance_eth: minEth || '0',
        require_invitation: requireInvite,
      });
      setInfoMsg('Group settings saved.');
      if (onGroupUpdated) await onGroupUpdated();
    } catch (err: any) {
      setErrorMsg(friendlyError(err, 'Could not save the group settings. Please try again.'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={modalBackdropStyle} onClick={onClose}>
      <div style={modalCardStyle} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Users size={20} />
            <h3 style={{ fontSize: '1.45rem', fontWeight: 500, letterSpacing: '-0.015em', margin: 0 }}>
              Group settings: {group.name}
            </h3>
          </div>
          <button className="btn-outline" style={{ padding: '6px' }} onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        {/* Sub-navigation */}
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          <button
            type="button"
            className={tab === 'members' ? 'btn-solid' : 'btn-outline'}
            style={{ padding: '6px 12px', fontSize: '0.86rem' }}
            onClick={() => setTab('members')}
          >
            Members ({uniqueUsers.length})
          </button>
          <button
            type="button"
            className={tab === 'policy' ? 'btn-solid' : 'btn-outline'}
            style={{ padding: '6px 12px', fontSize: '0.86rem' }}
            onClick={() => setTab('policy')}
          >
            <Award size={13} />
            <span>Who can join</span>
          </button>
          {isGroupAdmin && (
            <button
              type="button"
              className={tab === 'invites' ? 'btn-solid' : 'btn-outline'}
              style={{ padding: '6px 12px', fontSize: '0.86rem' }}
              onClick={() => setTab('invites')}
            >
              <Link2 size={13} />
              <span>Join requests ({joinRequests.length})</span>
            </button>
          )}
        </div>

        {errorMsg && (
          <div
            style={{
              padding: '10px 12px',
              borderRadius: '8px',
              border: '1px solid var(--border-strong)',
              fontSize: '0.86rem',
            }}
          >
            {errorMsg}
          </div>
        )}
        {infoMsg && (
          <div
            style={{
              padding: '10px 12px',
              borderRadius: '8px',
              background: 'var(--bg-input)',
              border: '1px solid var(--border-subtle)',
              fontSize: '0.86rem',
            }}
          >
            {infoMsg}
          </div>
        )}

        {tab === 'members' && (
          <>
            {isGroupAdmin && (
              <form
                onSubmit={async (e) => {
                  e.preventDefault();
                  if (!memberInput.trim() || busy) return;
                  setBusy(true);
                  setErrorMsg(null);
                  try {
                    const who = memberInput.trim();
                    const outcome = await onAddMember(who);
                    setMemberInput('');
                    setInfoMsg(
                      outcome === 'invited'
                        ? `Invitation sent to ${who}. They will join when they press Accept.`
                        : 'Member added to the group.'
                    );
                  } catch (err: any) {
                    setErrorMsg(friendlyError(err, 'Could not add this member. Please try again.'));
                  } finally {
                    setBusy(false);
                  }
                }}
                style={{ display: 'flex', gap: '8px' }}
              >
                <input
                  type="text"
                  placeholder="Add a member by @username or wallet address"
                  value={memberInput}
                  onChange={(e) => setMemberInput(e.target.value)}
                  style={{
                    flex: 1,
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-strong)',
                    color: 'var(--text-main)',
                    borderRadius: '8px',
                    padding: '8px 12px',
                    fontSize: '0.9rem',
                  }}
                />
                <button type="submit" className="btn-solid" disabled={busy || !memberInput.trim()}>
                  <UserPlus size={14} />
                  <span>Add</span>
                </button>
              </form>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {uniqueUsers.map((uid) => {
                const userDevs = activeMembers.filter((m) => m.user_id === uid);
                const role = userDevs.some((m) => m.role === 'admin') ? 'admin' : 'member';
                const uname = userDevs.find((m) => m.username)?.username;
                const displayLabel = uname
                  ? `@${uname}`
                  : 'Member';
                return (
                  <div
                    key={uid}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '8px 12px',
                      background: 'var(--bg-surface)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '8px',
                      fontSize: '0.86rem',
                      gap: '8px',
                      flexWrap: 'wrap',
                    }}
                  >
                    <div>
                      <span>{uid === currentUserId ? `${displayLabel} (You)` : displayLabel}</span>
                      <span style={{ color: 'var(--text-muted)', marginLeft: '8px' }}>
                        {role === 'admin' ? 'Admin' : 'Member'}
                      </span>
                    </div>
                    {isGroupAdmin && uid !== currentUserId && (
                      <div style={{ display: 'flex', gap: '6px' }}>
                        <button
                          type="button"
                          className="btn-outline"
                          style={{ padding: '4px 8px', fontSize: '0.9rem' }}
                          disabled={busy}
                          onClick={async () => {
                            setBusy(true);
                            try {
                              await setGroupMemberRole(
                                group.group_id,
                                uid,
                                role === 'admin' ? 'member' : 'admin'
                              );
                              if (onGroupUpdated) await onGroupUpdated();
                            } catch (err: any) {
                              setErrorMsg(friendlyError(err, 'Role update failed'));
                            } finally {
                              setBusy(false);
                            }
                          }}
                        >
                          {role === 'admin' ? 'Remove admin' : 'Make admin'}
                        </button>
                        <button
                          type="button"
                          className="btn-outline"
                          style={{ padding: '4px 8px', fontSize: '0.9rem' }}
                          disabled={busy}
                          onClick={async () => {
                            setBusy(true);
                            setErrorMsg(null);
                            try {
                              await onRemoveMember(uid);
                            } catch (err: any) {
                              setErrorMsg(friendlyError(err, 'Remove failed'));
                            } finally {
                              setBusy(false);
                            }
                          }}
                        >
                          <UserMinus size={12} />
                          <span>Remove</span>
                        </button>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {invitedUsers.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div style={{ fontSize: '0.9rem', fontWeight: 600 }}>Waiting for reply ({invitedUsers.length})</div>
                {invitedUsers.map(([uid, uname]) => (
                  <div
                    key={uid}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '8px 12px',
                      background: 'var(--bg-surface)',
                      border: '1px dashed var(--border-strong)',
                      borderRadius: '8px',
                      fontSize: '0.86rem',
                      gap: '8px',
                      flexWrap: 'wrap',
                    }}
                  >
                    <div>
                      <span>{uname ? `@${uname}` : 'Invited member'}</span>
                      <span style={{ color: 'var(--text-muted)', marginLeft: '8px' }}>Invited, not accepted yet</span>
                    </div>
                    {isGroupAdmin && (
                      <button
                        type="button"
                        className="btn-outline"
                        style={{ padding: '4px 8px', fontSize: '0.9rem' }}
                        disabled={busy}
                        onClick={async () => {
                          setBusy(true);
                          setErrorMsg(null);
                          try {
                            await onRemoveMember(uid);
                            setInfoMsg('Invitation cancelled.');
                          } catch (err: any) {
                            setErrorMsg(friendlyError(err, 'Could not cancel the invitation. Please try again.'));
                          } finally {
                            setBusy(false);
                          }
                        }}
                      >
                        <X size={12} />
                        <span>Cancel invite</span>
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}

            {onDeleteGroup && isGroupAdmin && (
              <div
                style={{
                  border: '1px solid var(--danger)',
                  borderRadius: '12px',
                  padding: '12px 14px',
                  marginBottom: '12px',
                  background: 'var(--danger-soft)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                }}
              >
                <div style={{ fontWeight: 600, fontSize: '0.92rem' }}>Delete this group</div>
                {paidInfo?.isPaid ? (
                  <div style={{ fontSize: '0.86rem', color: 'var(--text-secondary)' }}>
                    Paid groups can only be deleted by the platform admin, because members paid for access.
                  </div>
                ) : !deleteOpen ? (
                  <>
                    <div style={{ fontSize: '0.86rem', color: 'var(--text-secondary)' }}>
                      Removes the group for everyone: all members, messages and files. This cannot be undone.
                    </div>
                    <button
                      type="button"
                      className="btn-outline"
                      style={{ alignSelf: 'flex-start', borderColor: 'var(--danger)', color: 'var(--danger)' }}
                      disabled={busy}
                      onClick={() => {
                        setDeleteOpen(true);
                        setDeleteText('');
                      }}
                    >
                      <Trash2 size={14} />
                      <span>Delete group</span>
                    </button>
                  </>
                ) : (
                  <>
                    <label style={{ fontSize: '0.86rem', color: 'var(--text-secondary)' }}>
                      Type the group name <strong>{group.name}</strong> to confirm:
                      <input
                        type="text"
                        value={deleteText}
                        onChange={(e) => setDeleteText(e.target.value)}
                        autoFocus
                        aria-label="Group name to confirm deletion"
                        style={{ display: 'block', width: '100%', marginTop: '6px', padding: '8px 12px' }}
                      />
                    </label>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button
                        type="button"
                        className="btn-solid"
                        style={{ background: 'var(--danger)', color: '#fff' }}
                        disabled={busy || deleteText.trim() !== group.name}
                        onClick={async () => {
                          setBusy(true);
                          setErrorMsg(null);
                          try {
                            await onDeleteGroup();
                            onClose();
                          } catch (err: any) {
                            setErrorMsg(friendlyError(err, 'Could not delete the group'));
                          } finally {
                            setBusy(false);
                          }
                        }}
                      >
                        Delete for everyone
                      </button>
                      <button type="button" className="btn-outline" disabled={busy} onClick={() => setDeleteOpen(false)}>
                        Cancel
                      </button>
                    </div>
                  </>
                )}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
              {onLeaveGroup && (
                <button
                  type="button"
                  className="btn-outline"
                  disabled={busy}
                  onClick={async () => {
                    if (!confirm(`Leave the group "${group.name}"?`)) return;
                    setBusy(true);
                    setErrorMsg(null);
                    try {
                      await onLeaveGroup();
                      onClose();
                    } catch (err: any) {
                      setErrorMsg(friendlyError(err, 'Could not leave the group. Please try again.'));
                    } finally {
                      setBusy(false);
                    }
                  }}
                >
                  <LogOut size={14} />
                  <span>Leave group</span>
                </button>
              )}
            </div>
          </>
        )}

        {tab === 'policy' && (
          <form onSubmit={handleSavePolicy} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {paidInfo && (
              <div style={{ fontSize: '0.86rem', color: 'var(--text-secondary)' }}>
                {paidInfo.isPaid
                  ? `Paid group${paidInfo.monthlyUsd > 0 ? ` ($${paidInfo.monthlyUsd.toFixed(2)}/month)` : ''}. Saving here keeps it paid; only the platform admin changes prices.`
                  : 'Free group. Only the platform admin can make a group paid.'}
              </div>
            )}
            <div>
              <label style={{ fontSize: '0.86rem', color: 'var(--text-secondary)' }}>Group description</label>
              <input
                type="text"
                value={desc}
                disabled={!isGroupAdmin}
                onChange={(e) => setDesc(e.target.value)}
                placeholder="What this group is for, and its rules"
                style={{
                  width: '100%',
                  marginTop: '4px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-strong)',
                  borderRadius: '8px',
                  padding: '8px 12px',
                  color: 'var(--text-main)',
                  fontSize: '0.9rem',
                }}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              <div>
                <label style={{ fontSize: '0.86rem', color: 'var(--text-secondary)' }}>Visibility</label>
                <select
                  value={visibility}
                  disabled={!isGroupAdmin}
                  onChange={(e) => setVisibility(e.target.value as 'public' | 'invite_only')}
                  style={{
                    width: '100%',
                    marginTop: '4px',
                    backgroundColor: 'var(--bg-input)',
                    border: '1px solid var(--border-strong)',
                    borderRadius: '8px',
                    padding: '8px 36px 8px 12px',
                    color: 'var(--text-main)',
                    fontSize: '0.9rem',
                  }}
                >
                  <option value="invite_only">Private (admins add people)</option>
                  <option value="public">Anyone can find it</option>
                </select>
              </div>

              <div>
                <label style={{ fontSize: '0.86rem', color: 'var(--text-secondary)' }}>Minimum wallet balance (ETH)</label>
                <input
                  type="text"
                  value={minEth}
                  disabled={!isGroupAdmin}
                  onChange={(e) => setMinEth(e.target.value)}
                  placeholder="0"
                  style={{
                    width: '100%',
                    marginTop: '4px',
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-strong)',
                    borderRadius: '8px',
                    padding: '8px 10px',
                    color: 'var(--text-main)',
                    fontSize: '0.9rem',
                    fontFamily: 'ui-monospace, monospace',
                  }}
                />
              </div>
            </div>

            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.86rem' }}>
              <input
                type="checkbox"
                checked={requireInvite}
                disabled={!isGroupAdmin}
                onChange={(e) => setRequireInvite(e.target.checked)}
              />
              <span>New members need admin approval</span>
            </label>

            {isGroupAdmin ? (
              <button type="submit" className="btn-solid" disabled={busy} style={{ alignSelf: 'flex-end' }}>
                Save
              </button>
            ) : (
              <div style={{ fontSize: '0.86rem', color: 'var(--text-muted)' }}>
                Only group admins can change these settings.
              </div>
            )}
          </form>
        )}

        {tab === 'invites' && isGroupAdmin && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div>
              <div style={{ fontSize: '0.9rem', fontWeight: 600, marginBottom: '8px' }}>
                Requests to join ({joinRequests.length})
              </div>
              {joinRequests.length === 0 ? (
                <div style={{ fontSize: '0.86rem', color: 'var(--text-muted)' }}>
                  No one is waiting to join right now.
                </div>
              ) : (
                joinRequests.map((req) => (
                  <div
                    key={req.request_id}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      padding: '8px 12px',
                      background: 'var(--bg-surface)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '8px',
                      fontSize: '0.86rem',
                      marginBottom: '6px',
                      gap: '8px',
                      flexWrap: 'wrap',
                    }}
                  >
                    <div>
                      <strong>{req.username ? `@${req.username}` : 'New member'}</strong>{' '}
                      <span style={{ color: 'var(--text-secondary)' }}>
                        • {formatEth(req.qualifying_balance_wei || '0', 4)} ETH
                      </span>
                    </div>
                    <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                      <button
                        type="button"
                        className="btn-solid"
                        style={{ padding: '5px 10px', fontSize: '0.9rem' }}
                        disabled={busy}
                        onClick={async () => {
                          setBusy(true);
                          setErrorMsg(null);
                          try {
                            await onAddMember(req.user_id);
                            const refreshed = await fetchGroupJoinRequests(group.group_id);
                            setJoinRequests(refreshed.requests);
                            setInfoMsg(`${req.username ? `@${req.username}` : 'The member'} has been added to the group.`);
                          } catch (err: any) {
                            setErrorMsg(friendlyError(err, 'Could not add this member. Please try again.'));
                          } finally {
                            setBusy(false);
                          }
                        }}
                      >
                        Approve
                      </button>
                      <button
                        type="button"
                        className="btn-outline"
                        disabled={busy}
                        style={{ padding: '5px 10px', fontSize: '0.9rem' }}
                        onClick={async () => {
                          const who = req.username ? `@${req.username}` : 'this member';
                          if (!confirm(`Decline the request from ${who}?`)) return;
                          setBusy(true);
                          setErrorMsg(null);
                          try {
                            await declineGroupJoinRequest(group.group_id, req.request_id);
                            setJoinRequests((prev) => prev.filter((r) => r.request_id !== req.request_id));
                            setInfoMsg(`Declined the request from ${who}.`);
                          } catch (err: any) {
                            setErrorMsg(friendlyError(err, 'Could not decline the request'));
                          } finally {
                            setBusy(false);
                          }
                        }}
                      >
                        Decline
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Recent account activity: devices removed, fresh starts, wallet changes.
// Shown in plain words only; no device IDs, versions or other technical detail.
// ---------------------------------------------------------------------------
type AccountEvent = Awaited<ReturnType<typeof fetchIdentitySecurityEvents>>['events'][number];

const EVENT_LABELS: Record<string, string> = {
  device_revoked: 'A device was signed out',
  identity_reset_lost_keys: 'Private chats were started fresh',
  wallet_linked: 'A wallet was added to your account',
  wallet_changed: 'Your main wallet was changed',
};

const RecentActivity: React.FC<{ userId: string; refreshKey: string }> = ({ userId, refreshKey }) => {
  const [events, setEvents] = useState<AccountEvent[] | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        // The server returns oldest first, 50 at a time: page through, then show the newest few.
        let all: AccountEvent[] = [];
        let after = 0;
        for (let page = 0; page < 4; page++) {
          const res = await fetchIdentitySecurityEvents([userId], after);
          all = all.concat(res.events);
          if (res.events.length < 50) break;
          after = res.events[res.events.length - 1].seq;
        }
        if (alive) {
          setEvents(all.slice(-8).reverse());
          setFailed(false);
        }
      } catch {
        if (alive) setFailed(true);
      }
    })();
    return () => {
      alive = false;
    };
  }, [userId, refreshKey]);

  return (
    <div
      style={{
        background: 'var(--bg-input)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '12px',
        padding: '14px',
        fontSize: '0.9rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '6px',
      }}
    >
      <strong>Recent activity</strong>
      {failed ? (
        <span style={{ color: 'var(--text-secondary)' }}>Could not load recent activity right now.</span>
      ) : events === null ? (
        <ListRowsSkeleton count={3} compact />
      ) : events.length === 0 ? (
        <span style={{ color: 'var(--text-secondary)' }}>Nothing unusual. No changes to your account.</span>
      ) : (
        events.map((e) => (
          <div
            key={e.event_id}
            style={{ display: 'flex', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}
          >
            <span>{EVENT_LABELS[e.event_type] || 'Account change'}</span>
            <span style={{ color: 'var(--text-secondary)' }}>{new Date(e.timestamp).toLocaleString()}</span>
          </div>
        ))
      )}
      <span style={{ color: 'var(--text-secondary)', fontSize: '0.86rem' }}>
        If you see something you did not do, contact support.
      </span>
    </div>
  );
};

interface AccountDevicesVaultModalProps {
  open: boolean;
  onClose: () => void;
  profile: E2EEAccountProfile | null;
  devices: PeerActiveDeviceDescriptor[];
  localDeviceId: string | null;
  connectedWallet: string | null;
  onUpdateUsername: (username: string) => Promise<void>;
  onLinkCurrentWallet: (revokeOld: boolean) => Promise<void>;
  onRevokeDevice: (deviceId: string) => Promise<void>;
  onResetLostIdentity: () => Promise<void>;
}

/** Friendly name for a device; never shows internal IDs or key names. */
function deviceName(d: PeerActiveDeviceDescriptor, isThisDevice: boolean, index: number): string {
  if (isThisDevice) return 'This browser';
  const label = (d.device_label || '').trim();
  if (label && !/e2ee|vault|olm|mls|key/i.test(label)) return label;
  return `Other device ${index + 1}`;
}

export const AccountDevicesVaultModal: React.FC<AccountDevicesVaultModalProps> = ({
  open,
  onClose,
  profile,
  devices,
  localDeviceId,
  connectedWallet,
  onUpdateUsername,
  onLinkCurrentWallet,
  onRevokeDevice,
  onResetLostIdentity,
}) => {
  const [usernameInput, setUsernameInput] = useState(profile?.username || '');
  const [confirmLostReset, setConfirmLostReset] = useState(false);
  const [busy, setBusy] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  useEffect(() => {
    setUsernameInput(profile?.username || '');
  }, [profile?.username]);

  if (!open || !profile) return null;

  const isConnectedWalletAlreadyLinked = profile.wallets.some(
    (w) => connectedWallet && w.wallet_address.toLowerCase() === connectedWallet.toLowerCase()
  );
  const activeDevices = devices.filter((d) => d.status === 'active');
  const otherDevices = activeDevices.filter((d) => d.device_id !== localDeviceId);

  return (
    <div style={modalBackdropStyle} onClick={onClose}>
      <div style={modalCardStyle} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <UserCog size={20} />
            <h3 style={{ fontSize: '1.45rem', fontWeight: 500, letterSpacing: '-0.015em', margin: 0 }}>
              Account and devices
            </h3>
          </div>
          <button className="btn-outline" style={{ padding: '6px' }} onClick={onClose} aria-label="Close">
            <X size={16} />
          </button>
        </div>

        {statusMsg && (
          <div
            role="status"
            style={{
              padding: '10px 12px',
              background: 'var(--bg-input)',
              border: '1px solid var(--border-strong)',
              borderRadius: '8px',
              fontSize: '0.9rem',
            }}
          >
            {statusMsg}
          </div>
        )}

        {/* Username */}
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            if (!usernameInput.trim() || busy) return;
            setBusy(true);
            setStatusMsg(null);
            try {
              await onUpdateUsername(usernameInput.trim());
              setStatusMsg('Username saved. Your chats are unchanged.');
            } catch (err: any) {
              setStatusMsg(friendlyError(err, 'Could not save the username. Please try again.'));
            } finally {
              setBusy(false);
            }
          }}
          style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}
        >
          <label htmlFor="account-username" style={{ fontSize: '0.9rem', fontWeight: 600 }}>
            Username
          </label>
          <div style={{ display: 'flex', gap: '8px' }}>
            <input
              id="account-username"
              type="text"
              placeholder="3 to 32 characters"
              value={usernameInput}
              onChange={(e) => setUsernameInput(e.target.value)}
              style={{
                flex: 1,
                background: 'var(--bg-input)',
                border: '1px solid var(--border-strong)',
                color: 'var(--text-main)',
                borderRadius: '8px',
                padding: '8px 12px',
                fontSize: '0.9rem',
              }}
            />
            <button type="submit" className="btn-outline" disabled={busy}>
              Save
            </button>
          </div>
        </form>

        {/* Wallets */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ fontSize: '0.9rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Wallet size={14} /> Sign-in wallets
          </div>
          {profile.wallets.map((w) => (
            <div
              key={w.wallet_address}
              style={{
                padding: '8px 12px',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                fontSize: '0.86rem',
                display: 'flex',
                justifyContent: 'space-between',
              }}
            >
              <span>{formatAddress(w.wallet_address, 4)}</span>
              <span style={{ color: 'var(--text-secondary)' }}>{w.is_primary ? 'Main' : 'Added'}</span>
            </div>
          ))}
          {connectedWallet && !isConnectedWalletAlreadyLinked && (
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              <button
                type="button"
                className="btn-outline"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    await onLinkCurrentWallet(false);
                    setStatusMsg('Wallet added. You can now sign in with it too.');
                  } catch (err: any) {
                    setStatusMsg(friendlyError(err, 'Could not add this wallet. Please try again.'));
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Add this wallet ({formatAddress(connectedWallet, 4)})
              </button>
              <button
                type="button"
                className="btn-solid"
                disabled={busy}
                onClick={async () => {
                  if (!confirm('Make this your main wallet? The old wallet will be signed out and removed.')) return;
                  setBusy(true);
                  try {
                    await onLinkCurrentWallet(true);
                    setStatusMsg('This is now your main wallet. The old one was removed. Your chats are unchanged.');
                  } catch (err: any) {
                    setStatusMsg(friendlyError(err, 'Could not change your main wallet. Please try again.'));
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Make this my main wallet
              </button>
            </div>
          )}
        </div>

        {/* Devices */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <span style={{ fontSize: '0.9rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Smartphone size={14} /> Signed-in devices ({activeDevices.length})
          </span>
          {activeDevices.map((d) => {
            const isThis = d.device_id === localDeviceId;
            return (
              <div
                key={d.device_id}
                style={{
                  padding: '10px 12px',
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '8px',
                  fontSize: '0.86rem',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  gap: '8px',
                }}
              >
                <span style={{ fontWeight: 600 }}>
                  {deviceName(d, isThis, otherDevices.indexOf(d))}
                </span>
                {!isThis && (
                  <button
                    type="button"
                    className="btn-outline"
                    style={{ padding: '4px 8px', fontSize: '0.9rem' }}
                    disabled={busy}
                    onClick={async () => {
                      if (!confirm('Sign out this device? It will no longer receive your private messages.')) return;
                      setBusy(true);
                      try {
                        await onRevokeDevice(d.device_id);
                        setStatusMsg('Device signed out.');
                      } catch (err: any) {
                        setStatusMsg(friendlyError(err, 'Could not sign out the device. Please try again.'));
                      } finally {
                        setBusy(false);
                      }
                    }}
                  >
                    <Trash2 size={12} />
                    <span>Sign out</span>
                  </button>
                )}
              </div>
            );
          })}
        </div>

        <RecentActivity
          userId={profile.user_id}
          refreshKey={`${devices.length}:${profile.identity_version}:${profile.wallets.length}`}
        />

        {/* Lost every device: start private chats fresh */}
        <div
          style={{
            borderTop: '1px solid var(--border-subtle)',
            paddingTop: '14px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
          }}
        >
          <div style={{ fontSize: '0.9rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
            <AlertTriangle size={14} /> Lost your old phone or computer?
          </div>
          <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: 1.45, margin: 0 }}>
            Private messages are kept only on your own devices. If you lost all of them, you can start
            your private chats fresh here. Old private messages cannot be brought back. The people you
            chat with will see that you started fresh.
          </p>
          <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.86rem' }}>
            <input
              type="checkbox"
              checked={confirmLostReset}
              onChange={(e) => setConfirmLostReset(e.target.checked)}
            />
            <span>I understand old private messages cannot be brought back.</span>
          </label>
          <button
            type="button"
            className="btn-outline"
            style={{ alignSelf: 'flex-start' }}
            disabled={busy || !confirmLostReset}
            onClick={async () => {
              setBusy(true);
              try {
                await onResetLostIdentity();
                setConfirmLostReset(false);
                setStatusMsg('Done. Your private chats have started fresh.');
              } catch (err: any) {
                setStatusMsg(friendlyError(err, 'Could not start fresh. Please try again.'));
              } finally {
                setBusy(false);
              }
            }}
          >
            <span>Start private chats fresh</span>
          </button>
        </div>
      </div>
    </div>
  );
};