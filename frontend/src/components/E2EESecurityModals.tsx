import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  KeyRound,
  Smartphone,
  Wallet,
  RefreshCw,
  Trash2,
  UserPlus,
  UserMinus,
  AlertTriangle,
  X,
  Check,
  Copy,
  Link2,
  LogOut,
  Award,
} from 'lucide-react';
import type { E2EEAccountProfile, E2EEGroupRecord } from '../services/e2eeApi.ts';
import type { PeerActiveDeviceDescriptor } from '../services/olmService.ts';
import {
  fetchGroupPolicy,
  updateGroupPolicy,
  createGroupInvite,
  fetchGroupInvites,
  revokeGroupInvite,
  fetchGroupJoinRequests,
  setGroupMemberRole,
  type GroupInviteRecord,
  type GroupJoinRequestRecord,
} from '../services/platformApi.ts';
import { formatAddress, formatEth } from '../services/web3.ts';

interface SafetyNumberModalProps {
  open: boolean;
  onClose: () => void;
  localUserId: string;
  localEd25519Key: string;
  peerUserId: string;
  peerDisplayName: string;
  peerIdentityVersion: number;
  peerDevices: PeerActiveDeviceDescriptor[];
  safetyNumber: string;
  isVerified: boolean;
  onMarkVerified: () => Promise<void>;
  onResetSession: () => Promise<void>;
}

const modalBackdropStyle: React.CSSProperties = {
  position: 'fixed',
  inset: 0,
  zIndex: 300,
  background: 'rgba(0, 0, 0, 0.78)',
  backdropFilter: 'blur(8px)',
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

export const SafetyNumberModal: React.FC<SafetyNumberModalProps> = ({
  open,
  onClose,
  localUserId,
  localEd25519Key,
  peerUserId,
  peerDisplayName,
  peerIdentityVersion,
  peerDevices,
  safetyNumber,
  isVerified,
  onMarkVerified,
  onResetSession,
}) => {
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);

  if (!open) return null;

  const copySafety = () => {
    navigator.clipboard.writeText(safetyNumber);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={modalBackdropStyle} onClick={onClose}>
      <div style={modalCardStyle} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {isVerified ? <ShieldCheck size={20} /> : <KeyRound size={20} />}
            <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>
              Safety Number &amp; Identity Verification
            </h3>
          </div>
          <button className="btn-outline" style={{ padding: '6px' }} onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
          Compare this 60-digit Safety Number with <strong>{peerDisplayName}</strong> over an
          out-of-band channel. Matching digits prove no man-in-the-middle substituted Olm Curve25519
          or Ed25519 keys.
        </p>

        <div
          style={{
            background: 'var(--bg-input)',
            border: '1px solid var(--border-strong)',
            borderRadius: '12px',
            padding: '16px',
            textAlign: 'center',
          }}
        >
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: '10px',
              fontFamily: 'ui-monospace, monospace',
              fontSize: '1.02rem',
              fontWeight: 700,
              letterSpacing: '0.06em',
            }}
          >
            {safetyNumber.split(' ').map((block, idx) => (
              <span key={idx}>{block}</span>
            ))}
          </div>
          <button
            type="button"
            className="btn-outline"
            style={{ marginTop: '14px', padding: '5px 12px', fontSize: '0.75rem' }}
            onClick={copySafety}
          >
            {copied ? <Check size={13} /> : <Copy size={13} />}
            <span>{copied ? 'Copied' : 'Copy 60-Digit Safety Number'}</span>
          </button>
        </div>

        <div
          style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '10px',
            padding: '12px',
            fontSize: '0.76rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '6px',
            fontFamily: 'ui-monospace, monospace',
          }}
        >
          <div>Your Permanent ID: {localUserId}</div>
          <div>Your Ed25519 Key : {localEd25519Key}</div>
          <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '6px' }}>
            Peer Permanent ID: {peerUserId} (v{peerIdentityVersion})
          </div>
          {peerDevices.map((d) => (
            <div key={d.device_id} style={{ color: 'var(--text-secondary)' }}>
              Device {d.device_id.slice(0, 12)}: Ed25519 {d.ed25519_identity_key.slice(0, 22)}...
            </div>
          ))}
        </div>

        <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
          <button
            type="button"
            className="btn-outline"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await onResetSession();
              } finally {
                setBusy(false);
              }
            }}
          >
            <RefreshCw size={14} />
            <span>Re-establish Olm Session</span>
          </button>
          <button
            type="button"
            className="btn-solid"
            disabled={busy || isVerified}
            onClick={async () => {
              setBusy(true);
              try {
                await onMarkVerified();
              } finally {
                setBusy(false);
              }
            }}
          >
            <ShieldCheck size={15} />
            <span>{isVerified ? 'Verified' : 'Mark Identity Verified'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};

interface MlsGroupSecurityModalProps {
  open: boolean;
  onClose: () => void;
  group: E2EEGroupRecord | null;
  currentUserId: string;
  epochVerifyCode: string;
  epochAuthenticatorHex: string;
  onAddMember: (identifier: string) => Promise<void>;
  onRemoveMember: (targetUserId: string) => Promise<void>;
  onRotateOwnKey: () => Promise<void>;
  onLeaveGroup?: () => Promise<void>;
  onGroupUpdated?: () => Promise<void>;
}

export const MlsGroupSecurityModal: React.FC<MlsGroupSecurityModalProps> = ({
  open,
  onClose,
  group,
  currentUserId,
  epochVerifyCode,
  epochAuthenticatorHex,
  onAddMember,
  onRemoveMember,
  onRotateOwnKey,
  onLeaveGroup,
  onGroupUpdated,
}) => {
  const [tab, setTab] = useState<'members' | 'policy' | 'invites'>('members');
  const [memberInput, setMemberInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [infoMsg, setInfoMsg] = useState<string | null>(null);

  // Access Policy form state
  const [desc, setDesc] = useState('');
  const [visibility, setVisibility] = useState<'public' | 'invite_only'>('invite_only');
  const [minEth, setMinEth] = useState('0');
  const [requireInvite, setRequireInvite] = useState(true);

  // Invites & Join Requests
  const [invites, setInvites] = useState<GroupInviteRecord[]>([]);
  const [joinRequests, setJoinRequests] = useState<GroupJoinRequestRecord[]>([]);
  const [copiedCode, setCopiedCode] = useState<string | null>(null);

  const activeMembers = group ? group.members.filter((m) => m.status === 'active') : [];
  const isGroupAdmin = activeMembers.some(
    (m) => m.user_id === currentUserId && m.role === 'admin'
  );

  useEffect(() => {
    if (!open || !group) return;
    setErrorMsg(null);
    setInfoMsg(null);
    fetchGroupPolicy(group.group_id)
      .then((res) => {
        setDesc(res.policy.description || '');
        setVisibility(res.policy.visibility || 'invite_only');
        setMinEth(res.policy.min_eth_balance_eth || '0');
        setRequireInvite(Boolean(res.policy.require_invitation));
      })
      .catch(() => {});

    if (isGroupAdmin) {
      fetchGroupInvites(group.group_id)
        .then((r) => setInvites(r.invites || []))
        .catch(() => {});
      fetchGroupJoinRequests(group.group_id)
        .then((r) => setJoinRequests(r.requests || []))
        .catch(() => {});
    }
  }, [open, group?.group_id, isGroupAdmin]);

  if (!open || !group) return null;

  const uniqueUsers = Array.from(new Set(activeMembers.map((m) => m.user_id)));

  const handleSavePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErrorMsg(null);
    setInfoMsg(null);
    try {
      await updateGroupPolicy(group.group_id, {
        description: desc,
        visibility,
        min_level: 7,
        min_eth_balance_eth: minEth || '0',
        require_invitation: requireInvite,
      });
      setInfoMsg('Group access & ETH balance policy updated.');
      if (onGroupUpdated) await onGroupUpdated();
    } catch (err: any) {
      setErrorMsg(err?.message || 'Failed to save group policy');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={modalBackdropStyle} onClick={onClose}>
      <div style={modalCardStyle} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <ShieldCheck size={20} />
            <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>
              MLS Group Governance — {group.name}
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
            style={{ padding: '6px 12px', fontSize: '0.76rem' }}
            onClick={() => setTab('members')}
          >
            Members &amp; Keys ({uniqueUsers.length})
          </button>
          <button
            type="button"
            className={tab === 'policy' ? 'btn-solid' : 'btn-outline'}
            style={{ padding: '6px 12px', fontSize: '0.76rem' }}
            onClick={() => setTab('policy')}
          >
            <Award size={13} />
            <span>Access Policy</span>
          </button>
          {isGroupAdmin && (
            <button
              type="button"
              className={tab === 'invites' ? 'btn-solid' : 'btn-outline'}
              style={{ padding: '6px 12px', fontSize: '0.76rem' }}
              onClick={() => setTab('invites')}
            >
              <Link2 size={13} />
              <span>Invites &amp; Requests ({joinRequests.length})</span>
            </button>
          )}
        </div>

        {errorMsg && (
          <div
            style={{
              padding: '10px 12px',
              borderRadius: '8px',
              border: '1px solid var(--border-strong)',
              fontSize: '0.78rem',
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
              fontSize: '0.78rem',
            }}
          >
            {infoMsg}
          </div>
        )}

        {tab === 'members' && (
          <>
            <div
              style={{
                background: 'var(--bg-input)',
                border: '1px solid var(--border-strong)',
                borderRadius: '12px',
                padding: '14px',
                fontSize: '0.76rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '5px',
              }}
            >
              <div>
                <strong>Protocol:</strong> IETF RFC 9420 MLS ({group.ciphersuite}) &bull;{' '}
                <strong>Epoch:</strong> #{group.current_epoch}
              </div>
              <div style={{ fontFamily: 'ui-monospace, monospace' }}>
                <strong>Epoch Verify Code:</strong> {epochVerifyCode || 'Syncing...'}
              </div>
              <div
                style={{
                  fontFamily: 'ui-monospace, monospace',
                  fontSize: '0.7rem',
                  color: 'var(--text-secondary)',
                  wordBreak: 'break-all',
                }}
              >
                Authenticator: {epochAuthenticatorHex || '—'}
              </div>
              <div style={{ color: 'var(--text-secondary)' }}>
                Strict Epoch Isolation: new members cannot decrypt pre-join epochs; removed members
                trigger immediate TreeKEM rekeying.
              </div>
            </div>

            {isGroupAdmin && (
              <form
                onSubmit={async (e) => {
                  e.preventDefault();
                  if (!memberInput.trim() || busy) return;
                  setBusy(true);
                  setErrorMsg(null);
                  try {
                    await onAddMember(memberInput.trim());
                    setMemberInput('');
                    setInfoMsg('Member added & encrypted MLS Welcome delivered.');
                  } catch (err: any) {
                    setErrorMsg(err?.message || 'Failed to add member to MLS group');
                  } finally {
                    setBusy(false);
                  }
                }}
                style={{ display: 'flex', gap: '8px' }}
              >
                <input
                  type="text"
                  placeholder="Add eligible member by usr_..., @username, or 0x..."
                  value={memberInput}
                  onChange={(e) => setMemberInput(e.target.value)}
                  style={{
                    flex: 1,
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-strong)',
                    color: 'var(--text-main)',
                    borderRadius: '8px',
                    padding: '8px 12px',
                    fontSize: '0.8rem',
                    fontFamily: 'ui-monospace, monospace',
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
                const joinedAt = Math.min(...userDevs.map((m) => m.joined_epoch));
                const role = userDevs.some((m) => m.role === 'admin') ? 'admin' : 'member';
                const uname = userDevs.find((m) => m.username)?.username;
                const displayLabel = uname
                  ? `@${uname}`
                  : `${uid.slice(0, 16)}...`;
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
                      fontSize: '0.76rem',
                      gap: '8px',
                      flexWrap: 'wrap',
                    }}
                  >
                    <div style={{ fontFamily: 'ui-monospace, monospace' }}>
                      <span>{uid === currentUserId ? `${displayLabel} (You)` : displayLabel}</span>
                      <span style={{ color: 'var(--text-muted)', marginLeft: '8px' }}>
                        [{role.toUpperCase()} &bull; E#{joinedAt} &bull; {userDevs.length} dev]
                      </span>
                    </div>
                    {isGroupAdmin && uid !== currentUserId && (
                      <div style={{ display: 'flex', gap: '6px' }}>
                        <button
                          type="button"
                          className="btn-outline"
                          style={{ padding: '4px 8px', fontSize: '0.7rem' }}
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
                              setErrorMsg(err?.message || 'Role update failed');
                            } finally {
                              setBusy(false);
                            }
                          }}
                        >
                          {role === 'admin' ? 'Set Member' : 'Make Admin'}
                        </button>
                        <button
                          type="button"
                          className="btn-outline"
                          style={{ padding: '4px 8px', fontSize: '0.7rem' }}
                          disabled={busy}
                          onClick={async () => {
                            setBusy(true);
                            setErrorMsg(null);
                            try {
                              await onRemoveMember(uid);
                            } catch (err: any) {
                              setErrorMsg(err?.message || 'Remove failed');
                            } finally {
                              setBusy(false);
                            }
                          }}
                        >
                          <UserMinus size={12} />
                          <span>Remove &amp; Rekey</span>
                        </button>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
              {onLeaveGroup && (
                <button
                  type="button"
                  className="btn-outline"
                  disabled={busy}
                  onClick={async () => {
                    if (!confirm(`Leave encrypted group "${group.name}"?`)) return;
                    setBusy(true);
                    setErrorMsg(null);
                    try {
                      await onLeaveGroup();
                      onClose();
                    } catch (err: any) {
                      setErrorMsg(err?.message || 'Cannot leave group');
                    } finally {
                      setBusy(false);
                    }
                  }}
                >
                  <LogOut size={14} />
                  <span>Leave Group</span>
                </button>
              )}
              <button
                type="button"
                className="btn-outline"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  setErrorMsg(null);
                  try {
                    await onRotateOwnKey();
                    setInfoMsg('Rotated leaf key & advanced TreeKEM epoch.');
                  } catch (err: any) {
                    setErrorMsg(err?.message || 'Key rotation failed');
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                <RefreshCw size={14} />
                <span>Rotate My Leaf Key</span>
              </button>
            </div>
          </>
        )}

        {tab === 'policy' && (
          <form onSubmit={handleSavePolicy} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div>
              <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Group Description</label>
              <input
                type="text"
                value={desc}
                disabled={!isGroupAdmin}
                onChange={(e) => setDesc(e.target.value)}
                placeholder="Purpose & rules for this encrypted group..."
                style={{
                  width: '100%',
                  marginTop: '4px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-strong)',
                  borderRadius: '8px',
                  padding: '8px 12px',
                  color: 'var(--text-main)',
                  fontSize: '0.82rem',
                }}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              <div>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Visibility</label>
                <select
                  value={visibility}
                  disabled={!isGroupAdmin}
                  onChange={(e) => setVisibility(e.target.value as 'public' | 'invite_only')}
                  style={{
                    width: '100%',
                    marginTop: '4px',
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-strong)',
                    borderRadius: '8px',
                    padding: '8px 10px',
                    color: 'var(--text-main)',
                    fontSize: '0.82rem',
                  }}
                >
                  <option value="invite_only">Invite Only</option>
                  <option value="public">Public Discovery</option>
                </select>
              </div>

              <div>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Min ETH Balance</label>
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
                    fontSize: '0.82rem',
                    fontFamily: 'ui-monospace, monospace',
                  }}
                />
              </div>
            </div>

            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.78rem' }}>
              <input
                type="checkbox"
                checked={requireInvite}
                disabled={!isGroupAdmin}
                onChange={(e) => setRequireInvite(e.target.checked)}
              />
              <span>Require invite code or group admin approval before MLS onboarding</span>
            </label>

            {isGroupAdmin ? (
              <button type="submit" className="btn-solid" disabled={busy} style={{ alignSelf: 'flex-end' }}>
                Save Access Policy
              </button>
            ) : (
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Only group admins can modify access thresholds. Server enforces these rules on all invites,
                MLS Add commits, and message transmissions.
              </div>
            )}
          </form>
        )}

        {tab === 'invites' && isGroupAdmin && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ fontSize: '0.82rem', fontWeight: 600 }}>Invite Codes</div>
              <button
                type="button"
                className="btn-solid"
                style={{ padding: '6px 12px', fontSize: '0.75rem' }}
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    const created = await createGroupInvite(group.group_id, 72, 25);
                    setInvites((prev) => [created.invite, ...prev]);
                    setInfoMsg(`Created invite code ${created.invite.invite_code}`);
                  } catch (err: any) {
                    setErrorMsg(err?.message || 'Invite creation failed');
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                <Link2 size={13} />
                <span>Generate 72h Invite Code</span>
              </button>
            </div>

            {invites.length === 0 ? (
              <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                No invite links generated yet.
              </div>
            ) : (
              invites.map((inv) => (
                <div
                  key={inv.invite_code}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '8px 12px',
                    background: 'var(--bg-surface)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '8px',
                    fontSize: '0.76rem',
                    fontFamily: 'ui-monospace, monospace',
                  }}
                >
                  <div>
                    <strong>{inv.invite_code}</strong>{' '}
                    <span style={{ color: 'var(--text-muted)' }}>
                      ({inv.uses_count ?? (inv as any).use_count ?? 0}/{inv.max_uses} uses {inv.revoked ? '• REVOKED' : ''})
                    </span>
                  </div>
                  <div style={{ display: 'flex', gap: '6px' }}>
                    <button
                      type="button"
                      className="btn-outline"
                      style={{ padding: '4px 8px', fontSize: '0.7rem' }}
                      onClick={() => {
                        navigator.clipboard.writeText(inv.invite_code);
                        setCopiedCode(inv.invite_code);
                        setTimeout(() => setCopiedCode(null), 1800);
                      }}
                    >
                      {copiedCode === inv.invite_code ? <Check size={12} /> : <Copy size={12} />}
                    </button>
                    {!inv.revoked && (
                      <button
                        type="button"
                        className="btn-outline"
                        style={{ padding: '4px 8px', fontSize: '0.7rem' }}
                        onClick={async () => {
                          await revokeGroupInvite(group.group_id, inv.invite_code);
                          const refreshed = await fetchGroupInvites(group.group_id);
                          setInvites(refreshed.invites);
                        }}
                      >
                        Revoke
                      </button>
                    )}
                  </div>
                </div>
              ))
            )}

            <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '12px' }}>
              <div style={{ fontSize: '0.82rem', fontWeight: 600, marginBottom: '8px' }}>
                Pending Policy-Verified Join Requests ({joinRequests.length})
              </div>
              {joinRequests.length === 0 ? (
                <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                  No pending join requests waiting for MLS Welcome onboarding.
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
                      fontSize: '0.76rem',
                      marginBottom: '6px',
                    }}
                  >
                    <div>
                      <strong>{req.username ? `@${req.username}` : req.user_id.slice(0, 14)}</strong>{' '}
                      <span style={{ color: 'var(--text-secondary)' }}>
                        • {formatEth(req.qualifying_balance_wei || '0', 4)} ETH
                      </span>
                    </div>
                    <button
                      type="button"
                      className="btn-solid"
                      style={{ padding: '5px 10px', fontSize: '0.72rem' }}
                      disabled={busy}
                      onClick={async () => {
                        setBusy(true);
                        setErrorMsg(null);
                        try {
                          await onAddMember(req.user_id);
                          const refreshed = await fetchGroupJoinRequests(group.group_id);
                          setJoinRequests(refreshed.requests);
                          setInfoMsg(`Approved & encrypted MLS Welcome sent to ${req.username || req.user_id}`);
                        } catch (err: any) {
                          setErrorMsg(err?.message || 'MLS onboarding failed');
                        } finally {
                          setBusy(false);
                        }
                      }}
                    >
                      Approve &amp; Add (MLS)
                    </button>
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

interface AccountDevicesVaultModalProps {
  open: boolean;
  onClose: () => void;
  profile: E2EEAccountProfile | null;
  devices: PeerActiveDeviceDescriptor[];
  localDeviceId: string | null;
  connectedWallet: string | null;
  onUpdateUsername: (username: string) => Promise<void>;
  onLinkCurrentWallet: (revokeOld: boolean) => Promise<void>;
  onReplenishPrekeys: () => Promise<void>;
  onRevokeDevice: (deviceId: string) => Promise<void>;
  onResetLostIdentity: () => Promise<void>;
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
  onReplenishPrekeys,
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

  return (
    <div style={modalBackdropStyle} onClick={onClose}>
      <div style={modalCardStyle} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <KeyRound size={20} />
            <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>
              Permanent Identity, Devices &amp; E2EE Key Vault
            </h3>
          </div>
          <button className="btn-outline" style={{ padding: '6px' }} onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        {statusMsg && (
          <div
            style={{
              padding: '10px 12px',
              background: 'var(--bg-input)',
              border: '1px solid var(--border-strong)',
              borderRadius: '8px',
              fontSize: '0.8rem',
            }}
          >
            {statusMsg}
          </div>
        )}

        {/* Permanent Account Identity */}
        <div
          style={{
            background: 'var(--bg-input)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '12px',
            padding: '14px',
            fontSize: '0.8rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '6px',
          }}
        >
          <div>
            <strong>Immutable Permanent user_id:</strong>{' '}
            <code style={{ fontFamily: 'ui-monospace, monospace' }}>{profile.user_id}</code>
          </div>
          <div>
            <strong>Encryption Identity Version:</strong> v{profile.identity_version}
          </div>
          <div style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>
            Wallet authentication and message encryption are strictly separated. Changing your
            username or Ethereum wallet never replaces your device encryption keys.
          </div>
        </div>

        {/* Username Update */}
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            if (!usernameInput.trim() || busy) return;
            setBusy(true);
            setStatusMsg(null);
            try {
              await onUpdateUsername(usernameInput.trim());
              setStatusMsg('Username updated; encryption identity and history preserved.');
            } catch (err: any) {
              setStatusMsg(err?.message || 'Failed to update username');
            } finally {
              setBusy(false);
            }
          }}
          style={{ display: 'flex', gap: '8px' }}
        >
          <input
            type="text"
            placeholder="Set @username (3-32 chars)"
            value={usernameInput}
            onChange={(e) => setUsernameInput(e.target.value)}
            style={{
              flex: 1,
              background: 'var(--bg-input)',
              border: '1px solid var(--border-strong)',
              color: 'var(--text-main)',
              borderRadius: '8px',
              padding: '8px 12px',
              fontSize: '0.82rem',
            }}
          />
          <button type="submit" className="btn-outline" disabled={busy}>
            Save Username
          </button>
        </form>

        {/* Linked Wallets */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ fontSize: '0.8rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Wallet size={14} /> Linked Authentication Wallets
          </div>
          {profile.wallets.map((w) => (
            <div
              key={w.wallet_address}
              style={{
                padding: '8px 12px',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                fontSize: '0.78rem',
                fontFamily: 'ui-monospace, monospace',
                display: 'flex',
                justifyContent: 'space-between',
              }}
            >
              <span>{formatAddress(w.wallet_address, 6)}</span>
              <span>{w.is_primary ? 'PRIMARY AUTH WALLET' : 'LINKED'}</span>
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
                    setStatusMsg('New wallet linked to permanent user_id without changing E2EE keys.');
                  } catch (err: any) {
                    setStatusMsg(err?.message || 'Wallet link failed');
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Link Connected Wallet ({formatAddress(connectedWallet, 4)})
              </button>
              <button
                type="button"
                className="btn-solid"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    await onLinkCurrentWallet(true);
                    setStatusMsg('Primary wallet migrated & old wallet sessions revoked; E2EE keys preserved.');
                  } catch (err: any) {
                    setStatusMsg(err?.message || 'Wallet migration failed');
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Migrate Primary Wallet &amp; Revoke Old
              </button>
            </div>
          )}
        </div>

        {/* Devices & Prekey Rotation */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Smartphone size={14} /> Cryptographic Devices ({devices.length})
            </span>
            <button
              type="button"
              className="btn-outline"
              style={{ padding: '4px 10px', fontSize: '0.74rem' }}
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                try {
                  await onReplenishPrekeys();
                  setStatusMsg('Replenished Olm One-Time Prekeys, rotated Fallback Key & MLS KeyPackages.');
                } catch (err: any) {
                  setStatusMsg(err?.message || 'Prekey rotation failed');
                } finally {
                  setBusy(false);
                }
              }}
            >
              <RefreshCw size={12} />
              <span>Rotate &amp; Replenish Prekeys</span>
            </button>
          </div>

          {devices.map((d) => (
            <div
              key={d.device_id}
              style={{
                padding: '10px 12px',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                fontSize: '0.76rem',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div>
                <div style={{ fontWeight: 600, fontFamily: 'ui-monospace, monospace' }}>
                  {d.device_id} {d.device_id === localDeviceId ? '(This Browser Vault)' : ''}
                </div>
                <div style={{ color: 'var(--text-secondary)', fontFamily: 'ui-monospace, monospace' }}>
                  Ed25519: {d.ed25519_identity_key.slice(0, 20)}... &bull; Status: {d.status.toUpperCase()}
                </div>
              </div>
              {d.status === 'active' && d.device_id !== localDeviceId && (
                <button
                  type="button"
                  className="btn-outline"
                  style={{ padding: '4px 8px', fontSize: '0.72rem' }}
                  disabled={busy}
                  onClick={async () => {
                    setBusy(true);
                    try {
                      await onRevokeDevice(d.device_id);
                      setStatusMsg(`Device ${d.device_id} revoked.`);
                    } catch (err: any) {
                      setStatusMsg(err?.message || 'Revoke failed');
                    } finally {
                      setBusy(false);
                    }
                  }}
                >
                  <Trash2 size={12} />
                  <span>Revoke</span>
                </button>
              )}
            </div>
          ))}
        </div>

        {/* Explicit Lost-Keys / Identity Migration Reset */}
        <div
          style={{
            borderTop: '1px solid var(--border-subtle)',
            paddingTop: '14px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
          }}
        >
          <div style={{ fontSize: '0.78rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '6px' }}>
            <AlertTriangle size={14} /> Lost All Devices / Explicit Identity Reset
          </div>
          <p style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
            Because private decryption keys never leave your devices, losing all devices makes
            previously encrypted messages permanently unrecoverable. Resetting revokes all old
            devices, generates a fresh identity, and notifies conversation peers.
          </p>
          <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.75rem' }}>
            <input
              type="checkbox"
              checked={confirmLostReset}
              onChange={(e) => setConfirmLostReset(e.target.checked)}
            />
            <span>
              I understand prior E2EE messages without local keys cannot be decrypted.
            </span>
          </label>
          <button
            type="button"
            className="btn-outline"
            disabled={busy || !confirmLostReset}
            onClick={async () => {
              setBusy(true);
              try {
                await onResetLostIdentity();
                setConfirmLostReset(false);
                setStatusMsg('Encryption identity reset complete; conversation peers notified.');
              } catch (err: any) {
                setStatusMsg(err?.message || 'Identity reset failed');
              } finally {
                setBusy(false);
              }
            }}
          >
            <ShieldAlert size={14} />
            <span>Reset Encryption Identity &amp; Notify Peers</span>
          </button>
        </div>
      </div>
    </div>
  );
};
