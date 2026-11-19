import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Globe,
  Lock,
  Users,
  Award,
  Wallet,
  AlertTriangle,
  Send,
  Edit3,
  Trash2,
  Ban,
  Flag,
  Search,
  RefreshCw,
  Copy,
  Check,
  KeyRound,
  Link2,
  Settings as SettingsIcon,
  Sun,
  Moon,
  History,
  User,
  Menu,
  AlertCircle,
} from 'lucide-react';
import { getBaseApiUrl, setBaseApiUrl } from '../services/api';
import { formatAddress, formatEth } from '../services/web3';
import {
  requestE2EEAuthChallenge,
  updateMyE2EEUsername,
  checkUsernameAvailability,
  linkNewWalletToE2EEAccount,
  type E2EEAccountProfile,
} from '../services/e2eeApi';
import {
  fetchPublicChatFeed,
  postPublicChatMessage,
  editPublicChatMessage,
  deletePublicChatMessage,
  connectPublicChatWebSocket,
  searchUsers,
  updateMyProfile,
  fetchMyIdentityHistory,
  fetchBlockedUsers,
  blockUser,
  unblockUser,
  submitAbuseReport,
  verifyMyWalletBalance,
  discoverPublicGroups,
  requestJoinPublicGroup,
  joinGroupByInviteCode,
  type PublicChatMessageRecord,
  type DirectoryUserRecord,
  type DiscoverableGroupRecord,
  formatGroupFee,
} from '../services/platformApi';

// ============================================================================
// 1. OPEN PUBLIC CHAT VIEW (Real-Time WebSocket + Guest/Verified Modes)
// ============================================================================

export const OpenPublicChatView: React.FC<{
  account: string | null;
  e2eeProfile: E2EEAccountProfile | null;
  siweLoading: boolean;
  onConnectWallet: () => void;
  onAuthenticateSiwe: () => void;
  onStartPrivateChat: (identifier: string) => void;
  embedded?: boolean;
  onToggleChannels?: () => void;
  isPlatformPaid?: boolean | null;
  onOpenAdmissionModal?: () => void;
}> = ({
  account,
  e2eeProfile,
  siweLoading,
  onConnectWallet,
  onAuthenticateSiwe,
  onStartPrivateChat,
  embedded = false,
  onToggleChannels,
  isPlatformPaid,
  onOpenAdmissionModal,
}) => {
    const [messages, setMessages] = useState<
      (PublicChatMessageRecord & { isOptimistic?: boolean })[]
    >([]);
    const [nextBeforeSeq, setNextBeforeSeq] = useState<number | null>(null);
    const [onlineStats, setOnlineStats] = useState({ watching: 0, active_live: 0 });
    const [policy, setPolicy] = useState({
      guest_read_enabled: true,
      guest_posting_enabled: true,
      max_length: 1000,
      edit_window_seconds: 900,
    });
    const [input, setInput] = useState('');
    const [sending, setSending] = useState(false);
    const [editingId, setEditingId] = useState<string | null>(null);
    const [editText, setEditText] = useState('');
    const [errorMsg, setErrorMsg] = useState<string | null>(null);
    const [lastFailedText, setLastFailedText] = useState<string | null>(null);
    const streamRef = useRef<HTMLDivElement>(null);
    const initialScrolledRef = useRef(false);
    const accountRef = useRef<string | null>(account);
    const wsSubRef = useRef<ReturnType<typeof connectPublicChatWebSocket> | null>(null);
    accountRef.current = account;

    const normalizeOnlineStats = (raw: any) => ({
      watching: Number(raw?.watching ?? raw?.public_viewers ?? raw?.public_room_sockets ?? 0),
      active_live: Number(
        raw?.active_live ?? raw?.authenticated_users ?? raw?.authenticated_online ?? 0
      ),
    });

    const loadFeed = useCallback(async (walletAddr?: string | null) => {
      try {
        const feed = await fetchPublicChatFeed(null, 50, walletAddr ?? accountRef.current);
        setMessages(feed.messages);
        setNextBeforeSeq(feed.next_before_seq);
        setOnlineStats(normalizeOnlineStats(feed.online));
        setPolicy(feed.policy);
        setErrorMsg(null);
        if (!initialScrolledRef.current) {
          initialScrolledRef.current = true;
          setTimeout(() => {
            streamRef.current?.scrollTo({ top: streamRef.current.scrollHeight });
          }, 40);
        }
      } catch (err: any) {
        setErrorMsg(err?.message || 'Unable to load Open Public Chat');
      }
    }, []);

    useEffect(() => {
      loadFeed(accountRef.current);
      const wsSub = connectPublicChatWebSocket((evt) => {
        if (evt.online) {
          setOnlineStats(normalizeOnlineStats(evt.online));
        }
        if (evt.type === 'ws_reconnected') {
          // Socket was down (sleep / offline / server restart): re-sync anything we missed.
          void loadFeed(accountRef.current);
          return;
        }
        if (evt.type === 'public_message_created' && evt.message) {
          setMessages((prev) => {
            if (prev.some((m) => m.message_id === evt.message.message_id)) {
              return prev;
            }
            const optIdx = prev.findIndex(
              (m) =>
                (m as any).isOptimistic &&
                m.content === evt.message.content &&
                m.author_user_id === evt.message.author_user_id
            );
            if (optIdx !== -1) {
              const next = [...prev];
              next[optIdx] = evt.message;
              return next;
            }
            return [...prev, evt.message];
          });
          setTimeout(() => {
            streamRef.current?.scrollTo({ top: streamRef.current.scrollHeight, behavior: 'smooth' });
          }, 40);
        } else if (evt.type === 'public_message_edited' && evt.update) {
          setMessages((prev) =>
            prev.map((m) =>
              m.message_id === evt.update.message_id
                ? { ...m, content: evt.update.content, edited_at: evt.update.edited_at }
                : m
            )
          );
        } else if (evt.type === 'public_message_deleted' && evt.message_id) {
          setMessages((prev) => prev.filter((m) => m.message_id !== evt.message_id));
        }
      }, accountRef.current);
      wsSubRef.current = wsSub;
      return () => {
        wsSubRef.current = null;
        wsSub.close();
      };
    }, [loadFeed]);

    // Transition socket between non-connected "Watching" and MetaMask-connected "Active Live"
    useEffect(() => {
      wsSubRef.current?.setMemberWallet(account);
      if (!account) {
        setOnlineStats((prev) => ({ ...prev, active_live: 0 }));
      }
    }, [account]);

    const handleLoadOlder = async () => {
      if (!nextBeforeSeq) return;
      try {
        const older = await fetchPublicChatFeed(nextBeforeSeq, 40);
        setMessages((prev) => [...older.messages, ...prev]);
        setNextBeforeSeq(older.next_before_seq);
      } catch (err: any) {
        setErrorMsg(err?.message || 'Failed to load older messages');
      }
    };

    const isWalletMismatch = Boolean(
      account &&
      e2eeProfile &&
      !e2eeProfile.wallets.some(
        (w) => w.wallet_address.toLowerCase() === account.toLowerCase()
      )
    );

    const handleSend = async (e: React.FormEvent) => {
      e.preventDefault();
      if (!account) {
        onConnectWallet();
        return;
      }
      if (!e2eeProfile || isWalletMismatch) {
        onAuthenticateSiwe();
        return;
      }
      const trimmed = input.trim();
      if (!trimmed || sending) return;
      setSending(true);
      setErrorMsg(null);
      setLastFailedText(null);

      const tempId = `temp_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
      const optimisticMsg: PublicChatMessageRecord & { isOptimistic?: boolean } = {
        seq: Date.now(),
        message_id: tempId,
        author_user_id: e2eeProfile.user_id,
        guest_id: null,
        display_name: e2eeProfile.username
          ? `@${e2eeProfile.username}`
          : `User-${e2eeProfile.user_id.slice(4, 10)}`,
        author_level: 7,
        is_guest: false,
        content: trimmed,
        edited_at: null,
        created_at: new Date().toISOString(),
        isOptimistic: true,
      };

      setMessages((prev) => [...prev, optimisticMsg]);
      setInput('');
      setTimeout(() => {
        streamRef.current?.scrollTo({ top: streamRef.current.scrollHeight, behavior: 'smooth' });
      }, 20);

      try {
        const res = await postPublicChatMessage(
          trimmed,
          Boolean(account && e2eeProfile && !isWalletMismatch)
        );
        setMessages((prev) =>
          prev.map((m) =>
            m.message_id === tempId || m.message_id === res.message.message_id ? res.message : m
          )
        );
        setTimeout(() => {
          streamRef.current?.scrollTo({ top: streamRef.current.scrollHeight, behavior: 'smooth' });
        }, 30);
      } catch (err: any) {
        setMessages((prev) => prev.filter((m) => m.message_id !== tempId));
        setErrorMsg(err?.message || 'Message was not sent (server rejected or storage failed)');
        setLastFailedText(trimmed);
        setInput(trimmed);
      } finally {
        setSending(false);
      }
    };

    const handleRetryPublicSend = () => {
      if (!lastFailedText) return;
      setInput(lastFailedText);
      setErrorMsg(null);
      setLastFailedText(null);
    };

    const canPost = Boolean(account && e2eeProfile && !isWalletMismatch);
    const isModerator = Boolean(e2eeProfile?.admin_role);

    return (
      <div
        className={embedded ? 'chat-viewport' : 'deck-card'}
        style={
          embedded
            ? { overflow: 'hidden' }
            : {
              padding: 0,
              overflow: 'hidden',
              display: 'flex',
              flexDirection: 'column',
              height: 'calc(100vh - 150px)',
              minHeight: '560px',
            }
        }
      >
        {/* Header */}
        <div className="chat-stage-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0, flex: 1 }}>
            {onToggleChannels && (
              <button
                type="button"
                className="mobile-channels-toggle-btn"
                onClick={onToggleChannels}
                title="Chats Menu"
                aria-label="Chats Menu"
              >
                <Menu size={14} />
                <span>Chats</span>
              </button>
            )}
            <div style={{ minWidth: 0, flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, flexWrap: 'wrap' }}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                  <Globe size={18} />
                  <span>Open Public Chat Room</span>
                </span>
                <span className="audit-status">PUBLIC</span>
              </div>
              <div
                style={{
                  fontSize: '0.75rem',
                  color: 'var(--text-muted)',
                  marginTop: '2px',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                {onlineStats.watching} Watching
                {account && (
                  <>
                    {' '}&bull; {onlineStats.active_live} Active Live
                  </>
                )}{' '}
                &bull;{' '}
                {account ? (
                  <>
                    Posting as{' '}
                    <strong>
                      {e2eeProfile
                        ? e2eeProfile.username
                          ? `@${e2eeProfile.username}`
                          : `${e2eeProfile.user_id.slice(0, 12)}`
                        : `${account.slice(0, 6)}...${account.slice(-4)}`}
                    </strong>
                  </>
                ) : (
                  <strong style={{ color: 'var(--text-secondary)' }}>
                    Connect MetaMask to Chat
                  </strong>
                )}
              </div>
            </div>
          </div>

          {account && !e2eeProfile && (
            <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexShrink: 0 }}>
              <button
                type="button"
                className="btn-solid"
                style={{ padding: '6px 12px', fontSize: '0.76rem' }}
                disabled={siweLoading}
                onClick={onAuthenticateSiwe}
              >
                <KeyRound size={13} />
                <span>{siweLoading ? 'Signing...' : 'Verify Wallet (SIWE)'}</span>
              </button>
            </div>
          )}
        </div>

        {/* Honest Security Disclosure Banner */}
        <div
          style={{
            padding: '8px 20px',
            background: 'var(--bg-surface)',
            borderBottom: '1px solid var(--border-subtle)',
            fontSize: '0.75rem',
            color: 'var(--text-secondary)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <AlertTriangle size={14} style={{ flexShrink: 0 }} />
          <span>
            <strong>Non-Confidential Public Channel:</strong> Readable by all members and subject to
            platform moderation. For end-to-end encryption, use <strong>Private</strong> or{' '}
            <strong>Groups</strong>.
          </span>
        </div>

        {errorMsg && (
          <div
            style={{
              padding: '8px 20px',
              borderBottom: '1px solid var(--border-strong)',
              fontSize: '0.78rem',
              color: 'var(--color-danger, #ef4444)',
              background: 'rgba(239, 68, 68, 0.08)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '12px',
            }}
          >
            <span>{errorMsg}</span>
            {lastFailedText && (
              <button
                type="button"
                className="btn-outline"
                onClick={handleRetryPublicSend}
                style={{
                  padding: '2px 8px',
                  fontSize: '0.72rem',
                  borderRadius: '4px',
                  borderColor: 'currentColor',
                  color: 'inherit',
                  cursor: 'pointer',
                }}
              >
                Retry
              </button>
            )}
          </div>
        )}

        {/* Stream */}
        <div className="chat-stream-body" ref={streamRef} style={{ flex: 1, overflowY: 'auto' }}>
          {nextBeforeSeq && (
            <div style={{ textAlign: 'center', marginBottom: '12px' }}>
              <button
                type="button"
                className="btn-outline"
                style={{ padding: '5px 14px', fontSize: '0.75rem' }}
                onClick={handleLoadOlder}
              >
                Load Older Messages
              </button>
            </div>
          )}

          {messages.length === 0 ? (
            <div
              style={{
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--text-muted)',
                gap: '8px',
              }}
            >
              <Globe size={34} strokeWidth={1.5} />
              <div>Open Public Chat is ready — start the conversation!</div>
            </div>
          ) : (
            messages.map((m) => {
              const isMine = Boolean(
                e2eeProfile && m.author_user_id && m.author_user_id === e2eeProfile.user_id
              );
              const isOpt = Boolean((m as any).isOptimistic);
              const getInitials = (name: string) => {
                if (!name) return 'U';
                const clean = name.replace(/^[@~]/, '').trim();
                if (clean.toLowerCase().startsWith('user-')) {
                  return clean.slice(5, 7).toUpperCase() || 'U';
                }
                return clean.slice(0, 2).toUpperCase() || 'U';
              };
              const initials = getInitials(m.display_name);

              return (
                <div
                  key={m.message_id}
                  className={`chat-message-row ${isOpt ? 'is-optimistic' : ''}`}
                  style={{
                    display: 'flex',
                    flexDirection: isMine ? 'row-reverse' : 'row',
                    alignItems: 'flex-start',
                    gap: '12px',
                    marginBottom: '14px',
                    maxWidth: '85%',
                    alignSelf: isMine ? 'flex-end' : 'flex-start',
                  }}
                >
                  {/* Modern Avatar */}
                  <div
                    className="chat-avatar"
                    style={{
                      width: '32px',
                      height: '32px',
                      borderRadius: '8px',
                      fontSize: '0.74rem',
                      fontWeight: 700,
                      flexShrink: 0,
                      background: isMine ? 'var(--text-main)' : 'var(--bg-pill)',
                      color: isMine ? 'var(--text-inverse)' : 'var(--text-main)',
                      border: '1px solid var(--border-strong)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontFamily: 'ui-monospace, monospace',
                    }}
                  >
                    {initials}
                  </div>

                  {/* Packet & Header */}
                  <div
                    className="chat-packet"
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: isMine ? 'flex-end' : 'flex-start',
                      maxWidth: '100%',
                    }}
                  >
                    <div
                      className="chat-msg-header"
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                        fontSize: '0.72rem',
                        color: 'var(--text-muted)',
                        marginBottom: '4px',
                        flexWrap: 'wrap',
                      }}
                    >
                      <strong
                        style={{
                          color: 'var(--text-main)',
                          fontFamily: 'ui-monospace, monospace',
                          cursor: !m.is_guest && m.author_user_id && !isMine ? 'pointer' : 'default',
                        }}
                        onClick={() => {
                          if (!m.is_guest && m.author_user_id && !isMine) {
                            onStartPrivateChat(m.author_user_id);
                          }
                        }}
                        title={!m.is_guest && !isMine ? 'Click to start E2EE Private Chat' : undefined}
                      >
                        {m.display_name}
                      </strong>
                      <span className="audit-status" style={{ fontSize: '0.64rem', padding: '1px 6px' }}>
                        {m.is_guest ? 'GUEST' : 'VERIFIED'}
                      </span>
                      <span>
                        {new Date(m.created_at).toLocaleTimeString([], {
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </span>
                      {m.edited_at && <span>(edited)</span>}
                      {isOpt && (
                        <span style={{ fontSize: '0.66rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                          Sending...
                        </span>
                      )}

                      {/* Inline Action Buttons with Smooth Hover Cluster */}
                      {!isOpt && (
                        <span className="chat-action-cluster">
                          {isMine && (
                            <button
                              type="button"
                              className="chat-copy-btn"
                              title="Edit Message"
                              onClick={() => {
                                setEditingId(m.message_id);
                                setEditText(m.content);
                              }}
                            >
                              <Edit3 size={11} />
                            </button>
                          )}
                          {(isMine || isModerator) && (
                            <button
                              type="button"
                              className="chat-copy-btn"
                              title="Delete Message"
                              onClick={async () => {
                                try {
                                  await deletePublicChatMessage(m.message_id, 'Deleted from UI');
                                  setMessages((prev) =>
                                    prev.filter((item) => item.message_id !== m.message_id)
                                  );
                                } catch (err: any) {
                                  setErrorMsg(err?.message || 'Delete window expired or unauthorized');
                                }
                              }}
                            >
                              <Trash2 size={11} />
                            </button>
                          )}
                          {!isMine && e2eeProfile && m.author_user_id && (
                            <button
                              type="button"
                              className="chat-copy-btn"
                              title="Block Author"
                              onClick={async () => {
                                await blockUser(m.author_user_id!, 'Blocked in Open Public Chat');
                                await loadFeed();
                              }}
                            >
                              <Ban size={11} />
                            </button>
                          )}
                          {!isMine && e2eeProfile && (
                            <button
                              type="button"
                              className="chat-copy-btn"
                              title="Report Message"
                              onClick={async () => {
                                const reason = prompt('Reason for reporting this public message:');
                                if (!reason?.trim()) return;
                                await submitAbuseReport({
                                  scope_type: 'public_chat',
                                  scope_id: 'open_public',
                                  message_id: m.message_id,
                                  target_user_id: m.author_user_id,
                                  reason: reason.trim(),
                                });
                                alert('Report submitted to moderators.');
                              }}
                            >
                              <Flag size={11} />
                            </button>
                          )}
                        </span>
                      )}
                    </div>

                    {editingId === m.message_id ? (
                      <div style={{ display: 'flex', gap: '6px', width: '100%', maxWidth: '520px' }}>
                        <input
                          type="text"
                          value={editText}
                          onChange={(e) => setEditText(e.target.value)}
                          style={{
                            flex: 1,
                            background: 'var(--bg-input)',
                            border: '1px solid var(--border-focus)',
                            borderRadius: '8px',
                            padding: '8px 12px',
                            color: 'var(--text-main)',
                            fontSize: '0.86rem',
                          }}
                        />
                        <button
                          type="button"
                          className="btn-solid"
                          style={{ padding: '6px 12px', fontSize: '0.76rem' }}
                          onClick={async () => {
                            try {
                              const updated = await editPublicChatMessage(m.message_id, editText);
                              setMessages((prev) =>
                                prev.map((item) =>
                                  item.message_id === m.message_id
                                    ? {
                                      ...item,
                                      content: updated.content,
                                      edited_at: updated.edited_at,
                                    }
                                    : item
                                )
                              );
                              setEditingId(null);
                            } catch (err: any) {
                              setErrorMsg(err?.message || 'Edit failed');
                            }
                          }}
                        >
                          Save
                        </button>
                        <button
                          type="button"
                          className="btn-outline"
                          style={{ padding: '6px 10px', fontSize: '0.76rem' }}
                          onClick={() => setEditingId(null)}
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <div
                        className={`chat-message-bubble ${isMine ? 'bubble-me' : 'bubble-peer'}`}
                        style={{
                          padding: '11px 16px',
                          borderRadius: isMine ? '16px 16px 4px 16px' : '16px 16px 16px 4px',
                          background: isMine ? 'var(--text-main)' : 'var(--bg-input)',
                          color: isMine ? 'var(--text-inverse)' : 'var(--text-main)',
                          border: '1px solid var(--border-subtle)',
                          fontSize: '0.88rem',
                          lineHeight: '1.45',
                          wordBreak: 'break-word',
                          boxShadow: isMine
                            ? '0 3px 12px rgba(255, 255, 255, 0.08)'
                            : '0 2px 8px rgba(0, 0, 0, 0.35)',
                          opacity: isOpt ? 0.72 : 1,
                          transition: 'opacity 0.2s ease, transform 0.2s ease',
                        }}
                      >
                        {m.content}
                      </div>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Composer Bar */}
        <div className="chat-composer-bar">
          {account && isPlatformPaid === false ? (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                width: '100%',
                padding: '10px 16px',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                borderRadius: '9999px',
                gap: '12px',
              }}
            >
              <span style={{ fontSize: '0.86rem', color: 'var(--text-main)' }}>
                <strong>Platform Admission Required:</strong> Pay the one-time ETH entry fee to chat.
              </span>
              <button
                type="button"
                className="btn-solid"
                style={{ padding: '6px 14px', fontSize: '0.8rem', whiteSpace: 'nowrap' }}
                onClick={onOpenAdmissionModal}
              >
                Pay Admission Fee
              </button>
            </div>
          ) : (
            <form
              onSubmit={handleSend}
              onClick={() => {
                if (!account) {
                  onConnectWallet();
                } else if (!e2eeProfile) {
                  onAuthenticateSiwe();
                }
              }}
              style={{ display: 'flex', gap: '10px', width: '100%' }}
            >
              <input
                type="text"
                maxLength={policy.max_length}
                disabled={!canPost || sending}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder={
                  canPost
                    ? `Message Open Public Chat (max ${policy.max_length} chars)...`
                    : account
                      ? 'Click to sign in (SIWE) and chat with your verified wallet identity'
                      : 'Connect MetaMask wallet to chat in Open Public Chat'
                }
                title={
                  canPost
                    ? undefined
                    : account
                      ? 'Click to sign EIP-4361 SIWE challenge'
                      : 'Click to connect MetaMask wallet'
                }
                style={{
                  flex: 1,
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-strong)',
                  borderRadius: '9999px',
                  padding: '11px 18px',
                  color: 'var(--text-main)',
                  fontSize: '0.9rem',
                  outline: 'none',
                  cursor: canPost ? 'text' : 'pointer',
                  opacity: canPost ? 1 : 0.65,
                }}
              />
              <button
                type="submit"
                className="btn-solid"
                disabled={!canPost || !input.trim() || sending}
                title={
                  !canPost
                    ? 'Connect MetaMask wallet to send messages'
                    : !input.trim()
                      ? 'Enter a message to send'
                      : 'Send message'
                }
                style={{
                  width: '44px',
                  height: '44px',
                  borderRadius: '50%',
                  padding: 0,
                  justifyContent: 'center',
                }}
              >
                <Send size={16} />
              </button>
            </form>
          )}
        </div>
      </div>
    );
  };

// ============================================================================
// 3. DISCOVER USERS & LEVEL-GATED GROUPS VIEW
// ============================================================================

export const DiscoverUsersView: React.FC<{
  e2eeProfile: E2EEAccountProfile | null;
  onStartPrivateChat: (identifier: string) => void;
  onNavigateGroups: () => void;
  onOpenPaidGroupModal?: (groupId: string, groupName?: string) => void;
}> = ({ e2eeProfile, onStartPrivateChat, onNavigateGroups, onOpenPaidGroupModal }) => {
  const [query, setQuery] = useState('');
  const [users, setUsers] = useState<DirectoryUserRecord[]>([]);
  const [publicGroups, setPublicGroups] = useState<DiscoverableGroupRecord[]>([]);
  const [inviteCode, setInviteCode] = useState('');
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const runSearch = useCallback(async (q: string) => {
    setLoading(true);
    try {
      const [uRes, gRes] = await Promise.all([searchUsers(q, 30), discoverPublicGroups()]);
      setUsers(uRes.users);
      setPublicGroups(gRes.groups);
    } catch (err: any) {
      setStatusMsg(err?.message || 'Directory lookup failed');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    runSearch('');
  }, [runSearch]);

  // A group payment finished somewhere else in the app: refresh so "Pay & Join" updates.
  useEffect(() => {
    const refresh = () => void runSearch('');
    window.addEventListener('zyphra:groups-changed', refresh);
    return () => window.removeEventListener('zyphra:groups-changed', refresh);
  }, [runSearch]);

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '22px' }}>
      {/* Left: Username Search Directory */}
      <div className="deck-card">
        <div className="deck-header">
          <div>
            <div className="deck-title">
              <Search size={18} /> Username Directory
            </div>
            <div className="deck-subtitle">
              Search verified accounts by unique <code>@username</code> and launch
              Private Chats.
            </div>
          </div>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            runSearch(query);
          }}
          style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}
        >
          <input
            type="text"
            placeholder="Search @username or wallet..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{
              flex: 1,
              background: 'var(--bg-input)',
              border: '1px solid var(--border-strong)',
              borderRadius: '10px',
              padding: '10px 14px',
              color: 'var(--text-main)',
              fontSize: '0.86rem',
            }}
          />
          <button type="submit" className="btn-solid" disabled={loading}>
            Search
          </button>
        </form>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {users.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.84rem', padding: '16px 0' }}>
              {loading ? 'Searching directory...' : 'No matching users found.'}
            </div>
          ) : (
            users.map((u) => (
              <div
                key={u.user_id}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '12px 14px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '12px',
                  gap: '12px',
                  flexWrap: 'wrap',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 600 }}>
                    <span style={{ fontFamily: 'ui-monospace, monospace' }}>
                      {u.username ? `@${u.username}` : u.user_id.slice(0, 14)}
                    </span>
                    <span className="audit-status" style={{ fontSize: '0.66rem' }}>
                      Member
                    </span>
                    {u.online && (
                      <span
                        style={{
                          fontSize: '0.68rem',
                          color: '#10b981',
                          fontWeight: 600,
                        }}
                      >
                        ● Online
                      </span>
                    )}
                  </div>
                  {u.bio && (
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '3px' }}>
                      {u.bio}
                    </div>
                  )}
                </div>

                <div style={{ display: 'flex', gap: '6px' }}>
                  <button
                    type="button"
                    className="btn-solid"
                    style={{ padding: '6px 12px', fontSize: '0.76rem' }}
                    onClick={() => onStartPrivateChat(u.username ? `@${u.username}` : u.user_id)}
                  >
                    <Lock size={12} />
                    <span>Message E2EE</span>
                  </button>
                  {e2eeProfile && (
                    <button
                      type="button"
                      className="btn-outline"
                      style={{ padding: '6px 10px', fontSize: '0.74rem' }}
                      title="Block User"
                      onClick={async () => {
                        await blockUser(u.user_id, 'Blocked from directory');
                        setStatusMsg(`Blocked ${u.username ? `@${u.username}` : u.user_id}`);
                      }}
                    >
                      <Ban size={12} />
                    </button>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Right: Public Group Discovery + Invite Code Join */}
      <div className="deck-card">
        <div className="deck-header">
          <div>
            <div className="deck-title">
              <Users size={18} /> Public &amp; Paid Groups
            </div>
            <div className="deck-subtitle">
              Redeem an invite code or join verified public and paid Ethereum channels.
            </div>
          </div>
        </div>

        {statusMsg && (
          <div
            style={{
              padding: '10px 12px',
              marginBottom: '12px',
              background: 'var(--bg-input)',
              border: '1px solid var(--border-strong)',
              borderRadius: '8px',
              fontSize: '0.8rem',
            }}
          >
            {statusMsg}
          </div>
        )}

        <form
          onSubmit={async (e) => {
            e.preventDefault();
            if (!inviteCode.trim()) return;
            try {
              const res = await joinGroupByInviteCode(inviteCode.trim());
              setInviteCode('');
              const reqId = res.request_id ? `(${res.request_id.slice(0, 10)})` : '';
              setStatusMsg(
                `Eligibility verified! Join request ${reqId} queued for group admin MLS Welcome encryption.`
              );
            } catch (err: any) {
              setStatusMsg(err?.message || 'Invite redemption failed');
            }
          }}
          style={{ display: 'flex', gap: '8px', marginBottom: '18px' }}
        >
          <input
            type="text"
            placeholder="Paste invite code (zinv_...)"
            value={inviteCode}
            onChange={(e) => setInviteCode(e.target.value)}
            style={{
              flex: 1,
              background: 'var(--bg-input)',
              border: '1px solid var(--border-strong)',
              borderRadius: '10px',
              padding: '10px 14px',
              color: 'var(--text-main)',
              fontSize: '0.82rem',
              fontFamily: 'ui-monospace, monospace',
            }}
          />
          <button type="submit" className="btn-solid" disabled={!e2eeProfile || !inviteCode.trim()}>
            <Link2 size={14} />
            <span>Redeem</span>
          </button>
        </form>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {publicGroups.length === 0 ? (
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
              No public groups listed yet. Create a public MLS group in the Groups tab!
            </div>
          ) : (
            publicGroups.map((g) => (
              <div
                key={g.group_id}
                style={{
                  padding: '12px 14px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '12px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  gap: '10px',
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, fontSize: '0.88rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span>{g.name}</span>
                    {g.is_paid && (
                      <span
                        style={{
                          fontSize: '0.66rem',
                          fontWeight: 700,
                          padding: '1px 6px',
                          borderRadius: '4px',
                          backgroundColor: 'rgba(234, 179, 8, 0.15)',
                          color: '#eab308',
                          border: '1px solid rgba(234, 179, 8, 0.3)',
                        }}
                      >
                        PAID &bull; {formatGroupFee(g)}
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                    {g.is_paid ? (
                      <>
                        Paid Group &bull; Entry Fee: <strong>{formatGroupFee(g)}</strong> &bull;{' '}
                        {g.active_member_count} members
                      </>
                    ) : (
                      <>Free Group &bull; {g.active_member_count} members</>
                    )}
                  </div>
                  {g.description && (
                    <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '3px' }}>
                      {g.description}
                    </div>
                  )}
                </div>

                {g.is_member ? (
                  <button
                    type="button"
                    className="btn-outline"
                    style={{ padding: '6px 12px', fontSize: '0.75rem' }}
                    onClick={onNavigateGroups}
                  >
                    Open Group
                  </button>
                ) : g.is_paid && !g.has_paid ? (
                  <button
                    type="button"
                    className="btn-solid"
                    disabled={!e2eeProfile}
                    style={{
                      padding: '6px 12px',
                      fontSize: '0.75rem',
                      backgroundColor: '#eab308',
                      color: '#000000',
                      fontWeight: 600,
                    }}
                    onClick={() => {
                      if (onOpenPaidGroupModal) {
                        onOpenPaidGroupModal(g.group_id, g.name);
                      }
                    }}
                  >
                    Pay &amp; Join
                  </button>
                ) : (
                  <button
                    type="button"
                    className="btn-solid"
                    disabled={!e2eeProfile}
                    style={{ padding: '6px 12px', fontSize: '0.75rem' }}
                    onClick={async () => {
                      try {
                        await requestJoinPublicGroup(g.group_id);
                        setStatusMsg(
                          `Join request submitted for "${g.name}"! Group admins can now approve your MLS Welcome.`
                        );
                      } catch (err: any) {
                        setStatusMsg(err?.message || 'Join request denied by group policy');
                      }
                    }}
                  >
                    Request Join
                  </button>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// 4. MY PROFILE & PERMANENT IDENTITY / WALLET MIGRATION VIEW
// ============================================================================

export const MyProfileView: React.FC<{
  account: string | null;
  chainIdHex: string | null;
  e2eeProfile: E2EEAccountProfile | null;
  siweLoading: boolean;
  onConnectWallet: () => void;
  onAuthenticateSiwe: () => void;
  onProfileUpdated: (profile: E2EEAccountProfile) => void;
}> = ({
  account,
  chainIdHex,
  e2eeProfile,
  siweLoading,
  onConnectWallet,
  onAuthenticateSiwe,
  onProfileUpdated,
}) => {
    const [usernameInput, setUsernameInput] = useState(e2eeProfile?.username || '');
    const [bio, setBio] = useState(e2eeProfile?.bio || '');
    const [historyData, setHistoryData] = useState<any>(null);
    const [statusMsg, setStatusMsg] = useState<{ text: string; isError: boolean } | null>(null);
    const [busy, setBusy] = useState(false);
    const [copiedUid, setCopiedUid] = useState(false);
    const [usernameCheck, setUsernameCheck] = useState<{
      checking: boolean;
      available?: boolean;
      is_current?: boolean;
      reason?: string | null;
    }>({ checking: false });

    const loadHistory = useCallback(() => {
      if (!e2eeProfile) return;
      fetchMyIdentityHistory()
        .then((res) => setHistoryData(res))
        .catch(() => { });
    }, [e2eeProfile]);

    useEffect(() => {
      setUsernameInput(e2eeProfile?.username || '');
      setBio(e2eeProfile?.bio || '');
      loadHistory();
    }, [e2eeProfile, loadHistory]);

    // Real-time debounced username uniqueness and validity checker
    useEffect(() => {
      const trimmed = usernameInput.trim();
      if (!trimmed) {
        setUsernameCheck({ checking: false });
        return;
      }
      const clean = trimmed.startsWith('@') ? trimmed.slice(1) : trimmed;
      if (e2eeProfile?.username && clean.toLowerCase() === e2eeProfile.username.toLowerCase()) {
        setUsernameCheck({
          checking: false,
          available: true,
          is_current: true,
          reason: 'Your current username',
        });
        return;
      }
      if (!/^[a-zA-Z0-9_]{3,32}$/.test(clean)) {
        setUsernameCheck({
          checking: false,
          available: false,
          reason: 'Must be 3-32 characters (letters, numbers, or underscores only)',
        });
        return;
      }
      setUsernameCheck({ checking: true });
      const timer = setTimeout(() => {
        checkUsernameAvailability(clean)
          .then((res) => {
            setUsernameCheck({
              checking: false,
              available: res.available,
              is_current: res.is_current,
              reason: res.reason,
            });
          })
          .catch(() => {
            setUsernameCheck({ checking: false });
          });
      }, 280);
      return () => clearTimeout(timer);
    }, [usernameInput, e2eeProfile?.username]);

    if (!account || !e2eeProfile) {
      return (
        <div className="deck-card" style={{ textAlign: 'center', padding: '48px 24px' }}>
          <User size={36} style={{ marginBottom: '12px' }} />
          <h2 style={{ fontSize: '1.2rem', fontWeight: 700 }}>Authenticate Your Permanent Account</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.86rem', maxWidth: '460px', margin: '8px auto 20px' }}>
            Sign in with MetaMask via EIP-4361 (SIWE) to manage your permanent internal{' '}
            <code>user_id</code>, unique <code>@username</code>, and wallet history.
          </p>
          {!account ? (
            <button type="button" className="btn-solid" onClick={onConnectWallet}>
              <Wallet size={15} />
              <span>Connect MetaMask</span>
            </button>
          ) : (
            <button type="button" className="btn-solid" disabled={siweLoading} onClick={onAuthenticateSiwe}>
              <KeyRound size={15} />
              <span>{siweLoading ? 'Signing SIWE...' : 'Sign In with Ethereum (SIWE)'}</span>
            </button>
          )}
        </div>
      );
    }

    const isConnectedWalletLinked = e2eeProfile.wallets.some(
      (w) => w.wallet_address.toLowerCase() === account.toLowerCase() && w.status === 'active'
    );

    const handleWalletMigration = async (revokePrevious: boolean) => {
      setBusy(true);
      setStatusMsg(null);
      try {
        const chainNum = chainIdHex ? parseInt(chainIdHex, 16) || 1 : 1;
        const chal = await requestE2EEAuthChallenge(account, 'link_wallet', chainNum);
        const sig = await (window as any).ethereum.request({
          method: 'personal_sign',
          params: [chal.message, account],
        });
        const res = await linkNewWalletToE2EEAccount({
          challenge_id: chal.challenge_id,
          new_wallet_address: account,
          signature: sig,
          make_primary: true,
          revoke_previous_wallets: revokePrevious,
        });
        onProfileUpdated(res.user);
        loadHistory();
        setStatusMsg({
          text: revokePrevious
            ? 'Primary wallet replaced & old wallet sessions revoked! Permanent user_id and messages preserved.'
            : 'Additional wallet linked to your permanent user_id!',
          isError: false,
        });
      } catch (err: any) {
        setStatusMsg({ text: err?.message || 'Wallet change failed', isError: true });
      } finally {
        setBusy(false);
      }
    };

    return (
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '22px' }}>
        <div className="deck-card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div className="deck-title">
            <User size={18} /> Permanent Identity &amp; Profile
          </div>

          {statusMsg && (
            <div
              style={{
                padding: '10px 14px',
                background: statusMsg.isError ? 'rgba(239, 68, 68, 0.08)' : 'rgba(16, 185, 129, 0.08)',
                border: `1px solid ${statusMsg.isError ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                color: statusMsg.isError ? '#ef4444' : '#10b981',
                borderRadius: '8px',
                fontSize: '0.82rem',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                fontWeight: 500,
              }}
            >
              {statusMsg.isError ? <AlertTriangle size={15} /> : <Check size={15} />}
              <span>{statusMsg.text}</span>
            </div>
          )}

          <div
            style={{
              padding: '14px',
              background: 'var(--bg-input)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '12px',
              fontSize: '0.8rem',
            }}
          >
            <div style={{ color: 'var(--text-secondary)', marginBottom: '4px' }}>
              Immutable Internal User ID (Never changes across username or wallet updates):
            </div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
              <code style={{ fontFamily: 'ui-monospace, monospace', fontWeight: 700 }}>
                {e2eeProfile.user_id}
              </code>
              <button
                type="button"
                className="btn-outline"
                style={{ padding: '4px 8px', fontSize: '0.72rem' }}
                onClick={() => {
                  navigator.clipboard.writeText(e2eeProfile.user_id);
                  setCopiedUid(true);
                  setTimeout(() => setCopiedUid(false), 1800);
                }}
              >
                {copiedUid ? <Check size={12} /> : <Copy size={12} />}
              </button>
            </div>
          </div>

          {/* Case-insensitive Unique Username with Cooldown & Live Verification */}
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              const clean = usernameInput.trim().replace(/^@/, '');
              if (!clean || busy || usernameCheck.available === false || usernameCheck.is_current) return;
              setBusy(true);
              setStatusMsg(null);
              try {
                const res = await updateMyE2EEUsername(clean);
                onProfileUpdated(res.user);
                loadHistory();
                setStatusMsg({
                  text: `Username successfully updated to @${res.user.username}!`,
                  isError: false,
                });
              } catch (err: any) {
                setStatusMsg({ text: err?.message || 'Username update rejected', isError: true });
              } finally {
                setBusy(false);
              }
            }}
            style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}
          >
            <label style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', fontWeight: 600 }}>
              UNIQUE @USERNAME (CASE-INSENSITIVE • COOLDOWN &amp; RESERVATION PROTECTED)
            </label>
            <div style={{ display: 'flex', gap: '8px' }}>
              <input
                type="text"
                value={usernameInput}
                onChange={(e) => setUsernameInput(e.target.value)}
                placeholder="e.g. CryptoExplorer"
                style={{
                  flex: 1,
                  background: 'var(--bg-input)',
                  border: `1px solid ${usernameInput.trim() && usernameCheck.available === false
                    ? 'rgba(239, 68, 68, 0.6)'
                    : usernameInput.trim() && usernameCheck.available && !usernameCheck.is_current
                      ? 'rgba(16, 185, 129, 0.6)'
                      : 'var(--border-strong)'
                    }`,
                  borderRadius: '10px',
                  padding: '10px 14px',
                  color: 'var(--text-main)',
                  fontSize: '0.86rem',
                  fontFamily: 'ui-monospace, monospace',
                }}
              />
              <button
                type="submit"
                className="btn-solid"
                disabled={
                  busy ||
                  usernameCheck.checking ||
                  usernameCheck.available === false ||
                  usernameCheck.is_current ||
                  !usernameInput.trim()
                }
              >
                Update @Username
              </button>
            </div>
            {usernameInput.trim() && (
              <div style={{ fontSize: '0.74rem', marginTop: '2px', display: 'flex', alignItems: 'center', gap: '5px' }}>
                {usernameCheck.checking ? (
                  <span style={{ color: 'var(--text-muted)' }}>
                    Checking @{usernameInput.trim().replace(/^@/, '')} availability...
                  </span>
                ) : usernameCheck.is_current ? (
                  <span style={{ color: 'var(--text-secondary)' }}>(Your current username)</span>
                ) : usernameCheck.available ? (
                  <span style={{ color: '#10b981', display: 'inline-flex', alignItems: 'center', gap: '4px', fontWeight: 600 }}>
                    <Check size={12} /> @{usernameInput.trim().replace(/^@/, '')} is available!
                  </span>
                ) : (
                  <span style={{ color: '#ef4444', display: 'inline-flex', alignItems: 'center', gap: '4px', fontWeight: 600 }}>
                    <AlertCircle size={12} /> {usernameCheck.reason || 'Username is already taken'}
                  </span>
                )}
              </div>
            )}
          </form>

          {/* Bio */}
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              setStatusMsg(null);
              try {
                const res = await updateMyProfile({
                  bio,
                });
                onProfileUpdated(res.user);
                setStatusMsg({ text: 'Bio saved successfully.', isError: false });
              } catch (err: any) {
                setStatusMsg({ text: err?.message || 'Failed to update bio', isError: true });
              } finally {
                setBusy(false);
              }
            }}
            style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}
          >
            <div>
              <label style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', fontWeight: 600 }}>
                BIO (MAX 280 CHARS)
              </label>
              <textarea
                rows={3}
                maxLength={280}
                value={bio}
                onChange={(e) => setBio(e.target.value)}
                placeholder="Short bio visible in username search..."
                style={{
                  width: '100%',
                  marginTop: '4px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-strong)',
                  borderRadius: '10px',
                  padding: '10px 14px',
                  color: 'var(--text-main)',
                  fontSize: '0.86rem',
                }}
              />
            </div>
            <button type="submit" className="btn-solid" disabled={busy} style={{ alignSelf: 'flex-start' }}>
              Save Bio
            </button>
          </form>
        </div>

        {/* Right: Secure Wallet Change + Audit Timelines */}
        <div className="deck-card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div className="deck-title">
            <History size={18} /> Wallet Associations &amp; Audit History
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {e2eeProfile.wallets.map((w) => (
              <div
                key={w.wallet_address}
                style={{
                  padding: '10px 12px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '10px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  fontFamily: 'ui-monospace, monospace',
                  fontSize: '0.8rem',
                }}
              >
                <span>{formatAddress(w.wallet_address, 6)}</span>
                <span>{w.is_primary ? 'PRIMARY WALLET' : w.status.toUpperCase()}</span>
              </div>
            ))}
          </div>

          {!isConnectedWalletLinked ? (
            <div
              style={{
                padding: '14px',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-strong)',
                borderRadius: '12px',
                display: 'flex',
                flexDirection: 'column',
                gap: '10px',
                fontSize: '0.8rem',
              }}
            >
              <div>
                MetaMask switched to unlinked wallet{' '}
                <code>{formatAddress(account, 5)}</code>. Sign a fresh SIWE challenge to replace or
                link it to <code>{e2eeProfile.user_id.slice(0, 14)}...</code>:
              </div>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="btn-solid"
                  disabled={busy}
                  onClick={() => handleWalletMigration(true)}
                >
                  Replace Primary Wallet &amp; Revoke Old Sessions
                </button>
                <button
                  type="button"
                  className="btn-outline"
                  disabled={busy}
                  onClick={() => handleWalletMigration(false)}
                >
                  Link as Secondary Wallet
                </button>
              </div>
            </div>
          ) : (
            <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
              To replace your wallet, switch to your new account inside MetaMask while signed in—a
              secure SIWE migration button will appear above automatically.
            </div>
          )}

          <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '12px' }}>
            <div style={{ fontSize: '0.78rem', fontWeight: 700, marginBottom: '6px' }}>
              Username History ({historyData?.username_history?.length || 0})
            </div>
            {(historyData?.username_history || []).slice(0, 5).map((h: any, idx: number) => (
              <div
                key={h.history_id || `${h.new_username}-${idx}`}
                style={{
                  fontSize: '0.74rem',
                  color: 'var(--text-secondary)',
                  fontFamily: 'ui-monospace, monospace',
                  padding: '4px 0',
                }}
              >
                {h.old_username ? `@${h.old_username} → ` : ''}@{h.new_username} (
                {h.changed_at ? new Date(h.changed_at).toLocaleDateString() : 'recent'})
              </div>
            ))}
          </div>

          <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '12px' }}>
            <div style={{ fontSize: '0.78rem', fontWeight: 700, marginBottom: '6px' }}>
              Wallet Change Audit Trail ({historyData?.wallet_history?.length || 0})
            </div>
            {(historyData?.wallet_history || []).slice(0, 5).map((wh: any, idx: number) => {
              const oldAddr = wh.old_wallet_address || wh.old_wallet;
              const newAddr = wh.new_wallet_address || wh.new_wallet;
              return (
                <div
                  key={wh.history_id || `${newAddr || idx}-${idx}`}
                  style={{
                    fontSize: '0.74rem',
                    color: 'var(--text-secondary)',
                    fontFamily: 'ui-monospace, monospace',
                    padding: '4px 0',
                  }}
                >
                  [{wh.action || 'change'}] {oldAddr ? `${formatAddress(oldAddr, 4)} → ` : ''}
                  {newAddr ? formatAddress(newAddr, 4) : 'wallet'} (
                  {wh.created_at ? new Date(wh.created_at).toLocaleDateString() : 'recent'})
                </div>
              );
            })}
          </div>
        </div>
      </div>
    );
  };

// ============================================================================
// 5. SETTINGS (WALLET, PRIVACY TOGGLES, BLOCKED USERS, THEME & ENDPOINT) VIEW
// ============================================================================

export const SettingsView: React.FC<{
  account?: string | null;
  e2eeProfile: E2EEAccountProfile | null;
  siweLoading?: boolean;
  onConnectWallet?: () => void;
  onAuthenticateSiwe?: () => void;
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
  onProfileUpdated: (profile: E2EEAccountProfile) => void;
  onNavigateDmVault: () => void;
  initialSubTab?: 'wallet_level' | 'privacy' | 'blocked';
}> = ({
  account,
  e2eeProfile,
  siweLoading = false,
  onConnectWallet,
  onAuthenticateSiwe,
  theme,
  onToggleTheme,
  onProfileUpdated,
  onNavigateDmVault,
  initialSubTab,
}) => {
    const [activeSubTab, setActiveSubTab] = useState<'wallet_level' | 'privacy' | 'blocked'>(
      initialSubTab || 'wallet_level'
    );

    useEffect(() => {
      if (initialSubTab) {
        setActiveSubTab(initialSubTab);
      }
    }, [initialSubTab]);

    const [verifying, setVerifying] = useState(false);
    const [verifyMsg, setVerifyMsg] = useState<string | null>(null);
    const [historyData, setHistoryData] = useState<any>(null);

    const loadHistory = useCallback(() => {
      if (e2eeProfile) {
        fetchMyIdentityHistory()
          .then((h) => setHistoryData(h))
          .catch(() => { });
      }
    }, [e2eeProfile]);

    useEffect(() => {
      loadHistory();
    }, [loadHistory]);

    const handleVerifyRpc = async () => {
      setVerifying(true);
      setVerifyMsg(null);
      try {
        const res = await verifyMyWalletBalance();
        onProfileUpdated(res.user);
        loadHistory();
        setVerifyMsg(
          `Verified on-chain via ${res.snapshot.rpc_source} at Block #${res.snapshot.block_number}: ${res.snapshot.balance_eth || formatEth(res.snapshot.balance_wei, 6)
          } ETH`
        );
      } catch (err: any) {
        setVerifyMsg(err?.message || 'Backend RPC balance verification failed');
      } finally {
        setVerifying(false);
      }
    };

    // Privacy & Blocks State
    const [blocked, setBlocked] = useState<any[]>([]);
    const [apiUrl, setApiUrl] = useState(getBaseApiUrl());
    const [statusMsg, setStatusMsg] = useState<string | null>(null);

    const loadBlocks = useCallback(() => {
      if (!e2eeProfile) return;
      fetchBlockedUsers()
        .then((r) => setBlocked(r.blocked_users))
        .catch(() => { });
    }, [e2eeProfile]);

    useEffect(() => {
      loadBlocks();
    }, [loadBlocks]);

    const togglePrivacy = async (field: 'show_online_presence' | 'send_read_receipts', value: boolean) => {
      try {
        const res = await updateMyProfile({ [field]: value });
        onProfileUpdated(res.user);
        setStatusMsg('Privacy preferences saved.');
      } catch (err: any) {
        setStatusMsg(err?.message || 'Failed to update privacy setting');
      }
    };

    return (
      <div style={{ display: 'flex', flexDirection: 'column' }}>
        {/* Settings Sub-Navigation Tabs */}
        <div
          style={{
            display: 'flex',
            gap: '8px',
            borderBottom: '1px solid var(--border-subtle)',
            paddingTop: '4px',
            paddingBottom: '12px',
            marginBottom: '20px',
            flexWrap: 'wrap',
          }}
        >
          <button
            type="button"
            className={`btn-outline ${activeSubTab === 'wallet_level' ? 'active' : ''}`}
            style={{
              padding: '8px 16px',
              fontSize: '0.82rem',
              gap: '8px',
              fontWeight: 600,
              borderColor:
                activeSubTab === 'wallet_level' ? 'var(--border-focus)' : 'var(--border-subtle)',
              background:
                activeSubTab === 'wallet_level' ? 'var(--bg-card)' : 'transparent',
              color:
                activeSubTab === 'wallet_level' ? 'var(--text-main)' : 'var(--text-secondary)',
            }}
            onClick={() => setActiveSubTab('wallet_level')}
          >
            <Award size={15} />
            <span>Wallet &amp; Membership</span>
          </button>

          <button
            type="button"
            className={`btn-outline ${activeSubTab === 'privacy' ? 'active' : ''}`}
            style={{
              padding: '8px 16px',
              fontSize: '0.82rem',
              gap: '8px',
              fontWeight: 600,
              borderColor:
                activeSubTab === 'privacy' ? 'var(--border-focus)' : 'var(--border-subtle)',
              background:
                activeSubTab === 'privacy' ? 'var(--bg-card)' : 'transparent',
              color:
                activeSubTab === 'privacy' ? 'var(--text-main)' : 'var(--text-secondary)',
            }}
            onClick={() => setActiveSubTab('privacy')}
          >
            <SettingsIcon size={15} />
            <span>Privacy &amp; Security</span>
          </button>

          <button
            type="button"
            className={`btn-outline ${activeSubTab === 'blocked' ? 'active' : ''}`}
            style={{
              padding: '8px 16px',
              fontSize: '0.82rem',
              gap: '8px',
              fontWeight: 600,
              borderColor:
                activeSubTab === 'blocked' ? 'var(--border-focus)' : 'var(--border-subtle)',
              background:
                activeSubTab === 'blocked' ? 'var(--bg-card)' : 'transparent',
              color:
                activeSubTab === 'blocked' ? 'var(--text-main)' : 'var(--text-secondary)',
            }}
            onClick={() => setActiveSubTab('blocked')}
          >
            <Ban size={15} />
            <span>Blocked Accounts ({blocked.length})</span>
          </button>
        </div>

        {/* Sub-Tab 1: Wallet & Membership */}
        {activeSubTab === 'wallet_level' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
            <div className="deck-card">
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '16px',
                }}
              >
                <div>
                  <div className="deck-title">
                    <Award size={20} /> Wallet &amp; On-Chain Balance Verification
                  </div>
                  <div className="deck-subtitle">
                    Verify your primary MetaMask wallet’s on-chain ETH balance directly against
                    Ethereum RPC—browser-reported balances are never trusted.
                  </div>
                </div>

                {!account ? (
                  onConnectWallet && (
                    <button type="button" className="btn-solid" onClick={onConnectWallet}>
                      <Wallet size={15} />
                      <span>Connect MetaMask</span>
                    </button>
                  )
                ) : !e2eeProfile ? (
                  onAuthenticateSiwe && (
                    <button
                      type="button"
                      className="btn-solid"
                      disabled={siweLoading}
                      onClick={onAuthenticateSiwe}
                    >
                      <KeyRound size={15} />
                      <span>{siweLoading ? 'Signing...' : 'Sign SIWE to Verify Wallet'}</span>
                    </button>
                  )
                ) : (
                  <button
                    type="button"
                    className="btn-solid"
                    disabled={verifying}
                    onClick={handleVerifyRpc}
                  >
                    <RefreshCw size={14} />
                    <span>
                      {verifying ? 'Querying Ethereum RPC...' : 'Verify On-Chain ETH Balance'}
                    </span>
                  </button>
                )}
              </div>

              {verifyMsg && (
                <div
                  style={{
                    marginTop: '14px',
                    padding: '10px 14px',
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-strong)',
                    borderRadius: '10px',
                    fontSize: '0.82rem',
                    fontFamily: 'ui-monospace, monospace',
                  }}
                >
                  {verifyMsg}
                </div>
              )}

              {e2eeProfile && (
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                    gap: '12px',
                    marginTop: '18px',
                  }}
                >
                  <div className="spec-badge" style={{ textAlign: 'left', padding: '14px' }}>
                    <strong>MEMBERSHIP STATUS</strong>
                    <span style={{ fontSize: '1.2rem', fontWeight: 800, color: 'var(--text-main)' }}>
                      {e2eeProfile.is_platform_paid || e2eeProfile.admin_role ? 'Paid Member' : 'Member'}
                    </span>
                  </div>
                  <div className="spec-badge" style={{ textAlign: 'left', padding: '14px' }}>
                    <strong>LAST RPC VERIFIED BALANCE</strong>
                    <span
                      style={{
                        fontSize: '1.1rem',
                        fontWeight: 700,
                        fontFamily: 'ui-monospace, monospace',
                        color: 'var(--text-main)',
                      }}
                    >
                      {formatEth(e2eeProfile.qualifying_balance_wei || '0', 6)} ETH
                    </span>
                  </div>
                </div>
              )}
            </div>

            {/* Balance Snapshots History */}
            {historyData?.balance_snapshots?.length > 0 && (
              <div className="deck-card">
                <div className="deck-title" style={{ marginBottom: '10px' }}>
                  Recent On-Chain RPC Balance Snapshots
                </div>
                {historyData.balance_snapshots.slice(0, 6).map((s: any) => (
                  <div
                    key={s.snapshot_id}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      padding: '8px 0',
                      borderBottom: '1px solid var(--border-subtle)',
                      fontSize: '0.78rem',
                      fontFamily: 'ui-monospace, monospace',
                    }}
                  >
                    <span>
                      Chain {s.chain_id} • Block #{s.block_number} ({s.rpc_source})
                    </span>
                    <span>
                      {formatEth(s.balance_wei, 6)} ETH
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Sub-Tab 2: Privacy & Security */}
        {activeSubTab === 'privacy' && (
          <div
            className="deck-card"
            style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '780px' }}
          >
            <div className="deck-title">
              <SettingsIcon size={18} /> Privacy, Appearance &amp; E2EE Security
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

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.88rem' }}>Interface Theme</div>
                <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
                  Switch between Cyber-Monolithic Dark and Light mode
                </div>
              </div>
              <button type="button" className="btn-outline" onClick={onToggleTheme}>
                {theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />}
                <span>{theme === 'dark' ? 'Switch to Light' : 'Switch to Dark'}</span>
              </button>
            </div>

            {e2eeProfile && (
              <>
                <label
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    paddingTop: '12px',
                    borderTop: '1px solid var(--border-subtle)',
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '0.88rem' }}>Show Online Presence</div>
                    <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
                      Allow other users in the username directory to see when you are online
                    </div>
                  </div>
                  <input
                    type="checkbox"
                    checked={e2eeProfile.show_online_presence !== false}
                    onChange={(e) => togglePrivacy('show_online_presence', e.target.checked)}
                  />
                </label>

                <label
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    paddingTop: '12px',
                    borderTop: '1px solid var(--border-subtle)',
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '0.88rem' }}>
                      Send Private Chat Read Receipts
                    </div>
                    <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
                      Notify conversation peers when you have decrypted &amp; viewed their DM
                    </div>
                  </div>
                  <input
                    type="checkbox"
                    checked={e2eeProfile.send_read_receipts !== false}
                    onChange={(e) => togglePrivacy('send_read_receipts', e.target.checked)}
                  />
                </label>

                <div style={{ paddingTop: '12px', borderTop: '1px solid var(--border-subtle)' }}>
                  <button type="button" className="btn-solid" onClick={onNavigateDmVault}>
                    <KeyRound size={14} />
                    <span>Manage E2EE Devices &amp; Prekeys in Enclave</span>
                  </button>
                </div>
              </>
            )}

            <div style={{ paddingTop: '12px', borderTop: '1px solid var(--border-subtle)' }}>
              <label
                style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontWeight: 600 }}
              >
                BACKEND API BASE URL
              </label>
              <div style={{ display: 'flex', gap: '8px', marginTop: '6px' }}>
                <input
                  type="text"
                  value={apiUrl}
                  onChange={(e) => setApiUrl(e.target.value)}
                  style={{
                    flex: 1,
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-strong)',
                    borderRadius: '8px',
                    padding: '8px 12px',
                    color: 'var(--text-main)',
                    fontSize: '0.82rem',
                    fontFamily: 'ui-monospace, monospace',
                  }}
                />
                <button
                  type="button"
                  className="btn-outline"
                  onClick={() => {
                    setBaseApiUrl(apiUrl);
                    setStatusMsg('API Base URL updated.');
                  }}
                >
                  Apply
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Sub-Tab 3: Blocked Accounts */}
        {activeSubTab === 'blocked' && (
          <div className="deck-card" style={{ maxWidth: '780px' }}>
            <div className="deck-title" style={{ marginBottom: '12px' }}>
              <Ban size={18} /> Blocked Accounts ({blocked.length})
            </div>
            {!e2eeProfile ? (
              <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                Sign in with SIWE to view and manage blocked users.
              </div>
            ) : blocked.length === 0 ? (
              <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                You have not blocked any users.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {blocked.map((b) => {
                  const targetId = b.blocked_user_id || (b as any).user_id || '';
                  return (
                    <div
                      key={targetId}
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        padding: '10px 12px',
                        background: 'var(--bg-input)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: '10px',
                        fontSize: '0.8rem',
                      }}
                    >
                      <span style={{ fontFamily: 'ui-monospace, monospace' }}>
                        {b.username ? `@${b.username}` : targetId}
                      </span>
                      <button
                        type="button"
                        className="btn-outline"
                        style={{ padding: '4px 10px', fontSize: '0.74rem' }}
                        onClick={async () => {
                          await unblockUser(targetId);
                          loadBlocks();
                        }}
                      >
                        Unblock
                      </button>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>
    );
  };