import React, { useState, useEffect, useRef, useCallback } from 'react';
import { friendlyError } from '../services/friendlyError';
import {
  Globe,
  Award,
  Wallet,
  AlertTriangle,
  Edit3,
  Trash2,
  Ban,
  Flag,
  RefreshCw,
  Copy,
  Check,
  KeyRound,
  UserCog,
  Settings as SettingsIcon,
  History,
  User,
  Menu,
  AlertCircle,
  Reply,
  Pin,
  PinOff,
} from 'lucide-react';
import { formatAddress, formatEth } from '../services/web3';
import { ChatMessagesSkeleton } from './Skeleton';
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
  updateMyProfile,
  fetchMyIdentityHistory,
  fetchBlockedUsers,
  blockUser,
  unblockUser,
  submitAbuseReport,
  verifyMyWalletBalance,
  uploadPublicChatAttachment,
  fetchPublicChatAttachmentBlob,
  type PublicChatMessageRecord,
} from '../services/platformApi';
import { ChatTimeline, TextBubble, initialsFor, QuotedReply } from './chat/ChatTimeline';
import { jumpToMessage } from './chat/jumpToMessage';
import { ChatComposer } from './chat/ChatComposer';
import { ReactionChips, ReactButton, PinnedBar, TypingLine, ChatSearchBar } from './chat/MessageExtras';
import { searchMessages } from '../services/chatEvents';
import { reactToRoomMessage, sendRoomTyping, setRoomMessagePinned, type RoomPin } from '../services/platformApi';
import { AttachmentTile } from './chat/AttachmentTile';
import {
  attachmentKind,
  DAILY_LIMIT_TEXT_ROOM,
  MAX_FILES_PER_MESSAGE,
  MAX_ROOM_FILE_BYTES,
} from '../services/attachmentLimits';

type RoomMessage = PublicChatMessageRecord & { isOptimistic?: boolean; localFiles?: File[] };

/** Short one-line excerpt of a Members' room message, for the reply bar and live quote updates. */
function roomReplyPreview(m: Pick<RoomMessage, 'content' | 'attachments'>): string {
  const text = (m.content || '').replace(/\s+/g, ' ').trim();
  if (text) return text.length > 120 ? `${text.slice(0, 117)}\u2026` : text;
  const f = m.attachments?.[0];
  if (f) return f.kind === 'image' ? 'Photo' : `File: ${f.file_name}`;
  return 'Message';
}

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
    const [messages, setMessages] = useState<RoomMessage[]>([]);
    // Members' room extras: pinned messages, who is typing, in-room search
    const [roomPins, setRoomPins] = useState<RoomPin[]>([]);
    const [roomTyping, setRoomTyping] = useState<Record<string, { name: string; until: number }>>({});
    const [roomNow, setRoomNow] = useState(() => Date.now());
    const [roomSearchOpen, setRoomSearchOpen] = useState(false);
    const [roomQuery, setRoomQuery] = useState('');
    const [roomSearchIndex, setRoomSearchIndex] = useState(0);
    const lastRoomTypingRef = useRef(0);
    const myRoomIdRef = useRef<string | null>(null);
    myRoomIdRef.current = e2eeProfile?.user_id || null;
    // Files picked for the next message (uploaded when the member presses Send)
    const [pendingFiles, setPendingFiles] = useState<File[]>([]);
    const [nextBeforeSeq, setNextBeforeSeq] = useState<number | null>(null);
    const [onlineStats, setOnlineStats] = useState({ watching: 0, active_live: 0 });
    const [policy, setPolicy] = useState<{
      guest_read_enabled: boolean;
      guest_posting_enabled: boolean;
      max_length: number;
      edit_window_seconds: number;
      retention_days?: number;
      max_file_bytes?: number;
      max_files_per_message?: number;
    }>({
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
    // Message being replied to, and a short "original not loaded" note after tapping a quote
    const [replyTarget, setReplyTarget] = useState<{ message_id: string; author_user_id: string | null; display_name: string; preview: string } | null>(null);
    const [replyJumpMissId, setReplyJumpMissId] = useState<string | null>(null);
    const [initialLoading, setInitialLoading] = useState(true);
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
        setRoomPins(feed.pins || []);
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
        setErrorMsg(friendlyError(err, 'Unable to load Open Public Chat'));
      } finally {
        setInitialLoading(false);
      }
    }, []);

    useEffect(() => {
      loadFeed(accountRef.current);
      // If the server is full, live updates pause; refresh the feed every 10 s until the socket is back.
      let capacityPoll: ReturnType<typeof setInterval> | null = null;
      const stopCapacityPoll = () => {
        if (capacityPoll) clearInterval(capacityPoll);
        capacityPoll = null;
      };
      const wsSub = connectPublicChatWebSocket((evt) => {
        if (evt.type === 'ws_capacity') {
          if (!capacityPoll) capacityPoll = setInterval(() => void loadFeed(accountRef.current), 10000);
          return;
        }
        if (evt.type === 'ws_reconnected' || evt.type === 'public_connected') stopCapacityPoll();
        if (evt.online) {
          setOnlineStats(normalizeOnlineStats(evt.online));
        }
        if (evt.type === 'ws_reconnected') {
          // Socket was down (sleep / offline / server restart): re-sync anything we missed.
          void loadFeed(accountRef.current);
          return;
        }
        if (evt.type === 'public_reactions_updated' && evt.message_id) {
          setMessages((prev) => prev.map((m) => (m.message_id === evt.message_id ? { ...m, reactions: evt.reactions || {} } : m)));
          return;
        }
        if (evt.type === 'public_pins_updated') {
          setRoomPins(Array.isArray(evt.pins) ? evt.pins : []);
          return;
        }
        if (evt.type === 'public_typing' && evt.user_id) {
          if (evt.user_id !== myRoomIdRef.current) {
            setRoomTyping((prev) => ({ ...prev, [evt.user_id]: { name: String(evt.name || 'A member'), until: Date.now() + 6000 } }));
          }
          return;
        }
        if (evt.type === 'public_message_created' && evt.message?.author_user_id) {
          setRoomTyping((prev) => {
            if (!prev[evt.message.author_user_id]) return prev;
            const next = { ...prev };
            delete next[evt.message.author_user_id];
            return next;
          });
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
            prev.map((m) => {
              if (m.message_id === evt.update.message_id) {
                return { ...m, content: evt.update.content, edited_at: evt.update.edited_at };
              }
              if (m.reply_to?.available && m.reply_to.message_id === evt.update.message_id) {
                return { ...m, reply_to: { ...m.reply_to, preview: roomReplyPreview({ content: evt.update.content, attachments: [] }) } };
              }
              return m;
            })
          );
        } else if (evt.type === 'public_message_deleted' && evt.message_id) {
          // Remove it, and blank its text in any reply that quotes it (like the server does).
          setMessages((prev) =>
            prev
              .filter((m) => m.message_id !== evt.message_id)
              .map((m) =>
                m.reply_to && m.reply_to.message_id === evt.message_id
                  ? { ...m, reply_to: { message_id: evt.message_id, author_user_id: null, display_name: null, preview: null, available: false } }
                  : m
              )
          );
          setReplyTarget((cur) => (cur?.message_id === evt.message_id ? null : cur));
        } else if (evt.type === 'public_policy_updated' && evt.policy) {
          setPolicy(evt.policy);
          void loadFeed(accountRef.current);
        }
      }, accountRef.current);
      wsSubRef.current = wsSub;
      return () => {
        stopCapacityPoll();
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
        setErrorMsg(friendlyError(err, 'Failed to load older messages'));
      }
    };

    const isWalletMismatch = Boolean(
      account &&
      e2eeProfile &&
      !e2eeProfile.wallets.some(
        (w) => w.wallet_address.toLowerCase() === account.toLowerCase()
      )
    );

    const handleSend = async (e?: React.FormEvent) => {
      e?.preventDefault();
      if (!account) {
        onConnectWallet();
        return;
      }
      if (!e2eeProfile || isWalletMismatch) {
        onAuthenticateSiwe();
        return;
      }
      const trimmed = input.trim();
      const files = pendingFiles;
      if ((!trimmed && files.length === 0) || sending) return;
      const reply = replyTarget;
      setSending(true);
      setErrorMsg(null);
      setLastFailedText(null);

      // Shown straight away (with local previews of the picked files) while the upload runs.
      const tempId = `temp_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
      const optimisticMsg: RoomMessage = {
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
        localFiles: files,
        reply_to_message_id: reply?.message_id || null,
        reply_to: reply
          ? {
            message_id: reply.message_id,
            author_user_id: reply.author_user_id,
            display_name: reply.display_name,
            preview: reply.preview,
            available: true,
          }
          : null,
        attachments: files.map((f, i) => ({
          attachment_id: `${tempId}_${i}`,
          file_name: f.name,
          mime_type: f.type || 'application/octet-stream',
          kind: attachmentKind(f.type, f.name),
          size_bytes: f.size,
        })),
      };

      setMessages((prev) => [...prev, optimisticMsg]);
      setInput('');
      setPendingFiles([]);
      setReplyTarget(null);
      setTimeout(() => {
        streamRef.current?.scrollTo({ top: streamRef.current.scrollHeight, behavior: 'smooth' });
      }, 20);

      try {
        const attachmentIds: string[] = [];
        for (const f of files) {
          const up = await uploadPublicChatAttachment(f);
          attachmentIds.push(up.attachment.attachment_id);
        }
        const res = await postPublicChatMessage(
          trimmed,
          Boolean(account && e2eeProfile && !isWalletMismatch),
          attachmentIds,
          reply?.message_id || null
        );
        setMessages((prev) =>
          // The live socket may have delivered it first: then just drop the placeholder.
          prev.some((m) => m.message_id === res.message.message_id)
            ? prev.filter((m) => m.message_id !== tempId)
            : prev.map((m) => (m.message_id === tempId ? res.message : m))
        );
        setTimeout(() => {
          streamRef.current?.scrollTo({ top: streamRef.current.scrollHeight, behavior: 'smooth' });
        }, 30);
      } catch (err: any) {
        setMessages((prev) => prev.filter((m) => m.message_id !== tempId));
        setErrorMsg(friendlyError(err, 'Message was not sent (server rejected or storage failed)'));
        setLastFailedText(trimmed || (files.length ? `${files.length} file(s)` : null));
        setInput(trimmed);
        setPendingFiles(files);
        // Keep the reply unless its original is gone
        if (reply && !/no longer available/i.test(String(err?.message || ''))) setReplyTarget(reply);
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

    // ---- Members' room extras ----
    const roomSearchItems = React.useMemo(() => messages.map((m) => ({ id: m.message_id, message: m.content || '' })), [messages]);
    const roomHits = roomSearchOpen ? searchMessages(roomSearchItems, roomQuery) : [];
    const roomNameFor = (uid: string) => {
      if (uid === e2eeProfile?.user_id) return 'You';
      const m = messages.find((x) => x.author_user_id === uid);
      return m?.display_name || 'A member';
    };
    const roomMentionCandidates = React.useMemo(() => {
      const seen = new Map<string, string>();
      for (const m of messages) {
        if (m.author_user_id && m.author_user_id !== e2eeProfile?.user_id && m.display_name?.startsWith('@')) {
          seen.set(m.author_user_id, m.display_name.slice(1));
        }
      }
      return Array.from(seen, ([id, username]) => ({ id, username }));
    }, [messages, e2eeProfile?.user_id]);
    useEffect(() => {
      const ends = Object.values(roomTyping).map((t) => t.until).filter((t) => t > Date.now());
      if (!ends.length) return;
      const t = window.setTimeout(() => setRoomNow(Date.now()), Math.min(...ends) - Date.now() + 50);
      return () => window.clearTimeout(t);
    }, [roomTyping, roomNow]);
    const reactInRoom = async (m: RoomMessage, emoji: string | null) => {
      const myId = e2eeProfile?.user_id || '';
      const mineNow = emoji && (m.reactions?.[emoji] || []).includes(myId);
      try {
        const res = await reactToRoomMessage(m.message_id, mineNow ? null : emoji);
        setMessages((prev) => prev.map((x) => (x.message_id === m.message_id ? { ...x, reactions: res.reactions } : x)));
      } catch (err: any) {
        setErrorMsg(friendlyError(err, 'Your reaction was not saved.'));
      }
    };
    const pinRoomMessage = async (messageId: string, pinned: boolean) => {
      try {
        const res = await setRoomMessagePinned(messageId, pinned);
        setRoomPins(res.pins);
      } catch (err: any) {
        setErrorMsg(friendlyError(err, pinned ? 'The message was not pinned.' : 'The message was not unpinned.'));
      }
    };
    const signalRoomTyping = () => {
      if (e2eeProfile?.show_online_presence === false) return;
      const now = Date.now();
      if (now - lastRoomTypingRef.current < 3000) return;
      lastRoomTypingRef.current = now;
      sendRoomTyping().catch(() => { });
    };

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
                title="Conversations"
                aria-label="Conversations"
              >
                <Menu size={16} />
                <span>Conversations</span>
              </button>
            )}
            <div style={{ minWidth: 0, flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontWeight: 600, fontSize: '1.08rem', flexWrap: 'wrap' }}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
                  <Globe size={18} style={{ color: 'var(--accent)' }} />
                  <span>Members&rsquo; room</span>
                </span>
              </div>
              <div
                style={{
                  fontSize: '0.9rem',
                  color: 'var(--text-muted)',
                  marginTop: '4px',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                {onlineStats.watching} viewing
                {account && <>, {onlineStats.active_live} online now</>}
                {' · '}
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
                    Connect your wallet to write
                  </strong>
                )}
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexShrink: 0, marginLeft: 'auto' }}>
            {account && !e2eeProfile && (
              <button
                type="button"
                className="btn-solid"
                style={{ padding: '6px 12px', fontSize: '0.86rem' }}
                disabled={siweLoading}
                onClick={onAuthenticateSiwe}
              >
                <KeyRound size={13} />
                <span>{siweLoading ? 'Signing...' : 'Verify your wallet'}</span>
              </button>
            )}
            <ChatSearchBar
              open={roomSearchOpen}
              onOpen={() => {
                setRoomSearchOpen(true);
                setRoomQuery('');
              }}
              query={roomQuery}
              onQuery={(q) => {
                setRoomQuery(q);
                setRoomSearchIndex(Math.max(0, searchMessages(roomSearchItems, q).length - 1));
              }}
              count={roomHits.length}
              index={roomSearchIndex}
              onStep={(dir) => {
                const n = roomHits.length;
                if (!n) return;
                const next = (roomSearchIndex + dir + n) % n;
                setRoomSearchIndex(next);
                jumpToMessage(roomHits[next]);
              }}
              onClose={() => {
                setRoomSearchOpen(false);
                setRoomQuery('');
              }}
              ariaLabel="Search the Members' room"
            />
          </div>
        </div>

        {/* Honest Security Disclosure Banner */}
        <div
          style={{
            padding: '11px 26px',
            background: 'var(--bg-surface)',
            borderBottom: '1px solid var(--border-subtle)',
            fontSize: '0.86rem',
            color: 'var(--text-secondary)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '8px 16px',
          }}
        >
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
            <AlertTriangle size={16} style={{ flexShrink: 0, color: 'var(--warn)' }} />
            <span>
              <strong>Everyone in the club can read this room</strong>, and it is moderated. For private
              conversations, use a private chat or a group.
            </span>
          </span>
          {policy.retention_days != null && (
            <span
              style={{
                fontSize: '0.8rem',
                color: 'var(--text-muted)',
                whiteSpace: 'nowrap',
              }}
              title={`Older messages are no longer shown after ${policy.retention_days} ${policy.retention_days === 1 ? 'day' : 'days'}`}
            >
              Messages kept for <strong>{policy.retention_days}</strong>{' '}
              {policy.retention_days === 1 ? 'day' : 'days'}
            </span>
          )}
        </div>

        {errorMsg && (
          <div
            style={{
              padding: '8px 20px',
              borderBottom: '1px solid var(--border-strong)',
              fontSize: '0.86rem',
              color: 'var(--danger)',
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
                  fontSize: '0.9rem',
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

        {/* Room pinned messages */}
        {roomPins.length > 0 && (
          <div className="chat-extras-bar">
            <PinnedBar
              pins={roomPins}
              previewFor={(id) => {
                const m = messages.find((x) => x.message_id === id);
                return m ? roomReplyPreview(m) : null;
              }}
              onJump={(id) => {
                if (!jumpToMessage(id)) setErrorMsg('That pinned message is older than what is loaded. Scroll up to load more.');
              }}
              onUnpin={isModerator ? (id) => void pinRoomMessage(id, false) : undefined}
            />
          </div>
        )}

        {/* Stream */}
        <div className="chat-stream-body" ref={streamRef} style={{ flex: 1, overflowY: 'auto' }}>
          {roomHits.length > 0 && (
            <style>
              {roomHits
                .map(
                  (id, i) =>
                    `.ig-row[data-msg-id="${CSS.escape(id)}"] .ig-bubble{outline:2px solid ${i === roomSearchIndex ? 'var(--accent)' : 'var(--warn)'};outline-offset:1px}`
                )
                .join('\n')}
            </style>
          )}
          {nextBeforeSeq && (
            <div style={{ textAlign: 'center', marginBottom: '12px' }}>
              <button
                type="button"
                className="btn-outline"
                style={{ padding: '5px 14px', fontSize: '0.86rem' }}
                onClick={handleLoadOlder}
              >
                Show earlier messages
              </button>
            </div>
          )}

          {initialLoading && messages.length === 0 ? (
            <ChatMessagesSkeleton count={5} />
          ) : messages.length === 0 ? (
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
              <Globe size={38} strokeWidth={1.3} style={{ color: 'var(--accent)' }} />
              <div style={{ fontFamily: 'var(--font-display)', fontSize: '1.4rem', color: 'var(--text-secondary)' }}>
                No messages yet
              </div>
              <div style={{ fontSize: '0.92rem' }}>Be the first to say something.</div>
            </div>
          ) : (
            <ChatTimeline<RoomMessage>
              items={messages}
              getKey={(m) => m.message_id}
              getTime={(m) => m.created_at}
              getSender={(m) => m.author_user_id || m.guest_id || m.display_name}
              isMine={(m) => Boolean(e2eeProfile && m.author_user_id && m.author_user_id === e2eeProfile.user_id)}
              isPending={(m) => Boolean(m.isOptimistic)}
              getMessageId={(m) => m.message_id}
              showNames
              getName={(m) => m.display_name}
              getInitials={(m) => initialsFor(m.display_name)}
              onSenderClick={(m) => {
                if (!m.is_guest && m.author_user_id) onStartPrivateChat(m.author_user_id);
              }}
              renderBody={(m, ctx) => (
                <>
                  {m.reply_to && (
                    m.reply_to.available ? (
                      <QuotedReply
                        name={
                          e2eeProfile && m.reply_to.author_user_id === e2eeProfile.user_id
                            ? 'You'
                            : m.reply_to.display_name || 'Member'
                        }
                        preview={m.reply_to.preview || 'Message'}
                        onClick={() => {
                          if (!jumpToMessage(m.reply_to!.message_id)) {
                            setReplyJumpMissId(m.message_id);
                            setTimeout(() => setReplyJumpMissId((cur) => (cur === m.message_id ? null : cur)), 2500);
                          }
                        }}
                      />
                    ) : (
                      <QuotedReply name="Reply" preview="The original message is no longer available." />
                    )
                  )}
                  {replyJumpMissId === m.message_id && (
                    <span className="ig-footer">The original is older. Tap “Show earlier messages” at the top to load it.</span>
                  )}
                  {(m.attachments || []).map((att, i) => (
                    <AttachmentTile
                      key={att.attachment_id}
                      id={att.attachment_id}
                      name={att.file_name}
                      mime={att.mime_type}
                      size={att.size_bytes}
                      kind={att.kind}
                      load={() =>
                        m.isOptimistic && m.localFiles?.[i]
                          ? Promise.resolve(m.localFiles[i] as Blob)
                          : fetchPublicChatAttachmentBlob(att.attachment_id, att.mime_type)
                      }
                    />
                  ))}
                  {editingId === m.message_id ? (
                    <div style={{ display: 'flex', gap: '6px', width: 'min(520px, 70vw)' }}>
                      <input
                        type="text"
                        value={editText}
                        maxLength={policy.max_length}
                        autoFocus
                        onChange={(e) => setEditText(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === 'Escape') setEditingId(null);
                        }}
                        aria-label="Edit message"
                        style={{
                          flex: 1,
                          background: 'var(--bg-input)',
                          border: '1px solid var(--border-focus)',
                          borderRadius: '18px',
                          padding: '8px 14px',
                          color: 'var(--text-main)',
                          fontSize: '0.9rem',
                        }}
                      />
                      <button
                        type="button"
                        className="btn-solid"
                        style={{ padding: '6px 14px', fontSize: '0.86rem' }}
                        onClick={async () => {
                          try {
                            const updated = await editPublicChatMessage(m.message_id, editText);
                            setMessages((prev) =>
                              prev.map((item) =>
                                item.message_id === m.message_id
                                  ? { ...item, content: updated.content, edited_at: updated.edited_at }
                                  : item
                              )
                            );
                            setEditingId(null);
                          } catch (err: any) {
                            setErrorMsg(friendlyError(err, 'Edit failed'));
                          }
                        }}
                      >
                        Save
                      </button>
                      <button
                        type="button"
                        className="btn-outline"
                        style={{ padding: '6px 12px', fontSize: '0.86rem' }}
                        onClick={() => setEditingId(null)}
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <TextBubble text={m.content} title={ctx.fullTime} edited={Boolean(m.edited_at)} myUsername={e2eeProfile?.username} />
                  )}
                </>
              )}
              renderFooter={(m, ctx) => (
                <>
                  {m.reactions && Object.keys(m.reactions).length > 0 && (
                    <ReactionChips
                      reactions={m.reactions}
                      myId={e2eeProfile?.user_id || ''}
                      nameFor={(uid) => roomNameFor(uid)}
                      onToggle={canPost ? (emoji) => void reactInRoom(m, emoji) : undefined}
                    />
                  )}
                  {ctx.mine && ctx.isRunEnd && m.isOptimistic ? (
                    <span className="ig-footer">
                      {m.localFiles && m.localFiles.length > 0 ? 'Uploading…' : 'Sending…'}
                    </span>
                  ) : null}
                </>
              )}
              renderActions={(m, ctx) => {
                if (m.isOptimistic) return null;
                const mine = ctx.mine;
                const myId = e2eeProfile?.user_id || '';
                const myReaction = Object.entries(m.reactions || {}).find(([, ids]) => ids.includes(myId))?.[0];
                const pinned = roomPins.some((p) => p.message_id === m.message_id);
                return (
                  <>
                    {canPost && <ReactButton current={myReaction} onPick={(emoji) => void reactInRoom(m, emoji || null)} />}
                    {isModerator && (
                      <button
                        type="button"
                        className="ig-action"
                        title={pinned ? 'Unpin' : 'Pin for everyone'}
                        aria-label={pinned ? 'Unpin this message' : 'Pin this message'}
                        aria-pressed={pinned}
                        onClick={() => void pinRoomMessage(m.message_id, !pinned)}
                      >
                        {pinned ? <PinOff size={14} /> : <Pin size={14} />}
                      </button>
                    )}
                    {canPost && (
                      <button
                        type="button"
                        className="ig-action"
                        title="Reply"
                        aria-label="Reply to this message"
                        onClick={() =>
                          setReplyTarget({
                            message_id: m.message_id,
                            author_user_id: m.author_user_id,
                            display_name: mine ? 'You' : m.display_name,
                            preview: roomReplyPreview(m),
                          })
                        }
                      >
                        <Reply size={14} />
                      </button>
                    )}
                    {mine && m.content && (
                      <button
                        type="button"
                        className="ig-action"
                        title="Edit"
                        aria-label="Edit message"
                        onClick={() => {
                          setEditingId(m.message_id);
                          setEditText(m.content);
                        }}
                      >
                        <Edit3 size={14} />
                      </button>
                    )}
                    {(mine || isModerator) && (
                      <button
                        type="button"
                        className="ig-action"
                        title="Delete"
                        aria-label="Delete message"
                        onClick={async () => {
                          if (!confirm('Delete this message for everyone?')) return;
                          try {
                            await deletePublicChatMessage(m.message_id, 'Deleted from UI');
                            setMessages((prev) => prev.filter((item) => item.message_id !== m.message_id));
                          } catch (err: any) {
                            setErrorMsg(friendlyError(err, 'Delete window expired or unauthorized'));
                          }
                        }}
                      >
                        <Trash2 size={14} />
                      </button>
                    )}
                    {!mine && e2eeProfile && m.author_user_id && (
                      <button
                        type="button"
                        className="ig-action"
                        title="Block"
                        aria-label={`Block ${m.display_name}`}
                        onClick={async () => {
                          if (!confirm(`Block ${m.display_name}? You will no longer see their messages.`)) return;
                          await blockUser(m.author_user_id!, 'Blocked in Open Public Chat');
                          await loadFeed();
                        }}
                      >
                        <Ban size={14} />
                      </button>
                    )}
                    {!mine && e2eeProfile && (
                      <button
                        type="button"
                        className="ig-action"
                        title="Report"
                        aria-label="Report message"
                        onClick={async () => {
                          const reason = prompt('Reason for reporting this message:');
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
                        <Flag size={14} />
                      </button>
                    )}
                  </>
                );
              }}
            />
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
                <strong>Membership Required:</strong> Pay your monthly or yearly membership in ETH to chat.
              </span>
              <button
                type="button"
                className="btn-solid"
                style={{ padding: '6px 14px', fontSize: '0.9rem', whiteSpace: 'nowrap' }}
                onClick={onOpenAdmissionModal}
              >
                Pay / Renew Membership
              </button>
            </div>
          ) : (
            <>
              <TypingLine names={Object.values(roomTyping).filter((t) => t.until > roomNow).map((t) => (t.name.startsWith('@') ? t.name : `@${t.name}`))} />
              <ChatComposer
                value={input}
                onChange={setInput}
                onSubmit={() => void handleSend()}
                files={pendingFiles}
                onFilesChange={setPendingFiles}
                maxFileBytes={policy.max_file_bytes || MAX_ROOM_FILE_BYTES}
                maxFiles={policy.max_files_per_message || MAX_FILES_PER_MESSAGE}
                dailyLimitText={DAILY_LIMIT_TEXT_ROOM}
                maxLength={policy.max_length}
                disabled={!canPost}
                sending={sending}
                mentionCandidates={roomMentionCandidates}
                onTyping={signalRoomTyping}
                placeholder={
                  canPost
                    ? 'Message the room'
                    : account
                      ? 'Sign in with your wallet to write'
                      : 'Connect your wallet to write'
                }
                onDisabledClick={() => {
                  if (!account) onConnectWallet();
                  else if (!e2eeProfile || isWalletMismatch) onAuthenticateSiwe();
                }}
                note="Files in the members’ room are visible to all members and are not end-to-end encrypted."
                canAttach={false}
                replyTo={replyTarget ? { name: replyTarget.display_name, preview: replyTarget.preview } : null}
                onCancelReply={() => setReplyTarget(null)}
              />
            </>
          )}
        </div>
      </div>
    );
  };

// ============================================================================
// 3. DISCOVER USERS & LEVEL-GATED GROUPS VIEW
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
          <h2 style={{ fontSize: '1.2rem', fontWeight: 700 }}>Sign in to your account</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.86rem', maxWidth: '460px', margin: '8px auto 20px' }}>
            Sign in with MetaMask to manage your @username and wallets. Signing in is free.
          </p>
          {!account ? (
            <button type="button" className="btn-solid" onClick={onConnectWallet}>
              <Wallet size={15} />
              <span>Connect MetaMask</span>
            </button>
          ) : (
            <button type="button" className="btn-solid" disabled={siweLoading} onClick={onAuthenticateSiwe}>
              <KeyRound size={15} />
              <span>{siweLoading ? 'Signing in...' : 'Sign in with MetaMask'}</span>
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
            ? 'This is now your main wallet. The old one was removed. Your messages are unchanged.'
            : 'Wallet added to your account.',
          isError: false,
        });
      } catch (err: any) {
        setStatusMsg({ text: friendlyError(err, 'Wallet change failed'), isError: true });
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
                color: statusMsg.isError ? 'var(--danger)' : 'var(--ok)',
                borderRadius: '8px',
                fontSize: '0.9rem',
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
              fontSize: '0.9rem',
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
                style={{ padding: '4px 8px', fontSize: '0.9rem' }}
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
                setStatusMsg({ text: friendlyError(err, 'Username update rejected'), isError: true });
              } finally {
                setBusy(false);
              }
            }}
            style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}
          >
            <label style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', fontWeight: 600 }}>
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
              <div style={{ fontSize: '0.9rem', marginTop: '2px', display: 'flex', alignItems: 'center', gap: '5px' }}>
                {usernameCheck.checking ? (
                  <span style={{ color: 'var(--text-muted)' }}>
                    Checking @{usernameInput.trim().replace(/^@/, '')} availability...
                  </span>
                ) : usernameCheck.is_current ? (
                  <span style={{ color: 'var(--text-secondary)' }}>(Your current username)</span>
                ) : usernameCheck.available ? (
                  <span style={{ color: 'var(--ok)', display: 'inline-flex', alignItems: 'center', gap: '4px', fontWeight: 600 }}>
                    <Check size={12} /> @{usernameInput.trim().replace(/^@/, '')} is available!
                  </span>
                ) : (
                  <span style={{ color: 'var(--danger)', display: 'inline-flex', alignItems: 'center', gap: '4px', fontWeight: 600 }}>
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
                setStatusMsg({ text: friendlyError(err, 'Failed to update bio'), isError: true });
              } finally {
                setBusy(false);
              }
            }}
            style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}
          >
            <div>
              <label style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', fontWeight: 600 }}>
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
                  fontSize: '0.9rem',
                }}
              >
                <span>{formatAddress(w.wallet_address, 6)}</span>
                <span>{w.is_primary ? 'Primary wallet' : w.status.charAt(0).toUpperCase() + w.status.slice(1)}</span>
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
                fontSize: '0.9rem',
              }}
            >
              <div>
                MetaMask switched to a wallet that is not on your account yet:{' '}
                <code>{formatAddress(account, 5)}</code>. Choose what to do:
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
            <div style={{ fontSize: '0.86rem', color: 'var(--text-muted)' }}>
              To replace your wallet, switch to your new account inside MetaMask while signed in—a
              secure SIWE migration button will appear above automatically.
            </div>
          )}

          <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '12px' }}>
            <div style={{ fontSize: '0.86rem', fontWeight: 700, marginBottom: '6px' }}>
              Username History ({historyData?.username_history?.length || 0})
            </div>
            {(historyData?.username_history || []).slice(0, 5).map((h: any, idx: number) => (
              <div
                key={h.history_id || `${h.new_username}-${idx}`}
                style={{
                  fontSize: '0.9rem',
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
            <div style={{ fontSize: '0.86rem', fontWeight: 700, marginBottom: '6px' }}>
              Wallet Change Audit Trail ({historyData?.wallet_history?.length || 0})
            </div>
            {(historyData?.wallet_history || []).slice(0, 5).map((wh: any, idx: number) => {
              const oldAddr = wh.old_wallet_address || wh.old_wallet;
              const newAddr = wh.new_wallet_address || wh.new_wallet;
              return (
                <div
                  key={wh.history_id || `${newAddr || idx}-${idx}`}
                  style={{
                    fontSize: '0.9rem',
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
  onProfileUpdated: (profile: E2EEAccountProfile) => void;
  onNavigateDmVault: () => void;
  initialSubTab?: 'wallet_level' | 'privacy' | 'blocked';
}> = ({
  account,
  e2eeProfile,
  siweLoading = false,
  onConnectWallet,
  onAuthenticateSiwe,
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
        setVerifyMsg(friendlyError(err, 'Backend RPC balance verification failed'));
      } finally {
        setVerifying(false);
      }
    };

    // Privacy & Blocks State
    const [blocked, setBlocked] = useState<any[]>([]);
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
        setStatusMsg(friendlyError(err, 'Failed to update privacy setting'));
      }
    };

    return (
      <div style={{ display: 'flex', flexDirection: 'column', maxWidth: 920, width: '100%', margin: '0 auto' }}>
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
              fontSize: '0.9rem',
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
            <span>Wallet</span>
          </button>

          <button
            type="button"
            className={`btn-outline ${activeSubTab === 'privacy' ? 'active' : ''}`}
            style={{
              padding: '8px 16px',
              fontSize: '0.9rem',
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
            <span>Privacy</span>
          </button>

          <button
            type="button"
            className={`btn-outline ${activeSubTab === 'blocked' ? 'active' : ''}`}
            style={{
              padding: '8px 16px',
              fontSize: '0.9rem',
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
            <span>Blocked members{blocked.length > 0 ? ` (${blocked.length})` : ''}</span>
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
                    <Award size={20} /> Wallet balance
                  </div>
                  <div className="deck-subtitle">
                    We check your wallet’s ETH balance directly on the Ethereum network. Some groups
                    ask for a minimum balance.
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
                      <span>{siweLoading ? 'Signing...' : 'Verify your wallet'}</span>
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
                      {verifying ? 'Checking...' : 'Check my balance'}
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
                    fontSize: '0.9rem',
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
                    <strong>Membership</strong>
                    <span style={{ fontSize: '1.2rem', fontWeight: 800, color: 'var(--text-main)' }}>
                      {e2eeProfile.is_platform_paid || e2eeProfile.admin_role ? 'Active' : 'Inactive'}
                    </span>
                  </div>
                  <div className="spec-badge" style={{ textAlign: 'left', padding: '14px' }}>
                    <strong>Wallet balance (last checked)</strong>
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
                  Recent balance checks
                </div>
                {historyData.balance_snapshots.slice(0, 6).map((s: any) => (
                  <div
                    key={s.snapshot_id}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      padding: '8px 0',
                      borderBottom: '1px solid var(--border-subtle)',
                      fontSize: '0.86rem',
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
              <SettingsIcon size={18} /> Privacy
            </div>

            {statusMsg && (
              <div
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

            {e2eeProfile && (
              <>
                <label
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '0.88rem' }}>Show Online Presence</div>
                    <div style={{ fontSize: '0.86rem', color: 'var(--text-secondary)' }}>
                      Let other members see when you are online.
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
                      Read receipts in private chats
                    </div>
                    <div style={{ fontSize: '0.86rem', color: 'var(--text-secondary)' }}>
                      Let people know when you have read their private messages.
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
                    <UserCog size={14} />
                    <span>Account and devices</span>
                  </button>
                </div>
              </>
            )}
          </div>
        )}

        {/* Sub-Tab 3: Blocked Accounts */}
        {activeSubTab === 'blocked' && (
          <div className="deck-card" style={{ maxWidth: '780px' }}>
            <div className="deck-title" style={{ marginBottom: '12px' }}>
              <Ban size={18} /> Blocked Accounts ({blocked.length})
            </div>
            {!e2eeProfile ? (
              <div style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>
                Sign in with your wallet to manage blocked members.
              </div>
            ) : blocked.length === 0 ? (
              <div style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>
                You have not blocked anyone.
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
                        fontSize: '0.9rem',
                      }}
                    >
                      <span style={{ fontFamily: 'ui-monospace, monospace' }}>
                        {b.username ? `@${b.username}` : targetId}
                      </span>
                      <button
                        type="button"
                        className="btn-outline"
                        style={{ padding: '4px 10px', fontSize: '0.9rem' }}
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