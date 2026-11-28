import React, { useState, useEffect, useLayoutEffect, useRef, useCallback } from 'react';
import { friendlyError } from '../services/friendlyError';
import {
  MessageSquare,
  Users,
  UserPlus,
  ChevronDown,
  Lock,
  Copy,
  Check,
  Wallet,
  ShieldCheck,
  KeyRound,
  Plus,
  Globe,
  Ban,
  Flag,
  Menu,
  X,
  Search,
  AlertCircle,
  BellRing,
  Reply,
  Pencil,
  Trash2,
  Pin,
  PinOff,
  BellOff,
  Archive,
} from 'lucide-react';
import type { ChatMessage } from '../types';
import { formatAddress } from '../services/web3';

import {
  loadVaultDecryptedMessage,
  saveVaultDecryptedMessage,
  saveDeviceVaultRecord,
  wipeUserDeviceVault,
  deleteVaultRecord,
} from '../services/e2eeVault';
import {
  OLM_PROTOCOL_ID,
  generateFreshLocalOlmDevice,
  markLocalPrekeysPublished,
  generateMoreOlmPrekeys,
  encryptOlmMultiDevicePayload,
  decryptOlmDeviceCiphertext,
  evaluateAndRecordPeerTrust,
  type E2EEPlaintextEnvelope,
  type PeerActiveDeviceDescriptor,
} from '../services/olmService';
import {
  MLS_CIPHERSUITE_NAME,
  generateMlsKeyPackagesForDevice,
  initializeNewMlsGroupLocal,
  buildMlsAddMembersCommit,
  buildMlsRemoveMemberCommit,
  joinMlsGroupFromWelcomeB64,
  processIncomingMlsCommits,
  encryptMlsGroupMessage,
  decryptMlsGroupMessage,
  getMlsGroupSecurityInfo,
  clearLocalMlsGroupState,
} from '../services/mlsGroupService';
import { ensureLocalDeviceRegistered } from '../services/deviceProvisioning';
import { shouldWipeLocalDevice } from '../services/deviceRevocation';
import {
  encryptAttachmentOnDevice,
  decryptAttachmentOnDevice,
  type EncryptedAttachmentKeyDescriptor,
} from '../services/e2eeAttachmentCrypto';
import {
  requestE2EEAuthChallenge,
  verifyE2EEAuthChallenge,
  fetchMyE2EEAccount,
  updateMyE2EEUsername,
  linkNewWalletToE2EEAccount,
  resolveE2EEPeer,
  replenishE2EEPrekeys,
  revokeE2EEDevice,
  resetLostE2EEIdentity,
  claimPeerOlmPrekeyBundles,
  fetchPeerActiveDevices,
  submitOlmDmCiphertext,
  fetchOlmDmCiphertexts,
  fetchMyDmConversations,
  claimPeerMlsKeyPackages,
  createServerMlsGroup,
  fetchMyServerMlsGroups,
  fetchPendingServerMlsWelcomes,
  ackServerMlsWelcome,
  submitServerMlsCommit,
  fetchServerMlsCommits,
  submitServerMlsGroupMessage,
  fetchServerMlsGroupMessages,
  uploadEncryptedAttachmentBlob,
  downloadEncryptedAttachmentBlob,
  revokeEncryptedAttachment,
  fetchDevicePrekeyCounts,
  fetchMyGroupInvitations,
  acceptGroupInvitation,
  declineGroupInvitation,
  type GroupInvitationRecord,
  type E2EEAccountProfile,
  type E2EEGroupRecord,
  deleteDmMessageForEveryone,
  deleteGroupMessageForEveryone,
  sendTypingSignal,
  fetchConversationState,
  setMessagePinned,
  setDisappearingTimer,
  setGroupAdminsOnly,
  fetchConversationPrefs,
  setConversationPref,
  type ConversationRef,
  type ConversationState,
  type ConversationPref,
  type MuteChoice,
} from '../services/e2eeApi';
import {
  blockUser,
  sendDmReadReceipt,
  fetchDmReadReceipts,
  submitAbuseReport,
  leaveEncryptedGroup,
  deleteGroup,
  searchUsers,
  discoverPublicGroups,
  requestJoinPublicGroup,
  isGroupPaymentRequired,
  type DirectoryUserRecord,
  type DiscoverableGroupRecord,
  formatGroupFee,
} from '../services/platformApi';
import {
  MlsGroupSecurityModal,
  AccountDevicesVaultModal,
} from './E2EESecurityModals';
import { OpenPublicChatView } from './PlatformViews';
import { ChatMessagesSkeleton, ListRowsSkeleton, SidebarListSkeleton } from './Skeleton';
import { mergeLocalEntries } from '../services/chatSync';
import { ChatTimeline, TextBubble, initialsFor, QuotedReply } from './chat/ChatTimeline';
import { jumpToMessage } from './chat/jumpToMessage';
import {
  foldChatEvents,
  searchMessages,
  canEditMessage,
  canDeleteForEveryone,
  findMentionedIds,
  type EventEnvelopeFields,
  type FoldInput,
  type FoldedFields,
} from '../services/chatEvents';
import {
  ReactionChips,
  ReactButton,
  DeletedBubble,
  PollCard,
  PollComposer,
  PinnedBar,
  TypingLine,
  ChatSearchBar,
  ConversationMenu,
  ChatStatusChips,
} from './chat/MessageExtras';
import { setNotificationMutedScopes } from '../services/notificationStore';
import { subscribeE2EERealtime, isE2EERealtimeLive } from '../services/e2eeRealtime';
import {
  useNotifications,
  setActiveConversation,
  conversationShown,
  rememberNames,
} from '../services/notificationStore';
import { ChatComposer } from './chat/ChatComposer';
import { AttachmentTile } from './chat/AttachmentTile';
import {
  DAILY_LIMIT_TEXT_ENCRYPTED,
  MAX_ENCRYPTED_FILE_BYTES,
  MAX_FILES_PER_MESSAGE,
} from '../services/attachmentLimits';

export type ChatChannelMode = 'open_chat' | 'dm' | 'groups';

interface ChatProps {
  account: string | null;
  chainIdHex?: string | null;
  onConnectWallet: () => void;
  forcedMode?: ChatChannelMode;
  onModeChange?: (mode: ChatChannelMode) => void;
  siweLoading?: boolean;
  onAuthenticateSiwe?: () => void;
  onStartPrivateChat?: (identifier: string) => void;
  initialPeerIdentifier?: string | null;
  onConsumedInitialPeer?: () => void;
  /** Group to open (from a notification). '' opens the Groups page. */
  initialGroupId?: string | null;
  onConsumedInitialGroup?: () => void;
  externalProfile?: E2EEAccountProfile | null;
  onProfileChange?: (profile: E2EEAccountProfile | null) => void;
  initialOpenVault?: boolean;
  onVaultClosed?: () => void;
  isPlatformPaid?: boolean | null;
  onOpenAdmissionModal?: () => void;
  onOpenPaidGroupModal?: (groupId: string, groupName?: string) => void;
}

interface ResolvedPeerTarget {
  user_id: string;
  username: string | null;
  primary_wallet: string | null;
  identity_version: number;
  devices: PeerActiveDeviceDescriptor[];
}

/** Poll every 4.5 s while the live connection is down; every 30 s (safety net) while it is up. */
const FAST_POLL_MS = 4500;
const SAFETY_POLL_MS = 30_000;

interface FailedSendPayload {
  channelType: 'dm' | 'groups';
  targetId: string;
  msgId: string;
  plainEnvelope: E2EEPlaintextEnvelope;
  cipherPayload?: any;
  createdAt: number;
  /** Encrypted files already uploaded for this message (re-used on Retry). */
  attachmentIds?: string[];
  /** People @mentioned in a group message, so Retry still notifies them. */
  mentionIds?: string[];
}

interface RichDisplayMessage extends ChatMessage {
  seq?: number;
  attachments?: EncryptedAttachmentKeyDescriptor[];
  epoch?: number;
  protocolBadge?: string;
  sendStatus?: 'sending' | 'delivered' | 'failed';
  sendError?: string;
  canRetry?: boolean;
  failedPayload?: FailedSendPayload;
  /** Local-only: which conversation an optimistic/failed entry belongs to (e.g. `dm|<userId>`). */
  localScope?: string;
  /** Local-only: files being encrypted/uploaded, previewed from the device while sending. */
  localFiles?: File[];
  /** The message this one replies to. */
  replyTo?: ReplyRef;
  /** Decrypted event fields (reaction / edit / poll / vote / mentions), see services/chatEvents.ts */
  env?: EventEnvelopeFields;
  /** Deleted for everyone */
  deleted?: boolean;
  /** Disappeared (hidden) */
  expired?: boolean;
  expiresAt?: string | null;
}

/** A message as the timeline shows it: reactions, edits, votes and deletes already applied. */
type DisplayMsg = RichDisplayMessage & FoldedFields;

/** Per-conversation sync state so polls / live events fetch only NEW messages. */
interface ConversationSyncEntry {
  lastSeq: number;
  msgs: RichDisplayMessage[];
  /** Records we could not decrypt yet (e.g. own message whose vault copy was still being saved). */
  retry: Record<string, any>;
  lastReceiptSeq: number;
}

interface PeerSecuritySnapshot {
  at: number;
}

type ReplyRef = NonNullable<E2EEPlaintextEnvelope['reply_to']>;

/** Short one-line excerpt of a message for a reply quote. */
function replyPreviewFor(msg: { message: string; attachments?: Array<{ file_name: string; mime_type: string }>; localFiles?: File[] }): string {
  const text = (msg.message || '').replace(/\s+/g, ' ').trim();
  if (text) return text.length > 120 ? `${text.slice(0, 117)}…` : text;
  const file = msg.attachments?.[0] || (msg.localFiles?.[0] ? { file_name: msg.localFiles[0].name, mime_type: msg.localFiles[0].type } : null);
  if (file) return file.mime_type?.startsWith('image/') ? 'Photo' : `File: ${file.file_name}`;
  return 'Message';
}

/** Reply details arrive inside other people's encrypted messages: accept only well-formed, short values. */
function cleanReplyRef(raw: unknown): ReplyRef | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const r = raw as Record<string, unknown>;
  if (typeof r.message_id !== 'string' || typeof r.sender_user_id !== 'string') return undefined;
  const preview = typeof r.preview === 'string' ? r.preview.replace(/\s+/g, ' ').trim().slice(0, 160) : '';
  return {
    message_id: r.message_id.slice(0, 96),
    sender_user_id: r.sender_user_id.slice(0, 64),
    preview: preview || 'Message',
    has_files: r.has_files === true,
  };
}

/** The event fields of a decrypted envelope (other people's input: only well-formed values). */
function envFields(env: E2EEPlaintextEnvelope): EventEnvelopeFields {
  const kind = env.kind === 'reaction' || env.kind === 'edit' || env.kind === 'poll_vote' ? env.kind : 'message';
  return {
    kind,
    target_id: typeof env.target_id === 'string' ? env.target_id.slice(0, 96) : undefined,
    emoji: typeof env.emoji === 'string' ? env.emoji : undefined,
    text: typeof env.text === 'string' ? env.text : undefined,
    poll: env.poll,
    vote: Array.isArray(env.vote) ? env.vote.slice(0, 10) : undefined,
    mentions: Array.isArray(env.mentions) ? env.mentions.filter((m) => typeof m === 'string').slice(0, 50) : undefined,
  };
}

function parseEthStringToWeiString(ethVal: string): string {
  const trimmed = (ethVal || '').trim();
  if (!trimmed || trimmed === '0' || trimmed === '.') return '0';
  const parts = trimmed.split('.');
  if (parts.length > 2) return '0';
  const whole = parts[0] ? BigInt(parts[0].replace(/[^0-9]/g, '') || '0') : 0n;
  const fractionStr = (parts[1] || '').replace(/[^0-9]/g, '').slice(0, 18).padEnd(18, '0');
  const fraction = BigInt(fractionStr);
  const wei = whole * 1000000000000000000n + fraction;
  return wei.toString();
}

export const Chat: React.FC<ChatProps> = ({
  account,
  chainIdHex,
  onConnectWallet,
  forcedMode,
  onModeChange,
  siweLoading = false,
  onAuthenticateSiwe,
  onStartPrivateChat,
  initialPeerIdentifier,
  onConsumedInitialPeer,
  initialGroupId = null,
  onConsumedInitialGroup,
  externalProfile,
  onProfileChange,
  initialOpenVault = false,
  onVaultClosed,
  isPlatformPaid,
  onOpenAdmissionModal,
  onOpenPaidGroupModal,
}) => {
  const [activeTab, setActiveChannelTab] = useState<ChatChannelMode>(forcedMode || 'open_chat');
  const [mobileRailOpen, setMobileRailOpen] = useState(false);

  useEffect(() => {
    if (forcedMode) {
      setActiveChannelTab(forcedMode);
    }
  }, [forcedMode]);

  const handleSelectChannelTab = useCallback(
    (tab: ChatChannelMode) => {
      setActiveChannelTab(tab);
      setMobileRailOpen(false);
      onModeChange?.(tab);
    },
    [onModeChange]
  );

  // Authenticated permanent E2EE account & local device vault state
  const [e2eeProfile, setE2eeProfileInternal] = useState<E2EEAccountProfile | null>(
    externalProfile || null
  );
  const [myDevices, setMyDevices] = useState<PeerActiveDeviceDescriptor[]>([]);
  const [localDeviceId, setLocalDeviceId] = useState<string | null>(null);
  const [vaultBoundUserId, setVaultBoundUserId] = useState<string | null>(null);
  const [authLoading, setAuthLoading] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const vaultInitInFlightRef = useRef<string | null>(null);
  // A group that the server already created while adding its first members failed. Retrying the
  // form then only adds the members instead of creating a second, duplicate group.
  const halfCreatedGroupRef = useRef<Awaited<ReturnType<typeof createServerMlsGroup>>['group'] | null>(null);
  // KeyPackages are one-time: claiming consumes them on the server. Keep the ones claimed by a
  // failed attempt (per user id) so Retry re-uses them instead of burning a fresh batch.
  const claimedKeyPackagesRef = useRef<
    Record<string, Array<{ user_id: string; device_id: string; key_package_b64: string }>>
  >({});

  const setE2eeProfile = useCallback(
    (next: E2EEAccountProfile | null) => {
      setE2eeProfileInternal(next);
      if (onProfileChange) onProfileChange(next);
    },
    [onProfileChange]
  );

  useEffect(() => {
    if (externalProfile !== undefined) {
      setE2eeProfileInternal(externalProfile);
    }
  }, [externalProfile]);

  const isWalletMismatch = Boolean(
    account &&
    e2eeProfile &&
    !e2eeProfile.wallets.some(
      (w) => w.wallet_address.toLowerCase() === account.toLowerCase()
    )
  );

  const isVaultReadyForProfile = Boolean(
    e2eeProfile &&
    localDeviceId &&
    vaultBoundUserId === e2eeProfile.user_id &&
    !isWalletMismatch
  );

  const needsE2EEAuth = Boolean(account && !isVaultReadyForProfile);

  // "+Add" Menu & Action Modals State ("Create Group" | "Chat Individual")
  const [addMenuOpen, setAddMenuOpen] = useState(false);
  const [createGroupModalOpen, setCreateGroupModalOpen] = useState(false);
  const [chatIndividualModalOpen, setChatIndividualModalOpen] = useState(false);
  const addMenuRef = useRef<HTMLDivElement>(null);

  // Group Discovery & Invites State
  const [discoverableGroups, setDiscoverableGroups] = useState<DiscoverableGroupRecord[]>([]);
  const [groupsLoading, setGroupsLoading] = useState(false);
  const [sidebarLoadedUserId, setSidebarLoadedUserId] = useState<string | null>(null);
  const [loadedScopeKey, setLoadedScopeKey] = useState<string | null>(null);
  const [inviteStatusMsg, setInviteStatusMsg] = useState<string | null>(null);

  // Private DM state (Olm v2 Double Ratchet)
  const [individualIdInput, setIndividualIdInput] = useState('');
  const [individualSuggestions, setIndividualSuggestions] = useState<DirectoryUserRecord[]>([]);
  const [startingIndividualBusy, setStartingIndividualBusy] = useState(false);
  const [chatIndividualError, setChatIndividualError] = useState<string | null>(null);
  const [selectedPeer, setSelectedPeer] = useState<ResolvedPeerTarget | null>(null);
  const [openedPeers, setOpenedPeers] = useState<ResolvedPeerTarget[]>([]);
  const [dmConversations, setDmConversations] = useState<
    Array<{
      conversation_id: string;
      peer_user_id: string;
      peer_username: string | null;
      peer_primary_wallet: string | null;
    }>
  >([]);
  const [peerLastReadSeq, setPeerLastReadSeq] = useState<number>(0);

  // Encrypted MLS Group state (RFC 9420)
  const [groups, setGroups] = useState<E2EEGroupRecord[]>([]);
  const [selectedGroup, setSelectedGroup] = useState<E2EEGroupRecord | null>(null);
  const [newGroupName, setNewGroupName] = useState('');
  const [groupMemberInput, setGroupMemberInput] = useState('');
  const [pendingGroupMembers, setPendingGroupMembers] = useState<ResolvedPeerTarget[]>([]);
  const [groupMemberSuggestions, setGroupMemberSuggestions] = useState<DirectoryUserRecord[]>([]);
  const [addingGroupMemberBusy, setAddingGroupMemberBusy] = useState(false);
  const [creatingGroupBusy, setCreatingGroupBusy] = useState(false);
  const [createGroupError, setCreateGroupError] = useState<string | null>(null);
  const [newGroupVisibility, setNewGroupVisibility] = useState<'invite_only' | 'public'>('invite_only');
  const [newGroupMinEth, setNewGroupMinEth] = useState<string>('0');
  // Platform superadmin only: create the group as a paid group (price in USD)
  const [newGroupPaid, setNewGroupPaid] = useState(false);
  const [newGroupFeeUsd, setNewGroupFeeUsd] = useState<string>('10');
  const [newGroupYearlyFeeUsd, setNewGroupYearlyFeeUsd] = useState<string>('0');
  const [showGroupOpts, setShowGroupOpts] = useState(false);

  // Composer, attachments, & modals
  const [messages, setMessages] = useState<RichDisplayMessage[]>([]);
  const [inputMessage, setInputMessage] = useState('');
  // Files picked for the next message (up to MAX_FILES_PER_MESSAGE, each encrypted on this device)
  const [pendingFiles, setPendingFiles] = useState<File[]>([]);
  const [sending, setSending] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  // Message being replied to in the composer
  const [replyState, setReplyState] = useState<{ scope: string; ref: ReplyRef } | null>(null);
  const notifications = useNotifications();
  // Briefly shows "The original message is not loaded here." under a reply whose quote was tapped
  const [replyJumpMissId, setReplyJumpMissId] = useState<string | null>(null);

  /** Display name for a member in the open conversation ("You", "@name", or a short fallback). */
  const nameForSender = (userId: string): string => {
    if (e2eeProfile && userId === e2eeProfile.user_id) return 'You';
    if (selectedPeer && selectedPeer.user_id === userId && selectedPeer.username) return `@${selectedPeer.username}`;
    const gm = selectedGroup?.members.find((m) => m.user_id === userId && m.username);
    if (gm?.username) return `@${gm.username}`;
    const op = openedPeers.find((p) => p.user_id === userId && p.username);
    if (op?.username) return `@${op.username}`;
    return 'Member';
  };

  const [groupModalOpen, setGroupModalOpen] = useState(false);
  // Live "someone asked to join your group" alert for group admins (from the `group_join_request` event)
  const [joinRequestAlertGroupId, setJoinRequestAlertGroupId] = useState<string | null>(null);
  // Groups an admin added me to, waiting for my Accept / Reject (like Instagram group invites)
  const [groupInvitations, setGroupInvitations] = useState<GroupInvitationRecord[]>([]);
  const [invitationBusyId, setInvitationBusyId] = useState<string | null>(null);
  const [invitationNotice, setInvitationNotice] = useState<string | null>(null);
  // Pop-up shown when a new invitation arrives while the app is open
  const [invitationAlert, setInvitationAlert] = useState<{ group_id: string; group_name: string; by: string | null } | null>(null);
  // After Accept: open the group as soon as it appears in my group list (its keys are ready by then)
  const openGroupWhenReadyRef = useRef<{ id: string; at: number } | null>(null);
  // Counts list refreshes, so a waiting "open this group" is only dropped by a refresh started after it.
  const syncIterationRef = useRef(0);
  // Files this member removed in this session (the server already refuses downloads for them)
  const [revokedAttachmentIds, setRevokedAttachmentIds] = useState<Set<string>>(() => new Set());
  const prekeyTopUpInFlightRef = useRef(false);
  const [groupModalInitialTab, setGroupModalInitialTab] = useState<'members' | 'invites' | undefined>(undefined);
  const [vaultModalOpen, setVaultModalOpen] = useState(false);

  useEffect(() => {
    if (initialOpenVault) {
      setVaultModalOpen(true);
    }
  }, [initialOpenVault]);

  const chatBodyRef = useRef<HTMLDivElement>(null);
  const isFirstLoadRef = useRef(true);
  const syncInFlightRef = useRef(false);
  const syncQueuedRef = useRef(false);
  const scopeSyncChainRef = useRef<Record<string, Promise<void>>>({});
  const scopeSyncPendingRef = useRef<Record<string, boolean>>({});
  const activeScopeRef = useRef<string | null>(null);
  const loadGenRef = useRef(0);
  const selectedGroupIdRef = useRef<string | null>(null);
  const resolvedPeerCacheRef = useRef<Record<string, { peer: ResolvedPeerTarget; at: number }>>({});
  const syncCacheRef = useRef<Record<string, ConversationSyncEntry>>({});
  const convStateCacheRef = useRef<Record<string, ConversationState>>({});
  const peerSecCacheRef = useRef<Record<string, PeerSecuritySnapshot>>({});
  const forceSecurityRefreshRef = useRef(false);
  // Background sends run one at a time so Olm/MLS ratchet state is never used by two sends at once.
  const sendQueueRef = useRef<Promise<void>>(Promise.resolve());

  // Close "+Add" menu when clicking outside or pressing Escape
  useEffect(() => {
    if (!addMenuOpen) return;
    const handleOutside = (ev: MouseEvent) => {
      if (addMenuRef.current && !addMenuRef.current.contains(ev.target as Node)) {
        setAddMenuOpen(false);
      }
    };
    const handleEsc = (ev: KeyboardEvent) => {
      if (ev.key === 'Escape') setAddMenuOpen(false);
    };
    document.addEventListener('mousedown', handleOutside);
    document.addEventListener('keydown', handleEsc);
    return () => {
      document.removeEventListener('mousedown', handleOutside);
      document.removeEventListener('keydown', handleEsc);
    };
  }, [addMenuOpen]);

  // Live autocomplete for "Chat Individual" modal
  useEffect(() => {
    if (!chatIndividualModalOpen) return;
    const q = individualIdInput.trim();
    const timer = setTimeout(() => {
      searchUsers(q.replace(/^@/, ''), 8)
        .then((res) => {
          setIndividualSuggestions(
            res.users.filter((u) => !e2eeProfile || u.user_id !== e2eeProfile.user_id)
          );
        })
        .catch(() => setIndividualSuggestions([]));
    }, 160);
    return () => clearTimeout(timer);
  }, [chatIndividualModalOpen, individualIdInput, e2eeProfile]);

  // Live autocomplete for "Create Group" Add Members input
  useEffect(() => {
    if (!createGroupModalOpen) return;
    const q = groupMemberInput.trim();
    const timer = setTimeout(() => {
      searchUsers(q.replace(/^@/, ''), 8)
        .then((res) => {
          setGroupMemberSuggestions(
            res.users.filter(
              (u) =>
                (!e2eeProfile || u.user_id !== e2eeProfile.user_id) &&
                !pendingGroupMembers.some((pm) => pm.user_id === u.user_id)
            )
          );
        })
        .catch(() => setGroupMemberSuggestions([]));
    }, 160);
    return () => clearTimeout(timer);
  }, [createGroupModalOpen, groupMemberInput, e2eeProfile, pendingGroupMembers]);

  useEffect(() => {
    // Closing the form ends the retry window; the half-created group stays in the sidebar.
    if (!createGroupModalOpen) {
      halfCreatedGroupRef.current = null;
      claimedKeyPackagesRef.current = {};
    }
  }, [createGroupModalOpen]);

  const scrollToBottom = (smooth = true) => {
    if (chatBodyRef.current) {
      chatBodyRef.current.scrollTo({
        top: chatBodyRef.current.scrollHeight,
        behavior: smooth ? 'smooth' : 'auto',
      });
    }
  };

  const signWalletAuthChallenge = async (walletAddr: string, message: string): Promise<string> => {
    const eth = (window as any).ethereum;
    if (!eth) throw new Error('MetaMask provider not available');
    return eth.request({
      method: 'personal_sign',
      params: [message, walletAddr],
    });
  };

  // Reset per-account E2EE state cleanly upon disconnect or account change
  useEffect(() => {
    if (!e2eeProfile) {
      vaultInitInFlightRef.current = null;
      syncCacheRef.current = {};
      convStateCacheRef.current = {};
      resolvedPeerCacheRef.current = {};
      peerSecCacheRef.current = {};
      scopeSyncChainRef.current = {};
      scopeSyncPendingRef.current = {};
      setVaultBoundUserId(null);
      setLocalDeviceId(null);
      setMyDevices([]);
      setDmConversations([]);
      setOpenedPeers([]);
      setGroups([]);
      setSelectedPeer(null);
      setSelectedGroup(null);
      setLoadedScopeKey(null);
      setMessages([]);
      if (!account) {
        setAddMenuOpen(false);
        setCreateGroupModalOpen(false);
        setChatIndividualModalOpen(false);
        if (activeTab !== 'open_chat') {
          setActiveChannelTab('open_chat');
          onModeChange?.('open_chat');
        }
      }
      return;
    }
    if (vaultBoundUserId && vaultBoundUserId !== e2eeProfile.user_id) {
      syncCacheRef.current = {};
      convStateCacheRef.current = {};
      resolvedPeerCacheRef.current = {};
      peerSecCacheRef.current = {};
      scopeSyncChainRef.current = {};
      scopeSyncPendingRef.current = {};
      setLocalDeviceId(null);
      setMyDevices([]);
      setDmConversations([]);
      setOpenedPeers([]);
      setGroups([]);
      setSelectedPeer(null);
      setSelectedGroup(null);
      setLoadedScopeKey(null);
      setMessages([]);
    }
  }, [e2eeProfile, vaultBoundUserId, account, activeTab, onModeChange]);

  // Ensure local Olm + MLS device keys are initialized & registered whenever session is active
  const ensureLocalDeviceVaultReady = useCallback(
    async (userObj: E2EEAccountProfile) => {
      const userId = userObj.user_id;
      if (vaultInitInFlightRef.current === userId) return;
      vaultInitInFlightRef.current = userId;
      try {
        // Shared, single-flight registration (also started by App.tsx right after sign-in): a second
        // caller waits for the first run instead of registering the device and KeyPackages again.
        const provisioned = await ensureLocalDeviceRegistered(userId);

        const freshMe = await fetchMyE2EEAccount();
        setE2eeProfile(freshMe.user);
        setMyDevices(freshMe.devices);
        setLocalDeviceId(provisioned.deviceId);
        setVaultBoundUserId(userId);
      } finally {
        if (vaultInitInFlightRef.current === userId) {
          vaultInitInFlightRef.current = null;
        }
      }
    },
    [setE2eeProfile]
  );

  // Auto-resume local vault on SIWE login OR HttpOnly cookie session reload
  useEffect(() => {
    if (
      e2eeProfile &&
      !isWalletMismatch &&
      (!localDeviceId || vaultBoundUserId !== e2eeProfile.user_id)
    ) {
      ensureLocalDeviceVaultReady(e2eeProfile).catch((err) => {
        console.warn('Auto vault resume warning:', err);
      });
    }
  }, [e2eeProfile, isWalletMismatch, localDeviceId, vaultBoundUserId, ensureLocalDeviceVaultReady]);

  // Bootstrap E2EE authenticated session via EIP-4361 SIWE + local encrypted device vault
  const authenticateE2EESession = useCallback(async () => {
    if (!account || authLoading) return;
    setAuthLoading(true);
    setAuthError(null);
    try {
      const chainNum = chainIdHex ? parseInt(chainIdHex, 16) || 1 : 1;
      const chal = await requestE2EEAuthChallenge(account, 'login', chainNum);
      const sig = await signWalletAuthChallenge(account, chal.message);
      const verified = await verifyE2EEAuthChallenge(chal.challenge_id, account, sig);
      await ensureLocalDeviceVaultReady(verified.user);
    } catch (err: any) {
      if (err?.code === 4001) {
        setAuthError('Sign-in was cancelled in MetaMask. Please try again.');
      } else {
        setAuthError(friendlyError(err, 'Could not sign you in. Please try again.'));
      }
    } finally {
      setAuthLoading(false);
    }
  }, [account, chainIdHex, authLoading, ensureLocalDeviceVaultReady]);

  const registerOpenedPeer = useCallback((peer: ResolvedPeerTarget) => {
    resolvedPeerCacheRef.current[peer.user_id] = { peer, at: Date.now() };
    setOpenedPeers((prev) => {
      const existing = prev.find((p) => p.user_id === peer.user_id);
      if (
        existing &&
        existing.username === peer.username &&
        existing.primary_wallet === peer.primary_wallet &&
        existing.identity_version === peer.identity_version &&
        existing.devices.length === peer.devices.length
      ) {
        return prev;
      }
      const filtered = prev.filter((p) => p.user_id !== peer.user_id);
      return [peer, ...filtered];
    });
  }, []);

  // Open initial peer if jumped from Open Public Chat or external link
  useEffect(() => {
    if (!initialPeerIdentifier) return;
    if (!isVaultReadyForProfile || !e2eeProfile) {
      setIndividualIdInput(initialPeerIdentifier);
      setChatIndividualError(null);
      setChatIndividualModalOpen(true);
      onConsumedInitialPeer?.();
      return;
    }
    let cancelled = false;
    resolveE2EEPeer(initialPeerIdentifier)
      .then((peer) => {
        if (cancelled) return;
        if (peer.user_id === e2eeProfile.user_id) {
          return;
        }
        if (peer.devices.length === 0) {
          setIndividualIdInput(initialPeerIdentifier);
          setChatIndividualError(
            'This member has not signed in to chats yet. Ask them to sign in once.'
          );
          setChatIndividualModalOpen(true);
          return;
        }
        registerOpenedPeer(peer);
        setSelectedPeer(peer);
        handleSelectChannelTab('dm');
      })
      .catch((err) => {
        if (!cancelled) {
          setIndividualIdInput(initialPeerIdentifier);
          setChatIndividualError(
            friendlyError(err, 'This member has not signed in to chats yet.')
          );
          setChatIndividualModalOpen(true);
        }
      })
      .finally(() => {
        if (!cancelled && onConsumedInitialPeer) onConsumedInitialPeer();
      });
    return () => {
      cancelled = true;
    };
  }, [
    initialPeerIdentifier,
    isVaultReadyForProfile,
    e2eeProfile,
    onConsumedInitialPeer,
    registerOpenedPeer,
    handleSelectChannelTab,
  ]);

  const handleLoadDiscoverableGroups = useCallback(async () => {
    setGroupsLoading(true);
    try {
      const res = await discoverPublicGroups();
      setDiscoverableGroups(res.groups);
    } catch {
      // non-fatal
    } finally {
      setGroupsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === 'groups' && !selectedGroup) {
      handleLoadDiscoverableGroups();
    }
  }, [activeTab, selectedGroup, handleLoadDiscoverableGroups]);

  // A group payment finished: refresh the list so "Pay & Join" turns into "Request Join".
  useEffect(() => {
    const refresh = () => void handleLoadDiscoverableGroups();
    window.addEventListener('zyphra:groups-changed', refresh);
    return () => window.removeEventListener('zyphra:groups-changed', refresh);
  }, [handleLoadDiscoverableGroups]);

  const handleSelectPeerFromDirectory = useCallback(
    async (peerIdentifier: string) => {
      setMobileRailOpen(false);
      try {
        const resolved = await resolveE2EEPeer(peerIdentifier);
        if (e2eeProfile && resolved.user_id === e2eeProfile.user_id) {
          alert('You cannot start a private chat with yourself.');
          return;
        }
        if (resolved.devices.length === 0) {
          alert('This member has not signed in to chats yet.');
          return;
        }
        registerOpenedPeer(resolved);
        setSelectedPeer(resolved);
        handleSelectChannelTab('dm');
      } catch (err: any) {
        alert(friendlyError(err, `Could not resolve peer ${peerIdentifier}`));
      }
    },
    [e2eeProfile, registerOpenedPeer, handleSelectChannelTab]
  );

  // Sync DM conversation list & MLS groups/welcomes (serialized & safe Welcome ACK)
  const syncSidebarLists = useCallback(async () => {
    if (!isVaultReadyForProfile || !e2eeProfile || !localDeviceId) return;
    if (syncInFlightRef.current) {
      syncQueuedRef.current = true;
      return;
    }
    syncInFlightRef.current = true;
    try {
      do {
        syncQueuedRef.current = false;
        const iterationNo = ++syncIterationRef.current;
        const [dmRes, welcomeRes, invRes] = await Promise.all([
          fetchMyDmConversations(),
          fetchPendingServerMlsWelcomes(localDeviceId, false),
          fetchMyGroupInvitations().catch(() => null),
        ]);
        setDmConversations(dmRes.conversations);
        if (invRes) setGroupInvitations(invRes.invitations);

        for (const w of welcomeRes.welcomes) {
          try {
            await joinMlsGroupFromWelcomeB64(
              e2eeProfile.user_id,
              w.group_id,
              w.mls_welcome_b64
            );
            await ackServerMlsWelcome(w.welcome_id, localDeviceId);
          } catch (wErr) {
            console.warn('MLS Welcome processing deferred:', wErr);
          }
        }

        const grpRes = await fetchMyServerMlsGroups();
        setGroups(grpRes.groups);
        const pendingOpen = openGroupWhenReadyRef.current;
        const justAccepted = pendingOpen ? grpRes.groups.find((g) => g.group_id === pendingOpen.id) : undefined;
        // Not in a list fetched after the request (left or deleted): stop waiting for it.
        if (pendingOpen && !justAccepted && pendingOpen.at < iterationNo) openGroupWhenReadyRef.current = null;
        if (justAccepted) {
          openGroupWhenReadyRef.current = null;
          setSelectedGroup(justAccepted);
          handleSelectChannelTab('groups');
        } else if (selectedGroupIdRef.current) {
          const curId = selectedGroupIdRef.current;
          const updatedSel = grpRes.groups.find((g) => g.group_id === curId) || null;
          setSelectedGroup((prev) => {
            if (!prev || prev.group_id !== curId) return prev;
            if (!updatedSel) return null;
            if (
              prev.current_epoch === updatedSel.current_epoch &&
              prev.name === updatedSel.name &&
              prev.members.length === updatedSel.members.length &&
              JSON.stringify(prev.policy) === JSON.stringify(updatedSel.policy) &&
              JSON.stringify(prev.members) === JSON.stringify(updatedSel.members)
            ) {
              return prev;
            }
            return updatedSel;
          });
        }
      } while (syncQueuedRef.current);
    } catch (err: any) {
      if (err?.status === 403 && e2eeProfile) {
        // A 403 can mean many things (suspended account, block, "not in this group"...). Wipe the
        // local vault ONLY when the server confirms this exact device is revoked; otherwise keep
        // every key, session and cached message.
        const uid = e2eeProfile.user_id;
        const devId = localDeviceId;
        shouldWipeLocalDevice(err, devId, fetchMyE2EEAccount)
          .then(async (revoked) => {
            if (!revoked) return;
            await wipeUserDeviceVault(uid);
            setLocalDeviceId(null);
            setVaultBoundUserId(null);
          })
          .catch(() => { });
      }
    } finally {
      syncInFlightRef.current = false;
      if (e2eeProfile) setSidebarLoadedUserId(e2eeProfile.user_id);
    }
  }, [isVaultReadyForProfile, e2eeProfile, localDeviceId, handleSelectChannelTab]);

  const handleRequestJoinGroup = async (g: DiscoverableGroupRecord) => {
    if (!account) {
      onConnectWallet();
      return;
    }
    if (needsE2EEAuth) {
      (onAuthenticateSiwe || authenticateE2EESession)();
      return;
    }
    try {
      await requestJoinPublicGroup(g.group_id);
      setInviteStatusMsg(
        `Request sent to join "${g.name}". A group admin will add you soon.`
      );
    } catch (err: any) {
      if (isGroupPaymentRequired(err) && onOpenPaidGroupModal) {
        onOpenPaidGroupModal(err.detail.group_id, err.detail.group_name);
        setInviteStatusMsg(`"${err.detail.group_name}" is a paid group. Choose a plan to continue.`);
      } else {
        setInviteStatusMsg(friendlyError(err, 'Join request denied by group policy'));
      }
    }
  };

  const handleOpenDiscoverableGroup = async (g: DiscoverableGroupRecord) => {
    let match = groups.find((item) => item.group_id === g.group_id);
    if (!match) {
      try {
        const res = await fetchMyServerMlsGroups();
        setGroups(res.groups);
        match = res.groups.find((item) => item.group_id === g.group_id);
      } catch {
        // ignore
      }
    }
    if (match) {
      setSelectedGroup(match);
      handleSelectChannelTab('groups');
    }
  };

  const selectedPeerId = selectedPeer?.user_id || null;
  const selectedGroupId = selectedGroup?.group_id || null;
  selectedGroupIdRef.current = selectedGroupId;

  const activeScope =
    activeTab === 'dm' && selectedPeerId
      ? `dm|${selectedPeerId}`
      : activeTab === 'groups' && selectedGroupId
        ? `groups|${selectedGroupId}`
        : null;
  activeScopeRef.current = activeScope;

  // Instantly isolate & swap cached messages before paint whenever the active conversation changes.
  useLayoutEffect(() => {
    loadGenRef.current += 1;
    if (!isVaultReadyForProfile || !e2eeProfile || !localDeviceId || !activeScope) {
      setMessages([]);
      setLoadedScopeKey(null);
      return;
    }
    const cacheKey = `${e2eeProfile.user_id}|${localDeviceId}|${activeScope}`;
    const cached = syncCacheRef.current[cacheKey];
    if (cached) {
      const snapshot = [...cached.msgs];
      setMessages((prev) => mergeLocalEntries(snapshot, prev, activeScope));
      setLoadedScopeKey(activeScope);
    } else {
      setMessages((prev) => mergeLocalEntries([], prev, activeScope));
      setLoadedScopeKey(null);
    }
  }, [activeScope, isVaultReadyForProfile, e2eeProfile?.user_id, localDeviceId]); // eslint-disable-line react-hooks/exhaustive-deps

  // Stable primitives for hooks: depending on the whole profile object would re-create the sync
  // loop and re-subscribe the realtime socket every time the profile is refreshed.
  const myProfileUserId = e2eeProfile?.user_id ?? null;
  const myProfileSendReceipts = e2eeProfile?.send_read_receipts;

  const loadActiveChannelMessages = useCallback(async () => {
    if (!isVaultReadyForProfile || !myProfileUserId || !localDeviceId) {
      return;
    }
    const scopeAtStart = activeScopeRef.current;
    if (!scopeAtStart) return;
    const targetPeerId = activeTab === 'dm' ? selectedPeerId : null;
    const targetGroupId = activeTab === 'groups' ? selectedGroupId : null;
    if (activeTab === 'dm' && !targetPeerId) return;
    if (activeTab === 'groups' && !targetGroupId) return;

    // Coalesce duplicate triggers for the same conversation without blocking other conversations.
    if (scopeSyncPendingRef.current[scopeAtStart]) return;
    scopeSyncPendingRef.current[scopeAtStart] = true;

    const myUserId = myProfileUserId;
    const myDevId = localDeviceId;
    const mySendReceipts = myProfileSendReceipts !== false;
    const myGen = loadGenRef.current;
    const isStillCurrent = () =>
      activeScopeRef.current === scopeAtStart && loadGenRef.current === myGen;

    const prevChain = scopeSyncChainRef.current[scopeAtStart] || Promise.resolve();
    const run = prevChain.catch(() => { }).then(async () => {
      scopeSyncPendingRef.current[scopeAtStart] = false;
      try {
        // 1. PRIVATE 1-TO-1 CHAT (Olm v2 Double Ratchet)
        if (targetPeerId) {
          const dmScope = `dm|${targetPeerId}`;
          const dmCacheKey = `${myUserId}|${myDevId}|${dmScope}`;
          const dmEntry: ConversationSyncEntry = syncCacheRef.current[dmCacheKey] || {
            lastSeq: 0,
            msgs: [],
            retry: {},
            lastReceiptSeq: 0,
          };
          syncCacheRef.current[dmCacheKey] = dmEntry;

          const secKey = `${myUserId}|${targetPeerId}`;
          const cachedSec = peerSecCacheRef.current[secKey];
          const needSecCheck = !cachedSec || forceSecurityRefreshRef.current || Date.now() - cachedSec.at > 30000;
          if (needSecCheck) forceSecurityRefreshRef.current = false;

          const resolveDm = async (rec: any) => {
            if (rec.deleted || rec.expired) {
              const setupCt = rec.device_ciphertexts?.[myDevId];
              const already = await loadVaultDecryptedMessage<E2EEPlaintextEnvelope>(myUserId, rec.message_id);
              if (setupCt && !already) {
                try {
                  await decryptOlmDeviceCiphertext(myUserId, rec.sender_curve25519_key, setupCt.message_type, setupCt.ciphertext_b64);
                } catch {
                  // nothing to keep either way
                }
              }
              if (already) await deleteVaultRecord(`dec_msg:${myUserId}:${rec.message_id}`).catch(() => { });
              return null;
            }
            let cached = await loadVaultDecryptedMessage<E2EEPlaintextEnvelope>(myUserId, rec.message_id);
            if (!cached) {
              const devCt = rec.device_ciphertexts[myDevId];
              if (devCt) {
                try {
                  cached = await decryptOlmDeviceCiphertext(
                    myUserId,
                    rec.sender_curve25519_key,
                    devCt.message_type,
                    devCt.ciphertext_b64
                  );
                  await saveVaultDecryptedMessage(myUserId, rec.message_id, cached);
                } catch {
                  cached = null;
                }
              }
            }
            return cached;
          };
          const dmToDisplay = (rec: any, cached: E2EEPlaintextEnvelope | null): RichDisplayMessage => ({
            id: rec.message_id,
            seq: rec.seq,
            channel: rec.conversation_id,
            localScope: dmScope,
            sender: rec.sender_user_id,
            message: rec.deleted || rec.expired ? '' : cached ? cached.text : 'This message is not available on this device.',
            attachments: cached?.attachments,
            replyTo: cleanReplyRef(cached?.reply_to),
            isEncrypted: true,
            canDecrypt: Boolean(cached) || Boolean(rec.deleted),
            timestamp: rec.timestamp,
            protocolBadge: 'Encrypted',
            env: cached ? envFields(cached) : rec.event_kind === 'control' ? { kind: 'reaction' } : undefined,
            deleted: Boolean(rec.deleted),
            expired: Boolean(rec.expired),
            expiresAt: rec.expires_at || null,
          });

          // Run peer device check in parallel with fetching new DM ciphertexts.
          const secPromise = needSecCheck
            ? fetchPeerActiveDevices(targetPeerId)
              .then(async (latestPeer) => {
                await evaluateAndRecordPeerTrust(
                  myUserId,
                  targetPeerId,
                  latestPeer.identity_version,
                  latestPeer.devices
                );
                peerSecCacheRef.current[secKey] = { at: Date.now() };
              })
              .catch(() => { })
            : Promise.resolve();

          const fetchDmPromise = (async () => {
            let currentDmSeq = dmEntry.lastSeq;
            const out: any[] = [];
            while (true) {
              const dmFeed = await fetchOlmDmCiphertexts(targetPeerId, myDevId, currentDmSeq, 100);
              if (!dmFeed.messages || dmFeed.messages.length === 0) break;
              out.push(...dmFeed.messages);
              const lastMsg = dmFeed.messages[dmFeed.messages.length - 1];
              if (lastMsg.seq <= currentDmSeq) break;
              currentDmSeq = lastMsg.seq;
              if (dmFeed.messages.length < 100) break;
            }
            return out;
          })();

          const [, newDmMessages] = await Promise.all([secPromise, fetchDmPromise]);

          let changed = false;
          for (const [mid, rec] of Object.entries(dmEntry.retry)) {
            const cached = await resolveDm(rec);
            if (cached) {
              delete dmEntry.retry[mid];
              dmEntry.msgs = dmEntry.msgs.map((m) => (m.id === mid ? dmToDisplay(rec, cached) : m));
              changed = true;
            }
          }

          let maxSeq = dmEntry.lastSeq;
          for (const rec of newDmMessages) {
            if (rec.seq > maxSeq) maxSeq = rec.seq;
            const cached = await resolveDm(rec);
            if (!cached && !rec.deleted && !rec.expired) dmEntry.retry[rec.message_id] = rec;
            if (!dmEntry.msgs.some((m) => m.id === rec.message_id)) {
              dmEntry.msgs.push(dmToDisplay(rec, cached));
              changed = true;
            }
          }
          dmEntry.lastSeq = maxSeq;

          if (isStillCurrent()) {
            if (changed || newDmMessages.length > 0 || dmEntry.msgs.length === 0) {
              const dmServerMsgs = [...dmEntry.msgs];
              setMessages((prev) => mergeLocalEntries(dmServerMsgs, prev, dmScope));
            }
            setLoadedScopeKey(scopeAtStart);
            conversationShown(`dm:${targetPeerId}`, maxSeq);

            if (maxSeq > dmEntry.lastReceiptSeq && mySendReceipts) {
              dmEntry.lastReceiptSeq = maxSeq;
              sendDmReadReceipt(targetPeerId, maxSeq).catch(() => { });
            }
            fetchDmReadReceipts(targetPeerId)
              .then((r) => {
                if (!isStillCurrent()) return;
                const peerRec = r.receipts?.[targetPeerId];
                setPeerLastReadSeq(peerRec ? peerRec.last_read_seq : 0);
              })
              .catch(() => { });
          }
          return;
        }

        // 2. ENCRYPTED GROUP CHAT (RFC 9420 MLS TreeKEM)
        if (targetGroupId) {
          const grpScope = `groups|${targetGroupId}`;
          const grpCacheKey = `${myUserId}|${myDevId}|${grpScope}`;
          const grpEntry: ConversationSyncEntry = syncCacheRef.current[grpCacheKey] || {
            lastSeq: 0,
            msgs: [],
            retry: {},
            lastReceiptSeq: 0,
          };
          syncCacheRef.current[grpCacheKey] = grpEntry;

          const secBefore = await getMlsGroupSecurityInfo(myUserId, targetGroupId);
          const localEpoch = secBefore?.epoch ?? 0;

          // Fetch incoming MLS commits and new group ciphertexts in parallel.
          const [commitFeed, newGrpMessages] = await Promise.all([
            fetchServerMlsCommits(targetGroupId, localEpoch),
            (async () => {
              let currentGrpSeq = grpEntry.lastSeq;
              const out: any[] = [];
              while (true) {
                const grpMsgs = await fetchServerMlsGroupMessages(targetGroupId, currentGrpSeq, 100);
                if (!grpMsgs.messages || grpMsgs.messages.length === 0) break;
                out.push(...grpMsgs.messages);
                const lastMsg = grpMsgs.messages[grpMsgs.messages.length - 1];
                if (lastMsg.seq <= currentGrpSeq) break;
                currentGrpSeq = lastMsg.seq;
                if (grpMsgs.messages.length < 100) break;
              }
              return out;
            })(),
          ]);

          if (commitFeed.commits.length > 0) {
            const commitOutcome = await processIncomingMlsCommits(
              myUserId,
              targetGroupId,
              commitFeed.commits
            );
            if (commitOutcome.selfRemoved) {
              if (isStillCurrent()) setSelectedGroup(null);
              await syncSidebarLists();
              return;
            }
          }

          const resolveGrp = async (gm: any) => {
            if (gm.deleted) {
              await deleteVaultRecord(`dec_msg:${myUserId}:${gm.message_id}`).catch(() => { });
              return null;
            }
            let cached = await loadVaultDecryptedMessage<E2EEPlaintextEnvelope>(myUserId, gm.message_id);
            if (!cached) {
              try {
                cached = await decryptMlsGroupMessage(myUserId, targetGroupId, gm.mls_ciphertext_b64);
                await saveVaultDecryptedMessage(myUserId, gm.message_id, cached);
              } catch {
                cached = null;
              }
            }
            return cached;
          };
          const grpToDisplay = (gm: any, cached: E2EEPlaintextEnvelope | null): RichDisplayMessage => ({
            id: gm.message_id,
            seq: gm.seq,
            channel: targetGroupId,
            localScope: grpScope,
            sender: gm.sender_user_id,
            message: gm.deleted
              ? ''
              : cached
                ? cached.text
                : 'This message was sent before you joined, or is not available on this device.',
            attachments: cached?.attachments,
            replyTo: cleanReplyRef(cached?.reply_to),
            epoch: gm.epoch,
            isEncrypted: true,
            canDecrypt: Boolean(cached) || Boolean(gm.deleted),
            timestamp: gm.timestamp,
            protocolBadge: 'Encrypted',
            env: cached ? envFields(cached) : gm.event_kind === 'control' ? { kind: 'reaction' } : undefined,
            deleted: Boolean(gm.deleted),
            expiresAt: gm.expires_at || null,
          });

          let changed = false;
          for (const [mid, gm] of Object.entries(grpEntry.retry)) {
            const cached = await resolveGrp(gm);
            if (cached) {
              delete grpEntry.retry[mid];
              grpEntry.msgs = grpEntry.msgs.map((m) => (m.id === mid ? grpToDisplay(gm, cached) : m));
              changed = true;
            }
          }

          let grpMaxSeq = grpEntry.lastSeq;
          for (const gm of newGrpMessages) {
            if (gm.seq > grpMaxSeq) grpMaxSeq = gm.seq;
            const cached = await resolveGrp(gm);
            if (!cached && !gm.deleted) grpEntry.retry[gm.message_id] = gm;
            if (!grpEntry.msgs.some((m) => m.id === gm.message_id)) {
              grpEntry.msgs.push(grpToDisplay(gm, cached));
              changed = true;
            }
          }
          grpEntry.lastSeq = grpMaxSeq;

          if (isStillCurrent()) {
            if (changed || newGrpMessages.length > 0 || grpEntry.msgs.length === 0) {
              const grpServerMsgs = [...grpEntry.msgs];
              setMessages((prev) => mergeLocalEntries(grpServerMsgs, prev, grpScope));
            }
            setLoadedScopeKey(scopeAtStart);
            conversationShown(`group:${targetGroupId}`, grpMaxSeq);
          }
        }
      } catch (err) {
        console.warn('Message sync error:', err);
        if (isStillCurrent()) setLoadedScopeKey(scopeAtStart);
      }
    });
    scopeSyncChainRef.current[scopeAtStart] = run;
    await run;
  }, [
    activeTab,
    isVaultReadyForProfile,
    myProfileUserId,
    myProfileSendReceipts,
    localDeviceId,
    selectedPeerId,
    selectedGroupId,
    syncSidebarLists,
  ]);

  // Polling is a safety net. New messages, commits, invitations and receipts arrive instantly over the
  // live connection, so while it is up we only re-check every 30 s; when it is down (or the server is
  // full) we poll every 4.5 s as before. A hidden tab does not poll at all and catches up on return.
  useEffect(() => {
    isFirstLoadRef.current = true;
    void loadActiveChannelMessages();
    let last = Date.now();
    const tick = () => {
      if (document.visibilityState !== 'visible') return;
      if (isE2EERealtimeLive() && Date.now() - last < SAFETY_POLL_MS) return;
      last = Date.now();
      void loadActiveChannelMessages();
    };
    const onVisible = () => {
      if (document.visibilityState !== 'visible') return;
      last = Date.now();
      void loadActiveChannelMessages();
    };
    const interval = setInterval(tick, FAST_POLL_MS);
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      clearInterval(interval);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [loadActiveChannelMessages]);

  useEffect(() => {
    if (!isVaultReadyForProfile) return;
    void syncSidebarLists();
    let last = Date.now();
    const tick = () => {
      if (document.visibilityState !== 'visible') return;
      if (isE2EERealtimeLive() && Date.now() - last < SAFETY_POLL_MS) return;
      last = Date.now();
      void syncSidebarLists();
    };
    const onVisible = () => {
      if (document.visibilityState !== 'visible') return;
      last = Date.now();
      void syncSidebarLists();
    };
    const interval = setInterval(tick, FAST_POLL_MS);
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      clearInterval(interval);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [isVaultReadyForProfile, syncSidebarLists]);

  useEffect(() => {
    if (!isVaultReadyForProfile) return;
    return subscribeE2EERealtime((evt) => {
      if (evt.type === 'authenticated') {
        // (Re)connected: fetch whatever arrived while the live connection was down.
        void loadActiveChannelMessages();
        void syncSidebarLists();
        return;
      }
      if (
        evt.type === 'dm_ciphertext' ||
        evt.type === 'dm_read_receipt' ||
        evt.type === 'group_ciphertext' ||
        evt.type === 'group_commit' ||
        evt.type === 'group_welcome' ||
        evt.type === 'group_join_request' ||
        evt.type === 'group_invitation' ||
        evt.type === 'group_invitation_response' ||
        evt.type === 'group_member_left' ||
        evt.type === 'group_deleted' ||
        evt.type === 'identity_event'
      ) {
        if (evt.type === 'identity_event') forceSecurityRefreshRef.current = true;
        if (evt.type === 'group_deleted' && (evt as any).group_id && myProfileUserId) {
          // The group no longer exists: drop its keys from this device. The list refresh below removes it from view.
          void clearLocalMlsGroupState(myProfileUserId, String((evt as any).group_id)).catch(() => { });
        }
        if (evt.type === 'group_join_request' && (evt as any).group_id) {
          setJoinRequestAlertGroupId(String((evt as any).group_id));
        }
        if (evt.type === 'group_invitation' && (evt as any).group_id) {
          setInvitationAlert({
            group_id: String((evt as any).group_id),
            group_name: String((evt as any).group_name || 'a group'),
            by: (evt as any).invited_by_username ? String((evt as any).invited_by_username) : null,
          });
        }
        void loadActiveChannelMessages();
        const needsSidebarRefresh =
          evt.type !== 'dm_read_receipt' &&
          evt.type !== 'group_ciphertext' &&
          evt.type !== 'group_commit';
        if (needsSidebarRefresh) {
          void syncSidebarLists();
        }
      } else if (evt.type === 'support_reply') {
        // An admin answered a support conversation: update the badge and an open Contact Admin page now.
        window.dispatchEvent(new CustomEvent('zyphra:support-reply', { detail: evt }));
      }
    });
  }, [isVaultReadyForProfile, loadActiveChannelMessages, syncSidebarLists, myProfileUserId]);

  // ====================================================================================
  // CHAT FEATURES: reactions, edits, delete for everyone, polls, pins, typing, search,
  // disappearing messages, announcement groups, mute / archive.
  // Reactions, edits and votes are ENCRYPTED events folded on this device (services/chatEvents.ts);
  // the raw `messages` list stays as loaded, `displayMessages` is what the timeline shows.
  // ====================================================================================
  const [convState, setConvState] = useState<ConversationState | null>(null);
  const [convPrefs, setConvPrefs] = useState<Record<string, ConversationPref>>({});
  const [showArchived, setShowArchived] = useState(false);
  const [editTarget, setEditTarget] = useState<{ id: string; original: string } | null>(null);
  const [pollOpen, setPollOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchIndex, setSearchIndex] = useState(0);
  const [typingBy, setTypingBy] = useState<Record<string, Record<string, number>>>({});
  const [nowTick, setNowTick] = useState(() => Date.now());
  const [featureNotice, setFeatureNotice] = useState<string | null>(null);
  const lastTypingSentRef = useRef(0);

  const convKey =
    activeTab === 'dm' && selectedPeer
      ? `dm:${selectedPeer.user_id}`
      : activeTab === 'groups' && selectedGroup
        ? `group:${selectedGroup.group_id}`
        : null;
  const convKeyRef = useRef<string | null>(null);
  convKeyRef.current = convKey;
  const refFromKey = (key: string): ConversationRef =>
    key.startsWith('dm:') ? { scope_type: 'dm', peer_user_id: key.slice(3) } : { scope_type: 'group', group_id: key.slice(6) };

  const loadConvState = useCallback(async () => {
    const key = convKeyRef.current;
    if (!isVaultReadyForProfile || !key) {
      setConvState(null);
      return;
    }
    try {
      const st = await fetchConversationState(refFromKey(key));
      convStateCacheRef.current[key] = st;
      if (convKeyRef.current === key) setConvState(st);
    } catch {
      if (convKeyRef.current === key && !convStateCacheRef.current[key]) setConvState(null);
    }
  }, [isVaultReadyForProfile]);

  const loadConvPrefs = useCallback(async () => {
    if (!isVaultReadyForProfile) return;
    try {
      const res = await fetchConversationPrefs();
      setConvPrefs(res.prefs || {});
      setNotificationMutedScopes(Object.entries(res.prefs || {}).filter(([, p]) => p.muted).map(([k]) => k));
    } catch {
      // keep what we have
    }
  }, [isVaultReadyForProfile]);

  useEffect(() => {
    setConvState(convKey ? convStateCacheRef.current[convKey] || null : null);
    setEditTarget(null);
    setSearchOpen(false);
    setSearchQuery('');
    void loadConvState();
  }, [convKey, loadConvState]);

  useEffect(() => {
    void loadConvPrefs();
  }, [loadConvPrefs]);

  // Disappearing messages and "typing…" need the clock: re-check every 15 s, and right when a typing line ends.
  useEffect(() => {
    const t = window.setInterval(() => setNowTick(Date.now()), 15000);
    return () => window.clearInterval(t);
  }, []);
  useEffect(() => {
    const ends = Object.values(typingBy).flatMap((m) => Object.values(m)).filter((t) => t > Date.now());
    if (!ends.length) return;
    const t = window.setTimeout(() => setNowTick(Date.now()), Math.min(...ends) - Date.now() + 50);
    return () => window.clearTimeout(t);
  }, [typingBy, nowTick]);

  /** Deleted for everyone: show it as deleted everywhere on this device and drop the readable copy. */
  const markDeletedLocally = useCallback(
    (messageId: string) => {
      const scrub = (m: RichDisplayMessage): RichDisplayMessage =>
        m.id === messageId ? { ...m, deleted: true, message: '', env: undefined, attachments: undefined, replyTo: undefined } : m;
      for (const entry of Object.values(syncCacheRef.current)) entry.msgs = entry.msgs.map(scrub);
      setMessages((prev) => prev.map(scrub));
      if (e2eeProfile) void deleteVaultRecord(`dec_msg:${e2eeProfile.user_id}:${messageId}`).catch(() => { });
    },
    [e2eeProfile]
  );

  useEffect(() => {
    if (!isVaultReadyForProfile) return;
    return subscribeE2EERealtime((evt: any) => {
      if (evt.type === 'conversation_state_changed') {
        const key = convKeyRef.current;
        if (key && ((evt.scope_type === 'group' && key === `group:${evt.group_id}`) || (evt.scope_type === 'dm' && key.startsWith('dm:')))) {
          void loadConvState();
        }
      } else if (evt.type === 'conversation_prefs_changed') {
        void loadConvPrefs();
      } else if (evt.type === 'message_deleted' && evt.message_id) {
        markDeletedLocally(String(evt.message_id));
      } else if (evt.type === 'typing' && evt.user_id) {
        const key = evt.scope_type === 'dm' ? `dm:${evt.peer_user_id}` : `group:${evt.group_id}`;
        setTypingBy((prev) => ({ ...prev, [key]: { ...(prev[key] || {}), [evt.user_id]: Date.now() + 6000 } }));
      } else if ((evt.type === 'dm_ciphertext' || evt.type === 'group_ciphertext') && evt.sender_user_id) {
        // Their message arrived: they are no longer typing.
        const key = evt.type === 'dm_ciphertext' ? `dm:${evt.sender_user_id}` : `group:${evt.group_id}`;
        setTypingBy((prev) => {
          if (!prev[key]?.[evt.sender_user_id]) return prev;
          const next = { ...prev[key] };
          delete next[evt.sender_user_id];
          return { ...prev, [key]: next };
        });
      }
    });
  }, [isVaultReadyForProfile, loadConvState, loadConvPrefs, markDeletedLocally]);

  const groupAdminIds = React.useMemo(
    () => new Set((selectedGroup?.members || []).filter((m) => m.status === 'active' && m.role === 'admin').map((m) => m.user_id)),
    [selectedGroup]
  );
  const isGroupAdminHere = activeTab === 'groups' && Boolean(e2eeProfile && groupAdminIds.has(e2eeProfile.user_id));
  const adminsOnlyHere = activeTab === 'groups' && Boolean(convState?.admins_only);

  const displayMessages = React.useMemo(() => {
    const scoped = activeScope
      ? messages.filter((m) => !m.localScope || m.localScope === activeScope)
      : [];
    return foldChatEvents(scoped as Array<RichDisplayMessage & FoldInput>, {
      myUserId: e2eeProfile?.user_id || '',
      nowMs: nowTick,
      adminsOnly: adminsOnlyHere,
      adminIds: groupAdminIds,
    });
  }, [messages, activeScope, e2eeProfile?.user_id, nowTick, adminsOnlyHere, groupAdminIds]);

  const searchHits = React.useMemo(
    () => (searchOpen ? searchMessages(displayMessages, searchQuery) : []),
    [searchOpen, displayMessages, searchQuery]
  );
  useEffect(() => {
    setSearchIndex(Math.max(0, searchHits.length - 1)); // start from the newest match
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchQuery]);
  const stepSearch = (dir: 1 | -1) => {
    const n = searchHits.length;
    if (!n) return;
    const next = (searchIndex + dir + n) % n;
    setSearchIndex(next);
    jumpToMessage(searchHits[next]);
  };

  const typingNames = (() => {
    if (!convKey || !e2eeProfile) return [] as string[];
    const map = typingBy[convKey] || {};
    return Object.entries(map)
      .filter(([uid, until]) => until > nowTick && uid !== e2eeProfile.user_id)
      .map(([uid]) => nameForSender(uid));
  })();

  /** Encrypts and sends one envelope (a reaction, edit, vote or poll) in the open chat. */
  const sendEnvelopeNow = async (
    extra: Partial<E2EEPlaintextEnvelope>,
    eventKind: 'message' | 'control',
    mentionIds: string[] = []
  ): Promise<void> => {
    if (!e2eeProfile || !localDeviceId) throw new Error('Please sign in first.');
    const myUserId = e2eeProfile.user_id;
    const msgId = `emsg_${crypto.randomUUID().replace(/-/g, '')}`;
    const envelope: E2EEPlaintextEnvelope = { v: 1, text: '', sent_at: new Date().toISOString(), ...extra };
    if (activeTab === 'dm' && selectedPeer) {
      const [peerDevs, ownAccount] = await Promise.all([fetchPeerActiveDevices(selectedPeer.user_id), fetchMyE2EEAccount()]);
      const targets = [...peerDevs.devices, ...ownAccount.devices.filter((d) => d.status === 'active')];
      if (!targets.length) throw new Error('This member has not signed in to chats yet.');
      const enc = await encryptOlmMultiDevicePayload(myUserId, envelope, targets, (uid, ids) => claimPeerOlmPrekeyBundles(uid, ids));
      await saveVaultDecryptedMessage(myUserId, msgId, envelope);
      await submitOlmDmCiphertext({
        message_id: msgId,
        recipient_user_id: selectedPeer.user_id,
        sender_device_id: enc.senderDeviceId,
        protocol: OLM_PROTOCOL_ID,
        device_ciphertexts: enc.deviceCiphertexts,
        event_kind: eventKind,
      });
    } else if (activeTab === 'groups' && selectedGroup) {
      const enc = await encryptMlsGroupMessage(myUserId, selectedGroup.group_id, envelope);
      await saveVaultDecryptedMessage(myUserId, msgId, envelope);
      await submitServerMlsGroupMessage(selectedGroup.group_id, {
        message_id: msgId,
        sender_device_id: localDeviceId,
        epoch: enc.epoch,
        mls_ciphertext_b64: enc.mlsCiphertextB64,
        event_kind: eventKind,
        mention_user_ids: mentionIds,
      });
    } else {
      throw new Error('Open a chat first.');
    }
    await loadActiveChannelMessages();
  };

  const runFeature = async (fn: () => Promise<unknown>, fallback: string) => {
    setFeatureNotice(null);
    try {
      await fn();
    } catch (err: any) {
      if (isGroupPaymentRequired(err) && onOpenPaidGroupModal) onOpenPaidGroupModal(err.detail.group_id, err.detail.group_name);
      setFeatureNotice(err?.detail?.code === 'admins_only' ? 'Only admins can send messages in this group.' : friendlyError(err, fallback));
    }
  };

  const reactTo = (msgId: string, emoji: string) =>
    runFeature(() => sendEnvelopeNow({ kind: 'reaction', target_id: msgId, emoji }, 'control'), 'Your reaction was not sent.');
  const voteOn = (msgId: string, options: number[]) =>
    runFeature(() => sendEnvelopeNow({ kind: 'poll_vote', target_id: msgId, vote: options }, 'control'), 'Your vote was not sent.');
  const createPoll = async (question: string, options: string[], multi: boolean) => {
    await sendEnvelopeNow({ text: question, poll: { question, options, multi } }, 'message');
  };
  const deleteForEveryone = (msg: RichDisplayMessage) => {
    if (!window.confirm('Delete this message for everyone? It is removed from the server and from everyone\u2019s chat.')) return;
    void runFeature(async () => {
      if (activeTab === 'dm') await deleteDmMessageForEveryone(msg.id);
      else if (selectedGroup) await deleteGroupMessageForEveryone(selectedGroup.group_id, msg.id);
      markDeletedLocally(msg.id);
    }, 'The message was not deleted.');
  };
  const togglePin = (msgId: string, pinned: boolean) =>
    runFeature(async () => {
      if (!convKey) return;
      const res = await setMessagePinned(refFromKey(convKey), msgId, pinned);
      setConvState((s) => (s ? { ...s, pins: res.pins } : s));
    }, pinned ? 'The message was not pinned.' : 'The message was not unpinned.');
  const updatePref = (change: { mute?: MuteChoice; archived?: boolean }, key = convKey) =>
    runFeature(async () => {
      if (!key) return;
      const res = await setConversationPref(key, change);
      setConvPrefs((prev) => {
        const next = { ...prev };
        if (res.pref.muted || res.pref.archived) next[key] = res.pref;
        else delete next[key];
        setNotificationMutedScopes(Object.entries(next).filter(([, p]) => p.muted).map(([k]) => k));
        return next;
      });
    }, 'That setting was not saved.');
  const changeTimer = (ttl: number) =>
    runFeature(async () => {
      if (!convKey) return;
      const res = await setDisappearingTimer(refFromKey(convKey), ttl);
      setConvState((s) => (s ? { ...s, disappearing_ttl: res.disappearing_ttl } : s));
    }, 'The timer was not changed.');
  const changeAdminsOnly = (value: boolean) =>
    runFeature(async () => {
      if (!selectedGroup) return;
      const res = await setGroupAdminsOnly(selectedGroup.group_id, value);
      setConvState((s) => (s ? { ...s, admins_only: res.admins_only } : s));
    }, 'That setting was not saved.');
  const signalTyping = () => {
    if (!convKey || e2eeProfile?.show_online_presence === false) return;
    const now = Date.now();
    if (now - lastTypingSentRef.current < 3000) return;
    lastTypingSentRef.current = now;
    sendTypingSignal(refFromKey(convKey)).catch(() => { });
  };
  const currentPref = convKey ? convPrefs[convKey] : undefined;
  const mentionCandidates = React.useMemo(
    () =>
      (selectedGroup?.members || [])
        .filter((m) => m.status === 'active' && m.username && m.user_id !== e2eeProfile?.user_id)
        .map((m) => ({ id: m.user_id, username: m.username as string }))
        .filter((m, i, all) => all.findIndex((x) => x.id === m.id) === i),
    [selectedGroup, e2eeProfile?.user_id]
  );

  // Notifications: which conversation is on screen (it is never notified while you look at it).
  const activeConversationScope =
    activeTab === 'dm' && selectedPeer
      ? `dm:${selectedPeer.user_id}`
      : activeTab === 'groups' && selectedGroup
        ? `group:${selectedGroup.group_id}`
        : null;
  // A reply belongs to the conversation it was started in.
  const replyTarget = replyState && replyState.scope === activeConversationScope ? replyState.ref : null;
  const setReplyTarget = (ref: ReplyRef | null) =>
    setReplyState(ref && activeConversationScope ? { scope: activeConversationScope, ref } : null);
  useEffect(() => {
    setActiveConversation(activeConversationScope);
  }, [activeConversationScope]);
  useEffect(() => () => setActiveConversation(null), []);

  // Names for notifications ("@name in Group"), from what the sidebar already knows.
  useEffect(() => {
    const users: Record<string, string> = {};
    for (const c of dmConversations) if (c.peer_username) users[c.peer_user_id] = `@${c.peer_username}`;
    for (const p of openedPeers) if (p.username) users[p.user_id] = `@${p.username}`;
    const grp: Record<string, string> = {};
    for (const g of groups) {
      grp[g.group_id] = g.name;
      for (const m of g.members) if (m.username) users[m.user_id] = `@${m.username}`;
    }
    rememberNames({ users, groups: grp });
  }, [dmConversations, openedPeers, groups]);

  // Open a group from a notification: it opens as soon as the group list has it (same path as Accept).
  // ('' only means "the Groups page", which App already switched to.)
  useEffect(() => {
    if (initialGroupId === null || initialGroupId === undefined) return;
    if (initialGroupId) {
      openGroupWhenReadyRef.current = { id: initialGroupId, at: syncIterationRef.current };
      // Refresh right after this render; the refresh opens the group when the list has it.
      queueMicrotask(() => void syncSidebarLists());
    }
    onConsumedInitialGroup?.();
  }, [initialGroupId, syncSidebarLists, onConsumedInitialGroup]);

  // Keep this device's one-time prekeys and MLS KeyPackages topped up while the app stays open.
  // (Previously only done at sign-in, so a long session that was added to many groups could run out
  // and then nobody could add this member to a new group.)
  useEffect(() => {
    if (!isVaultReadyForProfile || !e2eeProfile || !localDeviceId) return;
    const userId = e2eeProfile.user_id;
    const deviceId = localDeviceId;
    const topUp = async () => {
      if (prekeyTopUpInFlightRef.current || document.visibilityState !== 'visible') return;
      prekeyTopUpInFlightRef.current = true;
      try {
        const counts = await fetchDevicePrekeyCounts(deviceId);
        if (counts.one_time_prekeys >= 5 && counts.mls_key_packages >= 3) return;
        const moreOlm = await generateMoreOlmPrekeys(userId, 12, false);
        const moreMls = await generateMlsKeyPackagesForDevice(userId, deviceId, 6);
        await replenishE2EEPrekeys(deviceId, { ...moreOlm, mls_key_packages: moreMls });
        await markLocalPrekeysPublished(userId);
      } catch (err) {
        console.warn('Prekey top-up deferred (non-fatal):', err);
      } finally {
        prekeyTopUpInFlightRef.current = false;
      }
    };
    const first = setTimeout(topUp, 60_000); // sign-in already topped up; check again after a minute
    const every = setInterval(topUp, 10 * 60_000);
    return () => {
      clearTimeout(first);
      clearInterval(every);
    };
  }, [isVaultReadyForProfile, e2eeProfile?.user_id, localDeviceId]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (chatBodyRef.current && messages.length > 0 && isFirstLoadRef.current) {
      setTimeout(() => scrollToBottom(false), 40);
      isFirstLoadRef.current = false;
    }
  }, [messages.length]);

  const executeMlsCommitWithRetry = async (
    groupId: string,
    buildFn: () => Promise<{
      expectedEpoch: number;
      mlsCommitB64: string;
      mlsWelcomeB64?: string;
      addedMembers?: Array<{ user_id: string; device_id: string; role: 'member' }>;
      removedMembers?: Array<{ user_id: string; device_id?: string }>;
      applyLocalCommit: () => Promise<number>;
    }>,
    commitType: 'add' | 'remove' | 'update'
  ): Promise<E2EEGroupRecord | null> => {
    if (!e2eeProfile || !localDeviceId) return null;
    for (let attempt = 0; attempt < 2; attempt++) {
      const built = await buildFn();
      try {
        const welcomes =
          built.mlsWelcomeB64 && built.addedMembers
            ? built.addedMembers.map((m) => ({
              target_user_id: m.user_id,
              target_device_id: m.device_id,
              mls_welcome_b64: built.mlsWelcomeB64!,
            }))
            : [];
        const res = await submitServerMlsCommit(groupId, {
          committer_device_id: localDeviceId,
          expected_epoch: built.expectedEpoch,
          commit_type: commitType,
          mls_commit_b64: built.mlsCommitB64,
          added_members: built.addedMembers,
          removed_members: built.removedMembers,
          welcomes,
        });
        await built.applyLocalCommit();
        setSelectedGroup(res.group);
        await syncSidebarLists();
        await loadActiveChannelMessages();
        return res.group;
      } catch (err: any) {
        if (err?.status === 409 && err?.detail?.missing_commits && attempt === 0) {
          await processIncomingMlsCommits(
            e2eeProfile.user_id,
            groupId,
            err.detail.missing_commits
          );
          continue;
        }
        throw err;
      }
    }
    return null;
  };

  // Start a 1-to-1 Individual Chat by Member ID (@username, usr_..., or 0x... wallet)
  const handleStartChatIndividual = async (e?: React.FormEvent, overrideId?: string) => {
    if (e) e.preventDefault();
    const targetId = (overrideId ?? individualIdInput).trim();
    if (!targetId) {
      setChatIndividualError('Enter a member ID (@username, usr_..., or 0x... wallet).');
      return;
    }
    if (!account) {
      onConnectWallet();
      return;
    }
    if (needsE2EEAuth || !e2eeProfile || !localDeviceId) {
      (onAuthenticateSiwe || authenticateE2EESession)();
      return;
    }

    setStartingIndividualBusy(true);
    setChatIndividualError(null);
    try {
      const resolved = await resolveE2EEPeer(targetId);
      if (resolved.user_id === e2eeProfile.user_id) {
        setChatIndividualError('That is your own account ID. Enter another member ID to chat.');
        return;
      }
      if (resolved.devices.length === 0) {
        setChatIndividualError(
          'This member has not signed in to chats yet. Ask them to connect MetaMask and sign in once.'
        );
        return;
      }
      registerOpenedPeer(resolved);
      setSelectedPeer(resolved);
      setIndividualIdInput('');
      setChatIndividualModalOpen(false);
      handleSelectChannelTab('dm');
    } catch (err: any) {
      setChatIndividualError(
        friendlyError(err, 'Could not find a verified member with that ID.')
      );
    } finally {
      setStartingIndividualBusy(false);
    }
  };

  // Resolve & stage a member chip inside the "Create Group" modal
  const handleStageMemberForGroup = async (rawIdentifier?: string) => {
    const target = (rawIdentifier ?? groupMemberInput).trim();
    if (!target || addingGroupMemberBusy) return;
    setAddingGroupMemberBusy(true);
    setCreateGroupError(null);
    try {
      const resolved = await resolveE2EEPeer(target);
      if (e2eeProfile && resolved.user_id === e2eeProfile.user_id) {
        setCreateGroupError('You are automatically included as the group creator/admin.');
        return;
      }
      if (resolved.devices.length === 0) {
        setCreateGroupError(
          `${resolved.username ? `@${resolved.username}` : 'This member'} has not signed in to chats yet.`
        );
        return;
      }
      setPendingGroupMembers((prev) =>
        prev.some((m) => m.user_id === resolved.user_id) ? prev : [...prev, resolved]
      );
      setGroupMemberInput('');
    } catch (err: any) {
      setCreateGroupError(friendlyError(err, `Member "${target}" not found.`));
    } finally {
      setAddingGroupMemberBusy(false);
    }
  };

  // Create Encrypted MLS Group + batch-add initial members in one seamless flow
  const handleCreateMlsGroup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newGroupName.trim()) {
      setCreateGroupError('Enter a name for the group.');
      return;
    }
    if (!account) {
      onConnectWallet();
      return;
    }
    if (needsE2EEAuth || !e2eeProfile || !localDeviceId) {
      (onAuthenticateSiwe || authenticateE2EESession)();
      return;
    }

    const isSuperadmin = e2eeProfile.admin_role === 'superadmin';
    const feeUsd = Number(newGroupFeeUsd);
    if (isSuperadmin && newGroupPaid && !(feeUsd > 0)) {
      setCreateGroupError('Enter a monthly price greater than $0 for a paid group.');
      return;
    }

    setCreatingGroupBusy(true);
    setCreateGroupError(null);
    try {
      let finalMembers = [...pendingGroupMembers];
      const unaddedInput = groupMemberInput.trim();
      if (unaddedInput) {
        const extraPeer = await resolveE2EEPeer(unaddedInput);
        if (extraPeer.user_id === e2eeProfile.user_id) {
          throw new Error('Remove your own ID from the Add Members field (you are added automatically).');
        }
        if (extraPeer.devices.length === 0) {
          throw new Error(
            `${extraPeer.username ? `@${extraPeer.username}` : 'This member'} has not signed in to chats yet.`
          );
        }
        if (!finalMembers.some((m) => m.user_id === extraPeer.user_id)) {
          finalMembers = [...finalMembers, extraPeer];
        }
      }

      // 1. Claim every member's MLS KeyPackages BEFORE anything is created, so the usual failure
      //    ("member has not opened Messages yet") stops here and leaves no group behind.
      const claimedAll: Array<{
        user_id: string;
        device_id: string;
        key_package_b64: string;
      }> = [];
      if (finalMembers.length > 0) {
        const cache = claimedKeyPackagesRef.current;
        // Claim secondary devices for creator if any exist (once per form session)
        if (!cache[e2eeProfile.user_id]) {
          try {
            const myExtraPkgs = await claimPeerMlsKeyPackages(e2eeProfile.user_id);
            cache[e2eeProfile.user_id] = myExtraPkgs.filter((p) => p.device_id !== localDeviceId);
          } catch {
            cache[e2eeProfile.user_id] = []; // no other devices
          }
        }
        claimedAll.push(...cache[e2eeProfile.user_id]);
        for (const member of finalMembers) {
          if (!cache[member.user_id]?.length) {
            const pkgs = await claimPeerMlsKeyPackages(member.user_id);
            if (pkgs.length === 0) {
              throw new Error(
                `${member.username ? `@${member.username}` : 'This member'} cannot be added right now. Ask them to open Messages once, then try again.`
              );
            }
            cache[member.user_id] = pkgs;
          }
          claimedAll.push(...cache[member.user_id]);
        }
      }

      // 2. Create the group (Epoch 0) — unless a previous attempt already created it.
      let created: { group: Awaited<ReturnType<typeof createServerMlsGroup>>['group'] };
      const reuse = halfCreatedGroupRef.current;
      if (reuse) {
        created = { group: reuse };
      } else {
        const localInit = await initializeNewMlsGroupLocal(e2eeProfile.user_id, localDeviceId);
        created = await createServerMlsGroup({
          name: newGroupName.trim(),
          mls_group_id_b64: localInit.mlsGroupIdB64,
          creator_device_id: localDeviceId,
          ciphersuite: MLS_CIPHERSUITE_NAME,
          visibility: newGroupVisibility,
          min_eth_balance_wei: parseEthStringToWeiString(newGroupMinEth),
          require_invitation: true,
          ...(isSuperadmin && newGroupPaid
            ? { is_paid: true, entry_fee_usd: feeUsd, entry_fee_yearly_usd: Number(newGroupYearlyFeeUsd) || 0 }
            : {}),
        });
        await localInit.finalizeWithServerGroupId(created.group.group_id);
        // From here on the group exists: remember it and show it, so a failure below is retried
        // as "add members" instead of creating a duplicate.
        halfCreatedGroupRef.current = created.group;
        const justCreated = created.group;
        setGroups((prev) => [justCreated, ...prev.filter((g) => g.group_id !== justCreated.group_id)]);
      }

      let activeGroupRecord = created.group;

      // 3. Commit Epoch 1 with the members + send their Welcomes.
      if (claimedAll.length > 0) {
        const updatedGrp = await executeMlsCommitWithRetry(
          created.group.group_id,
          () =>
            buildMlsAddMembersCommit(
              e2eeProfile.user_id,
              created.group.group_id,
              claimedAll
            ),
          'add'
        );
        if (updatedGrp) {
          activeGroupRecord = updatedGrp;
        }
      }

      halfCreatedGroupRef.current = null;
      claimedKeyPackagesRef.current = {}; // used by the successful commit
      setNewGroupName('');
      setNewGroupPaid(false);
      setNewGroupYearlyFeeUsd('0');
      setGroupMemberInput('');
      setPendingGroupMembers([]);
      setShowGroupOpts(false);
      setCreateGroupModalOpen(false);
      setGroups((prev) => [
        activeGroupRecord,
        ...prev.filter((g) => g.group_id !== activeGroupRecord.group_id),
      ]);
      setSelectedGroup(activeGroupRecord);
      handleSelectChannelTab('groups');
      await syncSidebarLists();
    } catch (err: any) {
      const msg = friendlyError(err, 'Failed to create encrypted group');
      setCreateGroupError(
        halfCreatedGroupRef.current
          ? `The group was created, but adding members failed: ${msg} Press Create again to retry adding them.`
          : msg
      );
    } finally {
      setCreatingGroupBusy(false);
    }
  };

  /**
   * Adds a member as group admin. Someone who asked to join (join request / invite code) is added
   * straight away; anyone else gets an invitation and joins only after they press Accept.
   */
  const handleAddGroupMember = async (identifier: string): Promise<'active' | 'invited'> => {
    if (!selectedGroup || !e2eeProfile) throw new Error('Open a group first.');
    const peer = await resolveE2EEPeer(identifier);
    const who = peer.username ? `@${peer.username}` : 'This member';
    if (peer.user_id === e2eeProfile.user_id) throw new Error('You are already in this group.');
    const rows = selectedGroup.members.filter((m) => m.user_id === peer.user_id);
    if (rows.some((m) => m.status === 'active')) throw new Error(`${who} is already in this group.`);
    if (rows.some((m) => m.status === 'invited')) {
      throw new Error(`${who} has already been invited and has not replied yet.`);
    }
    if (rows.some((m) => m.status === 'declined' || m.status === 'left')) {
      // Clear their old place in the group first, so they can be invited again cleanly.
      try {
        await handleRemoveGroupMember(peer.user_id);
      } catch {
        /* nothing left to clear */
      }
    }
    const claimed = await claimPeerMlsKeyPackages(peer.user_id);
    if (claimed.length === 0) {
      throw new Error('This member cannot be added right now. Ask them to open Messages once, then try again.');
    }
    const updated = await executeMlsCommitWithRetry(
      selectedGroup.group_id,
      () =>
        buildMlsAddMembersCommit(
          e2eeProfile.user_id,
          selectedGroup.group_id,
          claimed
        ),
      'add'
    );
    const after = (updated?.members || []).filter((m) => m.user_id === peer.user_id);
    return after.some((m) => m.status === 'invited') ? 'invited' : 'active';
  };

  const handleAcceptGroupInvitation = async (groupId: string, groupName: string) => {
    if (invitationBusyId) return;
    setInvitationBusyId(groupId);
    setInvitationNotice(null);
    try {
      await acceptGroupInvitation(groupId);
      setGroupInvitations((prev) => prev.filter((i) => i.group_id !== groupId));
      setInvitationAlert((cur) => (cur?.group_id === groupId ? null : cur));
      openGroupWhenReadyRef.current = { id: groupId, at: syncIterationRef.current };
      await syncSidebarLists();
    } catch (err: any) {
      if (isGroupPaymentRequired(err) && onOpenPaidGroupModal) {
        onOpenPaidGroupModal(err.detail.group_id, err.detail.group_name);
        setInvitationNotice(`"${groupName}" is a paid group. Choose a plan in the payment window, then press Accept again.`);
      } else {
        setInvitationNotice(friendlyError(err, 'Could not join the group. Please try again.'));
        void syncSidebarLists();
      }
    } finally {
      setInvitationBusyId(null);
    }
  };

  const handleDeclineGroupInvitation = async (groupId: string) => {
    if (invitationBusyId) return;
    setInvitationBusyId(groupId);
    setInvitationNotice(null);
    try {
      await declineGroupInvitation(groupId);
      setGroupInvitations((prev) => prev.filter((i) => i.group_id !== groupId));
      setInvitationAlert((cur) => (cur?.group_id === groupId ? null : cur));
    } catch (err: any) {
      setInvitationNotice(friendlyError(err, 'Could not reject the invitation. Please try again.'));
      void syncSidebarLists();
    } finally {
      setInvitationBusyId(null);
    }
  };

  const handleRemoveGroupMember = async (targetUserId: string) => {
    if (!selectedGroup) return;
    await executeMlsCommitWithRetry(
      selectedGroup.group_id,
      () =>
        buildMlsRemoveMemberCommit(
          e2eeProfile!.user_id,
          selectedGroup.group_id,
          targetUserId
        ),
      'remove'
    );
  };

  const handleSendMessage = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!account) {
      onConnectWallet();
      return;
    }

    const text = inputMessage.trim();
    const files = pendingFiles;
    if ((!text && files.length === 0) || sending) return;
    if (!e2eeProfile || !localDeviceId) {
      alert('Please sign in first.');
      return;
    }
    const channelType: 'dm' | 'groups' = activeTab === 'dm' ? 'dm' : 'groups';
    const peer = selectedPeer;
    const group = selectedGroup;
    if ((channelType === 'dm' && !peer) || (channelType === 'groups' && !group)) return;

    // Editing one of my messages: send an encrypted edit instead of a new message.
    if (editTarget) {
      if (!text) return;
      const target = editTarget;
      setInputMessage('');
      setEditTarget(null);
      await runFeature(() => sendEnvelopeNow({ kind: 'edit', target_id: target.id, text }, 'control'), 'Your edit was not saved.');
      return;
    }

    const targetId = channelType === 'dm' ? peer!.user_id : group!.group_id;
    const scope = `${channelType}|${targetId}`;
    const msgId = `emsg_${crypto.randomUUID().replace(/-/g, '')}`;
    const displayText = text;
    const myUserId = e2eeProfile.user_id;
    const sentAtIso = new Date().toISOString();
    const replyRef = replyTarget || undefined;
    // @mentions (groups): inside the encrypted message, and their ids to the server for the notice.
    const mentionIds =
      channelType === 'groups' && group
        ? findMentionedIds(text, group.members.filter((m) => m.status === 'active'), myUserId)
        : [];

    // 1) Show the message and free the input IMMEDIATELY. Encryption and the network call run
    //    behind it, so the sender never waits on the server to see their own message.
    setMessages((prev) => [
      ...prev,
      {
        id: msgId,
        channel: targetId,
        sender: myUserId,
        recipient: channelType === 'dm' ? targetId : undefined,
        message: displayText,
        isEncrypted: true,
        canDecrypt: true,
        timestamp: sentAtIso,
        protocolBadge: 'Encrypted',
        sendStatus: 'sending',
        localScope: scope,
        localFiles: files.length ? files : undefined,
        replyTo: replyRef,
      },
    ]);
    setInputMessage('');
    setPendingFiles([]);
    setReplyTarget(null);
    setTimeout(() => scrollToBottom(true), 20);

    const job = async () => {
      // Declared outside `try` so a failed send keeps the files that were already uploaded (for Retry).
      const attachments: EncryptedAttachmentKeyDescriptor[] = [];
      const attachmentIds: string[] = [];
      try {
        for (const file of files) {
          const fileBuf = new Uint8Array(await file.arrayBuffer());
          const encAtt = await encryptAttachmentOnDevice(fileBuf, {
            scopeType: channelType === 'dm' ? 'dm' : 'group',
            fileName: file.name,
            mimeType: file.type || 'application/octet-stream',
          });
          const uploaded = await uploadEncryptedAttachmentBlob({
            scope_type: channelType === 'dm' ? 'dm' : 'group',
            scope_id: targetId,
            uploader_device_id: localDeviceId,
            ciphertext_b64: encAtt.ciphertextB64,
            ciphertext_sha256: encAtt.ciphertextSha256Hex,
          });
          attachmentIds.push(uploaded.attachment.attachment_id);
          attachments.push({
            attachment_id: uploaded.attachment.attachment_id,
            key_b64: encAtt.ephemeralKeyB64,
            iv_b64: encAtt.ivB64,
            sha256_hex: encAtt.ciphertextSha256Hex,
            file_name: file.name,
            mime_type: file.type || 'application/octet-stream',
            size_bytes: encAtt.sizeBytes,
          });
        }

        const plainEnvelope: E2EEPlaintextEnvelope = {
          v: 1,
          text: displayText,
          attachments: attachments.length > 0 ? attachments : undefined,
          reply_to: replyRef,
          sent_at: sentAtIso,
          mentions: mentionIds.length ? mentionIds : undefined,
        };

        if (channelType === 'dm') {
          const [peerDevs, ownAccount] = await Promise.all([
            fetchPeerActiveDevices(targetId),
            fetchMyE2EEAccount(),
          ]);
          const targetDevices = [
            ...peerDevs.devices,
            ...ownAccount.devices.filter((d) => d.status === 'active'),
          ];

          if (!targetDevices || targetDevices.length === 0) {
            throw new Error('This member has not signed in to chats yet, so the message was not sent.');
          }

          const olmEncrypted = await encryptOlmMultiDevicePayload(
            myUserId,
            plainEnvelope,
            targetDevices,
            (uid, devIds) => claimPeerOlmPrekeyBundles(uid, devIds)
          );

          // Save our own readable copy first so the sender's view never races the server round trip.
          await saveVaultDecryptedMessage(myUserId, msgId, plainEnvelope);
          await submitOlmDmCiphertext({
            message_id: msgId,
            recipient_user_id: targetId,
            sender_device_id: olmEncrypted.senderDeviceId,
            protocol: OLM_PROTOCOL_ID,
            device_ciphertexts: olmEncrypted.deviceCiphertexts,
            attachment_ids: attachmentIds,
          });
        } else {
          const mlsEncrypted = await encryptMlsGroupMessage(myUserId, targetId, plainEnvelope);
          await saveVaultDecryptedMessage(myUserId, msgId, plainEnvelope);
          await submitServerMlsGroupMessage(targetId, {
            message_id: msgId,
            sender_device_id: localDeviceId,
            epoch: mlsEncrypted.epoch,
            mls_ciphertext_b64: mlsEncrypted.mlsCiphertextB64,
            attachment_ids: attachmentIds,
            mention_user_ids: mentionIds,
          });
        }

        setMessages((prev) =>
          prev.map((m) => (m.id === msgId ? { ...m, sendStatus: 'delivered' as const } : m))
        );
        // Incremental sync: fetches only what is new (including this message) - fast and non-blocking.
        void loadActiveChannelMessages();
      } catch (err: any) {
        console.warn('Encrypted transmission rejected or failed:', err);
        // Paid group whose subscription ended: open its payment window; the message stays with Retry.
        const paymentNeeded = isGroupPaymentRequired(err);
        if (paymentNeeded && onOpenPaidGroupModal) {
          onOpenPaidGroupModal(err.detail.group_id, err.detail.group_name);
        }
        const isKeyError =
          !paymentNeeded &&
          (err?.message?.toLowerCase().includes('key') ||
            err?.message?.toLowerCase().includes('device') ||
            err?.message?.toLowerCase().includes('epoch'));
        const safeError = paymentNeeded
          ? 'Your access to this group has ended. Renew it, then press Retry.'
          : err?.detail?.code === 'admins_only'
            ? 'Only admins can send messages in this group.'
            : isKeyError
              ? 'The message could not be sent securely right now. Please try again in a moment.'
              : (friendlyError(err, 'Message was not sent (server rejected or database failed)'));
        const allFilesUploaded = attachments.length === files.length;
        const fileNote =
          files.length > 0 && !allFilesUploaded ? ' The files were not sent: attach them again.' : '';

        const failedEntry: RichDisplayMessage = {
          id: `failed_${Date.now()}`,
          channel: channelType,
          sender: myUserId,
          recipient: channelType === 'dm' ? targetId : undefined,
          message: displayText,
          timestamp: new Date().toISOString(),
          isEncrypted: true,
          canDecrypt: true,
          sendStatus: 'failed',
          sendError: safeError + fileNote,
          canRetry: !isKeyError && (allFilesUploaded || Boolean(text)),
          localScope: scope,
          attachments: allFilesUploaded && attachments.length ? attachments : undefined,
          replyTo: replyRef,
          failedPayload: {
            channelType,
            targetId,
            msgId: `emsg_${Date.now()}`,
            plainEnvelope: {
              v: 1,
              text: text || '',
              attachments: allFilesUploaded && attachments.length ? attachments : undefined,
              reply_to: replyRef,
              sent_at: new Date().toISOString(),
              mentions: mentionIds.length ? mentionIds : undefined,
            },
            createdAt: Date.now(),
            attachmentIds: allFilesUploaded ? attachmentIds : [],
            mentionIds,
          },
        };
        // Replace the optimistic bubble with the failed one (which offers Retry).
        setMessages((prev) => [...prev.filter((m) => m.id !== msgId), failedEntry]);
        setTimeout(() => scrollToBottom(true), 20);
      }
    };
    // Run sends strictly one after another (ratchet safety) without ever blocking the UI.
    sendQueueRef.current = sendQueueRef.current.then(job, job);
  };

  const handleRetryFailedMessage = async (failedMsg: RichDisplayMessage) => {
    if (!failedMsg.failedPayload || sending) return;
    const { channelType, targetId, plainEnvelope, createdAt } = failedMsg.failedPayload;
    const retryAttachmentIds = failedMsg.failedPayload.attachmentIds || [];
    // Mentions must survive a retry (older failed entries only have them inside the envelope).
    const retryMentionIds = failedMsg.failedPayload.mentionIds ?? plainEnvelope.mentions ?? [];
    setSending(true);
    try {
      const isFresh = Date.now() - createdAt < 300000; // 5 min freshness
      const retryMsgId = `emsg_${crypto.randomUUID().replace(/-/g, '')}`;

      if (channelType === 'dm') {
        const [peerDevs, ownAccount] = await Promise.all([
          fetchPeerActiveDevices(targetId),
          fetchMyE2EEAccount(),
        ]);
        const targetDevices = [
          ...peerDevs.devices,
          ...ownAccount.devices.filter((d) => d.status === 'active'),
        ];
        if (!targetDevices || targetDevices.length === 0) {
          throw new Error('This member has not signed in to chats yet, so the message was not sent.');
        }
        const freshPlain = isFresh ? plainEnvelope : { ...plainEnvelope, sent_at: new Date().toISOString() };
        const olmEncrypted = await encryptOlmMultiDevicePayload(
          e2eeProfile!.user_id,
          freshPlain,
          targetDevices,
          (uid, devIds) => claimPeerOlmPrekeyBundles(uid, devIds)
        );
        await submitOlmDmCiphertext({
          message_id: retryMsgId,
          recipient_user_id: targetId,
          sender_device_id: olmEncrypted.senderDeviceId,
          protocol: OLM_PROTOCOL_ID,
          device_ciphertexts: olmEncrypted.deviceCiphertexts,
          attachment_ids: retryAttachmentIds,
        });
        await saveVaultDecryptedMessage(e2eeProfile!.user_id, retryMsgId, freshPlain);
      } else {
        const freshPlain = isFresh ? plainEnvelope : { ...plainEnvelope, sent_at: new Date().toISOString() };
        const mlsEncrypted = await encryptMlsGroupMessage(
          e2eeProfile!.user_id,
          targetId,
          freshPlain
        );
        await submitServerMlsGroupMessage(targetId, {
          message_id: retryMsgId,
          sender_device_id: localDeviceId!,
          epoch: mlsEncrypted.epoch,
          mls_ciphertext_b64: mlsEncrypted.mlsCiphertextB64,
          attachment_ids: retryAttachmentIds,
          mention_user_ids: retryMentionIds,
        });
        await saveVaultDecryptedMessage(e2eeProfile!.user_id, retryMsgId, freshPlain);
      }

      // Success! Clear failed message from state and reload active channel
      setMessages((prev) => prev.filter((m) => m.id !== failedMsg.id));
      await loadActiveChannelMessages();
      scrollToBottom(true);
    } catch (retryErr: any) {
      console.warn('Retry failed:', retryErr);
      setMessages((prev) =>
        prev.map((m) =>
          m.id === failedMsg.id
            ? { ...m, sendStatus: 'failed', sendError: retryErr?.message || 'Retry failed: message was not sent' }
            : m
        )
      );
    } finally {
      setSending(false);
    }
  };

  /** Downloads and decrypts one encrypted file on this device (used by image previews and downloads). */
  const loadDecryptedAttachment = async (
    att: EncryptedAttachmentKeyDescriptor,
    scopeType: 'dm' | 'group'
  ): Promise<Blob> => {
    try {
      const blobRes = await downloadEncryptedAttachmentBlob(att.attachment_id);
      const decryptedBytes = await decryptAttachmentOnDevice(blobRes.attachment.ciphertext_b64, att, scopeType);
      const copyBuf = new Uint8Array(decryptedBytes.byteLength);
      copyBuf.set(decryptedBytes);
      return new Blob([copyBuf.buffer], { type: att.mime_type || 'application/octet-stream' });
    } catch (err: any) {
      if (err?.status === 410) {
        setRevokedAttachmentIds((prev) => new Set(prev).add(att.attachment_id));
      }
      throw err;
    }
  };

  /** The sender removes a file they sent. The message stays; the file can no longer be downloaded. */
  const handleRevokeAttachment = async (att: EncryptedAttachmentKeyDescriptor) => {
    if (!confirm(`Remove "${att.file_name}"? Nobody will be able to download it any more.`)) return;
    try {
      await revokeEncryptedAttachment(att.attachment_id);
      setRevokedAttachmentIds((prev) => new Set(prev).add(att.attachment_id));
    } catch (err: any) {
      if (err?.status === 404 || err?.status === 410) {
        setRevokedAttachmentIds((prev) => new Set(prev).add(att.attachment_id));
      } else {
        alert(friendlyError(err, 'Could not remove the file.'));
      }
    }
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="chat-console-grid">
      {/* Mobile Drawer Backdrop */}
      {mobileRailOpen && (
        <div
          className="mobile-rail-backdrop"
          onClick={() => setMobileRailOpen(false)}
          aria-label="Close Channels Menu"
        />
      )}

      {/* Left Rail: Open Chat + "+Add" (Create Group | Chat Individual) + Unified Conversations */}
      <div className={`chat-channels-rail ${mobileRailOpen ? 'mobile-open' : ''}`}>
        <div
          className="chat-channels-header"
          style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
        >
          <span>Conversations</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <button
              type="button"
              className="mobile-rail-close-btn"
              onClick={() => setMobileRailOpen(false)}
              title="Close Channels"
              aria-label="Close Channels"
            >
              <X size={16} />
            </button>
          </div>
        </div>

        {/* Primary Channel Controls: Open Chat + "+Add" */}
        <div style={{ padding: '8px 0 10px', borderBottom: '1px solid var(--border-subtle)' }}>
          <button
            type="button"
            className={`channel-btn ${activeTab === 'open_chat' ? 'active' : ''}`}
            onClick={() => handleSelectChannelTab('open_chat')}
          >
            <Globe size={18} />
            <span>Members&rsquo; room</span>
          </button>

          {account && (
            <div className="channel-add-wrapper" ref={addMenuRef}>
              <button
                type="button"
                className={`channel-add-btn ${addMenuOpen ? 'open' : ''}`}
                onClick={() => setAddMenuOpen((prev) => !prev)}
                aria-expanded={addMenuOpen}
                aria-haspopup="menu"
              >
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
                  <Plus size={16} />
                  <span>Start a conversation</span>
                </span>
                <ChevronDown
                  size={14}
                  style={{
                    transform: addMenuOpen ? 'rotate(180deg)' : 'none',
                    transition: 'transform 0.16s ease',
                  }}
                />
              </button>

              {addMenuOpen && (
                <div className="channel-add-menu" role="menu">
                  <button
                    type="button"
                    role="menuitem"
                    className="channel-add-option"
                    onClick={() => {
                      setAddMenuOpen(false);
                      setCreateGroupError(null);
                      setCreateGroupModalOpen(true);
                    }}
                  >
                    <Users size={18} />
                    <div>
                      <div>New group</div>
                      <div style={{ fontSize: '0.9rem', fontWeight: 400, color: 'var(--text-muted)' }}>
                        Name a group and invite members
                      </div>
                    </div>
                  </button>

                  <button
                    type="button"
                    role="menuitem"
                    className="channel-add-option"
                    onClick={() => {
                      setAddMenuOpen(false);
                      setChatIndividualError(null);
                      setChatIndividualModalOpen(true);
                    }}
                  >
                    <UserPlus size={18} />
                    <div>
                      <div>New private chat</div>
                      <div style={{ fontSize: '0.9rem', fontWeight: 400, color: 'var(--text-muted)' }}>
                        Message one member, end-to-end encrypted
                      </div>
                    </div>
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Unified Scrollable Conversations List */}
        <div className="rail-conv-scroll">
          {isWalletMismatch && account && (
            <div
              style={{
                padding: '10px 12px',
                borderRadius: '10px',
                background: 'var(--bg-card)',
                border: '1px solid var(--border-focus)',
                fontSize: '0.9rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px',
              }}
            >
              <div style={{ color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                MetaMask switched to <code>{formatAddress(account, 4)}</code>. Sign in again to keep
                chatting, or add this wallet under <strong>Settings &gt; Privacy &gt; Account and devices</strong>.
              </div>
              <button
                type="button"
                className="btn-solid"
                style={{ padding: '6px 10px', fontSize: '0.9rem', justifyContent: 'center' }}
                disabled={siweLoading || authLoading}
                onClick={onAuthenticateSiwe || authenticateE2EESession}
              >
                <KeyRound size={12} />
                <span>
                  {siweLoading || authLoading
                    ? 'Signing...'
                    : `Switch to ${formatAddress(account, 4)}`}
                </span>
              </button>
            </div>
          )}

          {e2eeProfile && !isWalletMismatch && (
            <>
              {/* Encrypted Groups Section */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <div className="rail-section-label">
                  <span>Groups{groups.length > 0 ? ` (${groups.length})` : ''}</span>
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedGroup(null);
                      handleSelectChannelTab('groups');
                    }}
                    style={{
                      background: 'transparent',
                      border: 'none',
                      color: 'var(--accent-strong)',
                      fontSize: '0.86rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                      padding: 0,
                      textTransform: 'none',
                    }}
                    title="Browse public groups"
                  >
                    Join or browse
                  </button>
                </div>

                {groupInvitations.length > 0 && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }} aria-label="Group invitations">
                    {groupInvitations.map((inv) => (
                      <div
                        key={inv.group_id}
                        style={{
                          padding: '10px 12px',
                          borderRadius: '12px',
                          border: '1px solid var(--border-focus)',
                          background: 'var(--bg-card)',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '8px',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                          <Users size={14} style={{ flexShrink: 0, color: 'var(--accent)' }} />
                          <strong
                            style={{
                              fontSize: '0.92rem',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {inv.group_name}
                          </strong>
                        </div>
                        <div style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                          {inv.invited_by_username ? `@${inv.invited_by_username} added you` : 'You were added'}
                          {` · ${inv.member_count} ${inv.member_count === 1 ? 'member' : 'members'}`}
                          {inv.is_paid ? ' · Paid group' : ''}
                        </div>
                        <div style={{ display: 'flex', gap: '6px' }}>
                          <button
                            type="button"
                            className="btn-solid"
                            style={{ flex: 1, justifyContent: 'center', padding: '6px 10px', fontSize: '0.88rem' }}
                            disabled={invitationBusyId !== null}
                            onClick={() => handleAcceptGroupInvitation(inv.group_id, inv.group_name)}
                          >
                            <Check size={13} />
                            <span>{invitationBusyId === inv.group_id ? 'Joining...' : 'Accept'}</span>
                          </button>
                          <button
                            type="button"
                            className="btn-outline"
                            style={{ flex: 1, justifyContent: 'center', padding: '6px 10px', fontSize: '0.88rem' }}
                            disabled={invitationBusyId !== null}
                            onClick={() => handleDeclineGroupInvitation(inv.group_id)}
                          >
                            <X size={13} />
                            <span>Reject</span>
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
                {invitationNotice && (
                  <div role="status" style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', padding: '2px 10px' }}>
                    {invitationNotice}
                  </div>
                )}

                {isVaultReadyForProfile && e2eeProfile && sidebarLoadedUserId !== e2eeProfile.user_id && groups.length === 0 ? (
                  <SidebarListSkeleton count={3} />
                ) : groups.length === 0 && groupInvitations.length > 0 ? null : groups.length === 0 ? (
                  <div
                    style={{
                      fontSize: '0.9rem',
                      lineHeight: 1.5,
                      color: 'var(--text-muted)',
                      padding: '4px 10px 2px',
                    }}
                  >
                    You are not in any groups yet. Choose <strong>Start a conversation</strong> to create one.
                  </div>
                ) : (
                  groups
                    .filter(
                      (g) =>
                        showArchived ||
                        !convPrefs[`group:${g.group_id}`]?.archived ||
                        (activeTab === 'groups' && selectedGroup?.group_id === g.group_id)
                    )
                    .map((g) => {
                      const isGroupActive =
                        activeTab === 'groups' && selectedGroup?.group_id === g.group_id;
                      return (
                        <button
                          key={g.group_id}
                          type="button"
                          className={`rail-conv-item ${isGroupActive ? 'active' : ''}`}
                          onClick={() => {
                            setSelectedGroup(g);
                            handleSelectChannelTab('groups');
                          }}
                        >
                          <span
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '7px',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            <Users size={13} style={{ flexShrink: 0 }} />
                            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
                              {g.name}
                            </span>
                            {convPrefs[`group:${g.group_id}`]?.muted && <BellOff size={12} aria-label="Muted" style={{ flexShrink: 0, opacity: 0.6 }} />}
                            {convPrefs[`group:${g.group_id}`]?.archived && <Archive size={12} aria-label="Archived" style={{ flexShrink: 0, opacity: 0.6 }} />}
                          </span>
                          {(notifications.unread[`group:${g.group_id}`] || 0) > 0 && !isGroupActive && (
                            <span className="rail-unread" aria-label={`${notifications.unread[`group:${g.group_id}`]} unread`}>
                              {notifications.unread[`group:${g.group_id}`] > 99 ? '99+' : notifications.unread[`group:${g.group_id}`]}
                            </span>
                          )}
                        </button>
                      );
                    })
                )}
              </div>

              {/* Archived chats are hidden from the lists until shown */}
              {Object.entries(convPrefs).some(([k, p]) => p.archived && k !== 'room') && (
                <button
                  type="button"
                  className="rail-conv-item"
                  aria-pressed={showArchived}
                  onClick={() => setShowArchived((v) => !v)}
                  style={{ color: 'var(--text-secondary)' }}
                >
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7 }}>
                    <Archive size={13} />
                    {showArchived
                      ? 'Hide archived chats'
                      : `Archived chats (${Object.entries(convPrefs).filter(([k, p]) => p.archived && k !== 'room').length})`}
                  </span>
                </button>
              )}

              {/* Individual 1-to-1 Chats Section */}
              {(() => {
                const combinedPeers: Array<{
                  user_id: string;
                  username: string | null;
                  primary_wallet: string | null;
                }> = [];
                for (const op of openedPeers) {
                  if (!combinedPeers.some((x) => x.user_id === op.user_id)) {
                    combinedPeers.push({
                      user_id: op.user_id,
                      username: op.username,
                      primary_wallet: op.primary_wallet,
                    });
                  }
                }
                for (const c of dmConversations) {
                  if (!combinedPeers.some((x) => x.user_id === c.peer_user_id)) {
                    combinedPeers.push({
                      user_id: c.peer_user_id,
                      username: c.peer_username,
                      primary_wallet: c.peer_primary_wallet,
                    });
                  }
                }

                return (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <div className="rail-section-label">
                      <span>Private chats{combinedPeers.length > 0 ? ` (${combinedPeers.length})` : ''}</span>
                      <button
                        type="button"
                        onClick={() => {
                          setMobileRailOpen(false);
                          setChatIndividualError(null);
                          setChatIndividualModalOpen(true);
                        }}
                        style={{
                          background: 'transparent',
                          border: 'none',
                          color: 'var(--accent-strong)',
                          fontSize: '0.86rem',
                          fontWeight: 600,
                          cursor: 'pointer',
                          padding: 0,
                          textTransform: 'none',
                        }}
                        title="Search members by @username"
                      >
                        Find a member
                      </button>
                    </div>

                    {isVaultReadyForProfile && e2eeProfile && sidebarLoadedUserId !== e2eeProfile.user_id && combinedPeers.length === 0 ? (
                      <SidebarListSkeleton count={3} />
                    ) : combinedPeers.length === 0 ? (
                      <div
                        style={{
                          fontSize: '0.9rem',
                          lineHeight: 1.5,
                          color: 'var(--text-muted)',
                          padding: '4px 10px 2px',
                        }}
                      >
                        No private chats yet. Choose <strong>Start a conversation</strong> to message a member.
                      </div>
                    ) : (
                      combinedPeers
                        .filter(
                          (p) =>
                            showArchived ||
                            !convPrefs[`dm:${p.user_id}`]?.archived ||
                            (activeTab === 'dm' && selectedPeer?.user_id === p.user_id)
                        )
                        .map((peerItem) => {
                          const isPeerActive =
                            activeTab === 'dm' && selectedPeer?.user_id === peerItem.user_id;
                          const label = peerItem.username
                            ? `@${peerItem.username}`
                            : peerItem.primary_wallet
                              ? formatAddress(peerItem.primary_wallet, 4)
                              : peerItem.user_id.slice(0, 12);
                          return (
                            <button
                              key={peerItem.user_id}
                              type="button"
                              className={`rail-conv-item ${isPeerActive ? 'active' : ''}`}
                              onClick={() => {
                                setMobileRailOpen(false);
                                const cachedPeer =
                                  resolvedPeerCacheRef.current[peerItem.user_id]?.peer ||
                                  openedPeers.find((p) => p.user_id === peerItem.user_id) || {
                                    user_id: peerItem.user_id,
                                    username: peerItem.username,
                                    primary_wallet: peerItem.primary_wallet,
                                    identity_version: 0,
                                    devices: [],
                                  };
                                setSelectedPeer(cachedPeer);
                                handleSelectChannelTab('dm');

                                const cachedMeta = resolvedPeerCacheRef.current[peerItem.user_id];
                                if (!cachedMeta || cachedMeta.peer.devices.length === 0 || Date.now() - cachedMeta.at > 30000) {
                                  resolveE2EEPeer(peerItem.user_id)
                                    .then((freshPeer) => {
                                      registerOpenedPeer(freshPeer);
                                      setSelectedPeer((cur) =>
                                        cur?.user_id === freshPeer.user_id ? freshPeer : cur
                                      );
                                    })
                                    .catch(() => {
                                      // keep cached peer if offline
                                    });
                                }
                              }}
                            >
                              <span
                                style={{
                                  fontFamily: 'ui-monospace, monospace',
                                  overflow: 'hidden',
                                  textOverflow: 'ellipsis',
                                  whiteSpace: 'nowrap',
                                }}
                              >
                                {label}
                              </span>
                              {(notifications.unread[`dm:${peerItem.user_id}`] || 0) > 0 && !isPeerActive ? (
                                <span className="rail-unread" aria-label={`${notifications.unread[`dm:${peerItem.user_id}`]} unread`}>
                                  {notifications.unread[`dm:${peerItem.user_id}`] > 99 ? '99+' : notifications.unread[`dm:${peerItem.user_id}`]}
                                </span>
                              ) : (
                                <Lock size={11} style={{ flexShrink: 0 }} />
                              )}
                            </button>
                          );
                        })
                    )}
                  </div>
                );
              })()}
            </>
          )}

        </div>
      </div>

      {/* Main Conversation Viewport */}
      {activeTab === 'open_chat' ? (
        <OpenPublicChatView
          embedded
          account={account}
          e2eeProfile={e2eeProfile}
          siweLoading={Boolean(siweLoading || authLoading)}
          onConnectWallet={onConnectWallet}
          onAuthenticateSiwe={onAuthenticateSiwe || authenticateE2EESession}
          onStartPrivateChat={(identifier) => {
            if (isVaultReadyForProfile) {
              handleSelectPeerFromDirectory(identifier);
            } else if (onStartPrivateChat) {
              onStartPrivateChat(identifier);
            } else {
              setIndividualIdInput(identifier);
              setChatIndividualError(null);
              setChatIndividualModalOpen(true);
            }
          }}
          onToggleChannels={() => setMobileRailOpen((prev) => !prev)}
          isPlatformPaid={isPlatformPaid}
          onOpenAdmissionModal={onOpenAdmissionModal}
        />
      ) : (
        <div className="chat-viewport">
          {/* Stage Header */}
          <div className="chat-stage-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0, flex: 1 }}>
              <button
                type="button"
                className="mobile-channels-toggle-btn"
                onClick={() => setMobileRailOpen((prev) => !prev)}
                title="Chats Menu"
                aria-label="Chats Menu"
              >
                <Menu size={16} />
                <span>Conversations</span>
              </button>
              <div style={{ minWidth: 0, flex: 1 }}>
                <div
                  style={{
                    fontWeight: 600,
                    fontSize: '0.96rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    flexWrap: 'wrap',
                  }}
                >
                  {activeTab === 'dm' && (
                    <>
                      <span>
                        {selectedPeer
                          ? selectedPeer.username
                            ? `@${selectedPeer.username}`
                            : selectedPeer.primary_wallet
                              ? formatAddress(selectedPeer.primary_wallet, 6)
                              : selectedPeer.user_id
                          : 'Find a member'}
                      </span>
                      {selectedPeer && (
                        <span className="audit-status">
                          Private chat
                        </span>
                      )}
                    </>
                  )}
                  {activeTab === 'groups' && (
                    <>
                      <span>{selectedGroup ? selectedGroup.name : 'Groups'}</span>
                      {selectedGroup && (
                        <span className="audit-status">
                          {selectedGroup.policy?.is_paid
                            ? `Paid group: ${formatGroupFee(selectedGroup.policy)}`
                            : 'Free group'}
                        </span>
                      )}
                    </>
                  )}
                </div>
                <div style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>
                  {activeTab === 'dm' &&
                    (selectedPeer
                      ? 'End-to-end encrypted. Only you and this member can read these messages.'
                      : 'Enter a member’s @username, user ID, or wallet to start a private chat')}
                  {activeTab === 'groups' &&
                    (selectedGroup
                      ? 'End-to-end encrypted group. New members cannot read earlier messages.'
                      : 'Browse public groups')}
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '6px', alignItems: 'center', justifyContent: 'flex-end', flexWrap: 'wrap', flexShrink: 0, marginLeft: 'auto' }}>
              {activeTab === 'dm' && selectedPeer && e2eeProfile && (
                <>
                  <button
                    type="button"
                    className="btn-outline"
                    style={{ padding: '6px 10px', fontSize: '0.9rem' }}
                    title="Block User"
                    onClick={async () => {
                      if (!confirm(`Block ${selectedPeer.username || selectedPeer.user_id}?`)) return;
                      try {
                        await blockUser(selectedPeer.user_id, 'Blocked from Private Chat');
                        alert('User blocked. Server will reject new messages from this user.');
                      } catch (err: any) {
                        alert(friendlyError(err, 'Block failed'));
                      }
                    }}
                  >
                    <Ban size={13} />
                  </button>
                  <button
                    type="button"
                    className="btn-outline"
                    style={{ padding: '6px 10px', fontSize: '0.9rem' }}
                    title="Report Abuse"
                    onClick={async () => {
                      const reason = prompt('Report reason (spam, impersonation, harassment):');
                      if (!reason || !reason.trim()) return;
                      try {
                        await submitAbuseReport({
                          scope_type: 'dm',
                          scope_id: selectedPeer.user_id,
                          target_user_id: selectedPeer.user_id,
                          reason: reason.trim(),
                        });
                        alert('Moderation report submitted.');
                      } catch (err: any) {
                        alert(friendlyError(err, 'Report failed'));
                      }
                    }}
                  >
                    <Flag size={13} />
                  </button>
                </>
              )}

              {activeTab === 'groups' && selectedGroup && e2eeProfile && (
                <button
                  type="button"
                  className="btn-outline"
                  style={{ padding: '6px 12px', fontSize: '0.86rem' }}
                  onClick={() => setGroupModalOpen(true)}
                >
                  <ShieldCheck size={14} />
                  <span>Group settings</span>
                </button>
              )}

              {account && !needsE2EEAuth && ((activeTab === 'dm' && selectedPeer) || (activeTab === 'groups' && selectedGroup)) && (
                <>
                  <ChatSearchBar
                    open={searchOpen}
                    onOpen={() => {
                      setSearchOpen(true);
                      setSearchQuery('');
                    }}
                    query={searchQuery}
                    onQuery={setSearchQuery}
                    count={searchHits.length}
                    index={searchIndex}
                    onStep={stepSearch}
                    onClose={() => {
                      setSearchOpen(false);
                      setSearchQuery('');
                    }}
                  />
                  <ConversationMenu
                    kind={activeTab === 'dm' ? 'dm' : 'group'}
                    muted={Boolean(currentPref?.muted)}
                    mutedForever={currentPref?.muted_forever}
                    mutedUntil={currentPref?.muted_until}
                    archived={currentPref?.archived}
                    timer={convState?.disappearing_ttl || 0}
                    adminsOnly={adminsOnlyHere}
                    canManage={Boolean(convState?.can_manage)}
                    onMute={(choice) => void updatePref({ mute: choice })}
                    onArchive={(archived) => void updatePref({ archived })}
                    onTimer={(ttl) => void changeTimer(ttl)}
                    onAdminsOnly={(v) => void changeAdminsOnly(v)}
                    onSearch={() => setSearchOpen(true)}
                    onPoll={activeTab === 'groups' && (!adminsOnlyHere || isGroupAdminHere) ? () => setPollOpen(true) : undefined}
                  />
                </>
              )}
            </div>
          </div>


          {/* Viewport Content Case 1: Private Chats Prompt View */}
          {activeTab === 'dm' && !selectedPeer && (
            <div
              style={{
                flex: 1,
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                padding: '24px',
                textAlign: 'center',
                gap: '12px',
              }}
            >
              <Lock size={34} style={{ color: 'var(--accent)' }} />
              <div style={{ fontSize: '1.15rem', fontWeight: 600 }}>Start a private chat</div>
              <div style={{ fontSize: '0.92rem', color: 'var(--text-secondary)', maxWidth: '380px' }}>
                Enter a member&rsquo;s <code>@username</code>, user ID, or wallet address to start an end-to-end encrypted conversation.
              </div>
              <button
                type="button"
                className="btn-solid"
                onClick={() => {
                  setChatIndividualError(null);
                  setChatIndividualModalOpen(true);
                }}
              >
                <UserPlus size={16} />
                <span>Message a member</span>
              </button>
            </div>
          )}

          {/* Viewport Content Case 2: Encrypted Groups Public Discovery & Invites View */}
          {activeTab === 'groups' && !selectedGroup && (
            <div
              style={{
                flex: 1,
                overflowY: 'auto',
                padding: '24px',
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
                gap: '20px',
                maxWidth: '1100px',
                width: '100%',
                margin: '0 auto',
                alignContent: 'start',
              }}
            >
              {/* Left Card: how joining works (invite links were removed) */}
              <div className="deck-card" style={{ padding: '20px' }}>
                <div className="deck-title" style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                  <UserPlus size={18} />
                  <span>How joining works</span>
                </div>
                <p style={{ fontSize: '0.95rem', color: 'var(--text-secondary)', lineHeight: 1.55, margin: '0 0 10px 0' }}>
                  A group admin adds you, and the group appears under <strong>Invitations</strong> for you to
                  Accept or Reject. Nothing joins you without your Accept.
                </p>
                <p style={{ fontSize: '0.95rem', color: 'var(--text-secondary)', lineHeight: 1.55, margin: 0 }}>
                  Public groups are listed here: send a join request and an admin of the group adds you.
                </p>
              </div>

              {/* Right Card: Discoverable Public Groups */}
              <div className="deck-card" style={{ padding: '20px' }}>
                {inviteStatusMsg && (
                  <div role="status" style={{ fontSize: '0.92rem', marginBottom: 12, padding: '10px 12px', borderRadius: 10, background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)' }}>
                    {inviteStatusMsg}
                  </div>
                )}
                <div className="deck-header" style={{ marginBottom: '16px' }}>
                  <div>
                    <div
                      className="deck-title"
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        fontSize: '1.05rem',
                        fontWeight: 600,
                      }}
                    >
                      <Users size={18} />
                      <span>Discoverable Public Groups</span>
                    </div>
                    <div
                      className="deck-subtitle"
                      style={{ fontSize: '0.9rem', color: 'var(--text-muted)', marginTop: '4px' }}
                    >
                      Browse public groups or request entry when your wallet meets
                      requirements.
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {groupsLoading && discoverableGroups.length === 0 ? (
                    <ListRowsSkeleton count={3} showButton />
                  ) : discoverableGroups.length === 0 ? (
                    <div
                      style={{
                        fontSize: '0.9rem',
                        color: 'var(--text-muted)',
                        padding: '24px 0',
                        textAlign: 'center',
                      }}
                    >
                      No public groups listed yet. Create one in the sidebar!
                    </div>
                  ) : (
                    discoverableGroups.map((g) => (
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
                          flexWrap: 'wrap',
                        }}
                      >
                        <div>
                          <div style={{ fontWeight: 600, fontSize: '0.88rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span>{g.name}</span>
                            {g.is_paid && (
                              <span
                                style={{
                                  fontSize: '0.86rem',
                                  fontWeight: 700,
                                  padding: '1px 6px',
                                  borderRadius: '4px',
                                  backgroundColor: 'rgba(234, 179, 8, 0.15)',
                                  color: 'var(--accent)',
                                  border: '1px solid rgba(234, 179, 8, 0.3)',
                                }}
                              >
                                PAID &bull; {formatGroupFee(g)}
                              </span>
                            )}
                          </div>
                          <div
                            style={{
                              fontSize: '0.9rem',
                              color: 'var(--text-secondary)',
                              marginTop: '2px',
                            }}
                          >
                            {g.is_paid ? (
                              <>
                                Paid Group &bull; <strong>{formatGroupFee(g)}</strong> &bull;{' '}
                                {g.active_member_count} members
                              </>
                            ) : (
                              <>Free Group &bull; {g.active_member_count} members</>
                            )}
                          </div>
                          {g.description && (
                            <div
                              style={{
                                fontSize: '0.9rem',
                                color: 'var(--text-muted)',
                                marginTop: '3px',
                              }}
                            >
                              {g.description}
                            </div>
                          )}
                        </div>

                        {g.is_member ? (
                          <button
                            type="button"
                            className="btn-outline"
                            style={{ padding: '6px 14px', fontSize: '0.86rem' }}
                            onClick={() => handleOpenDiscoverableGroup(g)}
                          >
                            Open Group
                          </button>
                        ) : g.is_paid && !g.has_paid ? (
                          <button
                            type="button"
                            className="btn-solid"
                            style={{
                              padding: '6px 14px',
                              fontSize: '0.86rem',
                              backgroundColor: 'var(--accent)',
                              color: '#000000',
                              fontWeight: 600,
                            }}
                            onClick={() => {
                              if (onOpenPaidGroupModal) {
                                onOpenPaidGroupModal(g.group_id, g.name);
                              }
                            }}
                          >
                            Pay &amp; Join Group
                          </button>
                        ) : (
                          <button
                            type="button"
                            className="btn-solid"
                            style={{ padding: '6px 14px', fontSize: '0.86rem' }}
                            onClick={() => handleRequestJoinGroup(g)}
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
          )}

          {/* Viewport Content Case 3: Active Conversation Selected */}
          {((activeTab === 'dm' && selectedPeer) || (activeTab === 'groups' && selectedGroup)) && (
            !account ? (
              <div className="chat-locked-enclave">
                <div className="chat-locked-shield">
                  <Lock size={32} />
                </div>
                <h3 style={{ fontSize: '1.15rem', fontWeight: 700, margin: '0 0 8px 0' }}>
                  End-to-End Encrypted Enclave Locked
                </h3>
                <p
                  style={{
                    color: 'var(--text-muted)',
                    fontSize: '0.9rem',
                    maxWidth: '410px',
                    lineHeight: 1.5,
                    margin: '0 0 20px 0',
                  }}
                >
                  Connect MetaMask to verify wallet ownership via EIP-4361 (SIWE). Encryption keys are
                  generated purely on-device inside an AES-256-GCM IndexedDB vault—never derived from
                  your wallet.
                </p>
                <button
                  className="btn-solid"
                  onClick={onConnectWallet}
                  style={{ padding: '10px 20px', fontSize: '0.86rem' }}
                >
                  <Wallet size={15} />
                  <span>Connect MetaMask</span>
                </button>
              </div>
            ) : needsE2EEAuth ? (
              <div className="chat-locked-enclave">
                <div className="chat-locked-shield">
                  <KeyRound size={32} />
                </div>
                <h3 style={{ fontSize: '1.15rem', fontWeight: 700, margin: '0 0 8px 0' }}>
                  Sign in to see your messages
                </h3>
                <p
                  style={{
                    color: 'var(--text-muted)',
                    fontSize: '0.9rem',
                    maxWidth: '420px',
                    lineHeight: 1.5,
                    margin: '0 0 16px 0',
                  }}
                >
                  Approve the sign-in request in MetaMask. It is free and does not send any
                  payment.
                </p>
                {authError && (
                  <div
                    style={{
                      fontSize: '0.86rem',
                      marginBottom: '12px',
                      color: 'var(--text-secondary)',
                    }}
                  >
                    {authError}
                  </div>
                )}
                <button
                  className="btn-solid"
                  disabled={siweLoading || authLoading}
                  onClick={onAuthenticateSiwe || authenticateE2EESession}
                  style={{ padding: '10px 20px', fontSize: '0.86rem' }}
                >
                  <ShieldCheck size={15} />
                  <span>
                    {siweLoading || authLoading
                      ? 'Signing in...'
                      : 'Sign in with MetaMask'}
                  </span>
                </button>
              </div>
            ) : (
              <>
                {/* Chat status chips, pinned messages, and notices (shown only when active) */}
                {(activeTab === 'dm' ? selectedPeer : selectedGroup) &&
                  (Boolean(convState?.disappearing_ttl) ||
                    adminsOnlyHere ||
                    Boolean(currentPref?.muted) ||
                    Boolean(convState && convState.pins.length > 0) ||
                    Boolean(featureNotice)) && (
                    <div className="chat-extras-bar">
                      {(Boolean(convState?.disappearing_ttl) || adminsOnlyHere || Boolean(currentPref?.muted)) && (
                        <div className="chat-extras-row">
                          <ChatStatusChips timer={convState?.disappearing_ttl} adminsOnly={adminsOnlyHere} muted={Boolean(currentPref?.muted)} />
                        </div>
                      )}
                      {convState && convState.pins.length > 0 && (
                        <PinnedBar
                          pins={convState.pins}
                          previewFor={(id) => {
                            const m = displayMessages.find((x) => x.id === id);
                            if (!m) return null;
                            if (m.deleted) return 'Deleted message';
                            return m.poll ? `Poll: ${m.poll.question}` : m.message || 'Message';
                          }}
                          onJump={(id) => {
                            if (!jumpToMessage(id)) setFeatureNotice('That pinned message is not loaded on this device.');
                          }}
                          onUnpin={convState.can_manage ? (id) => void togglePin(id, false) : undefined}
                        />
                      )}
                      {featureNotice && (
                        <div className="chat-extras-row" role="alert">
                          <span className="chat-chip" style={{ whiteSpace: 'normal' }}>{featureNotice}</span>
                          <button type="button" className="chat-icon-btn" aria-label="Dismiss" onClick={() => setFeatureNotice(null)}>
                            <X size={13} />
                          </button>
                        </div>
                      )}
                    </div>
                  )}

                {/* Message Stream */}
                <div className="chat-stream-body" ref={chatBodyRef}>
                  {searchHits.length > 0 && (
                    <style>
                      {searchHits
                        .map(
                          (id, i) =>
                            `.ig-row[data-msg-id="${CSS.escape(id)}"] .ig-bubble{outline:2px solid ${i === searchIndex ? 'var(--accent)' : 'var(--warn)'};outline-offset:1px}`
                        )
                        .join('\n')}
                    </style>
                  )}
                  {(() => {
                    const activeScopeKey =
                      activeTab === 'dm' && selectedPeer
                        ? `dm|${selectedPeer.user_id}`
                        : activeTab === 'groups' && selectedGroup
                          ? `groups|${selectedGroup.group_id}`
                          : null;
                    return Boolean(activeScopeKey && loadedScopeKey !== activeScopeKey && messages.length === 0);
                  })() ? (
                    <ChatMessagesSkeleton count={5} />
                  ) : displayMessages.length === 0 ? (
                    <div
                      style={{
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: 'center',
                        justifyContent: 'center',
                        height: '100%',
                        color: 'var(--text-muted)',
                        textAlign: 'center',
                        gap: '12px',
                      }}
                    >
                      <MessageSquare size={36} strokeWidth={1.5} />
                      <div style={{ fontFamily: 'var(--font-display)', fontSize: '1.4rem', color: 'var(--text-secondary)' }}>
                        No messages yet
                      </div>
                      <div style={{ fontSize: '0.95rem', maxWidth: '360px' }}>
                        {activeTab === 'dm'
                          ? 'Say hello. Only you and this member can read what you write here.'
                          : 'Say something. Only the people in this group can read it.'}
                      </div>
                    </div>
                  ) : (
                    (() => {
                      const myId = e2eeProfile?.user_id || '';
                      const scopeType: 'dm' | 'group' = activeTab === 'dm' ? 'dm' : 'group';
                      const nameFor = (msg: RichDisplayMessage): string => {
                        if (msg.sender === myId) return 'You';
                        if (activeTab === 'dm' && selectedPeer && msg.sender === selectedPeer.user_id && selectedPeer.username) {
                          return `@${selectedPeer.username}`;
                        }
                        if (activeTab === 'groups' && selectedGroup) {
                          const gm = selectedGroup.members.find((m) => m.user_id === msg.sender && m.username);
                          if (gm?.username) return `@${gm.username}`;
                        }
                        return `User-${msg.sender.slice(4, 10)}`;
                      };
                      // Instagram shows "Seen" / "Sent" only under your latest message.
                      let lastMine: DisplayMsg | undefined;
                      for (let i = displayMessages.length - 1; i >= 0; i--) {
                        if (displayMessages[i].sender === myId) {
                          lastMine = displayMessages[i];
                          break;
                        }
                      }
                      return (
                        <ChatTimeline<DisplayMsg>
                          items={displayMessages}
                          getKey={(msg, index) => msg.id || `idx_${index}`}
                          getTime={(msg) => msg.timestamp}
                          getSender={(msg) => msg.sender}
                          isMine={(msg) => msg.sender === myId}
                          isPending={(msg) => msg.sendStatus === 'sending'}
                          getMessageId={(msg) => msg.id}
                          showNames={activeTab === 'groups'}
                          getName={nameFor}
                          getInitials={(msg) => initialsFor(nameFor(msg))}
                          renderBody={(msg, ctx) =>
                            msg.deleted ? (
                              <DeletedBubble mine={ctx.mine} title={ctx.fullTime} />
                            ) : !msg.canDecrypt ? (
                              <div className="ig-bubble ig-locked" title={ctx.fullTime}>
                                <Lock size={13} />
                                <span>{msg.message}</span>
                              </div>
                            ) : (
                              <>
                                {msg.replyTo && (
                                  <QuotedReply
                                    name={nameForSender(msg.replyTo.sender_user_id)}
                                    preview={msg.replyTo.preview}
                                    onClick={() => {
                                      if (!jumpToMessage(msg.replyTo!.message_id)) {
                                        setReplyJumpMissId(msg.id);
                                        setTimeout(() => setReplyJumpMissId((cur) => (cur === msg.id ? null : cur)), 2500);
                                      }
                                    }}
                                  />
                                )}
                                {replyJumpMissId === msg.id && (
                                  <span className="ig-footer">The original message is not loaded here.</span>
                                )}
                                {(msg.localFiles || []).map((f, i) => (
                                  <AttachmentTile
                                    key={`${msg.id}_local_${i}`}
                                    id={`${msg.id}_local_${i}`}
                                    name={f.name}
                                    mime={f.type || 'application/octet-stream'}
                                    size={f.size}
                                    load={() => Promise.resolve(f as Blob)}
                                  />
                                ))}
                                {(msg.attachments || []).map((att) => (
                                  <AttachmentTile
                                    key={att.attachment_id}
                                    id={att.attachment_id}
                                    name={att.file_name}
                                    mime={att.mime_type}
                                    size={att.size_bytes}
                                    removed={revokedAttachmentIds.has(att.attachment_id)}
                                    load={() => loadDecryptedAttachment(att, scopeType)}
                                    onRemove={ctx.mine && msg.sendStatus !== 'failed' ? () => handleRevokeAttachment(att) : undefined}
                                  />
                                ))}
                                {msg.poll ? (
                                  <PollCard poll={msg.poll} nameFor={nameForSender} onVote={(opts) => void voteOn(msg.id, opts)} title={ctx.fullTime} />
                                ) : (
                                  <TextBubble text={msg.message} title={ctx.fullTime} edited={msg.edited} myUsername={e2eeProfile?.username} />
                                )}
                              </>
                            )
                          }
                          renderFooter={(msg, ctx) => {
                            const chips =
                              Object.keys(msg.reactions || {}).length > 0 ? (
                                <ReactionChips
                                  reactions={msg.reactions}
                                  myId={myId}
                                  nameFor={nameForSender}
                                  onToggle={(emoji) => void reactTo(msg.id, (msg.reactions[emoji] || []).includes(myId) ? '' : emoji)}
                                />
                              ) : null;
                            const status = statusFooter(msg, ctx);
                            return chips || status ? (
                              <>
                                {chips}
                                {status}
                              </>
                            ) : null;
                          }}
                          renderActions={(msg, ctx) => renderMessageActions(msg, ctx)}
                        />
                      );
                      function statusFooter(msg: DisplayMsg, ctx: { mine: boolean }) {
                        if (msg.sendStatus === 'failed') {
                          return (
                            <span className="ig-footer ig-failed" role="alert">
                              <AlertCircle size={12} />
                              <span>{msg.sendError || 'Not sent'}</span>
                              {msg.canRetry && (
                                <button type="button" onClick={() => handleRetryFailedMessage(msg)} disabled={sending}>
                                  Retry
                                </button>
                              )}
                            </span>
                          );
                        }
                        if (!ctx.mine || msg !== lastMine) return null;
                        if (msg.sendStatus === 'sending') {
                          return <span className="ig-footer">{msg.localFiles?.length ? 'Encrypting and sending…' : 'Sending…'}</span>;
                        }
                        if (activeTab === 'dm') {
                          const seen = Boolean(msg.seq && peerLastReadSeq >= msg.seq);
                          return <span className="ig-footer">{seen ? 'Seen' : 'Sent'}</span>;
                        }
                        return null;
                      }
                      function renderMessageActions(msg: DisplayMsg, ctx: { mine: boolean }) {
                        const sent =
                          msg.canDecrypt && msg.sendStatus !== 'sending' && msg.sendStatus !== 'failed' && !msg.id.startsWith('failed_');
                        const canReply = sent && !msg.deleted;
                        const now = Date.now();
                        const myReaction = Object.entries(msg.reactions || {}).find(([, ids]) => ids.includes(myId))?.[0];
                        const pinned = Boolean(convState?.pins.some((p) => p.message_id === msg.id));
                        const canEdit = canReply && canEditMessage(msg, myId, now);
                        const canDelete = sent && canDeleteForEveryone(msg, myId, now, isGroupAdminHere);
                        if (!canReply && !canDelete && ctx.mine) return null;
                        return (
                          <>
                            {canReply && <ReactButton current={myReaction} onPick={(emoji) => void reactTo(msg.id, emoji)} />}
                            {canEdit && (
                              <button
                                type="button"
                                className="ig-action"
                                title="Edit (within 15 minutes)"
                                aria-label="Edit this message"
                                onClick={() => {
                                  setReplyTarget(null);
                                  setEditTarget({ id: msg.id, original: msg.message });
                                  setInputMessage(msg.message);
                                }}
                              >
                                <Pencil size={14} />
                              </button>
                            )}
                            {canDelete && (
                              <button
                                type="button"
                                className="ig-action"
                                title="Delete for everyone"
                                aria-label="Delete this message for everyone"
                                onClick={() => deleteForEveryone(msg)}
                              >
                                <Trash2 size={14} />
                              </button>
                            )}
                            {canReply && convState?.can_manage && (
                              <button
                                type="button"
                                className="ig-action"
                                title={pinned ? 'Unpin' : 'Pin'}
                                aria-label={pinned ? 'Unpin this message' : 'Pin this message'}
                                aria-pressed={pinned}
                                onClick={() => void togglePin(msg.id, !pinned)}
                              >
                                {pinned ? <PinOff size={14} /> : <Pin size={14} />}
                              </button>
                            )}
                            {canReply && (
                              <button
                                type="button"
                                className="ig-action"
                                title="Reply"
                                aria-label="Reply to this message"
                                onClick={() =>
                                  setReplyTarget({
                                    message_id: msg.id,
                                    sender_user_id: msg.sender,
                                    preview: replyPreviewFor(msg),
                                    has_files: Boolean(msg.attachments?.length || msg.localFiles?.length),
                                  })
                                }
                              >
                                <Reply size={14} />
                              </button>
                            )}
                            {!ctx.mine && (
                              <button
                                type="button"
                                className="ig-action"
                                title="Copy user ID"
                                aria-label="Copy user ID"
                                onClick={() => handleCopy(msg.sender, msg.id)}
                              >
                                {copiedId === msg.id ? <Check size={14} /> : <Copy size={14} />}
                              </button>
                            )}
                          </>
                        );
                      }
                    })()
                  )}
                </div>

                <TypingLine names={typingNames} />

                {/* Composer */}
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
                        borderRadius: '10px',
                        gap: '12px',
                      }}
                    >
                      <span style={{ fontSize: '0.86rem', color: 'var(--text-main)' }}>
                        <strong>Membership Required:</strong> Pay your monthly or yearly membership in ETH to send encrypted messages.
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
                    <ChatComposer
                      value={inputMessage}
                      onChange={setInputMessage}
                      onSubmit={() => void handleSendMessage()}
                      files={pendingFiles}
                      onFilesChange={setPendingFiles}
                      maxFileBytes={MAX_ENCRYPTED_FILE_BYTES}
                      maxFiles={MAX_FILES_PER_MESSAGE}
                      dailyLimitText={DAILY_LIMIT_TEXT_ENCRYPTED}
                      disabled={(activeTab === 'dm' && !selectedPeer) || (activeTab === 'groups' && !selectedGroup)}
                      autoFocusKey={activeTab === 'dm' ? selectedPeer?.user_id : selectedGroup?.group_id}
                      placeholder={
                        activeTab === 'dm'
                          ? selectedPeer
                            ? 'Message…'
                            : 'Choose a member first'
                          : selectedGroup
                            ? `Message ${selectedGroup.name}`
                            : 'Choose or create a group first'
                      }
                      note="Messages and files here are end-to-end encrypted on your device."
                      canAttach={false}
                      replyTo={
                        editTarget
                          ? { name: 'Editing your message', preview: editTarget.original }
                          : replyTarget
                            ? { name: nameForSender(replyTarget.sender_user_id), preview: replyTarget.preview }
                            : null
                      }
                      onCancelReply={() => {
                        if (editTarget) {
                          setEditTarget(null);
                          setInputMessage('');
                        } else setReplyTarget(null);
                      }}
                      mentionCandidates={activeTab === 'groups' ? mentionCandidates : undefined}
                      onTyping={signalTyping}
                      readOnlyNote={
                        adminsOnlyHere && !isGroupAdminHere
                          ? 'Only admins can send messages in this group. You can still react and vote.'
                          : null
                      }
                    />
                  )}
                </div>
              </>
            ))}
        </div>
      )}

      {/* Modals */}
      <PollComposer open={pollOpen} onClose={() => setPollOpen(false)} onCreate={createPoll} />

      {invitationAlert && groupInvitations.some((i) => i.group_id === invitationAlert.group_id) && (
        <div
          role="status"
          aria-live="polite"
          style={{
            position: 'fixed',
            right: 'max(16px, env(safe-area-inset-right, 0px))',
            bottom: joinRequestAlertGroupId
              ? 'calc(max(16px, env(safe-area-inset-bottom, 0px)) + 120px)'
              : 'max(16px, env(safe-area-inset-bottom, 0px))',
            zIndex: 900,
            maxWidth: 360,
            display: 'flex',
            gap: 10,
            alignItems: 'flex-start',
            padding: '12px 14px',
            background: 'var(--bg-card)',
            color: 'var(--text-main)',
            border: '1px solid var(--border-strong)',
            borderRadius: 14,
            boxShadow: 'var(--shadow-pop)',
            fontSize: '0.92rem',
          }}
        >
          <Users size={18} style={{ color: 'var(--accent)', flexShrink: 0, marginTop: 2 }} />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <span>
              {invitationAlert.by ? `@${invitationAlert.by} added you to ` : 'You were added to '}
              <strong>{invitationAlert.group_name}</strong>.
            </span>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <button
                type="button"
                className="btn-solid"
                style={{ padding: '6px 12px', fontSize: '0.88rem' }}
                disabled={invitationBusyId !== null}
                onClick={() => handleAcceptGroupInvitation(invitationAlert.group_id, invitationAlert.group_name)}
              >
                Accept
              </button>
              <button
                type="button"
                className="btn-outline"
                style={{ padding: '6px 12px', fontSize: '0.88rem' }}
                disabled={invitationBusyId !== null}
                onClick={() => handleDeclineGroupInvitation(invitationAlert.group_id)}
              >
                Reject
              </button>
              <button
                type="button"
                className="btn-outline"
                style={{ padding: '6px 12px', fontSize: '0.88rem' }}
                onClick={() => setInvitationAlert(null)}
              >
                Later
              </button>
            </div>
          </div>
        </div>
      )}

      {joinRequestAlertGroupId && (
        <div
          role="status"
          aria-live="polite"
          style={{
            position: 'fixed',
            right: 'max(16px, env(safe-area-inset-right, 0px))',
            bottom: 'max(16px, env(safe-area-inset-bottom, 0px))',
            zIndex: 900,
            maxWidth: 360,
            display: 'flex',
            gap: 10,
            alignItems: 'flex-start',
            padding: '12px 14px',
            background: 'var(--bg-card)',
            color: 'var(--text-main)',
            border: '1px solid var(--border-strong)',
            borderRadius: 14,
            boxShadow: 'var(--shadow-pop)',
            fontSize: '0.92rem',
          }}
        >
          <BellRing size={18} style={{ color: 'var(--accent)', flexShrink: 0, marginTop: 2 }} />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <span>
              Someone asked to join{' '}
              <strong>{groups.find((g) => g.group_id === joinRequestAlertGroupId)?.name || 'one of your groups'}</strong>.
            </span>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                type="button"
                className="btn-solid"
                style={{ padding: '6px 12px', fontSize: '0.88rem' }}
                onClick={() => {
                  const g = groups.find((item) => item.group_id === joinRequestAlertGroupId);
                  setJoinRequestAlertGroupId(null);
                  if (g) {
                    setSelectedGroup(g);
                    handleSelectChannelTab('groups');
                    setGroupModalInitialTab('invites');
                    setGroupModalOpen(true);
                  }
                }}
              >
                Review
              </button>
              <button
                type="button"
                className="btn-outline"
                style={{ padding: '6px 12px', fontSize: '0.88rem' }}
                onClick={() => setJoinRequestAlertGroupId(null)}
              >
                Later
              </button>
            </div>
          </div>
        </div>
      )}

      {selectedGroup && e2eeProfile && (
        <MlsGroupSecurityModal
          initialTab={groupModalInitialTab}
          open={groupModalOpen}
          onClose={() => {
            setGroupModalOpen(false);
            setGroupModalInitialTab(undefined);
          }}
          group={selectedGroup}
          currentUserId={e2eeProfile.user_id}
          onAddMember={handleAddGroupMember}
          onRemoveMember={handleRemoveGroupMember}
          onLeaveGroup={async () => {
            const gid = selectedGroup.group_id;
            await leaveEncryptedGroup(gid);
            await clearLocalMlsGroupState(e2eeProfile.user_id, gid);
            setSelectedGroup(null);
            handleSelectChannelTab('open_chat');
            await syncSidebarLists();
          }}
          onDeleteGroup={async () => {
            const gid = selectedGroup.group_id;
            await deleteGroup(gid);
            await clearLocalMlsGroupState(e2eeProfile.user_id, gid).catch(() => { });
            setSelectedGroup(null);
            handleSelectChannelTab('open_chat');
            await syncSidebarLists();
          }}
          onGroupUpdated={syncSidebarLists}
        />
      )}

      {/* "+Add -> Create Group" Modal */}
      {createGroupModalOpen && (
        <div
          className="chat-action-modal-backdrop"
          onClick={() => {
            if (!creatingGroupBusy) setCreateGroupModalOpen(false);
          }}
        >
          <div className="chat-action-modal-card" onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Users size={19} />
                <div>
                  <h3 style={{ fontSize: '1.45rem', fontWeight: 500, letterSpacing: '-0.015em', margin: 0 }}>New group</h3>
                  <div style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>
                    Create an end-to-end encrypted group and invite members.
                  </div>
                </div>
              </div>
              <button
                type="button"
                className="btn-outline"
                style={{ padding: '6px' }}
                disabled={creatingGroupBusy}
                onClick={() => setCreateGroupModalOpen(false)}
              >
                <X size={15} />
              </button>
            </div>

            {!account ? (
              <div
                style={{
                  padding: '12px 14px',
                  borderRadius: '10px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-strong)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '10px',
                  flexWrap: 'wrap',
                  fontSize: '0.86rem',
                }}
              >
                <span>Connect MetaMask to create an encrypted group.</span>
                <button
                  type="button"
                  className="btn-solid"
                  style={{ padding: '7px 14px', fontSize: '0.86rem' }}
                  onClick={onConnectWallet}
                >
                  <Wallet size={13} />
                  <span>Connect MetaMask</span>
                </button>
              </div>
            ) : needsE2EEAuth ? (
              <div
                style={{
                  padding: '12px 14px',
                  borderRadius: '10px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-strong)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '10px',
                  flexWrap: 'wrap',
                  fontSize: '0.86rem',
                }}
              >
                <span>
                  {isWalletMismatch
                    ? `Sign in as ${formatAddress(account, 4)} to keep chatting.`
                    : 'Sign in with MetaMask to see your private chats and groups.'}
                </span>
                <button
                  type="button"
                  className="btn-solid"
                  style={{ padding: '7px 14px', fontSize: '0.86rem' }}
                  disabled={siweLoading || authLoading}
                  onClick={onAuthenticateSiwe || authenticateE2EESession}
                >
                  <KeyRound size={13} />
                  <span>{siweLoading || authLoading ? 'Signing in...' : 'Sign in'}</span>
                </button>
              </div>
            ) : null}

            {createGroupError && (
              <div
                style={{
                  padding: '9px 12px',
                  borderRadius: '8px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-focus)',
                  fontSize: '0.86rem',
                  color: 'var(--text-main)',
                }}
              >
                {createGroupError}
              </div>
            )}

            <form
              onSubmit={handleCreateMlsGroup}
              style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}
            >
              <div>
                <label style={{ fontSize: '0.86rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                  Group name
                </label>
                <input
                  type="text"
                  autoFocus
                  placeholder="For example: Allocation committee"
                  value={newGroupName}
                  onChange={(e) => setNewGroupName(e.target.value)}
                  style={{
                    width: '100%',
                    marginTop: '5px',
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-strong)',
                    borderRadius: '10px',
                    padding: '10px 13px',
                    color: 'var(--text-main)',
                    fontSize: '0.88rem',
                    outline: 'none',
                  }}
                />
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <label style={{ fontSize: '0.86rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                  Add members (optional)
                </label>
                <span style={{ fontSize: '0.84rem', color: 'var(--text-muted)' }}>
                  They get an invitation and join when they press Accept.
                </span>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <input
                    type="text"
                    placeholder="@username, member ID or wallet address"
                    value={groupMemberInput}
                    onChange={(e) => setGroupMemberInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        if (groupMemberInput.trim()) {
                          handleStageMemberForGroup();
                        }
                      }
                    }}
                    style={{
                      flex: 1,
                      background: 'var(--bg-input)',
                      border: '1px solid var(--border-strong)',
                      borderRadius: '10px',
                      padding: '9px 13px',
                      color: 'var(--text-main)',
                      fontSize: '0.9rem',
                      fontFamily: 'ui-monospace, monospace',
                      outline: 'none',
                    }}
                  />
                  <button
                    type="button"
                    className="btn-outline"
                    disabled={!groupMemberInput.trim() || addingGroupMemberBusy}
                    onClick={() => handleStageMemberForGroup()}
                    style={{ padding: '0 14px', fontSize: '0.86rem', flexShrink: 0 }}
                  >
                    <Plus size={14} />
                    <span>{addingGroupMemberBusy ? 'Checking...' : 'Add'}</span>
                  </button>
                </div>

                {pendingGroupMembers.length > 0 && (
                  <div className="member-chip-list" style={{ marginTop: '4px' }}>
                    {pendingGroupMembers.map((pm) => (
                      <span key={pm.user_id} className="member-chip">
                        <span>
                          {pm.username
                            ? `@${pm.username}`
                            : pm.primary_wallet
                              ? formatAddress(pm.primary_wallet, 4)
                              : pm.user_id.slice(0, 14)}
                        </span>
                        <button
                          type="button"
                          title="Remove member"
                          onClick={() =>
                            setPendingGroupMembers((prev) =>
                              prev.filter((x) => x.user_id !== pm.user_id)
                            )
                          }
                        >
                          <X size={12} />
                        </button>
                      </span>
                    ))}
                  </div>
                )}

                {groupMemberInput.trim().length > 0 && groupMemberSuggestions.length > 0 && (
                  <div className="member-suggestions-box">
                    {groupMemberSuggestions.map((u) => {
                      const idStr = u.username ? `@${u.username}` : u.user_id;
                      return (
                        <button
                          key={u.user_id}
                          type="button"
                          className="member-suggestion-item"
                          onClick={() => handleStageMemberForGroup(idStr)}
                        >
                          <span style={{ fontFamily: 'ui-monospace, monospace', fontWeight: 600 }}>
                            {idStr}
                          </span>
                          <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>
                            Add
                          </span>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>

              <button
                type="button"
                className="btn-outline"
                style={{ padding: '6px 10px', fontSize: '0.9rem', justifyContent: 'center' }}
                onClick={() => setShowGroupOpts((p) => !p)}
              >
                {showGroupOpts
                  ? 'Hide Access Policy Options'
                  : `Who can join: ${newGroupVisibility === 'public' ? 'anyone, via the group list' : 'by invitation only'}. ${Number(newGroupMinEth || 0) > 0 ? `Minimum balance ${newGroupMinEth} ETH.` : 'No minimum balance.'}`}
              </button>

              {showGroupOpts && (
                <div
                  style={{
                    padding: '10px',
                    borderRadius: '10px',
                    background: 'var(--bg-surface)',
                    border: '1px solid var(--border-subtle)',
                    display: 'grid',
                    gridTemplateColumns: '1fr 1fr',
                    gap: '8px',
                    fontSize: '0.9rem',
                  }}
                >
                  <div>
                    <label style={{ color: 'var(--text-muted)' }}>Visibility</label>
                    <select
                      value={newGroupVisibility}
                      onChange={(e) =>
                        setNewGroupVisibility(e.target.value as 'invite_only' | 'public')
                      }
                      style={{
                        width: '100%',
                        marginTop: '3px',
                        backgroundColor: 'var(--bg-input)',
                        border: '1px solid var(--border-strong)',
                        color: 'var(--text-main)',
                        borderRadius: '6px',
                        padding: '7px 36px 7px 10px',
                      }}
                    >
                      <option value="invite_only">Invite Only</option>
                      <option value="public">Public</option>
                    </select>
                  </div>
                  <div>
                    <label style={{ color: 'var(--text-muted)' }}>Min ETH</label>
                    <input
                      type="text"
                      value={newGroupMinEth}
                      onChange={(e) => setNewGroupMinEth(e.target.value)}
                      placeholder="0"
                      style={{
                        width: '100%',
                        marginTop: '3px',
                        backgroundColor: 'var(--bg-input)',
                        border: '1px solid var(--border-strong)',
                        color: 'var(--text-main)',
                        borderRadius: '6px',
                        padding: '7px 10px',
                      }}
                    />
                  </div>
                </div>
              )}

              {e2eeProfile?.admin_role === 'superadmin' && (
                <div
                  style={{
                    border: '1px solid var(--border-strong)',
                    borderRadius: '10px',
                    padding: '10px 12px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '8px',
                    fontSize: '0.86rem',
                  }}
                >
                  <div style={{ display: 'flex', gap: '14px', alignItems: 'center' }}>
                    <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Entry</span>
                    <label style={{ display: 'flex', gap: '5px', alignItems: 'center', cursor: 'pointer' }}>
                      <input type="radio" name="group-entry" checked={!newGroupPaid} onChange={() => setNewGroupPaid(false)} />
                      Free
                    </label>
                    <label style={{ display: 'flex', gap: '5px', alignItems: 'center', cursor: 'pointer' }}>
                      <input type="radio" name="group-entry" checked={newGroupPaid} onChange={() => setNewGroupPaid(true)} />
                      Paid
                    </label>
                  </div>
                  {newGroupPaid && (
                    <div>
                      <label style={{ color: 'var(--text-muted)' }}>
                        MONTHLY price in US dollars (members pay the ETH equivalent for 30 days)
                      </label>
                      <input
                        type="number"
                        min={0}
                        step="0.5"
                        value={newGroupFeeUsd}
                        onChange={(e) => setNewGroupFeeUsd(e.target.value)}
                        style={{
                          width: '100%',
                          marginTop: '3px',
                          background: 'var(--bg-input)',
                          border: '1px solid var(--border-strong)',
                          color: 'var(--text-main)',
                          borderRadius: '6px',
                          padding: '6px',
                        }}
                      />
                      <label style={{ color: 'var(--text-muted)', display: 'block', marginTop: '8px' }}>
                        YEARLY price in US dollars (365 days). 0 = automatic: 12 x monthly
                      </label>
                      <input
                        type="number"
                        min={0}
                        step="0.5"
                        value={newGroupYearlyFeeUsd}
                        onChange={(e) => setNewGroupYearlyFeeUsd(e.target.value)}
                        style={{
                          width: '100%',
                          marginTop: '3px',
                          background: 'var(--bg-input)',
                          border: '1px solid var(--border-strong)',
                          color: 'var(--text-main)',
                          borderRadius: '6px',
                          padding: '6px',
                        }}
                      />
                    </div>
                  )}
                </div>
              )}

              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  gap: '10px',
                  marginTop: '4px',
                }}
              >
                <button
                  type="button"
                  className="btn-outline"
                  style={{ padding: '7px 12px', fontSize: '0.86rem' }}
                  onClick={() => {
                    setCreateGroupModalOpen(false);
                    setSelectedGroup(null);
                    handleSelectChannelTab('groups');
                  }}
                >
                  <Search size={13} />
                  <span>Browse public groups</span>
                </button>

                <button
                  type="submit"
                  className="btn-solid"
                  disabled={creatingGroupBusy || !newGroupName.trim()}
                  style={{ padding: '9px 18px', fontSize: '0.9rem' }}
                >
                  <Users size={15} />
                  <span>
                    {creatingGroupBusy
                      ? 'Creating Group...'
                      : pendingGroupMembers.length > 0
                        ? `Create group (${pendingGroupMembers.length + 1})`
                        : 'Create group'}
                  </span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* "+Add -> Chat Individual" Modal */}
      {chatIndividualModalOpen && (
        <div
          className="chat-action-modal-backdrop"
          onClick={() => {
            if (!startingIndividualBusy) setChatIndividualModalOpen(false);
          }}
        >
          <div className="chat-action-modal-card" onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <UserPlus size={19} />
                <div>
                  <h3 style={{ fontSize: '1.45rem', fontWeight: 500, letterSpacing: '-0.015em', margin: 0 }}>
                    Chat Individual
                  </h3>
                  <div style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>
                    Enter a member&apos;s ID to open a 1-to-1 end-to-end encrypted chat
                  </div>
                </div>
              </div>
              <button
                type="button"
                className="btn-outline"
                style={{ padding: '6px' }}
                disabled={startingIndividualBusy}
                onClick={() => setChatIndividualModalOpen(false)}
              >
                <X size={15} />
              </button>
            </div>

            {!account ? (
              <div
                style={{
                  padding: '12px 14px',
                  borderRadius: '10px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-strong)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '10px',
                  flexWrap: 'wrap',
                  fontSize: '0.86rem',
                }}
              >
                <span>Connect MetaMask to start an encrypted individual chat.</span>
                <button
                  type="button"
                  className="btn-solid"
                  style={{ padding: '7px 14px', fontSize: '0.86rem' }}
                  onClick={onConnectWallet}
                >
                  <Wallet size={13} />
                  <span>Connect MetaMask</span>
                </button>
              </div>
            ) : needsE2EEAuth ? (
              <div
                style={{
                  padding: '12px 14px',
                  borderRadius: '10px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-strong)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '10px',
                  flexWrap: 'wrap',
                  fontSize: '0.86rem',
                }}
              >
                <span>
                  {isWalletMismatch
                    ? `Sign in as ${formatAddress(account, 4)} to keep chatting.`
                    : 'Sign in with MetaMask to see your private chats and groups.'}
                </span>
                <button
                  type="button"
                  className="btn-solid"
                  style={{ padding: '7px 14px', fontSize: '0.86rem' }}
                  disabled={siweLoading || authLoading}
                  onClick={onAuthenticateSiwe || authenticateE2EESession}
                >
                  <KeyRound size={13} />
                  <span>{siweLoading || authLoading ? 'Signing in...' : 'Sign in'}</span>
                </button>
              </div>
            ) : null}

            {e2eeProfile && (
              <div
                style={{
                  padding: '9px 12px',
                  borderRadius: '9px',
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-subtle)',
                  fontSize: '0.86rem',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  gap: '8px',
                }}
              >
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  Your ID:{' '}
                  <code style={{ fontFamily: 'ui-monospace, monospace' }}>
                    {e2eeProfile.username ? `@${e2eeProfile.username}` : e2eeProfile.user_id}
                  </code>
                </span>
                <button
                  type="button"
                  className="btn-outline"
                  style={{ padding: '3px 8px', fontSize: '0.9rem', flexShrink: 0 }}
                  onClick={() =>
                    handleCopy(
                      e2eeProfile.username ? `@${e2eeProfile.username}` : e2eeProfile.user_id,
                      'my_own_id'
                    )
                  }
                >
                  {copiedId === 'my_own_id' ? <Check size={11} /> : <Copy size={11} />}
                  <span>{copiedId === 'my_own_id' ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            )}

            {chatIndividualError && (
              <div
                style={{
                  padding: '9px 12px',
                  borderRadius: '8px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-focus)',
                  fontSize: '0.86rem',
                  color: 'var(--text-main)',
                }}
              >
                {chatIndividualError}
              </div>
            )}

            <form
              onSubmit={(e) => handleStartChatIndividual(e)}
              style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}
            >
              <div>
                <label style={{ fontSize: '0.86rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                  Individual Member ID
                </label>
                <input
                  type="text"
                  autoFocus
                  placeholder="Write @username, usr_..., or 0x... wallet address"
                  value={individualIdInput}
                  onChange={(e) => setIndividualIdInput(e.target.value)}
                  style={{
                    width: '100%',
                    marginTop: '5px',
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-strong)',
                    borderRadius: '10px',
                    padding: '10px 13px',
                    color: 'var(--text-main)',
                    fontSize: '0.86rem',
                    fontFamily: 'ui-monospace, monospace',
                    outline: 'none',
                  }}
                />
              </div>

              {individualSuggestions.length > 0 && (
                <div>
                  <div
                    style={{
                      fontSize: '0.9rem',
                      color: 'var(--text-muted)',
                      marginBottom: '5px',
                      fontWeight: 600,
                    }}
                  >
                    Verified Accounts
                  </div>
                  <div className="member-suggestions-box">
                    {individualSuggestions.map((u) => {
                      const idStr = u.username ? `@${u.username}` : u.user_id;
                      return (
                        <button
                          key={u.user_id}
                          type="button"
                          className="member-suggestion-item"
                          onClick={() => {
                            setIndividualIdInput(idStr);
                            if (isVaultReadyForProfile) {
                              handleStartChatIndividual(undefined, idStr);
                            }
                          }}
                        >
                          <span style={{ fontFamily: 'ui-monospace, monospace', fontWeight: 600 }}>
                            {idStr}
                          </span>
                          <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>
                            {u.online ? '• Online ' : ''}&rarr; Chat
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '4px' }}>
                <button
                  type="button"
                  className="btn-outline"
                  disabled={startingIndividualBusy}
                  onClick={() => setChatIndividualModalOpen(false)}
                  style={{ padding: '8px 14px', fontSize: '0.9rem' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn-solid"
                  disabled={startingIndividualBusy || !individualIdInput.trim()}
                  style={{ padding: '8px 18px', fontSize: '0.9rem' }}
                >
                  <Lock size={14} />
                  <span>{startingIndividualBusy ? 'Opening Chat...' : 'Start Chat'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {e2eeProfile && (
        <AccountDevicesVaultModal
          open={vaultModalOpen}
          onClose={() => {
            setVaultModalOpen(false);
            onVaultClosed?.();
          }}
          profile={e2eeProfile}
          devices={myDevices}
          localDeviceId={localDeviceId}
          connectedWallet={account}
          onUpdateUsername={async (uname) => {
            const res = await updateMyE2EEUsername(uname);
            setE2eeProfile(res.user);
          }}
          onLinkCurrentWallet={async (revokeOld) => {
            if (!account) return;
            const chainNum = chainIdHex ? parseInt(chainIdHex, 16) || 1 : 1;
            const chal = await requestE2EEAuthChallenge(account, 'link_wallet', chainNum);
            const sig = await signWalletAuthChallenge(account, chal.message);
            const res = await linkNewWalletToE2EEAccount({
              challenge_id: chal.challenge_id,
              new_wallet_address: account,
              signature: sig,
              make_primary: true,
              revoke_previous_wallets: revokeOld,
            });
            setE2eeProfile(res.user);
          }}
          onRevokeDevice={async (devId) => {
            await revokeE2EEDevice(devId);
            const fresh = await fetchMyE2EEAccount();
            setMyDevices(fresh.devices);
          }}
          onResetLostIdentity={async () => {
            if (!account) return;
            const chainNum = chainIdHex ? parseInt(chainIdHex, 16) || 1 : 1;
            const chal = await requestE2EEAuthChallenge(account, 'reset_lost_identity', chainNum);
            const sig = await signWalletAuthChallenge(account, chal.message);
            const freshLocal = await generateFreshLocalOlmDevice(
              e2eeProfile.user_id,
              'Web browser',
              false
            );
            const freshMls = await generateMlsKeyPackagesForDevice(
              e2eeProfile.user_id,
              freshLocal.record.deviceId,
              8
            );
            await resetLostE2EEIdentity({
              challenge_id: chal.challenge_id,
              wallet_address: account,
              signature: sig,
              confirm_irrecoverable_history: true,
              new_device: {
                ...freshLocal.registrationBundle,
                mls_key_packages: freshMls,
              },
            });
            await wipeUserDeviceVault(e2eeProfile.user_id);
            await saveDeviceVaultRecord(freshLocal.record);
            await markLocalPrekeysPublished(e2eeProfile.user_id);
            const freshMe = await fetchMyE2EEAccount();
            setE2eeProfile(freshMe.user);
            setMyDevices(freshMe.devices);
            setLocalDeviceId(freshLocal.record.deviceId);
            setVaultBoundUserId(e2eeProfile.user_id);
          }}
        />
      )}
    </div>
  );
};