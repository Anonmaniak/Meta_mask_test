import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Send,
  MessageSquare,
  Users,
  UserPlus,
  ChevronDown,
  Lock,
  Copy,
  Check,
  Wallet,
  Radio,
  ShieldCheck,
  ShieldAlert,
  KeyRound,
  Plus,
  Paperclip,
  Download,
  Globe,
  Ban,
  Flag,
  CheckCheck,
  Menu,
  X,
  Search,
  Link2,
  Compass,
  AlertCircle,
  RotateCcw,
} from 'lucide-react';
import type { ChatMessage } from '../types';
import { formatAddress } from '../services/web3';

import {
  loadVaultDecryptedMessage,
  saveVaultDecryptedMessage,
  wipeUserDeviceVault,
} from '../services/e2eeVault';
import {
  OLM_PROTOCOL_ID,
  getOrCreateLocalOlmDevice,
  markLocalPrekeysPublished,
  generateMoreOlmPrekeys,
  encryptOlmMultiDevicePayload,
  decryptOlmDeviceCiphertext,
  resetOlmSessionWithPeerDevice,
  computeSafetyNumber,
  evaluateAndRecordPeerTrust,
  markPeerDevicesVerified,
  type E2EEPlaintextEnvelope,
  type PeerActiveDeviceDescriptor,
} from '../services/olmService';
import {
  MLS_CIPHERSUITE_NAME,
  generateMlsKeyPackagesForDevice,
  initializeNewMlsGroupLocal,
  buildMlsAddMembersCommit,
  buildMlsRemoveMemberCommit,
  buildMlsSelfKeyRotationCommit,
  joinMlsGroupFromWelcomeB64,
  processIncomingMlsCommits,
  encryptMlsGroupMessage,
  decryptMlsGroupMessage,
  getMlsGroupSecurityInfo,
  clearLocalMlsGroupState,
} from '../services/mlsGroupService';
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
  registerE2EEDeviceBundle,
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
  connectE2EEWebSocket,
  type E2EEAccountProfile,
  type E2EEGroupRecord,
} from '../services/e2eeApi';
import {
  blockUser,
  sendDmReadReceipt,
  fetchDmReadReceipts,
  submitAbuseReport,
  leaveEncryptedGroup,
  searchUsers,
  discoverPublicGroups,
  joinGroupByInviteCode,
  requestJoinPublicGroup,
  type DirectoryUserRecord,
  type DiscoverableGroupRecord,
  formatGroupFee,
} from '../services/platformApi';
import {
  SafetyNumberModal,
  MlsGroupSecurityModal,
  AccountDevicesVaultModal,
} from './E2EESecurityModals';
import { OpenPublicChatView } from './PlatformViews';
import { mergeLocalEntries } from '../services/chatSync';

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

interface FailedSendPayload {
  channelType: 'dm' | 'groups';
  targetId: string;
  msgId: string;
  plainEnvelope: E2EEPlaintextEnvelope;
  cipherPayload?: any;
  createdAt: number;
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
}

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
  warnings: any;
  verified: boolean;
  safetyNumber: any | null;
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
  const [localEd25519Key, setLocalEd25519Key] = useState<string>('');
  const [localCurve25519Key, setLocalCurve25519Key] = useState<string>('');
  const [authLoading, setAuthLoading] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const vaultInitInFlightRef = useRef<string | null>(null);

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

  // User Directory State (fallback view & modal live search)
  const [directoryQuery, setDirectoryQuery] = useState('');
  const [directoryUsers, setDirectoryUsers] = useState<DirectoryUserRecord[]>([]);
  const [directoryLoading, setDirectoryLoading] = useState(false);
  const [directoryStatusMsg, setDirectoryStatusMsg] = useState<string | null>(null);

  // Group Discovery & Invites State
  const [discoverableGroups, setDiscoverableGroups] = useState<DiscoverableGroupRecord[]>([]);
  const [groupsLoading, setGroupsLoading] = useState(false);
  const [inviteCodeInput, setInviteCodeInput] = useState('');
  const [inviteStatusMsg, setInviteStatusMsg] = useState<string | null>(null);
  const [inviteRedeeming, setInviteRedeeming] = useState(false);

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
  const [peerSecurityWarnings, setPeerSecurityWarnings] = useState<string[]>([]);
  const [peerIsVerified, setPeerIsVerified] = useState(false);
  const [safetyNumber, setSafetyNumber] = useState('');
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
  const [showGroupOpts, setShowGroupOpts] = useState(false);
  const [groupSecurityInfo, setGroupSecurityInfo] = useState<{
    epoch: number;
    epochAuthenticatorHex: string;
    exportedContextVerifyCode: string;
  } | null>(null);

  // Composer, attachments, & modals
  const [messages, setMessages] = useState<RichDisplayMessage[]>([]);
  const [inputMessage, setInputMessage] = useState('');
  const [pendingFile, setPendingFile] = useState<File | null>(null);
  const [sending, setSending] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const [safetyModalOpen, setSafetyModalOpen] = useState(false);
  const [groupModalOpen, setGroupModalOpen] = useState(false);
  const [vaultModalOpen, setVaultModalOpen] = useState(false);

  useEffect(() => {
    if (initialOpenVault) {
      setVaultModalOpen(true);
    }
  }, [initialOpenVault]);

  const chatBodyRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const isFirstLoadRef = useRef(true);
  const syncInFlightRef = useRef(false);
  const syncQueuedRef = useRef(false);
  const loadMsgsInFlightRef = useRef(false);
  const loadMsgsQueuedRef = useRef(false);
  const syncCacheRef = useRef<Record<string, ConversationSyncEntry>>({});
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
      setVaultBoundUserId(null);
      setLocalDeviceId(null);
      setLocalEd25519Key('');
      setLocalCurve25519Key('');
      setMyDevices([]);
      setDmConversations([]);
      setOpenedPeers([]);
      setGroups([]);
      setSelectedPeer(null);
      setSelectedGroup(null);
      setMessages([]);
      setPeerSecurityWarnings([]);
      setPeerIsVerified(false);
      setSafetyNumber('');
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
      setLocalDeviceId(null);
      setLocalEd25519Key('');
      setLocalCurve25519Key('');
      setMyDevices([]);
      setDmConversations([]);
      setOpenedPeers([]);
      setGroups([]);
      setSelectedPeer(null);
      setSelectedGroup(null);
      setMessages([]);
      setPeerSecurityWarnings([]);
      setPeerIsVerified(false);
      setSafetyNumber('');
    }
  }, [e2eeProfile, vaultBoundUserId, account, activeTab, onModeChange]);

  // Ensure local Olm + MLS device keys are initialized & registered whenever session is active
  const ensureLocalDeviceVaultReady = useCallback(
    async (userObj: E2EEAccountProfile) => {
      const userId = userObj.user_id;
      if (vaultInitInFlightRef.current === userId) return;
      vaultInitInFlightRef.current = userId;
      try {
        const localDev = await getOrCreateLocalOlmDevice(userId, 'Browser E2EE Vault');
        const mlsPackages = localDev.isNewDevice
          ? await generateMlsKeyPackagesForDevice(userId, localDev.record.deviceId, 8)
          : [];

        const regRes = await registerE2EEDeviceBundle({
          ...localDev.registrationBundle,
          mls_key_packages: mlsPackages,
        });
        await markLocalPrekeysPublished(userId);

        if (
          regRes.available_counts.one_time_prekeys < 5 ||
          regRes.available_counts.mls_key_packages < 3
        ) {
          const moreOlm = await generateMoreOlmPrekeys(userId, 12, false);
          const moreMls = await generateMlsKeyPackagesForDevice(
            userId,
            localDev.record.deviceId,
            6
          );
          await replenishE2EEPrekeys(localDev.record.deviceId, {
            ...moreOlm,
            mls_key_packages: moreMls,
          });
          await markLocalPrekeysPublished(userId);
        }

        const freshMe = await fetchMyE2EEAccount();
        setE2eeProfile(freshMe.user);
        setMyDevices(freshMe.devices);
        setLocalDeviceId(localDev.record.deviceId);
        setVaultBoundUserId(userId);
        setLocalEd25519Key(localDev.record.ed25519Key);
        setLocalCurve25519Key(localDev.record.curve25519Key);
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
        setAuthError('SIWE wallet authentication signature declined.');
      } else {
        setAuthError(err?.message || 'Failed to initialize SIWE + E2EE session');
      }
    } finally {
      setAuthLoading(false);
    }
  }, [account, chainIdHex, authLoading, ensureLocalDeviceVaultReady]);

  const registerOpenedPeer = useCallback((peer: ResolvedPeerTarget) => {
    setOpenedPeers((prev) => {
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
            'This user has not unlocked an E2EE Vault yet. Ask them to Sign In once.'
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
            err?.message || 'Selected user has not unlocked an E2EE device vault yet.'
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

  const handleSearchDirectory = useCallback(async (q: string) => {
    setDirectoryLoading(true);
    setDirectoryStatusMsg(null);
    try {
      const res = await searchUsers(q, 30);
      setDirectoryUsers(res.users);
    } catch (err: any) {
      setDirectoryStatusMsg(err?.message || 'Directory search failed');
    } finally {
      setDirectoryLoading(false);
    }
  }, []);

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
    if (activeTab === 'dm' && !selectedPeer) {
      const timer = setTimeout(() => {
        handleSearchDirectory(directoryQuery);
      }, 250);
      return () => clearTimeout(timer);
    } else if (activeTab === 'groups' && !selectedGroup) {
      handleLoadDiscoverableGroups();
    }
  }, [activeTab, selectedPeer, selectedGroup, directoryQuery, handleSearchDirectory, handleLoadDiscoverableGroups]);

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
          alert('This user has not unlocked their E2EE Vault yet.');
          return;
        }
        registerOpenedPeer(resolved);
        setSelectedPeer(resolved);
        handleSelectChannelTab('dm');
      } catch (err: any) {
        alert(err?.message || `Could not resolve peer ${peerIdentifier}`);
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
        const [dmRes, welcomeRes] = await Promise.all([
          fetchMyDmConversations(),
          fetchPendingServerMlsWelcomes(localDeviceId, false),
        ]);
        setDmConversations(dmRes.conversations);

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
        if (selectedGroup) {
          const updatedSel =
            grpRes.groups.find((g) => g.group_id === selectedGroup.group_id) || null;
          setSelectedGroup(updatedSel);
        }
      } while (syncQueuedRef.current);
    } catch {
      // Non-fatal background sync error
    } finally {
      syncInFlightRef.current = false;
    }
  }, [isVaultReadyForProfile, e2eeProfile, localDeviceId, selectedGroup]);

  const handleRedeemInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inviteCodeInput.trim()) return;
    if (!account) {
      onConnectWallet();
      return;
    }
    if (needsE2EEAuth) {
      (onAuthenticateSiwe || authenticateE2EESession)();
      return;
    }
    setInviteRedeeming(true);
    setInviteStatusMsg(null);
    try {
      const res = await joinGroupByInviteCode(inviteCodeInput.trim());
      setInviteCodeInput('');
      setInviteStatusMsg(
        res.status === 'already_member'
          ? 'You are already an active member of this group.'
          : `Eligibility verified! Join request (${(res.request_id || '').slice(0, 10)}) queued for group admin MLS Welcome encryption.`
      );
      await syncSidebarLists();
      await handleLoadDiscoverableGroups();
    } catch (err: any) {
      setInviteStatusMsg(err?.message || 'Invite redemption failed');
    } finally {
      setInviteRedeeming(false);
    }
  };

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
        `Join request submitted for "${g.name}"! Group admins can now approve your MLS Welcome.`
      );
    } catch (err: any) {
      setInviteStatusMsg(err?.message || 'Join request denied by group policy');
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

  const loadActiveChannelMessages = useCallback(async () => {
    if (loadMsgsInFlightRef.current) {
      loadMsgsQueuedRef.current = true;
      return;
    }
    loadMsgsInFlightRef.current = true;
    try {
      do {
        loadMsgsQueuedRef.current = false;
        if (!isVaultReadyForProfile || !e2eeProfile || !localDeviceId) {
          setMessages([]);
          return;
        }

        // 1. PRIVATE 1-TO-1 CHAT (Olm v2 Double Ratchet)
        if (activeTab === 'dm') {
          if (!selectedPeer) {
            setMessages([]);
            return;
          }

          const dmScope = `dm|${selectedPeer.user_id}`;
          const dmCacheKey = `${e2eeProfile.user_id}|${localDeviceId}|${dmScope}`;
          const dmEntry: ConversationSyncEntry = syncCacheRef.current[dmCacheKey] || {
            lastSeq: 0,
            msgs: [],
            retry: {},
            lastReceiptSeq: 0,
          };
          syncCacheRef.current[dmCacheKey] = dmEntry;
          // Show what we already have instantly (also on channel switch); network only adds the new part.
          setMessages((prev) => mergeLocalEntries([...dmEntry.msgs], prev, dmScope));

          // Peer trust + safety number only need recomputing on first open, identity events, or every 30s.
          const secKey = `${e2eeProfile.user_id}|${selectedPeer.user_id}`;
          const cachedSec = peerSecCacheRef.current[secKey];
          if (!cachedSec || forceSecurityRefreshRef.current || Date.now() - cachedSec.at > 30000) {
            forceSecurityRefreshRef.current = false;
            const latestPeer = await fetchPeerActiveDevices(selectedPeer.user_id);
            const trust = await evaluateAndRecordPeerTrust(
              e2eeProfile.user_id,
              selectedPeer.user_id,
              latestPeer.identity_version,
              latestPeer.devices
            );
            const allVerified =
              latestPeer.devices.length > 0 &&
              latestPeer.devices.every((d) => trust.devices[d.device_id]?.verified);
            let sn: any = null;
            if (latestPeer.devices.length > 0 && localEd25519Key && localCurve25519Key) {
              const primaryDev = latestPeer.devices[0];
              sn = await computeSafetyNumber(
                {
                  userId: e2eeProfile.user_id,
                  ed25519Key: localEd25519Key,
                  curve25519Key: localCurve25519Key,
                },
                {
                  userId: selectedPeer.user_id,
                  ed25519Key: primaryDev.ed25519_identity_key,
                  curve25519Key: primaryDev.curve25519_identity_key,
                }
              );
            }
            peerSecCacheRef.current[secKey] = {
              at: Date.now(),
              warnings: trust.securityWarnings,
              verified: allVerified,
              safetyNumber: sn,
            };
          }
          const peerSec = peerSecCacheRef.current[secKey];
          setPeerSecurityWarnings(peerSec.warnings);
          setPeerIsVerified(peerSec.verified);
          if (peerSec.safetyNumber) setSafetyNumber(peerSec.safetyNumber);

          const resolveDm = async (rec: any) => {
            let cached = await loadVaultDecryptedMessage<E2EEPlaintextEnvelope>(
              e2eeProfile.user_id,
              rec.message_id
            );
            if (!cached) {
              const devCt = rec.device_ciphertexts[localDeviceId];
              if (devCt) {
                try {
                  cached = await decryptOlmDeviceCiphertext(
                    e2eeProfile.user_id,
                    rec.sender_curve25519_key,
                    devCt.message_type,
                    devCt.ciphertext_b64
                  );
                  await saveVaultDecryptedMessage(e2eeProfile.user_id, rec.message_id, cached);
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
            sender: rec.sender_user_id,
            message: cached ? cached.text : 'Encrypted with prior keys (Unrecoverable on this device)',
            attachments: cached?.attachments,
            isEncrypted: true,
            canDecrypt: Boolean(cached),
            timestamp: rec.timestamp,
            protocolBadge: 'OLM v2 E2EE',
          });

          // Retry only the few records that could not be decrypted earlier.
          for (const [mid, rec] of Object.entries(dmEntry.retry)) {
            const cached = await resolveDm(rec);
            if (cached) {
              delete dmEntry.retry[mid];
              dmEntry.msgs = dmEntry.msgs.map((m) => (m.id === mid ? dmToDisplay(rec, cached) : m));
            }
          }

          // Fetch ONLY messages newer than what we already hold (not the whole history every time).
          let currentDmSeq = dmEntry.lastSeq;
          const newDmMessages: any[] = [];
          while (true) {
            const dmFeed = await fetchOlmDmCiphertexts(selectedPeer.user_id, localDeviceId, currentDmSeq, 100);
            if (!dmFeed.messages || dmFeed.messages.length === 0) break;
            newDmMessages.push(...dmFeed.messages);
            const lastMsg = dmFeed.messages[dmFeed.messages.length - 1];
            if (lastMsg.seq <= currentDmSeq) break;
            currentDmSeq = lastMsg.seq;
            if (dmFeed.messages.length < 100) break;
          }

          let maxSeq = dmEntry.lastSeq;
          for (const rec of newDmMessages) {
            if (rec.seq > maxSeq) maxSeq = rec.seq;
            const cached = await resolveDm(rec);
            if (!cached) dmEntry.retry[rec.message_id] = rec;
            dmEntry.msgs.push(dmToDisplay(rec, cached));
          }
          dmEntry.lastSeq = maxSeq;
          const dmServerMsgs = [...dmEntry.msgs];
          setMessages((prev) => mergeLocalEntries(dmServerMsgs, prev, dmScope));

          // Optional DM read receipts - only when there is something newer to acknowledge
          if (maxSeq > dmEntry.lastReceiptSeq && e2eeProfile.send_read_receipts !== false) {
            dmEntry.lastReceiptSeq = maxSeq;
            sendDmReadReceipt(selectedPeer.user_id, maxSeq).catch(() => { });
          }
          fetchDmReadReceipts(selectedPeer.user_id)
            .then((r) => {
              const peerRec = r.receipts?.[selectedPeer.user_id];
              setPeerLastReadSeq(peerRec ? peerRec.last_read_seq : 0);
            })
            .catch(() => { });
          continue;
        }

        // 2. ENCRYPTED GROUP CHAT (RFC 9420 MLS TreeKEM)
        if (activeTab === 'groups') {
          if (!selectedGroup) {
            setMessages([]);
            return;
          }

          {
            const earlyKey = `${e2eeProfile.user_id}|${localDeviceId}|groups|${selectedGroup.group_id}`;
            const early = syncCacheRef.current[earlyKey];
            const earlyScope = `groups|${selectedGroup.group_id}`;
            setMessages((prev) => mergeLocalEntries(early ? [...early.msgs] : [], prev, earlyScope));
          }
          const secBefore = await getMlsGroupSecurityInfo(
            e2eeProfile.user_id,
            selectedGroup.group_id
          );
          const localEpoch = secBefore?.epoch ?? 0;
          const commitFeed = await fetchServerMlsCommits(selectedGroup.group_id, localEpoch);
          if (commitFeed.commits.length > 0) {
            const commitOutcome = await processIncomingMlsCommits(
              e2eeProfile.user_id,
              selectedGroup.group_id,
              commitFeed.commits
            );
            if (commitOutcome.selfRemoved) {
              setSelectedGroup(null);
              await syncSidebarLists();
              return;
            }
          }

          const secAfter = await getMlsGroupSecurityInfo(
            e2eeProfile.user_id,
            selectedGroup.group_id
          );
          setGroupSecurityInfo(secAfter);

          const grpScope = `groups|${selectedGroup.group_id}`;
          const grpCacheKey = `${e2eeProfile.user_id}|${localDeviceId}|${grpScope}`;
          const grpEntry: ConversationSyncEntry = syncCacheRef.current[grpCacheKey] || {
            lastSeq: 0,
            msgs: [],
            retry: {},
            lastReceiptSeq: 0,
          };
          syncCacheRef.current[grpCacheKey] = grpEntry;

          const resolveGrp = async (gm: any) => {
            let cached = await loadVaultDecryptedMessage<E2EEPlaintextEnvelope>(
              e2eeProfile.user_id,
              gm.message_id
            );
            if (!cached) {
              try {
                cached = await decryptMlsGroupMessage(
                  e2eeProfile.user_id,
                  selectedGroup.group_id,
                  gm.mls_ciphertext_b64
                );
                await saveVaultDecryptedMessage(e2eeProfile.user_id, gm.message_id, cached);
              } catch {
                cached = null;
              }
            }
            return cached;
          };
          const grpToDisplay = (gm: any, cached: E2EEPlaintextEnvelope | null): RichDisplayMessage => ({
            id: gm.message_id,
            seq: gm.seq,
            channel: selectedGroup.group_id,
            sender: gm.sender_user_id,
            message: cached
              ? cached.text
              : `Encrypted in Epoch #${gm.epoch} (Key not available on this device)`,
            attachments: cached?.attachments,
            epoch: gm.epoch,
            isEncrypted: true,
            canDecrypt: Boolean(cached),
            timestamp: gm.timestamp,
            protocolBadge: `MLS E#${gm.epoch}`,
          });

          for (const [mid, gm] of Object.entries(grpEntry.retry)) {
            const cached = await resolveGrp(gm);
            if (cached) {
              delete grpEntry.retry[mid];
              grpEntry.msgs = grpEntry.msgs.map((m) => (m.id === mid ? grpToDisplay(gm, cached) : m));
            }
          }

          // Fetch ONLY messages newer than what we already hold.
          let currentGrpSeq = grpEntry.lastSeq;
          const newGrpMessages: any[] = [];
          while (true) {
            const grpMsgs = await fetchServerMlsGroupMessages(selectedGroup.group_id, currentGrpSeq, 100);
            if (!grpMsgs.messages || grpMsgs.messages.length === 0) break;
            newGrpMessages.push(...grpMsgs.messages);
            const lastMsg = grpMsgs.messages[grpMsgs.messages.length - 1];
            if (lastMsg.seq <= currentGrpSeq) break;
            currentGrpSeq = lastMsg.seq;
            if (grpMsgs.messages.length < 100) break;
          }

          let grpMaxSeq = grpEntry.lastSeq;
          for (const gm of newGrpMessages) {
            if (gm.seq > grpMaxSeq) grpMaxSeq = gm.seq;
            const cached = await resolveGrp(gm);
            if (!cached) grpEntry.retry[gm.message_id] = gm;
            grpEntry.msgs.push(grpToDisplay(gm, cached));
          }
          grpEntry.lastSeq = grpMaxSeq;
          const grpServerMsgs = [...grpEntry.msgs];
          setMessages((prev) => mergeLocalEntries(grpServerMsgs, prev, grpScope));
        }
      } while (loadMsgsQueuedRef.current);
    } catch (err) {
      console.warn('Message sync error:', err);
    } finally {
      loadMsgsInFlightRef.current = false;
    }
  }, [
    activeTab,
    isVaultReadyForProfile,
    e2eeProfile,
    localDeviceId,
    localEd25519Key,
    localCurve25519Key,
    selectedPeer,
    selectedGroup,
    syncSidebarLists,
  ]);

  useEffect(() => {
    isFirstLoadRef.current = true;
    loadActiveChannelMessages();
    syncSidebarLists();
    const interval = setInterval(() => {
      loadActiveChannelMessages();
      syncSidebarLists();
    }, 4500);
    return () => clearInterval(interval);
  }, [loadActiveChannelMessages, syncSidebarLists]);

  useEffect(() => {
    if (!isVaultReadyForProfile) return;
    const sub = connectE2EEWebSocket((evt) => {
      if (
        evt.type === 'dm_ciphertext' ||
        evt.type === 'dm_read_receipt' ||
        evt.type === 'group_ciphertext' ||
        evt.type === 'group_commit' ||
        evt.type === 'group_welcome' ||
        evt.type === 'group_join_request' ||
        evt.type === 'group_member_left' ||
        evt.type === 'identity_event'
      ) {
        if (evt.type === 'identity_event') forceSecurityRefreshRef.current = true;
        loadActiveChannelMessages();
        syncSidebarLists();
      }
    });
    return () => sub.close();
  }, [isVaultReadyForProfile, loadActiveChannelMessages, syncSidebarLists]);

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
          'This member has not unlocked their E2EE Vault yet. Ask them to connect MetaMask & Sign In once.'
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
        err?.message || 'Could not find a verified member with that ID.'
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
          `${resolved.username ? `@${resolved.username}` : resolved.user_id} has not unlocked an E2EE Vault yet.`
        );
        return;
      }
      setPendingGroupMembers((prev) =>
        prev.some((m) => m.user_id === resolved.user_id) ? prev : [...prev, resolved]
      );
      setGroupMemberInput('');
    } catch (err: any) {
      setCreateGroupError(err?.message || `Member "${target}" not found.`);
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
      setCreateGroupError('Enter an entry fee greater than $0 for a paid group.');
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
            `${extraPeer.username ? `@${extraPeer.username}` : extraPeer.user_id} has not unlocked an E2EE Vault yet.`
          );
        }
        if (!finalMembers.some((m) => m.user_id === extraPeer.user_id)) {
          finalMembers = [...finalMembers, extraPeer];
        }
      }

      // 1. Initialize MLS Group at Epoch 0
      const localInit = await initializeNewMlsGroupLocal(e2eeProfile.user_id, localDeviceId);
      const created = await createServerMlsGroup({
        name: newGroupName.trim(),
        mls_group_id_b64: localInit.mlsGroupIdB64,
        creator_device_id: localDeviceId,
        ciphersuite: MLS_CIPHERSUITE_NAME,
        visibility: newGroupVisibility,
        min_level: 7,
        min_eth_balance_wei: parseEthStringToWeiString(newGroupMinEth),
        require_invitation: true,
        ...(isSuperadmin && newGroupPaid ? { is_paid: true, entry_fee_usd: feeUsd } : {}),
      });
      await localInit.finalizeWithServerGroupId(created.group.group_id);

      let activeGroupRecord = created.group;

      // 2. If members were selected, claim their MLS KeyPackages & batch-commit Epoch 1 + Welcomes
      if (finalMembers.length > 0) {
        const claimedAll: Array<{
          user_id: string;
          device_id: string;
          key_package_b64: string;
        }> = [];

        // Claim secondary devices for creator if any exist
        try {
          const myExtraPkgs = await claimPeerMlsKeyPackages(e2eeProfile.user_id);
          const filteredExtra = myExtraPkgs.filter((p) => p.device_id !== localDeviceId);
          claimedAll.push(...filteredExtra);
        } catch {
          // ignore if no other devices
        }

        for (const member of finalMembers) {
          const pkgs = await claimPeerMlsKeyPackages(member.user_id);
          if (pkgs.length === 0) {
            throw new Error(
              `${member.username ? `@${member.username}` : member.user_id} has no available MLS KeyPackages. Ask them to open Chats once to replenish.`
            );
          }
          claimedAll.push(...pkgs);
        }

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

      setNewGroupName('');
      setNewGroupPaid(false);
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
      setCreateGroupError(err?.message || 'Failed to create encrypted group');
    } finally {
      setCreatingGroupBusy(false);
    }
  };

  const handleAddGroupMember = async (identifier: string) => {
    if (!selectedGroup) return;
    const peer = await resolveE2EEPeer(identifier);
    const claimed = await claimPeerMlsKeyPackages(peer.user_id);
    if (claimed.length === 0) {
      throw new Error(`User ${identifier} has no active MLS KeyPackages available on the server. Ask them to unlock their vault.`);
    }
    await executeMlsCommitWithRetry(
      selectedGroup.group_id,
      () =>
        buildMlsAddMembersCommit(
          e2eeProfile!.user_id,
          selectedGroup.group_id,
          claimed
        ),
      'add'
    );
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

  const handleRotateGroupKey = async () => {
    if (!selectedGroup) return;
    await executeMlsCommitWithRetry(
      selectedGroup.group_id,
      () => buildMlsSelfKeyRotationCommit(e2eeProfile!.user_id, selectedGroup.group_id),
      'update'
    );
  };

  const handleSendMessage = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!account) {
      onConnectWallet();
      return;
    }

    const text = inputMessage.trim();
    const file = pendingFile;
    if ((!text && !file) || sending) return;
    if (!e2eeProfile || !localDeviceId) {
      alert('Authenticate your SIWE session & E2EE Vault first.');
      return;
    }
    const channelType: 'dm' | 'groups' = activeTab === 'dm' ? 'dm' : 'groups';
    const peer = selectedPeer;
    const group = selectedGroup;
    if ((channelType === 'dm' && !peer) || (channelType === 'groups' && !group)) return;

    const targetId = channelType === 'dm' ? peer!.user_id : group!.group_id;
    const scope = `${channelType}|${targetId}`;
    const msgId = `emsg_${crypto.randomUUID().replace(/-/g, '')}`;
    const displayText = text || (file ? `[Encrypted Attachment: ${file.name}]` : '');
    const myUserId = e2eeProfile.user_id;
    const sentAtIso = new Date().toISOString();

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
        protocolBadge: channelType === 'dm' ? 'OLM v2 E2EE' : 'MLS E2EE',
        sendStatus: 'sending',
        localScope: scope,
      },
    ]);
    setInputMessage('');
    setPendingFile(null);
    setTimeout(() => scrollToBottom(true), 20);

    const job = async () => {
      try {
        const attachments: EncryptedAttachmentKeyDescriptor[] = [];
        const attachmentIds: string[] = [];

        if (file) {
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
          sent_at: sentAtIso,
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
            throw new Error('Recipient has no active encryption keys registered. Transmission stopped for safety (plaintext fallback prohibited).');
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
          });
        }

        setMessages((prev) =>
          prev.map((m) => (m.id === msgId ? { ...m, sendStatus: 'delivered' as const } : m))
        );
        // Incremental sync: fetches only what is new (including this message) - fast and non-blocking.
        void loadActiveChannelMessages();
      } catch (err: any) {
        console.warn('Encrypted transmission rejected or failed:', err);
        const isKeyError =
          err?.message?.toLowerCase().includes('key') ||
          err?.message?.toLowerCase().includes('device') ||
          err?.message?.toLowerCase().includes('epoch');
        const safeError = isKeyError
          ? `Encryption keys unavailable or outdated: ${err?.message}. Refresh keys to proceed (never plaintext).`
          : (err?.message || 'Message was not sent (server rejected or database failed)');

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
          sendError: safeError,
          canRetry: !isKeyError,
          localScope: scope,
          failedPayload: {
            channelType,
            targetId,
            msgId: `emsg_${Date.now()}`,
            plainEnvelope: {
              v: 1,
              text: text || '',
              sent_at: new Date().toISOString(),
            },
            createdAt: Date.now(),
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
          throw new Error('Recipient has no active encryption keys registered. Please refresh keys.');
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
          attachment_ids: [],
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
          attachment_ids: [],
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

  const handleDownloadAttachment = async (att: EncryptedAttachmentKeyDescriptor) => {
    try {
      const scopeType = activeTab === 'dm' ? 'dm' : 'group';
      const blobRes = await downloadEncryptedAttachmentBlob(att.attachment_id);
      const decryptedBytes = await decryptAttachmentOnDevice(
        blobRes.attachment.ciphertext_b64,
        att,
        scopeType
      );
      const copyBuf = new Uint8Array(decryptedBytes.byteLength);
      copyBuf.set(decryptedBytes);
      const blob = new Blob([copyBuf.buffer], { type: att.mime_type });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = att.file_name;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    } catch (err: any) {
      alert(err?.message || 'Attachment integrity verification or decryption failed');
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
          <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Radio size={16} className="pulse-icon" /> Chats
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            {e2eeProfile && (
              <button
                type="button"
                className="btn-outline"
                style={{ padding: '4px 8px', fontSize: '0.7rem' }}
                onClick={() => setVaultModalOpen(true)}
                title="Manage Permanent Identity, Wallets & Device Keys"
              >
                <KeyRound size={12} />
                <span>Vault</span>
              </button>
            )}
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
            <Globe size={16} />
            <span>Open Chat</span>
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
                  <Plus size={15} />
                  <span>+Add</span>
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
                    <Users size={15} />
                    <div>
                      <div>Create Group</div>
                      <div style={{ fontSize: '0.7rem', fontWeight: 400, color: 'var(--text-muted)' }}>
                        Name a group &amp; add members
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
                    <UserPlus size={15} />
                    <div>
                      <div>Chat Individual</div>
                      <div style={{ fontSize: '0.7rem', fontWeight: 400, color: 'var(--text-muted)' }}>
                        Enter member ID to chat 1-to-1
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
                fontSize: '0.74rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px',
              }}
            >
              <div style={{ color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                MetaMask switched to <code>{formatAddress(account, 4)}</code>. Sign in to use this
                wallet&apos;s E2EE vault, or link it inside <strong>Vault</strong>.
              </div>
              <button
                type="button"
                className="btn-solid"
                style={{ padding: '6px 10px', fontSize: '0.74rem', justifyContent: 'center' }}
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
                  <span>Groups ({groups.length})</span>
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedGroup(null);
                      handleSelectChannelTab('groups');
                    }}
                    style={{
                      background: 'transparent',
                      border: 'none',
                      color: 'var(--text-secondary)',
                      fontSize: '0.68rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                      padding: 0,
                      textTransform: 'none',
                    }}
                    title="Redeem invite code or browse public groups"
                  >
                    Invites / Public &rarr;
                  </button>
                </div>

                {groups.length === 0 ? (
                  <div
                    style={{
                      fontSize: '0.73rem',
                      color: 'var(--text-muted)',
                      padding: '4px 4px 2px',
                    }}
                  >
                    No groups yet — click <strong>+Add &rarr; Create Group</strong>.
                  </div>
                ) : (
                  groups.map((g) => {
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
                        </span>
                        <span style={{ fontSize: '0.66rem', fontFamily: 'ui-monospace, monospace' }}>
                          E#{g.current_epoch}
                        </span>
                      </button>
                    );
                  })
                )}
              </div>

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
                      <span>Individual Chats ({combinedPeers.length})</span>
                      <button
                        type="button"
                        onClick={() => {
                          setSelectedPeer(null);
                          handleSelectChannelTab('dm');
                        }}
                        style={{
                          background: 'transparent',
                          border: 'none',
                          color: 'var(--text-secondary)',
                          fontSize: '0.68rem',
                          fontWeight: 600,
                          cursor: 'pointer',
                          padding: 0,
                          textTransform: 'none',
                        }}
                        title="Browse username directory"
                      >
                        Directory &rarr;
                      </button>
                    </div>

                    {combinedPeers.length === 0 ? (
                      <div
                        style={{
                          fontSize: '0.73rem',
                          color: 'var(--text-muted)',
                          padding: '4px 4px 2px',
                        }}
                      >
                        No individual chats — click <strong>+Add &rarr; Chat Individual</strong>.
                      </div>
                    ) : (
                      combinedPeers.map((peerItem) => {
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
                            onClick={async () => {
                              setMobileRailOpen(false);
                              const cachedOpened = openedPeers.find(
                                (p) => p.user_id === peerItem.user_id
                              );
                              if (cachedOpened) {
                                setSelectedPeer(cachedOpened);
                                handleSelectChannelTab('dm');
                              }
                              try {
                                const freshPeer = await resolveE2EEPeer(peerItem.user_id);
                                registerOpenedPeer(freshPeer);
                                setSelectedPeer(freshPeer);
                                handleSelectChannelTab('dm');
                              } catch {
                                // keep cached peer if offline
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
                            <Lock size={11} style={{ flexShrink: 0 }} />
                          </button>
                        );
                      })
                    )}
                  </div>
                );
              })()}
            </>
          )}

          {/* Global Public Room Info Card */}
          <div
            style={{
              padding: '10px 12px',
              borderRadius: '8px',
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              fontSize: '0.74rem',
              color: 'var(--text-secondary)',
              lineHeight: 1.45,
            }}
          >
            <div style={{ fontWeight: 600, color: 'var(--text-main)', marginBottom: '4px' }}>
              Global Public Room
            </div>
            <div>
              {account ? (
                <>
                  Open to all members in real time. Click <strong>+Add</strong> above to{' '}
                  <strong>Create Group</strong> or <strong>Chat Individual</strong> with end-to-end
                  encryption.
                </>
              ) : (
                <>
                  Open to all members in real time. Connect MetaMask to chat or start end-to-end
                  encrypted Groups and Individual Chats.
                </>
              )}
            </div>
          </div>
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
                <Menu size={14} />
                <span>Chats</span>
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
                          : 'Username Directory'}
                      </span>
                      {selectedPeer && (
                        <span className="audit-status">
                          {peerIsVerified ? 'VERIFIED' : 'PRIVATE CHAT'}
                        </span>
                      )}
                    </>
                  )}
                  {activeTab === 'groups' && (
                    <>
                      <span>{selectedGroup ? selectedGroup.name : 'Encrypted Groups & Invites'}</span>
                      {selectedGroup && (
                        <span className="audit-status">
                          EPOCH #{selectedGroup.current_epoch}
                          {selectedGroup.policy?.is_paid
                            ? ` • PAID (${formatGroupFee(selectedGroup.policy)})`
                            : ''}
                        </span>
                      )}
                    </>
                  )}
                </div>
                <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                  {activeTab === 'dm' &&
                    (selectedPeer
                      ? `Permanent Peer ID: ${selectedPeer.user_id} • Forward-Secret Curve25519 + Ed25519`
                      : 'Search verified accounts by unique @username or wallet to start Private Chats')}
                  {activeTab === 'groups' &&
                    (selectedGroup
                      ? `Encrypted Group (${selectedGroup.members.filter((m) => m.status === 'active').length} active devices) • Strict pre-join & post-removal secrecy`
                      : 'Redeem an invite code or browse public groups')}
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap', flexShrink: 0 }}>
              {activeTab === 'dm' && selectedPeer && (
                <button
                  type="button"
                  className="btn-outline"
                  style={{ padding: '6px 10px', fontSize: '0.74rem' }}
                  onClick={() => setSelectedPeer(null)}
                  title="Back to Username Directory"
                >
                  <Search size={13} />
                  <span>Directory</span>
                </button>
              )}

              {activeTab === 'groups' && selectedGroup && (
                <button
                  type="button"
                  className="btn-outline"
                  style={{ padding: '6px 10px', fontSize: '0.74rem' }}
                  onClick={() => setSelectedGroup(null)}
                  title="Back to Public Groups & Invites"
                >
                  <Compass size={13} />
                  <span>Browse Groups</span>
                </button>
              )}

              {activeTab === 'dm' && selectedPeer && e2eeProfile && (
                <>
                  <button
                    type="button"
                    className="btn-outline"
                    style={{ padding: '6px 10px', fontSize: '0.74rem' }}
                    onClick={() => setSafetyModalOpen(true)}
                  >
                    {peerIsVerified ? <ShieldCheck size={14} /> : <ShieldAlert size={14} />}
                    <span>{peerIsVerified ? 'Verified' : 'Verify Keys'}</span>
                  </button>
                  <button
                    type="button"
                    className="btn-outline"
                    style={{ padding: '6px 10px', fontSize: '0.74rem' }}
                    title="Block User"
                    onClick={async () => {
                      if (!confirm(`Block ${selectedPeer.username || selectedPeer.user_id}?`)) return;
                      try {
                        await blockUser(selectedPeer.user_id, 'Blocked from Private Chat');
                        alert('User blocked. Server will reject new messages from this user.');
                      } catch (err: any) {
                        alert(err?.message || 'Block failed');
                      }
                    }}
                  >
                    <Ban size={13} />
                  </button>
                  <button
                    type="button"
                    className="btn-outline"
                    style={{ padding: '6px 10px', fontSize: '0.74rem' }}
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
                        alert(err?.message || 'Report failed');
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
                  style={{ padding: '6px 12px', fontSize: '0.76rem' }}
                  onClick={() => setGroupModalOpen(true)}
                >
                  <ShieldCheck size={14} />
                  <span>Governance, Policy &amp; Keys</span>
                </button>
              )}
            </div>
          </div>

          {/* Non-Silent Peer Identity Key Change Warning Banner */}
          {activeTab === 'dm' && peerSecurityWarnings.length > 0 && (
            <div
              style={{
                padding: '10px 20px',
                background: 'var(--bg-surface)',
                borderBottom: '1px solid var(--border-strong)',
                fontSize: '0.76rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '12px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <ShieldAlert size={16} style={{ flexShrink: 0 }} />
                <span>{peerSecurityWarnings[peerSecurityWarnings.length - 1]}</span>
              </div>
              <button
                type="button"
                className="btn-outline"
                style={{ padding: '4px 10px', fontSize: '0.72rem' }}
                onClick={() => setSafetyModalOpen(true)}
              >
                Review Safety Number
              </button>
            </div>
          )}

          {/* Viewport Content Case 1: Private Chats Directory View */}
          {activeTab === 'dm' && !selectedPeer && (
            <div
              style={{
                flex: 1,
                overflowY: 'auto',
                padding: '24px',
                display: 'flex',
                flexDirection: 'column',
                gap: '18px',
                maxWidth: '900px',
                width: '100%',
                margin: '0 auto',
              }}
            >
              <div className="deck-card" style={{ padding: '20px' }}>
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
                      <Search size={18} />
                      <span>Username Directory</span>
                    </div>
                    <div
                      className="deck-subtitle"
                      style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '4px' }}
                    >
                      Search verified accounts by unique <code>@username</code> or
                      wallet to start Private Chats.
                    </div>
                  </div>
                </div>

                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    handleSearchDirectory(directoryQuery);
                  }}
                  style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}
                >
                  <input
                    type="text"
                    placeholder="Search @username or wallet..."
                    value={directoryQuery}
                    onChange={(e) => {
                      setDirectoryQuery(e.target.value);
                      handleSearchDirectory(e.target.value);
                    }}
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
                  <button
                    type="submit"
                    className="btn-solid"
                    disabled={directoryLoading}
                    style={{ padding: '0 18px' }}
                  >
                    <Search size={14} />
                    <span>Search</span>
                  </button>
                </form>

                {directoryStatusMsg && (
                  <div
                    style={{
                      padding: '8px 12px',
                      marginBottom: '12px',
                      background: 'var(--bg-input)',
                      border: '1px solid var(--border-strong)',
                      borderRadius: '8px',
                      fontSize: '0.8rem',
                      color: 'var(--text-secondary)',
                    }}
                  >
                    {directoryStatusMsg}
                  </div>
                )}

                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {directoryUsers.length === 0 ? (
                    <div
                      style={{
                        color: 'var(--text-muted)',
                        fontSize: '0.84rem',
                        padding: '24px 0',
                        textAlign: 'center',
                      }}
                    >
                      {directoryLoading ? 'Searching directory...' : 'No matching accounts found.'}
                    </div>
                  ) : (
                    directoryUsers.map((u) => {
                      const isMe = e2eeProfile && u.user_id === e2eeProfile.user_id;
                      return (
                        <div
                          key={u.user_id}
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            padding: '12px 16px',
                            background: 'var(--bg-input)',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: '12px',
                            gap: '12px',
                            flexWrap: 'wrap',
                          }}
                        >
                          <div>
                            <div
                              style={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: '8px',
                                fontWeight: 600,
                              }}
                            >
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
                              {isMe && (
                                <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                                  (You)
                                </span>
                              )}
                            </div>
                            {u.bio && (
                              <div
                                style={{
                                  fontSize: '0.78rem',
                                  color: 'var(--text-secondary)',
                                  marginTop: '3px',
                                }}
                              >
                                {u.bio}
                              </div>
                            )}
                          </div>

                          {!isMe && (
                            <div style={{ display: 'flex', gap: '6px' }}>
                              <button
                                type="button"
                                className="btn-solid"
                                style={{ padding: '6px 14px', fontSize: '0.76rem' }}
                                onClick={() => {
                                  if (!account) {
                                    onConnectWallet();
                                    return;
                                  }
                                  if (needsE2EEAuth) {
                                    (onAuthenticateSiwe || authenticateE2EESession)();
                                    return;
                                  }
                                  handleSelectPeerFromDirectory(
                                    u.username ? `@${u.username}` : u.user_id
                                  );
                                }}
                              >
                                <Lock size={12} />
                                <span>Message</span>
                              </button>
                              {e2eeProfile && (
                                <button
                                  type="button"
                                  className="btn-outline"
                                  style={{ padding: '6px 10px', fontSize: '0.74rem' }}
                                  title="Block User"
                                  onClick={async () => {
                                    await blockUser(u.user_id, 'Blocked from directory');
                                    setDirectoryStatusMsg(
                                      `Blocked ${u.username ? `@${u.username}` : u.user_id}`
                                    );
                                  }}
                                >
                                  <Ban size={12} />
                                </button>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
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
              {/* Left Card: Redeem Invite Code */}
              <div className="deck-card" style={{ padding: '20px' }}>
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
                      <Link2 size={18} />
                      <span>Redeem Group Invite</span>
                    </div>
                    <div
                      className="deck-subtitle"
                      style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '4px' }}
                    >
                      Enter a group invite code (<code>zinv_...</code>) to verify wallet qualifications
                      and join.
                    </div>
                  </div>
                </div>

                {inviteStatusMsg && (
                  <div
                    style={{
                      padding: '10px 12px',
                      marginBottom: '14px',
                      background: 'var(--bg-input)',
                      border: '1px solid var(--border-strong)',
                      borderRadius: '8px',
                      fontSize: '0.8rem',
                      lineHeight: 1.4,
                    }}
                  >
                    {inviteStatusMsg}
                  </div>
                )}

                <form
                  onSubmit={handleRedeemInvite}
                  style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}
                >
                  <input
                    type="text"
                    placeholder="Paste invite code (zinv_...)"
                    value={inviteCodeInput}
                    onChange={(e) => setInviteCodeInput(e.target.value)}
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
                  <button
                    type="submit"
                    className="btn-solid"
                    disabled={inviteRedeeming || !inviteCodeInput.trim()}
                    style={{ padding: '0 16px' }}
                  >
                    <Link2 size={14} />
                    <span>{inviteRedeeming ? 'Redeeming...' : 'Redeem'}</span>
                  </button>
                </form>

                <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                  Group invites provide end-to-end encrypted group admission. An existing group admin
                  will seal your initial welcome bundle.
                </div>
              </div>

              {/* Right Card: Discoverable Public Groups */}
              <div className="deck-card" style={{ padding: '20px' }}>
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
                      style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '4px' }}
                    >
                      Browse public groups or request entry when your wallet meets
                      requirements.
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {discoverableGroups.length === 0 ? (
                    <div
                      style={{
                        fontSize: '0.82rem',
                        color: 'var(--text-muted)',
                        padding: '24px 0',
                        textAlign: 'center',
                      }}
                    >
                      {groupsLoading
                        ? 'Loading discoverable groups...'
                        : 'No public groups listed yet. Create one in the sidebar!'}
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
                          <div
                            style={{
                              fontSize: '0.74rem',
                              color: 'var(--text-secondary)',
                              marginTop: '2px',
                            }}
                          >
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
                            <div
                              style={{
                                fontSize: '0.74rem',
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
                            style={{ padding: '6px 14px', fontSize: '0.75rem' }}
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
                            Pay &amp; Join Group
                          </button>
                        ) : (
                          <button
                            type="button"
                            className="btn-solid"
                            style={{ padding: '6px 14px', fontSize: '0.75rem' }}
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
                    fontSize: '0.84rem',
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
                  Sign In with Ethereum (SIWE) &amp; Unlock Vault
                </h3>
                <p
                  style={{
                    color: 'var(--text-muted)',
                    fontSize: '0.84rem',
                    maxWidth: '420px',
                    lineHeight: 1.5,
                    margin: '0 0 16px 0',
                  }}
                >
                  Sign a single-use EIP-4361 challenge to authenticate your permanent account and
                  unlock your on-device encryption keys.
                </p>
                {authError && (
                  <div
                    style={{
                      fontSize: '0.78rem',
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
                      ? 'Signing SIWE & Unlocking...'
                      : 'Sign SIWE & Unlock E2EE'}
                  </span>
                </button>
              </div>
            ) : (
              <>
                {/* Message Stream */}
                <div className="chat-stream-body" ref={chatBodyRef}>
                  {messages.length === 0 ? (
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
                      <div style={{ fontWeight: 500, fontSize: '0.98rem' }}>
                        No encrypted transmissions yet
                      </div>
                      <div style={{ fontSize: '0.82rem', maxWidth: '340px' }}>
                        {activeTab === 'dm'
                          ? 'Search a peer by @username, permanent user_id, or 0x wallet in the left rail.'
                          : 'Create or select an RFC 9420 MLS group to exchange TreeKEM-encrypted messages.'}
                      </div>
                    </div>
                  ) : (
                    messages.map((msg, index) => {
                      const isMe = Boolean(e2eeProfile && msg.sender === e2eeProfile.user_id);
                      const initials = msg.sender.slice(4, 6).toUpperCase() || 'E2';
                      const isReadByPeer =
                        activeTab === 'dm' && isMe && msg.seq && peerLastReadSeq >= msg.seq;

                      return (
                        <div
                          key={msg.id || index}
                          className="chat-message-row"
                          style={{
                            display: 'flex',
                            flexDirection: isMe ? 'row-reverse' : 'row',
                            alignItems: 'flex-start',
                            gap: '12px',
                            maxWidth: '80%',
                            alignSelf: isMe ? 'flex-end' : 'flex-start',
                          }}
                        >
                          <div
                            className="chat-avatar"
                            style={{
                              width: '32px',
                              height: '32px',
                              borderRadius: '8px',
                              fontSize: '0.74rem',
                              fontWeight: 600,
                              flexShrink: 0,
                              background: isMe ? 'var(--text-main)' : 'var(--bg-input)',
                              color: isMe ? 'var(--text-inverse)' : 'var(--text-main)',
                              border: '1px solid var(--border-strong)',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              fontFamily: 'ui-monospace, monospace',
                            }}
                          >
                            {initials}
                          </div>

                          <div
                            className="chat-packet"
                            style={{
                              display: 'flex',
                              flexDirection: 'column',
                              alignItems: isMe ? 'flex-end' : 'flex-start',
                            }}
                          >
                            <div
                              className="chat-msg-header"
                              style={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: '6px',
                                marginBottom: '4px',
                                fontSize: '0.72rem',
                                color: 'var(--text-muted)',
                              }}
                            >
                              <span
                                style={{
                                  fontWeight: 600,
                                  color: 'var(--text-main)',
                                  fontFamily: 'ui-monospace, monospace',
                                }}
                              >
                                {(() => {
                                  if (isMe) return 'You';
                                  if (
                                    activeTab === 'dm' &&
                                    selectedPeer &&
                                    msg.sender === selectedPeer.user_id &&
                                    selectedPeer.username
                                  ) {
                                    return `@${selectedPeer.username}`;
                                  }
                                  if (activeTab === 'groups' && selectedGroup) {
                                    const gm = selectedGroup.members.find(
                                      (m) => m.user_id === msg.sender && m.username
                                    );
                                    if (gm?.username) return `@${gm.username}`;
                                  }
                                  return msg.sender.slice(0, 12);
                                })()}
                              </span>
                              <button
                                onClick={() => handleCopy(msg.sender, msg.id)}
                                className="chat-copy-btn"
                                title="Copy Permanent User ID"
                              >
                                {copiedId === msg.id ? <Check size={11} /> : <Copy size={11} />}
                              </button>
                              <span>&bull;</span>
                              <span>
                                {new Date(msg.timestamp).toLocaleTimeString([], {
                                  hour: '2-digit',
                                  minute: '2-digit',
                                })}
                              </span>
                              <span
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '3px',
                                  fontSize: '0.66rem',
                                  fontWeight: 600,
                                  padding: '1px 6px',
                                  borderRadius: '4px',
                                  border: '1px solid var(--border-subtle)',
                                }}
                              >
                                <Lock size={9} />
                                {msg.protocolBadge || 'E2EE'}
                              </span>
                              {msg.sendStatus === 'sending' && (
                                <span style={{ opacity: 0.7, fontStyle: 'italic' }}>Sending…</span>
                              )}
                              {isReadByPeer && (
                                <span
                                  title="Read by peer"
                                  style={{ display: 'inline-flex', alignItems: 'center', gap: '2px' }}
                                >
                                  <CheckCheck size={12} />
                                </span>
                              )}
                            </div>

                            <div
                              className={`chat-message-bubble ${isMe ? 'bubble-me' : 'bubble-peer'}`}
                              style={{
                                padding: '12px 16px',
                                borderRadius: isMe ? '14px 14px 2px 14px' : '14px 14px 14px 2px',
                                background: isMe ? 'var(--text-main)' : 'var(--bg-input)',
                                color: isMe ? 'var(--text-inverse)' : 'var(--text-main)',
                                fontSize: '0.9rem',
                                lineHeight: '1.45',
                                wordBreak: 'break-word',
                              }}
                            >
                              {!msg.canDecrypt ? (
                                <div
                                  style={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '8px',
                                    opacity: 0.82,
                                    fontStyle: 'italic',
                                    fontSize: '0.82rem',
                                  }}
                                >
                                  <Lock size={13} style={{ flexShrink: 0 }} />
                                  <span>{msg.message}</span>
                                </div>
                              ) : (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                  <span>{msg.message}</span>
                                  {msg.attachments &&
                                    msg.attachments.map((att) => (
                                      <button
                                        key={att.attachment_id}
                                        type="button"
                                        onClick={() => handleDownloadAttachment(att)}
                                        style={{
                                          display: 'inline-flex',
                                          alignItems: 'center',
                                          gap: '6px',
                                          padding: '6px 10px',
                                          borderRadius: '8px',
                                          border: '1px solid currentColor',
                                          background: 'transparent',
                                          color: 'inherit',
                                          fontSize: '0.76rem',
                                          cursor: 'pointer',
                                        }}
                                      >
                                        <Download size={12} />
                                        <span>
                                          Decrypt {att.file_name} ({Math.ceil(att.size_bytes / 1024)} KB)
                                        </span>
                                      </button>
                                    ))}
                                </div>
                              )}
                            </div>

                            {msg.sendStatus === 'failed' && (
                              <div
                                style={{
                                  display: 'flex',
                                  alignItems: 'center',
                                  gap: '6px',
                                  marginTop: '6px',
                                  fontSize: '0.72rem',
                                  color: 'var(--color-danger, #ef4444)',
                                  background: 'rgba(239, 68, 68, 0.08)',
                                  padding: '5px 10px',
                                  borderRadius: '6px',
                                  border: '1px solid rgba(239, 68, 68, 0.25)',
                                  maxWidth: '100%',
                                  wordBreak: 'break-word',
                                }}
                              >
                                <AlertCircle size={13} style={{ flexShrink: 0 }} />
                                <span style={{ flex: 1 }}>{msg.sendError || 'Message was not sent'}</span>
                                {msg.canRetry && (
                                  <button
                                    type="button"
                                    className="btn-outline"
                                    style={{
                                      padding: '2px 8px',
                                      fontSize: '0.7rem',
                                      borderRadius: '4px',
                                      borderColor: 'currentColor',
                                      color: 'inherit',
                                      cursor: 'pointer',
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '3px',
                                    }}
                                    onClick={() => handleRetryFailedMessage(msg)}
                                    disabled={sending}
                                    title="Retry sending with safe encrypted payload"
                                  >
                                    <RotateCcw size={10} />
                                    <span>Retry</span>
                                  </button>
                                )}
                              </div>
                            )}
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>

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
                        <strong>Platform Admission Required:</strong> Pay the one-time ETH entry fee to send encrypted messages.
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
                      onSubmit={handleSendMessage}
                      style={{ display: 'flex', alignItems: 'center', gap: '10px', width: '100%' }}
                    >
                      <input
                        ref={fileInputRef}
                        type="file"
                        style={{ display: 'none' }}
                        onChange={(e) => {
                          const f = e.target.files?.[0] || null;
                          setPendingFile(f);
                          e.target.value = '';
                        }}
                      />
                      <button
                        type="button"
                        className="btn-outline"
                        style={{
                          width: '40px',
                          height: '40px',
                          borderRadius: '50%',
                          padding: 0,
                          justifyContent: 'center',
                        }}
                        disabled={
                          sending ||
                          (activeTab === 'dm' && !selectedPeer) ||
                          (activeTab === 'groups' && !selectedGroup)
                        }
                        onClick={() => fileInputRef.current?.click()}
                        title="Attach E2EE Encrypted File"
                      >
                        <Paperclip size={15} />
                      </button>

                      <input
                        type="text"
                        placeholder={
                          pendingFile
                            ? `Attached E2EE file: ${pendingFile.name} — add caption or press send...`
                            : activeTab === 'dm'
                              ? selectedPeer
                                ? 'Type an encrypted private message...'
                                : 'Select a peer first...'
                              : selectedGroup
                                ? `Message ${selectedGroup.name}...`
                                : 'Select or create a group first...'
                        }
                        value={inputMessage}
                        onChange={(e) => setInputMessage(e.target.value)}
                        disabled={
                          sending ||
                          (activeTab === 'dm' && !selectedPeer) ||
                          (activeTab === 'groups' && !selectedGroup)
                        }
                        style={{
                          flex: 1,
                          background: 'var(--bg-input)',
                          border: '1px solid var(--border-strong)',
                          borderRadius: '9999px',
                          padding: '12px 20px',
                          fontSize: '0.9rem',
                          color: 'var(--text-main)',
                          outline: 'none',
                        }}
                      />

                      <button
                        type="submit"
                        disabled={
                          (!inputMessage.trim() && !pendingFile) ||
                          sending ||
                          (activeTab === 'dm' && !selectedPeer) ||
                          (activeTab === 'groups' && !selectedGroup)
                        }
                        className="btn-solid"
                        style={{
                          width: '44px',
                          height: '44px',
                          borderRadius: '50%',
                          padding: 0,
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                        }}
                        title="Encrypt & Transmit"
                      >
                        <Send size={16} />
                      </button>
                    </form>
                  )}
                </div>
              </>
            ))}
        </div>
      )}

      {/* Modals */}
      {selectedPeer && e2eeProfile && (
        <SafetyNumberModal
          open={safetyModalOpen}
          onClose={() => setSafetyModalOpen(false)}
          localUserId={e2eeProfile.user_id}
          localEd25519Key={localEd25519Key}
          peerUserId={selectedPeer.user_id}
          peerDisplayName={
            selectedPeer.username
              ? `@${selectedPeer.username}`
              : selectedPeer.primary_wallet || selectedPeer.user_id
          }
          peerIdentityVersion={selectedPeer.identity_version}
          peerDevices={selectedPeer.devices}
          safetyNumber={safetyNumber}
          isVerified={peerIsVerified}
          onMarkVerified={async () => {
            await markPeerDevicesVerified(e2eeProfile.user_id, selectedPeer.user_id);
            setPeerIsVerified(true);
            setPeerSecurityWarnings([]);
          }}
          onResetSession={async () => {
            for (const d of selectedPeer.devices) {
              await resetOlmSessionWithPeerDevice(
                e2eeProfile.user_id,
                d.curve25519_identity_key
              );
            }
          }}
        />
      )}

      {selectedGroup && e2eeProfile && (
        <MlsGroupSecurityModal
          open={groupModalOpen}
          onClose={() => setGroupModalOpen(false)}
          group={selectedGroup}
          currentUserId={e2eeProfile.user_id}
          epochVerifyCode={groupSecurityInfo?.exportedContextVerifyCode || ''}
          epochAuthenticatorHex={groupSecurityInfo?.epochAuthenticatorHex || ''}
          onAddMember={handleAddGroupMember}
          onRemoveMember={handleRemoveGroupMember}
          onRotateOwnKey={handleRotateGroupKey}
          onLeaveGroup={async () => {
            const gid = selectedGroup.group_id;
            await leaveEncryptedGroup(gid);
            await clearLocalMlsGroupState(e2eeProfile.user_id, gid);
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
                  <h3 style={{ fontSize: '1.02rem', fontWeight: 700, margin: 0 }}>Create Group</h3>
                  <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                    Name your group &amp; add members with RFC 9420 MLS encryption
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
                  fontSize: '0.78rem',
                }}
              >
                <span>Connect MetaMask to create an encrypted group.</span>
                <button
                  type="button"
                  className="btn-solid"
                  style={{ padding: '7px 14px', fontSize: '0.76rem' }}
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
                  fontSize: '0.78rem',
                }}
              >
                <span>
                  {isWalletMismatch
                    ? `Sign in as ${formatAddress(account, 4)} to unlock your E2EE Vault.`
                    : 'Sign SIWE challenge to unlock your on-device E2EE Vault.'}
                </span>
                <button
                  type="button"
                  className="btn-solid"
                  style={{ padding: '7px 14px', fontSize: '0.76rem' }}
                  disabled={siweLoading || authLoading}
                  onClick={onAuthenticateSiwe || authenticateE2EESession}
                >
                  <KeyRound size={13} />
                  <span>{siweLoading || authLoading ? 'Signing...' : 'Sign In & Unlock'}</span>
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
                  fontSize: '0.78rem',
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
                <label style={{ fontSize: '0.76rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                  Group Name
                </label>
                <input
                  type="text"
                  autoFocus
                  placeholder="Enter group name..."
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
                <label style={{ fontSize: '0.76rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                  Add Members (Optional — by <code>@username</code>, <code>usr_...</code>, or{' '}
                  <code>0x...</code>)
                </label>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <input
                    type="text"
                    placeholder="Type member ID (@username, usr_..., or 0x...)"
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
                      fontSize: '0.82rem',
                      fontFamily: 'ui-monospace, monospace',
                      outline: 'none',
                    }}
                  />
                  <button
                    type="button"
                    className="btn-outline"
                    disabled={!groupMemberInput.trim() || addingGroupMemberBusy}
                    onClick={() => handleStageMemberForGroup()}
                    style={{ padding: '0 14px', fontSize: '0.78rem', flexShrink: 0 }}
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
                          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
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
                style={{ padding: '6px 10px', fontSize: '0.74rem', justifyContent: 'center' }}
                onClick={() => setShowGroupOpts((p) => !p)}
              >
                {showGroupOpts
                  ? 'Hide Access Policy Options'
                  : `Access Policy: ${newGroupVisibility === 'public' ? 'Public Discovery' : 'Invite Only'} • Min ETH ${newGroupMinEth || '0'}`}
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
                    fontSize: '0.74rem',
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
                        background: 'var(--bg-input)',
                        border: '1px solid var(--border-strong)',
                        color: 'var(--text-main)',
                        borderRadius: '6px',
                        padding: '6px',
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
                        background: 'var(--bg-input)',
                        border: '1px solid var(--border-strong)',
                        color: 'var(--text-main)',
                        borderRadius: '6px',
                        padding: '6px',
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
                    fontSize: '0.78rem',
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
                        Entry fee in US dollars (members pay the ETH equivalent)
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
                  style={{ padding: '7px 12px', fontSize: '0.75rem' }}
                  onClick={() => {
                    setCreateGroupModalOpen(false);
                    setSelectedGroup(null);
                    handleSelectChannelTab('groups');
                  }}
                >
                  <Link2 size={13} />
                  <span>Have Invite Code?</span>
                </button>

                <button
                  type="submit"
                  className="btn-solid"
                  disabled={creatingGroupBusy || !newGroupName.trim()}
                  style={{ padding: '9px 18px', fontSize: '0.84rem' }}
                >
                  <Users size={15} />
                  <span>
                    {creatingGroupBusy
                      ? 'Creating Group...'
                      : pendingGroupMembers.length > 0
                        ? `Create Group (${pendingGroupMembers.length + 1})`
                        : 'Create Group'}
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
                  <h3 style={{ fontSize: '1.02rem', fontWeight: 700, margin: 0 }}>
                    Chat Individual
                  </h3>
                  <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
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
                  fontSize: '0.78rem',
                }}
              >
                <span>Connect MetaMask to start an encrypted individual chat.</span>
                <button
                  type="button"
                  className="btn-solid"
                  style={{ padding: '7px 14px', fontSize: '0.76rem' }}
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
                  fontSize: '0.78rem',
                }}
              >
                <span>
                  {isWalletMismatch
                    ? `Sign in as ${formatAddress(account, 4)} to unlock your E2EE Vault.`
                    : 'Sign SIWE challenge to unlock your on-device E2EE Vault.'}
                </span>
                <button
                  type="button"
                  className="btn-solid"
                  style={{ padding: '7px 14px', fontSize: '0.76rem' }}
                  disabled={siweLoading || authLoading}
                  onClick={onAuthenticateSiwe || authenticateE2EESession}
                >
                  <KeyRound size={13} />
                  <span>{siweLoading || authLoading ? 'Signing...' : 'Sign In & Unlock'}</span>
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
                  fontSize: '0.75rem',
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
                  style={{ padding: '3px 8px', fontSize: '0.7rem', flexShrink: 0 }}
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
                  fontSize: '0.78rem',
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
                <label style={{ fontSize: '0.76rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
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
                      fontSize: '0.7rem',
                      color: 'var(--text-muted)',
                      marginBottom: '5px',
                      fontWeight: 600,
                      textTransform: 'uppercase',
                      letterSpacing: '0.04em',
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
                          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
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
                  style={{ padding: '8px 14px', fontSize: '0.82rem' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn-solid"
                  disabled={startingIndividualBusy || !individualIdInput.trim()}
                  style={{ padding: '8px 18px', fontSize: '0.84rem' }}
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
          onReplenishPrekeys={async () => {
            if (!localDeviceId) return;
            const moreOlm = await generateMoreOlmPrekeys(e2eeProfile.user_id, 15, true);
            const moreMls = await generateMlsKeyPackagesForDevice(
              e2eeProfile.user_id,
              localDeviceId,
              6
            );
            await replenishE2EEPrekeys(localDeviceId, {
              ...moreOlm,
              mls_key_packages: moreMls,
            });
            await markLocalPrekeysPublished(e2eeProfile.user_id);
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
            const freshLocal = await getOrCreateLocalOlmDevice(
              e2eeProfile.user_id,
              'Reset Browser Vault'
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
            await markLocalPrekeysPublished(e2eeProfile.user_id);
            const freshMe = await fetchMyE2EEAccount();
            setE2eeProfile(freshMe.user);
            setMyDevices(freshMe.devices);
            setLocalDeviceId(freshLocal.record.deviceId);
            setVaultBoundUserId(e2eeProfile.user_id);
            setLocalEd25519Key(freshLocal.record.ed25519Key);
            setLocalCurve25519Key(freshLocal.record.curve25519Key);
          }}
        />
      )}
    </div>
  );
};