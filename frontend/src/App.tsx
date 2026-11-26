import { AppBanners } from './components/AppBanners';
import React, { useState, useEffect, useCallback, useRef } from 'react';
import { friendlyError } from './services/friendlyError';
import { Header, type PlatformSection } from './components/Header';
import { Chat } from './components/Chat';
import { AdminPortal } from './components/AdminPortal';
import { PaymentsView } from './components/PaymentsView';
import { SupportView } from './components/SupportView';
import {
  MyProfileView,
  SettingsView,
} from './components/PlatformViews';
import { fetchHealth } from './services/api';
import {
  isMetaMaskInstalled,
  requestAccounts,
  getChainId,
  getBalance,
} from './services/web3';
import {
  requestE2EEAuthChallenge,
  verifyE2EEAuthChallenge,
  fetchMyE2EEAccount,
  hasStoredSessionToken,
  setE2EESessionToken,
  logoutE2EESession,
  registerE2EEDeviceBundle,
  replenishE2EEPrekeys,
  type E2EEAccountProfile,
} from './services/e2eeApi';
import { subscribeE2EERealtime } from './services/e2eeRealtime';
import { startNotifications } from './services/notificationStore';
import { NotificationToast } from './components/NotificationBell';
import { wipeUserDeviceVault } from './services/e2eeVault';
import {
  getOrCreateLocalOlmDevice,
  markLocalPrekeysPublished,
  generateMoreOlmPrekeys,
} from './services/olmService';
import { generateMlsKeyPackagesForDevice } from './services/mlsGroupService';
import {
  connectMemberPresenceWebSocket,
  fetchMembershipStatus,
  fetchSupportUnread,
  formatDate,
} from './services/platformApi';
import { PlatformAdmissionModal } from './components/PlatformAdmissionModal';
import { PaidGroupAdmissionModal } from './components/PaidGroupAdmissionModal';
import { UsernamePromptModal } from './components/UsernamePromptModal';
import { AppResumeSkeleton } from './components/Skeleton';
import WelcomeGate from './components/WelcomeGate';

export const MainApp: React.FC = () => {
  const isInitialSettings =
    typeof window !== 'undefined' && window.location.pathname.toLowerCase().startsWith('/settings');
  const isInitialPayments =
    typeof window !== 'undefined' && window.location.pathname.toLowerCase().startsWith('/payments');
  const isInitialSupport =
    typeof window !== 'undefined' && window.location.pathname.toLowerCase().startsWith('/support');
  const isInitialProfile =
    typeof window !== 'undefined' && window.location.pathname.toLowerCase().startsWith('/profile');

  // Invite links were removed (admins add people, who Accept or Reject). An old /?invite=CODE link
  // just opens the app: take the code out of the address bar and forget any code kept from before.
  useEffect(() => {
    try {
      if (new URLSearchParams(window.location.search).has('invite')) {
        window.history.replaceState({}, '', window.location.pathname);
      }
      sessionStorage.removeItem('zyphra_pending_invite');
    } catch {
      // storage unavailable
    }
  }, []);

  const [activeSection, setActiveSection] = useState<PlatformSection>(
    isInitialSettings && isMetaMaskInstalled()
      ? 'settings'
      : isInitialPayments
        ? 'payments'
        : isInitialSupport
          ? 'support'
          : isInitialProfile && isMetaMaskInstalled()
            ? 'profile'
            : 'open_chat'
  );

  // MetaMask Web3 State
  const [account, setAccount] = useState<string | null>(null);
  const accountRef = useRef<string | null>(null);
  useEffect(() => {
    accountRef.current = account;
  }, [account]);
  const [chainId, setChainId] = useState<string | null>(null);
  const [balanceWei, setBalanceWei] = useState<bigint>(0n);
  const [walletCheckDone, setWalletCheckDone] = useState(false);
  const [openVaultModal, setOpenVaultModal] = useState(false);
  const userDisconnectedRef = useRef<boolean>(
    typeof window !== 'undefined' && sessionStorage.getItem('zyphra_user_disconnected') === '1'
  );

  // Keep the URL in sync with the active section (/settings, /payments, /) and handle back/forward.
  useEffect(() => {
    if (!walletCheckDone) return;
    const path =
      account && (activeSection === 'settings' || activeSection === 'wallet_level')
        ? '/settings'
        : activeSection === 'payments'
          ? '/payments'
          : activeSection === 'support'
            ? '/support'
            : account && activeSection === 'profile'
              ? '/profile'
              : '/';
    if (window.location.pathname !== path) {
      window.history.pushState({}, '', path);
    }
  }, [activeSection, account, walletCheckDone]);

  useEffect(() => {
    const onPopState = () => {
      const p = window.location.pathname.toLowerCase();
      if ((p.startsWith('/settings') || p.startsWith('/profile')) && !accountRef.current) {
        window.history.replaceState({}, '', '/');
        setActiveSection('open_chat');
        return;
      }
      setActiveSection((prev) =>
        p.startsWith('/settings')
          ? 'settings'
          : p.startsWith('/payments')
            ? 'payments'
            : p.startsWith('/support')
              ? 'support'
              : p.startsWith('/profile')
                ? 'profile'
                : prev === 'settings' ||
                  prev === 'wallet_level' ||
                  prev === 'payments' ||
                  prev === 'support' ||
                  prev === 'profile'
                  ? 'open_chat'
                  : prev
      );
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    const saved = localStorage.getItem('zyphra_theme');
    return saved === 'light' ? 'light' : 'dark';
  });

  // Unified SIWE + Permanent Account State
  const [e2eeProfile, setE2eeProfile] = useState<E2EEAccountProfile | null>(null);
  const e2eeProfileRef = useRef<E2EEAccountProfile | null>(null);
  useEffect(() => {
    e2eeProfileRef.current = e2eeProfile;
  }, [e2eeProfile]);
  const [siweLoading, setSiweLoading] = useState(false);
  const [pendingPeerTarget, setPendingPeerTarget] = useState<string | null>(null);
  // A group to open (from a notification). '' opens the Groups page (e.g. to answer an invitation).
  const [pendingGroupTarget, setPendingGroupTarget] = useState<string | null>(null);
  const autoAuthAttemptedRef = useRef<string | null>(null);
  const userDeclinedAuthRef = useRef<boolean>(false);
  const siweInFlightRef = useRef<boolean>(false);

  // Platform Admission Paywall & Paid Groups State
  const [isAdmissionModalOpen, setIsAdmissionModalOpen] = useState(false);
  const [isPlatformPaid, setIsPlatformPaid] = useState<boolean | null>(null);
  const [paidGroupTarget, setPaidGroupTarget] = useState<{
    id: string;
    name: string;
    renewing?: boolean;
  } | null>(null);
  // Renewal of an existing membership (opened from the Payments tab or after a 402)
  const [isRenewingMembership, setIsRenewingMembership] = useState(false);
  // What the server said about this wallet's membership the last time we asked (null = not checked yet).
  // `paidUntil` set while `active` is false means the membership has lapsed (renewal, not a first payment).
  const [membershipInfo, setMembershipInfo] = useState<{ active: boolean; paidUntil: string | null } | null>(null);
  const [totalPaidWei, setTotalPaidWei] = useState<string | null>(null);

  // Access gate: visitors see only the welcome screen until they are connected AND paid.
  const [accessEntered, setAccessEntered] = useState(false);
  const [usernamePromptDismissed, setUsernamePromptDismissed] = useState(false);
  const [gateBusyText, setGateBusyText] = useState<string | null>(null);
  const [gateError, setGateError] = useState<string | null>(null);
  const [gateNotice, setGateNotice] = useState<string | null>(null);
  const enterAfterAuthRef = useRef(false);

  /**
   * Asks the server whether the signed-in wallet has an active membership. This is the single source
   * of truth: never decide from a value remembered earlier in the tab (the member may have paid on
   * another device, an admin may have credited a payment, or the membership may have lapsed).
   * Throws the server error (e.g. 401 when the session has expired) so the caller can re-verify.
   */
  const checkMembership = useCallback(async (): Promise<{ paid: boolean; paidUntil: string | null }> => {
    const s = await fetchMembershipStatus();
    setIsPlatformPaid(s.is_platform_paid);
    setMembershipInfo({ active: s.is_platform_paid, paidUntil: s.platform_paid_until });
    setTotalPaidWei(s.total_verified_wei ?? '0');
    return { paid: s.is_platform_paid, paidUntil: s.platform_paid_until };
  }, []);

  /** Plain-language result of the membership check, shown on the welcome screen. */
  const describeMembership = (paid: boolean, paidUntil: string | null): string =>
    paid
      ? paidUntil
        ? `Active member until ${formatDate(paidUntil)}. Welcome back.`
        : 'Active member. Welcome back.'
      : paidUntil
        ? `Your membership ended on ${formatDate(paidUntil)}. Renew to enter.`
        : 'Payment required: this wallet does not have an active membership yet.';

  // A request was refused with 402 (membership or group subscription expired): re-verify platform
  // payment status; if unpaid/expired, lock access and pop up the payment modal, otherwise open Payments.
  useEffect(() => {
    const onPaymentRequired = () => {
      checkMembership()
        .then((m) => {
          if (!m.paid) {
            setAccessEntered(false);
            setGateNotice(describeMembership(false, m.paidUntil));
            setIsAdmissionModalOpen(true);
          } else {
            setActiveSection('payments');
          }
        })
        .catch(() => {
          setAccessEntered(false);
          setIsAdmissionModalOpen(true);
        });
    };
    window.addEventListener('zyphra:payment-required', onPaymentRequired);
    return () => window.removeEventListener('zyphra:payment-required', onPaymentRequired);
  }, [checkMembership]);

  // Hard invariant: never remain inside the app when membership is confirmed unpaid.
  useEffect(() => {
    if (accessEntered && isPlatformPaid === false) {
      setAccessEntered(false);
      setIsAdmissionModalOpen(true);
    }
  }, [accessEntered, isPlatformPaid]);

  /** After the check: members enter (when they pressed Connect), everyone else gets the payment window. */
  const applyMembershipResult = useCallback((paid: boolean, paidUntil: string | null, enter: boolean) => {
    setGateError(null);
    if (paid) {
      setIsAdmissionModalOpen(false);
      setGateNotice(describeMembership(true, paidUntil));
      if (enter) setAccessEntered(true);
    } else {
      setAccessEntered(false);
      setGateNotice(describeMembership(false, paidUntil));
      setIsAdmissionModalOpen(true);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // "Talk to admin": unread admin replies, shown as a badge on the Support tab
  const [supportUnread, setSupportUnread] = useState(0);
  useEffect(() => {
    if (!accessEntered || !e2eeProfile) {
      setSupportUnread(0);
      return;
    }
    let alive = true;
    const poll = () => {
      if (document.visibilityState !== 'visible') return;
      fetchSupportUnread()
        .then((r) => alive && setSupportUnread(r.unread_total))
        .catch(() => { });
    };
    poll();
    const t = setInterval(poll, 30000);
    // An admin replied: the live socket relays `support_reply` (see Chat.tsx), refresh the badge now.
    const onLiveReply = () => {
      fetchSupportUnread()
        .then((r) => alive && setSupportUnread(r.unread_total))
        .catch(() => { });
    };
    window.addEventListener('zyphra:support-reply', onLiveReply);
    return () => {
      alive = false;
      clearInterval(t);
      window.removeEventListener('zyphra:support-reply', onLiveReply);
    };
  }, [accessEntered, e2eeProfile?.user_id]); // eslint-disable-line react-hooks/exhaustive-deps
  // Automatic "welcome back" entry may only happen once, at page load (never after a later re-check).
  const resumeDoneRef = useRef(false);

  // Backend Health State
  const [serverHealthy, setServerHealthy] = useState<boolean>(true);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('zyphra_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  // Poll Backend Health
  useEffect(() => {
    let mounted = true;
    const poll = async () => {
      try {
        const h = await fetchHealth();
        if (mounted) {
          setServerHealthy(h.status === 'healthy');
        }
      } catch {
        if (mounted) setServerHealthy(false);
      }
    };
    poll();
    // Once a minute is plenty (thousands of open tabs polling every 20 s was needless server load).
    const timer = setInterval(poll, 60000);
    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, []);

  const refreshWalletData = useCallback(async (addr: string) => {
    try {
      const [cid, bal] = await Promise.all([getChainId(), getBalance(addr)]);
      setChainId(cid);
      setBalanceWei(bal);
    } catch {
      // ignore provider read errors
    }
  }, []);

  // System-wide presence socket for MetaMask-connected members ("Active Live")
  const memberPresenceRef = useRef<ReturnType<typeof connectMemberPresenceWebSocket> | null>(null);
  useEffect(() => {
    if (!account) {
      if (memberPresenceRef.current) {
        memberPresenceRef.current.close();
        memberPresenceRef.current = null;
      }
      return;
    }
    if (!memberPresenceRef.current) {
      memberPresenceRef.current = connectMemberPresenceWebSocket(account);
    } else {
      memberPresenceRef.current.updateWallet(account);
    }
  }, [account, e2eeProfile?.user_id]);

  useEffect(() => {
    return () => {
      if (memberPresenceRef.current) {
        memberPresenceRef.current.close();
        memberPresenceRef.current = null;
      }
    };
  }, []);

  const triggerSiweAuth = useCallback(
    async (walletAddress: string) => {
      if (siweLoading || siweInFlightRef.current) return;
      siweInFlightRef.current = true;
      setSiweLoading(true);
      try {
        let chainNum = 1;
        try {
          const eth = window.ethereum;
          if (eth?.request) {
            const directChainHex = await eth.request({ method: 'eth_chainId' });
            if (directChainHex) {
              chainNum = parseInt(directChainHex, 16) || 1;
            }
          }
        } catch {
          chainNum = chainId ? parseInt(chainId, 16) || 1 : 1;
        }

        const chal = await requestE2EEAuthChallenge(walletAddress, 'login', chainNum);
        const signature: string = await window.ethereum.request({
          method: 'personal_sign',
          params: [chal.message, walletAddress],
        });
        const verified = await verifyE2EEAuthChallenge(chal.challenge_id, walletAddress, signature);

        // Immediately set the verified user profile so the user is authenticated without delay
        setE2eeProfile(verified.user);
        userDeclinedAuthRef.current = false;

        // Always verify authoritative payment status from the server before granting access.
        setGateBusyText('Verifying payment status...');
        const membership = await checkMembership();
        applyMembershipResult(membership.paid, membership.paidUntil, enterAfterAuthRef.current);
        enterAfterAuthRef.current = false;

        // Safe non-blocking initialization & publish of on-device E2EE bundle + MLS KeyPackages
        try {
          const uid = verified.user.user_id;
          let localDev = await getOrCreateLocalOlmDevice(uid, 'Web browser');
          let mlsPkgs = localDev.isNewDevice
            ? await generateMlsKeyPackagesForDevice(uid, localDev.record.deviceId, 8)
            : [];
          let regRes;
          try {
            regRes = await registerE2EEDeviceBundle({
              ...localDev.registrationBundle,
              mls_key_packages: mlsPkgs,
            });
          } catch (regErr: any) {
            if (regErr?.status === 403) {
              // Stored local device was revoked on the server: replace it with a fresh device identity.
              await wipeUserDeviceVault(uid);
              localDev = await getOrCreateLocalOlmDevice(uid, 'Web browser');
              mlsPkgs = await generateMlsKeyPackagesForDevice(uid, localDev.record.deviceId, 8);
              regRes = await registerE2EEDeviceBundle({
                ...localDev.registrationBundle,
                mls_key_packages: mlsPkgs,
              });
            } else {
              throw regErr;
            }
          }
          await markLocalPrekeysPublished(uid);

          if (
            regRes.available_counts.one_time_prekeys < 5 ||
            regRes.available_counts.mls_key_packages < 3
          ) {
            const rep = await generateMoreOlmPrekeys(uid, 12, false);
            const extraMls = await generateMlsKeyPackagesForDevice(uid, localDev.record.deviceId, 6);
            await replenishE2EEPrekeys(localDev.record.deviceId, {
              ...rep,
              mls_key_packages: extraMls,
            });
            await markLocalPrekeysPublished(uid);
          }
          const fresh = await fetchMyE2EEAccount();
          if (fresh?.user) {
            setE2eeProfile(fresh.user);
          }
        } catch (vaultErr) {
          console.warn('E2EE device vault background setup warning (non-fatal):', vaultErr);
        }
      } catch (err: any) {
        enterAfterAuthRef.current = false;
        setAccessEntered(false);
        if (err?.code === 4001) {
          // User explicitly declined/cancelled the signature in MetaMask; avoid loop
          userDeclinedAuthRef.current = true;
          setGateError('Signature cancelled. Press Connect to verify your wallet.');
        } else {
          console.error('SIWE authentication failed:', err);
          setGateError(friendlyError(err, 'Could not verify your wallet or payment status. Please try again.'));
        }
      } finally {
        siweInFlightRef.current = false;
        setSiweLoading(false);
        setGateBusyText(null);
      }
    },
    [chainId, siweLoading, applyMembershipResult, checkMembership]
  );

  // Unified Session Verification, MetaMask Wallet Discovery & Auto-Signup on Refresh
  useEffect(() => {
    let mounted = true;

    const initAuthAndWallet = async () => {
      if (!isMetaMaskInstalled()) {
        if (mounted) setWalletCheckDone(true);
        return;
      }

      const eth = window.ethereum;

      try {
        const accs: string[] = await eth.request({ method: 'eth_accounts' });
        if (!mounted) return;

        if (accs && accs.length > 0) {
          const activeAddr = accs[0];
          userDisconnectedRef.current = false;
          sessionStorage.removeItem('zyphra_user_disconnected');
          setAccount(activeAddr);
          refreshWalletData(activeAddr);

          if (hasStoredSessionToken()) {
            try {
              const res = await fetchMyE2EEAccount();
              if (!mounted) return;
              const user = res?.user;
              const hasMatchingSession = Boolean(
                user &&
                user.wallets.some(
                  (w) => w.wallet_address.toLowerCase() === activeAddr.toLowerCase()
                )
              );

              if (!hasMatchingSession) {
                // Stored session belongs to a different wallet: drop it and require fresh sign-in.
                logoutE2EESession().catch(() => { });
                setE2EESessionToken(null);
                setE2eeProfile(null);
                setIsPlatformPaid(null);
                setMembershipInfo(null);
                setTotalPaidWei(null);
                setAccessEntered(false);
                setIsAdmissionModalOpen(false);
              } else if (user) {
                setE2eeProfile(user);
                try {
                  const m = await checkMembership();
                  if (!mounted) return;
                  const allowResume = !resumeDoneRef.current;
                  resumeDoneRef.current = true;
                  if (m.paid) {
                    if (allowResume) setAccessEntered(true);
                  } else {
                    setAccessEntered(false);
                    setGateNotice(describeMembership(false, m.paidUntil));
                    setIsAdmissionModalOpen(true);
                  }
                } catch (membershipErr: any) {
                  // Only clear session if the server explicitly rejected it (401); keep session on transient errors.
                  if (mounted) {
                    if (membershipErr?.status === 401) {
                      setE2EESessionToken(null);
                      setE2eeProfile(null);
                    } else {
                      setGateError(friendlyError(membershipErr, 'Could not verify membership status. Please try again.'));
                    }
                    setIsPlatformPaid(null);
                    setAccessEntered(false);
                  }
                }
              }
            } catch (meErr: any) {
              // Only clear stored session when the server confirms it is invalid/expired (401).
              if (meErr?.status === 401) {
                setE2EESessionToken(null);
              } else if (mounted) {
                setGateError(friendlyError(meErr, 'Could not reach the server to resume your session.'));
              }
            }
          }
        } else {
          setAccessEntered(false);
          setIsAdmissionModalOpen(false);
          setActiveSection((prev) =>
            prev === 'settings' || prev === 'wallet_level' || prev === 'profile'
              ? 'open_chat'
              : prev
          );
        }
      } catch (err) {
        console.warn('MetaMask account check error:', err);
      } finally {
        if (mounted) setWalletCheckDone(true);
      }
    };

    initAuthAndWallet();

    const handleAccountsChanged = (accs: string[]) => {
      if (!accs || accs.length === 0) {
        userDisconnectedRef.current = true;
        sessionStorage.setItem('zyphra_user_disconnected', '1');
        setAccount(null);
        setBalanceWei(0n);
        logoutE2EESession().catch(() => { });
        setE2eeProfile(null);
        setIsPlatformPaid(null);
        setMembershipInfo(null);
        setTotalPaidWei(null);
        setIsAdmissionModalOpen(false);
        setAccessEntered(false);
        setUsernamePromptDismissed(false);
        setGateNotice(null);
        setActiveSection((prev) =>
          prev === 'settings' || prev === 'wallet_level' || prev === 'profile'
            ? 'open_chat'
            : prev
        );
      } else {
        const newAddr = accs[0];
        userDisconnectedRef.current = false;
        sessionStorage.removeItem('zyphra_user_disconnected');
        setAccount(newAddr);
        refreshWalletData(newAddr);

        const prevProfile = e2eeProfileRef.current;
        const isLinked = Boolean(
          prevProfile?.wallets.some(
            (w) => w.wallet_address.toLowerCase() === newAddr.toLowerCase()
          )
        );
        if (!isLinked) {
          // Switched to a different wallet: drop the old session and send them back to the
          // welcome screen. They verify the new wallet by pressing Connect.
          logoutE2EESession().catch(() => { });
          setE2eeProfile(null);
          setIsPlatformPaid(null);
          setMembershipInfo(null);
          setTotalPaidWei(null);
          setIsAdmissionModalOpen(false);
          setAccessEntered(false);
          setUsernamePromptDismissed(false);
          setGateNotice(null);
        } else {
          // Switched to a wallet linked to the same account: re-verify payment status cleanly.
          checkMembership()
            .then((m) => {
              if (!m.paid) {
                setAccessEntered(false);
                setGateNotice(describeMembership(false, m.paidUntil));
                setIsAdmissionModalOpen(true);
              }
            })
            .catch(() => { });
        }
      }
    };

    const handleChainChanged = (newChainHex: string) => {
      setChainId(newChainHex);
      if (accountRef.current) refreshWalletData(accountRef.current);
    };

    const eth = window.ethereum;
    eth?.on?.('accountsChanged', handleAccountsChanged);
    eth?.on?.('chainChanged', handleChainChanged);

    return () => {
      mounted = false;
      eth?.removeListener?.('accountsChanged', handleAccountsChanged);
      eth?.removeListener?.('chainChanged', handleChainChanged);
    };
  }, [refreshWalletData, checkMembership]);

  // Authoritative Membership Status Sync
  useEffect(() => {
    if (e2eeProfile && isPlatformPaid === null) {
      fetchMembershipStatus()
        .then((status) => {
          setIsPlatformPaid(status.is_platform_paid);
          setMembershipInfo({ active: status.is_platform_paid, paidUntil: status.platform_paid_until });
          setTotalPaidWei(status.total_verified_wei ?? '0');
          if (!status.is_platform_paid) {
            setIsAdmissionModalOpen(true);
          }
        })
        .catch(() => { });
    }
  }, [e2eeProfile, isPlatformPaid]);

  // Keep topbar paid total in sync whenever a membership or group payment succeeds elsewhere.
  useEffect(() => {
    if (!e2eeProfile) return;
    const onChanged = () => {
      void checkMembership().catch(() => { });
    };
    window.addEventListener('zyphra:groups-changed', onChanged);
    return () => window.removeEventListener('zyphra:groups-changed', onChanged);
  }, [e2eeProfile, checkMembership]);

  const handleConnectWallet = async () => {
    setGateError(null);
    userDisconnectedRef.current = false;
    sessionStorage.removeItem('zyphra_user_disconnected');
    userDeclinedAuthRef.current = false;
    autoAuthAttemptedRef.current = null;

    // 1. Scan for MetaMask before anything else
    setGateBusyText('Checking for MetaMask...');
    if (!isMetaMaskInstalled()) {
      setGateBusyText(null);
      setGateError('MetaMask wallet not available');
      return;
    }
    try {
      // 2. Ask MetaMask for the current active account
      let addr: string | null = account;
      const eth = (window as any).ethereum;
      if (eth?.request) {
        try {
          const currentAccs: string[] = await eth.request({ method: 'eth_accounts' });
          if (currentAccs && currentAccs.length > 0) {
            addr = currentAccs[0];
            if (addr.toLowerCase() !== (account || '').toLowerCase()) {
              setAccount(addr);
            }
          } else {
            addr = null;
          }
        } catch {
          // fall back to requestAccounts below
        }
      }
      if (!addr) {
        setGateBusyText('Waiting for MetaMask...');
        const accs = await requestAccounts();
        if (accs.length > 0) {
          addr = accs[0];
          setAccount(addr);
        }
      }
      if (!addr) {
        setGateError('No wallet account was selected in MetaMask.');
        return;
      }
      refreshWalletData(addr).catch(() => { });

      const sessionMatchesWallet = Boolean(
        e2eeProfile &&
        e2eeProfile.wallets.some((w) => w.wallet_address.toLowerCase() === addr!.toLowerCase())
      );

      if (sessionMatchesWallet) {
        // Wallet already verified in this session: ask the server again whether it is a paid member
        // (it may have paid on another device, been credited by an admin, or lapsed since).
        setGateBusyText('Checking your membership...');
        try {
          const m = await checkMembership();
          applyMembershipResult(m.paid, m.paidUntil, true);
          return;
        } catch (statusErr: any) {
          if (statusErr?.status !== 401) {
            setGateError(friendlyError(statusErr, 'Could not check your membership. Please try again.'));
            return;
          }
          // 401: the session expired on the server. Fall through and verify the wallet again.
        }
      }

      // 3. Verify wallet identity (signature) -> new session. Paid wallets enter straight away,
      //    including wallets that paid on another device; unpaid wallets get the payment popup.
      setGateBusyText('Verify the signature in MetaMask...');
      enterAfterAuthRef.current = true;
      if (e2eeProfile) {
        await logoutE2EESession().catch(() => { });
        setE2eeProfile(null);
      }
      await triggerSiweAuth(addr);
    } catch (err: any) {
      if (err?.code === 4001) setGateError('Connection cancelled in MetaMask.');
      else setGateError(friendlyError(err, 'Failed to connect MetaMask'));
    } finally {
      setGateBusyText(null);
    }
  };

  const handleAuthenticateSiwe = async () => {
    if (!account || siweLoading) return;
    userDeclinedAuthRef.current = false;
    autoAuthAttemptedRef.current = null;
    if (
      e2eeProfile &&
      !e2eeProfile.wallets.some(
        (w) => w.wallet_address.toLowerCase() === account.toLowerCase()
      )
    ) {
      await logoutE2EESession().catch(() => { });
      setE2eeProfile(null);
    }
    await triggerSiweAuth(account);
  };

  const handleDisconnect = async () => {
    userDisconnectedRef.current = true;
    sessionStorage.setItem('zyphra_user_disconnected', '1');
    userDeclinedAuthRef.current = true;
    autoAuthAttemptedRef.current = null;
    await logoutE2EESession();
    setE2eeProfile(null);
    setIsPlatformPaid(null);
    setMembershipInfo(null);
    setTotalPaidWei(null);
    setIsAdmissionModalOpen(false);
    setAccessEntered(false);
    setUsernamePromptDismissed(false);
    setGateNotice(null);
    setGateError(null);
    setAccount(null);
    setBalanceWei(0n);
    setActiveSection((prev) =>
      prev === 'settings' || prev === 'wallet_level' || prev === 'profile' ? 'open_chat' : prev
    );
  };

  const handleStartPrivateChat = (identifier: string) => {
    setPendingPeerTarget(identifier);
    setActiveSection('dm');
  };

  const resolvedSection: PlatformSection =
    !account &&
      (activeSection === 'settings' || activeSection === 'wallet_level' || activeSection === 'profile')
      ? 'open_chat'
      : activeSection;

  const isChatSection =
    resolvedSection === 'open_chat' || resolvedSection === 'dm' || resolvedSection === 'groups';

  // Live support replies on the non-chat pages. In the chat views Chat.tsx already holds the encrypted
  // channel socket and relays `support_reply`; elsewhere (Concierge, Membership, Settings) Chat is not
  // mounted, so listen here instead. Only one socket is open at a time.
  useEffect(() => {
    if (!accessEntered || !e2eeProfile || isChatSection) return;
    return subscribeE2EERealtime((evt) => {
      if (evt.type === 'support_reply') {
        window.dispatchEvent(new CustomEvent('zyphra:support-reply', { detail: evt }));
      }
    });
  }, [accessEntered, e2eeProfile?.user_id, isChatSection]); // eslint-disable-line react-hooks/exhaustive-deps

  // Notifications for new messages and group invitations, on every page of the app.
  useEffect(() => {
    if (!accessEntered || !e2eeProfile?.user_id) return;
    return startNotifications(e2eeProfile.user_id);
  }, [accessEntered, e2eeProfile?.user_id]);

  // Tapping a notification opens that conversation.
  useEffect(() => {
    const onOpen = (e: Event) => {
      const d = (e as CustomEvent).detail || {};
      if (d.type === 'dm' && d.id) {
        setPendingPeerTarget(String(d.id));
        setActiveSection('dm');
      } else if (d.type === 'group' && d.id) {
        setPendingGroupTarget(String(d.id));
        setActiveSection('groups');
      } else if (d.type === 'invites') {
        setPendingGroupTarget('');
        setActiveSection('groups');
      } else if (d.type === 'room') {
        setActiveSection('open_chat');
      } else if (d.type === 'payments') {
        setActiveSection('payments');
      }
    };
    window.addEventListener('zyphra:open-conversation', onOpen);
    return () => window.removeEventListener('zyphra:open-conversation', onOpen);
  }, []);

  return (
    <div className="app-root">
      <Header
        activeSection={resolvedSection}
        setActiveSection={(sec) => {
          if (!account && (sec === 'settings' || sec === 'wallet_level' || sec === 'profile')) {
            return;
          }
          setActiveSection(sec);
        }}
        account={account}
        balanceWei={balanceWei}
        e2eeProfile={e2eeProfile}
        siweLoading={siweLoading}
        onConnect={handleConnectWallet}
        onAuthenticateSiwe={handleAuthenticateSiwe}
        onDisconnect={handleDisconnect}
        theme={theme}
        onToggleTheme={toggleTheme}
        serverHealthy={serverHealthy}
        gated={!accessEntered}
        connectLabel="Connect to MetaMask"
        connectBusy={Boolean(gateBusyText) || siweLoading}
        supportUnread={supportUnread}
        totalPaidWei={totalPaidWei}
      />

      {/* Admin banner for everyone + renewal reminders (7 days, 1 day, ended) */}
      <AppBanners signedIn={Boolean(e2eeProfile)} onOpenPayments={() => setActiveSection('payments')} />

      {!accessEntered && !walletCheckDone && hasStoredSessionToken() ? (
        <AppResumeSkeleton />
      ) : !accessEntered ? (
        <main className="console-workspace wg-workspace">
          <WelcomeGate
            onConnect={handleConnectWallet}
            label="Connect to MetaMask"
            busy={Boolean(gateBusyText) || siweLoading}
            busyText={gateBusyText || 'Verifying wallet...'}
            error={gateError}
            notice={gateNotice}
            showInstallLink={gateError === 'MetaMask wallet not available'}
          />
        </main>
      ) : (
        <main
          className={`console-workspace ${isChatSection ? 'chat-workspace-mode' : 'scrollable-workspace-mode'
            }`}
        >
          {(resolvedSection === 'open_chat' ||
            resolvedSection === 'dm' ||
            resolvedSection === 'groups') && (
              <Chat
                account={account}
                chainIdHex={chainId}
                onConnectWallet={handleConnectWallet}
                forcedMode={resolvedSection}
                onModeChange={(mode) => setActiveSection(mode)}
                siweLoading={siweLoading}
                onAuthenticateSiwe={handleAuthenticateSiwe}
                onStartPrivateChat={handleStartPrivateChat}
                initialPeerIdentifier={pendingPeerTarget}
                onConsumedInitialPeer={() => setPendingPeerTarget(null)}
                initialGroupId={pendingGroupTarget}
                onConsumedInitialGroup={() => setPendingGroupTarget(null)}
                externalProfile={e2eeProfile}
                onProfileChange={(newProf) => {
                  setE2eeProfile(newProf);
                  if (newProf) {
                    checkMembership()
                      .then((m) => {
                        if (!m.paid) {
                          setAccessEntered(false);
                          setGateNotice(describeMembership(false, m.paidUntil));
                          setIsAdmissionModalOpen(true);
                        }
                      })
                      .catch(() => { });
                  }
                }}
                initialOpenVault={openVaultModal}
                onVaultClosed={() => setOpenVaultModal(false)}
                isPlatformPaid={isPlatformPaid}
                onOpenAdmissionModal={() => setIsAdmissionModalOpen(true)}
                onOpenPaidGroupModal={(groupId, groupName) =>
                  setPaidGroupTarget({ id: groupId, name: groupName || 'Paid Group' })
                }
              />
            )}

          {account && resolvedSection === 'profile' && (
            <MyProfileView
              account={account}
              chainIdHex={chainId}
              e2eeProfile={e2eeProfile}
              siweLoading={siweLoading}
              onConnectWallet={handleConnectWallet}
              onAuthenticateSiwe={handleAuthenticateSiwe}
              onProfileUpdated={setE2eeProfile}
            />
          )}

          {account && (resolvedSection === 'settings' || resolvedSection === 'wallet_level') && (
            <SettingsView
              account={account}
              e2eeProfile={e2eeProfile}
              siweLoading={siweLoading}
              onConnectWallet={handleConnectWallet}
              onAuthenticateSiwe={handleAuthenticateSiwe}
              onProfileUpdated={setE2eeProfile}
              onNavigateDmVault={() => {
                setActiveSection('dm');
                setOpenVaultModal(true);
              }}
              initialSubTab={resolvedSection === 'wallet_level' ? 'wallet_level' : undefined}
            />
          )}

          {resolvedSection === 'payments' && (
            <PaymentsView
              account={account}
              username={e2eeProfile?.username}
              signedIn={Boolean(e2eeProfile)}
              onRenewMembership={() => setIsRenewingMembership(true)}
              onRenewGroup={(id, name) => setPaidGroupTarget({ id, name, renewing: true })}
            />
          )}

          {resolvedSection === 'support' && <SupportView onUnreadChange={setSupportUnread} />}
        </main>
      )}

      {/* Platform Admission Paywall Modal (ETH fee converted to USD) */}
      <PlatformAdmissionModal
        isOpen={isAdmissionModalOpen || isRenewingMembership}
        renewing={isRenewingMembership || Boolean(membershipInfo && !membershipInfo.active && membershipInfo.paidUntil)}
        lapsedOn={membershipInfo && !membershipInfo.active ? membershipInfo.paidUntil : null}
        activeUntil={membershipInfo?.active ? membershipInfo.paidUntil : null}
        onClose={() => {
          setIsAdmissionModalOpen(false);
          setIsRenewingMembership(false);
        }}
        walletAddress={account}
        onSuccess={async () => {
          window.dispatchEvent(new Event('zyphra:groups-changed')); // refresh the Payments tab
          try {
            const m = await checkMembership();
            if (e2eeProfile) {
              setE2eeProfile({ ...e2eeProfile, is_platform_paid: m.paid } as any);
            }
            if (m.paid) {
              setGateError(null);
              setGateNotice('Payment verified. Welcome to Zyphra.');
              setAccessEntered(true);
            } else {
              setGateNotice(describeMembership(false, m.paidUntil));
            }
          } catch {
            setGateNotice('Payment submitted. Press Connect to verify and enter.');
          }
        }}
      />

      {/* Paid Group Admission Modal (Group ETH fee converted to USD) */}
      <PaidGroupAdmissionModal
        isOpen={Boolean(paidGroupTarget)}
        onClose={() => setPaidGroupTarget(null)}
        groupId={paidGroupTarget?.id || null}
        groupName={paidGroupTarget?.name}
        renewing={Boolean(paidGroupTarget?.renewing)}
        walletAddress={account}
        onSuccess={() => {
          setPaidGroupTarget(null);
          window.dispatchEvent(new Event('zyphra:groups-changed'));
        }}
      />

      {/* Prompt user to set a @username when authenticated without one */}
      <UsernamePromptModal
        isOpen={Boolean(
          accessEntered &&
          e2eeProfile &&
          !e2eeProfile.username?.trim() &&
          !usernamePromptDismissed &&
          !isAdmissionModalOpen &&
          !isRenewingMembership &&
          !paidGroupTarget
        )}
        onSuccess={(updatedUser) => {
          setE2eeProfile(updatedUser);
          setUsernamePromptDismissed(false);
        }}
        onDismiss={() => setUsernamePromptDismissed(true)}
      />

      {accessEntered && e2eeProfile && <NotificationToast />}
    </div>
  );
};

/** Top-level router: /Admin456 is a fully separate page (login-gated); everything else is the chat app. */
export const App: React.FC = () => {
  const isAdminRoute =
    typeof window !== 'undefined' &&
    window.location.pathname.replace(/\/+$/, '').toLowerCase() === '/admin456';
  return isAdminRoute ? <AdminPortal /> : <MainApp />;
};

export default App;