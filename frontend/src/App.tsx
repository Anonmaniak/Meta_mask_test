import React, { useState, useEffect, useCallback, useRef } from 'react';
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
import {
  getOrCreateLocalOlmDevice,
  markLocalPrekeysPublished,
  generateMoreOlmPrekeys,
} from './services/olmService';
import { generateMlsKeyPackagesForDevice } from './services/mlsGroupService';
import { connectMemberPresenceWebSocket, fetchMembershipStatus, fetchSupportUnread } from './services/platformApi';
import { PlatformAdmissionModal } from './components/PlatformAdmissionModal';
import { PaidGroupAdmissionModal } from './components/PaidGroupAdmissionModal';
import WelcomeGate from './components/WelcomeGate';

export const MainApp: React.FC = () => {
  const isInitialSettings =
    typeof window !== 'undefined' && window.location.pathname.toLowerCase().startsWith('/settings');
  const isInitialPayments =
    typeof window !== 'undefined' && window.location.pathname.toLowerCase().startsWith('/payments');
  const isInitialSupport =
    typeof window !== 'undefined' && window.location.pathname.toLowerCase().startsWith('/support');

  const [activeSection, setActiveSection] = useState<PlatformSection>(
    isInitialSettings && isMetaMaskInstalled()
      ? 'settings'
      : isInitialPayments
        ? 'payments'
        : isInitialSupport
          ? 'support'
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
            : '/';
    if (window.location.pathname !== path) {
      window.history.pushState({}, '', path);
    }
  }, [activeSection, account, walletCheckDone]);

  useEffect(() => {
    const onPopState = () => {
      const p = window.location.pathname.toLowerCase();
      if (p.startsWith('/settings') && !accountRef.current) {
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
              : prev === 'settings' || prev === 'wallet_level' || prev === 'payments' || prev === 'support'
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
  const [siweLoading, setSiweLoading] = useState(false);
  const [pendingPeerTarget, setPendingPeerTarget] = useState<string | null>(null);
  const autoAuthAttemptedRef = useRef<string | null>(null);
  const userDeclinedAuthRef = useRef<boolean>(false);
  const siweInFlightRef = useRef<boolean>(false);

  // Platform Admission Paywall & Paid Groups State
  const [isAdmissionModalOpen, setIsAdmissionModalOpen] = useState(false);
  const [isPlatformPaid, setIsPlatformPaid] = useState<boolean | null>(null);
  const [paidGroupTarget, setPaidGroupTarget] = useState<{ id: string; name: string } | null>(null);

  // Access gate: visitors see only the welcome screen until they are connected AND paid.
  const [accessEntered, setAccessEntered] = useState(false);
  const [gateBusyText, setGateBusyText] = useState<string | null>(null);
  const [gateError, setGateError] = useState<string | null>(null);
  const [gateNotice, setGateNotice] = useState<string | null>(null);
  const enterAfterAuthRef = useRef(false);

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
    return () => {
      alive = false;
      clearInterval(t);
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
    const timer = setInterval(poll, 20000);
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

        const isPaid = Boolean((verified.user as any)?.is_platform_paid);
        setIsPlatformPaid(isPaid);
        if (!isPaid) {
          setGateNotice(null);
          setIsAdmissionModalOpen(true);
        } else if (enterAfterAuthRef.current) {
          // Wallet already paid (on this or another device): identity verified, session issued, enter.
          setAccessEntered(true);
        }
        enterAfterAuthRef.current = false;

        // Safe non-blocking initialization & publish of on-device E2EE bundle + MLS KeyPackages
        try {
          const uid = verified.user.user_id;
          const localDev = await getOrCreateLocalOlmDevice(uid, 'Browser E2EE Vault');
          const mlsPkgs = localDev.isNewDevice
            ? await generateMlsKeyPackagesForDevice(uid, localDev.record.deviceId, 8)
            : [];
          const regRes = await registerE2EEDeviceBundle({
            ...localDev.registrationBundle,
            mls_key_packages: mlsPkgs,
          });
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
            setIsPlatformPaid(Boolean((fresh.user as any)?.is_platform_paid));
          }
        } catch (vaultErr) {
          console.warn('E2EE device vault background setup warning (non-fatal):', vaultErr);
        }
      } catch (err: any) {
        enterAfterAuthRef.current = false;
        if (err?.code === 4001) {
          // User explicitly declined/cancelled the signature in MetaMask; avoid loop
          userDeclinedAuthRef.current = true;
          setGateError('Signature cancelled. Press Connect to verify your wallet.');
        } else {
          console.error('SIWE authentication failed:', err);
          setGateError(err?.message || 'Could not verify your wallet. Please try again.');
        }
      } finally {
        siweInFlightRef.current = false;
        setSiweLoading(false);
      }
    },
    [chainId, siweLoading]
  );

  // Unified Session Verification, MetaMask Wallet Discovery & Auto-Signup on Refresh
  useEffect(() => {
    let mounted = true;

    const initAuthAndWallet = async () => {
      // 1. Silent session resume only if an active session token exists in storage
      let activeSessionUser: E2EEAccountProfile | null = null;
      if (hasStoredSessionToken()) {
        try {
          const res = await fetchMyE2EEAccount();
          if (mounted && res?.user) {
            activeSessionUser = res.user;
            setE2eeProfile(res.user);
            const isPaid = Boolean((res.user as any)?.is_platform_paid);
            setIsPlatformPaid(isPaid);
            if (!isPaid) {
              setIsAdmissionModalOpen(true);
            }
          }
        } catch {
          // Token expired or invalid; clear safely
          setE2EESessionToken(null);
        }
      }

      if (!isMetaMaskInstalled()) {
        if (mounted) setWalletCheckDone(true);
        return;
      }

      const eth = window.ethereum;

      try {
        const accs: string[] = await eth.request({ method: 'eth_accounts' });
        if (!mounted) return;
        const allowResume = !resumeDoneRef.current;
        resumeDoneRef.current = true;

        if (accs && accs.length > 0) {
          const activeAddr = accs[0];
          userDisconnectedRef.current = false;
          sessionStorage.removeItem('zyphra_user_disconnected');
          setAccount(activeAddr);
          refreshWalletData(activeAddr);

          const hasMatchingSession =
            activeSessionUser &&
            activeSessionUser.wallets.some(
              (w) => w.wallet_address.toLowerCase() === activeAddr.toLowerCase()
            );

          // Returning member on this device: valid session for this wallet + paid -> straight in.
          // No signature prompt on page load; a new device signs when the user presses Connect.
          if (allowResume && hasMatchingSession && Boolean((activeSessionUser as any)?.is_platform_paid)) {
            setAccessEntered(true);
          }
        } else {
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
        setIsAdmissionModalOpen(false);
        setAccessEntered(false);
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

        setE2eeProfile((prevProfile) => {
          const isLinked = prevProfile?.wallets.some(
            (w) => w.wallet_address.toLowerCase() === newAddr.toLowerCase()
          );
          if (!isLinked) {
            // Switched to a different wallet: drop the old session and send them back to the
            // welcome screen. They verify the new wallet by pressing Connect.
            logoutE2EESession().catch(() => { });
            setIsPlatformPaid(null);
            setAccessEntered(false);
            setGateNotice(null);
            return null;
          }
          return prevProfile;
        });
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
  }, [refreshWalletData, triggerSiweAuth]);

  // Authoritative Membership Status Sync
  useEffect(() => {
    if (e2eeProfile && isPlatformPaid === null) {
      fetchMembershipStatus()
        .then((status) => {
          setIsPlatformPaid(status.is_platform_paid);
          if (!status.is_platform_paid) {
            setIsAdmissionModalOpen(true);
          }
        })
        .catch(() => { });
    }
  }, [e2eeProfile, isPlatformPaid]);

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
      // 2. Ask MetaMask for the account
      let addr = account;
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
        // Wallet already verified in this session
        if (isPlatformPaid) {
          setGateNotice(null);
          setAccessEntered(true);
        } else {
          setIsAdmissionModalOpen(true);
        }
        return;
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
      else setGateError(err?.message || 'Failed to connect MetaMask');
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
    setIsAdmissionModalOpen(false);
    setAccessEntered(false);
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
        connectLabel={
          e2eeProfile && isPlatformPaid && !accessEntered ? 'Connect' : 'Connect MetaMask'
        }
        connectBusy={Boolean(gateBusyText) || siweLoading}
        supportUnread={supportUnread}
      />

      {!accessEntered ? (
        <main className="console-workspace chat-workspace-mode wg-workspace">
          <WelcomeGate
            onConnect={handleConnectWallet}
            label={e2eeProfile && isPlatformPaid ? 'Connect' : 'Connect MetaMask'}
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
                externalProfile={e2eeProfile}
                onProfileChange={(newProf) => {
                  setE2eeProfile(newProf);
                  if (newProf) {
                    setIsPlatformPaid(Boolean((newProf as any).is_platform_paid));
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
              theme={theme}
              onToggleTheme={toggleTheme}
              onProfileUpdated={setE2eeProfile}
              onNavigateDmVault={() => {
                setActiveSection('dm');
                setOpenVaultModal(true);
              }}
              initialSubTab={resolvedSection === 'wallet_level' ? 'wallet_level' : undefined}
            />
          )}

          {resolvedSection === 'payments' && <PaymentsView />}

          {resolvedSection === 'support' && <SupportView onUnreadChange={setSupportUnread} />}
        </main>
      )}

      {/* Platform Admission Paywall Modal (ETH fee converted to USD) */}
      <PlatformAdmissionModal
        isOpen={isAdmissionModalOpen}
        onClose={() => setIsAdmissionModalOpen(false)}
        walletAddress={account}
        onSuccess={() => {
          setIsPlatformPaid(true);
          if (e2eeProfile) {
            setE2eeProfile({ ...e2eeProfile, is_platform_paid: true } as any);
          }
          setGateError(null);
          setGateNotice('Payment confirmed. Press Connect to enter.');
        }}
      />

      {/* Paid Group Admission Modal (Group ETH fee converted to USD) */}
      <PaidGroupAdmissionModal
        isOpen={Boolean(paidGroupTarget)}
        onClose={() => setPaidGroupTarget(null)}
        groupId={paidGroupTarget?.id || null}
        groupName={paidGroupTarget?.name}
        walletAddress={account}
        onSuccess={() => {
          setPaidGroupTarget(null);
        }}
      />
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