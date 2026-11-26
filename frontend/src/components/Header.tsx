import React, { useState, useRef, useEffect } from 'react';
import {
  Sun,
  Moon,
  Wallet,
  LogOut,
  MessageSquare,
  LifeBuoy,
  User,
  Settings,
  CreditCard,
  KeyRound,
  ChevronDown,
  Receipt,
} from 'lucide-react';
import { formatAddress, formatEth } from '../services/web3';
import { NotificationBell } from './NotificationBell';
import type { E2EEAccountProfile } from '../services/e2eeApi';

export type PlatformSection =
  | 'open_chat'
  | 'dm'
  | 'groups'
  | 'profile'
  | 'wallet_level'
  | 'settings'
  | 'payments'
  | 'support';

interface HeaderProps {
  activeSection: PlatformSection;
  setActiveSection: (sec: PlatformSection) => void;
  account: string | null;
  balanceWei: bigint;
  e2eeProfile: E2EEAccountProfile | null;
  siweLoading?: boolean;
  onConnect: () => void;
  onAuthenticateSiwe: () => void;
  onDisconnect: () => void;
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
  serverHealthy?: boolean;
  /** Before access is granted: show only the brand, theme toggle and Connect button. */
  gated?: boolean;
  /** Label shown on the gated Connect button. */
  connectLabel?: string;
  connectBusy?: boolean;
  /** Unread admin replies, shown as a badge on the Support tab. */
  supportUnread?: number;
  /** Total verified ETH paid by the signed-in user (in wei). */
  totalPaidWei?: string | null;
}

function formatPaidAmount(weiStr: string): string {
  try {
    const wei = BigInt(weiStr || '0');
    if (wei <= 0n) return '0 ETH';
    const short4 = formatEth(wei, 4);
    if (short4 !== '0.0000') return `${short4} ETH`;
    const short6 = formatEth(wei, 6);
    return short6 !== '0.000000' ? `${short6} ETH` : '<0.000001 ETH';
  } catch {
    return '0 ETH';
  }
}

/** Monogram avatar: the first letter of the member's @username (or a quiet "Z"), on a brass-ringed disc. */
const AvatarCircle: React.FC<{ address: string; size?: number; name?: string | null }> = ({ address, size = 36, name }) => {
  const hash = address.toLowerCase().replace('0x', '');
  const hue = 140 + (parseInt(hash.slice(0, 2) || '0', 16) % 40); // keeps every avatar inside the green family
  const letter = (name || '').replace(/^@/, '').charAt(0).toUpperCase() || 'Z';
  return (
    <span
      aria-hidden="true"
      style={{
        width: size,
        height: size,
        borderRadius: '50%',
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexShrink: 0,
        fontFamily: 'var(--font-display)',
        fontStyle: 'normal',
        fontWeight: 600,
        fontSize: size * 0.5,
        lineHeight: 1,
        color: 'var(--accent-strong)',
        background: `radial-gradient(circle at 30% 25%, hsla(${hue}, 45%, 38%, 0.55), hsla(${hue}, 45%, 14%, 0.9))`,
        border: '1px solid var(--accent-line)',
      }}
    >
      {letter}
    </span>
  );
};

const NAV_ITEMS: Array<{
  id: PlatformSection;
  label: string;
  icon: React.FC<{ size?: number }>;
}> = [
    { id: 'open_chat', label: 'Messages', icon: MessageSquare },
    { id: 'payments', label: 'Membership', icon: CreditCard },
    { id: 'support', label: 'Concierge', icon: LifeBuoy },
  ];

export const Header: React.FC<HeaderProps> = ({
  activeSection,
  setActiveSection,
  account,
  balanceWei,
  e2eeProfile,
  siweLoading = false,
  onConnect,
  onAuthenticateSiwe,
  onDisconnect,
  theme,
  onToggleTheme,
  gated = false,
  connectLabel = 'Connect to MetaMask',
  connectBusy = false,
  supportUnread = 0,
  totalPaidWei = null,
}) => {
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsDropdownOpen(false);
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsDropdownOpen(false);
      }
    };

    if (isDropdownOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('keydown', handleKeyDown);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isDropdownOpen]);

  const isWalletMismatch = Boolean(
    account &&
    e2eeProfile &&
    !e2eeProfile.wallets.some(
      (w) => w.wallet_address.toLowerCase() === account.toLowerCase()
    )
  );

  return (
    <header className={`console-topbar${gated ? ' console-topbar--gated' : ''}`}>
      {/* Brand Monolith */}
      <div className="brand-block" onClick={() => setActiveSection('open_chat')}>
        <div className="brand-monolith" aria-hidden="true">Z</div>
        <div className="brand-title">Zyphra</div>
      </div>

      {/* Responsive 9-Section Navigation Bar (hidden until access is granted) */}
      {!gated && (
        <nav
          className="console-switcher"
          aria-label="Platform sections"
        >
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isChatSection =
              activeSection === 'open_chat' || activeSection === 'dm' || activeSection === 'groups';
            const isSettingsSection =
              item.id === 'settings' &&
              (activeSection === 'settings' || activeSection === 'wallet_level');
            const isActive =
              item.id === 'open_chat'
                ? isChatSection
                : isSettingsSection || activeSection === item.id;
            return (
              <button
                key={item.id}
                type="button"
                className={`switcher-btn ${isActive ? 'active' : ''}`}
                onClick={() => setActiveSection(item.id)}
                style={{ whiteSpace: 'nowrap' }}
              >
                <Icon size={16} />
                <span>{item.label}</span>
                {item.id === 'support' && supportUnread > 0 && (
                  <span
                    aria-label={`${supportUnread} unread replies from the concierge`}
                    style={{
                      minWidth: 20,
                      height: 20,
                      borderRadius: 10,
                      padding: '0 6px',
                      display: 'inline-flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '0.9rem',
                      fontWeight: 700,
                      background: 'var(--accent)',
                      color: 'var(--accent-ink)',
                    }}
                  >
                    {supportUnread}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      )}

      {/* Right Web3 + Identity Action Cluster */}
      <div className="topbar-actions" style={{ position: 'relative' }} ref={dropdownRef}>
        {account && !gated ? (
          <>
            {e2eeProfile && totalPaidWei !== null && totalPaidWei !== undefined && (
              <button
                type="button"
                className="topbar-paid-badge"
                onClick={() => setActiveSection('payments')}
                title="Total verified amount paid — click to view payment history"
                aria-label={`Paid amount: ${formatPaidAmount(totalPaidWei)}`}
              >
                <Receipt size={15} />
                <span className="hide-on-mobile-text">Paid:</span>
                <span className="topbar-paid-value">{formatPaidAmount(totalPaidWei)}</span>
              </button>
            )}
            {e2eeProfile && !isWalletMismatch && <NotificationBell />}
            <button
              type="button"
              className="theme-toggle-btn"
              onClick={onToggleTheme}
              title="Switch between dark and light"
              aria-label="Switch between dark and light"
            >
              {theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}
            </button>
            <button
              type="button"
              className={`btn-outline topbar-settings-btn ${activeSection === 'settings' || activeSection === 'wallet_level' ? 'active' : ''
                }`}
              onClick={() => setActiveSection('settings')}
              title="Settings"
              aria-label="Settings"
            >
              <Settings size={16} />
              <span className="hide-on-mobile-text">Settings</span>
            </button>
            {account && (!e2eeProfile || isWalletMismatch) && (
              <button
                type="button"
                className="btn-solid"
                disabled={siweLoading}
                onClick={onAuthenticateSiwe}
                style={{ padding: '6px 12px', fontSize: '0.86rem', borderRadius: '9999px' }}
                title={
                  isWalletMismatch
                    ? `Sign in as ${formatAddress(account, 4)} (or add this wallet in Settings)`
                    : 'Sign in with MetaMask (free, no payment)'
                }
              >
                <KeyRound size={14} />
                <span>
                  {siweLoading
                    ? 'Signing...'
                    : isWalletMismatch
                      ? `Switch to ${formatAddress(account, 3)}`
                      : 'Sign In'}
                </span>
              </button>
            )}

            {/* Connected User Profile Pill / Button */}
            <button
              id="profile-avatar-btn"
              className={`profile-connected-pill ${activeSection === 'profile' ? 'active' : ''}`}
              onClick={() => setIsDropdownOpen((prev) => !prev)}
              aria-label="User Profile"
              title={`Your profile: ${e2eeProfile?.username ? '@' + e2eeProfile.username : formatAddress(account, 4)}`}
            >
              <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                <AvatarCircle address={account} size={34} name={e2eeProfile?.username} />
                <span className="profile-online-badge" />
              </div>
              <div className="profile-pill-text">
                <span className="profile-pill-name">
                  {e2eeProfile?.username ? `@${e2eeProfile.username}` : formatAddress(account, 4)}
                </span>
                <span className="profile-pill-lvl">
                  {(e2eeProfile as any)?.is_platform_paid ? 'Active member' : 'Membership inactive'}
                </span>
              </div>
              <ChevronDown size={13} className="profile-pill-chevron" />
            </button>

            {isDropdownOpen && (
              <div className="profile-dropdown-menu">
                <div
                  className="dropdown-user-header profile-clickable-header"
                  onClick={() => {
                    setIsDropdownOpen(false);
                    setActiveSection('profile');
                  }}
                  title="Click to view & edit Profile"
                  style={{ cursor: 'pointer' }}
                >
                  <AvatarCircle address={account} size={46} name={e2eeProfile?.username} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: '6px',
                      }}
                    >
                      <span
                        style={{
                          fontWeight: 600,
                          fontSize: '1rem',
                        }}
                      >
                        {e2eeProfile?.username
                          ? `@${e2eeProfile.username}`
                          : formatAddress(account, 4)}
                      </span>
                      <span className="audit-status">
                        {(e2eeProfile as any)?.is_platform_paid ? 'Active' : 'Inactive'}
                      </span>
                    </div>
                    <div
                      style={{
                        fontSize: '0.9rem',
                        color: 'var(--text-secondary)',
                        marginTop: '2px',
                      }}
                    >
                      {formatAddress(account, 5)} · {formatEth(balanceWei, 4)} ETH
                    </div>
                    <div
                      style={{
                        fontSize: '0.9rem',
                        color: 'var(--accent-strong)',
                        marginTop: '6px',
                        fontWeight: 600,
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                      }}
                    >
                      <User size={14} />
                      <span>View and edit your profile</span>
                    </div>
                  </div>
                </div>

                <button
                  type="button"
                  className="dropdown-disconnect-btn"
                  onClick={() => {
                    setIsDropdownOpen(false);
                    onDisconnect();
                  }}
                >
                  <LogOut size={15} />
                  <span>Disconnect wallet</span>
                </button>
              </div>
            )}
          </>
        ) : (
          <>
            <button
              type="button"
              className="theme-toggle-btn"
              onClick={onToggleTheme}
              title="Switch between dark and light"
              aria-label="Switch between dark and light"
            >
              {theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}
            </button>
            <button
              type="button"
              className="btn-solid topbar-connect-btn"
              onClick={onConnect}
              disabled={connectBusy}
            >
              <Wallet size={16} />
              <span>{connectLabel}</span>
            </button>
          </>
        )}
      </div>
    </header>
  );
};