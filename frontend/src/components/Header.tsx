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
} from 'lucide-react';
import { formatAddress, formatEth } from '../services/web3';
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
  /** 'Connect MetaMask' until the wallet has paid, then 'Connect'. */
  connectLabel?: string;
  connectBusy?: boolean;
  /** Unread admin replies, shown as a badge on the Support tab. */
  supportUnread?: number;
}

const AvatarCircle: React.FC<{ address: string; size?: number }> = ({ address, size = 36 }) => {
  const hash = address.toLowerCase().replace('0x', '');
  const h1 = parseInt(hash.slice(0, 2) || '0', 16);
  const h2 = parseInt(hash.slice(2, 4) || '0', 16);
  const h3 = parseInt(hash.slice(4, 6) || '0', 16);
  const h4 = parseInt(hash.slice(6, 8) || '0', 16);
  const initials = address.length >= 4 ? address.slice(2, 4).toUpperCase() : 'Ξ';
  const angle = (h1 * 360) / 255;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 40 40"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      style={{ borderRadius: '50%', display: 'block' }}
    >
      <defs>
        <linearGradient id={`grad-${address}`} gradientTransform={`rotate(${angle})`}>
          <stop offset="0%" stopColor="var(--text-main)" stopOpacity="0.85" />
          <stop offset="100%" stopColor="var(--bg-input)" stopOpacity="0.3" />
        </linearGradient>
      </defs>
      <circle
        cx="20"
        cy="20"
        r="19"
        fill={`url(#grad-${address})`}
        stroke="var(--border-strong)"
        strokeWidth="2"
      />
      <circle
        cx={14 + (h2 % 12)}
        cy={14 + (h3 % 12)}
        r="7"
        fill="var(--text-main)"
        fillOpacity="0.22"
      />
      <rect
        x={10 + (h3 % 8)}
        y={18 + (h4 % 8)}
        width="16"
        height="14"
        rx="4"
        fill="var(--text-main)"
        fillOpacity="0.25"
      />
      <text
        x="20"
        y="24"
        textAnchor="middle"
        fill="var(--text-inverse)"
        fontSize="12"
        fontWeight="700"
        fontFamily="ui-monospace, monospace"
      >
        {initials}
      </text>
    </svg>
  );
};

const NAV_ITEMS: Array<{
  id: PlatformSection;
  label: string;
  icon: React.FC<{ size?: number }>;
}> = [
    { id: 'open_chat', label: 'Chats', icon: MessageSquare },
    { id: 'payments', label: 'Payments', icon: CreditCard },
    { id: 'support', label: 'Support', icon: LifeBuoy },
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
  connectLabel = 'Connect MetaMask',
  connectBusy = false,
  supportUnread = 0,
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
        <div className="brand-monolith">Z</div>
        <div className="brand-title">zyphra.in</div>
      </div>

      {/* Responsive 9-Section Navigation Bar (hidden until access is granted) */}
      {!gated && (
        <nav
          className="console-switcher"
          aria-label="Platform sections"
          style={{
            overflowX: 'auto',
            maxWidth: '100%',
            padding: '3px',
            gap: '2px',
            scrollbarWidth: 'none',
          }}
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
                style={{
                  padding: '6px 12px',
                  fontSize: '0.78rem',
                  whiteSpace: 'nowrap',
                  gap: '6px',
                }}
              >
                <Icon size={13} />
                <span>{item.label}</span>
                {item.id === 'support' && supportUnread > 0 && (
                  <span
                    aria-label={`${supportUnread} unread admin replies`}
                    style={{
                      minWidth: 16,
                      height: 16,
                      borderRadius: 8,
                      padding: '0 4px',
                      display: 'inline-flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '0.64rem',
                      fontWeight: 700,
                      background: 'var(--btn-primary-bg)',
                      color: 'var(--btn-primary-text)',
                      border: '1px solid var(--border-focus)',
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
            <button
              type="button"
              className="theme-toggle-btn"
              onClick={onToggleTheme}
              title="Toggle Dark / Light Theme"
              aria-label="Toggle Dark / Light Theme"
            >
              {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
            </button>
            <button
              type="button"
              className={`btn-outline topbar-settings-btn ${activeSection === 'settings' || activeSection === 'wallet_level' ? 'active' : ''
                }`}
              onClick={() => setActiveSection('settings')}
              title="Settings"
              aria-label="Settings"
              style={{ padding: '8px 14px', fontSize: '0.82rem', borderRadius: '9999px' }}
            >
              <Settings size={14} />
              <span className="hide-on-mobile-text">Settings</span>
            </button>
            {account && (!e2eeProfile || isWalletMismatch) && (
              <button
                type="button"
                className="btn-solid"
                disabled={siweLoading}
                onClick={onAuthenticateSiwe}
                style={{ padding: '6px 12px', fontSize: '0.76rem', borderRadius: '9999px' }}
                title={
                  isWalletMismatch
                    ? `Sign in as ${formatAddress(account, 4)} (or link this wallet in Vault)`
                    : 'Sign EIP-4361 SIWE challenge to authenticate account & unlock E2EE Vault'
                }
              >
                <KeyRound size={13} />
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
              title={`Profile: ${e2eeProfile?.username ? '@' + e2eeProfile.username : formatAddress(account, 4)}`}
            >
              <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                <AvatarCircle address={account} size={30} />
                <span className="profile-online-badge" />
              </div>
              <div className="profile-pill-text">
                <span className="profile-pill-name">
                  {e2eeProfile?.username ? `@${e2eeProfile.username}` : formatAddress(account, 4)}
                </span>
                <span className="profile-pill-lvl">
                  {(e2eeProfile as any)?.is_platform_paid ? 'Paid Member' : 'Member'}
                </span>
              </div>
              <ChevronDown size={13} className="profile-pill-chevron" />
            </button>

            {isDropdownOpen && (
              <div className="profile-dropdown-menu" style={{ width: '310px' }}>
                <div
                  className="dropdown-user-header profile-clickable-header"
                  onClick={() => {
                    setIsDropdownOpen(false);
                    setActiveSection('profile');
                  }}
                  title="Click to view & edit Profile"
                  style={{ cursor: 'pointer' }}
                >
                  <AvatarCircle address={account} size={42} />
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
                          fontSize: '0.86rem',
                          fontFamily: 'ui-monospace, monospace',
                        }}
                      >
                        {e2eeProfile?.username
                          ? `@${e2eeProfile.username}`
                          : formatAddress(account, 4)}
                      </span>
                      <span className="audit-status" style={{ fontSize: '0.64rem', padding: '1px 6px' }}>
                        {(e2eeProfile as any)?.is_platform_paid ? 'Paid Member' : 'Member'}
                      </span>
                    </div>
                    <div
                      style={{
                        fontSize: '0.74rem',
                        color: 'var(--text-secondary)',
                        marginTop: '2px',
                        fontFamily: 'ui-monospace, monospace',
                      }}
                    >
                      {formatAddress(account, 5)} &bull; {formatEth(balanceWei, 4)} ETH
                    </div>
                    <div
                      style={{
                        fontSize: '0.72rem',
                        color: 'var(--text-main)',
                        marginTop: '4px',
                        fontWeight: 600,
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px',
                      }}
                    >
                      <User size={12} />
                      <span>View &amp; Edit Profile &rarr;</span>
                    </div>
                  </div>
                </div>

                <button
                  type="button"
                  className="btn-outline"
                  style={{
                    width: '100%',
                    justifyContent: 'center',
                    padding: '8px 12px',
                    fontSize: '0.76rem',
                    color: 'var(--color-danger, #ef4444)',
                    borderColor: 'var(--border-subtle)',
                    gap: '6px',
                  }}
                  onClick={() => {
                    setIsDropdownOpen(false);
                    onDisconnect();
                  }}
                >
                  <LogOut size={13} />
                  <span>Disconnect Wallet</span>
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
              title="Toggle Dark / Light Theme"
            >
              {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
            </button>
            <button
              type="button"
              className="btn-solid"
              onClick={onConnect}
              disabled={connectBusy}
              style={{ padding: '8px 16px', fontSize: '0.82rem', borderRadius: '9999px' }}
            >
              <Wallet size={14} />
              <span>{connectLabel}</span>
            </button>
          </>
        )}
      </div>
    </header>
  );
};