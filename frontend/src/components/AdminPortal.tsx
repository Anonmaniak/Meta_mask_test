import React, { useCallback, useEffect, useState } from 'react';
import { Lock, LogIn, Shield, Sun, Moon } from 'lucide-react';
import { AdminDashboard } from './AdminDashboard';
import {
  adminLogin,
  adminLogout,
  adminSessionValid,
  getStoredAdminSession,
} from '../services/platformApi';

const inputStyle: React.CSSProperties = {
  width: '100%',
  background: 'var(--bg-input)',
  border: '1px solid var(--border-strong)',
  borderRadius: '10px',
  padding: '11px 12px',
  color: 'var(--text-main)',
  fontSize: '0.9rem',
};

/**
 * Standalone Admin Console page served at /Admin456.
 * Nothing from the admin dashboard is rendered (or even requested) until the server accepts the login.
 */
export const AdminPortal: React.FC = () => {
  const [token, setToken] = useState<string | null>(null);
  const [checking, setChecking] = useState<boolean>(() => Boolean(getStoredAdminSession()));
  const [loginId, setLoginId] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [theme, setTheme] = useState<'dark' | 'light'>(() =>
    localStorage.getItem('zyphra_theme') === 'light' ? 'light' : 'dark'
  );

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('zyphra_theme', theme);
  }, [theme]);

  useEffect(() => {
    document.title = 'Sign in';
    const meta = document.createElement('meta');
    meta.name = 'robots';
    meta.content = 'noindex, nofollow';
    document.head.appendChild(meta);
    return () => {
      document.head.removeChild(meta);
    };
  }, []);

  // Re-validate a stored session with the server on load.
  useEffect(() => {
    const stored = getStoredAdminSession();
    if (!stored) return;
    let cancelled = false;
    adminSessionValid(stored).then((ok) => {
      if (cancelled) return;
      if (ok) setToken(stored);
      else void adminLogout(null);
      setChecking(false);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleLogout = useCallback(() => {
    void adminLogout(token);
    setToken(null);
    setPassword('');
  }, [token]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      const t = await adminLogin(loginId.trim(), password);
      setPassword('');
      setToken(t);
    } catch (err: any) {
      setPassword('');
      setError(
        err?.status === 429
          ? 'Too many attempts. Please wait and try again later.'
          : err?.status === 401
            ? 'Invalid credentials.'
            : 'Unable to sign in right now.'
      );
    } finally {
      setSubmitting(false);
    }
  };

  const themeButton = (
    <button
      type="button"
      className="theme-toggle-btn"
      onClick={() => setTheme((p) => (p === 'dark' ? 'light' : 'dark'))}
      title="Toggle Dark / Light Theme"
    >
      {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
    </button>
  );

  if (token) {
    return (
      <div className="app-root">
        <header className="console-topbar">
          <div className="brand-block">
            <div className="brand-monolith">Z</div>
            <div className="brand-title">zyphra.in</div>
          </div>
          <div className="topbar-actions">{themeButton}</div>
        </header>
        <main className="console-workspace scrollable-workspace-mode">
          <AdminDashboard adminToken={token} onLogout={handleLogout} />
        </main>
      </div>
    );
  }

  return (
    <div className="app-root">
      <header className="console-topbar">
        <div className="brand-block">
          <div className="brand-monolith">Z</div>
          <div className="brand-title">zyphra.in</div>
        </div>
        <div className="topbar-actions">{themeButton}</div>
      </header>
      <main
        className="console-workspace scrollable-workspace-mode"
        style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}
      >
        <form
          onSubmit={handleSubmit}
          className="deck-card"
          autoComplete="off"
          style={{ width: '100%', maxWidth: '400px', padding: '28px', display: 'flex', flexDirection: 'column', gap: '14px' }}
        >
          <div style={{ textAlign: 'center' }}>
            <Shield size={28} />
            <div className="deck-title" style={{ justifyContent: 'center', marginTop: '8px' }}>
              Restricted Access
            </div>
            <div className="deck-subtitle">Authorized personnel only. Sign in to continue.</div>
          </div>

          {checking ? (
            <div style={{ textAlign: 'center', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Verifying session...
            </div>
          ) : (
            <>
              <label style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '0.8rem' }}>
                <span>Login ID</span>
                <input
                  type="text"
                  name="admin-login-id"
                  value={loginId}
                  onChange={(e) => setLoginId(e.target.value)}
                  maxLength={128}
                  autoComplete="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  required
                  style={inputStyle}
                />
              </label>
              <label style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '0.8rem' }}>
                <span>Password</span>
                <input
                  type="password"
                  name="admin-login-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  maxLength={256}
                  autoComplete="off"
                  required
                  style={inputStyle}
                />
              </label>

              {error && (
                <div role="alert" style={{ fontSize: '0.8rem', color: 'var(--text-danger, #ef4444)' }}>
                  <Lock size={12} style={{ verticalAlign: '-2px', marginRight: '6px' }} />
                  {error}
                </div>
              )}

              <button
                type="submit"
                className="btn-solid"
                disabled={submitting || !loginId.trim() || !password}
                style={{ justifyContent: 'center', padding: '11px 14px' }}
              >
                <LogIn size={15} />
                <span>{submitting ? 'Signing in...' : 'Sign In'}</span>
              </button>
            </>
          )}
        </form>
      </main>
    </div>
  );
};

export default AdminPortal;

