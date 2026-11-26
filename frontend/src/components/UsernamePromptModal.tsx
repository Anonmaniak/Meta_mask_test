import React, { useEffect, useState } from 'react';
import { friendlyError } from '../services/friendlyError';
import { AtSign, Check, AlertCircle, Loader2, X } from 'lucide-react';
import {
  checkUsernameAvailability,
  updateMyE2EEUsername,
  type E2EEAccountProfile,
} from '../services/e2eeApi';

interface UsernamePromptModalProps {
  isOpen: boolean;
  onSuccess: (updatedUser: E2EEAccountProfile) => void;
  onDismiss: () => void;
}

const USERNAME_PATTERN = /^[a-zA-Z0-9_]{3,32}$/;

/** Modal shown after login when the authenticated member has not chosen a @username yet. */
export const UsernamePromptModal: React.FC<UsernamePromptModalProps> = ({
  isOpen,
  onSuccess,
  onDismiss,
}) => {
  const [usernameInput, setUsernameInput] = useState('');
  const [lookupResult, setLookupResult] = useState<{
    target: string;
    available?: boolean;
    reason?: string | null;
  } | null>(null);
  const [saving, setSaving] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const clean = usernameInput.trim().replace(/^@+/, '');
  const formatValid = USERNAME_PATTERN.test(clean);

  useEffect(() => {
    if (!isOpen || !clean || !formatValid) return;

    let cancelled = false;
    const timer = setTimeout(() => {
      checkUsernameAvailability(clean)
        .then((res) => {
          if (cancelled) return;
          setLookupResult({
            target: clean,
            available: res.available,
            reason: res.reason || null,
          });
        })
        .catch(() => {
          if (cancelled) return;
          setLookupResult({ target: clean, available: undefined, reason: null });
        });
    }, 260);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [isOpen, clean, formatValid]);

  if (!isOpen) return null;

  const checking = Boolean(clean && formatValid && lookupResult?.target !== clean);
  const available = !clean
    ? undefined
    : !formatValid
      ? false
      : lookupResult?.target === clean
        ? lookupResult.available
        : undefined;
  const reason = !clean
    ? null
    : !formatValid
      ? 'Must be 3-32 characters (letters, numbers, or underscores only).'
      : lookupResult?.target === clean
        ? lookupResult.reason || null
        : null;

  const canSubmit = Boolean(clean && formatValid && !saving && !checking && available !== false);

  const handleClose = () => {
    setUsernameInput('');
    setLookupResult(null);
    setSubmitError(null);
    onDismiss();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setSaving(true);
    setSubmitError(null);
    try {
      const res = await updateMyE2EEUsername(clean);
      setUsernameInput('');
      setLookupResult(null);
      onSuccess(res.user);
    } catch (err: any) {
      setSubmitError(friendlyError(err, 'Could not save username. Please try another.'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="username-prompt-title"
      className="chat-action-modal-backdrop"
      style={{ zIndex: 9998 }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '460px',
          background: 'var(--bg-card)',
          color: 'var(--text-main)',
          borderRadius: '24px',
          border: '1px solid var(--border-strong)',
          boxShadow: 'var(--shadow-pop)',
          overflow: 'hidden',
          maxHeight: '92dvh',
          overflowY: 'auto',
        }}
      >
        <div
          style={{
            padding: '1.3rem 1.6rem',
            borderBottom: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.7rem' }}>
            <AtSign size={22} style={{ color: 'var(--accent)', flexShrink: 0 }} />
            <div>
              <h3 id="username-prompt-title" style={{ margin: 0, fontSize: '1.35rem', fontWeight: 600 }}>
                Choose your username
              </h3>
              <p style={{ margin: '2px 0 0', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                Set a unique @username so members can find and message you
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={handleClose}
            disabled={saving}
            aria-label="Close"
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--text-secondary)',
              cursor: saving ? 'not-allowed' : 'pointer',
              padding: 4,
            }}
          >
            <X size={18} />
          </button>
        </div>

        <form
          onSubmit={handleSubmit}
          style={{ padding: '1.5rem 1.6rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}
        >
          <div>
            <label
              htmlFor="username-prompt-input"
              style={{
                display: 'block',
                fontSize: '0.84rem',
                fontWeight: 600,
                color: 'var(--text-secondary)',
                marginBottom: '6px',
              }}
            >
              Username
            </label>
            <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
              <span
                aria-hidden="true"
                style={{
                  position: 'absolute',
                  left: '14px',
                  color: 'var(--text-muted)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.96rem',
                  pointerEvents: 'none',
                }}
              >
                @
              </span>
              <input
                id="username-prompt-input"
                type="text"
                autoFocus
                autoComplete="off"
                value={usernameInput.replace(/^@+/, '')}
                onChange={(e) => {
                  setSubmitError(null);
                  setUsernameInput(e.target.value);
                }}
                placeholder="your_username"
                maxLength={32}
                disabled={saving}
                style={{
                  width: '100%',
                  background: 'var(--bg-input)',
                  border: `1px solid ${clean && available === false
                      ? 'var(--danger)'
                      : clean && available
                        ? 'var(--ok)'
                        : 'var(--border-strong)'
                    }`,
                  borderRadius: '12px',
                  padding: '11px 14px 11px 32px',
                  color: 'var(--text-main)',
                  fontSize: '0.96rem',
                  fontFamily: 'var(--font-mono)',
                }}
              />
            </div>

            {clean ? (
              <div style={{ marginTop: '8px', fontSize: '0.86rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
                {checking ? (
                  <span style={{ color: 'var(--text-muted)', display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                    <Loader2 size={13} className="wg__spin" /> Checking @{clean} availability...
                  </span>
                ) : available ? (
                  <span style={{ color: 'var(--ok)', display: 'inline-flex', alignItems: 'center', gap: '6px', fontWeight: 600 }}>
                    <Check size={14} /> @{clean} is available
                  </span>
                ) : available === false ? (
                  <span style={{ color: 'var(--danger)', display: 'inline-flex', alignItems: 'center', gap: '6px', fontWeight: 600 }}>
                    <AlertCircle size={14} /> {reason || 'Username is unavailable'}
                  </span>
                ) : null}
              </div>
            ) : (
              <p style={{ margin: '8px 0 0', fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                3-32 characters using letters, numbers, or underscores.
              </p>
            )}
          </div>

          {submitError && (
            <div
              role="alert"
              style={{
                display: 'flex',
                gap: '8px',
                alignItems: 'flex-start',
                border: '1px solid color-mix(in srgb, var(--danger) 35%, transparent)',
                background: 'var(--danger-soft)',
                color: 'var(--danger)',
                borderRadius: '12px',
                padding: '0.7rem 0.9rem',
                fontSize: '0.88rem',
              }}
            >
              <AlertCircle size={16} style={{ flexShrink: 0, marginTop: 2 }} />
              <span>{submitError}</span>
            </div>
          )}

          <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end', marginTop: '4px' }}>
            <button
              type="button"
              className="btn-outline"
              onClick={handleClose}
              disabled={saving}
            >
              Skip for now
            </button>
            <button
              type="submit"
              className="btn-solid"
              disabled={!canSubmit}
            >
              {saving ? (
                <>
                  <Loader2 size={15} className="wg__spin" /> Saving...
                </>
              ) : (
                'Save Username'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};