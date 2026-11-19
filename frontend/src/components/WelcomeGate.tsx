import { Loader2, Wallet } from 'lucide-react';
import DotField from './DotField';
import './WelcomeGate.css';

interface WelcomeGateProps {
  /** Click handler for the main button (scan MetaMask -> verify wallet -> pay or enter). */
  onConnect: () => void;
  /** "Connect MetaMask" until the wallet has paid, then "Connect". */
  label: string;
  busy: boolean;
  /** Short progress text shown while busy ("Verifying wallet..."). */
  busyText?: string;
  error: string | null;
  /** Neutral confirmation, e.g. "Payment confirmed. Press Connect to enter." */
  notice: string | null;
  /** Shows an "Install MetaMask" link next to the error. */
  showInstallLink?: boolean;
}

/**
 * What visitors see before they have connected and paid: only the welcome statement and one button.
 * The chat itself (Open Chat, Private, Groups ...) is not rendered until access is granted.
 */
export default function WelcomeGate({
  onConnect,
  label,
  busy,
  busyText,
  error,
  notice,
  showInstallLink,
}: WelcomeGateProps) {
  return (
    <section className="wg" aria-labelledby="wg-headline">
      <div className="wg__stage">
        <DotField className="wg__field" />
        <p className="wg__caption">1 in 10,000</p>
        <h1 id="wg-headline" className="wg__headline">
          Welcome to Zyphra.in
        </h1>
        <p className="wg__subline">For 1% of 1%</p>

        <button type="button" className="btn-solid wg__connect" onClick={onConnect} disabled={busy}>
          {busy ? <Loader2 size={16} className="wg__spin" /> : <Wallet size={16} />}
          <span>{busy ? busyText || 'Working...' : label}</span>
        </button>

        <div className="wg__status" role="status" aria-live="polite">
          {error && (
            <p className="wg__error" role="alert">
              {error}
              {showInstallLink && (
                <>
                  {' '}
                  <a href="https://metamask.io/download/" target="_blank" rel="noopener noreferrer">
                    Install MetaMask
                  </a>
                </>
              )}
            </p>
          )}
          {!error && notice && <p className="wg__notice">{notice}</p>}
        </div>
      </div>
    </section>
  );
}
