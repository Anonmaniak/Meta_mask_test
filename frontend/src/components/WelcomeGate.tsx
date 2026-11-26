import { Loader2, Wallet, Lock, KeyRound, Coins } from 'lucide-react';
import './WelcomeGate.css';

interface WelcomeGateProps {
  /** Click handler for the main button (scan MetaMask -> verify wallet -> pay or enter). */
  onConnect: () => void;
  /** Label shown on the main Connect button. */
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
 * What visitors see before they have connected and paid: who we are, why it is safe, and one button.
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
        <div className="wg__copy">
          <h1 id="wg-headline" className="wg__headline">
            For the one percent of the one percent.
          </h1>
          <p className="wg__lede">
            Zyphra is a private members&rsquo; club. Speak freely in end-to-end encrypted chats and
            groups, with a membership tied to nothing but your wallet.
          </p>

          <div className="wg__actions">
            <button type="button" className="btn-solid wg__connect" onClick={onConnect} disabled={busy}>
              {busy ? <Loader2 size={18} className="wg__spin" /> : <Wallet size={18} />}
              <span>{busy ? busyText || 'Working...' : label}</span>
            </button>
            <p className="wg__hint">You sign in with your MetaMask wallet. We never ask for an email or phone number.</p>
          </div>

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

          <ul className="wg__points">
            <li>
              <Lock size={18} aria-hidden="true" />
              <span>
                <strong>Private by design.</strong> Private chats and groups are end-to-end encrypted. Not even we can read them.
              </span>
            </li>
            <li>
              <KeyRound size={18} aria-hidden="true" />
              <span>
                <strong>Your wallet is your identity.</strong> No password to remember, and nothing else to hand over.
              </span>
            </li>
            <li>
              <Coins size={18} aria-hidden="true" />
              <span>
                <strong>Simple membership.</strong> Pay monthly or yearly in ETH. Some private groups have their own subscription.
              </span>
            </li>
          </ul>
        </div>

        <div className="wg__object" aria-hidden="true">
          <div className="mcard wg__card">
            <div className="mcard__top">
              <span className="mcard__brand">Zyphra</span>
              <span className="mcard__seal">Z</span>
            </div>
            <div className="mcard__main">
              <span className="mcard__name">Members&rsquo; Club</span>
              <span className="mcard__addr mcard__addr--text">Wallet-only identity</span>
            </div>
            <div className="mcard__foot">
              <div>
                <div className="mcard__label">Membership</div>
                <div className="mcard__value">1 in 10,000</div>
              </div>
              <span className="mcard__state is-soon">
                <i /> Members only
              </span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}