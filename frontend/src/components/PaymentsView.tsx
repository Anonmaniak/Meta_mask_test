import React, { useCallback, useEffect, useState } from 'react';
import { CreditCard, RefreshCw, Users, Loader2, Wallet, Receipt } from 'lucide-react';
import {
  fetchMembershipStatus,
  fetchMyPaymentHistory,
  daysLeft,
  formatDate,
  type PaymentRecord,
  type PlatformMembershipStatus,
} from '../services/platformApi';
import { formatAddress } from '../services/web3';
import { PaymentsViewSkeleton } from './Skeleton';

interface PaymentsViewProps {
  /** Connected wallet (null = not connected). */
  account: string | null;
  /** The member's @username, when they have chosen one. */
  username?: string | null;
  /** True once the wallet has signed in (SIWE). Payments data needs a session. */
  signedIn: boolean;
  onRenewMembership: () => void;
  onRenewGroup: (groupId: string, groupName: string) => void;
}

type Tone = 'ok' | 'warn' | 'bad';

/** Plain-language standing of a subscription. */
function standing(active: boolean, until: string | null): { tone: Tone; label: string } {
  if (!until) return { tone: 'bad', label: 'Not paid' };
  if (!active) return { tone: 'bad', label: 'Expired' };
  const d = daysLeft(until);
  return d <= 7 ? { tone: 'warn', label: d <= 1 ? 'Ends today' : `${d} days left` } : { tone: 'ok', label: 'Active' };
}

const Chip: React.FC<{ tone: Tone; children: React.ReactNode }> = ({ tone, children }) => (
  <span className={`chip chip--${tone}`}>{children}</span>
);

const purposeLabel = (p: PaymentRecord): string =>
  (p.metadata?.purpose || 'platform_entry') === 'group_entry' ? 'Group' : 'Membership';

const periodLabel = (p: PaymentRecord): string => ((p.metadata?.billing_period || 'monthly') === 'yearly' ? 'Yearly' : 'Monthly');

const statusLabel = (s: PaymentRecord['status']): { tone: Tone; label: string } => {
  switch (s) {
    case 'verified':
      return { tone: 'ok', label: 'Confirmed' };
    case 'pending':
      return { tone: 'warn', label: 'Pending' };
    case 'failed':
      return { tone: 'bad', label: 'Failed' };
    case 'cancelled':
      return { tone: 'bad', label: 'Cancelled' };
    default:
      return { tone: 'bad', label: 'Reversed' };
  }
};

export const PaymentsView: React.FC<PaymentsViewProps> = ({
  account,
  username,
  signedIn,
  onRenewMembership,
  onRenewGroup,
}) => {
  const [status, setStatus] = useState<PlatformMembershipStatus | null>(null);
  const [history, setHistory] = useState<PaymentRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!signedIn) return;
    setLoading(true);
    setError(null);
    try {
      const [s, h] = await Promise.all([fetchMembershipStatus(), fetchMyPaymentHistory(30)]);
      setStatus(s);
      setHistory(h.payments);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'We could not load your membership. Please try again.');
    } finally {
      setLoading(false);
    }
  }, [signedIn]);

  useEffect(() => {
    void load();
    // After a payment (or an expiry notice elsewhere) the app announces a change: refresh when asked.
    const refresh = () => void load();
    window.addEventListener('zyphra:groups-changed', refresh);
    return () => window.removeEventListener('zyphra:groups-changed', refresh);
  }, [load]);

  if (!account || !signedIn) {
    return (
      <div className="deck-card" style={{ textAlign: 'center', padding: '56px 24px', maxWidth: 560, margin: '0 auto' }}>
        <CreditCard size={32} style={{ color: 'var(--accent)' }} />
        <div className="deck-title" style={{ justifyContent: 'center', marginTop: 12 }}>Membership</div>
        <div className="deck-subtitle">Connect and sign in with your wallet to see your membership and subscriptions.</div>
      </div>
    );
  }

  const free = Boolean(status?.membership_is_free);
  // Free membership given by an admin (the server only sends active grants)
  const gift = status?.platform_free_access || null;
  const giftDays = gift && !gift.lifetime ? daysLeft(gift.expires_at) : null;
  const platformStanding = status
    ? standing(status.is_platform_paid && !!status.platform_paid_until, status.platform_paid_until)
    : null;
  const cardState: { cls: string; text: string } = !status
    ? { cls: 'is-soon', text: 'Loading' }
    : free
      ? { cls: '', text: 'Free membership' }
      : gift
        ? { cls: giftDays !== null && giftDays <= 7 ? 'is-soon' : '', text: 'Free access' }
        : platformStanding?.tone === 'ok'
          ? { cls: '', text: 'Active' }
          : platformStanding?.tone === 'warn'
            ? { cls: 'is-soon', text: platformStanding.label }
            : { cls: 'is-off', text: platformStanding?.label || 'Not active' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 28, maxWidth: 1040, margin: '0 auto' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', gap: 16, flexWrap: 'wrap' }}>
        <div>
          <h1 style={{ fontSize: 'clamp(1.9rem, 3.4vw, 2.6rem)', fontWeight: 400, letterSpacing: '-0.02em' }}>Membership</h1>
          <p className="deck-subtitle" style={{ maxWidth: '56ch' }}>
            Your membership and each paid group renew monthly (30 days) or yearly (365 days). Renewing adds time on top of
            what you have left.
          </p>
        </div>
        <button type="button" className="btn-outline" onClick={() => void load()} disabled={loading}>
          {loading ? <Loader2 size={15} className="wg__spin" /> : <RefreshCw size={15} />}
          <span>Refresh</span>
        </button>
      </div>

      {error && (
        <div role="alert" className="wg__error" style={{ maxWidth: '70ch' }}>
          {error}
        </div>
      )}

      {loading && !status ? (
        <PaymentsViewSkeleton />
      ) : (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'minmax(0, 440px) minmax(0, 1fr)',
            gap: 'clamp(24px, 4vw, 56px)',
            alignItems: 'start',
          }}
          className="membership-grid"
        >
          {/* The membership card: real data */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
            <div className="mcard">
              <div className="mcard__top">
                <span className="mcard__brand">Zyphra</span>
                <span className="mcard__seal">Z</span>
              </div>
              <div className="mcard__main">
                <span className="mcard__name">{username ? `@${username}` : 'Member'}</span>
                <span className="mcard__addr">{formatAddress(account, 6)}</span>
              </div>
              <div className="mcard__foot">
                <div>
                  <div className="mcard__label">{free ? 'Membership' : 'Valid until'}</div>
                  <div className="mcard__value">
                    {free
                      ? 'Free of charge'
                      : gift
                        ? gift.lifetime
                          ? 'No end date'
                          : formatDate(gift.expires_at)
                        : status?.platform_paid_until
                          ? formatDate(status.platform_paid_until)
                          : 'Not yet paid'}
                  </div>
                </div>
                <span className={`mcard__state ${cardState.cls}`}>
                  <i /> {cardState.text}
                </span>
              </div>
            </div>

            {status && !free && gift && (
              <p className="deck-subtitle" style={{ marginTop: 0 }}>
                An admin gave you free membership{gift.lifetime ? ' with no end date' : ` until ${formatDate(gift.expires_at)}`}, so
                there is nothing to pay.{gift.lifetime ? '' : ' You can pay for a plan once it ends.'}
              </p>
            )}
            {status && !free && !gift && (
              <>
                <button type="button" className="btn-solid" style={{ alignSelf: 'flex-start' }} onClick={onRenewMembership}>
                  <Wallet size={17} />
                  <span>{status.is_platform_paid ? 'Renew or extend' : 'Pay for membership'}</span>
                </button>
                <p className="deck-subtitle" style={{ marginTop: 0 }}>
                  Monthly ${status.pricing.plans.monthly.usd.toFixed(2)}, or yearly ${status.pricing.plans.yearly.usd.toFixed(2)}.
                  Paid in ETH at the current rate.
                </p>
              </>
            )}
            {status && free && (
              <p className="deck-subtitle" style={{ marginTop: 0 }}>
                Membership is free right now, so there is nothing to pay. Some groups may have their own subscription.
              </p>
            )}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 28, minWidth: 0 }}>
            <section>
              <h2 style={{ fontSize: '1.5rem', display: 'flex', alignItems: 'center', gap: 10 }}>
                <Users size={20} style={{ color: 'var(--accent)' }} /> Paid groups
              </h2>
              {status && status.group_subscriptions.length === 0 && (status.group_free_access || []).length === 0 ? (
                <p className="deck-subtitle">
                  You are not in any paid groups. When you join one, its renewal date will appear here.
                </p>
              ) : (
                <div style={{ marginTop: 6 }}>
                  {(status?.group_free_access || []).map((g) => (
                    <div key={`free-${g.group_id}`} className="list-row">
                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontWeight: 600, fontSize: '1.02rem' }}>{g.group_name}</div>
                        <div className="deck-subtitle" style={{ marginTop: 2 }}>
                          Free access from an admin{g.lifetime ? ', no end date' : ` until ${formatDate(g.expires_at)}`}
                        </div>
                      </div>
                      <Chip tone="ok">Free access</Chip>
                    </div>
                  ))}
                  {status?.group_subscriptions
                    .filter((g) => !(status.group_free_access || []).some((f) => f.group_id === g.group_id))
                    .map((g) => {
                      const st = standing(g.active, g.paid_until);
                      return (
                        <div key={g.group_id} className="list-row">
                          <div style={{ minWidth: 0 }}>
                            <div style={{ fontWeight: 600, fontSize: '1.02rem' }}>{g.group_name}</div>
                            <div className="deck-subtitle" style={{ marginTop: 2 }}>
                              {g.active ? `Active until ${formatDate(g.paid_until)}` : `Expired on ${formatDate(g.paid_until)}`}
                              {g.last_period === 'yearly' ? ', yearly plan' : ', monthly plan'}
                            </div>
                          </div>
                          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                            <Chip tone={st.tone}>{st.label}</Chip>
                            <button type="button" className="btn-outline" onClick={() => onRenewGroup(g.group_id, g.group_name)}>
                              Renew
                            </button>
                          </div>
                        </div>
                      );
                    })}
                </div>
              )}
            </section>

            <section>
              <h2 style={{ fontSize: '1.5rem', display: 'flex', alignItems: 'center', gap: 10 }}>
                <Receipt size={20} style={{ color: 'var(--accent)' }} /> Payment history
              </h2>
              {history.length === 0 ? (
                <p className="deck-subtitle">No payments yet.</p>
              ) : (
                <div style={{ overflowX: 'auto', marginTop: 8 }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.92rem' }}>
                    <thead>
                      <tr style={{ textAlign: 'left', color: 'var(--text-muted)' }}>
                        {['Date', 'For', 'Plan', 'Amount', 'Status'].map((h) => (
                          <th key={h} style={{ padding: '8px 10px 8px 0', fontWeight: 600, fontSize: '0.9rem' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((p) => {
                        const st = statusLabel(p.status);
                        return (
                          <tr key={p.payment_id} style={{ borderTop: '1px solid var(--border-subtle)' }}>
                            <td style={{ padding: '12px 10px 12px 0' }}>{formatDate(p.verified_at || p.created_at)}</td>
                            <td style={{ padding: '12px 10px 12px 0' }}>{purposeLabel(p)}</td>
                            <td style={{ padding: '12px 10px 12px 0' }}>{periodLabel(p)}</td>
                            <td style={{ padding: '12px 10px 12px 0', fontVariantNumeric: 'tabular-nums' }}>
                              {p.status === 'verified' ? `${p.amount_formatted} ${p.currency}` : '–'}
                            </td>
                            <td style={{ padding: '12px 0' }}>
                              <Chip tone={st.tone}>{st.label}</Chip>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </div>
        </div>
      )}
    </div>
  );
};

export default PaymentsView;