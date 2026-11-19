import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  fetchPlatformPricing,
  submitPaymentForVerification,
  type PlatformPricing,
} from '../services/platformApi';
import { isMetaMaskInstalled } from '../services/web3';
import { X, ShieldCheck, Loader2, AlertCircle, CheckCircle2, Wallet } from 'lucide-react';

interface PlatformAdmissionModalProps {
  isOpen: boolean;
  onClose: () => void;
  walletAddress: string | null;
  onSuccess: () => void;
}

const CHAIN_NAMES: Record<number, string> = {
  1: 'Ethereum Mainnet',
  11155111: 'Sepolia (test network)',
};

const POLL_EVERY_MS = 4000;
const POLL_FOR_MS = 5 * 60 * 1000;
const QUOTE_REFRESH_MS = 30000;

type Phase = 'quote' | 'wallet' | 'confirming' | 'success';

const pendingKey = (addr: string) => `zyphra_pending_entry_tx:${addr.toLowerCase()}`;

function readPending(addr: string): { hash: string; chainId: number } | null {
  try {
    const raw = localStorage.getItem(pendingKey(addr));
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}
function writePending(addr: string, value: { hash: string; chainId: number } | null) {
  try {
    if (value) localStorage.setItem(pendingKey(addr), JSON.stringify(value));
    else localStorage.removeItem(pendingKey(addr));
  } catch {
    // storage unavailable: payment still works, it just cannot be resumed after a refresh
  }
}

const shortHash = (h: string) => `${h.slice(0, 10)}...${h.slice(-8)}`;

function formatUsd(n: number): string {
  return n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

export const PlatformAdmissionModal: React.FC<PlatformAdmissionModalProps> = ({
  isOpen,
  onClose,
  walletAddress,
  onSuccess,
}) => {
  const [pricing, setPricing] = useState<PlatformPricing | null>(null);
  const [loading, setLoading] = useState(true);
  const [phase, setPhase] = useState<Phase>('quote');
  const [error, setError] = useState<string | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);
  const aliveRef = useRef(false);
  const busyRef = useRef(false);

  const loadPricing = useCallback(async (): Promise<PlatformPricing | null> => {
    try {
      const p = await fetchPlatformPricing();
      if (aliveRef.current) setPricing(p);
      return p;
    } catch (err) {
      if (aliveRef.current) {
        setError(err instanceof Error ? err.message : 'Could not load the membership price.');
      }
      return null;
    }
  }, []);

  /** Asks the server to verify `hash` until it is confirmed, failed, or we run out of time. */
  const confirmPayment = useCallback(
    async (hash: string, chainId: number) => {
      if (!walletAddress) return;
      setPhase('confirming');
      setTxHash(hash);
      const startedAt = Date.now();
      let lastReason = '';
      while (aliveRef.current && Date.now() - startedAt < POLL_FOR_MS) {
        try {
          const res = await submitPaymentForVerification(hash, chainId, 'platform_entry');
          if (res.success && res.status === 'verified') {
            writePending(walletAddress, null);
            if (!aliveRef.current) return;
            setPhase('success');
            setTimeout(() => {
              if (!aliveRef.current) return;
              onSuccess();
              onClose();
            }, 1400);
            return;
          }
          if (res.status === 'failed') {
            writePending(walletAddress, null);
            if (aliveRef.current) {
              setPhase('quote');
              setTxHash(null);
              setError(
                res.reason ||
                'The payment could not be verified. If you were charged, contact the admin with your transaction hash.'
              );
              void loadPricing();
            }
            return;
          }
          lastReason = res.reason || '';
        } catch (err: any) {
          // 409 = hash belongs to another account; other errors: keep trying briefly, then surface
          if (err?.status === 409 || err?.status === 400) {
            writePending(walletAddress, null);
            if (aliveRef.current) {
              setPhase('quote');
              setTxHash(null);
              setError(err.message);
            }
            return;
          }
          lastReason = err?.message || lastReason;
        }
        await new Promise((r) => setTimeout(r, POLL_EVERY_MS));
      }
      if (aliveRef.current) {
        setError(
          `Still waiting for the network to confirm your payment${lastReason ? ` (${lastReason})` : ''}. ` +
          'You can close this window; it will keep checking next time you connect.'
        );
      }
    },
    [walletAddress, onSuccess, onClose, loadPricing]
  );

  // Open / close lifecycle: load the price, resume any payment that was still confirming.
  useEffect(() => {
    if (!isOpen) {
      aliveRef.current = false;
      return;
    }
    aliveRef.current = true;
    setError(null);
    setPhase('quote');
    setTxHash(null);
    setLoading(true);
    loadPricing().finally(() => {
      if (aliveRef.current) setLoading(false);
    });
    if (walletAddress) {
      const pending = readPending(walletAddress);
      if (pending) void confirmPayment(pending.hash, pending.chainId);
    }
    const refresh = setInterval(() => {
      if (!busyRef.current && aliveRef.current) void loadPricing();
    }, QUOTE_REFRESH_MS);
    return () => {
      aliveRef.current = false;
      clearInterval(refresh);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen, walletAddress]);

  if (!isOpen) return null;

  const handlePay = async () => {
    setError(null);
    if (!isMetaMaskInstalled()) {
      setError('MetaMask wallet not available');
      return;
    }
    if (!walletAddress) {
      setError('Connect your MetaMask wallet first.');
      return;
    }
    busyRef.current = true;
    try {
      // Always pay against a fresh quote (the ETH price moves)
      const fresh = (await loadPricing()) || pricing;
      if (!fresh || !fresh.authorized_payment_destination) {
        throw new Error('The payment address is not configured yet. Please contact the administrator.');
      }
      const valueWei = BigInt(fresh.platform_entry_fee_wei || '0');
      if (valueWei <= 0n) {
        throw new Error('Membership is currently free. Close this window and press Connect.');
      }

      const ethereum = (window as any).ethereum;
      setPhase('wallet');

      // Network must be one the server accepts
      const allowed = fresh.allowed_payment_chain_ids?.length ? fresh.allowed_payment_chain_ids : [1];
      let chainId = parseInt(await ethereum.request({ method: 'eth_chainId' }), 16);
      if (!allowed.includes(chainId)) {
        try {
          await ethereum.request({
            method: 'wallet_switchEthereumChain',
            params: [{ chainId: '0x' + allowed[0].toString(16) }],
          });
          chainId = allowed[0];
        } catch {
          throw new Error(
            `Switch MetaMask to ${allowed.map((c) => CHAIN_NAMES[c] || `chain ${c}`).join(' or ')} and try again.`
          );
        }
      }

      // Friendly balance check before MetaMask opens
      try {
        const balHex: string = await ethereum.request({
          method: 'eth_getBalance',
          params: [walletAddress, 'latest'],
        });
        if (BigInt(balHex) < valueWei) {
          throw new Error(
            `Not enough ETH on ${CHAIN_NAMES[chainId] || `chain ${chainId}`}: you need ${fresh.platform_entry_fee_eth} ETH plus the network fee.`
          );
        }
      } catch (balErr) {
        if (balErr instanceof Error && balErr.message.startsWith('Not enough ETH')) throw balErr;
        // balance lookup failed: let MetaMask decide
      }

      const hash: string = await ethereum.request({
        method: 'eth_sendTransaction',
        params: [
          {
            from: walletAddress,
            to: fresh.authorized_payment_destination,
            value: '0x' + valueWei.toString(16),
          },
        ],
      });
      writePending(walletAddress, { hash, chainId });
      await confirmPayment(hash, chainId);
    } catch (err: any) {
      setPhase('quote');
      if (err?.code === 4001) setError('You cancelled the payment in MetaMask.');
      else setError(err instanceof Error ? err.message : String(err));
    } finally {
      busyRef.current = false;
    }
  };

  const feeUsd = pricing ? formatUsd(pricing.platform_entry_fee_usd) : null;
  const working = phase === 'wallet' || phase === 'confirming';
  const sourceNote =
    pricing?.rate_source === 'admin_fixed'
      ? 'Fixed rate set by the admin'
      : pricing?.rate_source === 'live_stale'
        ? 'Last known market rate'
        : 'Live market rate';

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="admission-title"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(0,0,0,0.78)',
        backdropFilter: 'blur(6px)',
        zIndex: 9999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1rem',
      }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '460px',
          background: 'var(--bg-card)',
          color: 'var(--text-main)',
          borderRadius: '16px',
          border: '1px solid var(--border-strong)',
          boxShadow: 'var(--shadow-console)',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            padding: '1.1rem 1.4rem',
            borderBottom: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.7rem' }}>
            <ShieldCheck size={20} />
            <div>
              <h3 id="admission-title" style={{ margin: 0, fontSize: '1.05rem', fontWeight: 600 }}>
                Join Zyphra
              </h3>
              <p style={{ margin: 0, fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                One-time membership, paid in ETH
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={phase === 'wallet'}
            aria-label="Close"
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--text-secondary)',
              cursor: phase === 'wallet' ? 'not-allowed' : 'pointer',
              padding: 4,
            }}
          >
            <X size={18} />
          </button>
        </div>

        <div style={{ padding: '1.4rem', display: 'flex', flexDirection: 'column', gap: '1.1rem' }}>
          {loading && !pricing ? (
            <div style={{ textAlign: 'center', padding: '1.5rem 0' }}>
              <Loader2 size={26} className="wg__spin" />
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem' }}>Getting today&apos;s price...</p>
            </div>
          ) : phase === 'success' ? (
            <div style={{ textAlign: 'center', padding: '1rem 0' }}>
              <CheckCircle2 size={44} />
              <h4 style={{ margin: '0.7rem 0 0.2rem', fontSize: '1.1rem' }}>Payment confirmed</h4>
              <p style={{ margin: 0, fontSize: '0.88rem', color: 'var(--text-secondary)' }}>
                Your wallet is now a member. Press Connect to enter.
              </p>
            </div>
          ) : (
            <>
              {pricing && (
                <div
                  style={{
                    border: '1px solid var(--border-strong)',
                    borderRadius: 12,
                    padding: '1rem 1.1rem',
                    background: 'var(--bg-surface)',
                  }}
                >
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>Membership price</div>
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginTop: 4, flexWrap: 'wrap' }}>
                    <span style={{ fontSize: '2rem', fontWeight: 700, fontFamily: "'Outfit', sans-serif" }}>
                      ${feeUsd}
                    </span>
                    <span style={{ fontSize: '1.05rem', fontFamily: 'ui-monospace, monospace' }}>
                      = {pricing.platform_entry_fee_eth} ETH
                    </span>
                  </div>
                  <div style={{ marginTop: 6, fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                    1 ETH = ${formatUsd(pricing.eth_usd_price)} · {sourceNote}. The price refreshes automatically.
                  </div>
                </div>
              )}

              {phase === 'confirming' && (
                <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start', fontSize: '0.88rem' }}>
                  <Loader2 size={18} className="wg__spin" style={{ flexShrink: 0, marginTop: 2 }} />
                  <div>
                    Waiting for the network to confirm your payment. This usually takes under a minute.
                    {txHash && (
                      <div
                        style={{
                          marginTop: 4,
                          fontFamily: 'ui-monospace, monospace',
                          fontSize: '0.76rem',
                          color: 'var(--text-secondary)',
                        }}
                      >
                        {shortHash(txHash)}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {error && (
                <div
                  role="alert"
                  style={{
                    display: 'flex',
                    gap: 8,
                    alignItems: 'flex-start',
                    border: '1px solid var(--border-focus)',
                    borderRadius: 10,
                    padding: '0.7rem 0.85rem',
                    fontSize: '0.85rem',
                    lineHeight: 1.45,
                  }}
                >
                  <AlertCircle size={16} style={{ flexShrink: 0, marginTop: 2 }} />
                  <span>{error}</span>
                </div>
              )}

              {phase !== 'confirming' && (
                <button
                  type="button"
                  className="btn-solid"
                  onClick={handlePay}
                  disabled={working || !pricing}
                  style={{ justifyContent: 'center', padding: '0.8rem 1rem', borderRadius: 9999, gap: 8 }}
                >
                  {phase === 'wallet' ? (
                    <>
                      <Loader2 size={16} className="wg__spin" /> Confirm in MetaMask...
                    </>
                  ) : (
                    <>
                      <Wallet size={16} /> Pay {pricing ? `$${feeUsd} (${pricing.platform_entry_fee_eth} ETH)` : ''}
                    </>
                  )}
                </button>
              )}

              <p style={{ margin: 0, fontSize: '0.76rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                Your membership is tied to your wallet, so you can connect from any device without paying again.
              </p>
            </>
          )}
        </div>
      </div>
    </div>
  );
};