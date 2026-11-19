import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  fetchGroupPricing,
  submitPaymentForVerification,
  requestJoinPublicGroup,
  type GroupPricing,
} from '../services/platformApi';
import { isMetaMaskInstalled } from '../services/web3';
import { X, Users, Loader2, AlertCircle, CheckCircle2, Wallet } from 'lucide-react';

interface PaidGroupAdmissionModalProps {
  groupId: string | null;
  groupName?: string;
  isOpen: boolean;
  onClose: () => void;
  walletAddress: string | null;
  onSuccess: () => void;
}

const CHAIN_NAMES: Record<number, string> = { 1: 'Ethereum Mainnet', 11155111: 'Sepolia (test network)' };
const POLL_EVERY_MS = 4000;
const POLL_FOR_MS = 5 * 60 * 1000;
const QUOTE_REFRESH_MS = 30000;

type Phase = 'quote' | 'wallet' | 'confirming' | 'success';

const pendingKey = (addr: string, groupId: string) => `zyphra_pending_group_tx:${addr.toLowerCase()}:${groupId}`;
function readPending(addr: string, groupId: string): { hash: string; chainId: number } | null {
  try {
    const raw = localStorage.getItem(pendingKey(addr, groupId));
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}
function writePending(addr: string, groupId: string, value: { hash: string; chainId: number } | null) {
  try {
    if (value) localStorage.setItem(pendingKey(addr, groupId), JSON.stringify(value));
    else localStorage.removeItem(pendingKey(addr, groupId));
  } catch {
    // storage unavailable: payment still works, it just cannot be resumed after a refresh
  }
}

const shortHash = (h: string) => `${h.slice(0, 10)}...${h.slice(-8)}`;
const usd = (n: number) => n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });

export const PaidGroupAdmissionModal: React.FC<PaidGroupAdmissionModalProps> = ({
  groupId,
  groupName,
  isOpen,
  onClose,
  walletAddress,
  onSuccess,
}) => {
  const [pricing, setPricing] = useState<GroupPricing | null>(null);
  const [loading, setLoading] = useState(true);
  const [phase, setPhase] = useState<Phase>('quote');
  const [error, setError] = useState<string | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);
  const [joinNote, setJoinNote] = useState<string | null>(null);
  const aliveRef = useRef(false);
  const busyRef = useRef(false);

  const loadPricing = useCallback(async (): Promise<GroupPricing | null> => {
    if (!groupId) return null;
    try {
      const p = await fetchGroupPricing(groupId);
      if (aliveRef.current) setPricing(p);
      return p;
    } catch (err) {
      if (aliveRef.current) setError(err instanceof Error ? err.message : 'Could not load the group price.');
      return null;
    }
  }, [groupId]);

  const confirmPayment = useCallback(
    async (hash: string, chainId: number) => {
      if (!walletAddress || !groupId) return;
      setPhase('confirming');
      setTxHash(hash);
      const startedAt = Date.now();
      let lastReason = '';
      while (aliveRef.current && Date.now() - startedAt < POLL_FOR_MS) {
        try {
          const res = await submitPaymentForVerification(hash, chainId, 'group_entry', groupId);
          if (res.success && res.status === 'verified') {
            writePending(walletAddress, groupId, null);
            // Paid: ask to join straight away so the user does not have to hunt for another button.
            try {
              await requestJoinPublicGroup(groupId);
              if (aliveRef.current) setJoinNote('Your join request was sent to the group admins.');
            } catch (joinErr: any) {
              if (aliveRef.current) {
                setJoinNote(
                  joinErr?.message
                    ? `Paid. ${joinErr.message}`
                    : 'Paid. Press Request Join on the group to continue.'
                );
              }
            }
            window.dispatchEvent(new Event('zyphra:groups-changed'));
            if (!aliveRef.current) return;
            setPhase('success');
            setTimeout(() => {
              if (!aliveRef.current) return;
              onSuccess();
              onClose();
            }, 2200);
            return;
          }
          if (res.status === 'failed') {
            writePending(walletAddress, groupId, null);
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
          if (err?.status === 409 || err?.status === 400) {
            writePending(walletAddress, groupId, null);
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
          'You can close this window; it will keep checking when you reopen it.'
        );
      }
    },
    [walletAddress, groupId, onSuccess, onClose, loadPricing]
  );

  useEffect(() => {
    if (!isOpen || !groupId) {
      aliveRef.current = false;
      return;
    }
    aliveRef.current = true;
    setError(null);
    setPhase('quote');
    setTxHash(null);
    setJoinNote(null);
    setLoading(true);
    loadPricing().finally(() => {
      if (aliveRef.current) setLoading(false);
    });
    if (walletAddress) {
      const pending = readPending(walletAddress, groupId);
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
  }, [isOpen, groupId, walletAddress]);

  if (!isOpen || !groupId) return null;

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
      const fresh = (await loadPricing()) || pricing;
      if (!fresh || !fresh.authorized_payment_destination) {
        throw new Error('The payment address is not configured yet. Please contact the administrator.');
      }
      if (!fresh.is_paid) throw new Error('This group is free now. Close this window and request to join.');
      const valueWei = BigInt(fresh.entry_fee_wei || '0');
      if (valueWei <= 0n) throw new Error('This group has no entry price set.');

      const ethereum = (window as any).ethereum;
      setPhase('wallet');

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

      try {
        const balHex: string = await ethereum.request({ method: 'eth_getBalance', params: [walletAddress, 'latest'] });
        if (BigInt(balHex) < valueWei) {
          throw new Error(
            `Not enough ETH on ${CHAIN_NAMES[chainId] || `chain ${chainId}`}: you need ${fresh.entry_fee_eth} ETH plus the network fee.`
          );
        }
      } catch (balErr) {
        if (balErr instanceof Error && balErr.message.startsWith('Not enough ETH')) throw balErr;
      }

      const hash: string = await ethereum.request({
        method: 'eth_sendTransaction',
        params: [{ from: walletAddress, to: fresh.authorized_payment_destination, value: '0x' + valueWei.toString(16) }],
      });
      writePending(walletAddress, groupId, { hash, chainId });
      await confirmPayment(hash, chainId);
    } catch (err: any) {
      setPhase('quote');
      if (err?.code === 4001) setError('You cancelled the payment in MetaMask.');
      else setError(err instanceof Error ? err.message : String(err));
    } finally {
      busyRef.current = false;
    }
  };

  const working = phase === 'wallet' || phase === 'confirming';
  const feeUsd = pricing ? usd(pricing.entry_fee_usd) : null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="group-admission-title"
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
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.7rem', minWidth: 0 }}>
            <Users size={20} />
            <div style={{ minWidth: 0 }}>
              <h3 id="group-admission-title" style={{ margin: 0, fontSize: '1.05rem', fontWeight: 600 }}>
                Join {groupName || 'this group'}
              </h3>
              <p style={{ margin: 0, fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                One-time entry fee, paid in ETH
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
                {joinNote || 'Your entry fee is paid.'}
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
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>Entry fee</div>
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginTop: 4, flexWrap: 'wrap' }}>
                    <span style={{ fontSize: '2rem', fontWeight: 700, fontFamily: "'Outfit', sans-serif" }}>
                      ${feeUsd}
                    </span>
                    <span style={{ fontSize: '1.05rem', fontFamily: 'ui-monospace, monospace' }}>
                      = {pricing.entry_fee_eth} ETH
                    </span>
                  </div>
                  <div style={{ marginTop: 6, fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                    1 ETH = ${usd(pricing.eth_usd_price)} ·{' '}
                    {pricing.rate_source === 'admin_fixed' ? 'Fixed rate set by the admin' : 'Live market rate'}. The
                    price refreshes automatically.
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
                      <Wallet size={16} /> Pay {pricing ? `$${feeUsd} (${pricing.entry_fee_eth} ETH)` : ''}
                    </>
                  )}
                </button>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};