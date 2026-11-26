import React, { useCallback, useEffect, useRef, useState } from 'react';
import { LifeBuoy, RefreshCw } from 'lucide-react';
import {
  adminGetSupportThread,
  adminListSupportThreads,
  adminReplySupportThread,
  adminSetSupportThreadStatus,
  type SupportMessage,
  type SupportThread,
} from '../services/platformApi';
import { SupportConversation, formatSupportTime } from './SupportConversation';
import { ChatMessagesSkeleton, ListRowsSkeleton } from './Skeleton';

interface AdminSupportInboxProps {
  adminToken: string;
}

type Filter = 'open' | 'closed' | 'all';

/** Admin side of "Talk to admin": inbox, replies, close / reopen. */
export const AdminSupportInbox: React.FC<AdminSupportInboxProps> = ({ adminToken }) => {
  const [filter, setFilter] = useState<Filter>('open');
  const [threads, setThreads] = useState<SupportThread[]>([]);
  const [unreadTotal, setUnreadTotal] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<SupportThread | null>(null);
  const [messages, setMessages] = useState<SupportMessage[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [listLoadedOnce, setListLoadedOnce] = useState(false);
  const aliveRef = useRef(true);

  const loadList = useCallback(async () => {
    try {
      const res = await adminListSupportThreads(filter === 'all' ? null : filter, adminToken);
      if (!aliveRef.current) return;
      setThreads(res.threads);
      setUnreadTotal(res.unread_total);
      setError(null);
    } catch (err: any) {
      if (aliveRef.current) setError(err?.message || 'Could not load the support inbox.');
    } finally {
      if (aliveRef.current) setListLoadedOnce(true);
    }
  }, [filter, adminToken]);

  const loadThread = useCallback(
    async (id: string) => {
      try {
        const res = await adminGetSupportThread(id, adminToken);
        if (!aliveRef.current) return;
        setSelected(res.thread);
        setMessages(res.messages);
      } catch (err: any) {
        if (aliveRef.current) setError(err?.message || 'Could not open this conversation.');
      }
    },
    [adminToken]
  );

  useEffect(() => {
    aliveRef.current = true;
    void loadList();
    const t = setInterval(() => {
      if (document.visibilityState === 'visible') void loadList();
    }, 8000);
    return () => {
      aliveRef.current = false;
      clearInterval(t);
    };
  }, [loadList]);

  useEffect(() => {
    if (!selectedId) return;
    void loadThread(selectedId).then(() => loadList());
    const t = setInterval(() => {
      if (document.visibilityState === 'visible') void loadThread(selectedId);
    }, 5000);
    return () => clearInterval(t);
  }, [selectedId, loadThread, loadList]);

  const who = (t: SupportThread) =>
    t.username ? `@${t.username}` : t.wallet_address ? `${t.wallet_address.slice(0, 6)}...${t.wallet_address.slice(-4)}` : t.user_id;

  return (
    <div className="deck-card" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div className="deck-title" style={{ justifyContent: 'space-between' }}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
          <LifeBuoy size={18} /> Support inbox {unreadTotal > 0 && `(${unreadTotal} unread)`}
        </span>
        <div style={{ display: 'flex', gap: 6 }}>
          {(['open', 'closed', 'all'] as Filter[]).map((f) => (
            <button
              key={f}
              type="button"
              className={filter === f ? 'btn-solid' : 'btn-outline'}
              style={{ padding: '4px 10px', fontSize: '0.9rem' }}
              onClick={() => {
                setFilter(f);
                setSelectedId(null);
              }}
            >
              {f === 'open' ? 'Open' : f === 'closed' ? 'Closed' : 'All'}
            </button>
          ))}
          <button type="button" className="btn-outline" style={{ padding: '4px 8px' }} onClick={() => void loadList()} aria-label="Refresh">
            <RefreshCw size={13} />
          </button>
        </div>
      </div>

      {error && (
        <div role="alert" style={{ fontSize: '0.9rem', fontWeight: 600 }}>
          {error}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 18, alignItems: 'start' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {!listLoadedOnce && threads.length === 0 ? (
            <ListRowsSkeleton count={3} compact />
          ) : threads.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              {filter === 'open' ? 'No open conversations.' : 'Nothing here.'}
            </div>
          ) : null}
          {threads.map((t) => {
            const active = t.thread_id === selectedId;
            return (
              <button
                key={t.thread_id}
                type="button"
                onClick={() => setSelectedId(t.thread_id)}
                style={{
                  textAlign: 'left',
                  padding: '10px 12px',
                  borderRadius: 12,
                  cursor: 'pointer',
                  background: active ? 'var(--bg-card-hover)' : 'var(--bg-input)',
                  border: `1px solid ${active ? 'var(--border-focus)' : 'var(--border-subtle)'}`,
                  color: 'var(--text-main)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                  <span style={{ fontWeight: 600, fontSize: '0.88rem' }}>{t.subject}</span>
                  {t.unread > 0 && (
                    <span
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
                        background: 'var(--bg-pill-active)',
                        color: 'var(--text-inverse)',
                      }}
                    >
                      {t.unread}
                    </span>
                  )}
                </div>
                <div style={{ marginTop: 3, fontSize: '0.9rem', color: 'var(--text-muted)' }}>
                  {who(t)} · {t.status === 'closed' ? 'Closed' : t.last_sender_role === 'user' ? 'Needs reply' : 'Replied'} ·{' '}
                  {formatSupportTime(t.last_message_at)}
                </div>
              </button>
            );
          })}
        </div>

        <div>
          {selectedId && (!selected || selected.thread_id !== selectedId) ? (
            <ChatMessagesSkeleton count={3} />
          ) : selectedId && selected ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontWeight: 700, fontSize: '0.95rem' }}>{selected.subject}</div>
                  <div style={{ fontSize: '0.9rem', color: 'var(--text-muted)', fontFamily: 'ui-monospace, monospace' }}>
                    {who(selected)} · {selected.user_id}
                  </div>
                </div>
                <button
                  type="button"
                  className="btn-outline"
                  style={{ padding: '5px 12px', fontSize: '0.86rem' }}
                  onClick={async () => {
                    try {
                      await adminSetSupportThreadStatus(selectedId, selected.status === 'open' ? 'closed' : 'open', adminToken);
                      await loadThread(selectedId);
                      await loadList();
                    } catch (err: any) {
                      setError(err?.message || 'Could not change the status.');
                    }
                  }}
                >
                  {selected.status === 'open' ? 'Close conversation' : 'Reopen'}
                </button>
              </div>
              <SupportConversation
                messages={messages}
                viewer="admin"
                placeholder="Reply to the member..."
                onSend={async (text) => {
                  await adminReplySupportThread(selectedId, text, adminToken);
                  await loadThread(selectedId);
                  await loadList();
                }}
              />
            </div>
          ) : (
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.88rem' }}>Pick a conversation to read and reply.</div>
          )}
        </div>
      </div>
    </div>
  );
};