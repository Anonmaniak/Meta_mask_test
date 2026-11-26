import React, { useCallback, useEffect, useRef, useState } from 'react';
import { friendlyError } from '../services/friendlyError';
import { LifeBuoy, Plus, ArrowLeft } from 'lucide-react';
import { ChatMessagesSkeleton, ListRowsSkeleton } from './Skeleton';
import {
  createSupportThread,
  fetchMySupportThreads,
  fetchSupportThread,
  sendSupportMessage,
  type SupportMessage,
  type SupportThread,
} from '../services/platformApi';
import { SupportConversation, formatSupportTime } from './SupportConversation';

interface SupportViewProps {
  /** Lets the header show an unread badge. */
  onUnreadChange?: (count: number) => void;
}

const LIST_REFRESH_MS = 8000;
const THREAD_REFRESH_MS = 5000;

const inputStyle: React.CSSProperties = {
  width: '100%',
  background: 'var(--bg-input)',
  border: '1px solid var(--border-strong)',
  borderRadius: 10,
  padding: '9px 12px',
  color: 'var(--text-main)',
  fontSize: '0.88rem',
  fontFamily: 'inherit',
};

/** "Talk to admin": members write to the admin team and read replies here. */
export const SupportView: React.FC<SupportViewProps> = ({ onUnreadChange }) => {
  const [threads, setThreads] = useState<SupportThread[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<SupportThread | null>(null);
  const [messages, setMessages] = useState<SupportMessage[]>([]);
  const [composing, setComposing] = useState(false);
  const [subject, setSubject] = useState('');
  const [firstMessage, setFirstMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const aliveRef = useRef(true);

  const loadList = useCallback(async () => {
    try {
      const res = await fetchMySupportThreads();
      if (!aliveRef.current) return;
      setThreads(res.threads);
      onUnreadChange?.(res.unread_total);
      setError(null);
    } catch (err: any) {
      if (aliveRef.current) setError(friendlyError(err, 'Could not load your conversations.'));
    } finally {
      if (aliveRef.current) setLoading(false);
    }
  }, [onUnreadChange]);

  const loadThread = useCallback(async (id: string) => {
    try {
      const res = await fetchSupportThread(id);
      if (!aliveRef.current) return;
      setSelected(res.thread);
      setMessages(res.messages);
    } catch (err: any) {
      if (aliveRef.current) setError(friendlyError(err, 'Could not open this conversation.'));
    }
  }, []);

  useEffect(() => {
    aliveRef.current = true;
    void loadList();
    const t = setInterval(() => {
      if (document.visibilityState === 'visible') void loadList();
    }, LIST_REFRESH_MS);
    return () => {
      aliveRef.current = false;
      clearInterval(t);
    };
  }, [loadList]);

  // An admin replied (pushed live over the socket): refresh the list and the open conversation now.
  useEffect(() => {
    const onLiveReply = () => {
      void loadList();
      if (selectedId) void loadThread(selectedId);
    };
    window.addEventListener('zyphra:support-reply', onLiveReply);
    return () => window.removeEventListener('zyphra:support-reply', onLiveReply);
  }, [selectedId, loadList, loadThread]);

  useEffect(() => {
    if (!selectedId) return;
    void loadThread(selectedId).then(() => loadList());
    const t = setInterval(() => {
      if (document.visibilityState === 'visible') void loadThread(selectedId);
    }, THREAD_REFRESH_MS);
    return () => clearInterval(t);
  }, [selectedId, loadThread, loadList]);

  const startConversation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const res = await createSupportThread(subject.trim(), firstMessage.trim());
      setSubject('');
      setFirstMessage('');
      setComposing(false);
      await loadList();
      setSelectedId(res.thread.thread_id);
    } catch (err: any) {
      setError(friendlyError(err, 'Could not send your message.'));
    } finally {
      setBusy(false);
    }
  };

  const showThread = Boolean(selectedId) && !composing;

  return (
    <div className="deck-card" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div className="deck-title" style={{ justifyContent: 'space-between' }}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
          <LifeBuoy size={18} /> Your concierge
        </span>
        <button
          type="button"
          className="btn-solid"
          style={{ padding: '9px 18px' }}
          onClick={() => {
            setComposing(true);
            setSelectedId(null);
            setError(null);
          }}
        >
          <Plus size={16} /> New message
        </button>
      </div>

      {error && (
        <div role="alert" style={{ fontSize: '0.9rem', fontWeight: 600 }}>
          {error}
        </div>
      )}

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: 18,
          alignItems: 'start',
        }}
      >
        {/* Conversation list */}
        <div style={{ display: showThread ? undefined : 'block' }}>
          {loading ? (
            <ListRowsSkeleton count={3} compact />
          ) : threads.length === 0 && !composing ? (
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', lineHeight: 1.5 }}>
              No conversations yet. Write to our team about payments, access, groups or anything else. Choose
              <strong> New message</strong> to begin.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {threads.map((t) => {
                const active = t.thread_id === selectedId && !composing;
                return (
                  <button
                    key={t.thread_id}
                    type="button"
                    onClick={() => {
                      setComposing(false);
                      setSelectedId(t.thread_id);
                    }}
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
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, alignItems: 'center' }}>
                      <span style={{ fontWeight: 600, fontSize: '0.88rem', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {t.subject}
                      </span>
                      {t.unread > 0 && (
                        <span
                          aria-label={`${t.unread} unread`}
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
                      {t.status === 'closed' ? 'Closed' : t.last_sender_role === 'admin' ? 'Admin replied' : 'Waiting for admin'}{' '}
                      · {formatSupportTime(t.last_message_at)}
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Right panel: new message form or open conversation */}
        <div>
          {composing ? (
            <form onSubmit={startConversation} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <label style={{ fontSize: '0.86rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                What is this about?
                <input
                  type="text"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value.slice(0, 120))}
                  placeholder="For example: My payment is still pending"
                  required
                  minLength={3}
                  style={{ ...inputStyle, marginTop: 5 }}
                />
              </label>
              <label style={{ fontSize: '0.86rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                Your message
                <textarea
                  value={firstMessage}
                  onChange={(e) => setFirstMessage(e.target.value.slice(0, 2000))}
                  rows={6}
                  required
                  placeholder="Tell us what happened. Include any transaction hash if it is about a payment."
                  style={{ ...inputStyle, marginTop: 5, resize: 'vertical' }}
                />
              </label>
              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  type="submit"
                  className="btn-solid"
                  disabled={busy || subject.trim().length < 3 || !firstMessage.trim()}
                  style={{ padding: '8px 18px', borderRadius: 9999 }}
                >
                  {busy ? 'Sending...' : 'Send to admin'}
                </button>
                <button
                  type="button"
                  className="btn-outline"
                  onClick={() => setComposing(false)}
                  style={{ padding: '8px 16px', borderRadius: 9999 }}
                >
                  Cancel
                </button>
              </div>
            </form>
          ) : selectedId && (!selected || selected.thread_id !== selectedId) ? (
            <ChatMessagesSkeleton count={3} />
          ) : selectedId && selected ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <button
                  type="button"
                  className="btn-outline"
                  onClick={() => setSelectedId(null)}
                  aria-label="Back to conversations"
                  style={{ padding: '4px 8px' }}
                >
                  <ArrowLeft size={14} />
                </button>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontWeight: 700, fontSize: '0.95rem' }}>{selected.subject}</div>
                  <div style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>
                    {selected.status === 'closed'
                      ? 'Closed. Reply to reopen it.'
                      : 'Open. The admin team will reply here.'}
                  </div>
                </div>
              </div>
              <SupportConversation
                messages={messages}
                viewer="user"
                placeholder="Write a reply..."
                onSend={async (text) => {
                  await sendSupportMessage(selectedId, text);
                  await loadThread(selectedId);
                  await loadList();
                }}
              />
            </div>
          ) : (
            !loading &&
            threads.length > 0 && (
              <div style={{ color: 'var(--text-secondary)', fontSize: '0.88rem' }}>
                Pick a conversation to read it, or press <strong>New message</strong>.
              </div>
            )
          )}
        </div>
      </div>
    </div>
  );
};