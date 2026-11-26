import React, { useEffect, useRef, useState } from 'react';
import { friendlyError } from '../services/friendlyError';
import { Send, Loader2 } from 'lucide-react';
import type { SupportMessage } from '../services/platformApi';

interface SupportConversationProps {
  messages: SupportMessage[];
  /** Who is looking: their own messages sit on the right. */
  viewer: 'user' | 'admin';
  onSend: (text: string) => Promise<void>;
  placeholder?: string;
}

const MAX_LEN = 2000;

export const formatSupportTime = (iso: string): string => {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
};

/** Message bubbles plus a reply box. Shared by the member Support page and the admin inbox. */
export const SupportConversation: React.FC<SupportConversationProps> = ({
  messages,
  viewer,
  onSend,
  placeholder = 'Write a message...',
}) => {
  const [text, setText] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement>(null);
  const lastCount = useRef(0);

  useEffect(() => {
    if (messages.length !== lastCount.current) {
      lastCount.current = messages.length;
      endRef.current?.scrollIntoView({ block: 'end' });
    }
  }, [messages.length]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = text.trim();
    if (!trimmed || sending) return;
    setSending(true);
    setError(null);
    try {
      await onSend(trimmed);
      setText('');
    } catch (err: any) {
      setError(friendlyError(err, 'Could not send your message. Please try again.'));
    } finally {
      setSending(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
      <div
        style={{
          flex: 1,
          minHeight: 160,
          maxHeight: 420,
          overflowY: 'auto',
          display: 'flex',
          flexDirection: 'column',
          gap: 10,
          padding: '4px 2px 10px',
        }}
      >
        {messages.map((m) => {
          const mine = m.sender_role === viewer;
          return (
            <div key={m.message_id} style={{ alignSelf: mine ? 'flex-end' : 'flex-start', maxWidth: '82%' }}>
              <div
                style={{
                  padding: '9px 13px',
                  borderRadius: 14,
                  background: mine ? 'var(--bg-pill-active)' : 'var(--bg-card-hover)',
                  color: mine ? 'var(--text-inverse)' : 'var(--text-main)',
                  border: mine ? 'none' : '1px solid var(--border-subtle)',
                  fontSize: '0.88rem',
                  lineHeight: 1.45,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                }}
              >
                {m.content}
              </div>
              <div
                style={{
                  marginTop: 3,
                  fontSize: '0.86rem',
                  color: 'var(--text-muted)',
                  textAlign: mine ? 'right' : 'left',
                }}
              >
                {m.sender_role === 'admin' && viewer === 'user' ? 'Admin team · ' : ''}
                {formatSupportTime(m.created_at)}
              </div>
            </div>
          );
        })}
        <div ref={endRef} />
      </div>

      {error && (
        <div role="alert" style={{ fontSize: '0.9rem', marginBottom: 6 }}>
          {error}
        </div>
      )}
      <form onSubmit={submit} style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value.slice(0, MAX_LEN))}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              void submit(e as unknown as React.FormEvent);
            }
          }}
          rows={2}
          placeholder={placeholder}
          aria-label="Message"
          style={{
            flex: 1,
            resize: 'vertical',
            minHeight: 44,
            background: 'var(--bg-input)',
            border: '1px solid var(--border-strong)',
            borderRadius: 12,
            padding: '9px 12px',
            color: 'var(--text-main)',
            fontSize: '0.88rem',
            fontFamily: 'inherit',
          }}
        />
        <button
          type="submit"
          className="btn-solid"
          disabled={sending || !text.trim()}
          style={{ padding: '10px 14px', borderRadius: 12 }}
          aria-label="Send message"
        >
          {sending ? <Loader2 size={16} className="wg__spin" /> : <Send size={16} />}
        </button>
      </form>
    </div>
  );
};