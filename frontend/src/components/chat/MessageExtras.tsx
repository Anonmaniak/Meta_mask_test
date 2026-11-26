import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Ban, BarChart3, ChevronDown, ChevronUp, MoreVertical, Pin, Search, SmilePlus, Timer, X } from 'lucide-react';
import { QUICK_REACTIONS, describeTimer, type PollTally, MAX_POLL_OPTIONS } from '../../services/chatEvents';
import './chatExtras.css';

/** Reaction chips under a message: "❤️ 2". Pressing one you used removes it; another sets it. */
export const ReactionChips: React.FC<{
  reactions: Record<string, string[]>;
  myId: string;
  nameFor: (userId: string) => string;
  onToggle?: (emoji: string) => void;
}> = ({ reactions, myId, nameFor, onToggle }) => {
  const entries = Object.entries(reactions).filter(([, ids]) => ids.length > 0);
  if (!entries.length) return null;
  return (
    <div className="ig-reactions">
      {entries.map(([emoji, ids]) => {
        const mine = ids.includes(myId);
        const who = ids.map((id) => (id === myId ? 'You' : nameFor(id))).join(', ');
        return (
          <button
            key={emoji}
            type="button"
            className={`ig-reaction-chip ${mine ? 'is-mine' : ''}`}
            title={who}
            aria-label={`${emoji} from ${who}${mine ? '. Press to remove yours' : ''}`}
            aria-pressed={mine}
            disabled={!onToggle}
            onClick={() => onToggle?.(emoji)}
          >
            <span>{emoji}</span>
            <span className="count">{ids.length}</span>
          </button>
        );
      })}
    </div>
  );
};

/** The react button with its quick emoji row. */
export const ReactButton: React.FC<{ current?: string; onPick: (emoji: string) => void }> = ({ current, onPick }) => {
  const [open, setOpen] = useState(false);
  const wrap = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !wrap.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', close);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('keydown', close);
    };
  }, [open]);
  return (
    <div className="ig-actions-wrap" ref={wrap}>
      <button type="button" className="ig-action" title="React" aria-label="React to this message" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        <SmilePlus size={14} />
      </button>
      {open && (
        <div className="ig-picker" role="menu" aria-label="Reactions">
          {QUICK_REACTIONS.map((e) => (
            <button
              key={e}
              type="button"
              role="menuitem"
              className={current === e ? 'is-mine' : ''}
              aria-label={current === e ? `Remove ${e}` : `React ${e}`}
              onClick={() => {
                setOpen(false);
                onPick(current === e ? '' : e);
              }}
            >
              {e}
            </button>
          ))}
        </div>
      )}
    </div>
  );
};

/** "This message was deleted" */
export const DeletedBubble: React.FC<{ mine: boolean; title?: string }> = ({ mine, title }) => (
  <div className="ig-bubble ig-deleted" title={title}>
    <Ban size={13} />
    <span>{mine ? 'You deleted this message' : 'This message was deleted'}</span>
  </div>
);

/** Text with @mentions highlighted (yours stand out). */
export const MentionText: React.FC<{ text: string; myUsername?: string | null }> = ({ text, myUsername }) => {
  const parts = useMemo(() => text.split(/((?<![A-Za-z0-9_])@[A-Za-z0-9_]{3,32})/g), [text]);
  if (parts.length === 1) return <>{text}</>;
  const me = (myUsername || '').toLowerCase();
  return (
    <>
      {parts.map((p, i) =>
        i % 2 === 1 ? (
          <span key={i} className={`ig-mention ${me && p.slice(1).toLowerCase() === me ? 'is-me' : ''}`}>
            {p}
          </span>
        ) : (
          <React.Fragment key={i}>{p}</React.Fragment>
        )
      )}
    </>
  );
};

/** A poll with live results. Single choice: press an option (again to withdraw). Multi: tick several. */
export const PollCard: React.FC<{
  poll: PollTally;
  nameFor: (userId: string) => string;
  onVote?: (options: number[]) => void;
  title?: string;
}> = ({ poll, nameFor, onVote, title }) => {
  const mine = new Set(poll.myVote);
  const press = (i: number) => {
    if (!onVote) return;
    if (poll.multi) {
      const next = new Set(mine);
      if (next.has(i)) next.delete(i);
      else next.add(i);
      onVote(Array.from(next).sort((a, b) => a - b));
    } else {
      onVote(mine.has(i) ? [] : [i]);
    }
  };
  const total = Math.max(poll.totalVoters, 1);
  return (
    <div className="ig-poll" title={title} role="group" aria-label={`Poll: ${poll.question}`}>
      <div className="ig-poll-q">
        <BarChart3 size={14} style={{ verticalAlign: '-2px', marginRight: 6 }} />
        {poll.question}
      </div>
      <div className="ig-poll-sub">
        {poll.multi ? 'Choose one or more' : 'Choose one'} · {poll.totalVoters} {poll.totalVoters === 1 ? 'vote' : 'votes'}
      </div>
      {poll.options.map((opt, i) => {
        const n = poll.votes[i]?.length || 0;
        const pct = Math.round((n / total) * 100);
        const who = (poll.votes[i] || []).map(nameFor).join(', ');
        return (
          <button
            key={i}
            type="button"
            className={`ig-poll-opt ${mine.has(i) ? 'is-mine' : ''}`}
            onClick={() => press(i)}
            disabled={!onVote}
            aria-pressed={mine.has(i)}
            title={who || 'No votes yet'}
          >
            <i className="bar" style={{ width: `${poll.totalVoters ? pct : 0}%` }} />
            <span>
              {mine.has(i) ? '✓ ' : ''}
              {opt}
            </span>
            <span className="pct">{poll.totalVoters ? `${pct}% · ${n}` : ''}</span>
          </button>
        );
      })}
    </div>
  );
};

/** Window to create a poll. */
export const PollComposer: React.FC<{ open: boolean; onClose: () => void; onCreate: (q: string, options: string[], multi: boolean) => Promise<void> }> = ({
  open,
  onClose,
  onCreate,
}) => {
  const [question, setQuestion] = useState('');
  const [options, setOptions] = useState<string[]>(['', '']);
  const [multi, setMulti] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!open) return null;
  const clean = options.map((o) => o.trim()).filter(Boolean);
  const ready = question.trim().length > 0 && clean.length >= 2 && new Set(clean.map((o) => o.toLowerCase())).size === clean.length;
  const submit = async () => {
    if (!ready || busy) return;
    setBusy(true);
    setError(null);
    try {
      await onCreate(question.trim(), clean, multi);
      setQuestion('');
      setOptions(['', '']);
      setMulti(false);
      onClose();
    } catch (err: any) {
      setError(err?.message || 'The poll was not sent.');
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="chat-action-modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="poll-title" onClick={() => !busy && onClose()}>
      <div className="chat-action-modal-card" style={{ maxWidth: 460, width: '100%' }} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <h3 id="poll-title" style={{ margin: 0 }}>New poll</h3>
          <button type="button" className="chat-icon-btn" onClick={onClose} aria-label="Close">
            <X size={15} />
          </button>
        </div>
        <label className="admin-settings-label" htmlFor="poll-q">Question</label>
        <input id="poll-q" className="admin-settings-input" maxLength={300} value={question} onChange={(e) => setQuestion(e.target.value)} placeholder="Ask something" />
        <div className="admin-settings-label" style={{ marginTop: 12 }}>Options</div>
        {options.map((o, i) => (
          <div key={i} style={{ display: 'flex', gap: 6, marginTop: 6 }}>
            <input
              className="admin-settings-input"
              maxLength={100}
              value={o}
              aria-label={`Option ${i + 1}`}
              placeholder={`Option ${i + 1}`}
              onChange={(e) => setOptions((prev) => prev.map((x, j) => (j === i ? e.target.value : x)))}
            />
            {options.length > 2 && (
              <button type="button" className="chat-icon-btn" aria-label={`Remove option ${i + 1}`} onClick={() => setOptions((prev) => prev.filter((_, j) => j !== i))}>
                <X size={14} />
              </button>
            )}
          </div>
        ))}
        {options.length < MAX_POLL_OPTIONS && (
          <button type="button" className="btn-outline" style={{ marginTop: 8 }} onClick={() => setOptions((prev) => [...prev, ''])}>
            Add option
          </button>
        )}
        <label style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 12 }}>
          <input type="checkbox" checked={multi} onChange={(e) => setMulti(e.target.checked)} />
          Allow more than one answer
        </label>
        {error && <div role="alert" style={{ marginTop: 10, color: 'var(--danger)' }}>{error}</div>}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <button type="button" className="btn-outline" onClick={onClose}>Cancel</button>
          <button type="button" className="btn-solid" disabled={!ready || busy} onClick={() => void submit()}>
            {busy ? 'Sending…' : 'Send poll'}
          </button>
        </div>
        <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', margin: '10px 0 0' }}>
          The poll and every vote are end-to-end encrypted: the server never sees who voted for what.
        </p>
      </div>
    </div>
  );
};

/** The pinned bar: shows one pin at a time; press to jump, the counter cycles through up to 3. */
export const PinnedBar: React.FC<{
  pins: Array<{ message_id: string }>;
  previewFor: (messageId: string) => string | null;
  onJump: (messageId: string) => void;
  onUnpin?: (messageId: string) => void;
}> = ({ pins, previewFor, onJump, onUnpin }) => {
  const [index, setIndex] = useState(0);
  if (!pins.length) return null;
  const i = index % pins.length;
  const pin = pins[i];
  const preview = previewFor(pin.message_id);
  return (
    <div className="chat-extras-row">
      <button
        type="button"
        className="chat-pin-bar"
        onClick={() => {
          onJump(pin.message_id);
          setIndex((v) => v + 1);
        }}
        title="Show the pinned message"
      >
        <Pin size={14} />
        <span className="txt">{preview ?? 'Pinned message (not loaded here)'}</span>
        {pins.length > 1 && <span className="meta">{i + 1}/{pins.length}</span>}
      </button>
      {onUnpin && (
        <button type="button" className="chat-icon-btn" title="Unpin" aria-label="Unpin this message" onClick={() => onUnpin(pin.message_id)}>
          <X size={14} />
        </button>
      )}
    </div>
  );
};

/** "@a is typing…" */
export function typingText(names: string[]): string {
  if (!names.length) return '';
  if (names.length === 1) return `${names[0]} is typing…`;
  if (names.length === 2) return `${names[0]} and ${names[1]} are typing…`;
  return 'Several people are typing…';
}

export const TypingLine: React.FC<{ names: string[] }> = ({ names }) => (
  <div className="chat-typing" aria-live="polite">{typingText(names)}</div>
);

/** In-chat search over the messages on this device (circular button that animates into a search bar). */
export const ChatSearchBar: React.FC<{
  open: boolean;
  onOpen: () => void;
  query: string;
  onQuery: (q: string) => void;
  count: number;
  index: number;
  onStep: (dir: 1 | -1) => void;
  onClose: () => void;
  ariaLabel?: string;
}> = ({ open, onOpen, query, onQuery, count, index, onStep, onClose, ariaLabel }) => {
  const inputRef = useRef<HTMLInputElement | null>(null);
  useEffect(() => {
    if (!open) return;
    const t = window.setTimeout(() => inputRef.current?.focus(), 60);
    return () => window.clearTimeout(t);
  }, [open]);

  const label = ariaLabel || 'Search this chat';
  return (
    <div className="chat-header-search-slot">
      <div
        className={`chat-header-search ${open ? 'is-open' : ''}`}
        role="search"
        onKeyDown={(e) => {
          if (open && e.key === 'Escape') {
            e.stopPropagation();
            onClose();
          }
        }}
      >
        <button
          type="button"
          className="chat-header-search-trigger"
          aria-label={label}
          aria-expanded={open}
          title={label}
          onClick={() => {
            if (!open) onOpen();
            else inputRef.current?.focus();
          }}
        >
          <Search size={15} aria-hidden="true" />
        </button>
        <div className="chat-header-search-fields" aria-hidden={!open}>
          <input
            ref={inputRef}
            tabIndex={open ? 0 : -1}
            value={query}
            onChange={(e) => onQuery(e.target.value)}
            placeholder="Search this chat"
            aria-label={label}
            onKeyDown={(e) => {
              if (e.key === 'Enter') onStep(e.shiftKey ? -1 : 1);
            }}
          />
          <span className="count">{query.trim().length >= 2 ? (count ? `${index + 1} of ${count}` : 'No matches') : ''}</span>
          <button
            type="button"
            className="chat-header-search-step"
            tabIndex={open ? 0 : -1}
            aria-label="Previous match"
            disabled={!open || !count}
            onClick={() => onStep(-1)}
          >
            <ChevronUp size={14} />
          </button>
          <button
            type="button"
            className="chat-header-search-step"
            tabIndex={open ? 0 : -1}
            aria-label="Next match"
            disabled={!open || !count}
            onClick={() => onStep(1)}
          >
            <ChevronDown size={14} />
          </button>
          <button
            type="button"
            className="chat-header-search-close"
            tabIndex={open ? 0 : -1}
            aria-label="Close search"
            onClick={onClose}
          >
            <X size={14} />
          </button>
        </div>
      </div>
    </div>
  );
};

export type MuteChoice = 'off' | '8h' | '1w' | 'always';
export const TIMER_CHOICES: Array<[number, string]> = [
  [0, 'Off'],
  [86400, '24 hours'],
  [604800, '7 days'],
  [7776000, '90 days'],
];

/** The ⋮ menu of a chat: mute, archive, disappearing messages, announcement mode, poll, search. */
export const ConversationMenu: React.FC<{
  kind: 'dm' | 'group' | 'room';
  muted: boolean;
  mutedForever?: boolean;
  mutedUntil?: string | null;
  archived?: boolean;
  timer?: number;
  adminsOnly?: boolean;
  canManage?: boolean;
  onMute: (choice: MuteChoice) => void;
  onArchive?: (archived: boolean) => void;
  onTimer?: (ttl: number) => void;
  onAdminsOnly?: (value: boolean) => void;
  onSearch: () => void;
  onPoll?: () => void;
}> = (p) => {
  const [open, setOpen] = useState(false);
  const wrap = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !wrap.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', close);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('keydown', close);
    };
  }, [open]);
  const act = (fn: () => void) => () => {
    setOpen(false);
    fn();
  };
  const muteLabel = p.muted ? (p.mutedForever ? 'Muted' : `Muted until ${p.mutedUntil ? new Date(p.mutedUntil).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : ''}`) : 'Not muted';
  return (
    <div className="chat-menu-wrap" ref={wrap}>
      <button type="button" className="chat-icon-btn" aria-label="Chat options" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        <MoreVertical size={16} />
      </button>
      {open && (
        <div className="chat-menu" role="menu">
          <button type="button" role="menuitem" onClick={act(p.onSearch)}>
            <span>Search this chat</span>
            <Search size={14} />
          </button>
          {p.onPoll && (
            <button type="button" role="menuitem" onClick={act(p.onPoll)}>
              <span>New poll</span>
              <BarChart3 size={14} />
            </button>
          )}
          <hr />
          <div className="label">Notifications · {muteLabel}</div>
          {(
            [
              ['8h', 'Mute for 8 hours'],
              ['1w', 'Mute for a week'],
              ['always', 'Mute always'],
            ] as Array<[MuteChoice, string]>
          ).map(([v, label]) => (
            <button key={v} type="button" role="menuitemradio" aria-checked={p.muted && (v === 'always' ? Boolean(p.mutedForever) : false)} onClick={act(() => p.onMute(v))}>
              <span>{label}</span>
            </button>
          ))}
          {p.muted && (
            <button type="button" role="menuitem" onClick={act(() => p.onMute('off'))}>
              <span>Unmute</span>
            </button>
          )}
          {p.onArchive && (
            <>
              <hr />
              <button type="button" role="menuitem" onClick={act(() => p.onArchive!(!p.archived))}>
                <span>{p.archived ? 'Unarchive chat' : 'Archive chat'}</span>
              </button>
            </>
          )}
          {p.onTimer && (
            <>
              <hr />
              <div className="label">
                <Timer size={11} style={{ verticalAlign: '-1px' }} /> Disappearing messages
                {p.kind === 'group' && !p.canManage ? ' (admins set this)' : ''}
              </div>
              {TIMER_CHOICES.map(([ttl, label]) => (
                <button
                  key={ttl}
                  type="button"
                  role="menuitemradio"
                  aria-checked={(p.timer || 0) === ttl}
                  disabled={!p.canManage}
                  onClick={act(() => p.onTimer!(ttl))}
                >
                  <span>{label}</span>
                </button>
              ))}
            </>
          )}
          {p.kind === 'group' && p.canManage && p.onAdminsOnly && (
            <>
              <hr />
              <button type="button" role="menuitemcheckbox" aria-checked={Boolean(p.adminsOnly)} onClick={act(() => p.onAdminsOnly!(!p.adminsOnly))}>
                <span>Only admins can send messages</span>
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
};

/** Small chips beside the pinned bar: timer and announcement mode. */
export const ChatStatusChips: React.FC<{ timer?: number; adminsOnly?: boolean; muted?: boolean }> = ({ timer, adminsOnly, muted }) => (
  <>
    {timer ? (
      <span className="chat-chip" title="New messages disappear after this time">
        <Timer size={12} /> {describeTimer(timer)}
      </span>
    ) : null}
    {adminsOnly && <span className="chat-chip">Announcements: only admins post</span>}
    {muted && <span className="chat-chip">Muted</span>}
  </>
);

/** Suggestions while typing "@na…" in a composer. Returns the list element (or null). */
export function useMentionSuggestions(text: string, candidates: ReadonlyArray<{ id: string; username: string }>) {
  const match = /(?:^|\s)@([A-Za-z0-9_]{0,32})$/.exec(text);
  const q = match ? match[1].toLowerCase() : null;
  const list = q === null ? [] : candidates.filter((c) => c.username.toLowerCase().startsWith(q)).slice(0, 8);
  return { active: q !== null && list.length > 0, list, query: q };
}
