import React, { useMemo } from 'react';
import { buildTimeline, formatFullTimestamp, isEmojiOnly, type RunPosition } from '../../services/chatFormat';
import './chatIg.css';
import { MentionText } from './MessageExtras';

/**
 * Instagram-style conversation used by the Members' room, private chats and groups.
 * The caller supplies how to read its message type and what goes inside each row; this component
 * handles the session labels ("Today 4:10 PM"), runs (tight corners, name once, avatar once),
 * alignment (yours right, others left) and the hover / tap actions.
 */
export interface RowContext {
  mine: boolean;
  position: RunPosition;
  /** Last message of a run (where "Seen" / "Sending..." go). */
  isRunEnd: boolean;
  /** Full date and time, for tooltips. */
  fullTime: string;
}

export interface ChatTimelineProps<T> {
  items: readonly T[];
  getKey: (item: T, index: number) => string;
  getTime: (item: T) => string | number | Date;
  getSender: (item: T) => string;
  isMine: (item: T) => boolean;
  /** Show names above other people's runs (groups and the Members' room; not 1-to-1 chats). */
  showNames: boolean;
  getName?: (item: T) => string;
  getInitials?: (item: T) => string;
  /** Click on a name / avatar (e.g. start a private chat). */
  onSenderClick?: (item: T) => void;
  renderBody: (item: T, ctx: RowContext) => React.ReactNode;
  renderFooter?: (item: T, ctx: RowContext) => React.ReactNode;
  renderActions?: (item: T, ctx: RowContext) => React.ReactNode;
  isPending?: (item: T) => boolean;
  /** Message id put on the row (`data-msg-id`), so a reply can jump to the message it quotes. */
  getMessageId?: (item: T) => string | undefined;
}

export function ChatTimeline<T>(props: ChatTimelineProps<T>) {
  const {
    items,
    getKey,
    getTime,
    getSender,
    isMine,
    showNames,
    getName,
    getInitials,
    onSenderClick,
    renderBody,
    renderFooter,
    renderActions,
    isPending,
    getMessageId,
  } = props;

  // Recompute labels when the minute changes so "Today" turns into "Yesterday" after midnight.
  const minute = Math.floor(Date.now() / 60_000);
  const entries = useMemo(
    () => buildTimeline(items, { getKey, getTime, getSender }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [items, minute]
  );

  return (
    <div className="ig-timeline" role="log" aria-live="polite" aria-relevant="additions">
      {entries.map((entry) => {
        if (entry.kind === 'label') {
          return (
            <div key={entry.key} className="ig-label" title={entry.title}>
              {entry.text}
            </div>
          );
        }
        const item = entry.item;
        const mine = isMine(item);
        const ctx: RowContext = {
          mine,
          position: entry.position,
          isRunEnd: entry.showAvatar,
          fullTime: formatFullTimestamp(getTime(item)),
        };
        const name = getName?.(item) || '';
        const clickable = !mine && Boolean(onSenderClick);
        const actions = renderActions?.(item, ctx);
        return (
          <div
            key={entry.key}
            className={`ig-row ${mine ? 'ig-me' : 'ig-peer'} ig-pos-${entry.position} ${isPending?.(item) ? 'ig-pending' : ''}`}
            tabIndex={actions ? 0 : undefined}
            data-msg-id={getMessageId?.(item) || undefined}
          >
            {!mine && (
              <div className="ig-avatar-slot">
                {entry.showAvatar &&
                  (clickable ? (
                    <button type="button" className="ig-avatar" title={name} aria-label={`Message ${name}`} onClick={() => onSenderClick!(item)}>
                      {getInitials?.(item) || '•'}
                    </button>
                  ) : (
                    <div className="ig-avatar" title={name} aria-hidden="true">
                      {getInitials?.(item) || '•'}
                    </div>
                  ))}
              </div>
            )}
            <div className="ig-stack">
              {!mine && showNames && entry.showName && name && (
                clickable ? (
                  <button type="button" className="ig-name" onClick={() => onSenderClick!(item)} title={`Message ${name} privately`}>
                    {name}
                  </button>
                ) : (
                  <div className="ig-name">{name}</div>
                )
              )}
              {renderBody(item, ctx)}
              {renderFooter?.(item, ctx)}
            </div>
            {actions && <div className="ig-actions">{actions}</div>}
          </div>
        );
      })}
    </div>
  );
}

/** A text bubble. 1 to 3 emoji alone are shown large without a bubble. */
export const TextBubble: React.FC<{ text: string; title?: string; edited?: boolean; myUsername?: string | null }> = ({
  text,
  title,
  edited,
  myUsername,
}) => {
  if (!text) return null;
  if (isEmojiOnly(text)) {
    return (
      <div className="ig-emoji-only" title={title}>
        {text.trim()}
      </div>
    );
  }
  return (
    <div className="ig-bubble" title={title}>
      <MentionText text={text} myUsername={myUsername} />
      {edited && <span className="ig-edited">Edited</span>}
    </div>
  );
};

/** Two-letter initials for an avatar from a display name like "@zfire" or "User-575c5b". */
export function initialsFor(name: string | null | undefined): string {
  const clean = (name || '').replace(/^[@~]/, '').trim();
  if (!clean) return '?';
  if (clean.toLowerCase().startsWith('user-')) return clean.slice(5, 7).toUpperCase() || 'U';
  return clean.slice(0, 2).toUpperCase();
}

/** The quoted message shown on top of a reply. Click jumps to the original (when it is loaded). */
export const QuotedReply: React.FC<{
  name: string;
  preview: string;
  onClick?: () => void;
}> = ({ name, preview, onClick }) => (
  <button
    type="button"
    className="ig-quote"
    onClick={onClick}
    title="Show the original message"
    aria-label={`Reply to ${name}: ${preview}. Show the original message`}
  >
    <span className="ig-quote-name">{name}</span>
    <span className="ig-quote-text">{preview}</span>
  </button>
);