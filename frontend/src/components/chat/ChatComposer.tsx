import React, { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { Paperclip, Send, Smile, X } from 'lucide-react';
import { EmojiPicker, insertAtCaret } from './EmojiPicker';
import { PendingFilesTray } from './AttachmentTile';
import { checkFilesForMessage, MAX_FILES_PER_MESSAGE } from '../../services/attachmentLimits';
import { formatBytes } from '../../services/chatFormat';
import { useMentionSuggestions } from './MessageExtras';

/**
 * Composer for every chat: [emoji] [attach] [text that grows] [Send].
 * Enter sends, Shift+Enter makes a new line. Files can be picked, pasted or dropped onto the composer.
 * Limits (size per file, files per message) are checked here first; the server checks them again.
 */
export interface ChatComposerProps {
  value: string;
  onChange: (value: string) => void;
  onSubmit: () => void;
  files: File[];
  onFilesChange: (files: File[]) => void;
  /** Bytes allowed per file in this chat. */
  maxFileBytes: number;
  maxFiles?: number;
  /** Shown under the composer when files are attached, e.g. "100 files / 250 MB a day". */
  dailyLimitText?: string;
  placeholder: string;
  disabled?: boolean;
  sending?: boolean;
  maxLength?: number;
  canAttach?: boolean;
  /** Clicking a disabled composer (e.g. to connect the wallet). */
  onDisabledClick?: () => void;
  /** Extra note shown when files are selected (e.g. "Files here are end-to-end encrypted"). */
  note?: React.ReactNode;
  autoFocusKey?: string;
  /** Message being replied to (shows a "Replying to" bar above the text box). */
  replyTo?: { name: string; preview: string } | null;
  onCancelReply?: () => void;
  /** People who can be @mentioned here: typing "@" shows them. */
  mentionCandidates?: ReadonlyArray<{ id: string; username: string }>;
  /** Called on each keystroke (the caller throttles the "typing…" signal). */
  onTyping?: () => void;
  /** Replaces the composer with a note (e.g. announcement groups: "Only admins can send messages"). */
  readOnlyNote?: string | null;
}

export const ChatComposer: React.FC<ChatComposerProps> = ({
  value,
  onChange,
  onSubmit,
  files,
  onFilesChange,
  maxFileBytes,
  maxFiles = MAX_FILES_PER_MESSAGE,
  dailyLimitText,
  placeholder,
  disabled = false,
  sending = false,
  maxLength,
  canAttach = false,
  onDisabledClick,
  note,
  autoFocusKey,
  replyTo,
  onCancelReply,
  mentionCandidates,
  onTyping,
  readOnlyNote,
}) => {
  const taRef = useRef<HTMLTextAreaElement>(null);
  const mention = useMentionSuggestions(value, mentionCandidates || []);
  const [mentionIndex, setMentionIndex] = useState(0);
  const [mentionDismissed, setMentionDismissed] = useState<string | null>(null);
  const showMentions = mention.active && mentionDismissed !== value;
  const pickMention = (username: string) => {
    const next = value.replace(/@([A-Za-z0-9_]{0,32})$/, `@${username} `);
    if (maxLength && next.length > maxLength) return;
    onChange(next);
    setMentionIndex(0);
    taRef.current?.focus();
  };
  const fileRef = useRef<HTMLInputElement>(null);
  const emojiBtnRef = useRef<HTMLButtonElement>(null);
  const [emojiOpen, setEmojiOpen] = useState(false);
  const [fileErrors, setFileErrors] = useState<string[]>([]);
  const [dragging, setDragging] = useState(false);
  const pendingCaret = useRef<number | null>(null);

  // Grow with the text (up to the CSS max-height), and keep the caret where an emoji was inserted.
  useLayoutEffect(() => {
    const ta = taRef.current;
    if (!ta) return;
    ta.style.height = 'auto';
    ta.style.height = `${Math.min(ta.scrollHeight, 140)}px`;
    // Scrollbar only when the text is taller than the box (otherwise it shows as a stray bar).
    ta.style.overflowY = ta.scrollHeight > 140 ? 'auto' : 'hidden';
    if (pendingCaret.current !== null) {
      ta.setSelectionRange(pendingCaret.current, pendingCaret.current);
      pendingCaret.current = null;
    }
  }, [value]);

  useEffect(() => {
    if (autoFocusKey && !disabled) taRef.current?.focus();
  }, [autoFocusKey, disabled]);

  // Starting a reply puts the cursor in the text box, ready to type.
  useEffect(() => {
    if (replyTo && !disabled) taRef.current?.focus();
  }, [replyTo, disabled]);

  useEffect(() => {
    if (!fileErrors.length) return;
    const t = setTimeout(() => setFileErrors([]), 7000);
    return () => clearTimeout(t);
  }, [fileErrors]);

  const addFiles = useCallback(
    (incoming: File[]) => {
      if (!incoming.length) return;
      const { accepted, errors } = checkFilesForMessage(incoming, files, maxFileBytes, maxFiles);
      if (accepted.length) onFilesChange([...files, ...accepted]);
      setFileErrors(errors);
    },
    [files, maxFileBytes, maxFiles, onFilesChange]
  );

  const canSend = !disabled && !sending && (value.trim().length > 0 || files.length > 0);
  const attachAllowed = canAttach && !disabled;

  const submit = () => {
    if (!canSend) return;
    setEmojiOpen(false);
    onSubmit();
  };

  if (readOnlyNote) {
    return <div className="chat-readonly-note" role="status">{readOnlyNote}</div>;
  }

  return (
    <div
      className={`ig-composer ${dragging ? 'ig-dragging' : ''}`}
      onDragOver={(e) => {
        if (!attachAllowed || !Array.from(e.dataTransfer.types).includes('Files')) return;
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node)) setDragging(false);
      }}
      onDrop={(e) => {
        if (!attachAllowed) return;
        e.preventDefault();
        setDragging(false);
        addFiles(Array.from(e.dataTransfer.files || []));
      }}
    >
      {replyTo && (
        <div className="ig-reply-bar" role="group" aria-label={`Replying to ${replyTo.name}`}>
          <div className="ig-reply-bar-text">
            <strong>Replying to {replyTo.name}</strong>
            <span>{replyTo.preview}</span>
          </div>
          {onCancelReply && (
            <button
              type="button"
              className="ig-icon-btn"
              title="Cancel reply (Esc)"
              aria-label="Cancel reply"
              onClick={onCancelReply}
            >
              <X size={16} />
            </button>
          )}
        </div>
      )}

      <PendingFilesTray files={files} onRemove={(i) => onFilesChange(files.filter((_, idx) => idx !== i))} />

      {showMentions && (
        <div className="mention-suggest" role="listbox" aria-label="Mention someone">
          {mention.list.map((c, i) => (
            <button
              key={c.id}
              type="button"
              role="option"
              aria-selected={i === mentionIndex % mention.list.length}
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => pickMention(c.username)}
            >
              @{c.username}
            </button>
          ))}
        </div>
      )}

      <EmojiPicker
        open={emojiOpen}
        onClose={() => setEmojiOpen(false)}
        ignoreRef={emojiBtnRef}
        onPick={(emoji) => {
          const { value: next, caret } = insertAtCaret(taRef.current, value, emoji);
          if (maxLength && next.length > maxLength) return;
          pendingCaret.current = caret;
          onChange(next);
          taRef.current?.focus();
        }}
      />

      <form
        className="ig-composer-row"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
        onClick={() => {
          if (disabled && onDisabledClick) onDisabledClick();
        }}
      >
        <button
          ref={emojiBtnRef}
          type="button"
          className="ig-icon-btn"
          title="Emoji"
          aria-label="Emoji"
          aria-expanded={emojiOpen}
          disabled={disabled}
          onClick={(e) => {
            e.stopPropagation();
            setEmojiOpen((v) => !v);
          }}
        >
          <Smile size={20} />
        </button>

        <textarea
          ref={taRef}
          rows={1}
          value={value}
          maxLength={maxLength}
          disabled={disabled}
          placeholder={placeholder}
          aria-label={placeholder}
          onChange={(e) => {
            onChange(e.target.value);
            setMentionIndex(0);
            if (e.target.value.trim()) onTyping?.();
          }}
          onKeyDown={(e) => {
            if (showMentions) {
              const n = mention.list.length;
              if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                e.preventDefault();
                setMentionIndex((v) => (v + (e.key === 'ArrowDown' ? 1 : n - 1)) % n);
                return;
              }
              if (e.key === 'Enter' || e.key === 'Tab') {
                e.preventDefault();
                pickMention(mention.list[mentionIndex % n].username);
                return;
              }
              if (e.key === 'Escape') {
                e.preventDefault();
                setMentionDismissed(value);
                return;
              }
            }
            if (e.key === 'Escape' && replyTo && onCancelReply) {
              e.preventDefault();
              onCancelReply();
              return;
            }
            if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
              e.preventDefault();
              submit();
            }
          }}
          onPaste={(e) => {
            if (!attachAllowed) return;
            const pasted = Array.from(e.clipboardData?.files || []);
            if (pasted.length) {
              e.preventDefault();
              addFiles(pasted);
            }
          }}
        />

        {canAttach && (
          <>
            <input
              ref={fileRef}
              type="file"
              multiple
              hidden
              onChange={(e) => {
                addFiles(Array.from(e.target.files || []));
                e.target.value = '';
              }}
            />
            <button
              type="button"
              className="ig-icon-btn"
              title={`Attach files (up to ${maxFiles}, ${formatBytes(maxFileBytes)} each)`}
              aria-label="Attach files"
              disabled={!attachAllowed || files.length >= maxFiles}
              onClick={(e) => {
                e.stopPropagation();
                fileRef.current?.click();
              }}
            >
              <Paperclip size={19} />
            </button>
          </>
        )}

        <button type="submit" className="ig-send" disabled={!canSend} aria-label="Send" title="Send (Enter)">
          {value.trim() || files.length ? 'Send' : <Send size={16} />}
        </button>
      </form>

      {fileErrors.length > 0 && (
        <div className="ig-composer-note ig-error" role="alert">
          {fileErrors.join(' ')}
        </div>
      )}
      {files.length > 0 && fileErrors.length === 0 && (
        <div className="ig-composer-note">
          {files.length} of {maxFiles} files, up to {formatBytes(maxFileBytes)} each.
          {dailyLimitText ? ` Daily limit: ${dailyLimitText}.` : ''}
          {note ? <> {note}</> : null}
        </div>
      )}
    </div>
  );
};