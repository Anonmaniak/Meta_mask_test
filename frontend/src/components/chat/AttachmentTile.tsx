import React, { useCallback, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import {
  AlertTriangle,
  Download,
  File as FileIcon,
  FileArchive,
  FileAudio,
  FileCode,
  FileSpreadsheet,
  FileText,
  FileVideo,
  ImageOff,
  Loader2,
  Play,
  Trash2,
  X,
} from 'lucide-react';
import { attachmentKind, isRiskyFileName, type AttachmentKind } from '../../services/attachmentLimits';
import { formatBytes } from '../../services/chatFormat';

/**
 * One attachment in a message.
 * - Images load when scrolled into view and open full-screen on click.
 * - Video / audio load only when the member presses Play (they can be large, and in encrypted chats
 *   they must be downloaded and decrypted first).
 * - Everything else is a file card with a Download button.
 * `load` returns the file's bytes (already decrypted for encrypted chats); results are cached per id.
 */

const urlCache = new Map<string, Promise<string>>();
const MAX_CACHED = 80;

function cachedObjectUrl(id: string, load: () => Promise<Blob>): Promise<string> {
  const hit = urlCache.get(id);
  if (hit) {
    urlCache.delete(id); // refresh LRU position
    urlCache.set(id, hit);
    return hit;
  }
  const p = load().then((blob) => URL.createObjectURL(blob));
  p.catch(() => urlCache.delete(id));
  urlCache.set(id, p);
  while (urlCache.size > MAX_CACHED) {
    const oldestKey = urlCache.keys().next().value as string;
    const oldest = urlCache.get(oldestKey);
    urlCache.delete(oldestKey);
    oldest?.then((u) => URL.revokeObjectURL(u)).catch(() => {});
  }
  return p;
}

export function forgetCachedAttachment(id: string): void {
  const p = urlCache.get(id);
  urlCache.delete(id);
  p?.then((u) => URL.revokeObjectURL(u)).catch(() => {});
}

function saveUrl(url: string, fileName: string) {
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName || 'file';
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
}

function iconFor(name: string, kind: AttachmentKind) {
  if (kind === 'video') return <FileVideo size={18} />;
  if (kind === 'audio') return <FileAudio size={18} />;
  const n = name.toLowerCase();
  if (/\.(zip|rar|7z|tar|gz|tgz|bz2|xz)$/.test(n)) return <FileArchive size={18} />;
  if (/\.(xlsx?|csv|ods|numbers)$/.test(n)) return <FileSpreadsheet size={18} />;
  if (/\.(js|ts|tsx|jsx|py|json|html?|css|sh|sql|xml|ya?ml|java|c|cpp|go|rs|sol)$/.test(n)) return <FileCode size={18} />;
  if (/\.(pdf|docx?|odt|rtf|txt|md|pptx?|key|pages)$/.test(n)) return <FileText size={18} />;
  return <FileIcon size={18} />;
}

function errorText(err: any): string {
  if (err?.status === 410) return 'The sender removed this file.';
  if (err?.status === 404) return 'This file is no longer available.';
  return err?.message || 'Could not open this file.';
}

export const Lightbox: React.FC<{ url: string; name: string; onClose: () => void }> = ({ url, name, onClose }) => {
  const closeRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = prevOverflow;
      prev?.focus?.();
    };
  }, [onClose]);
  return createPortal(
    <div className="ig-lightbox" role="dialog" aria-modal="true" aria-label={name} onClick={onClose}>
      <div className="ig-lightbox-bar" onClick={(e) => e.stopPropagation()}>
        <span title={name}>{name}</span>
        <button type="button" title="Download" aria-label="Download" onClick={() => saveUrl(url, name)}>
          <Download size={18} />
        </button>
        <button ref={closeRef} type="button" title="Close" aria-label="Close" onClick={onClose}>
          <X size={18} />
        </button>
      </div>
      <img src={url} alt={name} onClick={(e) => e.stopPropagation()} />
    </div>,
    document.body
  );
};

export interface AttachmentTileProps {
  /** Unique, stable id (cache key). */
  id: string;
  name: string;
  mime: string;
  size: number;
  /** Server-decided kind (Members' room). Otherwise derived from mime + name. */
  kind?: AttachmentKind;
  load: () => Promise<Blob>;
  removed?: boolean;
  /** Shown to the sender: remove the file for everyone. */
  onRemove?: () => void;
}

export const AttachmentTile: React.FC<AttachmentTileProps> = ({ id, name, mime, size, kind, load, removed, onRemove }) => {
  const k = kind || attachmentKind(mime, name);
  const [url, setUrl] = useState<string | null>(null);
  const [state, setState] = useState<'idle' | 'loading' | 'ready' | 'error'>('idle');
  const [error, setError] = useState<string>('');
  const [lightbox, setLightbox] = useState(false);
  const boxRef = useRef<HTMLDivElement>(null);
  const loadRef = useRef(load);
  useEffect(() => {
    loadRef.current = load;
  }, [load]);

  const fetchIt = useCallback(async (): Promise<string | null> => {
    setState('loading');
    setError('');
    try {
      const u = await cachedObjectUrl(id, () => loadRef.current());
      setUrl(u);
      setState('ready');
      return u;
    } catch (err: any) {
      setError(errorText(err));
      setState('error');
      return null;
    }
  }, [id]);

  // Images: load when they scroll into view.
  useEffect(() => {
    if (k !== 'image' || removed || state !== 'idle') return;
    const el = boxRef.current;
    if (!el || typeof IntersectionObserver === 'undefined') {
      void fetchIt();
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          io.disconnect();
          void fetchIt();
        }
      },
      { rootMargin: '200px' }
    );
    io.observe(el);
    return () => io.disconnect();
  }, [k, removed, state, fetchIt]);

  if (removed) {
    return <div className="ig-removed">{name} was removed by the sender.</div>;
  }

  const removeBtn = onRemove ? (
    <button type="button" className="ig-media-remove" title="Remove this file for everyone" aria-label={`Remove ${name}`} onClick={onRemove}>
      <Trash2 size={13} />
    </button>
  ) : null;

  if (k === 'image') {
    return (
      <div className="ig-media" ref={boxRef}>
        {state === 'ready' && url ? (
          <button type="button" className="ig-media-open" onClick={() => setLightbox(true)} aria-label={`Open ${name}`}>
            <img src={url} alt={name} loading="lazy" />
          </button>
        ) : state === 'error' ? (
          <div className="ig-media-placeholder ig-static">
            <div>
              <ImageOff size={22} />
              <div style={{ marginTop: 6 }}>{error}</div>
              <button type="button" className="ig-file-btn" style={{ margin: '8px auto 0', width: 'auto', padding: '0 12px', borderRadius: 16 }} onClick={() => void fetchIt()}>
                Retry
              </button>
            </div>
          </div>
        ) : (
          <div className="ig-media-placeholder" aria-label={`Loading ${name}`} />
        )}
        {removeBtn}
        {lightbox && url && <Lightbox url={url} name={name} onClose={() => setLightbox(false)} />}
      </div>
    );
  }

  if ((k === 'video' || k === 'audio') && state === 'ready' && url) {
    return (
      <div className="ig-media" style={k === 'audio' ? { padding: 8, maxWidth: 320 } : undefined}>
        {k === 'video' ? (
          <video src={url} controls playsInline preload="metadata" />
        ) : (
          <audio src={url} controls preload="metadata" style={{ width: 280, maxWidth: '100%' }} />
        )}
        {removeBtn}
      </div>
    );
  }

  const risky = isRiskyFileName(name);
  const busy = state === 'loading';
  const playable = k === 'video' || k === 'audio';
  return (
    <div className="ig-file">
      <div className="ig-file-icon">{iconFor(name, k)}</div>
      <div className="ig-file-meta">
        <span className="ig-file-name" title={name}>
          {name}
        </span>
        <span className="ig-file-sub">{state === 'error' ? error : formatBytes(size)}</span>
        {risky && (
          <span className="ig-file-warn">
            <AlertTriangle size={11} style={{ verticalAlign: '-1px' }} /> Can run programs. Open only if you trust the sender.
          </span>
        )}
      </div>
      <button
        type="button"
        className="ig-file-btn"
        disabled={busy}
        title={playable ? 'Play' : 'Download'}
        aria-label={playable ? `Play ${name}` : `Download ${name}`}
        onClick={async () => {
          const u = url || (await fetchIt());
          if (u && !playable) saveUrl(u, name);
        }}
      >
        {busy ? <Loader2 size={16} className="ig-spin" /> : playable ? <Play size={16} /> : <Download size={16} />}
      </button>
      {playable && state === 'ready' && url && (
        <button type="button" className="ig-file-btn" title="Download" aria-label={`Download ${name}`} onClick={() => saveUrl(url, name)}>
          <Download size={16} />
        </button>
      )}
      {removeBtn}
    </div>
  );
};

/** Thumbnails of files picked for the next message, each with a remove button. */
export const PendingFilesTray: React.FC<{ files: File[]; onRemove: (index: number) => void }> = ({ files, onRemove }) => {
  const [previews, setPreviews] = useState<(string | null)[]>([]);
  useEffect(() => {
    const urls = files.map((f) => (attachmentKind(f.type, f.name) === 'image' ? URL.createObjectURL(f) : null));
    setPreviews(urls);
    return () => urls.forEach((u) => u && URL.revokeObjectURL(u));
  }, [files]);
  if (!files.length) return null;
  return (
    <div className="ig-tray" aria-label="Files to send">
      {files.map((f, i) => (
        <div className="ig-tray-item" key={`${f.name}_${f.size}_${f.lastModified}_${i}`} title={`${f.name} (${formatBytes(f.size)})`}>
          {previews[i] ? (
            <img src={previews[i]!} alt={f.name} />
          ) : (
            <>
              {iconFor(f.name, attachmentKind(f.type, f.name))}
              <small>{f.name}</small>
            </>
          )}
          <button type="button" aria-label={`Remove ${f.name}`} onClick={() => onRemove(i)}>
            <X size={12} />
          </button>
        </div>
      ))}
    </div>
  );
};
