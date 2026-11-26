/**
 * File limits for chats. The server enforces the same numbers (backend/e2ee_routes.py for private
 * chats and groups, backend/public_attachments_db.py for the Members' room); these let the app refuse
 * early with a clear message instead of after an upload.
 */
import { formatBytes } from './chatFormat.ts';

export const MAX_FILES_PER_MESSAGE = 5;
/** Encrypted chats: the server caps the ENCRYPTED blob at 5 MiB; AES-GCM adds 16 bytes, keep 1 KiB spare. */
export const MAX_ENCRYPTED_FILE_BYTES = 5 * 1024 * 1024 - 1024;
/** Members' room: stored as uploaded, 5 MiB per file. */
export const MAX_ROOM_FILE_BYTES = 5 * 1024 * 1024;
/** Daily limits (rolling 24 h), shown in the composer's help text. */
export const DAILY_LIMIT_TEXT_ENCRYPTED = '100 files or 250 MB';
export const DAILY_LIMIT_TEXT_ROOM = '60 files or 150 MB';

export type AttachmentKind = 'image' | 'video' | 'audio' | 'file';

// Raster images the app previews inline. SVG is treated as a file (it can carry script).
const IMAGE_MIME = new Set(['image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/webp', 'image/avif', 'image/bmp']);
const IMAGE_EXT = /\.(png|jpe?g|gif|webp|avif|bmp)$/i;
const VIDEO_EXT = /\.(mp4|m4v|webm|mov|ogv)$/i;
const AUDIO_EXT = /\.(mp3|m4a|aac|wav|ogg|oga|opus|flac|weba)$/i;

export function attachmentKind(mime: string | null | undefined, fileName = ''): AttachmentKind {
  const m = (mime || '').toLowerCase();
  if (IMAGE_MIME.has(m) || (!m.startsWith('image/svg') && m.startsWith('image/') && IMAGE_EXT.test(fileName))) return 'image';
  if (!m && IMAGE_EXT.test(fileName)) return 'image';
  if (m.startsWith('video/') || (!m && VIDEO_EXT.test(fileName))) return 'video';
  if (m.startsWith('audio/') || (!m && AUDIO_EXT.test(fileName))) return 'audio';
  return 'file';
}

// Files that can run code when opened. Allowed (the member asked for "any type"), but flagged.
const RISKY_EXT =
  /\.(exe|msi|bat|cmd|com|scr|pif|ps1|vbs|vbe|js|jse|jar|apk|app|dmg|pkg|deb|rpm|sh|run|bin|dll|hta|lnk|reg|iso|img|docm|xlsm|pptm)$/i;

export function isRiskyFileName(name: string): boolean {
  return RISKY_EXT.test(name || '');
}

export interface FileCheckResult {
  accepted: File[];
  errors: string[];
}

/** Applies the per-file size limit, the per-message count, and drops empty or duplicate files. */
export function checkFilesForMessage(
  incoming: readonly File[],
  alreadyPicked: readonly File[],
  maxFileBytes: number,
  maxFiles: number = MAX_FILES_PER_MESSAGE
): FileCheckResult {
  const accepted: File[] = [];
  const errors: string[] = [];
  const sameFile = (a: File, b: File) => a.name === b.name && a.size === b.size && a.lastModified === b.lastModified;
  for (const f of incoming) {
    if (alreadyPicked.length + accepted.length >= maxFiles) {
      errors.push(`You can send up to ${maxFiles} files in one message.`);
      break;
    }
    if (alreadyPicked.some((p) => sameFile(p, f)) || accepted.some((p) => sameFile(p, f))) continue;
    if (f.size === 0) {
      errors.push(`"${f.name}" is empty.`);
      continue;
    }
    if (f.size > maxFileBytes) {
      errors.push(`"${f.name}" is ${formatBytes(f.size)}. Files can be at most ${formatBytes(maxFileBytes)}.`);
      continue;
    }
    accepted.push(f);
  }
  return { accepted, errors };
}
