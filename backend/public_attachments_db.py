"""
Files and images in the Members' room (`public_chat_messages`).

The room is readable by every paid member and is moderated, so these files are stored as uploaded
(not end-to-end encrypted). Private chats and groups use the device-side encrypted attachments in
`e2ee_db` instead.

Lifecycle: upload (message_id NULL) -> attach to one message when it is posted -> purged when the
message is deleted. Unattached uploads older than 24 hours are purged opportunistically.
Works on PostgreSQL (tables from migration 011) and the SQLite fallback (created here).
"""

import base64
import hashlib
import re
import secrets
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import chat_db
import e2ee_db
import platform_db

# ---- Limits (kept in step with frontend/src/services/attachmentLimits.ts) ----
MAX_FILE_BYTES = 5 * 1024 * 1024          # 5 MB per file
MAX_FILES_PER_MESSAGE = 5
DAILY_MAX_FILES = 60                      # per member, rolling 24 hours (room uploads)
DAILY_MAX_BYTES = 150 * 1024 * 1024       # 150 MB per member, rolling 24 hours
UNATTACHED_TTL_HOURS = 24

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS public_chat_attachments (
    attachment_id TEXT PRIMARY KEY,
    uploader_user_id TEXT NOT NULL,
    message_id TEXT,
    file_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'file',
    byte_length INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    data_b64 TEXT,
    deleted INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_public_chat_attachments_message ON public_chat_attachments(message_id);
CREATE INDEX IF NOT EXISTS idx_public_chat_attachments_uploader ON public_chat_attachments(uploader_user_id, created_at);
"""

_sqlite_schema_conn = None  # the SQLite connection the schema was created on

# Raster images that browsers show inline. Decided from the file's own bytes, never from its name
# or the browser-reported type. SVG is deliberately NOT here (it can carry script): it is a file.
_IMAGE_SIGNATURES: Tuple[Tuple[bytes, int, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", 0, "image/png"),
    (b"\xff\xd8\xff", 0, "image/jpeg"),
    (b"GIF87a", 0, "image/gif"),
    (b"GIF89a", 0, "image/gif"),
)


class AttachmentError(ValueError):
    """Rejected upload / attach (message is safe to show to the member). `status` is the HTTP code."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _is_pg() -> bool:
    return e2ee_db._is_pg()


def _ensure_schema() -> None:
    global _sqlite_schema_conn
    platform_db.ensure_platform_tables()
    if _is_pg() or _sqlite_schema_conn is chat_db._sqlite_conn:
        return
    with chat_db._sqlite_lock:
        chat_db._sqlite_conn.executescript(SQLITE_SCHEMA)
        chat_db._sqlite_conn.commit()
    _sqlite_schema_conn = chat_db._sqlite_conn


def reset_for_tests() -> None:
    global _sqlite_schema_conn
    _sqlite_schema_conn = None


def _run(statements: List[Tuple[str, tuple]], fetch: Optional[str] = None) -> Any:
    """Runs statements in ONE transaction; returns rows of the LAST statement if `fetch` is set."""
    _ensure_schema()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            result = None
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                for sql, params in statements:
                    cur.execute(sql.replace("?", "%s"), params)
                if fetch == "all":
                    result = [dict(r) for r in cur.fetchall()]
                elif fetch == "one":
                    row = cur.fetchone()
                    result = dict(row) if row else None
                elif fetch == "rowcount":
                    result = cur.rowcount
            conn.commit()
            return result
        except Exception:
            conn.rollback()
            raise
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        try:
            for sql, params in statements:
                cur.execute(sql, params)
            result = None
            if fetch == "all":
                result = [dict(r) for r in cur.fetchall()]
            elif fetch == "one":
                row = cur.fetchone()
                result = dict(row) if row else None
            elif fetch == "rowcount":
                result = cur.rowcount
            chat_db._sqlite_conn.commit()
            return result
        except Exception:
            chat_db._sqlite_conn.rollback()
            raise


# ----------------------------------------------------------------------------- helpers

def sniff_image_type(data: bytes) -> Optional[str]:
    """The real image type from the first bytes (PNG, JPEG, GIF, WebP), else None."""
    for sig, offset, mime in _IMAGE_SIGNATURES:
        if data[offset:offset + len(sig)] == sig:
            return mime
    if len(data) >= 12 and data[0:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


_UNSAFE_NAME_CHARS = re.compile(r'[\x00-\x1f\x7f/\\:*?"<>|]+')


def clean_file_name(raw: str) -> str:
    """A safe display / download name: no path parts or control characters, at most 120 characters."""
    name = unicodedata.normalize("NFC", (raw or "").strip())
    name = name.replace("\\", "/").split("/")[-1]
    name = _UNSAFE_NAME_CHARS.sub("_", name).strip(" .")
    if not name:
        name = "file"
    if len(name) > 120:
        stem, dot, ext = name.rpartition(".")
        if dot and 0 < len(ext) <= 12:
            name = stem[: 119 - len(ext)] + "." + ext
        else:
            name = name[:120]
    return name


def _kind_for(mime_reported: str, sniffed_image: Optional[str]) -> str:
    if sniffed_image:
        return "image"
    m = (mime_reported or "").lower()
    if m.startswith("video/"):
        return "video"
    if m.startswith("audio/"):
        return "audio"
    return "file"


def _public_record(r: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "attachment_id": r["attachment_id"],
        "file_name": r["file_name"],
        "mime_type": r["mime_type"],
        "kind": r["kind"],
        "size_bytes": int(r["byte_length"]),
    }


def purge_expired_unattached() -> None:
    """Frees storage: drops uploads that were never sent (older than 24 h) and the files of messages
    that fell out of the room's retention window (they are no longer shown, so their files are not kept)."""
    cutoff = _iso(_now() - timedelta(hours=UNATTACHED_TTL_HOURS))
    try:
        retention_days = int(platform_db.get_platform_settings().get("public_chat_retention_days") or 90)
    except Exception:
        retention_days = 90
    retention_cutoff = _iso(_now() - timedelta(days=retention_days))
    _run([
        (
            "UPDATE public_chat_attachments SET data_b64 = NULL, deleted = 1 "
            "WHERE message_id IS NULL AND deleted = 0 AND created_at < ?",
            (cutoff,),
        ),
        (
            "UPDATE public_chat_attachments SET data_b64 = NULL, deleted = 1 "
            "WHERE deleted = 0 AND message_id IN (SELECT message_id FROM public_chat_messages WHERE created_at < ?)",
            (retention_cutoff,),
        ),
    ])


def usage_last_24h(user_id: str) -> Tuple[int, int]:
    since = _iso(_now() - timedelta(hours=24))
    row = _run([(
        "SELECT COUNT(*) AS n, COALESCE(SUM(byte_length), 0) AS b FROM public_chat_attachments "
        "WHERE uploader_user_id = ? AND created_at >= ?",
        (user_id, since),
    )], fetch="one")
    return int(row["n"] or 0), int(row["b"] or 0)


# ----------------------------------------------------------------------------- writes

def store_upload(user_id: str, file_name: str, mime_type: str, data_b64: str) -> Dict[str, Any]:
    """Validates and stores one file (not yet attached to a message)."""
    try:
        data = base64.b64decode(data_b64, validate=True)
    except Exception:
        raise AttachmentError("The file could not be read (invalid encoding).")
    if not data:
        raise AttachmentError("Empty files cannot be sent.")
    if len(data) > MAX_FILE_BYTES:
        raise AttachmentError(f"Files can be at most {MAX_FILE_BYTES // (1024 * 1024)} MB.", status=413)

    purge_expired_unattached()
    n, b = usage_last_24h(user_id)
    if n + 1 > DAILY_MAX_FILES or b + len(data) > DAILY_MAX_BYTES:
        raise AttachmentError(
            f"Daily limit reached: up to {DAILY_MAX_FILES} files and "
            f"{DAILY_MAX_BYTES // (1024 * 1024)} MB in 24 hours in the Members' room.",
            status=429,
        )

    sniffed = sniff_image_type(data)
    reported = (mime_type or "").strip().lower()[:100]
    if not re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+-]+", reported or ""):
        reported = "application/octet-stream"
    # An image's type always comes from its bytes; a file that only CLAIMS to be an image is a file.
    eff_mime = sniffed or ("application/octet-stream" if reported.startswith("image/") else reported)
    rec = {
        "attachment_id": f"patt_{secrets.token_hex(14)}",
        "uploader_user_id": user_id,
        "file_name": clean_file_name(file_name),
        "mime_type": eff_mime,
        "kind": _kind_for(eff_mime, sniffed),
        "byte_length": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "created_at": _iso(_now()),
    }
    _run([(
        "INSERT INTO public_chat_attachments (attachment_id, uploader_user_id, message_id, file_name, mime_type, "
        "kind, byte_length, sha256, data_b64, deleted, created_at) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, 0, ?)",
        (rec["attachment_id"], user_id, rec["file_name"], rec["mime_type"], rec["kind"], rec["byte_length"],
         rec["sha256"], base64.b64encode(data).decode("ascii"), rec["created_at"]),
    )])
    return _public_record(rec)


def validate_attachable(user_id: str, attachment_ids: Iterable[str]) -> List[str]:
    """Checks the ids belong to this member, are not attached yet and not expired. Returns them de-duplicated."""
    ids: List[str] = []
    for a in attachment_ids or []:
        if isinstance(a, str) and a and a not in ids:
            ids.append(a)
    if not ids:
        return []
    if len(ids) > MAX_FILES_PER_MESSAGE:
        raise AttachmentError(f"At most {MAX_FILES_PER_MESSAGE} files per message.")
    placeholders = ",".join("?" for _ in ids)
    rows = _run([(
        f"SELECT attachment_id, uploader_user_id, message_id, deleted FROM public_chat_attachments "
        f"WHERE attachment_id IN ({placeholders})",
        tuple(ids),
    )], fetch="all") or []
    found = {r["attachment_id"]: r for r in rows}
    for a in ids:
        r = found.get(a)
        if not r or r["uploader_user_id"] != user_id or int(r["deleted"] or 0):
            raise AttachmentError("One of the files is no longer available. Attach it again.")
        if r["message_id"]:
            raise AttachmentError("One of the files was already sent.")
    return ids


def attach_to_message(user_id: str, message_id: str, attachment_ids: List[str]) -> List[Dict[str, Any]]:
    if not attachment_ids:
        return []
    placeholders = ",".join("?" for _ in attachment_ids)
    _run([(
        f"UPDATE public_chat_attachments SET message_id = ? WHERE uploader_user_id = ? AND message_id IS NULL "
        f"AND deleted = 0 AND attachment_id IN ({placeholders})",
        (message_id, user_id, *attachment_ids),
    )])
    return attachments_for_messages([message_id]).get(message_id, [])


def purge_for_message(message_id: str) -> None:
    _run([(
        "UPDATE public_chat_attachments SET data_b64 = NULL, deleted = 1 WHERE message_id = ?",
        (message_id,),
    )])


# ----------------------------------------------------------------------------- reads

def attachments_for_messages(message_ids: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    ids = [m for m in message_ids if m]
    if not ids:
        return out
    placeholders = ",".join("?" for _ in ids)
    rows = _run([(
        f"SELECT attachment_id, message_id, file_name, mime_type, kind, byte_length, created_at "
        f"FROM public_chat_attachments WHERE deleted = 0 AND message_id IN ({placeholders}) "
        f"ORDER BY created_at, attachment_id",
        tuple(ids),
    )], fetch="all") or []
    for r in rows:
        out.setdefault(r["message_id"], []).append(_public_record(r))
    return out


def get_for_download(attachment_id: str, viewer_user_id: str) -> Optional[Dict[str, Any]]:
    """The file with its bytes, if the viewer may see it: attached to a live message, or their own upload."""
    row = _run([(
        "SELECT a.attachment_id, a.uploader_user_id, a.message_id, a.file_name, a.mime_type, a.kind, "
        "a.byte_length, a.sha256, a.data_b64, a.deleted, m.deleted AS message_deleted "
        "FROM public_chat_attachments a LEFT JOIN public_chat_messages m ON m.message_id = a.message_id "
        "WHERE a.attachment_id = ?",
        (attachment_id,),
    )], fetch="one")
    if not row:
        return None
    gone = int(row["deleted"] or 0) or not row["data_b64"]
    if row["message_id"]:
        gone = gone or bool(int(row["message_deleted"] or 0)) or row["message_deleted"] is None
    elif row["uploader_user_id"] != viewer_user_id:
        return None  # pending uploads are private to their uploader
    row["gone"] = bool(gone)
    return row