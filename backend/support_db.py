"""
"Talk to admin": support conversations between members and the admin team.

Storage works on PostgreSQL (Neon) and the SQLite fallback. Timestamps are ISO-8601 UTC
strings in both, so ordering by them is correct.
"""

import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import chat_db
import e2ee_db
import platform_db

MAX_OPEN_THREADS_PER_USER = 5

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS support_threads (
    thread_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_message_at TEXT NOT NULL,
    last_sender_role TEXT NOT NULL DEFAULT 'user',
    user_unread INTEGER NOT NULL DEFAULT 0,
    admin_unread INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_support_threads_user ON support_threads(user_id, last_message_at);
CREATE INDEX IF NOT EXISTS idx_support_threads_status ON support_threads(status, last_message_at);
CREATE TABLE IF NOT EXISTS support_messages (
    message_id TEXT PRIMARY KEY,
    thread_id TEXT NOT NULL,
    sender_role TEXT NOT NULL,
    sender_id TEXT,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_support_messages_thread ON support_messages(thread_id, created_at);
"""

_sqlite_schema_ready = False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_pg() -> bool:
    return e2ee_db._is_pg()


def _ensure_schema() -> None:
    """PostgreSQL gets its tables from migration 008; SQLite is created here on first use."""
    global _sqlite_schema_ready
    platform_db.ensure_platform_tables()
    if _is_pg() or _sqlite_schema_ready:
        return
    with chat_db._sqlite_lock:
        chat_db._sqlite_conn.executescript(SQLITE_SCHEMA)
        chat_db._sqlite_conn.commit()
    _sqlite_schema_ready = True


def reset_for_tests() -> None:
    global _sqlite_schema_ready
    _sqlite_schema_ready = False


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
            chat_db._sqlite_conn.commit()
            return result
        except Exception:
            chat_db._sqlite_conn.rollback()
            raise


# ----------------------------------------------------------------------------- writes

def create_thread(user_id: str, subject: str, content: str) -> Dict[str, Any]:
    open_count = _run(
        [("SELECT COUNT(*) AS n FROM support_threads WHERE user_id = ? AND status = 'open'", (user_id,))],
        fetch="one",
    )
    if int(open_count["n"]) >= MAX_OPEN_THREADS_PER_USER:
        raise ValueError(
            f"You already have {MAX_OPEN_THREADS_PER_USER} open conversations. "
            "Please reply in one of them or wait for the admin to close it."
        )
    ts = _now()
    thread_id = f"sup_{secrets.token_hex(10)}"
    message_id = f"supm_{secrets.token_hex(10)}"
    _run([
        (
            """INSERT INTO support_threads
               (thread_id, user_id, subject, status, created_at, updated_at, last_message_at,
                last_sender_role, user_unread, admin_unread)
               VALUES (?, ?, ?, 'open', ?, ?, ?, 'user', 0, 1)""",
            (thread_id, user_id, subject, ts, ts, ts),
        ),
        (
            """INSERT INTO support_messages (message_id, thread_id, sender_role, sender_id, content, created_at)
               VALUES (?, ?, 'user', ?, ?, ?)""",
            (message_id, thread_id, user_id, content, ts),
        ),
    ])
    return get_thread(thread_id)  # type: ignore[return-value]


def add_message(thread_id: str, sender_role: str, sender_id: str, content: str) -> Dict[str, Any]:
    """A user reply re-opens a closed conversation; an admin reply never changes its status."""
    if sender_role not in ("user", "admin"):
        raise ValueError("invalid sender role")
    ts = _now()
    message_id = f"supm_{secrets.token_hex(10)}"
    if sender_role == "user":
        update = (
            """UPDATE support_threads SET last_message_at = ?, updated_at = ?, last_sender_role = 'user',
               status = 'open', admin_unread = admin_unread + 1 WHERE thread_id = ?""",
            (ts, ts, thread_id),
        )
    else:
        update = (
            """UPDATE support_threads SET last_message_at = ?, updated_at = ?, last_sender_role = 'admin',
               user_unread = user_unread + 1 WHERE thread_id = ?""",
            (ts, ts, thread_id),
        )
    _run([
        (
            """INSERT INTO support_messages (message_id, thread_id, sender_role, sender_id, content, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (message_id, thread_id, sender_role, sender_id, content, ts),
        ),
        update,
    ])
    return {"message_id": message_id, "thread_id": thread_id, "sender_role": sender_role,
            "content": content, "created_at": ts}


def mark_read(thread_id: str, role: str) -> None:
    col = "user_unread" if role == "user" else "admin_unread"
    _run([(f"UPDATE support_threads SET {col} = 0 WHERE thread_id = ? AND {col} <> 0", (thread_id,))])


def set_status(thread_id: str, status: str) -> None:
    if status not in ("open", "closed"):
        raise ValueError("status must be 'open' or 'closed'")
    _run([("UPDATE support_threads SET status = ?, updated_at = ? WHERE thread_id = ?", (status, _now(), thread_id))])


# ----------------------------------------------------------------------------- reads

def get_thread(thread_id: str) -> Optional[Dict[str, Any]]:
    return _run([("SELECT * FROM support_threads WHERE thread_id = ?", (thread_id,))], fetch="one")


def list_messages(thread_id: str, limit: int = 300) -> List[Dict[str, Any]]:
    return _run(
        [("""SELECT message_id, thread_id, sender_role, content, created_at FROM support_messages
             WHERE thread_id = ? ORDER BY created_at ASC LIMIT ?""", (thread_id, int(limit)))],
        fetch="all",
    )


def list_user_threads(user_id: str) -> List[Dict[str, Any]]:
    return _run(
        [("""SELECT * FROM support_threads WHERE user_id = ? ORDER BY last_message_at DESC LIMIT 100""", (user_id,))],
        fetch="all",
    )


def user_unread_total(user_id: str) -> int:
    row = _run([("SELECT COALESCE(SUM(user_unread), 0) AS n FROM support_threads WHERE user_id = ?", (user_id,))], fetch="one")
    return int(row["n"] or 0)


def admin_list_threads(status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    if status in ("open", "closed"):
        return _run(
            [("SELECT * FROM support_threads WHERE status = ? ORDER BY last_message_at DESC LIMIT ?", (status, int(limit)))],
            fetch="all",
        )
    return _run([("SELECT * FROM support_threads ORDER BY last_message_at DESC LIMIT ?", (int(limit),))], fetch="all")


def admin_unread_total() -> int:
    row = _run([("SELECT COALESCE(SUM(admin_unread), 0) AS n FROM support_threads", ())], fetch="one")
    return int(row["n"] or 0)
