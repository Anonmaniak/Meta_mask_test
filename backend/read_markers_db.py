"""
Unread counts for private chats and groups (notification badges).

For every conversation the member has opened, the server remembers how far they have read
(`last_read_seq`, the highest message `seq` they have seen). Unread = messages from OTHER people
after that point. Message contents stay end-to-end encrypted; only these positions are stored,
and they are never shown to anyone else (they are separate from the opt-in read receipts).

The first time a member asks for unread counts, everything they already had is marked as read
(a `__baseline__` row records that this was done), so old history is never shown as "new".
Conversations and groups that appear after that start at 0, so all of their messages count.

Works on PostgreSQL (table from migration 012, also created here if missing) and the SQLite fallback.
"""

from typing import Any, Dict, Optional

import chat_db
import e2ee_db

BASELINE_KEY = "__baseline__"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS chat_read_markers (
    user_id VARCHAR(64) NOT NULL,
    scope_key VARCHAR(96) NOT NULL,
    last_read_seq BIGINT NOT NULL DEFAULT 0,
    updated_bucket VARCHAR(40) NOT NULL,
    PRIMARY KEY (user_id, scope_key)
);
CREATE INDEX IF NOT EXISTS idx_dm_recipient_seq ON chat_dm_messages(recipient_user_id, seq);
"""

_schema_ready_for: Optional[object] = None  # the connection/pool the schema was created on


def _is_pg() -> bool:
    return e2ee_db._is_pg()


def _ensure_schema() -> None:
    global _schema_ready_for
    e2ee_db._ready()
    target = chat_db._pg_pool if _is_pg() else chat_db._sqlite_conn
    if _schema_ready_for is target and target is not None:
        return
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(_SCHEMA)
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            chat_db._sqlite_conn.executescript(_SCHEMA)
            chat_db._sqlite_conn.commit()
    _schema_ready_for = target


def dm_scope_key(conversation_id: str) -> str:
    return f"dm:{conversation_id}"


def group_scope_key(group_id: str) -> str:
    return f"group:{group_id}"


def _ensure_baseline(user_id: str) -> None:
    """First call for a member: mark everything they already have as read (once)."""
    bucket = e2ee_db.coarse_timestamp_iso()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM chat_read_markers WHERE user_id = %s AND scope_key = %s;",
                    (user_id, BASELINE_KEY),
                )
                if cur.fetchone():
                    return
                cur.execute(
                    """
                    INSERT INTO chat_read_markers (user_id, scope_key, last_read_seq, updated_bucket)
                    SELECT %s, 'dm:' || conversation_id, MAX(seq), %s
                    FROM chat_dm_messages
                    WHERE sender_user_id = %s OR recipient_user_id = %s
                    GROUP BY conversation_id
                    ON CONFLICT (user_id, scope_key) DO NOTHING;
                    """,
                    (user_id, bucket, user_id, user_id),
                )
                cur.execute(
                    """
                    INSERT INTO chat_read_markers (user_id, scope_key, last_read_seq, updated_bucket)
                    SELECT %s, 'group:' || gm.group_id, MAX(gm.seq), %s
                    FROM chat_group_messages gm
                    WHERE gm.group_id IN (
                        SELECT group_id FROM chat_group_members WHERE user_id = %s AND status = 'active'
                    )
                    GROUP BY gm.group_id
                    ON CONFLICT (user_id, scope_key) DO NOTHING;
                    """,
                    (user_id, bucket, user_id),
                )
                cur.execute(
                    """
                    INSERT INTO chat_read_markers (user_id, scope_key, last_read_seq, updated_bucket)
                    VALUES (%s, %s, 0, %s)
                    ON CONFLICT (user_id, scope_key) DO NOTHING;
                    """,
                    (user_id, BASELINE_KEY, bucket),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            chat_db._pg_pool.putconn(conn)
        return

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            "SELECT 1 FROM chat_read_markers WHERE user_id = ? AND scope_key = ?",
            (user_id, BASELINE_KEY),
        )
        if cur.fetchone():
            return
        cur.execute(
            """
            INSERT OR IGNORE INTO chat_read_markers (user_id, scope_key, last_read_seq, updated_bucket)
            SELECT ?, 'dm:' || conversation_id, MAX(seq), ?
            FROM chat_dm_messages
            WHERE sender_user_id = ? OR recipient_user_id = ?
            GROUP BY conversation_id
            """,
            (user_id, bucket, user_id, user_id),
        )
        cur.execute(
            """
            INSERT OR IGNORE INTO chat_read_markers (user_id, scope_key, last_read_seq, updated_bucket)
            SELECT ?, 'group:' || gm.group_id, MAX(gm.seq), ?
            FROM chat_group_messages gm
            WHERE gm.group_id IN (
                SELECT group_id FROM chat_group_members WHERE user_id = ? AND status = 'active'
            )
            GROUP BY gm.group_id
            """,
            (user_id, bucket, user_id),
        )
        cur.execute(
            """
            INSERT OR IGNORE INTO chat_read_markers (user_id, scope_key, last_read_seq, updated_bucket)
            VALUES (?, ?, 0, ?)
            """,
            (user_id, BASELINE_KEY, bucket),
        )
        chat_db._sqlite_conn.commit()


def mark_read(user_id: str, scope_key: str, last_read_seq: int) -> None:
    """Moves the member's read position forward (never backwards)."""
    _ensure_schema()
    _ensure_baseline(user_id)
    bucket = e2ee_db.coarse_timestamp_iso()
    seq = max(0, int(last_read_seq))
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO chat_read_markers (user_id, scope_key, last_read_seq, updated_bucket)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (user_id, scope_key) DO UPDATE SET
                        last_read_seq = GREATEST(chat_read_markers.last_read_seq, EXCLUDED.last_read_seq),
                        updated_bucket = EXCLUDED.updated_bucket;
                    """,
                    (user_id, scope_key, seq, bucket),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
        return
    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            """
            INSERT INTO chat_read_markers (user_id, scope_key, last_read_seq, updated_bucket)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id, scope_key) DO UPDATE SET
                last_read_seq = MAX(chat_read_markers.last_read_seq, excluded.last_read_seq),
                updated_bucket = excluded.updated_bucket
            """,
            (user_id, scope_key, seq, bucket),
        )
        chat_db._sqlite_conn.commit()


_DM_COUNT_SQL = """
    SELECT m.conversation_id AS conversation_id,
           MIN(m.sender_user_id) AS peer_user_id,
           COUNT(*) AS n,
           MAX(m.seq) AS last_seq
    FROM chat_dm_messages m
    LEFT JOIN chat_read_markers r
           ON r.user_id = {ph} AND r.scope_key = 'dm:' || m.conversation_id
    WHERE m.recipient_user_id = {ph}
      AND m.sender_user_id <> {ph}
      AND m.seq > COALESCE(r.last_read_seq, 0)
      AND COALESCE(m.event_kind, 'message') = 'message'
      AND m.deleted_at IS NULL
      AND (m.expires_at IS NULL OR m.expires_at > {now})
    GROUP BY m.conversation_id
"""

_GROUP_COUNT_SQL = """
    SELECT gm.group_id AS group_id, COUNT(*) AS n, MAX(gm.seq) AS last_seq
    FROM chat_group_messages gm
    JOIN (
        SELECT group_id, MIN(joined_epoch) AS joined_epoch
        FROM chat_group_members
        WHERE user_id = {ph} AND status = 'active'
        GROUP BY group_id
    ) mem ON mem.group_id = gm.group_id
    LEFT JOIN chat_read_markers r
           ON r.user_id = {ph} AND r.scope_key = 'group:' || gm.group_id
    WHERE gm.sender_user_id <> {ph}
      AND gm.epoch >= mem.joined_epoch
      AND gm.seq > COALESCE(r.last_read_seq, 0)
      AND COALESCE(gm.event_kind, 'message') = 'message'
      AND gm.deleted_at IS NULL
      AND (gm.expires_at IS NULL OR gm.expires_at > {now})
    GROUP BY gm.group_id
"""


def unread_counts(user_id: str) -> Dict[str, Any]:
    """Unread messages from other people, per private chat and per group the member is in."""
    _ensure_schema()
    _ensure_baseline(user_id)
    params = (user_id, user_id, user_id)
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(_DM_COUNT_SQL.format(ph="%s", now="CURRENT_TIMESTAMP"), params)
                dm_rows = [dict(r) for r in cur.fetchall()]
                cur.execute(_GROUP_COUNT_SQL.format(ph="%s", now="CURRENT_TIMESTAMP"), params)
                grp_rows = [dict(r) for r in cur.fetchall()]
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            # SQLite stores ISO text in the same format as now_iso, so text comparison is time order.
            now_iso = e2ee_db.now_utc().isoformat()
            cur.execute(_DM_COUNT_SQL.format(ph="?", now="?"), params + (now_iso,))
            dm_rows = [dict(r) for r in cur.fetchall()]
            cur.execute(_GROUP_COUNT_SQL.format(ph="?", now="?"), params + (now_iso,))
            grp_rows = [dict(r) for r in cur.fetchall()]

    dms = []
    for r in dm_rows:
        peer = e2ee_db.get_user_by_id(r["peer_user_id"]) or {}
        dms.append({
            "conversation_id": r["conversation_id"],
            "peer_user_id": r["peer_user_id"],
            "peer_username": peer.get("username"),
            "unread": int(r["n"]),
            "last_seq": int(r["last_seq"]),
        })
    groups = []
    for r in grp_rows:
        g = e2ee_db.get_mls_group(r["group_id"])
        groups.append({
            "group_id": r["group_id"],
            "name": g["name"] if g else "Group",
            "unread": int(r["n"]),
            "last_seq": int(r["last_seq"]),
        })
    total = sum(d["unread"] for d in dms) + sum(g["unread"] for g in groups)
    return {"dm": dms, "groups": groups, "total": total}