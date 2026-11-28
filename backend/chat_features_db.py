"""
Chat features that need the server: pinned messages, disappearing-message timers, mute / archive,
announcement-only groups, and reactions in the Members' room.

What the server stores here is never message text:
- pins:        which message ids are pinned in a chat (the text stays encrypted on devices)
- timers:      how long new messages in a chat live (the server must know to remove its copies)
- prefs:       a member's own mute / archive choice per chat (synced across their devices)
- group flags: whether only admins may post
- room reactions: the Members' room is not end-to-end encrypted, so its reactions are stored normally.
  Reactions in private chats and groups travel inside the encrypted messages instead.

Scope keys: 'dm:<conversation_id>' (shared by both people), 'group:<group_id>', 'room'.
Preference keys are from the member's point of view: 'dm:<peer_user_id>', 'group:<group_id>', 'room'.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import chat_db
import e2ee_db

PIN_LIMIT = 3  # like WhatsApp: pinning a fourth replaces the oldest
DISAPPEARING_CHOICES = (0, 86400, 7 * 86400, 90 * 86400)  # off, 24 hours, 7 days, 90 days
MUTE_CHOICES = {"off": 0, "8h": 8 * 3600, "1w": 7 * 86400, "always": None}
MUTE_FOREVER = "9999-12-31T23:59:59+00:00"
ROOM = "room"

_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS chat_message_pins (
        scope_key VARCHAR(160) NOT NULL,
        message_id VARCHAR(96) NOT NULL,
        pinned_by VARCHAR(64) NOT NULL,
        pinned_at {ts} NOT NULL,
        PRIMARY KEY (scope_key, message_id)
    )""",
    """CREATE TABLE IF NOT EXISTS chat_disappearing (
        scope_key VARCHAR(160) PRIMARY KEY,
        ttl_seconds INTEGER NOT NULL DEFAULT 0,
        set_by VARCHAR(64) NOT NULL,
        set_at {ts} NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS chat_conversation_prefs (
        user_id VARCHAR(64) NOT NULL,
        scope_key VARCHAR(160) NOT NULL,
        muted_until {ts},
        archived BOOLEAN NOT NULL DEFAULT FALSE,
        updated_at {ts} NOT NULL,
        PRIMARY KEY (user_id, scope_key)
    )""",
    """CREATE TABLE IF NOT EXISTS chat_group_settings (
        group_id VARCHAR(64) PRIMARY KEY,
        admins_only_posting BOOLEAN NOT NULL DEFAULT FALSE,
        updated_by VARCHAR(64) NOT NULL,
        updated_at {ts} NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS public_chat_reactions (
        message_id VARCHAR(96) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        emoji VARCHAR(32) NOT NULL,
        created_at {ts} NOT NULL,
        PRIMARY KEY (message_id, user_id)
    )""",
]

# The connection/pool object the tables were created on. We keep a real reference and compare with
# `is`: an id() integer can be reused by a new object once the old one is garbage collected, which
# would make us skip creating the tables on a brand-new database.
_ready_for: Any = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def _is_pg() -> bool:
    return e2ee_db._is_pg()


def _ensure_schema() -> None:
    """Creates the tables once per database connection (tests swap the SQLite database per class)."""
    global _ready_for
    e2ee_db._ready()
    target = chat_db._pg_pool if _is_pg() else chat_db._sqlite_conn
    if target is not None and _ready_for is target:
        return
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                for stmt in _SCHEMA:
                    cur.execute(stmt.format(ts="TIMESTAMP WITH TIME ZONE") + ";")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            for stmt in _SCHEMA:
                cur.execute(stmt.format(ts="TEXT"))
            chat_db._sqlite_conn.commit()
    _ready_for = target


def _run(sql: str, params: tuple = (), fetch: Optional[str] = None) -> Tuple[Any, int]:
    """One statement; `sql` uses {p} placeholders. Writes commit. Returns (rows, rowcount)."""
    _ensure_schema()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(sql.format(p="%s"), params)
                rows = cur.fetchall() if fetch == "all" else (cur.fetchone() if fetch == "one" else None)
                n = int(cur.rowcount or 0)
            conn.commit()
            return rows, n
        except Exception:
            conn.rollback()
            raise
        finally:
            chat_db._pg_pool.putconn(conn)
    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        try:
            cur.execute(sql.format(p="?"), params)
            rows = cur.fetchall() if fetch == "all" else (cur.fetchone() if fetch == "one" else None)
            n = int(cur.rowcount or 0)
            chat_db._sqlite_conn.commit()
            return rows, n
        except Exception:
            chat_db._sqlite_conn.rollback()
            raise


def _in_transaction(work, lock_key: Optional[str] = None):
    """Runs `work(execute)` as ONE transaction. `execute(sql, params, fetch)` behaves like `_run`
    but on the same connection. With `lock_key`, concurrent transactions for that key are
    serialized (Postgres advisory lock across processes; the SQLite connection lock in-process)."""
    _ensure_schema()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                if lock_key:
                    cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (lock_key,))

                def execute(sql: str, params: tuple = (), fetch: Optional[str] = None):
                    cur.execute(sql.format(p="%s"), params)
                    return cur.fetchall() if fetch == "all" else (cur.fetchone() if fetch == "one" else None)

                result = work(execute)
            conn.commit()
            return result
        except Exception:
            conn.rollback()
            raise
        finally:
            chat_db._pg_pool.putconn(conn)
    with chat_db._sqlite_lock:  # RLock: held for the whole read-modify-write
        cur = chat_db._sqlite_conn.cursor()
        try:
            def execute(sql: str, params: tuple = (), fetch: Optional[str] = None):
                cur.execute(sql.format(p="?"), params)
                return cur.fetchall() if fetch == "all" else (cur.fetchone() if fetch == "one" else None)

            result = work(execute)
            chat_db._sqlite_conn.commit()
            return result
        except Exception:
            chat_db._sqlite_conn.rollback()
            raise


def _as_dt(val: Any) -> Optional[datetime]:
    return e2ee_db._as_dt(val)


# ----------------------------------------------------------------------------- scope keys
def dm_scope_key(user_a: str, user_b: str) -> str:
    return "dm:" + e2ee_db.make_dm_conversation_id(user_a, user_b)


def group_scope_key(group_id: str) -> str:
    return "group:" + group_id


_PREF_KEY_RE = re.compile(r"^(room|dm:[A-Za-z0-9_\-]{6,64}|group:[A-Za-z0-9_\-]{6,64})$")


def is_valid_pref_key(key: str) -> bool:
    return bool(_PREF_KEY_RE.match(key or ""))


# ----------------------------------------------------------------------------- pins
def _pins_from_rows(rows) -> List[Dict[str, Any]]:
    pins = [{"message_id": r[0], "pinned_by": r[1], "pinned_at": _iso(_as_dt(r[2]))} for r in rows or []]
    pins.sort(key=lambda x: x["pinned_at"] or "", reverse=True)  # newest first
    return pins


_LIST_PINS_SQL = "SELECT message_id, pinned_by, pinned_at FROM chat_message_pins WHERE scope_key = {p}"


def list_pins(scope_key: str) -> List[Dict[str, Any]]:
    rows, _ = _run(_LIST_PINS_SQL, (scope_key,), fetch="all")
    return _pins_from_rows(rows)


def set_pin(scope_key: str, message_id: str, user_id: str, pinned: bool) -> Dict[str, Any]:
    """Pins or unpins a message. Pinning a 4th replaces the oldest pin (returned as `replaced`).

    The read (current pins), the eviction and the insert happen in one transaction that is
    serialized per chat, so two people pinning at the same moment can never exceed PIN_LIMIT."""

    def work(execute):
        replaced = None
        if not pinned:
            execute("DELETE FROM chat_message_pins WHERE scope_key = {p} AND message_id = {p}", (scope_key, message_id))
            return {"pins": _pins_from_rows(execute(_LIST_PINS_SQL, (scope_key,), "all")), "replaced": None}
        current = _pins_from_rows(execute(_LIST_PINS_SQL, (scope_key,), "all"))
        if any(p["message_id"] == message_id for p in current):
            return {"pins": current, "replaced": None}
        # Evict as many of the oldest as needed (normally one) to make room for the new pin.
        while len(current) >= PIN_LIMIT:
            oldest = current.pop()["message_id"]
            execute("DELETE FROM chat_message_pins WHERE scope_key = {p} AND message_id = {p}", (scope_key, oldest))
            replaced = replaced or oldest
        # Strictly newer than every remaining pin: on fast clocks (Windows ~1 ms) two pins can get the
        # same timestamp, and then "oldest" would be ambiguous and the wrong pin could be evicted.
        pinned_at = _now()
        newest = _as_dt(current[0]["pinned_at"]) if current else None
        if newest is not None and pinned_at <= newest:
            pinned_at = newest + timedelta(microseconds=1)
        execute(
            "INSERT INTO chat_message_pins (scope_key, message_id, pinned_by, pinned_at) VALUES ({p}, {p}, {p}, {p})",
            (scope_key, message_id, user_id, pinned_at.isoformat()),
        )
        return {"pins": _pins_from_rows(execute(_LIST_PINS_SQL, (scope_key,), "all")), "replaced": replaced}

    return _in_transaction(work, lock_key="pins:" + scope_key)


def unpin_everywhere(message_id: str) -> None:
    """A deleted message cannot stay pinned."""
    _run("DELETE FROM chat_message_pins WHERE message_id = {p}", (message_id,))


# ----------------------------------------------------------------------------- disappearing messages
def get_disappearing_ttl(scope_key: str) -> int:
    row, _ = _run("SELECT ttl_seconds FROM chat_disappearing WHERE scope_key = {p}", (scope_key,), fetch="one")
    return int(row[0]) if row else 0


def set_disappearing_ttl(scope_key: str, ttl_seconds: int, user_id: str) -> int:
    ttl = int(ttl_seconds)
    if ttl not in DISAPPEARING_CHOICES:
        raise ValueError("Choose off, 24 hours, 7 days or 90 days")
    _run(
        """INSERT INTO chat_disappearing (scope_key, ttl_seconds, set_by, set_at) VALUES ({p}, {p}, {p}, {p})
           ON CONFLICT (scope_key) DO UPDATE SET ttl_seconds = excluded.ttl_seconds,
               set_by = excluded.set_by, set_at = excluded.set_at""",
        (scope_key, ttl, user_id, _now().isoformat()),
    )
    return ttl


def expires_at_for(scope_key: str) -> Optional[str]:
    """When a message sent NOW in this chat should disappear (None = keep)."""
    ttl = get_disappearing_ttl(scope_key)
    return (_now() + timedelta(seconds=ttl)).isoformat() if ttl > 0 else None


# ----------------------------------------------------------------------------- announcement-only groups
def is_admins_only(group_id: str) -> bool:
    row, _ = _run("SELECT admins_only_posting FROM chat_group_settings WHERE group_id = {p}", (group_id,), fetch="one")
    return bool(row and row[0])


def set_admins_only(group_id: str, value: bool, user_id: str) -> bool:
    _run(
        """INSERT INTO chat_group_settings (group_id, admins_only_posting, updated_by, updated_at) VALUES ({p}, {p}, {p}, {p})
           ON CONFLICT (group_id) DO UPDATE SET admins_only_posting = excluded.admins_only_posting,
               updated_by = excluded.updated_by, updated_at = excluded.updated_at""",
        (group_id, bool(value), user_id, _now().isoformat()),
    )
    return bool(value)


def delete_group_features(group_id: str) -> None:
    """Called when a group is deleted."""
    key = group_scope_key(group_id)
    _run("DELETE FROM chat_message_pins WHERE scope_key = {p}", (key,))
    _run("DELETE FROM chat_disappearing WHERE scope_key = {p}", (key,))
    _run("DELETE FROM chat_group_settings WHERE group_id = {p}", (group_id,))
    _run("DELETE FROM chat_conversation_prefs WHERE scope_key = {p}", (key,))


# ----------------------------------------------------------------------------- mute & archive
def _pref_dict(muted_until: Any, archived: Any) -> Dict[str, Any]:
    until = _as_dt(muted_until)
    muted = bool(until and until > _now())
    return {
        "muted": muted,
        "muted_until": _iso(until) if muted else None,
        "muted_forever": bool(muted and until and until.year >= 9999),
        "archived": bool(archived),
    }


def get_prefs(user_id: str) -> Dict[str, Dict[str, Any]]:
    rows, _ = _run(
        "SELECT scope_key, muted_until, archived FROM chat_conversation_prefs WHERE user_id = {p}",
        (user_id,),
        fetch="all",
    )
    out = {}
    for r in rows:
        p = _pref_dict(r[1], r[2])
        if p["muted"] or p["archived"]:
            out[r[0]] = p
    return out


def get_pref(user_id: str, scope_key: str) -> Dict[str, Any]:
    row, _ = _run(
        "SELECT muted_until, archived FROM chat_conversation_prefs WHERE user_id = {p} AND scope_key = {p}",
        (user_id, scope_key),
        fetch="one",
    )
    return _pref_dict(row[0], row[1]) if row else _pref_dict(None, False)


def set_pref(user_id: str, scope_key: str, mute: Optional[str] = None, archived: Optional[bool] = None) -> Dict[str, Any]:
    """mute: 'off' | '8h' | '1w' | 'always' (None = leave as is). archived: True/False (None = leave)."""
    if not is_valid_pref_key(scope_key):
        raise ValueError("Unknown chat")
    current_row, _ = _run(
        "SELECT muted_until, archived FROM chat_conversation_prefs WHERE user_id = {p} AND scope_key = {p}",
        (user_id, scope_key),
        fetch="one",
    )
    muted_until = current_row[0] if current_row else None
    arch = bool(current_row[1]) if current_row else False
    if mute is not None:
        if mute not in MUTE_CHOICES:
            raise ValueError("mute must be off, 8h, 1w or always")
        secs = MUTE_CHOICES[mute]
        muted_until = None if secs == 0 else (MUTE_FOREVER if secs is None else (_now() + timedelta(seconds=secs)).isoformat())
    if archived is not None:
        arch = bool(archived)
    _run(
        """INSERT INTO chat_conversation_prefs (user_id, scope_key, muted_until, archived, updated_at)
           VALUES ({p}, {p}, {p}, {p}, {p})
           ON CONFLICT (user_id, scope_key) DO UPDATE SET muted_until = excluded.muted_until,
               archived = excluded.archived, updated_at = excluded.updated_at""",
        (user_id, scope_key, muted_until if not hasattr(muted_until, "isoformat") else muted_until.isoformat(),
         arch, _now().isoformat()),
    )
    return get_pref(user_id, scope_key)


def is_muted(user_id: str, scope_key: str) -> bool:
    return get_pref(user_id, scope_key)["muted"]


# ----------------------------------------------------------------------------- Members' room reactions
# One emoji = one "unit": a pictograph (optionally with variation selector, skin tone, tag
# sequence), a keycap (0-9 # * + optional FE0F + U+20E3), or a flag (two regional indicators);
# several units joined by ZWJ (U+200D) still count as one emoji (families, professions...).
_PICTO_RANGES = (
    (0x00A9, 0x00A9), (0x00AE, 0x00AE), (0x203C, 0x203C), (0x2049, 0x2049), (0x2122, 0x2122),
    (0x2139, 0x2139), (0x2194, 0x2199), (0x21A9, 0x21AA), (0x231A, 0x231B), (0x2328, 0x2328),
    (0x23CF, 0x23CF), (0x23E9, 0x23F3), (0x23F8, 0x23FA), (0x24C2, 0x24C2), (0x25AA, 0x25AB),
    (0x25B6, 0x25B6), (0x25C0, 0x25C0), (0x25FB, 0x25FE), (0x2600, 0x27BF), (0x2934, 0x2935),
    (0x2B05, 0x2B07), (0x2B1B, 0x2B1C), (0x2B50, 0x2B50), (0x2B55, 0x2B55), (0x3030, 0x3030),
    (0x303D, 0x303D), (0x3297, 0x3297), (0x3299, 0x3299), (0x1F000, 0x1F1E5), (0x1F200, 0x1F3FA),
    (0x1F400, 0x1FAFF), (0x1FC00, 0x1FFFD),
)
_KEYCAP_BASES = set("0123456789#*")
_VS = (0xFE0E, 0xFE0F)
_ZWJ = 0x200D
_KEYCAP = 0x20E3
MAX_EMOJI_CODEPOINTS = 16


def _is_picto(cp: int) -> bool:
    return any(lo <= cp <= hi for lo, hi in _PICTO_RANGES)


def _is_regional(cp: int) -> bool:
    return 0x1F1E6 <= cp <= 0x1F1FF


def _is_skin(cp: int) -> bool:
    return 0x1F3FB <= cp <= 0x1F3FF


def _is_tag(cp: int) -> bool:
    return 0xE0020 <= cp <= 0xE007E


def is_single_emoji(text: str) -> bool:
    cps = [ord(c) for c in text]
    if not cps or len(cps) > MAX_EMOJI_CODEPOINTS:
        return False
    i, n = 0, len(cps)

    def unit(i: int) -> int:
        """Parses one emoji unit starting at i; returns the index after it, or -1."""
        cp = cps[i]
        if chr(cp) in _KEYCAP_BASES:
            j = i + 1
            if j < n and cps[j] == 0xFE0F:
                j += 1
            return j + 1 if j < n and cps[j] == _KEYCAP else -1
        if _is_regional(cp):
            return i + 2 if i + 1 < n and _is_regional(cps[i + 1]) else -1
        if not _is_picto(cp):
            return -1
        j = i + 1
        if j < n and cps[j] in _VS:
            j += 1
        if j < n and _is_skin(cps[j]):
            j += 1
        if j < n and _is_tag(cps[j]):  # subdivision flags, e.g. England
            while j < n and _is_tag(cps[j]):
                j += 1
            if j >= n or cps[j] != 0xE007F:
                return -1
            j += 1
        return j

    i = unit(0)
    while 0 < i < n:
        if cps[i] != _ZWJ or i + 1 >= n:
            return False  # a second emoji (or stray text) not joined by ZWJ
        i = unit(i + 1)
    return i == n


def clean_reaction_emoji(raw: Any) -> str:
    """Exactly one emoji (skin tones, ZWJ sequences, flags and keycaps like 1️⃣ included).
    Letters, digits on their own, other scripts (Cyrillic, CJK...) and markup are rejected."""
    e = str(raw or "").strip()
    if not is_single_emoji(e):
        raise ValueError("A reaction must be a single emoji")
    return e


def set_public_reaction(message_id: str, user_id: str, emoji: Optional[str]) -> None:
    """One reaction per member per message (like WhatsApp). emoji None removes it."""
    if emoji is None:
        _run("DELETE FROM public_chat_reactions WHERE message_id = {p} AND user_id = {p}", (message_id, user_id))
        return
    e = clean_reaction_emoji(emoji)
    _run(
        """INSERT INTO public_chat_reactions (message_id, user_id, emoji, created_at) VALUES ({p}, {p}, {p}, {p})
           ON CONFLICT (message_id, user_id) DO UPDATE SET emoji = excluded.emoji, created_at = excluded.created_at""",
        (message_id, user_id, e, _now().isoformat()),
    )


def reactions_for_messages(message_ids: List[str]) -> Dict[str, Dict[str, List[str]]]:
    """{message_id: {emoji: [user_id, ...]}} for the given room messages (one query)."""
    ids = [m for m in dict.fromkeys(message_ids or []) if m]
    if not ids:
        return {}
    marks = ", ".join(["{p}"] * len(ids))
    rows, _ = _run(
        f"SELECT message_id, emoji, user_id FROM public_chat_reactions WHERE message_id IN ({marks}) ORDER BY created_at",
        tuple(ids),
        fetch="all",
    )
    out: Dict[str, Dict[str, List[str]]] = {}
    for mid, emoji, uid in rows:
        out.setdefault(mid, {}).setdefault(emoji, []).append(uid)
    return out


def delete_public_reactions(message_id: str) -> None:
    _run("DELETE FROM public_chat_reactions WHERE message_id = {p}", (message_id,))


# ----------------------------------------------------------------------------- housekeeping
_last_purge = 0.0


def purge_expired_if_due(min_interval_sec: float = 60.0) -> Optional[Dict[str, int]]:
    """Removes disappeared messages at most once a minute per server process (called from read paths)."""
    import time

    global _last_purge
    now = time.monotonic()
    if now - _last_purge < min_interval_sec:
        return None
    _last_purge = now
    try:
        return e2ee_db.purge_expired_messages()
    except Exception:  # never break a read because housekeeping failed
        return None