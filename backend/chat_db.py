"""
Neon PostgreSQL Database Adapter for Chat Platform & E2EE Storage.
Provides unified relational connection pooling on PostgreSQL (Neon DB)
with an isolated thread-safe SQLite fallback for local/automated testing.
"""

import os
import sys
import json
import sqlite3
import threading
import time
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Read Neon / PostgreSQL connection string
NEON_DATABASE_URL = (
    os.getenv("NEON_DATABASE_URL")
    or os.getenv("DATABASE_URL")
    or os.getenv("POSTGRES_URL")
)

_HAS_PSYCOPG2 = False
try:
    import psycopg2
    from psycopg2 import pool, extras
    from psycopg2.extras import RealDictCursor
    _HAS_PSYCOPG2 = True
except ImportError:
    _HAS_PSYCOPG2 = False
    RealDictCursor = None

_pg_pool: Optional[Any] = None


# ---------------------------------------------------------------------------
# Resilient Neon connection pool
#
# Neon (and any NAT/firewall in between) silently drops idle SSL connections and
# suspends idle compute. psycopg2's stock pool happily hands that dead socket to
# the next request, which then fails with
#   "SSL SYSCALL error: Software caused connection abort"
# -> HTTP 500 -> "Failed to fetch" in the browser on the first load after idle.
# This pool validates any connection that has sat idle before handing it out,
# silently replaces dead ones, retries transient connect errors (Neon waking up),
# and turns on TCP keepalives so the OS notices dead sockets early.
# ---------------------------------------------------------------------------
_DB_POOL_MIN = int(os.getenv("DB_POOL_MIN", "3"))
_DB_POOL_MAX = int(os.getenv("DB_POOL_MAX", "10"))
_DB_VALIDATE_AFTER_SECS = float(os.getenv("DB_POOL_VALIDATE_AFTER_SECS", "5"))
_DB_CONNECT_RETRIES = int(os.getenv("DB_CONNECT_RETRIES", "3"))
# How long a request waits for a free database connection when all are busy, before giving up (503).
_DB_POOL_WAIT_SECS = float(os.getenv("DB_POOL_WAIT_SECS", "10"))

if _HAS_PSYCOPG2:
    from psycopg2 import extensions as _pg_ext

    class ResilientConnectionPool(pool.ThreadedConnectionPool):
        """ThreadedConnectionPool that never returns a stale/dead connection."""

        def __init__(self, minconn, maxconn, *args, **kwargs):
            self._last_used = {}
            # psycopg2's pool raises "connection pool exhausted" the instant all connections are busy.
            # This semaphore makes extra requests WAIT their turn instead of failing.
            self._slots = threading.BoundedSemaphore(maxconn)
            super().__init__(minconn, maxconn, *args, **kwargs)

        # -- helpers ---------------------------------------------------------
        def _is_usable(self, conn) -> bool:
            if conn.closed:
                return False
            idle = time.monotonic() - self._last_used.get(id(conn), 0.0)
            if idle < _DB_VALIDATE_AFTER_SECS:
                return True  # used moments ago: skip the extra round-trip
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                if conn.get_transaction_status() != _pg_ext.TRANSACTION_STATUS_IDLE:
                    conn.rollback()
                return True
            except Exception:
                return False

        def _discard(self, conn, key=None) -> None:
            self._last_used.pop(id(conn), None)
            try:
                super().putconn(conn, key, close=True)
            except Exception:
                pass

        # -- pool API --------------------------------------------------------
        def getconn(self, key=None):
            if not self._slots.acquire(timeout=_DB_POOL_WAIT_SECS):
                raise pool.PoolError("timed out waiting for a free database connection (server busy)")
            try:
                return self._getconn_holding_slot(key)
            except BaseException:
                self._slots.release()
                raise

        def _getconn_holding_slot(self, key=None):
            attempts = self.maxconn + _DB_CONNECT_RETRIES + 1
            connect_failures = 0
            last_err: Optional[Exception] = None
            for _ in range(attempts):
                try:
                    conn = super().getconn(key)
                except (psycopg2.OperationalError, psycopg2.InterfaceError) as exc:
                    # Could not open a fresh connection (e.g. Neon compute waking up).
                    last_err = exc
                    connect_failures += 1
                    if connect_failures > _DB_CONNECT_RETRIES:
                        break
                    time.sleep(min(0.4 * (2 ** (connect_failures - 1)), 2.0))
                    continue
                if self._is_usable(conn):
                    return conn
                self._discard(conn, key)  # dead socket: drop it, try the next one
            raise last_err or psycopg2.OperationalError(
                "Could not obtain a healthy database connection"
            )

        def putconn(self, conn, key=None, close=False):
            if conn is not None and (close or conn.closed):
                self._last_used.pop(id(conn), None)
                close = True
            elif conn is not None:
                self._last_used[id(conn)] = time.monotonic()
            try:
                return super().putconn(conn, key, close=close)
            finally:
                try:
                    self._slots.release()
                except ValueError:
                    pass  # returned a connection this pool never handed out

        def purge_idle(self) -> int:
            """Close every idle pooled connection (used after a connection error)."""
            closed = 0
            with self._lock:
                idle, self._pool = list(self._pool), []
            for conn in idle:
                self._last_used.pop(id(conn), None)
                try:
                    conn.close()
                    closed += 1
                except Exception:
                    pass
            return closed


def purge_idle_connections() -> int:
    """Drop idle pooled connections so the next request opens fresh ones."""
    p = _pg_pool
    if p is not None and hasattr(p, "purge_idle"):
        try:
            return p.purge_idle()
        except Exception:
            return 0
    return 0
_sqlite_conn: Optional[sqlite3.Connection] = None
_sqlite_lock = threading.RLock()
_use_sqlite_fallback = ("unittest" in sys.modules or os.getenv("TESTING") == "1")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _init_sqlite_engine():
    global _sqlite_conn
    with _sqlite_lock:
        if _sqlite_conn is None:
            db_path = ":memory:"
            if (
                os.getenv("TESTING") != "1"
                and "unittest" not in sys.modules
                and not os.getenv("NEON_DATABASE_URL")
                and not os.getenv("DATABASE_URL")
                and not os.getenv("POSTGRES_URL")
            ):
                base_dir = os.path.dirname(os.path.abspath(__file__))
                db_path = os.path.join(base_dir, "local_dev.sqlite3")
            _sqlite_conn = sqlite3.connect(db_path, check_same_thread=False)
            _sqlite_conn.row_factory = sqlite3.Row
            cur = _sqlite_conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS chat_messages (
                    id TEXT PRIMARY KEY,
                    room_id TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    content_iv TEXT NOT NULL,
                    content_ciphertext TEXT NOT NULL,
                    recipients TEXT NOT NULL,
                    sender_public_key TEXT,
                    signature TEXT,
                    client_timestamp TEXT,
                    server_timestamp TEXT,
                    created_at TEXT NOT NULL
                );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_msg_room_time ON chat_messages(room_id, created_at DESC);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_msg_sender ON chat_messages(sender);")
            cur.execute("PRAGMA table_info(chat_messages);")
            existing_cols = {row[1] for row in cur.fetchall()}
            if "client_timestamp" not in existing_cols:
                cur.execute("ALTER TABLE chat_messages ADD COLUMN client_timestamp TEXT;")
            if "server_timestamp" not in existing_cols:
                cur.execute("ALTER TABLE chat_messages ADD COLUMN server_timestamp TEXT;")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS chat_public_keys (
                    address TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL,
                    public_key_raw_b64 TEXT NOT NULL,
                    public_key_fingerprint TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    curve TEXT NOT NULL,
                    key_format_version INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    registered_at TEXT NOT NULL,
                    last_updated_at TEXT NOT NULL,
                    rotation_history TEXT NOT NULL
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS chat_key_challenges (
                    challenge_id TEXT PRIMARY KEY,
                    address TEXT NOT NULL,
                    public_key_fingerprint TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    message TEXT NOT NULL,
                    chain_id INTEGER NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );
            """)
            _sqlite_conn.commit()


def _ensure_initialized():
    global _pg_pool, _use_sqlite_fallback, _sqlite_conn
    if _use_sqlite_fallback or "unittest" in sys.modules or os.getenv("TESTING") == "1":
        _use_sqlite_fallback = True
        _init_sqlite_engine()
        return
    if _pg_pool is None and not _use_sqlite_fallback and _sqlite_conn is None:
        init_chat_db()


def init_chat_db():
    """
    Initializes the Chat PostgreSQL database schema on Neon DB.
    Falls back gracefully to SQLite if no Neon URL is configured.
    """
    global _pg_pool, _use_sqlite_fallback, _sqlite_conn
    if _use_sqlite_fallback or "unittest" in sys.modules or os.getenv("TESTING") == "1":
        _use_sqlite_fallback = True
        _init_sqlite_engine()
        return

    current_neon_url = (
        os.getenv("NEON_DATABASE_URL")
        or os.getenv("DATABASE_URL")
        or os.getenv("POSTGRES_URL")
    )

    if current_neon_url and _HAS_PSYCOPG2:
        try:
            conn_url = current_neon_url
            if conn_url.startswith("postgres://"):
                conn_url = "postgresql://" + conn_url[len("postgres://"):]

            if _pg_pool is None:
                _pg_pool = ResilientConnectionPool(
                    minconn=_DB_POOL_MIN,
                    maxconn=_DB_POOL_MAX,
                    dsn=conn_url,
                    sslmode="require",
                    connect_timeout=10,
                    # TCP keepalives: detect dead sockets quickly instead of on first use
                    keepalives=1,
                    keepalives_idle=30,
                    keepalives_interval=10,
                    keepalives_count=3,
                )

            conn = _pg_pool.getconn()
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS chat_messages (
                            id VARCHAR(64) PRIMARY KEY,
                            room_id VARCHAR(64) NOT NULL,
                            sender VARCHAR(42) NOT NULL,
                            algorithm VARCHAR(64) NOT NULL,
                            content_iv VARCHAR(64) NOT NULL,
                            content_ciphertext TEXT NOT NULL,
                            recipients JSONB NOT NULL,
                            sender_public_key JSONB,
                            signature VARCHAR(256),
                            client_timestamp VARCHAR(64),
                            server_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                        );
                        CREATE INDEX IF NOT EXISTS idx_chat_msg_room_time ON chat_messages(room_id, created_at DESC);
                        CREATE INDEX IF NOT EXISTS idx_chat_msg_sender ON chat_messages(sender);
                        ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS client_timestamp VARCHAR(64);
                        ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS server_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;
                    """)
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS chat_public_keys (
                            address VARCHAR(42) PRIMARY KEY,
                            public_key JSONB NOT NULL,
                            public_key_raw_b64 TEXT NOT NULL,
                            public_key_fingerprint VARCHAR(128) NOT NULL,
                            algorithm VARCHAR(64) NOT NULL,
                            curve VARCHAR(32) NOT NULL,
                            key_format_version INT NOT NULL,
                            status VARCHAR(32) NOT NULL DEFAULT 'active',
                            registered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                            last_updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                            rotation_history JSONB DEFAULT '[]'::jsonb
                        );
                        CREATE INDEX IF NOT EXISTS idx_chat_pk_fp ON chat_public_keys(public_key_fingerprint);
                        CREATE TABLE IF NOT EXISTS chat_key_challenges (
                            challenge_id VARCHAR(64) PRIMARY KEY,
                            address VARCHAR(42) NOT NULL,
                            public_key_fingerprint VARCHAR(128) NOT NULL,
                            nonce VARCHAR(64) NOT NULL,
                            message TEXT NOT NULL,
                            chain_id INT NOT NULL,
                            issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
                            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                            consumed BOOLEAN NOT NULL DEFAULT FALSE,
                            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                        );
                        CREATE INDEX IF NOT EXISTS idx_chat_chal_addr ON chat_key_challenges(address);
                        CREATE INDEX IF NOT EXISTS idx_chat_chal_exp ON chat_key_challenges(expires_at);
                    """)
                conn.commit()
                print("[OK] Neon PostgreSQL Chat Database connected & initialized.")
                _use_sqlite_fallback = ("unittest" in sys.modules or os.getenv("TESTING") == "1")
                import e2ee_db
                e2ee_db.ensure_e2ee_tables()
                return
            finally:
                _pg_pool.putconn(conn)
        except Exception as e:
            print(f"[WARN] Neon PostgreSQL connection note ({e}). Falling back to local isolated engine for chat.")
            _use_sqlite_fallback = True
    else:
        _use_sqlite_fallback = True

    _init_sqlite_engine()
    import e2ee_db
    e2ee_db.ensure_e2ee_tables()


def get_pg_conn():
    global _pg_pool
    if _pg_pool is None:
        raise RuntimeError("PostgreSQL connection pool not initialized")
    conn = _pg_pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
    except Exception:
        try:
            _pg_pool.putconn(conn, close=True)
        except Exception:
            pass
        conn = _pg_pool.getconn()
    return conn


def put_pg_conn(conn, close: bool = False):
    global _pg_pool
    if _pg_pool is not None:
        _pg_pool.putconn(conn, close=close)


def ping_pg_health() -> bool:
    global _pg_pool, _use_sqlite_fallback
    if _use_sqlite_fallback or _pg_pool is None:
        return True
    try:
        conn = get_pg_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1;")
            return True
        finally:
            put_pg_conn(conn)
    except Exception:
        return False


# ============================================================================
# CHAT MESSAGES PERSISTENCE & RETRIEVAL
# ============================================================================

class MessageInsertResult:
    """
    Structured outcome of an encrypted chat message insertion attempt.
    Tracks whether a new row was created, whether a duplicate message ID existed,
    and provides the pre-existing record when duplicate conflicts occur.
    """
    def __init__(
        self,
        created: bool,
        duplicate: bool = False,
        existing: Optional[Dict[str, Any]] = None,
        message_id: Optional[str] = None,
    ):
        self.created = bool(created)
        self.duplicate = bool(duplicate)
        self.existing = existing
        self.message_id = message_id

    def __bool__(self) -> bool:
        """Returns True if and only if a new message row was actually inserted."""
        return self.created

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "created": self.created,
            "duplicate": self.duplicate,
            "existing": self.existing,
            "message_id": self.message_id,
        }

    def __repr__(self) -> str:
        return (
            f"<MessageInsertResult created={self.created} "
            f"duplicate={self.duplicate} message_id={self.message_id}>"
        )


def get_chat_message_by_id(msg_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves a single encrypted message envelope by its unique client message ID.
    Supports both PostgreSQL (Neon DB) and SQLite engine fallbacks.
    Returns ciphertext only; server never decrypts content.
    """
    _ensure_initialized()
    if not msg_id:
        return None

    if _pg_pool and not _use_sqlite_fallback:
        conn = _pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, room_id, sender, algorithm, content_iv,
                           content_ciphertext, recipients, sender_public_key,
                           signature, client_timestamp, server_timestamp, created_at
                    FROM chat_messages
                    WHERE id = %s;
                """, (msg_id,))
                r = cur.fetchone()
                if not r:
                    return None
                recipients = r["recipients"] if isinstance(r["recipients"], list) else json.loads(r["recipients"])
                spk = r["sender_public_key"]
                if spk and isinstance(spk, str):
                    spk = json.loads(spk)
                server_ts = r["created_at"].isoformat() if hasattr(r["created_at"], "isoformat") else str(r["created_at"])
                client_ts = r.get("client_timestamp") or server_ts
                return {
                    "id": r["id"],
                    "room_id": r["room_id"],
                    "sender": r["sender"],
                    "algorithm": r["algorithm"],
                    "content_iv": r["content_iv"],
                    "content_ciphertext": r["content_ciphertext"],
                    "recipients": recipients,
                    "sender_public_key": spk,
                    "signature": r["signature"],
                    "client_timestamp": client_ts,
                    "server_timestamp": server_ts,
                    "created_at": server_ts,
                    "timestamp": client_ts,
                }
        finally:
            _pg_pool.putconn(conn)

    with _sqlite_lock:
        if _sqlite_conn is None:
            _init_sqlite_engine()
        cur = _sqlite_conn.cursor()
        cur.execute("""
            SELECT id, room_id, sender, algorithm, content_iv,
                   content_ciphertext, recipients, sender_public_key,
                   signature, client_timestamp, server_timestamp, created_at
            FROM chat_messages
            WHERE id = ?;
        """, (msg_id,))
        row = cur.fetchone()
        if not row:
            return None
        r = dict(row)
        recipients = json.loads(r["recipients"]) if r.get("recipients") else []
        spk = json.loads(r["sender_public_key"]) if r.get("sender_public_key") else None
        server_ts = str(r.get("created_at") or r.get("server_timestamp") or "")
        client_ts = str(r.get("client_timestamp") or server_ts)
        return {
            "id": r["id"],
            "room_id": r["room_id"],
            "sender": r["sender"],
            "algorithm": r["algorithm"],
            "content_iv": r["content_iv"],
            "content_ciphertext": r["content_ciphertext"],
            "recipients": recipients,
            "sender_public_key": spk,
            "signature": r["signature"],
            "client_timestamp": client_ts,
            "server_timestamp": server_ts,
            "created_at": server_ts,
            "timestamp": client_ts,
        }


def insert_chat_message(msg: Dict[str, Any]) -> MessageInsertResult:
    """
    Inserts a verified encrypted message envelope into Neon PostgreSQL or SQLite.
    Enforces:
    1. Strict zero-plaintext storage.
    2. Authoritative server-generated UTC creation timestamp (created_at).
       Never uses client-controlled timestamps for database creation or ordering.
    3. Preserves original client-signed timestamp in client_timestamp.
    4. Accurate row-creation detection across both PostgreSQL and SQLite.
    5. Clear duplicate conflict detection with retrieval of pre-existing record.
    6. Never silently overwrites an existing message row.
    """
    _ensure_initialized()
    if "plaintext" in msg or "message" in msg or "text" in msg:
        raise ValueError("Security violation: plaintext detected inside message payload")

    msg_id = msg.get("id") or msg.get("message_id")
    if not msg_id:
        raise ValueError("Message ID is required for storage")

    room_id = msg.get("room_id") or msg.get("channel", "global")
    sender = msg.get("sender")
    algorithm = msg.get("algorithm", "ECDH-P256-HKDF-AES-GCM-256")
    content_iv = msg.get("content_iv") or msg.get("iv", "")
    content_ciphertext = msg.get("content_ciphertext") or msg.get("ciphertext", "")
    recipients = msg.get("recipients", [])
    sender_public_key = msg.get("sender_public_key")
    signature = msg.get("signature")

    # Original client timestamp signed by sender wallet (never used for server ordering)
    client_timestamp = msg.get("client_timestamp") or msg.get("timestamp") or _now_iso()

    # Authoritative server-generated UTC creation timestamp
    # Must NOT use client-controlled timestamp for creation or ordering
    server_created_at = msg.get("server_timestamp") or msg.get("server_created_at") or _now_iso()
    created_at = server_created_at

    if _pg_pool and not _use_sqlite_fallback:
        conn = _pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO chat_messages (
                        id, room_id, sender, algorithm, content_iv,
                        content_ciphertext, recipients, sender_public_key,
                        signature, client_timestamp, server_timestamp, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                    RETURNING id;
                """, (
                    msg_id, room_id, sender, algorithm, content_iv,
                    content_ciphertext, json.dumps(recipients),
                    json.dumps(sender_public_key) if sender_public_key else None,
                    signature, client_timestamp, server_created_at, created_at
                ))
                row = cur.fetchone()
                created = (row is not None)
            conn.commit()

            if created:
                return MessageInsertResult(created=True, duplicate=False, message_id=msg_id)

            # Row was not created; primary key conflict detected on id
            existing = get_chat_message_by_id(msg_id)
            return MessageInsertResult(
                created=False,
                duplicate=True,
                existing=existing,
                message_id=msg_id,
            )
        finally:
            _pg_pool.putconn(conn)

    # SQLite fallback engine
    with _sqlite_lock:
        if _sqlite_conn is None:
            _init_sqlite_engine()
        cur = _sqlite_conn.cursor()
        cur.execute("""
            INSERT OR IGNORE INTO chat_messages (
                id, room_id, sender, algorithm, content_iv,
                content_ciphertext, recipients, sender_public_key,
                signature, client_timestamp, server_timestamp, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            msg_id, room_id, sender, algorithm, content_iv,
            content_ciphertext, json.dumps(recipients),
            json.dumps(sender_public_key) if sender_public_key else None,
            signature, client_timestamp, server_created_at, created_at
        ))
        created = bool(cur.rowcount > 0)
        _sqlite_conn.commit()

        if created:
            return MessageInsertResult(created=True, duplicate=False, message_id=msg_id)

        # Row was ignored; primary key conflict detected on id
        existing = get_chat_message_by_id(msg_id)
        return MessageInsertResult(
            created=False,
            duplicate=True,
            existing=existing,
            message_id=msg_id,
        )


def get_chat_messages(room_id: str = "global", recipient: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Retrieves the most recent encrypted messages for a room.
    Orders strictly by authoritative server creation timestamp (created_at DESC).
    Supports optional recipient address filtering for global chat envelopes.
    Returns ciphertext only; server never decrypts content.
    """
    _ensure_initialized()
    bounded_limit = max(1, min(limit, 100))
    norm_recip = recipient.strip().lower() if recipient else None

    if _pg_pool and not _use_sqlite_fallback:
        conn = _pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=extras.RealDictCursor) as cur:
                if norm_recip:
                    cur.execute("""
                        SELECT id, room_id, sender, algorithm, content_iv,
                               content_ciphertext, recipients, sender_public_key,
                               signature, client_timestamp, server_timestamp, created_at
                        FROM chat_messages
                        WHERE room_id = %s
                          AND (LOWER(sender) = %s OR recipients::text ILIKE %s)
                        ORDER BY created_at DESC
                        LIMIT %s;
                    """, (room_id, norm_recip, f"%{norm_recip}%", bounded_limit))
                else:
                    cur.execute("""
                        SELECT id, room_id, sender, algorithm, content_iv,
                               content_ciphertext, recipients, sender_public_key,
                               signature, client_timestamp, server_timestamp, created_at
                        FROM chat_messages
                        WHERE room_id = %s
                        ORDER BY created_at DESC
                        LIMIT %s;
                    """, (room_id, bounded_limit))
                rows = cur.fetchall()
                # Return in chronological order
                rows.reverse()
                results = []
                for r in rows:
                    recipients = r["recipients"] if isinstance(r["recipients"], list) else json.loads(r["recipients"])
                    if norm_recip:
                        is_sender = str(r["sender"]).strip().lower() == norm_recip
                        has_wrapper = any(
                            str(rec.get("recipient", "")).strip().lower() == norm_recip
                            for rec in (recipients if isinstance(recipients, list) else [])
                        )
                        if not (is_sender or has_wrapper):
                            continue
                    spk = r["sender_public_key"]
                    if spk and isinstance(spk, str):
                        spk = json.loads(spk)
                    server_ts = r["created_at"].isoformat() if hasattr(r["created_at"], "isoformat") else str(r["created_at"])
                    client_ts = r.get("client_timestamp") or server_ts
                    results.append({
                        "id": r["id"],
                        "room_id": r["room_id"],
                        "sender": r["sender"],
                        "algorithm": r["algorithm"],
                        "content_iv": r["content_iv"],
                        "content_ciphertext": r["content_ciphertext"],
                        "recipients": recipients,
                        "sender_public_key": spk,
                        "signature": r["signature"],
                        "client_timestamp": client_ts,
                        "server_timestamp": server_ts,
                        "created_at": server_ts,
                        "timestamp": client_ts,
                    })
                return results
        finally:
            _pg_pool.putconn(conn)

    # SQLite fallback
    with _sqlite_lock:
        if _sqlite_conn is None:
            init_chat_db()
        cur = _sqlite_conn.cursor()
        if norm_recip:
            cur.execute("""
                SELECT id, room_id, sender, algorithm, content_iv,
                       content_ciphertext, recipients, sender_public_key,
                       signature, client_timestamp, server_timestamp, created_at
                FROM chat_messages
                WHERE room_id = ?
                  AND (LOWER(sender) = ? OR LOWER(recipients) LIKE ?)
                ORDER BY created_at DESC
                LIMIT ?
            """, (room_id, norm_recip, f"%{norm_recip}%", bounded_limit))
        else:
            cur.execute("""
                SELECT id, room_id, sender, algorithm, content_iv,
                       content_ciphertext, recipients, sender_public_key,
                       signature, client_timestamp, server_timestamp, created_at
                FROM chat_messages
                WHERE room_id = ?
                ORDER BY created_at DESC
                LIMIT ?
            """, (room_id, bounded_limit))
        rows = cur.fetchall()
        rows = list(rows)
        rows.reverse()
        results = []
        for row in rows:
            r = dict(row)
            recipients = json.loads(r["recipients"]) if r.get("recipients") else []
            if norm_recip:
                is_sender = str(r["sender"]).strip().lower() == norm_recip
                has_wrapper = any(
                    str(rec.get("recipient", "")).strip().lower() == norm_recip
                    for rec in (recipients if isinstance(recipients, list) else [])
                )
                if not (is_sender or has_wrapper):
                    continue
            spk = json.loads(r["sender_public_key"]) if r.get("sender_public_key") else None
            server_ts = str(r.get("created_at") or r.get("server_timestamp") or "")
            client_ts = str(r.get("client_timestamp") or server_ts)
            results.append({
                "id": r["id"],
                "room_id": r["room_id"],
                "sender": r["sender"],
                "algorithm": r["algorithm"],
                "content_iv": r["content_iv"],
                "content_ciphertext": r["content_ciphertext"],
                "recipients": recipients,
                "sender_public_key": spk,
                "signature": r["signature"],
                "client_timestamp": client_ts,
                "server_timestamp": server_ts,
                "created_at": server_ts,
                "timestamp": client_ts,
            })
        return results


# ============================================================================
# CHAT PUBLIC KEYS DIRECTORY (Neon DB)
# ============================================================================

def insert_or_update_chat_key(doc: Dict[str, Any]) -> bool:
    """
    Inserts or updates a verified public key in Neon PostgreSQL.
    """
    _ensure_initialized()
    address = doc["address"]
    public_key = doc["public_key"]
    raw_b64 = doc["public_key_raw_b64"]
    fingerprint = doc["public_key_fingerprint"]
    algorithm = doc.get("algorithm", "ECDH-ES+A256GCM")
    curve = doc.get("curve", "P-256")
    version = doc.get("key_format_version", 1)
    status = doc.get("status", "active")
    now_str = doc.get("registered_at") or _now_iso()
    history = doc.get("rotation_history", [])

    if _pg_pool and not _use_sqlite_fallback:
        conn = _pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO chat_public_keys (
                        address, public_key, public_key_raw_b64,
                        public_key_fingerprint, algorithm, curve,
                        key_format_version, status, registered_at,
                        last_updated_at, rotation_history
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (address) DO UPDATE SET
                        public_key = EXCLUDED.public_key,
                        public_key_raw_b64 = EXCLUDED.public_key_raw_b64,
                        public_key_fingerprint = EXCLUDED.public_key_fingerprint,
                        last_updated_at = EXCLUDED.last_updated_at,
                        rotation_history = EXCLUDED.rotation_history;
                """, (
                    address, json.dumps(public_key), raw_b64, fingerprint,
                    algorithm, curve, version, status, now_str, now_str,
                    json.dumps(history)
                ))
            conn.commit()
            return True
        finally:
            _pg_pool.putconn(conn)

    # SQLite fallback
    with _sqlite_lock:
        if _sqlite_conn is None:
            init_chat_db()
        cur = _sqlite_conn.cursor()
        cur.execute("""
            INSERT INTO chat_public_keys (
                address, public_key, public_key_raw_b64,
                public_key_fingerprint, algorithm, curve,
                key_format_version, status, registered_at,
                last_updated_at, rotation_history
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (address) DO UPDATE SET
                public_key = excluded.public_key,
                public_key_raw_b64 = excluded.public_key_raw_b64,
                public_key_fingerprint = excluded.public_key_fingerprint,
                last_updated_at = excluded.last_updated_at,
                rotation_history = excluded.rotation_history;
        """, (
            address, json.dumps(public_key), raw_b64, fingerprint,
            algorithm, curve, version, status, now_str, now_str,
            json.dumps(history)
        ))
        _sqlite_conn.commit()
        return True


def get_chat_key(address: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves a registered public key for an address.
    """
    _ensure_initialized()
    if _pg_pool and not _use_sqlite_fallback:
        conn = _pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT address, public_key, public_key_raw_b64,
                           public_key_fingerprint, algorithm, curve,
                           key_format_version, status, registered_at,
                           last_updated_at, rotation_history
                    FROM chat_public_keys
                    WHERE LOWER(address) = LOWER(%s);
                """, (address,))
                row = cur.fetchone()
                if not row:
                    return None
                pk = row["public_key"] if isinstance(row["public_key"], dict) else json.loads(row["public_key"])
                history = row["rotation_history"] if isinstance(row["rotation_history"], list) else json.loads(row["rotation_history"])
                return {
                    "address": row["address"],
                    "public_key": pk,
                    "public_key_raw_b64": row["public_key_raw_b64"],
                    "public_key_fingerprint": row["public_key_fingerprint"],
                    "algorithm": row["algorithm"],
                    "curve": row["curve"],
                    "key_format_version": row["key_format_version"],
                    "status": row["status"],
                    "registered_at": row["registered_at"].isoformat() if hasattr(row["registered_at"], "isoformat") else str(row["registered_at"]),
                    "last_updated_at": row["last_updated_at"].isoformat() if hasattr(row["last_updated_at"], "isoformat") else str(row["last_updated_at"]),
                    "rotation_history": history,
                }
        finally:
            _pg_pool.putconn(conn)

    # SQLite fallback
    with _sqlite_lock:
        if _sqlite_conn is None:
            _init_sqlite_engine()
        cur = _sqlite_conn.cursor()
        cur.execute("""
            SELECT address, public_key, public_key_raw_b64,
                   public_key_fingerprint, algorithm, curve,
                   key_format_version, status, registered_at,
                   last_updated_at, rotation_history
            FROM chat_public_keys
            WHERE LOWER(address) = LOWER(?)
        """, (address,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            "address": row["address"],
            "public_key": json.loads(row["public_key"]),
            "public_key_raw_b64": row["public_key_raw_b64"],
            "public_key_fingerprint": row["public_key_fingerprint"],
            "algorithm": row["algorithm"],
            "curve": row["curve"],
            "key_format_version": row["key_format_version"],
            "status": row["status"],
            "registered_at": str(row["registered_at"]),
            "last_updated_at": str(row["last_updated_at"]),
            "rotation_history": json.loads(row["rotation_history"]),
        }


def get_chat_keys_batch(addresses: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Retrieves a dictionary of address -> key_doc for a list of addresses.
    """
    _ensure_initialized()
    if not addresses:
        return {}

    results = {}
    if _pg_pool and not _use_sqlite_fallback:
        conn = _pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT address, public_key, public_key_raw_b64,
                           public_key_fingerprint, algorithm, curve,
                           key_format_version, status, registered_at,
                           last_updated_at, rotation_history
                    FROM chat_public_keys
                    WHERE LOWER(address) = ANY(%s);
                """, ([a.lower() for a in addresses],))
                rows = cur.fetchall()
                for row in rows:
                    pk = row["public_key"] if isinstance(row["public_key"], dict) else json.loads(row["public_key"])
                    history = row["rotation_history"] if isinstance(row["rotation_history"], list) else json.loads(row["rotation_history"])
                    addr = row["address"]
                    results[addr] = {
                        "address": addr,
                        "public_key": pk,
                        "public_key_raw_b64": row["public_key_raw_b64"],
                        "public_key_fingerprint": row["public_key_fingerprint"],
                        "algorithm": row["algorithm"],
                        "curve": row["curve"],
                        "key_format_version": row["key_format_version"],
                        "status": row["status"],
                        "registered_at": row["registered_at"].isoformat() if hasattr(row["registered_at"], "isoformat") else str(row["registered_at"]),
                        "last_updated_at": row["last_updated_at"].isoformat() if hasattr(row["last_updated_at"], "isoformat") else str(row["last_updated_at"]),
                        "rotation_history": history,
                    }
            return results
        finally:
            _pg_pool.putconn(conn)

    # SQLite fallback
    with _sqlite_lock:
        if _sqlite_conn is None:
            init_chat_db()
        cur = _sqlite_conn.cursor()
        placeholders = ",".join("?" for _ in addresses)
        cur.execute(f"""
            SELECT address, public_key, public_key_raw_b64,
                   public_key_fingerprint, algorithm, curve,
                   key_format_version, status, registered_at,
                   last_updated_at, rotation_history
            FROM chat_public_keys
            WHERE LOWER(address) IN ({placeholders})
        """, [a.lower() for a in addresses])
        rows = cur.fetchall()
        for row in rows:
            addr = row["address"]
            results[addr] = {
                "address": addr,
                "public_key": json.loads(row["public_key"]),
                "public_key_raw_b64": row["public_key_raw_b64"],
                "public_key_fingerprint": row["public_key_fingerprint"],
                "algorithm": row["algorithm"],
                "curve": row["curve"],
                "key_format_version": row["key_format_version"],
                "status": row["status"],
                "registered_at": str(row["registered_at"]),
                "last_updated_at": str(row["last_updated_at"]),
                "rotation_history": json.loads(row["rotation_history"]),
            }
        return results


def get_active_room_public_keys(room_id: str = "global", limit: int = 50) -> List[Dict[str, Any]]:
    """
    Returns the authoritative list of active registered wallet public keys
    available to receive encrypted room messages.
    """
    _ensure_initialized()
    bounded_limit = max(1, min(limit, 50))

    if _pg_pool and not _use_sqlite_fallback:
        conn = _pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT address, public_key, public_key_raw_b64,
                           public_key_fingerprint, algorithm, curve,
                           key_format_version, last_updated_at
                    FROM chat_public_keys
                    WHERE status = 'active'
                    ORDER BY last_updated_at DESC
                    LIMIT %s;
                """, (bounded_limit,))
                rows = cur.fetchall()
                results = []
                for r in rows:
                    pk = r["public_key"] if isinstance(r["public_key"], dict) else json.loads(r["public_key"])
                    results.append({
                        "address": r["address"],
                        "public_key": pk,
                        "public_key_raw_b64": r["public_key_raw_b64"],
                        "public_key_fingerprint": r["public_key_fingerprint"],
                        "algorithm": r["algorithm"],
                        "curve": r["curve"],
                        "key_format_version": r["key_format_version"],
                    })
                return results
        finally:
            _pg_pool.putconn(conn)

    # SQLite fallback
    with _sqlite_lock:
        if _sqlite_conn is None:
            init_chat_db()
        cur = _sqlite_conn.cursor()
        cur.execute("""
            SELECT address, public_key, public_key_raw_b64,
                   public_key_fingerprint, algorithm, curve,
                   key_format_version, last_updated_at
            FROM chat_public_keys
            WHERE status = 'active'
            ORDER BY last_updated_at DESC
            LIMIT ?
        """, (bounded_limit,))
        rows = cur.fetchall()
        results = []
        for r in rows:
            results.append({
                "address": r["address"],
                "public_key": json.loads(r["public_key"]),
                "public_key_raw_b64": r["public_key_raw_b64"],
                "public_key_fingerprint": r["public_key_fingerprint"],
                "algorithm": r["algorithm"],
                "curve": r["curve"],
                "key_format_version": r["key_format_version"],
            })
        return results


# ============================================================================
# CHAT CHALLENGES PERSISTENCE & VERIFICATION (NEON POSTGRESQL ONLY)
# ============================================================================

def save_chat_challenge(record: Dict[str, Any]) -> bool:
    """Saves a key-binding challenge to Neon PostgreSQL."""
    _ensure_initialized()
    if not _use_sqlite_fallback and _pg_pool is not None:
        conn = _pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO chat_key_challenges (
                        challenge_id, address, public_key_fingerprint, nonce,
                        message, chain_id, issued_at, expires_at, consumed, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (challenge_id) DO UPDATE SET
                        expires_at = EXCLUDED.expires_at,
                        consumed = EXCLUDED.consumed;
                """, (
                    record["challenge_id"],
                    record["address"],
                    record["public_key_fingerprint"],
                    record["nonce"],
                    record["message"],
                    record.get("chain_id", 1),
                    record["issued_at"],
                    record["expires_at"],
                    record.get("consumed", False)
                ))
            conn.commit()
            return True
        except Exception as e:
            print(f"⚠️ [Neon DB Error] save_chat_challenge: {e}")
            return False
        finally:
            _pg_pool.putconn(conn)

    with _sqlite_lock:
        if _sqlite_conn is None:
            init_chat_db()
        cur = _sqlite_conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO chat_key_challenges (
                challenge_id, address, public_key_fingerprint, nonce,
                message, chain_id, issued_at, expires_at, consumed, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record["challenge_id"],
            record["address"],
            record["public_key_fingerprint"],
            record["nonce"],
            record["message"],
            record.get("chain_id", 1),
            record["issued_at"],
            record["expires_at"],
            1 if record.get("consumed") else 0,
            record.get("created_at", _now_iso())
        ))
        _sqlite_conn.commit()
        return True


def get_chat_challenge(challenge_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a challenge record by challenge_id from Neon PostgreSQL."""
    _ensure_initialized()
    if not _use_sqlite_fallback and _pg_pool is not None:
        conn = _pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT challenge_id, address, public_key_fingerprint, nonce,
                           message, chain_id, issued_at, expires_at, consumed, created_at
                    FROM chat_key_challenges
                    WHERE challenge_id = %s;
                """, (challenge_id,))
                row = cur.fetchone()
                if not row:
                    return None
                return {
                    "challenge_id": row["challenge_id"],
                    "address": row["address"],
                    "public_key_fingerprint": row["public_key_fingerprint"],
                    "nonce": row["nonce"],
                    "message": row["message"],
                    "chain_id": row["chain_id"],
                    "issued_at": row["issued_at"].isoformat() if hasattr(row["issued_at"], "isoformat") else str(row["issued_at"]),
                    "expires_at": row["expires_at"].isoformat() if hasattr(row["expires_at"], "isoformat") else str(row["expires_at"]),
                    "consumed": bool(row["consumed"]),
                }
        finally:
            _pg_pool.putconn(conn)

    with _sqlite_lock:
        if _sqlite_conn is None:
            init_chat_db()
        cur = _sqlite_conn.cursor()
        cur.execute("""
            SELECT challenge_id, address, public_key_fingerprint, nonce,
                   message, chain_id, issued_at, expires_at, consumed, created_at
            FROM chat_key_challenges
            WHERE challenge_id = ?
        """, (challenge_id,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            "challenge_id": row["challenge_id"],
            "address": row["address"],
            "public_key_fingerprint": row["public_key_fingerprint"],
            "nonce": row["nonce"],
            "message": row["message"],
            "chain_id": row["chain_id"],
            "issued_at": row["issued_at"],
            "expires_at": row["expires_at"],
            "consumed": bool(row["consumed"]),
        }


def consume_chat_challenge(challenge_id: str) -> bool:
    """Marks a challenge as consumed in Neon PostgreSQL."""
    _ensure_initialized()
    if not _use_sqlite_fallback and _pg_pool is not None:
        conn = _pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE chat_key_challenges
                    SET consumed = TRUE
                    WHERE challenge_id = %s;
                """, (challenge_id,))
            conn.commit()
            return True
        finally:
            _pg_pool.putconn(conn)

    with _sqlite_lock:
        if _sqlite_conn is None:
            init_chat_db()
        cur = _sqlite_conn.cursor()
        cur.execute("""
            UPDATE chat_key_challenges
            SET consumed = 1
            WHERE challenge_id = ?
        """, (challenge_id,))
        _sqlite_conn.commit()
        return True


def update_chat_challenge_expiry(challenge_id: str, expires_at: str) -> bool:
    """Updates challenge expiry timestamp in Neon PostgreSQL."""
    _ensure_initialized()
    if not _use_sqlite_fallback and _pg_pool is not None:
        conn = _pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE chat_key_challenges
                    SET expires_at = %s
                    WHERE challenge_id = %s;
                """, (expires_at, challenge_id))
            conn.commit()
            return True
        finally:
            _pg_pool.putconn(conn)

    with _sqlite_lock:
        if _sqlite_conn is None:
            init_chat_db()
        cur = _sqlite_conn.cursor()
        cur.execute("""
            UPDATE chat_key_challenges
            SET expires_at = ?
            WHERE challenge_id = ?
        """, (expires_at, challenge_id))
        _sqlite_conn.commit()
        return True


def delete_chat_message(msg_id: str) -> bool:
    """Deletes a message by id (for test cleanup or moderation)."""
    _ensure_initialized()
    if not _use_sqlite_fallback and _pg_pool is not None:
        conn = _pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM chat_messages WHERE id = %s;", (msg_id,))
            conn.commit()
            return True
        finally:
            _pg_pool.putconn(conn)

    with _sqlite_lock:
        if _sqlite_conn is None:
            init_chat_db()
        cur = _sqlite_conn.cursor()
        cur.execute("DELETE FROM chat_messages WHERE id = ?", (msg_id,))
        _sqlite_conn.commit()
        return True


def delete_chat_key(address: str) -> bool:
    """Deletes a public key by address (for test cleanup)."""
    _ensure_initialized()
    if not _use_sqlite_fallback and _pg_pool is not None:
        conn = _pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM chat_public_keys WHERE LOWER(address) = LOWER(%s);", (address,))
            conn.commit()
            return True
        finally:
            _pg_pool.putconn(conn)

    with _sqlite_lock:
        if _sqlite_conn is None:
            init_chat_db()
        cur = _sqlite_conn.cursor()
        cur.execute("DELETE FROM chat_public_keys WHERE LOWER(address) = LOWER(?)", (address,))
        _sqlite_conn.commit()
        return True


def delete_chat_challenge(challenge_id: str) -> bool:
    """Deletes a challenge by id (for test cleanup)."""
    _ensure_initialized()
    if not _use_sqlite_fallback and _pg_pool is not None:
        conn = _pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM chat_key_challenges WHERE challenge_id = %s;", (challenge_id,))
            conn.commit()
            return True
        finally:
            _pg_pool.putconn(conn)

    with _sqlite_lock:
        if _sqlite_conn is None:
            init_chat_db()
        cur = _sqlite_conn.cursor()
        cur.execute("DELETE FROM chat_key_challenges WHERE challenge_id = ?", (challenge_id,))
        _sqlite_conn.commit()
        return True