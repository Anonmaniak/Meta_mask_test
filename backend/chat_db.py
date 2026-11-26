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
import capacity as _capacity  # noqa: E402  (sizes the pool to the plan this server runs on)

_DB_POOL_MAX = int(os.getenv("DB_POOL_MAX") or _capacity.default_pool_max())
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


class DatabaseUnavailableError(RuntimeError):
    """Production must never run on the local SQLite fallback (see is_production())."""


def is_production() -> bool:
    """On Render (which sets RENDER) or with ENVIRONMENT=production, and not under tests.
    ALLOW_SQLITE_FALLBACK=1 deliberately opts out (single-machine installs only)."""
    if "unittest" in sys.modules or os.getenv("TESTING") == "1":
        return False
    if os.getenv("ALLOW_SQLITE_FALLBACK", "").strip().lower() in ("1", "true", "yes"):
        return False
    return bool(os.getenv("RENDER")) or os.getenv("ENVIRONMENT", "").strip().lower() == "production"


def init_chat_db():
    """
    Initializes the Chat PostgreSQL database schema on Neon DB.
    Local development falls back to SQLite when no Neon URL is configured or it cannot be reached.
    PRODUCTION NEVER DOES: a local SQLite file on Render is wiped on every deploy / restart, so members'
    messages and payments written there would silently disappear. In production a missing URL, or a
    database that is still unreachable after ~30 s of retries, raises DatabaseUnavailableError so the
    deploy / start fails loudly instead.
    """
    global _pg_pool, _use_sqlite_fallback, _sqlite_conn
    if _use_sqlite_fallback or "unittest" in sys.modules or os.getenv("TESTING") == "1":
        _use_sqlite_fallback = True
        _init_sqlite_engine()
        return
    if is_production():
        url = os.getenv("NEON_DATABASE_URL") or os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL")
        if not url or not _HAS_PSYCOPG2:
            raise DatabaseUnavailableError(
                "Production start refused: set NEON_DATABASE_URL (and install psycopg2). "
                "The app will not run on a temporary local database."
            )
        last_err: Optional[Exception] = None
        for attempt, wait in enumerate((0, 2, 4, 8, 16)):
            if wait:
                time.sleep(wait)
            try:
                _init_chat_db_inner(allow_fallback=False)  # raises instead of touching SQLite
                return
            except Exception as exc:  # a failed pool / connection
                last_err = exc
            try:
                if _pg_pool is not None:
                    _pg_pool.closeall()
            except Exception:
                pass
            _pg_pool = None
            print(f"[WARN] Database not reachable yet (attempt {attempt + 1}/5): {last_err}")
        raise DatabaseUnavailableError(
            f"Production start refused: PostgreSQL is unreachable ({last_err or 'see the warnings above'}). "
            "Check NEON_DATABASE_URL and that the Neon project is running."
        )
    _init_chat_db_inner()


def _init_chat_db_inner(allow_fallback: bool = True):
    global _pg_pool, _use_sqlite_fallback, _sqlite_conn

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
            if not allow_fallback:
                raise
            print(f"[WARN] Neon PostgreSQL connection note ({e}). Falling back to local isolated engine for chat.")
            _use_sqlite_fallback = True
    else:
        if not allow_fallback:
            raise DatabaseUnavailableError("No PostgreSQL URL configured")
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