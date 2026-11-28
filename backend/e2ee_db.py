"""
High-Security End-to-End Encryption (E2EE) Database Layer (Neon PostgreSQL + SQLite Fallback).

Shares the connection pool and SQLite fallback engine from `chat_db.py` while keeping
permanent account identities (`user_id`), wallet authentication bindings, Olm v2
device/prekey state, MLS RFC 9420 group epochs/commits/welcomes, security identity
events, and encrypted file attachments cleanly structured and enforced at the storage layer.
"""

import uuid
import json
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple

import chat_db


import auth_cache
class EpochConflictError(Exception):
    """Raised when an MLS Commit targets a stale group epoch."""

    def __init__(self, current_epoch: int, expected_epoch: int):
        super().__init__(
            f"Group epoch conflict: expected {expected_epoch}, current is {current_epoch}"
        )
        self.current_epoch = current_epoch
        self.expected_epoch = expected_epoch


class DuplicateMessageError(Exception):
    """Raised when a message_id has already been recorded (replay attempt)."""


FORBIDDEN_PLAINTEXT_KEYS = frozenset({
    "plaintext",
    "message",
    "text",
    "body",
    "content",
    "decrypted",
    "private_key",
    "seed_phrase",
    "mnemonic",
    "pickle_key",
})

_e2ee_tables_initialized = False


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now_utc().isoformat()


def coarse_timestamp_iso(dt: Optional[datetime] = None) -> str:
    """
    Buckets message timestamps to 1-minute UTC granularity to minimize
    fine-grained timing correlation metadata while `seq` preserves exact order.
    """
    target = dt or now_utc()
    return target.astimezone(timezone.utc).replace(second=0, microsecond=0).isoformat()


def assert_zero_plaintext(payload: Any, context: str = "payload") -> None:
    """Recursively verifies that no forbidden plaintext or secret key fields exist."""
    if isinstance(payload, dict):
        for k, v in payload.items():
            key_norm = str(k).strip().lower()
            if key_norm in FORBIDDEN_PLAINTEXT_KEYS:
                raise ValueError(
                    f"Security violation: forbidden field '{k}' rejected in {context}"
                )
            assert_zero_plaintext(v, context)
    elif isinstance(payload, list):
        for item in payload:
            assert_zero_plaintext(item, context)


def hash_session_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def make_dm_conversation_id(user_a: str, user_b: str) -> str:
    lo, hi = sorted([user_a.strip(), user_b.strip()])
    digest = hashlib.sha256(f"dm:{lo}:{hi}".encode("utf-8")).hexdigest()[:28]
    return f"conv_{digest}"


def _is_pg() -> bool:
    chat_db._ensure_initialized()
    return bool(chat_db._pg_pool is not None and not chat_db._use_sqlite_fallback)


def ensure_e2ee_tables() -> None:
    """Creates all E2EE tables idempotently on PostgreSQL or SQLite."""
    global _e2ee_tables_initialized
    chat_db._ensure_initialized()

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS chat_users (
                        user_id VARCHAR(64) PRIMARY KEY,
                        username VARCHAR(64) UNIQUE,
                        identity_version INT NOT NULL DEFAULT 1,
                        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_chat_users_username_lower ON chat_users (LOWER(username)) WHERE username IS NOT NULL;

                    CREATE TABLE IF NOT EXISTS chat_user_wallets (
                        wallet_address VARCHAR(42) PRIMARY KEY,
                        user_id VARCHAR(64) NOT NULL REFERENCES chat_users(user_id),
                        is_primary BOOLEAN NOT NULL DEFAULT TRUE,
                        status VARCHAR(24) NOT NULL DEFAULT 'active',
                        linked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        revoked_at TIMESTAMP WITH TIME ZONE
                    );
                    CREATE INDEX IF NOT EXISTS idx_wallets_user ON chat_user_wallets(user_id);

                    CREATE TABLE IF NOT EXISTS chat_auth_challenges (
                        challenge_id VARCHAR(64) PRIMARY KEY,
                        wallet_address VARCHAR(42) NOT NULL,
                        user_id VARCHAR(64),
                        purpose VARCHAR(32) NOT NULL,
                        nonce VARCHAR(64) NOT NULL,
                        message TEXT NOT NULL,
                        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                        consumed BOOLEAN NOT NULL DEFAULT FALSE,
                        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );

                    CREATE TABLE IF NOT EXISTS chat_auth_sessions (
                        session_id VARCHAR(64) PRIMARY KEY,
                        token_hash VARCHAR(64) NOT NULL UNIQUE,
                        user_id VARCHAR(64) NOT NULL REFERENCES chat_users(user_id),
                        wallet_address VARCHAR(42) NOT NULL,
                        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                        revoked BOOLEAN NOT NULL DEFAULT FALSE,
                        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE INDEX IF NOT EXISTS idx_sessions_user ON chat_auth_sessions(user_id);
                    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON chat_auth_sessions(expires_at);

                    CREATE TABLE IF NOT EXISTS chat_devices (
                        device_id VARCHAR(64) PRIMARY KEY,
                        user_id VARCHAR(64) NOT NULL REFERENCES chat_users(user_id),
                        device_label VARCHAR(64) NOT NULL,
                        ed25519_identity_key VARCHAR(128) NOT NULL,
                        curve25519_identity_key VARCHAR(128) NOT NULL,
                        fallback_key_id VARCHAR(64),
                        fallback_public_key VARCHAR(128),
                        bundle_signature VARCHAR(256) NOT NULL,
                        signed_payload TEXT NOT NULL,
                        status VARCHAR(24) NOT NULL DEFAULT 'active',
                        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        revoked_at TIMESTAMP WITH TIME ZONE
                    );
                    CREATE INDEX IF NOT EXISTS idx_devices_user ON chat_devices(user_id, status);

                    CREATE TABLE IF NOT EXISTS chat_one_time_prekeys (
                        prekey_row_id VARCHAR(96) PRIMARY KEY,
                        device_id VARCHAR(64) NOT NULL REFERENCES chat_devices(device_id),
                        user_id VARCHAR(64) NOT NULL,
                        key_id VARCHAR(64) NOT NULL,
                        public_key VARCHAR(128) NOT NULL,
                        consumed BOOLEAN NOT NULL DEFAULT FALSE,
                        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE INDEX IF NOT EXISTS idx_otk_device ON chat_one_time_prekeys(device_id, consumed);

                    CREATE TABLE IF NOT EXISTS chat_mls_key_packages (
                        package_id VARCHAR(64) PRIMARY KEY,
                        device_id VARCHAR(64) NOT NULL REFERENCES chat_devices(device_id),
                        user_id VARCHAR(64) NOT NULL,
                        ciphersuite VARCHAR(96) NOT NULL,
                        key_package_b64 TEXT NOT NULL,
                        key_package_ref VARCHAR(128) NOT NULL,
                        consumed BOOLEAN NOT NULL DEFAULT FALSE,
                        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE INDEX IF NOT EXISTS idx_mlskp_user ON chat_mls_key_packages(user_id, consumed);

                    CREATE TABLE IF NOT EXISTS chat_dm_messages (
                        seq BIGSERIAL PRIMARY KEY,
                        message_id VARCHAR(64) NOT NULL UNIQUE,
                        conversation_id VARCHAR(64) NOT NULL,
                        sender_user_id VARCHAR(64) NOT NULL,
                        sender_device_id VARCHAR(64) NOT NULL,
                        sender_curve25519_key VARCHAR(128) NOT NULL,
                        sender_ed25519_key VARCHAR(128) NOT NULL,
                        recipient_user_id VARCHAR(64) NOT NULL,
                        protocol VARCHAR(64) NOT NULL,
                        ciphertexts_json JSONB NOT NULL,
                        attachment_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
                        created_bucket VARCHAR(40) NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_dm_conv_seq ON chat_dm_messages(conversation_id, seq ASC);
                    -- The sidebar lists DM conversations by sender OR recipient on every sync; both sides need an index.
                    CREATE INDEX IF NOT EXISTS idx_dm_sender_seq ON chat_dm_messages(sender_user_id, seq);
                    CREATE INDEX IF NOT EXISTS idx_dm_recipient_seq ON chat_dm_messages(recipient_user_id, seq);

                    CREATE TABLE IF NOT EXISTS chat_groups (
                        group_id VARCHAR(64) PRIMARY KEY,
                        mls_group_id_b64 VARCHAR(128) NOT NULL UNIQUE,
                        name VARCHAR(96) NOT NULL,
                        creator_user_id VARCHAR(64) NOT NULL,
                        current_epoch INT NOT NULL DEFAULT 0,
                        ciphersuite VARCHAR(96) NOT NULL,
                        history_sharing_mode VARCHAR(32) NOT NULL DEFAULT 'none',
                        created_bucket VARCHAR(40) NOT NULL,
                        updated_bucket VARCHAR(40) NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS chat_group_members (
                        group_id VARCHAR(64) NOT NULL REFERENCES chat_groups(group_id),
                        user_id VARCHAR(64) NOT NULL REFERENCES chat_users(user_id),
                        device_id VARCHAR(64) NOT NULL,
                        role VARCHAR(24) NOT NULL DEFAULT 'member',
                        leaf_index INT,
                        status VARCHAR(24) NOT NULL DEFAULT 'active',
                        joined_epoch INT NOT NULL DEFAULT 0,
                        removed_epoch INT,
                        updated_bucket VARCHAR(40) NOT NULL,
                        PRIMARY KEY (group_id, user_id, device_id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_gm_user ON chat_group_members(user_id, status);

                    CREATE TABLE IF NOT EXISTS chat_group_commits (
                        seq BIGSERIAL PRIMARY KEY,
                        commit_id VARCHAR(64) NOT NULL UNIQUE,
                        group_id VARCHAR(64) NOT NULL REFERENCES chat_groups(group_id),
                        epoch INT NOT NULL,
                        committer_user_id VARCHAR(64) NOT NULL,
                        committer_device_id VARCHAR(64) NOT NULL,
                        commit_type VARCHAR(32) NOT NULL,
                        mls_commit_b64 TEXT NOT NULL,
                        ratchet_tree_b64 TEXT,
                        created_bucket VARCHAR(40) NOT NULL,
                        UNIQUE (group_id, epoch)
                    );

                    CREATE TABLE IF NOT EXISTS chat_group_welcomes (
                        welcome_id VARCHAR(64) PRIMARY KEY,
                        group_id VARCHAR(64) NOT NULL REFERENCES chat_groups(group_id),
                        epoch INT NOT NULL,
                        target_user_id VARCHAR(64) NOT NULL,
                        target_device_id VARCHAR(64) NOT NULL,
                        mls_welcome_b64 TEXT NOT NULL,
                        ratchet_tree_b64 TEXT,
                        consumed BOOLEAN NOT NULL DEFAULT FALSE,
                        created_bucket VARCHAR(40) NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_gw_target ON chat_group_welcomes(target_user_id, target_device_id, consumed);

                    CREATE TABLE IF NOT EXISTS chat_group_messages (
                        seq BIGSERIAL PRIMARY KEY,
                        message_id VARCHAR(64) NOT NULL UNIQUE,
                        group_id VARCHAR(64) NOT NULL REFERENCES chat_groups(group_id),
                        epoch INT NOT NULL,
                        sender_user_id VARCHAR(64) NOT NULL,
                        sender_device_id VARCHAR(64) NOT NULL,
                        mls_ciphertext_b64 TEXT NOT NULL,
                        attachment_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
                        created_bucket VARCHAR(40) NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_gmsg_group_seq ON chat_group_messages(group_id, seq ASC);

                    CREATE TABLE IF NOT EXISTS chat_identity_events (
                        seq BIGSERIAL PRIMARY KEY,
                        event_id VARCHAR(64) NOT NULL UNIQUE,
                        user_id VARCHAR(64) NOT NULL,
                        event_type VARCHAR(48) NOT NULL,
                        device_id VARCHAR(64),
                        identity_version INT NOT NULL DEFAULT 1,
                        details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                        created_bucket VARCHAR(40) NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_idev_user ON chat_identity_events(user_id, seq DESC);

                    CREATE TABLE IF NOT EXISTS chat_encrypted_attachments (
                        attachment_id VARCHAR(64) PRIMARY KEY,
                        scope_type VARCHAR(16) NOT NULL,
                        scope_id VARCHAR(64) NOT NULL,
                        uploader_user_id VARCHAR(64) NOT NULL,
                        uploader_device_id VARCHAR(64) NOT NULL,
                        algorithm VARCHAR(48) NOT NULL,
                        ciphertext_b64 TEXT NOT NULL,
                        ciphertext_sha256 VARCHAR(64) NOT NULL,
                        byte_length INT NOT NULL,
                        revoked BOOLEAN NOT NULL DEFAULT FALSE,
                        created_bucket VARCHAR(40) NOT NULL
                    );
                """)
                # Chat features (reactions/edits as encrypted events, delete for everyone, disappearing messages):
                # event_kind 'message' | 'control' (control = an encrypted reaction / edit / poll vote: never unread,
                # never notified); deleted_at = deleted for everyone; expires_at = disappearing-message deadline.
                for _tbl in ("chat_dm_messages", "chat_group_messages"):
                    cur.execute(f"ALTER TABLE {_tbl} ADD COLUMN IF NOT EXISTS event_kind VARCHAR(16) NOT NULL DEFAULT 'message';")
                    cur.execute(f"ALTER TABLE {_tbl} ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP WITH TIME ZONE;")
                    cur.execute(f"ALTER TABLE {_tbl} ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP WITH TIME ZONE;")
                    cur.execute(f"CREATE INDEX IF NOT EXISTS idx_{_tbl}_expires ON {_tbl}(expires_at) WHERE expires_at IS NOT NULL;")
            conn.commit()
            _e2ee_tables_initialized = True
        finally:
            chat_db._pg_pool.putconn(conn)
        import platform_db
        platform_db._platform_tables_initialized = False
        platform_db.ensure_platform_tables()
        return

    with chat_db._sqlite_lock:
        if chat_db._sqlite_conn is None:
            chat_db._init_sqlite_engine()
        cur = chat_db._sqlite_conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS chat_users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE,
                identity_version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_chat_users_username_lower ON chat_users (LOWER(username)) WHERE username IS NOT NULL;

            CREATE TABLE IF NOT EXISTS chat_user_wallets (
                wallet_address TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                is_primary INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'active',
                linked_at TEXT NOT NULL,
                revoked_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_wallets_user ON chat_user_wallets(user_id);

            CREATE TABLE IF NOT EXISTS chat_auth_challenges (
                challenge_id TEXT PRIMARY KEY,
                wallet_address TEXT NOT NULL,
                user_id TEXT,
                purpose TEXT NOT NULL,
                nonce TEXT NOT NULL,
                message TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chat_auth_sessions (
                session_id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                user_id TEXT NOT NULL,
                wallet_address TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON chat_auth_sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_expires ON chat_auth_sessions(expires_at);

            CREATE TABLE IF NOT EXISTS chat_devices (
                device_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                device_label TEXT NOT NULL,
                ed25519_identity_key TEXT NOT NULL,
                curve25519_identity_key TEXT NOT NULL,
                fallback_key_id TEXT,
                fallback_public_key TEXT,
                bundle_signature TEXT NOT NULL,
                signed_payload TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                revoked_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_devices_user ON chat_devices(user_id, status);

            CREATE TABLE IF NOT EXISTS chat_one_time_prekeys (
                prekey_row_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                key_id TEXT NOT NULL,
                public_key TEXT NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_otk_device ON chat_one_time_prekeys(device_id, consumed);

            CREATE TABLE IF NOT EXISTS chat_mls_key_packages (
                package_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                ciphersuite TEXT NOT NULL,
                key_package_b64 TEXT NOT NULL,
                key_package_ref TEXT NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_mlskp_user ON chat_mls_key_packages(user_id, consumed);

            CREATE TABLE IF NOT EXISTS chat_dm_messages (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL UNIQUE,
                conversation_id TEXT NOT NULL,
                sender_user_id TEXT NOT NULL,
                sender_device_id TEXT NOT NULL,
                sender_curve25519_key TEXT NOT NULL,
                sender_ed25519_key TEXT NOT NULL,
                recipient_user_id TEXT NOT NULL,
                protocol TEXT NOT NULL,
                ciphertexts_json TEXT NOT NULL,
                attachment_ids_json TEXT NOT NULL DEFAULT '[]',
                created_bucket TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_dm_conv_seq ON chat_dm_messages(conversation_id, seq ASC);
            -- The sidebar lists DM conversations by sender OR recipient on every sync; both sides need an index.
            CREATE INDEX IF NOT EXISTS idx_dm_sender_seq ON chat_dm_messages(sender_user_id, seq);
            CREATE INDEX IF NOT EXISTS idx_dm_recipient_seq ON chat_dm_messages(recipient_user_id, seq);

            CREATE TABLE IF NOT EXISTS chat_groups (
                group_id TEXT PRIMARY KEY,
                mls_group_id_b64 TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                creator_user_id TEXT NOT NULL,
                current_epoch INTEGER NOT NULL DEFAULT 0,
                ciphersuite TEXT NOT NULL,
                history_sharing_mode TEXT NOT NULL DEFAULT 'none',
                created_bucket TEXT NOT NULL,
                updated_bucket TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chat_group_members (
                group_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                leaf_index INTEGER,
                status TEXT NOT NULL DEFAULT 'active',
                joined_epoch INTEGER NOT NULL DEFAULT 0,
                removed_epoch INTEGER,
                updated_bucket TEXT NOT NULL,
                PRIMARY KEY (group_id, user_id, device_id)
            );
            CREATE INDEX IF NOT EXISTS idx_gm_user ON chat_group_members(user_id, status);

            CREATE TABLE IF NOT EXISTS chat_group_commits (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                commit_id TEXT NOT NULL UNIQUE,
                group_id TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                committer_user_id TEXT NOT NULL,
                committer_device_id TEXT NOT NULL,
                commit_type TEXT NOT NULL,
                mls_commit_b64 TEXT NOT NULL,
                ratchet_tree_b64 TEXT,
                created_bucket TEXT NOT NULL,
                UNIQUE (group_id, epoch)
            );

            CREATE TABLE IF NOT EXISTS chat_group_welcomes (
                welcome_id TEXT PRIMARY KEY,
                group_id TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                target_user_id TEXT NOT NULL,
                target_device_id TEXT NOT NULL,
                mls_welcome_b64 TEXT NOT NULL,
                ratchet_tree_b64 TEXT,
                consumed INTEGER NOT NULL DEFAULT 0,
                created_bucket TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_gw_target ON chat_group_welcomes(target_user_id, target_device_id, consumed);

            CREATE TABLE IF NOT EXISTS chat_group_messages (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL UNIQUE,
                group_id TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                sender_user_id TEXT NOT NULL,
                sender_device_id TEXT NOT NULL,
                mls_ciphertext_b64 TEXT NOT NULL,
                attachment_ids_json TEXT NOT NULL DEFAULT '[]',
                created_bucket TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_gmsg_group_seq ON chat_group_messages(group_id, seq ASC);

            CREATE TABLE IF NOT EXISTS chat_identity_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                user_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                device_id TEXT,
                identity_version INTEGER NOT NULL DEFAULT 1,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_bucket TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_idev_user ON chat_identity_events(user_id, seq DESC);

            CREATE TABLE IF NOT EXISTS chat_encrypted_attachments (
                attachment_id TEXT PRIMARY KEY,
                scope_type TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                uploader_user_id TEXT NOT NULL,
                uploader_device_id TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                ciphertext_b64 TEXT NOT NULL,
                ciphertext_sha256 TEXT NOT NULL,
                byte_length INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_bucket TEXT NOT NULL
            );
        """)
        for _tbl in ("chat_dm_messages", "chat_group_messages"):
            for _col in ("event_kind TEXT NOT NULL DEFAULT 'message'", "deleted_at TEXT", "expires_at TEXT"):
                try:
                    cur.execute(f"ALTER TABLE {_tbl} ADD COLUMN {_col}")
                except Exception:
                    pass  # already there
        chat_db._sqlite_conn.commit()
        _e2ee_tables_initialized = True

    import platform_db
    platform_db._platform_tables_initialized = False
    platform_db.ensure_platform_tables()


def _ready() -> None:
    if not _e2ee_tables_initialized:
        ensure_e2ee_tables()


def _parse_json(val: Any, default: Any) -> Any:
    if val is None:
        return default
    if isinstance(val, (dict, list)):
        return val
    try:
        return json.loads(val)
    except Exception:
        return default


def _iso_str(val: Any) -> Optional[str]:
    if val is None:
        return None
    if hasattr(val, "isoformat"):
        return val.isoformat()
    return str(val)


# ============================================================================
# 1. AUTH CHALLENGES, PERMANENT USERS, WALLETS, & SESSIONS
# ============================================================================

def create_auth_challenge(
    wallet_address: str,
    purpose: str,
    nonce: str,
    message: str,
    expires_at: str,
    user_id: Optional[str] = None,
) -> Dict[str, Any]:
    _ready()
    challenge_id = f"echal_{secrets.token_hex(16)}"
    created_at = now_iso()

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO chat_auth_challenges (
                        challenge_id, wallet_address, user_id, purpose,
                        nonce, message, expires_at, consumed, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, FALSE, %s);
                    """,
                    (challenge_id, wallet_address, user_id, purpose, nonce, message, expires_at, created_at),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                INSERT INTO chat_auth_challenges (
                    challenge_id, wallet_address, user_id, purpose,
                    nonce, message, expires_at, consumed, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (challenge_id, wallet_address, user_id, purpose, nonce, message, expires_at, created_at),
            )
            chat_db._sqlite_conn.commit()

    return {
        "challenge_id": challenge_id,
        "wallet_address": wallet_address,
        "user_id": user_id,
        "purpose": purpose,
        "nonce": nonce,
        "message": message,
        "expires_at": expires_at,
    }


def consume_auth_challenge_atomic(challenge_id: str) -> Optional[Dict[str, Any]]:
    """
    Atomically fetches and marks an auth challenge consumed if and only if
    it exists and has not yet been consumed. Prevents concurrent replay.
    """
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    UPDATE chat_auth_challenges
                    SET consumed = TRUE
                    WHERE challenge_id = %s AND consumed = FALSE
                    RETURNING challenge_id, wallet_address, user_id, purpose, nonce, message, expires_at;
                    """,
                    (challenge_id,),
                )
                row = cur.fetchone()
            conn.commit()
            if not row:
                return None
            return {
                "challenge_id": row["challenge_id"],
                "wallet_address": row["wallet_address"],
                "user_id": row["user_id"],
                "purpose": row["purpose"],
                "nonce": row["nonce"],
                "message": row["message"],
                "expires_at": _iso_str(row["expires_at"]),
            }
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            """
            SELECT challenge_id, wallet_address, user_id, purpose, nonce, message, expires_at, consumed
            FROM chat_auth_challenges
            WHERE challenge_id = ?
            """,
            (challenge_id,),
        )
        row = cur.fetchone()
        if not row or bool(row["consumed"]):
            return None
        cur.execute(
            "UPDATE chat_auth_challenges SET consumed = 1 WHERE challenge_id = ? AND consumed = 0",
            (challenge_id,),
        )
        if cur.rowcount != 1:
            chat_db._sqlite_conn.rollback()
            return None
        chat_db._sqlite_conn.commit()
        return {
            "challenge_id": row["challenge_id"],
            "wallet_address": row["wallet_address"],
            "user_id": row["user_id"],
            "purpose": row["purpose"],
            "nonce": row["nonce"],
            "message": row["message"],
            "expires_at": _iso_str(row["expires_at"]),
        }


@auth_cache.invalidates_auth_cache
def get_or_create_user_for_wallet(wallet_address: str) -> Tuple[Dict[str, Any], bool]:
    """
    Resolves an active wallet binding to its permanent `user_id`, or creates a
    brand-new permanent UUID-anchored `user_id` if this wallet has never been linked.
    """
    _ready()
    existing_user = get_user_by_wallet(wallet_address)
    if existing_user:
        return existing_user, False

    user_id = f"usr_{uuid.uuid4().hex}"
    ts = now_iso()

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO chat_users (user_id, username, identity_version, created_at, updated_at)
                    VALUES (%s, NULL, 1, %s, %s);
                    """,
                    (user_id, ts, ts),
                )
                cur.execute(
                    """
                    INSERT INTO chat_user_wallets (wallet_address, user_id, is_primary, status, linked_at, revoked_at)
                    VALUES (%s, %s, TRUE, 'active', %s, NULL)
                    ON CONFLICT (wallet_address) DO UPDATE SET
                        user_id = EXCLUDED.user_id,
                        is_primary = TRUE,
                        status = 'active',
                        linked_at = EXCLUDED.linked_at,
                        revoked_at = NULL;
                    """,
                    (wallet_address, user_id, ts),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                INSERT INTO chat_users (user_id, username, identity_version, created_at, updated_at)
                VALUES (?, NULL, 1, ?, ?)
                """,
                (user_id, ts, ts),
            )
            cur.execute(
                """
                INSERT INTO chat_user_wallets (wallet_address, user_id, is_primary, status, linked_at, revoked_at)
                VALUES (?, ?, 1, 'active', ?, NULL)
                ON CONFLICT(wallet_address) DO UPDATE SET
                    user_id = excluded.user_id,
                    is_primary = 1,
                    status = 'active',
                    linked_at = excluded.linked_at,
                    revoked_at = NULL
                """,
                (wallet_address, user_id, ts),
            )
            chat_db._sqlite_conn.commit()

    import platform_db
    platform_db.record_wallet_change_and_revoke_old_sessions(
        user_id=user_id,
        action="initial_wallet_linked",
        old_wallet=None,
        new_wallet=wallet_address,
        performed_by=user_id,
        revoke_previous_sessions=False,
    )
    return get_user_by_id(user_id), True  # type: ignore[return-value]


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    cached = auth_cache.get("user", user_id)
    if cached is not None:
        return cached
    gen = auth_cache.generation()
    doc = _get_user_by_id_uncached(user_id)
    if doc:
        auth_cache.put("user", user_id, doc, gen)
    return doc


def _get_user_by_id_uncached(user_id: str) -> Optional[Dict[str, Any]]:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT user_id, username, identity_version, created_at, updated_at
                    FROM chat_users WHERE user_id = %s;
                    """,
                    (user_id,),
                )
                row = cur.fetchone()
                if not row:
                    return None
                cur.execute(
                    """
                    SELECT wallet_address, is_primary, status, linked_at
                    FROM chat_user_wallets
                    WHERE user_id = %s AND status = 'active'
                    ORDER BY is_primary DESC, linked_at ASC;
                    """,
                    (user_id,),
                )
                wallets = [
                    {
                        "wallet_address": w["wallet_address"],
                        "is_primary": bool(w["is_primary"]),
                        "status": w["status"],
                        "linked_at": _iso_str(w["linked_at"]),
                    }
                    for w in cur.fetchall()
                ]
                base_doc = {
                    "user_id": row["user_id"],
                    "username": row["username"],
                    "identity_version": int(row["identity_version"]),
                    "wallets": wallets,
                    "primary_wallet": wallets[0]["wallet_address"] if wallets else None,
                    "created_at": _iso_str(row["created_at"]),
                    "updated_at": _iso_str(row["updated_at"]),
                }
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                SELECT user_id, username, identity_version, created_at, updated_at
                FROM chat_users WHERE user_id = ?
                """,
                (user_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            cur.execute(
                """
                SELECT wallet_address, is_primary, status, linked_at
                FROM chat_user_wallets
                WHERE user_id = ? AND status = 'active'
                ORDER BY is_primary DESC, linked_at ASC
                """,
                (user_id,),
            )
            wallets = [
                {
                    "wallet_address": w["wallet_address"],
                    "is_primary": bool(w["is_primary"]),
                    "status": w["status"],
                    "linked_at": _iso_str(w["linked_at"]),
                }
                for w in cur.fetchall()
            ]
            base_doc = {
                "user_id": row["user_id"],
                "username": row["username"],
                "identity_version": int(row["identity_version"]),
                "wallets": wallets,
                "primary_wallet": wallets[0]["wallet_address"] if wallets else None,
                "created_at": _iso_str(row["created_at"]),
                "updated_at": _iso_str(row["updated_at"]),
            }

    import platform_db
    ext = platform_db.get_extended_user_fields(user_id)
    return {**base_doc, **ext}


def get_user_by_wallet(wallet_address: str) -> Optional[Dict[str, Any]]:
    _ready()
    target_user_id: Optional[str] = None
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT user_id FROM chat_user_wallets
                    WHERE LOWER(wallet_address) = LOWER(%s) AND status = 'active';
                    """,
                    (wallet_address,),
                )
                row = cur.fetchone()
                if row:
                    target_user_id = row[0]
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                SELECT user_id FROM chat_user_wallets
                WHERE LOWER(wallet_address) = LOWER(?) AND status = 'active'
                """,
                (wallet_address,),
            )
            row = cur.fetchone()
            if row:
                target_user_id = row["user_id"]

    if not target_user_id:
        return None
    return get_user_by_id(target_user_id)


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    _ready()
    target_user_id: Optional[str] = None
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT user_id FROM chat_users WHERE LOWER(username) = LOWER(%s);",
                    (username.strip(),),
                )
                row = cur.fetchone()
                if row:
                    target_user_id = row[0]
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                "SELECT user_id FROM chat_users WHERE LOWER(username) = LOWER(?)",
                (username.strip(),),
            )
            row = cur.fetchone()
            if row:
                target_user_id = row["user_id"]

    if not target_user_id:
        return None
    return get_user_by_id(target_user_id)


def resolve_peer_identifier(identifier: str) -> Optional[Dict[str, Any]]:
    """Resolves `usr_...`, `0x...` wallet address, or `@username`/`username` to user doc."""
    ident = identifier.strip()
    if not ident:
        return None
    if ident.startswith("@"):
        ident = ident[1:]
    if ident.startswith("usr_"):
        return get_user_by_id(ident)
    if ident.startswith("0x") and len(ident) == 42:
        return get_user_by_wallet(ident)
    return get_user_by_username(ident)


@auth_cache.invalidates_auth_cache
def update_username(user_id: str, new_username: str) -> Dict[str, Any]:
    """Updates username while keeping `user_id` and encryption keys completely untouched."""
    _ready()
    existing = get_user_by_username(new_username)
    if existing and existing["user_id"] != user_id:
        raise ValueError("Username is already claimed by another account")

    ts = now_iso()
    try:
        if _is_pg():
            conn = chat_db._pg_pool.getconn()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE chat_users SET username = %s, updated_at = %s WHERE user_id = %s;",
                        (new_username, ts, user_id),
                    )
                conn.commit()
            finally:
                chat_db._pg_pool.putconn(conn)
        else:
            with chat_db._sqlite_lock:
                cur = chat_db._sqlite_conn.cursor()
                cur.execute(
                    "UPDATE chat_users SET username = ?, updated_at = ? WHERE user_id = ?",
                    (new_username, ts, user_id),
                )
                chat_db._sqlite_conn.commit()
    except Exception as exc:
        err_msg = str(exc).lower()
        if "unique" in err_msg or "integrity" in err_msg or "idx_chat_users_username" in err_msg:
            raise ValueError("Username is already claimed by another account")
        raise
    return get_user_by_id(user_id)  # type: ignore[return-value]


@auth_cache.invalidates_auth_cache
def link_wallet_to_user(
    user_id: str,
    new_wallet_address: str,
    make_primary: bool = True,
    revoke_previous_wallets: bool = False,
) -> Dict[str, Any]:
    """
    Links a verified new wallet to an existing permanent `user_id` without altering
    or invalidating the user's cryptographic device identities or message history.
    Rejects if `new_wallet_address` is already bound to a different `user_id`.
    """
    _ready()
    owner = get_user_by_wallet(new_wallet_address)
    if owner and owner["user_id"] != user_id:
        raise ValueError("Wallet address is already linked to a different user account")

    ts = now_iso()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                if revoke_previous_wallets:
                    cur.execute(
                        """
                        UPDATE chat_user_wallets
                        SET status = 'revoked', is_primary = FALSE, revoked_at = %s
                        WHERE user_id = %s AND LOWER(wallet_address) != LOWER(%s);
                        """,
                        (ts, user_id, new_wallet_address),
                    )
                elif make_primary:
                    cur.execute(
                        "UPDATE chat_user_wallets SET is_primary = FALSE WHERE user_id = %s;",
                        (user_id,),
                    )
                cur.execute(
                    """
                    INSERT INTO chat_user_wallets (wallet_address, user_id, is_primary, status, linked_at, revoked_at)
                    VALUES (%s, %s, %s, 'active', %s, NULL)
                    ON CONFLICT (wallet_address) DO UPDATE SET
                        user_id = EXCLUDED.user_id,
                        is_primary = EXCLUDED.is_primary,
                        status = 'active',
                        revoked_at = NULL;
                    """,
                    (new_wallet_address, user_id, make_primary, ts),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            if revoke_previous_wallets:
                cur.execute(
                    """
                    UPDATE chat_user_wallets
                    SET status = 'revoked', is_primary = 0, revoked_at = ?
                    WHERE user_id = ? AND LOWER(wallet_address) != LOWER(?)
                    """,
                    (ts, user_id, new_wallet_address),
                )
            elif make_primary:
                cur.execute(
                    "UPDATE chat_user_wallets SET is_primary = 0 WHERE user_id = ?",
                    (user_id,),
                )
            cur.execute(
                """
                INSERT INTO chat_user_wallets (wallet_address, user_id, is_primary, status, linked_at, revoked_at)
                VALUES (?, ?, ?, 'active', ?, NULL)
                ON CONFLICT(wallet_address) DO UPDATE SET
                    user_id = excluded.user_id,
                    is_primary = excluded.is_primary,
                    status = 'active',
                    revoked_at = NULL
                """,
                (new_wallet_address, user_id, 1 if make_primary else 0, ts),
            )
            chat_db._sqlite_conn.commit()

    return get_user_by_id(user_id)  # type: ignore[return-value]


# ---- Session housekeeping -------------------------------------------------------------------------
# Every sign-in adds a session row. Without limits the table only grew, and a person who signed in
# again and again without signing out kept every old token valid for 24 hours.
MAX_ACTIVE_SESSIONS_PER_USER = 10   # signing in beyond this signs out the OLDEST sessions
SESSION_KEEP_DAYS = 7               # expired / signed-out sessions are deleted after this many days
_SESSION_PURGE_EVERY_SECS = 3600.0
_last_session_purge = 0.0


def _cap_user_sessions(user_id: str, max_active: int = MAX_ACTIVE_SESSIONS_PER_USER) -> None:
    """Signs out this user's oldest live sessions beyond `max_active` (the newest ones are kept)."""
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE chat_auth_sessions SET revoked = TRUE
                    WHERE session_id IN (
                        SELECT session_id FROM chat_auth_sessions
                        WHERE user_id = %s AND revoked = FALSE AND expires_at > CURRENT_TIMESTAMP
                        ORDER BY created_at DESC, session_id DESC
                        OFFSET %s
                    );
                    """,
                    (user_id, max_active),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                UPDATE chat_auth_sessions SET revoked = 1
                WHERE session_id IN (
                    SELECT session_id FROM chat_auth_sessions
                    WHERE user_id = ? AND revoked = 0 AND expires_at > ?
                    ORDER BY created_at DESC, session_id DESC
                    LIMIT -1 OFFSET ?
                )
                """,
                (user_id, now_iso(), max_active),
            )
            chat_db._sqlite_conn.commit()


def purge_stale_auth_sessions(keep_days: int = SESSION_KEEP_DAYS) -> int:
    """Deletes sessions that expired more than `keep_days` ago, and signed-out ones older than that.
    Returns how many rows were removed."""
    _ready()
    from datetime import timedelta as _td

    cutoff = (now_utc() - _td(days=keep_days)).isoformat()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM chat_auth_sessions WHERE expires_at < %s OR (revoked = TRUE AND created_at < %s);",
                    (cutoff, cutoff),
                )
                removed = cur.rowcount
            conn.commit()
            return int(removed or 0)
        finally:
            chat_db._pg_pool.putconn(conn)
    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            "DELETE FROM chat_auth_sessions WHERE expires_at < ? OR (revoked = 1 AND created_at < ?)",
            (cutoff, cutoff),
        )
        chat_db._sqlite_conn.commit()
        return int(cur.rowcount or 0)


def _housekeep_sessions_after_login(user_id: str) -> None:
    """Runs after every sign-in. Never lets a housekeeping problem block a login."""
    import logging
    import time as _time

    global _last_session_purge
    try:
        _cap_user_sessions(user_id)
        if _time.monotonic() - _last_session_purge > _SESSION_PURGE_EVERY_SECS:
            _last_session_purge = _time.monotonic()
            purge_stale_auth_sessions()
    except Exception as exc:  # pragma: no cover - defensive
        logging.getLogger(__name__).warning("Session housekeeping skipped: %s", exc)


def create_auth_session(user_id: str, wallet_address: str, expires_at: str) -> Tuple[str, Dict[str, Any]]:
    """Creates an opaque random session token; stores only its SHA-256 hash."""
    _ready()
    raw_token = f"zys_{secrets.token_urlsafe(32)}"
    token_hash = hash_session_token(raw_token)
    session_id = f"sess_{secrets.token_hex(12)}"
    created_at = now_iso()

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO chat_auth_sessions (
                        session_id, token_hash, user_id, wallet_address, expires_at, revoked, created_at
                    ) VALUES (%s, %s, %s, %s, %s, FALSE, %s);
                    """,
                    (session_id, token_hash, user_id, wallet_address, expires_at, created_at),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                INSERT INTO chat_auth_sessions (
                    session_id, token_hash, user_id, wallet_address, expires_at, revoked, created_at
                ) VALUES (?, ?, ?, ?, ?, 0, ?)
                """,
                (session_id, token_hash, user_id, wallet_address, expires_at, created_at),
            )
            chat_db._sqlite_conn.commit()

    _housekeep_sessions_after_login(user_id)
    return raw_token, {
        "session_id": session_id,
        "user_id": user_id,
        "wallet_address": wallet_address,
        "expires_at": expires_at,
    }


def get_session_by_token(raw_token: str) -> Optional[Dict[str, Any]]:
    """Resolve a session token. The SIWE signature was verified once at login; this is
    only a row lookup, so successful results are cached for a few seconds (see auth_cache)."""
    if not raw_token:
        return None
    token_hash = hash_session_token(raw_token.strip())
    cached = auth_cache.get("session", token_hash)
    if cached is not None:
        try:
            if datetime.fromisoformat(str(cached["expires_at"]).replace("Z", "+00:00")) > now_utc():
                return cached
        except Exception:
            pass
        return _get_session_by_token_uncached(raw_token)  # expired/odd entry -> authoritative read
    gen = auth_cache.generation()
    sess = _get_session_by_token_uncached(raw_token)
    if sess:
        auth_cache.put("session", token_hash, sess, gen)
    return sess


def _get_session_by_token_uncached(raw_token: str) -> Optional[Dict[str, Any]]:
    _ready()
    if not raw_token:
        return None
    token_hash = hash_session_token(raw_token.strip())

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT session_id, user_id, wallet_address, expires_at, revoked
                    FROM chat_auth_sessions
                    WHERE token_hash = %s;
                    """,
                    (token_hash,),
                )
                row = cur.fetchone()
                if not row or bool(row["revoked"]):
                    return None
                exp_str = _iso_str(row["expires_at"]) or ""
                exp_dt = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                if exp_dt <= now_utc():
                    return None
                return {
                    "session_id": row["session_id"],
                    "user_id": row["user_id"],
                    "wallet_address": row["wallet_address"],
                    "expires_at": exp_str,
                }
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            """
            SELECT session_id, user_id, wallet_address, expires_at, revoked
            FROM chat_auth_sessions
            WHERE token_hash = ?
            """,
            (token_hash,),
        )
        row = cur.fetchone()
        if not row or bool(row["revoked"]):
            return None
        exp_str = str(row["expires_at"])
        exp_dt = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
        if exp_dt <= now_utc():
            return None
        return {
            "session_id": row["session_id"],
            "user_id": row["user_id"],
            "wallet_address": row["wallet_address"],
            "expires_at": exp_str,
        }


@auth_cache.invalidates_auth_cache
def revoke_session_token(raw_token: str) -> None:
    _ready()
    if not raw_token:
        return
    token_hash = hash_session_token(raw_token.strip())
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE chat_auth_sessions SET revoked = TRUE WHERE token_hash = %s;",
                    (token_hash,),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                "UPDATE chat_auth_sessions SET revoked = 1 WHERE token_hash = ?",
                (token_hash,),
            )
            chat_db._sqlite_conn.commit()


# ============================================================================
# 2. IDENTITY EVENTS (SECURITY-RELEVANT NOTIFICATIONS)
# ============================================================================

def record_identity_event(
    user_id: str,
    event_type: str,
    device_id: Optional[str] = None,
    identity_version: int = 1,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    _ready()
    event_id = f"ievt_{secrets.token_hex(12)}"
    bucket = coarse_timestamp_iso()
    details_safe = details or {}
    assert_zero_plaintext(details_safe, "identity_event_details")

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO chat_identity_events (
                        event_id, user_id, event_type, device_id,
                        identity_version, details_json, created_bucket
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING seq;
                    """,
                    (
                        event_id,
                        user_id,
                        event_type,
                        device_id,
                        identity_version,
                        json.dumps(details_safe),
                        bucket,
                    ),
                )
                seq = cur.fetchone()[0]
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                INSERT INTO chat_identity_events (
                    event_id, user_id, event_type, device_id,
                    identity_version, details_json, created_bucket
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    user_id,
                    event_type,
                    device_id,
                    identity_version,
                    json.dumps(details_safe),
                    bucket,
                ),
            )
            seq = cur.lastrowid
            chat_db._sqlite_conn.commit()

    return {
        "seq": int(seq or 0),
        "event_id": event_id,
        "user_id": user_id,
        "event_type": event_type,
        "device_id": device_id,
        "identity_version": identity_version,
        "details": details_safe,
        "timestamp": bucket,
    }


def list_identity_events_for_users(user_ids: List[str], after_seq: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
    _ready()
    clean_ids = [u for u in dict.fromkeys(user_ids) if u]
    if not clean_ids:
        return []
    bounded = max(1, min(limit, 100))

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT seq, event_id, user_id, event_type, device_id,
                           identity_version, details_json, created_bucket
                    FROM chat_identity_events
                    WHERE user_id = ANY(%s) AND seq > %s
                    ORDER BY seq ASC
                    LIMIT %s;
                    """,
                    (clean_ids, after_seq, bounded),
                )
                return [
                    {
                        "seq": int(r["seq"]),
                        "event_id": r["event_id"],
                        "user_id": r["user_id"],
                        "event_type": r["event_type"],
                        "device_id": r["device_id"],
                        "identity_version": int(r["identity_version"]),
                        "details": _parse_json(r["details_json"], {}),
                        "timestamp": r["created_bucket"],
                    }
                    for r in cur.fetchall()
                ]
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        placeholders = ",".join("?" for _ in clean_ids)
        cur.execute(
            f"""
            SELECT seq, event_id, user_id, event_type, device_id,
                   identity_version, details_json, created_bucket
            FROM chat_identity_events
            WHERE user_id IN ({placeholders}) AND seq > ?
            ORDER BY seq ASC
            LIMIT ?
            """,
            [*clean_ids, after_seq, bounded],
        )
        return [
            {
                "seq": int(r["seq"]),
                "event_id": r["event_id"],
                "user_id": r["user_id"],
                "event_type": r["event_type"],
                "device_id": r["device_id"],
                "identity_version": int(r["identity_version"]),
                "details": _parse_json(r["details_json"], {}),
                "timestamp": r["created_bucket"],
            }
            for r in cur.fetchall()
        ]


# ============================================================================
# 3. DEVICES, OLM ONE-TIME PREKEYS, & MLS KEYPACKAGES
# ============================================================================

@auth_cache.read_cached("device")
def get_device(device_id: str) -> Optional[Dict[str, Any]]:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT device_id, user_id, device_label, ed25519_identity_key,
                           curve25519_identity_key, fallback_key_id, fallback_public_key,
                           bundle_signature, signed_payload, status, created_at, updated_at, revoked_at
                    FROM chat_devices WHERE device_id = %s;
                    """,
                    (device_id,),
                )
                r = cur.fetchone()
                if not r:
                    return None
                return dict(
                    device_id=r["device_id"],
                    user_id=r["user_id"],
                    device_label=r["device_label"],
                    ed25519_identity_key=r["ed25519_identity_key"],
                    curve25519_identity_key=r["curve25519_identity_key"],
                    fallback_key_id=r["fallback_key_id"],
                    fallback_public_key=r["fallback_public_key"],
                    bundle_signature=r["bundle_signature"],
                    signed_payload=r["signed_payload"],
                    status=r["status"],
                    created_at=_iso_str(r["created_at"]),
                    updated_at=_iso_str(r["updated_at"]),
                    revoked_at=_iso_str(r["revoked_at"]),
                )
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            """
            SELECT device_id, user_id, device_label, ed25519_identity_key,
                   curve25519_identity_key, fallback_key_id, fallback_public_key,
                   bundle_signature, signed_payload, status, created_at, updated_at, revoked_at
            FROM chat_devices WHERE device_id = ?
            """,
            (device_id,),
        )
        r = cur.fetchone()
        if not r:
            return None
        return dict(
            device_id=r["device_id"],
            user_id=r["user_id"],
            device_label=r["device_label"],
            ed25519_identity_key=r["ed25519_identity_key"],
            curve25519_identity_key=r["curve25519_identity_key"],
            fallback_key_id=r["fallback_key_id"],
            fallback_public_key=r["fallback_public_key"],
            bundle_signature=r["bundle_signature"],
            signed_payload=r["signed_payload"],
            status=r["status"],
            created_at=_iso_str(r["created_at"]),
            updated_at=_iso_str(r["updated_at"]),
            revoked_at=_iso_str(r["revoked_at"]),
        )


def list_user_devices(user_id: str, include_revoked: bool = False) -> List[Dict[str, Any]]:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                if include_revoked:
                    cur.execute(
                        """
                        SELECT device_id, user_id, device_label, ed25519_identity_key,
                               curve25519_identity_key, fallback_key_id, fallback_public_key,
                               bundle_signature, status, created_at, updated_at, revoked_at
                        FROM chat_devices WHERE user_id = %s ORDER BY created_at ASC;
                        """,
                        (user_id,),
                    )
                else:
                    cur.execute(
                        """
                        SELECT device_id, user_id, device_label, ed25519_identity_key,
                               curve25519_identity_key, fallback_key_id, fallback_public_key,
                               bundle_signature, status, created_at, updated_at, revoked_at
                        FROM chat_devices WHERE user_id = %s AND status = 'active' ORDER BY created_at ASC;
                        """,
                        (user_id,),
                    )
                rows = cur.fetchall()
                return [
                    {
                        "device_id": r["device_id"],
                        "user_id": r["user_id"],
                        "device_label": r["device_label"],
                        "ed25519_identity_key": r["ed25519_identity_key"],
                        "curve25519_identity_key": r["curve25519_identity_key"],
                        "fallback_key_id": r["fallback_key_id"],
                        "fallback_public_key": r["fallback_public_key"],
                        "bundle_signature": r["bundle_signature"],
                        "status": r["status"],
                        "created_at": _iso_str(r["created_at"]),
                        "updated_at": _iso_str(r["updated_at"]),
                        "revoked_at": _iso_str(r["revoked_at"]),
                    }
                    for r in rows
                ]
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        sql = """
            SELECT device_id, user_id, device_label, ed25519_identity_key,
                   curve25519_identity_key, fallback_key_id, fallback_public_key,
                   bundle_signature, status, created_at, updated_at, revoked_at
            FROM chat_devices
            WHERE user_id = ?
        """
        if not include_revoked:
            sql += " AND status = 'active'"
        sql += " ORDER BY created_at ASC"
        cur.execute(sql, (user_id,))
        return [
            {
                "device_id": r["device_id"],
                "user_id": r["user_id"],
                "device_label": r["device_label"],
                "ed25519_identity_key": r["ed25519_identity_key"],
                "curve25519_identity_key": r["curve25519_identity_key"],
                "fallback_key_id": r["fallback_key_id"],
                "fallback_public_key": r["fallback_public_key"],
                "bundle_signature": r["bundle_signature"],
                "status": r["status"],
                "created_at": _iso_str(r["created_at"]),
                "updated_at": _iso_str(r["updated_at"]),
                "revoked_at": _iso_str(r["revoked_at"]),
            }
            for r in cur.fetchall()
        ]


@auth_cache.invalidates_auth_cache(namespaces=('device',))
def upsert_device_and_keys(
    user_id: str,
    device_id: str,
    device_label: str,
    ed25519_identity_key: str,
    curve25519_identity_key: str,
    fallback_key_id: Optional[str],
    fallback_public_key: Optional[str],
    bundle_signature: str,
    signed_payload: str,
    one_time_keys: Dict[str, str],
    mls_key_packages: List[Dict[str, str]],
) -> Tuple[Dict[str, Any], Optional[str]]:
    """
    Registers a new device or updates prekeys/fallback key for an existing owned device.
    Prevents silent identity key substitution on an existing `device_id`.
    Returns `(device_doc, security_event_type_or_none)`.
    """
    _ready()
    existing = get_device(device_id)
    prior_devices = list_user_devices(user_id, include_revoked=True)
    event_type: Optional[str] = None

    if existing:
        if existing["user_id"] != user_id:
            raise PermissionError("Device ID belongs to another user")
        if existing["status"] == "revoked":
            raise PermissionError("Revoked device cannot be re-activated; generate a new device identity")
        if (
            existing["ed25519_identity_key"] != ed25519_identity_key
            or existing["curve25519_identity_key"] != curve25519_identity_key
        ):
            raise ValueError(
                "Unauthorized identity key substitution on existing device_id rejected"
            )
    else:
        if prior_devices:
            event_type = "device_added"

    ts = now_iso()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO chat_devices (
                        device_id, user_id, device_label, ed25519_identity_key,
                        curve25519_identity_key, fallback_key_id, fallback_public_key,
                        bundle_signature, signed_payload, status, created_at, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'active', %s, %s)
                    ON CONFLICT (device_id) DO UPDATE SET
                        device_label = EXCLUDED.device_label,
                        fallback_key_id = COALESCE(EXCLUDED.fallback_key_id, chat_devices.fallback_key_id),
                        fallback_public_key = COALESCE(EXCLUDED.fallback_public_key, chat_devices.fallback_public_key),
                        bundle_signature = EXCLUDED.bundle_signature,
                        signed_payload = EXCLUDED.signed_payload,
                        updated_at = EXCLUDED.updated_at;
                    """,
                    (
                        device_id,
                        user_id,
                        device_label,
                        ed25519_identity_key,
                        curve25519_identity_key,
                        fallback_key_id,
                        fallback_public_key,
                        bundle_signature,
                        signed_payload,
                        ts,
                        ts,
                    ),
                )
                for key_id, pub_key in one_time_keys.items():
                    row_id = f"{device_id}:{key_id}"
                    cur.execute(
                        """
                        INSERT INTO chat_one_time_prekeys (
                            prekey_row_id, device_id, user_id, key_id, public_key, consumed, created_at
                        ) VALUES (%s, %s, %s, %s, %s, FALSE, %s)
                        ON CONFLICT (prekey_row_id) DO NOTHING;
                        """,
                        (row_id, device_id, user_id, key_id, pub_key, ts),
                    )
                for kp in mls_key_packages:
                    pkg_id = kp.get("package_id") or f"mkp_{secrets.token_hex(12)}"
                    cur.execute(
                        """
                        INSERT INTO chat_mls_key_packages (
                            package_id, device_id, user_id, ciphersuite,
                            key_package_b64, key_package_ref, consumed, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, FALSE, %s)
                        ON CONFLICT (package_id) DO NOTHING;
                        """,
                        (
                            pkg_id,
                            device_id,
                            user_id,
                            kp["ciphersuite"],
                            kp["key_package_b64"],
                            kp["key_package_ref"],
                            ts,
                        ),
                    )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                INSERT INTO chat_devices (
                    device_id, user_id, device_label, ed25519_identity_key,
                    curve25519_identity_key, fallback_key_id, fallback_public_key,
                    bundle_signature, signed_payload, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    device_label = excluded.device_label,
                    fallback_key_id = COALESCE(excluded.fallback_key_id, chat_devices.fallback_key_id),
                    fallback_public_key = COALESCE(excluded.fallback_public_key, chat_devices.fallback_public_key),
                    bundle_signature = excluded.bundle_signature,
                    signed_payload = excluded.signed_payload,
                    updated_at = excluded.updated_at
                """,
                (
                    device_id,
                    user_id,
                    device_label,
                    ed25519_identity_key,
                    curve25519_identity_key,
                    fallback_key_id,
                    fallback_public_key,
                    bundle_signature,
                    signed_payload,
                    ts,
                    ts,
                ),
            )
            for key_id, pub_key in one_time_keys.items():
                row_id = f"{device_id}:{key_id}"
                cur.execute(
                    """
                    INSERT OR IGNORE INTO chat_one_time_prekeys (
                        prekey_row_id, device_id, user_id, key_id, public_key, consumed, created_at
                    ) VALUES (?, ?, ?, ?, ?, 0, ?)
                    """,
                    (row_id, device_id, user_id, key_id, pub_key, ts),
                )
            for kp in mls_key_packages:
                pkg_id = kp.get("package_id") or f"mkp_{secrets.token_hex(12)}"
                cur.execute(
                    """
                    INSERT OR IGNORE INTO chat_mls_key_packages (
                        package_id, device_id, user_id, ciphersuite,
                        key_package_b64, key_package_ref, consumed, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 0, ?)
                    """,
                    (
                        pkg_id,
                        device_id,
                        user_id,
                        kp["ciphersuite"],
                        kp["key_package_b64"],
                        kp["key_package_ref"],
                        ts,
                    ),
                )
            chat_db._sqlite_conn.commit()

    return get_device(device_id), event_type  # type: ignore[return-value]


def count_available_prekeys(device_id: str) -> Dict[str, int]:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM chat_one_time_prekeys WHERE device_id = %s AND consumed = FALSE;",
                    (device_id,),
                )
                otk_count = int(cur.fetchone()[0])
                cur.execute(
                    "SELECT COUNT(*) FROM chat_mls_key_packages WHERE device_id = %s AND consumed = FALSE;",
                    (device_id,),
                )
                mls_count = int(cur.fetchone()[0])
                return {"one_time_prekeys": otk_count, "mls_key_packages": mls_count}
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM chat_one_time_prekeys WHERE device_id = ? AND consumed = 0",
            (device_id,),
        )
        otk_count = int(cur.fetchone()[0])
        cur.execute(
            "SELECT COUNT(*) FROM chat_mls_key_packages WHERE device_id = ? AND consumed = 0",
            (device_id,),
        )
        mls_count = int(cur.fetchone()[0])
        return {"one_time_prekeys": otk_count, "mls_key_packages": mls_count}


@auth_cache.invalidates_auth_cache(namespaces=('device', 'group', 'user_groups'))
def revoke_device(user_id: str, device_id: str) -> Dict[str, Any]:
    """Revokes a device and purges its unconsumed one-time prekeys and MLS KeyPackages."""
    _ready()
    dev = get_device(device_id)
    if not dev or dev["user_id"] != user_id:
        raise PermissionError("Device not found or not owned by user")

    ts = now_iso()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE chat_devices
                    SET status = 'revoked', revoked_at = %s, updated_at = %s
                    WHERE device_id = %s AND user_id = %s;
                    """,
                    (ts, ts, device_id, user_id),
                )
                cur.execute(
                    "DELETE FROM chat_one_time_prekeys WHERE device_id = %s AND consumed = FALSE;",
                    (device_id,),
                )
                cur.execute(
                    "DELETE FROM chat_mls_key_packages WHERE device_id = %s AND consumed = FALSE;",
                    (device_id,),
                )
                cur.execute(
                    """
                    UPDATE chat_group_members
                    SET status = 'removed', updated_bucket = %s
                    WHERE device_id = %s AND user_id = %s;
                    """,
                    (ts, device_id, user_id),
                )
                cur.execute(
                    "DELETE FROM chat_group_welcomes WHERE target_device_id = %s AND consumed = FALSE;",
                    (device_id,),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                UPDATE chat_devices
                SET status = 'revoked', revoked_at = ?, updated_at = ?
                WHERE device_id = ? AND user_id = ?
                """,
                (ts, ts, device_id, user_id),
            )
            cur.execute(
                "DELETE FROM chat_one_time_prekeys WHERE device_id = ? AND consumed = 0",
                (device_id,),
            )
            cur.execute(
                "DELETE FROM chat_mls_key_packages WHERE device_id = ? AND consumed = 0",
                (device_id,),
            )
            cur.execute(
                """
                UPDATE chat_group_members
                SET status = 'removed', updated_bucket = ?
                WHERE device_id = ? AND user_id = ?
                """,
                (ts, device_id, user_id),
            )
            cur.execute(
                "DELETE FROM chat_group_welcomes WHERE target_device_id = ? AND consumed = 0",
                (device_id,),
            )
            chat_db._sqlite_conn.commit()

    return get_device(device_id)  # type: ignore[return-value]


@auth_cache.invalidates_auth_cache
def reset_all_user_devices_lost_keys(user_id: str) -> int:
    """
    Explicit lost-all-devices reset: revokes all active devices, deletes all unconsumed
    prekeys/KeyPackages, and increments `identity_version` so conversation peers are alerted.
    Does NOT delete historical ciphertexts (though prior messages cannot be decrypted without old keys).
    """
    _ready()
    ts = now_iso()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE chat_devices
                    SET status = 'revoked', revoked_at = %s, updated_at = %s
                    WHERE user_id = %s AND status = 'active';
                    """,
                    (ts, ts, user_id),
                )
                cur.execute(
                    "DELETE FROM chat_one_time_prekeys WHERE user_id = %s AND consumed = FALSE;",
                    (user_id,),
                )
                cur.execute(
                    "DELETE FROM chat_mls_key_packages WHERE user_id = %s AND consumed = FALSE;",
                    (user_id,),
                )
                cur.execute(
                    """
                    UPDATE chat_group_members
                    SET status = 'removed', updated_bucket = %s
                    WHERE user_id = %s;
                    """,
                    (ts, user_id),
                )
                cur.execute(
                    "DELETE FROM chat_group_welcomes WHERE target_user_id = %s AND consumed = FALSE;",
                    (user_id,),
                )
                cur.execute(
                    """
                    UPDATE chat_users
                    SET identity_version = identity_version + 1, updated_at = %s
                    WHERE user_id = %s
                    RETURNING identity_version;
                    """,
                    (ts, user_id),
                )
                new_ver = int(cur.fetchone()[0])
            conn.commit()
            return new_ver
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            """
            UPDATE chat_devices
            SET status = 'revoked', revoked_at = ?, updated_at = ?
            WHERE user_id = ? AND status = 'active'
            """,
            (ts, ts, user_id),
        )
        cur.execute(
            "DELETE FROM chat_one_time_prekeys WHERE user_id = ? AND consumed = 0",
            (user_id,),
        )
        cur.execute(
            "DELETE FROM chat_mls_key_packages WHERE user_id = ? AND consumed = 0",
            (user_id,),
        )
        cur.execute(
            """
            UPDATE chat_group_members
            SET status = 'removed', updated_bucket = ?
            WHERE user_id = ?
            """,
            (ts, user_id),
        )
        cur.execute(
            "DELETE FROM chat_group_welcomes WHERE target_user_id = ? AND consumed = 0",
            (user_id,),
        )
        cur.execute(
            "UPDATE chat_users SET identity_version = identity_version + 1, updated_at = ? WHERE user_id = ?",
            (ts, user_id),
        )
        cur.execute("SELECT identity_version FROM chat_users WHERE user_id = ?", (user_id,))
        new_ver = int(cur.fetchone()[0])
        chat_db._sqlite_conn.commit()
        return new_ver


def claim_one_time_prekey_for_device(device_id: str) -> Optional[Dict[str, Any]]:
    """
    Atomically consumes a single unconsumed Olm One-Time Prekey for `device_id`.
    If exhausted, returns the device's signed fallback key (`is_fallback=True`).
    """
    _ready()
    dev = get_device(device_id)
    if not dev or dev["status"] != "active":
        return None

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    UPDATE chat_one_time_prekeys
                    SET consumed = TRUE
                    WHERE prekey_row_id = (
                        SELECT prekey_row_id FROM chat_one_time_prekeys
                        WHERE device_id = %s AND consumed = FALSE
                        ORDER BY created_at ASC
                        LIMIT 1
                        FOR UPDATE SKIP LOCKED
                    )
                    RETURNING key_id, public_key;
                    """,
                    (device_id,),
                )
                row = cur.fetchone()
            conn.commit()
            if row:
                return {
                    "device_id": device_id,
                    "user_id": dev["user_id"],
                    "ed25519_identity_key": dev["ed25519_identity_key"],
                    "curve25519_identity_key": dev["curve25519_identity_key"],
                    "prekey_id": row["key_id"],
                    "prekey_public": row["public_key"],
                    "is_fallback": False,
                    "bundle_signature": dev["bundle_signature"],
                    "signed_payload": dev["signed_payload"],
                }
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                SELECT prekey_row_id, key_id, public_key
                FROM chat_one_time_prekeys
                WHERE device_id = ? AND consumed = 0
                ORDER BY created_at ASC
                LIMIT 1
                """,
                (device_id,),
            )
            row = cur.fetchone()
            if row:
                cur.execute(
                    "UPDATE chat_one_time_prekeys SET consumed = 1 WHERE prekey_row_id = ? AND consumed = 0",
                    (row["prekey_row_id"],),
                )
                chat_db._sqlite_conn.commit()
                if cur.rowcount == 1:
                    return {
                        "device_id": device_id,
                        "user_id": dev["user_id"],
                        "ed25519_identity_key": dev["ed25519_identity_key"],
                        "curve25519_identity_key": dev["curve25519_identity_key"],
                        "prekey_id": row["key_id"],
                        "prekey_public": row["public_key"],
                        "is_fallback": False,
                        "bundle_signature": dev["bundle_signature"],
                        "signed_payload": dev["signed_payload"],
                    }

    if dev.get("fallback_public_key"):
        return {
            "device_id": device_id,
            "user_id": dev["user_id"],
            "ed25519_identity_key": dev["ed25519_identity_key"],
            "curve25519_identity_key": dev["curve25519_identity_key"],
            "prekey_id": dev.get("fallback_key_id") or "fallback",
            "prekey_public": dev["fallback_public_key"],
            "is_fallback": True,
            "bundle_signature": dev["bundle_signature"],
            "signed_payload": dev["signed_payload"],
        }
    return None


def claim_mls_key_packages_for_user(target_user_id: str) -> List[Dict[str, Any]]:
    """
    Atomically claims one single-use MLS KeyPackage per active device of `target_user_id`.
    """
    _ready()
    devices = list_user_devices(target_user_id, include_revoked=False)
    claimed: List[Dict[str, Any]] = []

    for dev in devices:
        dev_id = dev["device_id"]
        if _is_pg():
            conn = chat_db._pg_pool.getconn()
            try:
                with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                    cur.execute(
                        """
                        UPDATE chat_mls_key_packages
                        SET consumed = TRUE
                        WHERE package_id = (
                            SELECT package_id FROM chat_mls_key_packages
                            WHERE device_id = %s AND consumed = FALSE
                            ORDER BY created_at ASC
                            LIMIT 1
                            FOR UPDATE SKIP LOCKED
                        )
                        RETURNING package_id, ciphersuite, key_package_b64, key_package_ref;
                        """,
                        (dev_id,),
                    )
                    row = cur.fetchone()
                conn.commit()
                if row:
                    claimed.append({
                        "package_id": row["package_id"],
                        "user_id": target_user_id,
                        "device_id": dev_id,
                        "ciphersuite": row["ciphersuite"],
                        "key_package_b64": row["key_package_b64"],
                        "key_package_ref": row["key_package_ref"],
                    })
            finally:
                chat_db._pg_pool.putconn(conn)
        else:
            with chat_db._sqlite_lock:
                cur = chat_db._sqlite_conn.cursor()
                cur.execute(
                    """
                    SELECT package_id, ciphersuite, key_package_b64, key_package_ref
                    FROM chat_mls_key_packages
                    WHERE device_id = ? AND consumed = 0
                    ORDER BY created_at ASC
                    LIMIT 1
                    """,
                    (dev_id,),
                )
                row = cur.fetchone()
                if row:
                    cur.execute(
                        "UPDATE chat_mls_key_packages SET consumed = 1 WHERE package_id = ? AND consumed = 0",
                        (row["package_id"],),
                    )
                    chat_db._sqlite_conn.commit()
                    if cur.rowcount == 1:
                        claimed.append({
                            "package_id": row["package_id"],
                            "user_id": target_user_id,
                            "device_id": dev_id,
                            "ciphersuite": row["ciphersuite"],
                            "key_package_b64": row["key_package_b64"],
                            "key_package_ref": row["key_package_ref"],
                        })
    return claimed


# ============================================================================
# 4. PRIVATE 1-TO-1 / MULTI-DEVICE OLM v2 MESSAGES
# ============================================================================

def insert_dm_ciphertext(
    message_id: str,
    sender_user_id: str,
    sender_device_id: str,
    sender_curve25519_key: str,
    sender_ed25519_key: str,
    recipient_user_id: str,
    protocol: str,
    device_ciphertexts: Dict[str, Dict[str, Any]],
    attachment_ids: Optional[List[str]] = None,
    event_kind: str = "message",
    expires_at: Optional[str] = None,
) -> Dict[str, Any]:
    _ready()
    assert_zero_plaintext(device_ciphertexts, "device_ciphertexts")
    event_kind = _clean_event_kind(event_kind)
    conv_id = make_dm_conversation_id(sender_user_id, recipient_user_id)
    bucket = coarse_timestamp_iso()
    att_list = attachment_ids or []

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            # message_id is UNIQUE, so the duplicate check is part of the INSERT itself
            # (ON CONFLICT DO NOTHING) and autocommit removes the separate COMMIT: ONE round trip.
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO chat_dm_messages (
                        message_id, conversation_id, sender_user_id, sender_device_id,
                        sender_curve25519_key, sender_ed25519_key, recipient_user_id,
                        protocol, ciphertexts_json, attachment_ids_json, created_bucket,
                        event_kind, expires_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (message_id) DO NOTHING
                    RETURNING seq;
                    """,
                    (
                        message_id, conv_id, sender_user_id, sender_device_id,
                        sender_curve25519_key, sender_ed25519_key, recipient_user_id,
                        protocol, json.dumps(device_ciphertexts), json.dumps(att_list), bucket,
                        event_kind, expires_at,
                    ),
                )
                row = cur.fetchone()
                if not row:
                    raise DuplicateMessageError(f"Duplicate message_id rejected: {message_id}")
                seq = int(row[0])
        finally:
            try:
                conn.autocommit = False
            except Exception:
                pass
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                INSERT OR IGNORE INTO chat_dm_messages (
                    message_id, conversation_id, sender_user_id, sender_device_id,
                    sender_curve25519_key, sender_ed25519_key, recipient_user_id,
                    protocol, ciphertexts_json, attachment_ids_json, created_bucket,
                    event_kind, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_id, conv_id, sender_user_id, sender_device_id,
                    sender_curve25519_key, sender_ed25519_key, recipient_user_id,
                    protocol, json.dumps(device_ciphertexts), json.dumps(att_list), bucket,
                    event_kind, expires_at,
                ),
            )
            if cur.rowcount == 0:
                chat_db._sqlite_conn.rollback()
                raise DuplicateMessageError(f"Duplicate message_id rejected: {message_id}")
            seq = int(cur.lastrowid or 0)
            chat_db._sqlite_conn.commit()

    return {
        "seq": seq,
        "message_id": message_id,
        "conversation_id": conv_id,
        "sender_user_id": sender_user_id,
        "sender_device_id": sender_device_id,
        "sender_curve25519_key": sender_curve25519_key,
        "sender_ed25519_key": sender_ed25519_key,
        "recipient_user_id": recipient_user_id,
        "protocol": protocol,
        "device_ciphertexts": device_ciphertexts,
        "attachment_ids": att_list,
        "timestamp": bucket,
        "event_kind": event_kind,
        "expires_at": expires_at,
    }


def list_dm_ciphertexts(
    requester_user_id: str,
    peer_user_id: str,
    requester_device_id: Optional[str] = None,
    after_seq: int = 0,
    limit: int = 60,
) -> List[Dict[str, Any]]:
    """
    Returns DM ciphertexts strictly for conversations where `requester_user_id` is a participant.
    If `requester_device_id` is provided, filters `device_ciphertexts` to only that device's
    ciphertext so other devices' ciphertexts aren't unnecessarily exposed.
    """
    _ready()
    conv_id = make_dm_conversation_id(requester_user_id, peer_user_id)
    bounded = max(1, min(limit, 100))

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT seq, message_id, conversation_id, sender_user_id, sender_device_id,
                           sender_curve25519_key, sender_ed25519_key, recipient_user_id,
                           protocol, ciphertexts_json, attachment_ids_json, created_bucket,
                           event_kind, deleted_at, expires_at
                    FROM chat_dm_messages
                    WHERE conversation_id = %s
                      AND (sender_user_id = %s OR recipient_user_id = %s)
                      AND seq > %s
                    ORDER BY seq ASC
                    LIMIT %s;
                    """,
                    (conv_id, requester_user_id, requester_user_id, after_seq, bounded),
                )
                rows = cur.fetchall()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                SELECT seq, message_id, conversation_id, sender_user_id, sender_device_id,
                       sender_curve25519_key, sender_ed25519_key, recipient_user_id,
                       protocol, ciphertexts_json, attachment_ids_json, created_bucket,
                       event_kind, deleted_at, expires_at
                FROM chat_dm_messages
                WHERE conversation_id = ?
                  AND (sender_user_id = ? OR recipient_user_id = ?)
                  AND seq > ?
                ORDER BY seq ASC
                LIMIT ?
                """,
                (conv_id, requester_user_id, requester_user_id, after_seq, bounded),
            )
            rows = cur.fetchall()

    results: List[Dict[str, Any]] = []
    now = now_utc()
    for r in rows:
        ct_map = _parse_json(r["ciphertexts_json"], {})
        if requester_device_id and isinstance(ct_map, dict):
            scoped_ct = (
                {requester_device_id: ct_map[requester_device_id]}
                if requester_device_id in ct_map
                else {}
            )
        else:
            scoped_ct = ct_map
        deleted = bool(r["deleted_at"])
        expires = _as_dt(r["expires_at"])
        expired = bool(expires and expires <= now)
        if deleted or expired:
            # Enforced here, not only by the periodic purge: after expiry / deletion a device may only get
            # an undelivered session-setup copy, never a normal readable one.
            scoped_ct = _setup_copies_only(scoped_ct)
        if expired and not scoped_ct:
            continue  # gone for good: nothing left for this device
        results.append({
            "seq": int(r["seq"]),
            "message_id": r["message_id"],
            "conversation_id": r["conversation_id"],
            "sender_user_id": r["sender_user_id"],
            "sender_device_id": r["sender_device_id"],
            "sender_curve25519_key": r["sender_curve25519_key"],
            "sender_ed25519_key": r["sender_ed25519_key"],
            "recipient_user_id": r["recipient_user_id"],
            "protocol": r["protocol"],
            "device_ciphertexts": scoped_ct,
            "attachment_ids": [] if (deleted or expired) else _parse_json(r["attachment_ids_json"], []),
            "timestamp": r["created_bucket"],
            "event_kind": r["event_kind"] or "message",
            # Deleted / expired: only a never-delivered session-setup copy may remain. The device uses it to
            # keep its encrypted session working and must NOT show or keep the text.
            "deleted": deleted,
            "expired": expired,
            "expires_at": expires.isoformat() if expires else None,
        })
    return results


def list_dm_conversations_for_user(user_id: str) -> List[Dict[str, Any]]:
    """Lists distinct DM peer `user_id`s for `user_id`."""
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT conversation_id,
                           CASE WHEN sender_user_id = %s THEN recipient_user_id ELSE sender_user_id END AS peer_user_id,
                           MAX(seq) AS last_seq,
                           MAX(created_bucket) AS last_bucket
                    FROM chat_dm_messages
                    WHERE sender_user_id = %s OR recipient_user_id = %s
                    GROUP BY conversation_id, peer_user_id
                    ORDER BY last_seq DESC;
                    """,
                    (user_id, user_id, user_id),
                )
                rows = cur.fetchall()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                SELECT conversation_id,
                       CASE WHEN sender_user_id = ? THEN recipient_user_id ELSE sender_user_id END AS peer_user_id,
                       MAX(seq) AS last_seq,
                       MAX(created_bucket) AS last_bucket
                FROM chat_dm_messages
                WHERE sender_user_id = ? OR recipient_user_id = ?
                GROUP BY conversation_id, peer_user_id
                ORDER BY last_seq DESC
                """,
                (user_id, user_id, user_id),
            )
            rows = cur.fetchall()

    out = []
    for r in rows:
        peer = get_user_by_id(r["peer_user_id"])
        out.append({
            "conversation_id": r["conversation_id"],
            "peer_user_id": r["peer_user_id"],
            "peer_username": peer["username"] if peer else None,
            "peer_primary_wallet": peer["primary_wallet"] if peer else None,
            "last_seq": int(r["last_seq"]),
            "last_timestamp": r["last_bucket"],
        })
    return out


# ============================================================================
# 5. MLS RFC 9420 ENCRYPTED GROUPS (EPOCHS, COMMITS, WELCOMES, MESSAGES)
# ============================================================================

@auth_cache.invalidates_auth_cache(namespaces=('group', 'user_groups'))
def create_mls_group(
    mls_group_id_b64: str,
    name: str,
    creator_user_id: str,
    creator_device_id: str,
    ciphersuite: str,
    return_group: bool = True,
    creator_profile: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    _ready()
    # New members never see messages from before they joined (enforced in list_group_ciphertexts).
    history_sharing_mode = "none"
    group_id = f"grp_{secrets.token_hex(12)}"
    bucket = coarse_timestamp_iso()

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            # Both INSERTs go to the server as ONE multi-statement request (a single network round
            # trip). With autocommit the server runs them as one implicit transaction, so the group
            # and its admin member are created atomically - never one without the other.
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO chat_groups (
                        group_id, mls_group_id_b64, name, creator_user_id,
                        current_epoch, ciphersuite, history_sharing_mode,
                        created_bucket, updated_bucket
                    ) VALUES (%s, %s, %s, %s, 0, %s, %s, %s, %s);
                    INSERT INTO chat_group_members (
                        group_id, user_id, device_id, role, leaf_index,
                        status, joined_epoch, removed_epoch, updated_bucket
                    ) VALUES (%s, %s, %s, 'admin', 0, 'active', 0, NULL, %s);
                    """,
                    (
                        group_id, mls_group_id_b64, name, creator_user_id,
                        ciphersuite, history_sharing_mode, bucket, bucket,
                        group_id, creator_user_id, creator_device_id, bucket,
                    ),
                )
        finally:
            try:
                conn.autocommit = False
            except Exception:
                pass
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                INSERT INTO chat_groups (
                    group_id, mls_group_id_b64, name, creator_user_id,
                    current_epoch, ciphersuite, history_sharing_mode,
                    created_bucket, updated_bucket
                ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)
                """,
                (
                    group_id,
                    mls_group_id_b64,
                    name,
                    creator_user_id,
                    ciphersuite,
                    history_sharing_mode,
                    bucket,
                    bucket,
                ),
            )
            cur.execute(
                """
                INSERT INTO chat_group_members (
                    group_id, user_id, device_id, role, leaf_index,
                    status, joined_epoch, removed_epoch, updated_bucket
                ) VALUES (?, ?, ?, 'admin', 0, 'active', 0, NULL, ?)
                """,
                (group_id, creator_user_id, creator_device_id, bucket),
            )
            chat_db._sqlite_conn.commit()

    if not return_group:
        return {"group_id": group_id}

    # Build the response from values we just wrote instead of re-reading 3 tables (3 round trips).
    # Shape is identical to get_mls_group(); test_group_create_matches_read_back guards that.
    # `creator_profile` (already loaded by the route) avoids another lookup inside the write.
    creator = creator_profile or get_user_by_id(creator_user_id) or {}
    return {
        "group_id": group_id,
        "mls_group_id_b64": mls_group_id_b64,
        "name": name,
        "creator_user_id": creator_user_id,
        "current_epoch": 0,
        "ciphersuite": ciphersuite,
        "history_sharing_mode": history_sharing_mode,
        "policy": {
            "group_id": group_id,
            "description": "",
            "visibility": "invite_only",
            "min_eth_balance_wei": "0",
            "require_invitation": True,
        },
        "created_at": bucket,
        "updated_at": bucket,
        "members": [
            {
                "user_id": creator_user_id,
                "username": creator.get("username"),
                "display_name": creator.get("display_name"),
                "device_id": creator_device_id,
                "role": "admin",
                "leaf_index": 0,
                "status": "active",
                "joined_epoch": 0,
                "removed_epoch": None,
            }
        ],
    }


@auth_cache.read_cached("group")
def get_mls_group(group_id: str) -> Optional[Dict[str, Any]]:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT group_id, mls_group_id_b64, name, creator_user_id,
                           current_epoch, ciphersuite, history_sharing_mode,
                           created_bucket, updated_bucket
                    FROM chat_groups WHERE group_id = %s;
                    """,
                    (group_id,),
                )
                g = cur.fetchone()
                if not g:
                    return None
                cur.execute(
                    """
                    SELECT m.user_id, m.device_id, m.role, m.leaf_index, m.status,
                           m.joined_epoch, m.removed_epoch,
                           u.username, u.display_name
                    FROM chat_group_members m
                    LEFT JOIN chat_users u ON u.user_id = m.user_id
                    WHERE m.group_id = %s
                    ORDER BY m.joined_epoch ASC, m.user_id ASC;
                    """,
                    (group_id,),
                )
                members = [dict(m) for m in cur.fetchall()]
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                SELECT group_id, mls_group_id_b64, name, creator_user_id,
                       current_epoch, ciphersuite, history_sharing_mode,
                       created_bucket, updated_bucket
                FROM chat_groups WHERE group_id = ?
                """,
                (group_id,),
            )
            g = cur.fetchone()
            if not g:
                return None
            cur.execute(
                """
                SELECT m.user_id, m.device_id, m.role, m.leaf_index, m.status,
                       m.joined_epoch, m.removed_epoch,
                       u.username, u.display_name
                FROM chat_group_members m
                LEFT JOIN chat_users u ON u.user_id = m.user_id
                WHERE m.group_id = ?
                ORDER BY m.joined_epoch ASC, m.user_id ASC
                """,
                (group_id,),
            )
            members = [dict(m) for m in cur.fetchall()]

    import platform_db
    pol = platform_db.get_group_access_policy(group_id)
    return _shape_group(g, members, pol)


def _shape_group(g: Any, members: List[Dict[str, Any]], pol: Dict[str, Any]) -> Dict[str, Any]:
    """Single source of truth for the group dict returned by get_mls_group / list_groups_for_user."""
    return {
        "group_id": g["group_id"],
        "mls_group_id_b64": g["mls_group_id_b64"],
        "name": g["name"],
        "creator_user_id": g["creator_user_id"],
        "current_epoch": int(g["current_epoch"]),
        "ciphersuite": g["ciphersuite"],
        "history_sharing_mode": g["history_sharing_mode"],
        "policy": pol,
        "created_at": g["created_bucket"],
        "updated_at": g["updated_bucket"],
        "members": [
            {
                "user_id": m["user_id"],
                "username": m.get("username"),
                "display_name": m.get("display_name"),
                "device_id": m["device_id"],
                "role": m["role"],
                "leaf_index": m["leaf_index"],
                "status": m["status"],
                "joined_epoch": int(m["joined_epoch"]),
                "removed_epoch": int(m["removed_epoch"]) if m["removed_epoch"] is not None else None,
            }
            for m in members
        ],
    }


def _load_groups_batch(group_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """Load many groups (+members, +policies) in 3 queries total, instead of 3 per group."""
    import platform_db
    ids = list(dict.fromkeys(group_ids))
    if not ids:
        return {}
    g_rows: List[Dict[str, Any]] = []
    m_rows: List[Dict[str, Any]] = []
    g_sql = """
        SELECT group_id, mls_group_id_b64, name, creator_user_id,
               current_epoch, ciphersuite, history_sharing_mode,
               created_bucket, updated_bucket
        FROM chat_groups WHERE group_id {cond}
    """
    m_sql = """
        SELECT m.group_id, m.user_id, m.device_id, m.role, m.leaf_index, m.status,
               m.joined_epoch, m.removed_epoch,
               u.username, u.display_name
        FROM chat_group_members m
        LEFT JOIN chat_users u ON u.user_id = m.user_id
        WHERE m.group_id {cond}
        ORDER BY m.group_id, m.joined_epoch ASC, m.user_id ASC
    """
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(g_sql.format(cond="= ANY(%s)"), (ids,))
                g_rows = [dict(r) for r in cur.fetchall()]
                cur.execute(m_sql.format(cond="= ANY(%s)"), (ids,))
                m_rows = [dict(r) for r in cur.fetchall()]
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        marks = ",".join("?" for _ in ids)
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(g_sql.format(cond=f"IN ({marks})"), ids)
            g_rows = [dict(r) for r in cur.fetchall()]
            cur.execute(m_sql.format(cond=f"IN ({marks})"), ids)
            m_rows = [dict(r) for r in cur.fetchall()]

    policies = platform_db.get_group_access_policies_batch(ids)
    by_group: Dict[str, List[Dict[str, Any]]] = {}
    for m in m_rows:
        by_group.setdefault(m["group_id"], []).append(m)
    return {
        g["group_id"]: _shape_group(g, by_group.get(g["group_id"], []), policies[g["group_id"]])
        for g in g_rows
    }


def get_member_record(group_id: str, user_id: str) -> List[Dict[str, Any]]:
    grp = get_mls_group(group_id)
    if not grp:
        return []
    return [m for m in grp["members"] if m["user_id"] == user_id]


def is_active_group_member(group_id: str, user_id: str, device_id: Optional[str] = None) -> bool:
    if device_id:
        dev = get_device(device_id)
        if not dev or dev.get("status") != "active" or dev.get("user_id") != user_id:
            return False
    records = get_member_record(group_id, user_id)
    for r in records:
        if r["status"] == "active" and (device_id is None or r["device_id"] == device_id):
            return True
    return False


@auth_cache.read_cached("user_groups")
def list_groups_for_user(user_id: str) -> List[Dict[str, Any]]:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT DISTINCT group_id FROM chat_group_members
                    WHERE user_id = %s AND status = 'active';
                    """,
                    (user_id,),
                )
                gids = [r[0] for r in cur.fetchall()]
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                SELECT DISTINCT group_id FROM chat_group_members
                WHERE user_id = ? AND status = 'active'
                """,
                (user_id,),
            )
            gids = [r[0] for r in cur.fetchall()]

    gen = auth_cache.generation()
    loaded = _load_groups_batch(gids)
    out = []
    for gid in gids:
        g = loaded.get(gid)
        if g:
            out.append(g)
            # later single-group lookups (message sends, fetches) are then served from memory
            auth_cache.put("group", auth_cache.make_key((gid,), {}), g, gen)
    return out


GROUP_INVITED_STATUS = "invited"
GROUP_DECLINED_STATUS = "declined"


def _added_member_status(am: Dict[str, Any]) -> str:
    """'invited' = an admin added this person and they still have to Accept; anything else = 'active'."""
    return GROUP_INVITED_STATUS if am.get("status") == GROUP_INVITED_STATUS else "active"


@auth_cache.invalidates_auth_cache(namespaces=('group', 'user_groups'))
def submit_mls_commit_atomic(
    group_id: str,
    committer_user_id: str,
    committer_device_id: str,
    expected_epoch: int,
    commit_type: str,
    mls_commit_b64: str,
    ratchet_tree_b64: Optional[str],
    added_members: List[Dict[str, Any]],
    removed_members: List[Dict[str, Any]],
    welcomes: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Atomically validates membership and `expected_epoch == current_epoch`, advances
    the group to `new_epoch = expected_epoch + 1`, updates member statuses (granting
    no pre-join history to added members and revoking future access for removed members),
    and stores Welcome packages for offline/online added devices.
    """
    _ready()
    commit_id = f"cmt_{secrets.token_hex(12)}"
    bucket = coarse_timestamp_iso()
    new_epoch = expected_epoch + 1

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    "SELECT current_epoch FROM chat_groups WHERE group_id = %s FOR UPDATE;",
                    (group_id,),
                )
                g_row = cur.fetchone()
                if not g_row:
                    raise ValueError("Group not found")
                cur_epoch = int(g_row["current_epoch"])

                cur.execute(
                    """
                    SELECT m.status AS member_status, m.role, d.status AS dev_status
                    FROM chat_group_members m
                    LEFT JOIN chat_devices d ON d.device_id = m.device_id
                    WHERE m.group_id = %s AND m.user_id = %s AND m.device_id = %s;
                    """,
                    (group_id, committer_user_id, committer_device_id),
                )
                m_row = cur.fetchone()
                if not m_row or m_row["member_status"] != "active" or m_row.get("dev_status") != "active":
                    raise PermissionError("Committer device is not an active member of this group or is revoked")

                if cur_epoch != expected_epoch:
                    raise EpochConflictError(current_epoch=cur_epoch, expected_epoch=expected_epoch)

                cur.execute(
                    """
                    INSERT INTO chat_group_commits (
                        commit_id, group_id, epoch, committer_user_id, committer_device_id,
                        commit_type, mls_commit_b64, ratchet_tree_b64, created_bucket
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
                    """,
                    (
                        commit_id,
                        group_id,
                        new_epoch,
                        committer_user_id,
                        committer_device_id,
                        commit_type,
                        mls_commit_b64,
                        ratchet_tree_b64,
                        bucket,
                    ),
                )

                for am in added_members:
                    cur.execute(
                        """
                        INSERT INTO chat_group_members (
                            group_id, user_id, device_id, role, leaf_index,
                            status, joined_epoch, removed_epoch, updated_bucket
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, NULL, %s)
                        ON CONFLICT (group_id, user_id, device_id) DO UPDATE SET
                            status = EXCLUDED.status,
                            role = EXCLUDED.role,
                            leaf_index = EXCLUDED.leaf_index,
                            joined_epoch = EXCLUDED.joined_epoch,
                            removed_epoch = NULL,
                            updated_bucket = EXCLUDED.updated_bucket;
                        """,
                        (
                            group_id,
                            am["user_id"],
                            am["device_id"],
                            am.get("role", "member"),
                            am.get("leaf_index"),
                            _added_member_status(am),
                            new_epoch,
                            bucket,
                        ),
                    )

                for rm in removed_members:
                    rm_uid = rm["user_id"]
                    rm_did = rm.get("device_id")
                    if rm_did:
                        cur.execute(
                            """
                            UPDATE chat_group_members
                            SET status = 'removed', removed_epoch = %s, updated_bucket = %s
                            WHERE group_id = %s AND user_id = %s AND device_id = %s;
                            """,
                            (new_epoch, bucket, group_id, rm_uid, rm_did),
                        )
                    else:
                        cur.execute(
                            """
                            UPDATE chat_group_members
                            SET status = 'removed', removed_epoch = %s, updated_bucket = %s
                            WHERE group_id = %s AND user_id = %s;
                            """,
                            (new_epoch, bucket, group_id, rm_uid),
                        )
                    cur.execute(
                        "DELETE FROM chat_group_welcomes WHERE group_id = %s AND target_user_id = %s AND consumed = FALSE;",
                        (group_id, rm_uid),
                    )

                for w in welcomes:
                    wid = f"wlc_{secrets.token_hex(12)}"
                    cur.execute(
                        """
                        INSERT INTO chat_group_welcomes (
                            welcome_id, group_id, epoch, target_user_id, target_device_id,
                            mls_welcome_b64, ratchet_tree_b64, consumed, created_bucket
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, FALSE, %s);
                        """,
                        (
                            wid,
                            group_id,
                            new_epoch,
                            w["target_user_id"],
                            w["target_device_id"],
                            w["mls_welcome_b64"],
                            w.get("ratchet_tree_b64") or ratchet_tree_b64,
                            bucket,
                        ),
                    )

                cur.execute(
                    "UPDATE chat_groups SET current_epoch = %s, updated_bucket = %s WHERE group_id = %s;",
                    (new_epoch, bucket, group_id),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            try:
                cur.execute("SELECT current_epoch FROM chat_groups WHERE group_id = ?", (group_id,))
                g_row = cur.fetchone()
                if not g_row:
                    raise ValueError("Group not found")
                cur_epoch = int(g_row["current_epoch"])

                cur.execute(
                    """
                    SELECT m.status AS member_status, m.role, d.status AS dev_status
                    FROM chat_group_members m
                    LEFT JOIN chat_devices d ON d.device_id = m.device_id
                    WHERE m.group_id = ? AND m.user_id = ? AND m.device_id = ?
                    """,
                    (group_id, committer_user_id, committer_device_id),
                )
                m_row = cur.fetchone()
                if not m_row or m_row["member_status"] != "active" or m_row["dev_status"] != "active":
                    raise PermissionError("Committer device is not an active member of this group or is revoked")

                if cur_epoch != expected_epoch:
                    raise EpochConflictError(current_epoch=cur_epoch, expected_epoch=expected_epoch)

                cur.execute(
                    """
                    INSERT INTO chat_group_commits (
                        commit_id, group_id, epoch, committer_user_id, committer_device_id,
                        commit_type, mls_commit_b64, ratchet_tree_b64, created_bucket
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        commit_id,
                        group_id,
                        new_epoch,
                        committer_user_id,
                        committer_device_id,
                        commit_type,
                        mls_commit_b64,
                        ratchet_tree_b64,
                        bucket,
                    ),
                )

                for am in added_members:
                    cur.execute(
                        """
                        INSERT INTO chat_group_members (
                            group_id, user_id, device_id, role, leaf_index,
                            status, joined_epoch, removed_epoch, updated_bucket
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)
                        ON CONFLICT(group_id, user_id, device_id) DO UPDATE SET
                            status = excluded.status,
                            role = excluded.role,
                            leaf_index = excluded.leaf_index,
                            joined_epoch = excluded.joined_epoch,
                            removed_epoch = NULL,
                            updated_bucket = excluded.updated_bucket
                        """,
                        (
                            group_id,
                            am["user_id"],
                            am["device_id"],
                            am.get("role", "member"),
                            am.get("leaf_index"),
                            _added_member_status(am),
                            new_epoch,
                            bucket,
                        ),
                    )

                for rm in removed_members:
                    rm_uid = rm["user_id"]
                    rm_did = rm.get("device_id")
                    if rm_did:
                        cur.execute(
                            """
                            UPDATE chat_group_members
                            SET status = 'removed', removed_epoch = ?, updated_bucket = ?
                            WHERE group_id = ? AND user_id = ? AND device_id = ?
                            """,
                            (new_epoch, bucket, group_id, rm_uid, rm_did),
                        )
                    else:
                        cur.execute(
                            """
                            UPDATE chat_group_members
                            SET status = 'removed', removed_epoch = ?, updated_bucket = ?
                            WHERE group_id = ? AND user_id = ?
                            """,
                            (new_epoch, bucket, group_id, rm_uid),
                        )
                    cur.execute(
                        "DELETE FROM chat_group_welcomes WHERE group_id = ? AND target_user_id = ? AND consumed = 0",
                        (group_id, rm_uid),
                    )

                for w in welcomes:
                    wid = f"wlc_{secrets.token_hex(12)}"
                    cur.execute(
                        """
                        INSERT INTO chat_group_welcomes (
                            welcome_id, group_id, epoch, target_user_id, target_device_id,
                            mls_welcome_b64, ratchet_tree_b64, consumed, created_bucket
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
                        """,
                        (
                            wid,
                            group_id,
                            new_epoch,
                            w["target_user_id"],
                            w["target_device_id"],
                            w["mls_welcome_b64"],
                            w.get("ratchet_tree_b64") or ratchet_tree_b64,
                            bucket,
                        ),
                    )

                cur.execute(
                    "UPDATE chat_groups SET current_epoch = ?, updated_bucket = ? WHERE group_id = ?",
                    (new_epoch, bucket, group_id),
                )
                chat_db._sqlite_conn.commit()
            except Exception:
                chat_db._sqlite_conn.rollback()
                raise

    return {
        "commit_id": commit_id,
        "group_id": group_id,
        "epoch": new_epoch,
        "commit_type": commit_type,
        "timestamp": bucket,
    }


def list_pending_welcomes(user_id: str, device_id: str, consume: bool = True) -> List[Dict[str, Any]]:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT w.welcome_id, w.group_id, w.epoch, w.mls_welcome_b64, w.ratchet_tree_b64, w.created_bucket
                    FROM chat_group_welcomes w
                    WHERE w.target_user_id = %s AND w.target_device_id = %s AND w.consumed = FALSE
                      AND EXISTS (
                          SELECT 1 FROM chat_group_members m
                          WHERE m.group_id = w.group_id AND m.user_id = w.target_user_id
                            AND m.device_id = w.target_device_id AND m.status = 'active'
                      )
                    ORDER BY w.epoch ASC;
                    """,
                    (user_id, device_id),
                )
                rows = cur.fetchall()
                if consume and rows:
                    ids = [r["welcome_id"] for r in rows]
                    cur.execute(
                        "UPDATE chat_group_welcomes SET consumed = TRUE WHERE welcome_id = ANY(%s);",
                        (ids,),
                    )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                SELECT w.welcome_id, w.group_id, w.epoch, w.mls_welcome_b64, w.ratchet_tree_b64, w.created_bucket
                FROM chat_group_welcomes w
                WHERE w.target_user_id = ? AND w.target_device_id = ? AND w.consumed = 0
                  AND EXISTS (
                      SELECT 1 FROM chat_group_members m
                      WHERE m.group_id = w.group_id AND m.user_id = w.target_user_id
                        AND m.device_id = w.target_device_id AND m.status = 'active'
                  )
                ORDER BY w.epoch ASC
                """,
                (user_id, device_id),
            )
            rows = cur.fetchall()
            if consume and rows:
                for r in rows:
                    cur.execute(
                        "UPDATE chat_group_welcomes SET consumed = 1 WHERE welcome_id = ?",
                        (r["welcome_id"],),
                    )
                chat_db._sqlite_conn.commit()

    out = []
    for r in rows:
        grp = get_mls_group(r["group_id"])
        out.append({
            "welcome_id": r["welcome_id"],
            "group_id": r["group_id"],
            "group_name": grp["name"] if grp else "Encrypted Group",
            "epoch": int(r["epoch"]),
            "mls_welcome_b64": r["mls_welcome_b64"],
            "ratchet_tree_b64": r["ratchet_tree_b64"],
            "timestamp": r["created_bucket"],
        })
    return out


def ack_welcome_consumed(welcome_id: str, user_id: str, device_id: str) -> bool:
    """
    Marks a specific MLS Welcome package consumed only after the client has
    durably imported the group state into its local IndexedDB vault.
    """
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE chat_group_welcomes
                    SET consumed = TRUE
                    WHERE welcome_id = %s AND target_user_id = %s AND target_device_id = %s;
                    """,
                    (welcome_id, user_id, device_id),
                )
                updated = cur.rowcount > 0
            conn.commit()
            return updated
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            """
            UPDATE chat_group_welcomes
            SET consumed = 1
            WHERE welcome_id = ? AND target_user_id = ? AND target_device_id = ?
            """,
            (welcome_id, user_id, device_id),
        )
        updated = cur.rowcount > 0
        chat_db._sqlite_conn.commit()
        return updated


def list_group_invitations_for_user(user_id: str) -> List[Dict[str, Any]]:
    """Groups an admin added this user to that are waiting for the user's Accept / Reject."""
    _ready()
    sql = """
        SELECT DISTINCT m.group_id, m.joined_epoch, m.updated_bucket
        FROM chat_group_members m
        WHERE m.user_id = {ph} AND m.status = 'invited'
    """
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(sql.format(ph="%s"), (user_id,))
                rows = [dict(r) for r in cur.fetchall()]
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(sql.format(ph="?"), (user_id,))
            rows = [dict(r) for r in cur.fetchall()]

    by_group: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        prev = by_group.get(r["group_id"])
        if not prev or int(r["joined_epoch"]) < int(prev["joined_epoch"]):
            by_group[r["group_id"]] = r
    if not by_group:
        return []

    loaded = _load_groups_batch(list(by_group.keys()))
    out: List[Dict[str, Any]] = []
    for gid, r in by_group.items():
        g = loaded.get(gid)
        if not g:
            continue
        inviter_id = _committer_of_epoch(gid, int(r["joined_epoch"])) or g["creator_user_id"]
        inviter = get_user_by_id(inviter_id) or {}
        creator = inviter if inviter_id == g["creator_user_id"] else (get_user_by_id(g["creator_user_id"]) or {})
        active_users = {m["user_id"] for m in g["members"] if m["status"] == "active"}
        pol = g.get("policy") or {}
        out.append({
            "group_id": gid,
            "group_name": g["name"],
            "description": pol.get("description") or "",
            "is_paid": bool(pol.get("is_paid")),
            "member_count": len(active_users),
            "invited_by_user_id": inviter_id,
            "invited_by_username": inviter.get("username"),
            "creator_username": creator.get("username"),
            "invited_at": r["updated_bucket"],
        })
    out.sort(key=lambda x: x["invited_at"] or "", reverse=True)
    return out


def _committer_of_epoch(group_id: str, epoch: int) -> Optional[str]:
    sql = "SELECT committer_user_id FROM chat_group_commits WHERE group_id = {ph} AND epoch = {ph}"
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(sql.format(ph="%s"), (group_id, epoch))
                row = cur.fetchone()
        finally:
            chat_db._pg_pool.putconn(conn)
        return row[0] if row else None
    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(sql.format(ph="?"), (group_id, epoch))
        row = cur.fetchone()
    return row[0] if row else None


def has_group_invitation(group_id: str, user_id: str) -> bool:
    return any(r["status"] == GROUP_INVITED_STATUS for r in get_member_record(group_id, user_id))


@auth_cache.invalidates_auth_cache(namespaces=('group', 'user_groups'))
def respond_to_group_invitation(group_id: str, user_id: str, accept: bool) -> bool:
    """
    Accept: the member becomes active and their waiting Welcome is released, so the app joins the group.
    Reject: the member is marked declined and the waiting Welcome is deleted; they never get the group keys.
    Returns False when there was no open invitation.
    """
    _ready()
    bucket = coarse_timestamp_iso()
    new_status = "active" if accept else GROUP_DECLINED_STATUS
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                if accept:
                    cur.execute(
                        """
                        UPDATE chat_group_members SET status = %s, updated_bucket = %s
                        WHERE group_id = %s AND user_id = %s AND status = 'invited';
                        """,
                        (new_status, bucket, group_id, user_id),
                    )
                else:
                    cur.execute(
                        """
                        UPDATE chat_group_members
                        SET status = %s, removed_epoch = joined_epoch - 1, updated_bucket = %s
                        WHERE group_id = %s AND user_id = %s AND status = 'invited';
                        """,
                        (new_status, bucket, group_id, user_id),
                    )
                changed = cur.rowcount
                if changed and not accept:
                    cur.execute(
                        "DELETE FROM chat_group_welcomes WHERE group_id = %s AND target_user_id = %s AND consumed = FALSE;",
                        (group_id, user_id),
                    )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            chat_db._pg_pool.putconn(conn)
        return changed > 0

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        try:
            if accept:
                cur.execute(
                    """
                    UPDATE chat_group_members SET status = ?, updated_bucket = ?
                    WHERE group_id = ? AND user_id = ? AND status = 'invited'
                    """,
                    (new_status, bucket, group_id, user_id),
                )
            else:
                cur.execute(
                    """
                    UPDATE chat_group_members
                    SET status = ?, removed_epoch = joined_epoch - 1, updated_bucket = ?
                    WHERE group_id = ? AND user_id = ? AND status = 'invited'
                    """,
                    (new_status, bucket, group_id, user_id),
                )
            changed = cur.rowcount
            if changed and not accept:
                cur.execute(
                    "DELETE FROM chat_group_welcomes WHERE group_id = ? AND target_user_id = ? AND consumed = 0",
                    (group_id, user_id),
                )
            chat_db._sqlite_conn.commit()
        except Exception:
            chat_db._sqlite_conn.rollback()
            raise
    return changed > 0


def list_group_commits(
    group_id: str,
    requester_user_id: str,
    after_epoch: int = 0,
) -> List[Dict[str, Any]]:
    """
    Returns ordered MLS Commits strictly for epochs the requester is authorized to observe
    (`epoch >= joined_epoch`, and if removed, `epoch <= removed_epoch`).
    """
    _ready()
    records = get_member_record(group_id, requester_user_id)
    if not records:
        raise PermissionError("User is not a member of this group")

    min_joined = min(r["joined_epoch"] for r in records)
    has_active = any(r["status"] == "active" for r in records)
    max_removed = max((r["removed_epoch"] or 0) for r in records)

    lower_epoch = max(after_epoch, min_joined - 1)

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                if has_active:
                    cur.execute(
                        """
                        SELECT commit_id, group_id, epoch, committer_user_id, committer_device_id,
                               commit_type, mls_commit_b64, ratchet_tree_b64, created_bucket
                        FROM chat_group_commits
                        WHERE group_id = %s AND epoch > %s
                        ORDER BY epoch ASC;
                        """,
                        (group_id, lower_epoch),
                    )
                else:
                    cur.execute(
                        """
                        SELECT commit_id, group_id, epoch, committer_user_id, committer_device_id,
                               commit_type, mls_commit_b64, ratchet_tree_b64, created_bucket
                        FROM chat_group_commits
                        WHERE group_id = %s AND epoch > %s AND epoch <= %s
                        ORDER BY epoch ASC;
                        """,
                        (group_id, lower_epoch, max_removed),
                    )
                rows = cur.fetchall()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            if has_active:
                cur.execute(
                    """
                    SELECT commit_id, group_id, epoch, committer_user_id, committer_device_id,
                           commit_type, mls_commit_b64, ratchet_tree_b64, created_bucket
                    FROM chat_group_commits
                    WHERE group_id = ? AND epoch > ?
                    ORDER BY epoch ASC
                    """,
                    (group_id, lower_epoch),
                )
            else:
                cur.execute(
                    """
                    SELECT commit_id, group_id, epoch, committer_user_id, committer_device_id,
                           commit_type, mls_commit_b64, ratchet_tree_b64, created_bucket
                    FROM chat_group_commits
                    WHERE group_id = ? AND epoch > ? AND epoch <= ?
                    ORDER BY epoch ASC
                    """,
                    (group_id, lower_epoch, max_removed),
                )
            rows = cur.fetchall()

    return [
        {
            "commit_id": r["commit_id"],
            "group_id": r["group_id"],
            "epoch": int(r["epoch"]),
            "committer_user_id": r["committer_user_id"],
            "committer_device_id": r["committer_device_id"],
            "commit_type": r["commit_type"],
            "mls_commit_b64": r["mls_commit_b64"],
            "ratchet_tree_b64": r["ratchet_tree_b64"],
            "timestamp": r["created_bucket"],
        }
        for r in rows
    ]


def insert_group_ciphertext(
    message_id: str,
    group_id: str,
    epoch: int,
    sender_user_id: str,
    sender_device_id: str,
    mls_ciphertext_b64: str,
    attachment_ids: Optional[List[str]] = None,
    event_kind: str = "message",
    expires_at: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Validates that `sender_user_id`/`sender_device_id` is an active member of `group_id`
    and `epoch == current_epoch`, then stores the MLS PrivateMessage ciphertext.
    """
    _ready()
    grp = get_mls_group(group_id)
    if not grp:
        raise ValueError("Group not found")
    if not is_active_group_member(group_id, sender_user_id, sender_device_id):
        raise PermissionError("Sender device is not an active member of this encrypted group")
    if int(grp["current_epoch"]) != int(epoch):
        raise EpochConflictError(current_epoch=int(grp["current_epoch"]), expected_epoch=int(epoch))

    bucket = coarse_timestamp_iso()
    att_list = attachment_ids or []
    event_kind = _clean_event_kind(event_kind)

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            # UNIQUE(message_id) + ON CONFLICT DO NOTHING + autocommit => ONE round trip.
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO chat_group_messages (
                        message_id, group_id, epoch, sender_user_id, sender_device_id,
                        mls_ciphertext_b64, attachment_ids_json, created_bucket, event_kind, expires_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (message_id) DO NOTHING
                    RETURNING seq;
                    """,
                    (
                        message_id, group_id, epoch, sender_user_id, sender_device_id,
                        mls_ciphertext_b64, json.dumps(att_list), bucket, event_kind, expires_at,
                    ),
                )
                row = cur.fetchone()
                if not row:
                    raise DuplicateMessageError(f"Duplicate group message_id rejected: {message_id}")
                seq = int(row[0])
        finally:
            try:
                conn.autocommit = False
            except Exception:
                pass
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                INSERT OR IGNORE INTO chat_group_messages (
                    message_id, group_id, epoch, sender_user_id, sender_device_id,
                    mls_ciphertext_b64, attachment_ids_json, created_bucket, event_kind, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_id, group_id, epoch, sender_user_id, sender_device_id,
                    mls_ciphertext_b64, json.dumps(att_list), bucket, event_kind, expires_at,
                ),
            )
            if cur.rowcount == 0:
                chat_db._sqlite_conn.rollback()
                raise DuplicateMessageError(f"Duplicate group message_id rejected: {message_id}")
            seq = int(cur.lastrowid or 0)
            chat_db._sqlite_conn.commit()

    return {
        "seq": seq,
        "message_id": message_id,
        "group_id": group_id,
        "epoch": epoch,
        "sender_user_id": sender_user_id,
        "sender_device_id": sender_device_id,
        "mls_ciphertext_b64": mls_ciphertext_b64,
        "attachment_ids": att_list,
        "timestamp": bucket,
        "event_kind": event_kind,
        "expires_at": expires_at,
    }


def list_group_ciphertexts(
    group_id: str,
    requester_user_id: str,
    after_seq: int = 0,
    limit: int = 60,
) -> List[Dict[str, Any]]:
    """
    Enforces group membership and epoch boundaries on ciphertext retrieval:
    - Non-members receive PermissionError (HTTP 403).
    - Members with `history_sharing_mode == 'none'` only receive messages from
      `epoch >= joined_epoch`.
    - Removed members cannot retrieve messages from `epoch >= removed_epoch` (and if
      completely removed, are rejected from live group feeds).
    """
    _ready()
    grp = get_mls_group(group_id)
    if not grp:
        raise ValueError("Group not found")

    records = get_member_record(group_id, requester_user_id)
    if not records:
        raise PermissionError("Not authorized to access this group")

    active_records = [r for r in records if r["status"] == "active"]
    if not active_records:
        raise PermissionError("Member has been removed from this group and cannot fetch group feed")

    min_joined_epoch = min(r["joined_epoch"] for r in active_records)
    min_epoch = min_joined_epoch if grp["history_sharing_mode"] == "none" else 0
    bounded = max(1, min(limit, 100))

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT seq, message_id, group_id, epoch, sender_user_id, sender_device_id,
                           mls_ciphertext_b64, attachment_ids_json, created_bucket,
                           event_kind, deleted_at, expires_at
                    FROM chat_group_messages
                    WHERE group_id = %s AND epoch >= %s AND seq > %s
                    ORDER BY seq ASC
                    LIMIT %s;
                    """,
                    (group_id, min_epoch, after_seq, bounded),
                )
                rows = cur.fetchall()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                SELECT seq, message_id, group_id, epoch, sender_user_id, sender_device_id,
                       mls_ciphertext_b64, attachment_ids_json, created_bucket,
                       event_kind, deleted_at, expires_at
                FROM chat_group_messages
                WHERE group_id = ? AND epoch >= ? AND seq > ?
                ORDER BY seq ASC
                LIMIT ?
                """,
                (group_id, min_epoch, after_seq, bounded),
            )
            rows = cur.fetchall()

    now = now_utc()
    out: List[Dict[str, Any]] = []
    for r in rows:
        expires = _as_dt(r["expires_at"])
        if expires and expires <= now:
            continue  # disappeared (group encryption tolerates gaps, so nothing has to be kept)
        deleted = bool(r["deleted_at"])
        out.append({
            "seq": int(r["seq"]),
            "message_id": r["message_id"],
            "group_id": r["group_id"],
            "epoch": int(r["epoch"]),
            "sender_user_id": r["sender_user_id"],
            "sender_device_id": r["sender_device_id"],
            "mls_ciphertext_b64": "" if deleted else r["mls_ciphertext_b64"],
            "attachment_ids": [] if deleted else _parse_json(r["attachment_ids_json"], []),
            "timestamp": r["created_bucket"],
            "event_kind": r["event_kind"] or "message",
            "deleted": deleted,
            "expires_at": expires.isoformat() if expires else None,
        })
    return out


# ============================================================================
# 6. ENCRYPTED FILE ATTACHMENTS (CIPHERTEXT-ONLY STORAGE & REVOCATION)
# ============================================================================

def encrypted_attachment_usage_since(uploader_user_id: str, since_iso: str) -> Dict[str, int]:
    """How many encrypted files (and bytes) this member uploaded since `since_iso` (for the daily limit)."""
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*), COALESCE(SUM(byte_length), 0) FROM chat_encrypted_attachments "
                    "WHERE uploader_user_id = %s AND created_bucket >= %s;",
                    (uploader_user_id, since_iso),
                )
                n, b = cur.fetchone()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(byte_length), 0) AS b FROM chat_encrypted_attachments "
                "WHERE uploader_user_id = ? AND created_bucket >= ?",
                (uploader_user_id, since_iso),
            )
            row = cur.fetchone()
            n, b = row[0], row[1]
    return {"files": int(n or 0), "bytes": int(b or 0)}


def store_encrypted_attachment(
    scope_type: str,
    scope_id: str,
    uploader_user_id: str,
    uploader_device_id: str,
    algorithm: str,
    ciphertext_b64: str,
    ciphertext_sha256: str,
    byte_length: int,
) -> Dict[str, Any]:
    _ready()
    attachment_id = f"att_{secrets.token_hex(14)}"
    bucket = coarse_timestamp_iso()

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO chat_encrypted_attachments (
                        attachment_id, scope_type, scope_id, uploader_user_id,
                        uploader_device_id, algorithm, ciphertext_b64,
                        ciphertext_sha256, byte_length, revoked, created_bucket
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, FALSE, %s);
                    """,
                    (
                        attachment_id,
                        scope_type,
                        scope_id,
                        uploader_user_id,
                        uploader_device_id,
                        algorithm,
                        ciphertext_b64,
                        ciphertext_sha256,
                        byte_length,
                        bucket,
                    ),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                INSERT INTO chat_encrypted_attachments (
                    attachment_id, scope_type, scope_id, uploader_user_id,
                    uploader_device_id, algorithm, ciphertext_b64,
                    ciphertext_sha256, byte_length, revoked, created_bucket
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    attachment_id,
                    scope_type,
                    scope_id,
                    uploader_user_id,
                    uploader_device_id,
                    algorithm,
                    ciphertext_b64,
                    ciphertext_sha256,
                    byte_length,
                    bucket,
                ),
            )
            chat_db._sqlite_conn.commit()

    return {
        "attachment_id": attachment_id,
        "scope_type": scope_type,
        "scope_id": scope_id,
        "uploader_user_id": uploader_user_id,
        "algorithm": algorithm,
        "ciphertext_sha256": ciphertext_sha256,
        "byte_length": byte_length,
        "revoked": False,
        "timestamp": bucket,
    }


def get_encrypted_attachment(attachment_id: str) -> Optional[Dict[str, Any]]:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT attachment_id, scope_type, scope_id, uploader_user_id,
                           uploader_device_id, algorithm, ciphertext_b64,
                           ciphertext_sha256, byte_length, revoked, created_bucket
                    FROM chat_encrypted_attachments WHERE attachment_id = %s;
                    """,
                    (attachment_id,),
                )
                r = cur.fetchone()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                SELECT attachment_id, scope_type, scope_id, uploader_user_id,
                       uploader_device_id, algorithm, ciphertext_b64,
                       ciphertext_sha256, byte_length, revoked, created_bucket
                FROM chat_encrypted_attachments WHERE attachment_id = ?
                """,
                (attachment_id,),
            )
            r = cur.fetchone()

    if not r:
        return None
    return {
        "attachment_id": r["attachment_id"],
        "scope_type": r["scope_type"],
        "scope_id": r["scope_id"],
        "uploader_user_id": r["uploader_user_id"],
        "uploader_device_id": r["uploader_device_id"],
        "algorithm": r["algorithm"],
        "ciphertext_b64": r["ciphertext_b64"],
        "ciphertext_sha256": r["ciphertext_sha256"],
        "byte_length": int(r["byte_length"]),
        "revoked": bool(r["revoked"]),
        "timestamp": r["created_bucket"],
    }


def revoke_encrypted_attachment(attachment_id: str, requester_user_id: str) -> bool:
    _ready()
    att = get_encrypted_attachment(attachment_id)
    if not att:
        raise ValueError("Attachment not found")
    if att["uploader_user_id"] != requester_user_id:
        raise PermissionError("Only the uploader can revoke an encrypted attachment")

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE chat_encrypted_attachments
                    SET revoked = TRUE, ciphertext_b64 = ''
                    WHERE attachment_id = %s;
                    """,
                    (attachment_id,),
                )
            conn.commit()
            return True
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            """
            UPDATE chat_encrypted_attachments
            SET revoked = 1, ciphertext_b64 = ''
            WHERE attachment_id = ?
            """,
            (attachment_id,),
        )
        chat_db._sqlite_conn.commit()
        return True

# ============================================================================
# 7. DELETE FOR EVERYONE & DISAPPEARING MESSAGES
# ============================================================================
# The server never sees message text. It can still really remove the encrypted copy it stores:
# - Group messages (MLS) are removed outright: MLS copes with a missing message.
# - Private messages (Olm) keep only per-device copies of type 0 ("pre-key"): such a copy sets up a
#   device's encrypted session, and dropping one a device has not fetched yet would leave that device
#   unable to read the rest of the conversation. It stays encrypted (the server cannot read it) and the
#   app never shows or stores its text. Every normal copy (type 1) is removed.

EVENT_KINDS = ("message", "control")
DELETE_FOR_EVERYONE_HOURS = 48


class MessageDeleteError(Exception):
    def __init__(self, message: str, status: int = 403):
        super().__init__(message)
        self.status = status


def _clean_event_kind(kind: Any) -> str:
    k = str(kind or "message").strip().lower()
    if k not in EVENT_KINDS:
        raise ValueError("event_kind must be 'message' or 'control'")
    return k


def _as_dt(val: Any) -> Optional[datetime]:
    """A stored timestamp (datetime from PostgreSQL, ISO text from SQLite) as an aware datetime."""
    if val is None or val == "":
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(val).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _setup_copies_only(ct_map: Any) -> Dict[str, Any]:
    """Keeps only the session-setup (type 0) per-device copies of a private message."""
    if not isinstance(ct_map, dict):
        return {}
    return {d: c for d, c in ct_map.items() if isinstance(c, dict) and int(c.get("message_type", 1)) == 0}


def _within_delete_window(created_bucket: Any) -> bool:
    created = _as_dt(created_bucket)
    # created_bucket is rounded down to the minute: allow that minute on top of the window
    return bool(created and now_utc() - created <= timedelta(hours=DELETE_FOR_EVERYONE_HOURS, minutes=1))


def delete_dm_message(message_id: str, requester_user_id: str) -> Dict[str, Any]:
    """Delete for everyone (private chat): only the sender, within 48 hours. Idempotent."""
    _ready()
    q = (
        "SELECT message_id, conversation_id, sender_user_id, recipient_user_id, ciphertexts_json, "
        "created_bucket, deleted_at, event_kind FROM chat_dm_messages WHERE message_id = {p}"
    )
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(q.format(p="%s") + " FOR UPDATE;", (message_id,))
                row = cur.fetchone()
                if not row:
                    conn.rollback()
                    raise MessageDeleteError("Message not found", 404)
                _check_dm_delete(row, requester_user_id)
                if not row["deleted_at"]:
                    cur.execute(
                        "UPDATE chat_dm_messages SET deleted_at = %s, ciphertexts_json = %s, attachment_ids_json = '[]' "
                        "WHERE message_id = %s;",
                        (now_utc().isoformat(), json.dumps(_setup_copies_only(_parse_json(row["ciphertexts_json"], {}))), message_id),
                    )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(q.format(p="?"), (message_id,))
            row = cur.fetchone()
            if not row:
                raise MessageDeleteError("Message not found", 404)
            _check_dm_delete(row, requester_user_id)
            if not row["deleted_at"]:
                cur.execute(
                    "UPDATE chat_dm_messages SET deleted_at = ?, ciphertexts_json = ?, attachment_ids_json = '[]' "
                    "WHERE message_id = ?",
                    (now_utc().isoformat(), json.dumps(_setup_copies_only(_parse_json(row["ciphertexts_json"], {}))), message_id),
                )
                chat_db._sqlite_conn.commit()
    return {
        "message_id": message_id,
        "conversation_id": row["conversation_id"],
        "sender_user_id": row["sender_user_id"],
        "recipient_user_id": row["recipient_user_id"],
    }


def _check_dm_delete(row: Any, requester_user_id: str) -> None:
    if row["sender_user_id"] != requester_user_id:
        raise MessageDeleteError("Only the sender can delete this message for everyone", 403)
    if (row["event_kind"] or "message") != "message":
        raise MessageDeleteError("Only messages can be deleted", 400)
    if not row["deleted_at"] and not _within_delete_window(row["created_bucket"]):
        raise MessageDeleteError(f"Messages can be deleted for everyone within {DELETE_FOR_EVERYONE_HOURS} hours", 403)


def delete_group_message(group_id: str, message_id: str, requester_user_id: str, requester_is_admin: bool) -> Dict[str, Any]:
    """Delete for everyone (group): the sender within 48 hours, or a group admin at any time. Idempotent."""
    _ready()
    q = (
        "SELECT message_id, group_id, sender_user_id, created_bucket, deleted_at, event_kind "
        "FROM chat_group_messages WHERE message_id = {p} AND group_id = {p}"
    )

    def check(row: Any) -> None:
        if (row["event_kind"] or "message") != "message":
            raise MessageDeleteError("Only messages can be deleted", 400)
        if requester_is_admin or row["deleted_at"]:
            return
        if row["sender_user_id"] != requester_user_id:
            raise MessageDeleteError("Only the sender or a group admin can delete this message for everyone", 403)
        if not _within_delete_window(row["created_bucket"]):
            raise MessageDeleteError(f"Messages can be deleted for everyone within {DELETE_FOR_EVERYONE_HOURS} hours", 403)

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(q.format(p="%s") + " FOR UPDATE;", (message_id, group_id))
                row = cur.fetchone()
                if not row:
                    conn.rollback()
                    raise MessageDeleteError("Message not found", 404)
                check(row)
                if not row["deleted_at"]:
                    cur.execute(
                        "UPDATE chat_group_messages SET deleted_at = %s, mls_ciphertext_b64 = '', attachment_ids_json = '[]' "
                        "WHERE message_id = %s;",
                        (now_utc().isoformat(), message_id),
                    )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(q.format(p="?"), (message_id, group_id))
            row = cur.fetchone()
            if not row:
                raise MessageDeleteError("Message not found", 404)
            check(row)
            if not row["deleted_at"]:
                cur.execute(
                    "UPDATE chat_group_messages SET deleted_at = ?, mls_ciphertext_b64 = '', attachment_ids_json = '[]' "
                    "WHERE message_id = ?",
                    (now_utc().isoformat(), message_id),
                )
                chat_db._sqlite_conn.commit()
    return {"message_id": message_id, "group_id": group_id, "sender_user_id": row["sender_user_id"]}


def message_exists_in_scope(scope_type: str, scope_id: str, message_id: str) -> bool:
    """True when the (not deleted) message belongs to that private chat (conversation id) or group."""
    _ready()
    if scope_type == "dm":
        q = "SELECT 1 FROM chat_dm_messages WHERE message_id = {p} AND conversation_id = {p} AND deleted_at IS NULL"
    else:
        q = "SELECT 1 FROM chat_group_messages WHERE message_id = {p} AND group_id = {p} AND deleted_at IS NULL"
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(q.format(p="%s") + ";", (message_id, scope_id))
                return cur.fetchone() is not None
        finally:
            chat_db._pg_pool.putconn(conn)
    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(q.format(p="?"), (message_id, scope_id))
        return cur.fetchone() is not None


def purge_expired_messages() -> Dict[str, int]:
    """Removes the stored encrypted copies of disappearing messages whose time is up.
    Group rows are deleted. Private rows keep only undelivered session-setup copies (see above),
    and are deleted once none is left."""
    _ready()
    now_iso = now_utc().isoformat()
    removed = {"group": 0, "dm_rows": 0, "dm_trimmed": 0}
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute("DELETE FROM chat_group_messages WHERE expires_at IS NOT NULL AND expires_at <= %s;", (now_iso,))
                removed["group"] = int(cur.rowcount or 0)
                cur.execute(
                    "SELECT message_id, ciphertexts_json FROM chat_dm_messages "
                    "WHERE expires_at IS NOT NULL AND expires_at <= %s FOR UPDATE;",
                    (now_iso,),
                )
                for r in cur.fetchall():
                    keep = _setup_copies_only(_parse_json(r["ciphertexts_json"], {}))
                    if keep:
                        cur.execute(
                            "UPDATE chat_dm_messages SET ciphertexts_json = %s, attachment_ids_json = '[]' WHERE message_id = %s;",
                            (json.dumps(keep), r["message_id"]),
                        )
                        removed["dm_trimmed"] += 1
                    else:
                        cur.execute("DELETE FROM chat_dm_messages WHERE message_id = %s;", (r["message_id"],))
                        removed["dm_rows"] += 1
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            chat_db._pg_pool.putconn(conn)
        return removed
    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute("DELETE FROM chat_group_messages WHERE expires_at IS NOT NULL AND expires_at <= ?", (now_iso,))
        removed["group"] = int(cur.rowcount or 0)
        cur.execute(
            "SELECT message_id, ciphertexts_json FROM chat_dm_messages WHERE expires_at IS NOT NULL AND expires_at <= ?",
            (now_iso,),
        )
        for r in cur.fetchall():
            keep = _setup_copies_only(_parse_json(r["ciphertexts_json"], {}))
            if keep:
                cur.execute(
                    "UPDATE chat_dm_messages SET ciphertexts_json = ?, attachment_ids_json = '[]' WHERE message_id = ?",
                    (json.dumps(keep), r["message_id"]),
                )
                removed["dm_trimmed"] += 1
            else:
                cur.execute("DELETE FROM chat_dm_messages WHERE message_id = ?", (r["message_id"],))
                removed["dm_rows"] += 1
        chat_db._sqlite_conn.commit()
    return removed