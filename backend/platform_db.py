"""
Unified Relational Platform Database Layer (Neon PostgreSQL + SQLite Fallback).

Implements all non-payment chatting platform entities anchored to permanent `user_id`:
- Extended user profiles, username history & reservation quarantine, wallet change history
- Configurable Wallet-Based Levels (starting at Level 7), RPC balance snapshots & level history
- Open Public Chat (readable feed, configurable guest policy, edit/delete, retention)
- Username search directory, user blocks, DM read receipts, abuse reports & moderation actions
- Group access policies (min_level, min_eth_balance_wei, visibility), invite links, join requests & leave-group
- Role-based Admin roles (`superadmin`, `moderator`), platform settings & immutable audit logs
"""

import os
import sys
import json
import secrets
import sqlite3
import logging
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple, Union
from web3 import Web3

import chat_db
import e2ee_db

import auth_cache

logger = logging.getLogger(__name__)
_platform_tables_initialized = False

_user_qualification_locks: Dict[str, threading.Lock] = {}
_locks_meta_lock = threading.Lock()


def _get_user_qualification_lock(user_id: str) -> threading.Lock:
    with _locks_meta_lock:
        if user_id not in _user_qualification_locks:
            _user_qualification_locks[user_id] = threading.Lock()
        return _user_qualification_locks[user_id]

DEFAULT_PLATFORM_SETTINGS: Dict[str, Any] = {
    "public_chat_max_length": 1000,
    "public_chat_edit_window_seconds": 900,
    "public_chat_retention_days": 90,
    "username_cooldown_hours": 24,
    "username_reservation_days": 30,
    "balance_reeval_minutes": 30,
    "default_balance_chain_id": int(os.getenv("EXPECTED_CHAIN_ID") or 11155111),
    "authorized_payment_destination": os.getenv("AUTHORIZED_PAYMENT_DESTINATION") or "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "allowed_payment_chain_ids": [1, 11155111],
    # Membership price is set in USD by the admin and converted to ETH at the live rate.
    # Production default is $10. Automated tests default to $0 (free) so they can focus on
    # other features; paywall tests switch it on explicitly.
    "platform_entry_fee_usd": os.getenv(
        "PLATFORM_ENTRY_FEE_USD",
        "0" if (os.getenv("TESTING") == "1" or "unittest" in sys.modules or "pytest" in sys.modules) else "10",
    ),
    "use_live_eth_price": True,
    # Fixed ETH/USD rate: used when live pricing is off or every live source is unreachable.
    "eth_usd_price": float(os.getenv("ETH_USD_PRICE", "2500.0")),
    # Legacy (ETH-denominated) fee. Kept for old databases; no longer used for pricing.
    "platform_entry_fee_eth": os.getenv("PLATFORM_ENTRY_FEE_ETH", "0.01"),
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def _iso(val: Any) -> Optional[str]:
    if val is None:
        return None
    if hasattr(val, "isoformat"):
        return val.isoformat()
    return str(val)


def _jload(val: Any, fallback: Any) -> Any:
    if val is None:
        return fallback
    if isinstance(val, (dict, list, bool, int, float)):
        return val
    try:
        return json.loads(val)
    except Exception:
        if isinstance(val, str) and isinstance(fallback, str):
            return val
        return fallback


def _is_pg() -> bool:
    return e2ee_db._is_pg()


def _sqlite_add_col_safe(cur: Any, table: str, col_def: str) -> None:
    try:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {col_def};")
    except Exception:
        pass


def ensure_platform_tables() -> None:
    """Idempotently creates and upgrades all platform tables on PostgreSQL or SQLite."""
    global _platform_tables_initialized
    if not e2ee_db._e2ee_tables_initialized:
        e2ee_db.ensure_e2ee_tables()
    if _platform_tables_initialized:
        return

    if _is_pg():
        mig_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "migrations")
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                for mig_file in (
                    "001_chat_platform_schema.sql",
                    "002_drop_legacy_subscription_columns.sql",
                    "003_server_verified_payments.sql",
                    "004_level_min_payment_requirement.sql",
                    "005_authorized_payment_destination.sql",
                    "006_paid_membership_and_groups.sql",
                    "007_group_entry_fee_usd.sql",
                    "008_support_threads.sql",
                ):
                    mig_path = os.path.join(mig_dir, mig_file)
                    if os.path.exists(mig_path):
                        with open(mig_path, "r", encoding="utf-8") as f:
                            cur.execute(f.read())
            conn.commit()
            _platform_tables_initialized = True
        finally:
            chat_db._pg_pool.putconn(conn)
        seed_default_settings()
        return

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        for col_def in (
            "display_name TEXT",
            "bio TEXT",
            "avatar_url TEXT",
            "username_changed_at TEXT",
            "current_level INTEGER NOT NULL DEFAULT 7",
            "highest_level INTEGER NOT NULL DEFAULT 7",
            "qualifying_balance_wei TEXT NOT NULL DEFAULT '0'",
            "qualifying_chain_id INTEGER NOT NULL DEFAULT 1",
            "last_balance_verified_at TEXT",
            "level_grace_expires_at TEXT",
            "account_status TEXT NOT NULL DEFAULT 'active'",
            "suspended_until TEXT",
            "suspension_reason TEXT",
            "show_online_presence INTEGER NOT NULL DEFAULT 1",
            "send_read_receipts INTEGER NOT NULL DEFAULT 1",
            "is_platform_paid INTEGER NOT NULL DEFAULT 0",
            "platform_paid_at TEXT",
        ):
            _sqlite_add_col_safe(cur, "chat_users", col_def)

        _sqlite_add_col_safe(cur, "level_definitions", "min_payment_wei TEXT NOT NULL DEFAULT '0'")
        _sqlite_add_col_safe(cur, "group_access_policies", "is_paid INTEGER NOT NULL DEFAULT 0")
        _sqlite_add_col_safe(cur, "group_access_policies", "entry_fee_eth TEXT NOT NULL DEFAULT '0'")
        _sqlite_add_col_safe(cur, "group_access_policies", "entry_fee_usd TEXT NOT NULL DEFAULT '0'")
        _sqlite_add_col_safe(cur, "group_access_policies", "entry_fee_wei TEXT NOT NULL DEFAULT '0'")

        cur.executescript("""
            CREATE TABLE IF NOT EXISTS username_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                old_username TEXT,
                new_username TEXT NOT NULL,
                reserved_until TEXT,
                changed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_username_hist_user ON username_history(user_id, changed_at DESC);

            CREATE TABLE IF NOT EXISTS wallet_change_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                old_wallet TEXT,
                new_wallet TEXT,
                performed_by TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_wallet_hist_user ON wallet_change_history(user_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS level_definitions (
                level INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                min_balance_wei TEXT NOT NULL DEFAULT '0',
                min_payment_wei TEXT NOT NULL DEFAULT '0',
                max_balance_wei TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                privileges_json TEXT NOT NULL DEFAULT '{}',
                policy_version INTEGER NOT NULL DEFAULT 1,
                effective_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS wallet_balance_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                wallet_address TEXT NOT NULL,
                chain_id INTEGER NOT NULL,
                balance_wei TEXT NOT NULL,
                block_number INTEGER NOT NULL,
                rpc_source TEXT NOT NULL DEFAULT 'verified_rpc',
                verified_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_bal_snap_user ON wallet_balance_snapshots(user_id, verified_at DESC);

            CREATE TABLE IF NOT EXISTS level_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                previous_level INTEGER NOT NULL,
                new_level INTEGER NOT NULL,
                qualifying_balance_wei TEXT NOT NULL,
                block_number INTEGER,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS public_chat_messages (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL UNIQUE,
                author_user_id TEXT,
                guest_id TEXT,
                display_name TEXT NOT NULL,
                author_level INTEGER NOT NULL DEFAULT 7,
                is_guest INTEGER NOT NULL DEFAULT 0,
                content TEXT NOT NULL,
                edited_at TEXT,
                deleted INTEGER NOT NULL DEFAULT 0,
                deleted_by TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS group_access_policies (
                group_id TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                avatar_url TEXT,
                visibility TEXT NOT NULL DEFAULT 'invite_only',
                min_level INTEGER NOT NULL DEFAULT 7,
                min_eth_balance_wei TEXT NOT NULL DEFAULT '0',
                require_invitation INTEGER NOT NULL DEFAULT 1,
                is_paid INTEGER NOT NULL DEFAULT 0,
                entry_fee_eth TEXT NOT NULL DEFAULT '0',
                entry_fee_usd TEXT NOT NULL DEFAULT '0',
                entry_fee_wei TEXT NOT NULL DEFAULT '0',
                updated_by TEXT,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS group_invite_links (
                invite_code TEXT PRIMARY KEY,
                group_id TEXT NOT NULL,
                created_by TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                max_uses INTEGER NOT NULL DEFAULT 25,
                use_count INTEGER NOT NULL DEFAULT 0,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS group_join_requests (
                request_id TEXT PRIMARY KEY,
                group_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                invite_code TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                reviewed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS user_blocks (
                blocker_user_id TEXT NOT NULL,
                blocked_user_id TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                PRIMARY KEY (blocker_user_id, blocked_user_id)
            );

            CREATE TABLE IF NOT EXISTS chat_dm_receipts (
                conversation_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                last_read_seq INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (conversation_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS message_reports (
                report_id TEXT PRIMARY KEY,
                reporter_user_id TEXT NOT NULL,
                target_user_id TEXT,
                scope_type TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                message_id TEXT,
                reason TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open',
                resolution_note TEXT,
                reviewed_by TEXT,
                reviewed_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS moderation_actions (
                action_id TEXT PRIMARY KEY,
                moderator_user_id TEXT NOT NULL,
                target_user_id TEXT,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS admin_roles (
                user_id TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                granted_by TEXT NOT NULL,
                granted_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS platform_settings (
                setting_key TEXT PRIMARY KEY,
                setting_value_json TEXT NOT NULL,
                updated_by TEXT,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS payment_records (
                payment_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES chat_users(user_id),
                wallet_address TEXT,
                recipient_address TEXT,
                amount_atomic TEXT NOT NULL DEFAULT '0',
                amount_formatted TEXT NOT NULL DEFAULT '0',
                currency TEXT NOT NULL DEFAULT 'ETH',
                network TEXT NOT NULL DEFAULT 'ethereum',
                chain_id INTEGER,
                status TEXT NOT NULL DEFAULT 'pending',
                transaction_reference TEXT NOT NULL UNIQUE,
                block_number INTEGER,
                verification_source TEXT NOT NULL DEFAULT 'ethereum_rpc',
                verified_at TEXT,
                error_message TEXT,
                retry_count INTEGER NOT NULL DEFAULT 0,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                purpose TEXT NOT NULL DEFAULT 'platform_entry',
                target_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_records_tx_ref ON payment_records(transaction_reference);
            CREATE INDEX IF NOT EXISTS idx_payment_records_user ON payment_records(user_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_payment_records_status ON payment_records(status);
            CREATE INDEX IF NOT EXISTS idx_payment_records_recipient ON payment_records(recipient_address);
            CREATE INDEX IF NOT EXISTS idx_payment_records_purpose_target ON payment_records(purpose, target_id);
            CREATE INDEX IF NOT EXISTS idx_group_policies_is_paid ON group_access_policies(is_paid);
        """)
        _sqlite_add_col_safe(cur, "payment_records", "recipient_address TEXT")
        _sqlite_add_col_safe(cur, "payment_records", "purpose TEXT NOT NULL DEFAULT 'platform_entry'")
        _sqlite_add_col_safe(cur, "payment_records", "target_id TEXT")
        chat_db._sqlite_conn.commit()
        _platform_tables_initialized = True

    seed_default_settings()


def _ready() -> None:
    if not _platform_tables_initialized:
        ensure_platform_tables()


@auth_cache.invalidates_auth_cache(namespaces=('settings',))
def seed_default_settings() -> None:
    ts = _now_iso()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                for k, v in DEFAULT_PLATFORM_SETTINGS.items():
                    cur.execute(
                        """
                        INSERT INTO platform_settings (setting_key, setting_value_json, updated_by, updated_at)
                        VALUES (%s, %s::jsonb, 'system', %s)
                        ON CONFLICT (setting_key) DO NOTHING;
                        """,
                        (k, json.dumps(v), ts),
                    )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
        return

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        for k, v in DEFAULT_PLATFORM_SETTINGS.items():
            cur.execute(
                """
                INSERT OR IGNORE INTO platform_settings (setting_key, setting_value_json, updated_by, updated_at)
                VALUES (?, ?, 'system', ?)
                """,
                (k, json.dumps(v), ts),
            )
        chat_db._sqlite_conn.commit()


# ============================================================================
# AUDIT LOGS & PLATFORM SETTINGS
# ============================================================================

FORBIDDEN_AUDIT_KEYS = {
    "private_key",
    "secret",
    "plaintext",
    "decrypted",
    "password",
    "auth_token",
    "session_token",
    "admin_token",
    "vault_key",
    "device_key",
    "seed_phrase",
    "mnemonic",
    "signature",
}


def _sanitize_audit_details(details: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Recursively strips sensitive secrets from audit log details:
    never logs private keys, auth secrets, decrypted E2EE content,
    or raw cryptographic signatures.
    """
    if not details:
        return {}
    sanitized: Dict[str, Any] = {}
    for k, v in details.items():
        k_lower = str(k).lower()
        if any(fk in k_lower for fk in FORBIDDEN_AUDIT_KEYS):
            continue
        if isinstance(v, dict):
            sanitized[k] = _sanitize_audit_details(v)
        elif isinstance(v, list):
            sanitized[k] = [
                _sanitize_audit_details(item) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            sanitized[k] = v
    return sanitized


def record_audit_log(
    actor_user_id: str,
    action: str,
    entity_type: str,
    entity_id: str,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    _ready()
    ts = _now_iso()
    clean_details = _sanitize_audit_details(details)
    if "event_type" not in clean_details:
        clean_details["event_type"] = action
    if "timestamp" not in clean_details:
        clean_details["timestamp"] = ts
    d_json = json.dumps(clean_details)
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            conn.autocommit = True  # single atomic INSERT: one round trip, no separate COMMIT
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO audit_logs (actor_user_id, action, entity_type, entity_id, details_json, created_at)
                    VALUES (%s, %s, %s, %s, %s::jsonb, %s);
                    """,
                    (actor_user_id, action, entity_type, entity_id, d_json, ts),
                )
        finally:
            try:
                conn.autocommit = False
            except Exception:
                pass
            chat_db._pg_pool.putconn(conn)
        return

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            """
            INSERT INTO audit_logs (actor_user_id, action, entity_type, entity_id, details_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (actor_user_id, action, entity_type, entity_id, d_json, ts),
        )
        chat_db._sqlite_conn.commit()


def list_audit_logs(
    limit: int = 100,
    action: Optional[str] = None,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    _ready()
    lim = max(1, min(int(limit), 500))
    if _is_pg():
        where_parts: List[str] = []
        params: List[Any] = []
        if action:
            where_parts.append("action = %s")
            params.append(action)
        if entity_type:
            where_parts.append("entity_type = %s")
            params.append(entity_type)
        if entity_id:
            where_parts.append("entity_id = %s")
            params.append(str(entity_id))
        where_sql = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""
        params.append(lim)

        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    f"""
                    SELECT log_id, actor_user_id, action, entity_type, entity_id, details_json, created_at
                    FROM audit_logs {where_sql} ORDER BY log_id DESC LIMIT %s;
                    """,
                    tuple(params),
                )
                res = []
                for r in cur.fetchall():
                    d = _jload(r["details_json"], {})
                    res.append({
                        "log_id": int(r["log_id"]),
                        "audit_id": int(r["log_id"]),
                        "actor_user_id": r["actor_user_id"],
                        "action": r["action"],
                        "event_type": d.get("event_type") or r["action"],
                        "entity_type": r["entity_type"],
                        "target_type": r["entity_type"],
                        "entity_id": r["entity_id"],
                        "target_id": r["entity_id"],
                        "details": d,
                        "created_at": _iso(r["created_at"]),
                    })
                return res
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        where_parts = []
        params = []
        if action:
            where_parts.append("action = ?")
            params.append(action)
        if entity_type:
            where_parts.append("entity_type = ?")
            params.append(entity_type)
        if entity_id:
            where_parts.append("entity_id = ?")
            params.append(str(entity_id))
        where_sql = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""
        params.append(lim)

        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            f"""
            SELECT log_id, actor_user_id, action, entity_type, entity_id, details_json, created_at
            FROM audit_logs {where_sql} ORDER BY log_id DESC LIMIT ?
            """,
            tuple(params),
        )
        res = []
        for r in cur.fetchall():
            d = _jload(r["details_json"], {})
            res.append({
                "log_id": int(r["log_id"]),
                "audit_id": int(r["log_id"]),
                "actor_user_id": r["actor_user_id"],
                "action": r["action"],
                "event_type": d.get("event_type") or r["action"],
                "entity_type": r["entity_type"],
                "target_type": r["entity_type"],
                "entity_id": r["entity_id"],
                "target_id": r["entity_id"],
                "details": d,
                "created_at": _iso(r["created_at"]),
            })
        return res


def get_platform_settings() -> Dict[str, Any]:
    """Platform settings change rarely; cached for a few seconds (cleared on every settings write)."""
    cached = auth_cache.get("settings", "all")
    if cached is not None:
        return cached
    gen = auth_cache.generation()
    merged = _get_platform_settings_uncached()
    auth_cache.put("settings", "all", merged, gen)
    return merged


def _get_platform_settings_uncached() -> Dict[str, Any]:
    _ready()
    merged = dict(DEFAULT_PLATFORM_SETTINGS)
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute("SELECT setting_key, setting_value_json FROM platform_settings;")
                for r in cur.fetchall():
                    merged[r["setting_key"]] = _jload(r["setting_value_json"], None)
            return merged
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute("SELECT setting_key, setting_value_json FROM platform_settings")
        for r in cur.fetchall():
            merged[r["setting_key"]] = _jload(r["setting_value_json"], None)
        return merged


_BURN_DESTINATIONS = {"0x000000000000000000000000000000000000dead"}


def is_placeholder_payment_destination(addr: str) -> bool:
    """True for addresses nobody controls or that are obvious placeholders (0x000..0, 0x111..1, 0x..dEaD).

    Real addresses are random 40-hex strings with many different digits; anything built from fewer than
    4 distinct hex digits is a placeholder. Payments to such an address would be lost, so they are never
    accepted as the authorized destination (fail closed)."""
    body = (addr or "").strip().lower()
    if body.startswith("0x"):
        body = body[2:]
    return len(set(body)) < 4 or ("0x" + body) in _BURN_DESTINATIONS


def get_authorized_payment_destination() -> Optional[str]:
    """
    Returns the server-controlled authorized payment destination EVM address,
    or None if missing, empty, invalid or a placeholder/burn address. Fails closed.
    """
    settings = get_platform_settings()
    dest = settings.get("authorized_payment_destination")
    if not dest or not isinstance(dest, str):
        return None
    cleaned = dest.strip()
    if not Web3.is_address(cleaned) or is_placeholder_payment_destination(cleaned):
        return None
    return Web3.to_checksum_address(cleaned)


def get_allowed_payment_chain_ids() -> List[int]:
    """Returns the list of EVM chain IDs accepted for verified on-chain payments."""
    settings = get_platform_settings()
    raw = settings.get("allowed_payment_chain_ids")
    if isinstance(raw, list) and raw:
        try:
            return [int(c) for c in raw if int(c) > 0]
        except (ValueError, TypeError):
            pass
    return [1, 11155111]


def usd_to_eth_quote(fee_usd: Any) -> Dict[str, Any]:
    """Converts a USD amount to ETH at the current rate (live, with the admin's fixed fallback).
    The ETH amount is rounded UP to 6 decimals so a quote can never be below the USD price."""
    from decimal import Decimal, ROUND_CEILING
    import price_oracle

    settings = get_platform_settings()
    try:
        usd = Decimal(str(fee_usd if fee_usd not in (None, "") else "0").strip())
        if usd < 0:
            usd = Decimal(0)
    except Exception:
        usd = Decimal(0)

    rate, rate_source = price_oracle.get_eth_usd_rate(
        settings.get("eth_usd_price") or 2500.0,
        use_live=bool(settings.get("use_live_eth_price", True)),
    )
    rate_dec = Decimal(str(rate))
    if usd == 0:
        wei = 0
    else:
        eth_rounded = (usd / rate_dec).quantize(Decimal("0.000001"), rounding=ROUND_CEILING)
        wei = int(eth_rounded * Decimal(10**18))

    eth_str = format(Decimal(wei) / Decimal(10**18), "f") if wei else "0"
    if "." in eth_str:
        eth_str = eth_str.rstrip("0").rstrip(".") or "0"
    return {
        "usd": float(usd),
        "eth": eth_str,
        "wei": str(wei),
        "eth_usd_price": float(rate_dec),
        "rate_source": rate_source,
    }


def get_group_pricing(group_id: str) -> Dict[str, Any]:
    """Authoritative entry price of a paid group.

    New groups are priced in USD (`entry_fee_usd`) and converted at the live rate. Groups
    created before USD pricing existed keep their fixed ETH fee."""
    pol = get_group_access_policy(group_id)
    is_paid = bool(pol.get("is_paid"))
    fee_usd = 0.0
    try:
        fee_usd = float(pol.get("entry_fee_usd") or 0)
    except Exception:
        fee_usd = 0.0

    if is_paid and fee_usd > 0:
        q = usd_to_eth_quote(fee_usd)
        return {"is_paid": True, "entry_fee_usd": q["usd"], "entry_fee_eth": q["eth"],
                "entry_fee_wei": q["wei"], "eth_usd_price": q["eth_usd_price"],
                "rate_source": q["rate_source"], "pricing_mode": "usd"}

    # Legacy fixed-ETH group (or free group)
    fee_wei = str(pol.get("entry_fee_wei") or "0") if is_paid else "0"
    fee_eth = str(pol.get("entry_fee_eth") or "0") if is_paid else "0"
    q = usd_to_eth_quote(0)
    try:
        usd_equiv = round(float(fee_eth) * q["eth_usd_price"], 2) if is_paid else 0.0
    except Exception:
        usd_equiv = 0.0
    return {"is_paid": is_paid, "entry_fee_usd": usd_equiv, "entry_fee_eth": fee_eth,
            "entry_fee_wei": fee_wei, "eth_usd_price": q["eth_usd_price"],
            "rate_source": q["rate_source"], "pricing_mode": "fixed_eth"}


def get_platform_pricing() -> Dict[str, Any]:
    """
    Authoritative membership pricing.

    The admin sets `platform_entry_fee_usd`; the ETH amount is derived from the live
    ETH/USD rate (falling back to the admin's fixed `eth_usd_price`). The ETH amount is
    rounded UP to 6 decimals so a quote can never be a hair below the USD price, and
    the wei value is exactly what the ETH string says.

    Returns:
    - platform_entry_fee_usd: float (what the admin configured)
    - platform_entry_fee_eth / platform_entry_fee_wei: the amount to send now
    - eth_usd_price: rate used, rate_source: 'live' | 'live_cached' | 'live_stale' | 'admin_fixed'
    - authorized_payment_destination, allowed_payment_chain_ids, quoted_at
    """
    from decimal import Decimal, ROUND_CEILING
    import price_oracle

    settings = get_platform_settings()
    try:
        fee_usd = Decimal(str(settings.get("platform_entry_fee_usd") or "0").strip())
        if fee_usd < 0:
            fee_usd = Decimal(0)
    except Exception:
        fee_usd = Decimal(0)

    rate, rate_source = price_oracle.get_eth_usd_rate(
        settings.get("eth_usd_price") or 2500.0,
        use_live=bool(settings.get("use_live_eth_price", True)),
    )
    rate_dec = Decimal(str(rate))

    if fee_usd == 0:
        fee_wei_int = 0
    else:
        eth_exact = fee_usd / rate_dec
        eth_rounded = eth_exact.quantize(Decimal("0.000001"), rounding=ROUND_CEILING)
        fee_wei_int = int(eth_rounded * Decimal(10**18))

    fee_eth_str = format(Decimal(fee_wei_int) / Decimal(10**18), "f") if fee_wei_int else "0"
    if "." in fee_eth_str:
        fee_eth_str = fee_eth_str.rstrip("0").rstrip(".") or "0"

    return {
        "platform_entry_fee_usd": float(fee_usd),
        "platform_entry_fee_eth": fee_eth_str,
        "platform_entry_fee_wei": str(fee_wei_int),
        "eth_usd_price": float(rate_dec),
        "rate_source": rate_source,
        "quoted_at": _now_iso(),
        "authorized_payment_destination": get_authorized_payment_destination(),
        "allowed_payment_chain_ids": get_allowed_payment_chain_ids(),
    }


def has_user_paid_platform_entry(user_id: str) -> bool:
    """Membership check used on every chat request, so a positive answer is cached briefly
    (30 s, cleared on payments, role changes and price changes). Negative answers are never
    cached, so a user who has just paid is recognised immediately."""
    uid = (user_id or "").strip()
    if not uid:
        return False
    if auth_cache.get("paid", uid) is True:
        return True
    gen = auth_cache.generation()
    result = _has_user_paid_platform_entry_uncached(uid)
    if result:
        auth_cache.put("paid", uid, True, gen)
    return result


def _has_user_paid_platform_entry_uncached(user_id: str) -> bool:
    """Checks if a user has paid the platform entry fee or is an admin."""
    _ready()
    clean_uid = (user_id or "").strip()
    if not clean_uid:
        return False
    # Check if admin (superadmins/moderators bypass fee)
    role = get_admin_role(clean_uid)
    if role in ("superadmin", "moderator"):
        return True
    ext = get_extended_user_fields(clean_uid)
    if ext.get("is_platform_paid"):
        return True
    # Admin set the membership price to $0: membership is free for everyone.
    try:
        if float(get_platform_settings().get("platform_entry_fee_usd") or 0) <= 0:
            return True
    except Exception:
        pass
    # Fallback: check verified payment records with purpose = 'platform_entry'
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT 1 FROM payment_records
                    WHERE user_id = %s AND status = 'verified' AND purpose = 'platform_entry'
                    LIMIT 1;
                    """,
                    (clean_uid,)
                )
                return cur.fetchone() is not None
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                SELECT 1 FROM payment_records
                WHERE user_id = ? AND status = 'verified' AND purpose = 'platform_entry'
                LIMIT 1
                """,
                (clean_uid,)
            )
            return cur.fetchone() is not None


def has_user_paid_group_entry(user_id: str, group_id: str) -> bool:
    """Checks if a user has paid the specific group entry fee or is an admin / group admin."""
    _ready()
    clean_uid = (user_id or "").strip()
    clean_gid = (group_id or "").strip()
    if not clean_uid or not clean_gid:
        return False
    # Check if platform admin or group admin
    role = get_admin_role(clean_uid)
    if role in ("superadmin", "moderator"):
        return True
    if is_group_admin(clean_gid, clean_uid):
        return True

    # Check verified payment record with purpose = 'group_entry' and target_id = clean_gid
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT 1 FROM payment_records
                    WHERE user_id = %s AND status = 'verified' AND purpose = 'group_entry' AND target_id = %s
                    LIMIT 1;
                    """,
                    (clean_uid, clean_gid)
                )
                return cur.fetchone() is not None
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                SELECT 1 FROM payment_records
                WHERE user_id = ? AND status = 'verified' AND purpose = 'group_entry' AND target_id = ?
                LIMIT 1
                """,
                (clean_uid, clean_gid)
            )
            return cur.fetchone() is not None


@auth_cache.invalidates_auth_cache(namespaces=('settings', 'user', 'paid'))
def update_platform_settings(updates: Dict[str, Any], actor_user_id: str) -> Dict[str, Any]:
    _ready()
    ts = _now_iso()
    old_dest = get_authorized_payment_destination()

    # Normalize & validate platform_entry_fee_usd (the price the admin actually sets)
    if "platform_entry_fee_usd" in updates:
        raw_usd = updates["platform_entry_fee_usd"]
        try:
            usd_flt = float(raw_usd)
            if usd_flt < 0 or usd_flt > 100000:
                raise ValueError("must be between 0 and 100000")
            updates["platform_entry_fee_usd"] = str(round(usd_flt, 2))
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid platform entry fee (USD): {exc}")

    if "use_live_eth_price" in updates:
        updates["use_live_eth_price"] = bool(updates["use_live_eth_price"])

    # Normalize & validate platform_entry_fee_eth if present
    if "platform_entry_fee_eth" in updates:
        raw_fee = updates["platform_entry_fee_eth"]
        try:
            fee_flt = float(raw_fee)
            if fee_flt < 0:
                raise ValueError("Platform entry fee cannot be negative")
            updates["platform_entry_fee_eth"] = str(raw_fee).strip()
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid platform entry fee: {exc}")

    # Normalize & validate eth_usd_price if present
    if "eth_usd_price" in updates:
        raw_price = updates["eth_usd_price"]
        try:
            price_flt = float(raw_price)
            if price_flt <= 0:
                raise ValueError("ETH USD price must be greater than 0")
            updates["eth_usd_price"] = price_flt
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid ETH USD price: {exc}")

    # Normalize & validate authorized_payment_destination if present in updates
    if "authorized_payment_destination" in updates:
        raw_dest = updates["authorized_payment_destination"]
        if raw_dest is not None and str(raw_dest).strip() != "":
            raw_dest_str = str(raw_dest).strip()
            if not Web3.is_address(raw_dest_str):
                raise ValueError(f"Invalid Ethereum address for authorized payment destination: {raw_dest}")
            if is_placeholder_payment_destination(raw_dest_str):
                raise ValueError(
                    "That looks like a placeholder or burn address (for example 0x000...0 or 0x111...1). "
                    "Funds sent there would be lost. Enter the real wallet that should receive payments."
                )
            updates["authorized_payment_destination"] = Web3.to_checksum_address(raw_dest_str)
        else:
            updates["authorized_payment_destination"] = None

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                for k, v in updates.items():
                    if k not in DEFAULT_PLATFORM_SETTINGS:
                        continue
                    cur.execute(
                        """
                        INSERT INTO platform_settings (setting_key, setting_value_json, updated_by, updated_at)
                        VALUES (%s, %s::jsonb, %s, %s)
                        ON CONFLICT (setting_key) DO UPDATE SET
                            setting_value_json = EXCLUDED.setting_value_json,
                            updated_by = EXCLUDED.updated_by,
                            updated_at = EXCLUDED.updated_at;
                        """,
                        (k, json.dumps(v), actor_user_id, ts),
                    )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            for k, v in updates.items():
                if k not in DEFAULT_PLATFORM_SETTINGS:
                    continue
                cur.execute(
                    """
                    INSERT INTO platform_settings (setting_key, setting_value_json, updated_by, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(setting_key) DO UPDATE SET
                        setting_value_json = excluded.setting_value_json,
                        updated_by = excluded.updated_by,
                        updated_at = excluded.updated_at
                    """,
                    (k, json.dumps(v), actor_user_id, ts),
                )
            chat_db._sqlite_conn.commit()

    record_audit_log(actor_user_id, "platform_settings_updated", "settings", "global", updates)

    # Dedicated audit requirement for authorized payment destination creation/change
    if "authorized_payment_destination" in updates:
        new_dest = updates["authorized_payment_destination"]
        if new_dest != old_dest:
            dest_action = "authorized_payment_destination_changed" if old_dest else "authorized_payment_destination_created"
            record_audit_log(
                actor_user_id=actor_user_id,
                action=dest_action,
                entity_type="payment_destination",
                entity_id="authorized_destination",
                details={
                    "event_type": dest_action,
                    "actor": actor_user_id,
                    "timestamp": ts,
                    "previous_value": old_dest,
                    "new_value": new_dest,
                },
            )

    return get_platform_settings()


def update_authorized_payment_destination(new_destination: str, actor_user_id: str) -> Dict[str, Any]:
    """
    Authoritatively updates the authorized payment destination configuration.
    Validates EVM address format, records audit log with actor, timestamp, previous value, and new value.
    Restricted to superadmin callers.
    """
    _ready()
    clean_dest = (new_destination or "").strip()
    if not clean_dest or not Web3.is_address(clean_dest):
        raise ValueError("Invalid Ethereum address for authorized payment destination")
    if is_placeholder_payment_destination(clean_dest):
        raise ValueError(
            "That looks like a placeholder or burn address; funds sent there would be lost. "
            "Enter the real wallet that should receive payments."
        )

    checksum_dest = Web3.to_checksum_address(clean_dest)
    old_dest = get_authorized_payment_destination()
    ts = _now_iso()

    update_platform_settings(
        {"authorized_payment_destination": checksum_dest},
        actor_user_id=actor_user_id,
    )

    return {
        "success": True,
        "authorized_payment_destination": checksum_dest,
        "previous_value": old_dest,
        "updated_at": ts,
    }


# ============================================================================
# EXTENDED USER PROFILE, USERNAME COOLDOWN/HISTORY & WALLET HISTORY
# ============================================================================

def get_admin_role(user_id: str) -> Optional[str]:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT role FROM admin_roles WHERE user_id = %s;", (user_id,))
                row = cur.fetchone()
                return row[0] if row else None
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute("SELECT role FROM admin_roles WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        return row["role"] if row else None


def bootstrap_admin_if_configured(user_id: str, wallet_address: str) -> Optional[str]:
    raw_list = os.getenv("ADMIN_WALLET_ADDRESSES", "")
    configured = {
        w.strip().lower()
        for w in raw_list.split(",")
        if w.strip() and w.strip().lower() != "0x0000000000000000000000000000000000000000"
    }
    if wallet_address.strip().lower() in configured:
        set_admin_role(user_id=user_id, role="superadmin", actor_user_id="env_bootstrap")
        return "superadmin"
    return get_admin_role(user_id)


@auth_cache.invalidates_auth_cache(namespaces=('user', 'ext_user', 'paid'))
def set_admin_role(user_id: str, role: Optional[str], actor_user_id: str) -> None:
    _ready()
    ts = _now_iso()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                if not role:
                    cur.execute("DELETE FROM admin_roles WHERE user_id = %s;", (user_id,))
                else:
                    cur.execute(
                        """
                        INSERT INTO admin_roles (user_id, role, granted_by, granted_at)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (user_id) DO UPDATE SET
                            role = EXCLUDED.role,
                            granted_by = EXCLUDED.granted_by,
                            granted_at = EXCLUDED.granted_at;
                        """,
                        (user_id, role, actor_user_id, ts),
                    )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            if not role:
                cur.execute("DELETE FROM admin_roles WHERE user_id = ?", (user_id,))
            else:
                cur.execute(
                    """
                    INSERT INTO admin_roles (user_id, role, granted_by, granted_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(user_id) DO UPDATE SET
                        role = excluded.role,
                        granted_by = excluded.granted_by,
                        granted_at = excluded.granted_at
                    """,
                    (user_id, role, actor_user_id, ts),
                )
            chat_db._sqlite_conn.commit()

    record_audit_log(actor_user_id, "admin_role_changed", "user", user_id, {"role": role})


@auth_cache.read_cached("ext_user")
def _membership_is_free() -> bool:
    try:
        return float(get_platform_settings().get("platform_entry_fee_usd") or 0) <= 0
    except Exception:
        return False


def get_extended_user_fields(user_id: str) -> Dict[str, Any]:
    _ready()
    cols = """
        display_name, bio, avatar_url, username_changed_at,
        current_level, highest_level, qualifying_balance_wei, qualifying_chain_id,
        last_balance_verified_at, level_grace_expires_at,
        account_status, suspended_until, suspension_reason,
        show_online_presence, send_read_receipts,
        is_platform_paid, platform_paid_at
    """
    row: Optional[Any] = None
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(f"SELECT {cols} FROM chat_users WHERE user_id = %s;", (user_id,))
                row = cur.fetchone()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(f"SELECT {cols} FROM chat_users WHERE user_id = ?", (user_id,))
            row = cur.fetchone()

    if not row:
        return {}

    return {
        "display_name": row["display_name"],
        "bio": row["bio"],
        "avatar_url": row["avatar_url"],
        "username_changed_at": _iso(row["username_changed_at"]),
        "current_level": int(row["current_level"] or 7),
        "highest_level": int(row["highest_level"] or 7),
        "qualifying_balance_wei": str(row["qualifying_balance_wei"] or "0"),
        "qualifying_chain_id": int(row["qualifying_chain_id"] or 1),
        "last_balance_verified_at": _iso(row["last_balance_verified_at"]),
        "level_grace_expires_at": _iso(row["level_grace_expires_at"]),
        "account_status": row["account_status"] or "active",
        "suspended_until": _iso(row["suspended_until"]),
        "suspension_reason": row["suspension_reason"],
        "show_online_presence": bool(row["show_online_presence"]),
        "send_read_receipts": bool(row["send_read_receipts"]),
        # Paid for real, OR membership is free right now (admin set the price to $0), OR an admin.
        "is_platform_paid": (
            (bool(row["is_platform_paid"]) if "is_platform_paid" in row.keys() else False)
            or _membership_is_free()
            or get_admin_role(user_id) in ("superadmin", "moderator")
        ),
        "platform_paid_at": _iso(row["platform_paid_at"]) if "platform_paid_at" in row.keys() else None,
        "admin_role": get_admin_role(user_id),
    }


def enrich_user_dict(user: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not user:
        return None
    ext = get_extended_user_fields(user["user_id"])
    return {**user, **ext}


@auth_cache.invalidates_auth_cache
def update_username_with_history_and_cooldown(user_id: str, new_username: str) -> Dict[str, Any]:
    _ready()
    base_user = e2ee_db.get_user_by_id(user_id)
    if not base_user:
        raise ValueError("Account not found")

    ext = get_extended_user_fields(user_id)
    old_username = base_user.get("username")
    if old_username and old_username.lower() == new_username.lower() and old_username == new_username:
        return enrich_user_dict(base_user)  # type: ignore[return-value]

    settings = get_platform_settings()
    cooldown_hours = int(settings.get("username_cooldown_hours") or 0)
    reservation_days = int(settings.get("username_reservation_days") or 30)

    # 1. Check active claim by another user (case-insensitive)
    existing_owner = e2ee_db.get_user_by_username(new_username)
    if existing_owner and existing_owner["user_id"] != user_id:
        raise ValueError("Username is already claimed by another account")

    # 2. Check reservation quarantine from another account's historical username
    now = _now()
    now_str = now.isoformat()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT user_id, reserved_until FROM username_history
                    WHERE LOWER(old_username) = LOWER(%s) AND user_id != %s
                    ORDER BY changed_at DESC LIMIT 1;
                    """,
                    (new_username, user_id),
                )
                hist_row = cur.fetchone()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                SELECT user_id, reserved_until FROM username_history
                WHERE LOWER(old_username) = LOWER(?) AND user_id != ?
                ORDER BY changed_at DESC LIMIT 1
                """,
                (new_username, user_id),
            )
            hist_row = cur.fetchone()

    if hist_row and hist_row[1]:
        res_dt = datetime.fromisoformat(str(hist_row[1]).replace("Z", "+00:00"))
        if res_dt > now:
            raise ValueError(
                "Username was recently used by another account and is reserved against impersonation"
            )

    # 3. Enforce cooldown if user already had a username
    if old_username and cooldown_hours > 0 and ext.get("username_changed_at"):
        last_dt = datetime.fromisoformat(ext["username_changed_at"].replace("Z", "+00:00"))
        next_allowed = last_dt + timedelta(hours=cooldown_hours)
        if now < next_allowed:
            rem_mins = max(1, int((next_allowed - now).total_seconds() // 60))
            raise ValueError(f"Username change cooldown active; try again in {rem_mins} minutes")

    reserved_until = (
        (now + timedelta(days=reservation_days)).isoformat() if old_username else None
    )

    try:
        if _is_pg():
            conn = chat_db._pg_pool.getconn()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE chat_users
                        SET username = %s, username_changed_at = %s, updated_at = %s
                        WHERE user_id = %s;
                        """,
                        (new_username, now_str, now_str, user_id),
                    )
                    cur.execute(
                        """
                        INSERT INTO username_history (user_id, old_username, new_username, reserved_until, changed_at)
                        VALUES (%s, %s, %s, %s, %s);
                        """,
                        (user_id, old_username, new_username, reserved_until, now_str),
                    )
                conn.commit()
            finally:
                chat_db._pg_pool.putconn(conn)
        else:
            with chat_db._sqlite_lock:
                cur = chat_db._sqlite_conn.cursor()
                cur.execute(
                    """
                    UPDATE chat_users
                    SET username = ?, username_changed_at = ?, updated_at = ?
                    WHERE user_id = ?
                    """,
                    (new_username, now_str, now_str, user_id),
                )
                cur.execute(
                    """
                    INSERT INTO username_history (user_id, old_username, new_username, reserved_until, changed_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (user_id, old_username, new_username, reserved_until, now_str),
                )
                chat_db._sqlite_conn.commit()
    except Exception as exc:
        err_msg = str(exc).lower()
        if "unique" in err_msg or "integrity" in err_msg or "idx_chat_users_username" in err_msg:
            raise ValueError("Username is already claimed by another account")
        raise

    record_audit_log(
        user_id,
        "username_changed",
        "user",
        user_id,
        {"old_username": old_username, "new_username": new_username},
    )
    return enrich_user_dict(e2ee_db.get_user_by_id(user_id))  # type: ignore[return-value]


def list_username_history(user_id: str) -> List[Dict[str, Any]]:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT old_username, new_username, reserved_until, changed_at
                    FROM username_history WHERE user_id = %s ORDER BY changed_at DESC LIMIT 30;
                    """,
                    (user_id,),
                )
                return [
                    {
                        "old_username": r["old_username"],
                        "new_username": r["new_username"],
                        "reserved_until": _iso(r["reserved_until"]),
                        "changed_at": _iso(r["changed_at"]),
                    }
                    for r in cur.fetchall()
                ]
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            """
            SELECT old_username, new_username, reserved_until, changed_at
            FROM username_history WHERE user_id = ? ORDER BY changed_at DESC LIMIT 30
            """,
            (user_id,),
        )
        return [
            {
                "old_username": r["old_username"],
                "new_username": r["new_username"],
                "reserved_until": _iso(r["reserved_until"]),
                "changed_at": _iso(r["changed_at"]),
            }
            for r in cur.fetchall()
        ]


@auth_cache.invalidates_auth_cache
def record_wallet_change_and_revoke_old_sessions(
    user_id: str,
    action: str,
    old_wallet: Optional[str],
    new_wallet: Optional[str],
    performed_by: str,
    revoke_previous_sessions: bool = False,
) -> None:
    _ready()
    ts = _now_iso()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO wallet_change_history (user_id, action, old_wallet, new_wallet, performed_by, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s);
                    """,
                    (user_id, action, old_wallet, new_wallet, performed_by, ts),
                )
                if revoke_previous_sessions and new_wallet:
                    cur.execute(
                        """
                        UPDATE chat_auth_sessions
                        SET revoked = TRUE
                        WHERE user_id = %s AND LOWER(wallet_address) != LOWER(%s);
                        """,
                        (user_id, new_wallet),
                    )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                INSERT INTO wallet_change_history (user_id, action, old_wallet, new_wallet, performed_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, action, old_wallet, new_wallet, performed_by, ts),
            )
            if revoke_previous_sessions and new_wallet:
                cur.execute(
                    """
                    UPDATE chat_auth_sessions
                    SET revoked = 1
                    WHERE user_id = ? AND LOWER(wallet_address) != LOWER(?)
                    """,
                    (user_id, new_wallet),
                )
            chat_db._sqlite_conn.commit()

    record_audit_log(
        performed_by,
        action,
        "wallet",
        user_id,
        {"old_wallet": old_wallet, "new_wallet": new_wallet, "revoked_old_sessions": revoke_previous_sessions},
    )


def list_wallet_history(user_id: str) -> Dict[str, Any]:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT wallet_address, is_primary, status, linked_at, revoked_at
                    FROM chat_user_wallets WHERE user_id = %s ORDER BY linked_at DESC;
                    """,
                    (user_id,),
                )
                wallets = [
                    {
                        "wallet_address": w["wallet_address"],
                        "is_primary": bool(w["is_primary"]),
                        "status": w["status"],
                        "linked_at": _iso(w["linked_at"]),
                        "revoked_at": _iso(w["revoked_at"]),
                    }
                    for w in cur.fetchall()
                ]
                cur.execute(
                    """
                    SELECT action, old_wallet, new_wallet, performed_by, created_at
                    FROM wallet_change_history WHERE user_id = %s ORDER BY created_at DESC LIMIT 50;
                    """,
                    (user_id,),
                )
                events = [
                    {
                        "action": e["action"],
                        "old_wallet": e["old_wallet"],
                        "old_wallet_address": e["old_wallet"],
                        "new_wallet": e["new_wallet"],
                        "new_wallet_address": e["new_wallet"],
                        "performed_by": e["performed_by"],
                        "created_at": _iso(e["created_at"]),
                    }
                    for e in cur.fetchall()
                ]
                return {"wallets": wallets, "history": events}
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            """
            SELECT wallet_address, is_primary, status, linked_at, revoked_at
            FROM chat_user_wallets WHERE user_id = ? ORDER BY linked_at DESC
            """,
            (user_id,),
        )
        wallets = [
            {
                "wallet_address": w["wallet_address"],
                "is_primary": bool(w["is_primary"]),
                "status": w["status"],
                "linked_at": _iso(w["linked_at"]),
                "revoked_at": _iso(w["revoked_at"]),
            }
            for w in cur.fetchall()
        ]
        cur.execute(
            """
            SELECT action, old_wallet, new_wallet, performed_by, created_at
            FROM wallet_change_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 50
            """,
            (user_id,),
        )
        events = [
            {
                "action": e["action"],
                "old_wallet": e["old_wallet"],
                "old_wallet_address": e["old_wallet"],
                "new_wallet": e["new_wallet"],
                "new_wallet_address": e["new_wallet"],
                "performed_by": e["performed_by"],
                "created_at": _iso(e["created_at"]),
            }
            for e in cur.fetchall()
        ]
        return {"wallets": wallets, "history": events}


@auth_cache.invalidates_auth_cache
def update_user_profile(
    user_id: str,
    display_name: Optional[str] = None,
    bio: Optional[str] = None,
    avatar_url: Optional[str] = None,
    show_online_presence: Optional[bool] = None,
    send_read_receipts: Optional[bool] = None,
) -> Dict[str, Any]:
    _ready()
    ext = get_extended_user_fields(user_id)
    if not ext:
        raise ValueError("User not found")

    new_dn = ext["display_name"] if display_name is None else (display_name.strip() or None)
    new_bio = ext["bio"] if bio is None else (bio.strip() or None)
    new_av = ext["avatar_url"] if avatar_url is None else (avatar_url.strip() or None)
    new_pres = ext["show_online_presence"] if show_online_presence is None else bool(show_online_presence)
    new_rcpt = ext["send_read_receipts"] if send_read_receipts is None else bool(send_read_receipts)
    ts = _now_iso()

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE chat_users
                    SET display_name = %s, bio = %s, avatar_url = %s,
                        show_online_presence = %s, send_read_receipts = %s, updated_at = %s
                    WHERE user_id = %s;
                    """,
                    (new_dn, new_bio, new_av, new_pres, new_rcpt, ts, user_id),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                UPDATE chat_users
                SET display_name = ?, bio = ?, avatar_url = ?,
                    show_online_presence = ?, send_read_receipts = ?, updated_at = ?
                WHERE user_id = ?
                """,
                (new_dn, new_bio, new_av, 1 if new_pres else 0, 1 if new_rcpt else 0, ts, user_id),
            )
            chat_db._sqlite_conn.commit()

    return enrich_user_dict(e2ee_db.get_user_by_id(user_id))  # type: ignore[return-value]


# ============================================================================
# RPC WALLET BALANCE VERIFICATION & SNAPSHOTS
# ============================================================================

@auth_cache.invalidates_auth_cache
def record_verified_balance_snapshot(
    user_id: str,
    wallet_address: str,
    chain_id: int,
    balance_wei_int: int,
    block_number: int,
    rpc_source: str = "ethereum_rpc",
) -> Dict[str, Any]:
    """Persists an RPC-verified balance snapshot and updates qualifying_balance_wei."""
    _ready()
    uid = (user_id or "").strip()
    bal_wei = int(balance_wei_int or 0)
    cid = int(chain_id or 1)
    blk = int(block_number or 0)
    src_label = (rpc_source or "ethereum_rpc").strip()
    snapshot_id = "bal_" + secrets.token_hex(10)
    now_ts = _now_iso()

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO wallet_balance_snapshots (
                        snapshot_id, user_id, wallet_address, chain_id,
                        balance_wei, block_number, rpc_source, verified_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                    """,
                    (snapshot_id, uid, wallet_address, cid, str(bal_wei), blk, src_label, now_ts),
                )
                cur.execute(
                    """
                    UPDATE chat_users
                    SET qualifying_balance_wei = %s,
                        qualifying_chain_id = %s,
                        last_balance_verified_at = %s,
                        updated_at = %s
                    WHERE user_id = %s;
                    """,
                    (str(bal_wei), cid, now_ts, now_ts, uid),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                INSERT INTO wallet_balance_snapshots (
                    snapshot_id, user_id, wallet_address, chain_id,
                    balance_wei, block_number, rpc_source, verified_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (snapshot_id, uid, wallet_address, cid, str(bal_wei), blk, src_label, now_ts),
            )
            cur.execute(
                """
                UPDATE chat_users
                SET qualifying_balance_wei = ?,
                    qualifying_chain_id = ?,
                    last_balance_verified_at = ?,
                    updated_at = ?
                WHERE user_id = ?
                """,
                (str(bal_wei), cid, now_ts, now_ts, uid),
            )
            chat_db._sqlite_conn.commit()

    return {
        "snapshot_id": snapshot_id,
        "user_id": uid,
        "wallet_address": wallet_address,
        "chain_id": cid,
        "balance_wei": str(bal_wei),
        "balance_eth": str(Web3.from_wei(bal_wei, "ether")),
        "block_number": blk,
        "rpc_source": src_label,
        "verified_at": now_ts,
        "wallet_balance_wei": str(bal_wei),
    }


@auth_cache.invalidates_auth_cache
def reset_user_balance_on_wallet_revoke(user_id: str) -> None:
    """When a primary wallet is revoked or replaced, reset verified balance to 0."""
    _ready()
    ts = _now_iso()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE chat_users
                    SET qualifying_balance_wei = '0',
                        qualifying_chain_id = 1,
                        updated_at = %s
                    WHERE user_id = %s;
                    """,
                    (ts, user_id),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                UPDATE chat_users
                SET qualifying_balance_wei = '0',
                    qualifying_chain_id = 1,
                    updated_at = ?
                WHERE user_id = ?
                """,
                (ts, user_id),
            )
            chat_db._sqlite_conn.commit()


def list_user_balance_history(user_id: str) -> Dict[str, Any]:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT snapshot_id, wallet_address, chain_id, balance_wei, block_number, rpc_source, verified_at
                    FROM wallet_balance_snapshots WHERE user_id = %s ORDER BY verified_at DESC LIMIT 25;
                    """,
                    (user_id,),
                )
                snaps = [
                    {
                        "snapshot_id": r["snapshot_id"],
                        "wallet_address": r["wallet_address"],
                        "chain_id": int(r["chain_id"]),
                        "balance_wei": str(r["balance_wei"]),
                        "block_number": int(r["block_number"]),
                        "rpc_source": r["rpc_source"],
                        "verified_at": _iso(r["verified_at"]),
                    }
                    for r in cur.fetchall()
                ]
                return {"snapshots": snaps}
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            """
            SELECT snapshot_id, wallet_address, chain_id, balance_wei, block_number, rpc_source, verified_at
            FROM wallet_balance_snapshots WHERE user_id = ? ORDER BY verified_at DESC LIMIT 25
            """,
            (user_id,),
        )
        snaps = [
            {
                "snapshot_id": r["snapshot_id"],
                "wallet_address": r["wallet_address"],
                "chain_id": int(r["chain_id"]),
                "balance_wei": str(r["balance_wei"]),
                "block_number": int(r["block_number"]),
                "rpc_source": r["rpc_source"],
                "verified_at": _iso(r["verified_at"]),
            }
            for r in cur.fetchall()
        ]
        return {"snapshots": snaps}


# ============================================================================
# AUTHORITATIVE SERVER-SIDE VERIFIED PAYMENT RECORDS
# ============================================================================

def _serialize_payment_record(r: Any) -> Dict[str, Any]:
    meta = _jload(r["metadata_json"], {})
    recip = None
    try:
        if "recipient_address" in r.keys() and r["recipient_address"]:
            recip = str(r["recipient_address"])
    except Exception:
        pass
    if not recip and isinstance(meta, dict) and meta.get("recipient_address"):
        recip = str(meta["recipient_address"])

    purpose = "platform_entry"
    try:
        if "purpose" in r.keys() and r["purpose"]:
            purpose = str(r["purpose"])
    except Exception:
        pass
    if purpose == "platform_entry" and isinstance(meta, dict) and meta.get("purpose"):
        purpose = str(meta["purpose"])

    target_id = None
    try:
        if "target_id" in r.keys() and r["target_id"]:
            target_id = str(r["target_id"])
    except Exception:
        pass
    if not target_id and isinstance(meta, dict) and meta.get("target_id"):
        target_id = str(meta["target_id"])

    return {
        "payment_id": str(r["payment_id"]),
        "user_id": str(r["user_id"]),
        "wallet_address": str(r["wallet_address"]) if r["wallet_address"] else None,
        "recipient_address": recip,
        "purpose": purpose,
        "target_id": target_id,
        "amount_atomic": str(r["amount_atomic"] or "0"),
        "amount_formatted": str(r["amount_formatted"] or "0"),
        "currency": str(r["currency"] or "ETH"),
        "network": str(r["network"] or "ethereum"),
        "chain_id": int(r["chain_id"]) if r["chain_id"] is not None else None,
        "status": str(r["status"] or "pending"),
        "transaction_reference": str(r["transaction_reference"]),
        "block_number": int(r["block_number"]) if r["block_number"] is not None else None,
        "verification_source": str(r["verification_source"] or "ethereum_rpc"),
        "verified_at": _iso(r["verified_at"]),
        "error_message": str(r["error_message"]) if r["error_message"] else None,
        "retry_count": int(r["retry_count"] or 0),
        "metadata": meta,
        "created_at": _iso(r["created_at"]),
        "updated_at": _iso(r["updated_at"]),
    }


def get_payment_record(payment_id: str) -> Optional[Dict[str, Any]]:
    _ready()
    clean_id = (payment_id or "").strip()
    if not clean_id:
        return None
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute("SELECT * FROM payment_records WHERE payment_id = %s;", (clean_id,))
                row = cur.fetchone()
                return _serialize_payment_record(row) if row else None
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute("SELECT * FROM payment_records WHERE payment_id = ?", (clean_id,))
        row = cur.fetchone()
        return _serialize_payment_record(row) if row else None


def get_payment_by_tx_ref(transaction_reference: str) -> Optional[Dict[str, Any]]:
    _ready()
    ref = (transaction_reference or "").strip().lower()
    if not ref:
        return None
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute("SELECT * FROM payment_records WHERE LOWER(transaction_reference) = %s;", (ref,))
                row = cur.fetchone()
                return _serialize_payment_record(row) if row else None
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute("SELECT * FROM payment_records WHERE LOWER(transaction_reference) = ?", (ref,))
        row = cur.fetchone()
        return _serialize_payment_record(row) if row else None


def get_user_verified_payment_total_wei(user_id: str) -> int:
    """
    Returns the total sum of all authoritative VERIFIED ETH payments for `user_id` in Wei.
    Pending, failed, cancelled, reversed, or unverified payments STRICTLY return 0 and are not counted.
    """
    _ready()
    uid = (user_id or "").strip()
    if not uid:
        return 0

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COALESCE(SUM(CAST(amount_atomic AS NUMERIC)), 0)
                    FROM payment_records
                    WHERE user_id = %s AND status = 'verified' AND currency = 'ETH';
                    """,
                    (uid,),
                )
                row = cur.fetchone()
                return int(row[0]) if row and row[0] is not None else 0
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            """
            SELECT amount_atomic FROM payment_records
            WHERE user_id = ? AND status = 'verified' AND currency = 'ETH'
            """,
            (uid,),
        )
        total = 0
        for r in cur.fetchall():
            try:
                total += int(r["amount_atomic"] or "0")
            except (ValueError, TypeError):
                pass
        return total


def create_or_submit_payment_record(
    user_id: str,
    transaction_reference: str,
    chain_id: Optional[int] = None,
    wallet_address: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    purpose: str = "platform_entry",
    target_id: Optional[str] = None,
) -> Tuple[Dict[str, Any], bool]:
    """
    Idempotently creates a pending payment record or returns an existing record for the given transaction_reference.
    Returns (payment_record, created_new_bool).
    Enforces uniqueness so a transaction reference can never be created more than once.
    """
    _ready()
    clean_uid = user_id.strip()
    clean_ref = transaction_reference.strip().lower()
    if not clean_ref:
        raise ValueError("transaction_reference is required")

    existing = get_payment_by_tx_ref(clean_ref)
    if existing:
        return existing, False

    payment_id = f"pay_{secrets.token_hex(12)}"
    now_ts = _now_iso()
    meta = dict(metadata or {})
    meta["purpose"] = purpose
    if target_id:
        meta["target_id"] = target_id
    meta_json = json.dumps(meta)
    w_addr = wallet_address.strip() if wallet_address else None

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    INSERT INTO payment_records (
                        payment_id, user_id, wallet_address, amount_atomic, amount_formatted,
                        currency, network, chain_id, status, transaction_reference,
                        verification_source, retry_count, metadata_json, purpose, target_id, created_at, updated_at
                    ) VALUES (
                        %s, %s, %s, '0', '0', 'ETH', 'ethereum', %s, 'pending', %s,
                        'ethereum_rpc', 0, %s::jsonb, %s, %s, %s, %s
                    )
                    ON CONFLICT (transaction_reference) DO NOTHING
                    RETURNING *;
                    """,
                    (payment_id, clean_uid, w_addr, chain_id, clean_ref, meta_json, purpose, target_id, now_ts, now_ts),
                )
                row = cur.fetchone()
            conn.commit()
            if row:
                return _serialize_payment_record(row), True
        finally:
            chat_db._pg_pool.putconn(conn)
        # If conflict occurred on insert, fetch and return existing
        return get_payment_by_tx_ref(clean_ref), False  # type: ignore[return-value]

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO payment_records (
                    payment_id, user_id, wallet_address, amount_atomic, amount_formatted,
                    currency, network, chain_id, status, transaction_reference,
                    verification_source, retry_count, metadata_json, purpose, target_id, created_at, updated_at
                ) VALUES (?, ?, ?, '0', '0', 'ETH', 'ethereum', ?, 'pending', ?, 'ethereum_rpc', 0, ?, ?, ?, ?, ?)
                """,
                (payment_id, clean_uid, w_addr, chain_id, clean_ref, meta_json, purpose, target_id, now_ts, now_ts),
            )
            chat_db._sqlite_conn.commit()
            return get_payment_record(payment_id), True  # type: ignore[return-value]
        except sqlite3.IntegrityError:
            return get_payment_by_tx_ref(clean_ref), False  # type: ignore[return-value]


@auth_cache.invalidates_auth_cache
def record_verified_payment(
    payment_id: str,
    wallet_address: Optional[str],
    amount_atomic: str,
    amount_formatted: str,
    currency: str = "ETH",
    network: str = "ethereum",
    chain_id: Optional[int] = None,
    block_number: Optional[int] = None,
    verification_source: str = "ethereum_rpc",
    metadata: Optional[Dict[str, Any]] = None,
    recipient_address: Optional[str] = None,
    purpose: Optional[str] = None,
    target_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Authoritatively updates a payment record to 'verified' inside an atomic database transaction.
    Recalculates user level based on verified balance + verified payments.
    Idempotent: if already verified, returns existing record without double-counting.
    """
    _ready()
    existing = get_payment_record(payment_id)
    if not existing:
        raise ValueError(f"Payment {payment_id} not found")
    if existing["status"] == "verified":
        # Idempotent return — already counted once, never count again!
        return existing

    user_id = existing["user_id"]
    now_ts = _now_iso()
    meta = dict(metadata or existing.get("metadata") or {})
    if recipient_address:
        meta["recipient_address"] = recipient_address

    p_purpose = purpose or existing.get("purpose") or meta.get("purpose") or "platform_entry"
    p_target = target_id or existing.get("target_id") or meta.get("target_id")
    meta["purpose"] = p_purpose
    if p_target:
        meta["target_id"] = p_target

    meta_json = json.dumps(meta)
    w_addr = (wallet_address or existing.get("wallet_address") or "").strip() or None
    r_addr = (recipient_address or existing.get("recipient_address") or meta.get("recipient_address") or "").strip() or None
    cid = chain_id if chain_id is not None else existing.get("chain_id")

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE payment_records
                    SET wallet_address = %s,
                        recipient_address = %s,
                        amount_atomic = %s,
                        amount_formatted = %s,
                        currency = %s,
                        network = %s,
                        chain_id = %s,
                        status = 'verified',
                        block_number = %s,
                        verification_source = %s,
                        verified_at = %s,
                        error_message = NULL,
                        metadata_json = %s::jsonb,
                        purpose = %s,
                        target_id = %s,
                        updated_at = %s
                    WHERE payment_id = %s;
                    """,
                    (
                        w_addr,
                        r_addr,
                        str(int(amount_atomic)),
                        str(amount_formatted),
                        currency,
                        network,
                        cid,
                        block_number,
                        verification_source,
                        now_ts,
                        meta_json,
                        p_purpose,
                        p_target,
                        now_ts,
                        payment_id,
                    ),
                )
                if p_purpose == "platform_entry":
                    cur.execute(
                        """
                        UPDATE chat_users
                        SET is_platform_paid = TRUE, platform_paid_at = %s
                        WHERE user_id = %s;
                        """,
                        (now_ts, user_id),
                    )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                UPDATE payment_records
                SET wallet_address = ?,
                    recipient_address = ?,
                    amount_atomic = ?,
                    amount_formatted = ?,
                    currency = ?,
                    network = ?,
                    chain_id = ?,
                    status = 'verified',
                    block_number = ?,
                    verification_source = ?,
                    verified_at = ?,
                    error_message = NULL,
                    metadata_json = ?,
                    purpose = ?,
                    target_id = ?,
                    updated_at = ?
                WHERE payment_id = ?
                """,
                (
                    w_addr,
                    r_addr,
                    str(int(amount_atomic)),
                    str(amount_formatted),
                    currency,
                    network,
                    cid,
                    block_number,
                    verification_source,
                    now_ts,
                    meta_json,
                    p_purpose,
                    p_target,
                    now_ts,
                    payment_id,
                ),
            )
            if p_purpose == "platform_entry":
                cur.execute(
                    """
                    UPDATE chat_users
                    SET is_platform_paid = 1, platform_paid_at = ?
                    WHERE user_id = ?
                    """,
                    (now_ts, user_id),
                )
            chat_db._sqlite_conn.commit()

    if p_purpose == "group_entry" and p_target:
        try:
            e2ee_db.add_group_member(p_target, user_id, role="member")
        except Exception as add_err:
            logger.warning("Auto-adding member to paid group %s failed: %s", p_target, add_err)

    audit_details = {
        "event_type": "payment_verified",
        "result": "verified",
        "transaction_reference": existing["transaction_reference"],
        "amount_formatted": amount_formatted,
        "currency": currency,
        "network": network,
        "chain_id": cid,
        "verification_source": verification_source,
    }
    if r_addr:
        audit_details["recipient_address"] = r_addr

    record_audit_log(
        actor_user_id=user_id,
        action="payment_verified",
        entity_type="payment",
        entity_id=payment_id,
        details=audit_details,
    )

    return get_payment_record(payment_id)  # type: ignore[return-value]


def record_failed_payment(
    payment_id: str,
    error_message: str,
    verification_source: str = "ethereum_rpc",
    recipient_address: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Marks a payment record as 'failed'. Failed payments do not count toward level qualification.
    If the payment was already verified, it is protected and remains verified.
    """
    _ready()
    existing = get_payment_record(payment_id)
    if not existing:
        raise ValueError(f"Payment {payment_id} not found")
    if existing["status"] == "verified":
        return existing

    now_ts = _now_iso()
    err = (error_message or "Payment verification failed")[:500]
    meta = dict(existing.get("metadata") or {})
    if recipient_address:
        meta["recipient_address"] = recipient_address
    meta_json = json.dumps(meta)
    r_addr = (recipient_address or existing.get("recipient_address") or meta.get("recipient_address") or "").strip() or None

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE payment_records
                    SET status = 'failed',
                        recipient_address = COALESCE(%s, recipient_address),
                        error_message = %s,
                        verification_source = %s,
                        metadata_json = %s::jsonb,
                        updated_at = %s
                    WHERE payment_id = %s;
                    """,
                    (r_addr, err, verification_source, meta_json, now_ts, payment_id),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                UPDATE payment_records
                SET status = 'failed',
                    recipient_address = COALESCE(?, recipient_address),
                    error_message = ?,
                    verification_source = ?,
                    metadata_json = ?,
                    updated_at = ?
                WHERE payment_id = ?
                """,
                (r_addr, err, verification_source, meta_json, now_ts, payment_id),
            )
            chat_db._sqlite_conn.commit()

    reject_details = {
        "event_type": "payment_rejected",
        "result": "rejected",
        "reason": err,
        "safe_error_code": "PAYMENT_REJECTED",
        "verification_source": verification_source,
    }
    if r_addr:
        reject_details["recipient_address"] = r_addr

    record_audit_log(
        actor_user_id=existing.get("user_id") or "system",
        action="payment_rejected",
        entity_type="payment",
        entity_id=payment_id,
        details=reject_details,
    )

    return get_payment_record(payment_id)  # type: ignore[return-value]


def record_pending_payment_retry(
    payment_id: str,
    error_message: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Increments retry_count and stores a safe retryable pending state.
    Does NOT count toward level qualification.
    """
    _ready()
    existing = get_payment_record(payment_id)
    if not existing:
        raise ValueError(f"Payment {payment_id} not found")
    if existing["status"] == "verified":
        return existing

    now_ts = _now_iso()
    err = error_message[:500] if error_message else existing.get("error_message")

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE payment_records
                    SET status = 'pending',
                        retry_count = retry_count + 1,
                        error_message = %s,
                        updated_at = %s
                    WHERE payment_id = %s;
                    """,
                    (err, now_ts, payment_id),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                UPDATE payment_records
                SET status = 'pending',
                    retry_count = retry_count + 1,
                    error_message = ?,
                    updated_at = ?
                WHERE payment_id = ?
                """,
                (err, now_ts, payment_id),
            )
            chat_db._sqlite_conn.commit()

    return get_payment_record(payment_id)  # type: ignore[return-value]


def list_user_payment_records(user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    _ready()
    uid = (user_id or "").strip()
    lim = max(1, min(limit, 200))
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT * FROM payment_records
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s;
                    """,
                    (uid, lim),
                )
                return [_serialize_payment_record(r) for r in cur.fetchall()]
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            """
            SELECT * FROM payment_records
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (uid, lim),
        )
        return [_serialize_payment_record(r) for r in cur.fetchall()]


def admin_list_payment_records(
    limit: int = 100,
    status_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    _ready()
    lim = max(1, min(limit, 300))
    stat = status_filter.strip().lower() if status_filter else None

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                if stat:
                    cur.execute(
                        "SELECT * FROM payment_records WHERE status = %s ORDER BY created_at DESC LIMIT %s;",
                        (stat, lim),
                    )
                else:
                    cur.execute(
                        "SELECT * FROM payment_records ORDER BY created_at DESC LIMIT %s;",
                        (lim,),
                    )
                return [_serialize_payment_record(r) for r in cur.fetchall()]
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        if stat:
            cur.execute(
                "SELECT * FROM payment_records WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (stat, lim),
            )
        else:
            cur.execute(
                "SELECT * FROM payment_records ORDER BY created_at DESC LIMIT ?",
                (lim,),
            )
        return [_serialize_payment_record(r) for r in cur.fetchall()]


# ============================================================================
# OPEN PUBLIC CHAT (READABLE FEED + GUEST POLICY + EDIT/DELETE + PAGINATION)
# ============================================================================

def insert_public_chat_message(
    content: str,
    author_user_id: Optional[str],
    guest_id: Optional[str],
    display_name: str,
    author_level: int = 7,
    is_guest: bool = False,
) -> Dict[str, Any]:
    _ready()
    message_id = f"pub_{secrets.token_hex(12)}"
    ts = _now_iso()

    # Duplicate burst protection (same author/guest posting identical content within last 15s)
    # is folded into the INSERT itself (INSERT ... WHERE NOT EXISTS): ONE database round trip
    # instead of a separate SELECT followed by an INSERT.
    recent_cutoff = (_now() - timedelta(seconds=15)).isoformat()
    dup_col, dup_val = ("author_user_id", author_user_id) if author_user_id else ("guest_id", guest_id)
    dup_msg = "Duplicate message detected; please wait before repeating the same message"

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            # A single INSERT is atomic on its own: autocommit makes it ONE network round trip
            # (no separate COMMIT). The flag is a local setting, reset before the connection is pooled.
            conn.autocommit = True
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    f"""
                    INSERT INTO public_chat_messages (
                        message_id, author_user_id, guest_id, display_name,
                        author_level, is_guest, content, deleted, created_at
                    )
                    SELECT %s, %s, %s, %s, %s, %s, %s, FALSE, %s
                    WHERE NOT EXISTS (
                        SELECT 1 FROM public_chat_messages
                        WHERE {dup_col} = %s AND content = %s AND created_at >= %s AND deleted = FALSE
                    )
                    RETURNING seq;
                    """,
                    (message_id, author_user_id, guest_id, display_name, author_level, is_guest, content, ts,
                     dup_val, content, recent_cutoff),
                )
                row = cur.fetchone()
                if not row:
                    raise ValueError(dup_msg)
                seq = int(row["seq"])
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
                f"""
                INSERT INTO public_chat_messages (
                    message_id, author_user_id, guest_id, display_name,
                    author_level, is_guest, content, deleted, created_at
                )
                SELECT ?, ?, ?, ?, ?, ?, ?, 0, ?
                WHERE NOT EXISTS (
                    SELECT 1 FROM public_chat_messages
                    WHERE {dup_col} = ? AND content = ? AND created_at >= ? AND deleted = 0
                )
                """,
                (message_id, author_user_id, guest_id, display_name, author_level, 1 if is_guest else 0, content, ts,
                 dup_val, content, recent_cutoff),
            )
            if cur.rowcount == 0:
                chat_db._sqlite_conn.rollback()
                raise ValueError(dup_msg)
            seq = int(cur.lastrowid)
            chat_db._sqlite_conn.commit()

    return {
        "seq": seq,
        "message_id": message_id,
        "author_user_id": author_user_id,
        "display_name": display_name,
        "author_level": author_level,
        "is_guest": is_guest,
        "content": content,
        "edited_at": None,
        "deleted": False,
        "created_at": ts,
    }


def list_public_chat_messages(
    before_seq: Optional[int] = None,
    limit: int = 50,
    viewer_user_id: Optional[str] = None,
) -> Dict[str, Any]:
    _ready()
    blocked_ids = set(list_blocked_user_ids(viewer_user_id)) if viewer_user_id else set()
    settings = get_platform_settings()
    retention_days = int(settings.get("public_chat_retention_days") or 90)
    retention_cutoff = (_now() - timedelta(days=retention_days)).isoformat()

    rows: List[Any] = []
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                if before_seq is not None and before_seq > 0:
                    cur.execute(
                        """
                        SELECT seq, message_id, author_user_id, display_name, author_level,
                               is_guest, content, edited_at, deleted, created_at
                        FROM public_chat_messages
                        WHERE deleted = FALSE AND created_at >= %s AND seq < %s
                        ORDER BY seq DESC LIMIT %s;
                        """,
                        (retention_cutoff, before_seq, limit),
                    )
                else:
                    cur.execute(
                        """
                        SELECT seq, message_id, author_user_id, display_name, author_level,
                               is_guest, content, edited_at, deleted, created_at
                        FROM public_chat_messages
                        WHERE deleted = FALSE AND created_at >= %s
                        ORDER BY seq DESC LIMIT %s;
                        """,
                        (retention_cutoff, limit),
                    )
                rows = cur.fetchall()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            if before_seq is not None and before_seq > 0:
                cur.execute(
                    """
                    SELECT seq, message_id, author_user_id, display_name, author_level,
                           is_guest, content, edited_at, deleted, created_at
                    FROM public_chat_messages
                    WHERE deleted = 0 AND created_at >= ? AND seq < ?
                    ORDER BY seq DESC LIMIT ?
                    """,
                    (retention_cutoff, before_seq, limit),
                )
            else:
                cur.execute(
                    """
                    SELECT seq, message_id, author_user_id, display_name, author_level,
                           is_guest, content, edited_at, deleted, created_at
                    FROM public_chat_messages
                    WHERE deleted = 0 AND created_at >= ?
                    ORDER BY seq DESC LIMIT ?
                    """,
                    (retention_cutoff, limit),
                )
            rows = cur.fetchall()

    items = []
    for r in reversed(rows):
        if r["author_user_id"] and r["author_user_id"] in blocked_ids:
            continue
        items.append({
            "seq": int(r["seq"]),
            "message_id": r["message_id"],
            "author_user_id": r["author_user_id"],
            "display_name": r["display_name"],
            "author_level": int(r["author_level"] or 7),
            "is_guest": bool(r["is_guest"]),
            "content": r["content"],
            "edited_at": _iso(r["edited_at"]),
            "created_at": _iso(r["created_at"]),
        })

    next_cursor = int(rows[-1]["seq"]) if len(rows) == limit else None
    return {"messages": items, "next_before_seq": next_cursor}


def edit_public_chat_message(
    message_id: str,
    actor_user_id: str,
    new_content: str,
) -> Dict[str, Any]:
    _ready()
    settings = get_platform_settings()
    edit_window = int(settings.get("public_chat_edit_window_seconds") or 900)
    now = _now()
    ts = now.isoformat()

    row: Optional[Any] = None
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM public_chat_messages WHERE message_id = %s;",
                    (message_id,),
                )
                row = cur.fetchone()
                if not row or row["deleted"]:
                    raise ValueError("Public message not found")
                if row["author_user_id"] != actor_user_id:
                    raise PermissionError("Only the original verified author can edit this message")
                created_dt = datetime.fromisoformat(_iso(row["created_at"]).replace("Z", "+00:00"))  # type: ignore[union-attr]
                if (now - created_dt).total_seconds() > edit_window:
                    raise PermissionError("Message edit window has expired")
                cur.execute(
                    "UPDATE public_chat_messages SET content = %s, edited_at = %s WHERE message_id = %s;",
                    (new_content, ts, message_id),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute("SELECT * FROM public_chat_messages WHERE message_id = ?", (message_id,))
            row = cur.fetchone()
            if not row or row["deleted"]:
                raise ValueError("Public message not found")
            if row["author_user_id"] != actor_user_id:
                raise PermissionError("Only the original verified author can edit this message")
            created_dt = datetime.fromisoformat(str(row["created_at"]).replace("Z", "+00:00"))
            if (now - created_dt).total_seconds() > edit_window:
                raise PermissionError("Message edit window has expired")
            cur.execute(
                "UPDATE public_chat_messages SET content = ?, edited_at = ? WHERE message_id = ?",
                (new_content, ts, message_id),
            )
            chat_db._sqlite_conn.commit()

    return {
        "message_id": message_id,
        "content": new_content,
        "edited_at": ts,
    }


def delete_public_chat_message(
    message_id: str,
    actor_user_id: str,
    is_moderator: bool = False,
    reason: str = "",
) -> Dict[str, Any]:
    _ready()
    ts = _now_iso()
    target_author: Optional[str] = None

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute("SELECT * FROM public_chat_messages WHERE message_id = %s;", (message_id,))
                row = cur.fetchone()
                if not row:
                    raise ValueError("Public message not found")
                target_author = row["author_user_id"]
                if not is_moderator and target_author != actor_user_id:
                    raise PermissionError("Not authorized to delete this message")
                cur.execute(
                    "UPDATE public_chat_messages SET deleted = TRUE, deleted_by = %s WHERE message_id = %s;",
                    (actor_user_id, message_id),
                )
                if is_moderator and target_author != actor_user_id:
                    cur.execute(
                        """
                        INSERT INTO moderation_actions (
                            action_id, moderator_user_id, target_user_id,
                            target_type, target_id, action_type, reason, created_at
                        ) VALUES (%s, %s, %s, 'public_message', %s, 'delete_message', %s, %s);
                        """,
                        (f"mod_{secrets.token_hex(10)}", actor_user_id, target_author, message_id, reason, ts),
                    )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute("SELECT * FROM public_chat_messages WHERE message_id = ?", (message_id,))
            row = cur.fetchone()
            if not row:
                raise ValueError("Public message not found")
            target_author = row["author_user_id"]
            if not is_moderator and target_author != actor_user_id:
                raise PermissionError("Not authorized to delete this message")
            cur.execute(
                "UPDATE public_chat_messages SET deleted = 1, deleted_by = ? WHERE message_id = ?",
                (actor_user_id, message_id),
            )
            if is_moderator and target_author != actor_user_id:
                cur.execute(
                    """
                    INSERT INTO moderation_actions (
                        action_id, moderator_user_id, target_user_id,
                        target_type, target_id, action_type, reason, created_at
                    ) VALUES (?, ?, ?, 'public_message', ?, 'delete_message', ?, ?)
                    """,
                    (f"mod_{secrets.token_hex(10)}", actor_user_id, target_author, message_id, reason, ts),
                )
            chat_db._sqlite_conn.commit()

    if is_moderator:
        record_audit_log(actor_user_id, "public_message_moderated", "public_message", message_id, {"reason": reason})
    return {"message_id": message_id, "deleted": True}


# ============================================================================
# USER SEARCH, BLOCKING, DM READ RECEIPTS & ABUSE REPORTS
# ============================================================================

def search_users_directory(query: str, limit: int = 25, exclude_user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    _ready()
    q = query.strip().lstrip("@")
    pattern = f"%{q.lower()}%" if q else "%"

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT user_id, username, display_name, bio, current_level,
                           show_online_presence, account_status, created_at
                    FROM chat_users
                    WHERE account_status != 'suspended'
                      AND (
                          LOWER(COALESCE(username, '')) LIKE %s
                          OR LOWER(COALESCE(display_name, '')) LIKE %s
                          OR LOWER(user_id) LIKE %s
                      )
                    ORDER BY current_level DESC, created_at DESC
                    LIMIT %s;
                    """,
                    (pattern, pattern, pattern, limit),
                )
                rows = cur.fetchall()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                SELECT user_id, username, display_name, bio, current_level,
                       show_online_presence, account_status, created_at
                FROM chat_users
                WHERE account_status != 'suspended'
                  AND (
                      LOWER(COALESCE(username, '')) LIKE ?
                      OR LOWER(COALESCE(display_name, '')) LIKE ?
                      OR LOWER(user_id) LIKE ?
                  )
                ORDER BY current_level DESC, created_at DESC
                LIMIT ?
                """,
                (pattern, pattern, pattern, limit),
            )
            rows = cur.fetchall()

    results = []
    for r in rows:
        if exclude_user_id and r["user_id"] == exclude_user_id:
            continue
        results.append({
            "user_id": r["user_id"],
            "username": r["username"],
            "display_name": r["display_name"],
            "bio": r["bio"],
            "current_level": int(r["current_level"] or 7),
            "show_online_presence": bool(r["show_online_presence"]),
            "created_at": _iso(r["created_at"]),
        })
    return results


@auth_cache.invalidates_auth_cache(namespaces=('blocked',))
def block_user(blocker_user_id: str, blocked_user_id: str, reason: str = "") -> None:
    _ready()
    if blocker_user_id == blocked_user_id:
        raise ValueError("Cannot block your own account")
    ts = _now_iso()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO user_blocks (blocker_user_id, blocked_user_id, reason, created_at)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (blocker_user_id, blocked_user_id) DO UPDATE SET reason = EXCLUDED.reason;
                    """,
                    (blocker_user_id, blocked_user_id, reason.strip()[:200], ts),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                INSERT INTO user_blocks (blocker_user_id, blocked_user_id, reason, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(blocker_user_id, blocked_user_id) DO UPDATE SET reason = excluded.reason
                """,
                (blocker_user_id, blocked_user_id, reason.strip()[:200], ts),
            )
            chat_db._sqlite_conn.commit()


@auth_cache.invalidates_auth_cache(namespaces=('blocked',))
def unblock_user(blocker_user_id: str, blocked_user_id: str) -> None:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM user_blocks WHERE blocker_user_id = %s AND blocked_user_id = %s;",
                    (blocker_user_id, blocked_user_id),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                "DELETE FROM user_blocks WHERE blocker_user_id = ? AND blocked_user_id = ?",
                (blocker_user_id, blocked_user_id),
            )
            chat_db._sqlite_conn.commit()


def list_blocked_user_ids(blocker_user_id: str) -> List[str]:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT blocked_user_id FROM user_blocks WHERE blocker_user_id = %s;",
                    (blocker_user_id,),
                )
                return [r[0] for r in cur.fetchall()]
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute("SELECT blocked_user_id FROM user_blocks WHERE blocker_user_id = ?", (blocker_user_id,))
        return [r["blocked_user_id"] for r in cur.fetchall()]


def list_blocked_users_detailed(blocker_user_id: str) -> List[Dict[str, Any]]:
    _ready()
    ids = list_blocked_user_ids(blocker_user_id)
    out = []
    for uid in ids:
        u = e2ee_db.get_user_by_id(uid)
        out.append({
            "user_id": uid,
            "blocked_user_id": uid,
            "username": u["username"] if u else None,
            "created_at": _now_iso(),
        })
    return out


@auth_cache.read_cached("blocked")
def is_blocked_between(user_a: str, user_b: str) -> bool:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT 1 FROM user_blocks
                    WHERE (blocker_user_id = %s AND blocked_user_id = %s)
                       OR (blocker_user_id = %s AND blocked_user_id = %s)
                    LIMIT 1;
                    """,
                    (user_a, user_b, user_b, user_a),
                )
                return cur.fetchone() is not None
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            """
            SELECT 1 FROM user_blocks
            WHERE (blocker_user_id = ? AND blocked_user_id = ?)
               OR (blocker_user_id = ? AND blocked_user_id = ?)
            LIMIT 1
            """,
            (user_a, user_b, user_b, user_a),
        )
        return cur.fetchone() is not None


def upsert_dm_read_receipt(user_id: str, peer_user_id: str, last_read_seq: int) -> Optional[Dict[str, Any]]:
    _ready()
    ext = get_extended_user_fields(user_id)
    if not ext.get("send_read_receipts", True):
        return None
    conv_id = e2ee_db.make_dm_conversation_id(user_id, peer_user_id)
    ts = _now_iso()

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO chat_dm_receipts (conversation_id, user_id, last_read_seq, updated_at)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (conversation_id, user_id) DO UPDATE SET
                        last_read_seq = GREATEST(chat_dm_receipts.last_read_seq, EXCLUDED.last_read_seq),
                        updated_at = EXCLUDED.updated_at;
                    """,
                    (conv_id, user_id, last_read_seq, ts),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                INSERT INTO chat_dm_receipts (conversation_id, user_id, last_read_seq, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(conversation_id, user_id) DO UPDATE SET
                    last_read_seq = MAX(chat_dm_receipts.last_read_seq, excluded.last_read_seq),
                    updated_at = excluded.updated_at
                """,
                (conv_id, user_id, last_read_seq, ts),
            )
            chat_db._sqlite_conn.commit()

    return {"conversation_id": conv_id, "user_id": user_id, "last_read_seq": last_read_seq, "updated_at": ts}


def get_dm_read_receipts(user_id: str, peer_user_id: str) -> Dict[str, Any]:
    _ready()
    conv_id = e2ee_db.make_dm_conversation_id(user_id, peer_user_id)
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    "SELECT user_id, last_read_seq, updated_at FROM chat_dm_receipts WHERE conversation_id = %s;",
                    (conv_id,),
                )
                return {
                    r["user_id"]: {"last_read_seq": int(r["last_read_seq"]), "updated_at": _iso(r["updated_at"])}
                    for r in cur.fetchall()
                }
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            "SELECT user_id, last_read_seq, updated_at FROM chat_dm_receipts WHERE conversation_id = ?",
            (conv_id,),
        )
        return {
            r["user_id"]: {"last_read_seq": int(r["last_read_seq"]), "updated_at": _iso(r["updated_at"])}
            for r in cur.fetchall()
        }


def create_abuse_report(
    reporter_user_id: str,
    scope_type: str,
    scope_id: str,
    reason: str,
    details: str = "",
    target_user_id: Optional[str] = None,
    message_id: Optional[str] = None,
) -> Dict[str, Any]:
    _ready()
    report_id = f"rep_{secrets.token_hex(10)}"
    ts = _now_iso()

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO message_reports (
                        report_id, reporter_user_id, target_user_id, scope_type, scope_id,
                        message_id, reason, details, status, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'open', %s);
                    """,
                    (report_id, reporter_user_id, target_user_id, scope_type, scope_id, message_id, reason, details, ts),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                INSERT INTO message_reports (
                    report_id, reporter_user_id, target_user_id, scope_type, scope_id,
                    message_id, reason, details, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
                """,
                (report_id, reporter_user_id, target_user_id, scope_type, scope_id, message_id, reason, details, ts),
            )
            chat_db._sqlite_conn.commit()

    return {
        "report_id": report_id,
        "status": "open",
        "created_at": ts,
    }


def list_abuse_reports(status_filter: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                if status_filter:
                    cur.execute(
                        "SELECT * FROM message_reports WHERE status = %s ORDER BY created_at DESC LIMIT %s;",
                        (status_filter, limit),
                    )
                else:
                    cur.execute(
                        "SELECT * FROM message_reports ORDER BY created_at DESC LIMIT %s;",
                        (limit,),
                    )
                rows = cur.fetchall()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            if status_filter:
                cur.execute(
                    "SELECT * FROM message_reports WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                    (status_filter, limit),
                )
            else:
                cur.execute(
                    "SELECT * FROM message_reports ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                )
            rows = cur.fetchall()

    return [
        {
            "report_id": r["report_id"],
            "reporter_user_id": r["reporter_user_id"],
            "target_user_id": r["target_user_id"],
            "scope_type": r["scope_type"],
            "scope_id": r["scope_id"],
            "message_id": r["message_id"],
            "reason": r["reason"],
            "details": r["details"],
            "status": r["status"],
            "resolution_note": r["resolution_note"],
            "reviewed_by": r["reviewed_by"],
            "reviewed_at": _iso(r["reviewed_at"]),
            "created_at": _iso(r["created_at"]),
        }
        for r in rows
    ]


def resolve_abuse_report(
    report_id: str,
    reviewer_user_id: str,
    new_status: str,
    resolution_note: str = "",
) -> Dict[str, Any]:
    _ready()
    ts = _now_iso()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE message_reports
                    SET status = %s, resolution_note = %s, reviewed_by = %s, reviewed_at = %s
                    WHERE report_id = %s;
                    """,
                    (new_status, resolution_note, reviewer_user_id, ts, report_id),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                UPDATE message_reports
                SET status = ?, resolution_note = ?, reviewed_by = ?, reviewed_at = ?
                WHERE report_id = ?
                """,
                (new_status, resolution_note, reviewer_user_id, ts, report_id),
            )
            chat_db._sqlite_conn.commit()

    record_audit_log(
        reviewer_user_id,
        "abuse_report_resolved",
        "report",
        report_id,
        {"status": new_status, "resolution_note": resolution_note},
    )
    return {"report_id": report_id, "status": new_status, "reviewed_at": ts}


# ============================================================================
# GROUP ACCESS POLICIES, INVITE LINKS, DISCOVERY & LEAVE GROUP
# ============================================================================

@auth_cache.read_cached("group_policy")
def get_group_access_policy(group_id: str) -> Dict[str, Any]:
    _ready()
    row: Optional[Any] = None
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute("SELECT * FROM group_access_policies WHERE group_id = %s;", (group_id,))
                row = cur.fetchone()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute("SELECT * FROM group_access_policies WHERE group_id = ?", (group_id,))
            row = cur.fetchone()

    return _policy_from_row(group_id, row)


def _policy_from_row(group_id: str, row: Optional[Any]) -> Dict[str, Any]:
    if not row:
        return {
            "group_id": group_id,
            "description": "",
            "avatar_url": None,
            "visibility": "invite_only",
            "min_level": 7,
            "min_eth_balance_wei": "0",
            "require_invitation": True,
            "is_paid": False,
            "entry_fee_eth": "0",
            "entry_fee_usd": "0",
            "entry_fee_wei": "0",
        }

    is_paid = False
    try:
        if "is_paid" in row.keys() and row["is_paid"]:
            is_paid = bool(row["is_paid"])
    except Exception:
        pass

    fee_eth = "0"
    try:
        if "entry_fee_eth" in row.keys() and row["entry_fee_eth"]:
            fee_eth = str(row["entry_fee_eth"])
    except Exception:
        pass

    fee_wei = "0"
    try:
        if "entry_fee_wei" in row.keys() and row["entry_fee_wei"]:
            fee_wei = str(row["entry_fee_wei"])
    except Exception:
        pass

    fee_usd_str = "0"
    try:
        if "entry_fee_usd" in row.keys() and row["entry_fee_usd"]:
            fee_usd_str = str(row["entry_fee_usd"])
    except Exception:
        pass

    return {
        "group_id": row["group_id"],
        "description": row["description"] or "",
        "avatar_url": row["avatar_url"],
        "visibility": row["visibility"] or "invite_only",
        "min_level": int(row["min_level"] or 7),
        "min_eth_balance_wei": str(row["min_eth_balance_wei"] or "0"),
        "require_invitation": bool(row["require_invitation"]),
        "is_paid": is_paid,
        "entry_fee_eth": fee_eth,
        "entry_fee_usd": fee_usd_str,
        "entry_fee_wei": fee_wei,
        "updated_at": _iso(row["updated_at"]),
    }


def get_group_access_policies_batch(group_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """Policies for many groups in ONE query (same shape as get_group_access_policy)."""
    _ready()
    ids = list(dict.fromkeys(group_ids))
    rows: Dict[str, Any] = {}
    if ids:
        if _is_pg():
            conn = chat_db._pg_pool.getconn()
            try:
                with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                    cur.execute("SELECT * FROM group_access_policies WHERE group_id = ANY(%s);", (ids,))
                    rows = {r["group_id"]: r for r in cur.fetchall()}
            finally:
                chat_db._pg_pool.putconn(conn)
        else:
            marks = ",".join("?" for _ in ids)
            with chat_db._sqlite_lock:
                cur = chat_db._sqlite_conn.cursor()
                cur.execute(f"SELECT * FROM group_access_policies WHERE group_id IN ({marks})", ids)
                rows = {r["group_id"]: r for r in cur.fetchall()}
    return {gid: _policy_from_row(gid, rows.get(gid)) for gid in ids}


@auth_cache.invalidates_auth_cache(namespaces=('group', 'group_policy', 'user_groups'))
def upsert_group_access_policy(
    group_id: str,
    description: str,
    avatar_url: Optional[str],
    visibility: str,
    min_level: int = 7,
    min_eth_balance_wei: str = "0",
    require_invitation: bool = True,
    actor_user_id: str = "system",
    is_paid: bool = False,
    entry_fee_eth: str = "0",
    entry_fee_usd: Optional[Any] = None,
) -> Dict[str, Any]:
    _ready()
    if min_level < 7:
        raise ValueError("Group min_level must be >= 7")
    if int(min_eth_balance_wei) < 0:
        raise ValueError("min_eth_balance_wei cannot be negative")

    try:
        fee_float = float(entry_fee_eth or "0")
        if fee_float < 0:
            raise ValueError("Group entry fee cannot be negative")
        clean_entry_fee_eth = str(entry_fee_eth).strip()
        clean_entry_fee_wei = str(Web3.to_wei(fee_float, "ether"))
    except ValueError as v_err:
        raise v_err
    except Exception:
        clean_entry_fee_eth = "0"
        clean_entry_fee_wei = "0"

    # USD price (the way admins set it). If given, it replaces the legacy fixed-ETH fee.
    if entry_fee_usd is None:
        clean_entry_fee_usd = None
    else:
        try:
            usd_flt = float(entry_fee_usd)
            if usd_flt < 0 or usd_flt > 100000:
                raise ValueError("Group entry fee (USD) must be between 0 and 100000")
        except (TypeError, ValueError) as v_err:
            raise ValueError(str(v_err) if "Group entry" in str(v_err) else "Invalid group entry fee (USD)")
        clean_entry_fee_usd = str(round(usd_flt, 2))
        clean_entry_fee_eth, clean_entry_fee_wei = "0", "0"  # USD is now the source of truth
    if is_paid and clean_entry_fee_usd is None and float(clean_entry_fee_eth or 0) <= 0:
        raise ValueError("A paid group needs an entry fee greater than 0")
    if is_paid and clean_entry_fee_usd is not None and float(clean_entry_fee_usd) <= 0:
        raise ValueError("A paid group needs an entry fee greater than 0")
    if not is_paid:
        clean_entry_fee_usd, clean_entry_fee_eth, clean_entry_fee_wei = "0", "0", "0"
    if clean_entry_fee_usd is None:
        clean_entry_fee_usd = "0"

    ts = _now_iso()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            conn.autocommit = True  # single atomic statement: one round trip, no separate COMMIT
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO group_access_policies (
                        group_id, description, avatar_url, visibility,
                        min_level, min_eth_balance_wei, require_invitation,
                        is_paid, entry_fee_eth, entry_fee_wei, entry_fee_usd,
                        updated_by, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (group_id) DO UPDATE SET
                        description = EXCLUDED.description,
                        avatar_url = EXCLUDED.avatar_url,
                        visibility = EXCLUDED.visibility,
                        min_level = EXCLUDED.min_level,
                        min_eth_balance_wei = EXCLUDED.min_eth_balance_wei,
                        require_invitation = EXCLUDED.require_invitation,
                        is_paid = EXCLUDED.is_paid,
                        entry_fee_eth = EXCLUDED.entry_fee_eth,
                        entry_fee_wei = EXCLUDED.entry_fee_wei,
                        entry_fee_usd = EXCLUDED.entry_fee_usd,
                        updated_by = EXCLUDED.updated_by,
                        updated_at = EXCLUDED.updated_at;
                    """,
                    (
                        group_id,
                        description.strip()[:500],
                        avatar_url,
                        visibility,
                        min_level,
                        str(int(min_eth_balance_wei)),
                        require_invitation,
                        bool(is_paid),
                        clean_entry_fee_eth,
                        clean_entry_fee_wei,
                        clean_entry_fee_usd,
                        actor_user_id,
                        ts,
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
                INSERT INTO group_access_policies (
                    group_id, description, avatar_url, visibility,
                    min_level, min_eth_balance_wei, require_invitation,
                    is_paid, entry_fee_eth, entry_fee_wei, entry_fee_usd,
                    updated_by, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(group_id) DO UPDATE SET
                    description = excluded.description,
                    avatar_url = excluded.avatar_url,
                    visibility = excluded.visibility,
                    min_level = excluded.min_level,
                    min_eth_balance_wei = excluded.min_eth_balance_wei,
                    require_invitation = excluded.require_invitation,
                    is_paid = excluded.is_paid,
                    entry_fee_eth = excluded.entry_fee_eth,
                    entry_fee_wei = excluded.entry_fee_wei,
                    entry_fee_usd = excluded.entry_fee_usd,
                    updated_by = excluded.updated_by,
                    updated_at = excluded.updated_at
                """,
                (
                    group_id,
                    description.strip()[:500],
                    avatar_url,
                    visibility,
                    min_level,
                    str(int(min_eth_balance_wei)),
                    1 if require_invitation else 0,
                    1 if is_paid else 0,
                    clean_entry_fee_eth,
                    clean_entry_fee_wei,
                    clean_entry_fee_usd,
                    actor_user_id,
                    ts,
                ),
            )
            chat_db._sqlite_conn.commit()

    record_audit_log(
        actor_user_id,
        "group_policy_updated",
        "group",
        group_id,
        {
            "visibility": visibility,
            "min_level": min_level,
            "min_eth_balance_wei": str(int(min_eth_balance_wei)),
            "is_paid": bool(is_paid),
            "entry_fee_eth": clean_entry_fee_eth,
            "entry_fee_usd": clean_entry_fee_usd,
        },
    )
    return get_group_access_policy(group_id)


def verify_user_meets_group_policy(group_id: str, candidate_user_id: str) -> Tuple[bool, str]:
    """
    Server-side group access policy gate enforcing:
    1. Active non-suspended account
    2. Minimum verified ETH balance check (`policy.min_eth_balance_wei`)
    3. Paid group status: If group is marked `is_paid`, candidate must have paid group entry fee
    """
    ext = get_extended_user_fields(candidate_user_id)
    if not ext:
        return False, "Candidate user account not found"
    if ext.get("account_status") == "suspended":
        return False, "Account is currently suspended"

    pol = get_group_access_policy(group_id)
    req_bal = int(pol.get("min_eth_balance_wei") or "0")
    user_bal = int(ext.get("qualifying_balance_wei") or "0")

    if user_bal < req_bal:
        return (
            False,
            f"Requires verified ETH balance >= {req_bal} Wei (verify your wallet balance in Settings)",
        )

    if pol.get("is_paid"):
        # People already inside when a group becomes paid keep their place; the fee applies to newcomers.
        if e2ee_db.is_active_group_member(group_id, candidate_user_id):
            return True, "ok"
        if not has_user_paid_group_entry(candidate_user_id, group_id):
            gp = get_group_pricing(group_id)
            return False, f"Paid group: requires an entry fee of ${gp['entry_fee_usd']:.2f} ({gp['entry_fee_eth']} ETH)"

    return True, "ok"


def list_discoverable_groups(viewer_user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT g.group_id, g.name, g.creator_user_id, g.current_epoch,
                           p.description, p.avatar_url, p.visibility, p.min_level,
                           p.min_eth_balance_wei, p.require_invitation,
                           p.is_paid, p.entry_fee_eth, p.entry_fee_wei,
                           (SELECT COUNT(DISTINCT m.user_id) FROM chat_group_members m WHERE m.group_id = g.group_id AND m.status = 'active') AS member_count
                    FROM chat_groups g
                    JOIN group_access_policies p ON p.group_id = g.group_id
                    WHERE p.visibility = 'public'
                    ORDER BY g.created_bucket DESC;
                    """
                )
                rows = cur.fetchall()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                SELECT g.group_id, g.name, g.creator_user_id, g.current_epoch,
                       p.description, p.avatar_url, p.visibility, p.min_level,
                       p.min_eth_balance_wei, p.require_invitation,
                       p.is_paid, p.entry_fee_eth, p.entry_fee_wei,
                       (SELECT COUNT(DISTINCT m.user_id) FROM chat_group_members m WHERE m.group_id = g.group_id AND m.status = 'active') AS member_count
                FROM chat_groups g
                JOIN group_access_policies p ON p.group_id = g.group_id
                WHERE p.visibility = 'public'
                ORDER BY g.created_bucket DESC
                """
            )
            rows = cur.fetchall()

    out = []
    for r in rows:
        gid = r["group_id"]
        is_member = e2ee_db.is_active_group_member(gid, viewer_user_id) if viewer_user_id else False
        eligible, reason = (
            verify_user_meets_group_policy(gid, viewer_user_id)
            if viewer_user_id
            else (False, "Sign in with MetaMask to check eligibility")
        )
        cnt = int(r["member_count"] or 0)
        is_paid = bool(r["is_paid"] if "is_paid" in r.keys() else False)
        fee_eth = str(r["entry_fee_eth"] if "entry_fee_eth" in r.keys() else "0")
        fee_wei = str(r["entry_fee_wei"] if "entry_fee_wei" in r.keys() else "0")
        has_paid = has_user_paid_group_entry(viewer_user_id, gid) if (viewer_user_id and is_paid) else True

        out.append({
            "group_id": gid,
            "name": r["name"],
            "description": r["description"] or "",
            "avatar_url": r["avatar_url"],
            "visibility": r["visibility"],
            "min_level": int(r["min_level"] or 7),
            "min_eth_balance_wei": str(r["min_eth_balance_wei"] or "0"),
            "require_invitation": bool(r["require_invitation"]),
            "is_paid": is_paid,
            "entry_fee_eth": fee_eth,
            "entry_fee_wei": fee_wei,
            "has_paid": has_paid,
            "member_count": cnt,
            "active_member_count": cnt,
            "is_member": is_member,
            "eligible": eligible,
            "eligibility_reason": reason,
        })
    return out


def create_group_invite_link(
    group_id: str,
    creator_user_id: str,
    expires_hours: int = 72,
    max_uses: int = 25,
) -> Dict[str, Any]:
    _ready()
    code = f"zinv_{secrets.token_urlsafe(12)}"
    now = _now()
    exp = (now + timedelta(hours=max(1, expires_hours))).isoformat()
    ts = now.isoformat()

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO group_invite_links (
                        invite_code, group_id, created_by, expires_at, max_uses, use_count, revoked, created_at
                    ) VALUES (%s, %s, %s, %s, %s, 0, FALSE, %s);
                    """,
                    (code, group_id, creator_user_id, exp, max_uses, ts),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                INSERT INTO group_invite_links (
                    invite_code, group_id, created_by, expires_at, max_uses, use_count, revoked, created_at
                ) VALUES (?, ?, ?, ?, ?, 0, 0, ?)
                """,
                (code, group_id, creator_user_id, exp, max_uses, ts),
            )
            chat_db._sqlite_conn.commit()

    return {
        "invite_code": code,
        "group_id": group_id,
        "expires_at": exp,
        "max_uses": max_uses,
        "use_count": 0,
        "uses_count": 0,
        "revoked": False,
    }


def list_group_invite_links(group_id: str) -> List[Dict[str, Any]]:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM group_invite_links WHERE group_id = %s ORDER BY created_at DESC;",
                    (group_id,),
                )
                return [
                    {
                        "invite_code": r["invite_code"],
                        "group_id": r["group_id"],
                        "created_by": r["created_by"],
                        "expires_at": _iso(r["expires_at"]),
                        "max_uses": int(r["max_uses"]),
                        "use_count": int(r["use_count"]),
                        "uses_count": int(r["use_count"]),
                        "revoked": bool(r["revoked"]),
                    }
                    for r in cur.fetchall()
                ]
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute("SELECT * FROM group_invite_links WHERE group_id = ? ORDER BY created_at DESC", (group_id,))
        return [
            {
                "invite_code": r["invite_code"],
                "group_id": r["group_id"],
                "created_by": r["created_by"],
                "expires_at": _iso(r["expires_at"]),
                "max_uses": int(r["max_uses"]),
                "use_count": int(r["use_count"]),
                "uses_count": int(r["use_count"]),
                "revoked": bool(r["revoked"]),
            }
            for r in cur.fetchall()
        ]


def revoke_group_invite_link(group_id: str, invite_code: str) -> None:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE group_invite_links SET revoked = TRUE WHERE group_id = %s AND invite_code = %s;",
                    (group_id, invite_code),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                "UPDATE group_invite_links SET revoked = 1 WHERE group_id = ? AND invite_code = ?",
                (group_id, invite_code),
            )
            chat_db._sqlite_conn.commit()


def create_group_join_request(
    user_id: str,
    group_id: Optional[str] = None,
    invite_code: Optional[str] = None,
) -> Dict[str, Any]:
    _ready()
    now = _now()
    ts = now.isoformat()

    if invite_code:
        if _is_pg():
            conn = chat_db._pg_pool.getconn()
            try:
                with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                    cur.execute("SELECT * FROM group_invite_links WHERE invite_code = %s;", (invite_code,))
                    inv = cur.fetchone()
            finally:
                chat_db._pg_pool.putconn(conn)
        else:
            with chat_db._sqlite_lock:
                cur = chat_db._sqlite_conn.cursor()
                cur.execute("SELECT * FROM group_invite_links WHERE invite_code = ?", (invite_code,))
                inv = cur.fetchone()

        if not inv or inv["revoked"]:
            raise ValueError("Invite link is invalid or has been revoked")
        exp_dt = datetime.fromisoformat(str(inv["expires_at"]).replace("Z", "+00:00"))
        if exp_dt <= now:
            raise ValueError("Invite link has expired")
        if int(inv["use_count"]) >= int(inv["max_uses"]):
            raise ValueError("Invite link has reached its maximum usage limit")
        group_id = inv["group_id"]

    if not group_id:
        raise ValueError("group_id or invite_code required")

    grp = e2ee_db.get_mls_group(group_id)
    if not grp:
        raise ValueError("Group not found")

    if e2ee_db.is_active_group_member(group_id, user_id):
        return {"status": "already_member", "group_id": group_id}

    pol = get_group_access_policy(group_id)
    if not invite_code and pol["visibility"] != "public":
        raise PermissionError("This group is invite-only; a valid invite link or admin invite is required")

    ok, reason = verify_user_meets_group_policy(group_id, user_id)
    if not ok:
        raise PermissionError(reason)

    req_id = f"greq_{secrets.token_hex(10)}"
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT request_id FROM group_join_requests
                    WHERE group_id = %s AND user_id = %s AND status = 'pending'
                    LIMIT 1;
                    """,
                    (group_id, user_id),
                )
                existing = cur.fetchone()
                if existing:
                    return {"request_id": existing[0], "group_id": group_id, "status": "pending_mls_welcome"}
                if invite_code:
                    cur.execute(
                        "UPDATE group_invite_links SET use_count = use_count + 1 WHERE invite_code = %s;",
                        (invite_code,),
                    )
                cur.execute(
                    """
                    INSERT INTO group_join_requests (request_id, group_id, user_id, invite_code, status, created_at)
                    VALUES (%s, %s, %s, %s, 'pending', %s);
                    """,
                    (req_id, group_id, user_id, invite_code, ts),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                SELECT request_id FROM group_join_requests
                WHERE group_id = ? AND user_id = ? AND status = 'pending'
                LIMIT 1
                """,
                (group_id, user_id),
            )
            existing = cur.fetchone()
            if existing:
                return {"request_id": existing["request_id"], "group_id": group_id, "status": "pending_mls_welcome"}
            if invite_code:
                cur.execute(
                    "UPDATE group_invite_links SET use_count = use_count + 1 WHERE invite_code = ?",
                    (invite_code,),
                )
            cur.execute(
                """
                INSERT INTO group_join_requests (request_id, group_id, user_id, invite_code, status, created_at)
                VALUES (?, ?, ?, ?, 'pending', ?)
                """,
                (req_id, group_id, user_id, invite_code, ts),
            )
            chat_db._sqlite_conn.commit()

    return {"request_id": req_id, "group_id": group_id, "status": "pending_mls_welcome"}


def list_pending_group_join_requests(group_id: str) -> List[Dict[str, Any]]:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT r.request_id, r.user_id, r.invite_code, r.created_at,
                           u.username, u.current_level, u.qualifying_balance_wei
                    FROM group_join_requests r
                    JOIN chat_users u ON u.user_id = r.user_id
                    WHERE r.group_id = %s AND r.status = 'pending'
                    ORDER BY r.created_at ASC;
                    """,
                    (group_id,),
                )
                return [
                    {
                        "request_id": r["request_id"],
                        "user_id": r["user_id"],
                        "username": r["username"],
                        "current_level": int(r["current_level"] or 7),
                        "qualifying_balance_wei": str(r["qualifying_balance_wei"] or "0"),
                        "invite_code": r["invite_code"],
                        "created_at": _iso(r["created_at"]),
                    }
                    for r in cur.fetchall()
                ]
        finally:
            chat_db._pg_pool.putconn(conn)

    with chat_db._sqlite_lock:
        cur = chat_db._sqlite_conn.cursor()
        cur.execute(
            """
            SELECT r.request_id, r.user_id, r.invite_code, r.created_at,
                   u.username, u.current_level, u.qualifying_balance_wei
            FROM group_join_requests r
            JOIN chat_users u ON u.user_id = r.user_id
            WHERE r.group_id = ? AND r.status = 'pending'
            ORDER BY r.created_at ASC
            """,
            (group_id,),
        )
        return [
            {
                "request_id": r["request_id"],
                "user_id": r["user_id"],
                "username": r["username"],
                "current_level": int(r["current_level"] or 7),
                "qualifying_balance_wei": str(r["qualifying_balance_wei"] or "0"),
                "invite_code": r["invite_code"],
                "created_at": _iso(r["created_at"]),
            }
            for r in cur.fetchall()
        ]


def mark_group_join_requests_approved(group_id: str, user_ids: List[str]) -> None:
    if not user_ids:
        return
    _ready()
    ts = _now_iso()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE group_join_requests
                    SET status = 'approved', reviewed_at = %s
                    WHERE group_id = %s AND user_id = ANY(%s) AND status = 'pending';
                    """,
                    (ts, group_id, user_ids),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            placeholders = ",".join("?" for _ in user_ids)
            cur.execute(
                f"""
                UPDATE group_join_requests
                SET status = 'approved', reviewed_at = ?
                WHERE group_id = ? AND user_id IN ({placeholders}) AND status = 'pending'
                """,
                [ts, group_id, *user_ids],
            )
            chat_db._sqlite_conn.commit()


@auth_cache.invalidates_auth_cache(namespaces=('group', 'user_groups'))
def leave_group_self(group_id: str, user_id: str) -> Dict[str, Any]:
    _ready()
    grp = e2ee_db.get_mls_group(group_id)
    if not grp:
        raise ValueError("Group not found")
    if not e2ee_db.is_active_group_member(group_id, user_id):
        raise PermissionError("You are not an active member of this group")

    active_members = [m for m in grp.get("members", []) if m["status"] == "active"]
    other_active_users = {m["user_id"] for m in active_members if m["user_id"] != user_id}
    other_active_admins = {
        m["user_id"]
        for m in active_members
        if m["user_id"] != user_id and (m.get("role") == "admin" or m["user_id"] == grp["creator_user_id"])
    }
    if other_active_users and not other_active_admins and is_group_admin(group_id, user_id):
        raise PermissionError("Promote another active member to admin before leaving this group")

    bucket = e2ee_db.coarse_timestamp_iso()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE chat_group_members
                    SET status = 'left', removed_epoch = %s, updated_bucket = %s
                    WHERE group_id = %s AND user_id = %s AND status = 'active';
                    """,
                    (grp["current_epoch"], bucket, group_id, user_id),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                UPDATE chat_group_members
                SET status = 'left', removed_epoch = ?, updated_bucket = ?
                WHERE group_id = ? AND user_id = ? AND status = 'active'
                """,
                (grp["current_epoch"], bucket, group_id, user_id),
            )
            chat_db._sqlite_conn.commit()

    return {"group_id": group_id, "user_id": user_id, "status": "left"}


def is_group_admin(group_id: str, user_id: str) -> bool:
    grp = e2ee_db.get_mls_group(group_id)
    if not grp:
        return False
    if grp["creator_user_id"] == user_id:
        return True
    for m in grp.get("members", []):
        if m["user_id"] == user_id and m["status"] == "active" and m.get("role") == "admin":
            return True
    return False


@auth_cache.invalidates_auth_cache(namespaces=('group', 'user_groups'))
def update_group_member_role(group_id: str, target_user_id: str, new_role: str, actor_user_id: str) -> None:
    _ready()
    if new_role not in ("admin", "member"):
        raise ValueError("Role must be 'admin' or 'member'")
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE chat_group_members
                    SET role = %s
                    WHERE group_id = %s AND user_id = %s AND status = 'active';
                    """,
                    (new_role, group_id, target_user_id),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                UPDATE chat_group_members
                SET role = ?
                WHERE group_id = ? AND user_id = ? AND status = 'active'
                """,
                (new_role, group_id, target_user_id),
            )
            chat_db._sqlite_conn.commit()

    record_audit_log(actor_user_id, "group_member_role_updated", "group", group_id, {"target_user_id": target_user_id, "role": new_role})


# ============================================================================
# ADMIN USER INSPECTION & ACCOUNT MODERATION
# ============================================================================

def admin_list_users(query: str = "", limit: int = 50) -> List[Dict[str, Any]]:
    _ready()
    q = query.strip().lstrip("@").lower()
    pattern = f"%{q}%" if q else "%"

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT u.user_id,
                           u.username,
                           u.qualifying_balance_wei,
                           u.account_status,
                           ar.role AS admin_role,
                           (
                               SELECT w2.wallet_address
                               FROM chat_user_wallets w2
                               WHERE w2.user_id = u.user_id AND w2.status = 'active'
                               ORDER BY w2.is_primary DESC, w2.linked_at DESC
                               LIMIT 1
                           ) AS primary_wallet
                    FROM chat_users u
                    LEFT JOIN admin_roles ar ON ar.user_id = u.user_id
                    WHERE (
                        %s = '%%'
                        OR LOWER(u.user_id) LIKE %s
                        OR LOWER(COALESCE(u.username, '')) LIKE %s
                        OR EXISTS (
                            SELECT 1 FROM chat_user_wallets w
                            WHERE w.user_id = u.user_id
                              AND LOWER(w.wallet_address) LIKE %s
                        )
                    )
                    ORDER BY u.created_at DESC
                    LIMIT %s;
                    """,
                    (pattern, pattern, pattern, pattern, limit),
                )
                rows = cur.fetchall()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                SELECT u.user_id,
                       u.username,
                       u.qualifying_balance_wei,
                       u.account_status,
                       ar.role AS admin_role,
                       (
                           SELECT w2.wallet_address
                           FROM chat_user_wallets w2
                           WHERE w2.user_id = u.user_id AND w2.status = 'active'
                           ORDER BY w2.is_primary DESC, w2.linked_at DESC
                           LIMIT 1
                       ) AS primary_wallet
                FROM chat_users u
                LEFT JOIN admin_roles ar ON ar.user_id = u.user_id
                WHERE (
                    ? = '%'
                    OR LOWER(u.user_id) LIKE ?
                    OR LOWER(COALESCE(u.username, '')) LIKE ?
                    OR EXISTS (
                        SELECT 1 FROM chat_user_wallets w
                        WHERE w.user_id = u.user_id
                          AND LOWER(w.wallet_address) LIKE ?
                    )
                )
                ORDER BY u.created_at DESC
                LIMIT ?
                """,
                (pattern, pattern, pattern, pattern, limit),
            )
            rows = cur.fetchall()

    return [
        {
            "user_id": r["user_id"],
            "username": r["username"],
            "primary_wallet": r["primary_wallet"],
            "qualifying_balance_wei": str(r["qualifying_balance_wei"] or "0"),
            "account_status": r["account_status"] or "active",
            "admin_role": r["admin_role"],
        }
        for r in rows
    ]


@auth_cache.invalidates_auth_cache
def admin_moderate_user_account(
    target_user_id: str,
    action_type: str,
    reason: str,
    moderator_user_id: str,
    duration_hours: Optional[int] = None,
) -> Dict[str, Any]:
    """Applies suspend, mute, or restore action to a user and revokes sessions on suspension."""
    _ready()
    if action_type not in ("suspend", "mute", "restore"):
        raise ValueError("Invalid moderation action")

    new_status = {"suspend": "suspended", "mute": "muted", "restore": "active"}[action_type]
    now = _now()
    ts = now.isoformat()
    until = (
        (now + timedelta(hours=duration_hours)).isoformat()
        if duration_hours and new_status != "active"
        else None
    )

    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE chat_users
                    SET account_status = %s, suspended_until = %s, suspension_reason = %s, updated_at = %s
                    WHERE user_id = %s;
                    """,
                    (new_status, until, reason if new_status != "active" else None, ts, target_user_id),
                )
                if new_status == "suspended":
                    cur.execute(
                        "UPDATE chat_auth_sessions SET revoked = TRUE WHERE user_id = %s;",
                        (target_user_id,),
                    )
                cur.execute(
                    """
                    INSERT INTO moderation_actions (
                        action_id, moderator_user_id, target_user_id,
                        target_type, target_id, action_type, reason, created_at
                    ) VALUES (%s, %s, %s, 'user', %s, %s, %s, %s);
                    """,
                    (f"mod_{secrets.token_hex(10)}", moderator_user_id, target_user_id, target_user_id, action_type, reason, ts),
                )
            conn.commit()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                UPDATE chat_users
                SET account_status = ?, suspended_until = ?, suspension_reason = ?, updated_at = ?
                WHERE user_id = ?
                """,
                (new_status, until, reason if new_status != "active" else None, ts, target_user_id),
            )
            if new_status == "suspended":
                cur.execute("UPDATE chat_auth_sessions SET revoked = 1 WHERE user_id = ?", (target_user_id,))
            cur.execute(
                """
                INSERT INTO moderation_actions (
                    action_id, moderator_user_id, target_user_id,
                    target_type, target_id, action_type, reason, created_at
                ) VALUES (?, ?, ?, 'user', ?, ?, ?, ?)
                """,
                (f"mod_{secrets.token_hex(10)}", moderator_user_id, target_user_id, target_user_id, action_type, reason, ts),
            )
            chat_db._sqlite_conn.commit()

    record_audit_log(
        moderator_user_id,
        f"user_{action_type}",
        "user",
        target_user_id,
        {"status": new_status, "reason": reason, "suspended_until": until},
    )
    return enrich_user_dict(e2ee_db.get_user_by_id(target_user_id))  # type: ignore[return-value]


def admin_get_overview_stats() -> Dict[str, Any]:
    _ready()
    now_iso = _now_iso()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM chat_users;")
                total_users = int(cur.fetchone()[0])
                cur.execute("SELECT COUNT(*) FROM chat_auth_sessions WHERE revoked = FALSE AND expires_at > CURRENT_TIMESTAMP;")
                active_sessions = int(cur.fetchone()[0])
                cur.execute("SELECT COUNT(*) FROM chat_devices WHERE status = 'active';")
                active_devices = int(cur.fetchone()[0])
                cur.execute("SELECT COUNT(*) FROM public_chat_messages WHERE deleted = FALSE;")
                public_messages = int(cur.fetchone()[0])
                cur.execute("SELECT COUNT(*) FROM chat_groups;")
                encrypted_groups = int(cur.fetchone()[0])
                cur.execute("SELECT COUNT(*) FROM chat_dm_messages;")
                encrypted_dm_messages = int(cur.fetchone()[0])
                cur.execute("SELECT COUNT(*) FROM chat_group_messages;")
                encrypted_group_messages = int(cur.fetchone()[0])
                cur.execute("SELECT COUNT(*) FROM message_reports WHERE status = 'open';")
                open_reports = int(cur.fetchone()[0])
                cur.execute("SELECT COUNT(*) FROM moderation_actions;")
                mod_actions = int(cur.fetchone()[0])
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute("SELECT COUNT(*) FROM chat_users")
            total_users = int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM chat_auth_sessions WHERE revoked = 0 AND expires_at > ?", (now_iso,))
            active_sessions = int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM chat_devices WHERE status = 'active'")
            active_devices = int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM public_chat_messages WHERE deleted = 0")
            public_messages = int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM chat_groups")
            encrypted_groups = int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM chat_dm_messages")
            encrypted_dm_messages = int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM chat_group_messages")
            encrypted_group_messages = int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM message_reports WHERE status = 'open'")
            open_reports = int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM moderation_actions")
            mod_actions = int(cur.fetchone()[0])

    return {
        "total_users": total_users,
        "active_sessions": active_sessions,
        "active_devices": active_devices,
        "total_groups": encrypted_groups,
        "encrypted_groups": encrypted_groups,
        "public_messages": public_messages,
        "encrypted_dm_messages": encrypted_dm_messages,
        "encrypted_group_messages": encrypted_group_messages,
        "open_reports": open_reports,
        "moderation_actions": mod_actions,
    }


def admin_list_all_groups(limit: int = 100) -> List[Dict[str, Any]]:
    _ready()
    if _is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor(cursor_factory=chat_db.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT g.group_id, g.name, g.creator_user_id, g.current_epoch, g.created_bucket,
                           (SELECT COUNT(DISTINCT m.user_id) FROM chat_group_members m WHERE m.group_id = g.group_id AND m.status = 'active') AS member_count
                    FROM chat_groups g
                    ORDER BY g.created_bucket DESC
                    LIMIT %s;
                    """,
                    (limit,),
                )
                rows = cur.fetchall()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                """
                SELECT g.group_id, g.name, g.creator_user_id, g.current_epoch, g.created_bucket,
                       (SELECT COUNT(DISTINCT m.user_id) FROM chat_group_members m WHERE m.group_id = g.group_id AND m.status = 'active') AS member_count
                FROM chat_groups g
                ORDER BY g.created_bucket DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cur.fetchall()

    out = []
    for r in rows:
        gid = r["group_id"]
        pol = get_group_access_policy(gid)
        out.append({
            "group_id": gid,
            "name": r["name"],
            "creator_user_id": r["creator_user_id"],
            "current_epoch": int(r["current_epoch"]),
            "member_count": int(r["member_count"] or 0),
            "created_at": r["created_bucket"],
            "policy": pol,
        })
    return out