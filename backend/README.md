# Zyphra.in — Backend Chat & Cryptography Relay Service

The backend is an asynchronous **Python FastAPI + WebSockets** service backed by **Neon PostgreSQL**. It provides EIP-4361 Sign-In with Ethereum (SIWE), immutable internal `user_id` management, server-side Ethereum RPC wallet balance & on-chain payment verification, Open Public Chat (Paid Members), zero-plaintext E2EE relay for **Olm v2** DMs and **RFC 9420 MLS** groups, and RBAC administration.

> **Zero Custodial / Private Keys**: This service holds zero custodial funds, zero escrow wallets, and zero blockchain private keys. It performs purely read-only Ethereum JSON-RPC queries (`eth_getBalance`, `eth_blockNumber`, `eth_getTransactionReceipt`, `eth_getTransaction`) to authoritatively verify balances and payments.

---

## Architecture Modules

| File | Responsibility |
| :--- | :--- |
| `app.py` | Explicit `backend/.env` loader (`load_dotenv(..., override=True)`), unified `_is_test_env()`, FastAPI lifespan (seeds RPC cache), strict CSP/HSTS/Frame-Options security headers, outermost CORS (`FRONTEND_URL` + `_LOCAL_DEV_ORIGIN_REGEX`), dropped-DB `503 Retry-After: 1` recovery, zero-RPC `/api/health?deep=1` (`peek_rpc_health_status()`), privacy-preserving request logger, scrubbed error handlers, and router registration. |
| `admin_auth.py` | Standalone `/Admin456` Admin Console authentication (`ADMIN_LOGIN_ID` / `ADMIN_LOGIN_PASSWORD` from server env only, constant-time `hmac.compare_digest` over SHA-256 digests, global login slowdown (every failed attempt waits longer, up to 8 s; no IP or other visitor data is read and there is no lockout), in-memory SHA-256 hashed 256-bit sessions with 30-min idle / 4-hour absolute TTL, and logout revocation; zero SQL queries). |
| `price_oracle.py` | Live ETH/USD spot rate oracle querying Coinbase then Kraken (`ETH_PRICE_CACHE_SECS=60`, stale window `ETH_PRICE_STALE_OK_SECS=3600`) with fallback to admin-configured fixed `eth_usd_price`. |
| `migrations/` (`001` through `015`) | Normalized PostgreSQL & SQLite schema covering `chat_users` (`is_platform_paid`, `platform_paid_at`), `username_history`, `chat_user_wallets`, `wallet_change_history`, `payment_records`, `member_subscriptions` (`009`–`010`), `public_chat_attachments` (`011`), `chat_read_markers` (`012`), `public_chat_replies` (`013`), `access_grants` (`014`), widened `audit_logs.entity_id` (`015`), `wallet_balance_snapshots`, `public_chat_messages`, `user_blocks`, `chat_dm_receipts`, `group_access_policies` (including `entry_fee_usd` in `007`), `group_join_requests`, `support_threads` & `support_messages` (`008`), `message_reports`, `admin_roles`, `moderation_actions`, `platform_settings`, and `audit_logs`. |
| `run_migrations.py` | Idempotent PostgreSQL & SQLite migration runner (`schema_migrations` tracking) & default platform settings seeder. |
| `eth_rpc.py` | Server-side Ethereum JSON-RPC balance and payment verifier (`is_test_environment()`, immediate failure for pending `to=None` contract-creation txs, stale-while-revalidate `get_cached_rpc_health_status()` + zero-I/O `peek_rpc_health_status()`), supporting Mainnet (`chain_id=1`, `RPC_URL_MAINNET` + fallback) and Sepolia (`chain_id=11155111`, `RPC_URL_SEPOLIA`) per Admin `default_balance_chain_id`. |
| `chat_features_db.py`, `read_markers_db.py` & `public_attachments_db.py` | Atomic pin management (`set_pin` inside `_in_transaction` with advisory/RLock + monotonic timestamps), connection-identity schema caching (`_ready_for`), disappearing timers, mute/archive prefs, announcement-only groups, `is_single_emoji` reaction validator, unread read markers, and Members' room attachments. |
| `e2ee_db.py` & `e2ee_routes.py` | `/api/e2ee/*` & `/ws/e2ee`: SIWE challenge/verify, permanent `user_id` accounts, case-insensitive unique `@username` (`idx_chat_users_username_lower`), real-time availability check (`GET /account/username/check`), multi-wallet rotation, Ed25519-verified device bundles, atomic OTK & MLS `KeyPackage` claiming, Olm v2 DM relay (with `idx_dm_sender_seq` / `idx_dm_recipient_seq` indexes), RFC 9420 MLS group epoch commits/welcomes, active-member conversation pref guard, `AES-256-GCM` attachment storage (`_resolve_upload_attachment_scope` enforcing DM blocks, active participation, and muted-account rejection), and `E2EERealtimeHub`. |
| `platform_db.py`, `support_db.py` & `platform_routes.py` | `/api/platform/*`, `/ws/public-chat` & `/ws/member-presence`: USD-denominated platform & paid-group pricing (`/pricing`, `/membership/status`, `/groups/{id}/pricing` with cookie & case-insensitive Bearer support, `/admin/pricing`), on-demand stale balance refresh (`BALANCE_REFRESH_SECS=600`), verified superadmin check on `update_group_policy_endpoint`, cached RPC health on `/admin/overview`, authoritative payment verification, "Talk to admin" support threads (`support_db.py` with connection-identity schema guard), Paid-Member Open Public Chat, single-query `admin_list_users`, access grants, reports, and RBAC admin endpoints. |
| `chat_db.py` | PostgreSQL `ThreadedConnectionPool` (`DB_POOL_MIN`/`MAX`, stale socket validation & `purge_idle_connections`) with a SQLite fallback for local development (refuses fallback in production unless `ALLOW_SQLITE_FALLBACK=1`). |

---

## Environment Variables (`backend/.env`)

Copy `backend/.env.example` to `backend/.env`:

| Variable | Required | Description |
| :--- | :---: | :--- |
| `NEON_DATABASE_URL` | **Yes (Prod)** | PostgreSQL TLS connection string (`postgresql://user:pass@host/dbname?sslmode=require`; also accepts `DATABASE_URL` / `POSTGRES_URL` aliases). Falls back to persistent local SQLite (`backend/local_dev.sqlite3`) for local dev when unset, and thread-safe `:memory:` SQLite during automated unit tests. |
| `FRONTEND_URL` | **Yes (Prod)** | Comma-separated allowed CORS origins (e.g., `http://localhost:5173,https://zyphra.in`); first origin is also used as the SIWE `APP_URI`. Localhost / `127.0.0.1` / `[::1]` dev ports are also allowed automatically. |
| `APP_DOMAIN` | No | Expected domain in EIP-4361 SIWE statements (default: `zyphra.in`; `localhost` also accepted in dev). |
| `RPC_URL_MAINNET` | Recommended | Primary read-only Ethereum Mainnet JSON-RPC endpoint (`chain_id=1`) for `eth_getBalance` verification. |
| `RPC_URL_MAINNET_FALLBACK` | Optional | Automatic failover Ethereum Mainnet JSON-RPC endpoint. |
| `RPC_URL_SEPOLIA` | Recommended | Read-only Ethereum Sepolia Testnet JSON-RPC endpoint (`chain_id=11155111`). |
| _(Admin console only)_ | - | Active network, membership price (USD) and payment destination wallet are managed in `/Admin456` (Platform Settings), not by environment variables. |
| `PAYMENT_PRICE_TOLERANCE_PCT` | Optional | Allowed ETH/USD price movement (%) between quote and on-chain verification (default: `5`). |
| `ETH_USD_PRICE` / `ETH_PRICE_CACHE_SECS` | Optional | Fallback fixed ETH/USD rate (`2500.0`) and live oracle cache TTL in seconds (`60`). |
| `DB_POOL_MIN` / `DB_POOL_MAX` | Optional | PostgreSQL pool bounds (`3` / `10`) plus `DB_POOL_VALIDATE_AFTER_SECS` (`5`) and `DB_CONNECT_RETRIES` (`3`). |
| `AUTH_CACHE_TTL_SEC` | Optional | In-memory TTL in seconds for auth/session lookups (default: `30`). |
| `BALANCE_REFRESH_SECS` | Optional | Minimum age (seconds) before a failed min-ETH group rule triggers an on-demand RPC balance refresh (default: `600`; throttled at `60 s` per member). |
| `PORT` | No | Uvicorn HTTP & WebSocket server port (default: `10000`). |
| `RENDER_EXTERNAL_URL` | Optional | Self health-check keep-alive base URL when deployed on Render. |
| `ADMIN_WALLET_ADDRESSES` | Optional | Comma-separated `0x...` wallet addresses automatically granted the `superadmin` role upon SIWE login. |
| `ADMIN_TOKEN` | Optional | Break-glass header (`X-Admin-Token`) secret; ignored unless at least 24 characters. |
| `ADMIN_LOGIN_ID` / `ADMIN_LOGIN_PASSWORD` | Optional | Server-only credentials for the `/Admin456` Admin Console login (`POST /api/platform/admin/login`, implemented in `admin_auth.py`). Login fails closed (`503`) if unset. |

---

## Running Locally

### Unified Single-Command Startup (Recommended)
You can run the entire backend with a single command. It explicitly loads `backend/.env` (`override=True`), verifies/installs `requirements.txt`, applies all database migrations on Neon PostgreSQL, seeds default platform settings, and starts the Uvicorn server on port 10000:

```bash
cd backend
python app.py
```
*(Case-insensitive: `python App.py` or running `python app.py` from repository root works identically via built-in trampolines.)*

### Manual Multi-Step Startup
```bash
cd backend
pip install -r requirements.txt

# Apply PostgreSQL migrations and seed default settings
python run_migrations.py

# Start FastAPI + WebSocket server
uvicorn app:app --reload --port 10000
```

Health check:
```bash
curl http://localhost:10000/api/health
```

---

## Automated Test Suite (267 Tests + Live Neon Probe)

Run all backend unit and security integration tests (runs hermetically against isolated in-memory SQLite without touching production Neon data):

```bash
TESTING=1 python -m pytest backend -k "not test_neon_conn" -v
```

### Test Suites Included
- `test_audit_fixes_round2.py` (21 tests): group-policy superadmin privilege check, DM attachment block/participant checks, pricing cookie/lowercase-Bearer auth, former-member pref denial, cached admin RPC health, pending contract-creation failure, concurrent `set_pin` atomicity & object-identity schema cache, keycap/script reaction emoji validation, and test-env detection.
- `test_rpc_on_demand.py` (6 tests): on-demand RPC balance refresh on min-ETH group join/retry cooldown, RPC outage fail-closed handling, zero RPC calls during group sends and login, and zero-RPC `/api/health` peek.
- `test_user_isolation.py` (5 tests): cross-user access isolation across private groups, DMs, attachments, devices, support threads, payment history, and admin routes.
- `test_paid_membership_and_groups.py` (6 tests), `test_subscriptions.py` (21 tests), `test_verified_payments.py` (16 tests), `test_access_grants.py` (12 tests): USD pricing, monthly/yearly subscriptions, free access grants, and strict on-chain payment verification.
- `test_platform_features.py` (7 tests), `test_group_invitations.py` (6 tests), `test_group_join_fixes.py` (15 tests), `test_chat_features.py` (19 tests), `test_chat_files.py` (16 tests), `test_public_chat_replies.py` (5 tests), `test_unread_notifications.py` (5 tests): identity, invitations, join requests, pins/timers/polls/reactions, attachments, replies, and unread counters.
- `test_admin_hardening.py` (16 tests), `test_admin_login.py` (8 tests), `test_admin_stats_and_sessions.py` (22 tests), `test_production_hardening.py` (6 tests), `test_postgres_compat.py` (4 tests): admin security, session limits, overview stats, production DB enforcement, and PostgreSQL compatibility.
- `test_e2ee_security.py` (7 tests), `test_group_dm_speed.py` (13 tests), `test_send_performance.py` (10 tests), `test_support.py` (6 tests), `test_capacity.py` (15 tests): E2EE security, DM/group speed, support inbox, and capacity estimates.
