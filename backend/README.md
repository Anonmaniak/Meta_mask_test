# Zyphra.in — Backend Chat & Cryptography Relay Service

The backend is an asynchronous **Python FastAPI + WebSockets** service backed by **Neon PostgreSQL**. It provides EIP-4361 Sign-In with Ethereum (SIWE), immutable internal `user_id` management, server-side Ethereum RPC wallet balance & on-chain payment verification, Open Public Chat (Paid Members), zero-plaintext E2EE relay for **Olm v2** DMs and **RFC 9420 MLS** groups, and RBAC administration.

> **Zero Custodial / Private Keys**: This service holds zero custodial funds, zero escrow wallets, and zero blockchain private keys. It performs purely read-only Ethereum JSON-RPC queries (`eth_getBalance`, `eth_blockNumber`, `eth_getTransactionReceipt`, `eth_getTransaction`) to authoritatively verify balances and payments.

---

## Architecture Modules

| File | Responsibility |
| :--- | :--- |
| `app.py` | Explicit `backend/.env` loader (`load_dotenv(..., override=True)`), FastAPI lifespan initialization, strict CSP/HSTS/Frame-Options security headers, outermost CORS (`FRONTEND_URL` + `_LOCAL_DEV_ORIGIN_REGEX`), dropped-DB `503 Retry-After: 1` recovery, cached RPC `/api/health?deep=1`, privacy-preserving request logger, scrubbed error handlers, and router registration. |
| `admin_auth.py` | Standalone `/Admin456` Admin Console authentication (`ADMIN_LOGIN_ID` / `ADMIN_LOGIN_PASSWORD` from server env only, constant-time `hmac.compare_digest` over SHA-256 digests, per-IP brute-force lockout with fixed delay, in-memory SHA-256 hashed 256-bit sessions with 30-min idle / 4-hour absolute TTL, and logout revocation; zero SQL queries). |
| `price_oracle.py` | Live ETH/USD spot rate oracle querying Coinbase then Kraken (`ETH_PRICE_CACHE_SECS=60`, stale window `ETH_PRICE_STALE_OK_SECS=3600`) with fallback to admin-configured fixed `eth_usd_price`. |
| `migrations/` (`001` through `008`) | Normalized PostgreSQL & SQLite schema covering `chat_users` (`is_platform_paid`, `platform_paid_at`), `username_history`, `chat_user_wallets`, `wallet_change_history`, `payment_records`, `wallet_balance_snapshots`, `public_chat_messages`, `user_blocks`, `chat_dm_receipts`, `group_access_policies` (including `entry_fee_usd` in `007`), `group_invite_links`, `group_join_requests`, `support_threads` & `support_messages` (`008`), `message_reports`, `admin_roles`, `moderation_actions`, `platform_settings` (`platform_entry_fee_usd`, `use_live_eth_price`, `eth_usd_price`, `authorized_payment_destination`, `default_balance_chain_id`, `username_cooldown_hours`), and `audit_logs`. |
| `run_migrations.py` | Idempotent PostgreSQL & SQLite migration runner (`schema_migrations` tracking) & default platform settings seeder. |
| `eth_rpc.py` | Server-side Ethereum JSON-RPC balance and payment verifier supporting Mainnet (`chain_id=1`, `RPC_URL_MAINNET` + fallback) and Sepolia (`chain_id=11155111`, `RPC_URL_SEPOLIA`), switched at runtime via Admin `default_balance_chain_id`. |
| `e2ee_db.py` & `e2ee_routes.py` | `/api/e2ee/*` & `/ws/e2ee`: SIWE challenge/verify, permanent `user_id` accounts, case-insensitive unique `@username` (`idx_chat_users_username_lower`), real-time availability check (`GET /account/username/check`), multi-wallet rotation, Ed25519-verified device bundles, atomic OTK & MLS `KeyPackage` claiming, Olm v2 DM relay, RFC 9420 MLS group epoch commits/welcomes, `AES-256-GCM` attachment storage, and `E2EERealtimeHub` (excluding Admins from online presence metrics and indicators). |
| `platform_db.py`, `support_db.py` & `platform_routes.py` | `/api/platform/*`, `/ws/public-chat` & `/ws/member-presence`: USD-denominated platform & paid-group pricing (`/pricing`, `/membership/status`, `/groups/{id}/pricing`, `/admin/pricing`), authoritative treasury destination & tolerance verification (`POST /api/platform/payments/verify`), "Talk to admin" support threads (`/support/*`, `/admin/support/*`), Paid-Member Open Public Chat (`_require_paid_member_ctx`, guest policy removed), single-query `admin_list_users`, `@username` search, blocking, read receipts, group policies/invites/join requests, reports, `/admin/login` + `/admin/session` + `/admin/logout`, and RBAC admin endpoints. |
| `chat_db.py` & `chat_routes.py` | `/api/chat/*`: PostgreSQL `ThreadedConnectionPool` (`DB_POOL_MIN`/`MAX`, stale socket validation & `purge_idle_connections`), global public room directory & explicit `public-non-confidential` security model notice. |

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
| `EXPECTED_CHAIN_ID` | No | Default EVM chain ID for balance verification (`11155111` Sepolia or `1` Mainnet; default: `11155111`). |
| `PLATFORM_ENTRY_FEE_USD` | Optional | Default platform membership fee in USD (default: `10`, `0` in tests), converted to ETH via `price_oracle.py`. |
| `PAYMENT_PRICE_TOLERANCE_PCT` | Optional | Allowed ETH/USD price movement (%) between quote and on-chain verification (default: `5`). |
| `ETH_USD_PRICE` / `ETH_PRICE_CACHE_SECS` | Optional | Fallback fixed ETH/USD rate (`2500.0`) and live oracle cache TTL in seconds (`60`). |
| `DB_POOL_MIN` / `DB_POOL_MAX` | Optional | PostgreSQL pool bounds (`3` / `10`) plus `DB_POOL_VALIDATE_AFTER_SECS` (`5`) and `DB_CONNECT_RETRIES` (`3`). |
| `AUTH_CACHE_TTL_SEC` | Optional | In-memory TTL in seconds for auth/session lookups (default: `30`). |
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

## Automated Test Suite (132 Tests + Live Neon Probe)

Run all backend unit and security integration tests (runs hermetically against isolated in-memory SQLite without touching production Neon data):

```bash
TESTING=1 python -m pytest backend -k "not test_neon_conn" -v
```

### Test Suites Included
- `test_paid_membership_and_groups.py` (6 tests): Public platform pricing endpoint with USD conversion, Admin pricing updates and audit logging, platform admission paywall flow, paid group creation with on-chain fee verification, and support thread coverage.
- `test_verified_payments.py` (13 tests): Authoritative treasury destination matching, wrong destination rejection, wrong sender rejection, on-chain failure, pending tx, missing destination fail-closed, RPC outage retryability, and strict duplicate transaction anti-replay.
- `test_platform_features.py` (7 tests): Permanent `user_id` across `@username` cooldowns & primary wallet replacement, Paid-Member Open Public Chat (`_require_paid_member_ctx` / WebSocket / moderation), `@username` search + peer blocking + opt-in DM read receipts, group policies + invite links + join requests + Leave Group, and RBAC admin settings/reports/audit logs.
- `test_chat_e2ee.py` (35 tests): Public-room directory, E2EE envelope validation, and key security tests.
- `test_admin_hardening.py` (15 tests): Admin credential policy, lockout isolation, and startup self-checks.
- `test_admin_login.py` (8 tests): Admin authentication & brute-force lockout tests.
- `test_chat_keys.py` (18 tests): Olm and prekey tests.
- `test_e2ee_security.py` (7 tests): Multi-device and replay protection tests.
- `test_group_dm_speed.py` (13 tests): Group and DM speed benchmarks.
- `test_send_performance.py` (10 tests): Message delivery speed tests.
