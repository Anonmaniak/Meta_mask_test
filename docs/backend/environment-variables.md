# Backend Environment Variables Reference

Location: `backend/.env` (template at `backend/.env.example`; loaded explicitly by `backend/app.py` with `load_dotenv(..., override=True)` outside test runs)

This document details all environment variables used by the **Zyphra.in** Chat Platform backend.

---

## 1. Environment Variables Catalog

| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `NEON_DATABASE_URL` | **Yes (Prod)** | `:memory:` SQLite in tests | Neon PostgreSQL TLS connection URI (`postgresql://user:pass@host/neondb?sslmode=require`; also accepts `DATABASE_URL` / `POSTGRES_URL` aliases). |
| `FRONTEND_URL` | **Yes (Prod)** | `https://zyphra.in` (+ local dev regex) | Comma-separated whitelisted CORS origins; first entry is also used as the SIWE `APP_URI`. Local dev/preview origins (`localhost`, `127.0.0.1`, `[::1]` on any port) are additionally allowed via `_LOCAL_DEV_ORIGIN_REGEX`. |
| `APP_DOMAIN` | No | `zyphra.in` | Expected domain validated in EIP-4361 Sign-In with Ethereum challenges (`localhost` / `127.0.0.1` also accepted in dev). |
| `PORT` | No | `10000` | Port for Uvicorn ASGI HTTP & WebSocket server. |
| `RPC_URL_MAINNET` | Recommended | None | Primary read-only Ethereum Mainnet JSON-RPC endpoint (`chain_id = 1`, `eth_getBalance` + `eth_blockNumber`), used when Admin `Active Ethereum Network` (`default_balance_chain_id`) is `1`. |
| `RPC_URL_MAINNET_FALLBACK` | Optional | None | Automatic failover Ethereum Mainnet JSON-RPC endpoint (e.g., `https://ethereum-rpc.publicnode.com`). |
| `RPC_URL_SEPOLIA` | Recommended | None | Read-only Ethereum Sepolia Testnet JSON-RPC endpoint (`chain_id = 11155111`), used when Admin `Active Ethereum Network` (`default_balance_chain_id`) is `11155111`. |
| `EXPECTED_CHAIN_ID` | No | `11155111` | Initial default EVM chain ID (`11155111` Sepolia or `1` Mainnet) used before or unless overridden by Admin `/Admin456` `Active Ethereum Network` (`default_balance_chain_id`). |
| `AUTHORIZED_PAYMENT_DESTINATION` | Recommended | `0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed` | Server-controlled authorized treasury address. On-chain payments sent to any other destination are permanently rejected. |
| `PLATFORM_ENTRY_FEE_USD` | Optional | `10` (`0` in tests) | Default platform admission fee in US Dollars, converted to ETH at quote time. Editable in `/Admin456`. |
| `PAYMENT_PRICE_TOLERANCE_PCT` | Optional | `5` | Allowed ETH/USD price movement (%) between quote and on-chain payment confirmation. |
| `ETH_USD_PRICE` | Optional | `2500.0` | Fixed/fallback 1 ETH to USD rate used when live pricing is disabled or all live sources fail. Editable in `/Admin456`. |
| `ETH_PRICE_CACHE_SECS` | Optional | `60` | Cache TTL (seconds) for live Coinbase/Kraken ETH/USD spot quotes in `price_oracle.py`. |
| `ETH_PRICE_STALE_OK_SECS` | Optional | `3600` | Max age (seconds) a last-known live ETH/USD quote may still be served if upstream price APIs are unreachable. |
| `PLATFORM_ENTRY_FEE_ETH` | Legacy / Optional | `0.01` | Legacy ETH-denominated entry fee fallback retained for backward compatibility with older databases. |
| `DB_POOL_MIN` / `DB_POOL_MAX` | Optional | `3` / `10` | Minimum and maximum PostgreSQL connections maintained in `chat_db` `ThreadedConnectionPool`. |
| `DB_POOL_VALIDATE_AFTER_SECS` | Optional | `5` | Idle duration (seconds) after which a pooled PostgreSQL connection is validated with `SELECT 1`. |
| `DB_CONNECT_RETRIES` | Optional | `3` | Retry attempts when establishing initial Neon PostgreSQL connections. |
| `AUTH_CACHE_TTL_SEC` | Optional | `30` | In-memory TTL (seconds) for session/user/settings lookups (`0` disables; invalidated immediately on writes). |
| `RENDER_EXTERNAL_URL` | Optional | `""` | Base URL for periodic self `/api/health` keep-alive pings on Render. |
| `CHAT_KEY_CHALLENGE_TTL_SECONDS` | Optional | `300` | Challenge expiration window (seconds) for legacy public-room key challenges. |
| `ADMIN_WALLET_ADDRESSES` | Optional | `""` | Comma-separated `0x...` wallet addresses automatically granted `superadmin` RBAC on SIWE login. |
| `ADMIN_TOKEN` | Optional | `""` | Break-glass administrative secret (`X-Admin-Token`); ignored unless at least 24 characters. |
| `ADMIN_LOGIN_ID` | Optional | `""` | Login ID for the `/Admin456` Admin Console page. Login fails closed (`503`) if this or `ADMIN_LOGIN_PASSWORD` is unset. |
| `ADMIN_LOGIN_PASSWORD` | Optional | `""` | Password for the `/Admin456` Admin Console page. Keep strictly in `backend/.env` / server secrets (never in `frontend/.env`). |

---

## 2. Sample `backend/.env.example`

```ini
# ============================================================================
# Zyphra.in — Ethereum Wallet-Linked Chat Platform (Backend Configuration)
# ============================================================================

# Neon PostgreSQL Connection String (falls back to in-memory SQLite in dev/tests)
NEON_DATABASE_URL=postgresql://user:password@your-neon-host/neondb?sslmode=require

# Ethereum RPC Providers (used strictly for server-side balance verification)
RPC_URL_MAINNET=https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY
RPC_URL_MAINNET_FALLBACK=https://ethereum-rpc.publicnode.com
RPC_URL_SEPOLIA=https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY

# Default EVM Chain ID for balance verification (1 = Mainnet, 11155111 = Sepolia)
EXPECTED_CHAIN_ID=11155111

# Application Domain & Allowed Frontend Origins (comma-separated)
APP_DOMAIN=zyphra.in
FRONTEND_URL=http://localhost:5173

# Comma-separated Ethereum addresses automatically granted superadmin on SIWE login
ADMIN_WALLET_ADDRESSES=0x0000000000000000000000000000000000000000

# Optional emergency administrative API token for CLI/ops (ignored unless >= 24 characters)
ADMIN_TOKEN=replace_with_high_entropy_random_secret_min_24_chars

# Admin Console login for the /Admin456 page (server-side only; leave unset to disable the login)
ADMIN_LOGIN_ID=replace_with_admin_login_id
ADMIN_LOGIN_PASSWORD=replace_with_strong_admin_password

# Authorized payment recipient destination (checksummed EVM address for qualifying level payments)
# Server-controlled, never accepted from client; editable at runtime via Superadmin settings.
AUTHORIZED_PAYMENT_DESTINATION=0x0000000000000000000000000000000000000000

# Platform Admission Fee in ETH (default: 0.01 ETH) and ETH USD Valuation Rate (default: $2,500)
PLATFORM_ENTRY_FEE_ETH=0.01
ETH_USD_PRICE=2500.0

# Server Port
PORT=10000
```

---

## 3. Operational Security Notes

1. **No Chat/Escrow Private Keys Required**: Never place user or custodial wallet private keys in `backend/.env`. All balance checks are strictly read-only JSON-RPC calls.
2. **Database TLS**: Always include `?sslmode=require` on `NEON_DATABASE_URL` in staging and production.
3. **Explicit CORS Origins**: Enumerate exact origins in `FRONTEND_URL` rather than `*` so authenticated `HttpOnly` session cookies (`zyphra_session`) remain strictly scoped.
4. **Server-Only `/Admin456` Credentials**: Keep `ADMIN_LOGIN_ID` and `ADMIN_LOGIN_PASSWORD` exclusively in `backend/.env` or hosting secret managers—never in `frontend/.env` (`VITE_*` variables are exposed to browsers)—and rotate any local development password to a strong secret before deploying.
