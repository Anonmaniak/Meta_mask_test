# Production Deployment Guide — Zyphra.in Chat Platform

This guide covers deploying the **Zyphra.in** Ethereum Wallet-Linked Chat Platform to production using **Neon PostgreSQL**, **Render** (FastAPI + WebSockets), and **Vercel** (React + Vite SPA).

> **Security Highlight**: Zyphra.in uses client-side E2EE and read-only Ethereum RPC balance & transaction receipt verification. **Zero server-side wallet private keys** are ever deployed or stored on any server.

---

## 1. Provision Neon PostgreSQL

1. Create a PostgreSQL 16+ project on [Neon](https://neon.tech).
2. Copy the pooled/direct TLS connection string (`postgresql://user:password@ep-....neon.tech/neondb?sslmode=require`).
3. Apply the versioned database schema (migrations `001` through `008`) and seed default platform settings:
   ```bash
   cd backend
   export NEON_DATABASE_URL="postgresql://user:password@ep-....neon.tech/neondb?sslmode=require"
   python run_migrations.py
   ```
   *(Note: `app.py` also verifies/initializes required tables and seeds default settings idempotently on startup via its `lifespan` handler, and explicitly loads `backend/.env` with `override=True` in local/dev launches.)*

---

## 2. Configure Read-Only Ethereum RPC Endpoints

Server-side wallet balance and payment verification (`eth_rpc.py`) queries Ethereum JSON-RPC directly so clients can never spoof ETH balances or transaction receipts. The **Active Ethereum Network** toggle in `/Admin456` (`default_balance_chain_id`) controls whether `1` (Mainnet via `RPC_URL_MAINNET`) or `11155111` (Sepolia via `RPC_URL_SEPOLIA`) is used:

1. Create a read-only API key on [Alchemy](https://www.alchemy.com/), [Infura](https://www.infura.io/), or QuickNode.
2. Obtain HTTPS endpoints for:
   - **Ethereum Mainnet (`chain_id = 1`)**: `https://eth-mainnet.g.alchemy.com/v2/<KEY>`
   - **Ethereum Sepolia Testnet (`chain_id = 11155111`)**: `https://eth-sepolia.g.alchemy.com/v2/<KEY>`

---

## 3. Deploy Backend to Render (`backend/render.yaml`)

1. Connect the repository to [Render](https://render.com) with Root Directory set to `backend` (or deploy via Blueprint using `backend/render.yaml`).
2. **Build Command**:
   ```bash
   pip install -r requirements.txt && python run_migrations.py
   ```
3. **Start Command**:
   ```bash
   uvicorn app:app --host 0.0.0.0 --port $PORT --no-access-log
   ```
4. **Environment Variables**:

   | Key | Value |
   | :--- | :--- |
   | `NEON_DATABASE_URL` | `postgresql://...?sslmode=require` |
   | `FRONTEND_URL` | `https://zyphra.in,https://www.zyphra.in` (exact Vercel/custom domain origins, comma-separated, no trailing slash) |
   | `APP_DOMAIN` | `zyphra.in` (EIP-4361 SIWE domain binding) |
   | `RPC_URL_MAINNET` | Primary Ethereum Mainnet HTTPS JSON-RPC URL (`chain_id = 1`) |
   | `RPC_URL_MAINNET_FALLBACK` | Fallback Ethereum Mainnet HTTPS JSON-RPC URL (e.g., `https://ethereum-rpc.publicnode.com`) |
   | `RPC_URL_SEPOLIA` | Ethereum Sepolia HTTPS JSON-RPC URL (`chain_id = 11155111`) |
   | `PAYMENT_PRICE_TOLERANCE_PCT` | Optional quote-to-payment tolerance `%` (default `5`) |
   | `DB_POOL_MIN` / `DB_POOL_MAX` | Optional PostgreSQL pool bounds (default `3` / `10`) |
   | `RENDER_EXTERNAL_URL` | Optional `https://<your-render-service>.onrender.com` for periodic `/api/health` keep-alive |
   | `ADMIN_WALLET_ADDRESSES` | Optional comma-separated `0x...` wallet addresses granted `superadmin` RBAC upon SIWE login |
   | `ADMIN_TOKEN` | Optional break-glass secret, honoured only if >= 24 chars (`python -c "import secrets; print(secrets.token_urlsafe(32))"`) |
   | `ADMIN_LOGIN_ID` / `ADMIN_LOGIN_PASSWORD` | Strong server-only credentials for the `/Admin456` Admin Console login page (login is disabled if unset) |

5. Verify deployment health (append `?deep=1` to also verify Neon PostgreSQL connectivity):
   ```bash
   curl https://<your-render-service>.onrender.com/api/health?deep=1
   ```
   Expected response:
   ```json
   {
     "status": "healthy",
     "service": "zyphra-chat-platform",
     "storage": "postgresql",
     "database": "ok"
   }
   ```

> **Horizontal Scaling Note**: In-process WebSocket hubs (`E2EERealtimeHub` for `/ws/e2ee` and `PublicChatHub` for `/ws/public-chat`) handle single-instance real-time fanout cleanly. If scaling beyond `1` web worker replica, back the WebSocket broadcast layer with Redis Pub/Sub or PostgreSQL `LISTEN/NOTIFY` while keeping persistent state in Neon PostgreSQL.

---

## 4. Deploy Frontend to Render (Static Site)

1. In Render: **New → Static Site**, connect the repository, set **Root Directory** to `frontend`.
2. **Build Command**: `npm ci && npm run build`
3. **Publish Directory**: `dist`
4. **Environment Variable**: `VITE_BACKEND_URL` = `https://<your-render-backend>.onrender.com/api`
   - It must start with `https://`. The build stops with a clear error otherwise, because the page's
     security policy (written into `index.html` at build time, see `frontend/csp.config.ts`) only lets
     the app talk to this backend.
   - After changing this value, redeploy the static site so the policy is rebuilt.
5. **Redirects/Rewrites** (Settings → Redirects/Rewrites): add a **Rewrite** from `/*` to `/index.html`, so
   direct loads and refreshes of `/settings`, `/payments`, `/support` and `/Admin456` work.
6. **Headers** (Settings → Headers), path `/*` (a page cannot set these itself):
   - `X-Frame-Options: DENY`
   - `Content-Security-Policy: frame-ancestors 'none'`
   - `Strict-Transport-Security: max-age=63072000; includeSubDomains`
   - `X-Content-Type-Options: nosniff`
   - `Referrer-Policy: no-referrer`
   - `Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=()`
   And for path `/assets/*`: `Cache-Control: public, max-age=31536000, immutable`
7. Attach your custom domain (e.g. `zyphra.in`) and make sure `FRONTEND_URL` and `APP_DOMAIN` on the backend
   service match it exactly.

(`frontend/vercel.json` is only used if you ever host the frontend on Vercel instead.)

---

## 5. Post-Deployment Verification Checklist (Sepolia & Mainnet)

1. **Welcome Gate, Splash & Open Public Chat**: Load `/` in a fresh incognito window; confirm the one-time `WelcomeSplash` (`1 in 10,000` / `For 1% of 1%`) plays, `WelcomeGate` renders with zero scrollbar until connected & paid, and after admission **Chats → Open Chat** opens with the **`PUBLIC`** badge and streams messages over HTTPS/WSS.
2. **SIWE & Admission Paywall**: Click **Connect MetaMask**, complete the 1-click SIWE signature, and verify `PlatformAdmissionModal` displays the USD fee converted to ETH via the live oracle. After verifying payment, confirm your account pill (`@username`, `Paid Member`) and click `View & Edit Profile →` in its dropdown to open **Profile**.
3. **Sepolia / Mainnet Verification & Support**: Open **Settings** (`/settings`) to verify balance/membership, and open **Support** (`/support`) to submit a "Talk to admin" thread (works both pre- and post-payment when signed in).
4. **Private Chats**: Open **Private Chats**, find a member, and exchange encrypted messages and a file attachment.
5. **Encrypted Groups & Paid Group Gate**: Open **Encrypted Groups**, create a Paid or policy-gated group, verify `PaidGroupAdmissionModal` USD-to-ETH conversion on join, approve an eligible member via `Browse Groups & Invites` / Group Security, and test **Leave Group**.
6. **Admin RBAC Console (`/Admin456`)**: Open `/Admin456`, verify unauthenticated requests show only the login gate, sign in with `ADMIN_LOGIN_ID` / `ADMIN_LOGIN_PASSWORD` (rotate any local test password to a strong secret in production!), verify automatic 5-second polling, `Active Ethereum Network` (`1` / `11155111`) switching, live pricing, **Support Inbox** replies, moderation actions, and `audit_logs`, and test **Sign Out**.