# Zyphra.in — Ethereum Wallet-Linked Real-Time Chat Platform

**Zyphra.in** is a full-stack, real-time messaging platform linking **Ethereum wallets (MetaMask via EIP-4361 SIWE)** to **permanent internal user identities (`usr_<uuid>`)**, **an Admin-controlled Ethereum platform admission paywall with USD conversion**, **paid groups**, **verified on-chain payments**, **Open Public Chat**, **Olm v2 Double Ratchet Private Chat**, and **IETF RFC 9420 MLS Encrypted Group Chat**.

> **Scope & Security Notice**: Zyphra.in is a pure **chat platform** backed by **Neon PostgreSQL** with client-side End-to-End Encryption (E2EE) for private and group conversations. The platform incorporates a **server-side verified on-chain payment record system** (`payment_records`) where transactions are validated on-chain against an Admin-controlled authorized treasury destination. Zero custodial private keys or payment secrets are stored on the server. Private 1-to-1 chats and group conversations use client-side E2EE, whereas Open Public Chat is intentionally public, non-confidential, and moderated.

---

## Core Capabilities

1. **Permanent Identity & Mutable Attributes**
   - Every user receives an immutable internal `user_id` (`usr_...`).
   - Case-insensitive unique `@username` with database-level partial unique index (`idx_chat_users_username_lower`), configurable rename cooldown (`Username change Hrs`), old-handle reservation quarantine, and `username_history` auditing.
   - Real-time live username availability checking (`GET /api/e2ee/account/username/check`).
   - Pure identity model: Display Name has been completely eliminated to prevent impersonation; identity is represented solely by the unique `@username` and immutable `user_id`, paired with an optional short Bio.
   - Multi-wallet linking and primary wallet replacement (`wallet_change_history`) with automatic revocation of old wallet sessions—while preserving message history, contacts, and group memberships.
2. **EIP-4361 Sign-In with Ethereum (SIWE) & 1-Click Seamless Onboarding**
   - **1-Click Seamless Authentication**: Single click on "Connect MetaMask" connects the wallet account and immediately requests the single-use SIWE personal signature in one unified flow—unlocking the on-device E2EE enclave without secondary prompt friction.
   - **Auto-Signup & Refresh Persistence**: If an unauthenticated or newly connected wallet is detected on page load or refresh, the system automatically executes the SIWE sign-up/in challenge. Active sessions are silently validated, and expired tokens are cleanly purged to prevent 401 unhandled errors.
   - Single-use, domain-bound, time-limited SIWE challenges verified via `eth-account` (`EIP-191`) without ever requesting a seed phrase or private key.
   - `HttpOnly` (`zyphra_session`) + Bearer session tokens stored at rest solely as `SHA-256` hashes.
3. **Platform Admission Paywall (USD-Denominated with Live ETH/USD Conversion)**
   - **USD-Anchored Pricing**: Administrators configure the platform admission fee in US Dollars (`platform_entry_fee_usd`, default `$0` (free) until set in `/Admin456`; no environment variable).
   - **Live ETH/USD Price Oracle (`price_oracle.py`)**: Quotes convert the USD fee into ETH at the live spot rate (Coinbase, with Kraken as fallback, cached briefly and falling back to `eth_usd_price` if live sources are unreachable). On-chain verification (`POST /api/platform/payments/verify`) applies `PAYMENT_PRICE_TOLERANCE_PCT` (default `5%`) for price movement between quote and confirmation.
   - **Welcome Gate, First-Visit Splash & Admission Paywall**: First-time visitors see the `1 in 10,000` dot-field `WelcomeSplash` once per browser, followed by `WelcomeGate` (`Welcome to Zyphra.in — For 1% of 1%`) with zero page overflow until MetaMask is connected and platform admission is verified via `PlatformAdmissionModal.tsx`.
4. **Paid Groups with USD Entry Fees**
   - **Admin Paid Group Tagging**: Administrators can designate any group as "Paid Members Only" (`is_paid: true`) and assign an individual entry fee in USD (`entry_fee_usd`, migration `007`).
   - **In-App Fee Display & Admission Modal**: Discoverable paid groups display their fee in USD and live ETH equivalent. Members wishing to join are prompted with `PaidGroupAdmissionModal.tsx` to pick a **monthly or yearly** plan, and access is granted for that period once the on-chain transaction is verified with `purpose: "group_entry"`. Without an active group subscription a member cannot join, send or read in a paid group.
5. **Clean Membership Status & Streamlined Topbar (`Header.tsx`)**
   - Legacy `Level 7+` UI, routes, and qualification logic have been completely removed across the backend and frontend in favor of clean **Paid Member** / **Member** status.
   - For signed-in members, a clickable Paid Amount pill (`.topbar-paid-badge`) directly to the left of the circular theme toggle displays their total verified ETH paid (`Paid: <amount> ETH`) and navigates to Membership/Payments; the circular theme toggle button sits next to `Settings` (and next to `Connect MetaMask` when disconnected), and the Account Pill dropdown displays only the clickable profile header (`View & Edit Profile →`) and `Disconnect Wallet`.
   - Active Ethereum Network switching (`Ethereum Mainnet (1)` / `Sepolia Testnet (11155111)`) is exclusively controlled by administrators inside `/Admin456`.
6. **Server-Side Verified Payment Record System**
   - Authoritative `payment_records` storage tracking `payment_id`, `user_id`, `wallet_address`, `amount_atomic`, `currency`, `network`, `chain_id`, `status`, `transaction_reference`, `purpose` (`platform_entry` vs `group_entry`), `target_id`, and verification timestamps.
   - **Strict On-Chain Verification**:
     1. Transaction succeeded on-chain (`status == 1`).
     2. Sender matches the authenticated user's wallet address.
     3. Recipient matches the server-controlled authorized treasury destination (`authorized_payment_destination`).
     4. Transaction is on an allowed chain/network.
   - **Strict Idempotency & Anti-Replay**: Database uniqueness on `transaction_reference` ensures a transaction is never counted twice.
   - **Fail-Closed Security**: Missing or invalid treasury configuration, wrong recipients, or RPC failures fail closed.
   - User-facing pricing and status endpoints (`GET /api/platform/pricing`, `GET /api/platform/membership/status`, `GET /api/platform/groups/{group_id}/pricing`).
7. **Open Public Chat & Dual Presence (Paid Members Only)**
   - Once admitted, opens at `/` (`Chats → Open Chat`) with a clean **`PUBLIC`** room badge and live real-time streaming over `/api/platform/public-chat/messages` and `/ws/public-chat`. Both reading and posting require an authenticated Paid Member (`_require_paid_member_ctx`); legacy guest access and guest settings toggles have been removed.
   - **Dynamic Retention Notice & Live Policy Sync**: The room notice banner dynamically displays the active retention period on the right (`Messages kept for N days`). Saving settings in `/Admin456` broadcasts `public_policy_updated` over `/ws/public-chat`, instantly updating the banner for all active viewers without page reload.
   - **Streamlined Composer**: The composer padding has been tightened, file policy notices render only when files are selected, and the paperclip attachment icon is hidden across all three chat interfaces (`canAttach = false`).
   - **Smooth Animated Messaging**: Messages glide in with fluid entrance physics (`@keyframes chatMsgEntrance`), spring curves, optimistic send pulses with automatic message upgrade, sleek hover action clusters (copy, edit, delete), and smooth auto-scrolling (`scroll-behavior: smooth`).
   - **Zero Device & IP Tracking**: Privacy audit verified zero device hardware fingerprinting (purely random CSPRNG `dev_...` IDs), zero client IP logging/storage, strict Permissions-Policy headers disabling camera/mic/geo, and zero third-party trackers.
   - **Dual-Tier Presence**: Displays **`Watching`** (live public chat viewers) and **`Active Live`** (live connected MetaMask members). `Active Live` is strictly **hidden from non-connected visitors**, and **Admins are excluded** from all online presence counts and indicators (`is_user_online` / `active_live`).
   - Cursor pagination (`before_seq`), inline edit/delete window, malicious URI & duplicate-burst spam protection, user block filtering, and moderator controls.
8. **High-Security E2EE Private & Group Messaging**
   - **Member-Gated `+Add` Control**: Connected members click **`+Add`** to either **Create Group** (RFC 9420 MLS) or **Chat Individual** (Olm v2 1-to-1).
   - **1-to-1 & Multi-Device Private Chat**: Matrix Foundation **Vodozemac** (`@towns-protocol/vodozemac@0.1.0`) Olm v2 Double Ratchet (`X25519` + `Ed25519`), integrated `@username` directory, infinite cursor pagination (`after_seq`), 60-digit Safety Numbers, interactive Short Authentication Strings (SAS), opt-in read receipts, and peer blocking.
   - **Encrypted Group Chat**: **IETF RFC 9420 MLS** (`ts-mls@1.6.4`) TreeKEM ratcheting with strict pre-join secrecy (`epoch >= joined_epoch`), post-removal rekeying, optimistic concurrency (`HTTP 409` epoch reconciliation), **Leave Group**, integrated public group discovery & invite-code redemption, join-request queues, and server-enforced **Paid Group / Minimum ETH** access policies.
   - **Encrypted File Attachments & Local Vault**: On-device `AES-256-GCM` + `SHA-256` encrypted attachments (`e2eeAttachmentCrypto.ts`) with 14 MB limit, and non-extractable WebCrypto IndexedDB key storage (`e2eeVault.ts`) with inflight promise deduplication. (The paperclip attachment icon is hidden across all chats in the current UI via `canAttach = false` to keep conversations streamlined).
9. **"Talk to Admin" Support Conversations (`/support`)**
   - Dedicated **Support** tab (`/support`, `SupportView.tsx` + `SupportConversation.tsx`) with unread reply badge in the top navigation bar, allowing signed-in users (paid or unpaid) to open up to 5 concurrent support threads (`support_threads`, `support_messages`) and receive live `support_reply` notifications.
   - Admins manage and reply to threads in the **Support Inbox** tab (`AdminSupportInbox.tsx`) of `/Admin456`.
10. **Member-Gated Settings & Profile**
    - **Settings (`/settings`)**: Visible and accessible strictly to MetaMask-connected members from the top-right **Settings** button. Covers **Wallet & Membership** (RPC balance verify, verified payment totals & platform admission status), **Privacy & Security** (read receipts, presence visibility, enclave device vault shortcut), and **Blocked Accounts** (with one-click unblocking).
    - **Profile**: Accessed by clicking the profile header (`View & Edit Profile →`) in the Account Pill dropdown. Provides permanent identity review (`usr_...`), `@username` editor with real-time availability check, bio, and chronological audit trails for username and wallet changes.
11. **Login-Gated Admin Console (`/Admin456`) & Live Polling Dashboard**
    - Standalone **`/Admin456`** page (unlinked from the public UI) protected by server-side `ADMIN_LOGIN_ID` / `ADMIN_LOGIN_PASSWORD` verification (`admin_auth.py`: constant-time comparison, global brute-force slowdown (no IP is ever read, and no lockout), 256-bit hashed sessions with idle/absolute expiry).
    - **8-Tab RBAC Console** (`Overview`, `Users & Wallets`, `Groups & Policies` with monthly + yearly paid-group prices, `Payments` with Retry for stuck payments, `Moderation & Reports`, `Support Inbox`, `Platform Settings`, `Audit Logs`) with **automatic 5-second background polling** (no manual Refresh button needed) and instant single-query user filtering (`admin_list_users`).
    - Role-based administrators (`superadmin`, `moderator`) configure **Active Ethereum Network** (`Ethereum Mainnet (1)` vs `Sepolia Testnet (11155111)` selecting `RPC_URL_MAINNET` / `RPC_URL_SEPOLIA`), **`Username change Hrs`**, monthly + yearly USD membership pricing (`platform_entry_fee_usd`, `platform_yearly_fee_usd`), live/fixed ETH valuation (`use_live_eth_price`, `eth_usd_price`), authorized treasury destination, paid group tagging with monthly + yearly USD prices, **Support Inbox**, public chat moderation, user mutes/suspensions, group access policies, abuse reports, and `audit_logs`.
    - **Reorganized Platform Settings UI**: Structured into 3 clear cards with uniform 42px controls and `align-items: start`: (1) **Usernames & Identity** (cooldown hours & quarantine days), (2) **Members' Room** (max length, edit window, and retention days with live WebSocket sync to connected clients), and (3) **Membership, Pricing & Payments** (network toggle, treasury destination, USD pricing, and live ETH oracle toggles).
12. **Cold-Start & Connection Resilience**
    - Frontend `warmUpBackend()` (`GET /api/health?deep=1`) wakes Neon/Render on page load, `resilientFetch.ts` automatically retries idempotent `GET`/`HEAD`/`OPTIONS` requests with backoff (`onWake` reconnects WebSockets immediately on online/tab focus), and `backend/app.py` explicitly loads `backend/.env` (`override=True`) and converts dropped PostgreSQL/Neon connections into `503 Retry-After: 1` after flushing idle pool sockets.

---

## Repository Structure

```text
MetaMask_chatonly/
├── backend/                     # Python FastAPI + WebSockets + Neon PostgreSQL backend
│   ├── app.py                   # ASGI entrypoint, backend/.env loader, security headers, CORS, 503 DB recovery & router mounting
│   ├── admin_auth.py            # /Admin456 login verifier, global login slowdown (no IPs) & session guard
│   ├── eth_rpc.py               # Server-side Ethereum Mainnet/Sepolia RPC balance & tx verifier
│   ├── price_oracle.py          # Live ETH/USD spot oracle (Coinbase/Kraken) with admin fixed fallback
│   ├── e2ee_db.py               # Permanent identity, SIWE sessions, Olm prekeys & MLS group store
│   ├── e2ee_routes.py           # /api/e2ee/* REST endpoints + /ws/e2ee real-time ciphertext hub (admins excluded from online presence)
│   ├── platform_db.py           # Admission paywall, paid groups, payments, Open Chat, single-query admin user listing, RBAC & audit DB
│   ├── platform_routes.py       # /api/platform/* REST endpoints + /ws/public-chat & /ws/member-presence
│   ├── support_db.py            # "Talk to admin" support threads & messages persistence
│   ├── chat_db.py               # Database connection pool (PostgreSQL / SQLite fallback)
│   ├── migrations/              # Versioned PostgreSQL SQL migrations (001 through 010; 010 is a one-time grandfathering step)
│   ├── run_migrations.py        # Idempotent PostgreSQL migration runner & default settings seeder
│   └── test_*.py                # 125 automated backend unit & end-to-end security integration tests (+1 live Neon test)
├── frontend/                    # React 19 + TypeScript + Tailwind CSS v4 + Vite 8 SPA
│   ├── src/components/          # Responsive UI: WelcomeGate/Splash, Header, Chats, Payments, Support, Settings & /Admin456
│   ├── src/services/            # SIWE, Web3, Payments, Pricing, Olm v2, RFC 9420 MLS, Vault, resilientFetch & API clients
│   ├── vercel.json              # SPA route rewrite rules (/, /settings, /payments, /support, /Admin456)
│   └── tests/                   # 43 automated Node.js cryptographic, vault & sync tests
└── docs/                        # Threat model, system architecture, API reference, and workflows
```

---

## Quick Start

### 1. Backend Startup (Unified Single Command)
The backend features an automated single-command entrypoint that loads `backend/.env` explicitly (`override=True`), auto-detects dependencies, pip-installs missing packages, runs database migrations on Neon PostgreSQL, seeds default settings, and starts the server on port 10000:

```bash
cd backend
# Copy .env.example to .env and configure NEON_DATABASE_URL, RPC URLs, and ADMIN_LOGIN_ID / ADMIN_LOGIN_PASSWORD
python app.py
```
*(Supports `python App.py` or running `python app.py` directly from project root.)*

### 2. Frontend Startup (Automated Dev Bootstrap)
The frontend automatically runs `npm install` on first launch via its `predev` lifecycle hook:

```bash
cd frontend
# Optional: copy .env.example to .env (defaults to http://localhost:10000/api)
npm run dev
```
*(Or run `npm run dev` directly from project root.)*

### 3. Run All Automated Tests
```bash
# Backend (132 unit/integration tests across permanent identity, SIWE, verified payments, paid membership/groups, Open Chat, Olm v2, MLS, /Admin456 login & RBAC)
TESTING=1 python -m pytest backend -k "not test_neon_conn" -q

# Frontend (43 cryptographic, vault, MLS, sync & failed-send retry tests + linter + production build)
npm --prefix frontend test
npm --prefix frontend run lint
npm --prefix frontend run build
```

---

## Documentation Index
- [High-Security E2EE Architecture & Threat Model](docs/e2ee-security-architecture.md)
- [System Architecture & Data Flows](docs/system-architecture.md)
- [Platform Feature Catalog](docs/features.md)
- [Backend Service Guide](backend/README.md)
- [Frontend Application Guide](frontend/README.md)
- [Production Deployment Guide (Render + Vercel + Neon)](backend/DEPLOYMENT.md)

