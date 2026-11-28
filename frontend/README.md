# Zyphra.in — Frontend Web3 & E2EE Chat Application

A responsive **React 19 + TypeScript + Tailwind CSS v4 + Vite 8** Single Page Application providing **WelcomeGate & first-visit WelcomeSplash**, **MetaMask EIP-4361 (SIWE)** authentication with 1-click auto-signup and refresh session persistence, **USD-denominated Platform & Paid Group Admission Modals (converted to live ETH)**, a unified **Messages** console (**Members' room** + **Olm v2 Double Ratchet Private Chats** + **RFC 9420 MLS Group Chat** with instant isolated conversation switching and circular animated header search/`⋮` menus), **Contact Admin (`/support`)**, clean **Active member** status, **Server-Verified Payments**, **cold-start `resilientFetch`**, and an **Admin Console (`/Admin456`)**.

---

## Navigation, Routes & Unified Chat Console

The top command bar (`Header.tsx`) presents a `[Z] Zyphra` brand monolith (matching `public/favicon.svg`), a 3-tab center switcher (**`Messages`**, **`Membership`**, and **`Contact Admin`** with unread reply badge), and a right-hand action cluster (**Paid Amount pill `.topbar-paid-badge`** showing `Paid: <amount> ETH` for signed-in users, **Notification Bell**, **circular theme toggle `.theme-toggle-btn`**, member-gated **`Settings`** button, and **`Connect to MetaMask`** button / connected **Account Pill**). Before entering (`!accessEntered`), `Header` displays in `gated` mode with generous top padding and `WelcomeGate.tsx` renders over the canvas (while `WelcomeSplash.tsx` runs once per browser on first visit and `warmUpBackend()` wakes the backend via `/api/health?deep=1`). Clicking **Connect to MetaMask** connects the wallet and immediately prompts for the EIP-4361 SIWE signature. If a connected member has not yet paid the platform admission fee, `PlatformAdmissionModal.tsx` appears showing the USD fee converted to ETH at the live oracle rate, the rate source, and the authorized treasury destination.

| Route / Surface | Component | Highlights |
| :--- | :--- | :--- |
| **`/` — Welcome Gate & Messages** | `WelcomeGate` / `Chat` (`Chat.tsx`, `forcedMode="open_chat" \| "dm" \| "groups"`) | `WelcomeGate` protects entry until connected & paid; inside the app, unified two-pane chat console with **Members' room** (`OpenPublicChatView`, module-cached per account, dynamic retention banner `Messages kept for N days`), **Start a conversation** (**Create a group** / **Start a private chat**), instant isolated switching across **Members' room**, **Groups**, and **Private chats** (pre-paint cache swap, per-scope sync serialization, parallel fetches), top-right circular animated `ChatSearchBar` & circular `⋮` `ConversationMenu`, and Paid Group cards with `PaidGroupAdmissionModal`. |
| **`/payments` — Membership** | `PaymentsView` (`PaymentsView.tsx`) | Subscriptions page: platform membership status with expiry and Renew, each paid-group subscription with expiry and Renew, and payment history. Plans are **monthly (30 days) or yearly (365 days)**; renewing stacks on the time left. A `402` from any request sends the member here. |
| **`/support` — Contact Admin** | `SupportView` (`SupportView.tsx` + `SupportConversation.tsx`) | **Contact Admin**: Signed-in users (paid or unpaid) can start up to 5 open support threads, read admin replies, and track unread counts via the header badge. |
| **`/settings` — Settings** | `SettingsView` (`PlatformViews.tsx`) | Member-gated view opened via the top-right **Settings** button (rendered strictly for MetaMask-connected members). Sub-tabs: **Wallet & Membership** (live on-chain Mainnet/Sepolia RPC ETH balance verification, verified payment totals, platform admission status), **Privacy & Security** (DM read receipts, online status, device vault guidance), and **Blocked Accounts** (with one-click unblocking). |
| **Account Pill → Profile** | `MyProfileView` (`PlatformViews.tsx`) | Shown in the top-right connected pill (initial badge, `@username`, `Active member` / `Member`) once MetaMask is connected. Its streamlined dropdown contains only the clickable profile header (`View & Edit Profile →`) and `Disconnect Wallet`: immutable `user_id` badge, `@username` editor with debounced real-time availability indicator (`GET /account/username/check`), cooldown feedback, bio editor (Display Name removed to prevent impersonation), username audit log, and multi-wallet link/replace history. |
| **`/Admin456` — Admin** | `AdminPortal` (`AdminPortal.tsx`) → `AdminDashboard` (`AdminDashboard.tsx`) | Standalone page (titled **`Admin`**, unlinked from the public header, marked `noindex, nofollow`). Renders strictly a login form until the backend verifies `ADMIN_LOGIN_ID` / `ADMIN_LOGIN_PASSWORD` (`POST /api/platform/admin/login`); stores the session token in `sessionStorage` (`X-Admin-Token`), supports server-side Sign Out revocation, and mounts the RBAC console (`Overview`, `Users & Wallets`, `Groups & Policies` with monthly + yearly Paid Group prices, `Payments`, `Free access`, `Moderation & Reports`, `Support Inbox` via `AdminSupportInbox.tsx`, `Platform Settings` with 2×2 pricing controls, custom-chevron selects, and live WebSocket retention broadcast, and `Activity log`) with **automatic 5-second background polling**. |

`App.tsx` keeps `/`, `/settings`, `/payments`, and `/support` synchronized with browser history (`pushState` + `popstate` Back/Forward support), and `frontend/vercel.json` rewrites SPA paths to `/index.html` for direct loads/refreshes in production.

---

## Cryptographic & Storage Services (`src/services/`)

- **`e2eeVault.ts`**: Generates a **non-extractable** (`extractable: false`) 256-bit `AES-256-GCM` WebCrypto master key in IndexedDB (`zyphra_e2ee_vault_v2`). Encrypts all Vodozemac pickles, Olm sessions, MLS `PrivateKeyPackage`s, MLS `GroupState`s, and cached envelopes at rest. Never stores private keys or plaintext messages in `localStorage`.
- **`olmService.ts`**: Matrix Foundation `@towns-protocol/vodozemac@0.1.0` WASM wrapper for Olm v2 3DH + Double Ratchet, Ed25519 device bundle signing, OTK replenishment, and 60-digit Safety Numbers.
- **`mlsGroupService.ts`**: `ts-mls@1.6.4` (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`) wrapper for signed `KeyPackage`s, `Create` / `Add` / `Remove` / `Update` Commits, `Welcome` onboarding, `PrivateMessage` encryption, and `epochAuthenticator` verification.
- **`e2eeAttachmentCrypto.ts`**: Per-file ephemeral 256-bit `AES-256-GCM` encryption + constant-time `SHA-256` digest verification before decryption.
- **`deviceProvisioning.ts` & `deviceRevocation.ts`**: Single-flight device registration & KeyPackage upload (`ensureLocalDeviceRegistered`) shared by `App.tsx` and `Chat.tsx`, plus safe vault-wipe gating (`shouldWipeLocalDevice`) that wipes local keys only upon server-confirmed device revocation.
- **`e2eeRealtime.ts` & `chatEvents.ts`**: Shared `/ws/e2ee` subscriber tracking connection state (`isE2EERealtimeLive()` so `Chat.tsx` uses a `30 s` safety poll when connected and `4.5 s` fallback only when disconnected, skipping hidden tabs) plus encrypted message/event folding and `isSingleEmoji` reaction validation.
- **`web3.ts`, `e2eeApi.ts`, `platformApi.ts`, `api.ts`, `resilientFetch.ts`**: MetaMask EIP-1193 provider integration, EIP-4361 SIWE authentication, typed REST/WebSocket clients (`ws_closed` disconnect signaling), initial `warmUpBackend()` (`/api/health?deep=1`), visibility-aware health polling, and automatic idempotent retry + `onWake` WebSocket reconnection on transient cold-start/network failures.

---

## Environment Variables (`frontend/.env`)

Copy `frontend/.env.example` to `frontend/.env`:

```env
VITE_BACKEND_URL=http://localhost:10000/api
```

In local development without `VITE_BACKEND_URL`, Vite automatically proxies `/api` and `/ws` to `http://localhost:10000`.

---

## Scripts & Verification

```bash
cd frontend

# Install dependencies
npm install

# Start Vite development server (http://localhost:5173)
npm run dev

# Run all 56 Node.js cryptographic, vault, revocation, MLS, CSP, notification & chat-event unit tests across 14 suites
npm test

# Run Oxlint static analysis
npm run lint

# Type-check (tsc -b) and build production bundle (dist/)
npm run build
```
