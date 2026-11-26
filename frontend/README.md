# Zyphra.in — Frontend Web3 & E2EE Chat Application

A responsive **React 19 + TypeScript + Tailwind CSS v4 + Vite 8** Single Page Application providing **WelcomeGate & first-visit WelcomeSplash (`DotField`)**, **MetaMask EIP-4361 (SIWE)** authentication with 1-click auto-signup and refresh session persistence, **USD-denominated Platform & Paid Group Admission Modals (converted to live ETH)**, a unified **Chats** console (**Open Chat** + **Olm v2 Double Ratchet Private Chats** + **RFC 9420 MLS Group Chat**), **"Talk to Admin" Support (`/support`)**, clean **Paid Member** status, **Server-Verified Payments**, **cold-start `resilientFetch`**, and an **RBAC Administrative Console**.

---

## Navigation, Routes & Unified Chat Console

The top command bar (`Header.tsx`) presents a clean `[Z] zyphra.in` brand monolith, a 3-pill center switcher (**`Chats`**, **`Payments`**, and **`Support`** with unread reply badge), and a right-hand action cluster (**Paid Amount pill `.topbar-paid-badge`** showing `Paid: <amount> ETH` for signed-in users, **circular theme toggle `.theme-toggle-btn`**, member-gated **`Settings`** button, and **`Connect MetaMask`** button / connected **Account Pill**). Before entering (`!accessEntered`), `Header` displays in `gated` mode and `WelcomeGate.tsx` (`For 1% of 1%`) renders over the `DotField.tsx` canvas (while `WelcomeSplash.tsx` runs once per browser on first visit and `warmUpBackend()` wakes the backend via `/api/health?deep=1`). Clicking **Connect MetaMask** connects the wallet and immediately prompts for the EIP-4361 SIWE signature. If a connected member has not yet paid the platform admission fee, `PlatformAdmissionModal.tsx` appears showing the USD fee converted to ETH at the live oracle rate, the rate source, and the authorized treasury destination.

| Route / Surface | Component | Highlights |
| :--- | :--- | :--- |
| **`/` — Welcome Gate & Chats** | `WelcomeGate` / `Chat` (`Chat.tsx`, `forcedMode="open_chat" \| "dm" \| "groups"`) | `WelcomeGate` (`For 1% of 1%`) protects entry until connected & paid; inside the app, unified two-pane chat console with **Open Chat** (`PUBLIC` badge, Paid-Member gated `/ws/public-chat`, dynamic retention banner showing `Messages kept for N days` with real-time `public_policy_updated` sync, verified `@username • VERIFIED` badges, smooth animated messages, edit/delete window, moderator tools, live `Watching` viewer count), hidden attachment paperclip across all 3 chat modes (`canAttach = false`), member-gated **`+Add`** control (**Create Group** / **Chat Individual**), dynamic list of active DMs and joined MLS groups with infinite cursor pagination (`after_seq`), Paid Group cards with `PaidGroupAdmissionModal`, and member-only **`Active Live`** presence badge (with Admins excluded). |
| **`/payments` — Payments** | `PaymentsView` (`PaymentsView.tsx`) | Subscriptions page: platform membership status with expiry and Renew, each paid-group subscription with expiry and Renew, and payment history. Plans are **monthly (30 days) or yearly (365 days)**; renewing stacks on the time left. A `402` from any request sends the member here. |
| **`/support` — Support** | `SupportView` (`SupportView.tsx` + `SupportConversation.tsx`) | **"Talk to Admin"**: Signed-in users (paid or unpaid) can start up to 5 open support threads, read admin replies, and track unread counts via the header badge. |
| **`/settings` — Settings** | `SettingsView` (`PlatformViews.tsx`) | Member-gated view opened via the top-right **Settings** button (rendered strictly for MetaMask-connected members). Sub-tabs: **Wallet & Membership** (live on-chain Mainnet/Sepolia RPC ETH balance verification, verified payment totals, platform admission status), **Privacy & Security** (DM read receipts, online status, device vault guidance), and **Blocked Accounts** (with one-click unblocking). |
| **Account Pill → Profile** | `MyProfileView` (`PlatformViews.tsx`) | Shown in the top-right connected pill (initial badge, `@username`, `Paid Member` / `Member`) once MetaMask is connected. Its streamlined dropdown contains only the clickable profile header (`View & Edit Profile →`) and `Disconnect Wallet`: immutable `user_id` badge, `@username` editor with debounced real-time availability indicator (`GET /account/username/check`), cooldown feedback, bio editor (Display Name removed to prevent impersonation), username audit log, and multi-wallet link/replace history. |
| **`/Admin456` — Admin Console** | `AdminPortal` (`AdminPortal.tsx`) → `AdminDashboard` (`AdminDashboard.tsx`) | Standalone page (unlinked from the public header, marked `noindex, nofollow`). Renders strictly a login form until the backend verifies `ADMIN_LOGIN_ID` / `ADMIN_LOGIN_PASSWORD` (`POST /api/platform/admin/login`); stores the session token in `sessionStorage` (`X-Admin-Token`), supports server-side Sign Out revocation, and mounts the **8-tab** RBAC console (`Overview`, `Users & Wallets`, `Groups & Policies` with monthly + yearly Paid Group prices, `Payments`, `Moderation & Reports`, `Support Inbox` via `AdminSupportInbox.tsx`, `Platform Settings` organized into 3 clear cards with 42px inputs and live WebSocket retention broadcast, and `Audit Logs`) with **automatic 5-second background polling**. |

`App.tsx` keeps `/`, `/settings`, `/payments`, and `/support` synchronized with browser history (`pushState` + `popstate` Back/Forward support), and `frontend/vercel.json` rewrites SPA paths to `/index.html` for direct loads/refreshes in production.

---

## Cryptographic & Storage Services (`src/services/`)

- **`e2eeVault.ts`**: Generates a **non-extractable** (`extractable: false`) 256-bit `AES-256-GCM` WebCrypto master key in IndexedDB (`zyphra_e2ee_vault_v2`). Encrypts all Vodozemac pickles, Olm sessions, MLS `PrivateKeyPackage`s, MLS `GroupState`s, and cached envelopes at rest. Never stores private keys or plaintext messages in `localStorage`.
- **`olmService.ts`**: Matrix Foundation `@towns-protocol/vodozemac@0.1.0` WASM wrapper for Olm v2 3DH + Double Ratchet, Ed25519 device bundle signing, OTK replenishment, and 60-digit Safety Numbers.
- **`mlsGroupService.ts`**: `ts-mls@1.6.4` (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`) wrapper for signed `KeyPackage`s, `Create` / `Add` / `Remove` / `Update` Commits, `Welcome` onboarding, `PrivateMessage` encryption, and `epochAuthenticator` verification.
- **`e2eeAttachmentCrypto.ts`**: Per-file ephemeral 256-bit `AES-256-GCM` encryption + constant-time `SHA-256` digest verification before decryption.
- **`web3.ts`, `e2eeApi.ts`, `platformApi.ts`, `api.ts`, `resilientFetch.ts`**: MetaMask EIP-1193 provider integration, EIP-4361 SIWE authentication, typed REST/WebSocket clients, initial `warmUpBackend()` (`/api/health?deep=1`), and automatic idempotent retry + `onWake` WebSocket reconnection on transient cold-start/network failures.

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

# Run all 43 Node.js cryptographic, vault, MLS & failed-send unit tests
npm test

# Run Oxlint static analysis
npm run lint

# Type-check (tsc -b) and build production bundle (dist/)
npm run build
```
