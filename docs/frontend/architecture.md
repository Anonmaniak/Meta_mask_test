# Frontend Architecture & Technical Implementation

## 1. Technology Stack

- **Framework**: [React 19](https://react.dev/) + [TypeScript](https://www.typescriptlang.org/) (strict mode)
- **Bundler**: [Vite 8](https://vite.dev/)
- **Styling**: Tailwind CSS v4 + CSS custom property design tokens (`index.css`)
- **Web3 Auth**: [ethers.js v6](https://docs.ethers.org/v6/) EIP-1193 MetaMask integration (SIWE signing & chain switching only)
- **E2EE Protocols**:
  - `@towns-protocol/vodozemac@0.1.0` (Olm v2 Double Ratchet + Ed25519 + SAS)
  - `ts-mls@1.6.4` + `@hpke/core@1.9.0` (IETF RFC 9420 MLS TreeKEM)
  - Native W3C `SubtleCrypto` (`AES-256-GCM` IndexedDB vault & encrypted attachments)

---

## 2. Component Hierarchy & Navigation Routing

The top bar (`Header.tsx`) presents a clean `[Z] zyphra.in` brand monolith alongside **3 center navigation pills** (`Chats`, `Payments`, `Support` with an unread reply badge), and a right-hand action cluster containing a **circular theme toggle button (`.theme-toggle-btn`)**, a member-gated **Settings** button (rendered strictly for MetaMask-connected members, opening `/settings`), and the **Connect MetaMask** button (which provides a **1-click seamless authentication flow** connecting the wallet and immediately chaining the EIP-4361 SIWE signature request; once connected, it becomes an **Account Pill** displaying avatar, unique `@username`, and `Paid Member` / `Member` whose streamlined dropdown shows only the clickable profile header **`View & Edit Profile →`** and **`Disconnect Wallet`** — with legacy Membership Status cards, Profile/Settings quick buttons, theme toggle, and network switcher removed). Before access is granted (`!accessEntered`), `Header` runs in `gated` mode (keeping the circular theme toggle and `Connect MetaMask` button visible) and `MainApp` renders `WelcomeGate.tsx` (`For 1% of 1%`, with `DotField.tsx`) while `WelcomeSplash.tsx` plays once on a browser's first visit (`main.tsx` also fires `warmUpBackend()` on load). If a connected member has not paid the platform admission fee, `PlatformAdmissionModal.tsx` appears showing the USD fee converted to ETH via the live oracle, the rate source, and the authorized treasury destination.

- **URL Synchronization (`MainApp` in `App.tsx` + `vercel.json`)**: Keeps the browser URL synchronized across `/`, `/settings`, `/payments`, and `/support` via `history.pushState` and `popstate`. Direct access to `/settings` verifies wallet connection state before redirecting.
- **Standalone Admin Route (`/Admin456`)**: `App` routes `/Admin456` (case-insensitive) directly to `AdminPortal.tsx`, which renders strictly a login form (`noindex, nofollow`) until the backend validates `ADMIN_LOGIN_ID` / `ADMIN_LOGIN_PASSWORD` and only then mounts the **7-tab** `AdminDashboard.tsx` (`Overview`, `Users & Wallets`, `Groups & Policies`, `Moderation & Reports`, `Support Inbox` via `AdminSupportInbox.tsx`, `Platform Settings` with `Username change Hrs` and the `Active Ethereum Network` segmented toggle, and `Audit Logs`) with **automatic 5-second background polling** and instant single-query user filtering.
- **Unified Chat Console (`Chat.tsx`)**: Left channel rail (`Chats`) integrates:
  1. **Open Chat** (`PUBLIC` badge, Paid-Member gated read/post access, admission fee prompt if unpaid, `Watching` viewer count, smooth entrance glide `@keyframes chatMsgEntrance`, optimistic sending pulse with automatic upgrade, sleek hover action clusters, smooth auto-scrolling).
  2. **Member-Gated `+Add` Control**: Rendered only when connected with MetaMask.
     - **Create Group**: Opens creation modal with group name, entry fee / thresholds, visibility, and member selection to initiate RFC 9420 MLS TreeKEM groups.
     - **Chat Individual**: Prompts for target `@username` or user ID to initiate an Olm v2 Double Ratchet private conversation.
  3. **Conversations List**: Dynamically displays all active 1-to-1 DMs and joined encrypted groups.
  4. **Paid Group Cards**: Displays entry fee in ETH and USD equivalent, providing a "Pay & Join Group" action opening `PaidGroupAdmissionModal.tsx`.
  5. **Dual Presence Model**: Displays live `Watching` viewers (for all visitors) and `Active Live` connected non-admin members (strictly visible to connected members; admins excluded).
- **Pure Identity Model in Profile (`MyProfileView`)**: Redundant display names have been removed to prevent user confusion and impersonation. Users manage their unique `@username` (with real-time availability feedback via `GET /account/username/check`) and optional bio.

```mermaid
graph TD
    App["App.tsx\n(Top-Level Path Router)"] -->|"path /Admin456"| AdminPortal["AdminPortal.tsx (Login Gate)\n-> AdminDashboard.tsx (7-Tab Live-Polled RBAC Console + AdminSupportInbox)"]
    App -->|"all other paths"| MainApp["MainApp (Wallet + SIWE + Gate & Paywall Coordinator)"]
    MainApp --> Splash["WelcomeSplash.tsx + DotField.tsx\n(First-Visit 1-in-10,000 Reveal)"]
    MainApp --> Header["Header.tsx\n(Nav: Chats | Payments | Support + Theme Circle + Settings + Account Pill)"]
    MainApp -->|"!accessEntered"| Gate["WelcomeGate.tsx\n(For 1% of 1% Gate + Connect MetaMask)"]
    MainApp -->|"accessEntered"| Router{"activeSection (Default: 'open_chat' at /)"}
    MainApp --> AdmissionModal["PlatformAdmissionModal.tsx\n(USD Fee converted to Live ETH)"]
    MainApp --> PaidGroupModal["PaidGroupAdmissionModal.tsx\n(Group USD Fee converted to Live ETH)"]

    Router -->|"open_chat | dm | groups (/)"| ChatConsole["Chat.tsx\n(Unified Two-Pane Chat Console)"]
    Router -->|"profile (Account Pill)"| MyProfileView["MyProfileView (PlatformViews.tsx)"]
    Router -->|"settings | wallet_level (/settings)"| SettingsView["SettingsView (PlatformViews.tsx)\nTabs: Wallet & Membership | Privacy & Security | Blocked Accounts"]
    Router -->|"payments (/payments)"| PaymentsView["PaymentsView.tsx"]
    Router -->|"support (/support)"| SupportView["SupportView.tsx + SupportConversation.tsx\n(Talk to Admin Threads)"]

    ChatConsole -->|"Channel Rail: Open Chat"| OpenPublicChatView["OpenPublicChatView (embedded=true, PUBLIC badge)"]
    ChatConsole -->|"Channel Rail: +Add (Members Only)"| AddDropdown["+Add Dropdown\nCreate Group (MLS) | Chat Individual (Olm v2)"]
    ChatConsole -->|"Active DMs"| DmChat["1-to-1 Olm v2 DM (Infinite Cursor Pagination)"]
    ChatConsole -->|"Active Groups"| MlsChat["RFC 9420 MLS Group (TreeKEM Ratchet)"]
```

---

## 3. Service Layer (`frontend/src/services/`)

| Module | Purpose |
| :--- | :--- |
| `web3.ts` | MetaMask EIP-1193 account detection, EIP-191 `personal_sign` for SIWE challenges, Mainnet/Sepolia chain switching, and `BigInt` Wei/ETH formatting. |
| `e2eeVault.ts` | Non-extractable (`extractable: false`) `AES-256-GCM` WebCrypto master key in IndexedDB (`zyphra_e2ee_vault_v2`) wrapping all local secrets and cached envelopes. |
| `olmService.ts` | Vodozemac Olm v2 account/session lifecycle, Ed25519 bundle signing, OTK replenishment, 60-digit Safety Numbers, and SAS verification. |
| `mlsGroupService.ts` | RFC 9420 MLS `KeyPackage` generation, `Create`/`Add`/`Remove`/`Update` Commits, `Welcome` onboarding, and `PrivateMessage` AEAD. |
| `e2eeAttachmentCrypto.ts` | On-device `AES-256-GCM` file encryption and `SHA-256` ciphertext verification. |
| `chatCrypto.ts` & `chatKeyService.ts` | P-256 ECDH / AES-256-GCM envelope primitives and key registration helpers validated by unit tests. |
| `e2eeApi.ts` | Typed REST & `/ws/e2ee` client for SIWE auth, identity/wallet linking, device bundles, Olm DM relay, and MLS group commits/messages. |
| `platformApi.ts` | Typed REST & `/ws/public-chat` / `/ws/member-presence` client for pricing, membership status, RPC wallet verification, Open Public Chat, `@username` search, blocks, read receipts, group policies/invites/join requests, reports, "Talk to admin" support threads, `/Admin456` session login (`adminLogin`, `adminSessionValid`, `adminLogout`), and RBAC admin APIs. |
| `resilientFetch.ts` | Cold-start & transient error retry helper for idempotent (`GET`/`HEAD`/`OPTIONS`) requests (`resilientFetch`, `NetworkUnreachableError`, `backoffDelay`) plus `onWake` listener to reconnect WebSockets on `online` / `visibilitychange`. |
| `api.ts` | Health status check, `warmUpBackend()` (`GET /api/health?deep=1`), and backend base URL resolver (Node-safe for automated unit tests). |
