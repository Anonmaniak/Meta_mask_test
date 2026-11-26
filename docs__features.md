# Zyphra.in — Platform Feature Catalog

**Zyphra.in** is a pure **Ethereum Wallet-Linked Real-Time Chat Platform** built on **FastAPI**, **Neon PostgreSQL**, **React 19**, **MetaMask (EIP-4361 SIWE)**, **Vodozemac (Olm v2)**, and **RFC 9420 MLS**.

---

## 1. Permanent Internal Identity & Multi-Wallet Management
- **Immutable `user_id` (`usr_...`)**: Every account has a permanent UUID-backed identifier decoupled from mutable attributes.
- **Unique `@username` Handle**: Case-insensitive uniqueness (`^[a-z0-9_]{3,28}$`) guaranteed by database partial unique index (`idx_chat_users_username_lower`), configurable rename cooldown (`username_cooldown_hours`, labeled **Username change Hrs** in `/Admin456`), old-username quarantine reservation (`username_reservation_days`) preventing handle-hijack impersonation, and full `username_history`.
- **Real-Time Username Availability**: Debounced endpoint `GET /api/e2ee/account/username/check` provides immediate live visual feedback (`available`, `is_current`, `reason`) before submission.
- **Pure Identity Model (No Redundant Display Name)**: Display Name has been completely eliminated across the platform to prevent impersonation attacks. Users are identified solely by their cryptographically bound `@username` and permanent `user_id`, paired with an optional bio.
- **Authenticated Wallet Linking & Replacement**: Link additional MetaMask wallets or replace a primary wallet via signed SIWE challenges (`link_wallet`), automatically revoking old wallet sessions while keeping all DMs, groups, and E2EE device keys attached to the same `user_id`.

## 2. EIP-4361 Sign-In with Ethereum (SIWE) & 1-Click Onboarding
- **1-Click Seamless Authentication**: Clicking "Connect MetaMask" connects the wallet account and immediately requests the single-use SIWE personal signature in one unified flow—unlocking the on-device E2EE enclave without secondary prompt friction.
- **Auto-Signup & Refresh Persistence**: If an unauthenticated or newly connected wallet is detected on page load or refresh, the system automatically executes the SIWE sign-up/in challenge. Active sessions are silently validated, and expired tokens are cleanly purged to prevent 401 unhandled errors.
- **Standards-Compliant EIP-4361 Challenges**: Challenge messages contain domain binding, chain ID, single-use nonce, issued/expiration timestamps, and an explicit security notice separating authentication signatures from encryption keys.
- **Secure Session Management**: Verified server-side via `eth-account` (`EIP-191` `personal_sign`) with `HttpOnly` cookie (`zyphra_session`) + `SHA-256` hashed session persistence.

## 3. Welcome Gate, First-Visit Splash & Platform Admission Paywall (USD-Denominated)
- **First-Visit Welcome Splash (`WelcomeSplash.tsx`)**: On a browser's very first visit (`zyphra_welcome_seen_v1` in `localStorage`), a full-screen `100 x 100` `DotField` (`1 in 10,000`) plays a one-time reveal animation (`Welcome to Zyphra.in — For 1% of 1%`) while `warmUpBackend()` wakes the backend and database (`GET /api/health?deep=1`) in the background.
- **Welcome Gate (`WelcomeGate.tsx`)**: Visitors who have not yet connected and satisfied platform admission see only the Welcome Gate canvas (`Welcome to Zyphra.in — For 1% of 1%`, zero page scrollbar) and a **Connect MetaMask** (or **Connect** once paid) button; the chat workspace mounts only after access is granted.
- **USD-Denominated Pricing with Live ETH Conversion**: Platform membership is priced in US Dollars (`platform_entry_fee_usd`, default `$0` until the admin sets it in `/Admin456`; no environment variable) and converted into ETH at quote time by `price_oracle.py` (Coinbase -> Kraken -> admin-configured `eth_usd_price` fallback, rounded up to 6 decimals). `PAYMENT_PRICE_TOLERANCE_PCT` (default `5%`) accommodates ETH price movement between quote and confirmation.
- **Monthly & Yearly Subscriptions**: membership and each paid group are billed monthly (30 days) or yearly (365 days, `platform_yearly_fee_usd` / per-group `entry_fee_yearly_usd`; 0 = 12 x monthly). Members choose when paying; time stacks on renewal; expired subscriptions lose access (HTTP 402) until renewed. Members see their status in the Payments tab and admins see every payment in `/Admin456` -> Payments.
- **Authoritative Admin Pricing & Network Control**: `platform_entry_fee_usd`, `use_live_eth_price`, fallback `eth_usd_price`, `authorized_payment_destination`, and `default_balance_chain_id` (**Active Ethereum Network**: Mainnet `1` vs Sepolia `11155111`) are strictly controlled by administrators from `/Admin456`.
- **Admission Paywall Popup (`PlatformAdmissionModal.tsx`)**: Auto-refreshes quotes every 30 seconds, persists pending transaction hashes in `localStorage` across refreshes, and displays:
  1. The USD membership fee and live ETH equivalent (`platform_entry_fee_eth`).
  2. The current ETH/USD rate and rate source (`live`, `live_cached`, `live_stale`, or `admin_fixed`).
  3. The authorized platform treasury destination address and active network chain.
- **Fail-Closed Access Gating**: Access remains gated until the member signs the on-chain transfer to the authorized treasury and passes server verification (`POST /api/platform/payments/verify`), authoritatively marking `chat_users.is_platform_paid = True`.

## 4. Paid Groups with USD Entry Fees
- **Admin Paid Group Tagging**: Administrators can designate any group as "Paid Members Only" (`is_paid: true`) in the Admin Dashboard (`Groups` tab) and configure an entry fee in USD (`entry_fee_usd`, migration `007`).
- **In-App Fee Display**: Discoverable paid groups display their USD entry fee and live ETH conversion (`GET /api/platform/groups/{group_id}/pricing`).
- **Dedicated Group Admission Paywall**: Members wishing to join a paid group are prompted with `PaidGroupAdmissionModal.tsx` displaying the live quote and treasury destination. Upon verifying the on-chain receipt with `purpose: "group_entry"` and matching `group_id`, access is granted.

## 5. Responsive Navigation, Routes & Unified Chats Console
- **Clean Membership Status (Removal of Legacy Levels UI & Backend Engine)**:
  - Legacy `Level 7+` tiers, routes, database qualification logic (`level_qualification.py`), and UI badges (`LVL 7`) have been completely removed in favor of clean **Paid Member** / **Member** status.
  - Header profile pill, Open Chat messages, and directory cards reflect clean membership status.
- **Streamlined Top Command Bar & URL Routes**:
  1. **Center Switcher (`Chats`, `Payments`, `Support`)**:
     - **`Chats` (`/`)**: Unified two-pane messaging console containing the Open Public Chat room, member-gated **`+Add`** control, and dynamically listed direct messages & encrypted groups.
     - **`Payments` (`/payments`)**: Subscriptions page (`PaymentsView.tsx`): platform membership status with expiry and a Renew button, each paid-group subscription with its expiry and a Renew button, and payment history (period, amount, status). Membership and every paid group are billed **monthly (30 days) or yearly (365 days)**; renewing adds time on top of what is left. Any request refused with `402` (expired subscription) sends the member here.
     - **`Support` (`/support`)**: **"Talk to Admin"** (`SupportView.tsx`) with a live unread-reply badge. Signed-in members (paid or unpaid) can start up to 5 concurrent support conversations and exchange replies with the admin team.
  2. **Top-Right Action Cluster (`Header.tsx`)**:
     - **Circular Theme Toggle Button (`.theme-toggle-btn`)**: Positioned directly in the topbar next to `Settings` (and next to `Connect MetaMask` when disconnected) for instant Dark/Light switching.
     - **Member-Gated `Settings` Button (`/settings`)**: Visible **strictly for MetaMask-connected members**, with readable active-hover contrast and properly padded sub-tab navigation. Hosts 3 sub-tabs: **Wallet & Membership** (on-chain RPC balance verification, verified payment progress, platform admission status), **Privacy & Security** (DM read receipts, online presence, enclave device vault shortcut), and **Blocked Accounts** (with one-click unblocking).
     - **`Connect MetaMask` / Minimal Account Pill**: Once connected, displays an **Account Pill** (initial badge, `@username`, `Paid Member` / `Member`) whose streamlined dropdown shows only the clickable profile header (`View & Edit Profile →`, opening permanent `user_id`, username editor, bio, and wallet/audit history) and `Disconnect Wallet` (with legacy Membership Status cards, Profile/Settings quick buttons, theme toggle, and network switcher removed).
  3. **Standalone Login-Gated Admin Console (`/Admin456`)**: Unlinked from the public header; renders strictly a login page (`AdminPortal.tsx`) until server-side credentials are verified.
- **Unified Channel Rail & Member-Gated `+Add` Control**:
  - **Open Chat** (default): Open public room with a **`PUBLIC`** header badge; both reading (`GET /public-chat/messages`) and posting (`POST /public-chat/messages`) require an authenticated Paid Member (`_require_paid_member_ctx`), with legacy guest settings and branches removed.
  - **`+Add` Dropdown (Member-Only)**: Visible strictly to connected MetaMask members. Clicking **`+Add`** displays two streamlined options:
    1. **Create Group**: Opens a modal to set the group name, description, privacy mode (`invite_only` vs `public`), entry fee / access thresholds, and add members. Bootstraps an RFC 9420 MLS TreeKEM encrypted room with pre-join and post-removal secrecy.
    2. **Chat Individual**: Opens a modal to enter an individual member's ID or `@username` to immediately initiate a forward-secret 1-to-1 Olm v2 Double Ratchet private chat.
- **Dual-Tier Presence Model: `Watching` vs. `Active Live` (Admins Excluded)**:
  - **`Watching`**: Displays the count of live non-connected visitors watching the Open Public Chat room (powered by `/ws/public-chat`).
  - **`Active Live`**: Displays the count of live non-admin connected MetaMask members active in the system (powered by `/ws/member-presence` & `/ws/e2ee`).
  - **Member-Gated Privacy & Admin Exclusion**: `Active Live` is strictly **hidden from non-connected visitors** and rendered only for MetaMask-connected members. **Administrators** (`superadmin`, `moderator`, `ADMIN_WALLET_ADDRESSES`) and users who disable `show_online_presence` are excluded from `active_live` counts and directory online indicators (`E2EERealtimeHub.is_user_online`).
- **Clean Open Chat Header & Paid-Member Gate**: Open Chat access requires a connected, platform-paid member (`_require_paid_member_ctx`); unpaid members receive an admission paywall prompt.
- **Responsive Layout**: Zero outer window scrollbar on laptop/desktop screens (`height: 100%; overflow: hidden` with internal pane scrolling); on tablet/mobile the channel rail becomes a slide-out drawer, and multi-column grids adapt with responsive `repeat(auto-fit, minmax(...))` rules.
- **Verified Member Posting**: Connected Paid Members post with verified `@username • VERIFIED` badges (clicking any verified `@username` launches a Private Chat).
- **Real-Time WebSocket Delivery**: Instant message broadcast, live edit/delete sync, and separated presence channels.
- **Smooth Animated Messaging & UI Enhancements**: Sent and received messages render with fluid entrance physics (`@keyframes chatMsgEntrance`), spring curves, optimistic send pulses with automatic message upgrade upon WebSocket/REST sync, sleek hover action clusters (copy, edit, delete), and smooth auto-scrolling (`scroll-behavior: smooth`).
- **Privacy Audit Assurances**: Verified zero device hardware fingerprinting (device IDs are random CSPRNG `dev_...` strings), zero client IP logging or database persistence, strict Permissions-Policy headers disabling camera/microphone/geolocation/payment/usb, and zero third-party telemetry.
- **Safety & Hygiene**: Cursor pagination (`before_seq`), 10-minute author edit window, author & moderator delete, malicious URI blocking (`javascript:`, `data:text/html`), duplicate burst suppression, and personal block-list filtering.

## 6. Private 1-to-1 Chat (Olm v2 Double Ratchet E2EE)
- **Direct Initiation & Directory**: Initiate 1-to-1 chats via the **`+Add` → Chat Individual** modal or search peers by `@username` (with verified badges) in the directory.
- **Vodozemac Olm v2 E2EE**: X25519 + Ed25519 3DH handshake + per-message Double Ratchet across multiple devices per user.
- **Infinite Cursor Pagination**: Automatic loop pagination (`after_seq`) ensures conversations scale past 60 messages with zero message invisibility or truncation.
- **Account and devices** (Settings > Privacy): username, sign-in wallets, signing out other devices, a **Recent activity** list (device signed out, private chats started fresh, wallet added / changed), and a "start private chats fresh" option for members who lost every device. No keys, safety numbers or other technical detail are shown to members.
- **Safe Lost-Identity Reset**: Identity reset requests verify signing wallet ownership server-side prior to execution, and local device keys are destroyed only after the server confirms the reset.
- **Privacy & Safety Controls**: Bidirectional `user_blocks` enforced on DM relay, prekey claims, and mutual group additions; opt-in DM Read Receipts (`CheckCheck`), opt-in online presence visibility, and client-submitted abuse reports.

## 7. Encrypted Group Chat (RFC 9420 MLS + Paid Group Access Policies)
- **IETF RFC 9420 MLS (`ts-mls`)**: TreeKEM group encryption with cryptographic **pre-join secrecy** (`epoch >= joined_epoch`), **post-removal secrecy** (TreeKEM path secret rotation on `Remove` Commit), self-key rotation (`Update` Commit), and optimistic epoch concurrency (`HTTP 409` catch-up).
- **Group Creation via `+Add`**: Creators configure group name, privacy mode (`invite_only` vs `public`), description, and initial members in one atomic transaction.
- **Paid Group Access Policies**: Groups can be designated as Paid Groups requiring an on-chain entry fee in ETH. The server verifies payments with `purpose: "group_entry"` before allowing MLS `Add` commits or message broadcasts.
- **Reply to a message (like WhatsApp / Instagram)**: In private chats and groups, the **Reply** button on any message starts a reply; a "Replying to @name" bar shows above the message box (Esc cancels). The reply shows the quoted message on top; tapping the quote jumps to the original. The quote travels inside the end-to-end encrypted message, so the server never sees it.
- **Notifications**: A bell in the header with an unread count and recent messages / group invitations (tap to open, "Mark all as read"), unread badges on each private chat and group, the unread count in the browser tab title, a small pop-up when a message arrives elsewhere in the app, an optional sound, and optional system notifications while Zyphra is in the background. Notifications show who wrote and where, never the message text. Unread counts come from the server, so they survive a reload and match across devices.
- **Accept / Reject Group Invitations (like Instagram)**: When a group admin adds someone, that person gets an invitation with **Accept** and **Reject** (in the Groups list and as a pop-up) instead of being added straight away. Until they accept they cannot see the group, its messages or its keys. Rejecting means they are never added. Admins see a **Waiting for reply** list with **Cancel invite**. People who asked to join (join request or invite link) are added directly when approved. The group creator is the group's admin, and Admin456 shows who created each group.
- **Invite Links, Discovery & Join Queue**: Group admins can mint expiring/max-use invite codes and share them as links (`https://<site>/?invite=CODE`, which opens Groups with the code filled in), see each invite's expiry/used-up state, review incoming join requests (with a live "Someone asked to join" alert), and **Approve & Add** or **Decline** each one. Paid groups reached through an invite open the group's payment window, then join with the same invite.
- **Role Management & Leave Group**: Owner/Admin/Member roles plus self-service **Leave Group** with automated device cleanup and pending welcome purges.

## 8. Encrypted File Attachments & Non-Extractable Device Vault
- **Removing a sent file**: the sender can remove a file they sent (trash icon next to it); the message stays, the encrypted blob is deleted and others see "removed by the sender".
- **Automatic key top-up**: every 10 minutes the app checks this device's one-time prekeys and MLS KeyPackages (`GET /api/e2ee/devices/{id}/prekey-count`) and uploads more when low.
- **Encrypted Attachments**: Client-side `AES-256-GCM` per-file encryption + `SHA-256` ciphertext integrity verification (`e2eeAttachmentCrypto.ts`) with a 14 MB payload ceiling; decryption keys travel exclusively inside Olm/MLS ciphertexts.
- **Hardened Local Key Storage**: Non-extractable WebCrypto `AES-256-GCM` master key in IndexedDB (`e2eeVault.ts`) protecting pickled keys, sessions, and cached envelopes at rest. Inflight mutex serialization prevents master key initialization races across tabs.
- **Complete Vault Cleanup**: Vault wipe purges decrypted message caches, trust records, and device bundles without leaving orphaned records.

## 9. RBAC Administrative Console & Audit Logging
- **Dedicated Login Page (`/Admin456`)**: The console is not linked from the app. It shows only a login form until the server validates `ADMIN_LOGIN_ID` / `ADMIN_LOGIN_PASSWORD` (backend `.env` only, never in the frontend bundle). Hardening: constant-time comparison, generic error messages, global login slowdown (every failed attempt waits longer, up to 8 s; no IP or other visitor data is read and there is no lockout), random 256-bit server-side sessions with idle (30 min) and absolute (4 h) expiry, logout revocation, parameterized SQL everywhere, and `noindex`.
- **Automatic 5-Second Live Polling**: The dashboard automatically refreshes every 5 seconds while visible (`visibilitychange`-aware), replacing manual Refresh controls.
- **Role-Based Access**: Supports `superadmin` and `moderator` roles via `ADMIN_WALLET_ADDRESSES`, runtime role assignment, or an optional break-glass `ADMIN_TOKEN` (ignored unless at least 24 characters).
- **Operational Administrative Tabs (8 Tabs)**:
  1. **Overview**: Real-time platform metrics (`Total Accounts`, `Active SIWE Sessions`, `Encrypted Groups`, `Open Public Messages`, `E2EE DM Envelopes`, `E2EE Group Envelopes`, `Open Abuse Reports`, `Online Right Now`) with safe `0` fallbacks.
  2. **Users & Wallets**: Fast single-query user listing (`admin_list_users`) with debounced search and instant client-side filtering, full JSON wallet/username/balance/payment inspection, mute (`N` hours), suspend, restore, or assign admin roles.
  3. **Groups & Policies**: Inspect encrypted group metadata (never plaintext), tag groups as Paid Groups, configure custom entry fees in USD (`entry_fee_usd`), and adjust visibility.
  4. **Moderation & Reports**: Review abuse reports and record resolution/dismissal actions.
  5. **Support Inbox (`AdminSupportInbox.tsx`)**: View open/closed member support conversations, reply directly (pushing real-time `support_reply` alerts), and close or reopen threads.
  6. **Platform Settings**: Configure **`Username change Hrs`** (`username_cooldown_hours`), old-username reservation days (`username_reservation_days`), Members' room longest message (`public_chat_max_length`), edit window (`public_chat_edit_window_seconds`, entered in minutes) and retention days (`public_chat_retention_days`), switch **Active Ethereum Network** via the segmented pill toggle (`Ethereum Mainnet (1)` using `RPC_URL_MAINNET` vs `Sepolia Testnet (11155111)` using `RPC_URL_SEPOLIA`), set USD membership fee (`platform_entry_fee_usd`), toggle live ETH/USD pricing (`use_live_eth_price`) or fallback rate (`eth_usd_price`), and set authorized treasury destination (`authorized_payment_destination`). Legacy Open Chat guest toggles have been removed.
  7. **Audit Logs**: Immutable chronological trail (`audit_logs`) tracking administrative actions, treasury destination modifications, payment verification/rejections, support replies/status updates, and moderation events. Sensitive cryptographic keys and private transaction data are never logged.

## 10. "Talk to Admin" Support & Connection Resilience
- **Member Support Threads (`/support`)**: Any authenticated user (paid or unpaid, so payment issues can always be reported) can start support conversations (`POST /api/platform/support/threads`, capped at `5` open threads per user), exchange replies, and track unread admin responses from the header badge; user replies automatically reopen closed threads.
- **Cold-Start & Stale-Connection Recovery (`resilientFetch.ts`)**: Safe `GET`/`HEAD`/`OPTIONS` requests automatically retry transient `500`/`502`/`503`/`504` and network errors with jittered exponential backoff (`onWake` reconnects WebSockets on online/tab focus), while non-idempotent writes (`POST`/`PUT`/`PATCH`/`DELETE`) are never auto-retried to prevent duplicate sends.

## 11. Chat features (Nov 2026)
- **Reactions, edit (15 min), delete for everyone (48 h; group admins any time)** in private chats, groups and the Members' room. In encrypted chats reactions and edits are encrypted events applied on each device.
- **Typing indicator**, respecting "show my online status". **@mentions** with suggestions and a "mentioned you" notice.
- **Polls** in groups (encrypted votes), **pinned messages** (up to 3), **search in a chat** (on the device), **mute / archive**, **disappearing messages** (24 h / 7 days / 90 days), **announcement groups** (only admins post).
- **Renewal reminders** (banner + bell at 7 days, 1 day and on expiry) and an **admin banner for everyone**.
- **Invite links were removed**: a group admin adds people and they Accept or Reject; public groups take join requests.
