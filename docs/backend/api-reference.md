# Backend API Specification & Reference

Base Local URL: `http://localhost:10000/api`  
WebSocket Endpoints:
- `ws://localhost:10000/ws/e2ee` (Encrypted DM & MLS notification stream)
- `ws://localhost:10000/ws/public-chat` (Open Public Chat feed & `Watching` viewer count)
- `ws://localhost:10000/ws/member-presence` (Connected member heartbeat & `Active Live` counter)

---

## 1. System & Health

### `GET /api/health`
Returns service health (`status: "healthy"`), `timestamp`, `service`, `storage` (`postgresql` or `sqlite_fallback`), and cached Ethereum RPC network status (`_RPC_HEALTH_TTL_SECS = 30.0`). Passing `?deep=1` also runs `chat_db.ping_pg_health()` (`database: "ok" | "unavailable"`) to wake a suspended Neon compute and refresh pooled connections on initial app load.

---

## 2. SIWE Authentication, Permanent Identity & E2EE Relay (`/api/e2ee/*`)

| Method & Path | Auth | Purpose |
| :--- | :---: | :--- |
| `POST /api/e2ee/auth/challenge` | Public / Session | Generates a single-use, domain-bound EIP-4361 (SIWE) challenge (`login`, `link_wallet`, or `reset_lost_identity`). For `reset_lost_identity`, validates that the requested wallet is an active linked wallet of the user. Rate-limited by client IP. |
| `POST /api/e2ee/auth/verify` | Public | Verifies EIP-191 wallet signature, creates/resolves permanent `user_id`, and sets cookie `zyphra_session` (`SameSite=None; Secure` on HTTPS). Supports safe re-activation of previously revoked wallets via `ON CONFLICT DO UPDATE`. |
| `POST /api/e2ee/auth/logout` | Session | Revokes active session token in `chat_auth_sessions` and clears `zyphra_session` cookie. |
| `GET /api/e2ee/me` | Session | Returns permanent `user_id`, `@username`, `is_platform_paid`, linked wallets, devices, privacy flags, and `admin_role`. |
| `PATCH /api/e2ee/account/username` | Session | Updates `@username` (enforcing case-insensitive uniqueness, configurable `username_cooldown_hours` / `Username change Hrs`, and old-username reservation quarantine) and records `username_history`. |
| `GET /api/e2ee/account/username/check` | Public / Session | Checks real-time availability of a candidate `@username` query param (`available`, `is_current`, `reason`) validating format, active database claims, and 30-day quarantine status. |
| `POST /api/e2ee/account/wallets/link` | Session | Links an additional wallet or replaces primary wallet (`revoke_previous_wallets`), logs `wallet_change_history`, revokes old wallet sessions, and issues a fresh session token. |
| `POST /api/e2ee/devices/register` | Session | Verifies 64-byte Ed25519 device bundle signature (`zyphra-e2ee-device-v1\|...`) and stores Curve25519 identity + OTKs + signed fallback key. |
| `POST /api/e2ee/devices/{device_id}/prekeys` | Session | Uploads replenished One-Time Prekeys and/or rotated signed fallback key. |
| `POST /api/e2ee/devices/{device_id}/revoke` | Session | Revokes a device, marks active group memberships removed, deletes unconsumed prekeys and pending MLS welcomes, and emits `device_revoked`. |
| `POST /api/e2ee/identity/reset` | Session | Executes authenticated lost-all-devices reset (`confirm_irrecoverable_history=true`). Validates signing wallet ownership, increments `identity_version`, purges old device keys, and registers the replacement device bundle. |
| `GET /api/e2ee/users/resolve/{identifier}` | Session | Resolves `user_id`, `@username`, or `0x...` wallet address to permanent account + active device public bundles. |
| `POST /api/e2ee/prekeys/claim` | Session | Atomically claims one unconsumed OTK per active device of a peer (rejects if caller and target are mutually blocked). |
| `POST /api/e2ee/dm/messages` | Session | Relays zero-plaintext Olm v2 multi-device DM ciphertexts (enforcing `user_blocks` and account suspension checks). |
| `GET /api/e2ee/dm/conversations` | Session | Lists active DM conversation summaries for the authenticated `user_id`. |
| `GET /api/e2ee/dm/messages` | Session | Fetches DM ciphertexts for a `peer_user_id` supporting `after_seq` and `limit` (default 100) for infinite cursor pagination. |
| `POST /api/e2ee/mls/key-packages` | Session | Uploads RFC 9420 MLS `KeyPackage`s for a registered device. |
| `POST /api/e2ee/mls/key-packages/claim` | Session | Atomically claims one MLS `KeyPackage` per active device of an invited user (rejects if blocked). |
| `POST /api/e2ee/groups` | Session | Creates an RFC 9420 MLS encrypted group (`epoch = 0`) with `description`, `visibility`, `is_paid`/`entry_fee_usd`, and `min_eth_balance_wei`. |
| `GET /api/e2ee/groups` | Session | Lists MLS groups where `user_id` has active membership, including access policy metadata. |
| `POST /api/e2ee/groups/{group_id}/commits` | Session | Submits an atomic MLS Commit. For member additions or removals, strictly enforces `is_group_admin`, verifies committer device is active, validates active device ownership for added members, and checks non-blocked status. Returns `HTTP 409` on stale epoch. |
| `GET /api/e2ee/groups/{group_id}/sync` | Session | Retrieves ordered MLS Commits (`after_epoch`) and pending `Welcome` envelopes for an active device. |
| `POST /api/e2ee/groups/{group_id}/welcomes/{welcome_id}/ack` | Session | Acknowledges receipt of a pending MLS welcome, returning `{"success": true, "acknowledged": true, "consumed": true}`. |
| `POST /api/e2ee/groups/{group_id}/messages` | Session | Relays an MLS `PrivateMessage` ciphertext (enforcing active device status, membership, and Paid / ETH group access policy). The `group_ciphertext` realtime event includes `sender_user_id`. |
| `GET /api/e2ee/groups/{group_id}/messages` | Session | Returns MLS group ciphertexts strictly for `epoch >= joined_epoch` (pre-join secrecy) with `after_seq` and `limit` support. |
| `POST /api/e2ee/attachments` | Session | Uploads `AES-256-GCM` ciphertext blob (up to 14 MB) after constant-time `SHA-256` digest verification and scope authorization. |
| `GET /api/e2ee/attachments/{id}` | Session | Downloads authorized attachment ciphertext (`410 Gone` if revoked, `403` if unauthorized/blocked). |
| `POST /api/e2ee/attachments/{id}/revoke` | Session | Marks an uploaded encrypted attachment revoked. |

---

## 3. Platform Features, Admission Pricing, Paid Groups, Verified Payments & RBAC Admin (`/api/platform/*`)

| Method & Path | Auth | Purpose |
| :--- | :---: | :--- |
| `GET /api/platform/pricing` | Public | Returns public platform admission pricing: `platform_entry_fee_usd`, `platform_entry_fee_eth`, `platform_entry_fee_wei`, `eth_usd_price`, `rate_source` (`live` / `live_cached` / `live_stale` / `admin_fixed`), `use_live_eth_price`, `authorized_payment_destination`, `allowed_payment_chain_ids`, and `quoted_at`. |
| `GET /api/platform/membership/status` | Session | Returns caller's platform membership status: `{ user_id, wallet_address, is_platform_paid, platform_paid_at, platform_paid_until, platform_period, membership_is_free, total_verified_wei, total_verified_eth, group_subscriptions, pricing }`. |
| `GET /api/platform/groups/{group_id}/pricing` | Optional / Session | Returns group admission pricing: `{ group_id, name, is_paid, entry_fee_eth, entry_fee_wei, entry_fee_usd, eth_usd_price, rate_source, has_paid, authorized_payment_destination, allowed_payment_chain_ids }`. |
| `PUT /api/platform/admin/pricing` | Superadmin | Updates USD admission fee (`platform_entry_fee_usd`), live price toggle (`use_live_eth_price`), fallback/fixed ETH/USD rate (`eth_usd_price`), legacy ETH fee (`platform_entry_fee_eth`), and/or `authorized_payment_destination`. Records audit log with actor, timestamp, previous value, and new value. |
| `POST /api/platform/payments/verify` | Session | Submits an on-chain transaction reference (`transaction_reference`, `purpose` e.g. `platform_entry` or `group_entry`, optional `group_id`). Verifies on-chain: receipt status == 1, sender matches user's wallet, recipient matches `authorized_payment_destination`, chain is allowed, and transaction is unique (never counted twice). Marks `is_platform_paid = True` on platform entry. |
| `GET /api/platform/payments/history` | Session | Returns user's authoritative payment history (`payment_records`) and total verified payment amount. |
| `POST /api/platform/wallet/verify-balance` | Session | Triggers server-side Ethereum RPC balance verification (`RPC_URL_MAINNET` / `RPC_URL_SEPOLIA` per `default_balance_chain_id`) for the authenticated user's wallet. |
| `GET /api/platform/public-chat/messages` | Paid Member | Lists Open Public Chat messages (`before_seq` cursor pagination, filtered by caller's block list) + online viewer metrics and room policy (`policy`: `retention_days`, `edit_window_minutes`, `max_message_chars`; `_require_paid_member_ctx`; returns `"guest_read_enabled": false`, `"guest_posting_enabled": false`). |
| `POST /api/platform/public-chat/messages` | Paid Member | Posts to Open Public Chat as verified `@username • VERIFIED` (`_require_paid_member_ctx`; legacy guest posting removed). |
| `PATCH /api/platform/public-chat/messages/{message_id}` | Session | Edits caller's own public message within the 10-minute edit window (rejects if account is muted). |
| `DELETE /api/platform/public-chat/messages/{message_id}` | Session / Admin | Soft-deletes a public message (author or `moderator`/`superadmin`; supports `/Admin456` session token via `X-Admin-Token`) and broadcasts removal over `/ws/public-chat`. |
| `PATCH /api/platform/profile` | Session | Updates `bio`, `show_online_presence`, and `send_read_receipts` (Display Name removed to eliminate impersonation). |
| `GET /api/platform/profile/history` | Session | Returns caller's `username_history`, `wallets`, `wallet_history` (`old_wallet_address` / `new_wallet_address`), `balance_snapshots`, and `payment_records`. |
| `GET /api/platform/users/search` | Public / Session | Case-insensitive `@username` directory search (`q`, `limit`) respecting `show_online_presence` (and always reporting Admins as offline). Anonymous searches are rate-limited per client IP. |
| `GET /api/platform/blocks` | Session | Lists users blocked by the caller, returning detailed `{ blocked_user_id, username, reason, created_at }` records for one-click unblocking. |
| `POST /api/platform/blocks` & `DELETE .../blocks/{target_user_id}` | Session | Blocks or unblocks a `user_id` (enforced across DMs, prekey claims, group commits, and Open Chat). |
| `POST /api/platform/dm/read-receipt` & `GET .../dm/read-receipts/{peer_user_id}` | Session | Records or retrieves opt-in DM read receipt watermarks (`last_read_seq`). Rejects if caller and peer are mutually blocked. |
| `GET /api/platform/groups/discover` | Optional | Lists discoverable encrypted groups with member counts, paid group status (`is_paid`, `entry_fee_eth`), and whether caller has paid. |
| `GET /api/platform/groups/{group_id}/policy` & `PUT ...` | Session / Admin | Reads or updates group policy including `is_paid`, `entry_fee_eth`, `visibility`, `min_eth_balance_wei`, and `description` (accepts `/Admin456` session token). |
| `POST /api/platform/groups/{group_id}/invites`, `GET ...` & `DELETE .../{invite_code}` | Group Admin | Creates, lists, or revokes expiring / max-use group invite codes. |
| `POST /api/platform/groups/join-by-invite/{invite_code}` | Session | Validates invite code + Paid/ETH eligibility and queues join request for MLS `Welcome` onboarding. |
| `POST /api/platform/groups/{group_id}/join-request` | Session | Submits a join request for a `public` group (verifies Paid/ETH eligibility and `require_invitation` policy). |
| `GET /api/platform/groups/{group_id}/join-requests` | Group Admin | Lists pending join requests with applicant public device status for 1-click MLS `Approve & Add`. |
| `POST /api/platform/groups/{group_id}/leave` | Session | Self-service **Leave Group** for active group members, cleanly purging unconsumed welcomes. |
| `POST /api/platform/groups/{group_id}/members/{target_user_id}/role` | Group Admin | Promotes/demotes group members (`admin` / `member`). |
| `POST /api/platform/reports` | Session | Submits an abuse report (`public_chat`, `dm`, `group`, or `user` scope). |
| `POST /api/platform/admin/login` | Public (Slowdown-Guarded) | Authenticates `/Admin456` console login (`login_id`, `password`, `extra="forbid"`) against server-only `ADMIN_LOGIN_ID` / `ADMIN_LOGIN_PASSWORD`; returns `{ token, expires_in_seconds, idle_timeout_seconds }` (`401` invalid credentials, `429` locked out, `503` unconfigured). Failed attempts slow every later attempt (up to 8 s); no IP is read and nobody is locked out. |
| `GET /api/platform/admin/session` | `X-Admin-Token` | Validates an active `/Admin456` session token and refreshes its 30-minute idle timer (`401` if invalid/expired). |
| `POST /api/platform/admin/logout` | `X-Admin-Token` | Immediately revokes the `/Admin456` session token in server memory. |
| `GET /api/platform/admin/overview` | Mod / Admin | Returns aggregate platform health, RPC network status, and activity counters (accepts `/Admin456` `X-Admin-Token`, RBAC wallet session, or `>= 24`-char `ADMIN_TOKEN`). |
| `GET /api/platform/admin/users` & `.../{target_user_id}/inspect` | Mod / Admin | Single-query user search (`admin_list_users`) and detailed account inspection (wallet/username/balance/payment/device history). |
| `POST /api/platform/admin/users/{target_user_id}/verify-balance` | Mod / Admin | Triggers server-side Ethereum RPC balance verification for a user's primary wallet (using `default_balance_chain_id` if omitted). |
| `POST /api/platform/admin/users/{target_user_id}/moderate` | Mod / Admin | Mutes (`duration_hours`), suspends, or restores an account and writes `moderation_actions` + `audit_logs`. Automatic expiration unblocks expired actions. |
| `POST /api/platform/admin/users/{target_user_id}/role` | Superadmin | Grants or revokes `superadmin` / `moderator` RBAC roles. |
| `GET /api/platform/admin/access-grants` | Mod / Admin | Members given free access. Filters: `scope_type`, `group_id`, `user_id`, `include_inactive`, `limit`. Each row has the member's `username`, the `group_name`, `granted_by`, `note`, `expires_at`, `lifetime`, `revoked_at`, `active`. |
| `POST /api/platform/admin/access-grants` | Superadmin | Free access without payment. Body `{user_id, scope_type: "platform"\|"group", group_id?, days: 1..3650 \| null, note?}`; `days: null` = no end date. Granting again replaces the old grant. Audited (`access_granted`); sends `access_changed` to the member. |
| `POST /api/platform/admin/access-grants/revoke` | Superadmin | Body `{user_id, scope_type, group_id?}`. Switches the grant off at once (404 when nothing is active). Audited (`access_revoked`). |
| `GET /api/platform/admin/groups` & `PUT /api/platform/groups/{group_id}/policy` | Mod / Admin | Audits group metadata and updates group access policies. |
| `GET /api/platform/admin/reports` & `POST .../{report_id}/resolve` | Mod / Admin | Reviews and resolves/dismisses abuse reports. |
| `GET /api/platform/admin/settings` & `PUT ...` | Mod / Superadmin | Reads and updates live `platform_settings` (`username_cooldown_hours` / `Username change Hrs`, `default_balance_chain_id` for Mainnet `1` vs Sepolia `11155111`, etc.). Legacy guest Open Chat flags removed. |
| `GET /api/platform/admin/audit-logs` | Mod / Admin | Queries immutable chronological `audit_logs` (`payment_verified`, `payment_rejected`, `verification_failure`, `support_reply`, `support_status`, pricing & destination updates, moderation events). |
| `POST /api/platform/support/threads` | Session (Paid or Unpaid) | Opens a "Talk to admin" support conversation (`subject`, `message`; rate-limited, max `5` open threads per user). |
| `GET /api/platform/support/threads` & `GET .../support/unread` | Session (Paid or Unpaid) | Lists caller's support threads (`threads`, `unread_total`) or returns unread admin reply count (`unread_total`). |
| `GET /api/platform/support/threads/{thread_id}` & `POST .../messages` | Session (Paid or Unpaid) | Loads thread messages (marks `user_unread = 0`) or posts a user reply (automatically reopens a closed thread). Returns `404` for missing or non-owned thread IDs. |
| `GET /api/platform/admin/support/threads` & `GET .../admin/support/threads/{thread_id}` | Mod / Admin | Lists support inbox (optional `?status=open|closed`) with caller metadata (`user_id`, `username`, `wallet_address`) and `unread_total`, or loads a thread (clears `admin_unread`). |
| `POST /api/platform/admin/support/threads/{thread_id}/reply` & `POST .../status` | Mod / Admin | Sends an admin reply (logs `support_reply` audit entry and pushes `support_reply` over `/ws/e2ee`) or sets thread status (`open` / `closed`, logging `support_status`). |

---

## 4. Real-Time WebSockets Architecture

### `ws://localhost:10000/ws/public-chat`
- **Authentication**: Public (anonymous or connected).
- **Function**: Streams real-time messages, edits, and deletions in the Open Public Chat room. Broadcasts live `watching` viewer count changes. Broadcasts `public_policy_updated` (with updated `policy` object containing `retention_days`, `edit_window_minutes`, `max_message_chars`) immediately whenever an administrator saves platform settings in `/Admin456`.
- **Client Inbound Actions**: Optional heartbeat ping; incoming chat broadcast subscription.

### `ws://localhost:10000/ws/member-presence`
- **Authentication**: Connected MetaMask wallet address (`?wallet=0x...` or initial `{ type: "init", wallet_address: "0x..." }`).
- **Function**: Tracks connected MetaMask members active in the system. Maintains the `Active Live` presence counter, filtering users who have disabled `show_online_presence` and **always excluding Administrators** (`superadmin`, `moderator`, `ADMIN_WALLET_ADDRESSES`).
- **Client Inbound Actions**: `{ type: "ping" }`, `{ type: "update_wallet", wallet_address: "0x..." }`.

### `ws://localhost:10000/ws/e2ee`
- **Authentication**: Authenticated user session (`zyphra_session` cookie or first-frame `{ type: "auth", token }`).
- **Function**: Real-time push delivery of incoming Olm v2 DM ciphertexts, RFC 9420 MLS group Commits, pending MLS Welcomes, device revocations, identity trust alerts, and `support_reply` nudges. Enforces immediate disconnect if the account is suspended by moderation.

---

## 5. Subscriptions: monthly & yearly billing

Platform membership and every paid group are **subscriptions**. A member chooses a plan when paying:

| Plan | Access added | Price |
| :--- | :---: | :--- |
| `monthly` | 30 days | `platform_entry_fee_usd` (membership) / `entry_fee_usd` (group), set by the admin in USD |
| `yearly` | 365 days | `platform_yearly_fee_usd` / `entry_fee_yearly_usd`; **0 = automatic, 12 x monthly** |

- `GET /api/platform/pricing` and `GET /api/platform/groups/{id}/pricing` return `plans: { monthly: {usd, eth, wei, days}, yearly: {...} }`. (The older `*_fee_usd/eth/wei` keys describe the monthly plan.)
- `POST /api/platform/payments/verify` takes `billing_period` (`monthly` | `yearly`, default `monthly`). The paid amount must cover that plan (minus the ETH-price tolerance). The response includes `subscription: { paid_until, last_period, active }`.
- Paying again **adds** time on top of what is left; after expiry it starts from the payment time.
- `GET /api/platform/membership/status` returns `platform_paid_until`, `platform_period`, `membership_is_free`, `total_verified_wei`, `total_verified_eth`, and `group_subscriptions[]`.
- When a subscription expires the API answers **402** (platform routes, paid-group send/read). Joining a paid group needs an active group subscription. Platform/group admins are exempt.
- Existing payers were given 30 days to renew by the one-time migration `010_subscription_grandfather.sql`.
- PostgreSQL: text settings (the payout address) are read correctly now; they used to read as empty, so verification always failed closed. `audit_logs.entity_id` is now `VARCHAR(128)` (migration 015) so audit entries keyed by a transaction hash no longer fail.
- A paid-group refusal on **send** is now a 402 with `detail: {code: "group_payment_required", group_id, group_name, message}` (it was a 403), like read and Accept.

## 6. Free access granted by an admin

A superadmin can let a member in without paying (table `access_grants`, migration `014_access_grants.sql`).

- `scope_type: "platform"` opens the membership. `scope_type: "group"` opens one group: its fee **and** its minimum-balance rule are waived for that member, and the member may send a join request even if the group is invite-only. A suspended account is always blocked.
- A group grant does not include the membership, and a membership grant does not pay for groups.
- Grants are separate from `member_subscriptions`, so they never count as paid members, never create payment records, and the admin's `note` is never shown to the member.
- Revoking takes effect immediately (the server clears its short "paid" cache). With several server processes, others notice within `AUTH_CACHE_TTL_SEC` (30 s).
- `GET /api/platform/membership/status` adds `platform_free_access: {expires_at, lifetime} | null` and `group_free_access: [{group_id, group_name, expires_at, lifetime}]`.
- Encrypted groups: the server cannot add anyone to an encrypted group. A grant removes the payment and balance obstacles; a group admin then adds the member from the app, and the member accepts the invitation as usual. Deleting a group deletes its grants.
- The admin payment **retry** now enforces the amount stored on the payment record (it used to credit any amount).

## 7. Chat features (Nov 2026)

End-to-end encrypted chats: reactions (`kind: "reaction"`), edits (`"edit"`) and poll votes (`"poll_vote"`) are encrypted envelopes pointing at `target_id`, sent with `event_kind: "control"` so the server never counts or notifies them. A poll is a normal message whose envelope has `poll: {question, options[2..10], multi}`. The rules (one reaction per person, author-only edits within 15 min, latest vote wins) are applied on every device (`frontend/src/services/chatEvents.ts`).

| Endpoint | Who | What |
|---|---|---|
| `POST /api/e2ee/dm/messages` / `POST /api/e2ee/groups/{gid}/messages` | Member | New optional fields: `event_kind` (`message` \| `control`), groups also `mention_user_ids` (active members only; they get a `mention` event). Announcement groups: a non-admin `message` gets 403 `{code: "admins_only"}`; `control` is allowed. Responses carry `expires_at` when a timer is on. |
| `GET` message lists | Member | Records carry `event_kind`, `deleted`, `expires_at` (DMs also `expired`). Deleted group messages have an empty ciphertext; expired group messages are omitted. Deleted / expired private messages keep only an undelivered session-setup (type 0) copy for that device. |
| `POST /api/e2ee/dm/messages/{id}/delete` | Sender, 48 h | Delete for everyone; removes the stored copies (except session-setup copies, see above). Event `message_deleted`. |
| `POST /api/e2ee/groups/{gid}/messages/{id}/delete` | Sender 48 h, or group admin | Delete for everyone; the ciphertext is removed. |
| `POST /api/e2ee/typing` | Member | `{scope_type: dm\|group, peer_user_id\|group_id}` -> `typing` event to the others; `sent: false` when the sender hides their online status. |
| `GET /api/e2ee/conversations/state` | Member of the chat | `pins`, `disappearing_ttl`, `admins_only`, `can_manage`, my `pref`. |
| `POST /api/e2ee/pins` | Group admin / either DM person | `{..., message_id, pinned}`; max 3, a 4th replaces the oldest (`replaced`). |
| `POST /api/e2ee/disappearing` | Group admin / either DM person | `ttl_seconds` 0, 86400, 604800 or 7776000. Applies to new messages; the server purges expired copies. |
| `POST /api/e2ee/groups/{gid}/settings` | Group admin | `{admins_only_posting}` (announcement group). |
| `GET\|POST /api/e2ee/conversation-prefs` | Member | Mute (`off`, `8h`, `1w`, `always`) and `archived` per `dm:<peer>`, `group:<gid>`, `room`. |
| `POST /api/platform/public-chat/messages/{id}/reaction` | Member | `{emoji \| null}`; one per member. Feed messages carry `reactions: {emoji: [user_id]}`; event `public_reactions_updated`. |
| `POST /api/platform/public-chat/typing` | Member | Event `public_typing`. |
| `POST /api/platform/public-chat/pins` | Moderator / admin | Feed carries `pins`; event `public_pins_updated`. Room `@username` mentions send a `mention` event. |
| `GET /api/platform/announcement` | Anyone | The admin banner or `null` (settings `announcement_text`, `announcement_level`, `announcement_ends_at`). |
| `GET /api/platform/reminders` | Signed in | Access ending within 7 days (`7d`), a day (`1d`) or ended in the last 14 days (`expired`), with a `key` per stage. |
| Invite links (`/groups/{gid}/invites*`, `/groups/join-by-invite/{code}`) | — | **410 Gone**: removed. Admins add people, who Accept or Reject. |
