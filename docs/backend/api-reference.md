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
| `POST /api/e2ee/groups/{group_id}/messages` | Session | Relays an MLS `PrivateMessage` ciphertext (enforcing active device status, membership, and Paid / ETH group access policy). |
| `GET /api/e2ee/groups/{group_id}/messages` | Session | Returns MLS group ciphertexts strictly for `epoch >= joined_epoch` (pre-join secrecy) with `after_seq` and `limit` support. |
| `POST /api/e2ee/attachments` | Session | Uploads `AES-256-GCM` ciphertext blob (up to 14 MB) after constant-time `SHA-256` digest verification and scope authorization. |
| `GET /api/e2ee/attachments/{id}` | Session | Downloads authorized attachment ciphertext (`410 Gone` if revoked, `403` if unauthorized/blocked). |
| `POST /api/e2ee/attachments/{id}/revoke` | Session | Marks an uploaded encrypted attachment revoked. |

---

## 3. Platform Features, Admission Pricing, Paid Groups, Verified Payments & RBAC Admin (`/api/platform/*`)

| Method & Path | Auth | Purpose |
| :--- | :---: | :--- |
| `GET /api/platform/pricing` | Public | Returns public platform admission pricing: `platform_entry_fee_usd`, `platform_entry_fee_eth`, `platform_entry_fee_wei`, `eth_usd_price`, `rate_source` (`live` / `live_cached` / `live_stale` / `admin_fixed`), `use_live_eth_price`, `authorized_payment_destination`, `allowed_payment_chain_ids`, and `quoted_at`. |
| `GET /api/platform/membership/status` | Session | Returns caller's platform membership status: `{ user_id, wallet_address, is_platform_paid, platform_paid_at, pricing }`. |
| `GET /api/platform/groups/{group_id}/pricing` | Optional / Session | Returns group admission pricing: `{ group_id, name, is_paid, entry_fee_eth, entry_fee_wei, entry_fee_usd, eth_usd_price, rate_source, has_paid, authorized_payment_destination, allowed_payment_chain_ids }`. |
| `PUT /api/platform/admin/pricing` | Superadmin | Updates USD admission fee (`platform_entry_fee_usd`), live price toggle (`use_live_eth_price`), fallback/fixed ETH/USD rate (`eth_usd_price`), legacy ETH fee (`platform_entry_fee_eth`), and/or `authorized_payment_destination`. Records audit log with actor, timestamp, previous value, and new value. |
| `POST /api/platform/payments/verify` | Session | Submits an on-chain transaction reference (`transaction_reference`, `purpose` e.g. `platform_entry` or `group_entry`, optional `group_id`). Verifies on-chain: receipt status == 1, sender matches user's wallet, recipient matches `authorized_payment_destination`, chain is allowed, and transaction is unique (never counted twice). Marks `is_platform_paid = True` on platform entry. |
| `GET /api/platform/payments/history` | Session | Returns user's authoritative payment history (`payment_records`) and total verified payment amount. |
| `POST /api/platform/wallet/verify-balance` | Session | Triggers server-side Ethereum RPC balance verification (`RPC_URL_MAINNET` / `RPC_URL_SEPOLIA` per `default_balance_chain_id`) for the authenticated user's wallet. |
| `GET /api/platform/public-chat/messages` | Paid Member | Lists Open Public Chat messages (`before_seq` cursor pagination, filtered by caller's block list) + online viewer metrics (`_require_paid_member_ctx`; returns `"guest_read_enabled": false`, `"guest_posting_enabled": false`). |
| `POST /api/platform/public-chat/messages` | Paid Member | Posts to Open Public Chat as verified `@username • VERIFIED` (`_require_paid_member_ctx`; legacy guest posting removed). |
| `PATCH /api/platform/public-chat/messages/{message_id}` | Session | Edits caller's own public message within the 10-minute edit window (rejects if account is muted). |
| `DELETE /api/platform/public-chat/messages/{message_id}` | Session / Admin | Soft-deletes a public message (author or `moderator`/`superadmin`; supports `/Admin456` session token via `X-Admin-Token`) and broadcasts removal over `/ws/public-chat`. |
| `PATCH /api/platform/profile` | Session | Updates `bio`, `avatar_url`, `show_online_presence`, and `send_read_receipts` (Display Name removed to eliminate impersonation). |
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
| `POST /api/platform/admin/login` | Public (Lockout-Guarded) | Authenticates `/Admin456` console login (`login_id`, `password`, `extra="forbid"`) against server-only `ADMIN_LOGIN_ID` / `ADMIN_LOGIN_PASSWORD`; returns `{ token, expires_in_seconds, idle_timeout_seconds }` (`401` invalid credentials, `429` locked out, `503` unconfigured). Memory table cleans up expired failures using `IP_FAILURE_WINDOW_SEC` without resetting active lockouts. |
| `GET /api/platform/admin/session` | `X-Admin-Token` | Validates an active `/Admin456` session token and refreshes its 30-minute idle timer (`401` if invalid/expired). |
| `POST /api/platform/admin/logout` | `X-Admin-Token` | Immediately revokes the `/Admin456` session token in server memory. |
| `GET /api/platform/admin/overview` | Mod / Admin | Returns aggregate platform health, RPC network status, and activity counters (accepts `/Admin456` `X-Admin-Token`, RBAC wallet session, or `>= 24`-char `ADMIN_TOKEN`). |
| `GET /api/platform/admin/users` & `.../{target_user_id}/inspect` | Mod / Admin | Single-query user search (`admin_list_users`) and detailed account inspection (wallet/username/balance/payment/device history). |
| `POST /api/platform/admin/users/{target_user_id}/verify-balance` | Mod / Admin | Triggers server-side Ethereum RPC balance verification for a user's primary wallet (using `default_balance_chain_id` if omitted). |
| `POST /api/platform/admin/users/{target_user_id}/moderate` | Mod / Admin | Mutes (`duration_hours`), suspends, or restores an account and writes `moderation_actions` + `audit_logs`. Automatic expiration unblocks expired actions. |
| `POST /api/platform/admin/users/{target_user_id}/role` | Superadmin | Grants or revokes `superadmin` / `moderator` RBAC roles. |
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
- **Function**: Streams real-time messages, edits, and deletions in the Open Public Chat room. Broadcasts live `watching` viewer count changes.
- **Client Inbound Actions**: Optional heartbeat ping; incoming chat broadcast subscription.

### `ws://localhost:10000/ws/member-presence`
- **Authentication**: Connected MetaMask wallet address (`?wallet=0x...` or initial `{ type: "init", wallet_address: "0x..." }`).
- **Function**: Tracks connected MetaMask members active in the system. Maintains the `Active Live` presence counter, filtering users who have disabled `show_online_presence` and **always excluding Administrators** (`superadmin`, `moderator`, `ADMIN_WALLET_ADDRESSES`).
- **Client Inbound Actions**: `{ type: "ping" }`, `{ type: "update_wallet", wallet_address: "0x..." }`.

### `ws://localhost:10000/ws/e2ee`
- **Authentication**: Authenticated user session (`zyphra_session` cookie or first-frame `{ type: "auth", token }`).
- **Function**: Real-time push delivery of incoming Olm v2 DM ciphertexts, RFC 9420 MLS group Commits, pending MLS Welcomes, device revocations, identity trust alerts, and `support_reply` nudges. Enforces immediate disconnect if the account is suspended by moderation.

---

## 5. Cryptographic Global Envelope Channel (`/api/chat/*`)

| Method & Path | Auth | Purpose |
| :--- | :---: | :--- |
| `GET /api/chat/public-security-model` | Public | Returns the explicit confidentiality model of the public room, disclosing the multi-recipient public-room key distribution and warning that Olm v2 / MLS RFC 9420 should be used for confidential discussions. |
| `GET /api/chat/rooms/{room_id}/recipients` | Public | Returns active registered public keys authorized to receive encrypted room envelopes for multi-recipient pairwise wrapping. |
| `GET /api/chat/messages` | Public | Returns encrypted envelopes for the public room (`global`), ordered strictly by the server's authoritative UTC creation timestamp (`ORDER BY created_at DESC`) to ensure feed ordering is immune to client clock skew. Supports optional `recipient` query parameter (`?recipient=0x...`): validates EVM address format (`400 Bad Request` if invalid) and filters returned envelopes to those where the recipient is the sender or in the recipient wrappers list. Strictly rejects private/group rooms with HTTP 403. Guarantees zero plaintext fields and catches DB exceptions returning safe generic errors without leaking stack traces. |
| `GET /api/chat/messages/{message_id}` | Public | Returns a single encrypted message envelope by message ID (`404` if not found). Includes both `client_timestamp` (for signature verification) and `server_timestamp` / `created_at`. Guarantees zero plaintext fields and returns safe generic error if database lookup fails. |
| `POST /api/chat/messages` | EIP-191 Envelope Signature | Submits a multi-recipient encrypted envelope to the global chat room. Enforces: (1) 128 KB request payload ceiling rejecting oversized requests with `HTTP 413 Payload Too Large`, (2) zero plaintext (`extra="forbid"`), (3) strict protocol validation (`version=1`, rejecting unsupported versions with "client update required"; exact algorithm `ECDH-P256-HKDF-AES-GCM-256`; `key_version=1`), (4) strict base64url validation and exact 12-byte IV length for AES-GCM across `content_iv` and all recipient wrappers, (5) non-empty ciphertext size bounds (16 to 65,536 bytes), (6) replay protection via strict 5-minute clock-skew window on client timestamps, (7) server-authoritative UTC creation timestamp generation (`server_timestamp`, `created_at`) decoupled from the signed client timestamp (`client_timestamp`), ensuring signature integrity is preserved while database indexing/ordering is immune to client clock tampering, (8) self-inclusion of sender in recipient wrappers, (9) duplicate recipient rejection (case-insensitive), (10) server-side verification that every recipient has an active registered encryption key in `chat_db` and that submitted `keyFingerprint` matches the registered key, (11) deterministic canonical JSON representation of all 10 security fields (`algorithm`, `channel`, `content_ciphertext`, `content_iv`, `key_version`, `message_id`, `recipients`, `room`, `sender`, `timestamp`, `version`), (12) EIP-191 wallet signature binding the SHA-256 envelope hash (rejecting unhashed envelopes with HTTP 400 upgrade error), (13) database row-creation detection across PostgreSQL and SQLite returning `HTTP 409 Conflict` for duplicate message IDs (or returning the original message with `?idempotent=true` only if verified exactly identical, never silently overwriting), and (14) safe generic error responses (`HTTP 500`: `"Unable to save encrypted message"`) with detailed server-side error logging, guaranteeing failed storage prevents WebSocket broadcast or success responses. |


