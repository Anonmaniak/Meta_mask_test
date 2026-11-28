# Zyphra: all changes (cumulative)

File names in this folder use `__` for `/` (e.g. `backend__platform_db.py` -> `backend/platform_db.py`).
Copy each file to its path, and DELETE the files listed under "Delete".

## Delete these (legacy, nothing uses them)
backend/chat_keys.py, backend/chat_routes.py, backend/send-speedup.patch,
backend/test_chat_e2ee.py, backend/test_chat_keys.py,
frontend/src/services/chatCrypto.ts, frontend/src/services/chatKeyService.ts,
frontend/src/tests/browserCryptoRunner.ts, frontend/test-crypto.html,
frontend/tests/chatCrypto.node.test.ts, frontend/tests/chatCryptoMulti.node.test.ts,
frontend/tests/chatKeyService.node.test.ts, frontend/tests/failedSendHandling.node.test.ts, frontend/src/App.css

## 17. Security audit fixes, on-demand RPC, smart polling & isolation (Nov 2026)
- **Group policy superadmin check (`backend/platform_routes.py`)**: `update_group_policy_endpoint` now grants superadmin pricing privileges (`is_paid`, `entry_fee_usd`, `entry_fee_yearly_usd`) only when `_resolve_admin_actor` actually verifies `role == "superadmin"` or the caller's session account holds `superadmin`; stale or forged `X-Admin-Token` headers fall back to ordinary session rights instead of escalating privileges.
- **DM attachment upload & inactive group prefs hardening (`backend/e2ee_routes.py`)**:
  - `upload_encrypted_attachment` now routes all uploads through `_resolve_upload_attachment_scope` before base64 decoding or quota consumption: refuses muted accounts (`403`), enforces bidirectional `user_blocks` for both `usr_...` and `conv_...` targets, rejects self-targets (`400`) and unknown recipients (`404`), and requires active participation for `conv_...` uploads (`403`).
  - `set_my_conversation_pref` now requires `e2ee_db.is_active_group_member(group_id, uid)` so members who left, were removed, or declined cannot write group preferences.
- **Group pricing session resolution (`backend/platform_routes.py`)**: `get_group_pricing_endpoint` now uses `get_optional_session(request, authorization)`, honoring both `HttpOnly` session cookies and case-insensitive `Bearer` headers when computing `has_paid`.
- **Zero-RPC `/api/health`, cached admin RPC health & on-demand balance checks (`backend/app.py`, `backend/eth_rpc.py`, `backend/platform_db.py`, `backend/e2ee_routes.py`)**:
  - `/api/health` calls `eth_rpc.peek_rpc_health_status()` and never triggers live Ethereum RPC probes (probing runs at startup via `get_cached_rpc_health_status(block_if_empty=True)` and in `/api/platform/admin/overview` via non-blocking stale-while-revalidate `get_cached_rpc_health_status()`, TTL `30 s`).
  - `verify_user_meets_group_policy(..., refresh_balance=True)` triggers `refresh_verified_balance_if_stale` (cooldown `60 s`, staleness `BALANCE_REFRESH_SECS=600`) only when a stored balance fails a group's minimum-ETH requirement on join/discovery, never on group message sends (`refresh_balance=False`) or at login. Unmined contract-creation txs (`to=None`) now fail verification immediately.
  - Added unified `is_test_environment()` / `_is_test_env()` detection across `app.py` and `eth_rpc.py` covering `TESTING=1`, `pytest`, and `unittest`.
- **Atomic pins, DB indexes & connection-identity schema guards (`backend/chat_features_db.py`, `backend/e2ee_db.py`, `backend/support_db.py`)**:
  - `set_pin` now runs inside `_in_transaction(..., lock_key="pins:" + scope_key)` (PostgreSQL `pg_advisory_xact_lock` / SQLite `RLock`) with strictly monotonic `pinned_at` (`+1 µs` on fast-clock ties) so concurrent pins never exceed `PIN_LIMIT` (`3`) or evict the wrong message.
  - `chat_features_db._ready_for` and `support_db._sqlite_schema_ready_for` compare DB connection/pool objects via `is` instead of `id()` ints or booleans.
  - Added `idx_dm_sender_seq` and `idx_dm_recipient_seq` indexes on `chat_dm_messages`.
- **Consistent single-emoji reaction validator (`backend/chat_features_db.py`, `frontend/src/services/chatEvents.ts`)**: Added `is_single_emoji` / `isSingleEmoji` accepting keycaps (`1️⃣`, `#️⃣`, `*️⃣`), flags, skin tones, variation selectors, and ZWJ sequences (up to 16 code points) while rejecting plain ASCII and non-emoji text in any script.
- **Single-flight E2EE provisioning, confirmed-only vault wipe & smart polling (`frontend/src/services/deviceProvisioning.ts`, `frontend/src/services/deviceRevocation.ts`, `frontend/src/services/e2eeRealtime.ts`, `frontend/src/services/e2eeApi.ts`, `frontend/src/App.tsx`, `frontend/src/components/Chat.tsx`, `frontend/src/components/AdminDashboard.tsx`, `frontend/src/components/E2EESecurityModals.tsx`)**:
  - Added `ensureLocalDeviceRegistered` so `App.tsx` and `Chat.tsx` share one in-flight device/KeyPackage registration per user.
  - Added `shouldWipeLocalDevice` so `wipeUserDeviceVault` runs only when the server explicitly confirms revocation of the local device (never on `Account suspended`, `muted`, or permission `403`s).
  - Tracked `/ws/e2ee` live state via `isE2EERealtimeLive()` (`authenticated` / `ws_closed` events); `Chat.tsx` now polls every `30 s` while connected, falls back to `4.5 s` only when disconnected, pauses polling in hidden tabs, and syncs on reconnect/tab return. `App.tsx` also skips hidden-tab `/api/health` polls.
  - `handleCreateMlsGroup` claims peer KeyPackages up front and caches them (`claimedKeyPackagesRef`) alongside `halfCreatedGroupRef` across retries; `handleRetryFailedMessage` preserves `mentionIds`; `AccountDevicesVaultModal` checks `w.status === 'active'`; `AdminDashboard.tsx` moves `userQueryRef` update into `useEffect`.
- **Tests**: Added `backend/test_audit_fixes_round2.py` (21), `backend/test_rpc_on_demand.py` (6), `backend/test_user_isolation.py` (5), and `frontend/tests/auditFixes.node.test.ts` (8). Verified: **267 passed** backend tests, **56 passed** frontend Node tests across 14 suites, `oxlint` `0` errors (`28` warnings), and `tsc -b` `0` errors.

## 0000000. UI polish, instant isolated chat switching & branding (NEW)
- **Instant, strictly isolated chat switching (`Chat.tsx`, `PlatformViews.tsx`)**:
  - Clicking a **Private chat** in the sidebar now selects the peer immediately without blocking on a network lookup, and refreshes device details in the background only when missing or stale.
  - Switching between **Members' room**, **Groups**, and **Private chats** swaps cached messages and conversation state synchronously before paint (`useLayoutEffect`), isolates in-flight fetches per conversation scope with a generation guard so slower responses from a previous chat can never overwrite the active chat, and parallelizes DM/Group network requests (`Promise.all`).
  - Removed the `syncSidebarLists` <-> `selectedGroup` re-sync cascade and cached the Members' room feed per account so returning to Members' room renders immediately.
- **Circular animated header search & streamlined chat headers (`MessageExtras.tsx`, `chatExtras.css`, `PlatformViews.tsx`, `Chat.tsx`)**:
  - Moved in-chat search (`ChatSearchBar`) into the top-right of `.chat-stage-header` across **Members' room**, **Group chats**, and **1-to-1 private chats** as a `36px` circular icon button that smoothly expands into a pill search bar (with inner input borders suppressed).
  - Moved the circular `⋮` (`ConversationMenu`) button up into `.chat-stage-header` next to search (capped height so it stays above the composer without clipping), removed the empty toolbar strip when no pins/chips/notices are active, and removed the redundant **Browse groups** / **Find a member** buttons from active chat headers.
- **Branding, welcome gate & forms (`Header.tsx`, `SupportView.tsx`, `AdminPortal.tsx`, `AdminDashboard.tsx`, `E2EESecurityModals.tsx`, `WelcomeGate.css`, `index.css`, `favicon.svg`, `index.html`)**:
  - Renamed the **Concierge** tab and page heading to **Contact Admin**, and updated the `/Admin456` tab title and header subtitle to **Admin**.
  - Added the circular brass **Z** emblem as the browser tab favicon (`frontend/public/favicon.svg` linked in `frontend/index.html`).
  - Scaled up the left column copy/button/feature list in `WelcomeGate.css` slightly and added top breathing room to `.console-topbar--gated`.
  - Added custom theme-aware dropdown chevrons (`36px` right padding) to all `<select>` elements across client and Admin screens, and switched the Admin pricing fields to a 2x2 grid (`admin-settings-grid--two`) so option labels never clip.

## 000000. Production readiness (launch scan)
- **Production never runs on a temporary database.** On Render (or `ENVIRONMENT=production`) the server used to fall back silently to a local SQLite file when PostgreSQL was missing or unreachable; Render wipes that file on every deploy / restart, so messages and payments made meanwhile would vanish. Now it retries for about 30 s and then refuses to start (the build's migration step too). `/api/health` answers 503 if it is ever on the fallback. `ALLOW_SQLITE_FALLBACK=1` opts out (single-machine installs only). Local development is unchanged. (`backend/chat_db.py`, `backend/app.py`)
- **Frontend build requires `VITE_BACKEND_URL`.** Without it the app called `https://<site>/api`, which Vercel answers with the web page, so every request failed. The production build now stops with instructions. (`frontend/vite.config.ts`)
- Checked: 235 backend tests on Python 3.12 and on Python 3.11 with `requirements.txt` (Render's version), every test class against PostgreSQL 16, 48 frontend tests, type-check, build.
- See `LAUNCH_CHECKLIST.md` for the steps outside the code (commit everything, secrets, Render / Vercel settings, Admin456 payment settings, legal pages).

## 00000. Chat features: reactions, edit/delete, typing, mentions, reminders, announcement groups, pins, polls, search, mute/archive, disappearing messages, banner (NEW). Invite links REMOVED.
**Private chats and groups** (end-to-end encrypted: the server never sees the text, emoji, edits or votes)
- **Reactions** ❤️ 👍 😂 😮 😢 🙏: one per person per message; press yours again to remove it. Sent as an *encrypted event* that points at the message; devices apply it.
- **Edit** your message within **15 minutes** (shows "Edited"); **Delete for everyone** within **48 hours** (group admins: any message, any time). Deleting really removes the stored encrypted copy from the server and shows "This message was deleted".
- **Typing…** in private chats, groups and the Members' room. Never sent for members who hide their online status.
- **@mentions** in groups and the Members' room: type `@` for suggestions; the mentioned member gets "@x mentioned you" (even in a muted chat). In encrypted groups the server learns *who* was mentioned (never the text), so it can notify them.
- **Polls** in groups (2 to 10 options, one or several answers). Votes are encrypted: the server never sees who voted for what.
- **Pinned messages** (up to 3; a 4th replaces the oldest): group admins in groups, either person in a private chat, moderators in the Members' room.
- **Search** within a chat: runs on your device over the messages it has decrypted (server-side search would mean the server reading messages).
- **Mute** (8 hours, a week, always) and **Archive** (hidden under "Archived chats"), saved per member and synced across their devices. Muted chats still count unread but make no pop-up or sound.
- **Disappearing messages**: off, 24 hours, 7 days or 90 days per chat (groups: admins set it). Devices hide the messages, and the server deletes its copies when time is up.
- **Announcement groups**: "Only admins can send messages" (⋮ menu, group admins). Members still read, react and vote. The server enforces it.
- Reactions, edits and votes never count as unread and never notify.

**Whole app**
- **Renewal reminders**: banner + bell 7 days before membership / paid-group access ends, 1 day before, and when it ends (each once). Free membership, lifetime free access and group admins get none.
- **Banner for everyone**: Admin456 > Platform Settings > "Banner for everyone" (text, information / warning, optional end time). Members can close it; a new text shows again.

**Invite links removed**: no links are created or redeemed anywhere. People join only when a group admin adds them and they press **Accept** (or by a join request to a public group). The invite endpoints answer **410 Gone** with a clear message; old `?invite=` links just open the app. "Invite only" groups are now called **Private (admins add people)**.

**Private-chat detail, deliberately**: after a delete or expiry the server keeps only a device's undelivered *session-setup* copy (still encrypted, unreadable to the server): dropping it would stop that device from reading the rest of the chat. The app never shows or stores its text.

**Backend**: new `backend/chat_features_db.py` (pins, timers, mute/archive, announcement mode, room reactions; tables made automatically at start-up). New columns on `chat_dm_messages` / `chat_group_messages` (`event_kind`, `deleted_at`, `expires_at`), added automatically. New endpoints: `POST /api/e2ee/dm/messages/{id}/delete`, `POST /api/e2ee/groups/{gid}/messages/{id}/delete`, `POST /api/e2ee/typing`, `GET /api/e2ee/conversations/state`, `POST /api/e2ee/pins`, `POST /api/e2ee/disappearing`, `POST /api/e2ee/groups/{gid}/settings`, `GET|POST /api/e2ee/conversation-prefs`, `POST /api/platform/public-chat/messages/{id}/reaction`, `POST /api/platform/public-chat/typing`, `POST /api/platform/public-chat/pins`, `GET /api/platform/announcement`, `GET /api/platform/reminders`. Sends accept `event_kind` ('message' | 'control') and, for groups, `mention_user_ids`.

**Frontend**: new `services/chatEvents.ts` (applies encrypted reactions / edits / votes with the rules above; unit-tested), `components/chat/MessageExtras.tsx` + `chatExtras.css`, `components/AppBanners.tsx`. Changed `Chat.tsx`, `PlatformViews.tsx`, `ChatComposer.tsx`, `ChatTimeline.tsx`, `E2EESecurityModals.tsx`, `PaidGroupAdmissionModal.tsx`, `App.tsx`, `AdminDashboard.tsx`, `NotificationBell.tsx`, `services/e2eeApi.ts`, `services/platformApi.ts`, `services/olmService.ts`, `services/notificationStore.ts`.

**Tests**: new `backend/test_chat_features.py` (19) and `frontend/tests/chatEvents.node.test.ts` (14); three old tests updated for the removed invite links. 231 backend and 48 frontend tests pass; the new backend tests also pass on a real PostgreSQL 16.

## 0000. Free access from the admin (NEW)
**Admin456 > Free access (new tab)**
- Search a member, choose **Membership** or **one group**, choose how long (30 days, 90 days, 1 year, custom days, or no end date), add a private note, press **Give free access**. The list shows who has free access, with **Revoke**. Only a superadmin can give or revoke; moderators can look.
- Membership grant: the member enters the app without paying. Group grant: that group's fee AND minimum-balance rule are skipped for them, and they can ask to join even an invite-only group. Suspended accounts stay blocked.
- A group grant is not a membership (give both if membership is paid), and a membership grant does not pay for groups.
- Revoking works at once. Giving access again replaces the old length.
- Free access is kept apart from payments: it never counts as a paid member, never creates a payment record, and the note is never shown to the member. Every grant and revoke is in the Activity log.
- Encrypted groups: the server cannot put anyone into an encrypted group (that is what keeps admins from reading them). With a grant, a group admin can now add the member (adding an unpaid member to a paid group used to be refused), and the member accepts the invitation as before.
- Members see **Free access** (and its end date) on their Membership page instead of "Not yet paid" and the pay button. Their screens refresh live when access is given or taken back.

**Backend**: new table `access_grants` (`migrations/014_access_grants.sql`, created automatically at startup). New `GET /api/platform/admin/access-grants`, `POST /api/platform/admin/access-grants`, `POST /api/platform/admin/access-grants/revoke`. `membership/status` adds `platform_free_access` and `group_free_access`. The checks for membership, paid groups, group policy, group discovery and join requests all honour grants. Deleting a group deletes its grants.

**Bug fixes**
- **PostgreSQL (Neon): the payout address always read as empty, so payments could not be verified.** Settings are stored as JSONB, which the database driver already turns into Python values; the code JSON-decoded them a second time, and every text setting (the authorized payout address above all) came back as `None`. Payment verification then always took the "server misconfigured" branch, and `/pricing` sent no payout address to the payment window. Prices were not affected only by luck (a number in text decodes). Fixed in `platform_db.py` (`_pg_setting_value`): PostgreSQL now returns exactly what SQLite returns. SQLite (used by the tests and local development) never had this problem, so the test suite could not see it; it was found by running the tests against a real PostgreSQL.
- **PostgreSQL: some payment errors crashed with HTTP 500.** `audit_logs.entity_id` was 64 characters but a transaction hash is 66, so the audit entry for a payment on an unsupported network, or while the payout address was missing, failed with "value too long". New `migrations/015_audit_entity_id_length.sql` widens it to 128 (metadata-only, runs once, automatically at start-up).
- Sending a message in a paid group after its subscription ended answered **403**, so the app showed an error instead of the renew window (reading already answered 402). Sending now answers **402** with the group's id and name, and the app opens that group's payment window; the message stays with **Retry**.
- A paid-group refusal from the encrypted API (Accept, send) used to open the group's payment window AND jump to the Payments tab at the same time. It now only opens the payment window, like the other screens.

**Frontend files**: new `src/components/AdminFreeAccess.tsx`; changed `AdminDashboard.tsx`, `PaymentsView.tsx`, `Chat.tsx`, `services/platformApi.ts`, `services/e2eeApi.ts`, `services/e2eeRealtime.ts`.
**Tests**: new `backend/test_access_grants.py` (12 tests) and `backend/test_postgres_compat.py` (4 tests). 212 backend and 34 frontend tests pass. The grant tests and the existing paywall, subscription and verified-payment suites were also run against a real PostgreSQL 16 server: all pass.

**Please check on your live server**: because of the payout-address bug, payment verification cannot have worked on PostgreSQL. If members have paid successfully in production anyway, the server is probably not connected to Neon at all: when it cannot reach the database it silently falls back to a local SQLite file (look for "Falling back to local isolated engine" in the start-up log).

## 000. Reply to messages + Notifications (NEW)
**Reply (all three chats: Members' room, private chats and groups)**
- Reply button on every message (hover on desktop, always visible on phones). A "Replying to @name" bar shows above the message box; Esc or the X cancels.
- The reply shows the quoted message on top. Tapping the quote scrolls to the original and highlights it (or says it is not loaded).
- The quote (sender + short excerpt) travels inside the end-to-end encrypted message (`reply_to` in the message envelope), so the server never sees it and the other person sees it even when the original is not loaded. Reply details from others are length-checked before display.
- Retrying a failed message keeps its reply.
- Members' room: replies store which message they answer (`reply_to_message_id`, migration `013_public_chat_replies.sql`, added automatically). The server builds the quote from the original when the room loads, so a deleted (moderated) original shows "The original message is no longer available" in every quote, and originals from members you blocked show no text. Live edits and deletes update quotes straight away. Replying to a deleted message is refused.

**Notifications**
- Bell in the header: unread count, recent new messages and group invitations (one entry per conversation), tap to open the conversation, "Mark all as read".
- Unread badges on each private chat and group in the sidebar; unread count in the browser tab title ("(3) Zyphra").
- Small pop-up when a message arrives while you are elsewhere in the app; optional sound (on by default, switch in the bell panel); optional system notifications when Zyphra is in the background ("Turn on" in the bell panel).
- Never shows message text, only who wrote and where. Works on every page (Membership, Concierge, Settings), not only Messages.
- A conversation counts as read only when it is on screen and the tab is visible; while the tab is hidden, messages stay unread until you come back.
- One shared live connection for the chat screen and notifications (`frontend/src/services/e2eeRealtime.ts`).

**Backend**
- New `backend/read_markers_db.py` and `migrations/012_read_markers.sql` (table `chat_read_markers`, created automatically at startup). New `GET /api/e2ee/unread` and `POST /api/e2ee/read-markers`. The first unread request marks existing history as read, so old messages never show as new.
- The `group_ciphertext` live event now includes `sender_user_id` (so your own messages are not notified).

**Tests**: new `backend/test_unread_notifications.py` (5), `backend/test_public_chat_replies.py` (5) and `frontend/tests/notificationStore.node.test.ts` (8). 194 backend and 27 frontend tests pass.

## 00. Accept / Reject group invitations, Instagram-style (NEW)
- When a group admin adds someone, that person now gets an invitation with **Accept** / **Reject** instead of being put in the group. It shows at the top of their Groups list and as a pop-up when it arrives.
- While invited they cannot see the group, read its messages, post, or receive its keys (server-enforced). Accept: they join and the group opens. Reject: they are never added (`declined`), and the admin can invite them again later.
- People who asked to join (join request or invite link) are still added directly when the admin approves them. Invite links and join requests are unchanged.
- Group settings: new **Waiting for reply** list with **Cancel invite**. After adding, the admin sees whether the person was invited or added.
- Admin456 Groups tab shows **Created by @username (wallet)**. The creator is the group's admin (unchanged, now tested).
- Backend: `e2ee_db.py` (member status `invited` / `declined`, Welcomes only for active members, invitation list and accept/reject), `e2ee_routes.py` (new `GET /groups/invitations`, `POST /groups/{id}/invitation/accept|decline`, `group_invitation` and `group_invitation_response` events), `platform_db.py` (`has_pending_join_request`, creator name and wallet in the admin group list). No database migration needed.
- Tests: new `backend/test_group_invitations.py` (6 tests); `test_e2ee_security.py` updated so a directly added member accepts first. 184 backend tests pass.
- Deploy the backend and frontend together: with only the new backend, invited people would have no Accept button.

## 0. Simpler, safer screens: no keys shown to members (NEW)
- Removed the **Security** button (Conversations) and **Verify Keys** (private chats), the safety-number window and the key-change warning banner. Encryption is unchanged.
- Username, wallets, signing out devices and "start private chats fresh" moved to **Settings > Privacy > Account and devices**, in plain words. Removed the manual "Refresh encryption keys" button (keys top up automatically).
- Group settings keep every feature (members, admins, invites, join requests, who can join, delete, leave); removed the protocol / epoch / authenticator panel and "Rotate My Leaf Key".
- Plain language everywhere (no SIWE / E2EE Vault / MLS / Epoch wording). New `frontend/src/services/friendlyError.ts`: members see short friendly errors; technical detail goes to the browser console only.
- `getBaseApiUrl()` no longer accepts a `backend_url` saved in the browser (could redirect API calls and sign-in tokens to another server). The backend address comes only from `VITE_BACKEND_URL` / the site address.
- New devices are labelled "Web browser".
- Never zip or share `backend/.env`, `frontend/.env`, `*.sqlite3`, `__pycache__`, `.pytest_cache` or `node_modules`.

## 1. Monthly / Yearly subscriptions (NEW)
- Membership: monthly price = `platform_entry_fee_usd`, yearly = `platform_yearly_fee_usd` (0 = 12 x monthly). Members choose when paying. Access = 30 / 365 days; renewing stacks on the time left.
- Each paid group has its own monthly + yearly price (`entry_fee_usd`, `entry_fee_yearly_usd`). Without an active group subscription a member cannot join, send or read in that group (HTTP 402). Platform/group admins are exempt.
- Two kinds of payment: (1) platform membership to enter the app, (2) per-group subscription for paid groups. Free groups need nothing.
- New table `member_subscriptions` (migration 009). Migration 010 runs ONCE and gives everyone who already paid 30 days to renew.
- Members: new Payments tab (status, expiry, renew, history); any 402 sends the member there. Admin456: yearly price field, monthly+yearly per group, new Payments tab (with Retry).
- Superadmin "create group" form has monthly + yearly price.

## 2. Bugs fixed
- Admin "retry payment" credited ANY amount (even 1 wei). Now enforces the amount stored on the payment.
- Paid-group payment called `e2ee_db.add_group_member`, which does not exist (error was swallowed). Removed.
- Concurrent verification of the same payment could credit twice; the update is now conditional.
- Payments are accepted only on the admin's active network (free testnet ETH could buy access on Mainnet).
- Removed the public unauthenticated `/api/chat/*` feed.

## 3. Privacy: wallet is the only identity (no IP anywhere), self-hosted fonts (no Google), uvicorn access log off.
## 4. Admin456 is the only place for network, membership price and payment wallet (no env vars).
## 5. Speed: group discovery 121 -> 3 queries (identical output).
## 6. Legacy removed: old multi-recipient chat stack (backend + frontend), DiscoverUsersView, 11 unused types, 9 unused API wrappers, ~860 lines in chat_db.py.


## 7. Cleanup round (unfinished items finished)
- Removed the `balance_reeval_minutes` setting (nothing read it).
- Removed the unused interactive SAS code (and its test): Safety Numbers remain the key-verification feature.
- Identity events are now shown: Devices & Key Vault window -> "Security activity" (device revoked, identity reset, wallet linked / changed).
- Removed group/profile avatar links and `min_level` from the API, UI and types (levels no longer exist; avatars were never displayed, and loading image URLs would leak viewers' IPs). Database columns are kept as inert constants, so no data migration is needed. Older app versions that still send these fields are tolerated (ignored).
- CORRECTION: the group "history sharing" mode is NOT dead: `none` is what stops newly added members reading messages from before they joined. Kept. Only the unreachable `explicit_export` option was removed.
- Documentation refreshed (README, backend/frontend READMEs, docs/*): subscriptions, 8 admin tabs, no IP / no lockout, removed legacy `/api/chat` channel and SAS references, accurate test list.
- Backend 125 tests, frontend 11 tests, tsc and vite build clean.

## Still NOT built (these never existed, so they were not "unfinished code")
Typing indicators, message replies, reactions, @mentions. They need design decisions (public chat vs end-to-end encrypted chats, metadata privacy) before building.

## 8. Premium redesign for high-net-worth members (same features, new look)
- Design system: racing-green ink, warm ivory text, one brass accent; Newsreader (serif) for titles and prices, Hanken Grotesk for everything else (both self-hosted, no Google). Dark and light themes, tested on desktop and phone sizes.
- New: the metal Membership Card (welcome screen hero + your real status and renewal date on the Membership page), plan cards for Monthly / Yearly, soft status chips, flat list rows.
- Rebuilt: top bar (Zyphra wordmark, text tabs with a brass underline, account chip), welcome screen, first-visit splash, Membership page, both payment pop-ups, Settings (narrower, plainer, server address under "Advanced"), Concierge, Administration console styling.
- Plain language instead of developer vocabulary: Messages / Membership / Concierge, Members' room, Start a conversation, New group, New private chat, Security, Find a member, Group settings, Refresh encryption keys, etc. Technical detail is still available, just not in your face.
- Readability: small text sizes raised across the app; removed all-caps tracked labels, arrows and monospace names; visible keyboard focus; reduced-motion respected.
- Modals now correctly dim the whole page including the top bar.
- Removed dead code: src/App.css (unused), old Inter / Outfit font packages. No features were removed or changed.
- Backend untouched in this round (125 tests pass). Frontend: tsc clean, production build clean, 11 tests pass.
- ACTION: in frontend/ run `npm install` (new font packages) before building.
- NOT visually checked: Admin Payments / Support / Audit tabs in the light theme, the Support thread view, invite screens, and private (1-to-1) chats with two real users. Review these once in your browser with MetaMask.

## Run after copying
- `cd frontend && npm install` (new font packages), then build.
- Backend: deploy; migrations 009 + 010 run automatically at start (`python run_migrations.py` also works).
- In backend/.env and Render: delete EXPECTED_CHAIN_ID, AUTHORIZED_PAYMENT_DESTINATION, PLATFORM_ENTRY_FEE_USD.
- Open /Admin456 -> Platform Settings: set network, monthly + yearly price, treasury wallet.
- Rotate the Neon password, Alchemy keys and admin login (they were visible in your screenshot / zip).

## Tests
backend 125 passed; frontend 11 passed; tsc clean; vite build clean.
NOT tested: migrations 009/010 against a real PostgreSQL (SQL syntax checked only), and the new screens in a real browser with MetaMask.

## Known limits
- The server blocks lapsed members from sending/reading, but cannot remove their encryption keys: an admin's app must remove them from the encrypted (MLS) group.
- Left in place on purpose: levels leftovers (min_level, level tables, `wallet_level` tab name), duplicate admin endpoints (/admin/pricing, /admin/payment-destination), fixed-ETH legacy group fee, 3 legacy DB tables, unused SAS-verification functions.

## 9. Connect MetaMask now detects paid / not paid / expired (fix)
- Every Connect press (and the step right after the MetaMask signature, and page load) asks the server for the wallet's membership instead of trusting a value remembered earlier in the tab. Active -> enters; never paid -> Join window; lapsed -> Renew window with the end date; expired session -> sign again.
- The welcome screen and the payment window say what was detected.

## 10. Audit round: things that were missing or not wired to the UI (fixed)
Backend
- BUG: a superadmin saving a group's Access Policy in the app (e.g. only the description) turned a PAID group FREE (missing `is_paid` defaulted to false). Missing fields now keep the current value.
- Paid groups: `join-request` / `join-by-invite` answer 402 `group_payment_required` with the group id and name (was a dead-end 403). A refused attempt does not use up the invite.
- NEW `POST /api/platform/groups/{id}/join-requests/{request_id}/decline` (admins could only approve before).
- Admin user list now includes `suspended_until` and `suspension_reason`.
Members' app
- Invite for a paid group -> opens that group's payment window; after payment the SAME invite is used to join (a public join request was refused for invite-only groups, so paying did not get you in).
- Group settings: Decline button for join requests; invites show "Expires <date> / Expired / Used up / Revoked"; copy button copies a shareable link (`/?invite=CODE`); Revoke errors are shown; paid status shown (read-only) on Access Policy.
- Invite links: opening `https://<site>/?invite=CODE` takes the member (after connecting) to Groups with the code filled in. They still press Redeem.
- Live "Someone asked to join <group>" alert for group admins, with Review (opens the requests tab).
- Sender can remove a file they sent (trash icon). Others see "removed by the sender" instead of a decryption error.
- Encryption keys (one-time prekeys + MLS KeyPackages) are topped up automatically every 10 minutes, not only at sign-in.
- Admin replies in Concierge arrive live (the server's `support_reply` push was ignored; only a 30 s poll existed), on every page.
- `/profile` is now a real address (refresh no longer drops you on the chat).
Admin456
- Platform Settings: added old-username reservation days, Members' room longest message, edit window (minutes) and retention days (the backend supported them, there was no field).
- Mute / Suspend ask for a reason and a duration (empty = until restored). Mute was permanent and Suspend had no confirmation. Status shows "until <date>".
- Reports show the reporter's written details, the date and the outcome; Resolve asks what was done.
- Settings save reloads the saved values and clears an old error.
Checked and fine: "Watching" count updates live; every API helper is used; read receipts / presence settings honoured.

Tests: backend 140 passed (3 new in `test_group_join_fixes.py`, one updated for the 402). Frontend: tsc clean, build clean, 11 tests pass.
NOT tested in a real browser with MetaMask: invite links, paid-group invite payment, file removal, the join-request alert, live Concierge replies.
Still NOT built: typing indicators, replies, reactions, @mentions; a member cannot see or cancel their own pending join request.


## 11. Instagram-style chat: dates, bubbles, emoji, files and images
Applies to the Members' room, private chats and groups (one shared component: `frontend/src/components/chat/`).
- Dates like Instagram: a centered label starts each day and every gap over 1 hour: "Today 4:10 PM", "Yesterday 12:23 AM", "Mon 9:15 AM", "12 Nov, 4:10 PM", "12 Nov 2025, 4:10 PM". Hover a message for the full date.
- Bubbles: yours on the right in gold, others on the left. Consecutive messages from one person are grouped (tighter corners, name once at the top in groups / the room, avatar once at the bottom). 1 to 3 emoji alone show large without a bubble. Private chats show "Seen" / "Sent" under your latest message. Actions (edit, delete, block, report, copy ID) appear on hover, or on tap on phones.
- Emoji picker built in (no external library): search, categories, recently used.
- Composer: text grows as you type, Enter sends, Shift+Enter new line. Attach up to 5 files per message by button, paste or drag-and-drop; thumbnails before sending.
- Files and images: images preview inline and open full screen; video and audio play inline; other files show as a card with Download (program files such as .exe get a warning).
  - Private chats and groups: files are encrypted on the device as before; now up to 5 per message, images preview after decrypting, and files already uploaded are kept if a message needs Retry.
  - Members' room: NEW. Files are visible to all members and NOT end-to-end encrypted (the composer says so).
- Limits (checked in the app first, enforced by the server): 5 MB per file, 5 files per message; per member per 24 h: 100 files / 250 MB in private chats + groups, 60 files / 150 MB in the Members' room. Empty files refused.
- Safety (Members' room): a file is shown as an image only if its bytes are PNG/JPEG/GIF/WebP; anything else (SVG included) downloads as a plain file the browser will not open or run. File names are cleaned. Unsent uploads are private and purged after 24 h. Deleting a message removes its files.
- BUG fixed: the Members' room showed Delete on your own messages, but the server allowed only moderators. Members can now delete their own messages.
- New backend files: `public_attachments_db.py`, `migrations/011_public_chat_attachments.sql` (created automatically at start-up; on SQLite too).
- Tests: backend 156 passed (4 new in `test_chat_files.py`); frontend 19 passed (8 new in `tests/chatFormat.node.test.ts`); tsc and build clean.
- NOT tested in a real browser: please try sending an image, a PDF and a video in the Members' room, a private chat and a group, on desktop and phone.
- Delete the two stray files at the project root from an earlier copy: `docs__backend__api-reference.md`, `docs__features.md`.

## 12. Admin numbers, login sessions, group deletion, "Online now" (audit round 2)
Admin456 overview cards
- "Members" is now **Registered wallets** (everyone who ever signed in). NEW card **Paid members** (active subscriptions; says "Membership is free right now" while the price is $0).
- "Signed in now" is now **Signed in (last 24 h)**: it counts people with a valid login (a login lasts 24 h), which is not the same as online. "Online now" is the live number.
- **Members' room messages** counts only what members can still see (inside the retention window).
- **Groups** counts groups that exist and still have at least one active member.
- **Online now** includes admin wallets that are using the chat and says "Includes N admins" (members still never see admins in their own count).
- Each card has a one-line explanation, the page shows "Updated hh:mm:ss", and a warning appears when refreshing fails ("Live updates are paused ... may be out of date"). Before, a dead server left old numbers on screen with no sign.
Login sessions
- A person can hold at most 10 live sessions; signing in beyond that signs out the oldest. Expired sessions (7 days after expiry) and signed-out ones (7 days) are deleted automatically (at most once an hour, on sign-in). An index on `expires_at` keeps this fast. Before, rows were never deleted.
Groups
- NEW: groups can be deleted for good. Group admins: Group settings, "Delete this group" (type the group name to confirm). Platform admin: Admin456, Groups, "Delete group". Removes members, messages, encrypted files, invites, join requests, policy and group subscriptions in one transaction; payment records are kept; it is audit-logged; online members see the group disappear at once and their device drops its keys for it.
- **Paid groups can only be deleted by the platform admin** (members paid for access).
- BUG fixed: the Admin456 Groups tab showed a blank member count (the page read `active_member_count`, the server sent `member_count`). Groups with no members left are labelled "No members left (not counted)".
Storage
- Members' room files are also deleted when their message falls out of the retention window (not only unsent uploads after 24 h).
Tools / docs
- NEW `backend/loadtest_polling.py`: simulates N signed-in members against a real running server using only a temporary in-memory database. `SCALING.md` has the measured results for 100 and 300 members and what decides real-world speed.
- `docs/backend/api-reference.md`: the "Files in chats" section was missing from the uploaded copy; restored, plus this round.
Tests: backend 178 passed (7 new in `test_admin_stats_and_sessions.py`: session cap, session purge, paid vs registered, retention count, group count/delete/permissions, paid-group rule, online-now admins). Frontend: tsc, build and 19 tests pass. NOT tested in a real browser: the new Admin456 cards and warning, group deletion on both screens.

## 13. Composer file notice & top-bar Paid Amount pill
- **Composer note only when files are selected (`ChatComposer.tsx`, `index.css`)**:
  - Moved the composer `note` (such as `"Files in the members’ room are visible to all members and are not end-to-end encrypted."` and the E2EE file notice) so it renders inside the `.ig-composer-note` line only when `files.length > 0 && fileErrors.length === 0`, instead of permanently sitting beneath the text box when no files are attached.
  - Tightened desktop `.chat-composer-bar` padding from `18px 28px 22px` to `14px 24px` to remove excess bottom whitespace.
- **Top-bar Paid Amount pill (`platform_routes.py`, `platformApi.ts`, `App.tsx`, `Header.tsx`, `index.css`)**:
  - `GET /api/platform/membership/status` now also returns `total_verified_wei` and `total_verified_eth` (sum of the user's verified ETH payments).
  - Added a clickable `.topbar-paid-badge` pill in `Header.tsx` (directly to the left of the theme toggle button) showing `Paid: <amount> ETH` for each signed-in member and linking to the Membership (`payments`) view. Refreshes automatically on sign-in, session resume, wallet switch, and after platform or group payments.
- **Verification**: Frontend `oxlint` (`0` errors), `tsc -b && vite build` (`built in 1.66s`), `npm test` (`19` passed); backend `test_subscriptions.py` (`21` passed) and `test_paid_membership_and_groups.py` (`6` passed) run separately so shared SQLite fixtures do not collide.

## 14. Admin456 Platform Settings UI redesign (`AdminDashboard.tsx`, `index.css`)
- **Organized 3-card layout**: Replaced the cluttered horizontal row layout with three structured, clean visual cards:
  1. **Usernames & Identity**: 2-column grid covering *Hours between username changes* (`username_cooldown_hours`) and *Days an old username stays reserved* (`username_quarantine_days`).
  2. **Members' Room**: 3-column grid covering *Longest message (characters)* (`public_chat_max_message_chars`), *Minutes a message can be edited* (`public_chat_edit_window_minutes`), and *Keep messages for (days)* (`public_chat_retention_days`).
  3. **Membership, Pricing & Payments**: Dedicated panel card covering *Payment network* segmented pill (Ethereum Mainnet vs Sepolia Testnet), *Payment wallet (treasury address)* (`authorized_payment_destination`), *Monthly price (USD $)* (`platform_entry_fee_usd`), *Yearly price (USD $)* (`platform_yearly_fee_usd`), *ETH price source* (`use_live_eth_price`), and *Backup price of 1 ETH (USD)* (`eth_usd_price`).
- **Standardized styles**: Added `.admin-settings-card`, `.admin-settings-grid-2`, `.admin-settings-grid-3`, `.admin-settings-label`, `.admin-settings-input`, `.admin-settings-select`, and `.admin-settings-hint`. Replaced jagged `alignItems: 'end'` with uniform `align-items: start`, fixed control heights at 42px, and added clear explanatory helper text below each input.

## 15. Members' room retention display & real-time sync (`platform_routes.py`, `PlatformViews.tsx`, `platformApi.ts`)
- **Retention display in Members' room**: Added `retention_days` to `_public_chat_policy_dict` on the backend (`backend/platform_routes.py`) and typed in `PublicChatFeedResponse['policy']` (`frontend/src/services/platformApi.ts`). The room banner in `PlatformViews.tsx` now dynamically displays `"Messages kept for {policy.retention_days} days"` on the right-hand side of the warning notice.
- **Real-time WebSocket sync**: When an administrator saves platform settings in `/Admin456`, `backend/platform_routes.py` broadcasts `{"type": "public_policy_updated", "policy": ...}` over `/ws/public-chat`.
- Connected clients in `PlatformViews.tsx` listen for `public_policy_updated` and update their local `policy` state immediately, so any change made in Admin456 automatically updates the retention notice on all active members' screens without needing a page refresh.

## 16. Hide attachment (paperclip) icon across all 3 chat interfaces (`ChatComposer.tsx`, `PlatformViews.tsx`, `Chat.tsx`)
- **Disabled file attachments in all chats**: Hid the `<Paperclip />` button across all three chat interfaces:
  1. **Members' Room / Open Chat** (`PlatformViews.tsx`)
  2. **1-to-1 Private Chats** (`Chat.tsx`)
  3. **Group Chats** (`Chat.tsx`)
- Set `canAttach = false` as default in `ChatComposer.tsx` and explicitly passed `canAttach={false}` in all three parent callers.
- When `canAttach` is `false`, the paperclip button is hidden, the hidden `<input type="file">` is omitted, file drag-and-drop is disabled, and clipboard paste file handling is prevented, keeping the composer focused solely on text, emoji, and replies.