# High-Security End-to-End Encryption (E2EE) Architecture & Threat Model

This document specifies the cryptographic architecture, threat model, protocol selection, key lifecycle, metadata controls, known limitations, and release requirements for **Zyphra.in** private and group messaging.

> [!IMPORTANT]
> **Security Assurance Notice (Section K.10)**: While this architecture uses established cryptographic protocols (**Olm v2 Double Ratchet** via Least-Authority-audited Vodozemac WASM and **IETF RFC 9420 MLS** via `ts-mls`), **no software is unhackable or perfectly secure**. Before claiming production readiness or equivalence to a professionally audited native encrypted messenger, an **independent third-party security and cryptographic review** of the full application, deployment pipeline, and client asset delivery is mandatory.

---

## 1. Threat Model & Security Assumptions (Section A.9)

### 1.1 Protected Assets
1. **Private 1-to-1 & Multi-Device Message Plaintexts**: Text envelopes and attachment decryption keys exchanged between users' authorized devices.
2. **Group Conversation Plaintexts & Epoch Secrets**: Application messages, attachment keys, and TreeKEM ratcheting secrets inside encrypted groups.
3. **Encrypted File Attachment Payloads**: Binary file contents uploaded by conversation participants.
4. **Device Private Keys & Session State**: Curve25519 identity scalars, Ed25519 signing keys, One-Time Prekey (OTK) private keys, Olm Double Ratchet chain keys, and MLS Leaf/HPKE/Signature private keys.

### 1.2 Adversaries Considered in Scope
| Adversary | Capabilities | Protection Provided |
| :--- | :--- | :--- |
| **Database Administrator / Cloud Storage Operator** | Full read access to Neon PostgreSQL tables, database snapshots, backups, and encrypted attachment blobs. | Sees only opaque Olm v2 / MLS / AES-256-GCM ciphertexts, public key bundles, and SHA-256 hashed session tokens. Cannot decrypt private or group messages. |
| **Application Backend / Hosting Provider (Passive)** | Inspects HTTP/WebSocket payloads, memory of FastAPI workers, and application logs. | Receives ciphertext only (`extra="forbid"` + recursive `assert_zero_plaintext`). Private keys never leave client devices. |
| **Ethereum RPC Provider / Public Blockchain Observer** | Observes all on-chain transactions, balances, and RPC calls. | Zero chat messages, usernames, peer graphs, or group memberships are ever written to or queried from Ethereum. |
| **Compromised / Replaced Wallet or Stolen Username** | Controls a replacement wallet or attempts to claim an existing username without an authenticated session. | Cannot link to an existing `user_id` without an active session; cannot silently substitute an active device's identity keys (`409 Conflict`); identity resets increment `identity_version` and trigger non-silent peer warnings. |
| **Newly Added Group Member** | Legitimately joins an MLS group at epoch `E+1`. | **Pre-Join Secrecy**: Receives `Welcome` epoch secrets starting strictly at `E+1` (`history_sharing_mode = "none"`) and cannot decrypt epochs `< E+1`. |
| **Removed Group Member** | Possesses local MLS group keys from prior epoch `E` before removal. | **Post-Removal Secrecy**: `Remove` Commit advances the group to `E+1` and rotates TreeKEM direct-path secrets; server simultaneously revokes membership (`403 Forbidden`). Cannot decrypt epochs `>= E+1`. |
| **Network Eavesdropper / Replay Attacker** | Captures TLS/WSS frames or replays previously valid auth challenges or ciphertexts. | Mitigated by TLS/WSS, atomic single-use auth challenges, `message_id` uniqueness (`409`), and Olm/MLS per-message ratchet key deletion. |

### 1.3 Explicit Trust & Environment Assumptions
1. **Endpoint Integrity During Active Use**: E2EE cannot protect plaintext against malware, keyloggers, malicious browser extensions, or compromised OS memory on the sender's or recipient's unlocked device.
2. **Authentic Client Code Delivery**: As a web application, security assumes the browser executes unmodified client JavaScript/WASM bundles served over HTTPS (see Section 11 for web-delivery limitations and Subresource Integrity / transparency mitigations).
3. **Platform CSPRNG & WebCrypto**: Relies on the browser/OS Cryptographically Secure Pseudo-Random Number Generator (`crypto.getRandomValues`) and W3C `SubtleCrypto` implementation.

---

## 2. Cryptographic Protocol Selection (Section B)

No custom encryption algorithms, homemade Diffie-Hellman handshakes, or static shared-secret AES wrappers are used for private or group chats.

| Conversation Scope | Protocol | Maintained Implementation | Cryptographic Primitives |
| :--- | :--- | :--- | :--- |
| **Private 1-to-1 & Multi-Device Chats** | **Olm v2** (Signal 3DH Extended Triple Diffie-Hellman + Double Ratchet, `SessionConfigVersion.V2`) | [`@towns-protocol/vodozemac@0.1.0`](https://github.com/matrix-org/vodozemac) (Matrix Foundation Rust/WASM implementation, audited by Least Authority) + Python [`cryptography>=43.0.0`](https://cryptography.io/) (OpenSSL `Ed25519PublicKey`) on backend | X25519 (Curve25519 ECDH), Ed25519 (device identity signatures), HKDF-SHA256 ratchet KDF, authenticated symmetric encryption per ratchet step, Curve25519 + HKDF Short Authentication Strings (SAS) |
| **Encrypted Group Conversations** | **IETF RFC 9420 Messaging Layer Security (MLS)** (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`) | [`ts-mls@1.6.4`](https://github.com/LukaJCB/ts-mls) + [`@hpke/core@1.9.0`](https://github.com/dajiaji/hpke-js) backed by native WebCrypto (`SubtleCrypto`) | TreeKEM asynchronous ratcheting tree, RFC 9180 HPKE (`DHKEM(X25519, HKDF-SHA256)`), `AES-128-GCM` content AEAD, `SHA-256` transcript & tree hashing, `Ed25519` leaf & `KeyPackage` signatures |
| **Encrypted File Attachments** | **Per-File Ephemeral AEAD + Content-Addressed Digest** | Native W3C WebCrypto (`crypto.subtle`) in [`e2eeAttachmentCrypto.ts`](file:///c:/Users/hp/OneDrive/Desktop/MetaMask_chatonly/frontend/src/services/e2eeAttachmentCrypto.ts) | 256-bit `AES-256-GCM` with 96-bit CSPRNG IV, AAD context binding, and `SHA-256` ciphertext verification prior to decryption; file keys travel exclusively inside Olm v2 or MLS `PrivateMessage` ciphertexts |
| **Global Envelope Channel** | **Multi-Recipient Wrapped Key + Cryptographic Envelope Hash Binding** | [`chatCrypto.ts`](file:///c:/Users/hp/OneDrive/Desktop/MetaMask_chatonly/frontend/src/services/chatCrypto.ts) & [`chat_routes.py`](file:///c:/Users/hp/OneDrive/Desktop/MetaMask_chatonly/backend/chat_routes.py) | Pairwise ECDH-P256 + HKDF key wrapping for registered room participants with single random 256-bit AES-GCM content key. Wallet signature cryptographically binds the complete envelope via a canonical SHA-256 digest |

---

### 2.1 Global Chat Signature Integrity Binding

To prevent tampering with ciphertexts, IVs, or recipient wrappers in transit, the Global Envelope channel implements cryptographic binding over the complete message envelope:

1. **Canonical Representation**: Security-relevant fields (`message_id`, `sender` [normalized lowercase], `channel` / `room`, `timestamp`, `version`, `algorithm`, `key_version`, `content_iv`, `content_ciphertext`, and `recipients`) are assembled into a deterministic canonical structure.
2. **Deterministic Ordering & Duplicate Rejection**:
   - Duplicate recipient addresses are strictly rejected (`HTTP 400`).
   - Recipient wrappers are sorted deterministically in lexicographical order by normalized recipient EVM address.
3. **Canonical SHA-256 Hashing**:
   - The canonical dictionary is serialized using RFC 8785 / JCS sorting (`sort_keys=True, separators=(',', ':')`).
   - A `SHA-256` hash is computed over the canonical UTF-8 bytes.
4. **EIP-191 Wallet Signature**:
   - The exact message verified by the wallet signature binds the hash:
     ```
     zyphra.in Chat Message
     Sender: 0x...
     Message ID: msg_...
     Room: global
     Timestamp: 2026-11-10T...
     Envelope Hash: <sha256_hex>
     ```
5. **Fail-Closed Backend Verification**:
   - The backend independently reconstructs the canonical dictionary and computes the SHA-256 hash.
   - Any tampering with ciphertext, IV, recipient wrappers, or metadata invalidates the recovered wallet address (`HTTP 401 Unauthorized`).
   - Old/unhashed envelopes are rejected with `HTTP 400 Bad Request` requiring a client upgrade.
   - If verification or hashing fails, the message is never stored or broadcast.
6. **Authoritative Server UTC Timestamp & Decoupled Storage**:
   - The signed client timestamp is preserved in `client_timestamp` solely for cryptographic signature verification and clock-skew replay validation (5-minute window).
   - The server independently generates the authoritative UTC timestamp upon insertion (`created_at` / `server_timestamp`).
   - Database queries order messages strictly by the server's creation timestamp (`ORDER BY created_at DESC`), guaranteeing feed ordering is immune to client clock manipulation.
7. **Database Row Creation Detection & Duplicate Handling**:
   - The persistence layer verifies that an `INSERT` statement actually created a row (using `rowcount` in SQLite and `RETURNING message_id` in PostgreSQL).
   - Duplicate message IDs return `HTTP 409 Conflict` (or safely return the original message if `?idempotent=true` and verified exactly identical). Messages are never silently overwritten or reported as delivered if storage failed.
8. **Request Size Limits, Safe Error Handling & Fail-Closed Broadcast**:
   - Chat endpoints enforce a strict 128 KB request body ceiling (`HTTP 413 Payload Too Large`) at the ASGI layer to prevent oversized payload abuse.
   - Database exceptions, table names, and internal tracebacks are strictly suppressed from client responses (`HTTP 500: Unable to save encrypted message`), with detailed stack traces recorded securely in server logs.
   - Storage failures fail closed: WebSocket broadcast (`schedule_public_ws_broadcast`) and success responses are prevented if storage fails.
9. **Frontend Failed-Send Handling & Absolute Plaintext Prohibition**:
   - Messages are never displayed as delivered until server confirmation succeeds.
   - If server rejection or storage failure occurs, messages enter an explicit "message was not sent" UI state with retry capabilities.
   - Retries reuse the original safe encrypted payload if within the 5-minute freshness window, or re-encrypt using fresh keys.
   - If recipient encryption keys are outdated, revoked, or unavailable, transmission is immediately stopped and a key refresh is requested. Plaintext fallback is strictly prohibited.


---

## 3. Complete Cryptographic Key Lifecycle (Section C)

### 3.1 Strict Separation from Wallet Keys & Signatures
- Ethereum wallets (`window.ethereum` / EIP-4361 Sign-In with Ethereum via EIP-191 `personal_sign`) are used **exclusively** for short-lived session authentication challenges (`/api/e2ee/auth/challenge` -> `/api/e2ee/auth/verify`).
- Every authentication challenge explicitly embeds: `Security Notice: Signing this challenge authenticates your session only. Never derive encryption keys from signatures.`
- Device encryption keys are generated independently on-device via CSPRNG and are **never** derived from a wallet address, ETH balance, username, or MetaMask signature.

### 3.2 Generation, Publication, Consumption, Rotation & Deletion
1. **Local Vault Wrapping Key**:
   - [`e2eeVault.ts`](file:///c:/Users/hp/OneDrive/Desktop/MetaMask_chatonly/frontend/src/services/e2eeVault.ts) generates a **non-extractable** (`extractable: false`) 256-bit `AES-256-GCM` `CryptoKey` stored in IndexedDB (`zyphra_e2ee_vault_v2`).
   - Every local secret record (Vodozemac 32-byte `pickleKey`, pickled `Account`, pickled Olm `Session`s, MLS `PrivateKeyPackage`s, encoded MLS `GroupState`, and locally cached decrypted envelopes) is encrypted with a fresh 96-bit CSPRNG IV and Additional Authenticated Data `zyphra-vault-v2|<recordId>`.
   - Private keys, pickle keys, and decrypted message bodies are **never** written to `localStorage` or `sessionStorage`.
2. **Device Identity & Bundle Signing**:
   - [`olmService.ts`](file:///c:/Users/hp/OneDrive/Desktop/MetaMask_chatonly/frontend/src/services/olmService.ts) creates a `Vodozemac.Account` (Ed25519 signing key + Curve25519 identity key), 15 initial One-Time Prekeys (OTKs), and 1 signed Fallback Key.
   - The device signs `zyphra-e2ee-device-v1|<user_id>|<device_id>|<ed25519_key>|<curve25519_key>|<fallback_id>|<fallback_pub>` with its Ed25519 private key.
   - [`e2ee_routes.py`](file:///c:/Users/hp/OneDrive/Desktop/MetaMask_chatonly/backend/e2ee_routes.py) verifies the 64-byte Ed25519 signature via OpenSSL (`Ed25519PublicKey.verify`) and rejects all-zero low-order Curve25519 points before persisting public keys.
3. **One-Time Prekeys (OTKs) & Fallback Keys**:
   - Claiming a peer prekey via `POST /api/e2ee/prekeys/claim` atomically marks one unconsumed OTK `consumed = TRUE` in PostgreSQL (`FOR UPDATE SKIP LOCKED` / atomic transaction) so two concurrent senders never receive the same OTK.
   - Only when all OTKs are exhausted does the server return the signed Fallback Key (`is_fallback = true`).
   - Upon decrypting an inbound PreKey message (`message_type = 0`), Vodozemac deletes the consumed OTK private key from `Account` and re-pickles the updated account into the encrypted vault.
   - Clients automatically replenish OTKs when available count drops below 5 and support signed Fallback Key rotation via `generateMoreOlmPrekeys(..., rotateFallback = true)`.
4. **MLS `KeyPackage`s & Epoch Secrets**:
   - [`mlsGroupService.ts`](file:///c:/Users/hp/OneDrive/Desktop/MetaMask_chatonly/frontend/src/services/mlsGroupService.ts) generates signed RFC 9420 `KeyPackage`s binding `userId|deviceId`.
   - `POST /api/e2ee/mls/key-packages/claim` atomically consumes one `KeyPackage` per active device of the invited user.
   - When the invitee processes a `Welcome` (`joinMlsGroupFromWelcomeB64`), `consumeMlsKeyPackageSecret` immediately deletes the consumed `initPrivateKey`, `hpkePrivateKey`, and `signaturePrivateKey` from the local vault and zeroizes transient `Uint8Array` buffers.
   - Active group members can rotate their own leaf HPKE key and TreeKEM path secrets at any time via `buildMlsSelfKeyRotationCommit` (`Update` Commit).
   - Group commit submissions (`POST /api/e2ee/groups/{group_id}/commits`) enforce group admin authorization on all member additions/removals, verify active committer device status, and validate that added members own active devices and are not blocked.
5. **Device Revocation & Safe Lost-Identity Reset**:
   - Users can revoke any compromised or retired device via `POST /api/e2ee/devices/{device_id}/revoke`. The backend atomically updates `chat_devices.status = 'revoked'`, marks group memberships removed, and purges unconsumed prekeys and pending MLS welcomes.
   - **Safe Lost-Identity Reset**: When executing `POST /api/e2ee/identity/reset`, the server strictly validates that the challenge was signed by an active linked wallet of the user. On the client, existing IndexedDB vault records are preserved until the server confirms successful reset, preventing unrecoverable key loss on network errors or signature failures.
   - Users can force a fresh 3DH handshake with a peer via `resetOlmSessionWithPeerDevice`.

### 3.3 Key Verification & Identity-Change Alerts
- **1-to-1 Verification**: [`SafetyNumberModal`](file:///c:/Users/hp/OneDrive/Desktop/MetaMask_chatonly/frontend/src/components/E2EESecurityModals.tsx) provides a symmetric **60-digit Safety Number** (64-round iterated SHA-512 commitment over `(user_id, ed25519_key, curve25519_key)` for both parties) derived deterministically across primary peer devices, plus interactive **Vodozemac SAS** (Curve25519 Diffie-Hellman + HKDF 3-number decimal code).
- **Group Verification**: [`MlsGroupSecurityModal`](file:///c:/Users/hp/OneDrive/Desktop/MetaMask_chatonly/frontend/src/components/E2EESecurityModals.tsx) exposes the RFC 9420 **`epochAuthenticator`** and **`mlsExporter` context verification code** so members can confirm identical cryptographic group transcripts.
- **Non-Silent Identity Alerts**: [`evaluateAndRecordPeerTrust`](file:///c:/Users/hp/OneDrive/Desktop/MetaMask_chatonly/frontend/src/services/olmService.ts) plus `/api/e2ee/identity/events` detect new peer devices, device revocations, key changes, or lost-key identity resets, automatically clearing `verified` badges and displaying prominent security warnings in [`Chat.tsx`](file:///c:/Users/hp/OneDrive/Desktop/MetaMask_chatonly/frontend/src/components/Chat.tsx).

---

## 4. Permanent `user_id`, Wallet Rotation & Lost Keys (Section D)

1. **Permanent Internal Identifier**: Every user account is anchored to an immutable internal `user_id` (`usr_<24-hex>`). Conversations, group memberships, and trust records reference `user_id`—never a mutable username or wallet address.
2. **Username Changes**: `PATCH /api/e2ee/account/username` updates the human-readable handle without modifying `user_id`, device encryption keys, Olm sessions, or MLS group memberships.
3. **Authenticated Wallet Linking & Replacement**:
   - Changing or linking a new Ethereum wallet (`POST /api/e2ee/account/wallets/link`) requires **both** (a) an active authenticated session for the existing `user_id` and (b) an EIP-191 signature from the new wallet over a `link_wallet` challenge explicitly bound to `Account User ID: usr_...`.
   - An attacker who merely creates a new wallet or claims an unused handle cannot link to or impersonate an existing `user_id`.
   - Legitimate wallet replacement (`revoke_previous_wallets = true`) preserves all encryption keys and conversation history.
4. **Lost All Devices & Private Keys**:
   - Because private decryption keys exist **only** inside local device vaults and are never escrowed on the server, **losing all devices and browser vaults permanently and irrecoverably prevents decryption of prior encrypted messages**.
   - To resume messaging under the same permanent `user_id`, the user must execute `POST /api/e2ee/identity/reset` with `confirm_irrecoverable_history = true` and a signed `reset_lost_identity` challenge. This revokes all lost devices, increments `identity_version`, registers a new verified device bundle, and broadcasts an `identity_reset_lost_keys` alert to conversation peers.

---

## 5. Group Encryption & Concurrency Model (Section E)

- **History Access Policy (`history_sharing_mode = "none"`)**: Adding a member does **not** grant access to prior group messages. Both RFC 9420 MLS key schedule derivation (`Welcome` starts at `epoch = E+1`) and server query filtering (`epoch >= joined_epoch`) enforce strict pre-join secrecy.
- **Member Removal & Rekeying**: Removing a member requires submitting an MLS `Remove` Commit (`commit_type = "remove"`). `ts-mls` blanks the removed member's leaf and rotates all TreeKEM ancestor path secrets along the committer's direct path to produce `epoch = E+1`; the server atomically marks the member `status = 'removed'` inside the same database transaction.
- **Optimistic Epoch Concurrency**: Every Commit and group message carries `expected_epoch` / `epoch`. In [`e2ee_db.py`](file:///c:/Users/hp/OneDrive/Desktop/MetaMask_chatonly/backend/e2ee_db.py), `submit_mls_commit_atomic` locks the group row and verifies `expected_epoch == current_epoch`. If two admins submit simultaneous Commits, the second receives `HTTP 409 Conflict` containing `current_epoch` and `missing_commits`, allowing the client to apply the winning Commit via `processIncomingMlsCommits` before retrying cleanly.
- **Offline Participants**: Pending `Welcome` envelopes are queued per `(user_id, device_id)` in `chat_group_welcomes`, and ordered per-epoch `Commit` messages are retained in `chat_group_commits` so offline devices catch up sequentially upon reconnecting.

---

## 6. Public Room Security Model (Section F)

- The **Global Public Room** (`channel = "global"`) is **intentionally public and non-confidential**.
- Its transport uses HTTPS/WSS and storage encryption at rest, and `GET /api/chat/public-security-model` plus response header `X-Chat-Room-Model: public-non-confidential`, the **`PUBLIC`** room badge, and a persistent UI notice in [`OpenPublicChatView`](file:///c:/Users/hp/OneDrive/Desktop/MetaMask_chatonly/frontend/src/components/PlatformViews.tsx) (embedded in [`Chat.tsx`](file:///c:/Users/hp/OneDrive/Desktop/MetaMask_chatonly/frontend/src/components/Chat.tsx)) explicitly inform users that any participant or moderator in the public directory may read public messages and server-side moderation applies.
- Even where legacy public-room multi-recipient P-256 key wrapping is used on `channel = "global"`, the UI and documentation explicitly clarify that wrapping keys to a public room directory does **not** make a public room confidential, and that genuine E2EE in public rooms limits server-side search, automated abuse detection, and content moderation.
- Non-`global` channels are strictly blocked (`403 Forbidden`) on `/api/chat/messages`.

---

## 7. Metadata Minimization & Server Visibility Inventory (Section G)

### 7.1 Metadata Minimization Controls Implemented
1. **Zero On-Chain Chat Metadata**: Ordinary chat messages, usernames, wallet-to-`user_id` links, contact lists, and group memberships are **never** published to Ethereum.
2. **No Persistent IP or Device Fingerprinting**: Request logging in [`app.py`](file:///c:/Users/hp/OneDrive/Desktop/MetaMask_chatonly/backend/app.py) strips `client_ip:client_port` and URL query strings. Rate limiting in [`e2ee_routes.py`](file:///c:/Users/hp/OneDrive/Desktop/MetaMask_chatonly/backend/e2ee_routes.py) hashes identifiers in memory using a process-ephemeral random 256-bit `BLAKE2b` salt (`_RATE_SALT`).
3. **Coarse Timestamp Bucketing**: All DM messages, group messages, commits, welcomes, identity events, and encrypted attachments store timestamps truncated to **1-minute UTC buckets** (`YYYY-MM-DDTHH:MM:00+00:00`), while monotonic `seq` integers preserve exact message ordering.
4. **Privacy-Controlled Presence & Optional DM Read Receipts**: Real-time `/ws/e2ee` routing uses a transient in-memory map (`E2EERealtimeHub`) that is never persisted to disk, online status visibility is user-controlled (`privacy_show_online`), **administrators are excluded** from all online presence counts and indicators, and 1-to-1 DM read receipts (`chat_dm_receipts`) are strictly opt-in (`privacy_read_receipts`) and never expose message plaintext.

### 7.2 Metadata Remaining Visible to the Server
Because E2EE encrypts content rather than providing mixnet/onion anonymous routing, the server necessarily observes:
- Account `user_id`, chosen `@username` (plus audit `username_history`), linked authentication wallet address(es) (plus `wallet_change_history`), verified ETH balance snapshots, and platform admission payment state (`is_platform_paid`).
- Device IDs (`dev_...`), user-chosen device labels, public identity keys, and unconsumed prekey/KeyPackage counts.
- DM participant pair (`sender_user_id`, `recipient_user_id`, `conversation_id`), 1-minute coarse timestamp bucket, monotonic `seq`, ciphertext size, and opt-in read receipt state.
- Encrypted group metadata (`group_id`, group display name, visibility/level/paid access policy, current `epoch`, active/removed `user_id` membership rows).
- Transient TCP/TLS connection IP addresses in memory at the edge reverse proxy / ASGI socket while a request or WebSocket is active.

---

## 8. Secure Storage, Transport & XSS Controls (Section H)

- **Transport**: Enforces HTTPS (`Strict-Transport-Security` when served over TLS) and authenticated WebSockets (`/ws/e2ee`). Session tokens are never sent in URL query parameters; WebSockets authenticate via `HttpOnly` cookie (`SameSite=Strict` on HTTPS) or a first-frame JSON `{ "type": "auth", "token": "..." }` message.
- **Session Tokens at Rest**: Raw user session tokens (`zys_...`) are held only in client JS memory / `HttpOnly` cookie, and the database stores only `SHA-256(token)`. Standalone `/Admin456` admin console sessions ([`admin_auth.py`](file:///c:/Users/hp/OneDrive/Desktop/MetaMask_chatonly/backend/admin_auth.py)) likewise store only `SHA-256(token)` in server memory (30-min idle / 4-hour absolute TTL) after constant-time credential verification and per-IP/global brute-force lockout checks, and never grant access to E2EE private keys or message plaintexts.
- **Database Encryption at Rest**: Neon PostgreSQL connections enforce TLS (`sslmode=require`) and cloud volume encryption at rest as defense-in-depth (never as a substitute for client-side E2EE).
- **XSS & Browser Hardening**:
  - React JSX automatic escaping (zero `dangerouslySetInnerHTML` in chat views).
  - Strict `Content-Security-Policy` (`default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, and tightened explicit-origin CORS in [`app.py`](file:///c:/Users/hp/OneDrive/Desktop/MetaMask_chatonly/backend/app.py).
- **Log & Error Hygiene**: Custom FastAPI `RequestValidationError`, `HTTPException`, and unhandled exception handlers strip raw `input` payloads and scrub sensitive keys (`private_key`, `seed_phrase`, `pickle_key`, `session_token`, `plaintext`) before logging or returning JSON errors.

---

## 9. Encrypted Attachments & Future Feature Boundaries (Section I)

### 9.1 Encrypted File Attachment Protocol
1. Before upload, [`encryptAttachmentOnDevice`](file:///c:/Users/hp/OneDrive/Desktop/MetaMask_chatonly/frontend/src/services/e2eeAttachmentCrypto.ts) generates a fresh random 256-bit `AES-256-GCM` key and 96-bit IV on-device and encrypts the file with AAD `zyphra-e2ee-attachment-v1|<scopeType>|<fileName>|<mimeType>`.
2. The client computes `SHA-256(ciphertext)` and uploads **only** `(ciphertext_b64, ciphertext_sha256, scope_type, scope_id)` to `POST /api/e2ee/attachments`. The server verifies `SHA-256(ciphertext)` in constant time (`secrets.compare_digest`) and never sees the file name, MIME type, or AES key.
3. The attachment key descriptor `{ attachment_id, key_b64, iv_b64, sha256_hex, file_name, mime_type, size_bytes }` is sent **exclusively inside** the Olm v2 or MLS `PrivateMessage` encrypted envelope.
4. On download (`GET /api/e2ee/attachments/{id}`), the server enforces participant/group membership authorization and revocation state (`410 Gone` if revoked via `POST /api/e2ee/attachments/{id}/revoke`), and the recipient verifies `SHA-256(ciphertext)` in constant time **before** invoking `AES-256-GCM` decryption.

### 9.2 Design Rules for Future Features
- **Message Search**: Must execute strictly against locally decrypted vault indexes on the client device; never ship plaintext search indexes to the server.
- **AI Features**: Any future summarization or assistant feature on private/group chats must run locally on-device or require explicit per-message user opt-in disclosure—never silent server-side decryption.
- **Abuse Reporting / Moderation**: In E2EE chats, moderation relies on user-initiated message franking / voluntary client-side report submission of specific offending messages rather than server wiretapping.
- **Multi-Device History Sync**: Historical messages predating a newly added device must only be transferred via an authenticated device-to-device encrypted backup/export channel verified via SAS/QR—never by storing plaintext or master keys on the server.

---

## 10. Wallet Balances, Payment Qualifications & Membership Independence (Section J)

- Cryptographic identities, local device vaults, and stored ciphertexts are strictly decoupled from Ethereum wallet balances, platform admission paywalls, and group entry fees.
- Wallet balance drops or platform admission status changes **never** delete, corrupt, or block decryption of a user's existing locally stored encrypted messages or local device keys.
- Conversely, holding a high ETH balance, paying the platform admission fee, or qualifying for a paid group **never** grants API or cryptographic access to another user's DMs or to an encrypted group without an explicit MLS `Add` Commit + `Welcome` from an active group member.

---

## 12. Global Public Room Cryptographic Envelope & Strict Schema Validation

Although the Global Public Room is explicitly non-confidential, it enforces strict cryptographic envelope integrity, authentication, and validation controls:

1. **Protocol Version & Fallback**:
   - `version: 1` is strictly enforced.
   - Any message with an unsupported or future version is rejected with HTTP 400/422 and a clear `Client update required: protocol version X is not supported` error, preventing insecure compatibility fallbacks.
2. **Exact Algorithm Identifier**:
   - Strictly validates `algorithm == "ECDH-P256-HKDF-AES-GCM-256"`. Any unknown or mismatched algorithm is rejected.
3. **Key Format Version**:
   - Strictly validates `key_version == 1`.
4. **Base64url Encoding & IV Length Validation**:
   - `content_iv` and all recipient wrapper `iv` fields must be valid base64url strings decoding to **strictly 12 bytes** (96 bits) for AES-GCM.
   - Malformed base64url characters (`+`, `/`, whitespace, newlines, illegal padding) and invalid lengths (`len % 4 == 1`) fail closed with validation errors.
5. **Ciphertext Size Safeguards**:
   - `content_ciphertext` must be valid base64url with a decoded byte length between 16 bytes (AES-GCM 128-bit authentication tag minimum) and 65,536 bytes (64 KB safe payload ceiling).
   - Recipient `wrappedKey` must decode to between 32 and 256 bytes.
6. **Recipient Wrapper & Key Directory Verification**:
   - Recipient addresses must be valid, normalized EVM checksummed addresses.
   - Duplicate recipient addresses are rejected (case-insensitive check).
   - The sender address must be included in the recipient wrappers to guarantee self-decryption capability.
   - For every recipient in the public room, the server queries `chat_db` to confirm:
     - The recipient has an active registered encryption key in the directory (`status == "active"`).
     - The submitted `keyFingerprint` matches the authoritative registered public key fingerprint in the database.
     - Unknown, inactive, or mismatched recipient keys are rejected with HTTP 400.
7. **Canonical Envelope Hashing & EIP-191 Wallet Signature**:
   - Deterministic RFC 8785 canonical JSON serialization of 10 envelope fields sorted lexicographically.
   - EIP-191 wallet signature cryptographically binds the SHA-256 envelope hash.
   - Unhashed legacy envelopes are rejected with an explicit client upgrade error.
8. **Duplicate Insertion & Safe Error Handling**:
   - Database row-creation detection returns HTTP 409 Conflict for duplicate message IDs unless `idempotent=true` and the existing envelope is verified byte-for-byte identical.
   - Database exceptions return a generic safe error (`HTTP 500: Unable to save encrypted message`) without exposing database connection strings, credentials, or internal schema details.


1. **Web Application Asset Delivery Risk**: Unlike compiled mobile/desktop apps pinned via OS app stores and binary transparency logs, a web browser fetches HTML/JS/WASM on load. A compromised hosting origin or CDN could attempt to serve modified JS to exfiltrate keys upon next load. Production deployments should add **Subresource Integrity (SRI)** hashes, immutable CDN artifact signing, or packaged desktop/browser-extension builds.
2. **Browser Same-Origin XSS Surface**: Although local keys use a non-extractable WebCrypto master wrapping key (`extractable: false`) and strict CSP, an active same-origin XSS vulnerability executing inside the unlocked app context could still invoke vault decryption APIs during that session. Strict CSP, dependency auditing, and zero unsafe DOM sinks must be continuously enforced.
3. **Classical Elliptic-Curve Security (Pre-Post-Quantum)**: Both Olm v2 (`X25519` + `Ed25519`) and MLS ciphersuite `0x0001` (`DHKEM(X25519)`) rely on classical elliptic curves rather than hybrid post-quantum KEMs (such as Signal's PQXDH/SPQR or MLS `X-Wing` hybrid ciphersuites). Migrating to hybrid PQ ciphersuites is recommended as standardized browser/WASM support matures.
4. **Group Metadata Visibility**: The server stores the MLS group membership roster (`user_id`s) to enforce delivery authorization and block unauthorized ciphertext scraping; anonymous/sealed-sender delivery and MLS `PublicMessage` metadata hiding (`PrivateMessage` is used for messages, while membership roster is server-tracked) remain subject to traffic analysis by a global network observer.
5. **Independent Security Review Required**: Automated unit and integration tests (`frontend/tests/*.node.test.ts` — 43 tests; `backend/test_*.py` — 132 tests including `test_chat_e2ee.py`, `test_e2ee_security.py`, `test_platform_features.py`, and `test_admin_login.py`) verify protocol wiring and access controls, but **do not replace an independent cryptographic and penetration audit**. Do not advertise formal audit equivalence until such a review is completed and remediated.

