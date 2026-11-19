# Zyphra.in System Documentation

Welcome to the system documentation for **Zyphra.in** — an **Ethereum Wallet-Linked Real-Time Chat Platform** combining **EIP-4361 Sign-In with Ethereum (SIWE)**, **permanent internal `user_id` accounts**, **an Admin-controlled Ethereum platform admission paywall with USD conversion**, **paid groups**, **server-verified on-chain payments**, **clean Paid Member status**, **Open Public Chat**, **Olm v2 Double Ratchet Private Chat**, and **RFC 9420 MLS Encrypted Group Chat** backed by **Neon PostgreSQL**.

---

## Documentation Index

| Section | Document | Description |
| :--- | :--- | :--- |
| **Security & Crypto** | [High-Security E2EE Architecture](e2ee-security-architecture.md) | Threat model, Olm v2 & RFC 9420 MLS protocol specifications, key lifecycle, vault storage, and limitations |
| **System Overview** | [System Architecture](system-architecture.md) | Component topology, permanent `user_id` & wallet rotation flow, live ETH/USD oracle, support threads, and schema overview (`001`–`008`) |
| **System Overview** | [System & User Workflows](workflows.md) | Step-by-step sequence diagrams for Welcome Gate/SIWE login, wallet migration, on-chain payments, Talk to Admin support, Open Chat, Olm DMs & MLS Groups |
| **System Overview** | [Platform Feature Catalog](features.md) | Complete feature breakdown across Welcome Gate/Splash, `Chats`, `/payments`, `/support` ("Talk to Admin"), `/settings`, `Profile`, and `/Admin456` RBAC console |
| **Backend System** | [Backend Architecture](backend/architecture.md) | FastAPI + WebSocket architecture, Neon PostgreSQL pool resilience, live ETH/USD oracle, `support_db`, Ethereum RPC verifier, `/Admin456` login guard, and migration runner |
| **Backend System** | [Backend API Reference](backend/api-reference.md) | Complete REST & WebSocket endpoint reference (`/api/e2ee/*`, `/api/platform/*`, `/api/platform/support/*`, `/api/platform/admin/*`, `/ws/e2ee`, `/ws/public-chat`, `/ws/member-presence`) |
| **Backend System** | [Backend Environment Variables](backend/environment-variables.md) | `.env` configuration guide, pricing/oracle settings, DB pool tuning, read-only RPC providers (`RPC_URL_*`), `/Admin456` credentials, and RBAC settings |
| **Frontend System** | [Frontend Architecture](frontend/architecture.md) | React 19 + TypeScript + Vite SPA routing (`/`, `/payments`, `/support`, `/settings`, `/Admin456`), Welcome Gate/Splash, Header & Profile UI, resilientFetch, Web3 SIWE client, and E2EE service layer |
| **Frontend System** | [Design System & Aesthetics](frontend/design-system.md) | Dark/Light cyber-console design tokens, `1 in 10,000` DotField welcome canvas, responsive layout breakpoints, and accessibility |
| **Frontend System** | [Frontend Environment Variables](frontend/environment-variables.md) | Client `.env` configuration, test/lint/build commands, and SPA deployment |
