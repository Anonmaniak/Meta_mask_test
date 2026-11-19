# Frontend Design System & Aesthetics

## 1. Design Philosophy: Cyber-Monolithic Chat Console

The visual architecture of **Zyphra.in** pairs high-contrast monochromatic dark/light surfaces with clear cryptographic trust and wallet-level indicators:
- **Minimalist Brand Monolith**: Clean `[Z] zyphra.in` header mark with zero clutter or subtitle noise.
- **Dual Theme Support (`dark` / `light`)**: Controlled via `[data-theme="dark"]` and `[data-theme="light"]` CSS custom properties in `frontend/src/index.css`.
- **Clear Security Mode Distinction Inside the Unified Chat Console**:
  - **Left Channel Rail**: Places **Open Chat** (default) directly above **Private Chats** and **Encrypted Groups**, with the rail header labeled `Chats` and clean jargon-free channel titles.
  - **Open Public Chat**: Displays a concise **`PUBLIC`** header badge alongside an explicit non-confidential/moderated disclosure banner (with redundant header buttons like manual Refresh and secondary Connect Wallet removed) so users never confuse public chat with E2EE rooms.
  - **Private & Group E2EE Views**: Surface verified lock badges, 60-digit Safety Number status, MLS `epoch` counters, and prominent alerts whenever peer device keys change.
- **Verified Membership Badges**: Every user pill displays `@username` alongside their clean **Paid Member** or **Member** badge.

---

## 2. Core Theme Tokens (`frontend/src/index.css`)

```css
:root,
[data-theme="dark"] {
  --bg-page: #000000;
  --bg-surface: #070707;
  --bg-card: #0c0c0c;
  --bg-card-hover: #141414;
  --bg-input: #050505;
  --bg-pill: #161616;
  --bg-pill-active: #ffffff;
  --border-subtle: #1c1c1c;
  --border-strong: #2f2f2f;
  --text-main: #ffffff;
  --text-secondary: #909090;
  --text-muted: #555555;
  --text-inverse: #000000;
}

[data-theme="light"] {
  --bg-page: #f9f9fa;
  --bg-surface: #f3f3f5;
  --bg-card: #ffffff;
  --bg-card-hover: #f5f5f7;
  --bg-input: #ffffff;
  --bg-pill: #ececed;
  --bg-pill-active: #000000;
  --border-subtle: #e4e4e7;
  --border-strong: #d1d1d6;
  --text-main: #000000;
  --text-secondary: #52525b;
  --text-muted: #a1a1aa;
  --text-inverse: #ffffff;
}
```

---

## 3. Responsive Layout & Motion Accessibility

- **Top Navigation Bar & Dedicated Routes**: Center pill navigation (`Chats` at `/`, `Payments` at `/payments`, `Support` at `/support` with unread badge), a top-right circular **Theme Toggle** (`.theme-toggle-btn`, shown both when connected next to `Settings` and when disconnected next to `Connect MetaMask`), a `Settings` button opening `/settings` (with fixed active hover contrast via `.topbar-settings-btn.active:hover` and properly padded sub-tabs: Wallet & Membership, Privacy & Security, Blocked Accounts), plus `Connect MetaMask` which becomes a connected account pill (avatar, `@username`, `Paid Member` / `Member`; text hidden below `640px`). Its streamlined dropdown contains only the clickable profile header (`View & Edit Profile →`) and `Disconnect Wallet` (with legacy Membership Status labels, Profile/Settings quick buttons, theme toggle, and network switcher removed). Before entering (`!accessEntered`), `WelcomeGate` renders over the `DotField` canvas (`1 in 10,000` / `Welcome to Zyphra.in` / `For 1% of 1%`) with zero page overflow, accompanied by a one-time `WelcomeSplash` reveal on the first visit; `/Admin456` renders a standalone login-gated 7-tab Admin Console (`noindex, nofollow`) with 5-second auto-polling, `Username change Hrs`, and the `Active Ethereum Network` segmented toggle (`Ethereum Mainnet (1)` / `Sepolia Testnet (11155111)`).
- **No Page Scrollbar on Desktop**: The app shell fills the viewport (`height: 100%; overflow: hidden`) on laptop/desktop; panes scroll internally. Tablet/mobile use a slide-out channel rail.
- **Wallet-Gated Composer**: Open Public Chat access and posting require a connected Paid Member; no quick-emoji bar or manual refresh control.
- **Two-Pane Unified Chat Workspace**: Left channel/conversation/group sidebar (`290px` on desktop) adapts cleanly on mobile screens while preserving quick access to **Open Chat**, Safety Numbers, MLS Group Policies, and attachment controls.
- **Reduced Motion Compliance**: `@media (prefers-reduced-motion: reduce)` and `WelcomeSplash` (`REDUCED_MOTION_TOTAL_MS`) shorten or disable non-essential animations automatically.

---

## 4. Message Bubble Components & Animation Tokens

The chat workspace implements a modern message bubble hierarchy with fluid physics:

- **Bubble Tokens & Layout**:
  - `.chat-message-row`: Full-width flex container aligned left (peer messages) or right (`.row-me` for authenticated sender).
  - `.chat-avatar`: Rounded-full monogram avatar displaying initials or icon, with gradient backgrounds.
  - `.chat-packet`: Content block grouping header, bubble, and inline status.
  - `.chat-message-bubble`: Padded speech bubble with distinct incoming (`.bubble-peer`: subtle border, elevated card background) and outgoing (`.bubble-me`: solid contrasting primary surface) styling.
- **Fluid Animation System**:
  - `@keyframes chatMsgEntrance`: Smooth vertical translation (`translateY(6px) -> translateY(0)`) combined with opacity ramp and spring easing (`cubic-bezier(0.16, 1, 0.3, 1)`).
  - `@keyframes msgSendingPulse`: Subtly pulses unconfirmed optimistic messages until delivery confirmation arrives from the server or WebSocket broadcast.
  - `.chat-action-cluster`: Floating utility cluster (copy, edit, delete, reply) appearing smoothly on hover with zero layout shift.
  - `scroll-behavior: smooth`: Auto-scrolls gracefully to the latest message on submission.
- **Pure Handle Presentation**: Display names and legacy level badges have been eliminated in favor of verified `@username` handles and clean `Paid Member` / `Member` status, preventing identity spoofing across all public and private channels.
