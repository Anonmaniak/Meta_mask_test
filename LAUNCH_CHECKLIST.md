# Zyphra launch checklist

Work top to bottom. Items marked **(blocker)** stop the app from working, or lose data, if skipped.

## 1. Code into GitHub (blocker)
Render builds from GitHub `main`. At scan time the repository's last commit was the first platform push;
70 modified, 50 new and 17 deleted files were not committed. New files the server imports include
`backend/chat_features_db.py`, `read_markers_db.py`, `public_attachments_db.py`, `capacity.py` and
`backend/migrations/009` to `015`. Pushing only the changed files makes the server crash at start.
- `git add -A` then check `git status` lists **no** `.env` and no `*.sqlite3` (both are ignored), commit, push.

## 2. Secrets (blocker)
The project zip has contained `backend/.env` with real values (database password, admin password, RPC keys).
- Rotate the Neon database password, set a new `ADMIN_LOGIN_PASSWORD` (`python backend/generate_admin_credentials.py`), regenerate paid RPC keys.
- Never zip or share `.env` again.

## 3. Render (backend)
- Environment: `NEON_DATABASE_URL` (Neon pooled URL), `FRONTEND_URL` (every site address, comma-separated,
  e.g. `https://zyphra.in,https://www.zyphra.in`), `RPC_URL_MAINNET` (+ `RPC_URL_MAINNET_FALLBACK`),
  `ADMIN_WALLET_ADDRESSES`, `ADMIN_LOGIN_ID`, `ADMIN_LOGIN_PASSWORD`. Do **not** set `ENABLE_API_DOCS`,
  `ALLOW_SQLITE_FALLBACK` or `TESTING`.
- New safety: on Render the server now **refuses to start** without a reachable PostgreSQL (it used to fall
  back to a local file that Render wipes on every deploy). A failed deploy here means: fix the database URL.
- Plan: the free plan sleeps after 15 minutes without traffic and restarts often; first visitors then wait
  30 to 60 s. For paying members use at least the Starter plan (single instance; do not add workers or
  instances, real-time and caches run in one process).
- Check `https://<service>.onrender.com/api/health?deep=1`: `"storage": "postgresql"`, `"database": "ok"`.

## 4. Vercel (frontend) (blocker)
- Set `VITE_BACKEND_URL=https://<service>.onrender.com/api`, then redeploy. The build now **stops** if it is
  missing (the app would otherwise call its own site and fail for everyone).

## 5. Admin456 settings before taking money (blocker)
- Platform Settings: **Treasury Destination Address** (your wallet), **Active network: Ethereum Mainnet**
  (default is Sepolia testnet), monthly / yearly prices. The server log prints `[CONFIG]` lines until done.
- Make one small real payment yourself and confirm it verifies.

## 6. Keep-alive
- GitHub repo secret `RENDER_BACKEND_HEALTH_URL` = `https://<service>.onrender.com/api/health` (the
  workflow pings every 5 minutes; GitHub may delay or pause scheduled runs, so do not rely on it alone).

## 7. Before announcing
- Terms of Service, Privacy Policy and refund policy pages (none exist in the app yet; you take payments).
- Two-account staging run: sign in, pay, DM, group add + Accept, reactions, edit, delete, poll, pin,
  timer, announcement mode, mute, typing, room mentions, admin banner, free access.
- Neon: confirm backups / point-in-time restore on your plan.
