# Frontend Environment Variables & Build Guide

Location: `frontend/.env` (template at `frontend/.env.example`)

---

## 1. Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `VITE_BACKEND_URL` | `http://localhost:10000/api` (dev) or `/api` (same-origin) | Base URL for the FastAPI chat backend (`/api` and WebSocket `/ws/*` derivation). |

### Sample `frontend/.env.example`
```ini
# Zyphra.in Chat Platform — Frontend Configuration
VITE_BACKEND_URL=http://localhost:10000/api
```

---

## 2. Build, Test & Lint Commands

Run inside `frontend/`:

| Command | Purpose |
| :--- | :--- |
| `npm run dev` | Starts Vite development server (default `http://localhost:5173`, or next free port such as `5175`) with `/api` and `/ws` proxy to `localhost:10000`. Backend CORS regex allows all `localhost`/`127.0.0.1`/`[::1]` ports. |
| `npm test` | Runs all 43 Node.js unit & cryptographic protocol tests across 5 suites (`tests/*.node.test.ts`). |
| `npm run lint` | Runs `oxlint` static analysis across `src/`. |
| `npm run build` | Type-checks (`tsc -b`) and builds production assets into `frontend/dist/`. |
| `npm run preview` | Serves `frontend/dist/` locally for pre-deployment verification. |

---

## 3. SPA Routing & Deployment Notes (`frontend/vercel.json`)

- **Client-Side Routes**: `frontend/vercel.json` configures `{ "source": "/(.*)", "destination": "/index.html" }` so direct visits and browser refreshes on `/`, `/settings`, `/payments`, `/support`, and `/Admin456` resolve cleanly to the SPA entrypoint.
- **Zero Client Secrets**: Never place `ADMIN_LOGIN_ID`, `ADMIN_LOGIN_PASSWORD`, or `ADMIN_TOKEN` inside `frontend/.env` (`VITE_*` variables are statically embedded in public JavaScript bundles). Admin credentials live exclusively in `backend/.env` / server environment variables.
