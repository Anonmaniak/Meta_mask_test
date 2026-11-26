# Zyphra capacity: what to expect, and what to do when you upgrade

## The short answer

| Render plan | CPU / memory | Online users the server allows | Notes |
|---|---|---|---|
| Free | 0.1 CPU, 512 MB | 200 (built for your first 100) | Sleeps after 15 minutes without traffic |
| Starter ($7) | 0.5 CPU, 512 MB | about 600 | Memory is the limit |
| **Standard ($25)** | 1 CPU, 2 GB | **2,000** | The plan for your 2,000-user target |
| Pro and above | 2+ CPU, 4+ GB | still 2,000 | See "Beyond 2,000" below |

"Online user" means a signed-in person with the app open. Each one holds three live connections.

**When you upgrade the plan you do not change any code.** After Render restarts the service, the server reads its new CPU and memory limits, raises the user limit by itself, and gives the database a bigger connection pool (10 up to 20 once the limit reaches 1,000).

## After every plan change: one check (30 seconds)

Open `https://<your-backend>/api/health` and read the `realtime` block:

```
"max_online_users": 2000,
"capacity_source": "detected from container limits (limited by CPU)",
"detected_cpu_cores": 1.0,
"detected_memory_mb": 2048
```

If `capacity_source` says **"limits not detected"**, Render did not expose its limits to the server. Nothing is broken. The server uses a safe limit of 300 until you tell it the plan size: in Render, Environment, add
`MAX_ONLINE_USERS` with the number from the table above (200, 600 or 2000), and restart.

## What happens when the server is full

New people still sign in and can read and send messages. Live updates pause for them: the app retries every 20 to 60 seconds, and Open Chat refreshes itself every 10 seconds meanwhile. Nobody is dropped, and the server is protected from running out of memory.

## What I measured (your code, real PostgreSQL, one CPU core)

Each simulated user held all three live connections. "Expected" figures are extrapolated from the measured 300 and 600 runs, not measured.

| Online users | Time to connect everyone, before | after | Server CPU used, before | after |
|---|---|---|---|---|
| 300 | 14 s | 4.6 s | 7.2 s | 1.6 s |
| 600 | 51 s | 8.7 s | 26 s | 3.1 s |
| 1,000 | not run (about 150 s expected) | 14 s | about 75 s expected | 5.3 s |
| 2,000 | not run (over 10 minutes expected) | 29 s | about 300 s expected | 11 s |

At 2,000 users every message reached all 2,000 people: median wait 99 ms, last person 226 ms on average, using 11% of one core at one message per second. Memory was about 1 GB (about 430 KB per user).

Before the fix, the cost of connecting grew with the square of the crowd, so the server would have stalled at roughly 1,000 to 2,000 users. It now grows in a straight line.

## Two things that decide real-world speed

1. **Where your database is.** Your Neon database is in `ap-southeast-1` (Singapore), but `render.yaml` says Render's `oregon`. If your live service really runs in Oregon, every database call crosses the Pacific (typically well over 100 ms each, not measured here). Saving one message takes about 6 database calls, so message saving would crawl at that distance. Put the Render service and Neon in the **same region** (for example, create the Render service in Singapore). This matters more for 2,000 users than the plan itself.
2. **Message-saving speed** is about: (database connections) divided by (6 calls x round-trip time). Same-region (about 5 ms): hundreds of messages per second. 150 ms away: only about 10 to 20 per second in total.

## Beyond 2,000 users

Paying for a bigger plan will not raise the limit past about 2,000 to 3,000. The live part of the app runs in one Python process, which uses one CPU core however large the plan is, and it keeps its connections in that process's memory, so you cannot simply run two copies. Going to 10,000 online users needs a code change (several servers sharing a message bus such as Redis). That is a separate project, and I'd suggest starting it only once you pass about 1,500 online users.

## Settings you can change without touching code (Render, Environment)

| Setting | Default | Meaning |
|---|---|---|
| `MAX_ONLINE_USERS` | automatic | Fixed user limit. `0` turns the limit off (not recommended) |
| `DB_POOL_MAX` | 10, or 20 on big plans | Database connections kept ready (Neon allows about 100) |
| `CAP_USERS_PER_CPU` | 2000 | Users one full CPU core serves; lower it if the server feels slow |
| `PAYMENT_PRICE_TOLERANCE_PCT` | 5 | Allowed ETH price movement while paying |

## Measured: 100 members polling (Nov 2026)

Every signed-in member's app asks the server for updates about 4 times every 4.5 seconds (private chats, groups, welcome messages, account), about 1 request per second per member, on top of the live connections. `backend/loadtest_polling.py` simulates that against a real running server (it only ever uses a temporary in-memory database, never your real one):

| Members | Requests per second | Response time: median / 95th / 99th | Server CPU | Memory |
|---|---|---|---|---|
| 100 | 72 to 77 | 4 ms / 11 to 14 ms / 21 to 28 ms | 8 to 9% of one core | 110 MB |
| 300 | 228 | 8 ms / 35 ms / 83 ms | 22% of one core | 113 MB |

No request failed. The test machine had one core shared with the test client, and the database was local, so this is the Python app's own cost only: about 1 ms of CPU per request. Run it again after any big change: `cd backend && python loadtest_polling.py`.

**What this does not include, and what decides real speed:**
1. **Distance to the database.** Each request makes a few database calls. Assuming 3 calls per request and 10 database connections, the server can handle about 10 / (3 x round-trip time) requests per second: about 660 per second at 5 ms (same region), but only about 22 per second at 150 ms (Oregon to Singapore). 100 members need about 75 per second, so across the ocean requests would queue for seconds. This is an estimate from that assumption, not a measurement. Keep Render and Neon in the same region.
2. **Render plan CPU.** 100 members use about 8 to 9% of a full core on the test machine. The Free plan gives 0.1 of a CPU, so it would be at its limit, and it also sleeps after 15 minutes without traffic (the first person waits for it to wake up). Starter ($7, 0.5 CPU) or higher is the safe choice for 100 members.
3. **One log line per request.** The server prints a line for every request; at 75 requests per second that is about 6.5 million lines a day. Check your Render log limits.

