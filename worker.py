# worker.py — Render background worker
# Runs monitor_transactions() forever — polls every POLL_INTERVAL seconds
# Handles: pending → verified → queued → forwarding_pending → complete
#          and all refund steps
import os
import sys

# ── ensure app.py can be imported cleanly ──────────────────────
sys.path.insert(0, os.path.dirname(__file__))

from app import monitor_transactions

if __name__ == '__main__':
    print('🤖 Transaction monitor worker starting...')
    monitor_transactions()   # blocks forever
