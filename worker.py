# worker.py — Render background worker
# Runs monitor_transactions() forever — polls every POLL_INTERVAL seconds
# Handles: pending -> verified -> queued -> forwarding_pending -> complete
#          and all refund steps
#
# Safety patch (2026-08-30): before the monitor starts, this file:
#   1. Hydrates any 'queued' / 'refunding_queued' jobs left in MongoDB
#      after a restart back into the in-memory forward queue, so they
#      don't sit idle for STUCK_QUEUED_TIMEOUT before being rescued.
#   2. Wraps queue_push() with a tx_hash dedupe guard so the same job
#      can never be queued twice in this process's memory.
#   3. Wraps _process_queue_job() so a 'forward' job can only be signed
#      and broadcast after it wins an atomic MongoDB claim
#      (status queued -> forwarding). This prevents a duplicate /
#      double-spend forward if the same job is ever queued twice
#      (restart races, anti-stuck rescues, overlapping deploys, etc).
#
# app.py itself is intentionally left untouched by this patch — we
# don't have full visibility into its complete source, so instead of
# guessing a rewrite, we patch the two specific unsafe call sites from
# the outside using normal Python module-attribute assignment.
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import app as _app
from queue_safety import hydrate_queue, queue_push_safe, claim_forward_job

_original_process_queue_job = _app._process_queue_job


def _safe_process_queue_job(job):
    if job.get('type') == 'forward':
        try:
            db = _app._get_db()
            claimed = claim_forward_job(db, job['tx_hash'])
        except Exception as e:
            print(f"WARNING: claim_forward_job check failed, skipping job for safety: {e}")
            return
        if not claimed:
            print(f"SKIP: forward job already claimed or no longer queued: {job['tx_hash'][:10]}")
            return
    _original_process_queue_job(job)


def _safe_queue_push(job):
    return queue_push_safe(_app._fwd_queue, job)


_app._process_queue_job = _safe_process_queue_job
_app.queue_push = _safe_queue_push

if __name__ == '__main__':
    print('Transaction monitor worker starting...')
    try:
        db = _app._get_db()
        restored = hydrate_queue(db, _app._fwd_queue)
        print(f"Hydrated {restored} queued job(s) from MongoDB after restart")
    except Exception as e:
        print(f"WARNING: queue hydration skipped: {e}")
    _app.monitor_transactions()   # blocks forever
