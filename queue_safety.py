"""
queue_safety.py
---------------
Additive helper module for the transaction forwarding queue.
Does NOT modify app.py or worker.py automatically — import and wire
these functions in manually where noted, after reviewing them.

Requires: a pymongo database handle (same one used by app.py / _get_db()).
"""

import os
import threading
from datetime import datetime, timedelta, timezone
from pymongo import ReturnDocument

WORKER_ID = os.getenv("RENDER_SERVICE_ID", "transaction-monitor")
LEASE_MINUTES = 3

_fwd_queue_lock = threading.Lock()


def hydrate_queue(db, fwd_queue: list) -> int:
    """
    Call once at worker startup (after RUN_MONITOR check, before
    starting the sender loop). Reloads any transactions left in
    'queued' or 'refunding_queued' status after a restart/redeploy,
    so they don't wait out the STUCK_QUEUED_TIMEOUT.

    Returns the number of jobs restored.
    """
    restored = 0
    docs = db.transactiondb.find(
        {"status": {"$in": ["queued", "refunding_queued"]}}
    ).sort("serial_number", 1)

    with _fwd_queue_lock:
        existing_hashes = {j.get("tx_hash") for j in fwd_queue}
        for doc in docs:
            if doc.get("tx_hash") in existing_hashes:
                continue
            fwd_queue.append(doc)
            existing_hashes.add(doc.get("tx_hash"))
            restored += 1
        fwd_queue.sort(key=lambda j: j.get("serial_number", 0))

    return restored


def queue_push_safe(fwd_queue: list, job: dict) -> bool:
    """
    Drop-in replacement for queue_push() that rejects a job if a
    job with the same tx_hash is already in the in-memory queue.
    This is a LOCAL guard only — it does not replace the database
    atomic claim below, which is required for cross-process safety.
    """
    tx_hash = job.get("tx_hash")

    with _fwd_queue_lock:
        if any(j.get("tx_hash") == tx_hash for j in fwd_queue):
            return False
        fwd_queue.append(job)
        fwd_queue.sort(key=lambda j: j.get("serial_number", 0))
        return True


def claim_forward_job(db, tx_hash: str):
    """
    Atomically transitions a transaction from 'queued' to 'forwarding'
    and stamps ownership + a lease expiry. Only the caller that
    receives a non-None result may sign and broadcast the forward
    transaction. All other callers (other workers, restarted
    processes, re-hydrated duplicates) must skip the job silently.

    Call this immediately before building/signing the forward tx —
    do NOT sign or send anything until this returns a document.
    """
    now = datetime.now(timezone.utc)
    lease_until = now + timedelta(minutes=LEASE_MINUTES)

    return db.transactiondb.find_one_and_update(
        {"_id": tx_hash, "status": "queued"},
        {
            "$set": {
                "status": "forwarding",
                "worker_id": WORKER_ID,
                "claimed_at": now.isoformat(),
                "lease_until": lease_until.isoformat(),
            },
            "$inc": {"queue_attempts": 1},
        },
        return_document=ReturnDocument.AFTER,
    )


def release_expired_lease(db, tx_hash: str) -> bool:
    """
    Recovery helper: if a worker died mid-forward without ever
    persisting a forward_tx_hash, and its lease has expired, this
    reverts the record back to 'queued' so another worker (or the
    same one after restart) can safely reclaim it via
    claim_forward_job(). Only call this AFTER confirming on-chain
    that no forward transaction was actually broadcast for this
    nonce/tx_hash.
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    result = db.transactiondb.find_one_and_update(
        {
            "_id": tx_hash,
            "status": "forwarding",
            "lease_until": {"$lt": now_iso},
            "forward_tx_hash": {"$in": [None, ""]},
        },
        {"$set": {"status": "queued"}},
        return_document=ReturnDocument.AFTER,
    )
    return result is not None
