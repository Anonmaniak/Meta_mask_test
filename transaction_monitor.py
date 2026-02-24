"""Transaction monitor entrypoint.

IMPORTANT:
- This project stores transactions in data/transactions.json as a JSON dict keyed by escrow tx_hash.
- The source of truth and monitor logic live in app.py.

This file intentionally delegates to app.monitor_transactions() so that a Render Background Worker
and the Render Web Service always use the exact same schema and logic.
"""

from app import monitor_transactions


if __name__ == '__main__':
    monitor_transactions()
