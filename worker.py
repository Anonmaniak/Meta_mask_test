"""Dedicated worker entrypoint.

Recommended Render setup:
- Web Service: python app.py (RUN_MONITOR=0)
- Background Worker: python worker.py (same env vars)

This avoids Render web-service sleeping stopping your monitor.
"""

from app import monitor_transactions


if __name__ == '__main__':
    monitor_transactions()
