"""
Version-controlled SQL Migration Runner for Zyphra Chat Platform.

Usage:
    python run_migrations.py

Applies all pending `migrations/*.sql` files against `NEON_DATABASE_URL` (PostgreSQL),
or initializes the local SQLite fallback schema when running in offline development mode.
"""

import os
import sys
import glob

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import chat_db
import e2ee_db
import platform_db


def run_all_migrations() -> None:
    chat_db.init_chat_db()
    e2ee_db.ensure_e2ee_tables()
    platform_db.ensure_platform_tables()

    if not e2ee_db._is_pg():
        print("[OK] Local SQLite schema initialized with all chat, E2EE, and platform tables.")
        return

    mig_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "migrations")
    sql_files = sorted(glob.glob(os.path.join(mig_dir, "*.sql")))

    conn = chat_db._pg_pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version VARCHAR(64) PRIMARY KEY,
                    applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()

            for filepath in sql_files:
                version = os.path.basename(filepath)
                cur.execute(
                    "SELECT 1 FROM schema_migrations WHERE version = %s;",
                    (version,),
                )
                if cur.fetchone():
                    print(f"[SKIP] Migration already applied: {version}")
                    continue

                with open(filepath, "r", encoding="utf-8") as f:
                    sql_text = f.read()

                cur.execute(sql_text)
                cur.execute(
                    "INSERT INTO schema_migrations (version) VALUES (%s);",
                    (version,),
                )
                conn.commit()
                print(f"[APPLIED] {version}")
    except Exception:
        conn.rollback()
        raise
    finally:
        chat_db._pg_pool.putconn(conn)

    platform_db.seed_default_settings()
    print("[OK] All PostgreSQL migrations applied and default settings seeded.")


if __name__ == "__main__":
    run_all_migrations()

