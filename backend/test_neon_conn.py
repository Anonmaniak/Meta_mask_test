"""
Verification script for Neon DB connection and schema initialization.
"""
import os
import sys
from dotenv import load_dotenv

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

def main():
    load_dotenv()

    neon_url = (
        os.getenv("NEON_DATABASE_URL")
        or os.getenv("DATABASE_URL")
        or os.getenv("POSTGRES_URL")
    )

    if not neon_url:
        print("❌ NEON_DATABASE_URL not found in environment!")
        sys.exit(1)

    # Mask password for safe display
    masked_url = neon_url
    if "@" in neon_url:
        creds, rest = neon_url.split("@", 1)
        if ":" in creds:
            prefix, user_pass = creds.split("://", 1)
            user = user_pass.split(":")[0]
            masked_url = f"{prefix}://{user}:****@{rest}"

    print(f"Connecting to Neon DB: {masked_url}...")

    import psycopg2
    from psycopg2 import pool, extras

    try:
        conn = psycopg2.connect(neon_url, sslmode="require")
        cur = conn.cursor()
        cur.execute("SELECT version();")
        ver = cur.fetchone()
        print("✅ Successfully connected to Neon PostgreSQL!")
        print(f"   PostgreSQL version: {ver[0] if ver else 'Unknown'}")

        # Test schema initialization via chat_db
        import chat_db
        chat_db.init_chat_db()
        print("✅ Chat database tables and indexes initialized successfully!")

        # Verify tables
        cur.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name IN ('chat_messages', 'chat_public_keys', 'chat_key_challenges');
        """)
        tables = [r[0] for r in cur.fetchall()]
        print(f"   Found tables in neondb: {tables}")

        cur.close()
        conn.close()
        print("🎉 Neon DB is completely configured and ready for Chat!")
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
