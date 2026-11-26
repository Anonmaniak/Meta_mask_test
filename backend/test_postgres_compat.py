"""
PostgreSQL-only behaviour that the SQLite test database cannot show.

- Settings: the JSONB column comes back from psycopg2 already decoded, so a text setting (the payout
  address) is a plain str. It used to be JSON-decoded a second time, which turned every text setting
  into None on PostgreSQL and made payment verification always fail closed.
- audit_logs.entity_id must fit a 66-character transaction hash (it was VARCHAR(64)).
- Both migrations run at start-up on PostgreSQL.
"""
import os
import sys
import unittest

os.environ["TESTING"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import platform_db

HERE = os.path.dirname(os.path.abspath(__file__))


class TestPostgresCompat(unittest.TestCase):
    def test_pg_settings_are_used_as_psycopg2_decoded_them(self):
        addr = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
        self.assertEqual(platform_db._pg_setting_value(addr), addr)  # was None before the fix
        self.assertEqual(platform_db._pg_setting_value("10.0"), "10.0")  # same as SQLite returns
        self.assertIs(platform_db._pg_setting_value(False), False)
        self.assertEqual(platform_db._pg_setting_value(11155111), 11155111)
        self.assertIsNone(platform_db._pg_setting_value(None))
        self.assertEqual(platform_db._pg_setting_value({"a": 1}), {"a": 1})
        # A driver that returns raw JSON text instead is still decoded
        self.assertEqual(platform_db._pg_setting_value(b'"%s"' % addr.encode()), addr)

    def test_old_double_decode_was_the_bug(self):
        # What the old code did with a psycopg2-decoded address: it lost it.
        self.assertIsNone(platform_db._jload("0x71C7656EC7ab88b098defB751B7401B5f6d8976F", None))

    def test_payout_address_round_trips_like_on_sqlite(self):
        # The SQLite path (text JSON) and the PostgreSQL path (decoded value) agree for every type written.
        import json
        for value in ("0x71C7656EC7ab88b098defB751B7401B5f6d8976F", "12.5", True, 1, None, 2500.0):
            sqlite_side = platform_db._jload(json.dumps(value), None)
            pg_side = platform_db._pg_setting_value(json.loads(json.dumps(value)))
            self.assertEqual(sqlite_side, pg_side, value)

    def test_startup_runs_the_new_postgres_migrations(self):
        src = open(os.path.join(HERE, "platform_db.py"), encoding="utf-8").read()
        for name in ("014_access_grants.sql", "015_audit_entity_id_length.sql"):
            self.assertIn(f'"{name}"', src)
            self.assertTrue(os.path.exists(os.path.join(HERE, "migrations", name)), name)
        sql = open(os.path.join(HERE, "migrations", "015_audit_entity_id_length.sql"), encoding="utf-8").read()
        self.assertIn("VARCHAR(128)", sql)
        self.assertIn("character_maximum_length < 128", sql)  # runs once, not on every start


if __name__ == "__main__":
    unittest.main()
