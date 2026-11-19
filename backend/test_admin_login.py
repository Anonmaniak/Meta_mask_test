"""Tests for the /Admin456 console login (backend/admin_auth.py + /api/platform/admin/*)."""

import os
import sys
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app
import admin_auth
import chat_db
import e2ee_db
import platform_db

CREDS = {"ADMIN_LOGIN_ID": "test_admin_id", "ADMIN_LOGIN_PASSWORD": "Zq9!vT4#mLw8-Rk2xP", "ADMIN_TOKEN": ""}


class TestAdminLogin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig = (
            chat_db._use_sqlite_fallback,
            chat_db._sqlite_conn,
            e2ee_db._e2ee_tables_initialized,
            platform_db._platform_tables_initialized,
        )
        chat_db._use_sqlite_fallback = True
        chat_db._sqlite_conn = None
        chat_db._init_sqlite_engine()
        e2ee_db._e2ee_tables_initialized = False
        platform_db._platform_tables_initialized = False
        e2ee_db.ensure_e2ee_tables()
        platform_db.ensure_platform_tables()
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        (
            chat_db._use_sqlite_fallback,
            chat_db._sqlite_conn,
            e2ee_db._e2ee_tables_initialized,
            platform_db._platform_tables_initialized,
        ) = cls._orig

    def setUp(self):
        admin_auth._reset_for_tests()
        self._env = patch.dict(os.environ, CREDS)
        self._env.start()
        self._delay = patch.object(admin_auth, "FAILED_ATTEMPT_DELAY_SEC", 0)
        self._delay.start()

    def tearDown(self):
        self._delay.stop()
        self._env.stop()
        admin_auth._reset_for_tests()

    def _login(self, login_id="test_admin_id", password="Zq9!vT4#mLw8-Rk2xP"):
        return self.client.post("/api/platform/admin/login", json={"login_id": login_id, "password": password})

    def test_admin_endpoints_reject_unauthenticated(self):
        self.assertEqual(self.client.get("/api/platform/admin/overview").status_code, 401)
        self.assertEqual(
            self.client.get("/api/platform/admin/overview", headers={"X-Admin-Token": "bogus"}).status_code, 401
        )

    def test_login_success_grants_access_and_logout_revokes(self):
        res = self._login()
        self.assertEqual(res.status_code, 200)
        token = res.json()["token"]
        self.assertGreaterEqual(len(token), 40)

        ok = self.client.get("/api/platform/admin/overview", headers={"X-Admin-Token": token})
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(self.client.get("/api/platform/admin/session", headers={"X-Admin-Token": token}).status_code, 200)

        self.client.post("/api/platform/admin/logout", headers={"X-Admin-Token": token})
        self.assertEqual(
            self.client.get("/api/platform/admin/overview", headers={"X-Admin-Token": token}).status_code, 401
        )

    def test_wrong_credentials_are_rejected_with_generic_message(self):
        for lid, pw in [("test_admin_id", "wrong"), ("wrong", "Zq9!vT4#mLw8-Rk2xP"), ("", "x")]:
            res = self._login(lid, pw)
            self.assertIn(res.status_code, (401, 422))
        res = self._login("test_admin_id", "wrong")
        self.assertEqual(res.json()["detail"], "Invalid credentials")

    def test_sql_injection_payloads_do_not_authenticate(self):
        for payload in ["' OR '1'='1", "admin'--", "\" OR \"\"=\"", "'; DROP TABLE users;--"]:
            res = self._login(payload, payload)
            self.assertEqual(res.status_code, 401)
        admin_auth._reset_for_tests()  # clear lockout counters, then confirm real login still works
        self.assertEqual(self._login().status_code, 200)

    def test_brute_force_lockout(self):
        for _ in range(admin_auth.MAX_FAILURES_PER_IP):
            self.assertEqual(self._login("test_admin_id", "nope").status_code, 401)
        locked = self._login()  # even the correct password is refused during lockout
        self.assertEqual(locked.status_code, 429)

    def test_login_disabled_when_not_configured(self):
        with patch.dict(os.environ, {"ADMIN_LOGIN_ID": "", "ADMIN_LOGIN_PASSWORD": ""}):
            self.assertEqual(self._login().status_code, 503)

    def test_weak_breakglass_token_is_ignored(self):
        with patch.dict(os.environ, {"ADMIN_TOKEN": "short"}):
            res = self.client.get("/api/platform/admin/overview", headers={"X-Admin-Token": "short"})
            self.assertEqual(res.status_code, 401)

    def test_extra_fields_rejected(self):
        res = self.client.post(
            "/api/platform/admin/login",
            json={"login_id": "a", "password": "b", "role": "superadmin"},
        )
        self.assertEqual(res.status_code, 422)


if __name__ == "__main__":
    unittest.main()