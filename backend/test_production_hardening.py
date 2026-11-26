"""
Production hardening checks.

- The interactive API docs (/docs, /redoc, /openapi.json) are off by default, so the server does not
  publish a map of every endpoint (including admin ones).
- If someone turns them on while running on Render, the startup self-check warns about it.
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["TESTING"] = "1"

from fastapi.testclient import TestClient

from app import app
import startup_checks


class TestProductionHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_api_docs_are_off_by_default(self):
        for path in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"):
            self.assertEqual(self.client.get(path).status_code, 404, path)
        self.assertEqual(self.client.get("/api/health").status_code, 200)

    def test_startup_warns_if_docs_enabled_on_render(self):
        with patch.dict(os.environ, {"ENABLE_API_DOCS": "1", "RENDER": "true"}):
            self.assertTrue(any("ENABLE_API_DOCS" in w for w in startup_checks.collect_warnings()))
        env = {k: v for k, v in os.environ.items() if k not in ("ENABLE_API_DOCS",)}
        with patch.dict(os.environ, env, clear=True):
            os.environ["RENDER"] = "true"
            self.assertFalse(any("ENABLE_API_DOCS" in w for w in startup_checks.collect_warnings()))


if __name__ == "__main__":
    unittest.main()


class ProductionDatabaseFailSafeTests(unittest.TestCase):
    """Production must never run on the throwaway local SQLite fallback.

    These start the real start-up code in a separate process (outside the test runner), the way Render
    runs it, with RENDER=true and no usable database."""

    def setUp(self):
        # Work on a throwaway copy of the backend: the local fallback writes a SQLite file next to
        # chat_db.py, and a test must never touch the developer's own local_dev.sqlite3 (or read .env).
        import shutil
        import tempfile
        self._tmp = tempfile.mkdtemp(prefix="zyphra_failsafe_")
        here = os.path.dirname(os.path.abspath(__file__))
        for name in os.listdir(here):
            if name.endswith(".py"):
                shutil.copy2(os.path.join(here, name), self._tmp)
        self.addCleanup(shutil.rmtree, self._tmp, True)

    def _run(self, extra_env, timeout=90):
        import subprocess
        env = {k: v for k, v in os.environ.items() if k not in ("TESTING", "NEON_DATABASE_URL", "DATABASE_URL", "POSTGRES_URL")}
        env.update({"NEON_DATABASE_URL": "", "DATABASE_URL": "", "POSTGRES_URL": ""})
        env.update(extra_env)
        code = (
            "import sys; sys.path.insert(0, %r)\n"
            "import chat_db\n"
            "try:\n"
            "    chat_db.init_chat_db()\n"
            "except chat_db.DatabaseUnavailableError as e:\n"
            "    print('REFUSED', e); sys.exit(3)\n"
            "print('FALLBACK' if chat_db._use_sqlite_fallback else 'PG')\n"
        ) % self._tmp
        return subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=timeout,
                              cwd="/tmp")

    def test_render_without_database_url_refuses_to_start(self):
        r = self._run({"RENDER": "true"})
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("Production start refused", r.stdout)

    def test_production_flag_without_database_url_refuses_to_start(self):
        r = self._run({"ENVIRONMENT": "production"})
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)

    def test_local_development_still_falls_back(self):
        r = self._run({})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("FALLBACK", r.stdout)

    def test_explicit_opt_out_allows_the_fallback(self):
        r = self._run({"RENDER": "true", "ALLOW_SQLITE_FALLBACK": "1"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("FALLBACK", r.stdout)