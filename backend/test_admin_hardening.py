"""Tests for the admin-login hardening: strength policy, no global lockout, attempt cap, startup self-check."""

import os
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["TESTING"] = "1"

import admin_auth
import startup_checks
import generate_admin_credentials

STRONG_ID = "console_admin_01"
STRONG_PW = "Zq9!vT4#mLw8-Rk2xP"


class CredentialPolicyTests(unittest.TestCase):
    def test_strong_credentials_pass(self):
        self.assertEqual(admin_auth.credential_problems(STRONG_ID, STRONG_PW), [])

    def test_short_lowercase_password_is_rejected(self):
        # Same shape as a typical weak setup: 8 chars, lowercase + digits only.
        self.assertTrue(admin_auth.credential_problems(STRONG_ID, "abcd1234"))

    def test_each_rule_is_enforced(self):
        cases = {
            "short id": ("adm", STRONG_PW),
            "short password": (STRONG_ID, "Aa1!aA1!"),
            "single character class": (STRONG_ID, "abcdefghijklmnop"),
            "few distinct chars": (STRONG_ID, "Aa1!Aa1!Aa1!Aa1!"),
            "contains login id": ("console_admin_01", "xx-Console_Admin_01-Zq9!"),
            "common pattern": (STRONG_ID, "Password-Zq9!vT4#mLw8"),
        }
        for label, (lid, pw) in cases.items():
            with self.subTest(label):
                self.assertTrue(admin_auth.credential_problems(lid, pw), f"{label} should be rejected")

    def test_long_passphrase_without_symbols_is_accepted(self):
        self.assertEqual(admin_auth.credential_problems(STRONG_ID, "correct horse battery staple"), [])

    def test_problems_never_contain_the_secret_values(self):
        probs = " ".join(admin_auth.credential_problems("weakid", "hunter2hunter2xx"))
        self.assertNotIn("hunter2", probs)
        self.assertNotIn("weakid", probs)

    def test_weak_configured_credentials_disable_login_even_with_correct_values(self):
        with patch.dict(os.environ, {"ADMIN_LOGIN_ID": "admin", "ADMIN_LOGIN_PASSWORD": "abcd1234"}):
            self.assertFalse(admin_auth.credentials_configured())
            with self.assertRaises(admin_auth.LoginError) as cm:
                admin_auth.attempt_login("admin", "abcd1234", "1.2.3.4")
            self.assertEqual(cm.exception.status, 503)
            self.assertIn("security policy", cm.exception.detail)

    def test_generator_output_always_satisfies_the_policy(self):
        for _ in range(25):
            login_id, password, token = generate_admin_credentials.generate()
            self.assertEqual(admin_auth.credential_problems(login_id, password), [])
            self.assertGreaterEqual(len(token), 24)


class LockoutDesignTests(unittest.TestCase):
    def setUp(self):
        admin_auth._reset_for_tests()
        self._env = patch.dict(os.environ, {"ADMIN_LOGIN_ID": STRONG_ID, "ADMIN_LOGIN_PASSWORD": STRONG_PW})
        self._env.start()
        self._delay = patch.object(admin_auth, "FAILED_ATTEMPT_DELAY_SEC", 0)
        self._delay.start()

    def tearDown(self):
        self._delay.stop()
        self._env.stop()
        admin_auth._reset_for_tests()

    def test_attackers_cannot_lock_the_real_admin_out(self):
        # 200 failures from many different addresses used to trigger a global 5-minute lockout.
        for i in range(200):
            with self.assertRaises(admin_auth.LoginError) as cm:
                admin_auth.attempt_login(STRONG_ID, "wrong-guess", f"10.0.{i // 250}.{i % 250}")
            self.assertEqual(cm.exception.status, 401)
        token = admin_auth.attempt_login(STRONG_ID, STRONG_PW, "203.0.113.7")  # the real admin, new address
        self.assertTrue(admin_auth.verify_session(token))

    def test_same_address_is_still_locked_after_repeated_failures(self):
        for _ in range(admin_auth.MAX_FAILURES_PER_IP):
            with self.assertRaises(admin_auth.LoginError):
                admin_auth.attempt_login(STRONG_ID, "nope", "198.51.100.9")
        with self.assertRaises(admin_auth.LoginError) as cm:
            admin_auth.attempt_login(STRONG_ID, STRONG_PW, "198.51.100.9")
        self.assertEqual(cm.exception.status, 429)

    def test_concurrent_attempts_are_capped_and_overflow_gets_429_immediately(self):
        held = []
        for _ in range(admin_auth.MAX_CONCURRENT_ATTEMPTS):
            self.assertTrue(admin_auth._attempt_slots.acquire(blocking=False))
            held.append(1)
        try:
            with self.assertRaises(admin_auth.LoginError) as cm:
                admin_auth.attempt_login(STRONG_ID, STRONG_PW, "192.0.2.1")
            self.assertEqual(cm.exception.status, 429)
        finally:
            for _ in held:
                admin_auth._attempt_slots.release()
        # Capacity is returned afterwards: a normal login works again.
        self.assertTrue(admin_auth.verify_session(admin_auth.attempt_login(STRONG_ID, STRONG_PW, "192.0.2.1")))

    def test_slots_are_released_after_success_and_failure(self):
        for _ in range(admin_auth.MAX_CONCURRENT_ATTEMPTS * 3):
            with self.assertRaises(admin_auth.LoginError):
                admin_auth.attempt_login(STRONG_ID, "bad", "192.0.2.50")
            admin_auth._reset_for_tests()
        admin_auth.attempt_login(STRONG_ID, STRONG_PW, "192.0.2.51")  # would 429 if slots had leaked


class StartupSelfCheckTests(unittest.TestCase):
    def _clean_env(self, **extra):
        env = {k: v for k, v in os.environ.items() if not k.endswith("PRIVATE_KEY") and k not in
               ("MONGO_URL", "MONGODB_URI", "MONGO_URI", "ADMIN_LOGIN_ID", "ADMIN_LOGIN_PASSWORD", "ADMIN_TOKEN")}
        env.update(extra)
        return patch.dict(os.environ, env, clear=True)

    def test_clean_environment_has_no_warnings(self):
        with self._clean_env(ADMIN_LOGIN_ID=STRONG_ID, ADMIN_LOGIN_PASSWORD=STRONG_PW):
            self.assertEqual(startup_checks.collect_warnings(), [])

    def test_leftover_wallet_key_and_mongo_url_are_flagged_without_printing_values(self):
        secret_key, secret_url = "5" * 64, "mongodb+srv://user:topsecret@cluster.example/db"
        with self._clean_env(ADMIN_PRIVATE_KEY=secret_key, MONGO_URL=secret_url):
            text = " ".join(startup_checks.collect_warnings())
        self.assertIn("ADMIN_PRIVATE_KEY", text)
        self.assertIn("MONGO_URL", text)
        self.assertNotIn(secret_key, text)
        self.assertNotIn("topsecret", text)

    def test_weak_admin_password_is_flagged(self):
        with self._clean_env(ADMIN_LOGIN_ID="rest", ADMIN_LOGIN_PASSWORD="abcd1234"):
            text = " ".join(startup_checks.collect_warnings())
        self.assertIn("DISABLED", text)
        self.assertNotIn("abcd1234", text)

    def test_short_breakglass_token_is_flagged(self):
        with self._clean_env(ADMIN_TOKEN="short"):
            self.assertTrue(any("ADMIN_TOKEN" in w for w in startup_checks.collect_warnings()))


if __name__ == "__main__":
    unittest.main()
