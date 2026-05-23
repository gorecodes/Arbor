"""Tests for PR 1 (hardening/web-edge): CSRF, HSTS, TLS bind, WS origin."""

import os
import unittest
import unittest.mock
from unittest.mock import patch

from fastapi.testclient import TestClient

import arbor.main as web_main
import arbor.server as web_server
from arbor.csrf import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    generate_csrf_token,
    verify_csrf_tokens,
)


def _client(base_url: str = "http://testserver") -> TestClient:
    # raise_server_exceptions=False so middleware-rejected requests do not
    # bubble unhandled. We assert on the returned status_code directly.
    return TestClient(web_main.app, base_url=base_url, raise_server_exceptions=False)


class CSRFTokenTests(unittest.TestCase):
    def test_token_is_url_safe_and_long(self):
        tok = generate_csrf_token()
        self.assertGreater(len(tok), 30)
        # URL-safe base64 (no '+', '/', '=')
        for ch in ("+", "/", "="):
            self.assertNotIn(ch, tok)

    def test_verify_requires_non_empty(self):
        self.assertFalse(verify_csrf_tokens("", ""))
        self.assertFalse(verify_csrf_tokens("a", ""))
        self.assertFalse(verify_csrf_tokens("", "a"))

    def test_verify_match(self):
        t = generate_csrf_token()
        self.assertTrue(verify_csrf_tokens(t, t))

    def test_verify_mismatch(self):
        self.assertFalse(verify_csrf_tokens("abc", "def"))


class CSRFMiddlewareTests(unittest.TestCase):
    def test_post_without_csrf_returns_403(self):
        client = _client()
        # any mutating /api/* path that is not exempt; logout is a small one
        r = client.post("/api/auth/logout")
        self.assertEqual(r.status_code, 403)
        self.assertIn("csrf", r.json().get("error", "").lower())

    def test_post_with_mismatched_csrf_returns_403(self):
        client = _client()
        client.cookies.set(CSRF_COOKIE_NAME, "cookie-value")
        r = client.post("/api/auth/logout", headers={CSRF_HEADER_NAME: "header-value"})
        self.assertEqual(r.status_code, 403)

    def test_post_with_matching_csrf_passes_middleware(self):
        client = _client()
        token = generate_csrf_token()
        client.cookies.set(CSRF_COOKIE_NAME, token)
        # logout is idempotent; it should not 403 on CSRF when token matches.
        r = client.post("/api/auth/logout", headers={CSRF_HEADER_NAME: token})
        self.assertNotEqual(r.status_code, 403)

    def test_login_is_exempt(self):
        client = _client()
        # No CSRF cookie, no header — middleware must let the request reach
        # the handler. The handler may return 503 (no users) or 401 (bad
        # creds), but never 403 from our CSRF middleware.
        r = client.post("/api/auth/login", json={"username": "x", "password": "y"})
        self.assertNotEqual(r.status_code, 403)

    def test_get_does_not_require_csrf(self):
        client = _client()
        r = client.get("/api/auth/backend")
        self.assertEqual(r.status_code, 200)


class HSTSHeaderTests(unittest.TestCase):
    def test_hsts_present_on_https_scheme(self):
        client = _client(base_url="https://testserver")
        r = client.get("/api/auth/backend")
        self.assertIn("strict-transport-security", {k.lower() for k in r.headers.keys()})
        value = r.headers.get("strict-transport-security", "")
        self.assertIn("max-age=", value)

    def test_hsts_absent_on_http_scheme(self):
        client = _client(base_url="http://testserver")
        r = client.get("/api/auth/backend")
        self.assertNotIn(
            "strict-transport-security",
            {k.lower() for k in r.headers.keys()},
        )

    def test_core_security_headers_always_set(self):
        client = _client()
        r = client.get("/api/auth/backend")
        keys = {k.lower() for k in r.headers.keys()}
        self.assertIn("content-security-policy", keys)
        self.assertIn("x-frame-options", keys)
        self.assertIn("x-content-type-options", keys)
        self.assertIn("referrer-policy", keys)


class WSOriginAllowedTests(unittest.TestCase):
    def test_loopback_bind_allows_null_origin(self):
        with patch.object(web_main, "_BIND_IS_LOOPBACK", True):
            self.assertTrue(web_main._ws_origin_allowed(None))
            self.assertTrue(web_main._ws_origin_allowed(""))

    def test_public_bind_rejects_null_origin(self):
        with patch.object(web_main, "_BIND_IS_LOOPBACK", False):
            self.assertFalse(web_main._ws_origin_allowed(None))
            self.assertFalse(web_main._ws_origin_allowed(""))

    def test_known_origin_always_allowed(self):
        with patch.object(web_main, "_cors_origins", ["https://example.com"]):
            with patch.object(web_main, "_BIND_IS_LOOPBACK", False):
                self.assertTrue(web_main._ws_origin_allowed("https://example.com"))

    def test_unknown_origin_rejected(self):
        with patch.object(web_main, "_cors_origins", ["https://example.com"]):
            with patch.object(web_main, "_BIND_IS_LOOPBACK", True):
                self.assertFalse(web_main._ws_origin_allowed("https://evil.com"))


class TLSBindEnforcementTests(unittest.TestCase):
    def test_loopback_without_tls_is_ok(self):
        # No SystemExit expected.
        web_server._enforce_loopback_or_tls("127.0.0.1", tls=False)
        web_server._enforce_loopback_or_tls("::1", tls=False)
        web_server._enforce_loopback_or_tls("localhost", tls=False)

    def test_public_with_tls_is_ok(self):
        web_server._enforce_loopback_or_tls("0.0.0.0", tls=True)
        web_server._enforce_loopback_or_tls("10.0.0.5", tls=True)

    def test_public_without_tls_exits_2(self):
        with self.assertRaises(SystemExit) as cm:
            web_server._enforce_loopback_or_tls("0.0.0.0", tls=False)
        self.assertEqual(cm.exception.code, 2)

        with self.assertRaises(SystemExit) as cm:
            web_server._enforce_loopback_or_tls("192.168.1.10", tls=False)
        self.assertEqual(cm.exception.code, 2)

    def test_public_without_tls_allowed_by_plaintext_override(self):
        with unittest.mock.patch.dict(os.environ, {"ARBOR_ALLOW_PLAINTEXT": "1"}):
            # No SystemExit expected — user explicitly opted in (e.g. behind VPN).
            web_server._enforce_loopback_or_tls("0.0.0.0", tls=False)
            web_server._enforce_loopback_or_tls("10.0.0.1", tls=False)


if __name__ == "__main__":
    unittest.main()
