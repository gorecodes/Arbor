"""Tests for PR 3 (hardening/log-and-edges).

Coverage:
  - _scrub_secrets / _scrub_chunk: basic-auth URL masking in log chunks.
  - _quote_ident: DDL identifier safety helper.
  - _resolve_trusted_proxies: ARBOR_TRUSTED_PROXIES parsing.
"""

import os
import unittest
from unittest.mock import patch

import arbor.server as web_server
from daemon.main import _quote_ident, _scrub_chunk, _scrub_secrets


# ---------------------------------------------------------------------------
# Log credential scrubbing
# ---------------------------------------------------------------------------


class ScrubSecretsTests(unittest.TestCase):
    def test_https_basic_auth_masked(self):
        out = _scrub_secrets("fetching https://alice:s3cret@example.com/foo.tar.gz")
        self.assertIn("https://***:***@example.com/", out)
        self.assertNotIn("s3cret", out)
        self.assertNotIn("alice", out)

    def test_git_basic_auth_masked(self):
        out = _scrub_secrets("clone of git://u:p@gitsvc/repo.git")
        self.assertIn("git://***:***@gitsvc/", out)

    def test_rsync_basic_auth_masked(self):
        out = _scrub_secrets("rsync://anon:tok@mirror/foo")
        self.assertIn("rsync://***:***@mirror/", out)

    def test_clean_url_unchanged(self):
        s = "fetching https://distfiles.gentoo.org/foo.tar.gz"
        self.assertEqual(_scrub_secrets(s), s)

    def test_email_not_falsely_matched(self):
        # Plain @ in text with no scheme://user:pwd@ must not be touched.
        s = "build done by user@hostname at 12:00:00"
        self.assertEqual(_scrub_secrets(s), s)

    def test_empty_string(self):
        self.assertEqual(_scrub_secrets(""), "")


class ScrubChunkTests(unittest.TestCase):
    def test_chunk_without_credentials_returned_unchanged(self):
        chunk = {"line": "ok"}
        # Same object identity allowed; the helper short-circuits.
        self.assertIs(_scrub_chunk(chunk), chunk)

    def test_chunk_line_with_credentials_scrubbed(self):
        chunk = {"line": "https://u:p@host/x"}
        out = _scrub_chunk(chunk)
        self.assertIsNot(out, chunk)
        self.assertEqual(out["line"], "https://***:***@host/x")
        # original not mutated
        self.assertEqual(chunk["line"], "https://u:p@host/x")

    def test_chunk_error_with_credentials_scrubbed(self):
        chunk = {"error": "failed to fetch https://u:p@host/x"}
        out = _scrub_chunk(chunk)
        self.assertIn("***:***", out["error"])

    def test_chunk_non_string_line_returned_unchanged(self):
        chunk = {"line": None, "done": True}
        self.assertIs(_scrub_chunk(chunk), chunk)


# ---------------------------------------------------------------------------
# DDL identifier safety
# ---------------------------------------------------------------------------


class QuoteIdentTests(unittest.TestCase):
    def test_valid_identifiers(self):
        for name in ("users", "_table", "User_2", "T"):
            self.assertEqual(_quote_ident(name), name)

    def test_rejects_injection_attempt(self):
        with self.assertRaises(ValueError):
            _quote_ident("users; DROP TABLE users")

    def test_rejects_starts_with_digit(self):
        with self.assertRaises(ValueError):
            _quote_ident("1table")

    def test_rejects_empty(self):
        with self.assertRaises(ValueError):
            _quote_ident("")

    def test_rejects_whitespace(self):
        with self.assertRaises(ValueError):
            _quote_ident("user id")

    def test_rejects_non_string(self):
        with self.assertRaises(ValueError):
            _quote_ident(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Trusted proxies resolution
# ---------------------------------------------------------------------------


class ResolveTrustedProxiesTests(unittest.TestCase):
    def _no_file(self):
        return patch.dict(os.environ, {"ARBOR_ENV_FILE": "/nonexistent/arbor.env"})

    def test_unset_defaults_to_loopback(self):
        with self._no_file():
            os.environ.pop("ARBOR_TRUSTED_PROXIES", None)
            self.assertEqual(web_server._resolve_trusted_proxies(), "127.0.0.1")

    def test_explicit_list(self):
        with self._no_file(), patch.dict(
            os.environ, {"ARBOR_TRUSTED_PROXIES": "10.0.0.1,10.0.0.2"}, clear=False
        ):
            self.assertEqual(
                web_server._resolve_trusted_proxies(), "10.0.0.1,10.0.0.2"
            )

    def test_wildcard(self):
        with self._no_file(), patch.dict(
            os.environ, {"ARBOR_TRUSTED_PROXIES": "*"}, clear=False
        ):
            self.assertEqual(web_server._resolve_trusted_proxies(), "*")


if __name__ == "__main__":
    unittest.main()
