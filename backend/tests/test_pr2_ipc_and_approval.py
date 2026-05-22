"""Tests for PR 2 (hardening/ipc-and-approval).

Coverage:
  - IPC protocol v2: sign/verify roundtrip, v1 rejection, tampering.
  - Replay guard: stale timestamp, duplicate nonce, capacity eviction.
  - Approval mode boot guard: legacy 'totp' rejected, 'none' requires ack.
  - TOTP secret from process env is rejected at runtime.
  - require_recent_step_up: missing, stale, fresh.
"""

import asyncio
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import arbor.approval_mode as approval_mode
import arbor.authorization as authz
import arbor.ipc_auth as ipc_auth
from arbor.ipc_auth import (
    IPCAuthError,
    IPC_PROTOCOL_VERSION,
    sign_request,
    verify_request,
)


# ---------------------------------------------------------------------------
# IPC v2 wire format
# ---------------------------------------------------------------------------


class IPCProtocolV2Tests(unittest.TestCase):
    def setUp(self):
        # Make sure the cached key is reset; tests below patch the env.
        ipc_auth._cached_ipc_key = b"test-ipc-key-please-rotate"

    def tearDown(self):
        ipc_auth._cached_ipc_key = None

    def test_sign_includes_v_nonce_ts(self):
        msg = sign_request("emerge_pretend", {"atom": "sys-apps/portage"})
        self.assertEqual(msg["v"], IPC_PROTOCOL_VERSION)
        self.assertEqual(msg["cmd"], "emerge_pretend")
        self.assertEqual(len(msg["nonce"]), 32)
        self.assertIsInstance(msg["ts"], float)
        self.assertIn("auth", msg)
        self.assertEqual(msg["auth"]["alg"], "hmac-sha256")

    def test_verify_roundtrip(self):
        msg = sign_request("system_status", {})
        cmd, args, nonce, ts = verify_request(msg)
        self.assertEqual(cmd, "system_status")
        self.assertEqual(args, {})
        self.assertEqual(len(nonce), 32)
        self.assertIsInstance(ts, float)

    def test_verify_rejects_v1_payload(self):
        # v1: no nonce, no ts in the canonical request — simulate by passing
        # an empty 'v' field.
        msg = sign_request("system_status", {})
        msg["v"] = 1
        with self.assertRaisesRegex(IPCAuthError, "unsupported IPC protocol version"):
            verify_request(msg)

    def test_verify_rejects_missing_nonce(self):
        msg = sign_request("system_status", {})
        del msg["nonce"]
        with self.assertRaisesRegex(IPCAuthError, "missing or invalid nonce"):
            verify_request(msg)

    def test_verify_rejects_tampered_args(self):
        msg = sign_request("emerge_pretend", {"atom": "sys-apps/portage"})
        msg["args"] = {"atom": "evil-payload"}
        with self.assertRaisesRegex(IPCAuthError, "invalid IPC auth signature"):
            verify_request(msg)


# ---------------------------------------------------------------------------
# Replay guard
# ---------------------------------------------------------------------------


class ReplayGuardTests(unittest.TestCase):
    def _make_guard(self, **kwargs):
        # Import lazily so the daemon module is loaded only when needed.
        from daemon.main import _ReplayGuard
        return _ReplayGuard(**kwargs)

    def test_first_call_accepts(self):
        guard = self._make_guard()
        ok, reason = asyncio.run(guard.check_and_record("a" * 32, time.time()))
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_replay_rejected(self):
        guard = self._make_guard()
        now = time.time()
        ok1, _ = asyncio.run(guard.check_and_record("b" * 32, now))
        ok2, reason = asyncio.run(guard.check_and_record("b" * 32, now))
        self.assertTrue(ok1)
        self.assertFalse(ok2)
        self.assertEqual(reason, "replayed IPC nonce")

    def test_stale_timestamp_rejected(self):
        guard = self._make_guard(window=30.0)
        old_ts = time.time() - 120.0
        ok, reason = asyncio.run(guard.check_and_record("c" * 32, old_ts))
        self.assertFalse(ok)
        self.assertEqual(reason, "stale or skewed IPC timestamp")

    def test_future_timestamp_rejected(self):
        guard = self._make_guard(window=30.0)
        future_ts = time.time() + 120.0
        ok, reason = asyncio.run(guard.check_and_record("d" * 32, future_ts))
        self.assertFalse(ok)

    def test_capacity_eviction(self):
        guard = self._make_guard(max_size=3, ttl=3600.0)
        async def run():
            now = time.time()
            await guard.check_and_record("1" * 32, now)
            await guard.check_and_record("2" * 32, now)
            await guard.check_and_record("3" * 32, now)
            await guard.check_and_record("4" * 32, now)  # evicts "1"
            # nonce "1" should be free again because evicted
            ok, _ = await guard.check_and_record("1" * 32, now)
            return ok
        self.assertTrue(asyncio.run(run()))


# ---------------------------------------------------------------------------
# Approval mode boot guard
# ---------------------------------------------------------------------------


class ApprovalModeBootGuardTests(unittest.TestCase):
    def _isolated_env(self, **env):
        return patch.dict(os.environ, env, clear=False)

    def _no_arbor_env_file(self):
        # Point env_file_path at a missing file so file-first lookups fall back.
        return patch.dict(os.environ, {"ARBOR_ENV_FILE": "/nonexistent/arbor.env"})

    def test_default_cli_mode_ok(self):
        with self._no_arbor_env_file(), self._isolated_env(ARBOR_APPROVAL_MODE="cli"):
            mode = approval_mode.validate_approval_mode_config()
            self.assertIs(mode, approval_mode.ApprovalMode.CLI)

    def test_legacy_totp_mode_rejected(self):
        with self._no_arbor_env_file(), self._isolated_env(ARBOR_APPROVAL_MODE="totp"):
            with self.assertRaisesRegex(approval_mode.ApprovalModeError, "no longer supported"):
                approval_mode.validate_approval_mode_config()

    def test_none_mode_requires_ack(self):
        with self._no_arbor_env_file(), self._isolated_env(ARBOR_APPROVAL_MODE="none"):
            os.environ.pop("ARBOR_ALLOW_AUTO_APPROVAL", None)
            with self.assertRaisesRegex(approval_mode.ApprovalModeError, "refused by default"):
                approval_mode.validate_approval_mode_config()

    def test_none_mode_with_ack_accepted(self):
        with self._no_arbor_env_file(), self._isolated_env(
            ARBOR_APPROVAL_MODE="none", ARBOR_ALLOW_AUTO_APPROVAL="1"
        ):
            mode = approval_mode.validate_approval_mode_config()
            self.assertIs(mode, approval_mode.ApprovalMode.NONE)


# ---------------------------------------------------------------------------
# TOTP secret from env is rejected
# ---------------------------------------------------------------------------


class TOTPSecretEnvRejectionTests(unittest.TestCase):
    def test_secret_in_process_env_is_refused(self):
        with patch.dict(os.environ, {"ARBOR_TOTP_SECRET": "JBSWY3DPEHPK3PXP"}, clear=False):
            with self.assertRaisesRegex(approval_mode.ApprovalModeError, "no longer accepted from the process environment"):
                approval_mode.get_totp_secret()

    def test_secret_in_file_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = Path(tmpdir) / "totp.secret"
            secret_path.write_text("JBSWY3DPEHPK3PXP")
            os.environ.pop("ARBOR_TOTP_SECRET", None)
            with patch.dict(
                os.environ,
                {
                    "ARBOR_TOTP_SECRET_FILE": str(secret_path),
                    "ARBOR_ENV_FILE": "/nonexistent/arbor.env",
                },
                clear=False,
            ):
                self.assertEqual(approval_mode.get_totp_secret(), "JBSWY3DPEHPK3PXP")


# ---------------------------------------------------------------------------
# Step-up freshness
# ---------------------------------------------------------------------------


class RequireRecentStepUpTests(unittest.TestCase):
    def test_missing_step_up_raises(self):
        principal = {"backend": "local", "role": "owner", "subject": "u1", "username": "owner", "step_up_at": None}
        with self.assertRaises(authz.StepUpRequiredError):
            authz.require_recent_step_up(principal=principal)

    def test_stale_step_up_raises(self):
        principal = {
            "backend": "local",
            "role": "owner",
            "subject": "u1",
            "username": "owner",
            "step_up_at": time.time() - 600.0,
        }
        with self.assertRaises(authz.StepUpRequiredError):
            authz.require_recent_step_up(max_age_seconds=120.0, principal=principal)

    def test_fresh_step_up_ok(self):
        principal = {
            "backend": "local",
            "role": "owner",
            "subject": "u1",
            "username": "owner",
            "step_up_at": time.time() - 5.0,
        }
        # Must not raise
        authz.require_recent_step_up(max_age_seconds=120.0, principal=principal)


if __name__ == "__main__":
    unittest.main()
