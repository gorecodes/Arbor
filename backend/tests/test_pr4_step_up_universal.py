"""Tests for PR 4 (hardening/step-up-universal).

Coverage:
  - require_recent_step_up_unless_cli_mode: cli mode skips, others enforce.
  - _ws_step_up_if_mutating: pretend = pass, mutating without step-up =
    fail 4401.
  - /api/auth/step-up/ensure endpoint.
"""

import asyncio
import json
import os
import time
import unittest
from unittest.mock import patch

import arbor.approval_mode as approval_mode
import arbor.authorization as authz
import arbor.main as web_main


def _principal_with_step_up(at: float | None) -> dict:
    return {
        "backend": "local",
        "role": "owner",
        "subject": "u1",
        "username": "owner",
        "step_up_at": at,
    }


def _set_principal(principal: dict | None) -> None:
    authz.set_current_principal(principal)


# ---------------------------------------------------------------------------
# Mode-aware helper
# ---------------------------------------------------------------------------


class RequireStepUpUnlessCliModeTests(unittest.TestCase):
    def test_cli_mode_is_noop_even_without_step_up(self):
        principal = _principal_with_step_up(None)
        _set_principal(principal)
        try:
            with patch.object(approval_mode, "effective_approval_mode", return_value=approval_mode.ApprovalMode.CLI):
                authz.require_recent_step_up_unless_cli_mode()
        finally:
            _set_principal(None)

    def test_non_cli_mode_requires_step_up(self):
        principal = _principal_with_step_up(None)
        _set_principal(principal)
        try:
            with patch.object(approval_mode, "effective_approval_mode", return_value=approval_mode.ApprovalMode.NONE):
                with self.assertRaises(authz.StepUpRequiredError):
                    authz.require_recent_step_up_unless_cli_mode()
        finally:
            _set_principal(None)

    def test_non_cli_mode_passes_with_fresh_step_up(self):
        principal = _principal_with_step_up(time.time() - 5.0)
        _set_principal(principal)
        try:
            with patch.object(approval_mode, "effective_approval_mode", return_value=approval_mode.ApprovalMode.NONE):
                authz.require_recent_step_up_unless_cli_mode()
        finally:
            _set_principal(None)

    def test_non_cli_mode_rejects_stale_step_up(self):
        principal = _principal_with_step_up(time.time() - 600.0)
        _set_principal(principal)
        try:
            with patch.object(approval_mode, "effective_approval_mode", return_value=approval_mode.ApprovalMode.NONE):
                with self.assertRaises(authz.StepUpRequiredError):
                    authz.require_recent_step_up_unless_cli_mode()
        finally:
            _set_principal(None)


# ---------------------------------------------------------------------------
# WebSocket helper
# ---------------------------------------------------------------------------


class FakeWS:
    """Minimal websocket double for _ws_step_up_if_mutating."""

    def __init__(self):
        self.sent = []
        self.closed_with = None

    async def send_text(self, payload):
        self.sent.append(payload)

    async def close(self, code: int = 1000, reason: str = ""):
        self.closed_with = (code, reason)


class WSStepUpIfMutatingTests(unittest.TestCase):
    def _run(self, coro):
        return asyncio.run(coro)

    def test_pretend_cmd_returns_true_without_check(self):
        ws = FakeWS()
        _set_principal(_principal_with_step_up(None))
        try:
            with patch.object(approval_mode, "effective_approval_mode", return_value=approval_mode.ApprovalMode.NONE):
                ok = self._run(web_main._ws_step_up_if_mutating(ws, "emerge_pretend", {"atom": "x"}))
        finally:
            _set_principal(None)
        self.assertTrue(ok)
        self.assertIsNone(ws.closed_with)

    def test_mutating_cmd_without_step_up_closes_4401(self):
        ws = FakeWS()
        _set_principal(_principal_with_step_up(None))
        try:
            with patch.object(approval_mode, "effective_approval_mode", return_value=approval_mode.ApprovalMode.NONE):
                ok = self._run(web_main._ws_step_up_if_mutating(ws, "emerge_install", {"atom": "x"}))
        finally:
            _set_principal(None)
        self.assertFalse(ok)
        self.assertIsNotNone(ws.closed_with)
        code, reason = ws.closed_with
        self.assertEqual(code, 4401)
        self.assertIn("step_up_required", reason)

    def test_mutating_cmd_in_cli_mode_passes(self):
        ws = FakeWS()
        _set_principal(_principal_with_step_up(None))
        try:
            with patch.object(approval_mode, "effective_approval_mode", return_value=approval_mode.ApprovalMode.CLI):
                ok = self._run(web_main._ws_step_up_if_mutating(ws, "emerge_install", {"atom": "x"}))
        finally:
            _set_principal(None)
        self.assertTrue(ok)
        self.assertIsNone(ws.closed_with)

    def test_mutating_cmd_with_fresh_step_up_passes(self):
        ws = FakeWS()
        _set_principal(_principal_with_step_up(time.time() - 5.0))
        try:
            with patch.object(approval_mode, "effective_approval_mode", return_value=approval_mode.ApprovalMode.NONE):
                ok = self._run(web_main._ws_step_up_if_mutating(ws, "emerge_install", {"atom": "x"}))
        finally:
            _set_principal(None)
        self.assertTrue(ok)
        self.assertIsNone(ws.closed_with)


# ---------------------------------------------------------------------------
# /api/auth/step-up/ensure endpoint
# ---------------------------------------------------------------------------


class StepUpEnsureEndpointTests(unittest.TestCase):
    def _run(self, coro):
        return asyncio.run(coro)

    def test_returns_ok_when_step_up_fresh(self):
        _set_principal(_principal_with_step_up(time.time() - 5.0))
        try:
            with patch.object(approval_mode, "effective_approval_mode", return_value=approval_mode.ApprovalMode.NONE):
                result = self._run(web_main.auth_step_up_ensure("u1"))
        finally:
            _set_principal(None)
        self.assertEqual(result, {"ok": True})

    def test_raises_step_up_required_when_missing(self):
        _set_principal(_principal_with_step_up(None))
        try:
            with patch.object(approval_mode, "effective_approval_mode", return_value=approval_mode.ApprovalMode.NONE):
                with self.assertRaises(authz.StepUpRequiredError):
                    self._run(web_main.auth_step_up_ensure("u1"))
        finally:
            _set_principal(None)

    def test_returns_ok_in_cli_mode_without_step_up(self):
        _set_principal(_principal_with_step_up(None))
        try:
            with patch.object(approval_mode, "effective_approval_mode", return_value=approval_mode.ApprovalMode.CLI):
                result = self._run(web_main.auth_step_up_ensure("u1"))
        finally:
            _set_principal(None)
        self.assertEqual(result, {"ok": True})


if __name__ == "__main__":
    unittest.main()
