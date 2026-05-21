import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import arbor.approval_cli as approval_cli
import arbor.approval_mode as approval_mode
import arbor.main as web_main
import daemon.main as daemon_main

from test_phase0_characterization import FakeRequest


class ApprovalRequestStoreTests(unittest.TestCase):
    TOTP_SECRET = "JBSWY3DPEHPK3PXP"

    def test_create_request_records_action_metadata_and_plan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "history.db")
            with patch.object(daemon_main, "_DB_PATH", db_path):
                daemon_main._db_init()
                created = daemon_main._approval_request_create("emerge_install", {"atom": "sys-apps/portage"})

        self.assertEqual(created["status"], "pending")
        self.assertEqual(created["action_cmd"], "emerge_install")
        self.assertEqual(created["action_class"], "approval_required")
        self.assertEqual(created["action_target"], "sys-apps/portage")
        self.assertEqual(created["args"], {"atom": "sys-apps/portage"})
        self.assertTrue(created["request_hash"])
        self.assertIn("confirmation_phrase", created)

    def test_create_request_reuses_matching_pending_request(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "history.db")
            with patch.object(daemon_main, "_DB_PATH", db_path):
                daemon_main._db_init()
                first = daemon_main._approval_request_create("emerge_install", {"atom": "sys-apps/portage"})
                second = daemon_main._approval_request_create("emerge_install", {"atom": "sys-apps/portage"})

        self.assertEqual(second["request_id"], first["request_id"])
        self.assertEqual(second["status"], "pending")

    def test_approved_request_is_single_use(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "history.db")
            with patch.object(daemon_main, "_DB_PATH", db_path):
                daemon_main._db_init()
                created = daemon_main._approval_request_create("emerge_install", {"atom": "sys-apps/portage", "opts": ""})
                daemon_main._approval_issue_token(created["request_id"])
                first = daemon_main._require_approval(
                    "emerge_install",
                    {
                        "atom": "sys-apps/portage",
                        "opts": "",
                        "approval_request_id": created["request_id"],
                    },
                )
                second = daemon_main._require_approval(
                    "emerge_install",
                    {
                        "atom": "sys-apps/portage",
                        "opts": "",
                        "approval_request_id": created["request_id"],
                    },
                )

        self.assertIsNone(first)
        self.assertEqual(second, {"error": "approval request is not usable (status=consumed)"})

    def test_approved_request_can_be_consumed_without_exposing_token_to_browser(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "history.db")
            with patch.object(daemon_main, "_DB_PATH", db_path):
                daemon_main._db_init()
                created = daemon_main._approval_request_create("emerge_uninstall", {"atom": "sys-apps/portage"})
                daemon_main._approval_issue_token(created["request_id"])
                result = daemon_main._require_approval(
                    "emerge_uninstall",
                    {
                        "atom": "sys-apps/portage",
                        "approval_request_id": created["request_id"],
                    },
                )

        self.assertIsNone(result)

    def test_approval_extends_expiry_with_grace_window_after_approval(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "history.db")
            with patch.object(daemon_main, "_DB_PATH", db_path):
                daemon_main._db_init()
                with patch.object(daemon_main.time, "time", return_value=100.0):
                    created = daemon_main._approval_request_create("emerge_uninstall", {"atom": "sys-apps/portage"})
                with patch.object(daemon_main.time, "time", return_value=3699.0):
                    issued = daemon_main._approval_issue_token(created["request_id"])
                with patch.object(daemon_main.time, "time", return_value=3701.0):
                    result = daemon_main._require_approval(
                        "emerge_uninstall",
                        {
                            "atom": "sys-apps/portage",
                            "approval_request_id": created["request_id"],
                        },
                    )

        self.assertIsNone(result)
        self.assertGreaterEqual(issued["expires_at"], 3699.0 + daemon_main._APPROVAL_APPROVED_GRACE_SECONDS)

    def test_install_approval_uses_canonicalized_opts_for_matching(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "history.db")
            with patch.object(daemon_main, "_DB_PATH", db_path):
                daemon_main._db_init()
                created = daemon_main._approval_request_create(
                    "emerge_install",
                    {"atom": "sys-apps/portage", "opts": "jobs:4,unknown-flag,keep-going"},
                )
                daemon_main._approval_issue_token(created["request_id"])
                result = daemon_main._require_approval(
                    "emerge_install",
                    {
                        "atom": "sys-apps/portage",
                        "opts": "jobs:4,keep-going",
                        "approval_request_id": created["request_id"],
                    },
                )

        self.assertIsNone(result)

    def test_history_purge_approval_normalizes_days_type(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "history.db")
            with patch.object(daemon_main, "_DB_PATH", db_path):
                daemon_main._db_init()
                created = daemon_main._approval_request_create("history_purge", {"days": "30"})
                daemon_main._approval_issue_token(created["request_id"])
                result = daemon_main._require_approval(
                    "history_purge",
                    {
                        "days": 30,
                        "approval_request_id": created["request_id"],
                    },
                )

        self.assertIsNone(result)

    def test_pending_request_can_be_cancelled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "history.db")
            with patch.object(daemon_main, "_DB_PATH", db_path):
                daemon_main._db_init()
                created = daemon_main._approval_request_create("emerge_install", {"atom": "sys-apps/portage"})
                cancelled = daemon_main._approval_cancel(created["request_id"])
                stored = daemon_main._approval_request_get(created["request_id"])

        self.assertEqual(cancelled, {"request_id": created["request_id"], "status": "cancelled"})
        self.assertIsNotNone(stored)
        self.assertEqual(stored["status"], "cancelled")

    def test_approval_events_are_recorded_for_create_approve_consume(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "history.db")
            with patch.object(daemon_main, "_DB_PATH", db_path):
                daemon_main._db_init()
                created = daemon_main._approval_request_create("emerge_install", {"atom": "sys-apps/portage"})
                daemon_main._approval_issue_token(created["request_id"])
                daemon_main._require_approval(
                    "emerge_install",
                    {
                        "atom": "sys-apps/portage",
                        "approval_request_id": created["request_id"],
                    },
                )
                with daemon_main._db_conn() as conn:
                    conn.row_factory = daemon_main.sqlite3.Row
                    rows = conn.execute(
                        "SELECT event_type, request_id, action_cmd, action_target "
                        "FROM approval_events WHERE request_id=? ORDER BY event_id",
                        (created["request_id"],),
                    ).fetchall()

        self.assertEqual(
            [dict(row) for row in rows],
            [
                {
                    "event_type": "created",
                    "request_id": created["request_id"],
                    "action_cmd": "emerge_install",
                    "action_target": "sys-apps/portage",
                },
                {
                    "event_type": "approved",
                    "request_id": created["request_id"],
                    "action_cmd": "emerge_install",
                    "action_target": "sys-apps/portage",
                },
                {
                    "event_type": "consumed",
                    "request_id": created["request_id"],
                    "action_cmd": "emerge_install",
                    "action_target": "sys-apps/portage",
                },
            ],
        )

    def test_none_mode_auto_approves_request_creation(self):
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(os.environ, {"ARBOR_AUTH_MODE": "none"}, clear=False),
        ):
            db_path = str(Path(tmpdir) / "history.db")
            with patch.object(daemon_main, "_DB_PATH", db_path):
                daemon_main._db_init()
                created = daemon_main._approval_request_create("emerge_install", {"atom": "sys-apps/portage"})

        self.assertEqual(created["status"], "approved")
        self.assertEqual(created["approval_mode"], "none")
        self.assertTrue(created["auto_approved"])
        self.assertEqual(created["request_id"], "")

    def test_none_mode_bypasses_secondary_approval(self):
        with patch.dict(os.environ, {"ARBOR_AUTH_MODE": "none"}, clear=False):
            result = daemon_main._require_approval("emerge_install", {"atom": "sys-apps/portage"})

        self.assertIsNone(result)

    def test_totp_mode_approves_pending_request_with_valid_code(self):
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(
                os.environ,
                {"ARBOR_AUTH_MODE": "totp", "ARBOR_TOTP_SECRET": self.TOTP_SECRET},
                clear=False,
            ),
        ):
            db_path = str(Path(tmpdir) / "history.db")
            with patch.object(daemon_main, "_DB_PATH", db_path):
                daemon_main._db_init()
                created = daemon_main._approval_request_create("emerge_install", {"atom": "sys-apps/portage"})
                approved = daemon_main._approval_request_approve(
                    created["request_id"],
                    approval_mode.totp_code(self.TOTP_SECRET),
                )

        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["approval_mode"], "totp")

    def test_totp_mode_rejects_invalid_code(self):
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(
                os.environ,
                {"ARBOR_AUTH_MODE": "totp", "ARBOR_TOTP_SECRET": self.TOTP_SECRET},
                clear=False,
            ),
        ):
            db_path = str(Path(tmpdir) / "history.db")
            with patch.object(daemon_main, "_DB_PATH", db_path):
                daemon_main._db_init()
                created = daemon_main._approval_request_create("emerge_install", {"atom": "sys-apps/portage"})
                approved = daemon_main._approval_request_approve(created["request_id"], "000000")

        self.assertEqual(approved, {"error": "invalid TOTP code"})

    def test_totp_mode_can_cancel_pending_request(self):
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(
                os.environ,
                {"ARBOR_AUTH_MODE": "totp", "ARBOR_TOTP_SECRET": self.TOTP_SECRET},
                clear=False,
            ),
        ):
            db_path = str(Path(tmpdir) / "history.db")
            with patch.object(daemon_main, "_DB_PATH", db_path):
                daemon_main._db_init()
                created = daemon_main._approval_request_create("emerge_install", {"atom": "sys-apps/portage"})
                cancelled = daemon_main._approval_cancel(created["request_id"])
                stored = daemon_main._approval_request_get(created["request_id"])

        self.assertEqual(cancelled, {"request_id": created["request_id"], "status": "cancelled"})
        self.assertIsNotNone(stored)
        self.assertEqual(stored["status"], "cancelled")

    def test_totp_mode_throttles_repeated_failures_and_logs_them(self):
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(
                os.environ,
                {"ARBOR_AUTH_MODE": "totp", "ARBOR_TOTP_SECRET": self.TOTP_SECRET},
                clear=False,
            ),
        ):
            db_path = str(Path(tmpdir) / "history.db")
            with patch.object(daemon_main, "_DB_PATH", db_path):
                daemon_main._db_init()
                with patch.object(daemon_main.time, "time", return_value=100.0):
                    created = daemon_main._approval_request_create("emerge_install", {"atom": "sys-apps/portage"})
                    first = daemon_main._approval_request_approve(created["request_id"], "000000")
                with patch.object(daemon_main.time, "time", return_value=101.0):
                    second = daemon_main._approval_request_approve(created["request_id"], "111111")
                with patch.object(daemon_main.time, "time", return_value=101.1):
                    third = daemon_main._approval_request_approve(created["request_id"], "222222")
                with daemon_main._db_conn() as conn:
                    conn.row_factory = daemon_main.sqlite3.Row
                    rows = conn.execute(
                        "SELECT event_type, details_json FROM approval_events WHERE request_id=? ORDER BY event_id",
                        (created["request_id"],),
                    ).fetchall()

        self.assertEqual(first, {"error": "invalid TOTP code"})
        self.assertEqual(second, {"error": "invalid TOTP code", "retry_after": 2})
        self.assertEqual(third["error"], "approval temporarily throttled; retry in 2s")
        self.assertEqual(third["retry_after"], 2)
        self.assertEqual([row["event_type"] for row in rows[-3:]], ["totp_failed", "totp_failed", "totp_throttled"])

    def test_totp_mode_recovers_after_backoff_window(self):
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(
                os.environ,
                {"ARBOR_AUTH_MODE": "totp", "ARBOR_TOTP_SECRET": self.TOTP_SECRET},
                clear=False,
            ),
        ):
            db_path = str(Path(tmpdir) / "history.db")
            with patch.object(daemon_main, "_DB_PATH", db_path):
                daemon_main._db_init()
                with patch.object(daemon_main.time, "time", return_value=100.0):
                    created = daemon_main._approval_request_create("emerge_install", {"atom": "sys-apps/portage"})
                    daemon_main._approval_request_approve(created["request_id"], "000000")
                with patch.object(daemon_main.time, "time", return_value=101.0):
                    second = daemon_main._approval_request_approve(created["request_id"], "111111")
                with patch.object(daemon_main.time, "time", return_value=102.1):
                    throttled = daemon_main._approval_request_approve(created["request_id"], "222222")
                with patch.object(daemon_main.time, "time", return_value=103.1):
                    approved = daemon_main._approval_request_approve(
                        created["request_id"],
                        approval_mode.totp_code(self.TOTP_SECRET, 103.1),
                    )

        self.assertEqual(second, {"error": "invalid TOTP code", "retry_after": 2})
        self.assertEqual(throttled["error"], "approval temporarily throttled; retry in 1s")
        self.assertEqual(approved["status"], "approved")


class ApprovalRequestDaemonTests(unittest.IsolatedAsyncioTestCase):
    async def test_emerge_install_requires_approval_before_starting_job(self):
        chunks = [chunk async for chunk in daemon_main.cmd_emerge_install({"atom": "sys-apps/portage", "opts": ""})]
        self.assertEqual(
            chunks,
            [
                {
                    "error": "approval required",
                    "approval_required": True,
                    "action_cmd": "emerge_install",
                    "action_class": "approval_required",
                    "action_target": "sys-apps/portage",
                }
            ],
        )

    async def test_overlay_remove_requires_shell_approval_after_browser_confirmation(self):
        chunks = [
            chunk
            async for chunk in daemon_main.cmd_overlay_remove(
                {"name": "foo", "purge": False, "approve_danger": True, "approval_text": "REMOVE foo"}
            )
        ]
        self.assertEqual(
            chunks,
            [
                {
                    "error": "approval required",
                    "approval_required": True,
                    "action_cmd": "overlay_remove",
                    "action_class": "trust_heavy",
                    "action_target": "foo",
                }
            ],
        )

    async def test_web_approval_endpoint_forwards_totp_code(self):
        request = FakeRequest({"code": "123456"})
        query_one = AsyncMock(return_value={"request_id": "req-1", "status": "approved", "approval_mode": "totp"})

        with patch.object(web_main, "query_one", query_one):
            response = await web_main.approval_request_approve("test-token", "req-1", request)

        self.assertEqual(response["status"], "approved")
        query_one.assert_awaited_once_with("approval_request_approve", {"request_id": "req-1", "code": "123456"})

    async def test_web_cancel_endpoint_forwards_request_id(self):
        query_one = AsyncMock(return_value={"request_id": "req-1", "status": "cancelled"})

        with patch.object(web_main, "query_one", query_one):
            response = await web_main.approval_request_cancel("test-token", "req-1")

        self.assertEqual(response["status"], "cancelled")
        query_one.assert_awaited_once_with("approval_request_cancel", {"request_id": "req-1"})


class ApprovalCliTests(unittest.TestCase):
    def test_totp_setup_prints_uri_and_ascii_qr(self):
        class FakeQr:
            def add_data(self, _data):
                pass

            def make(self, fit=True):
                self.fit = fit

            def print_ascii(self, out, tty=False, invert=True):
                out.write("##\n##\n")

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.object(approval_cli, "_require_root"),
            patch.dict(
                os.environ,
                {
                    "ARBOR_AUTH_MODE": "totp",
                    "ARBOR_ENV_FILE": str(Path(tmpdir) / "arbor.env"),
                    "ARBOR_TOTP_SECRET_FILE": str(Path(tmpdir) / "totp.secret"),
                },
                clear=False,
            ),
            patch.dict(sys.modules, {"qrcode": SimpleNamespace(QRCode=lambda border=1: FakeQr())}),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            rc = approval_cli.main(["totp-setup"])
            env_text = (Path(tmpdir) / "arbor.env").read_text(encoding="utf-8")

        self.assertEqual(rc, 0)
        out = stdout.getvalue()
        self.assertIn("Arbor TOTP provisioning", out)
        self.assertIn("Scan this QR code", out)
        self.assertIn("otpauth://totp/", out)
        self.assertIn("##\n##", out)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("ARBOR_AUTH_MODE=totp", env_text)
        self.assertIn(f"ARBOR_TOTP_SECRET_FILE={Path(tmpdir) / 'totp.secret'}", env_text)

    def test_totp_setup_warns_when_qr_dependency_is_missing(self):
        real_import = __import__

        def fake_import(name, *args, **kwargs):
            if name == "qrcode":
                raise ImportError("missing qrcode")
            return real_import(name, *args, **kwargs)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.object(approval_cli, "_require_root"),
            patch.dict(
                os.environ,
                {
                    "ARBOR_AUTH_MODE": "totp",
                    "ARBOR_ENV_FILE": str(Path(tmpdir) / "arbor.env"),
                    "ARBOR_TOTP_SECRET_FILE": str(Path(tmpdir) / "totp.secret"),
                },
                clear=False,
            ),
            patch("builtins.__import__", side_effect=fake_import),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            rc = approval_cli.main(["totp-setup"])

        self.assertEqual(rc, 0)
        self.assertIn("otpauth://totp/", stdout.getvalue())
        self.assertIn("terminal QR rendering requires", stderr.getvalue())

    def test_totp_setup_updates_existing_env_assignments(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = Path(tmpdir) / "arbor.env"
            env_path.write_text(
                "ARBOR_AUTH_MODE=cli\nARBOR_TOTP_SECRET_FILE=/old/path\nOTHER_KEY=1\n",
                encoding="utf-8",
            )
            with (
                patch.object(approval_cli, "_require_root"),
                patch.dict(
                    os.environ,
                    {
                        "ARBOR_AUTH_MODE": "totp",
                        "ARBOR_ENV_FILE": str(env_path),
                        "ARBOR_TOTP_SECRET_FILE": str(Path(tmpdir) / "totp.secret"),
                    },
                    clear=False,
                ),
                patch.object(approval_cli, "_render_terminal_qr", return_value="QR"),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                rc = approval_cli.main(["totp-setup"])

            self.assertEqual(rc, 0)
            env_text = env_path.read_text(encoding="utf-8")
            self.assertIn("ARBOR_AUTH_MODE=totp", env_text)
            self.assertIn(f"ARBOR_TOTP_SECRET_FILE={Path(tmpdir) / 'totp.secret'}", env_text)
            self.assertIn("OTHER_KEY=1", env_text)
            self.assertEqual(stderr.getvalue(), "")

    def test_approve_rejects_when_cli_mode_is_disabled(self):
        stderr = io.StringIO()
        with (
            patch.object(approval_cli, "_require_root"),
            patch.dict(os.environ, {"ARBOR_AUTH_MODE": "totp"}, clear=False),
            redirect_stderr(stderr),
        ):
            rc = approval_cli.main(["approve", "req-1"])

        self.assertEqual(rc, 2)
        self.assertIn("ARBOR_AUTH_MODE must be 'cli'", stderr.getvalue())

    def test_approve_uses_simple_yes_no_confirmation(self):
        request = {
            "request_id": "req-1",
            "status": "pending",
            "action_cmd": "emerge_install",
            "action_class": "approval_required",
            "action_target": "app-misc/hello",
            "confirmation_tier": "standard",
            "confirmation_phrase": "APPROVE app-misc/hello",
            "created_at": 1.0,
            "expires_at": 2.0,
            "args": {"atom": "app-misc/hello"},
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.object(approval_cli, "_require_root"),
            patch.dict(os.environ, {"ARBOR_AUTH_MODE": "cli"}, clear=False),
            patch.object(daemon_main, "_db_init"),
            patch.object(daemon_main, "_approval_request_get", return_value=request),
            patch.object(daemon_main, "_approval_issue_token", return_value={"request_id": "req-1", "approval_token": "secret", "expires_at": 3.0}) as issue,
            patch("builtins.input", return_value="y"),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            rc = approval_cli.main(["approve", "req-1"])

        self.assertEqual(rc, 0)
        self.assertIn("Approved request req-1 for app-misc/hello.", stdout.getvalue())
        self.assertNotIn("Type exactly", stdout.getvalue())
        self.assertNotIn("approval_token=", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")
        issue.assert_called_once_with("req-1", {"method": "cli"})

    def test_approve_can_be_aborted_without_minting_token(self):
        request = {
            "request_id": "req-1",
            "status": "pending",
            "action_cmd": "emerge_install",
            "action_class": "approval_required",
            "action_target": "app-misc/hello",
            "confirmation_tier": "standard",
            "confirmation_phrase": "APPROVE app-misc/hello",
            "created_at": 1.0,
            "expires_at": 2.0,
            "args": {"atom": "app-misc/hello"},
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.object(approval_cli, "_require_root"),
            patch.dict(os.environ, {"ARBOR_AUTH_MODE": "cli"}, clear=False),
            patch.object(daemon_main, "_db_init"),
            patch.object(daemon_main, "_approval_request_get", return_value=request),
            patch.object(daemon_main, "_approval_cancel", return_value={"request_id": "req-1", "status": "cancelled"}) as cancel,
            patch.object(daemon_main, "_approval_issue_token") as issue,
            patch("builtins.input", return_value="n"),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            rc = approval_cli.main(["approve", "req-1"])

        self.assertEqual(rc, 0)
        self.assertIn("Cancelled request req-1 for app-misc/hello.", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")
        cancel.assert_called_once_with("req-1")
        issue.assert_not_called()

    def test_print_request_uses_human_readable_dates(self):
        request = {
            "request_id": "req-1",
            "status": "pending",
            "action_cmd": "emerge_install",
            "action_class": "approval_required",
            "action_target": "app-misc/hello",
            "created_at": 1.0,
            "expires_at": 2.0,
            "args": {"atom": "app-misc/hello"},
        }
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            approval_cli._print_request(request)

        out = stdout.getvalue()
        self.assertRegex(out, r"created_at:\s+1970-01-01 \d{2}:\d{2}:01")
        self.assertRegex(out, r"expires_at:\s+1970-01-01 \d{2}:\d{2}:02")

    def test_print_request_sanitizes_terminal_control_sequences(self):
        request = {
            "request_id": "req-1",
            "status": "pending",
            "action_cmd": "overlay_add",
            "action_class": "trust_heavy",
            "action_target": "foo\x1b[2Jbar",
            "created_at": 1.0,
            "expires_at": 2.0,
            "args": {"name": "foo\x1b[2Jbar"},
        }
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            approval_cli._print_request(request)

        out = stdout.getvalue()
        self.assertIn(r"target:     foo\x1b[2Jbar", out)
        self.assertNotIn("\x1b", out)

    def test_strong_request_requires_confirmation_phrase(self):
        request = {
            "request_id": "req-1",
            "status": "pending",
            "action_cmd": "overlay_add",
            "action_class": "trust_heavy",
            "action_target": "foo https://example.invalid/repo.git",
            "confirmation_tier": "strong",
            "confirmation_phrase": "APPROVE foo https://example.invalid/repo.git",
            "created_at": 1.0,
            "expires_at": 2.0,
            "args": {"name": "foo", "sync_uri": "https://example.invalid/repo.git"},
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.object(approval_cli, "_require_root"),
            patch.object(daemon_main, "_db_init"),
            patch.object(daemon_main, "_approval_request_get", return_value=request),
            patch.object(daemon_main, "_approval_issue_token", return_value={"request_id": "req-1", "approval_token": "secret", "expires_at": 3.0}) as issue,
            patch("builtins.input", return_value="APPROVE foo https://example.invalid/repo.git"),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            rc = approval_cli.main(["approve", "req-1"])

        self.assertEqual(rc, 0)
        self.assertIn("This is a high-impact request.", stdout.getvalue())
        self.assertIn("Type exactly: APPROVE foo https://example.invalid/repo.git", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")
        issue.assert_called_once_with("req-1", {"method": "cli"})

    def test_keyboard_interrupt_cancels_request(self):
        request = {
            "request_id": "req-1",
            "status": "pending",
            "action_cmd": "emerge_install",
            "action_class": "approval_required",
            "action_target": "app-misc/hello",
            "confirmation_tier": "standard",
            "confirmation_phrase": "APPROVE app-misc/hello",
            "created_at": 1.0,
            "expires_at": 2.0,
            "args": {"atom": "app-misc/hello"},
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.object(approval_cli, "_require_root"),
            patch.object(daemon_main, "_db_init"),
            patch.object(daemon_main, "_approval_request_get", return_value=request),
            patch.object(daemon_main, "_approval_cancel", return_value={"request_id": "req-1", "status": "cancelled"}) as cancel,
            patch.object(daemon_main, "_approval_issue_token") as issue,
            patch("builtins.input", side_effect=KeyboardInterrupt),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            rc = approval_cli.main(["approve", "req-1"])

        self.assertEqual(rc, 0)
        self.assertIn("Cancelled request req-1 for app-misc/hello.", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")
        cancel.assert_called_once_with("req-1")
        issue.assert_not_called()


class ApprovalRequestWebTests(unittest.IsolatedAsyncioTestCase):
    async def test_approval_request_create_rejects_non_object_args(self):
        response = await web_main.approval_request_create("test-token", FakeRequest({"cmd": "emerge_install", "args": []}))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.body, b'{"error":"args must be an object"}')

    async def test_etc_update_resolve_forwards_approval_fields(self):
        query_one = AsyncMock(return_value={"ok": True})
        with patch.object(web_main, "query_one", query_one):
            response = await web_main.etc_update_resolve(
                "test-token",
                FakeRequest(
                    {
                        "cfg_file": "/etc/portage/._cfg0001_make.conf",
                        "action": "keep",
                        "approval_request_id": "req-1",
                        "approval_token": "tok-1",
                    }
                ),
            )

        self.assertEqual(response, {"ok": True})
        query_one.assert_awaited_once_with(
            "etc_update_resolve",
            {
                "cfg_file": "/etc/portage/._cfg0001_make.conf",
                "action": "keep",
                "approval_request_id": "req-1",
                "approval_token": "tok-1",
            },
        )


class ApprovalFrontendWiringTests(unittest.TestCase):
    def test_approval_cli_exposes_totp_setup_command(self):
        cli_py = (Path(__file__).resolve().parents[2] / "backend" / "arbor" / "approval_cli.py").read_text(encoding="utf-8")
        self.assertIn("totp-setup", cli_py)
        self.assertIn("Show or generate the Arbor TOTP secret and QR code", cli_py)

    def test_frontend_totp_approval_keeps_input_and_pokes_polling_immediately(self):
        app_js = (Path(__file__).resolve().parents[2] / "frontend" / "alpine" / "app.js").read_text(encoding="utf-8")
        self.assertIn("this._approvalFormRequestId !== requestId", app_js)
        self.assertIn("window.dispatchEvent(new CustomEvent('arbor-approval-updated'", app_js)
        self.assertIn("const handleApprovalUpdate = async (request) => {", app_js)
        self.assertIn("void handleApprovalUpdate(updated)", app_js)
        self.assertIn("window.addEventListener('arbor-approval-updated', state._approvalUpdateHandler)", app_js)
        self.assertIn("window.removeEventListener('arbor-approval-updated', state._approvalUpdateHandler)", app_js)

    def test_jobs_view_uses_request_before_execute_for_privileged_actions(self):
        app_js = (Path(__file__).resolve().parents[2] / "frontend" / "alpine" / "app.js").read_text(encoding="utf-8")
        self.assertIn("'job_cancel'", app_js)
        self.assertIn("'history_delete'", app_js)
        self.assertIn("'history_purge'", app_js)
        self.assertIn("() => this._runKill(jobId)", app_js)
        self.assertIn("() => this._runDeleteEntry(jobId)", app_js)
        self.assertIn("() => this._runPurge(days)", app_js)
        self.assertIn("this.$watch('$store.approvalGate.active', request => { this._restorePendingApproval(request) })", app_js)

    def test_jobs_view_renders_approval_status_lines(self):
        index_html = (Path(__file__).resolve().parents[2] / "frontend" / "alpine" / "index.html").read_text(encoding="utf-8")
        self.assertIn('x-show="approvalLines.length > 0"', index_html)
        self.assertIn('x-text="line || \' \'"', index_html)

    def test_overlay_view_uses_request_before_execute_for_privileged_actions(self):
        app_js = (Path(__file__).resolve().parents[2] / "frontend" / "alpine" / "app.js").read_text(encoding="utf-8")
        self.assertIn("'overlay_add'", app_js)
        self.assertIn("'overlay_remove'", app_js)
        self.assertIn("'overlay_sync'", app_js)
        self.assertIn("() => this.add()", app_js)
        self.assertIn("() => this._removeConfirmed(name, purge)", app_js)
        self.assertIn("() => this.sync(name)", app_js)
        self.assertIn("this.$watch('$store.approvalGate.active', request => { this._restorePendingApproval(request) })", app_js)
        self.assertIn("wsOverlaySync(name, (msg) => {", app_js)
        self.assertIn("approval_request_id: approval.request_id", app_js)

    def test_overlay_view_renders_approval_status_lines(self):
        index_html = (Path(__file__).resolve().parents[2] / "frontend" / "alpine" / "index.html").read_text(encoding="utf-8")
        self.assertIn('<div class="terminal" x-show="approvalLines.length > 0">', index_html)
        self.assertIn("<h2>Overlays</h2>", index_html)

    def test_frontend_tracks_pending_queue_and_uses_backoff_refresh(self):
        app_js = (Path(__file__).resolve().parents[2] / "frontend" / "alpine" / "app.js").read_text(encoding="utf-8")
        self.assertIn("async function _refreshApprovalGate", app_js)
        self.assertIn("pendingCount()", app_js)
        self.assertIn("document.addEventListener('visibilitychange'", app_js)
        self.assertIn("Math.min(Math.max(state._approvalPollDelay || 1500, 1500) * 2, 30000)", app_js)
        self.assertIn("Math.min(Math.round(Math.max(state._approvalPollDelay || 1500, 1500) * 1.5), 10000)", app_js)
        self.assertIn("state._approvalPollingRequestId = requestId", app_js)
        self.assertIn("(state._approvalPollTimer || state._approvalPollingRequestId === request.request_id)", app_js)

    def test_install_and_uninstall_restore_accept_canonicalized_cpv_atoms(self):
        app_js = (Path(__file__).resolve().parents[2] / "frontend" / "alpine" / "app.js").read_text(encoding="utf-8")
        self.assertIn("function _approvalAtomKey(atom)", app_js)
        self.assertIn("_approvalAtomKey(request.args?.atom) !== _approvalAtomKey(atom)", app_js)
        self.assertIn("return { view: 'install', param: _approvalAtomKey(args.atom) }", app_js)
        self.assertIn("return { view: 'uninstall', param: _approvalAtomKey(args.atom) }", app_js)

    def test_install_and_uninstall_setup_do_not_clear_global_approval_gate(self):
        app_js = (Path(__file__).resolve().parents[2] / "frontend" / "alpine" / "app.js").read_text(encoding="utf-8")
        self.assertIn("clearApprovalState(state, { keepRequest: true, syncGate: false })", app_js)
        self.assertGreaterEqual(app_js.count("clearApprovalState(this, { syncGate: false })"), 2)

    def test_uninstall_close_done_returns_to_package_list(self):
        app_js = (Path(__file__).resolve().parents[2] / "frontend" / "alpine" / "app.js").read_text(encoding="utf-8")
        self.assertIn("closeDone() {\n        navigate('packages')\n      },", app_js)


if __name__ == "__main__":
    unittest.main()
