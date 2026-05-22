import importlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import arbor.config_env as config_env
import arbor.approval_mode as approval_mode
import arbor.main as web_main
import arbor.server as server_mod
import daemon.main as daemon_main


class EtcUpdateHardeningTests(unittest.TestCase):
    def test_etc_update_check_timeout_returns_partial_results_with_warning(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            cfg_file = root / "._cfg0001_test.conf"
            real_file = root / "test.conf"
            cfg_file.write_text("new-value\n", encoding="utf-8")
            real_file.write_text("old-value\n", encoding="utf-8")

            exc = subprocess.TimeoutExpired(cmd=["find", "/etc"], timeout=15)
            exc.stdout = f"{cfg_file}\n"

            with patch("subprocess.run", side_effect=exc):
                pending = daemon_main._etc_update_check()

        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["cfg_file"], str(cfg_file))
        self.assertIn("timed out", pending[0]["warning"])


class ArborEnvLoadingTests(unittest.TestCase):
    def test_config_env_reads_unexported_values_from_arbor_env(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / "arbor.env"
            env_file.write_text("ARBOR_HOST=0.0.0.0\nexport ARBOR_ENABLE_OVERLAY_ADD=1\n", encoding="utf-8")

            with patch.dict("os.environ", {"ARBOR_ENV_FILE": str(env_file)}, clear=False):
                self.assertEqual(config_env.env_value("ARBOR_HOST", "127.0.0.1"), "0.0.0.0")
                self.assertTrue(config_env.env_enabled("ARBOR_ENABLE_OVERLAY_ADD"))

    def test_file_first_env_overrides_stale_process_env_for_totp_settings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / "arbor.env"
            env_file.write_text(
                "ARBOR_AUTH_MODE=totp\nARBOR_TOTP_SECRET_FILE=/tmp/totp.secret\n",
                encoding="utf-8",
            )

            with patch.dict(
                "os.environ",
                {
                    "ARBOR_ENV_FILE": str(env_file),
                    "ARBOR_AUTH_MODE": "cli",
                    "ARBOR_TOTP_SECRET_FILE": "/stale/path",
                },
                clear=False,
            ):
                self.assertEqual(approval_mode.get_login_auth_mode(), approval_mode.ApprovalMode.TOTP)
                self.assertEqual(str(approval_mode.totp_secret_path()), "/tmp/totp.secret")

    def test_server_run_reads_bind_and_tls_settings_from_arbor_env(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            cert = root / "cert.pem"
            key = root / "key.pem"
            cert.write_text("cert\n", encoding="utf-8")
            key.write_text("key\n", encoding="utf-8")
            env_file = root / "arbor.env"
            env_file.write_text(
                f"ARBOR_HOST=0.0.0.0\nARBOR_PORT=9443\nARBOR_CERT={cert}\nARBOR_KEY={key}\n",
                encoding="utf-8",
            )

            with patch.dict("os.environ", {"ARBOR_ENV_FILE": str(env_file)}, clear=False):
                with patch.object(server_mod, "load_ipc_key"):
                    with patch.object(server_mod.uvicorn, "run") as run_mock:
                        server_mod.run()

        run_mock.assert_called_once_with(
            "arbor.main:app",
            host="0.0.0.0",
            port=9443,
            ssl_certfile=str(cert),
            ssl_keyfile=str(key),
            log_level="info",
            log_config=server_mod._log_config(),
            proxy_headers=True,
            forwarded_allow_ips="127.0.0.1",
        )

    def test_server_run_skips_cert_lookup_when_tls_disabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / "arbor.env"
            env_file.write_text(
                "ARBOR_HOST=127.0.0.1\nARBOR_PORT=8444\nARBOR_TLS=0\n",
                encoding="utf-8",
            )

            with (
                patch.dict("os.environ", {"ARBOR_ENV_FILE": str(env_file)}, clear=False),
                patch.object(server_mod, "load_ipc_key"),
                patch.object(server_mod, "validate_approval_mode_config", return_value=approval_mode.ApprovalMode.CLI),
                patch.object(server_mod.os.path, "exists", side_effect=AssertionError("cert lookup should be skipped")),
                patch.object(server_mod.uvicorn, "run") as run_mock,
            ):
                server_mod.run()

        run_mock.assert_called_once_with(
            "arbor.main:app",
            host="127.0.0.1",
            port=8444,
            ssl_certfile=None,
            ssl_keyfile=None,
            log_level="info",
            log_config=server_mod._log_config(),
            proxy_headers=True,
            forwarded_allow_ips="127.0.0.1",
        )

    def test_server_run_requires_cert_when_tls_explicitly_enabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / "arbor.env"
            env_file.write_text(
                "ARBOR_HOST=127.0.0.1\nARBOR_PORT=8443\nARBOR_TLS=1\n",
                encoding="utf-8",
            )

            with patch.dict("os.environ", {"ARBOR_ENV_FILE": str(env_file)}, clear=False):
                with self.assertRaises(SystemExit) as ctx:
                    server_mod.run()

        self.assertEqual(ctx.exception.code, 2)

    def test_web_main_reads_cors_origins_from_arbor_env(self):
        original_origins = list(web_main._cors_origins)
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / "arbor.env"
            env_file.write_text(
                "ARBOR_CORS_ORIGINS=https://192.168.1.10:8443,https://arbor.lan:8443\n",
                encoding="utf-8",
            )

            with patch.dict("os.environ", {"ARBOR_ENV_FILE": str(env_file)}, clear=False):
                reloaded = importlib.reload(web_main)
                self.assertEqual(
                    reloaded._cors_origins,
                    ["https://192.168.1.10:8443", "https://arbor.lan:8443"],
                )
        importlib.reload(web_main)
        self.assertEqual(web_main._cors_origins, original_origins)


if __name__ == "__main__":
    unittest.main()
