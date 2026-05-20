import importlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import arbor.auth as auth_mod
import arbor.config_env as config_env
import arbor.main as web_main
import arbor.server as server_mod
import daemon.main as daemon_main


class FakeTokenFile:
    def __init__(self, text="file-token", exists=True, mtime_ns=1):
        self.text = text
        self.exists = exists
        self.mtime_ns = mtime_ns
        self.read_calls = 0

    def stat(self):
        if not self.exists:
            raise FileNotFoundError
        return SimpleNamespace(st_mtime_ns=self.mtime_ns)

    def read_text(self):
        self.read_calls += 1
        return self.text

    def __str__(self):
        return "/fake/token"


class AuthCachingTests(unittest.TestCase):
    def setUp(self):
        self._saved = {
            "_ephemeral_token": auth_mod._ephemeral_token,
            "_cached_file_token": auth_mod._cached_file_token,
            "_cached_file_token_mtime_ns": auth_mod._cached_file_token_mtime_ns,
            "_warned_missing_token_file": auth_mod._warned_missing_token_file,
            "_printed_ephemeral_token": auth_mod._printed_ephemeral_token,
        }
        auth_mod._ephemeral_token = None
        auth_mod._cached_file_token = None
        auth_mod._cached_file_token_mtime_ns = None
        auth_mod._warned_missing_token_file = False
        auth_mod._printed_ephemeral_token = False

    def tearDown(self):
        for key, value in self._saved.items():
            setattr(auth_mod, key, value)

    def test_get_token_caches_file_contents_until_mtime_changes(self):
        fake = FakeTokenFile(text="alpha", exists=True, mtime_ns=1)
        with patch.object(auth_mod, "TOKEN_FILE", fake):
            self.assertEqual(auth_mod.get_token(), "alpha")
            self.assertEqual(auth_mod.get_token(), "alpha")
            self.assertEqual(fake.read_calls, 1)

            fake.text = "beta"
            fake.mtime_ns = 2
            self.assertEqual(auth_mod.get_token(), "beta")
            self.assertEqual(fake.read_calls, 2)

    def test_get_token_warns_without_printing_value_when_file_disappears(self):
        fake = FakeTokenFile(text="alpha", exists=True, mtime_ns=1)
        with patch.object(auth_mod, "TOKEN_FILE", fake):
            self.assertEqual(auth_mod.get_token(), "alpha")
            fake.exists = False
            with patch.object(auth_mod.log, "warning") as warning:
                with patch("arbor.auth.secrets.token_urlsafe", return_value="ephemeral"):
                    with patch("builtins.print") as print_mock:
                        self.assertEqual(auth_mod.get_token(), "ephemeral")

        warning.assert_called_once()
        print_mock.assert_not_called()


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
        )

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
