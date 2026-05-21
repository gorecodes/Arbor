import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import arbor.local_auth_cli as local_auth_cli


class LocalAuthCliTests(unittest.TestCase):
    def test_status_reports_empty_then_initialized(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "auth.db"
            env = {"ARBOR_AUTH_DB": str(db)}
            with patch.dict(os.environ, env, clear=False):
                with patch("builtins.print") as p:
                    rc = local_auth_cli.main(["status"])
                    self.assertEqual(rc, 0)
                    self.assertEqual(p.call_args.args[0], "empty")

                with patch("builtins.print"):
                    rc = local_auth_cli.main(
                        ["create-owner", "--username", "owner", "--password", "secret-password"]
                    )
                    self.assertEqual(rc, 0)

                with patch("builtins.print") as p:
                    rc = local_auth_cli.main(["status"])
                    self.assertEqual(rc, 0)
                    self.assertEqual(p.call_args.args[0], "initialized")

    def test_create_owner_rejects_short_password(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "auth.db"
            env = {"ARBOR_AUTH_DB": str(db)}
            with patch.dict(os.environ, env, clear=False):
                with patch("builtins.print"):
                    rc = local_auth_cli.main(["create-owner", "--username", "owner", "--password", "short"])
                self.assertEqual(rc, 2)

    def test_create_user_with_operator_role_and_list_users(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "auth.db"
            env = {"ARBOR_AUTH_DB": str(db)}
            with patch.dict(os.environ, env, clear=False):
                with patch("builtins.print"):
                    rc = local_auth_cli.main(
                        ["create-user", "--username", "op1", "--role", "operator", "--password", "secret-password"]
                    )
                self.assertEqual(rc, 0)

                with patch("builtins.print") as printed:
                    rc = local_auth_cli.main(["list-users"])
                self.assertEqual(rc, 0)
                lines = [call.args[0] for call in printed.call_args_list]
                self.assertTrue(any(line.startswith("op1\toperator\tactive\t") for line in lines))

    def test_set_role_updates_existing_user(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "auth.db"
            env = {"ARBOR_AUTH_DB": str(db)}
            with patch.dict(os.environ, env, clear=False):
                with patch("builtins.print"):
                    rc = local_auth_cli.main(
                        ["create-user", "--username", "viewer1", "--role", "viewer", "--password", "secret-password"]
                    )
                self.assertEqual(rc, 0)
                with patch("builtins.print"):
                    rc = local_auth_cli.main(["set-role", "--username", "viewer1", "--role", "operator"])
                self.assertEqual(rc, 0)
                with patch("builtins.print") as printed:
                    rc = local_auth_cli.main(["list-users"])
                self.assertEqual(rc, 0)
                lines = [call.args[0] for call in printed.call_args_list]
                self.assertTrue(any(line.startswith("viewer1\toperator\tactive\t") for line in lines))


if __name__ == "__main__":
    unittest.main()
