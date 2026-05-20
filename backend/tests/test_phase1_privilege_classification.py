import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import daemon.main as daemon_main
from arbor.action_security import (
    APPROVAL_REQUIRED,
    DESTRUCTIVE,
    PRETEND,
    READONLY,
    TRUST_HEAVY,
    action_metadata,
)


class ActionClassificationTests(unittest.TestCase):
    def test_representative_actions_are_classified_server_side(self):
        self.assertEqual(action_metadata("system_status")["action_class"], READONLY)
        self.assertFalse(action_metadata("system_status")["approval_required"])

        pretend = action_metadata("emerge_pretend", {"atom": "sys-apps/portage"})
        self.assertEqual(pretend["action_class"], PRETEND)
        self.assertFalse(pretend["approval_required"])

        install = action_metadata("emerge_install", {"atom": "sys-apps/portage"})
        self.assertEqual(install["action_class"], APPROVAL_REQUIRED)
        self.assertTrue(install["approval_required"])
        self.assertEqual(install["confirmation_tier"], "standard")

        overlay_add = action_metadata(
            "overlay_add",
            {"name": "foo", "sync_type": "git", "sync_uri": "https://example.invalid/repo.git"},
        )
        self.assertEqual(overlay_add["action_class"], TRUST_HEAVY)
        self.assertEqual(overlay_add["action_target"], "foo https://example.invalid/repo.git")
        self.assertEqual(overlay_add["confirmation_tier"], "strong")

        overlay_purge = action_metadata("overlay_remove", {"name": "foo", "purge": True})
        self.assertEqual(overlay_purge["action_class"], DESTRUCTIVE)
        self.assertEqual(overlay_purge["confirmation_tier"], "strong")

        etc_replace = action_metadata("etc_update_resolve", {"cfg_file": "/etc/portage/make.conf", "action": "replace"})
        self.assertEqual(etc_replace["action_class"], TRUST_HEAVY)

    def test_unknown_commands_fail_closed(self):
        meta = action_metadata("unexpected_command", {})
        self.assertEqual(meta["action_class"], APPROVAL_REQUIRED)
        self.assertTrue(meta["approval_required"])


class JobMetadataPersistenceTests(unittest.TestCase):
    def test_job_summary_exposes_action_metadata(self):
        job = daemon_main._Job(
            "sys-apps/portage",
            None,
            kind="install",
            action_cmd="emerge_install",
            action_class=APPROVAL_REQUIRED,
            action_target="sys-apps/portage",
        )

        summary = daemon_main._job_summary("job-1", job)

        self.assertEqual(summary["action_cmd"], "emerge_install")
        self.assertEqual(summary["action_class"], APPROVAL_REQUIRED)
        self.assertEqual(summary["action_target"], "sys-apps/portage")

    def test_history_rows_persist_action_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "history.db")
            with patch.object(daemon_main, "_DB_PATH", db_path):
                daemon_main._db_init()
                daemon_main._history_save(
                    "job-1",
                    "sys-apps/portage",
                    "install",
                    "done",
                    0,
                    10.0,
                    20.0,
                    "ok\n",
                    "emerge_install",
                    APPROVAL_REQUIRED,
                    "sys-apps/portage",
                )

                history = daemon_main._history_list(50, 0, "")

        self.assertEqual(history["items"][0]["action_cmd"], "emerge_install")
        self.assertEqual(history["items"][0]["action_class"], APPROVAL_REQUIRED)
        self.assertEqual(history["items"][0]["action_target"], "sys-apps/portage")

    def test_recovered_legacy_job_infers_missing_action_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = Path(tmpdir) / "jobs"
            db_path = str(Path(tmpdir) / "history.db")
            state_dir.mkdir()
            (state_dir / "job-1.json").write_text(
                '{"job_id":"job-1","kind":"install","atom":"sys-apps/portage","pid":1234,"created_at":10.0,"started_at":12.0,"status_updated_at":12.0}',
                encoding="utf-8",
            )

            with patch.object(daemon_main, "_STATE_DIR", state_dir):
                with patch.object(daemon_main, "_DB_PATH", db_path):
                    daemon_main._db_init()
                    with patch.object(daemon_main, "_pid_matches", return_value=False):
                        recovered = daemon_main._load_recovered_jobs()

        job = recovered["job-1"]
        self.assertEqual(job.action_cmd, "emerge_install")
        self.assertEqual(job.action_class, APPROVAL_REQUIRED)
        self.assertEqual(job.action_target, "sys-apps/portage")


if __name__ == "__main__":
    unittest.main()
