import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import daemon.main as daemon_main


class JobRecoveryTests(unittest.IsolatedAsyncioTestCase):
    def test_pid_matches_uses_start_time_when_available(self):
        with patch.object(daemon_main, "_pid_is_running", return_value=True):
            with patch.object(daemon_main, "_pid_start_time", return_value=1234):
                self.assertTrue(daemon_main._pid_matches(42, 1234))
                self.assertFalse(daemon_main._pid_matches(42, 9999))

    def test_checkpoint_running_job_saves_log_and_resets_dirty_counters(self):
        job = daemon_main._Job("sys-apps/portage", None, kind="world", created_at=10.0)
        job._push({"line": "line one"})
        job._history_lines_since_flush = daemon_main.RUNNING_HISTORY_FLUSH_LINES

        with patch.object(daemon_main, "_history_checkpoint_save") as checkpoint_save:
            daemon_main._checkpoint_running_job("job-1", job, now=55.0)

        checkpoint_save.assert_called_once_with(
            "job-1",
            "sys-apps/portage",
            "world",
            10.0,
            55.0,
            "line one\n",
            "emerge_world_update",
            "approval_required",
            "sys-apps/portage",
        )
        self.assertEqual(job._history_lines_since_flush, 0)
        self.assertEqual(job._history_checkpointed_at, 55.0)

    def test_load_recovered_jobs_uses_checkpoint_when_pid_identity_is_gone(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = Path(tmpdir) / "jobs"
            db_path = str(Path(tmpdir) / "history.db")
            state_dir.mkdir()
            (state_dir / "job-1.json").write_text(
                json.dumps(
                    {
                        "job_id": "job-1",
                        "kind": "world",
                        "atom": "@world",
                        "pid": 1234,
                        "pid_started_at": 9999,
                        "created_at": 10.0,
                        "started_at": 12.0,
                        "status_updated_at": 12.0,
                    }
                ),
                encoding="utf-8",
            )

            with patch.object(daemon_main, "_STATE_DIR", state_dir):
                with patch.object(daemon_main, "_DB_PATH", db_path):
                    daemon_main._db_init()
                    daemon_main._history_checkpoint_save("job-1", "@world", "world", 10.0, 20.0, "partial log\n")
                    with patch.object(daemon_main, "_pid_matches", return_value=False):
                        recovered = daemon_main._load_recovered_jobs()

                    self.assertEqual(recovered["job-1"].status, "unknown")
                    history = daemon_main._history_log("job-1")
                    self.assertEqual(history["log"], "partial log\n")
                    self.assertIsNone(daemon_main._history_checkpoint_load("job-1"))

    async def test_reconcile_recovered_jobs_promotes_orphaned_job_and_persists_history(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = Path(tmpdir) / "jobs"
            db_path = str(Path(tmpdir) / "history.db")
            state_dir.mkdir()
            job = daemon_main._Job(
                "@world",
                None,
                kind="world",
                status="orphaned",
                created_at=10.0,
                started_at=12.0,
                pid=1234,
                pid_started_at=9999,
                recovered=True,
                status_note="job process still exists after daemon restart, but live output cannot be reattached",
            )

            with patch.object(daemon_main, "_STATE_DIR", state_dir):
                with patch.object(daemon_main, "_DB_PATH", db_path):
                    daemon_main._db_init()
                    daemon_main._history_checkpoint_save("job-2", "@world", "world", 10.0, 20.0, "checkpoint log\n")
                    original_jobs = daemon_main._jobs
                    daemon_main._jobs = {"job-2": job}
                    try:
                        with patch.object(daemon_main, "_pid_matches", return_value=False):
                            await daemon_main._reconcile_recovered_jobs_once()
                    finally:
                        daemon_main._jobs = original_jobs

                    self.assertEqual(job.status, "unknown")
                    self.assertIn("final state is unknown", job.status_note)
                    history = daemon_main._history_log("job-2")
                    self.assertEqual(history["log"], "checkpoint log\n")
                    self.assertIsNone(daemon_main._history_checkpoint_load("job-2"))


if __name__ == "__main__":
    unittest.main()
