import unittest
from unittest.mock import MagicMock
from appsecctl import history


class HistoryPurgeTests(unittest.TestCase):
    def test_unknown_pipeline_cannot_be_removed(self):
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = None
        with self.assertRaises(LookupError):
            history.purge_pipeline(conn, "00000000-0000-0000-0000-000000000123")

    def test_active_jobs_block_deletion(self):
        conn = MagicMock()
        conn.execute.side_effect = [
            MagicMock(fetchone=lambda: {"id": "existing"}),
            MagicMock(fetchall=lambda: [{"status": "running"}]),
        ]
        with self.assertRaisesRegex(RuntimeError, "Pending or running"):
            history.purge_pipeline(conn, "00000000-0000-0000-0000-000000000123")

    def test_untrusted_file_path_rejected(self):
        with self.assertRaisesRegex(ValueError, "outside /reports"):
            history.remove_evidence({"/etc/passwd"}, "00000000-0000-0000-0000-000000000123")
