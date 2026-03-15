import tempfile
import unittest

from localnetworkprotector.database import DatabaseManager


class DatabasePaginationTests(unittest.TestCase):
    def test_scan_history_and_findings_are_paginated(self):
        with tempfile.NamedTemporaryFile(suffix=".db") as handle:
            db = DatabaseManager(handle.name)
            db.init_db()

            scan_one = db.record_scan("192.168.1.10", status="COMPLETED")
            scan_two = db.record_scan("192.168.1.11", status="FAILED")
            db.record_finding(scan_one, "alert", "medium", "one", {"k": "v"})
            db.record_finding(scan_one, "alert", "medium", "two", {"k": "v"})
            db.record_finding(scan_two, "alert", "high", "three", {"k": "v"})

            page_one = db.get_scan_history_page(page=1, per_page=1)
            page_two = db.get_scan_history_page(page=2, per_page=1)
            findings_page = db.get_findings_for_scan_page(scan_one, page=1, per_page=1)

        self.assertEqual(page_one["total"], 2)
        self.assertEqual(page_one["pages"], 2)
        self.assertEqual(len(page_one["items"]), 1)
        self.assertTrue(page_one["has_next"])
        self.assertEqual(len(page_two["items"]), 1)
        self.assertTrue(page_two["has_prev"])
        self.assertEqual(findings_page["total"], 2)
        self.assertEqual(findings_page["pages"], 2)
        self.assertEqual(len(findings_page["items"]), 1)


if __name__ == "__main__":
    unittest.main()
