import tempfile
import textwrap
import unittest
from pathlib import Path

from localnetworkprotector.repo_scanner import RepoScanner


class RepoScannerTests(unittest.TestCase):
    def test_parse_scan_result_extracts_package_and_generic_findings(self):
        sample = textwrap.dedent(
            """
            package_vulns {
              vuln {
                id: "GHSA-1234"
                severity: "HIGH"
              }
              package_id: "pkg:npm/example@1.0.0"
            }
            generic_findings {
              adv {
                id {
                  publisher: "CVE"
                  reference: "2026-9999"
                }
                sev: CRITICAL
              }
            }
            """
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            result_path = Path(temp_dir) / "result.textproto"
            result_path.write_text(sample, encoding="utf-8")
            findings = RepoScanner.parse_scan_result(result_path)

        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].vulnerability_id, "GHSA-1234")
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[1].vulnerability_id, "CVE-2026-9999")
        self.assertEqual(findings[1].severity, "critical")


if __name__ == "__main__":
    unittest.main()
