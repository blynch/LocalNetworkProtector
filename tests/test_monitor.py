import sys
import types
import unittest

sys.modules.setdefault("yaml", types.SimpleNamespace(safe_load=lambda _: {}))

from localnetworkprotector.config import build_config
from localnetworkprotector.monitor import MonitorService


class FakeScanner:
    def __init__(self):
        self.calls = []

    def scan_host(self, ip, ports, arguments):
        self.calls.append((ip, ports, arguments))
        return []


class FakeVulnerabilityManager:
    def check_service(self, product, version, cpe):
        return []


class FakeDatabase:
    def __init__(self):
        self.status_updates = []

    def record_scan(self, ip, status="STARTED"):
        self.status_updates.append(("record", ip, status))
        return 1

    def update_scan_status(self, scan_id, status):
        self.status_updates.append(("update", scan_id, status))

    def record_finding(self, **kwargs):
        pass


class MonitorSafetyTests(unittest.TestCase):
    def build_monitor(self, config_dict):
        config = build_config(config_dict)
        return MonitorService(
            config=config,
            detection_engine=types.SimpleNamespace(inspect=lambda packet: []),
            active_scanner=FakeScanner(),
            vulnerability_manager=FakeVulnerabilityManager(),
            alert_callback=lambda alert: None,
            database=FakeDatabase(),
            telemetry=None,
            eero_manager=None,
            tsunami_scanner=None,
        )

    def test_rejects_public_ip_when_not_allowlisted(self):
        monitor = self.build_monitor(
            {
                "active_scanning": {
                    "enabled": True,
                    "ports": "80",
                    "arguments": "-sV",
                }
            }
        )

        accepted, message = monitor.request_scan("8.8.8.8")

        self.assertFalse(accepted)
        self.assertIn("not private/local", message)
        self.assertEqual(monitor.active_scanner.calls, [])

    def test_allows_allowlisted_public_ip(self):
        monitor = self.build_monitor(
            {
                "active_scanning": {
                    "enabled": True,
                    "ports": "80,443",
                    "arguments": "-sV -Pn",
                    "allowed_targets": ["8.8.8.8/32"],
                }
            }
        )

        accepted, message = monitor.request_scan("8.8.8.8")

        self.assertTrue(accepted)
        self.assertEqual(message, "Scan completed")
        self.assertEqual(
            monitor.active_scanner.calls,
            [("8.8.8.8", "80,443", "-sV -Pn")],
        )


if __name__ == "__main__":
    unittest.main()
