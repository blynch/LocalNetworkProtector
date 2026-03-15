import unittest

from localnetworkprotector.scanner import ActiveScanner


class FakePortScanner:
    def __init__(self):
        self.calls = []

    def scan(self, ip, ports, arguments):
        self.calls.append((ip, ports, arguments))

    def all_hosts(self):
        return []


class ActiveScannerTests(unittest.TestCase):
    def test_scan_host_uses_configured_ports_and_arguments(self):
        scanner = ActiveScanner.__new__(ActiveScanner)
        scanner._nm = FakePortScanner()

        result = scanner.scan_host("192.168.1.50", ports="80,443", arguments="-sV -Pn")

        self.assertEqual(result, [])
        self.assertEqual(
            scanner._nm.calls,
            [("192.168.1.50", "80,443", "-sV -Pn")],
        )


if __name__ == "__main__":
    unittest.main()
