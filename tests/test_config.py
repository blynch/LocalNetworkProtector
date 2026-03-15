import sys
import types
import unittest

sys.modules.setdefault("yaml", types.SimpleNamespace(safe_load=lambda _: {}))

from localnetworkprotector.config import build_config


class ConfigLoadTests(unittest.TestCase):
    def test_builds_web_database_and_tsunami_config(self):
        config = build_config(
            {
                "log_level": "DEBUG",
                "database_path": "custom.db",
                "detection": {
                    "trusted_ips": ["192.168.1.10"],
                    "tsunami": {
                        "enabled": True,
                        "docker_image": "custom/tsunami",
                        "scan_timeout": 120,
                    },
                },
                "active_scanning": {
                    "enabled": True,
                    "ports": "80,443",
                    "arguments": "-sV -Pn",
                    "allowed_targets": ["203.0.113.5/32"],
                    "allow_public_targets": False,
                },
                "web": {
                    "enabled": False,
                    "host": "127.0.0.1",
                    "port": 5050,
                    "auth_enabled": True,
                    "username": "lnp-admin",
                    "password_hash": "hash",
                    "session_secret": "secret",
                    "api_tokens": ["token-1", "token-2"],
                },
                "repo_scanning": {
                    "enabled": True,
                    "schedule_time": "04:30",
                    "github_account": "blynch",
                    "repo_limit": 10,
                    "local_workspace": "/opt/repos",
                    "results_dir": "/opt/repo-results",
                    "scalibr_binary": "/root/go/bin/scalibr",
                },
            }
        )

        self.assertEqual(config.log_level, "DEBUG")
        self.assertEqual(config.database_path, "custom.db")
        self.assertEqual(config.detection.trusted_ips, ["192.168.1.10"])
        self.assertTrue(config.detection.tsunami.enabled)
        self.assertEqual(config.detection.tsunami.docker_image, "custom/tsunami")
        self.assertEqual(config.detection.tsunami.scan_timeout, 120)
        self.assertTrue(config.active_scanning.enabled)
        self.assertEqual(config.active_scanning.ports, "80,443")
        self.assertEqual(config.active_scanning.arguments, "-sV -Pn")
        self.assertEqual(config.active_scanning.allowed_targets, ["203.0.113.5/32"])
        self.assertFalse(config.active_scanning.allow_public_targets)
        self.assertFalse(config.web.enabled)
        self.assertEqual(config.web.host, "127.0.0.1")
        self.assertEqual(config.web.port, 5050)
        self.assertTrue(config.web.auth_enabled)
        self.assertEqual(config.web.username, "lnp-admin")
        self.assertEqual(config.web.password_hash, "hash")
        self.assertEqual(config.web.session_secret, "secret")
        self.assertEqual(config.web.api_tokens, ["token-1", "token-2"])
        self.assertTrue(config.repo_scanning.enabled)
        self.assertEqual(config.repo_scanning.schedule_time, "04:30")
        self.assertEqual(config.repo_scanning.github_account, "blynch")
        self.assertEqual(config.repo_scanning.repo_limit, 10)
        self.assertEqual(config.repo_scanning.local_workspace, "/opt/repos")
        self.assertEqual(config.repo_scanning.results_dir, "/opt/repo-results")
        self.assertEqual(config.repo_scanning.scalibr_binary, "/root/go/bin/scalibr")


if __name__ == "__main__":
    unittest.main()
