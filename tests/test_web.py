import sys
import types
import unittest

sys.modules.setdefault("yaml", types.SimpleNamespace(safe_load=lambda _: {}))

try:
    import flask  # noqa: F401
except ImportError:  # pragma: no cover
    flask = None

from localnetworkprotector.config import build_config

if flask is not None:
    from localnetworkprotector.web import create_app


@unittest.skipIf(flask is None, "Flask is not installed")
class WebApiAuthTests(unittest.TestCase):
    def test_api_token_allows_access_without_session(self):
        config = build_config(
            {
                "web": {
                    "auth_enabled": True,
                    "username": "admin",
                    "password": "password",
                    "api_tokens": ["secret-token"],
                    "session_secret": "secret",
                }
            }
        )

        db_manager = types.SimpleNamespace(
            get_scan_history_page=lambda page, per_page, status=None: {
                "items": [{"id": 1, "status": "COMPLETED"}],
                "page": page,
                "per_page": per_page,
                "total": 1,
                "pages": 1,
                "has_prev": False,
                "has_next": False,
            },
            get_scan_details=lambda scan_id, findings_page=1, findings_per_page=25: {
                "id": scan_id,
                "findings_page": {
                    "items": [],
                    "page": findings_page,
                    "per_page": findings_per_page,
                    "total": 0,
                    "pages": 0,
                    "has_prev": False,
                    "has_next": False,
                },
                "findings": [],
            },
            get_dashboard_stats=lambda: {"device_count": 0, "scan_count": 0, "tsunami_count": 0},
            get_recent_findings=lambda limit=5: [],
            get_eero_devices=lambda: [],
            get_tsunami_findings=lambda: [],
        )
        app = create_app(config, db_manager, monitor_service=None)
        app.config["TESTING"] = True

        with app.test_client() as client:
            response = client.get(
                "/api/scans",
                headers={"Authorization": "Bearer secret-token"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["items"][0]["id"], 1)


if __name__ == "__main__":
    unittest.main()
