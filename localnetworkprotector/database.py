"""Database management for storing scan results and findings."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    target_ip TEXT,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    timestamp TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    details_json TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);
"""

class DatabaseManager:
    """Manages SQLite database interactions."""

    def __init__(self, db_path: str = "lnp.db"):
        self.db_path = Path(db_path)

    def init_db(self) -> None:
        """Initialize database schema."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.executescript(SCHEMA_SQL)
        except Exception as e:
            log.error("Failed to initialize database: %s", e)

    def record_scan(self, target_ip: str, status: str = "COMPLETED") -> int:
        """Record a scan event and return its ID."""
        try:
            timestamp = datetime.now(tz=timezone.utc).isoformat()
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO scans (timestamp, target_ip, status) VALUES (?, ?, ?)",
                    (timestamp, target_ip, status),
                )
                return cursor.lastrowid or -1
        except Exception as e:
            log.error("Failed to record scan: %s", e)
            return -1

    def record_finding(
        self,
        scan_id: Optional[int],
        type_: str,
        severity: str,
        description: str,
        details: Dict[str, Any],
    ) -> None:
        """Record a finding (vulnerability or alert)."""
        try:
            timestamp = datetime.now(tz=timezone.utc).isoformat()
            details_json = json.dumps(details)
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO findings 
                    (scan_id, timestamp, type, severity, description, details_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (scan_id, timestamp, type_, severity, description, details_json),
                )
        except Exception as e:
            log.error("Failed to record finding: %s", e)
