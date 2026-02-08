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

CREATE TABLE IF NOT EXISTS eero_devices (
    mac TEXT PRIMARY KEY,
    hostname TEXT,
    ip TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    details_json TEXT
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

    def get_known_eero_macs(self) -> set[str]:
        """Retrieve all known Eero device MAC addresses."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT mac FROM eero_devices")
                return {row[0] for row in cursor.fetchall()}
        except Exception as e:
            log.error("Failed to fetch known Eero MACs: %s", e)
            return set()

    def record_eero_device(self, device: Dict[str, Any]) -> None:
        """Insert or update an Eero device record."""
        try:
            mac = device.get('mac')
            if not mac:
                return

            timestamp = datetime.now(tz=timezone.utc).isoformat()
            hostname = device.get('nickname') or device.get('hostname') or "Unknown"
            ip = device.get('ip', '')
            details_json = json.dumps(device)

            with sqlite3.connect(self.db_path) as conn:
                # Check if exists to preserve first_seen
                cursor = conn.cursor()
                cursor.execute("SELECT first_seen FROM eero_devices WHERE mac = ?", (mac,))
                row = cursor.fetchone()
                
                if row:
                    # Update existing
                    conn.execute(
                        """
                        UPDATE eero_devices 
                        SET hostname=?, ip=?, last_seen=?, details_json=?
                        WHERE mac=?
                        """,
                        (hostname, ip, timestamp, details_json, mac)
                    )
                else:
                    # Insert new
                    conn.execute(
                        """
                        INSERT INTO eero_devices 
                        (mac, hostname, ip, first_seen, last_seen, details_json)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (mac, hostname, ip, timestamp, timestamp, details_json)
                    )
        except Exception as e:
            log.error("Failed to record Eero device %s: %s", device.get('mac'), e)

    def get_tsunami_findings(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent Tsunami scanner findings."""
        findings = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Tsunami findings are identified by looking for "tsunami" in details_json
                # This is a simple heuristic based on how we store them in monitor.py
                cursor.execute(
                    """
                    SELECT * FROM findings 
                    WHERE details_json LIKE '%"service": "tsunami-scanner"%' 
                    ORDER BY id DESC LIMIT ?
                    """, 
                    (limit,)
                )
                cols = [desc[0] for desc in cursor.description]
                findings = [dict(zip(cols, row)) for row in cursor.fetchall()]
        except Exception as e:
            log.error("Failed to fetch Tsunami findings: %s", e)
        return findings
