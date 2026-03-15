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

CREATE TABLE IF NOT EXISTS repo_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    repo_url TEXT,
    local_path TEXT,
    status TEXT NOT NULL,
    vulnerability_count INTEGER NOT NULL DEFAULT 0,
    result_path TEXT
);

CREATE TABLE IF NOT EXISTS repo_scan_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_scan_id INTEGER NOT NULL,
    vulnerability_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    package_name TEXT,
    details_json TEXT,
    FOREIGN KEY(repo_scan_id) REFERENCES repo_scans(id)
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

    def update_scan_status(self, scan_id: Optional[int], status: str) -> None:
        """Update a previously recorded scan status."""
        if not scan_id or scan_id < 0:
            return
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "UPDATE scans SET status = ? WHERE id = ?",
                    (status, scan_id),
                )
        except Exception as e:
            log.error("Failed to update scan %s status to %s: %s", scan_id, status, e)

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

    def get_dashboard_stats(self) -> Dict[str, int]:
        """Return top-level dashboard metrics."""
        stats = {
            "device_count": 0,
            "scan_count": 0,
            "tsunami_count": 0,
            "repo_scan_count": 0,
            "repo_vulnerability_count": 0,
        }
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM eero_devices")
                stats["device_count"] = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM scans")
                stats["scan_count"] = cursor.fetchone()[0]
                cursor.execute(
                    """
                    SELECT COUNT(*) FROM findings
                    WHERE details_json LIKE '%"service": "tsunami-scanner"%'
                    """
                )
                stats["tsunami_count"] = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM repo_scans")
                stats["repo_scan_count"] = cursor.fetchone()[0]
                cursor.execute(
                    "SELECT COALESCE(SUM(vulnerability_count), 0) FROM repo_scans WHERE status = 'COMPLETED'"
                )
                stats["repo_vulnerability_count"] = cursor.fetchone()[0]
        except Exception as e:
            log.error("Failed to fetch dashboard stats: %s", e)
        return stats

    def get_recent_findings(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Return recent findings ordered by newest first."""
        findings: List[Dict[str, Any]] = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM findings ORDER BY id DESC LIMIT ?", (limit,))
                cols = [desc[0] for desc in cursor.description]
                findings = [dict(zip(cols, row)) for row in cursor.fetchall()]
        except Exception as e:
            log.error("Failed to fetch recent findings: %s", e)
        return findings

    def get_eero_devices(self) -> List[Dict[str, Any]]:
        """Return known Eero devices ordered by last seen descending."""
        devices: List[Dict[str, Any]] = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM eero_devices ORDER BY last_seen DESC")
                cols = [desc[0] for desc in cursor.description]
                devices = [dict(zip(cols, row)) for row in cursor.fetchall()]
        except Exception as e:
            log.error("Failed to fetch Eero devices: %s", e)
        return devices

    def get_scan_history(
        self,
        limit: int = 50,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return recent scan history with per-scan finding counts."""
        return self.get_scan_history_page(page=1, per_page=limit, status=status)["items"]

    def get_scan_history_page(
        self,
        page: int = 1,
        per_page: int = 50,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return paginated scan history with metadata."""
        scans: List[Dict[str, Any]] = []
        total = 0
        page = max(1, page)
        per_page = max(1, min(per_page, 200))
        offset = (page - 1) * per_page
        try:
            where_clause = ""
            where_params: List[Any] = []
            if status:
                where_clause = " WHERE scans.status = ?"
                where_params.append(status)

            count_query = f"SELECT COUNT(*) FROM scans{where_clause}"
            query = """
                SELECT
                    scans.id,
                    scans.timestamp,
                    scans.target_ip,
                    scans.status,
                    COUNT(findings.id) AS finding_count
                FROM scans
                LEFT JOIN findings ON findings.scan_id = scans.id
            """
            if status:
                query += " WHERE scans.status = ?"
            params = list(where_params)
            query += """
                GROUP BY scans.id, scans.timestamp, scans.target_ip, scans.status
                ORDER BY scans.id DESC
                LIMIT ? OFFSET ?
            """
            params.extend([per_page, offset])

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(count_query, where_params)
                total = cursor.fetchone()[0]
                cursor.execute(query, params)
                cols = [desc[0] for desc in cursor.description]
                scans = [dict(zip(cols, row)) for row in cursor.fetchall()]
        except Exception as e:
            log.error("Failed to fetch scan history: %s", e)
        pages = (total + per_page - 1) // per_page if total else 0
        return {
            "items": scans,
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": pages,
            "has_prev": page > 1,
            "has_next": page < pages,
        }

    def get_scan_details(
        self,
        scan_id: int,
        findings_page: int = 1,
        findings_per_page: int = 25,
    ) -> Optional[Dict[str, Any]]:
        """Return a single scan with its associated findings."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT
                        scans.id,
                        scans.timestamp,
                        scans.target_ip,
                        scans.status,
                        COUNT(findings.id) AS finding_count
                    FROM scans
                    LEFT JOIN findings ON findings.scan_id = scans.id
                    WHERE scans.id = ?
                    GROUP BY scans.id, scans.timestamp, scans.target_ip, scans.status
                    """,
                    (scan_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    return None
                cols = [desc[0] for desc in cursor.description]
                scan = dict(zip(cols, row))
                scan["findings_page"] = self.get_findings_for_scan_page(
                    scan_id,
                    page=findings_page,
                    per_page=findings_per_page,
                )
                scan["findings"] = scan["findings_page"]["items"]
                return scan
        except Exception as e:
            log.error("Failed to fetch scan %s details: %s", scan_id, e)
            return None

    def get_findings_for_scan(self, scan_id: int) -> List[Dict[str, Any]]:
        """Return findings associated with a scan."""
        return self.get_findings_for_scan_page(scan_id)["items"]

    def get_findings_for_scan_page(
        self,
        scan_id: int,
        page: int = 1,
        per_page: int = 25,
    ) -> Dict[str, Any]:
        """Return paginated findings associated with a scan."""
        findings: List[Dict[str, Any]] = []
        total = 0
        page = max(1, page)
        per_page = max(1, min(per_page, 200))
        offset = (page - 1) * per_page
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT COUNT(*) FROM findings WHERE scan_id = ?",
                    (scan_id,),
                )
                total = cursor.fetchone()[0]
                cursor.execute(
                    """
                    SELECT * FROM findings
                    WHERE scan_id = ?
                    ORDER BY id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (scan_id, per_page, offset),
                )
                cols = [desc[0] for desc in cursor.description]
                findings = [dict(zip(cols, row)) for row in cursor.fetchall()]
        except Exception as e:
            log.error("Failed to fetch findings for scan %s: %s", scan_id, e)
        pages = (total + per_page - 1) // per_page if total else 0
        return {
            "items": findings,
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": pages,
            "has_prev": page > 1,
            "has_next": page < pages,
        }

    def record_repo_scan(
        self,
        repo_name: str,
        repo_url: str,
        local_path: str,
        status: str,
        vulnerability_count: int,
        result_path: str,
    ) -> int:
        try:
            timestamp = datetime.now(tz=timezone.utc).isoformat()
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO repo_scans
                    (timestamp, repo_name, repo_url, local_path, status, vulnerability_count, result_path)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (timestamp, repo_name, repo_url, local_path, status, vulnerability_count, result_path),
                )
                return cursor.lastrowid or -1
        except Exception as e:
            log.error("Failed to record repo scan for %s: %s", repo_name, e)
            return -1

    def record_repo_scan_finding(
        self,
        repo_scan_id: int,
        vulnerability_id: str,
        severity: str,
        package_name: str,
        details: Dict[str, Any],
    ) -> None:
        try:
            details_json = json.dumps(details)
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO repo_scan_findings
                    (repo_scan_id, vulnerability_id, severity, package_name, details_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (repo_scan_id, vulnerability_id, severity, package_name, details_json),
                )
        except Exception as e:
            log.error("Failed to record repo scan finding for %s: %s", vulnerability_id, e)

    def get_recent_repo_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        scans: List[Dict[str, Any]] = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM repo_scans ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
                cols = [desc[0] for desc in cursor.description]
                scans = [dict(zip(cols, row)) for row in cursor.fetchall()]
        except Exception as e:
            log.error("Failed to fetch recent repo scans: %s", e)
        return scans

    def get_repo_scan_details(self, repo_scan_id: int) -> Optional[Dict[str, Any]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM repo_scans WHERE id = ?", (repo_scan_id,))
                row = cursor.fetchone()
                if row is None:
                    return None
                cols = [desc[0] for desc in cursor.description]
                scan = dict(zip(cols, row))
                scan["findings"] = self.get_repo_scan_findings(repo_scan_id)
                return scan
        except Exception as e:
            log.error("Failed to fetch repo scan details for %s: %s", repo_scan_id, e)
            return None

    def get_repo_scan_findings(self, repo_scan_id: int) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM repo_scan_findings WHERE repo_scan_id = ? ORDER BY id DESC",
                    (repo_scan_id,),
                )
                cols = [desc[0] for desc in cursor.description]
                findings = [dict(zip(cols, row)) for row in cursor.fetchall()]
        except Exception as e:
            log.error("Failed to fetch repo scan findings for %s: %s", repo_scan_id, e)
        return findings
