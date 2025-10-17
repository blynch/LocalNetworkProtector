"""Alert dataclasses used across the detection pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass(slots=True)
class Alert:
    """Represents a detection alert triggered by a rule."""

    rule_name: str
    description: str
    severity: str
    packet_summary: str
    first_seen: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )
    last_seen: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )
    occurrences: int = 1

    def bump(self) -> None:
        """Increase occurrence counter and bump last_seen timestamp."""
        self.occurrences += 1
        self.last_seen = datetime.now(tz=timezone.utc)

    def to_dict(self) -> dict:
        """Serialize the alert to a dict suitable for JSON or logs."""
        return {
            "rule": self.rule_name,
            "severity": self.severity,
            "description": self.description,
            "packet": self.packet_summary,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "occurrences": self.occurrences,
        }


@dataclass(slots=True)
class EmailNotification:
    """Container for data sent to the email notifier."""

    subject: str
    plain_body: str
    html_body: Optional[str] = None

