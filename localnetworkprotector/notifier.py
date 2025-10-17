"""Notification helpers for LocalNetworkProtector."""

from __future__ import annotations

import logging
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import List

from .alerts import Alert, EmailNotification
from .config import NotificationConfig
from .detector import severity_is_at_least

log = logging.getLogger(__name__)


class EmailNotifier:
    """Send email notifications about alerts."""

    def __init__(self, config: NotificationConfig) -> None:
        self.config = config
        self._pending: List[Alert] = []
        self._last_sent: datetime = datetime.fromtimestamp(0, tz=timezone.utc)

    def handle_alert(self, alert: Alert) -> None:
        if not self.config.enabled:
            log.debug("Notification disabled. Alert suppressed.")
            return

        if not severity_is_at_least(alert.severity, self.config.min_severity):
            log.debug(
                "Alert severity %s below minimum %s; skipping",
                alert.severity,
                self.config.min_severity,
            )
            return

        if not self.config.recipients or not (
            self.config.sender or self.config.username
        ):
            log.warning(
                "Notification recipients or sender not configured. Cannot send email."
            )
            return

        self._pending.append(alert)
        now = datetime.now(tz=timezone.utc)
        elapsed = (now - self._last_sent).total_seconds()
        if elapsed >= self.config.cool_down_seconds:
            self.flush()

    def flush(self) -> None:
        if not self._pending:
            return
        email = self._compose_email(self._pending)
        try:
            self._send_email(email)
            self._last_sent = datetime.now(tz=timezone.utc)
            log.info(
                "Sent email notification with %d alerts to %s",
                len(self._pending),
                ",".join(self.config.recipients),
            )
        except Exception as exc:
            log.exception("Failed to send email notification: %s", exc)
        finally:
            self._pending.clear()

    def _compose_email(self, alerts: List[Alert]) -> EmailNotification:
        subject = f"[LocalNetworkProtector] {len(alerts)} security alert(s)"
        lines = [
            "The following suspicious traffic patterns were detected:",
            "",
        ]
        for alert in alerts:
            lines.extend(
                [
                    f"- Rule: {alert.rule_name}",
                    f"  Severity: {alert.severity}",
                    f"  Description: {alert.description}",
                    f"  Packet: {alert.packet_summary}",
                    f"  First Seen: {alert.first_seen.isoformat()}",
                    f"  Last Seen: {alert.last_seen.isoformat()}",
                    f"  Occurrences: {alert.occurrences}",
                    "",
                ]
            )
        plain_body = "\n".join(lines)
        return EmailNotification(subject=subject, plain_body=plain_body)

    def _send_email(self, payload: EmailNotification) -> None:
        msg = EmailMessage()
        sender = self.config.sender or self.config.username
        if sender is None:
            raise RuntimeError("Sender or username must be configured for email.")
        msg["Subject"] = payload.subject
        msg["From"] = sender
        msg["To"] = ", ".join(self.config.recipients)
        msg.set_content(payload.plain_body)
        if payload.html_body:
            msg.add_alternative(payload.html_body, subtype="html")

        with smtplib.SMTP(
            self.config.smtp_host, self.config.smtp_port, timeout=30
        ) as smtp:
            if self.config.use_tls:
                smtp.starttls()
            if self.config.username and self.config.password:
                smtp.login(self.config.username, self.config.password)
            smtp.send_message(msg)

