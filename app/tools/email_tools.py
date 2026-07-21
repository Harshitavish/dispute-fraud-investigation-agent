"""Outbound notification tool.

Safety default: SMTP is OFF. Messages are rendered and written to ./outbox as
.eml files so you can inspect exactly what the agent would have sent. Flip
SMTP_ENABLED=true in .env only when you actually want mail to leave the box.
"""

from __future__ import annotations

import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any

from app.config import get_settings


def build_message(*, to: str, subject: str, body: str) -> EmailMessage:
    settings = get_settings()
    msg = EmailMessage()
    msg["From"] = settings.email_from
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    msg["X-Generated-By"] = "agentic-dispute-system"
    msg.set_content(body)
    return msg


def send_email(*, to: str, subject: str, body: str, tag: str = "notice") -> dict[str, Any]:
    """Send (or dry-run) one message. Never raises -- delivery failure must not
    roll back a refund that already succeeded."""
    settings = get_settings()
    msg = build_message(to=to, subject=subject, body=body)

    if not settings.smtp_enabled:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        path = settings.outbox_dir / f"{stamp}_{tag}_{to.replace('@', '_at_')}.eml"
        path.write_text(msg.as_string(), encoding="utf-8")
        return {
            "ok": True,
            "mode": "dry_run",
            "to": to,
            "subject": subject,
            "written_to": str(path),
        }

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as smtp:
            if settings.smtp_use_tls:
                smtp.starttls()
            if settings.smtp_username and settings.smtp_password:
                smtp.login(settings.smtp_username, settings.smtp_password)
            smtp.send_message(msg)
        return {"ok": True, "mode": "smtp", "to": to, "subject": subject}
    except Exception as exc:  # noqa: BLE001 - deliberately broad, see docstring
        return {"ok": False, "mode": "smtp", "to": to, "error": f"{type(exc).__name__}: {exc}"}
