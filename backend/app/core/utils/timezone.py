"""Standardized Timezone Utilities for MailForensix.

Canonical Standard:
- Database & Internal Storage: UTC (timezone-naive or timezone-aware ISO-8601).
- User-facing Display: Indian Standard Time (IST, UTC+05:30, IANA: Asia/Kolkata).
- Uses Python standard library zoneinfo.ZoneInfo("Asia/Kolkata") - no hardcoded arithmetic.
- Prevents double timezone conversions by detecting and handling existing tzinfo.
"""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import Optional, Union

# Canonical Timezones
IST = ZoneInfo("Asia/Kolkata")
UTC = timezone.utc


def now_utc() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


def now_ist() -> datetime:
    """Return timezone-aware current IST datetime."""
    return datetime.now(IST)


def to_utc(dt: Optional[Union[datetime, str]]) -> Optional[datetime]:
    """Convert any datetime or ISO-8601 string to a timezone-aware UTC datetime.

    If naive datetime is provided, it is assumed to represent UTC (matching database storage).
    """
    if dt is None:
        return None
    if isinstance(dt, str):
        clean_str = dt.strip()
        if not clean_str:
            return None
        try:
            # Handle ISO formats with 'Z'
            dt = datetime.fromisoformat(clean_str.replace("Z", "+00:00"))
        except ValueError:
            try:
                # Handle RFC 2822 or standard email date formats
                import email.utils
                parsed_tuple = email.utils.parsedate_to_datetime(clean_str)
                if parsed_tuple:
                    dt = parsed_tuple
            except Exception:
                return None

    if not isinstance(dt, datetime):
        return None

    if dt.tzinfo is None:
        # Naive datetime from database or internal source is assumed UTC
        dt = dt.replace(tzinfo=UTC)

    return dt.astimezone(UTC)


def to_ist(dt: Optional[Union[datetime, str]]) -> Optional[datetime]:
    """Convert any datetime or ISO-8601 string to a timezone-aware IST (Asia/Kolkata) datetime.

    If naive datetime is provided, it is treated as UTC and converted to Asia/Kolkata.
    If already timezone-aware, it is accurately transformed to Asia/Kolkata without double offset.
    """
    utc_dt = to_utc(dt)
    if utc_dt is None:
        return None
    return utc_dt.astimezone(IST)


def format_ist(
    dt: Optional[Union[datetime, str]],
    format_str: str = "%Y-%m-%d %H:%M:%S IST",
    default: str = "N/A",
) -> str:
    """Format any datetime or ISO string as an IST string for reports and user-facing output.

    Example output: '2026-08-27 20:23:12 IST'
    """
    ist_dt = to_ist(dt)
    if ist_dt is None:
        return default
    return ist_dt.strftime(format_str)


def to_iso_utc(dt: Optional[Union[datetime, str]]) -> Optional[str]:
    """Convert datetime to standard ISO-8601 string with UTC 'Z' or offset."""
    utc_dt = to_utc(dt)
    if utc_dt is None:
        return None
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z" if utc_dt.microsecond else utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def to_iso_ist(dt: Optional[Union[datetime, str]]) -> Optional[str]:
    """Convert datetime to standard ISO-8601 string with IST (+05:30) offset."""
    ist_dt = to_ist(dt)
    if ist_dt is None:
        return None
    return ist_dt.isoformat()
