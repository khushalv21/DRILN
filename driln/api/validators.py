"""Reusable security validators for API endpoints."""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

from fastapi import HTTPException

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def validate_uuid(value: str, param_name: str = "id") -> str:
    """Validate that a string is a valid UUID4 format.

    Raises:
        HTTPException: If the value is not a valid UUID.
    """
    if not _UUID_RE.match(value):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {param_name} format",
        )
    return value


def resolve_and_check_local(target: str) -> bool:
    """Returns True if the target resolves to a private or loopback IP."""
    # Strip protocol if present
    if "://" in target:
        target = urlparse(target).hostname or target
    else:
        # Just in case they provide port
        target = target.split(":")[0]

    try:
        ip = socket.gethostbyname(target)
        parsed_ip = ipaddress.ip_address(ip)
        return parsed_ip.is_private or parsed_ip.is_loopback
    except socket.gaierror:
        # If it doesn't resolve, it's either invalid or an external domain that is currently down
        return False

