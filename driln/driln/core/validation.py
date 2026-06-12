"""Core input validation logic."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# Strict regex for valid hostnames, IPs, and CIDRs
# Blocks spaces, shell metacharacters, and leading hyphens (argument injection)
_STRICT_TARGET_RE = re.compile(
    r"^(?!-)[a-zA-Z0-9-]{1,63}(?:\.[a-zA-Z0-9-]{1,63})*(?:\/[0-9]{1,2})?$"
)

# For IPv6, we want a simpler check to avoid complex regex
_IPV6_CIDR_RE = re.compile(r"^[0-9a-fA-F:]+(?:\/[0-9]{1,3})?$")

class TargetValidationError(ValueError):
    """Raised when a target fails validation."""
    pass

def validate_target_format(target: str) -> str:
    """Validate that a target is a valid FQDN, IP address, or URL.
    
    Raises:
        TargetValidationError: If the target format is invalid or potentially unsafe.
    """
    target = target.strip()
    
    if not target:
        raise TargetValidationError("Target cannot be empty")
        
    # Check for obvious injection characters
    dangerous = set(";|&$`!(){}[]<>\\'\"\n\r\t ")
    if any(c in target for c in dangerous):
        raise TargetValidationError("Target contains invalid characters")
        
    # If it's a URL, extract the hostname
    if "://" in target:
        parsed = urlparse(target)
        if not parsed.hostname:
            raise TargetValidationError("Invalid URL target")
        target_to_check = parsed.hostname
    else:
        # Strip port if present for validation
        target_to_check = target.split(":")[0]
        
    # Check if it's a valid IPv4/IPv6 or CIDR
    try:
        if "/" in target_to_check:
            ipaddress.ip_network(target_to_check, strict=False)
            return target
        else:
            ipaddress.ip_address(target_to_check)
            return target
    except ValueError:
        pass  # Not an IP/CIDR, must be a hostname
        
    # Must be a hostname
    if not _STRICT_TARGET_RE.match(target_to_check):
        # Could be an IPv6 without CIDR, handled by ip_address above,
        # but if it failed, it's invalid.
        raise TargetValidationError(f"Invalid target format: {target}")
        
    return target
