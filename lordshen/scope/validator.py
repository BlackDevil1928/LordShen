"""Scope validation — checks targets against scope with wildcard and CIDR support."""

import fnmatch
import ipaddress
from urllib.parse import urlparse

from lordshen.scope.models import ProgramScope


def extract_domain(target: str) -> str:
    """Extract domain from a URL or target string."""
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    # Strip port
    if ":" in target and not target.startswith("["):
        target = target.split(":")[0]
    return target.lower().strip()


def is_ip(target: str) -> bool:
    """Check if target string is an IP address."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _matches_domain_pattern(domain: str, pattern: str) -> bool:
    """Check if domain matches a scope pattern (supports wildcards)."""
    domain = domain.lower().strip()
    pattern = pattern.lower().strip()

    # Exact match
    if domain == pattern:
        return True

    # Wildcard *.example.com matches sub.example.com and deep.sub.example.com
    if pattern.startswith("*."):
        base = pattern[2:]
        if domain == base or domain.endswith("." + base):
            return True

    # fnmatch for other patterns
    return fnmatch.fnmatch(domain, pattern)


def _ip_in_range(ip_str: str, cidr: str) -> bool:
    """Check if an IP address falls within a CIDR range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(cidr, strict=False)
        return ip in network
    except ValueError:
        return False


def is_in_scope(target: str, scope: ProgramScope) -> tuple[bool, str]:
    """Check if a target is within the program scope.

    Checks out-of-scope FIRST (deny list priority), then in-scope.

    Args:
        target: URL, domain, or IP to check.
        scope: Program scope definition.

    Returns:
        Tuple of (is_in_scope: bool, reason: str).
    """
    domain = extract_domain(target)
    target_is_ip = is_ip(domain)

    # 1. Check out-of-scope domains (deny list takes priority)
    for oos in scope.oos_domains:
        if _matches_domain_pattern(domain, oos):
            return False, f"Target '{domain}' matches out-of-scope pattern '{oos}'"

    # 2. Check in-scope domains
    if scope.in_scope_domains:
        for pattern in scope.in_scope_domains:
            if _matches_domain_pattern(domain, pattern):
                return True, f"Target '{domain}' matches in-scope pattern '{pattern}'"

    # 3. Check in-scope IPs
    if target_is_ip and scope.in_scope_ips:
        for ip_range in scope.in_scope_ips:
            if "/" in ip_range:
                if _ip_in_range(domain, ip_range):
                    return True, f"IP '{domain}' is within in-scope range '{ip_range}'"
            elif domain == ip_range:
                return True, f"IP '{domain}' matches in-scope IP '{ip_range}'"

    # 4. If no in-scope rules defined, allow all (not out-of-scope)
    if not scope.in_scope_domains and not scope.in_scope_ips:
        return True, "No scope restrictions defined — allowing target"

    return False, f"Target '{domain}' is not in any in-scope pattern"


def is_vuln_in_scope(vuln_class: str, scope: ProgramScope) -> tuple[bool, str]:
    """Check if a vulnerability class is in scope.

    Args:
        vuln_class: Vulnerability class to check (e.g. 'self_xss', 'sqli').
        scope: Program scope definition.

    Returns:
        Tuple of (is_in_scope: bool, reason: str).
    """
    vuln_lower = vuln_class.lower().strip()

    for oos_vuln in scope.oos_vuln_classes:
        if vuln_lower == oos_vuln.lower().strip():
            return False, f"Vulnerability class '{vuln_class}' is out of scope"
        if fnmatch.fnmatch(vuln_lower, oos_vuln.lower().strip()):
            return False, f"Vulnerability class '{vuln_class}' matches OOS pattern '{oos_vuln}'"

    return True, f"Vulnerability class '{vuln_class}' is in scope"
