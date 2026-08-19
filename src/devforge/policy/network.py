"""Network destination checks (SSRF defence).

Any feature that fetches a URL on behalf of an agent is an SSRF primitive: the
agent chooses the destination, the request carries the workstation's network
position, and "internal only" services are exactly one hop away. The cloud
metadata endpoint is the classic prize - a plain HTTP GET to 169.254.169.254
returns instance credentials on several providers.

So a destination must clear three checks, in order:

1. **Scheme** - http/https only. ``file://``, ``gopher://`` and friends are how
   URL fetchers get turned into file readers and protocol smugglers.
2. **Address** - loopback, private, link-local, multicast and reserved ranges are
   refused, and hostnames that resolve to them are refused too. Resolution
   happens here so a name pointing at 127.0.0.1 cannot slip through.
3. **Allowlist** - the host must be named in ``permissions.yaml``.

DNS rebinding is *not* solved: the address checked here can differ from the one
connected to milliseconds later. Closing that needs the connection itself pinned
to the validated address, which belongs in whichever client does the fetching.
Stated plainly rather than implied away.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from fnmatch import fnmatch
from urllib.parse import urlsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})

#: Refused regardless of the allowlist - these names exist to reach the host itself.
BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
    }
)

#: Cloud metadata services, refused explicitly so the reason is legible in the log.
METADATA_ADDRESSES = frozenset({"169.254.169.254", "fd00:ec2::254", "100.100.100.200"})


@dataclass(frozen=True)
class DestinationVerdict:
    allowed: bool
    reason: str
    host: str = ""
    resolved: tuple[str, ...] = ()

    @property
    def blocked(self) -> bool:
        return not self.allowed


def _is_forbidden_address(address: str) -> str:
    """Return a reason when this IP must not be reached, else an empty string."""
    if address in METADATA_ADDRESSES:
        return f"{address} is a cloud metadata endpoint"
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return ""
    if ip.is_loopback:
        return f"{address} is loopback"
    if ip.is_link_local:
        return f"{address} is link-local"
    if ip.is_private:
        return f"{address} is a private address"
    if ip.is_multicast:
        return f"{address} is multicast"
    if ip.is_reserved or ip.is_unspecified:
        return f"{address} is reserved"
    return ""


def resolve(host: str) -> tuple[str, ...]:
    """Resolve a hostname to addresses. Empty on failure - the caller decides."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return ()
    return tuple(sorted({info[4][0] for info in infos}))


def check_destination(
    url: str,
    *,
    allow_hosts: list[str],
    resolve_names: bool = True,
) -> DestinationVerdict:
    """Decide whether a URL may be fetched."""
    parts = urlsplit(url)

    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        return DestinationVerdict(
            False, f"scheme '{parts.scheme or '(none)'}' is not allowed (http/https only)"
        )

    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host:
        return DestinationVerdict(False, "URL has no host")

    if parts.username or parts.password:
        return DestinationVerdict(False, "URL carries embedded credentials", host=host)

    if host in BLOCKED_HOSTNAMES:
        return DestinationVerdict(False, f"'{host}' refers to the local host", host=host)

    literal = _is_forbidden_address(host)
    if literal:
        return DestinationVerdict(False, literal, host=host)

    resolved: tuple[str, ...] = ()
    if resolve_names:
        resolved = resolve(host)
        if not resolved:
            return DestinationVerdict(False, f"'{host}' does not resolve", host=host)
        for address in resolved:
            reason = _is_forbidden_address(address)
            if reason:
                return DestinationVerdict(
                    False,
                    f"'{host}' resolves to {reason}",
                    host=host,
                    resolved=resolved,
                )

    for pattern in allow_hosts:
        if fnmatch(host, pattern.lower()):
            return DestinationVerdict(
                True, f"host allowed by rule '{pattern}'", host=host, resolved=resolved
            )

    return DestinationVerdict(
        False, f"'{host}' is not in the network allow list", host=host, resolved=resolved
    )
