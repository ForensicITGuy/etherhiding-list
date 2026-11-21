#!/usr/bin/env python3
"""Download Chainlist RPCs and generate Pi-hole compatible domain and hosts blocklists."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

DEFAULT_URL = "https://chainlist.org/rpcs.json"
DEFAULT_OUTPUT = Path("domains.txt")
DEFAULT_HOSTS_OUTPUT = Path("hosts.txt")

# Valid DNS hostname label pattern (RFC 1123 + Punycode TLDs)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*"
    r"\.(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$"
)


def get_utc_timestamp() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def extract_domain(raw_url: str) -> str | None:
    """Extract and validate a normalized domain name from an RPC URL string."""
    if not isinstance(raw_url, str):
        return None

    cleaned = raw_url.strip()
    if not cleaned:
        return None

    # Ensure a scheme is present so urlparse places the host in .hostname
    if "://" not in cleaned:
        cleaned = "https://" + cleaned

    try:
        parsed = urlparse(cleaned)
        host = parsed.hostname
    except ValueError:
        return None

    if not host:
        return None

    host = host.lower().rstrip(".")

    # Skip localhost and unexpanded template variables in the hostname
    if (
        host in ("localhost", "0.0.0.0")
        or "$" in host
        or "{" in host
        or "}" in host
    ):
        return None

    # Convert internationalized domain names (IDN) to ASCII/Punycode
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    # Skip raw IPv4 and IPv6 addresses
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass

    if not DOMAIN_RE.match(host):
        return None

    return host


def extract_domains_from_chainlist(data: list[Any]) -> list[str]:
    """Extract sorted, unique domains from Chainlist rpcs.json data."""
    if not isinstance(data, list):
        raise ValueError("Expected Chainlist data to be a JSON list of chain objects.")

    domains: set[str] = set()

    for chain in data:
        if not isinstance(chain, dict):
            continue
        rpcs = chain.get("rpc")
        if not isinstance(rpcs, list):
            continue

        for entry in rpcs:
            if isinstance(entry, str):
                raw_url = entry
            elif isinstance(entry, dict):
                raw_url = entry.get("url") or ""
            else:
                continue

            domain = extract_domain(raw_url)
            if domain:
                domains.add(domain)

    return sorted(domains)


def read_existing_domains(path: Path) -> list[str] | None:
    """Read existing domain entries from a plain domain or hosts blocklist file.

    Returns None if the file does not exist.
    """
    if not path.is_file():
        return None

    domains: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            domains.add(parts[1].lower())
        else:
            domains.add(parts[0].lower())

    return sorted(domains)


def format_blocklist(
    domains: list[str],
    source_url: str = DEFAULT_URL,
    timestamp: str | None = None,
) -> str:
    """Format a list of domains as a Pi-hole plain domain blocklist."""
    header = [
        "# Pi-hole Blocklist: Blockchain JSON-RPC Endpoints (Chainlist)",
        f"# Source: {source_url}",
    ]
    if timestamp:
        header.append(f"# Last updated: {timestamp}")
    header.extend(
        [
            f"# Total domains: {len(domains)}",
            "",
        ]
    )
    return "\n".join(header + domains) + "\n"


def format_hosts_blocklist(
    domains: list[str],
    source_url: str = DEFAULT_URL,
    timestamp: str | None = None,
) -> str:
    """Format a list of domains as a hosts-format blocklist (0.0.0.0 <domain>)."""
    header = [
        "# Pi-hole Blocklist (Hosts Format): Blockchain JSON-RPC Endpoints (Chainlist)",
        f"# Source: {source_url}",
    ]
    if timestamp:
        header.append(f"# Last updated: {timestamp}")
    header.extend(
        [
            f"# Total domains: {len(domains)}",
            "",
        ]
    )
    entries = [f"0.0.0.0 {domain}" for domain in domains]
    return "\n".join(header + entries) + "\n"


def fetch_chainlist_data(url: str = DEFAULT_URL, timeout: int = 60) -> list[Any]:
    """Fetch and parse Chainlist rpcs.json from the remote URL."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Etherhiding-List-Updater/1.0 (+https://github.com/forensicitguy/etherhiding-list)"
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Download Chainlist RPCs and output Pi-hole domain and hosts blocklists."
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_URL,
        help=f"Source JSON URL (default: {DEFAULT_URL})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output plain domain blocklist path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--hosts-output",
        type=Path,
        default=DEFAULT_HOSTS_OUTPUT,
        help=f"Output hosts-format blocklist path (default: {DEFAULT_HOSTS_OUTPUT})",
    )
    args = parser.parse_args(argv)

    data = fetch_chainlist_data(args.url)
    domains = extract_domains_from_chainlist(data)
    if not domains:
        raise RuntimeError("No domains extracted from source JSON; aborting update.")

    timestamp = get_utc_timestamp()

    existing_plain = read_existing_domains(args.output)
    if existing_plain == domains:
        print(f"No domain additions or removals for {args.output}; skipping update.")
    else:
        content = format_blocklist(domains, source_url=args.url, timestamp=timestamp)
        args.output.write_text(content, encoding="utf-8")
        print(f"Wrote {len(domains)} unique domains to {args.output} (timestamp: {timestamp})")

    existing_hosts = read_existing_domains(args.hosts_output)
    if existing_hosts == domains:
        print(f"No domain additions or removals for {args.hosts_output}; skipping update.")
    else:
        hosts_content = format_hosts_blocklist(
            domains, source_url=args.url, timestamp=timestamp
        )
        args.hosts_output.write_text(hosts_content, encoding="utf-8")
        print(
            f"Wrote {len(domains)} unique domains to {args.hosts_output} (timestamp: {timestamp})"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
