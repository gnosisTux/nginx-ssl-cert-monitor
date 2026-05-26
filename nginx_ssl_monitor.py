#!/usr/bin/env python3
"""
nginx_ssl_monitor.py
====================
Checks SSL certificates for all domains configured in Nginx.

Quick usage:
    python3 nginx_ssl_monitor.py

Options:
    python3 nginx_ssl_monitor.py --warn 30 --crit 7
    python3 nginx_ssl_monitor.py --json
    python3 nginx_ssl_monitor.py --json | jq .

Requirements:
    pip install cryptography

Requires nginx installed and permission to run:
    nginx -T

Exit codes:
    0 OK (all certs above warning threshold)
    1 WARNING (<= warn days)
    2 CRITICAL (<= crit days)
    3 EXPIRED
"""

import argparse
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from typing import NamedTuple

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print(
        "[ERROR] Missing dependency 'cryptography'.\n"
        "Install it with: pip install cryptography",
        file=sys.stderr,
    )
    sys.exit(1)

# ──────────────────────────────────────────────
# Defaults
# ──────────────────────────────────────────────
DEFAULT_WARN_DAYS = 30
DEFAULT_CRIT_DAYS = 7
DEFAULT_PORT = 443
CONNECT_TIMEOUT = 5


# ──────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────
class CertStatus(NamedTuple):
    domain: str
    days: int | None
    expires: str | None
    status: str
    detail: str


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────
def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _ignore_domain(domain: str) -> bool:
    return _is_ip(domain) or domain == "_"


# ──────────────────────────────────────────────
# Core logic
# ──────────────────────────────────────────────
def get_nginx_domains() -> list[str]:
    try:
        output = subprocess.check_output(
            ["nginx", "-T"],
            stderr=subprocess.STDOUT,
            timeout=15,
        ).decode(errors="replace")
    except Exception as e:
        print(f"[ERROR] nginx -T failed: {e}", file=sys.stderr)
        sys.exit(1)

    domains: set[str] = set()

    blocks = re.findall(r"server\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}", output, re.S)

    for block in blocks:
        if not re.search(r"listen\s+[^;]*443", block):
            continue

        matches = re.findall(r"server_name\s+([^;]+);", block)
        for match in matches:
            for d in match.split():
                d = d.strip().lower().rstrip(".")
                if d and not _ignore_domain(d):
                    domains.add(d)

    return sorted(domains)


def check_certificate(
    domain: str,
    port: int = DEFAULT_PORT,
    warn_days: int = DEFAULT_WARN_DAYS,
    crit_days: int = DEFAULT_CRIT_DAYS,
) -> CertStatus:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((domain, port), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
    except Exception as e:
        return CertStatus(domain, None, None, "ERROR", str(e))

    try:
        cert = x509.load_der_x509_certificate(cert_bin, default_backend())
        expires = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        days = (expires - now).days
        expires_str = expires.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception as e:
        return CertStatus(domain, None, None, "ERROR", f"Parse error: {e}")

    if days < 0:
        status = "EXPIRED"
        detail = f"Expired {abs(days)} day(s) ago"
    elif days <= crit_days:
        status = "CRITICAL"
        detail = f"Expires in {days} day(s)"
    elif days <= warn_days:
        status = "WARNING"
        detail = f"Expires in {days} day(s)"
    else:
        status = "OK"
        detail = ""

    return CertStatus(domain, days, expires_str, status, detail)


# ──────────────────────────────────────────────
# Output (COLOURS)
# ──────────────────────────────────────────────
COLOURS = {
    "OK": "\033[92m",
    "WARNING": "\033[93m",
    "CRITICAL": "\033[91m",
    "EXPIRED": "\033[95m",
    "ERROR": "\033[90m",
    "RESET": "\033[0m",
}


def _colour(text: str, status: str) -> str:
    if not sys.stdout.isatty():
        return text
    c = COLOURS.get(status, "")
    return f"{c}{text}{COLOURS['RESET']}"


def print_table(results: list[CertStatus]) -> None:
    width = max((len(r.domain) for r in results), default=30)

    print(f"\n{'DOMAIN':<{width}}  {'STATUS':<10}  {'DAYS':<6}  EXPIRES")
    print("─" * (width + 40))

    for r in results:
        days = str(r.days) if r.days is not None else "-"
        exp = r.expires or r.detail
        line = f"{r.domain:<{width}}  {r.status:<10}  {days:<6}  {exp}"
        print(_colour(line, r.status))

    print("─" * (width + 40))

    summary: dict[str, int] = {}
    for r in results:
        summary[r.status] = summary.get(r.status, 0) + 1

    parts = [f"{_colour(k, k)}: {v}" for k, v in sorted(summary.items())]
    print("Summary → " + "  |  ".join(parts) + "\n")


def print_json(results: list[CertStatus]) -> None:
    print(json.dumps([r._asdict() for r in results], indent=2))


def exit_code(results: list[CertStatus]) -> int:
    states = {r.status for r in results}
    if "EXPIRED" in states:
        return 3
    if "CRITICAL" in states:
        return 2
    if "WARNING" in states:
        return 1
    return 0


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description="Nginx SSL certificate checker")
    p.add_argument("--warn", type=int, default=DEFAULT_WARN_DAYS)
    p.add_argument("--crit", type=int, default=DEFAULT_CRIT_DAYS)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--json", action="store_true")
    p.add_argument("--domains", nargs="+")
    return p.parse_args()


def main():
    args = parse_args()

    if args.warn <= args.crit:
        print("[ERROR] warn must be greater than crit", file=sys.stderr)
        sys.exit(1)

    domains = sorted(set(args.domains)) if args.domains else get_nginx_domains()

    results = [
        check_certificate(d, args.port, args.warn, args.crit)
        for d in domains
    ]

    if args.json:
        print_json(results)
    else:
        print_table(results)

    sys.exit(exit_code(results))


if __name__ == "__main__":
    main()
