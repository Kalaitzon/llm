# -*- coding: utf-8 -*-
"""
00_config.py  --  Shared "system profile" (the single source of truth)
======================================================================

WHAT THIS FILE DOES
-------------------
Defines, in a single place, ALL the fixed properties of the fictional system
that the honeypot simulates: the host name, the operating system, the software
versions, the user accounts, the internal network topology and a fixed
reference date.

WHY IT EXISTS (its role in the project)
---------------------------------------
Every other script (01 decoys, 02 honeypot, 03 playbooks, 04 analysis) IMPORTS
this file instead of hard-coding names and versions itself. As a result, any
piece of information (e.g. the OpenSSH version) appears with the EXACT SAME
value everywhere: in the honeypot banner, in the configs, in the logs and in
the notes. This single source of truth guarantees the "internal consistency"
required by Task 2 and prevents contradictions, which are among the most common
things that give a honeypot away.

WHAT IT CONTAINS (the main objects)
-----------------------------------
- SEED         : the fixed random seed, for full reproducibility.
- REFERENCE_NOW: the fixed "now" date of the fictional system.
- SYSTEM       : machine identity (hostname, os, kernel, domain).
- VERSIONS     : software versions (openssh, nginx, postgres, etc.).
- USERS        : the user accounts (the first one is the "active" user).
- NETWORK      : the internal network (subnet + hosts + addresses).
- days_ago(), fmt() : helpers for consistent timestamps.

SAFETY / ETHICS NOTE
--------------------
Everything here is FICTIONAL. All IP addresses belong to documentation/private
ranges (RFC 1918 and RFC 5737), no hostname maps to a real system, and no
credential is functional. There are no real secrets or personal data.
"""

from datetime import datetime, timedelta, timezone

# --------------------------------------------------------------------------
# Reproducibility: a fixed random seed. Every run of the whole chain produces
# the same results.
# --------------------------------------------------------------------------
SEED = 25012

# --------------------------------------------------------------------------
# Fixed reference date (the "now" of the fictional system).
# datetime.now() is deliberately NOT used, so that the decoy timestamps do not
# shift on every run and do not contradict the text of the artefacts.
# --------------------------------------------------------------------------
REFERENCE_NOW = datetime(2026, 4, 20, 9, 15, 0, tzinfo=timezone.utc)

# --------------------------------------------------------------------------
# System identity (the "backstory" of the machine)
# --------------------------------------------------------------------------
SYSTEM = {
    "company":   "Internal Corp",
    "hostname":  "app-srv-01",
    "domain":    "corp.local",
    "fqdn":      "app-srv-01.corp.local",
    "os":        "Ubuntu 22.04.4 LTS",
    "kernel":    "5.15.0-105-generic",
    "arch":      "x86_64",
    "timezone":  "Europe/Athens",
    "role":      "production web/application host",
}

# Software versions. Always referenced with the same values everywhere
# (honeypot banner, configs, admin notes, logs).
VERSIONS = {
    "openssh":    "8.9p1 Ubuntu-3ubuntu0.7",
    "ssh_banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7",  # network banner
    "nginx":      "1.18.0 (Ubuntu)",
    "postgres":   "14.11",
    "python":     "3.10.12",
    "redis":      "6.0.16",
    "node":       "18.19.1",
}

# --------------------------------------------------------------------------
# User accounts (fictional). The first one is the "active" user of the
# honeypot shell. The service accounts explain the cron/deploy artefacts.
# --------------------------------------------------------------------------
USERS = [
    {"name": "mgeorgiou",    "uid": 1001, "gid": 1001, "role": "sysadmin",
     "home": "/home/mgeorgiou",   "shell": "/bin/bash", "primary": True},
    {"name": "kpapas",  "uid": 1002, "gid": 1002, "role": "backend developer",
     "home": "/home/kpapas", "shell": "/bin/bash", "primary": False},
    {"name": "svc_deploy",     "uid": 1500, "gid": 1500, "role": "CI/CD service account",
     "home": "/opt/deploy",         "shell": "/bin/bash", "primary": False},
    {"name": "backup",         "uid": 1501, "gid": 1501, "role": "backup service account",
     "home": "/var/backups",        "shell": "/usr/sbin/nologin", "primary": False},
]

# The user the attacker "logs in" as on the honeypot shell.
ACTIVE_USER = USERS[0]

# --------------------------------------------------------------------------
# Internal network topology (RFC 1918). All hosts are fictional.
# --------------------------------------------------------------------------
NETWORK = {
    "subnet": "10.20.0.0/16",
    "hosts": [
        {"host": "app-srv-01.corp.local", "ip": "10.20.1.5",  "svc": "web/app (this host)"},
        {"host": "db01.corp.local",        "ip": "10.20.1.10", "svc": "PostgreSQL 14"},
        {"host": "cache01.corp.local",     "ip": "10.20.1.20", "svc": "Redis"},
        {"host": "backup01.corp.local",    "ip": "10.20.1.30", "svc": "backup store"},
        {"host": "ci01.corp.local",        "ip": "10.20.2.15", "svc": "CI (Jenkins)"},
    ],
    "admin_workstation": "10.20.5.42",
    # Fictional "public" IP in a documentation range (RFC 5737), not a real one.
    "public_egress": "198.51.100.24",
}

# --------------------------------------------------------------------------
# Helper functions for consistent timestamps
# --------------------------------------------------------------------------
def days_ago(n, hour=None, minute=None):
    """Return a datetime n days before REFERENCE_NOW (optionally at a specific
    hour/minute), so that the decoy timestamps are in the past and consistent
    with one another."""
    d = REFERENCE_NOW - timedelta(days=n)
    if hour is not None:
        d = d.replace(hour=hour, minute=minute if minute is not None else 0, second=0, microsecond=0)
    return d


def fmt(dt, style="iso"):
    """Format a date in various styles (iso, log, syslog, date, ls)."""
    if style == "iso":
        return dt.strftime("%Y-%m-%dT%H:%M:%S%z")
    if style == "log":       # e.g. PostgreSQL
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    if style == "syslog":    # e.g. /var/log/auth.log
        return dt.strftime("%b %e %H:%M:%S").replace("  ", " ")
    if style == "date":
        return dt.strftime("%Y-%m-%d")
    if style == "ls":        # e.g. ls -la
        return dt.strftime("%b %e %H:%M")
    return dt.isoformat()


if __name__ == "__main__":
    # Quick overview of the profile
    print(f"System : {SYSTEM['fqdn']}  ({SYSTEM['os']})")
    print(f"OpenSSH: {VERSIONS['openssh']}")
    print(f"Users  : {', '.join(u['name'] for u in USERS)}")
    print(f"Network: {NETWORK['subnet']}  ({len(NETWORK['hosts'])} hosts)")
    print(f"Ref now: {fmt(REFERENCE_NOW)}")
