# ── Kalaitzidis Ioannis - MTE25012 ─────────────────────────────────────────────────────

"""
00_config.py  --  Κοινο "system profile" (η ενιαια πηγη αληθειας)
==================================================================

ΤΙ ΚΑΝΕΙ ΑΥΤΟ ΤΟ ΑΡΧΕΙΟ
-----------------------
Οριζει σε ενα και μονο σημειο ΟΛΑ τα σταθερα στοιχεια του πλασματικου
συστηματος που προσομοιωνει το honeypot: το ονομα του μηχανηματος, το
λειτουργικο, τις εκδοσεις του λογισμικου, τους λογαριασμους χρηστων, την
τοπολογια του εσωτερικου δικτυου και μια σταθερη ημερομηνια αναφορας.

ΓΙΑΤΙ ΥΠΑΡΧΕΙ (ο ρολος του στην εργασια)
---------------------------------------
Ολα τα υπολοιπα scripts (01 decoys, 02 honeypot, 03 playbooks, 04 analysis)
ΕΙΣΑΓΟΥΝ αυτο το αρχειο αντι να "γραφουν" μονα τους ονοματα και εκδοσεις.
Ετσι, οποιαδηποτε πληροφορια (π.χ. η εκδοση OpenSSH) εμφανιζεται με την ΙΔΙΑ
ακριβως τιμη παντου: στο banner του honeypot, στα configs, στα logs και στις
σημειωσεις. Αυτη η ενιαια πηγη αληθειας (single source of truth) εξασφαλιζει
την "εσωτερικη συνεπεια" που ζηταει το Task 2 και αποτρεπει αντιφασεις, οι
οποιες ειναι απο τα πιο συχνα σημεια που προδιδουν ενα honeypot.

ΤΙ ΠΕΡΙΕΧΕΙ (τα βασικα αντικειμενα)
----------------------------------
- SEED         : ο σταθερος σπορος τυχαιοτητας, για πληρη αναπαραγωγιμοτητα.
- REFERENCE_NOW: σταθερη ημερομηνια "τωρα" του πλασματικου συστηματος.
- SYSTEM       : ταυτοτητα μηχανηματος (hostname, os, kernel, domain).
- VERSIONS     : εκδοσεις λογισμικου (openssh, nginx, postgres κ.λπ.).
- USERS        : οι λογαριασμοι χρηστων (ο πρωτος ειναι ο "ενεργος").
- NETWORK      : το εσωτερικο δικτυο (subnet + hosts + διευθυνσεις).
- days_ago(), fmt() : βοηθητικες για συνεπεις χρονικες σφραγιδες.

"""

from datetime import datetime, timedelta, timezone

# --------------------------------------------------------------------------
# Επαναληψιμοτητα: σταθερος σπορος τυχαιοτητας (25012).
# Καθε εκτελεση ολης της αλυσιδας δινει τα ιδια αποτελεσματα.
# --------------------------------------------------------------------------
SEED = 25012

# --------------------------------------------------------------------------
# Σταθερη ημερομηνια αναφορας ("τωρα" του πλασματικου συστηματος).
# Δεν χρησιμοποιειται datetime.now(), ωστε τα timestamps των decoys να μη
# μετακινουνται σε καθε εκτελεση και να μην αντιφασκουν με τα κειμενα.
# --------------------------------------------------------------------------
REFERENCE_NOW = datetime(2026, 4, 20, 9, 15, 0, tzinfo=timezone.utc)

# --------------------------------------------------------------------------
# Ταυτοτητα του συστηματος
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

# Εκδοσεις λογισμικου. Αναφερονται ΠΑΝΤΑ με τις ιδιες τιμες παντου
# (banner honeypot, configs, admin notes, logs).
VERSIONS = {
    "openssh":    "8.9p1 Ubuntu-3ubuntu0.7",
    "ssh_banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7",  # banner στο δικτυο
    "nginx":      "1.18.0 (Ubuntu)",
    "postgres":   "14.11",
    "python":     "3.10.12",
    "redis":      "6.0.16",
    "node":       "18.19.1",
}

# --------------------------------------------------------------------------
# Λογαριασμοι χρηστων (πλασματικοι). Το πρωτο ειναι ο "ενεργος" χρηστης του
# honeypot shell. Τα service accounts εξηγουν τα cron/deploy artefacts.
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

# Ο χρηστης με τον οποιο "συνδεεται" ο επιτιθεμενος στο honeypot shell.
ACTIVE_USER = USERS[0]

# --------------------------------------------------------------------------
# Εσωτερικη τοπολογια δικτυου (RFC 1918). Ολα τα hosts ειναι πλασματικα.
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
    # Πλασματικη "δημοσια" IP σε ζωνη τεκμηριωσης (RFC 5737), οχι πραγματικη.
    "public_egress": "198.51.100.24",
}

# --------------------------------------------------------------------------
# Βοηθητικες συναρτησεις για συνεπεις χρονικες σφραγιδες
# --------------------------------------------------------------------------
def days_ago(n, hour=None, minute=None):
    """Επιστρεφει datetime n ημερες πριν την REFERENCE_NOW (προαιρετικα με
    συγκεκριμενη ωρα/λεπτο), ωστε τα timestamps των decoys να ειναι στο
    παρελθον και συνεπη μεταξυ τους."""
    d = REFERENCE_NOW - timedelta(days=n)
    if hour is not None:
        d = d.replace(hour=hour, minute=minute if minute is not None else 0, second=0, microsecond=0)
    return d


def fmt(dt, style="iso"):
    """Μορφοποιηση ημερομηνιας σε διαφορα στυλ (iso, log, syslog, date)."""
    if style == "iso":
        return dt.strftime("%Y-%m-%dT%H:%M:%S%z")
    if style == "log":       # π.χ. PostgreSQL
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    if style == "syslog":    # π.χ. /var/log/auth.log
        return dt.strftime("%b %e %H:%M:%S").replace("  ", " ")
    if style == "date":
        return dt.strftime("%Y-%m-%d")
    if style == "ls":        # π.χ. ls -la
        return dt.strftime("%b %e %H:%M")
    return dt.isoformat()


if __name__ == "__main__":
    # Γρηγορη επισκοπηση του profile
    print(f"System : {SYSTEM['fqdn']}  ({SYSTEM['os']})")
    print(f"OpenSSH: {VERSIONS['openssh']}")
    print(f"Users  : {', '.join(u['name'] for u in USERS)}")
    print(f"Network: {NETWORK['subnet']}  ({len(NETWORK['hosts'])} hosts)")
    print(f"Ref now: {fmt(REFERENCE_NOW)}")