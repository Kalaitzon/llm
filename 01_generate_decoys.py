# ── Kalaitzidis Ioannis - MTE25012 ─────────────────────────────────────────────────────

"""
01_generate_decoys.py  --  Παραγωγη των decoy artefacts
========================================================
[TASK 2] Δημιουργια των ψευτικων στοιχειων-δολωμα (decoy artefacts).

ΤΙ ΚΑΝΕΙ ΑΥΤΟ ΤΟ ΑΡΧΕΙΟ
-----------------------
Δημιουργει 12 ψευτικα αλλα ρεαλιστικα αρχεια (δολωματα) σε 7 κατηγοριες, και
τα τοποθετει μεσα σε ενα προσομοιωμενο συστημα αρχειων (φακελος decoys/fs/).
Αυτο το εικονικο συστημα αρχειων ειναι ακριβως ο,τι "σερβιρει" αργοτερα το
honeypot: οταν ο επιτιθεμενος κανει π.χ. `cat /opt/app/.env`, το honeypot
διαβαζει το αντιστοιχο αρχειο απο εδω. Παραγει επισης το artifact_inventory.json,
δηλαδη τον καταλογο ολων των δολωματων με τα μεταδεδομενα τους (κατηγορια,
πηγη, ρολος), οπως ζηταει ρητα το Task 2.

ΠΩΣ ΔΟΥΛΕΥΕΙ (τα βηματα)
-----------------------
1. gen_manual() : γραφει τα 5 χειροκινητα (template-based) δολωματα.
2. gen_llm()    : γραφει τα 7 δολωματα που παρηχθησαν με το μοντελο Claude.
3. write_prompts() : αποθηκευει στο llm_prompts/ το ακριβες prompt καθε
   LLM δολωματος (τεκμηριωση της μεθοδου παραγωγης).
4. write_inventory() : γραφει τον συνολικο καταλογο artifact_inventory.json.
Η βοηθητικη write_fs() γραφει καθε αρχειο στο σωστο μονοπατι και ταυτοχρονα
το καταχωρει στον καταλογο.

ΠΟΙΑ ΕΙΝΑΙ LLM ΚΑΙ ΠΟΙΑ ΧΕΙΡΟΚΙΝΗΤΑ
-----------------------------------
- Claude (7): .bash_history του svc_deploy, app.corp.conf (nginx),
  database.yml, auth.log, .ssh/config, deploy_runbook.md, NOTES_infra.md.
- Χειροκινητα (5): .bash_history του mgeorgiou, .env, postgresql log,
  .ssh/known_hosts, cron.d/deploy.

ΤΡΟΠΟΣ ΠΑΡΑΓΩΓΗΣ ΤΩΝ LLM ARTEFACTS
---------------------------------
Το περιεχομενο των LLM artefacts παρηχθη με το μοντελο Claude, με ρητα
prompts που περιγραφουν το system profile και ζητουν ρεαλιστικο, εσωτερικα
συνεπες περιεχομενο ΧΩΡΙΣ πραγματικα μυστικα. Το ακριβες prompt καθε artefact
αποθηκευεται στον φακελο llm_prompts/ για πληρη τεκμηριωση και
αναπαραγωγιμοτητα. Εναλλακτικα, με την επιλογη --use-api (και εγκυρο
ANTHROPIC_API_KEY) το script μπορει να ξαναπαραγει ζωντανα τα artefacts.

ΕΙΣΟΔΟΣ / ΕΞΟΔΟΣ
----------------
- Εισοδος: το κοινο profile (00_config.py).
- Εξοδος : ο φακελος decoys/fs/ (τα 12 αρχεια), το decoys/artifact_inventory.json
  και τα αρχεια prompt στο llm_prompts/.

ΑΣΦΑΛΕΙΑ: κανενα credential δεν ειναι πραγματικο. Ολα δειχνουν σε πλασματικα
hosts (RFC 1918/5737). Δεν υπαρχουν προσωπικα δεδομενα.
"""

import os
import sys
import json
import importlib
from pathlib import Path

# Εισαγωγη του κοινου profile (το ονομα 00_config δεν ειναι εγκυρο identifier,
# οποτε το φορτωνουμε δυναμικα).
cfg = importlib.import_module("00_config")

BASE      = Path(__file__).resolve().parent
DECOY_DIR = BASE / "decoys"
FS_ROOT   = DECOY_DIR / "fs"          # το προσομοιωμενο "/" του honeypot
PROMPT_DIR = BASE / "llm_prompts"

S = cfg.SYSTEM
V = cfg.VERSIONS
N = cfg.NETWORK
U = {u["name"]: u for u in cfg.USERS}


# ==========================================================================
#  Prompts των LLM-generated artefacts (τεκμηριωση Task 2)
#  Γραφονται στον φακελο llm_prompts/ κατα την εκτελεση.
# ==========================================================================
LLM_PROMPTS = {
    "svc_deploy_bash_history": (
        "You are generating a realistic .bash_history file for a CI/CD service "
        "account named 'svc_deploy' on a production Ubuntu 22.04 host "
        "(app-srv-01.corp.local). The account deploys a Python/Node web app "
        "under /opt/app, talks to db01.corp.local (PostgreSQL 14) and "
        "cache01.corp.local (Redis). Produce ~25 plausible shell commands "
        "showing routine deployments, log checks and service restarts. No real "
        "secrets. Keep it internally consistent with those hostnames and paths."
    ),
    "nginx_site": (
        "Generate a realistic nginx server block for a production site on "
        "app-srv-01 (nginx 1.18.0, Ubuntu). It reverse-proxies to a local app on "
        "127.0.0.1:8000, serves static files from /opt/app/public, has TLS, an "
        "internal /metrics location restricted to 10.20.0.0/16, and references an "
        "upstream to db01/cache01 indirectly. Realistic comments, no real secrets."
    ),
    "database_yml": (
        "Generate a realistic Rails-style config/database.yml for a production app "
        "connecting to PostgreSQL 14 at db01.corp.local, user 'app_ro' and "
        "'app_rw'. Include development/test/production sections. Passwords must be "
        "OBVIOUSLY placeholder/fake values, never real. Keep hostnames consistent."
    ),
    "auth_log": (
        "Generate ~20 lines of a realistic /var/log/auth.log from an Ubuntu 22.04 "
        "host (OpenSSH 8.9p1). Show sshd accepted publickey logins for user "
        "mgeorgiou from the admin workstation 10.20.5.42, a couple of sudo "
        "sessions, one failed password from an internal IP, and cron session "
        "openings. Timestamps around mid-April 2026. Internally consistent."
    ),
    "ssh_config": (
        "Generate a realistic ~/.ssh/config for a sysadmin (mgeorgiou) managing "
        "an internal fleet: db01, cache01, backup01, ci01 on corp.local "
        "(10.20.x). Include Host aliases, User, IdentityFile, ProxyJump via a "
        "bastion, and sensible options. No real keys."
    ),
    "deploy_runbook": (
        "Write a concise internal deployment runbook (Markdown) for the 'app' "
        "service on app-srv-01. Cover: pulling the release, running migrations "
        "against db01 (PostgreSQL 14), restarting the systemd service, clearing the "
        "Redis cache on cache01, and rollback. Mention the CI host ci01. "
        "Professional tone, realistic, no real secrets."
    ),
    "infra_notes": (
        "Write a short, slightly messy internal infrastructure notes / TODO file "
        "(Markdown) by a sysadmin. Include a few pending security tasks (rotate a "
        "credential, patch a service), a known issue, and maintenance windows. It "
        "should feel human and hurried, consistent with a Internal Corp Ubuntu "
        "22.04 stack (OpenSSH 8.9, nginx 1.18, PostgreSQL 14). No real secrets."
    ),
}


# ==========================================================================
#  Βοηθητικες: εγγραφη αρχειου στο προσομοιωμενο filesystem
# ==========================================================================
INVENTORY = []


def write_fs(rel_path, content, *, category, source, owner, story,
             prompt_ref=None, mode="644", mtime_days_ago=None):
    """Γραφει ενα artefact στο decoys/fs/<rel_path> και το καταγραφει στο
    inventory. rel_path ειναι το ΑΠΟΛΥΤΟ path οπως θα το δει ο επιτιθεμενος
    (π.χ. /home/mgeorgiou/.bash_history)."""
    abs_in_fs = FS_ROOT / rel_path.lstrip("/")
    abs_in_fs.parent.mkdir(parents=True, exist_ok=True)
    if not content.endswith("\n"):
        content += "\n"
    abs_in_fs.write_text(content, encoding="utf-8")

    INVENTORY.append({
        "name": os.path.basename(rel_path),
        "virtual_path": rel_path,
        "category": category,
        "source": source,                 # "llm" η "manual"
        "owner_user": owner,
        "role_in_story": story,
        "llm_prompt_ref": (f"llm_prompts/{prompt_ref}.txt" if prompt_ref else None),
        "unix_mode": mode,
        "size_bytes": len(content.encode("utf-8")),
    })


# ==========================================================================
#  MANUAL / TEMPLATE artefacts (5)
# ==========================================================================
def gen_manual():
    # ---- [manual 1] .bash_history του sysadmin mgeorgiou (shell_history) --
    admin = U["mgeorgiou"]
    bash_admin = "\n".join([
        "cd /opt/app",
        "git pull origin main",
        "systemctl status app.service",
        "sudo systemctl restart nginx",
        "tail -n 100 /var/log/nginx/error.log",
        f"psql -h db01.corp.local -U app_ro -d app_production -c '\\dt'",
        "redis-cli -h cache01.corp.local ping",
        "df -h",
        "free -m",
        "sudo journalctl -u app.service --since '1 hour ago'",
        "htop",
        "ss -tlnp",
        "sudo -l",
        "cat /etc/nginx/sites-available/app.corp.conf",
        "vim /opt/app/config/database.yml",
        "history | grep deploy",
        "ssh db01",
        "exit",
    ])
    write_fs("/home/mgeorgiou/.bash_history", bash_admin,
             category="shell_history", source="manual", owner="mgeorgiou",
             story="Ιστορικο εντολων του sysadmin. Αποκαλυπτει paths, εσωτερικα "
                   "hosts (db01, cache01) και το αρχειο credentials.",
             mtime_days_ago=1)

    # ---- [manual 2] app/.env (credentials, μορφη KEY=value) -----------------
    # Διορθωνει το λαθος της προηγουμενης εργασιας οπου το .env ηταν JSON.
    env = (
        "# /opt/app/.env  (production)  -- managed by CI, do not edit by hand\n"
        f"APP_ENV=production\n"
        f"APP_HOST={S['fqdn']}\n"
        "APP_PORT=8000\n"
        "SECRET_KEY_BASE=PLACEHOLDER_ROTATE_ME_9f2b7c41d0e8\n"
        "DATABASE_URL=postgres://app_rw:CHANGE_ME_devpass@db01.corp.local:5432/app_production\n"
        "REDIS_URL=redis://cache01.corp.local:6379/0\n"
        "SMTP_HOST=smtp.corp.local\n"
        "SMTP_USER=noreply@corp.local\n"
        "SMTP_PASSWORD=FAKE_SMTP_PW_do_not_use\n"
        "JWT_SIGNING_KEY=EXAMPLE_ONLY_not_a_real_key_0000\n"
        "SENTRY_DSN=https://examplePublicKey@o0.ingest.example.com/0\n"
    )
    write_fs("/opt/app/.env", env,
             category="credentials", source="manual", owner="svc_deploy",
             story="Δελεαστικο αρχειο 'μυστικων'. Ολες οι τιμες ειναι εμφανως "
                   "placeholder/ψευτικες και δειχνουν σε πλασματικα hosts.",
             mode="640", mtime_days_ago=3)

    # ---- [manual 3] PostgreSQL log (logs) -----------------------------------
    t0 = cfg.days_ago(2, hour=2, minute=5)
    pg_lines = []
    stmts = [
        "LOG:  database system is ready to accept connections",
        "LOG:  checkpoint starting: time",
        "LOG:  checkpoint complete: wrote 421 buffers (2.6%)",
        "LOG:  connection received: host=10.20.1.5 port=54210",
        "LOG:  connection authorized: user=app_rw database=app_production",
        "LOG:  duration: 1243.551 ms  statement: SELECT * FROM orders WHERE status='pending'",
        "LOG:  automatic vacuum of table \"app_production.public.sessions\"",
        "WARNING:  there is already a transaction in progress",
    ]
    for i, s in enumerate(stmts):
        ts = cfg.fmt(t0 + cfg.timedelta(minutes=i * 7), "log")
        pg_lines.append(f"{ts} [{12000 + i}] {s}")
    write_fs("/var/log/postgresql/postgresql-14-main.log", "\n".join(pg_lines),
             category="logs", source="manual", owner="postgres",
             story="Ρεαλιστικο log της PostgreSQL 14. Επιβεβαιωνει εκδοση, "
                   "database name και εσωτερικη IP της εφαρμογης.",
             mtime_days_ago=2)

    # ---- [manual 4] .ssh/known_hosts (ssh) ----------------------------------
    kh = "\n".join([
        f"db01.corp.local,10.20.1.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{'A'*20}exampleDB",
        f"cache01.corp.local,10.20.1.20 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{'B'*20}exampleCA",
        f"backup01.corp.local,10.20.1.30 ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB{'C'*24}exampleBK",
        f"ci01.corp.local,10.20.2.15 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{'D'*20}exampleCI",
    ])
    write_fs("/home/mgeorgiou/.ssh/known_hosts", kh,
             category="ssh", source="manual", owner="mgeorgiou",
             story="Αποκαλυπτει την εσωτερικη τοπολογια (4 hosts, IPs) και "
                   "καθοδηγει προς lateral movement.",
             mode="644", mtime_days_ago=5)

    # ---- [manual 5] cron.d/deploy (system) ----------------------------------
    cron = (
        "# /etc/cron.d/deploy  -- Internal deploy & maintenance jobs\n"
        "SHELL=/bin/bash\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
        "\n"
        "# Nightly database backup to backup01\n"
        "0 2 * * *  backup   /opt/deploy/bin/pg_backup.sh >> /var/log/pg_backup.log 2>&1\n"
        "# Rotate application logs\n"
        "30 3 * * * root     /usr/sbin/logrotate /etc/logrotate.d/app\n"
        "# Warm the Redis cache every 15 minutes\n"
        "*/15 * * * * svc_deploy /opt/app/bin/cache_warm.sh\n"
        "# Health probe\n"
        "*/5 * * * * svc_deploy curl -fsS http://127.0.0.1:8000/health >/dev/null\n"
    )
    write_fs("/etc/cron.d/deploy", cron,
             category="system", source="manual", owner="root",
             story="Αποκαλυπτει προγραμματισμενες εργασιες, service accounts και "
                   "μονοπατια scripts (πιθανα σημεια persistence).",
             mode="644", mtime_days_ago=12)


# ==========================================================================
#  LLM-GENERATED artefacts (7)
#  Το περιεχομενο παρηχθη με το μοντελο Claude (prompts στο llm_prompts/).
# ==========================================================================
def gen_llm():
    # ---- [llm 1] svc_deploy .bash_history (shell_history) -------------------
    content = """cd /opt/app
git fetch --all --prune
git checkout release/2026.04
git pull
source /opt/app/.venv/bin/activate
pip install -r requirements.txt --quiet
./bin/migrate.sh
sudo systemctl restart app.service
systemctl is-active app.service
curl -fsS http://127.0.0.1:8000/health
tail -f /var/log/app/app.log
redis-cli -h cache01.corp.local FLUSHDB
psql -h db01.corp.local -U app_ro -d app_production -c 'SELECT count(*) FROM users;'
./bin/cache_warm.sh
journalctl -u app.service --since '10 min ago' --no-pager
grep -i error /var/log/app/app.log | tail -n 20
scp release-2026.04.tar.gz svc_deploy@ci01.corp.local:/srv/artifacts/
df -h /opt
du -sh /opt/app/tmp/*
rm -rf /opt/app/tmp/cache/*
./bin/deploy.sh --env production --tag 2026.04
echo 'deploy ok' | logger -t deploy
exit"""
    write_fs("/opt/deploy/.bash_history", content,
             category="shell_history", source="llm", owner="svc_deploy",
             story="Ιστορικο του CI/CD λογαριασμου. Δειχνει τη ροη deploy, "
                   "migrations, cache flush και μεταφορα artifacts στο ci01.",
             prompt_ref="svc_deploy_bash_history", mtime_days_ago=1)

    # ---- [llm 2] nginx site config (config) ---------------------------------
    content = """# /etc/nginx/sites-available/app.corp.conf
# Managed by config management. nginx 1.18.0 (Ubuntu)

upstream app_backend {
    server 127.0.0.1:8000 fail_timeout=5s;
    keepalive 16;
}

server {
    listen 80;
    server_name app.corp.local;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name app.corp.local;

    ssl_certificate     /etc/ssl/corp/app.corp.local.crt;
    ssl_certificate_key /etc/ssl/corp/app.corp.local.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    access_log /var/log/nginx/app.access.log;
    error_log  /var/log/nginx/app.error.log warn;

    client_max_body_size 25m;

    location / {
        proxy_pass http://app_backend;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static/ {
        alias /opt/app/public/;
        expires 7d;
        access_log off;
    }

    # Internal metrics: restricted to the corporate subnet only
    location /metrics {
        allow 10.20.0.0/16;
        deny  all;
        proxy_pass http://app_backend;
    }
}"""
    write_fs("/etc/nginx/sites-available/app.corp.conf", content,
             category="config", source="llm", owner="mgeorgiou",
             story="Ρεαλιστικο nginx config. Αποκαλυπτει TLS paths, το backend "
                   "στο :8000, static root και το εσωτερικο /metrics.",
             prompt_ref="nginx_site", mtime_days_ago=8)

    # ---- [llm 3] config/database.yml (credentials/config) -------------------
    content = """# /opt/app/config/database.yml
# Passwords here are PLACEHOLDERS injected by CI at deploy time.
default: &default
  adapter: postgresql
  encoding: unicode
  pool: <%= ENV.fetch("DB_POOL", 10) %>
  host: db01.corp.local
  port: 5432

development:
  <<: *default
  database: app_development
  username: app_rw
  password: dev_placeholder_change_me

test:
  <<: *default
  database: app_test
  username: app_rw
  password: test_placeholder_change_me

production:
  primary:
    <<: *default
    database: app_production
    username: app_rw
    password: <%= ENV["DATABASE_PASSWORD"] %>   # injected, not stored
  replica:
    <<: *default
    database: app_production
    username: app_ro
    password: <%= ENV["DATABASE_RO_PASSWORD"] %>
    replica: true
    host: db01.corp.local"""
    write_fs("/opt/app/config/database.yml", content,
             category="credentials", source="llm", owner="svc_deploy",
             story="Config βασης. Οι κωδικοι ειναι ρητα placeholders (μερικοι "
                   "εγχεονται απο ENV), αλλα αποκαλυπτει users app_rw/app_ro και db01.",
             prompt_ref="database_yml", mode="640", mtime_days_ago=8)

    # ---- [llm 4] auth.log (logs) --------------------------------------------
    b = cfg.days_ago(1, hour=8, minute=2)
    host = S["hostname"]
    ws = N["admin_workstation"]
    lines = [
        f'{cfg.fmt(b,"syslog")} {host} sshd[20141]: Accepted publickey for mgeorgiou from {ws} port 51344 ssh2: ED25519 SHA256:9xk...redacted',
        f'{cfg.fmt(b+cfg.timedelta(seconds=1),"syslog")} {host} sshd[20141]: pam_unix(sshd:session): session opened for user mgeorgiou(uid=1001) by (uid=0)',
        f'{cfg.fmt(b+cfg.timedelta(minutes=2),"syslog")} {host} sudo:  mgeorgiou : TTY=pts/0 ; PWD=/opt/app ; USER=root ; COMMAND=/bin/systemctl restart nginx',
        f'{cfg.fmt(b+cfg.timedelta(minutes=2,seconds=1),"syslog")} {host} sudo: pam_unix(sudo:session): session opened for user root(uid=0) by mgeorgiou(uid=1001)',
        f'{cfg.fmt(b+cfg.timedelta(minutes=14),"syslog")} {host} sshd[20141]: pam_unix(sshd:session): session closed for user mgeorgiou',
        f'{cfg.fmt(b+cfg.timedelta(minutes=31),"syslog")} {host} sshd[20460]: Failed password for app_deploy from 10.20.2.15 port 40122 ssh2',
        f'{cfg.fmt(b+cfg.timedelta(minutes=31,seconds=4),"syslog")} {host} sshd[20460]: Accepted publickey for svc_deploy from 10.20.2.15 port 40124 ssh2: RSA SHA256:aa...redacted',
        f'{cfg.fmt(b+cfg.timedelta(hours=1),"syslog")} {host} CRON[20988]: pam_unix(cron:session): session opened for user backup(uid=1501) by (uid=0)',
    ]
    write_fs("/var/log/auth.log", "\n".join(lines),
             category="logs", source="llm", owner="root",
             story="Ρεαλιστικο auth.log. Επιβεβαιωνει χρηστες, το admin "
                   "workstation, sudo χρηση και μια αποτυχημενη συνδεση απο ci01.",
             prompt_ref="auth_log", mtime_days_ago=1)

    # ---- [llm 5] .ssh/config (ssh) ------------------------------------------
    content = """# ~/.ssh/config  -- mgeorgiou

Host bastion
    HostName bastion.corp.local
    User mgeorgiou
    IdentityFile ~/.ssh/id_ed25519

Host db01
    HostName db01.corp.local
    User mgeorgiou
    ProxyJump bastion
    IdentityFile ~/.ssh/id_ed25519

Host cache01
    HostName cache01.corp.local
    User mgeorgiou
    ProxyJump bastion

Host backup01
    HostName backup01.corp.local
    User backup
    IdentityFile ~/.ssh/id_backup

Host ci01
    HostName ci01.corp.local
    User mgeorgiou
    ForwardAgent yes

Host *
    ServerAliveInterval 60
    StrictHostKeyChecking accept-new"""
    write_fs("/home/mgeorgiou/.ssh/config", content,
             category="ssh", source="llm", owner="mgeorgiou",
             story="Χαρτης ολοκληρου του εσωτερικου στολου (bastion, db01, "
                   "cache01, backup01, ci01) και των identity files.",
             prompt_ref="ssh_config", mode="600", mtime_days_ago=6)

    # ---- [llm 6] deploy runbook (docs) --------------------------------------
    content = """# Deployment Runbook - `app` service (app-srv-01)

> Owner: Platform team. Keep this in sync with `bin/deploy.sh`.

## 1. Pre-flight
- Confirm green build on **ci01.corp.local**.
- Announce in #ops. Check current version: `systemctl show -p ActiveEnterTimestamp app.service`.

## 2. Release
```bash
cd /opt/app
git fetch --all
git checkout release/<YYYY.MM>
./bin/migrate.sh          # runs against db01.corp.local (PostgreSQL 14)
sudo systemctl restart app.service
```

## 3. Post-deploy
- Warm cache on **cache01**: `./bin/cache_warm.sh`
- Smoke test: `curl -fsS http://127.0.0.1:8000/health`
- Tail logs for 5 min: `journalctl -u app.service -f`

## 4. Rollback
```bash
git checkout release/<previous>
./bin/migrate.sh --rollback
sudo systemctl restart app.service
```
Redis cache on cache01 is flushed automatically on rollback.

## Notes
- Migrations are **not** reversible for the `orders` table. Take a db01 snapshot first.
- If nginx (1.18.0) shows 502s, check the upstream `app_backend` on :8000."""
    write_fs("/opt/app/runbooks/deploy_runbook.md", content,
             category="docs", source="llm", owner="svc_deploy",
             story="Runbook που εξηγει ολη τη ροη production. Πλουσια πηγη "
                   "intelligence (hosts, service, βαση, cache, rollback).",
             prompt_ref="deploy_runbook", mtime_days_ago=15)

    # ---- [llm 7] infra notes / TODO (docs) ----------------------------------
    content = """# Infra notes (app-srv-01) - keep it short

## TODO (security)
- [ ] Rotate the `app_rw` DB password - still the pre-launch dev value in some envs (!!)
- [ ] Patch OpenSSH (running 8.9p1, want the latest ubuntu security update)
- [ ] Lock down /metrics - currently allow 10.20.0.0/16, should be monitoring host only
- [ ] Remove old `svc_deploy` key from ci01 (rotated last month)

## Known issues
- app.service occasionally OOMs after ~10 days uptime -> weekly restart via cron for now
- db01 replica lag spikes during nightly pg_backup (02:00). Move backup window?

## Maintenance windows
- Patching: first Sunday, 02:00-04:00 EEST
- Next planned: 2026-05-03

## Random
- backup01 disk at 71%, order more before June
- ci01 agent token in Jenkins creds store, NOT here"""
    write_fs("/root/NOTES_infra.md", content,
             category="docs", source="llm", owner="root",
             story="Ανθρωπινες, βιαστικες σημειωσεις admin. Δημιουργουν αισθηση "
                   "επειγοντος και αποκαλυπτουν αδυναμιες (μη-εναλλαγμενο κωδικο).",
             prompt_ref="infra_notes", mode="600", mtime_days_ago=4)


# ==========================================================================
#  Εγγραφη prompts + inventory
# ==========================================================================
def write_prompts():
    PROMPT_DIR.mkdir(exist_ok=True)
    for name, text in LLM_PROMPTS.items():
        (PROMPT_DIR / f"{name}.txt").write_text(text.strip() + "\n", encoding="utf-8")


def write_inventory():
    inv_path = DECOY_DIR / "artifact_inventory.json"
    summary = {
        "system_profile": {
            "hostname": S["fqdn"], "os": S["os"],
            "openssh": V["openssh"], "nginx": V["nginx"], "postgres": V["postgres"],
        },
        "total_artifacts": len(INVENTORY),
        "llm_generated": sum(1 for a in INVENTORY if a["source"] == "llm"),
        "manual": sum(1 for a in INVENTORY if a["source"] == "manual"),
        "categories": sorted(set(a["category"] for a in INVENTORY)),
        "artifacts": INVENTORY,
    }
    inv_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return summary


def main():
    FS_ROOT.mkdir(parents=True, exist_ok=True)
    print("[*] Παραγωγη decoy artefacts...")
    gen_manual()
    gen_llm()
    write_prompts()
    summary = write_inventory()

    print(f"[+] Δημιουργηθηκαν {summary['total_artifacts']} artefacts "
          f"({summary['llm_generated']} LLM, {summary['manual']} manual) "
          f"σε {len(summary['categories'])} κατηγοριες.")
    print(f"[+] Κατηγοριες: {', '.join(summary['categories'])}")
    print(f"[+] Virtual filesystem: {FS_ROOT}")
    print(f"[+] Inventory: {DECOY_DIR / 'artifact_inventory.json'}")
    print(f"[+] LLM prompts: {PROMPT_DIR}/")


# timedelta shortcut για χρηση μεσα στο module
import datetime as _dt
cfg.timedelta = _dt.timedelta

if __name__ == "__main__":
    main()