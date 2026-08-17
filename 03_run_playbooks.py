# -*- coding: utf-8 -*-
"""
03_run_playbooks.py  --  Controlled attack scenarios
=====================================================
[TASK 4] Attacker playbooks: simulating attacker behaviour.

WHAT THIS FILE DOES
-------------------
Defines 7 playbooks (predefined attack scenarios), each with a distinct goal,
and runs them through a REAL SSH client (paramiko) against the honeypot. Each
playbook is a sequence of commands that an attacker with a specific intent
(e.g. searching for passwords) would issue. Since we did not have real
attackers, the playbooks "play" their role in a controlled way, so that
realistic traffic is produced towards the honeypot.

DEPTH VARIANTS
--------------
Each playbook is executed in three variants, to simulate the fact that some
attackers are hasty and others methodical:
- shallow   : only the first, basic commands (a surface glance).
- deep      : the full sequence (reads the decoys too).
- deep_plus : the full sequence + extra follow-up commands.
Each playbook runs 5 times (2 shallow, 2 deep, 1 deep_plus), so in total
7 x 5 = 35 sessions, with slight randomisation so that repetitions differ.
The assignment requires >=15 sessions - we deliberately exceed that for a more
meaningful analysis.

WHY WE KEEP GROUND TRUTH SEPARATE (methodology)
-----------------------------------------------
The "goal" (intent) of each playbook is stored as GROUND TRUTH (the known
truth) in a separate file (playbook_results/ground_truth.json). The honeypot
does NOT know the goal, it only records what happened. Thus, in Task 5 the
clustering is done "blind" on the behavioural features and only then compared
with the ground truth. This avoids the tautology "intent = playbook name" and
gives a real, unbiased evaluation. Each session is matched to its playbook via
the local port (src_port) of the SSH client.

HOW TO RUN
----------
Assumes the honeypot (02) is already running. Execution:
    python3 03_run_playbooks.py --host 127.0.0.1 --port 2222

Everything runs inside the isolated lab (localhost).
"""

import sys
import json
import time
import random
import argparse
import importlib
from datetime import datetime, timezone
from pathlib import Path

import paramiko

cfg = importlib.import_module("00_config")

BASE = Path(__file__).resolve().parent
PB_DIR = BASE / "playbook_results"
ACCEPTED_PASSWORD = "Corp2026!"


# ==========================================================================
#  Playbook catalogue (Task 4)
#  Each playbook: intent (ground truth), full command sequence (deep), number
#  of commands for the shallow variant, and follow-ups for the deep_plus variant.
# ==========================================================================
PLAYBOOKS = {
    "recon": {
        "intent": "reconnaissance",
        "objective": "Βασικη αναγνωριση συστηματος και ταυτοτητας.",
        "commands": [
            "whoami", "id", "uname -a", "hostname",
            "cat /etc/os-release", "ps aux", "ss -tlnp",
        ],
        "shallow_n": 3,
        "followups": ["cat /etc/issue", "env"],
    },
    "credential_search": {
        "intent": "credential_harvesting",
        "objective": "Αναζητηση κωδικων, κλειδιων και αρχειων ρυθμισεων.",
        "commands": [
            "history", "cat /opt/app/.env",
            "grep -r password /opt/app", "cat /opt/app/config/database.yml",
            "cat /home/mgeorgiou/.ssh/config", "find / -name '*.env'",
        ],
        "shallow_n": 2,
        "followups": ["cat /home/mgeorgiou/.ssh/known_hosts", "cat /opt/deploy/.bash_history"],
    },
    "config_discovery": {
        "intent": "environment_mapping",
        "objective": "Χαρτογραφηση υπηρεσιων και ρυθμισεων.",
        "commands": [
            "cat /etc/hosts", "cat /etc/nginx/sites-available/app.corp.conf",
            "ls -la /etc", "find /etc -name '*.conf'", "cat /etc/cron.d/deploy",
        ],
        "shallow_n": 2,
        "followups": ["cat /var/log/postgresql/postgresql-14-main.log"],
    },
    "privilege_escalation": {
        "intent": "privilege_escalation",
        "objective": "Προσπαθεια ανοδου προνομιων σε root.",
        "commands": [
            "sudo -l", "cat /etc/passwd", "cat /etc/shadow",
            "find / -perm -4000", "sudo cat /etc/shadow",
        ],
        "shallow_n": 2,
        "followups": ["sudo cat /root/NOTES_infra.md"],
    },
    "data_staging": {
        "intent": "data_exfiltration",
        "objective": "Εντοπισμος και προετοιμασια δεδομενων για διαρροη.",
        "commands": [
            "ls -la /opt/app", "find /opt/app -type f",
            "cat /opt/app/runbooks/deploy_runbook.md", "du -sh /opt/app",
        ],
        "shallow_n": 2,
        "followups": ["tar czf /tmp/stage.tgz /opt/app"],
    },
    "lateral_movement": {
        "intent": "lateral_movement",
        "objective": "Εντοπισμος και δοκιμη αλλων εσωτερικων συστηματων.",
        "commands": [
            "cat /etc/hosts", "cat /home/mgeorgiou/.ssh/known_hosts",
            "cat /home/mgeorgiou/.ssh/config", "cat /var/log/auth.log",
            "ssh db01.corp.local",
        ],
        "shallow_n": 2,
        "followups": ["ssh cache01.corp.local", "ping -c 2 10.20.1.10"],
    },
    "honeypot_fingerprinting": {
        "intent": "honeypot_detection",
        "objective": "Ελεγχος για sandbox/honeypot/VM.",
        "commands": [
            "uname -a", "cat /proc/version", "ls -la /.dockerenv",
            "ps aux", "cat /etc/shadow", "ip addr",
        ],
        "shallow_n": 3,
        "followups": ["cat /proc/cpuinfo", "cat /etc/mtab"],
    },
}

# Session plan: each playbook is run multiple times per depth, with
# randomisation, so that a sufficient and varied set (~35 sessions) is produced
# for meaningful clustering (Task 5) and supervised classification (optional).
# The assignment requires >=15 sessions - we deliberately exceed that.
SESSION_PLAN = []
for _pb in PLAYBOOKS:
    for _depth in ("shallow", "shallow", "deep", "deep", "deep_plus"):
        SESSION_PLAN.append((_pb, _depth))
# 7 playbooks x 5 = 35 command-sessions.

# Attacker personas (usernames + whether they make a failed attempt first)
PERSONAS = [
    {"user": "root",        "wrong_first": True},
    {"user": "admin",       "wrong_first": True},
    {"user": "ubuntu",      "wrong_first": False},
    {"user": "mgeorgiou", "wrong_first": False},
]


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f%z")


def build_commands(pb, depth, rng):
    """Return the command list for the given depth, with slight randomisation so
    that repetitions of the same playbook differ (realism + variety for the
    analysis)."""
    cmds = list(pb["commands"])
    if depth == "shallow":
        k = max(1, pb["shallow_n"] + rng.choice([-1, 0, 0, 1]))
        out = cmds[:k]
    elif depth == "deep":
        out = cmds[:]
        if len(out) > 3 and rng.random() < 0.4:
            out.pop(rng.randrange(1, len(out)))
    else:  # deep_plus: full sequence + follow-ups
        out = cmds[:] + pb.get("followups", [])
        if rng.random() < 0.5:
            tail = out[len(cmds):]
            rng.shuffle(tail)
            out = out[:len(cmds)] + tail
    return out


def run_session(host, port, playbook_name, depth, rng):
    """Run one session over SSH. Returns the ground-truth record."""
    pb = PLAYBOOKS[playbook_name]
    commands = build_commands(pb, depth, rng)
    persona = rng.choice(PERSONAS)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Optional failed authentication attempt (realism -> it gets logged)
    if persona["wrong_first"]:
        try:
            client.connect(host, port=port, username=persona["user"],
                           password="123456", look_for_keys=False,
                           allow_agent=False, timeout=8, banner_timeout=8)
        except Exception:
            pass  # expected failure

    client.connect(host, port=port, username=persona["user"],
                   password=ACCEPTED_PASSWORD, look_for_keys=False,
                   allow_agent=False, timeout=8, banner_timeout=8)

    # The local port the honeypot sees as src_port (used for matching)
    src_port = client.get_transport().sock.getsockname()[1]

    chan = client.invoke_shell()
    time.sleep(0.4)
    if chan.recv_ready():
        chan.recv(8192)

    for c in commands:
        chan.send(c + "\n")
        # realistic, variable delays (the deeper the session, the more "thoughtful")
        time.sleep(rng.uniform(0.25, 0.9))
        t0 = time.time()
        while time.time() - t0 < 0.6:
            if chan.recv_ready():
                chan.recv(16384)
            else:
                time.sleep(0.05)

    chan.send("exit\n")
    time.sleep(0.3)
    client.close()

    return {
        "playbook": playbook_name,
        "intent": pb["intent"],
        "depth": depth,
        "persona_user": persona["user"],
        "src_port": src_port,
        "commands_sent": len(commands),
        "timestamp": now_iso(),
    }


def main():
    ap = argparse.ArgumentParser(description="Attacker playbook executor")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2222)
    args = ap.parse_args()

    rng = random.Random(cfg.SEED)
    PB_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[*] Εκτελεση {len(SESSION_PLAN)} playbook sessions εναντια στο "
          f"{args.host}:{args.port}\n")

    ground_truth = []
    for i, (pb_name, depth) in enumerate(SESSION_PLAN, 1):
        try:
            gt = run_session(args.host, args.port, pb_name, depth, rng)
            ground_truth.append(gt)
            print(f"  [{i:>2}/{len(SESSION_PLAN)}] {pb_name:<24} {depth:<10} "
                  f"({gt['commands_sent']} cmds, src_port={gt['src_port']})")
        except Exception as e:
            print(f"  [{i:>2}/{len(SESSION_PLAN)}] {pb_name} {depth}  ΣΦΑΛΜΑ: {e}")
        time.sleep(0.4)

    # Playbook catalogue (Task 4 evidence)
    catalogue = {name: {"intent": pb["intent"], "objective": pb["objective"],
                        "max_commands": len(pb["commands"]) + len(pb.get("followups", []))}
                 for name, pb in PLAYBOOKS.items()}

    (PB_DIR / "ground_truth.json").write_text(
        json.dumps({"sessions": ground_truth, "catalogue": catalogue},
                   indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\n[+] Ολοκληρωθηκαν {len(ground_truth)} sessions.")
    print(f"[+] Ground truth: {PB_DIR / 'ground_truth.json'}")


if __name__ == "__main__":
    main()
