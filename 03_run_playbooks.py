# ── Kalaitzidis Ioannis - MTE25012 ─────────────────────────────────────────────────────

"""
03_run_playbooks.py  --  Ελεγχομενα σεναρια επιθεσης
=====================================================
[TASK 4] Attacker playbooks: προσομοιωση της συμπεριφορας επιτιθεμενων.

ΤΙ ΚΑΝΕΙ ΑΥΤΟ ΤΟ ΑΡΧΕΙΟ
-----------------------
Οριζει 7 playbooks (προκαθορισμενα σεναρια επιθεσης), καθενα με ξεχωριστο
στοχο, και τα εκτελει μεσω ΠΡΑΓΜΑΤΙΚΟΥ SSH client (paramiko) εναντια στο
honeypot. Καθε playbook ειναι μια ακολουθια εντολων που θα εδινε ενας
επιτιθεμενος με συγκεκριμενη προθεση (π.χ. αναζητηση κωδικων). Επειδη δεν
διαθεταμε πραγματικους επιτιθεμενους, τα playbooks "παιζουν" ελεγχομενα τον
ρολο τους, ωστε να παραχθει ρεαλιστικη κινηση προς το honeypot.

ΠΑΡΑΛΛΑΓΕΣ ΒΑΘΟΥΣ
----------------
Καθε playbook εκτελειται σε τρεις παραλλαγες, ωστε να προσομοιωθει το γεγονος
οτι αλλοι επιτιθεμενοι ειναι βιαστικοι και αλλοι μεθοδικοι:
- shallow   : μονο οι πρωτες, βασικες εντολες (επιφανειακη ματια).
- deep      : ολη η ακολουθια (διαβαζει και τα δολωματα).
- deep_plus : ολη η ακολουθια + επιπλεον εντολες follow-up.
Καθε playbook τρεχει 5 φορες (2 shallow, 2 deep, 1 deep_plus), αρα συνολικα
7 x 5 = 35 sessions, με ελαφρα τυχαιοτητα ωστε οι επαναληψεις να διαφερουν.
Η εκφωνηση απαιτει >=15 sessions - το υπερβαινουμε σκοπιμα για ουσιαστικοτερη
αναλυση.

ΓΙΑΤΙ ΚΡΑΤΑΜΕ GROUND TRUTH ΞΕΧΩΡΙΣΤΑ (μεθοδολογια)
-------------------------------------------------
Ο "στοχος" (intent) καθε playbook αποθηκευεται ως GROUND TRUTH
σε ξεχωριστο αρχειο (playbook_results/ground_truth.json). Το honeypot ΔΕΝ
γνωριζει τον στοχο, καταγραφει μονο τι συνεβη. Ετσι, στο Task 5 το clustering
γινεται "στα τυφλα" πανω στα behavioural features και μετα συγκρινεται με το
ground truth. Αυτο αποφευγει την ταυτολογια "intent = ονομα playbook" και
δινει πραγματικη, αμεροληπτη αξιολογηση. Η συσχετιση καθε session με το
playbook του γινεται μεσω της τοπικης θυρας (src_port) του SSH client.

ΠΩΣ ΤΡΕΧΕΙ
----------
Προϋποθετει οτι το honeypot (02) τρεχει ηδη. Εκτελεση:
    python3 03_run_playbooks.py --host 127.0.0.1 --port 2222

Ολα εκτελουνται εντος του απομονωμενου εργαστηριου (localhost).
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
#  Καταλογος playbooks (Task 4)
#  Καθε playbook: intent (ground truth), πληρης ακολουθια εντολων (deep),
#  αριθμος εντολων για την shallow παραλλαγη, και follow-ups για deep-variant.
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

# Πλανο sessions: καθε playbook εκτελειται πολλαπλες φορες ανα βαθος, με
# randomization, ωστε να παραχθει επαρκες και ποικιλο συνολο (~35 sessions)
# για ουσιαστικο clustering (Task 5) και supervised classification (optional).
# Η εκφωνηση απαιτει >=15 sessions - το υπερβαινουμε σκοπιμα.
SESSION_PLAN = []
for _pb in PLAYBOOKS:
    for _depth in ("shallow", "shallow", "deep", "deep", "deep_plus"):
        SESSION_PLAN.append((_pb, _depth))
# 7 playbooks x 5 = 35 command-sessions.

# Personas επιτιθεμενων (usernames + αν θα κανουν αποτυχημενη προσπαθεια πρωτα)
PERSONAS = [
    {"user": "root",        "wrong_first": True},
    {"user": "admin",       "wrong_first": True},
    {"user": "ubuntu",      "wrong_first": False},
    {"user": "mgeorgiou", "wrong_first": False},
]


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f%z")


def build_commands(pb, depth, rng):
    """Επιστρεφει τη λιστα εντολων για το δοσμενο βαθος, με ελαφρα
    randomization ωστε επαναληψεις του ιδιου playbook να διαφερουν
    (ρεαλισμος + ποικιλια για την αναλυση)."""
    cmds = list(pb["commands"])
    if depth == "shallow":
        k = max(1, pb["shallow_n"] + rng.choice([-1, 0, 0, 1]))
        out = cmds[:k]
    elif depth == "deep":
        out = cmds[:]
        if len(out) > 3 and rng.random() < 0.4:
            out.pop(rng.randrange(1, len(out)))
    else:  # deep_plus: πληρης ακολουθια + follow-ups
        out = cmds[:] + pb.get("followups", [])
        if rng.random() < 0.5:
            tail = out[len(cmds):]
            rng.shuffle(tail)
            out = out[:len(cmds)] + tail
    return out


def run_session(host, port, playbook_name, depth, rng):
    """Εκτελει ενα session μεσω SSH. Επιστρεφει ground-truth εγγραφη."""
    pb = PLAYBOOKS[playbook_name]
    commands = build_commands(pb, depth, rng)
    persona = rng.choice(PERSONAS)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Προαιρετικη αποτυχημενη προσπαθεια authentication (ρεαλισμος -> καταγραφεται)
    if persona["wrong_first"]:
        try:
            client.connect(host, port=port, username=persona["user"],
                           password="123456", look_for_keys=False,
                           allow_agent=False, timeout=8, banner_timeout=8)
        except Exception:
            pass  # αναμενομενη αποτυχια

    client.connect(host, port=port, username=persona["user"],
                   password=ACCEPTED_PASSWORD, look_for_keys=False,
                   allow_agent=False, timeout=8, banner_timeout=8)

    # Το local port που βλεπει το honeypot ως src_port (για συσχετιση)
    src_port = client.get_transport().sock.getsockname()[1]

    chan = client.invoke_shell()
    time.sleep(0.4)
    if chan.recv_ready():
        chan.recv(8192)

    for c in commands:
        chan.send(c + "\n")
        # ρεαλιστικες, μεταβλητες καθυστερησεις (deeper -> πιο "σκεπτικος")
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

    # Καταλογος playbooks (Task 4 evidence)
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