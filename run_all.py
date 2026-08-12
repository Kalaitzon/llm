# ── Kalaitzidis Ioannis - MTE25012 ─────────────────────────────────────────────────────
"""

ΤΙ ΠΡΟΣΦΕΡΕΙ ΑΥΤΟ ΤΟ ΑΡΧΕΙΟ
---------------------------
Ειναι το "κουμπι μιας εκτελεσης", και με τη σωστη σειρα:

  1. 01_generate_decoys.py   -> παραγει τα decoy artefacts
  2. 02_ssh_honeypot.py      -> ξεκιναει το honeypot ΣΤΟ ΠΑΡΑΣΚΗΝΙΟ (background)
  3. 03_run_playbooks.py     -> τρεχει τα playbooks εναντια στο honeypot
  4. (σταματαει αυτοματα το honeypot)
  5. 04_analyze_sessions.py  -> αναλυση, clustering, figures
  6. 05_intent_classifier.py -> προαιρετικος supervised classifier

Το κρισιμο σημειο ειναι το βημα 2-4: το script ξεκιναει το honeypot ως
ξεχωριστη διεργασια, περιμενει να "σηκωθει", τρεχει τα playbooks, και μετα
τερματιζει καθαρα το honeypot. Αυτο το συγχρονισμο θα επρεπε αλλιως να τον
κανει ο χρηστης χειροκινητα σε δυο διαφορετικα terminals.

ΧΡΗΣΗ
-----
    python3 run_all.py                 # ολα, στην προεπιλεγμενη θυρα 2222
    python3 run_all.py --port 2222     # σε αλλη θυρα
    python3 run_all.py --skip-optional # χωρις το βημα 5 (classifier)
"""

import sys
import time
import signal
import argparse
import subprocess
from pathlib import Path

BASE = Path(__file__).resolve().parent
PY = sys.executable


def run(script, *extra):
    print(f"\n{'='*64}\n>>> {script} {' '.join(extra)}\n{'='*64}")
    r = subprocess.run([PY, str(BASE / script), *extra])
    if r.returncode != 0:
        print(f"[!] Το {script} τερματισε με κωδικο {r.returncode}")
        sys.exit(r.returncode)


def main():
    ap = argparse.ArgumentParser(description="Honeypot analytics orchestrator")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--skip-optional", action="store_true")
    args = ap.parse_args()

    # 1. Decoys
    run("01_generate_decoys.py")

    # 2. Honeypot στο παρασκηνιο
    print(f"\n{'='*64}\n>>> Εκκινηση honeypot στο {args.host}:{args.port}\n{'='*64}")
    hp = subprocess.Popen([PY, str(BASE / "02_ssh_honeypot.py"),
                           "--host", args.host, "--port", str(args.port)])
    time.sleep(4)   # χρονος να σηκωθει ο server

    try:
        # 3. Playbooks
        run("03_run_playbooks.py", "--host", args.host, "--port", str(args.port))
    finally:
        # 4. Σταματαμε το honeypot
        print("\n[*] Τερματισμος honeypot...")
        if sys.platform == "win32":
            hp.terminate()
        else:
            hp.send_signal(signal.SIGINT)
        try:
            hp.wait(timeout=6)
        except subprocess.TimeoutExpired:
            hp.kill()

    # 5. Αναλυση
    run("04_analyze_sessions.py")

    # 6. Προαιρετικος classifier
    if not args.skip_optional:
        run("05_intent_classifier.py")

    print(f"\n{'='*64}\n[+] Ολοκληρωθηκε ολη η αλυσιδα.")
    print("[+] Δες: analysis/  figures/  logs/sessions/")
    print(f"{'='*64}")


if __name__ == "__main__":
    main()