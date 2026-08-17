# -*- coding: utf-8 -*-
"""
run_all.py  --  Single orchestrator for the whole pipeline
==========================================================

WHAT THIS FILE OFFERS
---------------------
This is the "one-run button". Instead of running the six scripts one by one in
the correct order (which is error-prone, especially because the honeypot must
run AT THE SAME TIME as the playbooks), this orchestrator wires everything up
automatically and in the right order:

  1. 01_generate_decoys.py   -> generates the decoy artefacts
  2. 02_ssh_honeypot.py      -> starts the honeypot IN THE BACKGROUND
  3. 03_run_playbooks.py     -> runs the playbooks against the honeypot
  4. (stops the honeypot automatically)
  5. 04_analyze_sessions.py  -> analysis, clustering, figures
  6. 05_intent_classifier.py -> optional supervised classifier

The critical part is steps 2-4: the script starts the honeypot as a separate
process, waits for it to come up, runs the playbooks, and then cleanly stops
the honeypot. Otherwise the user would have to do this synchronisation manually
in two separate terminals.

WHY run_all.sh ALSO EXISTS
--------------------------
run_all.py is the real orchestrator and works BOTH on Windows AND on
Linux/Kali. run_all.sh is just a small helper wrapper for Linux/Kali that calls
run_all.py (on Kali it is more natural to run a .sh). They do not share a name:
they differ in the extension (.py / .sh).

USAGE
-----
    python3 run_all.py                 # everything, on the default port 2222
    python3 run_all.py --port 2222     # on another port
    python3 run_all.py --skip-optional # without step 5 (classifier)
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
        print(f"[!] {script} exited with code {r.returncode}")
        sys.exit(r.returncode)


def main():
    ap = argparse.ArgumentParser(description="Honeypot analytics orchestrator")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--skip-optional", action="store_true")
    args = ap.parse_args()

    # 1. Decoys
    run("01_generate_decoys.py")

    # 2. Honeypot in the background
    print(f"\n{'='*64}\n>>> Starting honeypot on {args.host}:{args.port}\n{'='*64}")
    hp = subprocess.Popen([PY, str(BASE / "02_ssh_honeypot.py"),
                           "--host", args.host, "--port", str(args.port)])
    time.sleep(4)   # time for the server to come up

    try:
        # 3. Playbooks
        run("03_run_playbooks.py", "--host", args.host, "--port", str(args.port))
    finally:
        # 4. Stop the honeypot
        print("\n[*] Stopping honeypot...")
        if sys.platform == "win32":
            hp.terminate()
        else:
            hp.send_signal(signal.SIGINT)
        try:
            hp.wait(timeout=6)
        except subprocess.TimeoutExpired:
            hp.kill()

    # 5. Analysis
    run("04_analyze_sessions.py")

    # 6. Optional classifier
    if not args.skip_optional:
        run("05_intent_classifier.py")

    print(f"\n{'='*64}\n[+] The whole chain is complete.")
    print("[+] See: analysis/  figures/  logs/sessions/")
    print(f"{'='*64}")


if __name__ == "__main__":
    main()
