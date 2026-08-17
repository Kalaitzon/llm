SCREENSHOTS GUIDE

The screenshots document the execution of the system. Below is the
order to follow and the file names.

You need TWO PowerShell windows:
  - Window A: runs the honeypot (stays open)
  - Window B: everything else

(On Windows type "python", on Kali "python3".)


----------------------------------------------------------------
 STEP 0 - Setup (once)
----------------------------------------------------------------
In Window B, inside the LLM_MTE25012 folder:

    pip install -r requirements.txt


----------------------------------------------------------------
 STEP 1 - Generate decoys                [decoys_generated.png]
----------------------------------------------------------------
    python 01_generate_decoys.py

Screenshot: the result "Generated 12 artefacts (7 LLM, 5 manual)".


----------------------------------------------------------------
 STEP 2 - Start the honeypot             [honeypot_listening.png]
----------------------------------------------------------------
In Window A:

    python 02_ssh_honeypot.py --port 2222

Screenshot: the "Honeypot SSH listening on 127.0.0.1:2222" line.
LEAVE IT OPEN.


----------------------------------------------------------------
 STEP 3 - Manual connection (demo)       [manual_ssh_session_1.png]
                                         [manual_ssh_session_2.png]
----------------------------------------------------------------
In Window B:

    ssh -p 2222 root@127.0.0.1

Answer "yes", password: Corp2026!
Then issue:  whoami
             cat /opt/app/.env
             cat /root/NOTES_infra.md
             exit

Screenshot: the whole session. It shows that the honeypot really
serves the fake files (the most impressive screenshot).

NOTE: this manual connection is ONLY for the screenshot. It will
create one extra session in the logs. For that reason, BEFORE the
final run (Step 4) we clear the logs, so that the analysis is based
only on the 35 playbook sessions.


----------------------------------------------------------------
 STEP 4 - Clear + Playbooks              [playbooks_running_1.png]
                                         [playbooks_running_2.png]
----------------------------------------------------------------
FIRST delete any previous logs (Window B):

    Remove-Item logs\sessions\* -Force
    Remove-Item logs\sessions.jsonl -Force

(If the honeypot had been closed, re-run Step 2 with a clean honeypot.)

Then, with the honeypot running, run ONCE (Window B):

    python 03_run_playbooks.py --port 2222

Screenshot: the list "[ 1/35] ... [35/35]" and the
"Completed 35 sessions" line.


----------------------------------------------------------------
 STEP 5 - Stop the honeypot
----------------------------------------------------------------
In Window A: press Ctrl + C.


----------------------------------------------------------------
 STEP 6 - Analysis                       [analysis_summary.png]
----------------------------------------------------------------
In Window B:

    python 04_analyze_sessions.py

Screenshot: the "=== SUMMARY ===" section. It must show:
  - 55 logs: 35 command-sessions, 20 failed-auth probes
  - Touches manual vs LLM: manual 19, llm 21
  - Isolation Forest flagged: 9/35
  - Cluster-vs-intent ARI: 0.185


----------------------------------------------------------------
 STEP 7 - Classifier (optional task)     [classifier.png]
----------------------------------------------------------------
    python 05_intent_classifier.py

Screenshot: it must show:
  - LOOCV accuracy=0.571 | macro-F1=0.559  (n=35, 7 classes)


================================================================
 LIST OF SCREENSHOT FILES
================================================================
  decoys_generated.png       (Step 1)
  honeypot_listening.png     (Step 2)
  manual_ssh_session_1.png   (Step 3)
  manual_ssh_session_2.png   (Step 3)
  playbooks_running_1.png    (Step 4)
  playbooks_running_2.png    (Step 4)
  analysis_summary.png       (Step 6)
  classifier.png             (Step 7)

NOTE: with the same seed (25012), the numbers come out identical to
the report. Only the classifier accuracy may differ slightly
(0.57-0.60) because of the real execution time of the sessions.
================================================================
