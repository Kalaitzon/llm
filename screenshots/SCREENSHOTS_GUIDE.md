# Screenshots Guide

The screenshots document the execution of the system. Below is the order to
follow and the file names.

You need **two PowerShell windows**:

- **Window A**: runs the honeypot (stays open)
- **Window B**: everything else

> On Windows type `python`; on Kali type `python3`.

## Step 0 — Setup (once)

In Window B, inside the `LLM_MTE25012` folder:

```
pip install -r requirements.txt
```

## Step 1 — Generate decoys → `decoys_generated.png`

```
python 01_generate_decoys.py
```

Screenshot: the result "Generated 12 artefacts (7 LLM, 5 manual)".

## Step 2 — Start the honeypot → `honeypot_listening.png`

In Window A:

```
python 02_ssh_honeypot.py --port 2222
```

Screenshot: the "Honeypot SSH listening on 127.0.0.1:2222" line. **Leave it open.**

## Step 3 — Manual connection (demo) → `manual_ssh_session_1.png`, `manual_ssh_session_2.png`

In Window B:

```
ssh -p 2222 root@127.0.0.1
```

Answer `yes`, password: `Corp2026!`. Then issue:

```
whoami
cat /opt/app/.env
cat /root/NOTES_infra.md
exit
```

Screenshot: the whole session. It shows that the honeypot really serves the fake
files (the most impressive screenshot).

> **Note:** this manual connection is ONLY for the screenshot. It will create
> one extra session in the logs. For that reason, BEFORE the final run (Step 4)
> we clear the logs, so that the analysis is based only on the 35 playbook
> sessions.

## Step 4 — Clear + Playbooks → `playbooks_running_1.png`, `playbooks_running_2.png`

First delete any previous logs (Window B):

```
Remove-Item logs\sessions\* -Force
Remove-Item logs\sessions.jsonl -Force
```

(If the honeypot had been closed, re-run Step 2 with a clean honeypot.)

Then, with the honeypot running, run **once** (Window B):

```
python 03_run_playbooks.py --port 2222
```

Screenshot: the list "[ 1/35] ... [35/35]" and the "Completed 35 sessions" line.

## Step 5 — Stop the honeypot

In Window A: press **Ctrl + C**.

## Step 6 — Analysis → `analysis_summary.png`

In Window B:

```
python 04_analyze_sessions.py
```

Screenshot: the "=== SUMMARY ===" section. It must show:

- 55 logs: 35 command-sessions, 20 failed-auth probes
- Touches manual vs LLM: manual 19, llm 21
- Isolation Forest flagged: 9/35
- Cluster-vs-intent ARI: 0.185

## Step 7 — Classifier (optional task) → `classifier.png`

```
python 05_intent_classifier.py
```

Screenshot: it must show:

- LOOCV accuracy=0.571 | macro-F1=0.559  (n=35, 7 classes)

## List of screenshot files

| File | Step |
|------|------|
| `decoys_generated.png` | 1 |
| `honeypot_listening.png` | 2 |
| `manual_ssh_session_1.png` | 3 |
| `manual_ssh_session_2.png` | 3 |
| `playbooks_running_1.png` | 4 |
| `playbooks_running_2.png` | 4 |
| `analysis_summary.png` | 6 |
| `classifier.png` | 7 |

> With the same seed (25012), the numbers come out identical to the report. Only
> the classifier accuracy may differ slightly (0.57–0.60) because of the real
> execution time of the sessions.
