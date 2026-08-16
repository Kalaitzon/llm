# LLM-Enhanced Honeypot and Attacker Interaction Analytics

MSc assignment — University of Piraeus, MSc programme "Advanced Topics in
Cybersecurity and Artificial Intelligence", 2026.
Student: Ioannis Kalaitzidis (MTE25012).

A reproducible SSH honeypot enriched with LLM-generated decoy artefacts, driven
by scripted attacker playbooks and analysed with unsupervised and supervised
machine learning. The guiding principle is **honest, data-driven analysis**:
because the honeypot actually serves the decoys over a real SSH shell, every
metric (e.g. which artefacts an attacker read) comes from real logged events,
not from guesses.

## What it does

The system is a chain of small, single-purpose Python scripts:

| Script | Task | Role |
|--------|------|------|
| `00_config.py` | — | Shared system profile (single source of truth) |
| `01_generate_decoys.py` | 2 | Generates 12 decoy artefacts (7 via the Claude LLM, 5 manual) |
| `02_ssh_honeypot.py` | 1, 3 | Real SSH honeypot (paramiko) + shell emulator + structured logging |
| `03_run_playbooks.py` | 4 | Runs 7 attacker playbooks × depth variants = 35 sessions |
| `04_analyze_sessions.py` | 5, 6 | Feature extraction, K-means / DBSCAN / Isolation Forest, PCA / t-SNE, manual-vs-LLM |
| `05_intent_classifier.py` | optional | Supervised intent classifier (Random Forest, LOOCV) |
| `run_all.py` | — | Orchestrates the whole chain (Windows + Linux/Kali) |

## Requirements

- Python 3.10+ (tested on 3.10 and 3.12)
- Dependencies in `requirements.txt`: `paramiko`, `scikit-learn`, `numpy`,
  `pandas`, `matplotlib`

```bash
pip install -r requirements.txt
```

## How to run

The simplest way is the orchestrator, which starts the honeypot in the
background, runs the playbooks against it, stops it, then analyses:

```bash
python run_all.py
```

To run the steps manually you need **two terminals**, because the honeypot must
be listening while the playbooks run:

```bash
# terminal A — start the honeypot (leave it running)
python 02_ssh_honeypot.py --port 2222

# terminal B — generate decoys, run playbooks, analyse
python 01_generate_decoys.py
python 03_run_playbooks.py --port 2222
# then stop the honeypot (Ctrl+C in terminal A) and:
python 04_analyze_sessions.py
python 05_intent_classifier.py
```

You can also connect manually to see the honeypot serve the decoys:

```bash
ssh -p 2222 root@127.0.0.1        # password: Corp2026!
```

> Note: on Windows use `python`; on Kali use `python3`. Before a final
> analysis run, clear old logs (`logs/sessions/` and `logs/sessions.jsonl`)
> so that only the 35 playbook sessions are analysed.

## Output

- `decoys/fs/` — the virtual filesystem the honeypot serves (the 12 decoys)
- `logs/` — per-session JSON files and the master `sessions.jsonl`
- `analysis/` — extracted features and analysis results (CSV / JSON)
- `figures/` — generated plots (used in the report)
- `llm_prompts/` — the exact prompts used to generate the LLM decoys
- `playbook_results/` — the ground-truth intent of each session

## Reproducibility

A fixed random seed (25012) keeps the results stable across runs. Because
`dwell_time` is measured from the wall-clock time of a live SSH session, the
intent-classifier accuracy may vary slightly (≈0.57–0.60) between runs; all
other quantities remain constant.

## Safety and ethics

Everything is fictional and runs in isolation. The honeypot listens only on
loopback (`127.0.0.1`), no real credentials or secrets exist, all addresses are
in private / documentation ranges (RFC 1918 and RFC 5737), and full credentials
are never stored in the logs (only a short sample).
