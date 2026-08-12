================================================================
 LLM-ENHANCED HONEYPOT AND ATTACKER INTERACTION ANALYTICS
 Καλαιτζιδης Ιωαννης - MTE25012
================================================================


1. ΤΙ ΕΙΝΑΙ 
-----------

Με απλα λογια: στηνουμε ενα "δολωμα" (honeypot) που μοιαζει με πραγματικο
διακομιστη Linux με SSH. Οταν καποιος συνδεθει και αρχισει να ψαχνει, βρισκει
ρεαλιστικα (αλλα ΨΕΥΤΙΚΑ) αρχεια: κωδικους, configs, logs, σημειωσεις admin.
Το honeypot καταγραφει ΤΑ ΠΑΝΤΑ (ποιες εντολες εδωσε, ποια ψευτικα αρχεια
διαβασε, ποση ωρα εμεινε). Μετα, με τεχνικες μηχανικης μαθησης, αναλυουμε τη
συμπεριφορα των "επιτιθεμενων" και ομαδοποιουμε τις συνεδριες τους.

Επτα (7) απο τα δολωματα δημιουργηθηκαν με LLM (το μοντελο Claude), ωστε να
ειναι πιο ρεαλιστικα και εσωτερικα συνεπη.

ΟΛΑ τρεχουν ΤΟΠΙΚΑ (127.0.0.1). Δεν εκτιθεται
τιποτα στο διαδικτυο και δεν υπαρχει κανενα πραγματικο μυστικο.


2. ΒΑΣΙΚΕΣ ΕΝΝΟΙΕΣ (με απλα λογια)
----------------------------------

- HONEYPOT: ενα ψευτικο συστημα-παγιδα που δεν εχει καμια πραγματικη αξια.
  Οποιος το πειραζει, ειναι σχεδον σιγουρα κακοβουλος, οποτε καθε ενεργεια
  του ειναι πολυτιμη πληροφορια.

- DECOY ARTEFACT (δολωμα): ενα ψευτικο αρχειο (π.χ. ενα .env με "κωδικους")
  που μπαινει σκοπιμα για να δελεασει και να μελετησει τον επιτιθεμενο.

- PLAYBOOK: ενα προκαθορισμενο σεναριο επιθεσης (π.χ. "αναζητηση κωδικων").
  Το χρησιμοποιουμε για να παραγουμε ρεαλιστικη κινηση προς το honeypot.

- CLUSTERING: ομαδοποιηση των συνεδριων με βαση τη συμπεριφορα τους, ΧΩΡΙΣ
  να ξερουμε εκ των προτερων τις ετικετες (unsupervised).


3. ΔΟΜΗ ΤΟΥ ΦΑΚΕΛΟΥ
------------------------------------------------

LLM_MTE25012/
├── 00_config.py               # Κοινο system profile (ονοματα, εκδοσεις, IPs, ημ/νιες)
├── 01_generate_decoys.py      # [Task 2] Παραγει τα 12 decoys (7 LLM, 5 manual)
├── 02_ssh_honeypot.py         # [Task 1,3] Το honeypot SSH + καταγραφη
├── 03_run_playbooks.py        # [Task 4] Τα 7 playbooks -> 35 sessions
├── 04_analyze_sessions.py     # [Task 5,6] Αναλυση, clustering, figures
├── 05_intent_classifier.py    # [Προαιρετικο] Supervised intent classifier
├── run_all.py                 # Τρεχει ολη την αλυσιδα (Windows + Linux)
├── run_all.sh                 # Wrapper για Linux/Kali
│
├── README.txt                 # Αυτο το αρχειο
├── SCHEMA.md                  # Το σχημα των session logs
├── requirements.txt           # Εξαρτησεις Python
│
├── llm_prompts/               # Τα prompts που παρηγαγαν τα LLM decoys (τεκμηριωση)
├── decoys/
│   ├── fs/                    # Το εικονικο συστημα αρχειων που "σερβιρει" το honeypot
│   └── artifact_inventory.json# Ο καταλογος ολων των decoys (Task 2)
├── logs/
│   ├── sessions/              # Ενα JSON ανα session
│   └── sessions.jsonl         # Master log (μια γραμμη ανα session)
├── playbook_results/
│   ├── ground_truth.json      # Το πραγματικο intent καθε session (για αξιολογηση)
│   └── playbook_catalogue... 
├── analysis/                  # CSV/JSON αποτελεσματα αναλυσης
├── figures/                   # Ολα τα γραφηματα (PNG)
├── screenshots/               # Στιγμιοτυπα εκτελεσης
└── Report_MTE25012_LLM.docx


4. ΑΠΑΙΤΗΣΕΙΣ
------------------------------------------------

- Python 3.10 η νεοτερη (δοκιμασμενο σε 3.10 και 3.12)
- Λειτουργει σε Linux (Kali) και Windows
- Εγκατασταση εξαρτησεων:

    python3 -m venv venv
    source venv/bin/activate        # Windows: venv\Scripts\activate
    pip install -r requirements.txt


5. ΠΩΣ ΝΑ ΤΟ ΤΡΕΞΕΤΕ (ο ευκολος τροπος)
------------------------------------------------

Μια εντολη τα κανει ολα (decoys -> honeypot -> playbooks -> αναλυση):

    python3 run_all.py

    (ή σε Linux/Kali:  bash run_all.sh)

Οταν τελειωσει, δειτε τα αποτελεσματα στους φακελους analysis/ και figures/.


6. ΠΩΣ ΝΑ ΤΟ ΤΡΕΞΕΤΕ (χειροκινητα, βημα-βημα)
------------------------------------------------

    # 1. Δημιουργια των decoys
    python3 01_generate_decoys.py

    # 2. Εκκινηση honeypot (σε ενα terminal, μενει ανοιχτο)
    python3 02_ssh_honeypot.py --port 2222

    # 3. Σε ΑΛΛΟ terminal: εκτελεση των playbooks
    python3 03_run_playbooks.py --port 2222

    # 4. Σταματηστε το honeypot (Ctrl+C στο πρωτο terminal)

    # 5. Αναλυση + γραφηματα
    python3 04_analyze_sessions.py

    # 6. Προαιρετικος classifier
    python3 05_intent_classifier.py

Μπορειτε επισης να συνδεθειτε ΧΕΙΡΟΚΙΝΗΤΑ για δοκιμη:

    ssh -p 2222 root@127.0.0.1        # password: Corp2026!
    (δοκιμαστε: ls, cat /opt/app/.env, cat /root/NOTES_infra.md, exit)


7. ΤΙ ΚΑΝΕΙ ΤΟ ΚΑΘΕ TASK (και ποιο αρχειο)
------------------------------------------------

Task 1 - Σχεδιαση honeypot:        02_ssh_honeypot.py, 00_config.py
Task 2 - Decoy artefacts:          01_generate_decoys.py, decoys/, llm_prompts/
Task 3 - Καταγραφη (logging):      02_ssh_honeypot.py, logs/, SCHEMA.md
Task 4 - Attacker playbooks:       03_run_playbooks.py, playbook_results/
Task 5 - Αναλυση συμπεριφορας:     04_analyze_sessions.py, analysis/, figures/
Task 6 - Realism & fingerprinting: 04_analyze_sessions.py (analysis_report.json)
Task 7 - Ethics & ασφαλεια:        βλ. αναφορα (Report ... .docx)

Προαιρετικα:
- Intent classifier (ML):          05_intent_classifier.py
- Manual vs LLM decoys:            04_analyze_sessions.py (fig5)


8. ΤΕΚΜΗΡΙΩΣΗ
------------------------------------------------

- Report_MTE25012_LLM.docx : η πληρης αναφορα (ολα τα Tasks)
- SCHEMA.md                         : το σχημα των session logs
- decoys/artifact_inventory.json    : ο καταλογος των decoys
- llm_prompts/                      : πως παρηχθησαν τα LLM decoys

