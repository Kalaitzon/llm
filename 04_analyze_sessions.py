# ── Kalaitzidis Ioannis - MTE25012 ─────────────────────────────────────────────────────

"""
04_analyze_sessions.py  --  Αναλυση συμπεριφορας και ποιοτητας παραπλανησης
===========================================================================
[TASK 5] Αναλυση συμπεριφορας και προθεσης.
[TASK 6] Αξιολογηση ποιοτητας παραπλανησης και κινδυνου fingerprinting.

ΤΙ ΚΑΝΕΙ ΑΥΤΟ ΤΟ ΑΡΧΕΙΟ
-----------------------
Ειναι ο "αναλυτης". Διαβαζει τα ΠΡΑΓΜΑΤΙΚΑ session logs που παρηγαγε το
honeypot (logs/sessions.jsonl), μετατρεπει καθε συνεδρια σε αριθμητικα
χαρακτηριστικα (features), και εξαγει συμπερασματα για τη συμπεριφορα των
επιτιθεμενων μεσω Μηχανικης Μαθησης.

ΠΩΣ ΔΟΥΛΕΥΕΙ (τα βηματα)  --  Task 5
-----------------------------------
1. extract_features(): για καθε session υπολογιζει 8 χαρακτηριστικα. Πεντε
   μετρουν την ΕΝΤΑΣΗ της εμπλοκης (dwell time, πληθος εντολων, ποικιλια
   εντολων, artefacts touched, path depth) και τρια το ΕΙΔΟΣ της δραστηριοτητας
   ως αναλογιες (read_frac, recon_frac, privesc_frac).
2. do_clustering(): κανονικοποιει τα features και ομαδοποιει τα sessions με
   K-means (k=4) και DBSCAN (διαλεξη 3). Εφαρμοζει επισης Isolation Forest για
   να ξεχωρισει αυτοματα τα "βαθια/ανωμαλα" sessions απο τα ρηχα.
3. Οπτικοποιηση σε 2D με PCA και t-SNE (διαλεξη 3).
4. Συγκριση των ομαδων με το GROUND TRUTH (intent) μεσω του δεικτη ARI, ωστε
   να φανει ποσο η "τυφλη" ομαδοποιηση ανακαλυπτει τις πραγματικες ταχτικες.
5. make_summaries(): παραγει αντιπροσωπευτικες συνοψεις συνεδριων απο
   πραγματικα δεδομενα.

ΠΩΣ ΔΟΥΛΕΥΕΙ (τα βηματα)  --  Task 6
-----------------------------------
6. analyse_decoy_sources(): συγκρινει ποσο engagement τραβηξαν τα χειροκινητα
   εναντι των LLM-generated δολωματων (πραγματικα artefact touches), και
   συγκρινει με ενα minimal στατικο baseline χωρις δολωματα.
Τα σημεια fingerprinting (πως προδιδεται το honeypot) τεκμηριωνονται στην
αναφορα, με βαση τους περιορισμους που φαινονται εδω.

ΕΙΣΟΔΟΣ / ΕΞΟΔΟΣ
----------------
- Εισοδος: logs/sessions.jsonl (honeypot) και playbook_results/ground_truth.json.
- Εξοδος : ο φακελος analysis/ (session_features.csv, analysis_report.json,
  cluster_composition.json) και ο φακελος figures/ (γραφηματα PNG).

ΠΩΣ ΤΡΕΧΕΙ:  python3 04_analyze_sessions.py   (αφου εχουν παραχθει τα logs)
"""

import json
import importlib
from pathlib import Path
from collections import Counter

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans, DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from sklearn.metrics import adjusted_rand_score, silhouette_score

cfg = importlib.import_module("00_config")

BASE     = Path(__file__).resolve().parent
LOG_DIR  = BASE / "logs"
MASTER   = LOG_DIR / "sessions.jsonl"
PB_DIR   = BASE / "playbook_results"
OUT      = BASE / "analysis"
FIG      = BASE / "figures"
OUT.mkdir(exist_ok=True)
FIG.mkdir(exist_ok=True)

RNG = cfg.SEED

# Κατηγοριες εντολων. Χρησιμοποιουνται για να μετρησουμε ΤΙ ΕΙΔΟΥΣ δραστηριοτητα
# εκανε ο επιτιθεμενος (αναγνωριση συστηματος, αναγνωση αρχειων, αναβαθμιση
# προνομιων). Καθε εντολη κατατασσεται σε μια απο αυτες τις ομαδες.
RECON_VERBS   = {"whoami", "id", "uname", "hostname", "ps", "ss", "netstat", "env", "printenv", "ip", "ifconfig"}
READ_VERBS    = {"cat", "less", "more", "head", "tail", "grep"}
PRIVESC_TOKENS = ("sudo", "/etc/shadow", "/etc/sudoers", "-perm -4000", "/etc/passwd")


# ==========================================================================
#  1. Φορτωση δεδομενων (sessions + ground truth)
# ==========================================================================
def load_sessions():
    """Διαβαζει ολες τις συνεδριες απο το master αρχειο logs/sessions.jsonl.
    Καθε γραμμη ειναι μια συνεδρια σε μορφη JSON."""
    sessions = []
    with open(MASTER, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                sessions.append(json.loads(line))
    return sessions


def load_ground_truth():
    """Διαβαζει το ground truth (τη γνωστη αληθεια: ποιο playbook/intent
    παρηγαγε καθε συνεδρια). Επιστρεφει εναν χαρτη src_port -> στοιχεια
    συνεδριας, ωστε να μπορουμε να αντιστοιχισουμε καθε session log με το
    πραγματικο του intent μεσω της θυρας (src_port)."""
    gt = json.loads((PB_DIR / "ground_truth.json").read_text(encoding="utf-8"))
    by_port = {s["src_port"]: s for s in gt["sessions"]}
    return by_port, gt["catalogue"]


# ==========================================================================
#  2. Εξαγωγη χαρακτηριστικων (feature engineering) ανα συνεδρια
# ==========================================================================
def path_depth(path):
    """Υπολογιζει το "βαθος" μιας διαδρομης = ποσοι φακελοι βαθια ειναι.
    Π.χ. /opt/app/config -> βαθος 3. Δειχνει ποσο βαθια εξερευνησε ο χρηστης."""
    return path.strip("/").count("/") + 1 if path.strip("/") else 0


def extract_features(sess):
    """Μετατρεπει μια συνεδρια σε 8 αριθμητικα χαρακτηριστικα (features), τα
    οποια θα τροφοδοτησουν τα μοντελα Μηχανικης Μαθησης. Τα features χωριζονται
    σε δυο ομαδες: (α) ΕΝΤΑΣΗ εμπλοκης (ποσο βαθια), και (β) ΕΙΔΟΣ δραστηριοτητας
    (τι λογης εντολες), ωστε να ξεχωριζουμε οχι μονο ρηχες/βαθιες συνεδριες αλλα
    και το ειδος της ταχτικης."""
    cmds = sess["commands"]
    # Το "ρημα" καθε εντολης ειναι η πρωτη λεξη (π.χ. "cat", "grep", "whoami").
    verbs = [c.split()[0] for c in cmds if c.split()]
    unique_verbs = set(verbs)

    # path depth: το μεγιστο βαθος διαδρομης που εμφανιστηκε (ειτε στον τρεχοντα
    # καταλογο ειτε σε καποιο απολυτο μονοπατι μεσα σε εντολη). Δειχνει ποσο
    # βαθια στο συστημα αρχειων εφτασε ο επιτιθεμενος.
    depths = [0]
    for e in sess["events"]:
        depths.append(path_depth(e.get("cwd", "/")))
        for tok in e.get("input", "").split():
            if tok.startswith("/"):
                depths.append(path_depth(tok))

    # Μετραμε ποσες εντολες ανηκουν σε καθε κατηγορια.
    read_ops   = sum(1 for v in verbs if v in READ_VERBS)        # αναγνωση αρχειων
    recon_ops  = sum(1 for v in verbs if v in RECON_VERBS)       # αναγνωριση συστηματος
    privesc_ops = sum(1 for c in cmds if any(tok in c for tok in PRIVESC_TOKENS))  # αναβαθμιση

    n = max(len(cmds), 1)     # αποφυγη διαιρεσης με το μηδεν
    return {
        "session_id": sess["session_id"],
        "src_port": sess["src_port"],
        "auth_success": sess["auth"]["success"],
        # --- Χαρακτηριστικα ΕΝΤΑΣΗΣ (ΠΟΣΟ βαθια η εμπλοκη) ---
        "dwell_time": sess["duration_seconds"],                  # διαρκεια
        "command_count": len(cmds),                              # ποσες εντολες
        "cmd_diversity": round(len(unique_verbs) / n, 3),        # ποικιλια εντολων
        "artefacts_touched": len(sess["artefacts_touched"]),     # ποσα decoys διαβασε
        "path_depth": max(depths),                               # ποσο βαθια εφτασε
        # --- Χαρακτηριστικα ΕΙΔΟΥΣ (ΤΙ ΛΟΓΗΣ δραστηριοτητα), ως αναλογιες ---
        "read_frac": round(read_ops / n, 3),                     # ποσοστο αναγνωσης
        "recon_frac": round(recon_ops / n, 3),                   # ποσοστο αναγνωρισης
        "privesc_frac": round(privesc_ops / n, 3),               # ποσοστο αναβαθμισης
        # Ακατεργαστοι μετρητες (για τις συνοψεις/αναφορα, οχι για το clustering).
        "read_ops": read_ops,
        "recon_ops": recon_ops,
        "privesc_ops": privesc_ops,
        "_touched_list": sess["artefacts_touched"],              # η λιστα των decoys
    }


# Τα 8 χαρακτηριστικα που δινονται στα μοντελα. Ο συνδυασμος εντασης + ειδους
# βοηθα το clustering να ξεχωρισει και το ΕΙΔΟΣ της ταχτικης, οχι μονο το μεγεθος.
FEATURE_COLS = ["dwell_time", "command_count", "cmd_diversity",
                "artefacts_touched", "path_depth",
                "read_frac", "recon_frac", "privesc_frac"]


# ==========================================================================
#  3. Ομαδοποιηση (clustering) + ανιχνευση ανωμαλιων (Isolation Forest)
# ==========================================================================
def do_clustering(df):
    """Εφαρμοζει τρεις μεθοδους Μηχανικης Μαθησης πανω στα χαρακτηριστικα:
    (1) K-means: χωριζει τις συνεδριες σε 4 ομαδες (προφιλ συμπεριφορας).
    (2) DBSCAN: εναλλακτικη ομαδοποιηση με βαση την πυκνοτητα.
    (3) Isolation Forest: εντοπιζει τις "ανωμαλες" (βαθιες/στοχευμενες) συνεδριες.
    Πρωτα ομως τα features κανονικοποιουνται (StandardScaler), ωστε ολα να εχουν
    την ιδια βαρυτητα ανεξαρτητα απο τις μοναδες τους (π.χ. δευτερολεπτα vs πληθος)."""
    X = StandardScaler().fit_transform(df[FEATURE_COLS].values)

    # K-means με σταθερο k=4, που δινει τα πιο ερμηνευσιμα προφιλ (ρηχα probes,
    # μετρια εμπλοκη, βαθιοι αναγνωστες, βαθια αναγνωριση). Δοκιμη με silhouette
    # για k απο 3 εως 7 επιβεβαιωσε καλη ισορροπια διαχωρισμου/ερμηνευσιμοτητας.
    best_k = 4
    km = KMeans(n_clusters=best_k, random_state=RNG, n_init=10).fit(X)
    df["kmeans"] = km.labels_
    df.attrs["best_k"] = best_k
    best_sil = silhouette_score(X, km.labels_)     # ποιοτητα διαχωρισμου (0-1)

    # DBSCAN: ομαδοποιηση με βαση την πυκνοτητα (δεν χρειαζεται προκαθορισμενο k).
    db = DBSCAN(eps=1.6, min_samples=2).fit(X)
    df["dbscan"] = db.labels_

    # Isolation Forest: "απομονωνει" τα ασυνηθιστα σημεια. Οσο πιο ευκολα
    # απομονωνεται μια συνεδρια, τοσο πιο ανωμαλη (βαθια/στοχευμενη) ειναι.
    iso = IsolationForest(random_state=RNG, contamination=0.25).fit(X)
    df["iso_flag"] = (iso.predict(X) == -1)      # True = "ανωμαλο/βαθυ"
    df["iso_score"] = -iso.score_samples(X)      # μεγαλυτερο = πιο ανωμαλο

    return X, km, round(best_sil, 3), best_k


# ==========================================================================
#  4. Οπτικοποιησεις
# ==========================================================================
C1, C2, C3 = "#2b6cb0", "#c53030", "#2f855a"


def plot_depth_hist(df):
    """Σχημα 1: ιστογραμμα που δειχνει ποσες συνεδριες αγγιξαν 0, 1, 2, ...
    δολωματα. Αποκαλυπτει τη διασπορα του engagement (πολλες ρηχες με 0, λιγες
    βαθιες με πολλα)."""
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.hist(df["artefacts_touched"], bins=range(0, df["artefacts_touched"].max() + 2),
            color=C1, edgecolor="white", align="left")
    ax.set_xlabel("Artefacts touched ανά session")
    ax.set_ylabel("Πλήθος sessions")
    ax.set_title("Κατανομή engagement (πραγματικά artefact touches)")
    fig.tight_layout(); fig.savefig(FIG / "fig1_artefacts_touched.png", dpi=130); plt.close(fig)


def plot_pca(df, X):
    """Σχημα 2: προβολη PCA. Η PCA συμπυκνωνει τα 8 χαρακτηριστικα σε 2 αξονες
    ωστε να μπορουμε να δουμε τις συνεδριες σε ενα επιπεδο. Το χρωμα δειχνει την
    ομαδα K-means και η ετικετα το πραγματικο intent, ωστε να συγκρινουμε
    οπτικα αν οι ομαδες συμπιπτουν με τις πραγματικες ταχτικες."""
    pca = PCA(n_components=2, random_state=RNG).fit_transform(X)
    fig, ax = plt.subplots(figsize=(7, 5.5))
    sc = ax.scatter(pca[:, 0], pca[:, 1], c=df["kmeans"], cmap="tab10", s=90,
                    edgecolor="black", linewidth=0.5)
    for i, r in df.reset_index().iterrows():
        ax.annotate(r["intent"][:4], (pca[i, 0], pca[i, 1]), fontsize=7,
                    xytext=(4, 4), textcoords="offset points")
    ax.set_title("PCA των sessions (χρώμα = K-means cluster, ετικέτα = ground-truth intent)")
    ax.set_xlabel("PC1"); ax.set_ylabel("PC2")
    fig.tight_layout(); fig.savefig(FIG / "fig2_pca_clusters.png", dpi=130); plt.close(fig)


def plot_tsne(df, X):
    """Σχημα (συμπληρωματικο): προβολη t-SNE, μια εναλλακτικη μεθοδος
    οπτικοποιησης 2D. Το perplexity προσαρμοζεται στο μικρο δειγμα."""
    n = len(df)
    perp = max(2, min(5, n - 1))
    ts = TSNE(n_components=2, perplexity=perp, random_state=RNG, init="pca").fit_transform(X)
    fig, ax = plt.subplots(figsize=(7, 5.5))
    ax.scatter(ts[:, 0], ts[:, 1], c=df["kmeans"], cmap="tab10", s=90,
               edgecolor="black", linewidth=0.5)
    for i, r in df.reset_index().iterrows():
        ax.annotate(r["intent"][:4], (ts[i, 0], ts[i, 1]), fontsize=7,
                    xytext=(4, 4), textcoords="offset points")
    ax.set_title(f"t-SNE των sessions (perplexity={perp})")
    fig.tight_layout(); fig.savefig(FIG / "fig3_tsne_clusters.png", dpi=130); plt.close(fig)


def plot_iso(df):
    """Σχημα 3: ραβδογραμμα με τον βαθμο ανωμαλιας (Isolation Forest) καθε
    συνεδριας, ταξινομημενο. Οι κοκκινες ραβδοι ειναι οι συνεδριες που
    σημειωθηκαν ως βαθιες/ανωμαλες (αυτες που θα εξεταζε πρωτος ενας αναλυτης)."""
    d = df.sort_values("iso_score")
    fig, ax = plt.subplots(figsize=(8, 4.5))
    colors = [C2 if f else C1 for f in d["iso_flag"]]      # κοκκινο αν ανωμαλο
    ax.bar(range(len(d)), d["iso_score"], color=colors, edgecolor="white")
    ax.set_xticks(range(len(d)))
    ax.set_xticklabels(d["intent"].str[:6], rotation=60, ha="right", fontsize=7)
    ax.set_ylabel("Isolation Forest anomaly score")
    ax.set_title("Ξεχώρισμα βαθιών/στοχευμένων sessions (κόκκινο = flagged ως ανώμαλο)")
    fig.tight_layout(); fig.savefig(FIG / "fig4_isolation_forest.png", dpi=130); plt.close(fig)


def plot_llm_vs_manual(touch_by_source):
    """Σχημα 4: συγκριση engagement (συνολικα artefact touches) αναμεσα στα
    χειροκινητα και τα LLM-generated δολωματα. Απανταει στο ερωτημα του Task 6:
    αποδιδουν καλυτερα τα δολωματα που παρηχθησαν με LLM;"""
    fig, ax = plt.subplots(figsize=(6.5, 4))
    srcs = ["manual", "llm"]
    vals = [touch_by_source.get(s, 0) for s in srcs]
    ax.bar(srcs, vals, color=[C3, C1], edgecolor="white")
    for i, v in enumerate(vals):
        ax.text(i, v + 0.1, str(v), ha="center", fontsize=11)
    ax.set_ylabel("Συνολικά artefact touches")
    ax.set_title("Engagement ανά πηγή decoy (manual vs LLM-generated)")
    fig.tight_layout(); fig.savefig(FIG / "fig5_llm_vs_manual.png", dpi=130); plt.close(fig)


# ==========================================================================
#  5. Ενδεικτικες συνοψεις συνεδριων (απο πραγματικα δεδομενα)
# ==========================================================================
def make_summaries(df, sessions_by_port, top=4):
    """Παραγει συνοψεις για τις πιο ενδιαφερουσες (πιο ανωμαλες) συνεδριες, σε
    φυσικη γλωσσα. Καθε συνοψη περιγραφει το intent, ποσες εντολες, ποσα
    δολωματα αγγιχτηκαν κ.λπ., βασισμενη αποκλειστικα σε πραγματικα δεδομενα."""
    d = df.sort_values("iso_score", ascending=False).head(top)   # οι πιο ανωμαλες
    out = []
    for _, r in d.iterrows():
        touched = r["_touched_list"]
        out.append({
            "session_id": r["session_id"],
            "ground_truth_intent": r["intent"],
            "depth": r["depth"],
            "dwell_time": r["dwell_time"],
            "commands": r["command_count"],
            "artefacts_touched": touched,
            "narrative": (
                f"Session με προθεση '{r['intent']}' ({r['depth']}). Εκτελεσε "
                f"{r['command_count']} εντολες σε {r['dwell_time']}s, με path depth "
                f"{r['path_depth']}. Αγγιξε {len(touched)} decoys"
                + (f": {', '.join(touched)}." if touched else ".")
                + (f" Παρουσιασε {r['privesc_ops']} ενεργειες αναβαθμισης προνομιων."
                   if r["privesc_ops"] else "")
            ),
        })
    return out


# ==========================================================================
#  6. Συγκριση πηγων δολωματων (Task 6): χειροκινητα vs LLM
# ==========================================================================
def analyse_decoy_sources(df):
    """Μετραει ποσα αγγιγματα (touches) δεχτηκε καθε δολωμα, ομαδοποιωντας τα
    (α) κατα πηγη (χειροκινητο vs LLM), (β) κατα κατηγορια (ssh, credentials,
    κ.λπ.), και (γ) ανα μεμονωμενο αρχειο. Χρησιμοποιει τον καταλογο των decoys
    (artifact_inventory.json) για να ξερει την πηγη/κατηγορια καθε αρχειου."""
    inv = json.loads((BASE / "decoys" / "artifact_inventory.json").read_text(encoding="utf-8"))
    src_of = {a["virtual_path"]: a["source"] for a in inv["artifacts"]}      # πηγη
    cat_of = {a["virtual_path"]: a["category"] for a in inv["artifacts"]}    # κατηγορια

    touch_by_source = Counter()
    touch_by_cat = Counter()
    touch_by_artifact = Counter()
    for _, r in df.iterrows():
        for a in r["_touched_list"]:
            touch_by_source[src_of.get(a, "unknown")] += 1
            touch_by_cat[cat_of.get(a, "unknown")] += 1
            touch_by_artifact[a] += 1
    return touch_by_source, touch_by_cat, touch_by_artifact


def main():
    """Η κυρια ροη της αναλυσης, βημα προς βημα:
    1. Φορτωση των συνεδριων και του ground truth.
    2. Ξεχωρισμα των συνεδριων με εντολες απο τις αποτυχημενες συνδεσεις.
    3. Εξαγωγη χαρακτηριστικων και ενωση με το ground truth (intent).
    4. Clustering + Isolation Forest.
    5. Συγκριση χειροκινητων vs LLM δολωματων (Task 6).
    6. Παραγωγη γραφηματων και συνοψεων.
    7. Αποθηκευση ολων των αποτελεσματων σε analysis/."""
    print("[*] Φορτωση sessions...")
    sessions = load_sessions()
    by_port, catalogue = load_ground_truth()

    # Ξεχωριζουμε τις συνεδριες ΜΕ εντολες (τα playbooks) απο τις αποτυχημενες
    # συνδεσεις (failed-auth probes, 0 εντολες). Η αναλυση συμπεριφορας αφορα
    # μονο τις πρωτες.
    cmd_sessions = [s for s in sessions if s["command_count"] > 0]
    auth_probes  = [s for s in sessions if s["command_count"] == 0]
    print(f"[+] {len(sessions)} logs: {len(cmd_sessions)} command-sessions, "
          f"{len(auth_probes)} failed-auth probes")

    # Μετατρεπουμε καθε συνεδρια σε γραμμη χαρακτηριστικων (feature vector).
    rows = [extract_features(s) for s in cmd_sessions]
    df = pd.DataFrame(rows)

    # Προσθετουμε το ΠΡΑΓΜΑΤΙΚΟ intent καθε συνεδριας απο το ground truth,
    # αντιστοιχιζοντας μεσω της θυρας (src_port). Χρησιμευει ΜΟΝΟ για την
    # αξιολογηση στο τελος (το clustering εγινε "στα τυφλα").
    df["intent"] = df["src_port"].map(lambda p: by_port.get(p, {}).get("intent", "unknown"))
    df["depth"]  = df["src_port"].map(lambda p: by_port.get(p, {}).get("depth", "?"))

    # --- Clustering + Isolation Forest ---
    X, km, sil, best_k = do_clustering(df)
    # ARI: μετραει ποσο οι ομαδες K-means συμπιπτουν με τα πραγματικα intents.
    ari = adjusted_rand_score(df["intent"], df["kmeans"])
    print(f"[+] K-means k={best_k} silhouette={sil} | cluster-vs-intent ARI={ari:.3f}")

    # --- Συγκριση χειροκινητων vs LLM δολωματων (Task 6) ---
    touch_by_source, touch_by_cat, touch_by_artifact = analyse_decoy_sources(df)

    # --- Παραγωγη ολων των γραφηματων ---
    plot_depth_hist(df)
    plot_pca(df, X)
    plot_tsne(df, X)
    plot_iso(df)
    plot_llm_vs_manual(touch_by_source)
    print(f"[+] Figures -> {FIG}/")

    # --- Ενδεικτικες συνοψεις συνεδριων ---
    summaries = make_summaries(df, by_port)

    # --- Baseline: συγκριση με minimal περιβαλλον χωρις decoys ---
    # Σε ενα minimal περιβαλλον χωρις decoys, ολα τα cat/grep θα επεστρεφαν κενο,
    # αρα artefacts_touched=0 παντου. Η συγκριση δειχνει ποση επιπλεον εμπλοκη
    # προκαλεσαν τα decoys.
    baseline_note = {
        "with_decoys_avg_touched": round(df["artefacts_touched"].mean(), 2),
        "with_decoys_max_touched": int(df["artefacts_touched"].max()),
        "minimal_static_avg_touched": 0.0,
        "interpretation": (
            "Σε ενα minimal στατικο περιβαλλον χωρις decoys, καμια εντολη "
            "αναγνωσης δεν θα επεστρεφε περιεχομενο, οποτε το artefacts_touched "
            "θα ηταν 0 σε ολα τα sessions. Τα decoys προκαλεσαν βαθυτερη εμπλοκη "
            "(εως 6 artefacts σε ενα session)."
        ),
    }

    # --- Αποθηκευση: το CSV με τα χαρακτηριστικα (χρησιμοποιειται και απο το 05) ---
    df_out = df.drop(columns=["_touched_list"]).copy()
    df_out.to_csv(OUT / "session_features.csv", index=False)

    report = {
        "counts": {
            "total_logs": len(sessions),
            "command_sessions": len(cmd_sessions),
            "failed_auth_probes": len(auth_probes),
        },
        "behavioural_means": {
            "dwell_time": round(df["dwell_time"].mean(), 2),
            "command_count": round(df["command_count"].mean(), 2),
            "cmd_diversity": round(df["cmd_diversity"].mean(), 2),
            "artefacts_touched": round(df["artefacts_touched"].mean(), 2),
            "path_depth": round(df["path_depth"].mean(), 2),
        },
        "clustering": {
            "kmeans_k": int(best_k), "silhouette": sil,
            "cluster_vs_intent_ARI": round(ari, 3),
            "iso_flagged_deep": int(df["iso_flag"].sum()),
            "ari_interpretation": (
                "Το ARI μετρα ποσο τα unsupervised clusters συμπιπτουν με τα 7 "
                "intents. Χαμηλες τιμες σημαινουν οτι το clustering ομαδοποιει "
                "κυριως κατα ΒΑΘΟΣ/ΠΡΟΦΙΛ εμπλοκης (ρηχα probes, deep readers, "
                "privesc) και οχι κατα semantic intent - αναμενομενο, αφου τα "
                "features μετρανε συμπεριφορα. Η προβλεψη intent αντιμετωπιζεται "
                "με supervised μοντελο στο 05_intent_classifier.py."
            ),
        },
        "decoy_engagement": {
            "touches_by_source": dict(touch_by_source),
            "touches_by_category": dict(touch_by_cat),
            "top_artefacts": touch_by_artifact.most_common(6),
        },
        "static_vs_decoy_baseline": baseline_note,
        "session_summaries": summaries,
    }
    (OUT / "analysis_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    # Cluster composition (ποια intents μπηκαν σε ποιο cluster).
    # Χτιζεται ρητα με loop για να αποφευχθουν tuple keys (MultiIndex).
    comp = {}
    for k, sub in df.groupby("kmeans"):
        comp[f"cluster_{int(k)}"] = {
            "size": int(len(sub)),
            "intents": dict(Counter(sub["intent"])),
            "depths": dict(Counter(sub["depth"])),
            "avg_artefacts_touched": round(float(sub["artefacts_touched"].mean()), 2),
            "avg_command_count": round(float(sub["command_count"].mean()), 2),
        }
    (OUT / "cluster_composition.json").write_text(
        json.dumps(comp, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[+] Αναλυση -> {OUT}/analysis_report.json")
    print(f"[+] Features -> {OUT}/session_features.csv")
    print()
    print("=== ΣΥΝΟΨΗ ===")
    print(f"  Μεσο artefacts touched (με decoys): {report['behavioural_means']['artefacts_touched']} "
          f"(baseline χωρις decoys: 0)")
    print(f"  Touches manual vs LLM: {dict(touch_by_source)}")
    print(f"  Isolation Forest flagged ως βαθια: {int(df['iso_flag'].sum())}/{len(df)}")
    print(f"  Cluster-vs-intent ARI: {ari:.3f} (1.0 = τελεια συμφωνια)")


if __name__ == "__main__":
    main()
