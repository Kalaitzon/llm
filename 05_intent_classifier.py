# ── Kalaitzidis Ioannis - MTE25012 ─────────────────────────────────────────────────────

"""
05_intent_classifier.py  --  Supervised ταξινομητης προθεσης
=============================================================
[ΠΡΟΑΙΡΕΤΙΚΟ TASK] Προβλεψη του intent μιας συνεδριας με επιβλεπομενη μαθηση.

ΤΙ ΚΑΝΕΙ ΑΥΤΟ ΤΟ ΑΡΧΕΙΟ
-----------------------
Απανταει στο ερωτημα που αφησε ανοιχτο το Task 5. Εκει, το unsupervised
clustering ομαδοποιησε τα sessions κατα ΠΡΟΦΙΛ συμπεριφορας (βαθος εμπλοκης)
και οχι κατα ακριβες intent (χαμηλο ARI). Εδω δειχνουμε το συμπληρωματικο: με
ΕΠΙΒΛΕΠΟΜΕΝΗ μαθηση, τα ιδια behavioural features ΑΡΚΟΥΝ για να προβλεψουμε το
intent ενος session, οταν εχουμε ετικετες εκπαιδευσης (το ground truth).

ΠΩΣ ΔΟΥΛΕΥΕΙ
------------
Χρησιμοποιειται μοντελο Random Forest (διαλεξη 3), το οποιο μαθαινει να
αντιστοιχιζει τα χαρακτηριστικα μιας συνεδριας στο intent της. Επειδη το
συνολο δεδομενων ειναι μικρο (35 sessions, 7 κλασεις), η αξιολογηση γινεται
με Leave-One-Out Cross-Validation (LOOCV): καθε session προβλεπεται απο ενα
μοντελο εκπαιδευμενο στα υπολοιπα 34, ωστε καμια προβλεψη να μη γινεται πανω
σε δεδομενα που το μοντελο εχει ηδη δει. Τα αποτελεσματα ειναι ενδεικτικα
λογω του μικρου δειγματος, κατι που δηλωνεται ρητα.

ΕΙΣΟΔΟΣ / ΕΞΟΔΟΣ
----------------
- Εισοδος: analysis/session_features.csv (το παραγει το 04, με τα features
  και το intent καθε session).
- Εξοδος : analysis/intent_classifier.json (μετρικες, feature importance) και
  τα γραφηματα figures/fig6_confusion_matrix.png και fig7_feature_importance.png.

ΠΩΣ ΤΡΕΧΕΙ:  python3 05_intent_classifier.py   (αφου εχει τρεξει το 04)
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

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import LeaveOneOut
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix

cfg = importlib.import_module("00_config")

BASE = Path(__file__).resolve().parent
OUT  = BASE / "analysis"
FIG  = BASE / "figures"
RNG  = cfg.SEED

FEATURE_COLS = ["dwell_time", "command_count", "cmd_diversity",
                "artefacts_touched", "path_depth",
                "read_frac", "recon_frac", "privesc_frac"]


def main():
    # Το 04 εχει ηδη παραξει τα session features με ground-truth intent.
    df = pd.read_csv(OUT / "session_features.csv")

    X = df[FEATURE_COLS].values
    y = df["intent"].values
    classes = sorted(set(y))

    # --- Leave-One-Out Cross-Validation ---
    loo = LeaveOneOut()
    y_true, y_pred = [], []
    for tr, te in loo.split(X):
        clf = RandomForestClassifier(n_estimators=300, random_state=RNG)
        clf.fit(X[tr], y[tr])
        y_true.append(y[te][0])
        y_pred.append(clf.predict(X[te])[0])

    acc = accuracy_score(y_true, y_pred)
    f1m = f1_score(y_true, y_pred, average="macro", zero_division=0)
    print(f"[+] LOOCV accuracy={acc:.3f} | macro-F1={f1m:.3f}  (n={len(y)}, {len(classes)} classes)")

    # --- Feature importance (σε μοντελο εκπαιδευμενο σε ολα τα δεδομενα) ---
    full = RandomForestClassifier(n_estimators=300, random_state=RNG).fit(X, y)
    importances = sorted(zip(FEATURE_COLS, full.feature_importances_),
                         key=lambda t: t[1], reverse=True)

    # --- Figures ---
    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred, labels=classes)
    fig, ax = plt.subplots(figsize=(7.5, 6.5))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(classes))); ax.set_yticks(range(len(classes)))
    ax.set_xticklabels([c[:12] for c in classes], rotation=45, ha="right", fontsize=8)
    ax.set_yticklabels([c[:12] for c in classes], fontsize=8)
    for i in range(len(classes)):
        for j in range(len(classes)):
            if cm[i, j]:
                ax.text(j, i, cm[i, j], ha="center", va="center",
                        color="white" if cm[i, j] > cm.max() / 2 else "black")
    ax.set_xlabel("Προβλεψη"); ax.set_ylabel("Πραγματικο (ground truth)")
    ax.set_title(f"Confusion matrix intent classifier (LOOCV, acc={acc:.2f})")
    fig.colorbar(im, fraction=0.046, pad=0.04)
    fig.tight_layout(); fig.savefig(FIG / "fig6_confusion_matrix.png", dpi=130); plt.close(fig)

    # Feature importance
    fig, ax = plt.subplots(figsize=(7, 4.5))
    names = [n for n, _ in importances][::-1]
    vals  = [v for _, v in importances][::-1]
    ax.barh(names, vals, color="#2b6cb0", edgecolor="white")
    ax.set_xlabel("Feature importance (Random Forest)")
    ax.set_title("Σημαντικότητα χαρακτηριστικών για την πρόβλεψη intent")
    fig.tight_layout(); fig.savefig(FIG / "fig7_feature_importance.png", dpi=130); plt.close(fig)

    # --- Αποθηκευση ---
    result = {
        "model": "RandomForestClassifier(n_estimators=300)",
        "evaluation": "LeaveOneOut cross-validation",
        "n_samples": int(len(y)),
        "n_classes": len(classes),
        "accuracy": round(acc, 3),
        "macro_f1": round(f1m, 3),
        "feature_importance": [{"feature": n, "importance": round(float(v), 3)}
                               for n, v in importances],
        "note": ("Μικρο δειγμα (35 sessions) - τα αποτελεσματα ειναι ενδεικτικα "
                 "και δειχνουν οτι τα behavioural features φερουν πληροφορια "
                 "intent, συμπληρωνοντας το unsupervised clustering του Task 5."),
    }
    (OUT / "intent_classifier.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[+] Top features: {', '.join(n for n, _ in importances[:3])}")
    print(f"[+] Αποτελεσματα -> {OUT / 'intent_classifier.json'}")
    print(f"[+] Figures -> fig6_confusion_matrix.png, fig7_feature_importance.png")


if __name__ == "__main__":
    main()