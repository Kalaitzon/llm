# -*- coding: utf-8 -*-
"""
05_intent_classifier.py  --  Supervised intent classifier
==========================================================
[OPTIONAL TASK] Predicting the intent of a session with supervised learning.

WHAT THIS FILE DOES
-------------------
It answers the question left open by Task 5. There, the unsupervised clustering
grouped the sessions by behavioural PROFILE (depth of engagement) and not by
exact intent (low ARI). Here we show the complement: with SUPERVISED learning,
the same behavioural features ARE ENOUGH to predict the intent of a session,
once we have training labels (the ground truth).

HOW IT WORKS
------------
A Random Forest model is used (lecture 3), which learns to map the features of
a session to its intent. Because the dataset is small (35 sessions, 7 classes),
the evaluation is done with Leave-One-Out Cross-Validation (LOOCV): each session
is predicted by a model trained on the other 34, so that no prediction is made
on data the model has already seen. The results are indicative because of the
small sample, which is stated explicitly.

INPUT / OUTPUT
--------------
- Input : analysis/session_features.csv (produced by 04, with the features and
  the intent of each session).
- Output: analysis/intent_classifier.json (metrics, feature importance) and the
  plots figures/fig6_confusion_matrix.png and fig7_feature_importance.png.

HOW TO RUN:  python3 05_intent_classifier.py   (after 04 has run)
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
    # 04 has already produced the session features with ground-truth intent.
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

    # --- Feature importance (on a model trained on all the data) ---
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

    # --- Save ---
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
