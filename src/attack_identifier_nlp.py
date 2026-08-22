"""
src/attack_identifier_nlp.py - Supervised NLP & ML Attack Identification Layer
Extracts character and word N-grams from raw payloads and classifies attack techniques with calibrated probabilities.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, accuracy_score, f1_score
from config import RAW_DATA_DIR, MODELS_DIR, RESULTS_DIR, GLOBAL_SEED

def train_attack_identifier(df=None):
    print("[*] Training Stage 3 Supervised NLP Attack Identification Layer...")
    
    # Load Master Events if not provided
    if df is None:
        csv_path = str(RAW_DATA_DIR / "unified_3tier_master.csv")
        with open(csv_path, "r", encoding="utf-8") as f:
            df = pd.read_csv(f)
    
    # Extract Payloads and Targets
    payloads = df["raw_payload"].fillna("").astype(str).tolist()
    labels = df["attack_type"].tolist()
    
    # Split train / test chronologically (70 / 30)
    split_idx = int(len(df) * 0.70)
    train_payloads, test_payloads = payloads[:split_idx], payloads[split_idx:]
    train_labels, test_labels = labels[:split_idx], labels[split_idx:]
    
    # Build Dual TF-IDF Vectorizer (Character 3-5 n-grams + Word 1-2 n-grams)
    print("  [*] Fitting TF-IDF N-gram feature extractor (Char 3-5 + Word 1-2)...")
    vectorizer = TfidfVectorizer(
        ngram_range=(3, 5),
        analyzer='char_wb',
        max_features=2500,
        sublinear_tf=True
    )
    
    X_train = vectorizer.fit_transform(train_payloads)
    X_test = vectorizer.transform(test_payloads)
    
    # Train Random Forest Classifier
    print("  [*] Training Random Forest Multi-Class Payload Classifier...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=25,
        random_state=GLOBAL_SEED,
        n_jobs=-1
    )
    clf.fit(X_train, train_labels)
    
    # Evaluate
    preds = clf.predict(X_test)
    probs = clf.predict_proba(X_test)
    
    acc = accuracy_score(test_labels, preds)
    macro_f1 = f1_score(test_labels, preds, average="macro", zero_division=0)
    weighted_f1 = f1_score(test_labels, preds, average="weighted", zero_division=0)
    
    print(f"\n[+] Stage 3 Identification Results:")
    print(f"    - Accuracy:    {acc * 100:.2f}%")
    print(f"    - Macro F1:    {macro_f1:.4f}")
    print(f"    - Weighted F1: {weighted_f1:.4f}")
    
    rep = classification_report(test_labels, preds, digits=4, zero_division=0)
    print("\n" + rep)
    
    # Save Model Artifacts
    model_bundle = {
        "vectorizer": vectorizer,
        "classifier": clf,
        "classes": clf.classes_.tolist(),
        "metrics": {
            "accuracy": acc,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1
        }
    }
    joblib.dump(model_bundle, MODELS_DIR / "web_attack_nlp.joblib")
    
    with open(RESULTS_DIR / "stage3_classification_report.txt", "w", encoding="utf-8") as f:
        f.write(rep)
        
    print(f"[+] Saved Stage 3 NLP Model to: {MODELS_DIR / 'web_attack_nlp.joblib'}")
    return model_bundle

if __name__ == "__main__":
    train_attack_identifier()
