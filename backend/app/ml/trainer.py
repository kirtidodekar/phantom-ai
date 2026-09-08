import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support

from .dataset_generator import generate_synthetic_dataset, rebalance_dataset, FEATURE_NAMES, ATTACK_LABELS

MODEL_DIR = os.path.join(os.path.dirname(__file__), "saved_models")

def train_and_evaluate_models(num_samples: int = 6000) -> Dict[str, Any]:
    """
    Trains RandomForestClassifier (Known attacks) & IsolationForest (Zero-day / Anomaly detection),
    saves them to disk, and computes full validation metrics.

    Operates on the 12-feature / 9-class feature space defined in dataset_generator.
    """
    os.makedirs(MODEL_DIR, exist_ok=True)
    
    # 1. Generate dataset
    df = generate_synthetic_dataset(num_samples=num_samples, random_state=42)
    X = df[FEATURE_NAMES].values
    y = df["label"].values
    
    # Train test split before rebalancing to ensure honest evaluation
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    
    # Rebalance training split (SMOTE / Oversampling)
    X_train_res, y_train_res = rebalance_dataset(X_train, y_train)
    
    # 2. Train Random Forest Classifier
    rf_clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        class_weight="balanced",
        random_state=42
    )
    rf_clf.fit(X_train_res, y_train_res)
    
    # Evaluate RF on test set
    y_pred = rf_clf.predict(X_test)
    y_proba = rf_clf.predict_proba(X_test)
    
    # Explicit label list keeps the confusion matrix square (9x9) and aligned with
    # ATTACK_LABELS even if a class were ever missing from a test split.
    class_indices = list(range(len(ATTACK_LABELS)))

    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted")
    cm = confusion_matrix(y_test, y_pred, labels=class_indices).tolist()
    
    # Calculate False Positive Rate (FPR) for Benign (class 0)
    # FPR = FP / (FP + TN)
    cm_arr = np.array(cm)
    fp_benign = np.sum(cm_arr[:, 0]) - cm_arr[0, 0]
    tn_benign = np.sum(cm_arr[1:, 1:])
    fpr = float(fp_benign / (fp_benign + tn_benign + 1e-9))
    
    report_dict = classification_report(
        y_test, y_pred,
        labels=class_indices,
        target_names=[ATTACK_LABELS[i] for i in class_indices],
        output_dict=True,
        zero_division=0
    )
    
    # Feature importances
    importances = rf_clf.feature_importances_
    feat_importances_dict = {feat: float(imp) for feat, imp in zip(FEATURE_NAMES, importances)}
    
    # 3. Train Isolation Forest (trained on normal benign traffic)
    X_benign_train = X_train[y_train == 0]
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )
    iso_forest.fit(X_benign_train)
    
    # Save models
    rf_path = os.path.join(MODEL_DIR, "random_forest.joblib")
    iso_path = os.path.join(MODEL_DIR, "isolation_forest.joblib")
    joblib.dump(rf_clf, rf_path)
    joblib.dump(iso_forest, iso_path)
    
    metrics = {
        "dataset_name": "NSL-KDD / CIC-IDS2017 Feature Distribution",
        "num_classes": len(ATTACK_LABELS),
        "num_features": len(FEATURE_NAMES),
        "total_samples": len(df),
        "train_samples": len(X_train_res),
        "test_samples": len(X_test),
        "precision": float(round(prec, 4)),
        "recall": float(round(rec, 4)),
        "f1_score": float(round(f1, 4)),
        "false_positive_rate": float(round(fpr, 4)),
        "confusion_matrix": cm,
        "class_report": report_dict,
        "feature_importances": feat_importances_dict
    }
    
    return metrics

if __name__ == "__main__":
    res = train_and_evaluate_models()
    print("Models trained successfully!")
    print(f"Precision: {res['precision']}, Recall: {res['recall']}, F1: {res['f1_score']}, FPR: {res['false_positive_rate']}")
