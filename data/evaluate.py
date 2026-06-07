import csv
import json
import os
import sys
import time
import requests
import random
from datetime import datetime

# CONFIG
API_URL = "https://phishguard-production-93c3.up.railway.app/analyse"
CEAS_PATH = r"C:\Users\HP\Downloads\archive (4)\CEAS_08.csv"
ENRON_PATH = r"C:\Users\HP\Downloads\archive (4)\Enron.csv"
SAMPLE_SIZE = 100  # 100 from each dataset = 200 total
OUTPUT_FILE = "evaluation_results.json"

def load_ceas(path, n=50):
    """Load n phishing + n legit from CEAS_08"""
    phishing, legit = [], []
    with open(path, encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            label = str(row.get("label", "")).strip()
            entry = {
                "subject": row.get("subject", ""),
                "sender": row.get("sender", ""),
                "body": row.get("body", "")[:1000],
                "true_label": "PHISHING" if label == "1" else "LEGITIMATE",
                "source": "CEAS_08"
            }
            if label == "1" and len(phishing) < n:
                phishing.append(entry)
            elif label == "0" and len(legit) < n:
                legit.append(entry)
            if len(phishing) >= n and len(legit) >= n:
                break
    return phishing + legit

def load_enron(path, n=50):
    """Load n phishing + n legit from Enron"""
    phishing, legit = [], []
    with open(path, encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            label = str(row.get("label", "")).strip()
            entry = {
                "subject": row.get("subject", ""),
                "sender": "",
                "body": row.get("body", "")[:1000],
                "true_label": "PHISHING" if label == "1" else "LEGITIMATE",
                "source": "Enron"
            }
            if label == "1" and len(phishing) < n:
                phishing.append(entry)
            elif label == "0" and len(legit) < n:
                legit.append(entry)
            if len(phishing) >= n and len(legit) >= n:
                break
    return phishing + legit

def call_api(email: dict) -> str:
    email_text = f"""From: {email['sender']}
Subject: {email['subject']}

{email['body']}"""
    try:
        r = requests.post(
            API_URL,
            json={"email_text": email_text},
            timeout=30
        )
        data = r.json()
        if r.status_code == 403:
            # Rate limit hit — wait and retry
            time.sleep(10)
            return "UNKNOWN"
        return data.get("verdict", "UNKNOWN").upper()
    except Exception as e:
        print(f"  API error: {e}")
        return "UNKNOWN"

def calculate_metrics(results):
    tp = sum(1 for r in results if r["true"] == "PHISHING" and r["predicted"] == "PHISHING")
    tn = sum(1 for r in results if r["true"] == "LEGITIMATE" and r["predicted"] == "LEGITIMATE")
    fp = sum(1 for r in results if r["true"] == "LEGITIMATE" and r["predicted"] == "PHISHING")
    fn = sum(1 for r in results if r["true"] == "PHISHING" and r["predicted"] == "LEGITIMATE")

    total = len(results)
    accuracy  = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    return {
        "total": total,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy":  round(accuracy * 100, 2),
        "precision": round(precision * 100, 2),
        "recall":    round(recall * 100, 2),
        "f1_score":  round(f1 * 100, 2)
    }

def main():
    print("Loading datasets...")
    ceas_emails  = load_ceas(CEAS_PATH, n=50)
    enron_emails = load_enron(ENRON_PATH, n=50)
    all_emails   = ceas_emails + enron_emails
    random.shuffle(all_emails)

    print(f"Loaded {len(all_emails)} emails ({len(ceas_emails)} CEAS + {len(enron_emails)} Enron)")
    print(f"Phishing: {sum(1 for e in all_emails if e['true_label'] == 'PHISHING')}")
    print(f"Legit:    {sum(1 for e in all_emails if e['true_label'] == 'LEGITIMATE')}")
    print(f"\nStarting evaluation (this will take ~5-8 minutes)...\n")

    results = []
    for i, email in enumerate(all_emails):
        predicted = call_api(email)
        correct = "✓" if predicted == email["true_label"] else "✗"
        print(f"[{i+1:3d}/{len(all_emails)}] {correct} True: {email['true_label']:10s} | Predicted: {predicted:10s} | {email['source']} | {email['subject'][:40]}")

        results.append({
            "index": i + 1,
            "source": email["source"],
            "subject": email["subject"][:60],
            "true": email["true_label"],
            "predicted": predicted,
            "correct": predicted == email["true_label"]
        })

        # Be nice to the API — 1 request per second
        time.sleep(1)

    print("\n" + "="*60)
    print("EVALUATION RESULTS")
    print("="*60)

    # Overall metrics
    metrics = calculate_metrics(results)
    print(f"\nOverall ({metrics['total']} emails):")
    print(f"  Accuracy:  {metrics['accuracy']}%")
    print(f"  Precision: {metrics['precision']}%")
    print(f"  Recall:    {metrics['recall']}%")
    print(f"  F1 Score:  {metrics['f1_score']}%")
    print(f"  TP: {metrics['tp']}  TN: {metrics['tn']}  FP: {metrics['fp']}  FN: {metrics['fn']}")

    # Per-dataset metrics
    for source in ["CEAS_08", "Enron"]:
        subset = [r for r in results if r["source"] == source]
        m = calculate_metrics(subset)
        print(f"\n{source} ({m['total']} emails):")
        print(f"  Accuracy: {m['accuracy']}%  Precision: {m['precision']}%  Recall: {m['recall']}%  F1: {m['f1_score']}%")

    # Save results
    output = {
        "timestamp": datetime.now().isoformat(),
        "overall_metrics": metrics,
        "per_dataset": {
            source: calculate_metrics([r for r in results if r["source"] == source])
            for source in ["CEAS_08", "Enron"]
        },
        "results": results
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nFull results saved to {OUTPUT_FILE}")
    print("\nSave these numbers for your report!")

if __name__ == "__main__":
    main()
