# backend/ml_worker.py – simple transformer classifier retraining
# This script is invoked by the backend (cron or manual API call).
# It loads raw OSINT entries from MongoDB, extracts text, creates embeddings
# using a pre‑trained transformer (distilbert‑base‑uncased), trains a lightweight
# LogisticRegression classifier, and saves the model back to disk for the API
# to use during search/annotation.

import os
import json
import torch
from transformers import AutoTokenizer, AutoModel
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
from pymongo import MongoClient

# ---------------------------------------------------------------------------
# Configuration (environment variables – supply your own values in .env)
# ---------------------------------------------------------------------------
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/intel")
MODEL_DIR = os.getenv("ML_MODEL_DIR", "backend/models")
MODEL_NAME = os.getenv("TRANSFORMER_MODEL", "distilbert-base-uncased")

# Ensure model directory exists
os.makedirs(MODEL_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Helper to get raw text entries from MongoDB
# ---------------------------------------------------------------------------
def load_entries():
    client = MongoClient(MONGO_URI)
    db = client.intel
    # Assume collection "entries" holds raw OSINT strings and a label field.
    # For demo we treat any entry containing the word "phish" as label 1, else 0.
    cursor = db.entries.find({}, {"raw": 1, "label": 1})
    texts = []
    labels = []
    for doc in cursor:
        txt = doc.get("raw", "")
        if not txt:
            continue
        texts.append(txt)
        labels.append(int(doc.get("label", 1 if "phish" in txt.lower() else 0)))
    client.close()
    return texts, labels

# ---------------------------------------------------------------------------
# Embedding extraction using the transformer model
# ---------------------------------------------------------------------------
def compute_embeddings(texts, tokenizer, model, batch_size=16):
    model.eval()
    embeddings = []
    with torch.no_grad():
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i+batch_size]
            enc = tokenizer(batch, padding=True, truncation=True, return_tensors="pt", max_length=128)
            outputs = model(**enc)
            # Use the CLS token representation as sentence embedding
            batch_emb = outputs.last_hidden_state[:, 0, :].cpu().numpy()
            embeddings.append(batch_emb)
    return np.concatenate(embeddings, axis=0)

# ---------------------------------------------------------------------------
# Main training routine
# ---------------------------------------------------------------------------
def main():
    try:
        texts, labels = load_entries()
        if len(texts) < 10:
            print("Not enough data for training – skipping.")
            return
        print(f"Loaded {len(texts)} entries for training.")

        tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        model = AutoModel.from_pretrained(MODEL_NAME)
        import numpy as np
        X = compute_embeddings(texts, tokenizer, model)
        y = np.array(labels)

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        clf = LogisticRegression(max_iter=200)
        clf.fit(X_train, y_train)
        preds = clf.predict(X_test)
        print(classification_report(y_test, preds))

        model_path = os.path.join(MODEL_DIR, "classifier.joblib")
        joblib.dump({"tokenizer": tokenizer, "model": model, "classifier": clf}, model_path)
        print(f"Model saved to {model_path}")
    except Exception as e:
        print(f"Training failed: {e}")
        raise

if __name__ == "__main__":
    main()
