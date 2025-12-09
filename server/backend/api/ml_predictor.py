import os
import joblib
import re
import numpy as np
import warnings
import urllib.parse

# Suppress warnings for cleaner logs
warnings.filterwarnings("ignore", category=UserWarning)

# ==========================================
# 1. DYNAMIC PATH CONFIGURATION
# ==========================================
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(CURRENT_DIR)
ML_MODEL_DIR = os.path.join(BACKEND_DIR, 'ml_model')

_nb_model = None
_vectorizer = None

def load_ml_resources():
    global _nb_model, _vectorizer
    if _nb_model is not None and _vectorizer is not None:
        return True

    if not os.path.exists(os.path.join(ML_MODEL_DIR, "naive_bayes_url_model.joblib")):
        return False

    try:
        model_path = os.path.join(ML_MODEL_DIR, "naive_bayes_url_model.joblib")
        vect_path = os.path.join(ML_MODEL_DIR, "tfidf_vectorizer.joblib")
        
        _nb_model = joblib.load(model_path)
        _vectorizer = joblib.load(vect_path)
        return True
    except Exception:
        return False

# ==========================================
# 2. PRE-PROCESSING
# ==========================================
def clean_url(url):
    if not url: return ""
    url = url.lower().strip()
    try:
        url = urllib.parse.unquote(url)
    except: pass
    url = re.sub(r'[%]+', '%', url)
    url = re.sub(r'[/]+', '/', url)
    url = re.sub(r'[.]+', '.', url)
    url = re.sub(r'[=]+', '=', url)
    url = re.sub(r'&+', '&', url)
    url = re.sub(r"[^a-z0-9:/?&.=_%\-<>;'\" ]", "", url)
    return url.strip()

# ==========================================
# 3. PREDICTION LOGIC (Query Only)
# ==========================================
def predict_ml_attack(query_str):
    """
    Input: Query string (2nd part of URL) ONLY.
    Output: (Label, Confidence, Evidence)
    """
    if _nb_model is None:
        if not load_ml_resources():
            return "Benign", 0.0, "ML Model Missing"

    try:
        # 1. Preprocess
        cleaned_text = clean_url(query_str)
        
        # If query is empty or just symbols, ignore it
        if not cleaned_text or len(cleaned_text) < 2:
            return "Benign", 0.0, "Empty payload"

        # 2. Vectorize
        vectorized_input = _vectorizer.transform([cleaned_text])

        # 3. Get Probability (Top 1)
        probs = _nb_model.predict_proba(vectorized_input)[0]
        max_conf = float(np.max(probs))
        pred_idx = np.argmax(probs)
        prediction = _nb_model.classes_[pred_idx]

        # 4. Threshold Check
        # If confidence is low (< 70%), assume Benign.
        if max_conf < 0.70 or prediction == "Benign":
            return "Benign", max_conf, "Low Confidence"

        evidence = f"ML Confidence: {round(max_conf * 100)}%. Detected by Naive Bayes."
        return prediction, max_conf, evidence

    except Exception:
        return "Benign", 0.0, "ML Error"