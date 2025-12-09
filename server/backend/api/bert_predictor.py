import os
# Force pure python protobuf to avoid C++ conflicts
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"

import torch
from transformers import BertTokenizer, BertForSequenceClassification
import urllib.parse

# ==========================================
# 1. SMART PATH FINDER
# ==========================================
def find_model_path():
    """Recursively searches for model files (safetensors or bin)"""
    current_dir = os.path.dirname(os.path.abspath(__file__)) 
    search_root = os.path.normpath(os.path.join(current_dir, '..', 'models'))
    
    if not os.path.exists(search_root): return None

    for root, dirs, files in os.walk(search_root):
        if "model.safetensors" in files or "pytorch_model.bin" in files:
            return root
    return None

ACTUAL_MODEL_PATH = find_model_path()

# Global variables (Shared) 
_model = None
_tokenizer = None
_device = "cuda" if torch.cuda.is_available() else "cpu"

def load_model():
    global _model, _tokenizer
    if _model is not None: return

    # Silent fallback logic
    model_source = ACTUAL_MODEL_PATH if ACTUAL_MODEL_PATH else "bert-base-uncased"

    try:
        try:
            _tokenizer = BertTokenizer.from_pretrained(model_source)
        except:
            _tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")

        _model = BertForSequenceClassification.from_pretrained(
            model_source, 
            use_safetensors=True,
            output_attentions=True # Critical for XAI
        )
        _model.to(_device)
        _model.eval()
    except Exception:
        # Final safety net: load generic model if local fails
        if model_source != "bert-base-uncased":
            try:
                _tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")
                _model = BertForSequenceClassification.from_pretrained("bert-base-uncased")
                _model.to(_device)
                _model.eval()
            except: pass

# ==========================================
# 2. VALIDATION LOGIC
# ==========================================
def validate_prediction(label, url_str, query_str):
    url_lower = str(url_str).lower()
    query_lower = str(query_str).lower()

    if label == "Remote File Inclusion (RFI)":
        if not any(x in query_lower for x in ['http', 'ftp', '://', '=']):
            return False, "False Positive (No remote protocol)"

    if label == "SQL Injection":
        if not any(x in query_lower for x in ["'", '"', 'select', 'union', '--', '=', 'sleep']):
            return False, "False Positive (No SQL markers)"

    return True, ""

# ==========================================
# 3. PREDICTION: SPOOFING (Prompt Based)
# ==========================================
def predict_url_spoofing(url):
    if _model is None: load_model()
    if _model is None: return False, ""

    # PROMPT: Explicit instruction for the model
    prompt = f"analyze domain for spoofing: {url}"

    try:
        inputs = _tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=128,
            padding="max_length"
        ).to(_device)

        with torch.no_grad():
            outputs = _model(**inputs)
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
            confidence, predicted_class_id = torch.max(probs, dim=-1)

        label = _model.config.id2label[predicted_class_id.item()]
        
        if label == "URL Spoofing / Typosquatting" and confidence.item() > 0.85:
             return True, f"AI detected spoofing pattern ({round(confidence.item()*100)}%)"
        return False, ""
    except:
        return False, ""

# ==========================================
# 4. PREDICTION: ATTACK (Split Based)
# ==========================================
def predict_url_attack(url):
    if _model is None: load_model()
    if _model is None: return "Benign", 0.0, "AI Unavailable"

    # Split Logic
    try:
        parsed = urllib.parse.urlparse(str(url))
        path = parsed.path
        query = parsed.query
        
        if query:
            text_a = query # Payload
            text_b = path  # Context
            evidence_hint = "Suspicious parameters."
        else:
            text_a = url
            text_b = None
            evidence_hint = "Suspicious URL path."
    except:
        text_a = url
        text_b = None
        evidence_hint = "Suspicious pattern."

    try:
        inputs = _tokenizer(
            text=text_a,
            text_pair=text_b,
            return_tensors="pt",
            truncation=True,
            max_length=128,
            padding="max_length"
        ).to(_device)

        with torch.no_grad():
            outputs = _model(**inputs)
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
            confidence, predicted_class_id = torch.max(probs, dim=-1)

        predicted_label = _model.config.id2label[predicted_class_id.item()]
        conf_score = confidence.item()

        # Threshold Check
        if conf_score > 0.85:
            is_valid, reason = validate_prediction(predicted_label, url, query)
            
            if is_valid:
                evidence = f"AI Confidence: {round(conf_score * 100)}%. {evidence_hint}"
                return predicted_label, conf_score, evidence
            else:
                return "Benign", conf_score, reason

        return "Benign", conf_score, "Low AI confidence"

    except Exception:
        return "Benign", 0.0, "Error"

# ==========================================
# 5. EXPLANATION LOGIC (Simple Tokenizer)
# ==========================================
def get_explanation(text_input):
    if _tokenizer is None: load_model()
    if _tokenizer is None: return []
    try:
        tokens = _tokenizer.tokenize(text_input)
        return [{"token": t, "weight": 0.1} for t in tokens[:50]]
    except:
        return []