import torch
import os
import re
from transformers import AutoTokenizer, AutoModelForSequenceClassification, AutoModelForCausalLM
from captum.attr import LayerIntegratedGradients
from huggingface_hub import login

# ==========================================
#   0. SECURITY & AUTH
# ==========================================
print("\n--- 🔐 INITIALIZING AI SECURITY MODULE ---")
HF_TOKEN = None

try:
    from .secrets import HF_TOKEN
    print("   -> Loaded HF_TOKEN from secrets.py")
except ImportError:
    print("   -> secrets.py not found, checking environment variables")
    pass

if not HF_TOKEN:
    HF_TOKEN = os.getenv("HF_TOKEN")
    print(f"   -> Token from ENV: {'Yes' if HF_TOKEN else 'No'}")

if HF_TOKEN:
    try:
        login(token=HF_TOKEN)
        print("   -> ✅ HuggingFace Login Successful")
    except Exception as e:
        print(f"   -> ❌ HuggingFace Login Failed: {e}")
else:
    print("   -> ⚠️  No HuggingFace Token found. Model downloading may fail.")

# ==========================================
#   DEVICE SETUP
# ==========================================
_device = "cuda" if torch.cuda.is_available() else "cpu"
print(f"⚙️  AI Engine Running on: {_device.upper()}")

# ================================================================
#   1. SECBERT CLASSIFIER (Global Load)
# ================================================================
CLASSIFIER_MODEL_NAME = "jackaduma/SecBERT"
_classifier_tokenizer = None
_classifier_model = None

CLASS_INDEX_MAP = {
    "SQL Injection": 0, "SQL_INJECTION": 0,
    "XSS": 1, "Cross-Site Scripting": 1,
    "Directory Traversal": 2, "DIRECTORY_TRAVERSAL": 2,
    "Command Injection": 3, "COMMAND_INJECTION": 3,
    "SSRF": 4, 
    "LFI/RFI": 5, 
    "XXE": 6,
    "Other": 0 
}

IGNORE_TOKENS = {
    "http", "https", "ftp", "www", "com", "org", "net",
    "127", "0", "1", "localhost", "ip",
    ":", "/", ".", "?", "&", "=", "-", "_", "%",
    "protocol", "host", "port", "user", "agent",
    "[CLS]", "[SEP]", "[PAD]"
}

def _load_classifier():
    global _classifier_tokenizer, _classifier_model
    if _classifier_model is not None:
        return _classifier_tokenizer, _classifier_model

    print(f"📊 Loading SecBERT ({CLASSIFIER_MODEL_NAME})...")
    try:
        _classifier_tokenizer = AutoTokenizer.from_pretrained(CLASSIFIER_MODEL_NAME)
        print("   -> SecBERT Tokenizer Loaded")
        _classifier_model = AutoModelForSequenceClassification.from_pretrained(
            CLASSIFIER_MODEL_NAME, num_labels=7
        ).to(_device)
        _classifier_model.eval()
        print("   -> ✅ SecBERT Model Loaded & Moved to Device")
        return _classifier_tokenizer, _classifier_model
    except Exception as e:
        print(f"❌ SecBERT Load Error: {e}")
        return None, None

# ================================================================
#   2. CAPTUM EXPLANATION (Visual Analysis)
# ================================================================
def get_explanation(text_input: str, attack_type_str: str):
    print(f"\n🔍 [XAI] Analyzing Payload: {text_input[:30]}... (Type: {attack_type_str})")
    
    tokenizer, model = _load_classifier()
    if not model: 
        print("   -> ❌ Model unavailable")
        return []

    text = str(text_input).strip()
    if not text: return []

    target_class = CLASS_INDEX_MAP.get(attack_type_str, 0)
    print(f"   -> Mapped '{attack_type_str}' to Class Index: {target_class}")

    # 1. Tokenize
    encoded = tokenizer(
        text, return_tensors="pt", truncation=True, max_length=128, padding=True
    ).to(_device)
    
    input_ids = encoded["input_ids"]
    attention_mask = encoded["attention_mask"]

    # 2. Define Forward Function
    def forward_func(inputs, mask):
        out = model(input_ids=inputs, attention_mask=mask)
        return out.logits[:, target_class]

    # 3. Compute Gradients
    print("   -> Computing Integrated Gradients (Captum)...")
    target_layer = model.bert.embeddings
    lig = LayerIntegratedGradients(forward_func, target_layer)

    try:
        attributions, delta = lig.attribute(
            inputs=input_ids,
            additional_forward_args=(attention_mask,),
            n_steps=50,
            return_convergence_delta=True
        )
        print("   -> Gradients computed successfully")
    except Exception as e:
        print(f"   -> ❌ Captum Error: {e}")
        return []

    # 4. Process Attributions
    token_importance = attributions.sum(dim=-1).squeeze(0)
    
    # 5. Clean & Filter Logic
    tokens = tokenizer.convert_ids_to_tokens(input_ids[0])
    explanation = []
    max_score = 0.0
    
    for i, (tok, score_tensor) in enumerate(zip(tokens, token_importance)):
        raw_score = float(score_tensor.cpu().item())
        abs_score = abs(raw_score)

        clean_tok = tok.replace("##", "").lower()
        if clean_tok in IGNORE_TOKENS or (len(clean_tok) == 1 and not clean_tok.isalnum()):
            abs_score = 0.0
        
        if abs_score > max_score:
            max_score = abs_score
            
        explanation.append({
            "token": tok,
            "weight": abs_score,
            "original_index": i
        })

    # 6. Normalize
    final_explanation = []
    if max_score > 0:
        for item in explanation:
            normalized_weight = item["weight"] / max_score
            if normalized_weight < 0.15: 
                normalized_weight = 0.0
            
            if item["token"] not in ["[CLS]", "[SEP]", "[PAD]"]:
                final_explanation.append({
                    "token": item["token"],
                    "weight": round(normalized_weight, 4)
                })
    
    print(f"   -> ✅ Explanation generated ({len(final_explanation)} tokens)")
    return final_explanation

# ================================================================
#   3. GEMMA MITIGATION (Generative AI)
# ================================================================
GEMMA_MODEL_NAME = "google/gemma-3-270m-it" 
_ai_model = None
_ai_tokenizer = None

def _load_gemma():
    global _ai_model, _ai_tokenizer
    if _ai_model is not None: return _ai_tokenizer, _ai_model

    print(f"🧠 Loading Gemma ({GEMMA_MODEL_NAME})...")
    try:
        _ai_tokenizer = AutoTokenizer.from_pretrained(GEMMA_MODEL_NAME)
        print("   -> Gemma Tokenizer Loaded")
        
        dtype = torch.bfloat16 if (_device == "cuda" and torch.cuda.is_bf16_supported()) else torch.float32
        
        _ai_model = AutoModelForCausalLM.from_pretrained(
            GEMMA_MODEL_NAME,
            device_map="auto" if _device == "cuda" else None,
            torch_dtype=dtype,
            low_cpu_mem_usage=True
        )
        if _device == "cpu": 
            print("   -> Moving Gemma to CPU (Warning: Slow)")
            _ai_model.to(_device)
            
        _ai_model.eval()
        print("   -> ✅ Gemma Model Loaded")
        return _ai_tokenizer, _ai_model
    except Exception as e:
        print(f"❌ Gemma Load Error: {e}")
        return None, None

def get_mitigation_advice(text_input: str, attack_type: str, explanation: list):
    print(f"\n🛡️  [MITIGATION] Generative Advice for: {attack_type}")
    
    tokenizer, model = _load_gemma()
    if model is None: 
        print("   -> ❌ Gemma unavailable")
        return "AI Mitigation service unavailable."

    sorted_exp = sorted(explanation, key=lambda x: abs(x["weight"]), reverse=True)
    top_tokens = [f"'{e['token']}'" for e in sorted_exp if e['weight'] > 0][:3]
    xai_context = ", ".join(top_tokens)

    prompt = f"""<start_of_turn>user
You are a Security Engineer. 
Attack: {attack_type}
Payload: "{text_input}"
Suspicious Tokens: {xai_context}

Provide exactly 2 technical mitigation steps.
Format:
1. [Step 1]
2. [Step 2]<end_of_turn>
<start_of_turn>model
"""
    print("   -> Generating response...")
    
    try:
        inputs = tokenizer(prompt, return_tensors="pt").to(_device)

        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=100,
                do_sample=False,
                repetition_penalty=1.2
            )

        full_output = tokenizer.decode(outputs[0], skip_special_tokens=True)
        
        if "model\n" in full_output:
            response_text = full_output.split("model\n")[-1].strip()
        else:
            response_text = full_output.strip()

        clean_text = response_text.replace("**", "").replace("* ", "")
        print("   -> ✅ Advice Generated")
        return clean_text.strip()
    
    except Exception as e:
        print(f"   -> ❌ Generation Failed: {e}")
        return "Failed to generate advice."