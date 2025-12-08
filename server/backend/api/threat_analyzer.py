import pandas as pd
import urllib.parse
import re
from tqdm import tqdm

# Import Predictors
# from .bert_predictor import predict_url_attack, predict_url_spoofing
# from .ml_predictor import predict_ml_attack
# from bert_predictor import predict_url_attack, predict_url_spoofing
# from ml_predictor import predict_ml_attack

# --- REGEX PATTERNS ---
CMD_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"(?:;|\||\|\||&&|\n|\$\()\s*\b(ls|cat|pwd|whoami|id|uname|wget|curl|nc|net|ping|sleep|echo|python|perl|ruby|bash|sh|java|gcc|tar|nslookup)\b",
    r"/bin/(sh|bash|zsh|dash|ksh)",
    r"\b(fsockopen|pfsockopen|stream_socket_client|exec|system|passthru|shell_exec|popen|proc_open)\s*\(",
    r"cmd\.exe",
    r"powershell",
    r"\$\(.*\)",
    r"`.*`",
    r"{{.*system.*}}",
]]

SQLI_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"union\s+(all\s+)?select",
    r"\bselect\s+.*?\s+from\b",
    r"\b(insert\s+into|update\s+.*?set|delete\s+from|drop\s+table|alter\s+table|truncate\s+table)\b",
    r"information_schema|sysobjects|xp_cmdshell",
    r"(or|and)\s+\d+=\d+",
    r"(or|and)\s+['\"][^'\"]+['\"]=['\"][^'\"]+['\"]",
    r"['\"]\s*(or|and)\s*['\"]",
    r"--|/\*|#",
]]

XSS_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"<script.*?>",
    r"javascript:",
    r"vbscript:",
    r"(alert|confirm|prompt)\s*\(",
    r"on(error|load|mouseover|click|focus|blur|change|submit)\s*=",
    r"<img\s+src",
    r"<iframe",
    r"<svg",
    r"<body",
]]

LFI_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"\.\./",
    r"\.\.\\",
    r"\.\.%2f",
    r"/etc/(passwd|shadow|issue|group|hosts|motd)",
    r"[c-z]:\\(windows|winnt|boot\.ini)",
    r"php://(filter|input|expect)",
    r"file://",
]]

SSRF_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"=\s*http://127\.0\.0\.1",
    r"=\s*http://localhost",
    r"=\s*http://0\.0\.0\.0",
    r"=\s*http://169\.254\.169\.254",
    r"=\s*http://192\.168\.",
    r"=\s*http://10\.",
    r"=\s*http://172\.(1[6-9]|2[0-9]|3[0-1])\.",
    r"dict://",
    r"gopher://",
    r"ldap://",
]]

XXE_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"<!entity",
    r"<!doctype",
    r"system\s+[\"']",
    r"public\s+[\"']",
]]

URL_SPOOF_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"https?://[^/\s]*@[^/\s]+",
    r"xn--[a-z0-9\-]+",
    r"https?://[a-z0-9\-]{25,}\.(com|net|org)",
    r"(paypa1|paypai|paaypal)\.com",
    r"(g00gle|goog1e|gooogle)\.com",
    r"(faceb00k|facbook)\.com",
    r"(micros0ft|rnicrosoft)\.com",
    r"(instaqram|lnstagram)\.com",
    r"(linkedln|1inkedin)\.com",
]]

SHELL_UPLOAD_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"filename\s*=\s*\"?[^\"]*\.(php[0-9]?|phtml|pht|phar|asp|aspx|jsp|cfm|cgi|pl|sh|bash)\"?",
    r"(web)?shell\.php",
    r"(c99|r57|b374k)\.php",
    r"content-type\s*:\s*application/(x-php|x-httpd-php|x-shellscript)",
]]

# For improved RFI detection (URL passed as param value)
RFI_PROTOCOL_PATTERN = re.compile(r"^(?:https?|ftps?)://", re.IGNORECASE)


class PipelineStats:
    def __init__(self):
        self.total = 0
        self.regex = 0
        self.ml_in = 0
        self.ml_hit = 0
        self.spoof = 0
        self.bert_in = 0
        self.bert_hit = 0


# NEW: helper for per-layer attack counting (no logic change)
def add_attack(layer_dict, attack_name):
    if attack_name not in layer_dict:
        layer_dict[attack_name] = 0
    layer_dict[attack_name] += 1


# === HELPERS FOR RFI / HPP / PATH / BRUTEFORCE ===

def detect_rfi(url: str) -> bool:
    """Detect external URLs passed as parameter values (RFI style)."""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False

    base_host = (parsed.hostname or "").lower()
    query = parsed.query or ""
    if not query:
        return False

    params = urllib.parse.parse_qs(query, keep_blank_values=True)

    # 🔧 Restrict to typical inclusion-related parameter names
    rfi_param_keys = {"file", "page", "include", "inc", "template", "tmpl", "view", "path"}

    for key, values in params.items():
        key_l = key.lower()
        if key_l not in rfi_param_keys:
            continue

        for v in values:
            v_dec = urllib.parse.unquote_plus(v).strip()
            if not RFI_PROTOCOL_PATTERN.match(v_dec):
                continue

            try:
                v_host = urllib.parse.urlparse(v_dec).hostname or ""
            except Exception:
                v_host = ""
            v_host = v_host.lower()
            if not v_host:
                continue

            # ignore same-site and obvious internal URLs
            if v_host == base_host:
                continue
            if v_host in ("localhost", "127.0.0.1"):
                continue
            if v_host.startswith(("10.", "192.168.", "172.")):
                continue

            return True

    return False


def detect_hpp(query: str):
    """
    HTTP Parameter Pollution:
    - Duplicate parameter keys with DIFFERENT values
    - Ignore array-style keys like 'ids[]'
    """
    if not query or "=" not in query:
        return None

    params = urllib.parse.parse_qs(query, keep_blank_values=True)
    for k, v in params.items():
        # typical array style, don't flag
        if k.endswith("[]"):
            continue
        if len(v) > 1 and len(set(v)) > 1:
            return k

    return None


def get_path(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).path or ""
    except Exception:
        return ""


# === LAYER FUNCTIONS ===

def regex_layer_single(row):
    url = str(row.get('URL', '') or "").strip()
    body = str(row.get('POST_Body', '') or "").strip()

    try:
        decoded_url = urllib.parse.unquote_plus(url).lower()
    except Exception:
        decoded_url = url.lower()

    full_payload = decoded_url + " " + body.lower()

    def check(patterns, name):
        for p in patterns:
            if p.search(full_payload):
                return name, f"Matched regex pattern: '{p.pattern[:25]}...'"
        return None

    checks = [
        (CMD_PATTERNS, "Command Injection"),
        (SQLI_PATTERNS, "SQL Injection"),
        (XSS_PATTERNS, "Cross-Site Scripting (XSS)"),
        (LFI_PATTERNS, "Directory Traversal / LFI"),
        (SSRF_PATTERNS, "SSRF"),
        (SHELL_UPLOAD_PATTERNS, "Shell Upload Attempt"),
    ]

    for pats, name in checks:
        res = check(pats, name)
        if res:
            return res[0], res[1]

    # --- HPP (HTTP Parameter Pollution) in URL query or POST body ---
    try:
        parsed = urllib.parse.urlparse(url)
        query = parsed.query or ""
    except Exception:
        query = ""

    offending_key = detect_hpp(query)

    # HPP can also appear in form-encoded POST body
    if not offending_key and body and "=" in body and "&" in body:
        offending_key = detect_hpp(body)

    if offending_key:
        return "HPP (HTTP Parameter Pollution)", f"Duplicate parameter key with different values: '{offending_key}'"

    # --- RFI ---
    if detect_rfi(url):
        return "Remote File Inclusion (RFI)", "External URL passed as parameter"

    # --- XXE only if XML-like content present ---
    if "xml" in full_payload:
        res = check(XXE_PATTERNS, "XXE")
        if res:
            return res[0], res[1]

    return None, None


def ml_layer_single(row):
    url = str(row.get('URL', '') or "").strip()
    try:
        parsed = urllib.parse.urlparse(url)
        query_part = parsed.query
    except Exception:
        query_part = ""

    if not query_part:
        return None, None

    # ml_label, ml_conf, ml_evidence = predict_ml_attack(query_part)



    return None, None


def spoof_layer_single(row):
    """
    Layer 3: ONLY URL spoofing / typosquatting.
    HPP is handled in the REGEX layer.
    """
    url = str(row.get('URL', '') or "").strip()




# === MAIN PIPELINE ===

def run_full_analysis(df: pd.DataFrame) -> pd.DataFrame:
    """
    Returns a DataFrame with columns:
    - attack_type
    - evidence
    - detection_method
    (plus original columns)

    Flow: REGEX (includes HPP/RFI/SSRF/XXE etc) -> ML -> SPOOF -> BERT -> BRUTEFORCE
    """
    if df.empty:
        df = df.copy()
        df['attack_type'] = []
        df['evidence'] = []
        df['detection_method'] = []
        return df

    df = df.copy().fillna("")
    df['attack_type'] = "Benign"
    df['evidence'] = "No threat detected"
    df['detection_method'] = "None"

    stats = PipelineStats()
    stats.total = len(df)

    # per-layer attack dictionaries
    layer1_attacks = {}

    print(f"\n🚀 Pipeline started on {stats.total} requests.")

    # --- LAYER 1: REGEX ---
    mask_remaining = df['attack_type'] == "Benign"
    layer1_input = mask_remaining.sum()
    print(f"\n[1] REGEX LAYER")
    print(f"    Input records : {layer1_input}")

    if layer1_input > 0:
        tqdm.pandas(desc="Regex Layer")
        subset = df[mask_remaining]
        results = subset.progress_apply(
            lambda row: regex_layer_single(row),
            axis=1,
            result_type='expand'
        )
        detected_mask = results[0].notna()
        detected_idx = results[detected_mask].index

        df.loc[detected_idx, 'attack_type'] = results.loc[detected_idx, 0]
        df.loc[detected_idx, 'evidence'] = results.loc[detected_idx, 1]
        df.loc[detected_idx, 'detection_method'] = "Regex"

        # count attacks in regex layer
        for idx in detected_idx:
            add_attack(layer1_attacks, df.loc[idx, 'attack_type'])

    mask_remaining = df['attack_type'] == "Benign"
    layer1_passed = mask_remaining.sum()
    layer1_detected = layer1_input - layer1_passed
    stats.regex = layer1_detected

    print(f"    Detected      : {layer1_detected}")
    print(f"    Passed to ML  : {layer1_passed}")

    # regex layer breakdown
    print(f"\n[1] REGEX LAYER ATTACK BREAKDOWN")
    for k, v in layer1_attacks.items():
        print(f"   {k}: {v}")


    # Skip downstream layers: keep remaining rows as Benign
    stats.ml_in = layer1_passed
    stats.ml_hit = 0
    stats.spoof = 0
    stats.bert_in = layer1_passed
    stats.bert_hit = 0

    # === ATTACK TYPE COUNTS BY LAYER (only regex active) ===
    print("\n" + "=" * 80)
    print("🔥 ATTACK TYPE COUNTS BY LAYER")
    print("=" * 80)

    def print_layer(title, data):
        print(f"\n{title}")
        if not data:
            print("   (None)")
        else:
            for k, v in data.items():
                print(f"   {k}: {v}")

    print_layer("REGEX LAYER:", layer1_attacks)
   
    print("\n" + "=" * 80)

    # --- FINAL SUMMARY (regex-only) ---
    total = len(df)
    total_threats = (df['attack_type'] != 'Benign').sum()
    regex_det = stats.regex
    ml_det = stats.ml_hit  # 0
    spoof_det = stats.spoof  # 0
    bert_det = stats.bert_hit  # 0
    bruteforce_det = 0  # disabled with downstream layers

    print("\n" + "=" * 60)
    print("🛡️  FINAL PIPELINE SUMMARY (REGEX ONLY)")
    print("=" * 60)
    print(f"Total records            : {total}")
    print(f"Regex detections         : {regex_det}")
    print("=" * 60 + "\n")

    return df