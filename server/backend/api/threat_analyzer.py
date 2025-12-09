import pandas as pd
import urllib.parse
import re
from tqdm import tqdm
import time

# Import Predictors
from .bert_predictor import predict_url_attack, predict_url_spoofing
from .ml_predictor import predict_ml_attack

# ============================================================
#  TERMINAL FORMATTING HELPERS (Professional Output)
# ============================================================
class CliTable:
    @staticmethod
    def print_header(title):
        print(f"\n╔{'═'*68}╗")
        print(f"║ {title.center(66)} ║")
        print(f"╠{'═'*68}╣")

    @staticmethod
    def print_row(label, value):
        # Align label left, value right-ish
        print(f"║ {label:<35} : {str(value):<28} ║")

    @staticmethod
    def print_divider():
        print(f"╟{'─'*68}╢")

    @staticmethod
    def print_footer():
        print(f"╚{'═'*68}╝\n")

# ============================================================
#  REGEX PATTERNS
# ============================================================

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

SHELL_UPLOAD_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"filename\s*=\s*\"?[^\"]*\.(php[0-9]?|phtml|pht|phar|asp|aspx|jsp|cfm|cgi|pl|sh|bash)\"?",
    r"(web)?shell\.php",
    r"(c99|r57|b374k)\.php",
    r"content-type\s*:\s*application/(x-php|x-httpd-php|x-shellscript)",
]]

# --- STRICT NEW PATTERNS ---

NULL_BYTE_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"(?:%00|\\x00|\\u0000)",
]]

NOSQL_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"\b\$(?:eq|ne|gt|gte|lt|lte|in|nin|regex|where|expr|jsonSchema)\b",
    r"\{\s*[\"']\$[a-z]+[\"']\s*:",
    r"\$where\s*:\s*[\"'].+[\"']",
    r"\b(sleep|benchmark)\s*\(\s*\d+\s*\)",
]]

LDAP_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"[^\\\w]\)\s*(?:&|\||!)\s*\(",
    r"(?:%00|\x00)\s*\)",
    r"\b(objectClass|uid|cn)\s*=\s*\*[\)\s]",
]]

BUFFER_OVERFLOW_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"(.)\1{127,}", 
    r"(?:\\x[0-9a-fA-F]{2}){16,}",
    r"(\x90){16,}",
]]

IDOR_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"\b(?:user_id|account_id|profile_id|order_id)\[\d*\]\s*=\s*\d+",
    r"[\"'](is_admin|role|account_type)[\"']\s*:\s*[\"']?(admin|root|superuser)[\"']?",
]]

OBFUSCATION_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"(?:%[0-9a-fA-F]{2}){15,}",
    r"\b(String\.fromCharCode|atob|btoa|eval|setTimeout)\s*\(",
    r"(?:['\"]\s*\+\s*['\"]){3,}",
    r"(?:chr\(\d+\)\.){3,}",
]]

UNICODE_ATTACK_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"%u[0-9a-fA-F]{4}",
    r"(?:%c0%[89ab]|%e0%80%[89ab]|%f0%80%80%[89ab])",
]]

CACHE_POISONING_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"^\s*X-Forwarded-Host\s*:\s*[^\s]+",
    r"^\s*X-Original-URL\s*:",
    r"^\s*X-Rewrite-URL\s*:",
    r"[\r\n]\s*(?:Transfer-Encoding|Host):",
]]

URL_SPOOF_REGEX = [re.compile(p, re.IGNORECASE) for p in [
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
            if v_host == base_host: continue
            if v_host in ("localhost", "127.0.0.1"): continue
            if v_host.startswith(("10.", "192.168.", "172.")): continue
            return True
    return False


def detect_hpp(query: str):
    """HTTP Parameter Pollution"""
    if not query or "=" not in query:
        return None
    params = urllib.parse.parse_qs(query, keep_blank_values=True)
    for k, v in params.items():
        if k.endswith("[]"): continue
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
        (NULL_BYTE_PATTERNS, "Null Byte Injection"),
        (NOSQL_PATTERNS, "NoSQL Injection"),
        (LDAP_PATTERNS, "LDAP Injection"),
        (BUFFER_OVERFLOW_PATTERNS, "Buffer Overflow Attempt"),
        (IDOR_PATTERNS, "Potential IDOR"),
        (OBFUSCATION_PATTERNS, "Obfuscation Detected"),
        (UNICODE_ATTACK_PATTERNS, "Unicode/Homograph Attack"),
        (CACHE_POISONING_PATTERNS, "Cache Poisoning Indicator"),
    ]

    for pats, name in checks:
        res = check(pats, name)
        if res: return res[0], res[1]

    try:
        parsed = urllib.parse.urlparse(url)
        query = parsed.query or ""
    except Exception:
        query = ""

    offending_key = detect_hpp(query)
    if not offending_key and body and "=" in body and "&" in body:
        offending_key = detect_hpp(body)

    if offending_key:
        return "HPP (HTTP Parameter Pollution)", f"Duplicate parameter key: '{offending_key}'"

    if detect_rfi(url):
        return "Remote File Inclusion (RFI)", "External URL passed as parameter"

    if "xml" in full_payload or "<!entity" in full_payload:
        res = check(XXE_PATTERNS, "XXE")
        if res: return res[0], res[1]

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

    try:
        ml_label, ml_conf, ml_evidence = predict_ml_attack(query_part)
        if ml_label and ml_label != "Benign":
            return ml_label, f"ML Confidence: {ml_conf:.2f} | {ml_evidence}"
    except Exception:
        return None, None

    return None, None


def spoof_layer_single(row):
    url = str(row.get('URL', '') or "").strip()

    try:
        label, conf, evidence = predict_url_spoofing(url)
        if label and label != "Benign":
            return label, evidence
    except Exception:
        pass

    for p in URL_SPOOF_REGEX:
        if p.search(url):
             return "URL Spoofing", f"Matched spoofing pattern: {p.pattern}"

    return None, None


def bert_layer_single(row):
    url = str(row.get('URL', '') or "").strip()
    payload = url
    if row.get('POST_Body'):
        payload += " " + str(row['POST_Body'])

    try:
        label, conf, evidence = predict_url_attack(payload)
        if label and label != "Benign" and conf > 0.85: 
            return label, f"AI Model (Conf: {conf:.2f})"
    except Exception:
        pass
        
    return None, None


# ============================================================
#  MAIN PIPELINE (Modified for Formatting & Fixes)
# ============================================================

def run_full_analysis(df: pd.DataFrame, save_path: str = None) -> pd.DataFrame:
    """
    Analyzes dataframe and saves incrementally.
    Prints professional tabular output to terminal.
    """
    # --- FIX: Ensure Status_Code exists even if df is empty ---
    if df.empty:
        if save_path:
            # We explicitly define the columns here to prevent KeyError in frontend
            pd.DataFrame(columns=[
                "Timestamp", "Source_IP", "URL", "attack_type", 
                "evidence", "detection_method", "Status_Code"
            ]).to_csv(save_path, index=False)
        return df

    df = df.copy().fillna("")
    df['attack_type'] = "Benign"
    df['evidence'] = "No threat detected"
    df['detection_method'] = "None"

    # Save initial state
    if save_path:
        df.to_csv(save_path, index=False)

    stats = PipelineStats()
    stats.total = len(df)
    
    layer1_attacks = {}
    layer2_attacks = {}
    layer3_attacks = {}
    layer4_attacks = {}

    CliTable.print_header("🛡️  AURA THREAT ENGINE STARTED")
    CliTable.print_row("Total Requests to Scan", stats.total)
    CliTable.print_footer()

    # --- LAYER 1: REGEX ---
    mask_remaining = df['attack_type'] == "Benign"
    input_count = mask_remaining.sum()
    
    if input_count > 0:
        # Slight delay for visual effect in terminal
        time.sleep(0.5) 
        
        CliTable.print_header("LAYER 1: PATTERN MATCHING (REGEX)")
        CliTable.print_row("Status", "Running...")
        
        tqdm.pandas(desc="Scanning Patterns")
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
        
        for idx in detected_idx:
            add_attack(layer1_attacks, df.loc[idx, 'attack_type'])

        detected_count = len(detected_idx)
        stats.regex = detected_count
        
        CliTable.print_divider()
        CliTable.print_row("Input Records", input_count)
        CliTable.print_row("Threats Detected", detected_count)
        CliTable.print_row("Clean Traffic Passed", input_count - detected_count)
        CliTable.print_footer()
    
    if save_path: df.to_csv(save_path, index=False)

    # --- LAYER 2: ML ---
    mask_remaining = df['attack_type'] == "Benign"
    input_count = mask_remaining.sum()
    stats.ml_in = input_count
    
    if input_count > 0:
        CliTable.print_header("LAYER 2: MACHINE LEARNING (RF)")
        
        tqdm.pandas(desc="Analyzing Features")
        subset = df[mask_remaining]
        results = subset.progress_apply(
            lambda row: ml_layer_single(row), 
            axis=1, 
            result_type='expand'
        )
        detected_mask = results[0].notna()
        detected_idx = results[detected_mask].index

        df.loc[detected_idx, 'attack_type'] = results.loc[detected_idx, 0]
        df.loc[detected_idx, 'evidence'] = results.loc[detected_idx, 1]
        df.loc[detected_idx, 'detection_method'] = "ML"
        
        for idx in detected_idx:
            add_attack(layer2_attacks, df.loc[idx, 'attack_type'])

        detected_count = len(detected_idx)
        stats.ml_hit = detected_count

        CliTable.print_divider()
        CliTable.print_row("Input Records", input_count)
        CliTable.print_row("ML Predictions", detected_count)
        CliTable.print_footer()

    if save_path: df.to_csv(save_path, index=False)

    # --- LAYER 3: SPOOFING ---
    mask_remaining = df['attack_type'] == "Benign"
    input_count = mask_remaining.sum()

    if input_count > 0:
        CliTable.print_header("LAYER 3: URL SPOOFING DETECTION")
        
        tqdm.pandas(desc="Checking Typosquatting")
        subset = df[mask_remaining]
        results = subset.progress_apply(
            lambda row: spoof_layer_single(row), 
            axis=1, 
            result_type='expand'
        )
        detected_mask = results[0].notna()
        detected_idx = results[detected_mask].index

        df.loc[detected_idx, 'attack_type'] = results.loc[detected_idx, 0]
        df.loc[detected_idx, 'evidence'] = results.loc[detected_idx, 1]
        df.loc[detected_idx, 'detection_method'] = "Spoofing"
        
        for idx in detected_idx:
            add_attack(layer3_attacks, df.loc[idx, 'attack_type'])

        detected_count = len(detected_idx)
        stats.spoof = detected_count

        CliTable.print_divider()
        CliTable.print_row("Input Records", input_count)
        CliTable.print_row("Spoofs Detected", detected_count)
        CliTable.print_footer()

    if save_path: df.to_csv(save_path, index=False)

    # --- LAYER 4: BERT AI ---
    mask_remaining = df['attack_type'] == "Benign"
    input_count = mask_remaining.sum()
    stats.bert_in = input_count

    if input_count > 0:
        CliTable.print_header("LAYER 4: DEEP LEARNING (BERT)")
        
        tqdm.pandas(desc="AI Contextual Analysis")
        subset = df[mask_remaining]
        results = subset.progress_apply(
            lambda row: bert_layer_single(row), 
            axis=1, 
            result_type='expand'
        )
        detected_mask = results[0].notna()
        detected_idx = results[detected_mask].index

        df.loc[detected_idx, 'attack_type'] = results.loc[detected_idx, 0]
        df.loc[detected_idx, 'evidence'] = results.loc[detected_idx, 1]
        df.loc[detected_idx, 'detection_method'] = "AI"
        
        for idx in detected_idx:
            add_attack(layer4_attacks, df.loc[idx, 'attack_type'])

        detected_count = len(detected_idx)
        stats.bert_hit = detected_count

        CliTable.print_divider()
        CliTable.print_row("Input Records", input_count)
        CliTable.print_row("AI Detections", detected_count)
        CliTable.print_footer()

    # --- BRUTEFORCE CHECK ---
    if 'URL' in df.columns and 'Source_IP' in df.columns:
        url_series = df['URL'].astype(str)
        login_mask = url_series.str.contains(r"(login|signin|auth)", case=False, na=False)
        fail_mask = pd.Series(True, index=df.index)
        for col in ['Status_Code', 'HTTP_Status', 'Response_Code']:
            if col in df.columns:
                codes = df[col].astype(str)
                fail_mask = codes.str.match(r"[45]\d\d", na=False)
                break

        brute_subset = df[login_mask & fail_mask & (df['attack_type'] == 'Benign')].copy()
        if not brute_subset.empty:
            paths = url_series.apply(get_path)
            brute_subset['_path'] = paths.loc[brute_subset.index]
            counts = brute_subset.groupby(['Source_IP', '_path'])['_path'].transform('count')
            threshold = 5
            targets = brute_subset.index[counts >= threshold]

            if len(targets) > 0:
                df.loc[targets, 'attack_type'] = "Bruteforce Attack"
                df.loc[targets, 'evidence'] = "High frequency failed login attempts"
                df.loc[targets, 'detection_method'] = "Bruteforce Pattern"
    
    if save_path: df.to_csv(save_path, index=False)

    # --- FINAL SUMMARY TABLE ---
    total_threats = (df['attack_type'] != 'Benign').sum()
    
    print("\n")
    CliTable.print_header("🏁  ANALYSIS COMPLETE")
    CliTable.print_row("Total Scanned", stats.total)
    CliTable.print_row("Total Threats", total_threats)
    CliTable.print_row("Benign Traffic", stats.total - total_threats)
    CliTable.print_divider()
    CliTable.print_row("Layer 1 (Regex)", sum(layer1_attacks.values()))
    CliTable.print_row("Layer 2 (ML)", sum(layer2_attacks.values()))
    CliTable.print_row("Layer 3 (Spoof)", sum(layer3_attacks.values()))
    CliTable.print_row("Layer 4 (AI)", sum(layer4_attacks.values()))
    CliTable.print_footer()

    return df