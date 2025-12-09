from rest_framework.decorators import api_view, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response

import os
import uuid
import urllib.parse
import threading # <--- Added for background processing
import json      # <--- Added for analyze_attack

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings

import pandas as pd

from .parsers import parse_pcap_tshark as pcap_to_dataframe
from .threat_analyzer import run_full_analysis
from .xai_bert import get_explanation, get_mitigation_advice

# ============================================================
#  Upload endpoints
# ============================================================

@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
def upload_pcap(request):
    """
    Simple test endpoint (not used by frontend now).
    """
    return Response({"status": "ok", "message": "PCAP received successfully"})


@csrf_exempt
def upload_capture(request):
    """
    POST /api/upload-capture/
    Main endpoint used by frontend to upload a PCAP/PCAPNG/CSV.
    Runs analysis in a BACKGROUND THREAD and returns immediately.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    if "file" not in request.FILES:
        return JsonResponse({"error": "Missing file parameter"}, status=400)

    up_file = request.FILES["file"]
    _, ext = os.path.splitext(up_file.name)
    ext = ext.lower()

    # 🚀 UPDATED — allow CSV as input
    if ext not in [".pcap", ".pcapng", ".csv"]:
        return JsonResponse({"error": "Only .pcap, .pcapng or .csv supported"}, status=400)

    upload_dir = os.path.join(settings.BASE_DIR, "uploads")
    os.makedirs(upload_dir, exist_ok=True)

    tmp_name = f"{uuid.uuid4()}{ext}"
    tmp_path = os.path.join(upload_dir, tmp_name)

    # Define result path immediately
    result_name = f"analysis_{uuid.uuid4()}.csv"
    result_path = os.path.join(upload_dir, result_name)

    # save uploaded file to disk
    with open(tmp_path, "wb+") as dest:
        for chunk in up_file.chunks():
            dest.write(chunk)

    # --- THE BACKGROUND TASK (Threaded) ---
    def run_analysis_task(temp_path, output_csv_path, file_ext):
        try:
            # 1. Load Dataframe based on file type
            if file_ext == ".csv":
                # If uploading a raw CSV, read it directly
                df = pd.read_csv(temp_path).fillna("")
            else:
                # If PCAP, convert to DF using your parser
                df = pcap_to_dataframe(temp_path)

            if df.empty:
                # Save empty structure with ALL headers to prevent frontend crash
                pd.DataFrame(columns=[
                    "Timestamp", "Source_IP", "URL", "attack_type", 
                    "evidence", "detection_method", "Status_Code"
                ]).to_csv(output_csv_path, index=False)
                return

            # 2. SANITIZATION 🛡 (Prevent KeyErrors downstream)
            
            # Ensure URL exists
            if "URL" not in df.columns:
                df["URL"] = ""

            # Ensure Timestamp is numeric
            if "Timestamp" in df.columns:
                df["Timestamp"] = pd.to_numeric(df["Timestamp"], errors="coerce").fillna(0)
            
            # Ensure Status_Code is numeric (critical for Breach calculation)
            if "Status_Code" in df.columns:
                df["Status_Code"] = pd.to_numeric(df["Status_Code"], errors="coerce").fillna(0)
            else:
                df["Status_Code"] = 0

            # 3. Run Analysis
            # This calls the threat_analyzer which handles incremental saving
            run_full_analysis(df, save_path=output_csv_path)

        except Exception as e:
            print(f"Error in background analysis: {e}")
        finally:
            # Clean up input file
            if os.path.exists(temp_path):
                os.remove(temp_path)

    # Start the thread
    thread = threading.Thread(target=run_analysis_task, args=(tmp_path, result_path, ext))
    thread.daemon = True 
    thread.start()

    # Return IMMEDIATELY so frontend doesn't wait
    return JsonResponse({
        "message": "Analysis started in background",
        "csv": result_name,
        "status": "processing"
    })


# ============================================================
#  Helpers for reading latest analysis CSV
# ============================================================

UPLOAD_DIR = os.path.join(settings.BASE_DIR, "uploads")


def _get_latest_csv_path():
    """Return path to the most recent analysis_*.csv file, or None."""
    if not os.path.exists(UPLOAD_DIR):
        return None

    csv_files = [
        f for f in os.listdir(UPLOAD_DIR)
        if f.endswith(".csv") and f.startswith("analysis_")
    ]
    if not csv_files:
        return None

    csv_files.sort(
        key=lambda f: os.path.getmtime(os.path.join(UPLOAD_DIR, f)),
        reverse=True,
    )
    return os.path.join(UPLOAD_DIR, csv_files[0])


ATTACK_SEVERITY = {
    "Cross-Site Scripting (XSS)": 20,
    "SQL Injection": 35,
    "Command Injection": 40,
    "Directory Traversal / LFI": 25,
    "Remote File Inclusion (RFI)": 40,
    "Shell Upload Attempt": 50,
    "SSRF": 30,
    "Bruteforce Attack": 20,
    "URL Spoofing / Typosquatting": 20,
    "XXE": 35,
    "HPP (HTTP Parameter Pollution)": 20,
    "Benign": 0,
}

SENSITIVE_PATHS = [
    "login", "admin", "dashboard",
    "config", "wp-admin", "phpmyadmin",
]


def _risk_score(attack_type: str, url: str, success: bool, attempt_count: int) -> int:
    """
    Compute a numeric risk score (0–100) based on:
    - Base severity per attack type
    - Sensitive URL paths
    - Whether the attack appears successful
    - Frequency of attempts
    """
    risk = 0

    # 1) Attack type base severity
    risk += ATTACK_SEVERITY.get(attack_type, 10)

    # 2) Sensitive URL weighting
    url_l = (str(url) or "").lower()
    if any(x in url_l for x in SENSITIVE_PATHS):
        risk += 15

    # 3) Breach confirmation weighting
    if success:
        risk += 15

    # 4) Frequency weighting
    if attempt_count > 10:
        risk += 10

    return min(risk, 100)


def _severity_for_attack(
    attack_type: str,
    url: str = "",
    success: bool = False,
    attempt_count: int = 1,
) -> str:
    """
    Returns Low / Medium / High / Critical
    based on risk score thresholds.
    """
    risk = _risk_score(attack_type, url, success, attempt_count)

    if risk <= 25:
        return "Low"
    elif risk <= 50:
        return "Medium"
    elif risk <= 75:
        return "High"
    else:
        return "Critical"


def _filtered_attack_rows(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply the same filtering logic used by /api/attacks/:
    - drop Benign
    """
    if df.empty:
        return df

    # --- SAFETY CHECK FOR KeyError: 'URL' ---
    if "URL" not in df.columns:
        # Return empty DF to prevent crash if file is malformed
        return pd.DataFrame(columns=df.columns)

    df = df.copy()
    # Filter out Benign attacks
    mask = (df["attack_type"] != "Benign")
    return df[mask]


# ============================================================
#  /api/attacks/  – detailed rows for table + donut
# ============================================================
def attacks(request):
    """
    GET /api/attacks/
    """
    csv_path = _get_latest_csv_path()
    if not csv_path:
        return JsonResponse([], safe=False)

    try:
        df = pd.read_csv(csv_path).fillna("")
    except Exception:
        return JsonResponse([], safe=False)

    df_attacks = _filtered_attack_rows(df)

    records = []
    for idx, row in df_attacks.iterrows():

        # ===== BASE FIELDS =====
        attack_type = row.get("attack_type", "Benign")
        src_ip = row.get("Source_IP", "")
        url = row.get("URL", "")
        timestamp = row.get("Timestamp", "")
        dest_ip = row.get("Dest_IP", "-")
        method = row.get("Method", "GET")
        body = row.get("POST_Body", "")

        # NEW → Byte-Size (works for POST body)
        byte_size = row.get("Byte_Size", 0)
        if byte_size in ["", None, 0]:
            byte_size = len(body.encode())      # calculate if missing

        # ===== STATUS CODE FIX =====
        raw_status = row.get("Status_Code", 0)
        try:
            status_code = int(float(str(raw_status))) if raw_status != "" else 0
        except:
            status_code = 0

        base_stage = (
            "Successful" if 200 <= status_code < 300
            else "Unknown" if status_code == 0
            else "Blocked"
        )

        # ========== CUSTOM BODY-BASED LOGIC ==========
        custom_stage = base_stage
        evidence = ""

        atk = attack_type.lower()

        # --- SQL Injection ---
        if atk == "sql injection":
            evidence = f"SQLi payload size: {byte_size} bytes"
            custom_stage = "Successful" if byte_size > 30 else "Blocked"

        # --- XSS Detection ---
        elif atk == "xss":
            import re
            script = re.search(r"<script.*?</script>", body, re.I | re.S)
            if script:
                evidence = f"XSS script extracted: {script.group(0)[:100]}..."
                custom_stage = "Successful"
            else:
                evidence = "XSS markers detected"
                custom_stage = "Blocked"

        # --- Directory Traversal ---
        elif atk in ["directory traversal", "path traversal"]:
            traversal_patterns = ["../", "..\\", "%2e", "%2f", "/etc/passwd", "C:\\windows\\system32"]
            if any(p.lower() in body.lower() for p in traversal_patterns):
                evidence = f"Traversal attempt found in POST body ({body[:80]}...)"
                custom_stage = "Successful"
            else:
                evidence = "Traversal payload missing"
                custom_stage = "Blocked"

        # --- WebShell Upload ---
        elif atk == "webshell":
            if method.upper() in ["POST", "PUT"] and len(body) > 10:
                evidence = f"Possible webshell upload ({len(body)} bytes)"
                custom_stage = "Successful"
            else:
                evidence = "Suspicious method but insufficient payload"
                custom_stage = "Blocked"

        # --- OTHER ATTACK TYPES (Fallback) ---
        else:
            evidence = row.get("evidence", "Pattern match detected")
            custom_stage = base_stage

        # ======== SEVERITY ========
        severity = _severity_for_attack(
            attack_type,
            url,
            custom_stage == "Successful",
            1
        )

        # ======== FINAL OBJECT ========
        records.append({
            "id": int(idx) + 1,
            "timestamp": timestamp,
            "ip": src_ip,
            "dest_ip": dest_ip,
            "method": method,
            "post_body": body,
            "target": url,
            "type": attack_type,
            "severity": severity,
            "status_code": status_code if status_code > 0 else "N/A",
            "status": custom_stage,
            "result": custom_stage,
            "url": url,
            "evidence": evidence,
            "byte_size": byte_size,     # <--- INCLUDED
        })

    return JsonResponse(records, safe=False)


# ============================================================
#  /api/stats/  – cards at top of dashboard
# ============================================================

def stats(request):
    """
    GET /api/stats/
    Reflects the exact numbers from threat_analyzer.py
    """
    csv_path = _get_latest_csv_path()
    if not csv_path:
        return JsonResponse({
            "total": 0,
            "threats": 0,
            "breaches": 0,
            "health": 100,
            "breakdown": {},
        })

    try:
        df = pd.read_csv(csv_path).fillna("")
    except Exception:
        # Return empty stats if file read fails
        return JsonResponse({
            "total": 0, "threats": 0, "breaches": 0, "health": 100, "breakdown": {},
        })

    # 1. TOTAL RECORDS
    total = len(df)

    # 2. THREATS
    # logic: count any row where attack_type is NOT 'Benign'
    if "attack_type" in df.columns:
        df_threats = df[df["attack_type"] != "Benign"].copy()
    else:
        df_threats = pd.DataFrame()
        
    threats = len(df_threats)

    # 3. BREACHES (Critical Fix)
    # Only count as a breach if the Status Code indicates success (200-299)
    breaches = 0
    # FIX: Ensure columns exist before filtering
    if not df_threats.empty and "Status_Code" in df_threats.columns:
        df_threats["Status_Code"] = pd.to_numeric(
            df_threats["Status_Code"],
            errors='coerce'
        ).fillna(0).astype(int)

        breach_types = {
            "Command Injection", "SSRF", "Directory Traversal / LFI",
            "Remote File Inclusion (RFI)", "Shell Upload Attempt", "Bruteforce Attack",
        }

        # Filter: Critical Attack Type AND Successful HTTP Response (200 OK, 201 Created, etc.)
        active_breaches = df_threats[
            (df_threats["attack_type"].isin(breach_types)) &
            (df_threats["Status_Code"] >= 200) &
            (df_threats["Status_Code"] < 300)
        ]
        breaches = len(active_breaches)

    # 4. HEALTH CALCULATION
    if total == 0:
        health = 100
    else:
        risk = min(100, int((threats / total) * 100))
        health = max(0, 100 - risk)

    # 5. DETAILED BREAKDOWN by detection method
    breakdown = {}
    if not df_threats.empty:
        breakdown = df_threats.get('detection_method', pd.Series(dtype=str)).value_counts().to_dict()

    return JsonResponse({
        "total": int(total),
        "threats": int(threats),
        "breaches": int(breaches),
        "health": int(health),
        "breakdown": breakdown,
    })


# ============================================================
#  /api/traffic/  – aggregated data for AttackMap
# ============================================================

def traffic(request):
    """
    GET /api/traffic/
    Return time-series data for the AttackMap (AreaChart).
    Groups attacks by time intervals (e.g., Seconds/Minutes) to show traffic spikes.
    """
    csv_path = _get_latest_csv_path()
    if not csv_path:
        return JsonResponse([], safe=False)

    try:
        df = pd.read_csv(csv_path).fillna("")
    except Exception:
        return JsonResponse([], safe=False)

    # Filter out noise (Uses the robust function now)
    df_attacks = _filtered_attack_rows(df)

    if df_attacks.empty:
        return JsonResponse([], safe=False)

    # --- TIME SERIES LOGIC ---
    try:
        # Safety: Check if Timestamp exists
        if "Timestamp" not in df_attacks.columns:
             return JsonResponse([], safe=False)

        # Convert Timestamp column to datetime objects
        # We assume timestamp is Unix float (from Scapy) or standard string
        # 'coerce' handles errors gracefully
        df_attacks['dt'] = pd.to_datetime(
            df_attacks['Timestamp'],
            unit='s',
            errors='coerce'
        )

        # Drop rows where timestamp couldn't be parsed
        df_attacks = df_attacks.dropna(subset=['dt'])

        if df_attacks.empty:
            return JsonResponse([], safe=False)

        # Resample/Group by 1-second intervals
        timeline = (
            df_attacks.set_index('dt')
            .resample('s')['attack_type']
            .count()
            .reset_index(name='attacks')
        )

        # Format for Frontend
        data = []
        for _, row in timeline.iterrows():
            data.append({
                # Format time as HH:MM:SS for the X-Axis
                "time": row['dt'].strftime('%H:%M:%S'),
                "attacks": int(row['attacks'])
            })

        return JsonResponse(data, safe=False)

    except Exception as e:
        print(f"Error generating traffic chart: {e}")
        return JsonResponse([], safe=False)


# ============================================================
#  /api/explain/  – per-attack BERT XAI explanation
# ============================================================

@csrf_exempt
def analyze_attack(request):
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    try:
        data = json.loads(request.body)
        
        # Extract data from frontend request
        attack_data = data.get('attack_data') # The payload (e.g., <script>...)
        attack_type = data.get('attack_type') # The label (e.g., "XSS")

        if not attack_data or not attack_type:
            return JsonResponse({"error": "Missing attack_data or attack_type"}, status=400)

        # 1. Get Visual Explanation (Captum / SecBERT)
        # Note: We pass attack_type now so SecBERT knows which class output to analyze
        explanation = get_explanation(attack_data, attack_type)

        # 2. Get General Advice (Gemma)
        mitigation = get_mitigation_advice(attack_data, attack_type, explanation)

        return JsonResponse({
            "explanation": explanation,
            "mitigation": mitigation,
        })

    except Exception as e:
        print(f"Server Error in analyze_attack: {e}")
        return JsonResponse({"error": str(e)}, status=500)