import pandas as pd
import os
import shutil
from .parsers import parse_pcap_tshark, parse_csv, parse_xml
from .threat_analyzer import run_full_analysis

# ==========================================
# MAIN DISPATCHER
# ==========================================
def analyze_capture_file(file_path):
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    df = pd.DataFrame()

    if ext in ['.pcap', '.pcapng', '.cap']:
        # Check if tshark is installed
        if not shutil.which("tshark"):
            return {"error": "Tshark not found. Please install Wireshark/Tshark to analyze PCAP files."}
            
        # Use the new Tshark parser
        df = parse_pcap_tshark(file_path)
        
    elif ext in ['.csv', '.ipdr', '.txt']:
        df = parse_csv(file_path)
    elif ext in ['.xml']:
        df = parse_xml(file_path)
    else:
        return {"error": f"Unsupported file extension: {ext}"}

    if df.empty:
        return {"error": "Parsed file is empty or no HTTP traffic found."}

    # Run the Threat Analyzer
    # (The dataframe now perfectly matches the structure expected by your analyzer)
    analyzed_df = run_full_analysis(df)
    
    # Return as list of dicts for the View
    return analyzed_df.to_dict(orient='records')