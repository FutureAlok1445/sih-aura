import subprocess
import pandas as pd
import os
import sys
import tempfile

# ==========================================
# 1. TSHARK PARSER (Replaces Scapy)
# ==========================================
def parse_pcap_tshark(pcap_path):
    """
    Parses PCAP using Tshark CLI (much faster than Scapy).
    Extracts HTTP fields and correlates Requests/Responses via TCP Stream.
    """
    if not os.path.exists(pcap_path):
        return pd.DataFrame()

    # Tshark command to extract specific fields
    # We use tabs (-E separator=/t) to avoid conflicts with commas in data
    cmd = [
        "tshark",
        "-r", pcap_path,
        "-Y", "http",  # Only filter HTTP packets
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=/t", 
        "-E", "occurrence=f", # Taking first occurrence prevents duplicate field arrays
        "-E", "quote=d",      # Quote data to handle special chars
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "tcp.stream",          # Critical for matching Req/Res
        "-e", "http.request.method",
        "-e", "http.host",
        "-e", "http.request.uri",
        "-e", "http.response.code",
        "-e", "http.file_data"       # The payload/body
    ]

    # temporary file to store tshark output (avoids loading huge strings into RAM)
    with tempfile.TemporaryFile() as temp_out:
        try:
            subprocess.run(cmd, stdout=temp_out, check=True)
            temp_out.seek(0)
            
            # Read into Pandas
            # Handling bad lines/quoting issues that happen in network traffic
            df = pd.read_csv(
                temp_out, 
                sep="\t", 
                on_bad_lines='skip', 
                dtype=str # Read all as string initially to prevent type errors
            )
        except Exception as e:
            print(f"Error running Tshark: {e}")
            return pd.DataFrame()

    if df.empty:
        return pd.DataFrame()

    # --- CLEANUP & RENAMING ---
    df.rename(columns={
        "frame.time_epoch": "Timestamp",
        "ip.src": "Source_IP",
        "ip.dst": "Dest_IP",
        "http.request.method": "Method",
        "http.file_data": "POST_Body",
        "http.response.code": "Status_Code"
    }, inplace=True)

    # Construct Full URL
    df['http.host'] = df['http.host'].fillna('')
    df['http.request.uri'] = df['http.request.uri'].fillna('')
    df['URL'] = df.apply(lambda x: f"http://{x['http.host']}{x['http.request.uri']}" if x['http.host'] else x['http.request.uri'], axis=1)

    # --- CORRELATION LOGIC (The Magic Step) ---
    # Tshark gives rows for Request and rows for Response separately.
    # We group by 'tcp.stream' to merge them.
    
    # 1. Forward Fill: Propagates Method/URL from Request down to Response row
    # 2. Back Fill: Propagates Status Code from Response up to Request row
    # This ensures a single row contains both the malicious URL and the server's response code.
    
    # Convert types for operations
    df['Timestamp'] = pd.to_numeric(df['Timestamp'], errors='coerce')
    
    # Group by stream and fill gaps
    # Note: simple ffill/bfill assumes req/res order. 
    # For a stricter approach, we filter for Method != NaN (The Requests)
    
    # Fill logic:
    # If a row has a Method (Request), it needs the Status_Code from the future (bfill)
    # If a row has a Status (Response), it needs the URL from the past (ffill)
    
    # Optimization: strictly keeping rows that have a Method (Requests)
    # and trying to pull the next Status Code in that stream.
    
    df['Status_Code'] = df.groupby('tcp.stream')['Status_Code'].bfill()
    
    # Filter: Keep only the Request rows (now populated with response codes)
    final_df = df[df['Method'].notna() & (df['Method'] != '')].copy()
    
    # Cleanup empty bodies
    final_df['POST_Body'] = final_df['POST_Body'].fillna('')
    final_df['Status_Code'] = final_df['Status_Code'].fillna(0).astype(int)

    # Select final columns expected by your analyzer
    required_cols = ["Timestamp", "Source_IP", "Dest_IP", "Method", "URL", "POST_Body", "Status_Code"]
    return final_df[required_cols]


# ==========================================
# 2. CSV PARSER (Direct Read)
# ==========================================
def parse_csv(file_path):
    try:
        df = pd.read_csv(file_path)
        
        # Normalize Column Names
        mapping = {
            "Timestamp": ["time", "date", "timestamp", "datetime"],
            "Source_IP": ["src_ip", "source_ip", "client_ip", "c-ip", "ip"],
            "URL": ["url", "request_url", "uri", "path"],
            "POST_Body": ["body", "payload", "content", "data"],
            "Status_Code": ["status", "status_code", "sc-status", "code"],
            "Method": ["method", "verb", "request_method"]
        }
        
        normalized_data = {}
        for target_col, possible_names in mapping.items():
            found = False
            for name in possible_names:
                match = next((col for col in df.columns if col.lower() == name.lower()), None)
                if match:
                    normalized_data[target_col] = df[match]
                    found = True
                    break
            if not found:
                normalized_data[target_col] = "" 
        
        new_df = pd.DataFrame(normalized_data)
        new_df['Status_Code'] = pd.to_numeric(new_df['Status_Code'], errors='coerce').fillna(0).astype(int)
        return new_df

    except Exception as e:
        print(f"Error parsing CSV: {e}")
        return pd.DataFrame()

# ==========================================
# 3. XML PARSER
# ==========================================
def parse_xml(file_path):
    import xml.etree.ElementTree as ET
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        data_rows = []
        
        tag_mapping = {
            "Timestamp": ["Time", "Date", "Timestamp"],
            "Source_IP": ["SrcIP", "SourceIP", "ClientIP"],
            "URL": ["Url", "Uri", "Request"],
            "POST_Body": ["Body", "Payload"],
            "Status_Code": ["Status", "Code"],
            "Method": ["Method", "Verb"]
        }

        for item in root:
            row = {}
            for target_col, tags in tag_mapping.items():
                val = ""
                for tag in tags:
                    found_tag = item.find(tag)
                    if found_tag is not None and found_tag.text:
                        val = found_tag.text
                        break
                row[target_col] = val
            data_rows.append(row)
            
        return pd.DataFrame(data_rows)
    except Exception as e:
        print(f"Error parsing XML: {e}")
        return pd.DataFrame()