import pandas as pd
import os
import xml.etree.ElementTree as ET

# Safety check for Scapy (required for PCAP)
SCAPY_AVAILABLE = False
try:
    from scapy.all import rdpcap, IP, TCP, Raw
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    pass

from .threat_analyzer import run_full_analysis

# ==========================================
# 1. PCAP PARSER (Converts Binary -> DataFrame)
# ==========================================
def parse_pcap(file_path):
    if not SCAPY_AVAILABLE:
        return pd.DataFrame()
        
    if not os.path.exists(file_path):
        return pd.DataFrame()

    try:
        packets = rdpcap(file_path)
    except Exception as e:
        print(f"Error reading PCAP: {e}")
        return pd.DataFrame()

    data_rows = []
    pending_requests = {}

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        timestamp = float(pkt.time)

        if pkt.haslayer(HTTPRequest):
            http = pkt[HTTPRequest]
            host = http.Host.decode('utf-8', errors='ignore') if http.Host else ""
            path = http.Path.decode('utf-8', errors='ignore') if http.Path else ""
            url = f"http://{host}{path}" if host else path
            
            body = ""
            if pkt.haslayer(Raw):
                try:
                    load = pkt[Raw].load.decode('utf-8', errors='ignore')
                    if "\r\n\r\n" in load:
                        body = load.split("\r\n\r\n", 1)[1]
                    else:
                        body = load
                except:
                    pass

            key = (src_ip, src_port, dst_ip, dst_port)
            pending_requests[key] = {
                "Timestamp": timestamp,
                "Source_IP": src_ip,
                "URL": url,
                "POST_Body": body.strip(),
                "Status_Code": 0 
            }

        elif pkt.haslayer(HTTPResponse):
            match_key = (dst_ip, dst_port, src_ip, src_port)
            if match_key in pending_requests:
                try:
                    sc = pkt[HTTPResponse].Status_Code
                    status_code = int(sc.decode()) if hasattr(sc, 'decode') else int(sc)
                except:
                    status_code = 0
                
                req_data = pending_requests.pop(match_key)
                req_data["Status_Code"] = status_code
                data_rows.append(req_data)

    for req in pending_requests.values():
        data_rows.append(req)

    return pd.DataFrame(data_rows)

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
            "Status_Code": ["status", "status_code", "sc-status", "code"]
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
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        data_rows = []
        
        tag_mapping = {
            "Timestamp": ["Time", "Date", "Timestamp"],
            "Source_IP": ["SrcIP", "SourceIP", "ClientIP"],
            "URL": ["Url", "Uri", "Request"],
            "POST_Body": ["Body", "Payload"],
            "Status_Code": ["Status", "Code"]
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

# ==========================================
# 4. MAIN DISPATCHER
# ==========================================
def analyze_capture_file(file_path):
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    df = pd.DataFrame()

    if ext in ['.pcap', '.pcapng', '.cap']:
        if not SCAPY_AVAILABLE:
            return {"error": "Server missing Scapy. Cannot parse PCAP."}
        df = parse_pcap(file_path)
    elif ext in ['.csv', '.ipdr', '.txt']:
        df = parse_csv(file_path)
    elif ext in ['.xml']:
        df = parse_xml(file_path)
    else:
        return {"error": f"Unsupported file extension: {ext}"}

    if df.empty:
        return {"error": "Parsed file is empty."}

    # Run the Threat Analyzer
    analyzed_df = run_full_analysis(df)
    
    # Return as list of dicts for the View
    return analyzed_df.to_dict(orient='records')