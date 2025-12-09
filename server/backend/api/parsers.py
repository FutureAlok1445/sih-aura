import pandas as pd
from scapy.all import rdpcap, IP, TCP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
import os

def pcap_to_dataframe(pcap_path):
    """
    Reads a PCAP file using Scapy and correlates Requests with Responses.
    Captures Method, Body, Dest IP, etc.
    """
    if not os.path.exists(pcap_path):
        return pd.DataFrame()

    try:
        packets = rdpcap(pcap_path)
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

        # --- 1. HANDLE HTTP REQUESTS ---
        if pkt.haslayer(HTTPRequest):
            http = pkt[HTTPRequest]
            
            # Extract fields
            method = http.Method.decode('utf-8', errors='ignore') if http.Method else "GET"
            host = http.Host.decode('utf-8', errors='ignore') if http.Host else ""
            path = http.Path.decode('utf-8', errors='ignore') if http.Path else ""
            url = f"http://{host}{path}" if host else path

            # Extract Body
            body = ""
            if pkt.haslayer(Raw):
                try:
                    load = pkt[Raw].load.decode('utf-8', errors='ignore')
                    if "\r\n\r\n" in load:
                        body = load.split("\r\n\r\n", 1)[1]
                    else:
                        # Fallback for some packets where Raw is just body
                        if not load.startswith(method): 
                            body = load
                except:
                    pass

            key = (src_ip, src_port, dst_ip, dst_port)

            # Store ALL required fields
            pending_requests[key] = {
                "Timestamp": timestamp,
                "Source_IP": src_ip,
                "Dest_IP": dst_ip,        # <--- ADDED
                "Method": method,         # <--- ADDED
                "URL": url,
                "POST_Body": body.strip(),
                "Status_Code": "" 
            }

        # --- 2. HANDLE HTTP RESPONSES ---
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

    # Add unmatched requests
    for req in pending_requests.values():
        data_rows.append(req)

    df = pd.DataFrame(data_rows)

    # Ensure columns exist
    required_cols = ["Timestamp", "Source_IP", "Dest_IP", "Method", "URL", "POST_Body", "Status_Code"]
    for col in required_cols:
        if col not in df.columns:
            df[col] = ""

    return df