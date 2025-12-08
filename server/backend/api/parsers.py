import pandas as pd
from scapy.all import rdpcap, IP, TCP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
import os

def pcap_to_dataframe(pcap_path):
    """
    Reads a PCAP file using Scapy and correlates Requests with Responses
    to capture the Status Code.
    """
    if not os.path.exists(pcap_path):
        print(f"File not found: {pcap_path}")
        return pd.DataFrame()

    try:
        # Read all packets from the file
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"Error reading PCAP with Scapy: {e}")
        return pd.DataFrame()

    data_rows = []

    # Dictionary to store pending requests waiting for a response
    # Key = (Source_IP, Source_Port, Dest_IP, Dest_Port)
    pending_requests = {}

    for pkt in packets:
        # We only care about IP/TCP packets
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

            # Extract basic fields
            method = http.Method.decode('utf-8', errors='ignore') if http.Method else ""
            host = http.Host.decode('utf-8', errors='ignore') if http.Host else ""
            path = http.Path.decode('utf-8', errors='ignore') if http.Path else ""

            url = f"http://{host}{path}" if host else path

            # Extract Body (if present)
            body = ""
            if pkt.haslayer(Raw):
                try:
                    load = pkt[Raw].load.decode('utf-8', errors='ignore')
                    # If headers are included in Raw, split them out
                    if "\r\n\r\n" in load:
                        body = load.split("\r\n\r\n", 1)[1]
                    else:
                        body = load
                except:
                    pass

            # Create a unique key for this flow
            # (Client -> Server)
            key = (src_ip, src_port, dst_ip, dst_port)

            # Save this request to pending dict
            pending_requests[key] = {
                "Timestamp": timestamp,
                "Source_IP": src_ip,
                "URL": url,
                "POST_Body": body.strip(),
                "Status_Code": ""  # Will be filled later
            }

        # --- 2. HANDLE HTTP RESPONSES ---
        elif pkt.haslayer(HTTPResponse):
            # Response goes from Server -> Client
            # So we match using the REVERSE key: (DstIP, DstPort, SrcIP, SrcPort)
            match_key = (dst_ip, dst_port, src_ip, src_port)

            if match_key in pending_requests:
                # We found the original request!

                # Extract status code (e.g., "200", "404")
                try:
                    sc = pkt[HTTPResponse].Status_Code
                    # Scapy might return bytes or string
                    status_code = int(sc.decode()) if hasattr(sc, 'decode') else int(sc)
                except:
                    status_code = 0

                # Update the request
                req_data = pending_requests.pop(match_key)
                req_data["Status_Code"] = status_code

                # Add to final list
                data_rows.append(req_data)

    # --- 3. CLEANUP (Add requests that never got a response) ---
    # This ensures we don't lose data if the capture was cut off
    for req in pending_requests.values():
        data_rows.append(req)

    # Convert to DataFrame
    df = pd.DataFrame(data_rows)

    # Ensure columns exist to prevent "KeyError" later
    required_cols = ["Timestamp", "Source_IP", "URL", "POST_Body", "Status_Code"]
    for col in required_cols:
        if col not in df.columns:
            df[col] = ""

    return df

