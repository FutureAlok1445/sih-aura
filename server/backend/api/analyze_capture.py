import os
import sys

from parsers import pcap_to_dataframe       # ⬅ only import pcap parser
from threat_analyzer import run_full_analysis


def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_capture.py <path-to-file.pcap>")
        sys.exit(1)

    file_path = sys.argv[1]

    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        sys.exit(1)

    ext = os.path.splitext(file_path)[1].lower()

    # Only support pcap and pcapng for now
    if ext not in [".pcap", ".pcapng"]:
        print(f"❌ Unsupported file type: {ext}. Only .pcap or .pcapng supported right now.")
        sys.exit(1)

    print("📌 Extracting traffic from PCAP...")
    df = pcap_to_dataframe(file_path)

    if df.empty:
        print("⚠ No HTTP traffic found in this file.")
        sys.exit(0)

    print("🔍 Running threat analysis...")
    analyzed_df = run_full_analysis(df)

    # Save CSV next to the input pcap
    base, _ = os.path.splitext(file_path)
    out_csv = base + "_analyzed.csv"
    analyzed_df.to_csv(out_csv, index=False)

    print(f"\n✅ Analysis complete. CSV saved to:\n   {out_csv}")
    print("\n📊 Attack Summary:\n")
    print(analyzed_df["attack_type"].value_counts())


if __name__ == "__main__":
    main()