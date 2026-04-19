"""
detection_validator.py — Validate detection rules against Belgian train station dataset

This script analyzes the detection findings to:
- Validate each detection rule against real traffic
- Provide statistics for research documentation
- Identify true positives vs potential false positives

Usage:
    python detection_validator.py
"""

import warnings
import os
import sys
import pandas as pd
import numpy as np

warnings.filterwarnings('ignore')

DATASET_DIR = os.path.join(os.path.dirname(__file__), "..", "datasets")


def load_dataset():
    """Load both capture files."""
    df1 = pd.read_csv(os.path.join(DATASET_DIR, "1", "capture-1.csv"))
    df2 = pd.read_csv(os.path.join(DATASET_DIR, "2", "capture-2.csv"))
    df = pd.concat([df1, df2], ignore_index=True)
    return df, df1, df2


def validate_ssid_spoofing(df, findings):
    """Validate SSID Spoofing detections."""
    print("\n" + "="*60)
    print("RULE 1: SSID SPOOFING VALIDATION")
    print("="*60)
    
    ap_frames = df[df["type"].isin(["Dot11Beacon", "Dot11ProbeResp"]) & (df["SSID"] != "")]
    ssid_bssid = ap_frames.groupby("SSID")["addr2"].nunique()
    multi_bssid_ssids = ssid_bssid[ssid_bssid > 1]
    
    print(f"\nTotal SSIDs with multiple BSSIDs: {len(multi_bssid_ssids)}")
    print(f"Detection findings: {len([f for f in findings if 'SSID' in f.get('rule', '')])}")
    
    print("\n--- SSIDs with Multiple BSSIDs ---")
    for ssid in multi_bssid_ssids.index[:10]:
        bssids = ap_frames[ap_frames["SSID"] == ssid]["addr2"].unique()
        print(f"\n  SSID: {ssid}")
        print(f"  BSSIDs ({len(bssids)}):")
        for b in bssids[:5]:
            count = len(ap_frames[ap_frames["addr2"] == b])
            print(f"    - {b} ({count} frames)")
        if len(bssids) > 5:
            print(f"    ... and {len(bssids) - 5} more")
    
    return {
        "total_spoofed_ssids": len(multi_bssid_ssids),
        "ssid_details": {str(s): int(v) for s, v in multi_bssid_ssids.items()}
    }


def validate_mac_inconsistency(df, findings):
    """Validate MAC Address Inconsistency detections."""
    print("\n" + "="*60)
    print("RULE 2: MAC ADDRESS INCONSISTENCY VALIDATION")
    print("="*60)
    
    ap_frames = df[df["type"].isin(["Dot11Beacon", "Dot11ProbeResp"])]
    total_frames = len(ap_frames)
    consistent = len(ap_frames[ap_frames["addr2"] == ap_frames["addr3"]])
    inconsistent = len(ap_frames[ap_frames["addr2"] != ap_frames["addr3"]])
    
    print(f"\nTotal Beacon/ProbeResp frames: {total_frames:,}")
    print(f"  Consistent (addr2 == addr3): {consistent:,} ({100*consistent/total_frames:.2f}%)")
    print(f"  Inconsistent (addr2 != addr3): {inconsistent:,} ({100*inconsistent/total_frames:.2f}%)")
    print(f"\nDetection findings: {len([f for f in findings if 'MAC' in f.get('rule', '') and 'Inconsistency' in f.get('rule', '')])}")
    
    if inconsistent > 0:
        mismatches = ap_frames[ap_frames["addr2"] != ap_frames["addr3"]].head(10)
        print("\n--- Sample Inconsistent Frames ---")
        for _, row in mismatches.iterrows():
            print(f"  {row['addr2']} != {row['addr3']} | {row['type']} | {row['SSID']}")
    
    return {
        "total_frames": total_frames,
        "consistent": consistent,
        "inconsistent": inconsistent,
        "compliance_rate": round(100 * consistent / total_frames, 2)
    }


def validate_rssi_anomaly(df, findings):
    """Validate RSSI Anomaly detections."""
    print("\n" + "="*60)
    print("RULE 3: RSSI ANOMALY VALIDATION")
    print("="*60)
    
    ap_frames = df[df["type"].isin(["Dot11Beacon", "Dot11ProbeResp"])]
    all_rssi = ap_frames["rssi"].dropna()
    
    print(f"\n--- RSSI Distribution ---")
    print(f"  Min: {all_rssi.min()} dBm")
    print(f"  Max: {all_rssi.max()} dBm")
    print(f"  Mean: {all_rssi.mean():.1f} dBm")
    print(f"  Std Dev: {all_rssi.std():.1f} dBm")
    print(f"  Median: {all_rssi.median():.1f} dBm")
    
    print(f"\n--- Percentiles ---")
    for p in [5, 25, 50, 75, 95]:
        print(f"  {p}th: {np.percentile(all_rssi, p):.1f} dBm")
    
    print(f"\nDetection findings: {len([f for f in findings if 'RSSI' in f.get('rule', '')])}")
    
    # Group by BSSID
    bssid_stats = ap_frames.groupby("addr2")["rssi"].agg(['mean', 'std', 'count'])
    anomalous_bssids = bssid_stats[bssid_stats['std'] > 10]
    
    print(f"\nBSSIDs with high RSSI variance (std > 10): {len(anomalous_bssids)}")
    
    return {
        "min": float(all_rssi.min()),
        "max": float(all_rssi.max()),
        "mean": round(float(all_rssi.mean()), 1),
        "std": round(float(all_rssi.std()), 1),
        "median": round(float(all_rssi.median()), 1),
        "percentiles": {p: round(float(np.percentile(all_rssi, p)), 1) for p in [5, 25, 50, 75, 95]}
    }


def validate_probe_response_flood(df, findings):
    """Validate Probe Response Flood detections."""
    print("\n" + "="*60)
    print("RULE 4: PROBE RESPONSE FLOOD VALIDATION")
    print("="*60)
    
    probe_resp = df[df["type"] == "Dot11ProbeResp"]
    bssid_counts = probe_resp.groupby("addr2").size()
    
    print(f"\nTotal ProbeResponse frames: {len(probe_resp):,}")
    print(f"Unique responding BSSIDs: {len(bssid_counts)}")
    
    print(f"\n--- ProbeResponse Distribution ---")
    print(f"  Min per BSSID: {bssid_counts.min()}")
    print(f"  Max per BSSID: {bssid_counts.max()}")
    print(f"  Mean per BSSID: {bssid_counts.mean():.1f}")
    
    # Threshold analysis
    threshold = 3
    flooding = bssid_counts[bssid_counts > threshold]
    print(f"\nBSSIDs with > {threshold} ProbeResp: {len(flooding)}")
    
    print("\n--- Top ProbeResponse Senders ---")
    for bssid, count in bssid_counts.nlargest(10).items():
        ssids = probe_resp[probe_resp["addr2"] == bssid]["SSID"].unique()
        ssid_str = ", ".join([str(s)[:20] for s in ssids[:3]])
        print(f"  {bssid}: {count} responses | {ssid_str}")
    
    print(f"\nDetection findings: {len([f for f in findings if 'Probe' in f.get('rule', '')])}")
    
    return {
        "total_frames": len(probe_resp),
        "unique_bssids": len(bssid_counts),
        "flooding_bbsids": len(flooding),
        "max_count": int(bssid_counts.max())
    }


def validate_unknown_bssid(df, whitelist):
    """Validate Unknown BSSID detections."""
    print("\n" + "="*60)
    print("RULE 5: UNKNOWN BSSID VALIDATION")
    print("="*60)
    
    ap_frames = df[df["type"].isin(["Dot11Beacon", "Dot11ProbeResp"])]
    unique_bssids = ap_frames["addr2"].unique()
    
    known = set()
    unknown = set()
    
    for bssid in unique_bssids:
        if bssid in whitelist:
            known.add(bssid)
        else:
            unknown.add(bssid)
    
    print(f"\nTotal unique BSSIDs: {len(unique_bssids)}")
    print(f"  Known (in whitelist): {len(known)}")
    print(f"  Unknown (not in whitelist): {len(unknown)}")
    
    print("\n--- Sample Unknown BSSIDs ---")
    for bssid in list(unknown)[:10]:
        frames = ap_frames[ap_frames["addr2"] == bssid]
        ssids = frames["SSID"].unique()
        print(f"  {bssid}: {len(frames)} frames | SSIDs: {', '.join([str(s)[:15] for s in ssids[:3]])}")
    
    return {
        "total_bssids": len(unique_bssids),
        "known": len(known),
        "unknown": len(unknown)
    }


def validate_timestamp_drift(df, findings):
    """Validate MAC Timestamp Drift detections."""
    print("\n" + "="*60)
    print("RULE 6: MAC TIMESTAMP DRIFT VALIDATION")
    print("="*60)
    
    beacons = df[df["type"] == "Dot11Beacon"].copy()
    beacons = beacons.sort_values(["addr2", "Timestamp"])
    
    total_checks = 0
    drift_count = 0
    threshold_ms = 500
    
    print(f"\nMAC Timestamp Drift Threshold: {threshold_ms} ms")
    print(f"Detection findings: {len([f for f in findings if 'Timestamp' in f.get('rule', '')])}")
    
    for bssid, group in beacons.groupby("addr2"):
        if len(group) < 2:
            continue
        
        mac_ts = group["MAC_timestamp"].values
        wall_ts = group["Timestamp"].values
        
        for i in range(1, min(len(mac_ts), 10)):
            wall_delta_ms = (wall_ts[i] - wall_ts[i-1]) * 1000
            mac_delta_ms = (mac_ts[i] - mac_ts[i-1]) / 1000
            
            if wall_delta_ms <= 0:
                continue
            
            drift_ms = abs(mac_delta_ms - wall_delta_ms)
            total_checks += 1
            
            if drift_ms > threshold_ms:
                drift_count += 1
    
    if total_checks > 0:
        print(f"\nFrames checked: {total_checks}")
        print(f"Drift violations: {drift_count} ({100*drift_count/total_checks:.2f}%)")
    else:
        print("\nNo valid frame pairs to analyze")
    
    return {
        "frames_checked": total_checks,
        "violations": drift_count
    }


def main():
    print("="*60)
    print("ROGUE AP DETECTION VALIDATION REPORT")
    print("Belgian Train Station Dataset")
    print("="*60)
    
    # Load dataset
    print("\nLoading dataset...")
    df, df1, df2 = load_dataset()
    print(f"Total frames: {len(df):,}")
    print(f"  Capture 1: {len(df1):,} frames")
    print(f"  Capture 2: {len(df2):,} frames")
    
    # Import detection system
    sys.path.insert(0, os.path.dirname(__file__))
    from detector import run_detection
    from database import whitelist_bssids
    
    wl = whitelist_bssids()
    print(f"Whitelist entries: {len(wl)}")
    
    # Run detection
    print("\nRunning detection...")
    result = run_detection(
        [os.path.join(DATASET_DIR, "1", "capture-1.csv"),
         os.path.join(DATASET_DIR, "2", "capture-2.csv")],
        list(wl)
    )
    
    findings = result["findings"]
    
    # Run validations
    v1 = validate_ssid_spoofing(df, findings)
    v2 = validate_mac_inconsistency(df, findings)
    v3 = validate_rssi_anomaly(df, findings)
    v4 = validate_probe_response_flood(df, findings)
    v5 = validate_unknown_bssid(df, wl)
    v6 = validate_timestamp_drift(df, findings)
    
    # Summary
    print("\n" + "="*60)
    print("VALIDATION SUMMARY")
    print("="*60)
    print(f"""
| Rule                    | Findings | Key Metric              |
|-------------------------|----------|-------------------------|
| SSID Spoofing           | {len([f for f in findings if 'SSID' in f.get('rule', '')]):>8} | {v1['total_spoofed_ssids']} SSIDs w/ multiple BSSIDs |
| MAC Inconsistency       | {len([f for f in findings if 'Inconsistency' in f.get('rule', '')]):>8} | {v2['compliance_rate']}% compliant frames |
| RSSI Anomaly            | {len([f for f in findings if 'RSSI' in f.get('rule', '')]):>8} | Std: {v3['std']} dBm |
| Probe Response Flood    | {len([f for f in findings if 'Probe' in f.get('rule', '')]):>8} | {v4['flooding_bbsids']} flooding BSSIDs |
| Unknown BSSID           | {len([f for f in findings if 'Unknown' in f.get('rule', '')]):>8} | {v5['unknown']} unlisted BSSIDs |
| Timestamp Drift         | {len([f for f in findings if 'Timestamp' in f.get('rule', '')]):>8} | {v6['violations']} violations |
""")
    
    # Save report
    report_path = os.path.join(os.path.dirname(__file__), "..", "validation_report.txt")
    with open(report_path, "w") as f:
        f.write(f"Rogue AP Detection Validation Report\n")
        f.write(f"Generated: Validation run\n")
        f.write(f"Dataset: Belgian Train Station\n")
        f.write(f"Frames: {len(df):,}\n\n")
        f.write(f"Results:\n")
        f.write(f"  Rogue APs: {result['stats']['rogue_count']}\n")
        f.write(f"  Suspicious: {result['stats']['suspicious_count']}\n")
        f.write(f"  Total Findings: {result['stats']['total_findings']}\n")
    
    print(f"\nValidation report saved to: {report_path}")


if __name__ == "__main__":
    main()
