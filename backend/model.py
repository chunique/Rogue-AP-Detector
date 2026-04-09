"""
rogue_ap_system/backend/model.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Rogue Access Point Detection Model
Based on: "Rogue Access Point Detection Using Wireless Network Scanning
           with Signature Analysis"
Student:  Silvia Muthoni Munene | CT206/109336/22
MUST — Bachelor of Science in Computer Security and Forensics
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This module is the ORIGINAL standalone detection model — the first artefact
built for the project. It can be run directly from the command line:

    python model.py capture-1.csv capture-2.csv

It is also imported by detector.py (the extended engine) which adds the
Unknown-BSSID whitelist rule and the structured output format used by the
Flask API and the PDF report generator.

Detection strategies implemented
────────────────────────────────
1. SSID Spoofing Detection  — same SSID broadcast by multiple distinct MACs
2. MAC Inconsistency Check  — addr2 ≠ addr3 in Beacon/ProbeResp frames
3. RSSI Variance Analysis   — ML-based anomaly detection (Isolation Forest + Z-score)
4. Probe Response Flood    — excessive ProbeResp from same source (honeypot)
5. MAC Timestamp Drift     — implausible MAC-layer clock jumps between frames

Risk scoring
────────────
  HIGH   = 3 points   → ROGUE (HIGH CONFIDENCE) when total ≥ 5
  MEDIUM = 2 points   → SUSPICIOUS              when total ≥ 3
  LOW    = 1 point    → LOW RISK                when total < 3
"""

import os
import sys
import pandas as pd
import numpy as np
from collections import defaultdict
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor


# ── SSID normalisation ──────────────────────────────────────────────────────────

def clean_ssid(raw):
    """Strip Scapy's  b'...'  wrapper and return a plain string."""
    if pd.isna(raw):
        return ""
    s = str(raw).strip()
    for prefix in ("b'", 'b"'):
        if s.startswith(prefix):
            s = s[2:-1]
    return s


# ── Data loading ────────────────────────────────────────────────────────────────

def load_capture(filepath):
    """
    Load a single CSV wireless capture file into a normalised DataFrame.

    Expected columns:
        Timestamp, type, MAC_timestamp, rssi, addr1, addr2, addr3, SSID
    """
    df = pd.read_csv(filepath)
    df.columns = df.columns.str.strip()
    df["SSID"]          = df["SSID"].apply(clean_ssid)
    df["Timestamp"]     = pd.to_numeric(df["Timestamp"],     errors="coerce")
    df["rssi"]          = pd.to_numeric(df["rssi"],          errors="coerce")
    df["MAC_timestamp"] = pd.to_numeric(df["MAC_timestamp"], errors="coerce")
    df["source_file"]   = os.path.basename(filepath)
    return df


# ── Detection rules ─────────────────────────────────────────────────────────────

def detect_ssid_spoofing(df):
    """
    Rule 1 — SSID Spoofing  (Severity: HIGH)

    Flag every SSID that is advertised by more than one distinct BSSID across
    all capture files.  A legitimate ESS may have multiple APs sharing an SSID,
    but an *unknown* BSSID suddenly advertising a known campus SSID is the
    classic evil-twin signature.
    """
    ap_frames = df[
        df["type"].isin(["Dot11Beacon", "Dot11ProbeResp"]) & (df["SSID"] != "")
    ]
    ssid_to_bssids = ap_frames.groupby("SSID")["addr2"].nunique()
    spoofed = ssid_to_bssids[ssid_to_bssids > 1].index.tolist()

    findings = []
    for ssid in spoofed:
        bssids = ap_frames[ap_frames["SSID"] == ssid]["addr2"].unique().tolist()
        findings.append({
            "rule":     "SSID_SPOOFING",
            "severity": "HIGH",
            "ssid":     ssid,
            "bssids":   bssids,
            "detail":   (
                f"SSID '{ssid}' is broadcast by {len(bssids)} distinct BSSIDs: "
                f"{bssids}"
            ),
        })
    return findings


def detect_mac_inconsistency(df):
    """
    Rule 2 — MAC Address Inconsistency  (Severity: HIGH)

    In Beacon and ProbeResponse frames the transmitter address (addr2) MUST
    equal the BSSID field (addr3).  A mismatch is a direct indicator of frame
    injection or MAC address spoofing — a hallmark of rogue AP deployment.
    """
    ap_frames = df[df["type"].isin(["Dot11Beacon", "Dot11ProbeResp"])]
    mismatch  = ap_frames[ap_frames["addr2"] != ap_frames["addr3"]]

    findings = []
    for _, row in mismatch.iterrows():
        findings.append({
            "rule":     "MAC_INCONSISTENCY",
            "severity": "HIGH",
            "ssid":     row["SSID"],
            "bssid":    row["addr2"],
            "bssids":   [row["addr2"]],
            "detail":   (
                f"Frame transmitter ({row['addr2']}) ≠ BSSID ({row['addr3']}) "
                f"for SSID '{row['SSID']}' at t={row['Timestamp']:.3f}"
            ),
        })
    return findings


def detect_rssi_anomaly(df, z_threshold=2.5):
    """
    Rule 3 — RSSI Variance Anomaly  (Severity: MEDIUM)

    Uses ML-based anomaly detection combining:
    1. Isolation Forest - unsupervised ML that isolates anomalies in feature space
    2. Local Outlier Factor (LOF) - density-based anomaly detection
    3. Z-score fallback - traditional statistical method

    Physical interpretation: a rogue AP placed unusually close to the scanning
    device will exhibit a dramatically stronger (less negative) RSSI than the
    legitimate AP it is impersonating.
    """
    ap_frames = df[df["type"].isin(["Dot11Beacon", "Dot11ProbeResp"])].copy()
    ap_frames = ap_frames.reset_index(drop=True)

    findings = []
    for bssid, group in ap_frames.groupby("addr2"):
        if len(group) < 3:
            continue

        rssi_values = group["rssi"].values.reshape(-1, 1)
        mean_rssi = group["rssi"].mean()
        std_rssi  = group["rssi"].std()

        if std_rssi < 1e-6:
            continue

        z_scores_arr  = np.abs((group["rssi"].values - mean_rssi) / std_rssi)
        anomalous_z = z_scores_arr > z_threshold

        ml_anomaly = np.zeros(len(group), dtype=bool)
        if len(group) >= 10:
            try:
                iso_forest = IsolationForest(
                    contamination=0.1,
                    random_state=42,
                    n_estimators=100
                )
                iso_pred = iso_forest.fit_predict(rssi_values)
                ml_anomaly |= (iso_pred == -1)
            except Exception:
                pass

            try:
                lof = LocalOutlierFactor(n_neighbors=min(5, len(group)-1), contamination=0.1)
                lof_pred = lof.fit_predict(rssi_values)
                ml_anomaly |= (lof_pred == -1)
            except Exception:
                pass

        combined_anomaly = anomalous_z | ml_anomaly

        for idx, (_, row) in enumerate(group.iterrows()):
            if combined_anomaly[idx]:
                dev = abs(row['rssi'] - mean_rssi)
                detection_type = []
                if anomalous_z[idx]:
                    detection_type.append('z-score')
                if ml_anomaly[idx]:
                    detection_type.append('ML')
                findings.append({
                    "rule":      "RSSI_ANOMALY",
                    "severity":  "MEDIUM",
                    "ssid":      row["SSID"],
                    "bssid":     bssid,
                    "bssids":    [bssid],
                    "rssi":      row["rssi"],
                    "mean_rssi": round(mean_rssi, 2),
                    "detail":    (
                        f"BSSID {bssid} ('{row['SSID']}') RSSI={row['rssi']} dBm "
                        f"deviates {dev:.1f} dBm from mean {mean_rssi:.1f} dBm "
                        f"(detected by: {', '.join(detection_type)})"
                    ),
                })
    return findings


def detect_probe_response_flood(df, threshold=3):
    """
    Rule 4 — Probe Response Flood  (Severity: MEDIUM)

    A rogue AP operating as a honeypot eagerly responds to every ProbeRequest
    it overhears.  Any BSSID that sends more than *threshold* ProbeResponse
    frames within a single capture window is flagged as exhibiting honeypot
    behaviour.
    """
    probe_resp = df[df["type"] == "Dot11ProbeResp"]
    counts     = probe_resp.groupby("addr2").size()
    flooded    = counts[counts > threshold]

    findings = []
    for bssid, count in flooded.items():
        ssids = probe_resp[probe_resp["addr2"] == bssid]["SSID"].unique().tolist()
        findings.append({
            "rule":      "PROBE_RESP_FLOOD",
            "severity":  "MEDIUM",
            "ssid":      ssids[0] if ssids else "",
            "bssid":     bssid,
            "bssids":    [bssid],
            "count":     int(count),
            "detail":    (
                f"BSSID {bssid} sent {count} ProbeResp frames "
                f"(threshold={threshold}); SSIDs: {ssids}"
            ),
        })
    return findings


def detect_mac_timestamp_drift(df, drift_threshold_ms=500):
    """
    Rule 5 — MAC Timestamp Drift  (Severity: LOW)

    The MAC-layer timestamp embedded in Beacon frames should advance at
    approximately the same rate as the system wall clock.  A drift greater than
    drift_threshold_ms milliseconds per frame interval indicates replayed or
    synthetically generated frames — a characteristic of software-defined or
    firmware-spoofed rogue APs.
    """
    ap_frames = (
        df[df["type"] == "Dot11Beacon"]
        .sort_values(["addr2", "Timestamp"])
    )

    findings = []
    for bssid, group in ap_frames.groupby("addr2"):
        if len(group) < 2:
            continue

        mac_ts  = group["MAC_timestamp"].values
        wall_ts = group["Timestamp"].values

        for i in range(1, len(mac_ts)):
            mac_delta_ms  = (mac_ts[i]  - mac_ts[i - 1])  / 1000.0  # µs → ms
            wall_delta_ms = (wall_ts[i] - wall_ts[i - 1]) * 1000     # s  → ms

            if wall_delta_ms <= 0:
                continue

            drift_ms = abs(mac_delta_ms - wall_delta_ms)
            if drift_ms > drift_threshold_ms:
                findings.append({
                    "rule":      "MAC_TIMESTAMP_DRIFT",
                    "severity":  "LOW",
                    "ssid":      group.iloc[i]["SSID"],
                    "bssid":     bssid,
                    "bssids":    [bssid],
                    "drift_ms":  round(drift_ms, 2),
                    "detail":    (
                        f"BSSID {bssid} MAC-timestamp drift={drift_ms:.1f} ms "
                        f"(wall Δ={wall_delta_ms:.1f} ms, "
                        f"MAC Δ={mac_delta_ms:.1f} ms)"
                    ),
                })
    return findings


# ── Scoring & verdict ───────────────────────────────────────────────────────────

SEVERITY_SCORE = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def score_bssids(all_findings):
    """
    Aggregate per-BSSID risk scores across all detection rules.

    Returns
    -------
    dict  bssid → { score, verdict, findings }
    """
    bssid_scores = defaultdict(lambda: {"score": 0, "findings": []})

    for f in all_findings:
        bssids = f.get("bssids") or ([f["bssid"]] if "bssid" in f else [])
        for bssid in bssids:
            bssid_scores[bssid]["score"]    += SEVERITY_SCORE.get(f["severity"], 1)
            bssid_scores[bssid]["findings"].append(f)

    for bssid, data in bssid_scores.items():
        s = data["score"]
        if s >= 5:
            data["verdict"] = "ROGUE (HIGH CONFIDENCE)"
        elif s >= 3:
            data["verdict"] = "SUSPICIOUS"
        else:
            data["verdict"] = "LOW RISK"

    return dict(bssid_scores)


# ── Console report ──────────────────────────────────────────────────────────────

def print_report(bssid_scores, all_findings, capture_files):
    SEP = "=" * 70
    print(f"\n{SEP}")
    print("  ROGUE ACCESS POINT DETECTION REPORT")
    print(f"  Meru University of Science and Technology | CT206/109336/22")
    print(f"  Captures analysed: {', '.join(capture_files)}")
    print(SEP)

    if not bssid_scores:
        print("\n  ✓  No rogue APs detected.\n")
        return

    ranked = sorted(bssid_scores.items(), key=lambda x: x[1]["score"], reverse=True)

    print(f"\n  {'BSSID':<22} {'Score':>5}  Verdict")
    print("  " + "-" * 48)
    for bssid, data in ranked:
        print(f"  {bssid:<22} {data['score']:>5}  {data['verdict']}")

    print(f"\n{SEP}")
    print("  DETAILED FINDINGS")
    print(SEP)

    seen = set()
    for f in all_findings:
        key = (f["rule"], f.get("ssid", ""), f.get("bssid", str(f.get("bssids", ""))))
        if key in seen:
            continue
        seen.add(key)
        print(f"\n  [{f['severity']}] {f['rule']}")
        print(f"    {f['detail']}")

    print(f"\n{SEP}\n")


# ── Main entry point ────────────────────────────────────────────────────────────

def run_model(csv_files):
    """
    Load captures, run all 5 detection rules, score, and print a report.

    Parameters
    ----------
    csv_files : list[str]   Paths to CSV capture files.

    Returns
    -------
    tuple  (bssid_scores dict, all_findings list)
    """
    dfs = []
    for f in csv_files:
        try:
            dfs.append(load_capture(f))
            print(f"  Loaded: {f}  ({len(dfs[-1])} frames)")
        except Exception as e:
            print(f"  ERROR loading {f}: {e}")

    if not dfs:
        print("No valid capture files loaded.")
        return {}, []

    df = pd.concat(dfs, ignore_index=True)
    print(f"  Total frames: {len(df)}\n")

    findings = []
    findings += detect_ssid_spoofing(df)
    findings += detect_mac_inconsistency(df)
    findings += detect_rssi_anomaly(df)
    findings += detect_probe_response_flood(df)
    findings += detect_mac_timestamp_drift(df)

    bssid_scores = score_bssids(findings)
    print_report(bssid_scores, findings, [os.path.basename(f) for f in csv_files])

    return bssid_scores, findings


# ── CLI demo / self-test ────────────────────────────────────────────────────────

if __name__ == "__main__":
    # If CSV paths are passed as arguments, use them
    if len(sys.argv) > 1:
        run_model(sys.argv[1:])
        sys.exit(0)

    # Otherwise run the built-in demo using the original project sample data
    CAPTURE_1 = """Timestamp,type,MAC_timestamp,rssi,addr1,addr2,addr3,SSID
1682624219.462684,Dot11ProbeReq,698923371,-61,ff:ff:ff:ff:ff:ff,00:00:00:00:00:02,ff:ff:ff:ff:ff:ff,b''
1682624219.464591,Dot11Beacon,698926457,-49,ff:ff:ff:ff:ff:ff,00:00:00:00:00:03,00:00:00:00:00:03,b'NETWORK_1'
1682624219.465209,Dot11ProbeResp,698927083,-49,00:00:00:00:00:02,00:00:00:00:00:04,00:00:00:00:00:04,b'NETWORK_2'
1682624219.465514,Dot11ProbeResp,698927392,-49,00:00:00:00:00:02,00:00:00:00:00:05,00:00:00:00:00:05,b'NETWORK_3'
1682624219.466258,Dot11ProbeResp,698928136,-49,00:00:00:00:00:02,00:00:00:00:00:05,00:00:00:00:00:05,b'NETWORK_3'
1682624219.474424,Dot11ProbeResp,698936306,-49,00:00:00:00:00:02,00:00:00:00:00:06,00:00:00:00:00:06,b'NETWORK_4'
1682624219.474800,Dot11ProbeResp,698936666,-49,00:00:00:00:00:02,00:00:00:00:00:06,00:00:00:00:00:06,b'NETWORK_4'
1682624219.477729,Dot11ProbeResp,698939592,-49,00:00:00:00:00:02,00:00:00:00:00:06,00:00:00:00:00:06,b'NETWORK_4'
1682624219.478098,Dot11ProbeResp,698939967,-49,00:00:00:00:00:02,00:00:00:00:00:07,00:00:00:00:00:07,b'NETWORK_5'"""

    CAPTURE_2 = """Timestamp,type,MAC_timestamp,rssi,addr1,addr2,addr3,SSID
1682625745.192307,Dot11Beacon,2224644021,-55,ff:ff:ff:ff:ff:ff,00:00:00:00:00:02,00:00:00:00:00:02,b'NETWORK_1'
1682625745.211212,Dot11Beacon,2224662984,-70,ff:ff:ff:ff:ff:ff,00:00:00:00:00:03,00:00:00:00:00:03,b'NETWORK_2'
1682625745.211763,Dot11Beacon,2224663539,-71,ff:ff:ff:ff:ff:ff,00:00:00:00:00:04,00:00:00:00:00:04,b'NETWORK_1'
1682625745.212021,Dot11Beacon,2224663798,-70,ff:ff:ff:ff:ff:ff,00:00:00:00:00:05,00:00:00:00:00:05,b'NETWORK_3'
1682625745.212303,Dot11Beacon,2224664076,-71,ff:ff:ff:ff:ff:ff,00:00:00:00:00:06,00:00:00:00:00:06,b'NETWORK_4'
1682625745.225779,Dot11Beacon,2224677565,-56,ff:ff:ff:ff:ff:ff,00:00:00:00:00:07,00:00:00:00:00:07,b'NETWORK_3'
1682625745.242444,Dot11Beacon,2224694253,-55,ff:ff:ff:ff:ff:ff,00:00:00:00:00:08,00:00:00:00:00:08,b'NETWORK_2'
1682625745.257874,Dot11ProbeResp,2224709672,-56,00:00:00:00:00:09,00:00:00:00:00:0a,00:00:00:00:00:0a,b'NETWORK_4'
1682625745.258248,Dot11ProbeResp,2224710048,-56,00:00:00:00:00:09,00:00:00:00:00:0a,00:00:00:00:00:0a,b'NETWORK_4'"""

    for name, content in [("/tmp/capture-1.csv", CAPTURE_1),
                           ("/tmp/capture-2.csv", CAPTURE_2)]:
        with open(name, "w") as fh:
            fh.write(content)

    print("\n  Rogue AP Detection Model — built-in demo\n")
    run_model(["/tmp/capture-1.csv", "/tmp/capture-2.csv"])
