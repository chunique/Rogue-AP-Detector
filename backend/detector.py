"""
rogue_ap_system/backend/detector.py — Extended Detection Engine
Imports the 5 base rules from model.py, adds Rule 6 (Unknown BSSID),
exposes configurable thresholds for the Flask API.
"""

import os
from collections import defaultdict
import pandas as pd

from model import (
    clean_ssid, load_capture,
    detect_ssid_spoofing, detect_mac_inconsistency,
    detect_rssi_anomaly, detect_probe_response_flood,
    detect_mac_timestamp_drift, SEVERITY_SCORE,
)

_DISPLAY = {
    "SSID_SPOOFING":       "SSID Spoofing",
    "MAC_INCONSISTENCY":   "MAC Inconsistency",
    "RSSI_ANOMALY":        "RSSI Anomaly",
    "PROBE_RESP_FLOOD":    "Probe Response Flood",
    "MAC_TIMESTAMP_DRIFT": "MAC Timestamp Drift",
}

def rule_unknown_bssid(df, whitelist):
    if not whitelist:
        return []
    ap = df[df["type"].isin(["Dot11Beacon","Dot11ProbeResp"])]
    findings, seen = [], set()
    for _, row in ap.iterrows():
        b = row["addr2"]
        if b in whitelist or b in seen:
            continue
        seen.add(b)
        findings.append({
            "rule":"Unknown BSSID","severity":"HIGH","ssid":row["SSID"],
            "bssid":b,"bssids":[b],"affected_bssid":b,
            "detail":f"BSSID {b} ('{row['SSID']}') is not in the authorised whitelist",
        })
    return findings

def _norm(f):
    f = dict(f)
    if "affected_bssid" not in f:
        f["affected_bssid"] = f.get("bssid") or (f["bssids"][0] if f.get("bssids") else "unknown")
    f["rule"] = _DISPLAY.get(f["rule"], f["rule"])
    return f

def _verdict(s):
    return "ROGUE" if s >= 5 else ("SUSPICIOUS" if s >= 3 else "LOW RISK")

def run_detection(file_paths, whitelist=None,
                  probe_threshold=3, rssi_z_threshold=2.5, drift_threshold_ms=500):
    wl = set(whitelist) if whitelist else set()
    dfs, load_errors = [], []
    for path in file_paths:
        try:
            dfs.append(load_capture(path))
        except Exception as e:
            load_errors.append({"file": os.path.basename(path), "error": str(e)})

    if not dfs:
        return {"error": "No valid capture files loaded", "load_errors": load_errors}

    df = pd.concat(dfs, ignore_index=True)

    raw = []
    raw += detect_ssid_spoofing(df)
    raw += detect_mac_inconsistency(df)
    raw += detect_rssi_anomaly(df, z_threshold=rssi_z_threshold)
    raw += detect_probe_response_flood(df, threshold=probe_threshold)
    raw += detect_mac_timestamp_drift(df, drift_threshold_ms=drift_threshold_ms)
    raw += rule_unknown_bssid(df, wl)
    all_findings = [_norm(f) for f in raw]

    bssid_data = defaultdict(lambda: {"score":0,"findings":[],"ssids":set()})
    for f in all_findings:
        b = f["affected_bssid"]
        bssid_data[b]["score"] += SEVERITY_SCORE.get(f["severity"], 1)
        bssid_data[b]["findings"].append(f)
        if f.get("ssid"):
            bssid_data[b]["ssids"].add(f["ssid"])

    bssid_scores = dict(sorted({
        bssid: {
            "bssid":bssid,"score":d["score"],"verdict":_verdict(d["score"]),
            "ssids":list(d["ssids"]),"finding_count":len(d["findings"]),"findings":d["findings"],
        }
        for bssid,d in bssid_data.items()
    }.items(), key=lambda x: -x[1]["score"]))

    ap = df[df["type"].isin(["Dot11Beacon","Dot11ProbeResp"])]
    rc = defaultdict(int)
    sc = {"HIGH":0,"MEDIUM":0,"LOW":0}
    for f in all_findings:
        rc[f["rule"]] += 1
        sc[f["severity"]] = sc.get(f["severity"],0)+1

    stats = {
        "total_frames":      len(df),
        "capture_files":     len(file_paths),
        "unique_bssids":     ap["addr2"].nunique(),
        "unique_ssids":      ap[ap["SSID"]!=""]["SSID"].nunique(),
        "total_findings":    len(all_findings),
        "rogue_count":       sum(1 for v in bssid_scores.values() if v["verdict"]=="ROGUE"),
        "suspicious_count":  sum(1 for v in bssid_scores.values() if v["verdict"]=="SUSPICIOUS"),
        "frame_type_counts": df["type"].value_counts().to_dict(),
        "severity_counts":   sc,
    }

    return {
        "bssid_scores": bssid_scores,
        "findings":     all_findings,
        "stats":        stats,
        "rule_counts":  dict(rc),
        "source_files": [os.path.basename(p) for p in file_paths],
        "load_errors":  load_errors,
    }
