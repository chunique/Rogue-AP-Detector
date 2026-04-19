"""
dataset_importer.py — Import and store dataset analysis results in database

This script:
1. Runs detection on dataset captures
2. Stores results in database for historical analysis
3. Tracks BSSID appearances over time

Usage:
    python dataset_importer.py [--dry-run] [--save-frames]
"""

import warnings
import os
import sys
import json
import sqlite3
import pandas as pd
import uuid
from datetime import datetime

warnings.filterwarnings('ignore')

DATASET_DIR = os.path.join(os.path.dirname(__file__), "..", "datasets")
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "rogue_ap.db")


def init_database():
    """Initialize database with required tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create scan_history table if not exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL UNIQUE,
            capture_name TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            total_frames INTEGER,
            unique_bssids INTEGER,
            rogue_count INTEGER,
            suspicious_count INTEGER,
            total_findings INTEGER,
            whitelist_used INTEGER,
            result_json TEXT
        )
    """)
    
    # Create bssid_tracking table if not exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS bssid_tracking (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bssid TEXT NOT NULL,
            ssid TEXT,
            first_seen TEXT,
            last_seen TEXT,
            appearance_count INTEGER DEFAULT 0,
            avg_rssi REAL,
            is_known INTEGER DEFAULT 0,
            UNIQUE(bssid, ssid)
        )
    """)
    
    # Create capture_summaries table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS capture_summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            capture_name TEXT NOT NULL UNIQUE,
            file_path TEXT,
            timestamp TEXT NOT NULL,
            total_frames INTEGER,
            unique_bssids INTEGER,
            unique_ssids INTEGER,
            avg_rssi REAL,
            std_rssi REAL,
            rogue_count INTEGER,
            suspicious_count INTEGER,
            findings_json TEXT
        )
    """)
    
    conn.commit()
    conn.close()
    print("Database tables initialized")


def get_whitelist():
    """Get current whitelist BSSIDs."""
    sys.path.insert(0, os.path.dirname(__file__))
    from database import whitelist_bssids
    return whitelist_bssids()


def run_detection_on_capture(capture_path, whitelist):
    """Run detection on a single capture file."""
    sys.path.insert(0, os.path.dirname(__file__))
    from detector import run_detection
    
    result = run_detection([capture_path], list(whitelist))
    return result


def analyze_capture(capture_path, capture_name, whitelist, save_frames=False):
    """Analyze a single capture and store results."""
    print(f"\nAnalyzing: {capture_name}")
    
    # Load capture
    df = pd.read_csv(capture_path)
    print(f"  Frames: {len(df):,}")
    
    # Basic statistics
    ap_frames = df[df["type"].isin(["Dot11Beacon", "Dot11ProbeResp"])]
    rssi = ap_frames["rssi"].dropna()
    
    stats = {
        "total_frames": len(df),
        "unique_bssids": df["addr2"].nunique(),
        "unique_ssids": ap_frames[ap_frames["SSID"] != ""]["SSID"].nunique(),
        "avg_rssi": rssi.mean() if len(rssi) > 0 else None,
        "std_rssi": rssi.std() if len(rssi) > 0 else None,
    }
    
    # Run detection
    result = run_detection_on_capture(capture_path, whitelist)
    
    print(f"  BSSIDs: {stats['unique_bssids']}")
    print(f"  SSIDs: {stats['unique_ssids']}")
    print(f"  Rogue APs: {result['stats']['rogue_count']}")
    print(f"  Suspicious: {result['stats']['suspicious_count']}")
    print(f"  Findings: {result['stats']['total_findings']}")
    
    return df, stats, result


def store_scan_history(capture_name, stats, result, whitelist):
    """Store scan results in scan_history table."""
    conn = sqlite3.connect(DB_PATH)
    
    scan_id = f"dataset_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    conn.execute("""
        INSERT INTO scan_history 
        (scan_id, capture_name, timestamp, total_frames, unique_bssids, 
         rogue_count, suspicious_count, total_findings, whitelist_used, result_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        capture_name,
        datetime.now().isoformat(),
        stats["total_frames"],
        stats["unique_bssids"],
        result["stats"]["rogue_count"],
        result["stats"]["suspicious_count"],
        result["stats"]["total_findings"],
        len(whitelist),
        json.dumps(result)
    ))
    
    conn.commit()
    conn.close()
    
    return scan_id


def store_bssid_tracking(df, whitelist, scan_timestamp):
    """Track BSSID appearances in bssid_tracking table."""
    conn = sqlite3.connect(DB_PATH)
    
    ap_frames = df[df["type"].isin(["Dot11Beacon", "Dot11ProbeResp"])]
    
    for bssid in ap_frames["addr2"].unique():
        bssid_frames = ap_frames[ap_frames["addr2"] == bssid]
        ssids = bssid_frames["SSID"].dropna().unique()
        ssid = ssids[0] if len(ssids) > 0 else ""
        avg_rssi = bssid_frames["rssi"].mean()
        is_known = 1 if bssid in whitelist else 0
        
        # Check if exists
        existing = conn.execute(
            "SELECT first_seen, appearance_count FROM bssid_tracking WHERE bssid = ? AND ssid = ?",
            (bssid, ssid)
        ).fetchone()
        
        if existing:
            first_seen = existing[0]
            appearance_count = existing[1] + 1
        else:
            first_seen = scan_timestamp
            appearance_count = 1
        
        conn.execute("""
            INSERT OR REPLACE INTO bssid_tracking
            (bssid, ssid, first_seen, last_seen, appearance_count, avg_rssi, is_known)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (bssid, ssid, first_seen, scan_timestamp, appearance_count, avg_rssi, is_known))
    
    conn.commit()
    conn.close()


def store_capture_summary(capture_name, file_path, stats, result):
    """Store capture summary."""
    conn = sqlite3.connect(DB_PATH)
    
    findings_summary = {
        "rule_counts": result.get("rule_counts", {}),
        "severity_counts": result["stats"]["severity_counts"],
        "top_bssids": [
            {"bssid": b, "score": d["score"], "verdict": d["verdict"]}
            for b, d in list(result["bssid_scores"].items())[:10]
        ]
    }
    
    conn.execute("""
        INSERT OR REPLACE INTO capture_summaries
        (capture_name, file_path, timestamp, total_frames, unique_bssids, unique_ssids,
         avg_rssi, std_rssi, rogue_count, suspicious_count, findings_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        capture_name,
        file_path,
        datetime.now().isoformat(),
        stats["total_frames"],
        stats["unique_bssids"],
        stats["unique_ssids"],
        stats["avg_rssi"],
        stats["std_rssi"],
        result["stats"]["rogue_count"],
        result["stats"]["suspicious_count"],
        json.dumps(findings_summary)
    ))
    
    conn.commit()
    conn.close()


def generate_summary_report():
    """Generate summary report from stored data."""
    conn = sqlite3.connect(DB_PATH)
    
    print("\n" + "="*60)
    print("DATASET ANALYSIS SUMMARY")
    print("="*60)
    
    # Scan history
    scans = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
    print(f"\nScans stored: {scans}")
    
    # BSSID tracking
    total_bssids = conn.execute("SELECT COUNT(DISTINCT bssid) FROM bssid_tracking").fetchone()[0]
    known_bssids = conn.execute("SELECT COUNT(*) FROM bssid_tracking WHERE is_known = 1").fetchone()[0]
    unknown_bssids = conn.execute("SELECT COUNT(*) FROM bssid_tracking WHERE is_known = 0").fetchone()[0]
    
    print(f"\nBSSID Tracking:")
    print(f"  Total unique BSSIDs: {total_bssids}")
    print(f"  Known (whitelisted): {known_bssids}")
    print(f"  Unknown: {unknown_bssids}")
    
    # Capture summaries
    captures = conn.execute("SELECT * FROM capture_summaries").fetchall()
    print(f"\nCapture Summaries:")
    for c in captures:
        print(f"  {c[1]}: {c[4]} frames, {c[5]} BSSIDs, {c[9]} rogue, {c[10]} suspicious")
    
    # Top findings
    print(f"\nTop Rogue APs (from all scans):")
    top_bssids = conn.execute("""
        SELECT bssid, ssid, appearance_count, avg_rssi, is_known
        FROM bssid_tracking
        ORDER BY appearance_count DESC
        LIMIT 10
    """).fetchall()
    
    for b in top_bssids:
        known = "✓" if b[4] else "✗"
        print(f"  {b[0]}: {b[2]} appearances, RSSI: {b[3]:.1f}, Known: {known}")
    
    conn.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Import dataset into database")
    parser.add_argument("--dry-run", action="store_true", help="Preview without saving")
    parser.add_argument("--save-frames", action="store_true", help="Save raw frame data")
    
    args = parser.parse_args()
    
    print("="*60)
    print("DATASET IMPORT")
    print("="*60)
    
    # Initialize database
    if not args.dry_run:
        init_database()
    
    # Get whitelist
    whitelist = get_whitelist()
    print(f"\nWhitelist: {len(whitelist)} BSSIDs")
    
    # Process captures
    captures = [
        ("capture-1.csv", os.path.join(DATASET_DIR, "1", "capture-1.csv")),
        ("capture-2.csv", os.path.join(DATASET_DIR, "2", "capture-2.csv")),
    ]
    
    results = []
    for capture_name, capture_path in captures:
        if not os.path.exists(capture_path):
            print(f"Warning: {capture_path} not found, skipping")
            continue
        
        df, stats, result = analyze_capture(capture_path, capture_name, whitelist, args.save_frames)
        
        if not args.dry_run:
            timestamp = datetime.now().isoformat()
            
            # Store results
            scan_id = store_scan_history(capture_name, stats, result, whitelist)
            store_bssid_tracking(df, whitelist, timestamp)
            store_capture_summary(capture_name, capture_path, stats, result)
            
            print(f"  ✓ Stored with scan_id: {scan_id}")
        
        results.append({
            "name": capture_name,
            "stats": stats,
            "result": result
        })
    
    # Generate report
    if not args.dry_run:
        generate_summary_report()
    
    print("\n" + "="*60)
    print("IMPORT COMPLETE")
    print("="*60)


if __name__ == "__main__":
    main()
