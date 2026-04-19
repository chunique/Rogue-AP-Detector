"""
whitelist_generator.py — Generate whitelist from Belgian train station dataset

This script analyzes capture files to identify stable APs (BSSIDs appearing
in multiple captures) and generates a whitelist for the rogue AP detection system.

Usage:
    python whitelist_generator.py [--preview] [--insert]
"""

import os
import sys
import argparse
import pandas as pd

DATASET_DIR = os.path.join(os.path.dirname(__file__), "..", "datasets")
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "rogue_ap.db")


def load_captures():
    """Load all CSV files from datasets folder."""
    captures = {}
    for i in [1, 2]:
        path = os.path.join(DATASET_DIR, str(i), f"capture-{i}.csv")
        if os.path.exists(path):
            captures[f"capture-{i}"] = pd.read_csv(path)
            print(f"Loaded {path}: {len(captures[f'capture-{i}'])} frames")
    return captures


def find_stable_bssids(captures, min_appearances=2):
    """
    Find BSSIDs that appear in multiple captures.
    These are likely legitimate APs, not transient devices.
    """
    bssid_appearances = {}
    
    for name, df in captures.items():
        for bssid in df["addr2"].unique():
            if bssid not in bssid_appearances:
                bssid_appearances[bssid] = {"count": 0, "captures": []}
            bssid_appearances[bssid]["count"] += 1
            bssid_appearances[bssid]["captures"].append(name)
    
    stable = {b: v for b, v in bssid_appearances.items() if v["count"] >= min_appearances}
    return stable


def get_bssid_details(df, bssid):
    """Get SSID and average RSSI for a BSSID."""
    frames = df[df["addr2"] == bssid]
    ssids = frames["SSID"].dropna().unique()
    ssids = [s for s in ssids if s and s.strip() and s != "b''"]
    
    avg_rssi = frames["rssi"].mean() if len(frames) > 0 else None
    frame_count = len(frames)
    
    return {
        "ssid": ssids[0] if ssids else "Unknown",
        "avg_rssi": round(avg_rssi, 1) if avg_rssi else None,
        "frame_count": frame_count
    }


def generate_whitelist(captures, min_appearances=2):
    """Generate whitelist entries from captures."""
    stable = find_stable_bssids(captures, min_appearances)
    
    whitelist = []
    for bssid, info in stable.items():
        best_detail = {"ssid": "Unknown", "avg_rssi": None, "frame_count": 0}
        
        for name, df in captures.items():
            detail = get_bssid_details(df, bssid)
            if detail["frame_count"] > best_detail["frame_count"]:
                best_detail = detail
        
        whitelist.append({
            "bssid": bssid,
            "ssid": best_detail["ssid"],
            "avg_rssi": best_detail["avg_rssi"],
            "appearances": info["count"],
            "captures": ", ".join(info["captures"])
        })
    
    whitelist.sort(key=lambda x: -x["appearances"])
    return whitelist


def generate_sql(whitelist, table_name="whitelist"):
    """Generate SQL INSERT statements for whitelist."""
    from datetime import datetime
    
    now = datetime.now().isoformat(timespec="seconds")
    statements = []
    
    for entry in whitelist:
        ssid = entry["ssid"].replace("'", "''") if entry["ssid"] else ""
        label = f"Stable AP ({entry['appearances']} captures, RSSI: {entry['avg_rssi']})"
        
        sql = f"INSERT OR IGNORE INTO {table_name} (bssid, label, ssid, added_at) VALUES ('{entry['bssid']}', '{label}', '{ssid}', '{now}');"
        statements.append(sql)
    
    return statements


def main():
    parser = argparse.ArgumentParser(description="Generate whitelist from dataset captures")
    parser.add_argument("--preview", action="store_true", help="Preview whitelist entries")
    parser.add_argument("--sql", action="store_true", help="Generate SQL INSERT statements")
    parser.add_argument("--insert", action="store_true", help="Insert directly into database")
    parser.add_argument("--min", type=int, default=2, help="Minimum appearances (default: 2)")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of entries (0=all)")
    
    args = parser.parse_args()
    
    if not any([args.preview, args.sql, args.insert]):
        parser.print_help()
        print("\n=== Quick Start ===")
        print("1. Preview whitelist: python whitelist_generator.py --preview")
        print("2. Generate SQL:     python whitelist_generator.py --sql")
        print("3. Insert to DB:    python whitelist_generator.py --insert")
        return
    
    print("Loading captures...")
    captures = load_captures()
    
    if not captures:
        print("No capture files found in datasets folder")
        return
    
    print(f"\nGenerating whitelist (min {args.min} appearances)...")
    whitelist = generate_whitelist(captures, min_appearances=args.min)
    
    if args.limit > 0:
        whitelist = whitelist[:args.limit]
    
    print(f"Found {len(whitelist)} stable APs\n")
    
    if args.preview:
        print("=== Stable APs (BSSIDs) ===")
        print(f"{'BSSID':<20} {'SSID':<15} {'Avg RSSI':<10} {'Appearances':<12}")
        print("-" * 60)
        for entry in whitelist[:50]:
            ssid = entry["ssid"][:12] if entry["ssid"] else "Unknown"
            rssi = f"{entry['avg_rssi']} dBm" if entry["avg_rssi"] else "N/A"
            print(f"{entry['bssid']:<20} {ssid:<15} {rssi:<10} {entry['appearances']}")
        if len(whitelist) > 50:
            print(f"... and {len(whitelist) - 50} more")
    
    if args.sql:
        statements = generate_sql(whitelist)
        output_file = "whitelist_inserts.sql"
        with open(output_file, "w") as f:
            f.write("-- Whitelist entries from Belgian train station dataset\n")
            f.write("-- Generated by whitelist_generator.py\n\n")
            f.write("\n".join(statements))
        print(f"SQL statements written to {output_file}")
    
    if args.insert:
        if not os.path.exists(DB_PATH):
            print(f"Database not found at {DB_PATH}")
            return
        
        import sqlite3
        from datetime import datetime
        
        now = datetime.now().isoformat(timespec="seconds")
        inserted = 0
        
        conn = sqlite3.connect(DB_PATH)
        for entry in whitelist:
            try:
                ssid = entry["ssid"] if entry["ssid"] else ""
                label = f"Dataset AP ({entry['appearances']} captures)"
                
                conn.execute(
                    "INSERT OR IGNORE INTO whitelist (bssid, label, ssid, added_at) VALUES (?, ?, ?, ?)",
                    (entry["bssid"], label, ssid, now)
                )
                inserted += 1
            except sqlite3.IntegrityError:
                pass
        
        conn.commit()
        conn.close()
        print(f"Inserted {inserted} entries into whitelist")


if __name__ == "__main__":
    main()
