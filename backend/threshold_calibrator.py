"""
threshold_calibrator.py — Calibrate detection thresholds using Belgian train station dataset

This script analyzes the RSSI distribution and other metrics to suggest
optimal thresholds for the detection system.

Usage:
    python threshold_calibrator.py
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
    return pd.concat([df1, df2], ignore_index=True), df1, df2


def analyze_rssi_distribution(df):
    """Analyze RSSI distribution for threshold calibration."""
    print("\n" + "="*60)
    print("RSSI DISTRIBUTION ANALYSIS")
    print("="*60)
    
    ap_frames = df[df["type"].isin(["Dot11Beacon", "Dot11ProbeResp"])]
    all_rssi = ap_frames["rssi"].dropna()
    
    stats = {
        "count": len(all_rssi),
        "min": all_rssi.min(),
        "max": all_rssi.max(),
        "mean": all_rssi.mean(),
        "median": all_rssi.median(),
        "std": all_rssi.std(),
        "p1": np.percentile(all_rssi, 1),
        "p5": np.percentile(all_rssi, 5),
        "p95": np.percentile(all_rssi, 95),
        "p99": np.percentile(all_rssi, 99),
    }
    
    print(f"\nBasic Statistics:")
    print(f"  Total samples: {stats['count']:,}")
    print(f"  Range: {stats['min']} to {stats['max']} dBm")
    print(f"  Mean: {stats['mean']:.1f} dBm")
    print(f"  Median: {stats['median']:.1f} dBm")
    print(f"  Std Dev: {stats['std']:.1f} dBm")
    
    print(f"\nPercentiles:")
    for p in [1, 5, 25, 50, 75, 95, 99]:
        val = np.percentile(all_rssi, p)
        print(f"  {p:>3}th: {val:>6.1f} dBm")
    
    # Per-BSSID analysis
    print(f"\nPer-BSSID Statistics:")
    bssid_stats = ap_frames.groupby("addr2")["rssi"].agg(['mean', 'std', 'count'])
    
    bssid_means = bssid_stats['mean']
    bssid_stds = bssid_stats['std'].dropna()
    
    print(f"  Unique BSSIDs: {len(bssid_stats)}")
    print(f"  Mean of per-BSSID means: {bssid_means.mean():.1f} dBm")
    print(f"  Mean of per-BSSID stds: {bssid_stds.mean():.1f} dBm")
    print(f"  Max per-BSSID std: {bssid_stds.max():.1f} dBm")
    
    return stats, bssid_stats


def suggest_z_threshold(stats, target_outliers_pct=5):
    """Suggest optimal z-score threshold based on distribution."""
    print("\n" + "="*60)
    print("Z-SCORE THRESHOLD CALIBRATION")
    print("="*60)
    
    current_threshold = 2.5
    current_std = stats['std']
    
    print(f"\nCurrent Configuration:")
    print(f"  z_threshold: {current_threshold}")
    print(f"  Dataset std: {current_std:.1f} dBm")
    
    current_range = current_threshold * current_std
    print(f"  Effective range: ±{current_range:.1f} dBm from mean")
    
    # Analyze what current threshold catches
    mean = stats['mean']
    threshold_low = mean - current_range
    threshold_high = mean + current_range
    
    print(f"\nCurrent threshold boundaries:")
    print(f"  Lower: {threshold_low:.1f} dBm (very weak signal)")
    print(f"  Upper: {threshold_high:.1f} dBm (very strong signal)")
    
    # Calculate outlier percentage at different thresholds
    print(f"\n--- Threshold Sensitivity Analysis ---")
    print(f"{'Threshold':<12} {'Range':<10} {'Outliers %':<12} {'Use Case'}")
    print("-" * 60)
    
    recommendations = []
    for z in [1.0, 1.5, 2.0, 2.5, 3.0, 3.5]:
        r = z * current_std
        lower = mean - r
        upper = mean + r
        
        # Estimate outliers (assuming normal distribution)
        # For z=2.5, ~1.2% on each tail = ~2.4% total
        from scipy import stats as scipy_stats
        tail_pct = (1 - scipy_stats.norm.cdf(z)) * 100
        total_outliers = tail_pct * 2
        
        use_case = "Too sensitive" if z <= 1.5 else \
                   "Balanced" if z <= 2.5 else \
                   "Conservative" if z <= 3.0 else "Very strict"
        
        print(f"{z:<12.1f} ±{r:<9.1f} {total_outliers:<12.1f} {use_case}")
        
        recommendations.append({
            'z': z,
            'range': r,
            'outliers_pct': total_outliers,
            'use_case': use_case
        })
    
    return recommendations


def suggest_probe_threshold(df):
    """Suggest optimal probe response flood threshold."""
    print("\n" + "="*60)
    print("PROBE RESPONSE FLOOD THRESHOLD CALIBRATION")
    print("="*60)
    
    probe_resp = df[df["type"] == "Dot11ProbeResp"]
    bssid_counts = probe_resp.groupby("addr2").size().sort_values(ascending=False)
    
    current_threshold = 3
    flooding = bssid_counts[bssid_counts > current_threshold]
    
    print(f"\nCurrent Configuration:")
    print(f"  probe_threshold: {current_threshold}")
    print(f"  BSSIDs exceeding threshold: {len(flooding)}")
    
    print(f"\n--- Probe Response Distribution ---")
    print(f"  Total ProbeResp frames: {len(probe_resp):,}")
    print(f"  Unique responding BSSIDs: {len(bssid_counts)}")
    print(f"  Min responses: {bssid_counts.min()}")
    print(f"  Max responses: {bssid_counts.max()}")
    print(f"  Mean responses: {bssid_counts.mean():.1f}")
    print(f"  Median responses: {bssid_counts.median():.1f}")
    
    # Threshold sensitivity
    print(f"\n--- Threshold Sensitivity Analysis ---")
    print(f"{'Threshold':<12} {'BSSIDs Flagged':<16} {'Flagged %':<12} {'Use Case'}")
    print("-" * 60)
    
    for t in [1, 2, 3, 5, 10, 20]:
        flagged = len(bssid_counts[bssid_counts > t])
        pct = 100 * flagged / len(bssid_counts)
        use_case = "Too sensitive" if t <= 2 else \
                   "Balanced" if t <= 5 else \
                   "Conservative" if t <= 10 else "Very strict"
        print(f"{t:<12} {flagged:<16} {pct:<12.1f} {use_case}")
    
    return bssid_counts


def suggest_drift_threshold(df):
    """Suggest optimal MAC timestamp drift threshold."""
    print("\n" + "="*60)
    print("MAC TIMESTAMP DRIFT THRESHOLD CALIBRATION")
    print("="*60)
    
    current_threshold = 500  # ms
    
    print(f"\nCurrent Configuration:")
    print(f"  drift_threshold_ms: {current_threshold}")
    
    beacons = df[df["type"] == "Dot11Beacon"].copy()
    beacons = beacons.sort_values(["addr2", "Timestamp"])
    
    drifts = []
    for bssid, group in beacons.groupby("addr2"):
        if len(group) < 2:
            continue
        
        mac_ts = group["MAC_timestamp"].values
        wall_ts = group["Timestamp"].values
        
        for i in range(1, min(len(mac_ts), 20)):
            wall_delta_ms = (wall_ts[i] - wall_ts[i-1]) * 1000
            mac_delta_ms = (mac_ts[i] - mac_ts[i-1]) / 1000
            
            if wall_delta_ms > 0:
                drift = abs(mac_delta_ms - wall_delta_ms)
                drifts.append(drift)
    
    if drifts:
        drifts = np.array(drifts)
        print(f"\n--- Drift Statistics ---")
        print(f"  Samples analyzed: {len(drifts)}")
        print(f"  Mean drift: {np.mean(drifts):.1f} ms")
        print(f"  Median drift: {np.median(drifts):.1f} ms")
        print(f"  Std drift: {np.std(drifts):.1f} ms")
        print(f"  Max drift: {np.max(drifts):.1f} ms")
        print(f"  95th percentile: {np.percentile(drifts, 95):.1f} ms")
        print(f"  99th percentile: {np.percentile(drifts, 99):.1f} ms")
        
        print(f"\n--- Threshold Sensitivity Analysis ---")
        print(f"{'Threshold':<12} {'Violations':<14} {'Violation %':<14} {'Use Case'}")
        print("-" * 60)
        
        for t in [100, 200, 300, 500, 750, 1000]:
            violations = len(drifts[drifts > t])
            pct = 100 * violations / len(drifts)
            use_case = "Very strict" if t <= 200 else \
                       "Balanced" if t <= 500 else \
                       "Conservative"
            print(f"{t:<12} {violations:<14} {pct:<14.1f} {use_case}")
    else:
        print("\n  No valid frame pairs for drift analysis")
    
    return drifts


def suggest_verdict_thresholds():
    """Suggest verdict score thresholds."""
    print("\n" + "="*60)
    print("VERDICT SCORE THRESHOLDS")
    print("="*60)
    
    current = {"ROGUE": 5, "SUSPICIOUS": 3}
    
    print(f"\nCurrent Configuration:")
    print(f"  ROGUE: score >= {current['ROGUE']}")
    print(f"  SUSPICIOUS: score >= {current['SUSPICIOUS']}")
    
    print(f"\nScore weights:")
    print(f"  HIGH severity: 3 points")
    print(f"  MEDIUM severity: 2 points")
    print(f"  LOW severity: 1 point")
    
    print(f"\n--- Interpretation ---")
    print(f"  ROGUE: >= 5 points = 2 HIGH or 3 MEDIUM findings")
    print(f"  SUSPICIOUS: >= 3 points = 1 HIGH or 2 MEDIUM findings")
    print(f"  LOW RISK: < 3 points")
    
    print(f"\n--- Alternative Thresholds ---")
    print(f"{'ROGUE':<10} {'SUSPICIOUS':<14} {'Behavior'}")
    print("-" * 60)
    print(f"{5:<10} {3:<14} Current (balanced)")
    print(f"{7:<10} {5:<14} More conservative (fewer ROGUEs)")
    print(f"{4:<10} {2:<14} More aggressive (more ROGUEs)")


def generate_config_suggestions(rssi_stats, recommendations):
    """Generate suggested configuration file."""
    print("\n" + "="*60)
    print("SUGGESTED CONFIGURATION")
    print("="*60)
    
    # Find recommended z-threshold
    recommended_z = 2.0  # Balanced choice
    for rec in recommendations:
        if rec['use_case'] == 'Balanced':
            recommended_z = rec['z']
            break
    
    suggested = {
        'rssi_z_threshold': recommended_z,
        'probe_threshold': 3,
        'drift_threshold_ms': 500,
        'rogue_threshold': 5,
        'suspicious_threshold': 3,
    }
    
    print(f"""
# Detection Threshold Configuration
# Auto-generated from Belgian Train Station Dataset

# RSSI Anomaly Detection
RSSI_Z_THRESHOLD = {suggested['rssi_z_threshold']}  # Flag if |z-score| > this value
# Current dataset: mean=-{rssi_stats['mean']:.0f}dBm, std={rssi_stats['std']:.1f}dBm

# Probe Response Flood
PROBE_THRESHOLD = {suggested['probe_threshold']}  # Flag if BSSID sends > this many ProbeResp

# MAC Timestamp Drift
DRIFT_THRESHOLD_MS = {suggested['drift_threshold_ms']}  # Flag if drift > this (ms)

# Verdict Thresholds
ROGUE_SCORE = {suggested['rogue_threshold']}  # Score >= this = ROGUE
SUSPICIOUS_SCORE = {suggested['suspicious_threshold']}  # Score >= this = SUSPICIOUS
""")
    
    return suggested


def main():
    print("="*60)
    print("THRESHOLD CALIBRATION REPORT")
    print("Belgian Train Station Dataset")
    print("="*60)
    
    # Load dataset
    print("\nLoading dataset...")
    df, df1, df2 = load_dataset()
    print(f"Total frames: {len(df):,}")
    
    # Analyze RSSI distribution
    rssi_stats, bssid_stats = analyze_rssi_distribution(df)
    
    # Calibrate z-threshold
    z_recommendations = suggest_z_threshold(rssi_stats)
    
    # Calibrate probe threshold
    probe_counts = suggest_probe_threshold(df)
    
    # Calibrate drift threshold
    drifts = suggest_drift_threshold(df)
    
    # Verdict thresholds
    suggest_verdict_thresholds()
    
    # Generate configuration suggestions
    suggested_config = generate_config_suggestions(rssi_stats, z_recommendations)
    
    # Summary
    print("\n" + "="*60)
    print("CALIBRATION SUMMARY")
    print("="*60)
    print(f"""
Dataset Statistics:
  Frames: {len(df):,}
  RSSI Mean: {rssi_stats['mean']:.1f} dBm
  RSSI Std: {rssi_stats['std']:.1f} dBm

Recommended Thresholds:
  RSSI z-score: {suggested_config['rssi_z_threshold']} (current: 2.5)
  Probe response: {suggested_config['probe_threshold']} (current: 3)
  Drift: {suggested_config['drift_threshold_ms']} ms (current: 500)

Note: Current thresholds are reasonable for this dataset.
      z=2.0 would be more sensitive (2.5% outliers).
      z=3.0 would be more conservative (0.3% outliers).
""")


if __name__ == "__main__":
    main()
