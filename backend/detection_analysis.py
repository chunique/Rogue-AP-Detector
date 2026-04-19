"""
detection_analysis.py — Integrated detection rules from notebook into main system

This module contains all 6 detection rules implemented in the Jupyter notebook,
integrated for use with the Flask backend.

Usage:
    from detection_analysis import DetectionAnalyzer
    analyzer = DetectionAnalyzer()
    results = analyzer.analyze(['capture-1.csv', 'capture-2.csv'])
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Dict, List, Tuple
import os

# Configuration
Z_SCORE_THRESHOLD = 2.5
PROBE_THRESHOLD = 3
DRIFT_THRESHOLD_MS = 500
ROGUE_THRESHOLD = 5
SUSPICIOUS_THRESHOLD = 3

# Severity points
SEVERITY_POINTS = {
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1
}


class DetectionAnalyzer:
    """Complete detection system implementing all 6 rules."""
    
    def __init__(self, whitelist: List[str] = None):
        self.whitelist = set(whitelist) if whitelist else set()
        self.df = None
        self.df1 = None
        self.df2 = None
        self.ap_frames = None
        self.findings = []
        self.bssid_results = {}
        
    def load_data(self, file_paths: List[str]) -> bool:
        """Load capture files into dataframes."""
        try:
            dfs = []
            for path in file_paths:
                if os.path.exists(path):
                    df = pd.read_csv(path)
                    # Clean SSID column
                    df['SSID'] = df['SSID'].astype(str).str.replace("b'", "", regex=False).str.replace("'", "", regex=False)
                    dfs.append(df)
                else:
                    print(f"Warning: File not found: {path}")
            
            if dfs:
                self.df = pd.concat(dfs, ignore_index=True)
                if len(dfs) >= 2:
                    self.df1, self.df2 = dfs[0], dfs[1]
                else:
                    self.df1 = self.df2 = dfs[0]
                
                self.ap_frames = self.df[self.df['type'].isin(['Dot11Beacon', 'Dot11ProbeResp'])].copy()
                return True
            return False
        except Exception as e:
            print(f"Error loading data: {e}")
            return False
    
    def detect_ssid_spoofing(self) -> List[Dict]:
        """
        Rule 1: SSID Spoofing Detection
        
        Detects when the same SSID is advertised by multiple distinct BSSIDs.
        This may indicate an evil twin attack.
        
        Returns:
            List of findings with SSID spoofing detections
        """
        findings = []
        
        if self.ap_frames is None:
            return findings
            
        ssid_bssid = self.ap_frames.groupby('SSID')['addr2'].nunique().reset_index()
        ssid_bssid.columns = ['SSID', 'bssid_count']
        
        spoofed_ssids = ssid_bssid[ssid_bssid['bssid_count'] > 1]
        
        for _, row in spoofed_ssids.iterrows():
            ssid = row['SSID']
            if ssid == '' or ssid == 'b''':
                continue
                
            bssids = self.ap_frames[self.ap_frames['SSID'] == ssid]['addr2'].unique()
            
            findings.append({
                'rule': 'SSID Spoofing',
                'severity': 'HIGH',
                'ssid': ssid,
                'bssids': list(bssids),
                'bssid_count': len(bssids),
                'description': f'SSID "{ssid}" advertised by {len(bssids)} different BSSIDs'
            })
            
        return findings
    
    def detect_mac_inconsistency(self) -> List[Dict]:
        """
        Rule 2: MAC Address Inconsistency Detection
        
        According to IEEE 802.11, addr2 must equal addr3 in management frames.
        Mismatch indicates frame injection.
        
        Returns:
            List of findings with MAC inconsistencies
        """
        findings = []
        
        if self.ap_frames is None:
            return findings
            
        inconsistent = self.ap_frames[self.ap_frames['addr2'] != self.ap_frames['addr3']]
        
        for _, row in inconsistent.iterrows():
            findings.append({
                'rule': 'MAC Inconsistency',
                'severity': 'HIGH',
                'timestamp': row['Timestamp'],
                'bssid': row['addr2'],
                'addr1': row['addr1'],
                'addr2': row['addr2'],
                'addr3': row['addr3'],
                'ssid': row['SSID'],
                'description': f'{row["type"]}: addr2 ({row["addr2"]}) != addr3 ({row["addr3"]})'
            })
            
        return findings
    
    def detect_rssi_anomaly(self, threshold: float = Z_SCORE_THRESHOLD) -> List[Dict]:
        """
        Rule 3: RSSI Anomaly Detection
        
        Uses Z-score analysis to detect signal strength anomalies.
        Anomalous RSSI may indicate AP impersonation or interference.
        
        Args:
            threshold: Z-score threshold (default 2.5)
            
        Returns:
            List of findings with RSSI anomalies
        """
        findings = []
        
        if self.ap_frames is None:
            return findings
            
        bssid_stats = self.ap_frames.groupby('addr2')['rssi'].agg(['mean', 'std', 'count']).reset_index()
        bssid_stats.columns = ['bssid', 'rssi_mean', 'rssi_std', 'frame_count']
        
        for _, row in self.ap_frames.iterrows():
            bssid = row['addr2']
            rssi = row['rssi']
            
            stats_row = bssid_stats[bssid_stats['bssid'] == bssid]
            if len(stats_row) == 0:
                continue
                
            bssid_mean = stats_row['rssi_mean'].values[0]
            bssid_std = stats_row['rssi_std'].values[0]
            
            if bssid_std > 0:
                z_score = abs((rssi - bssid_mean) / bssid_std)
            else:
                z_score = 0
                
            if z_score > threshold:
                findings.append({
                    'rule': 'RSSI Anomaly',
                    'severity': 'MEDIUM',
                    'timestamp': row['Timestamp'],
                    'bssid': bssid,
                    'rssi': rssi,
                    'bssid_mean': bssid_mean,
                    'bssid_std': bssid_std,
                    'z_score': z_score,
                    'description': f'BSSID {bssid}: RSSI {rssi} (z={z_score:.2f})'
                })
                
        return findings
    
    def detect_rssi_anomaly_isolation_forest(self, contamination: float = 0.05) -> Tuple[List[str], List[float]]:
        """
        ML-based RSSI anomaly detection using Isolation Forest.
        
        Args:
            contamination: Expected proportion of anomalies (default 5%)
            
        Returns:
            Tuple of (anomalous bssids, anomaly scores)
        """
        if self.ap_frames is None:
            return [], []
            
        features = self.ap_frames[['rssi']].copy()
        
        iso_forest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        
        self.ap_frames['anomaly_score'] = iso_forest.fit_predict(features)
        self.ap_frames['anomaly_label'] = self.ap_frames['anomaly_score'].map({1: 'normal', -1: 'anomaly'})
        
        anomalies = self.ap_frames[self.ap_frames['anomaly_label'] == 'anomaly']
        anomalous_bssids = anomalies['addr2'].unique().tolist()
        
        return anomalous_bssids, []
    
    def detect_probe_flood(self, threshold: int = PROBE_THRESHOLD) -> List[Dict]:
        """
        Rule 4: Probe Response Flood Detection
        
        Detects BSSIDs sending excessive Probe Response frames.
        May indicate honeypot attack.
        
        Args:
            threshold: Minimum probe count to flag (default 3)
            
        Returns:
            List of findings with probe flood detections
        """
        findings = []
        
        if self.df is None:
            return findings
            
        probe_resp = self.df[self.df['type'] == 'Dot11ProbeResp']
        bssid_counts = probe_resp.groupby('addr2').size().reset_index(name='count')
        flooding = bssid_counts[bssid_counts['count'] > threshold]
        
        for _, row in flooding.iterrows():
            bssid = row['addr2']
            count = row['count']
            ssids = probe_resp[probe_resp['addr2'] == bssid]['SSID'].unique()
            
            findings.append({
                'rule': 'Probe Response Flood',
                'severity': 'LOW',
                'bssid': bssid,
                'frame_count': count,
                'ssids': list(ssids),
                'description': f'BSSID {bssid} sent {count} Probe Responses'
            })
            
        return findings
    
    def detect_timestamp_drift(self, threshold_ms: float = DRIFT_THRESHOLD_MS) -> List[Dict]:
        """
        Rule 5: MAC Timestamp Drift Detection
        
        Detects drift between MAC_timestamp and wall clock time.
        Large drift may indicate replay attacks or software APs.
        
        Args:
            threshold_ms: Maximum allowed drift in ms (default 500)
            
        Returns:
            List of findings with timestamp drift detections
        """
        findings = []
        drift_samples = []
        
        if self.df is None:
            return findings
            
        beacons = self.df[self.df['type'] == 'Dot11Beacon'].copy()
        beacons = beacons.sort_values(['addr2', 'Timestamp'])
        
        for bssid, group in beacons.groupby('addr2'):
            if len(group) < 2:
                continue
                
            timestamps = group['Timestamp'].values
            mac_timestamps = group['MAC_timestamp'].values
            
            for i in range(1, min(len(timestamps), 20)):
                wall_delta = (timestamps[i] - timestamps[i-1]) * 1000
                mac_delta = (mac_timestamps[i] - mac_timestamps[i-1]) / 1000
                
                if wall_delta <= 0:
                    continue
                    
                drift = abs(mac_delta - wall_delta)
                drift_samples.append({'bssid': bssid, 'drift': drift})
                
                if drift > threshold_ms:
                    findings.append({
                        'rule': 'MAC Timestamp Drift',
                        'severity': 'LOW',
                        'bssid': bssid,
                        'frame_index': i,
                        'drift_ms': drift,
                        'description': f'BSSID {bssid}: drift of {drift:.1f}ms'
                    })
                
        return findings, drift_samples
    
    def detect_unknown_bssid(self, whitelist: List[str] = None) -> Tuple[List[Dict], List[str]]:
        """
        Rule 6: Unknown BSSID Detection
        
        Flags BSSIDs not in the authorized whitelist.
        May indicate rogue APs.
        
        Args:
            whitelist: List of known BSSIDs (optional, uses self.whitelist if not provided)
            
        Returns:
            Tuple of (findings, whitelist used)
        """
        findings = []
        stable_bssids = list(self.whitelist)
        
        if self.df1 is not None and self.df2 is not None:
            bssids1 = set(self.df1['addr2'].unique())
            bssids2 = set(self.df2['addr2'].unique())
            stable_bssids = list(bssids1 & bssids2)
        
        wl = set(whitelist) if whitelist else self.whitelist
        if not wl and stable_bssids:
            wl = set(stable_bssids)
            
        all_bssids = set(self.df['addr2'].unique())
        unknown_bssids = all_bssids - wl
        
        for bssid in unknown_bssids:
            count = len(self.df[self.df['addr2'] == bssid])
            ssids = self.df[self.df['addr2'] == bssid]['SSID'].unique()
            ssids = [s for s in ssids if s and s != '']
            
            findings.append({
                'rule': 'Unknown BSSID',
                'severity': 'MEDIUM',
                'bssid': bssid,
                'frame_count': count,
                'ssids': ssids,
                'description': f'BSSID {bssid} not in whitelist ({count} frames)'
            })
            
        return findings, stable_bssids
    
    def calculate_verdict(self, score: int) -> str:
        """Calculate verdict based on score."""
        if score >= ROGUE_THRESHOLD:
            return 'ROGUE'
        elif score >= SUSPICIOUS_THRESHOLD:
            return 'SUSPICIOUS'
        else:
            return 'LOW RISK'
    
    def aggregate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Aggregate all findings by BSSID and calculate scores."""
        bssid_scores = {}
        bssid_findings = {}
        
        for finding in findings:
            bssid = finding.get('bssid') or finding.get('addr2')
            if not bssid:
                continue
                
            severity = finding['severity']
            points = SEVERITY_POINTS.get(severity, 0)
            
            if bssid not in bssid_scores:
                bssid_scores[bssid] = 0
                bssid_findings[bssid] = []
                
            bssid_scores[bssid] += points
            bssid_findings[bssid].append(finding)
        
        results = []
        for bssid, score in bssid_scores.items():
            verdict = self.calculate_verdict(score)
            
            ssids = []
            if self.ap_frames is not None:
                ssids = self.ap_frames[self.ap_frames['addr2'] == bssid]['SSID'].unique()
                ssids = [s for s in ssids if s and s != '']
            
            finding_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            for f in bssid_findings[bssid]:
                finding_counts[f['severity']] = finding_counts.get(f['severity'], 0) + 1
            
            results.append({
                'bssid': bssid,
                'score': score,
                'verdict': verdict,
                'ssids': ssids,
                'findings': bssid_findings[bssid],
                'finding_counts': finding_counts
            })
        
        results.sort(key=lambda x: -x['score'])
        return results
    
    def analyze(self, file_paths: List[str], whitelist: List[str] = None) -> Dict:
        """
        Run complete analysis on capture files.
        
        Args:
            file_paths: List of paths to CSV capture files
            whitelist: List of known BSSIDs
            
        Returns:
            Complete analysis results
        """
        if whitelist:
            self.whitelist = set(whitelist)
            
        if not self.load_data(file_paths):
            return {'error': 'Failed to load data'}
        
        all_findings = []
        
        # Run all detection rules
        all_findings.extend(self.detect_ssid_spoofing())
        all_findings.extend(self.detect_mac_inconsistency())
        all_findings.extend(self.detect_rssi_anomaly())
        all_findings.extend(self.detect_probe_flood())
        drift_results = self.detect_timestamp_drift()
        all_findings.extend(drift_results[0])
        unknown_results = self.detect_unknown_bssid()
        all_findings.extend(unknown_results[0])
        
        # Aggregate results
        bssid_results = self.aggregate_findings(all_findings)
        
        # Count verdicts
        verdict_counts = {'ROGUE': 0, 'SUSPICIOUS': 0, 'LOW RISK': 0}
        for r in bssid_results:
            verdict_counts[r['verdict']] += 1
        
        return {
            'stats': {
                'total_frames': len(self.df) if self.df is not None else 0,
                'unique_bssids': len(self.ap_frames['addr2'].unique()) if self.ap_frames is not None else 0,
                'rogue_count': verdict_counts['ROGUE'],
                'suspicious_count': verdict_counts['SUSPICIOUS'],
                'low_risk_count': verdict_counts['LOW RISK'],
                'total_findings': len(all_findings),
                'rule_counts': {
                    'SSID Spoofing': len([f for f in all_findings if f['rule'] == 'SSID Spoofing']),
                    'MAC Inconsistency': len([f for f in all_findings if f['rule'] == 'MAC Inconsistency']),
                    'RSSI Anomaly': len([f for f in all_findings if f['rule'] == 'RSSI Anomaly']),
                    'Probe Response Flood': len([f for f in all_findings if f['rule'] == 'Probe Response Flood']),
                    'MAC Timestamp Drift': len([f for f in all_findings if f['rule'] == 'MAC Timestamp Drift']),
                    'Unknown BSSID': len([f for f in all_findings if f['rule'] == 'Unknown BSSID']),
                }
            },
            'findings': all_findings,
            'bssid_scores': {r['bssid']: r for r in bssid_results},
            'verdict_counts': verdict_counts,
            'whitelist': unknown_results[1]
        }


def run_analysis(file_paths: List[str], whitelist: List[str] = None) -> Dict:
    """
    Convenience function to run complete analysis.
    
    Args:
        file_paths: List of paths to CSV capture files
        whitelist: List of known BSSIDs
        
    Returns:
        Complete analysis results
    """
    analyzer = DetectionAnalyzer(whitelist)
    return analyzer.analyze(file_paths, whitelist)


if __name__ == '__main__':
    # Example usage
    import sys
    
    datasets_path = os.path.join(os.path.dirname(__file__), '..', 'datasets')
    
    analyzer = DetectionAnalyzer()
    results = analyzer.analyze([
        os.path.join(datasets_path, '1', 'capture-1.csv'),
        os.path.join(datasets_path, '2', 'capture-2.csv')
    ])
    
    print("=" * 60)
    print("ROGUE AP DETECTION SYSTEM - ANALYSIS RESULTS")
    print("=" * 60)
    print(f"\nTotal Frames: {results['stats']['total_frames']:,}")
    print(f"Unique BSSIDs: {results['stats']['unique_bssids']}")
    
    print("\n--- Verdict Summary ---")
    for verdict, count in results['verdict_counts'].items():
        print(f"  {verdict}: {count}")
    
    print("\n--- Findings by Rule ---")
    for rule, count in results['stats']['rule_counts'].items():
        print(f"  {rule}: {count}")
    
    print("\n--- Top Findings ---")
    for r in list(results['bssid_scores'].values())[:10]:
        print(f"  {r['verdict']:12} | Score: {r['score']:3} | {r['bssid']}")
