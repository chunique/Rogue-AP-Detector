"""
test_model.py — Tests for detection rules
"""
import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from model import (
    load_capture, clean_ssid, detect_ssid_spoofing,
    detect_mac_inconsistency, detect_rssi_anomaly,
    detect_probe_response_flood, detect_mac_timestamp_drift,
    score_bssids
)
import pandas as pd

def create_temp_csv(content):
    f = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False)
    f.write(content)
    f.close()
    return f.name

def test_clean_ssid():
    assert clean_ssid("b'NETWORK'") == "NETWORK"
    assert clean_ssid("b\"NETWORK\"") == "NETWORK"
    assert clean_ssid("NETWORK") == "NETWORK"
    assert clean_ssid(None) == ""
    print("✓ clean_ssid tests passed")

def test_ssid_spoofing():
    csv_content = """Timestamp,type,MAC_timestamp,rssi,addr1,addr2,addr3,SSID
1682624219.4,Dot11Beacon,698926457,-49,ff:ff:ff:ff:ff:ff,00:00:00:00:00:01,00:00:00:00:00:01,b'NETWORK'
1682624219.5,Dot11Beacon,698926457,-49,ff:ff:ff:ff:ff:ff,00:00:00:00:00:02,00:00:00:00:00:02,b'NETWORK'"""
    path = create_temp_csv(csv_content)
    df = load_capture(path)
    findings = detect_ssid_spoofing(df)
    os.unlink(path)
    assert len(findings) == 1
    assert findings[0]['rule'] == 'SSID_SPOOFING'
    assert findings[0]['severity'] == 'HIGH'
    print("✓ SSID spoofing detection tests passed")

def test_mac_inconsistency():
    csv_content = """Timestamp,type,MAC_timestamp,rssi,addr1,addr2,addr3,SSID
1682624219.4,Dot11Beacon,698926457,-49,ff:ff:ff:ff:ff:ff,00:00:00:00:00:01,00:00:00:00:00:02,b'NETWORK'"""
    path = create_temp_csv(csv_content)
    df = load_capture(path)
    findings = detect_mac_inconsistency(df)
    os.unlink(path)
    assert len(findings) == 1
    assert findings[0]['rule'] == 'MAC_INCONSISTENCY'
    assert findings[0]['severity'] == 'HIGH'
    print("✓ MAC inconsistency detection tests passed")

def test_rssi_anomaly():
    csv_content = """Timestamp,type,MAC_timestamp,rssi,addr1,addr2,addr3,SSID
1682624219.4,Dot11Beacon,698926457,-50,ff:ff:ff:ff:ff:ff,00:00:00:00:00:01,00:00:00:00:00:01,b'NETWORK'
1682624219.5,Dot11Beacon,698926457,-55,ff:ff:ff:ff:ff:ff,00:00:00:00:00:01,00:00:00:00:00:01,b'NETWORK'
1682624219.6,Dot11Beacon,698926457,-60,ff:ff:ff:ff:ff:ff,00:00:00:00:00:01,00:00:00:00:00:01,b'NETWORK'
1682624219.7,Dot11Beacon,698926457,-65,ff:ff:ff:ff:ff:ff,00:00:00:00:00:01,00:00:00:00:00:01,b'NETWORK'
1682624219.8,Dot11Beacon,698926457,-70,ff:ff:ff:ff:ff:ff,00:00:00:00:00:01,00:00:00:00:00:01,b'NETWORK'
1682624219.9,Dot11Beacon,698926457,-75,ff:ff:ff:ff:ff:ff,00:00:00:00:00:01,00:00:00:00:00:01,b'NETWORK'
1682624220.0,Dot11Beacon,698926457,-30,ff:ff:ff:ff:ff:ff,00:00:00:00:00:01,00:00:00:00:00:01,b'NETWORK'
1682624220.1,Dot11Beacon,698926457,-25,ff:ff:ff:ff:ff:ff,00:00:00:00:00:01,00:00:00:00:00:01,b'NETWORK'
1682624220.2,Dot11Beacon,698926457,-28,ff:ff:ff:ff:ff:ff,00:00:00:00:00:01,00:00:00:00:00:01,b'NETWORK'
1682624220.3,Dot11Beacon,698926457,-27,ff:ff:ff:ff:ff:ff,00:00:00:00:00:01,00:00:00:00:00:01,b'NETWORK'
1682624220.4,Dot11Beacon,698926457,-29,ff:ff:ff:ff:ff:ff,00:00:00:00:00:01,00:00:00:00:00:01,b'NETWORK'"""
    path = create_temp_csv(csv_content)
    df = load_capture(path)
    findings = detect_rssi_anomaly(df, z_threshold=2.0)
    os.unlink(path)
    assert len(findings) >= 1
    assert findings[0]['rule'] == 'RSSI_ANOMALY'
    assert findings[0]['severity'] == 'MEDIUM'
    print("✓ RSSI anomaly detection tests passed")

def test_probe_response_flood():
    csv_content = """Timestamp,type,MAC_timestamp,rssi,addr1,addr2,addr3,SSID
1682624219.4,Dot11ProbeResp,698926457,-49,00:00:00:00:00:02,00:00:00:00:00:01,00:00:00:00:00:01,b'NETWORK'
1682624219.5,Dot11ProbeResp,698926458,-49,00:00:00:00:00:02,00:00:00:00:00:01,00:00:00:00:00:01,b'NETWORK'
1682624219.6,Dot11ProbeResp,698926459,-49,00:00:00:00:00:02,00:00:00:00:00:01,00:00:00:00:00:01,b'NETWORK'
1682624219.7,Dot11ProbeResp,698926460,-49,00:00:00:00:00:02,00:00:00:00:00:01,00:00:00:00:00:01,b'NETWORK'"""
    path = create_temp_csv(csv_content)
    df = load_capture(path)
    findings = detect_probe_response_flood(df, threshold=3)
    os.unlink(path)
    assert len(findings) == 1
    assert findings[0]['rule'] == 'PROBE_RESP_FLOOD'
    assert findings[0]['severity'] == 'MEDIUM'
    print("✓ Probe response flood detection tests passed")

def test_score_bssids():
    findings = [
        {'rule': 'SSID_SPOOFING', 'severity': 'HIGH', 'bssids': ['aa:bb:cc:dd:ee:ff']},
        {'rule': 'MAC_INCONSISTENCY', 'severity': 'HIGH', 'bssids': ['aa:bb:cc:dd:ee:ff']},
        {'rule': 'RSSI_ANOMALY', 'severity': 'MEDIUM', 'bssids': ['aa:bb:cc:dd:ee:ff']},
    ]
    scores = score_bssids(findings)
    assert 'aa:bb:cc:dd:ee:ff' in scores
    assert scores['aa:bb:cc:dd:ee:ff']['score'] == 8
    print("✓ BSSID scoring tests passed")

def run_all_tests():
    print("\nRunning detection model tests...\n")
    test_clean_ssid()
    test_ssid_spoofing()
    test_mac_inconsistency()
    test_rssi_anomaly()
    test_probe_response_flood()
    test_score_bssids()
    print("\n✓ All detection tests passed!\n")

if __name__ == '__main__':
    run_all_tests()
