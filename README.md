# RogueShield — Rogue Access Point Detection System

**Meru University of Science and Technology**  
Student: Silvia Muthoni Munene | CT206/109336/22  
Supervisor: Dr. Dorothy Bundi  
Course: Bachelor of Science in Computer Security and Forensics

---

## Project Objectives

This system implements all objectives from the research proposal:

1. **Gather data from CSV capture files** — Upload one or more Scapy-generated CSV wireless captures
2. **Scan available wireless networks** — Parse and index all Beacon and ProbeResp frames per BSSID/SSID
3. **Compare detected signatures with authorised AP records** — Whitelist-based Unknown BSSID detection
4. **Flag rogue access points** — Six detection rules, risk scoring, and verdict classification
5. **Generate alerts for detected rogue devices** — Visual dashboard alerts + downloadable PDF report

---

## Detection Rules

| Rule | Targets | Severity |
|---|---|---|
| SSID Spoofing | Same SSID on multiple BSSIDs | HIGH |
| MAC Inconsistency | addr2 ≠ addr3 in Beacon/ProbeResp | HIGH |
| Unknown BSSID | BSSID not in authorised whitelist | HIGH |
| RSSI Anomaly | ML-based (Isolation Forest + LOF + Z-score) | MEDIUM |
| Probe Response Flood | Honeypot behaviour (>3 ProbeResp) | MEDIUM |
| MAC Timestamp Drift | Clock jump >500 ms between beacons | LOW |

**Risk Scoring:**  HIGH=3 pts · MEDIUM=2 pts · LOW=1 pt  
**Verdict:** ROGUE (≥5) · SUSPICIOUS (≥3) · LOW RISK (<3)

---

## Project Structure

```
rogue_ap_system/
├── backend/
│   ├── app.py              ← Flask API server
│   ├── detector.py         ← Core detection engine (6 rules)
│   ├── database.py          ← SQLite persistence layer
│   ├── email_service.py     ← SMTP email service
│   └── report_generator.py ← PDF report generation (ReportLab)
├── frontend/
│   ├── index.html           ← Main SPA dashboard (Chart.js)
│   ├── login.html          ← Login page
│   ├── register.html        ← Registration page
│   ├── forgot-password.html ← Password reset request
│   └── reset-password.html  ← Password reset form
├── tests/                  ← Unit tests
├── data/
│   └── uploads/            ← Temporary uploaded CSVs
├── reports/                ← Generated PDF reports
├── .env.example           ← Environment variables template
├── requirements.txt
└── run.py                  ← Launch script
```

---

## Setup & Run

### 1. Install dependencies
```bash
cd rogue_ap_system
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure environment (optional)
```bash
cp .env.example .env
# Edit .env with your SMTP credentials and secret key
```

### 3. Start the server
```bash
python run.py
```

### 4. Open the dashboard
Navigate to: **http://localhost:5000**

**Default credentials:** `admin` / `Admin@1234`

---

## Security Features

- **bcrypt password hashing** with salt
- **Rate limiting** on login (5/min) and register (3/hr)
- **CSRF protection** enabled
- **Session secure cookies** (HTTPS only when configured)
- **Security headers** (HSTS, X-Frame-Options, etc.)
- **Role-based access control** (admin, analyst, viewer)
- **Password reset** with email verification

---

## Role-Based Access Control

| Role | Permissions |
|------|------------|
| admin | Full access to all features |
| analyst | Can add/remove whitelist, run scans |
| viewer | Can view results and reports only |

---

## CSV Format

Your capture files must follow this column structure:

```
Timestamp,type,MAC_timestamp,rssi,addr1,addr2,addr3,SSID
```

| Column | Description |
|---|---|
| Timestamp | Unix timestamp (float) |
| type | Frame type: Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp |
| MAC_timestamp | MAC-layer timestamp (microseconds) |
| rssi | Received Signal Strength Indicator (dBm) |
| addr1 | Destination MAC |
| addr2 | Transmitter MAC (BSSID for AP frames) |
| addr3 | BSSID |
| SSID | Network name (b'NAME' format supported) |

---

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/login` | User login |
| POST | `/api/logout` | User logout |
| POST | `/api/register` | User registration |
| POST | `/api/forgot-password` | Request password reset |
| POST | `/api/reset-password` | Reset password with token |
| GET | `/api/me` | Get current user info |

### Detection
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/analyse` | Upload CSVs and run detection |
| GET | `/api/demo` | Run demo with built-in sample data |

### Reports
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/report/<scan_id>` | Download PDF report |
| GET | `/api/export/<scan_id>/csv` | Export findings as CSV |
| GET | `/api/reports` | List all reports (admin) |
| POST | `/api/reports/cleanup` | Clean old reports (admin) |

### Whitelist
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/whitelist` | List whitelist entries |
| POST | `/api/whitelist` | Add BSSID (admin/analyst) |
| DELETE | `/api/whitelist/<bssid>` | Remove BSSID (admin) |

### History
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/history` | List scan history |
| GET | `/api/history/<scan_id>` | Get scan details |
| DELETE | `/api/history/<scan_id>` | Delete scan |

### User Management
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/users` | List all users (admin) |
| PUT | `/api/users/<id>/role` | Update user role (admin) |

---

## Running Tests

```bash
cd rogue_ap_system
source venv/bin/activate
python tests/test_model.py
python tests/test_database.py
```

---

## Usage

1. Open the dashboard at http://localhost:5000
2. Login with default credentials or register a new account
3. Upload one or more `.csv` wireless capture files
4. Optionally enter authorised BSSIDs in the whitelist field
5. Click **Run Detection**
6. Review the dashboard — stat cards, charts, BSSID risk table, findings
7. Click **Download PDF** to export the full professional report
