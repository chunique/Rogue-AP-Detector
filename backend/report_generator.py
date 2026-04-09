"""
PDF Report Generator for Rogue AP Detection System
Meru University of Science and Technology | CT206/109336/22
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable, KeepTogether)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF
import datetime
import os

# ── Colour palette ───────────────────────────────────────────────────────────────
DARK_NAVY  = colors.HexColor("#0D1B2A")
MID_BLUE   = colors.HexColor("#1B4F72")
ACCENT     = colors.HexColor("#2ECC71")
RED        = colors.HexColor("#E74C3C")
ORANGE     = colors.HexColor("#E67E22")
YELLOW     = colors.HexColor("#F1C40F")
LIGHT_GREY = colors.HexColor("#F2F3F4")
MID_GREY   = colors.HexColor("#BDC3C7")
WHITE      = colors.white

SEV_COLORS = {"HIGH": RED, "MEDIUM": ORANGE, "LOW": YELLOW}
VERDICT_COLORS = {"ROGUE": RED, "SUSPICIOUS": ORANGE, "LOW RISK": ACCENT}


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", parent=base["Title"],
                                 fontSize=22, textColor=WHITE,
                                 spaceAfter=4, alignment=TA_CENTER),
        "subtitle": ParagraphStyle("subtitle", parent=base["Normal"],
                                   fontSize=10, textColor=MID_GREY,
                                   alignment=TA_CENTER, spaceAfter=2),
        "h1": ParagraphStyle("h1", parent=base["Heading1"],
                              fontSize=14, textColor=MID_BLUE,
                              spaceBefore=14, spaceAfter=6, leading=18),
        "h2": ParagraphStyle("h2", parent=base["Heading2"],
                              fontSize=11, textColor=DARK_NAVY,
                              spaceBefore=8, spaceAfter=4),
        "body": ParagraphStyle("body", parent=base["Normal"],
                               fontSize=9, textColor=colors.HexColor("#2C3E50"),
                               leading=14, spaceAfter=4),
        "small": ParagraphStyle("small", parent=base["Normal"],
                                fontSize=8, textColor=colors.HexColor("#7F8C8D"),
                                leading=12),
        "code": ParagraphStyle("code", parent=base["Code"],
                               fontSize=8, textColor=DARK_NAVY,
                               backColor=LIGHT_GREY, leading=11),
        "verdict_rogue": ParagraphStyle("vr", parent=base["Normal"],
                                        fontSize=9, textColor=RED, fontName="Helvetica-Bold"),
        "verdict_susp":  ParagraphStyle("vs", parent=base["Normal"],
                                        fontSize=9, textColor=ORANGE, fontName="Helvetica-Bold"),
        "verdict_ok":    ParagraphStyle("vo", parent=base["Normal"],
                                        fontSize=9, textColor=ACCENT, fontName="Helvetica-Bold"),
    }


def _header_block(story, styles, stats, source_files, timestamp):
    """Dark banner header."""
    # Title table acting as coloured banner
    header_data = [[
        Paragraph("ROGUE ACCESS POINT DETECTION REPORT", styles["title"]),
    ]]
    t = Table(header_data, colWidths=[17*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), DARK_NAVY),
        ("TOPPADDING",    (0,0), (-1,-1), 18),
        ("BOTTOMPADDING", (0,0), (-1,-1), 18),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ("RIGHTPADDING",  (0,0), (-1,-1), 10),
        ("ROUNDEDCORNERS", [8]),
    ]))
    story.append(t)
    story.append(Spacer(1, 6))

    meta = [
        [Paragraph(f"<b>Institution:</b> Meru University of Science and Technology", styles["small"]),
         Paragraph(f"<b>Generated:</b> {timestamp}", styles["small"])],
        [Paragraph(f"<b>Student:</b> Silvia Muthoni Munene | CT206/109336/22", styles["small"]),
         Paragraph(f"<b>Supervisor:</b> Dr. Dorothy Bundi", styles["small"])],
        [Paragraph(f"<b>Captures analysed:</b> {', '.join(source_files)}", styles["small"]),
         Paragraph(f"<b>Total frames:</b> {stats['total_frames']:,}", styles["small"])],
    ]
    mt = Table(meta, colWidths=[9.5*cm, 7.5*cm])
    mt.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), LIGHT_GREY),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("RIGHTPADDING",  (0,0), (-1,-1), 8),
        ("GRID", (0,0), (-1,-1), 0.25, MID_GREY),
    ]))
    story.append(mt)
    story.append(Spacer(1, 10))


def _stat_cards(story, styles, stats):
    """4-cell stat card row."""
    cards = [
        (str(stats["total_frames"]),    "Total Frames",      MID_BLUE),
        (str(stats["unique_bssids"]),   "Unique BSSIDs",     MID_BLUE),
        (str(stats["rogue_count"]),     "Rogue APs",         RED),
        (str(stats["suspicious_count"]),"Suspicious APs",    ORANGE),
    ]
    row = []
    for val, label, col in cards:
        cell = Table(
            [[Paragraph(f'<font color="white" size="20"><b>{val}</b></font>', styles["body"])],
             [Paragraph(f'<font color="white" size="8">{label}</font>', styles["small"])]],
            colWidths=[3.8*cm]
        )
        cell.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), col),
            ("TOPPADDING",    (0,0), (-1,-1), 10),
            ("BOTTOMPADDING", (0,0), (-1,-1), 10),
            ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ]))
        row.append(cell)

    t = Table([row], colWidths=[4*cm, 4*cm, 4*cm, 4*cm], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("LEFTPADDING",  (0,0), (-1,-1), 3),
        ("RIGHTPADDING", (0,0), (-1,-1), 3),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))


def _severity_table(story, styles, stats):
    story.append(Paragraph("Finding Severity Breakdown", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GREY))
    story.append(Spacer(1, 6))

    data = [["Severity", "Count", "Risk Level"]]
    rows = [
        ("HIGH",   stats["severity_counts"].get("HIGH", 0),   "Critical — immediate action required"),
        ("MEDIUM", stats["severity_counts"].get("MEDIUM", 0), "Notable — investigate promptly"),
        ("LOW",    stats["severity_counts"].get("LOW", 0),    "Minor — monitor for escalation"),
    ]
    for sev, cnt, desc in rows:
        data.append([sev, str(cnt), desc])

    t = Table(data, colWidths=[3*cm, 2*cm, 12*cm])
    sev_fill = {"HIGH": colors.HexColor("#FDEDEC"),
                "MEDIUM": colors.HexColor("#FEF9E7"),
                "LOW": colors.HexColor("#EAFAF1")}
    ts = [
        ("BACKGROUND", (0,0), (-1,0), DARK_NAVY),
        ("TEXTCOLOR",  (0,0), (-1,0), WHITE),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 9),
        ("GRID",       (0,0), (-1,-1), 0.25, MID_GREY),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("ALIGN",      (1,1), (1,-1), "CENTER"),
    ]
    for i, (sev, _, _) in enumerate(rows, 1):
        ts.append(("BACKGROUND", (0,i), (-1,i), sev_fill[sev]))
        ts.append(("TEXTCOLOR",  (0,i), (0,i), SEV_COLORS[sev]))
        ts.append(("FONTNAME",   (0,i), (0,i), "Helvetica-Bold"))
    t.setStyle(TableStyle(ts))
    story.append(t)
    story.append(Spacer(1, 12))


def _bssid_table(story, styles, bssid_scores):
    story.append(Paragraph("Access Point Risk Summary", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GREY))
    story.append(Spacer(1, 6))

    data = [["BSSID", "SSID(s)", "Score", "Findings", "Verdict"]]
    sorted_bs = sorted(bssid_scores.values(), key=lambda x: -x["score"])
    for b in sorted_bs:
        data.append([
            b["bssid"],
            ", ".join(b["ssids"][:2]) or "—",
            str(b["score"]),
            str(b["finding_count"]),
            b["verdict"],
        ])

    t = Table(data, colWidths=[4*cm, 4.5*cm, 1.5*cm, 2*cm, 5*cm])
    ts = [
        ("BACKGROUND", (0,0), (-1,0), DARK_NAVY),
        ("TEXTCOLOR",  (0,0), (-1,0), WHITE),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 8),
        ("GRID",       (0,0), (-1,-1), 0.25, MID_GREY),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [WHITE, LIGHT_GREY]),
        ("ALIGN", (2,0), (3,-1), "CENTER"),
    ]
    for i, b in enumerate(sorted_bs, 1):
        vc = VERDICT_COLORS.get(b["verdict"], MID_BLUE)
        ts.append(("TEXTCOLOR",  (4,i), (4,i), vc))
        ts.append(("FONTNAME",   (4,i), (4,i), "Helvetica-Bold"))
        if b["verdict"] == "ROGUE":
            ts.append(("BACKGROUND", (0,i), (-1,i), colors.HexColor("#FDEDEC")))
    t.setStyle(TableStyle(ts))
    story.append(t)
    story.append(Spacer(1, 12))


def _findings_detail(story, styles, findings):
    story.append(Paragraph("Detailed Findings", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GREY))
    story.append(Spacer(1, 6))

    seen = set()
    for f in findings:
        key = (f["rule"], f.get("affected_bssid", ""), f.get("ssid", ""))
        if key in seen:
            continue
        seen.add(key)

        sev = f["severity"]
        sev_col = SEV_COLORS.get(sev, MID_BLUE)

        block = [
            [Paragraph(f'<b>{f["rule"]}</b>', styles["body"]),
             Paragraph(sev, ParagraphStyle("sv", fontSize=8,
                                           textColor=WHITE, fontName="Helvetica-Bold",
                                           alignment=TA_CENTER))],
            [Paragraph(f["detail"], styles["small"]), ""],
        ]
        bt = Table(block, colWidths=[14.5*cm, 2.5*cm])
        bt.setStyle(TableStyle([
            ("BACKGROUND", (1,0), (1,0), sev_col),
            ("BACKGROUND", (0,0), (0,0), colors.HexColor("#EAF2FB")),
            ("BACKGROUND", (0,1), (-1,1), WHITE),
            ("GRID",       (0,0), (-1,-1), 0.25, MID_GREY),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("SPAN",       (0,1), (1,1)),
            ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
            ("ALIGN",      (1,0), (1,0), "CENTER"),
        ]))
        story.append(KeepTogether([bt, Spacer(1, 5)]))


def _methodology_page(story, styles):
    """Brief methodology section explaining the 6 detection rules."""
    story.append(Paragraph("Detection Methodology", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GREY))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This system implements signature-based analysis of IEEE 802.11 wireless frames "
        "captured in a simulated campus environment. Six detection rules are applied to "
        "identify rogue access points based on frame anomalies, SSID conflicts, and "
        "signal behaviour patterns.",
        styles["body"]
    ))
    story.append(Spacer(1, 8))

    rules = [
        ("SSID Spoofing", "HIGH",
         "Detects when the same SSID is advertised by more than one distinct BSSID across "
         "captures. In a legitimate campus ESS, the same SSID may appear on multiple APs, "
         "but a new, unrecognised BSSID advertising a known SSID is a strong evil-twin indicator."),
        ("MAC Inconsistency", "HIGH",
         "In Beacon and ProbeResponse frames the transmitter address (addr2) must equal the "
         "BSSID field (addr3). A mismatch indicates frame injection or address spoofing — "
         "a hallmark of man-in-the-middle rogue AP deployment."),
        ("Unknown BSSID", "HIGH",
         "When an authorised BSSID whitelist is provided, any BSSID not appearing in that "
         "list is flagged immediately. This directly implements the signature comparison "
         "against authorised access point records described in the research objectives."),
        ("RSSI Anomaly", "MEDIUM",
         "Computes the Z-score of each BSSID's RSSI values across all frames. Readings "
         "deviating beyond 2.5 standard deviations suggest the device is positioned "
         "unusually close (rogue AP placed near victim) or that signal values are spoofed."),
        ("Probe Response Flood", "MEDIUM",
         "A rogue AP acting as a honeypot responds eagerly to every ProbeRequest. Any "
         "source BSSID sending more than three ProbeResponse frames within a single capture "
         "window is flagged as exhibiting honeypot behaviour."),
        ("MAC Timestamp Drift", "LOW",
         "The MAC-layer timestamp in Beacon frames should advance at the same rate as the "
         "system wall clock. A drift exceeding 500 ms per frame interval indicates replayed "
         "or synthesised frames — a characteristic of software-defined rogue APs."),
    ]

    data = [["Rule", "Severity", "Description"]]
    for name, sev, desc in rules:
        data.append([name, sev, desc])

    t = Table(data, colWidths=[3.8*cm, 2*cm, 11.2*cm])
    sev_fill = {"HIGH": colors.HexColor("#FDEDEC"),
                "MEDIUM": colors.HexColor("#FEF9E7"),
                "LOW": colors.HexColor("#EAFAF1")}
    ts = [
        ("BACKGROUND", (0,0), (-1,0), DARK_NAVY),
        ("TEXTCOLOR",  (0,0), (-1,0), WHITE),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 8),
        ("GRID",       (0,0), (-1,-1), 0.25, MID_GREY),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("VALIGN",     (0,0), (-1,-1), "TOP"),
    ]
    for i, (_, sev, _) in enumerate(rules, 1):
        ts.append(("BACKGROUND", (0,i), (-1,i), sev_fill[sev]))
        ts.append(("TEXTCOLOR",  (1,i), (1,i), SEV_COLORS[sev]))
        ts.append(("FONTNAME",   (1,i), (1,i), "Helvetica-Bold"))
        ts.append(("ALIGN",      (1,i), (1,i), "CENTER"))
    t.setStyle(TableStyle(ts))
    story.append(t)
    story.append(Spacer(1, 10))

    # Scoring table
    story.append(Paragraph("Risk Scoring System", styles["h2"]))
    score_data = [
        ["Severity", "Points", "Verdict Thresholds"],
        ["HIGH",   "3 pts", "ROGUE (HIGH CONFIDENCE): Score ≥ 5"],
        ["MEDIUM", "2 pts", "SUSPICIOUS: Score ≥ 3"],
        ["LOW",    "1 pt",  "LOW RISK: Score < 3"],
    ]
    st = Table(score_data, colWidths=[3*cm, 2.5*cm, 11.5*cm])
    sts = [
        ("BACKGROUND", (0,0), (-1,0), MID_BLUE),
        ("TEXTCOLOR",  (0,0), (-1,0), WHITE),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 8),
        ("GRID",       (0,0), (-1,-1), 0.25, MID_GREY),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [WHITE, LIGHT_GREY]),
    ]
    for i, (sev, *_) in enumerate([("HIGH",), ("MEDIUM",), ("LOW",)], 1):
        sts.append(("TEXTCOLOR", (0,i), (0,i), SEV_COLORS[sev]))
        sts.append(("FONTNAME",  (0,i), (0,i), "Helvetica-Bold"))
        sts.append(("TEXTCOLOR", (1,i), (1,i), SEV_COLORS[sev]))
    st.setStyle(TableStyle(sts))
    story.append(st)
    story.append(Spacer(1, 12))


def _recommendations(story, styles, stats):
    story.append(Spacer(1, 6))
    story.append(Paragraph("Recommendations", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GREY))
    story.append(Spacer(1, 6))

    recs = []
    if stats["rogue_count"] > 0:
        recs.append(("HIGH", "Immediately isolate and investigate all ROGUE-flagged BSSIDs. "
                              "Verify physical presence of the device on campus network infrastructure."))
    if stats["suspicious_count"] > 0:
        recs.append(("MEDIUM", "Monitor SUSPICIOUS-flagged BSSIDs closely. "
                               "Cross-reference against the authorised AP whitelist maintained by network administration."))
    if stats["severity_counts"].get("HIGH", 0) > 0:
        recs.append(("HIGH", "Investigate all HIGH-severity SSID Spoofing and MAC Inconsistency findings "
                              "— these are strong indicators of evil twin or frame injection attacks."))
    recs.append(("LOW", "Maintain and regularly update the authorised BSSID whitelist. "
                        "Schedule periodic wireless scans at minimum every 24 hours."))
    recs.append(("LOW", "Educate campus users to verify network authenticity before connecting "
                        "and to avoid networks with unfamiliar or duplicate SSIDs."))

    data = [["#", "Priority", "Action"]]
    for i, (p, txt) in enumerate(recs, 1):
        data.append([str(i), p, txt])

    t = Table(data, colWidths=[0.7*cm, 2*cm, 14.3*cm])
    ts = [
        ("BACKGROUND", (0,0), (-1,0), DARK_NAVY),
        ("TEXTCOLOR",  (0,0), (-1,0), WHITE),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 8),
        ("GRID",       (0,0), (-1,-1), 0.25, MID_GREY),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [WHITE, LIGHT_GREY]),
        ("ALIGN", (0,0), (1,-1), "CENTER"),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
    ]
    for i, (p, _) in enumerate(recs, 1):
        ts.append(("TEXTCOLOR", (1,i), (1,i), SEV_COLORS.get(p, MID_BLUE)))
        ts.append(("FONTNAME",  (1,i), (1,i), "Helvetica-Bold"))
    t.setStyle(TableStyle(ts))
    story.append(t)


def _footer(story, styles):
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=MID_GREY))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "Rogue AP Detection System · Meru University of Science and Technology · "
        "Bachelor of Science in Computer Security and Forensics · CT206/109336/22",
        ParagraphStyle("footer", fontSize=7, textColor=MID_GREY, alignment=TA_CENTER)
    ))


def generate_pdf(result, output_path):
    """
    Generate a full PDF report from a detection result dict.
    Returns output_path on success.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
        title="Rogue AP Detection Report",
        author="Silvia Muthoni Munene"
    )

    styles = _styles()
    story = []

    stats = result.get("stats", {})
    bssid_scores = result.get("bssid_scores", {})
    findings = result.get("findings", [])
    source_files = result.get("source_files", ["unknown"])

    _header_block(story, styles, stats, source_files, timestamp)
    _stat_cards(story, styles, stats)
    _severity_table(story, styles, stats)
    _bssid_table(story, styles, bssid_scores)
    _findings_detail(story, styles, findings)
    _methodology_page(story, styles)
    _recommendations(story, styles, stats)
    _footer(story, styles)

    doc.build(story)
    return output_path
