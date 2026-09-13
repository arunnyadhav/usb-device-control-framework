"""
report_generator.py
--------------------
Reads back the JSONL event log and file-transfer CSV produced during a
run and compiles a final human-readable security audit report
(plain-text and HTML), matching the "Reporting & Alerting Module"
requirement in the project specification.
"""

import csv
import json
import os
from collections import Counter
from datetime import datetime

from . import settings


def _load_events():
    events = []
    if os.path.exists(settings.JSON_LOG_PATH):
        with open(settings.JSON_LOG_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    return events


def _load_file_ops():
    ops = []
    if os.path.exists(settings.FILE_AUDIT_LOG_PATH):
        with open(settings.FILE_AUDIT_LOG_PATH, encoding="utf-8") as f:
            ops = list(csv.DictReader(f))
    return ops


def build_summary():
    events = _load_events()
    file_ops = _load_file_ops()

    total = len(events)
    allowed = sum(1 for e in events if e["decision"] == "ALLOW")
    blocked = sum(1 for e in events if e["decision"] == "BLOCK")
    critical = sum(1 for e in events if e["severity"] == "CRITICAL")
    device_counter = Counter(e["device_id"] for e in events)
    blocked_devices = Counter(e["device_id"] for e in events if e["decision"] == "BLOCK")
    total_bytes = sum(int(op["size_bytes"]) for op in file_ops if op["size_bytes"].isdigit())

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "total_events": total,
        "allowed": allowed,
        "blocked": blocked,
        "critical_alerts": critical,
        "unique_devices": len(device_counter),
        "most_active_devices": device_counter.most_common(5),
        "top_blocked_devices": blocked_devices.most_common(5),
        "file_ops_count": len(file_ops),
        "total_bytes_moved": total_bytes,
        "events": events,
        "file_ops": file_ops,
    }


def render_text_report(summary: dict) -> str:
    lines = []
    lines.append("=" * 78)
    lines.append(f"{settings.FRAMEWORK_NAME.upper()} -- FINAL SECURITY AUDIT REPORT")
    lines.append(f"{settings.ORG_NAME}")
    lines.append("=" * 78)
    lines.append(f"Generated: {summary['generated_at']}")
    lines.append("")
    lines.append("SUMMARY")
    lines.append("-" * 78)
    lines.append(f"Total USB events observed      : {summary['total_events']}")
    lines.append(f"  Allowed                       : {summary['allowed']}")
    lines.append(f"  Blocked                       : {summary['blocked']}")
    lines.append(f"  Critical-severity alerts      : {summary['critical_alerts']}")
    lines.append(f"Unique devices seen             : {summary['unique_devices']}")
    lines.append(f"File operations audited         : {summary['file_ops_count']}")
    lines.append(f"Total data volume moved         : {summary['total_bytes_moved']/1024/1024:.2f} MB")
    lines.append("")
    lines.append("MOST ACTIVE DEVICES")
    lines.append("-" * 78)
    for device_id, count in summary["most_active_devices"]:
        lines.append(f"  {device_id:12s}  {count} event(s)")
    lines.append("")
    lines.append("TOP BLOCKED / UNAUTHORIZED DEVICES")
    lines.append("-" * 78)
    if summary["top_blocked_devices"]:
        for device_id, count in summary["top_blocked_devices"]:
            lines.append(f"  {device_id:12s}  {count} blocked attempt(s)")
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("DETAILED EVENT LOG")
    lines.append("-" * 78)
    for e in summary["events"]:
        lines.append(
            f"  {e['timestamp']}  {e['decision']:6s} {e['severity']:8s} "
            f"{e['device_id']:12s} serial={e.get('serial_number')}"
        )
        lines.append(f"      reason: {e['reason']}")
    lines.append("")
    lines.append("FILE TRANSFER AUDIT TRAIL")
    lines.append("-" * 78)
    for op in summary["file_ops"]:
        size_kb = int(op["size_bytes"]) / 1024 if op["size_bytes"].isdigit() else 0
        lines.append(
            f"  {op['timestamp']}  {op['operation']:14s} {op['file_name']} "
            f"({size_kb:.1f} KB) sha256={op['sha256'][:16]}..."
        )
    lines.append("")
    lines.append("=" * 78)
    lines.append("END OF REPORT")
    lines.append("=" * 78)
    return "\n".join(lines)


def render_html_report(summary: dict) -> str:
    def esc(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    rows = "".join(
        f"<tr class='{ 'blocked' if e['decision']=='BLOCK' else 'allowed' }'>"
        f"<td>{esc(e['timestamp'])}</td><td>{esc(e['device_id'])}</td>"
        f"<td>{esc(e.get('serial_number'))}</td><td>{esc(e['decision'])}</td>"
        f"<td>{esc(e['severity'])}</td><td>{esc(e['reason'])}</td></tr>"
        for e in summary["events"]
    )
    file_rows = "".join(
        f"<tr><td>{esc(op['timestamp'])}</td><td>{esc(op['operation'])}</td>"
        f"<td>{esc(op['file_name'])}</td><td>{int(op['size_bytes'])/1024:.1f} KB</td>"
        f"<td><code>{esc(op['sha256'][:20])}...</code></td></tr>"
        for op in summary["file_ops"]
    )

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>USB Security Audit Report</title>
<style>
 body {{ font-family: Segoe UI, Arial, sans-serif; margin: 32px; color: #1B2A4A; }}
 h1 {{ color: #1B2A4A; }}
 .meta {{ color: #5B6472; margin-bottom: 24px; }}
 .cards {{ display: flex; gap: 16px; margin-bottom: 28px; flex-wrap: wrap; }}
 .card {{ background: #EAF1FB; border: 1px solid #2E5EAA; border-radius: 8px;
          padding: 14px 20px; min-width: 160px; }}
 .card b {{ font-size: 22px; display:block; }}
 table {{ border-collapse: collapse; width: 100%; margin-bottom: 32px; font-size: 13px; }}
 th, td {{ border: 1px solid #D7DCE3; padding: 6px 10px; text-align: left; }}
 th {{ background: #1B2A4A; color: white; }}
 tr.blocked {{ background: #FBEAEA; }}
 tr.allowed {{ background: #EAF7EF; }}
</style></head>
<body>
<h1>{esc(settings.FRAMEWORK_NAME)} &mdash; Final Security Audit Report</h1>
<div class="meta">{esc(settings.ORG_NAME)}<br>Generated: {esc(summary['generated_at'])}</div>
<div class="cards">
  <div class="card">Total Events<b>{summary['total_events']}</b></div>
  <div class="card">Allowed<b>{summary['allowed']}</b></div>
  <div class="card">Blocked<b>{summary['blocked']}</b></div>
  <div class="card">Critical Alerts<b>{summary['critical_alerts']}</b></div>
  <div class="card">Unique Devices<b>{summary['unique_devices']}</b></div>
  <div class="card">Data Moved<b>{summary['total_bytes_moved']/1024/1024:.2f} MB</b></div>
</div>
<h2>Detailed Event Log</h2>
<table>
<tr><th>Timestamp</th><th>Device ID</th><th>Serial</th><th>Decision</th><th>Severity</th><th>Reason</th></tr>
{rows}
</table>
<h2>File Transfer Audit Trail</h2>
<table>
<tr><th>Timestamp</th><th>Operation</th><th>File</th><th>Size</th><th>SHA-256</th></tr>
{file_rows}
</table>
</body></html>"""


def generate_reports():
    os.makedirs(settings.REPORT_DIR, exist_ok=True)
    summary = build_summary()

    text_path = os.path.join(settings.REPORT_DIR, "usb_security_audit_report.txt")
    with open(text_path, "w", encoding="utf-8") as f:
        f.write(render_text_report(summary))

    html_path = os.path.join(settings.REPORT_DIR, "usb_security_audit_report.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(render_html_report(summary))

    return text_path, html_path, summary
