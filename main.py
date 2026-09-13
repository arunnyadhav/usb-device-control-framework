"""
main.py
-------
Command-line entry point that wires every module together:

    Monitor -> Fingerprint -> Policy Engine -> Enforcement
                                   |
                                   v
                          File Audit + Anomaly Detector
                                   |
                                   v
                          Logger -> Report Generator

Usage:
    python -m usbguard.main --demo          # scripted, deterministic run
    python -m usbguard.main --live          # real OS monitoring (Win/Linux)
    python -m usbguard.main --report-only   # just rebuild the report from
                                             # existing logs
"""

import argparse
import os
import shutil
import tempfile
import time

from . import settings
from .device_monitor import get_monitor, SimulatedMonitor
from .policy_engine import PolicyEngine
from .enforcement import EnforcementModule
from .file_audit import FileAuditEngine, _snapshot
from .anomaly_detector import AnomalyDetector
from .logger import EventLogger
from .models import AuditLogEntry
from .report_generator import generate_reports
from . import scenarios


def reset_logs():
    if os.path.isdir(settings.LOG_DIR):
        shutil.rmtree(settings.LOG_DIR)
    if os.path.isdir(settings.REPORT_DIR):
        shutil.rmtree(settings.REPORT_DIR)
    os.makedirs(settings.LOG_DIR, exist_ok=True)
    os.makedirs(settings.REPORT_DIR, exist_ok=True)


def run_demo_file_audit(logger: EventLogger, anomaly: AnomalyDetector):
    """Creates a scratch 'USB volume' directory, copies the demo file
    list into it (simulating a user copying files onto approved
    storage), and runs the file-auditing diff so the CSV log and
    anomaly alerts are populated with realistic data."""
    tmp_root = tempfile.mkdtemp(prefix="usbguard_demo_volume_")
    before = _snapshot(tmp_root)

    for name in scenarios.DEMO_FILE_NAMES:
        path = os.path.join(tmp_root, name)
        # Deterministic pseudo-content sized by filename so hashes/sizes
        # are stable across runs but still look like real files.
        size_kb = (abs(hash(name)) % 400) + 20
        with open(path, "wb") as f:
            f.write((name + "\n").encode() * (size_kb * 1024 // (len(name) + 1) + 1))

    after = _snapshot(tmp_root)
    audit = FileAuditEngine(device_id=scenarios.DEMO_FILE_OPS_DEVICE)
    file_ops = audit.diff_snapshots(before, after)

    for op in file_ops:
        logger.log_file_transfer(op)

    alerts = anomaly.check_bulk_transfer(file_ops)
    for msg in alerts:
        logger.alert(msg, severity="WARNING")

    shutil.rmtree(tmp_root, ignore_errors=True)
    return file_ops, alerts


def process_event(event, policy: PolicyEngine, enforcement: EnforcementModule,
                   logger: EventLogger, anomaly: AnomalyDetector):
    decision = policy.evaluate(event)
    action_taken = enforcement.enforce(event, decision)

    spoof_alerts = []
    if event.serial_number:
        spoof_alerts = anomaly.check_serial_reuse(event.device_id, event.serial_number)
    offhours_alerts = anomaly.check_off_hours(event.timestamp)

    entry = AuditLogEntry(event=event, decision=decision, file_ops=[])
    logger.log_entry(entry)

    if decision.decision == "BLOCK":
        logger.alert(f"Unauthorized USB detected: {event.device_id} "
                      f"(serial={event.serial_number}) -> {action_taken}",
                      severity=decision.severity)
    for msg in spoof_alerts + offhours_alerts:
        logger.alert(msg, severity="WARNING")

    return entry


def main():
    parser = argparse.ArgumentParser(description=settings.FRAMEWORK_NAME)
    parser.add_argument("--demo", action="store_true", help="Run the scripted demo scenario")
    parser.add_argument("--live", action="store_true", help="Run real OS-level monitoring")
    parser.add_argument("--report-only", action="store_true", help="Only regenerate the report from existing logs")
    parser.add_argument("--keep-logs", action="store_true", help="Do not clear logs from a previous run")
    args = parser.parse_args()

    if args.report_only:
        text_path, html_path, summary = generate_reports()
        print(f"Report regenerated:\n  {text_path}\n  {html_path}")
        return

    if not args.keep_logs:
        reset_logs()

    logger = EventLogger()
    policy = PolicyEngine()
    enforcement = EnforcementModule()
    anomaly = AnomalyDetector()

    print("=" * 78)
    print(f"{settings.FRAMEWORK_NAME} -- starting run")
    print(f"Mode: {'LIVE' if args.live else 'DEMO (simulated)'}")
    print("=" * 78)

    if args.live:
        monitor = get_monitor(mode="auto")
    else:
        monitor = SimulatedMonitor(scripted_events=scenarios.DEMO_EVENTS, delay_seconds=0.15)

    for event in monitor.events():
        process_event(event, policy, enforcement, logger, anomaly)

    if not args.live:
        print("-" * 78)
        print("Simulating file-transfer session on the approved storage device...")
        file_ops, alerts = run_demo_file_audit(logger, anomaly)
        print(f"Audited {len(file_ops)} file operation(s).")
        for a in alerts:
            print(f"  ANOMALY: {a}")

    print("-" * 78)
    text_path, html_path, summary = generate_reports()
    print(f"Final report written to:\n  {text_path}\n  {html_path}")
    print(f"Summary: {summary['total_events']} events "
          f"({summary['allowed']} allowed / {summary['blocked']} blocked), "
          f"{summary['file_ops_count']} file ops audited.")
    print("=" * 78)


if __name__ == "__main__":
    main()
