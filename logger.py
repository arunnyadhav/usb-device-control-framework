"""
logger.py
---------
Writes every AuditLogEntry to two parallel sinks:
  * usb_events.jsonl  -- one JSON object per line (machine-readable,
                          easy to feed into a SIEM later)
  * usb_events.csv    -- flat table (easy to open in Excel for a
                          human reviewer / evaluator)

Also exposes a `console` helper for the live terminal feed shown
during a demo run.
"""

import csv
import json
import os
from datetime import datetime

from . import settings
from .models import AuditLogEntry, FileTransferRecord

CSV_FIELDS = ["timestamp", "device_id", "serial_number", "device_class",
              "action", "decision", "severity", "reason", "matched_rule",
              "file_op_count"]

FILE_AUDIT_FIELDS = ["timestamp", "device_id", "operation", "file_name",
                      "size_bytes", "sha256"]


class EventLogger:
    def __init__(self):
        os.makedirs(settings.LOG_DIR, exist_ok=True)
        self._ensure_csv_header(settings.CSV_LOG_PATH, CSV_FIELDS)
        self._ensure_csv_header(settings.FILE_AUDIT_LOG_PATH, FILE_AUDIT_FIELDS)

    @staticmethod
    def _ensure_csv_header(path, fields):
        if not os.path.exists(path):
            with open(path, "w", newline="", encoding="utf-8") as f:
                csv.DictWriter(f, fieldnames=fields).writeheader()

    def log_entry(self, entry: AuditLogEntry):
        record = entry.to_dict()

        with open(settings.JSON_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        with open(settings.CSV_LOG_PATH, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            writer.writerow({k: record.get(k, "") for k in CSV_FIELDS})

        for op in entry.file_ops:
            self.log_file_transfer(op)

        self.console(entry)

    def log_file_transfer(self, op: FileTransferRecord):
        with open(settings.FILE_AUDIT_LOG_PATH, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FILE_AUDIT_FIELDS)
            writer.writerow(op.to_dict())

    @staticmethod
    def console(entry: AuditLogEntry):
        icon = {"ALLOW": "[ALLOW]", "BLOCK": "[BLOCK]"}.get(entry.decision.decision, "[----]")
        sev = entry.decision.severity
        ts = entry.event.timestamp
        print(f"{ts}  {icon:8s} {sev:8s} {entry.event.device_id:9s} "
              f"serial={str(entry.event.serial_number):16s} -> {entry.decision.reason}")

    @staticmethod
    def alert(message: str, severity: str = "WARNING"):
        ts = datetime.now().isoformat(timespec="seconds")
        line = f"{ts}  [ALERT:{severity}] {message}"
        print(line)
        os.makedirs(settings.LOG_DIR, exist_ok=True)
        with open(os.path.join(settings.LOG_DIR, "alerts.log"), "a", encoding="utf-8") as f:
            f.write(line + "\n")
