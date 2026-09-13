"""
anomaly_detector.py
--------------------
Flags suspicious patterns that a simple per-event allow/block decision
would miss: bulk data movement in one session, activity during
off-hours, and VID/PID reuse across different serials (possible
cloning campaign rather than a one-off spoof).
"""

from datetime import datetime
from typing import List

from . import settings
from .models import FileTransferRecord


class AnomalyDetector:
    def __init__(self):
        self._serial_history = {}  # device_id -> set of serials seen

    def check_bulk_transfer(self, file_ops: List[FileTransferRecord]) -> List[str]:
        alerts = []
        if not file_ops:
            return alerts
        total_bytes = sum(op.size_bytes for op in file_ops)
        total_mb = total_bytes / (1024 * 1024)
        if len(file_ops) >= settings.BULK_TRANSFER_FILE_COUNT_THRESHOLD:
            alerts.append(
                f"Bulk transfer: {len(file_ops)} files moved in one session "
                f"(threshold {settings.BULK_TRANSFER_FILE_COUNT_THRESHOLD})"
            )
        if total_mb >= settings.BULK_TRANSFER_SIZE_MB_THRESHOLD:
            alerts.append(
                f"Bulk transfer: {total_mb:.1f} MB moved in one session "
                f"(threshold {settings.BULK_TRANSFER_SIZE_MB_THRESHOLD} MB)"
            )
        return alerts

    def check_off_hours(self, timestamp: str = None) -> List[str]:
        ts = datetime.fromisoformat(timestamp) if timestamp else datetime.now()
        hour = ts.hour
        if hour >= settings.OFF_HOURS_START_HOUR or hour < settings.OFF_HOURS_END_HOUR:
            return [f"Off-hours USB activity detected at {ts.strftime('%H:%M')}"]
        return []

    def check_serial_reuse(self, device_id: str, serial: str) -> List[str]:
        seen = self._serial_history.setdefault(device_id, set())
        alerts = []
        if seen and serial not in seen and len(seen) >= 1:
            alerts.append(
                f"VID:PID {device_id} previously seen with different serial(s) "
                f"{sorted(seen)} -- now presenting {serial!r}; possible cloned identity"
            )
        seen.add(serial)
        return alerts
