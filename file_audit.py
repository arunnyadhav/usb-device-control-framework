"""
file_audit.py
-------------
Watches a mounted USB volume for file copy/delete/modify operations
and produces FileTransferRecord entries, including a SHA-256 hash of
each file for integrity/forensic tracking.

Real deployment: point `watch_directory()` at the drive letter /
mount path the OS assigned to the USB device (e.g. "E:\\" on Windows
or "/media/<user>/<label>" on Linux) and it will diff directory
snapshots taken a configurable interval apart. `watchdog` can be
substituted for real-time inotify/ReadDirectoryChangesW events; a
polling diff is used here so the module has zero extra OS-level
dependencies and is easy to demo deterministically.
"""

import hashlib
import os
import time
from typing import Dict, List, Optional

from .models import FileTransferRecord


def sha256_of_file(path: str, chunk_size: int = 65536) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError):
        return "unreadable"


def _snapshot(directory: str) -> Dict[str, dict]:
    snap = {}
    if not os.path.isdir(directory):
        return snap
    for root, _, files in os.walk(directory):
        for name in files:
            full = os.path.join(root, name)
            try:
                stat = os.stat(full)
                snap[full] = {"size": stat.st_size, "mtime": stat.st_mtime}
            except OSError:
                continue
    return snap


class FileAuditEngine:
    def __init__(self, device_id: str):
        self.device_id = device_id

    def diff_snapshots(self, before: Dict[str, dict], after: Dict[str, dict]) -> List[FileTransferRecord]:
        records = []
        before_keys, after_keys = set(before), set(after)

        for new_file in after_keys - before_keys:
            records.append(FileTransferRecord(
                file_name=new_file,
                operation="COPY_TO_USB",
                size_bytes=after[new_file]["size"],
                sha256=sha256_of_file(new_file),
                device_id=self.device_id,
            ))

        for removed_file in before_keys - after_keys:
            records.append(FileTransferRecord(
                file_name=removed_file,
                operation="DELETE",
                size_bytes=before[removed_file]["size"],
                sha256="n/a (deleted)",
                device_id=self.device_id,
            ))

        for common in before_keys & after_keys:
            if before[common]["mtime"] != after[common]["mtime"]:
                records.append(FileTransferRecord(
                    file_name=common,
                    operation="MODIFY",
                    size_bytes=after[common]["size"],
                    sha256=sha256_of_file(common),
                    device_id=self.device_id,
                ))
        return records

    def watch_directory(self, directory: str, interval_seconds: float = 2.0,
                         iterations: Optional[int] = None):
        """Polling generator: yields List[FileTransferRecord] each interval.
        `iterations=None` runs forever (real deployment); pass a small
        integer for a bounded demo run."""
        before = _snapshot(directory)
        count = 0
        while iterations is None or count < iterations:
            time.sleep(interval_seconds)
            after = _snapshot(directory)
            changes = self.diff_snapshots(before, after)
            if changes:
                yield changes
            before = after
            count += 1
