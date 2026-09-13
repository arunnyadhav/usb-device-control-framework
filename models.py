"""
models.py
---------
Plain-data classes shared across the framework's modules, matching the
data model described in the project documentation
(USBDeviceEvent, PolicyRecord, AuditLogEntry, FileTransferRecord).
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List


@dataclass
class USBDeviceEvent:
    """Represents a single connect/disconnect event captured from the OS."""
    vendor_id: str          # e.g. "0781"
    product_id: str         # e.g. "5591"
    serial_number: Optional[str]
    device_class: str       # e.g. "Mass Storage", "HID", "Hub"
    action: str              # "CONNECT" | "DISCONNECT"
    mount_point: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    @property
    def device_id(self) -> str:
        return f"{self.vendor_id.lower()}:{self.product_id.lower()}"

    def to_dict(self) -> dict:
        return {
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "device_id": self.device_id,
            "serial_number": self.serial_number,
            "device_class": self.device_class,
            "action": self.action,
            "mount_point": self.mount_point,
            "timestamp": self.timestamp,
        }


@dataclass
class PolicyDecision:
    """Result of evaluating a USBDeviceEvent against the allow/blocklist."""
    decision: str            # "ALLOW" | "BLOCK"
    reason: str
    matched_rule: Optional[str] = None
    severity: str = "INFO"   # INFO | WARNING | CRITICAL


@dataclass
class FileTransferRecord:
    """A single file operation observed on a mounted USB volume."""
    file_name: str
    operation: str            # COPY_TO_USB | COPY_FROM_USB | DELETE | MODIFY
    size_bytes: int
    sha256: str
    device_id: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    def to_dict(self) -> dict:
        return {
            "file_name": self.file_name,
            "operation": self.operation,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "device_id": self.device_id,
            "timestamp": self.timestamp,
        }


@dataclass
class AuditLogEntry:
    """A fully-resolved, loggable record combining event + decision."""
    event: USBDeviceEvent
    decision: PolicyDecision
    file_ops: List[FileTransferRecord] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.event.to_dict()
        d.update({
            "decision": self.decision.decision,
            "reason": self.decision.reason,
            "matched_rule": self.decision.matched_rule,
            "severity": self.decision.severity,
            "file_op_count": len(self.file_ops),
        })
        return d
