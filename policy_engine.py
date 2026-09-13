"""
policy_engine.py
-----------------
Loads the allowlist/blocklist and decides ALLOW vs BLOCK for every
USBDeviceEvent, including a basic spoofing heuristic (VID:PID matches
an approved device but the serial number does not).
"""

import json
from typing import Dict, List, Optional

from . import settings
from .models import USBDeviceEvent, PolicyDecision


class PolicyEngine:
    def __init__(self, allowlist_path: str = settings.ALLOWLIST_PATH,
                 blocklist_path: str = settings.BLOCKLIST_PATH,
                 default_deny_unknown: bool = settings.DEFAULT_DENY_UNKNOWN_DEVICES):
        self.default_deny_unknown = default_deny_unknown
        self.allowlist = self._load(allowlist_path).get("approved_devices", [])
        self.blocklist = self._load(blocklist_path).get("banned_devices", [])
        self._allow_index: Dict[str, List[dict]] = {}
        for entry in self.allowlist:
            self._allow_index.setdefault(entry["device_id"].lower(), []).append(entry)
        self._block_index: Dict[str, List[dict]] = {}
        for entry in self.blocklist:
            self._block_index.setdefault(entry["device_id"].lower(), []).append(entry)

    @staticmethod
    def _load(path: str) -> dict:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def evaluate(self, event: USBDeviceEvent) -> PolicyDecision:
        device_id = event.device_id

        # 1. Explicit blocklist always wins.
        if device_id in self._block_index:
            for entry in self._block_index[device_id]:
                if entry.get("serial") in (None, event.serial_number):
                    return PolicyDecision(
                        decision="BLOCK",
                        reason=f"Device explicitly banned: {entry.get('reason', 'no reason given')}",
                        matched_rule=f"blocklist:{device_id}",
                        severity="CRITICAL",
                    )

        # 2. Allowlist match.
        if device_id in self._allow_index:
            for entry in self._allow_index[device_id]:
                required_serial = entry.get("serial")
                if required_serial is None or required_serial == event.serial_number:
                    return PolicyDecision(
                        decision="ALLOW",
                        reason=f"Matched approved device: {entry.get('label', device_id)}",
                        matched_rule=f"allowlist:{device_id}",
                        severity="INFO",
                    )
            # VID:PID matches an approved entry but serial differs ->
            # possible spoofed / cloned device identity.
            return PolicyDecision(
                decision="BLOCK",
                reason=(f"Serial mismatch for known VID:PID {device_id} "
                        f"(got {event.serial_number!r}) -- possible spoofed device"),
                matched_rule=f"spoof-check:{device_id}",
                severity="CRITICAL",
            )

        # 3. Unknown device.
        if self.default_deny_unknown:
            return PolicyDecision(
                decision="BLOCK",
                reason="Device not present in allowlist (default-deny policy)",
                matched_rule="default-deny",
                severity="WARNING",
            )
        return PolicyDecision(
            decision="ALLOW",
            reason="Unknown device permitted under learning-mode policy",
            matched_rule="learning-mode",
            severity="WARNING",
        )

    def add_to_allowlist(self, device_id: str, serial: Optional[str], label: str, owner: str = "unspecified"):
        """Runtime helper (e.g. an admin approving a device from a prompt)."""
        entry = {"device_id": device_id.lower(), "serial": serial, "label": label, "owner": owner}
        self.allowlist.append(entry)
        self._allow_index.setdefault(device_id.lower(), []).append(entry)
