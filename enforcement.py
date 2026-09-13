"""
enforcement.py
---------------
Acts on a PolicyDecision. On a real Windows host with admin rights,
BLOCK can disable the USB mass-storage class for that device via the
registry (UsbStor start=4) or PnP device disable; on Linux, via
`udevadm` rules or `authorized` sysfs toggles. Those OS calls are
represented here but gated behind settings.ENABLE_LIVE_ENFORCEMENT so
the toolkit is safe to run in a classroom/demo/grading environment
without requiring elevated privileges or touching the host's real
device state.
"""

import platform
import subprocess

from . import settings
from .models import USBDeviceEvent, PolicyDecision


class EnforcementModule:
    def __init__(self, live: bool = settings.ENABLE_LIVE_ENFORCEMENT):
        self.live = live
        self.system = platform.system().lower()

    def enforce(self, event: USBDeviceEvent, decision: PolicyDecision) -> str:
        """Returns a human-readable action string for logging."""
        if decision.decision == "ALLOW":
            return f"Access granted to {event.device_id} (serial={event.serial_number})"

        action_cmd = self._build_block_command(event)
        if self.live:
            try:
                subprocess.run(action_cmd, shell=False, check=True,
                                capture_output=True, timeout=5)
                return f"BLOCKED: executed '{' '.join(action_cmd)}'"
            except Exception as exc:
                return f"BLOCK ATTEMPTED but OS call failed ({exc}); device denied at policy layer"
        else:
            return (f"BLOCKED (simulated): would run "
                    f"'{' '.join(action_cmd)}' on a live host")

    def _build_block_command(self, event: USBDeviceEvent):
        if self.system == "windows":
            # Disables the PnP device instance matching this VID/PID.
            return ["powershell", "-Command",
                    f"Disable-PnpDevice -InstanceId '*VID_{event.vendor_id}&PID_{event.product_id}*' -Confirm:$false"]
        elif self.system == "linux":
            # Revokes authorization for the USB device at the sysfs level.
            return ["sh", "-c",
                    f"echo 0 > /sys/bus/usb/devices/*{event.vendor_id}:{event.product_id}*/authorized"]
        else:
            return ["echo", f"block {event.device_id}"]
