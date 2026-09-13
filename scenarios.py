"""
scenarios.py
------------
A scripted sequence of USBDeviceEvent objects used by main.py in
`--demo` mode, so the framework's behaviour can be graded/reviewed
deterministically without physical USB hardware. Mirrors the kinds of
events called out in the project spec (approved device, unauthorized
device auto-blocked, spoofed serial detected).
"""

from .models import USBDeviceEvent

DEMO_EVENTS = [
    # 1. Approved storage device (matches allowlist exactly) -> ALLOW
    USBDeviceEvent(vendor_id="0781", product_id="5591", serial_number="AA010203040506",
                    device_class="Mass Storage", action="CONNECT", mount_point="/media/usb0"),

    # 2. Approved peripheral (no serial required) -> ALLOW
    USBDeviceEvent(vendor_id="046d", product_id="c52b", serial_number=None,
                    device_class="HID", action="CONNECT"),

    # 3. Unknown storage device, never seen before -> BLOCK (default-deny)
    USBDeviceEvent(vendor_id="0930", product_id="6544", serial_number="TC58NC9010",
                    device_class="Mass Storage", action="CONNECT", mount_point="/media/usb1"),

    # 4. Explicitly blocklisted device (flagged BadUSB signature) -> BLOCK
    USBDeviceEvent(vendor_id="1234", product_id="5678", serial_number="ANYSERIAL01",
                    device_class="HID", action="CONNECT"),

    # 5. Spoofed device: correct VID:PID of the approved SanDisk drive,
    #    but a serial number that doesn't match -> BLOCK (spoof-check)
    USBDeviceEvent(vendor_id="0781", product_id="5591", serial_number="FAKE-CLONE-9999",
                    device_class="Mass Storage", action="CONNECT", mount_point="/media/usb2"),

    # 6. Previously reported lost/stolen device reconnecting -> BLOCK
    USBDeviceEvent(vendor_id="0951", product_id="1666", serial_number="LOST-0099",
                    device_class="Mass Storage", action="CONNECT", mount_point="/media/usb3"),

    # 7. A second unknown device, different VID:PID -> BLOCK
    USBDeviceEvent(vendor_id="13fe", product_id="4200", serial_number="KING0002211",
                    device_class="Mass Storage", action="CONNECT", mount_point="/media/usb4"),

    # 8. Approved hub -> ALLOW
    USBDeviceEvent(vendor_id="05e3", product_id="0608", serial_number=None,
                    device_class="Hub", action="CONNECT"),
]

# Simulated file operations performed on the ALLOWED SanDisk drive
# (device #1 above) during its session -- used to demonstrate the
# file-auditing module and a deliberately large "bulk transfer" to
# trigger the anomaly detector.
DEMO_FILE_OPS_DEVICE = "0781:5591"
DEMO_FILE_NAMES = [f"project_report_v{i}.docx" for i in range(1, 12)] + \
                   [f"dataset_part_{i}.csv" for i in range(1, 15)] + \
                   ["confidential_salary_sheet.xlsx", "source_code_backup.zip"]
