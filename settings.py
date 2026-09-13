"""
settings.py
-----------
Central configuration for the USB Device Control & Monitoring Framework.
Kept in one place so a viva/demo can tweak thresholds without touching
core logic.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ---- Paths -----------------------------------------------------------
ALLOWLIST_PATH = os.path.join(BASE_DIR, "config", "allowlist.json")
BLOCKLIST_PATH = os.path.join(BASE_DIR, "config", "blocklist.json")
LOG_DIR = os.path.join(BASE_DIR, "logs")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
JSON_LOG_PATH = os.path.join(LOG_DIR, "usb_events.jsonl")
CSV_LOG_PATH = os.path.join(LOG_DIR, "usb_events.csv")
FILE_AUDIT_LOG_PATH = os.path.join(LOG_DIR, "file_transfers.csv")

# ---- Policy engine -----------------------------------------------------
# If True, a device not present in EITHER list is denied by default
# (default-deny / zero-trust posture). If False, unknown devices are
# allowed with a WARNING logged (useful for a "learning mode" rollout).
DEFAULT_DENY_UNKNOWN_DEVICES = True

# ---- Enforcement -------------------------------------------------------
# In a real Windows/Linux deployment this toggles whether the
# enforcement module actually disables the USB mass-storage class
# (requires admin/root). Kept False in the sandbox demo so the toolkit
# only *simulates* the OS-level disable call and logs what it would run.
ENABLE_LIVE_ENFORCEMENT = False

# ---- Anomaly detection thresholds --------------------------------------
BULK_TRANSFER_FILE_COUNT_THRESHOLD = 20          # files in one session
BULK_TRANSFER_SIZE_MB_THRESHOLD = 500            # MB in one session
OFF_HOURS_START_HOUR = 21                        # 9 PM
OFF_HOURS_END_HOUR = 6                           # 6 AM

# ---- Reporting -----------------------------------------------------
ORG_NAME = "Department of Electronics & Communication Engineering"
FRAMEWORK_NAME = "USB Device Control & Monitoring Framework"
