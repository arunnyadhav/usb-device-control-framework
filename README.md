# USB Device Control & Monitoring Framework

A defensive, blue-team endpoint-security toolkit that detects USB connect/disconnect
events in real time, fingerprints connected devices, enforces an allowlist/blocklist
policy, audits file movement to and from removable media, and generates a
timestamped security audit report.

Built as a security capstone project for a Computer Networks & Network Security /
Cybersecurity elective (B.E., Electronics & Communication Engineering).

---

## Why This Project

USB storage devices remain one of the most common vectors for insider data
exfiltration, malware introduction (e.g. BadUSB), and unauthorized physical access
on endpoint systems. Firewalls and network IDS/IPS don't see what walks in through
a USB port — this framework closes that gap by monitoring and controlling USB
activity directly at the endpoint.

## Features

- **Real-time USB detection** — captures every connect/disconnect event via the OS
- **Device fingerprinting** — identifies devices by Vendor ID, Product ID, and Serial Number
- **Allowlist / blocklist policy engine** — default-deny (zero-trust) posture
- **Spoofing detection** — flags devices that reuse an approved VID:PID with a mismatched serial
- **Auto-blocking** — denies unauthorized devices and logs every attempt
- **File-transfer auditing** — SHA-256 hashing of every file copied to/from approved USB media
- **Anomaly detection** — bulk-transfer and off-hours activity alerts
- **Structured logging** — JSON Lines + CSV event logs
- **Automated reporting** — final
