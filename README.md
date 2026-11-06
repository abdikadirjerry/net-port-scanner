# Network Port & Vulnerability Scanner (`net-port-scanner`)

A multi-threaded Python CLI utility designed for network reconnaissance, open TCP port detection, service banner grabbing, and basic security risk auditing.

## Features
- Multi-threaded TCP port scanner for rapid network assessment.
- Service banner grabbing to identify running daemons.
- Automatic risk tagging for unencrypted or standard high-risk ports.
- Automated JSON export for audit logs.

## Setup & Usage
```bash
# Run a scan against localhost or a target IP
python3 src/scanner.py --target 127.0.0.1 --ports 20-100 --threads 20