#!/usr/bin/env python3
"""
Network Port & Vulnerability Scanner (net-port-scanner)
Multi-threaded TCP port scanner with banner grabbing and risk auditing capabilities.
"""

import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Tuple

HIGH_RISK_PORTS = {
    21: "FTP (Unencrypted File Transfer)",
    23: "Telnet (Unencrypted Remote Management)",
    80: "HTTP (Cleartext Web Server)",
    110: "POP3 (Cleartext Email Retrieval)",
    143: "IMAP (Cleartext Email Access)",
    3389: "RDP (Remote Desktop Protocol)",
}


def grab_banner(target_ip: str, port: int, timeout: float = 1.5) -> Optional[str]:
    """Attempts to retrieve the service banner header from an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target_ip, port))
            # Send HTTP HEAD request if port 80/8080, else probe generic daemon header
            if port in [80, 8080]:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            else:
                s.sendall(b"\r\n")
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner if banner else None
    except Exception:
        return None


def probe_port(target_ip: str, port: int, timeout: float = 1.0) -> Optional[Dict]:
    """Probes a single TCP port and assesses risk if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                banner = grab_banner(target_ip, port)
                risk = HIGH_RISK_PORTS.get(port, "Standard TCP Service")
                severity = "High" if port in [21, 23] else ("Medium" if port in [80, 3389] else "Low")
                return {
                    "port": port,
                    "status": "open",
                    "service_risk": risk,
                    "severity": severity,
                    "banner": banner,
                }
    except Exception:
        pass
    return None


def run_scan(target_host: str, start_port: int, end_port: int, max_threads: int = 50) -> Dict:
    """Executes a multi-threaded TCP port scan over the specified port range."""
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"[!] Error: Could not resolve hostname '{target_host}'")
        sys.exit(1)

    print(f"[*] Starting scan on target: {target_host} ({target_ip})")
    print(f"[*] Scanning port range: {start_port}-{end_port} across {max_threads} worker threads...")

    open_ports: List[Dict] = []
    start_time = datetime.utcnow()

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [
            executor.submit(probe_port, target_ip, port)
            for port in range(start_port, end_port + 1)
        ]
        for future in as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)
                print(f"[+] OPEN PORT {res['port']} | Risk: {res['severity']} | Banner: {res['banner'] or 'None'}")

    end_time = datetime.utcnow()
    duration = (end_time - start_time).total_seconds()

    return {
        "target_host": target_host,
        "target_ip": target_ip,
        "scan_start": start_time.isoformat() + "Z",
        "scan_end": end_time.isoformat() + "Z",
        "duration_seconds": round(duration, 2),
        "total_ports_scanned": (end_port - start_port + 1),
        "open_ports_count": len(open_ports),
        "open_ports": sorted(open_ports, key=lambda x: x["port"]),
    }


def main():
    parser = argparse.ArgumentParser(description="Multi-threaded TCP Port & Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target IP address or domain hostname")
    parser.add_argument("--ports", default="1-1024", help="Port range to scan (e.g., 20-100 or 1-1024)")
    parser.add_argument("--threads", type=int, default=50, help="Maximum concurrent worker threads")
    parser.add_argument("--output", help="Optional JSON file path to export scan report")

    args = parser.parse_args()

    try:
        if "-" in args.ports:
            start_p, end_p = map(int, args.ports.split("-"))
        else:
            start_p = end_p = int(args.ports)
    except ValueError:
        print("[!] Error: Invalid port range format. Use START-END (e.g., 1-1024).")
        sys.exit(1)

    scan_summary = run_scan(args.target, start_p, end_p, args.threads)

    print("\n" + "=" * 50)
    print(f"Scan Completed in {scan_summary['duration_seconds']}s")
    print(f"Open Ports Discovered: {scan_summary['open_ports_count']}")
    print("=" * 50)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(scan_summary, f, indent=2)
        print(f"[+] Scan report exported to: {args.output}")


if __name__ == "__main__":
    main()