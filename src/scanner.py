#!/usr/bin/env python3
"""
Network Port & Vulnerability Scanner (net-port-scanner)
Multi-threaded TCP port scanner with banner grabbing, port profiles, and progress tracking.
"""

import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional
from tqdm import tqdm

HIGH_RISK_PORTS = {
    21: "FTP (Unencrypted File Transfer)",
    23: "Telnet (Unencrypted Remote Management)",
    80: "HTTP (Cleartext Web Server)",
    110: "POP3 (Cleartext Email Retrieval)",
    143: "IMAP (Cleartext Email Access)",
    3389: "RDP (Remote Desktop Protocol)",
}

PORT_PROFILES = {
    "quick": [21, 22, 23, 25, 53, 80, 110, 443, 445, 3389, 8080],
    "web": [80, 443, 8080, 8443, 3000, 5000, 8000],
    "top100": list(range(1, 101)),
    "standard": list(range(1, 1025)),
}


def grab_banner(target_ip: str, port: int, timeout: float = 1.5) -> Optional[str]:
    """Attempts to retrieve the service banner header from an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target_ip, port))
            if port in [80, 8080, 8443, 3000]:
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


def run_scan(target_host: str, ports: List[int], max_threads: int = 50) -> Dict:
    """Executes a multi-threaded TCP port scan over a specified list of ports with a progress bar."""
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"[!] Error: Could not resolve hostname '{target_host}'")
        sys.exit(1)

    print(f"\n[*] Target: {target_host} ({target_ip})")
    print(f[*] Probing {len(ports)} ports with {max_threads} worker threads...\n")

    open_ports: List[Dict] = []
    start_time = datetime.utcnow()

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(probe_port, target_ip, port): port for port in ports}
        
        with tqdm(total=len(ports), desc="Scanning", unit="port", ncols=80) as pbar:
            for future in as_completed(futures):
                res = future.result()
                if res:
                    open_ports.append(res)
                pbar.update(1)

    end_time = datetime.utcnow()
    duration = (end_time - start_time).total_seconds()

    return {
        "target_host": target_host,
        "target_ip": target_ip,
        "scan_start": start_time.isoformat() + "Z",
        "scan_end": end_time.isoformat() + "Z",
        "duration_seconds": round(duration, 2),
        "total_ports_scanned": len(ports),
        "open_ports_count": len(open_ports),
        "open_ports": sorted(open_ports, key=lambda x: x["port"]),
    }


def main():
    parser = argparse.ArgumentParser(description="Multi-threaded TCP Port & Vulnerability Scanner with Profiles")
    parser.add_argument("--target", required=True, help="Target IP address or domain hostname")
    parser.add_argument("--profile", choices=list(PORT_PROFILES.keys()), help="Scan profile (quick, web, top100, standard)")
    parser.add_argument("--ports", help="Custom port range (e.g., 20-100) or single port")
    parser.add_argument("--threads", type=int, default=50, help="Maximum concurrent worker threads")
    parser.add_argument("--output", help="Optional JSON file path to export scan report")

    args = parser.parse_args()

    # Determine port list
    if args.profile:
        ports_to_scan = PORT_PROFILES[args.profile]
    elif args.ports:
        try:
            if "-" in args.ports:
                start_p, end_p = map(int, args.ports.split("-"))
                ports_to_scan = list(range(start_p, end_p + 1))
            else:
                ports_to_scan = [int(args.ports)]
        except ValueError:
            print("[!] Error: Invalid port range format. Use START-END (e.g., 1-1024).")
            sys.exit(1)
    else:
        # Default to 'quick' profile if neither specified
        ports_to_scan = PORT_PROFILES["quick"]

    scan_summary = run_scan(args.target, ports_to_scan, args.threads)

    print("\n" + "=" * 60)
    print(f" SCAN RESULTS SUMMARY ({scan_summary['duration_seconds']}s)")
    print("=" * 60)
    if scan_summary["open_ports"]:
        for op in scan_summary["open_ports"]:
            print(f" [+] PORT {op['port']:<5} | Risk: {op['severity']:<6} | Service: {op['service_risk']}")
            if op["banner"]:
                print(f"     Banner: {op['banner'][:60]}")
    else:
        print(" [-] No open ports discovered in target range.")
    print("=" * 60)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(scan_summary, f, indent=2)
        print(f"[+] Scan report successfully exported to: {args.output}")


if __name__ == "__main__":
    main()