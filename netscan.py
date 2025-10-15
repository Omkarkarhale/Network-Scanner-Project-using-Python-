"""
Python Network Scanner — internship_project.py

A simple, self-made network scanner intended for learning and internship demonstration.
Features:
- Host expansion: single IP, range (start-end), or CIDR (e.g., 192.168.1.0/24)
- TCP connect scan (fast and reliable) for specified port ranges
- Concurrent scanning using ThreadPoolExecutor
- Banner grabbing for simple service detection
- Reverse DNS lookup (where available)
- Results saved to JSON and pretty-printed on console
- Clean, commented code so you can explain how it works in your internship

Limitations & Notes:
- This is NOT a drop-in replacement for nmap. It demonstrates core concepts: host enumeration,
  concurrent TCP port scanning, simple banner grabbing, and result aggregation.
- UDP scanning, OS fingerprinting, and advanced NSE-style scripts are out of scope.
- Use only on networks and hosts you are authorized to scan.

Usage examples:
python internship_project.py --targets 192.168.1.1/28 --ports 22-1024 --threads 200 --timeout 1.0 --output results.json
python internship_project.py --targets 10.0.0.5-10.0.0.10 --ports 80,443,8080 --output results.json
python internship_project.py --targets 192.168.1.5 --ports 1-1024 --banner

Dependencies: only Python 3.8+ standard library.

Author: (Your Name) — customize the top of this file before submitting to your internship.
License: MIT
"""

import argparse
import concurrent.futures
import ipaddress
import json
import socket
import sys
import threading
import time
from datetime import datetime
from typing import List, Tuple, Dict, Optional

# Global lock for thread-safe prints and result updates
print_lock = threading.Lock()


def parse_targets(targets_str: str) -> List[str]:
    """Accepts a comma-separated list of targets: single IPs, ranges, CIDRs.
    Examples: '192.168.1.1', '192.168.1.1-192.168.1.10', '192.168.1.0/28'
    """
    targets = []
    for part in targets_str.split(','):
        part = part.strip()
        if '-' in part and '/' not in part:
            # range a-b
            start, end = part.split('-')
            start_ip = ipaddress.ip_address(start.strip())
            end_ip = ipaddress.ip_address(end.strip())
            for ip_int in range(int(start_ip), int(end_ip) + 1):
                targets.append(str(ipaddress.ip_address(ip_int)))
        elif '/' in part:
            # CIDR
            net = ipaddress.ip_network(part, strict=False)
            for ip in net.hosts():
                targets.append(str(ip))
        else:
            targets.append(part)
    # deduplicate while preserving order
    seen = set()
    ordered = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            ordered.append(t)
    return ordered


def parse_ports(ports_str: str) -> List[int]:
    """Accepts things like '80,443,8080' or '1-1024' or combination '22,80,1000-1010'"""
    ports = set()
    for part in ports_str.split(','):
        part = part.strip()
        if '-' in part:
            a, b = part.split('-')
            a = int(a.strip()); b = int(b.strip())
            for p in range(a, b + 1):
                ports.add(p)
        else:
            ports.add(int(part))
    return sorted([p for p in ports if 0 < p <= 65535])


def banner_grab(ip: str, port: int, timeout: float) -> Optional[str]:
    """Try to read a small banner from the service.
    This does a TCP connect, then attempts a recv. Not all services send banners.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(1024)
                if data:
                    # decode best-effort
                    try:
                        return data.decode('utf-8', errors='ignore').strip()
                    except Exception:
                        return repr(data)
            except socket.timeout:
                return None
    except Exception:
        return None


def scan_tcp_connect(ip: str, port: int, timeout: float) -> Tuple[int, bool, Optional[str]]:
    """Return (port, is_open, banner_or_none)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        res = sock.connect_ex((ip, port))
        if res == 0:
            # open
            banner = None
            try:
                sock.settimeout(0.5)
                banner_bytes = sock.recv(1024)
                if banner_bytes:
                    banner = banner_bytes.decode('utf-8', errors='ignore').strip()
            except Exception:
                banner = None
            sock.close()
            return (port, True, banner)
        else:
            sock.close()
            return (port, False, None)
    except Exception:
        return (port, False, None)


def reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


class Scanner:
    def __init__(self, targets: List[str], ports: List[int], timeout: float = 1.0, threads: int = 100, do_banner: bool = False):
        self.targets = targets
        self.ports = ports
        self.timeout = timeout
        self.threads = threads
        self.do_banner = do_banner
        self.results: Dict[str, Dict] = {}

    def scan_host(self, ip: str):
        host_result = {
            'ip': ip,
            'reverse_dns': None,
            'open_ports': [],
            'scanned_at': datetime.utcnow().isoformat() + 'Z'
        }
        host_result['reverse_dns'] = reverse_dns(ip)

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.threads, len(self.ports) or 1)) as ex:
            futures = {ex.submit(scan_tcp_connect, ip, port, self.timeout): port for port in self.ports}
            for fut in concurrent.futures.as_completed(futures):
                port = futures[fut]
                try:
                    p, is_open, banner = fut.result()
                    if is_open:
                        entry = {'port': p}
                        if banner:
                            entry['banner'] = banner
                        elif self.do_banner:
                            # attempt more aggressive banner grab
                            b = banner_grab(ip, p, self.timeout)
                            if b:
                                entry['banner'] = b
                        host_result['open_ports'].append(entry)
                except Exception as e:
                    with print_lock:
                        print(f"[!] Error scanning {ip}:{port} -> {e}")

        # sort ports
        host_result['open_ports'] = sorted(host_result['open_ports'], key=lambda x: x['port'])
        self.results[ip] = host_result

        with print_lock:
            now = datetime.now().strftime('%H:%M:%S')
            print(f"[{now}] {ip} -> {len(host_result['open_ports'])} open ports")

    def run(self):
        start = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.threads, max(1, len(self.targets)))) as ex:
            ex.map(self.scan_host, self.targets)
        elapsed = time.time() - start
        print(f"Scan finished in {elapsed:.2f}s. Hosts scanned: {len(self.targets)}")
        return self.results


def main():
    parser = argparse.ArgumentParser(description='Simple Python network scanner for internship/demo')
    parser.add_argument('--targets', '-t', required=True, help='Targets: single IP, comma-separated, ranges (a-b), or CIDR (x.x.x.x/24)')
    parser.add_argument('--ports', '-p', required=True, help='Ports: single, comma-separated, or ranges e.g. 22,80,1000-2000')
    parser.add_argument('--timeout', type=float, default=1.0, help='Socket timeout in seconds')
    parser.add_argument('--threads', type=int, default=200, help='Max concurrent threads')
    parser.add_argument('--banner', action='store_true', help='Try banner grabbing (best-effort)')
    parser.add_argument('--output', '-o', default=None, help='Write JSON results to this file')
    args = parser.parse_args()

    targets = parse_targets(args.targets)
    ports = parse_ports(args.ports)
    if not targets:
        print('No valid targets parsed. Exiting.')
        sys.exit(1)
    if not ports:
        print('No valid ports parsed. Exiting.')
        sys.exit(1)

    print(f"Targets: {len(targets)} hosts. Ports: {len(ports)} ports. Threads: {args.threads}. Timeout: {args.timeout}s")

    scanner = Scanner(targets=targets, ports=ports, timeout=args.timeout, threads=args.threads, do_banner=args.banner)
    results = scanner.run()

    # pretty print summary
    for ip, data in results.items():
        print('\n' + '='*60)
        print(f"Host: {ip} ({data.get('reverse_dns') or 'no-reverse-dns'})")
        if data['open_ports']:
            for p in data['open_ports']:
                line = f"  - {p['port']}"
                if 'banner' in p:
                    b = p['banner']
                    if len(b) > 100:
                        b = b[:97] + '...'
                    line += f"  {b}"
                print(line)
        else:
            print('  No open TCP ports found in the scanned range.')

    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump({'scanned_at': datetime.utcnow().isoformat() + 'Z', 'results': results}, f, indent=2)
            print(f"Results written to {args.output}")
        except Exception as e:
            print(f"Failed to write output: {e}")


if __name__ == '__main__':
    main()
