# Network-Scanner-Project-using-Python-

##  Python Network Scanner — A Lightweight Nmap-like Tool
⚡ Overview

This project is a custom-built network scanner written in pure Python to simulate core functionalities of Nmap — designed as an internship project and for learning the fundamentals of port scanning, banner grabbing, and concurrent networking in Python.

It can:

Enumerate multiple targets (single IPs, ranges, CIDRs)

Perform multi-threaded TCP connect scans

Fetch service banners (for quick service identification)

Perform reverse DNS lookups

Save results in structured JSON reports

## Built using only Python’s standard library — no external dependencies!

## Features
Feature	Description
🔢 Flexible Target Input	Supports single IPs, ranges (e.g., 192.168.1.1-192.168.1.10), and CIDRs (192.168.1.0/24).
⚙️ Custom Port Selection	Scan specific ports, lists, or ranges like 22,80,443 or 1-1024.
⚡ Concurrent Scanning	ThreadPoolExecutor-based scanning — extremely fast and efficient.
🧾 Banner Grabbing	Attempts to fetch and display service banners (e.g., “Apache/2.4.41”).
🌐 Reverse DNS Lookup	Tries to resolve hostnames automatically.
💾 JSON Output	Saves scan results neatly to a .json file.
🧩 Pure Python	No external libraries or root privileges required.
🧰 Requirements

Python 3.8+

Works on Linux, macOS, Windows, or WSL

No pip install needed (uses only standard libraries)

## How It Works

Target Parsing: Expands IPs, CIDRs, and ranges into full host lists.

TCP Connect Scan: Attempts socket connections to each port.

Concurrent Execution: Uses Python’s ThreadPoolExecutor for parallel scans.

Banner Grab: Reads initial service response bytes for quick fingerprinting.

Reverse DNS: Uses socket.gethostbyaddr() for hostname resolution.

Reporting: Aggregates and exports results in JSON format.

## Legal Disclaimer

This tool is for educational and authorized testing only.
Scanning networks or systems without explicit permission is illegal and punishable under law.
Use responsibly and ethically.

## Future Enhancements

Add UDP scanning

HTML report generation

Integration with Shodan or CVE lookup

Web UI dashboard

## Ideal For

Cybersecurity students & interns

Ethical hacking learners

SOC & Pen-Test beginners

Anyone who wants to understand network scanning fundamentals
