# CyberPulse

**A modular Python security automation toolkit: port scanner, password auditor, file/hash scanner, and web-log attack analyzer — with an auto-generated interactive HTML dashboard.**

Built as the Python companion to the Phase 1 internship deliverables. Zero external dependencies — pure Python 3 standard library, so it runs anywhere Python runs.

## ✨ Features

| Module | What it does |
|---|---|
| **Port Scanner** (`portscan`) | Multithreaded TCP connect-scan with a common-ports service-name lookup, custom port ranges, adjustable timeout/concurrency, and a live progress bar. |
| **Password Auditor** (`pwcheck`) | Scores password strength using entropy math, common-password blacklist checks, and sequential/keyboard-pattern detection; estimates crack time; supports single passwords (with **hidden terminal input**), batch files, or a built-in demo list. |
| **File / Hash Scanner** (`hashscan`) | Recursively SHA-256 hashes a directory to find duplicate files, match against a malware **hash blocklist** you supply, and list the largest / most recently modified files. |
| **Web Log Analyzer** (`weblog`) | Parses Apache/Nginx "combined" access logs and flags **SQL injection, XSS, path traversal**, and known scanner tools (`sqlmap`, `nikto`, `nmap`, ...) by user agent, plus directory-brute-force detection via 404 clustering. |
| **HTML Dashboard** (`dashboard`) | Turns any combination of the JSON reports above into one **self-contained, dark-themed dashboard with live Chart.js charts** — open it straight in a browser, no server required. |
| **Demo Mode** (`--demo`) | Every module can generate its own realistic synthetic data — a local port listener, a sample password list, a directory with planted duplicates/malware, or a synthetic attack log — so you can see every feature work immediately, without a real target. |

## 🚀 Quick Start

```bash
# No installation needed -- just Python 3.7+.
python3 cyberpulse.py all --demo
```

This single command runs **all four modules** in demo mode and automatically builds an HTML dashboard summarizing every result. Open the linked file in your browser to see it.

## 📖 Usage

```
python3 cyberpulse.py <command> [options]
```

### Commands
| Command | Purpose |
|---|---|
| `portscan` | Scan a host for open TCP ports |
| `pwcheck` | Audit password strength |
| `hashscan` | Scan a directory for duplicates / malware hashes |
| `weblog` | Analyze a web server access log for attacks |
| `dashboard` | Build an HTML dashboard from saved JSON reports |
| `all` | Run every module (demo unless real targets given) + auto-dashboard |

Run `python3 cyberpulse.py --help` or `python3 cyberpulse.py <command> --help` for the full flag list and examples.

## 🧪 Real-World Examples

```bash
# Scan common ports on a host:
python3 cyberpulse.py portscan --host 192.168.1.1 --ports common

# Scan a custom port range with more threads:
python3 cyberpulse.py portscan --host 10.0.0.5 --ports 1-1024 --threads 200

# Audit a password interactively -- input is hidden, nothing is echoed or logged in plaintext:
python3 cyberpulse.py pwcheck

# Audit a list of passwords from a file, one per line, and export CSV:
python3 cyberpulse.py pwcheck --file passwords.txt --csv --verbose

# Find duplicate files and check against a malware hash blocklist:
python3 cyberpulse.py hashscan --dir /opt/app --blocklist known_bad_hashes.txt

# Analyze a real Nginx access log, flag IPs sending 100+ requests:
python3 cyberpulse.py weblog --file /var/log/nginx/access.log --threshold 100

# Build a dashboard from a specific set of saved reports:
python3 cyberpulse.py dashboard --input cyberpulse_reports/portscan_*.json cyberpulse_reports/weblog_*.json

# Run the full suite against REAL targets instead of demo data:
python3 cyberpulse.py all --host 192.168.1.1 --dir /var/www --weblog-file /var/log/nginx/access.log
```

## 🖥️ The Dashboard (UI feature)

Every module writes a JSON report. The `dashboard` command (or `all`, automatically) reads those reports and renders a single HTML file with:

- Summary "at a glance" stat cards (open ports found, weak passwords, malware matches, attack attempts...)
- A bar chart of open ports, a doughnut chart of password-strength distribution, and a bar chart of top attacking IPs (via Chart.js, loaded from a CDN)
- Full data tables for duplicates, malware matches, and detected attack attempts
- A dark GitHub-style theme that matches the companion Bash tool's HTML reports for a consistent look across the whole project

No server, no build step — it's one `.html` file you can open locally, email, or drop into a ticket.

## 🛡️ Design Notes

- **Zero dependencies** — only the Python standard library. No `pip install` required.
- **Security-conscious by default** — passwords are never printed or stored in full; only a masked form (`pa******`) appears in terminal output, JSON, and CSV. Interactive mode uses `getpass` so input isn't echoed to the screen.
- **Real demo data, not fake output** — demo mode for the port scanner spins up *actual* local TCP listeners and scans them for real; the hash scanner demo creates real duplicate files and computes a real SHA-256 blocklist match. Nothing is hard-coded to "look" like it worked.
- **Never crashes with a raw traceback** — every subcommand validates its inputs first (file exists? readable? valid port spec?) with a clear, actionable error message, and a top-level safety net catches anything unexpected.
- **Correct exit codes** — `0` on success, `1` on any failure — safe to use in scripts, cron, or CI.
- **Threaded but bounded** — the port scanner uses a `ThreadPoolExecutor` with a configurable worker cap so it won't spawn thousands of unbounded threads.

## 📂 What gets created

```
cyberpulse_reports/
├── portscan_<timestamp>.json / .csv
├── pwcheck_<timestamp>.json / .csv
├── hashscan_<timestamp>.json
├── weblog_<timestamp>.json / .csv
└── dashboard_<timestamp>.html
```

## 🗺️ Roadmap Ideas (good interview talking points)

- Async I/O (`asyncio`) port scanning for even higher throughput
- CVE/version-banner grabbing on open ports
- Live-tailing web logs (like the Bash tool's real-time monitor) with dashboard auto-refresh
- Slack/email alerting when the dashboard detects a malware hash match

---
*Built as Phase 1 of a Cybersecurity Scripting & Automation Internship. Companion Bash tool: see `../bash-log-analyzer/`.*
