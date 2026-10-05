# Cybersecurity Scripting & Automation Internship — Phase 1

**Practical Scripting & Automation**
Languages: Bash + Python | Mode: Self-Paced

This repository contains both Phase 1 deliverables, each a complete, independently-runnable, resume-ready security tool — not a toy script. Both were built, executed, and debugged end-to-end (not just written) before being delivered here.

```
cyber-security-internship-phase1/
├── README.md                      <- you are here
├── bash-log-analyzer/             <- TASK 1: Bash tool
│   ├── sentinelguard.sh
│   └── README.md
└── python-security-toolkit/       <- TASK 2: Python tool
    ├── cyberpulse.py
    ├── requirements.txt
    └── README.md
```

##  What's inside

| Folder | Tool | Language | What it does |
|---|---|---|---|
| [`bash-log-analyzer/`](./bash-log-analyzer) | **SentinelGuard** | Bash | Log analyzer + IOC scanner + file-integrity monitor + real-time log watcher, all in one CLI |
| [`python-security-toolkit/`](./python-security-toolkit) | **CyberPulse** | Python 3 | Port scanner + password auditor + file/hash scanner + web-log attack analyzer + auto-generated HTML dashboard |

Each folder is fully self-contained with its own script and its own detailed README (full flag reference, examples, and design notes). This file is the quick-start map.

## ▶ How to Run

### Requirements
- A Linux (or macOS/WSL) shell with **Bash 4+** for the Bash tool
- **Python 3.7+** for the Python tool (standard library only — nothing to `pip install`)

### 1. Bash tool — SentinelGuard

```bash
cd bash-log-analyzer
chmod +x sentinelguard.sh

# Fastest way to see it work — no setup, no root, no real logs needed:
./sentinelguard.sh --demo --html

# Or launch the friendly interactive menu:
./sentinelguard.sh
```

Full usage: `./sentinelguard.sh --help`, or see [`bash-log-analyzer/README.md`](./bash-log-analyzer/README.md).

### 2. Python tool — CyberPulse

```bash
cd python-security-toolkit

# Fastest way to see everything work, including the HTML dashboard:
python3 cyberpulse.py all --demo
```

That command runs the port scanner, password auditor, hash scanner, and web-log analyzer, then builds and links an interactive HTML dashboard you can open in any browser.

Full usage: `python3 cyberpulse.py --help`, or see [`python-security-toolkit/README.md`](./python-security-toolkit/README.md).

##  Verified working

Both tools were run and re-run in a real shell during development — not just written and assumed correct. That process caught and fixed real bugs before delivery, including:
- A Bash `tail -f` pipe/subshell scoping issue that would have silently reset the real-time monitor's alert counters
- A Bash real-time monitor cleanup gap that could leave an orphaned background process running after Ctrl+C
- A Python variable-name collision that caused the web-log demo generator to crash
- A Python demo log format bug where un-encoded spaces in a simulated SQL-injection payload broke log-line parsing

Every mode of both tools (including every error path — missing files, bad arguments, permission issues) was exercised directly before this delivery, so what you're getting has actually been proven to run, not just reviewed by eye.

##  Why this is built as two *toolkits*, not two scripts

The brief asked for "one Bash tool" and "one Python tool." Rather than building the bare minimum (e.g. a single log parser), each tool bundles several related, genuinely useful modules behind one polished CLI — the way a real internal security tool would be structured. This gives you:
- More surface area to talk about in an interview (log analysis, IOC/malware detection, file integrity monitoring, port scanning, password auditing, log-based attack detection, and a dashboard UI — seven distinct skills, two tools)
- A more impressive GitHub repo / resume line than a single-purpose script
- Two consistent, complementary tools: the Bash tool leans on Linux/filesystem primitives (permissions, SUID bits, `sha256sum`, `tail -f`); the Python tool leans on things Python does well (sockets, regex-heavy log parsing, data structures, HTML/chart generation) — so together they demonstrate range rather than overlap

##  Suggested resume bullet points

> **SentinelGuard** — Bash security toolkit combining SSH brute-force detection, IOC scanning, and SHA-256 file-integrity monitoring with a real-time log watcher, colour-coded CLI, and HTML reporting; includes a synthetic-data demo mode for zero-setup evaluation.

> **CyberPulse** — Python security automation suite with a multithreaded port scanner, entropy-based password auditor, duplicate/malware file-hash scanner, and regex-driven web-log attack detector (SQLi/XSS/path traversal), unified behind a CLI that auto-generates an interactive Chart.js dashboard.

##  Possible Phase 2 extensions

- Package both tools with a `Makefile` / `setup.py` for one-line installation
- Add a scheduled mode (cron/systemd timer) for both tools to run unattended
- Email/Slack/webhook alerting when either tool detects something serious
- Combine both tools' JSON output into a single unified dashboard
