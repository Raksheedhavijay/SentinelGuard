# SentinelGuard

**A modular Bash security toolkit: log analyzer, IOC scanner, and file-integrity monitor in one CLI.**

SentinelGuard was built for the *Cybersecurity Scripting & Automation Internship — Phase 1 (Bash Tool)*. It goes beyond a single-purpose script and combines four real SOC/Blue-Team workflows into one polished, dependency-free command-line tool that runs on any standard Linux box.

```
   _____            __  _            _  _____                     _
  / ____|          / _|(_)          | ||  __ \                   | |
 | (___   ___ _ __ | |_ _ _ __   ___| || |  \/_   _  __ _ _ __ __| |
  \___ \ / _ \ '_ \|  _| | '_ \ / _ \ || | __| | | |/ _` | '__/ _` |
  ____) |  __/ | | | | | | | | |  __/ || |_\ \ |_| | (_| | | | (_| |
 |_____/ \___|_| |_|_| |_|_| |_|\___|_(_)____/\__,_|\__,_|_|  \__,_|
```

## ✨ Features

| Module | What it does |
|---|---|
| **Log Analyzer** | Parses SSH/auth-style logs, counts failed vs. successful logins, ranks the top offending IPs, auto-flags **brute-force attacks** past a configurable threshold, and cross-references successful logins against brute-force IPs to flag **possible compromises**. Also reports sudo usage and new user creation. |
| **IOC Scanner** | Recursively scans a directory for SUID/SGID binaries, world-writable files, hidden files, recently modified files, suspicious scripts dropped in `/tmp` or `/dev/shm`, and optional SHA-256 matches against a malware **hash blocklist** you supply. |
| **File Integrity Monitor (FIM)** | Creates a SHA-256 baseline of any directory (`--baseline`) and later verifies it (`--check`), reporting exactly which files were **added, modified, or deleted** — classic tripwire behavior. |
| **Real-Time Monitor** | Live-tails a log file and prints instant, colour-coded alerts as attacks happen, with a live session summary on exit. |
| **Reporting Engine** | Every run is saved as a timestamped, plain-text report; pass `--html` to also get a dark-themed, styled HTML report you can open in a browser or attach to a ticket. |
| **Demo Mode** | `--demo` generates a realistic synthetic auth log (including a real brute-force cluster and a compromise scenario) *and* a sample directory tree with planted IOCs — so anyone can clone the repo and see every feature work in seconds, with zero setup, root access, or real log files required. |
| **Interactive Menu** | Run the script with no arguments for a friendly numbered menu — great for people unfamiliar with the CLI flags. |

## 🚀 Quick Start

```bash
chmod +x sentinelguard.sh

# See everything work immediately, no setup required:
./sentinelguard.sh --demo --html
```

That single command generates a sample attack log + a sample directory with planted IOCs, runs the log analyzer and IOC scanner against them, and writes both a `.txt` and `.html` report to `./sentinelguard_reports/`.

## 📖 Usage

```
./sentinelguard.sh [OPTIONS]
./sentinelguard.sh                     # no args -> interactive menu
```

### Modes (`-m` / `--mode`)
| Mode | Description |
|---|---|
| `logscan` | Analyze an auth/syslog file |
| `ioc` | Scan a directory for indicators of compromise |
| `integrity` | Create (`-b`) or check (`-c`) a SHA-256 baseline |
| `monitor` | Live-tail a log file with real-time alerts |
| `all` | Run logscan + ioc + integrity check together |

### Key Options
```
-m, --mode <mode>          Select a mode
-f, --file <path>          Log file to analyze/monitor      (default: /var/log/auth.log)
-d, --dir <path>           Directory to scan / baseline     (default: .)
-o, --output <dir>         Report output directory          (default: ./sentinelguard_reports)
-t, --threshold <n>        Failed logins from one IP that trigger a brute-force flag (default: 5)
    --hours <n>             "Recently modified" window for IOC scan, in hours (default: 24)
-b, --baseline              Create a new integrity baseline
-c, --check                  Check integrity against the baseline
    --baseline-file <path>   Baseline file path
    --blocklist <path>       Known-bad SHA-256 hash list for the IOC scan
-w, --watch                  Shortcut for --mode monitor
-i, --interactive             Force the interactive menu
    --html                    Also export a styled HTML report
    --demo                    Generate synthetic demo data and run everything
-h, --help                    Full usage + examples
```

Run `./sentinelguard.sh --help` for the complete list with copy-pasteable examples.

## 🧪 Real-World Examples

```bash
# Hunt for SSH brute-force attacks on a live server (may need sudo to read the log):
sudo ./sentinelguard.sh -m logscan -f /var/log/auth.log -t 5

# Sweep a web root for compromise indicators, flagging anything touched in the last 6h:
./sentinelguard.sh -m ioc -d /var/www --hours 6

# Baseline /etc today, verify no tampering next week:
./sentinelguard.sh -m integrity -b -d /etc
./sentinelguard.sh -m integrity -c -d /etc

# Watch a log file live during an incident:
./sentinelguard.sh -w -f /var/log/auth.log

# Full sweep with a shareable HTML report:
./sentinelguard.sh -m all -f /var/log/auth.log -d /etc --html
```

## 🛡️ Design Notes (why it's built this way)

- **No external dependencies** — only `bash`, `awk`, `grep`, `sed`, `find`, `sha256sum` (all present on essentially every Linux distro).
- **Defensive error handling** — every mode validates its file/directory exists and is readable *before* running, with clear, actionable error messages (e.g. "try running with sudo") instead of a stack of raw shell errors.
- **Clean exit codes** — the tool exits `0` on success and `1` on any failure or missing dependency, so it can be dropped straight into cron jobs, CI pipelines, or other automation.
- **No orphaned processes** — the real-time monitor traps `Ctrl+C` (and `timeout`'s `SIGTERM`) to cleanly kill its background `tail -f` process rather than leaving it running.
- **Colour that degrades gracefully** — ANSI colours are auto-detected and stripped automatically for non-interactive output and for report files, so reports stay clean and greppable.
- **Everything is a single file** — `sentinelguard.sh` is fully self-contained and portable; copy it to any box and run it.

## 📂 What gets created

```
sentinelguard_reports/
├── logscan_<timestamp>.txt / .html
├── ioc_<timestamp>.txt / .html
├── integrity_<timestamp>.txt / .html
├── full_scan_<timestamp>.txt / .html
├── baseline.sha256                 # your FIM baseline
└── sentinelguard_tool.log          # internal audit log of every run
```

## 🗺️ Roadmap Ideas (good talking points for an interview)

- Email/webhook alerting on brute-force or FIM changes
- GeoIP lookups for offending IPs (optional, opt-in network dependency)
- systemd timer / cron wrapper for scheduled baselines and scans
- JSON export mode for SIEM ingestion

---
*Built as Phase 1 of a Cybersecurity Scripting & Automation Internship. Companion Python tool available on request.*
