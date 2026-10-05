#!/usr/bin/env python3
"""
CyberPulse - Python Security Automation Toolkit
=================================================
Author  : <Your Name Here>
License : MIT
Requires: Python 3.7+  (standard library only -- no pip install needed)

DESCRIPTION
-----------
CyberPulse bundles five practical, independently-runnable security modules
behind a single CLI:

  1. portscan   Multithreaded TCP port scanner with service-name lookup.
  2. pwcheck    Password strength auditor (entropy, crack-time estimate,
                common-password / pattern detection), single or batch.
  3. hashscan   Recursive SHA-256 file scanner: duplicate-file detection,
                known-malware hash blocklist matching, largest/most
                recently modified files.
  4. weblog     Web server access-log analyzer: detects SQL injection,
                XSS, path-traversal attempts and scanner tools (sqlmap,
                nikto, nmap, ...) in Apache/Nginx "combined" log format.
  5. dashboard  Turns the JSON output of any of the modules above into a
                single, self-contained, dark-themed HTML dashboard with
                live charts (Chart.js) -- open it in any browser.

Every module supports --demo, which generates realistic synthetic data
(a demo web server, a demo log file, a demo directory tree, a demo
password list) so the ENTIRE toolkit can be exercised in seconds with no
setup, no root access, and no real targets required.

Run `python3 cyberpulse.py all --demo` to see everything at once, capped
off with an auto-generated HTML dashboard.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import hashlib
import ipaddress
import json
import math
import os
import random
import re
import shutil
import socket
import string
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path

###############################################################################
# 0. UI HELPERS (colour, banner, tables, progress)
###############################################################################

_TTY = sys.stdout.isatty()


class C:
    """ANSI colour codes; auto-disabled when output isn't a terminal so
    report/CSV/piped output stays clean."""
    RED = "\033[91m" if _TTY else ""
    GREEN = "\033[92m" if _TTY else ""
    YELLOW = "\033[93m" if _TTY else ""
    BLUE = "\033[94m" if _TTY else ""
    MAGENTA = "\033[95m" if _TTY else ""
    CYAN = "\033[96m" if _TTY else ""
    BOLD = "\033[1m" if _TTY else ""
    DIM = "\033[2m" if _TTY else ""
    RESET = "\033[0m" if _TTY else ""


BANNER = r"""
   _____      _              ____        _
  / ____|    | |            |  _ \      | |
 | |    _   _| |__   ___ _ _| |_) |_   _| |___  ___
 | |   | | | | '_ \ / _ \ '__|  _ <| | | | / __|/ _ \
 | |___| |_| | |_) |  __/ |  | |_) | |_| | \__ \  __/
  \_____\__, |_.__/ \___|_|  |____/ \__,_|_|___/\___|
         __/ |
        |___/
"""


def banner() -> None:
    print(f"{C.CYAN}{C.BOLD}{BANNER}{C.RESET}")
    print(f"{C.BLUE}  Python Security Automation Toolkit  |  v1.0.0{C.RESET}")
    print(f"{C.BLUE}  ------------------------------------------------------{C.RESET}")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")


def section(title: str) -> None:
    print()
    print(f"{C.MAGENTA}{C.BOLD}{'=' * 62}{C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD} {title}{C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD}{'=' * 62}{C.RESET}")


def info(msg: str) -> None:
    print(f"{C.BLUE}[INFO]{C.RESET} {msg}")


def ok(msg: str) -> None:
    print(f"{C.GREEN}{C.BOLD}[OK]{C.RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{C.YELLOW}{C.BOLD}[WARN]{C.RESET} {msg}")


def error(msg: str) -> None:
    print(f"{C.RED}{C.BOLD}[ERROR]{C.RESET} {msg}", file=sys.stderr)


def progress(done: int, total: int, label: str = "") -> None:
    """Simple in-place progress bar; safe to call rapidly in a scan loop."""
    if not _TTY or total == 0:
        return
    width = 30
    filled = int(width * done / total)
    bar = "#" * filled + "-" * (width - filled)
    sys.stdout.write(f"\r  [{bar}] {done}/{total} {label}")
    sys.stdout.flush()
    if done == total:
        sys.stdout.write("\n")


def print_table(headers, rows, colour_fn=None) -> None:
    """Prints a simple fixed-width table. colour_fn(row) -> ANSI colour
    code applied to that row, if provided."""
    if not rows:
        print("  (no rows)")
        return
    widths = [len(h) for h in headers]
    str_rows = [[str(c) for c in row] for row in rows]
    for row in str_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    header_line = "  " + "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(f"{C.BOLD}{header_line}{C.RESET}")
    print("  " + "-" * (sum(widths) + 2 * (len(widths) - 1)))
    for row, raw in zip(str_rows, rows):
        colour = colour_fn(raw) if colour_fn else ""
        line = "  " + "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))
        print(f"{colour}{line}{C.RESET}" if colour else line)


###############################################################################
# 1. SHARED UTILITIES
###############################################################################

def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_dir(path: str) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def save_module_result(module: str, data: dict, output_dir: str) -> str:
    """Wraps a module's result dict with metadata and writes it as JSON.
    This JSON is what the `dashboard` module later reads."""
    out_dir = ensure_dir(output_dir)
    wrapped = {
        "module": module,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "data": data,
    }
    path = out_dir / f"{module}_{timestamp()}.json"
    try:
        with open(path, "w") as f:
            json.dump(wrapped, f, indent=2, default=str)
    except OSError as e:
        error(f"Could not write report file {path}: {e}")
        return ""
    ok(f"JSON report saved: {path}")
    return str(path)


def save_csv(rows, headers, path: str) -> None:
    try:
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        ok(f"CSV report saved: {path}")
    except OSError as e:
        error(f"Could not write CSV file {path}: {e}")


def humanize_seconds(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = [
        ("centuries", 100 * 365 * 86400),
        ("years", 365 * 86400),
        ("days", 86400),
        ("hours", 3600),
        ("minutes", 60),
        ("seconds", 1),
    ]
    for name, secs in units:
        if seconds >= secs:
            val = seconds / secs
            return f"{val:,.1f} {name}"
    return f"{seconds:.1f} seconds"


###############################################################################
# 2. MODULE 1: PORT SCANNER
###############################################################################

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def parse_ports(spec: str) -> list:
    """Accepts 'common', '22,80,443', '1-1024', or a mix like '22,1000-1010'."""
    if spec.strip().lower() == "common":
        return sorted(COMMON_PORTS.keys())
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p <= 65535)


def _check_port(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except (OSError, socket.error):
        return False


def start_demo_servers(count: int = 3):
    """Spins up real local TCP listeners on random free ports so the demo
    port scan has genuine, verifiable open ports to discover -- rather
    than faking results."""
    servers, ports = [], []
    for _ in range(count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        s.listen(5)
        s.settimeout(0.2)
        ports.append(s.getsockname()[1])
        servers.append(s)

        def accept_loop(sock=s):
            while True:
                try:
                    conn, _ = sock.accept()
                    conn.close()
                except socket.timeout:
                    continue
                except OSError:
                    return

        import threading
        t = threading.Thread(target=accept_loop, daemon=True)
        t.start()
    return servers, ports


def port_scan(host: str, ports: list, timeout: float = 0.5, workers: int = 100) -> list:
    open_ports = []
    total = len(ports)
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, min(workers, total or 1))) as ex:
        futures = {ex.submit(_check_port, host, p, timeout): p for p in ports}
        for fut in futures:
            port = futures[fut]
            if fut.result():
                open_ports.append(port)
            done += 1
            progress(done, total, "ports scanned")
    return sorted(open_ports)


def cmd_portscan(args) -> dict:
    banner()
    section("PORT SCAN")
    host = args.host
    demo_servers = []
    try:
        ports = parse_ports(args.ports)
    except ValueError:
        error(f"Invalid --ports spec: {args.ports}")
        sys.exit(1)

    if args.demo:
        info("Demo mode: starting real local listeners on 127.0.0.1 to scan...")
        demo_servers, demo_ports = start_demo_servers(3)
        host = "127.0.0.1"
        ports = sorted(set(ports) | set(demo_ports))
        time.sleep(0.3)

    try:
        ipaddress.ip_address(socket.gethostbyname(host))
    except socket.gaierror:
        error(f"Could not resolve host: {host}")
        for s in demo_servers:
            s.close()
        sys.exit(1)

    print(f"Target       : {host}")
    print(f"Ports        : {len(ports)} port(s)  (timeout={args.timeout}s, workers={args.threads})")
    print()

    t0 = time.time()
    open_ports = port_scan(host, ports, timeout=args.timeout, workers=args.threads)
    elapsed = time.time() - t0

    for s in demo_servers:
        s.close()

    print()
    print(f"{C.BOLD}Open Ports{C.RESET}")
    rows = [[p, COMMON_PORTS.get(p, "unknown")] for p in open_ports]
    print_table(["PORT", "SERVICE"], rows, colour_fn=lambda r: C.GREEN)
    print()
    ok(f"Scan complete: {len(open_ports)} open / {len(ports)} scanned in {elapsed:.2f}s")

    result = {
        "host": host,
        "ports_scanned": len(ports),
        "open_ports": [{"port": p, "service": COMMON_PORTS.get(p, "unknown")} for p in open_ports],
        "elapsed_seconds": round(elapsed, 2),
    }

    json_path = save_module_result("portscan", result, args.output_dir)
    if args.csv:
        save_csv(rows, ["PORT", "SERVICE"], str(Path(args.output_dir) / f"portscan_{timestamp()}.csv"))
    result["_json_path"] = json_path
    return result


###############################################################################
# 3. MODULE 2: PASSWORD STRENGTH AUDITOR
###############################################################################

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "1234567",
    "qwerty", "abc123", "111111", "123123", "admin", "letmein", "welcome",
    "monkey", "dragon", "football", "iloveyou", "master", "sunshine",
    "princess", "solo", "starwars", "passw0rd", "shadow", "michael",
    "superman", "1234", "qwertyuiop", "asdfghjkl", "zxcvbnm", "trustno1",
    "batman", "hello", "freedom", "whatever", "qazwsx", "1qaz2wsx",
    "000000", "666666", "121212", "654321", "7777777", "password1",
    "1q2w3e4r", "hunter2", "changeme", "temp123", "guest", "root",
    "toor", "default", "administrator",
}

SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm"]


def has_sequential_pattern(pw: str) -> bool:
    pwl = pw.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - 2):
            chunk = seq[i:i + 3]
            if chunk in pwl or chunk[::-1] in pwl:
                return True
    return False


def password_entropy_bits(pw: str) -> float:
    charset = 0
    if any(c.islower() for c in pw):
        charset += 26
    if any(c.isupper() for c in pw):
        charset += 26
    if any(c.isdigit() for c in pw):
        charset += 10
    if any(c in string.punctuation for c in pw):
        charset += len(string.punctuation)
    charset = max(charset, 1)
    return len(pw) * math.log2(charset)


def mask_password(pw: str) -> str:
    if len(pw) <= 2:
        return "*" * len(pw)
    return pw[:2] + "*" * (len(pw) - 2)


def check_password_strength(pw: str) -> dict:
    issues = []
    score = 0
    length = len(pw)

    if length >= 16:
        score += 2
    elif length >= 12:
        score += 1
    elif length < 8:
        issues.append("Too short -- use 12+ characters")

    if any(c.islower() for c in pw):
        score += 1
    else:
        issues.append("Add lowercase letters")
    if any(c.isupper() for c in pw):
        score += 1
    else:
        issues.append("Add uppercase letters")
    if any(c.isdigit() for c in pw):
        score += 1
    else:
        issues.append("Add numbers")
    if any(c in string.punctuation for c in pw):
        score += 1
    else:
        issues.append("Add special characters (!@#$...)")

    if pw.lower() in COMMON_PASSWORDS:
        issues.append("This is one of the most common leaked passwords")
        score = 0
    if re.search(r"(.)\1{2,}", pw):
        issues.append("Contains repeated characters (e.g. 'aaa', '111')")
        score = max(0, score - 1)
    if has_sequential_pattern(pw):
        issues.append("Contains a sequential/keyboard pattern (e.g. 'abc', '123', 'qwerty')")
        score = max(0, score - 1)

    entropy = round(password_entropy_bits(pw), 1)
    crack_seconds = (2 ** entropy) / 1e10  # assume 10B guesses/sec (fast offline attack)
    crack_time = humanize_seconds(crack_seconds)

    if score >= 6 and entropy >= 60:
        verdict = "Very Strong"
    elif score >= 5 and entropy >= 50:
        verdict = "Strong"
    elif score >= 3 and entropy >= 35:
        verdict = "Moderate"
    elif score >= 2:
        verdict = "Weak"
    else:
        verdict = "Very Weak"

    return {
        "length": length,
        "score": score,
        "entropy_bits": entropy,
        "estimated_crack_time": crack_time,
        "verdict": verdict,
        "issues": issues,
    }


def _verdict_colour(verdict: str) -> str:
    return {
        "Very Weak": C.RED, "Weak": C.RED, "Moderate": C.YELLOW,
        "Strong": C.GREEN, "Very Strong": C.GREEN,
    }.get(verdict, "")


def cmd_pwcheck(args) -> dict:
    banner()
    section("PASSWORD STRENGTH AUDIT")
    entries = []

    if args.demo:
        info("Demo mode: auditing a built-in sample password list...")
        demo_list = [
            "password123", "123456", "qwerty", "admin",
            "Tr0ub4dor&3", "MyD0g$Name2023", "correcthorsebatterystaple99!",
            "Sup3r$3cur3P@ssphrase!!2024", "P@ss1", "letmein",
        ]
        for pw in demo_list:
            entries.append((mask_password(pw), check_password_strength(pw)))
    elif args.file:
        if not os.path.isfile(args.file):
            error(f"Password file not found: {args.file}")
            sys.exit(1)
        with open(args.file, "r", errors="ignore") as f:
            for line in f:
                pw = line.rstrip("\n")
                if not pw:
                    continue
                entries.append((mask_password(pw), check_password_strength(pw)))
    elif args.password:
        entries.append((mask_password(args.password), check_password_strength(args.password)))
    else:
        try:
            pw = getpass.getpass("Enter a password to audit (input hidden): ")
        except (EOFError, KeyboardInterrupt):
            error("No password provided.")
            sys.exit(1)
        if not pw:
            error("No password provided.")
            sys.exit(1)
        entries.append((mask_password(pw), check_password_strength(pw)))

    print()
    rows = [[masked, r["verdict"], r["entropy_bits"], r["estimated_crack_time"]] for masked, r in entries]
    print_table(
        ["PASSWORD", "VERDICT", "ENTROPY(bits)", "EST. CRACK TIME"],
        rows,
        colour_fn=lambda r: _verdict_colour(r[1]),
    )

    if args.verbose:
        print()
        print(f"{C.BOLD}Details{C.RESET}")
        for masked, r in entries:
            if r["issues"]:
                print(f"  {masked}:")
                for issue in r["issues"]:
                    print(f"    - {issue}")

    summary = {}
    for _, r in entries:
        summary[r["verdict"]] = summary.get(r["verdict"], 0) + 1
    print()
    print(f"{C.BOLD}Summary:{C.RESET} " + "  ".join(f"{k}={v}" for k, v in summary.items()))

    result = {
        "count": len(entries),
        "summary_by_verdict": summary,
        "entries": [{"password_masked": m, **r} for m, r in entries],
    }
    json_path = save_module_result("pwcheck", result, args.output_dir)
    if args.csv:
        save_csv(rows, ["PASSWORD", "VERDICT", "ENTROPY_BITS", "EST_CRACK_TIME"],
                  str(Path(args.output_dir) / f"pwcheck_{timestamp()}.csv"))
    result["_json_path"] = json_path
    return result


###############################################################################
# 4. MODULE 3: FILE / HASH SCANNER
###############################################################################

def sha256_of_file(path: str, chunk_size: int = 1 << 16):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                block = f.read(chunk_size)
                if not block:
                    break
                h.update(block)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def hash_scan(directory: str, blocklist: str = None, recent_hours: int = 24) -> dict:
    file_hashes = {}
    hash_to_paths = {}
    sized_files = []
    recent_files = []
    now = time.time()
    scanned = 0

    for root, _, files in os.walk(directory):
        for fn in files:
            path = os.path.join(root, fn)
            try:
                size = os.path.getsize(path)
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            h = sha256_of_file(path)
            if h is None:
                continue
            scanned += 1
            file_hashes[path] = h
            hash_to_paths.setdefault(h, []).append(path)
            sized_files.append((path, size))
            if now - mtime <= recent_hours * 3600:
                recent_files.append(path)

    duplicates = {h: paths for h, paths in hash_to_paths.items() if len(paths) > 1}
    sized_files.sort(key=lambda x: -x[1])
    largest = sized_files[:10]

    blocklist_matches = []
    if blocklist:
        if not os.path.isfile(blocklist):
            warn(f"Blocklist file not found: {blocklist} -- skipping malware-hash check.")
        else:
            with open(blocklist) as f:
                bad_hashes = {line.strip() for line in f if line.strip()}
            for path, h in file_hashes.items():
                if h in bad_hashes:
                    blocklist_matches.append({"path": path, "hash": h})

    return {
        "directory": os.path.abspath(directory),
        "files_scanned": scanned,
        "duplicate_groups": [{"hash": h, "paths": paths} for h, paths in duplicates.items()],
        "largest_files": [{"path": p, "size_bytes": s} for p, s in largest],
        "recent_files": recent_files[:50],
        "blocklist_matches": blocklist_matches,
        "blocklist_used": blocklist or None,
    }


def generate_demo_tree(base: str) -> str:
    """Builds a small synthetic directory containing duplicate files and one
    'malicious' file, and returns a matching blocklist file path."""
    if os.path.exists(base):
        shutil.rmtree(base)
    os.makedirs(os.path.join(base, "uploads"))
    os.makedirs(os.path.join(base, "backups"))

    content = "This is a sample configuration export.\nversion=1.0\n"
    with open(os.path.join(base, "uploads", "config_export.txt"), "w") as f:
        f.write(content)
    # Exact duplicate elsewhere (common in messy file shares / backups)
    with open(os.path.join(base, "backups", "config_export_copy.txt"), "w") as f:
        f.write(content)

    with open(os.path.join(base, "uploads", "notes.txt"), "w") as f:
        f.write("Meeting notes: rotate creds next sprint.\n")

    malicious_content = "echo 'this simulates a known-bad binary for the demo' \n"
    malicious_path = os.path.join(base, "uploads", "invoice_update.exe.sh")
    with open(malicious_path, "w") as f:
        f.write(malicious_content)

    blocklist_path = base + "_blocklist.txt"
    bad_hash = sha256_of_file(malicious_path)
    with open(blocklist_path, "w") as f:
        f.write(bad_hash + "\n")

    return blocklist_path


def cmd_hashscan(args) -> dict:
    banner()
    section("FILE / HASH SCAN")

    directory = args.dir
    blocklist = args.blocklist

    if args.demo:
        demo_dir = str(Path(args.output_dir) / "demo_hashscan_tree")
        info(f"Demo mode: generating a sample directory with a duplicate file and a planted 'malicious' file -> {demo_dir}")
        blocklist = generate_demo_tree(demo_dir)
        directory = demo_dir
        ok(f"Demo blocklist created: {blocklist}")

    if not os.path.isdir(directory):
        error(f"Directory not found: {directory}")
        sys.exit(1)

    print(f"Directory : {directory}")
    print(f"Blocklist : {blocklist or '(none)'}")
    print(f"Recent    : last {args.hours}h")
    print()

    result = hash_scan(directory, blocklist=blocklist, recent_hours=args.hours)

    print(f"{C.BOLD}Duplicate Files{C.RESET}")
    if result["duplicate_groups"]:
        for grp in result["duplicate_groups"]:
            print(f"  {C.YELLOW}[DUPLICATE]{C.RESET} sha256={grp['hash'][:16]}...")
            for p in grp["paths"]:
                print(f"      - {p}")
    else:
        print("  None found.")

    print()
    print(f"{C.BOLD}Malware Blocklist Matches{C.RESET}")
    if result["blocklist_matches"]:
        for m in result["blocklist_matches"]:
            print(f"  {C.RED}{C.BOLD}[MALWARE MATCH]{C.RESET} {m['path']} (sha256: {m['hash'][:16]}...)")
    else:
        print("  None found." if blocklist else "  (no blocklist supplied)")

    print()
    print(f"{C.BOLD}Largest Files{C.RESET}")
    rows = [[f["path"], f"{f['size_bytes']:,} bytes"] for f in result["largest_files"][:5]]
    print_table(["PATH", "SIZE"], rows)

    print()
    ok(f"Scan complete: {result['files_scanned']} files hashed, "
       f"{len(result['duplicate_groups'])} duplicate group(s), "
       f"{len(result['blocklist_matches'])} blocklist match(es).")

    json_path = save_module_result("hashscan", result, args.output_dir)
    result["_json_path"] = json_path
    return result


###############################################################################
# 5. MODULE 4: WEB LOG ANALYZER
###############################################################################

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"'
)

SQLI_PATTERNS = [r"union(\s|%20)+select", r"\bor\b\s+1=1", r"'\s*or\s*'1'='1",
                 r"--\s", r"/\*.*\*/", r"drop\s+table", r"insert\s+into",
                 r"xp_cmdshell", r"select.+from.+information_schema"]
XSS_PATTERNS = [r"<script", r"onerror\s*=", r"javascript:", r"<img[^>]+onerror", r"alert\("]
TRAVERSAL_PATTERNS = [r"\.\./", r"\.\.%2f", r"/etc/passwd", r"boot\.ini", r"win\.ini"]
SCANNER_AGENTS = ["sqlmap", "nikto", "nmap", "masscan", "nessus", "acunetix", "wpscan", "gobuster", "dirbuster"]


def classify_request(path: str, agent: str) -> list:
    flags = []
    # Decode URL-encoding (%20, %2e, etc.) so patterns match encoded attack
    # payloads the same way they'd match raw ones -- real attack traffic is
    # very often URL-encoded.
    try:
        decoded = urllib.parse.unquote(path or "")
    except Exception:
        decoded = path or ""
    low = decoded.lower()
    for p in SQLI_PATTERNS:
        if re.search(p, low, re.I):
            flags.append("SQLi")
            break
    for p in XSS_PATTERNS:
        if re.search(p, low, re.I):
            flags.append("XSS")
            break
    for p in TRAVERSAL_PATTERNS:
        if re.search(p, low, re.I):
            flags.append("Path Traversal")
            break
    agent_low = (agent or "").lower()
    for tool in SCANNER_AGENTS:
        if tool in agent_low:
            flags.append(f"Scanner tool ({tool})")
            break
    return flags


def analyze_weblog(path: str, threshold: int = 50) -> dict:
    ip_counts, ip_404, status_counts, path_counts = {}, {}, {}, {}
    attacks = []
    total = 0
    parsed = 0

    with open(path, "r", errors="ignore") as f:
        for line in f:
            total += 1
            m = LOG_PATTERN.match(line)
            if not m:
                continue
            parsed += 1
            d = m.groupdict()
            ip = d["ip"]
            status = d["status"]
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            status_counts[status] = status_counts.get(status, 0) + 1
            path_counts[d["path"]] = path_counts.get(d["path"], 0) + 1
            if status == "404":
                ip_404[ip] = ip_404.get(ip, 0) + 1
            flags = classify_request(d["path"], d["agent"])
            if flags:
                attacks.append({"ip": ip, "path": d["path"], "flags": flags, "time": d["time"]})

    top_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:10]
    top_paths = sorted(path_counts.items(), key=lambda x: -x[1])[:10]
    scanning_ips = {ip: c for ip, c in ip_404.items() if c >= 10}
    heavy_ips = {ip: c for ip, c in ip_counts.items() if c >= threshold}

    return {
        "log_file": os.path.abspath(path),
        "total_lines": total,
        "parsed_lines": parsed,
        "top_ips": [{"ip": ip, "requests": c} for ip, c in top_ips],
        "top_paths": [{"path": p, "requests": c} for p, c in top_paths],
        "status_breakdown": status_counts,
        "scanning_ips": [{"ip": ip, "404_count": c} for ip, c in scanning_ips.items()],
        "heavy_ips": [{"ip": ip, "requests": c} for ip, c in heavy_ips.items()],
        "attack_attempts": attacks[:200],
        "attack_count": len(attacks),
        "threshold": threshold,
    }


def generate_demo_weblog(out_path: str) -> None:
    normal_paths = ["/", "/index.html", "/about", "/products", "/contact", "/login", "/api/health", "/static/app.css"]
    normal_ips = ["203.0.113.10", "203.0.113.11", "198.51.100.5", "198.51.100.6"]
    attacker_ip = "185.220.101.5"
    scanner_ip = "45.33.12.201"
    agents = ['"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"', '"Mozilla/5.0 (Macintosh; Intel Mac OS X)"']

    now = datetime.now()
    lines = []

    def fmt(t):
        return t.strftime("%d/%b/%Y:%H:%M:%S +0000")

    # normal traffic
    for i in range(40):
        ip = random.choice(normal_ips)
        req_path = random.choice(normal_paths)
        t = now - timedelta(seconds=random.randint(0, 3600))
        status = random.choice([200, 200, 200, 304, 301])
        size = random.randint(200, 15000)
        agent = random.choice(agents)
        lines.append(f'{ip} - - [{fmt(t)}] "GET {req_path} HTTP/1.1" {status} {size} "-" {agent}')

    # SQLi attempts (spaces URL-encoded as %20, like real attack traffic)
    sqli_payloads = [
        "/login.php?user=admin'%20OR%20'1'='1",
        "/product.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
    ]
    for payload in sqli_payloads:
        t = now - timedelta(seconds=random.randint(0, 1800))
        lines.append(f'{attacker_ip} - - [{fmt(t)}] "GET {payload} HTTP/1.1" 500 512 "-" "python-requests/2.28"')

    # XSS attempt
    t = now - timedelta(seconds=900)
    lines.append(f'{attacker_ip} - - [{fmt(t)}] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 1200 "-" "python-requests/2.28"')

    # Path traversal attempt
    t = now - timedelta(seconds=600)
    lines.append(f'{attacker_ip} - - [{fmt(t)}] "GET /download?file=../../../../etc/passwd HTTP/1.1" 403 300 "-" "python-requests/2.28"')

    # scanner doing directory brute force (many 404s, scanner user-agent)
    for i in range(25):
        t = now - timedelta(seconds=300 - i * 5)
        guess = random.choice(["/wp-admin", "/phpmyadmin", "/.env", "/admin.php", "/backup.zip", "/config.php.bak"])
        lines.append(f'{scanner_ip} - - [{fmt(t)}] "GET {guess} HTTP/1.1" 404 178 "-" "sqlmap/1.6#stable"')

    random.shuffle(lines)
    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")


def cmd_weblog(args) -> dict:
    banner()
    section("WEB LOG ANALYSIS")

    log_file = args.file
    if args.demo:
        ensure_dir(args.output_dir)
        log_file = str(Path(args.output_dir) / "demo_access.log")
        info(f"Demo mode: generating a synthetic Nginx/Apache access log -> {log_file}")
        generate_demo_weblog(log_file)

    if not os.path.isfile(log_file):
        error(f"Log file not found: {log_file}")
        sys.exit(1)
    if not os.access(log_file, os.R_OK):
        error(f"Permission denied reading: {log_file}")
        sys.exit(1)

    print(f"Log file  : {log_file}")
    print(f"Threshold : {args.threshold} requests from one IP flags it as 'heavy'")
    print()

    result = analyze_weblog(log_file, threshold=args.threshold)

    print(f"{C.BOLD}Summary{C.RESET}")
    print(f"  Lines parsed        : {result['parsed_lines']} / {result['total_lines']}")
    print(f"  Attack attempts     : {result['attack_count']}")
    print(f"  Directory-scanning IPs (10+ x 404): {len(result['scanning_ips'])}")
    print(f"  High-volume IPs (>= {args.threshold} req): {len(result['heavy_ips'])}")

    print()
    print(f"{C.BOLD}Top Source IPs{C.RESET}")
    print_table(["IP", "REQUESTS"], [[i["ip"], i["requests"]] for i in result["top_ips"]])

    print()
    print(f"{C.BOLD}Detected Attack Attempts{C.RESET}")
    if result["attack_attempts"]:
        rows = [[a["ip"], ",".join(a["flags"]), a["path"][:50]] for a in result["attack_attempts"][:15]]
        print_table(["IP", "TYPE", "PATH"], rows, colour_fn=lambda r: C.RED)
    else:
        print("  None found.")

    if result["scanning_ips"]:
        print()
        print(f"{C.BOLD}{C.YELLOW}Directory/Scanner Activity{C.RESET}")
        for s in result["scanning_ips"]:
            print(f"  {C.YELLOW}[SCANNING]{C.RESET} {s['ip']} -> {s['404_count']} not-found requests")

    print()
    ok("Web log analysis complete.")

    json_path = save_module_result("weblog", result, args.output_dir)
    if args.csv:
        save_csv([[i["ip"], i["requests"]] for i in result["top_ips"]], ["IP", "REQUESTS"],
                  str(Path(args.output_dir) / f"weblog_{timestamp()}.csv"))
    result["_json_path"] = json_path
    return result


###############################################################################
# 6. MODULE 5: HTML DASHBOARD
###############################################################################

DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CyberPulse Security Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg: #0d1117; --panel: #161b22; --border: #30363d;
    --text: #c9d1d9; --accent: #58a6ff; --green: #3fb950;
    --red: #f85149; --yellow: #d29922;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    background: var(--bg); color: var(--text); margin: 0; padding: 28px;
    font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }}
  h1 {{ color: var(--accent); margin-bottom: 4px; }}
  .subtitle {{ color: #8b949e; margin-bottom: 28px; font-size: 14px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 28px; }}
  .card {{
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 18px; text-align: center;
  }}
  .card .value {{ font-size: 30px; font-weight: 700; color: var(--accent); }}
  .card.alert .value {{ color: var(--red); }}
  .card .label {{ color: #8b949e; font-size: 13px; margin-top: 4px; }}
  .section {{
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 22px; margin-bottom: 22px;
  }}
  .section h2 {{ margin-top: 0; color: var(--accent); font-size: 18px; border-bottom: 1px solid var(--border); padding-bottom: 10px; }}
  .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 22px; }}
  @media (max-width: 900px) {{ .grid2 {{ grid-template-columns: 1fr; }} }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }}
  th {{ color: #8b949e; font-weight: 600; }}
  .tag {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: 600; }}
  .tag.red {{ background: rgba(248,81,73,0.15); color: var(--red); }}
  .tag.green {{ background: rgba(63,185,80,0.15); color: var(--green); }}
  .tag.yellow {{ background: rgba(210,153,34,0.15); color: var(--yellow); }}
  .empty {{ color: #8b949e; font-style: italic; }}
  canvas {{ max-height: 280px; }}
  .footer {{ color: #8b949e; font-size: 12px; margin-top: 20px; text-align: center; }}
</style>
</head>
<body>
  <h1>&#128737; CyberPulse Security Dashboard</h1>
  <div class="subtitle">Generated {generated_at}</div>

  <div class="cards">
    {cards_html}
  </div>

  {sections_html}

  <div class="footer">Generated by CyberPulse v1.0.0 -- Python Security Automation Toolkit</div>

<script>
const chartDefaults = {{
  color: '#c9d1d9',
  plugins: {{ legend: {{ labels: {{ color: '#c9d1d9' }} }} }},
  scales: {{
    x: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }},
    y: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }}
  }}
}};
{charts_js}
</script>
</body>
</html>
"""


def _card(value, label, alert=False):
    cls = "card alert" if alert else "card"
    return f'<div class="{cls}"><div class="value">{value}</div><div class="label">{label}</div></div>'


def _table(headers, rows):
    if not rows:
        return '<p class="empty">No data.</p>'
    th = "".join(f"<th>{h}</th>" for h in headers)
    trs = ""
    for row in rows:
        tds = "".join(f"<td>{c}</td>" for c in row)
        trs += f"<tr>{tds}</tr>"
    return f"<table><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table>"


def build_dashboard(modules: dict, output_path: str) -> str:
    """modules: dict of module_name -> data dict (the 'data' payload saved by
    save_module_result). Missing modules are simply skipped."""
    cards = []
    sections = []
    charts_js = []
    chart_id = 0

    def next_chart_id():
        nonlocal chart_id
        chart_id += 1
        return f"chart{chart_id}"

    # --- Port scan section ---
    if "portscan" in modules:
        d = modules["portscan"]
        open_ports = d.get("open_ports", [])
        cards.append(_card(len(open_ports), "Open Ports Found", alert=len(open_ports) > 0))
        cid = next_chart_id()
        labels = [str(p["port"]) for p in open_ports] or ["none"]
        data = [1 for _ in open_ports] or [0]
        charts_js.append(f"""
new Chart(document.getElementById('{cid}'), {{
  type: 'bar',
  data: {{ labels: {json.dumps(labels)}, datasets: [{{ label: 'Open Port', data: {json.dumps(data)},
    backgroundColor: '#58a6ff' }}] }},
  options: {{ ...chartDefaults, plugins: {{ legend: {{ display: false }} }} }}
}});""")
        table = _table(["Port", "Service"], [[p["port"], p["service"]] for p in open_ports])
        sections.append(f"""
<div class="section">
  <h2>Port Scan &mdash; {d.get('host','')}</h2>
  <div class="grid2">
    <div><canvas id="{cid}"></canvas></div>
    <div>{table}</div>
  </div>
</div>""")

    # --- Password audit section ---
    if "pwcheck" in modules:
        d = modules["pwcheck"]
        summary = d.get("summary_by_verdict", {})
        weak_count = summary.get("Very Weak", 0) + summary.get("Weak", 0)
        cards.append(_card(d.get("count", 0), "Passwords Audited"))
        cards.append(_card(weak_count, "Weak / Very Weak", alert=weak_count > 0))
        cid = next_chart_id()
        order = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
        labels = [k for k in order if k in summary]
        data = [summary[k] for k in labels]
        colours = {"Very Weak": "#f85149", "Weak": "#f85149", "Moderate": "#d29922",
                   "Strong": "#3fb950", "Very Strong": "#3fb950"}
        bg = [colours[k] for k in labels]
        charts_js.append(f"""
new Chart(document.getElementById('{cid}'), {{
  type: 'doughnut',
  data: {{ labels: {json.dumps(labels)}, datasets: [{{ data: {json.dumps(data)}, backgroundColor: {json.dumps(bg)} }}] }},
  options: {{ plugins: {{ legend: {{ labels: {{ color: '#c9d1d9' }} }} }} }}
}});""")
        rows = [[e["password_masked"], e["verdict"], e["entropy_bits"], e["estimated_crack_time"]]
                for e in d.get("entries", [])]
        table = _table(["Password", "Verdict", "Entropy (bits)", "Est. Crack Time"], rows)
        sections.append(f"""
<div class="section">
  <h2>Password Strength Audit</h2>
  <div class="grid2">
    <div><canvas id="{cid}"></canvas></div>
    <div>{table}</div>
  </div>
</div>""")

    # --- Hash / IOC scan section ---
    if "hashscan" in modules:
        d = modules["hashscan"]
        dup_count = len(d.get("duplicate_groups", []))
        match_count = len(d.get("blocklist_matches", []))
        cards.append(_card(d.get("files_scanned", 0), "Files Hashed"))
        cards.append(_card(dup_count, "Duplicate Groups"))
        cards.append(_card(match_count, "Malware Hash Matches", alert=match_count > 0))
        dup_rows = []
        for grp in d.get("duplicate_groups", []):
            dup_rows.append([grp["hash"][:16] + "...", "<br>".join(grp["paths"])])
        match_rows = [[m["path"], m["hash"][:16] + "..."] for m in d.get("blocklist_matches", [])]
        sections.append(f"""
<div class="section">
  <h2>File / Hash Scan &mdash; {d.get('directory','')}</h2>
  <div class="grid2">
    <div><h3 style="font-size:14px;color:#8b949e;">Duplicate Files</h3>{_table(["Hash","Paths"], dup_rows)}</div>
    <div><h3 style="font-size:14px;color:#8b949e;">Malware Blocklist Matches</h3>{_table(["Path","Hash"], match_rows)}</div>
  </div>
</div>""")

    # --- Web log section ---
    if "weblog" in modules:
        d = modules["weblog"]
        cards.append(_card(d.get("attack_count", 0), "Attack Attempts Detected", alert=d.get("attack_count", 0) > 0))
        cards.append(_card(len(d.get("scanning_ips", [])), "Directory-Scanning IPs", alert=len(d.get("scanning_ips", [])) > 0))
        cid = next_chart_id()
        top_ips = d.get("top_ips", [])
        labels = [i["ip"] for i in top_ips]
        data = [i["requests"] for i in top_ips]
        charts_js.append(f"""
new Chart(document.getElementById('{cid}'), {{
  type: 'bar',
  data: {{ labels: {json.dumps(labels)}, datasets: [{{ label: 'Requests', data: {json.dumps(data)},
    backgroundColor: '#d29922' }}] }},
  options: {{ ...chartDefaults, indexAxis: 'y', plugins: {{ legend: {{ display: false }} }} }}
}});""")
        attack_rows = [[a["ip"], ", ".join(a["flags"]), a["path"][:60]] for a in d.get("attack_attempts", [])[:20]]
        sections.append(f"""
<div class="section">
  <h2>Web Log Analysis &mdash; {os.path.basename(d.get('log_file',''))}</h2>
  <div class="grid2">
    <div><canvas id="{cid}"></canvas></div>
    <div>{_table(["IP","Type","Path"], attack_rows)}</div>
  </div>
</div>""")

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = DASHBOARD_TEMPLATE.format(
        generated_at=generated_at,
        cards_html="\n".join(cards) if cards else '<p class="empty">No data yet -- run a module first.</p>',
        sections_html="\n".join(sections),
        charts_js="\n".join(charts_js),
    )
    with open(output_path, "w") as f:
        f.write(html)
    return output_path


def cmd_dashboard(args) -> None:
    banner()
    section("BUILD DASHBOARD")
    modules = {}
    for path in args.input:
        if not os.path.isfile(path):
            warn(f"Skipping missing file: {path}")
            continue
        try:
            with open(path) as f:
                wrapped = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            warn(f"Skipping unreadable JSON {path}: {e}")
            continue
        mod = wrapped.get("module")
        data = wrapped.get("data")
        if mod and data is not None:
            modules[mod] = data
            info(f"Loaded module '{mod}' from {path}")

    if not modules:
        error("No valid module JSON files were loaded. Nothing to build.")
        sys.exit(1)

    out_path = args.output or str(Path(args.output_dir) / f"dashboard_{timestamp()}.html")
    build_dashboard(modules, out_path)
    ok(f"Dashboard saved: {out_path}")
    print(f"\n  Open it in a browser:  file://{os.path.abspath(out_path)}\n")


###############################################################################
# 7. 'ALL' COMMAND -- run every module (demo by default) + auto-dashboard
###############################################################################

def cmd_all(args) -> None:
    banner()
    section("RUNNING FULL SUITE")
    ensure_dir(args.output_dir)
    modules = {}

    # Port scan
    ps_args = argparse.Namespace(
        host=args.host or "127.0.0.1", ports=args.ports or "common",
        timeout=0.5, threads=100, demo=(args.host is None),
        output_dir=args.output_dir, csv=False,
    )
    modules["portscan"] = cmd_portscan(ps_args)

    # Password audit
    pw_args = argparse.Namespace(
        password=None, file=args.pwfile, demo=(args.pwfile is None),
        output_dir=args.output_dir, csv=False, verbose=False,
    )
    modules["pwcheck"] = cmd_pwcheck(pw_args)

    # Hash scan
    hs_args = argparse.Namespace(
        dir=args.dir or ".", blocklist=args.blocklist,
        demo=(args.dir is None), hours=24, output_dir=args.output_dir,
    )
    modules["hashscan"] = cmd_hashscan(hs_args)

    # Web log
    wl_args = argparse.Namespace(
        file=args.weblog_file, demo=(args.weblog_file is None),
        threshold=10, output_dir=args.output_dir, csv=False,
    )
    modules["weblog"] = cmd_weblog(wl_args)

    # Dashboard
    banner()
    section("BUILDING DASHBOARD")
    clean_modules = {k: {kk: vv for kk, vv in v.items() if kk != "_json_path"} for k, v in modules.items()}
    out_path = str(Path(args.output_dir) / f"dashboard_{timestamp()}.html")
    build_dashboard(clean_modules, out_path)
    ok(f"Dashboard saved: {out_path}")
    print(f"\n  Open it in a browser:  file://{os.path.abspath(out_path)}\n")


###############################################################################
# 8. ARGUMENT PARSING / MAIN
###############################################################################

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberpulse.py",
        description="CyberPulse - Python Security Automation Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES
  # See every module work in one shot, with an auto-built dashboard:
  python3 cyberpulse.py all --demo

  # Scan common ports on a host:
  python3 cyberpulse.py portscan --host 127.0.0.1 --ports common

  # Audit a password interactively (input hidden):
  python3 cyberpulse.py pwcheck

  # Audit a file of passwords, one per line:
  python3 cyberpulse.py pwcheck --file passwords.txt --csv

  # Scan a directory for duplicate files and malware hash matches:
  python3 cyberpulse.py hashscan --dir /path/to/dir --blocklist bad_hashes.txt

  # Analyze an Nginx/Apache access log for attacks:
  python3 cyberpulse.py weblog --file /var/log/nginx/access.log --threshold 100

  # Build a combined dashboard from previously saved JSON reports:
  python3 cyberpulse.py dashboard --input cyberpulse_reports/portscan_*.json
""",
    )
    sub = parser.add_subparsers(dest="command")

    # portscan
    p = sub.add_parser("portscan", help="Multithreaded TCP port scanner")
    p.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    p.add_argument("--ports", default="common", help="'common', '22,80,443', '1-1024', or a mix (default: common)")
    p.add_argument("--timeout", type=float, default=0.5, help="Per-port timeout in seconds (default: 0.5)")
    p.add_argument("--threads", type=int, default=100, help="Concurrent worker threads (default: 100)")
    p.add_argument("--demo", action="store_true", help="Scan real local demo listeners, no target needed")
    p.add_argument("--output-dir", default="./cyberpulse_reports", help="Report output directory")
    p.add_argument("--csv", action="store_true", help="Also export a CSV report")
    p.set_defaults(func=cmd_portscan)

    # pwcheck
    p = sub.add_parser("pwcheck", help="Password strength auditor")
    p.add_argument("--password", help="Password to check (prefer --file or interactive prompt for real passwords)")
    p.add_argument("--file", help="File with one password per line (batch mode)")
    p.add_argument("--demo", action="store_true", help="Audit a built-in sample password list")
    p.add_argument("--output-dir", default="./cyberpulse_reports", help="Report output directory")
    p.add_argument("--csv", action="store_true", help="Also export a CSV report")
    p.add_argument("-v", "--verbose", action="store_true", help="Show detailed issues per password")
    p.set_defaults(func=cmd_pwcheck)

    # hashscan
    p = sub.add_parser("hashscan", help="Recursive SHA-256 file / duplicate / malware-hash scanner")
    p.add_argument("--dir", default=".", help="Directory to scan (default: current directory)")
    p.add_argument("--blocklist", help="File of known-bad SHA-256 hashes, one per line")
    p.add_argument("--hours", type=int, default=24, help="'Recently modified' window in hours (default: 24)")
    p.add_argument("--demo", action="store_true", help="Generate and scan a sample directory with planted issues")
    p.add_argument("--output-dir", default="./cyberpulse_reports", help="Report output directory")
    p.set_defaults(func=cmd_hashscan)

    # weblog
    p = sub.add_parser("weblog", help="Web server access-log attack analyzer")
    p.add_argument("--file", help="Path to an Nginx/Apache 'combined' format access log")
    p.add_argument("--threshold", type=int, default=50, help="Requests from one IP that flags it as high-volume")
    p.add_argument("--demo", action="store_true", help="Generate and analyze a synthetic access log")
    p.add_argument("--output-dir", default="./cyberpulse_reports", help="Report output directory")
    p.add_argument("--csv", action="store_true", help="Also export a CSV report")
    p.set_defaults(func=cmd_weblog)

    # dashboard
    p = sub.add_parser("dashboard", help="Build an HTML dashboard from module JSON reports")
    p.add_argument("--input", nargs="+", required=True, help="One or more module JSON report files")
    p.add_argument("--output", help="Output HTML path (default: cyberpulse_reports/dashboard_<ts>.html)")
    p.add_argument("--output-dir", default="./cyberpulse_reports", help="Default output directory if --output not set")
    p.set_defaults(func=cmd_dashboard)

    # all
    p = sub.add_parser("all", help="Run every module (demo by default) and auto-build a dashboard")
    p.add_argument("--demo", action="store_true", help="(implied for any module without a real target)")
    p.add_argument("--host", help="Real host for the port scan (else demo)")
    p.add_argument("--ports", help="Ports spec for the port scan (default: common)")
    p.add_argument("--dir", help="Real directory for the hash scan (else demo)")
    p.add_argument("--blocklist", help="Blocklist file for the hash scan")
    p.add_argument("--pwfile", help="Real password file for pwcheck (else demo list)")
    p.add_argument("--weblog-file", help="Real access log for weblog analysis (else demo)")
    p.add_argument("--output-dir", default="./cyberpulse_reports", help="Report output directory")
    p.set_defaults(func=cmd_all)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if not getattr(args, "command", None):
        parser.print_help()
        sys.exit(0)
    try:
        args.func(args)
    except KeyboardInterrupt:
        print()
        warn("Interrupted by user.")
        sys.exit(130)
    except Exception as e:  # noqa: BLE001 - top-level safety net, never crash with a raw traceback
        error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
