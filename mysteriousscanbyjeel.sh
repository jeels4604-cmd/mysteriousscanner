#!/usr/bin/env bash
#
# MYSTERIOUS SCAN - Network Discovery & Port Scanning Interface
# Author: CSP Team
#
# A styled terminal front-end for network discovery / port scanning.
# Wraps the same legitimate ping-sweep + nmap logic behind an
# interactive menu with colors and an ASCII banner.
#
# IMPORTANT:
#   Only run this against networks you own or have explicit, written
#   authorization to test. Unauthorized scanning is illegal in most
#   jurisdictions.

set -euo pipefail

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
C_RESET='\033[0m'
C_CYAN='\033[1;36m'
C_GREEN='\033[1;32m'
C_RED='\033[1;31m'
C_YELLOW='\033[1;33m'
C_DIM='\033[2m'
C_BOLD='\033[1m'

REPORT_DIR="./netscan_reports"
COMMON_PORTS="21,22,23,25,53,80,110,139,143,443,445,3306,3389,8080"
mkdir -p "$REPORT_DIR"

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
banner() {
    clear
    echo -e "${C_CYAN}"
    cat <<'EOF'
  __  __       _____ _______ ______ _____  _____ ____  _    _  _____
 |  \/  |     / ____|__   __|  ____|  __ \|_   _/ __ \| |  | |/ ____|
 | \  / |_   _| (___    | |  | |__  | |__) | | || |  | | |  | | (___
 | |\/| | | | |\___ \   | |  |  __| |  _  /  | || |  | | |  | |\___ \
 | |  | | |_| |____) |  | |  | |____| | \ \ _| || |__| | |__| |____) |
 |_|  |_|\__, |_____/   |_|  |______|_|  \_\_____\____/ \____/|_____/
          __/ |              S  C  A  N
         |___/
EOF
    echo -e "${C_RESET}${C_DIM}        Network Discovery & Port Scanning Interface - CSP Team${C_RESET}"
    echo ""
}

divider() {
    echo -e "${C_DIM}------------------------------------------------------------${C_RESET}"
}

# ---------------------------------------------------------------------------
# Authorization gate
# ---------------------------------------------------------------------------
authorize() {
    echo -e "${C_YELLOW}This tool must only be used on networks you own or are${C_RESET}"
    echo -e "${C_YELLOW}explicitly authorized to test.${C_RESET}"
    read -rp "$(echo -e ${C_BOLD}"Type 'yes' to confirm authorization: "${C_RESET})" CONFIRM
    if [[ "$CONFIRM" != "yes" ]]; then
        echo -e "${C_RED}Authorization not confirmed. Exiting.${C_RESET}"
        exit 1
    fi
    echo ""
}

# ---------------------------------------------------------------------------
# Host discovery
# ---------------------------------------------------------------------------
discover_hosts() {
    local subnet="$1"
    local out_file="$2"
    echo -e "${C_CYAN}[*] Phase 1: Host discovery on ${subnet}${C_RESET}"
    if command -v nmap &>/dev/null; then
        nmap -sn "$subnet" -oG - 2>/dev/null | awk '/Up$/{print $2}' > "$out_file"
    else
        echo -e "${C_YELLOW}[!] nmap not found, using slower bash ping sweep${C_RESET}"
        local base_ip
        base_ip=$(echo "$subnet" | cut -d'.' -f1-3)
        for i in $(seq 1 254); do
            local ip="${base_ip}.${i}"
            if ping -c 1 -W 1 "$ip" &>/dev/null; then
                echo "$ip" >> "$out_file"
            fi
        done
    fi
}

# ---------------------------------------------------------------------------
# Device identification: hostname + OS/version guess
# ---------------------------------------------------------------------------
identify_device() {
    local host="$1"
    local name="unknown"
    local os_info="unknown"

    # Try to resolve a hostname
    if command -v getent &>/dev/null; then
        name=$(getent hosts "$host" 2>/dev/null | awk '{print $2}')
    fi
    if [[ -z "$name" ]] && command -v nslookup &>/dev/null; then
        name=$(nslookup "$host" 2>/dev/null | awk -F'= ' '/name =/{print $2}' | sed 's/\.$//')
    fi
    [[ -z "$name" ]] && name="unknown"

    # OS detection needs nmap -O, which needs root privileges.
    if command -v nmap &>/dev/null; then
        if [[ "$EUID" -eq 0 ]]; then
            os_info=$(nmap -O --osscan-guess "$host" 2>/dev/null \
                | grep -E "^(Running|OS details|Aggressive OS guesses)" \
                | head -n 1 \
                | sed -E 's/^(Running|OS details|Aggressive OS guesses): //')
        fi
        # Fall back to service/version banner grabbing (works without root)
        if [[ -z "$os_info" ]]; then
            os_info=$(nmap -sV --version-light "$host" 2>/dev/null \
                | grep -E "^[0-9]+/tcp" | head -n 1 | awk -F'  +' '{print $NF}')
        fi
    fi
    [[ -z "$os_info" ]] && os_info="unknown (needs sudo for OS detection)"

    echo -e "   ${C_CYAN}IP:${C_RESET} $host   ${C_CYAN}Name:${C_RESET} $name   ${C_CYAN}OS/Version:${C_RESET} $os_info" >&2
    echo "  IP: $host | Name: $name | OS/Version: $os_info"
}

# ---------------------------------------------------------------------------
# Port scan
# ---------------------------------------------------------------------------
scan_ports() {
    local host="$1"
    echo -e "${C_GREEN}[+] Scanning $host ${C_RESET}"
    if command -v nmap &>/dev/null; then
        nmap -p "$COMMON_PORTS" -T4 --open "$host" 2>/dev/null \
            | grep -E "^(PORT|[0-9]+/tcp)"
    else
        echo -e "${C_YELLOW}    nmap not installed - skipping port detail${C_RESET}"
    fi
}

# ---------------------------------------------------------------------------
# Full scan routine
# ---------------------------------------------------------------------------
run_scan() {
    local subnet="$1"
    local ts
    ts="$(date +'%Y%m%d_%H%M%S')"
    local report="${REPORT_DIR}/mysteriousscan_${ts}.txt"

    {
        echo "MYSTERIOUS SCAN - Report"
        echo "Target subnet: $subnet"
        echo "Started: $(date)"
        echo "============================================================"
    } > "$report"

    divider
    local hosts_file
    hosts_file=$(mktemp)
    discover_hosts "$subnet" "$hosts_file"

    local count
    count=$(wc -l < "$hosts_file" || echo 0)
    echo -e "${C_GREEN}[*] Live hosts found: $count${C_RESET}"
    {
        echo "Live hosts found: $count"
    } >> "$report"

    if [[ "$count" -eq 0 ]]; then
        echo -e "${C_YELLOW}No live hosts. Ending scan.${C_RESET}"
        rm -f "$hosts_file"
        return
    fi

    divider
    echo -e "${C_CYAN}[*] Phase 1b: Device identification (name + OS/version)${C_RESET}"
    while IFS= read -r h; do
        identify_device "$h" >> "$report"
        # also print to screen (identify_device writes colored line to stdout
        # via echo -e above, plus a plain line appended to report)
    done < "$hosts_file"

    divider
    echo -e "${C_CYAN}[*] Phase 2: Port scanning${C_RESET}"
    while IFS= read -r h; do
        {
            echo ""
            echo "Host: $h"
            echo "------------------------------------------------------"
        } >> "$report"
        scan_ports "$h" | tee -a "$report"
    done < "$hosts_file"

    rm -f "$hosts_file"
    divider
    echo -e "${C_GREEN}[*] Scan complete. Report saved to:${C_RESET} $report"
}

# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------
main_menu() {
    banner
    authorize
    echo -e "${C_BOLD}Select scan mode:${C_RESET}"
    echo "  1) Auto-detect local subnet and scan"
    echo "  2) Enter subnet manually (e.g. 192.168.1.0/24)"
    echo "  3) Exit"
    echo ""
    read -rp "Choice [1-3]: " choice

    case "$choice" in
        1)
            iface=$(ip route | awk '/default/ {print $5; exit}')
            if [[ -z "${iface:-}" ]]; then
                echo -e "${C_RED}Could not auto-detect interface.${C_RESET}"
                exit 1
            fi
            subnet=$(ip -o -f inet addr show "$iface" | awk '{print $4}')
            run_scan "$subnet"
            ;;
        2)
            read -rp "Enter subnet (CIDR): " subnet
            run_scan "$subnet"
            ;;
        3)
            echo "Goodbye."
            exit 0
            ;;
        *)
            echo -e "${C_RED}Invalid choice.${C_RESET}"
            exit 1
            ;;
    esac
}

main_menu
