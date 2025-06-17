#!/bin/bash
# Super Info – Admin Security Tool
# Author: Bocaletto Luca
# License: Apache 2.0
# Language: English
#
# Super Info is a comprehensive, text-based utility for system administrators
# on Ubuntu and other Debian-based distributions.
#
# Release: v2.1.0
#
# New Features in this release:
#   - Configuration file support (super_info.conf)
#   - Advanced logging (to file and console)
#   - Maintenance submenu for update/upgrade/cleanup/self-update/check_upgradable
#   - A new function: system_health_check() that reports disk usage, memory usage and CPU load.
#   - System monitor using vmstat.
#
###############################################################################

# --- Global Settings & Color Definitions ---
export LANG="en_US.UTF-8"
export NCURSES_NO_UTF8_ACS=1

if [ "$(tput colors)" -ge 8 ]; then
  RED=$(tput setaf 1)
  GREEN=$(tput setaf 2)
  YELLOW=$(tput setaf 3)
  BLUE=$(tput setaf 4)
  MAGENTA=$(tput setaf 5)
  CYAN=$(tput setaf 6)
  NC=$(tput sgr0)
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; NC="";
fi

# --- Load Configuration File if Available ---
CONFIG_FILE="./super_info.conf"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo -e "${YELLOW}Config file not found. Using default settings.${NC}"
    LOG_FILE="./super_info.log"
    DEFAULT_UPDATE_RESPONSE="Y"
    DEFAULT_UPGRADE_RESPONSE="Y"
fi

# --- Trap for clean exit on SIGINT and SIGTERM ---
cleanup() {
    echo -e "\n${MAGENTA}Exiting Super Info...${NC}"
    exit 0
}
trap cleanup SIGINT SIGTERM

# --- Logging Function (Advanced) ---
log_msg() {
    local level="$1"
    local msg="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %T")
    echo -e "[${level}] ${timestamp} : ${msg}"
    echo "[${level}] ${timestamp} : ${msg}" >> "$LOG_FILE"
}

# --- Utility Functions ---
print_border() {
    local width=$(( $(tput cols) - 2 ))
    printf "+%0.s-" $(seq 1 "$width")
    echo "+"
}

print_title() {
    local title="$1"
    echo -e "$title"
}

# --- Dependency Checker ---
check_install_dependencies() {
    local DEPS=(glances debsums)
    local missing=()
    for dep in "${DEPS[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${YELLOW}The following packages are missing and will be installed:${NC} ${missing[*]}"
        read -rp "Proceed with installation? [Y/n]: " answer
        if [[ "$answer" =~ ^[Yy] || -z "$answer" ]]; then
            sudo apt-get update && sudo apt-get install -y "${missing[@]}"
            if [ $? -ne 0 ]; then
                echo -e "${RED}Error installing packages. Exiting.${NC}"
                exit 1
            fi
            log_msg "INFO" "Installed missing dependencies: ${missing[*]}"
        else
            echo -e "${RED}Required dependencies missing. Exiting.${NC}"
            exit 1
        fi
    fi
}
check_install_dependencies

set_dialog_dimensions() {
    TERM_HEIGHT=$(tput lines)
    TERM_WIDTH=$(tput cols)
    local MIN_HEIGHT=15
    local MIN_WIDTH=40
    if [ "$TERM_HEIGHT" -lt "$MIN_HEIGHT" ] || [ "$TERM_WIDTH" -lt "$MIN_WIDTH" ]; then
        echo -e "${RED}The terminal must be at least ${MIN_WIDTH} columns x ${MIN_HEIGHT} rows. Current size: ${TERM_WIDTH}x${TERM_HEIGHT}.${NC}"
        exit 1
    fi
}
set_dialog_dimensions

###############################################################################
# Function: system_info
# Description: Displays basic system information.
###############################################################################
system_info() {
    clear
    print_border
    print_title "${YELLOW}SYSTEM INFO${NC}"
    print_border
    local os_info kernel arch host datetime lang
    if [ -f /etc/os-release ]; then
       os_info=$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
    else
       os_info="Unknown OS"
    fi
    kernel=$(uname -r)
    arch=$(uname -m)
    host=$(hostname)
    datetime=$(date +"%c")
    lang=$LANG

    echo -e "${CYAN}Description:${NC} This report displays basic system information."
    echo -e "${BLUE}OS:${NC}             ${GREEN}${os_info}${NC}"
    echo -e "${BLUE}Kernel:${NC}         ${GREEN}${kernel}${NC}"
    echo -e "${BLUE}Architecture:${NC}   ${GREEN}${arch}${NC}"
    echo -e "${BLUE}Hostname:${NC}       ${GREEN}${host}${NC}"
    echo -e "${BLUE}Date/Time:${NC}      ${GREEN}${datetime}${NC}"
    echo -e "${BLUE}Locale:${NC}         ${GREEN}${lang}${NC}"
    print_border
    read -rp "Press Enter to return to the menu..." dummy
}

###############################################################################
# Function: machine_info
# Description: Displays detailed hardware specifications.
###############################################################################
machine_info() {
    clear
    print_border
    print_title "${YELLOW}MACHINE INFO${NC}"
    print_border
    local cpu mem disk net
    if command -v lscpu &>/dev/null; then
       cpu=$(lscpu | sed 's/^/   /')
    else
       cpu=$(cat /proc/cpuinfo | head -n 15 | sed 's/^/   /')
    fi
    mem=$(free -h | sed 's/^/   /')
    disk=$(df -h | sed 's/^/   /')
    net=$(ip -brief addr | sed 's/^/   /')
    
    echo -e "${CYAN}Description:${NC} This report displays the hardware specifications."
    echo -e "${MAGENTA}CPU:${NC}\n${GREEN}${cpu}${NC}"
    echo -e "${MAGENTA}Memory:${NC}\n${GREEN}${mem}${NC}"
    echo -e "${MAGENTA}Disk Usage:${NC}\n${GREEN}${disk}${NC}"
    echo -e "${MAGENTA}Network Interfaces:${NC}\n${GREEN}${net}${NC}"
    print_border
    read -rp "Press Enter to return to the menu..." dummy
}

###############################################################################
# Function: user_info
# Description: Displays information about the current user.
###############################################################################
user_info() {
    clear
    print_border
    print_title "${YELLOW}USER INFO${NC}"
    print_border
    local info last_logins
    info="${CYAN}User:${NC}     ${GREEN}${USER}${NC}"
    info+="\n${CYAN}UID:${NC}      ${GREEN}$(id -u)${NC}"
    info+="\n${CYAN}Groups:${NC}   ${GREEN}$(id -Gn)${NC}"
    info+="\n${CYAN}Home Dir:${NC} ${GREEN}${HOME}${NC}"
    last_logins=$(last -n 3 | head -n 3 | sed 's/^/   /')
    
    echo -e "${CYAN}Description:${NC} This report shows details about the current user."
    echo -e "$info"
    echo -e "\n${MAGENTA}Recent Logins:${NC}\n${GREEN}${last_logins}${NC}"
    print_border
    read -rp "Press Enter to return to the menu..." dummy
}

###############################################################################
# Function: login_service_monitor
# Description: Monitors active sessions and status of critical services.
###############################################################################
login_service_monitor() {
    while true; do
        local ts sessions multi key output
        ts=$(date +"%c")
        sessions=$(who)
        output="${BLUE}Date/Time:${NC} ${GREEN}${ts}${NC}\n"
        output+="\n${MAGENTA}Active Sessions:${NC}\n${GREEN}${sessions}${NC}\n"
        multi=""
        while read -r user tty; do
            local count
            count=$(who | awk -v u="$user" '$1==u {print $2}' | sort -u | wc -l)
            if [ $count -gt 1 ]; then
                multi+="${RED}Warning:${NC} User ${YELLOW}$user${NC} has ${GREEN}$count${NC} simultaneous sessions.\n"
            fi
        done < <(who | awk '{print $1, $2}' | sort -u)
        [ -n "$multi" ] && output+="\n${RED}*** Multiple Login Warnings ***${NC}\n${multi}"
        output+="\n${MAGENTA}Service Status:${NC}\n"
        local SERVICES=("sshd" "apache2" "nginx" "mysqld" "mariadb" "postgresql")
        for svc in "${SERVICES[@]}"; do
            local status statustxt
            status=$(systemctl is-active "$svc" 2>/dev/null)
            if [ "$status" = "active" ]; then
                statustxt="${GREEN}Running${NC}"
            else
                statustxt="${RED}Not Running${NC}"
            fi
            output+="${CYAN}Service ${svc}:${NC} ${statustxt}\n"
        done
        clear
        echo -e "$output"
        echo -e "\nPress 'm' to return to the menu, or wait 5 seconds for an update..."
        read -t 5 -n 1 key
        [ "$key" = "m" ] && break
    done
}

###############################################################################
# Function: auth_log_monitor
# Description: Continuously displays the last 20 events from /var/log/auth.log.
###############################################################################
auth_log_monitor() {
    while true; do
        local rep key
        rep=$(tail -n 20 /var/log/auth.log 2>/dev/null)
        clear
        if [ -z "$rep" ]; then
            echo -e "${RED}The file /var/log/auth.log is inaccessible or empty.${NC}"
        else
            echo -e "${YELLOW}*** Last 20 Events from Auth Log ***${NC}\n${GREEN}${rep}${NC}"
        fi
        echo -e "\nPress 'm' to return to the menu, or wait 5 seconds for an update..."
        read -t 5 -n 1 key
        [ "$key" = "m" ] && break
    done
}

###############################################################################
# Function: network_ports_analysis
# Description: Scans and displays open network ports using the 'ss' command.
###############################################################################
network_ports_analysis() {
    clear
    print_border
    print_title "${YELLOW}NETWORK & PORTS ANALYSIS${NC}"
    print_border
    local rep
    rep=$(ss -tuln 2>/dev/null)
    if [ -z "$rep" ]; then
         echo -e "${RED}No output from ss.${NC}"
    else
         echo -e "${CYAN}Scan Results:${NC}\n${GREEN}${rep}${NC}"
    fi
    print_border
    read -rp "Press Enter to return to the menu..." dummy
}

###############################################################################
# Function: paginate_output
# Description: Paginates the provided output (default 20 lines per page).
###############################################################################
paginate_output() {
    local output="$1"
    local lines_per_page=${2:-20}
    IFS=$'\n' read -rd '' -a lines <<< "$output"
    local total_lines=${#lines[@]}
    local i=0
    while [ $i -lt $total_lines ]; do
        clear
        for (( j=0; j<lines_per_page && i<total_lines; j++, i++ )); do
            echo "${lines[$i]}"
        done
        echo -e "\nPress Enter to continue, or type 'm' to return to the menu (auto continue in 5 seconds)..."
        read -t 5 -n 1 choice
        [ "$choice" = "m" ] && break
    done
}

###############################################################################
# Function: file_integrity_check
# Description: Checks system file integrity using debsums.
###############################################################################
file_integrity_check() {
    clear
    print_border
    print_title "${YELLOW}FILE INTEGRITY CHECK${NC}"
    print_border
    echo -e "${CYAN}Description:${NC} This check verifies the current checksums of system files against those expected from installed packages."
    echo -e "If no errors are detected, the system is considered intact.\n"
    if command -v debsums &>/dev/null; then
       local tmpfile
       tmpfile=$(mktemp /tmp/debsums_output.XXXXXX)
       timeout 60s debsums -s 2>/dev/null > "$tmpfile"
       if [ ! -s "$tmpfile" ]; then
           echo -e "${GREEN}All system files are intact according to debsums.${NC}"
           read -rp "\nPress Enter to return to the menu..." dummy
       else
           echo -e "${RED}Integrity errors detected:${NC}\n"
           paginate_output "$(cat "$tmpfile")" 20
           read -rp "\nPress Enter to return to the menu..." dummy
       fi
       rm -f "$tmpfile"
    else
       echo -e "${RED}Debsums is not installed.${NC}"
       echo "Install debsums with: sudo apt-get install debsums"
       read -rp "\nPress Enter to return to the menu..." dummy
    fi
}

###############################################################################
# Function: advanced_dashboard
# Description: Launches the Glances dashboard for real-time monitoring.
###############################################################################
advanced_dashboard() {
    clear
    if command -v glances &>/dev/null; then
         echo -e "${YELLOW}Glances dashboard is now running.${NC}"
         echo -e "${CYAN}To return to the menu, press 'q' or Ctrl+C to exit Glances.${NC}"
         sleep 2
         glances
         echo -e "${YELLOW}Dashboard closed. Press Enter to return to the menu.${NC}"
         read -rp "" dummy
    else
         echo -e "${RED}Glances is not installed.${NC}"
         echo "Install Glances to use the advanced dashboard."
         read -rp "Press Enter to return to the menu..." dummy
    fi
}

###############################################################################
# Function: audit_log
# Description: Searches authentication logs for suspicious keywords.
###############################################################################
audit_log() {
    clear
    print_border
    print_title "${YELLOW}AUDIT & LOG CORRELATION${NC}"
    print_border
    echo -e "${CYAN}Description:${NC} This function searches the authentication logs for keywords such as 'failed', 'invalid', and 'error'."
    echo -e "It displays the last 30 suspicious events (if any).\n"
    local rep
    rep=$(grep -Ei "failed|invalid|error" /var/log/auth.log 2>/dev/null | tail -n 30)
    if [ -z "$rep" ]; then
         echo -e "${GREEN}No suspicious events found in authentication logs.${NC}"
    else
         echo -e "${YELLOW}${rep}${NC}"
    fi
    print_border
    read -rp "Press Enter to return to the menu..." dummy
}

###############################################################################
# Function: suspicious_process_check
# Description: Analyzes the top 30 CPU-consuming processes and flags those not on a whitelist.
###############################################################################
suspicious_process_check() {
    clear
    print_border
    print_title "${YELLOW}SUSPICIOUS PROCESS CHECK${NC}"
    print_border
    local WHITELIST=("bash" "sh" "init" "systemd" "kthreadd" "rcu_sched" "migration" "cron" "sshd" "apache2" "nginx" "mysqld" "mariadb" "postgres" "dbus-daemon" "rsyslogd" "glances")
    local suspicious=""
    while IFS= read -r line; do
         local cmd base found
         cmd=$(echo "$line" | awk '{print $11}')
         base=$(basename "$cmd")
         [ -z "$base" ] && continue
         found=0
         for proc in "${WHITELIST[@]}"; do
             if [[ "$base" == "$proc" ]]; then
                found=1
                break
             fi
         done
         if [ $found -eq 0 ]; then
            suspicious+="${RED}${line}${NC}\n"
         fi
    done < <(ps aux --sort=-%cpu | head -n 30)
    if [ -z "$suspicious" ]; then
         suspicious="${GREEN}No suspicious processes detected among the top 30 CPU consumers.${NC}"
    fi
    echo -e "${YELLOW}*** Suspicious Process Check ***${NC}\n"
    echo -e "${CYAN}${suspicious}${NC}"
    print_border
    read -rp "Press Enter to return to the menu..." dummy
}

###############################################################################
# NEW Function: system_update_upgrade
# Description: Runs "apt-get update" and, upon confirmation, "apt-get upgrade".
###############################################################################
system_update_upgrade() {
    clear
    print_border
    print_title "${YELLOW}SYSTEM UPDATE & UPGRADE${NC}"
    print_border
    echo -e "${CYAN}This function will update the package list and optionally upgrade installed packages.${NC}\n"
    
    read -rp "Proceed with 'apt-get update'? [${DEFAULT_UPDATE_RESPONSE}/n]: " ans_update
    if [[ "$ans_update" =~ ^[Yy] || -z "$ans_update" ]]; then
       sudo apt-get update && { echo -e "${GREEN}Update completed successfully.${NC}"; log_msg "INFO" "apt-get update succeeded."; } || { echo -e "${RED}Update failed.${NC}"; log_msg "ERROR" "apt-get update failed."; return; }
    else
       echo -e "${YELLOW}Update skipped.${NC}"
       log_msg "INFO" "apt-get update skipped.";
    fi

    echo ""
    read -rp "Proceed with 'apt-get upgrade'? [${DEFAULT_UPGRADE_RESPONSE}/n]: " ans_upgrade
    if [[ "$ans_upgrade" =~ ^[Yy] || -z "$ans_upgrade" ]]; then
       sudo apt-get upgrade -y && { echo -e "${GREEN}Upgrade completed successfully.${NC}"; log_msg "INFO" "apt-get upgrade succeeded."; } || { echo -e "${RED}Upgrade failed.${NC}"; log_msg "ERROR" "apt-get upgrade failed."; return; }
    else
       echo -e "${YELLOW}Upgrade skipped.${NC}"
       log_msg "INFO" "apt-get upgrade skipped.";
    fi
    print_border
    read -rp "Press Enter to return to the menu..." dummy
}

###############################################################################
# NEW Function: system_dist_upgrade
# Description: Runs "apt-get update" and, upon confirmation, "apt-get dist-upgrade".
###############################################################################
system_dist_upgrade() {
    clear
    print_border
    print_title "${YELLOW}SYSTEM DIST UPGRADE${NC}"
    print_border
    echo -e "${CYAN}This function will update the package list and perform a distribution upgrade (apt-get dist-upgrade).${NC}\n"
    
    read -rp "Proceed with 'apt-get update'? [${DEFAULT_UPDATE_RESPONSE}/n]: " ans_update
    if [[ "$ans_update" =~ ^[Yy] || -z "$ans_update" ]]; then
       sudo apt-get update && { echo -e "${GREEN}Update completed successfully.${NC}"; log_msg "INFO" "apt-get update succeeded for dist-upgrade."; } || { echo -e "${RED}Update failed.${NC}"; log_msg "ERROR" "apt-get update failed for dist-upgrade."; return; }
    else
       echo -e "${YELLOW}Update skipped.${NC}"
       log_msg "INFO" "apt-get update skipped for dist-upgrade.";
    fi

    echo ""
    read -rp "Proceed with 'apt-get dist-upgrade'? [${DEFAULT_UPGRADE_RESPONSE}/n]: " ans_dist_upgrade
    if [[ "$ans_dist_upgrade" =~ ^[Yy] || -z "$ans_dist_upgrade" ]]; then
       sudo apt-get dist-upgrade -y && { echo -e "${GREEN}Distribution upgrade completed successfully.${NC}"; log_msg "INFO" "apt-get dist-upgrade succeeded."; } || { echo -e "${RED}Distribution upgrade failed.${NC}"; log_msg "ERROR" "apt-get dist-upgrade failed."; return; }
    else
       echo -e "${YELLOW}Distribution upgrade skipped.${NC}"
       log_msg "INFO" "apt-get dist-upgrade skipped.";
    fi
    
    print_border
    read -rp "Press Enter to return to the menu..." dummy
}

###############################################################################
# NEW Function: self_update
# Description: Attempts to update the script by performing a 'git pull' from the repository.
###############################################################################
self_update() {
    clear
    print_border
    print_title "${YELLOW}SELF UPDATE${NC}"
    print_border
    echo -e "${CYAN}Attempting to update Super Info via git pull.${NC}\n"
    if command -v git &>/dev/null && [ -d ".git" ]; then
        git pull origin main || { echo -e "${RED}Self-update failed. Please update manually.${NC}"; log_msg "ERROR" "Self-update failed."; sleep 2; return; }
        echo -e "${GREEN}Super Info has been updated successfully.${NC}"
        log_msg "INFO" "Self-update succeeded.";
    else
        echo -e "${RED}Git is not available or this is not a git repository. Cannot perform self-update.${NC}"
        log_msg "ERROR" "Self-update not possible.";
    fi
    print_border
    read -rp "Press Enter to return to the menu..." dummy
}

###############################################################################
# NEW Function: system_cleanup
# Description: Runs "apt-get autoclean" and "apt-get autoremove" to clean up unused packages.
###############################################################################
system_cleanup() {
    clear
    print_border
    print_title "${YELLOW}SYSTEM CLEANUP${NC}"
    print_border
    echo -e "${CYAN}This function will run 'apt-get autoclean' and 'apt-get autoremove' to free up space by removing unused packages.${NC}\n"
    
    read -rp "Proceed with 'apt-get autoclean'? [Y/n]: " ans_autoclean
    if [[ "$ans_autoclean" =~ ^[Yy] || -z "$ans_autoclean" ]]; then
       sudo apt-get autoclean && { echo -e "${GREEN}Autoclean completed successfully.${NC}"; log_msg "INFO" "apt-get autoclean succeeded."; } || { echo -e "${RED}Autoclean failed.${NC}"; log_msg "ERROR" "apt-get autoclean failed."; return; }
    else
       echo -e "${YELLOW}Autoclean skipped.${NC}"
       log_msg "INFO" "apt-get autoclean skipped.";
    fi
    
    echo ""
    read -rp "Proceed with 'apt-get autoremove'? [Y/n]: " ans_autoremove
    if [[ "$ans_autoremove" =~ ^[Yy] || -z "$ans_autoremove" ]]; then
       sudo apt-get autoremove -y && { echo -e "${GREEN}Autoremove completed successfully.${NC}"; log_msg "INFO" "apt-get autoremove succeeded."; } || { echo -e "${RED}Autoremove failed.${NC}"; log_msg "ERROR" "apt-get autoremove failed."; return; }
    else
       echo -e "${YELLOW}Autoremove skipped.${NC}"
       log_msg "INFO" "apt-get autoremove skipped.";
    fi
    
    print_border
    read -rp "Press Enter to return to the menu..." dummy
}

###############################################################################
# NEW Function: check_outdated
# Description: Lists upgradable packages using 'apt list --upgradable'.
###############################################################################
check_outdated() {
    clear
    print_border
    print_title "${YELLOW}CHECK UPGRADABLE PACKAGES${NC}"
    print_border
    echo -e "${CYAN}The following packages are available for upgrade:${NC}\n"
    apt list --upgradable 2>/dev/null | sed '1d'
    print_border
    read -rp "Press Enter to return to the menu..." dummy
}

###############################################################################
# NEW Function: system_monitor
# Description: Monitors system performance using vmstat for a fixed period.
###############################################################################
system_monitor() {
    clear
    print_border
    print_title "${YELLOW}SYSTEM MONITOR (vmstat)${NC}"
    print_border
    echo -e "${CYAN}Launching system monitor for 10 iterations...${NC}"
    echo -e "Timestamp, procs, memory, swap, io, system, cpu"
    for i in {1..10}; do
         vmstat | tail -n 1 | awk -v ts="$(date +"%T")" '{print ts", "$0}'
         sleep 2
    done
    print_border
    read -rp "Press Enter to return to the menu..." dummy
    log_msg "INFO" "System monitor executed for 10 iterations."
}

###############################################################################
# NEW Function: system_health_check
# Description: Checks disk usage, memory usage and CPU load average.
###############################################################################
system_health_check() {
    clear
    print_border
    print_title "${YELLOW}SYSTEM HEALTH CHECK${NC}"
    print_border

    # Check Disk Usage (for / partition)
    local disk_usage
    disk_usage=$(df / | tail -1 | awk '{print $5}' | tr -d '%')
    echo -e "${BLUE}Disk Usage ( / ):${NC} ${GREEN}${disk_usage}%${NC}"
    if [ "$disk_usage" -ge 90 ]; then
        echo -e "${RED}Warning: Disk usage is above 90%!${NC}"
        log_msg "WARNING" "Disk usage critical: ${disk_usage}%"
    fi

    # Check Memory Usage
    local mem_usage total used available percentage
    read total used available _ < <(free -m | awk 'NR==2{print $2, $3, $7}')
    percentage=$(( 100 * used / total ))
    echo -e "${BLUE}Memory Usage:${NC} ${GREEN}${percentage}%${NC} (Used: ${used}MB / Total: ${total}MB)"
    if [ "$percentage" -ge 90 ]; then
        echo -e "${RED}Warning: Memory usage is above 90%!${NC}"
        log_msg "WARNING" "Memory usage critical: ${percentage}%"
    fi

    # Check CPU Load Average (1 minute)
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | cut -d, -f1 | sed 's/ //g')
    echo -e "${BLUE}CPU Load Average (1 min):${NC} ${GREEN}${load_avg}${NC}"
    # Supponiamo un carico > 2.0 come critico; questo valore va adattato in base al numero di core.
    awk -v load="$load_avg" 'BEGIN { if (load+0 > 2.0) exit 1; else exit 0; }'
    if [ $? -ne 0 ]; then
        echo -e "${RED}Warning: CPU load average is above 2.0!${NC}"
        log_msg "WARNING" "CPU load average critical: ${load_avg}"
    fi

    print_border
    read -rp "Press Enter to return to the menu..." dummy
}

###############################################################################
# NEW Function: update_menu (Maintenance Submenu)
# Description: Displays a submenu for update/upgrade/maintenance operations.
###############################################################################
update_menu() {
    while true; do
        clear
        print_border
        print_title "${YELLOW}MAINTENANCE OPERATIONS MENU${NC}"
        print_border
        echo -e "${CYAN}Select an option:${NC}\n"
        echo -e "${YELLOW}1) System Update & Upgrade"
        echo -e "2) System Dist Upgrade"
        echo -e "3) Self Update"
        echo -e "4) System Cleanup (Autoclean & Autoremove)"
        echo -e "5) Check Upgradable Packages"
        echo -e "6) Return to Main Menu${NC}"
        print_border
        read -rp "Enter your choice: " choice_update
        case $choice_update in
             1) system_update_upgrade ;;
             2) system_dist_upgrade ;;
             3) self_update ;;
             4) system_cleanup ;;
             5) check_outdated ;;
             6) break ;;
             *) echo -e "${RED}Invalid option. Try again.${NC}"; sleep 2 ;;
        esac
    done
}

###############################################################################
# Main Menu: Displays the main menu and routes user choices.
###############################################################################
main_menu() {
    while true; do
         clear
         print_border
         print_title "${MAGENTA}ADMIN SECURITY TOOL (Super Info)${NC}"
         print_border
         echo -e "${CYAN}Select an option by entering the corresponding number:${NC}\n"
         echo -e "${YELLOW}1) System Info"
         echo -e "2) Machine Info"
         echo -e "3) User Info"
         echo -e "4) Login & Service Monitoring"
         echo -e "5) Authentication Log Monitoring"
         echo -e "6) Network & Ports Analysis"
         echo -e "7) Advanced Dashboard"
         echo -e "8) Audit & Log Correlation"
         echo -e "9) Suspicious Process Check"
         echo -e "10) System Monitor (vmstat)"
         echo -e "15) Maintenance Operations (Update/Upgrade/Cleanup)"
         echo -e "16) System Health Check"
         echo -e "${RED}0) Exit${NC}\n"
         print_border
         read -rp "Enter your choice: " choice
         case $choice in
              1) system_info ;;
              2) machine_info ;;
              3) user_info ;;
              4) login_service_monitor ;;
              5) auth_log_monitor ;;
              6) network_ports_analysis ;;
              7) advanced_dashboard ;;
              8) audit_log ;;
              9) suspicious_process_check ;;
              10) system_monitor ;;
              15) update_menu ;;
              16) system_health_check ;;
              0) clear; echo -e "${MAGENTA}Exiting...${NC}"; exit 0 ;;
              *) echo -e "${RED}Invalid choice. Please try again.${NC}"; sleep 2 ;;
         esac
    done
}

# --- Initialization & Start ---
clear
echo -e "${MAGENTA}Starting Super Info – Admin Security Tool...${NC}"
sleep 1
main_menu
