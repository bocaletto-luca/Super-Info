#!/bin/bash
# Super Info
# Author: Bocaletto Luca
# License: Apache 2.0
# Language: English
# Super Info is a comprehensive, text-based utility for system administrators on 
# Ubuntu and other Debian-based distributions. It provides essential security 
# monitoring and system checks via a custom ASCII interface with colors (when supported).
#
# Features:
#   1) System Info                – Displays basic system information.
#   2) Machine Info               – Displays detailed hardware specifications.
#   3) User Info                  – Shows details about the current user.
#   4) Login & Service Monitoring – Monitors active sessions and the status of critical services.
#   5) Authentication Log Monitoring – Continuously displays the last 20 events from /var/log/auth.log.
#   6) Network & Ports Analysis   – Scans and displays open network ports (using ss).
#   7) File Integrity Check       – Checks system file integrity using Debsums.
#   8) Advanced Dashboard         – Launches the Glances real-time monitoring dashboard (if installed).
#   9) Audit & Log Correlation    – Searches auth logs for suspicious keywords.
#  10) Suspicious Process Check   – Analyzes the top 30 CPU-consuming processes and flags those not on a whitelist.
#   0) Exit                      – Terminates the program.
#
# At startup, the tool checks for required packages (Glances and Debsums) and 
# prompts the user to install them if missing.
#
# ----------------------------------------------------------------------------- #
# Environment settings and portable color definitions

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
  RED=""
  GREEN=""
  YELLOW=""
  BLUE=""
  MAGENTA=""
  CYAN=""
  NC=""
fi

# Function: print_border
# Prints a horizontal border based on the terminal width.
print_border() {
    local width=$(( $(tput cols) - 2 ))
    printf "+%0.s-" $(seq 1 "$width")
    echo "+"
}

# Function: print_title
# Prints the title.
print_title() {
    local title="$1"
    echo "$title"
}

###############################################################################
# Dependency Checker
# Checks if the required packages (glances, debsums) are installed; 
# if missing, prompts the user to install them.
###############################################################################
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
        read -rp "Proceed with installation? [Y/n] " answer
        if [[ "$answer" =~ ^[Yy] || -z "$answer" ]]; then
            sudo apt-get update
            sudo apt-get install -y "${missing[@]}"
            if [ $? -ne 0 ]; then
                echo -e "${RED}Error installing packages. Exiting.${NC}"
                exit 1
            fi
        else
            echo -e "${RED}Required dependencies missing. Exiting.${NC}"
            exit 1
        fi
    fi
}
check_install_dependencies

###############################################################################
# set_dialog_dimensions
# Checks terminal dimensions.
###############################################################################
set_dialog_dimensions() {
    TERM_HEIGHT=$(tput lines)
    TERM_WIDTH=$(tput cols)
    MIN_HEIGHT=15
    MIN_WIDTH=40
    if [ "$TERM_HEIGHT" -lt "$MIN_HEIGHT" ] || [ "$TERM_WIDTH" -lt "$MIN_WIDTH" ]; then
        echo -e "${RED}The terminal must be at least ${MIN_WIDTH} columns x ${MIN_HEIGHT} rows. Current size: ${TERM_WIDTH}x${TERM_HEIGHT}.${NC}"
        exit 1
    fi
}
set_dialog_dimensions

###############################################################################
# Function: system_info
# Displays basic system information.
###############################################################################
system_info() {
    clear
    print_border
    print_title "${YELLOW}SYSTEM INFO${NC}"
    print_border
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
# Displays detailed hardware specifications.
###############################################################################
machine_info() {
    clear
    print_border
    print_title "${YELLOW}MACHINE INFO${NC}"
    print_border
    if command -v lscpu &>/dev/null; then
       cpu=$(lscpu | sed 's/^/   /')
    else
       cpu=$(cat /proc/cpuinfo | head -n 15 | sed 's/^/   /')
    fi
    mem=$(free -h | sed 's/^/   /')
    disk=$(df -h | sed 's/^/   /')
    net=$(ip -brief addr | sed 's/^/   /')
    
    echo -e "${CYAN}Description:${NC} This report displays the hardware specifications of the machine."
    echo -e "${MAGENTA}CPU:${NC}\n${GREEN}${cpu}${NC}"
    echo -e "${MAGENTA}Memory:${NC}\n${GREEN}${mem}${NC}"
    echo -e "${MAGENTA}Disk Usage:${NC}\n${GREEN}${disk}${NC}"
    echo -e "${MAGENTA}Network Interfaces:${NC}\n${GREEN}${net}${NC}"
    print_border
    read -rp "Press Enter to return to the menu..." dummy
}

###############################################################################
# Function: user_info
# Displays details about the current user.
###############################################################################
user_info() {
    clear
    print_border
    print_title "${YELLOW}USER INFO${NC}"
    print_border
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
# Monitors active sessions and status of critical services.
# At each update, the user may press 'm' during a brief timeout to return to the menu.
###############################################################################
login_service_monitor() {
    while true; do
        ts=$(date +"%c")
        sessions=$(who)
        output="${BLUE}Date/Time:${NC} ${GREEN}${ts}${NC}\n"
        output+="\n${MAGENTA}Active Sessions:${NC}\n${GREEN}${sessions}${NC}\n"
        multi=""
        while read -r user tty; do
            count=$(who | awk -v u="$user" '$1==u {print $2}' | sort -u | wc -l)
            if [ $count -gt 1 ]; then
                multi+="${RED}Warning:${NC} User ${YELLOW}$user${NC} has ${GREEN}$count${NC} simultaneous sessions.\n"
            fi
        done < <(who | awk '{print $1, $2}' | sort -u)
        if [ -n "$multi" ]; then
            output+="\n${RED}*** Multiple Login Warnings ***${NC}\n${multi}"
        fi
        output+="\n${MAGENTA}Service Status:${NC}\n"
        SERVICES=("sshd" "apache2" "nginx" "mysqld" "mariadb" "postgresql")
        for svc in "${SERVICES[@]}"; do
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
        if [ "$key" = "m" ]; then break; fi
    done
}

###############################################################################
# Function: auth_log_monitor
# Continuously displays the last 20 events from /var/log/auth.log.
# Press 'm' during a timeout to return to the menu.
###############################################################################
auth_log_monitor() {
    while true; do
        rep=$(tail -n 20 /var/log/auth.log 2>/dev/null)
        clear
        if [ -z "$rep" ]; then
            echo -e "${RED}The file /var/log/auth.log is inaccessible or empty.${NC}"
        else
            echo -e "${YELLOW}*** Last 20 Events from Auth Log ***${NC}\n${GREEN}${rep}${NC}"
        fi
        echo -e "\nPress 'm' to return to the menu, or wait 5 seconds for an update..."
        read -t 5 -n 1 key
        if [ "$key" = "m" ]; then break; fi
    done
}

###############################################################################
# Function: network_ports_analysis
# Scans and displays open network ports using the 'ss' command.
###############################################################################
network_ports_analysis() {
    clear
    print_border
    print_title "${YELLOW}NETWORK & PORTS ANALYSIS${NC}"
    print_border
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
# Paginates the provided output (default 20 lines per page).
# At the end of each page, waits 5 seconds for input; if 'm' is pressed, returns.
###############################################################################
paginate_output() {
    local output="$1"
    local lines_per_page=${2:-20}
    IFS=$'\n' read -rd '' -a lines <<< "$output"
    local total_lines=${#lines[@]}
    local i=0
    while [ $i -lt $total_lines ]; do
        clear
        for ((j=0; j<lines_per_page && i<total_lines; j++, i++)); do
            echo "${lines[$i]}"
        done
        echo -e "\nPress Enter to continue, or type 'm' to return to the menu (auto continue in 5 seconds)..."
        read -t 5 -n 1 choice
        # If user presses 'm', exit pagination
        if [ "$choice" = "m" ]; then
            break
        fi
    done
}

###############################################################################
# Function: file_integrity_check
# Checks system file integrity using debsums; output is displayed in pages.
###############################################################################
file_integrity_check() {
    clear
    print_border
    print_title "${YELLOW}FILE INTEGRITY CHECK${NC}"
    print_border
    echo -e "${CYAN}Description:${NC} This check verifies the current checksums of system files against those expected from installed packages."
    echo -e "If no errors are detected, the system is considered intact.\n"
    if command -v debsums &>/dev/null; then
       # Create a temporary file for debsums output
       tmpfile=$(mktemp /tmp/debsums_output.XXXXXX)
       # Use timeout to prevent hanging (60 seconds)
       timeout 60s debsums -s 2>/dev/null > "$tmpfile"
       if [ ! -s "$tmpfile" ]; then
           echo -e "${GREEN}All system files are intact according to debsums.${NC}"
           echo -e "\nPress Enter to return to the menu..."
           read -r
       else
           echo -e "${RED}Integrity errors detected:${NC}\n"
           # Paginate the output so the user can review it
           paginate_output "$(cat "$tmpfile")" 20
           echo -e "\nPress Enter to return to the menu..."
           read -r
       fi
       rm -f "$tmpfile"
    else
       echo -e "${RED}Debsums is not installed.${NC}"
       echo "Install debsums with: sudo apt-get install debsums"
       echo -e "\nPress Enter to return to the menu..."
       read -r
    fi
}

###############################################################################
# Function: advanced_dashboard
# Launches the Glances dashboard for real-time monitoring.
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
# Searches the authentication logs for suspicious keywords.
###############################################################################
audit_log() {
    clear
    print_border
    print_title "${YELLOW}AUDIT & LOG CORRELATION${NC}"
    print_border
    echo -e "${CYAN}Description:${NC} This function searches the authentication logs for keywords such as 'failed', 'invalid', and 'error'."
    echo -e "It displays the last 30 suspicious events (if any).\n"
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
# Analyzes the top 30 CPU-consuming processes and flags those not in a whitelist.
###############################################################################
suspicious_process_check() {
    clear
    print_border
    print_title "${YELLOW}SUSPICIOUS PROCESS CHECK${NC}"
    print_border
    local WHITELIST=("bash" "sh" "init" "systemd" "kthreadd" "rcu_sched" "migration" "cron" "sshd" "apache2" "nginx" "mysqld" "mariadb" "postgres" "dbus-daemon" "rsyslogd" "glances")
    local suspicious=""
    while IFS= read -r line; do
         local cmd=$(echo "$line" | awk '{print $11}')
         local base
         base=$(basename "$cmd")
         if [ -z "$base" ]; then
            continue
         fi
         local found=0
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
# Main Menu: Displays the menu and routes user choices.
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
         #echo -e "7) File Integrity Check"
         echo -e "7) Advanced Dashboard"
         echo -e "8) Audit & Log Correlation"
         echo -e "9) Suspicious Process Check${NC}"
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
              #7) file_integrity_check ;;
              7) advanced_dashboard ;;
              8) audit_log ;;
              9) suspicious_process_check ;;
              0) clear; echo -e "${MAGENTA}Exiting...${NC}"; exit 0 ;;
              *) echo -e "${RED}Invalid choice. Please try again.${NC}"; sleep 2 ;;
         esac
    done
}

# Initialization and start
clear
echo -e "${MAGENTA}Starting Super Info – Admin Security Tool...${NC}"
sleep 1
main_menu
