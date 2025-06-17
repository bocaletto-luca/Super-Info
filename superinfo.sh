#!/bin/bash
# Super Info – Admin Security Tool
# Author: Bocaletto Luca
# License: Apache 2.0
# Language: English
#
# Super Info is a comprehensive, text-based utility for system administrators on 
# Ubuntu and other Debian-based distributions. It provides essential security 
# monitoring and system checks via a custom ASCII interface with colors.
#
# Features:
#   1) System Info                – Displays basic system information.
#   2) Machine Info               – Displays detailed hardware specifications.
#   3) User Info                  – Shows details about the current user.
#   4) Login & Service Monitoring – Monitors active sessions and status of critical services.
#   5) Authentication Log Monitoring – Continuously displays the last 20 events from /var/log/auth.log.
#   6) Network & Ports Analysis   – Scans and displays open network ports.
#   7) Advanced Dashboard         – Launches the Glances dashboard.
#   8) Audit & Log Correlation    – Searches auth logs for suspicious keywords.
#   9) Suspicious Process Check   – Analyzes top 30 CPU-consuming processes and flags those not on a whitelist.
#   10) System Update & Upgrade   – Update the package list and upgrade installed packages.
#   11) System Dist Upgrade       – Performs a distribution upgrade (apt-get dist-upgrade).
#   12) Self Update               – Updates the script itself via 'git pull'.
#   0) Exit                      – Terminates the program.
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

# --- Trap for clean exit on SIGINT and SIGTERM ---
cleanup() {
    echo -e "\n${MAGENTA}Exiting Super Info...${NC}"
    exit 0
}
trap cleanup SIGINT SIGTERM

# --- Logging function (estendibile) ---
log_msg() {
    local level="$1"
    local msg="$2"
    echo -e "[${level}] $(date +"%Y-%m-%d %T") : ${msg}"
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
        read -rp "Proceed with installation? [Y/n] " answer
        if [[ "$answer" =~ ^[Yy] || -z "$answer" ]]; then
            sudo apt-get update && sudo apt-get install -y "${missing[@]}"
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
# Description: Mostra le informazioni di base del sistema.
# Input: Nessuno.
# Output: Visualizza le informazioni e attende l'input per tornare al menu.
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
# Description: Mostra le specifiche hardware della macchina.
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
# Description: Mostra le informazioni relative all'utente corrente.
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
# Description: Monitora le sessioni attive e lo stato dei servizi critici.
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
# Description: Mostra in continuazione gli ultimi 20 eventi da /var/log/auth.log.
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
# Description: Scansiona e mostra le porte di rete aperte usando il comando ss.
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
# Description: Paginazione dell'output (default 20 righe per pagina).
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
# Description: Verifica l'integrità dei file di sistema usando debsums.
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
# Description: Avvia il dashboard Glances per il monitoraggio in tempo reale.
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
# Description: Cerca nei log di autenticazione parole chiave sospette.
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
# Description: Analizza i processi top (30 per uso CPU) e segnala quelli non in whitelist.
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
# Description: Esegue "apt-get update" e, previa conferma, "apt-get upgrade"
###############################################################################
system_update_upgrade() {
    clear
    print_border
    print_title "${YELLOW}SYSTEM UPDATE & UPGRADE${NC}"
    print_border
    echo -e "${CYAN}This function will update the package list and optionally upgrade installed packages.${NC}\n"
    
    read -rp "Proceed with 'apt-get update'? [Y/n]: " ans_update
    if [[ "$ans_update" =~ ^[Yy] || -z "$ans_update" ]]; then
       sudo apt-get update && echo -e "${GREEN}Update completed successfully.${NC}" || { echo -e "${RED}Update failed.${NC}"; return; }
    else
       echo -e "${YELLOW}Update skipped.${NC}"
    fi

    echo ""
    read -rp "Proceed with 'apt-get upgrade'? [Y/n]: " ans_upgrade
    if [[ "$ans_upgrade" =~ ^[Yy] || -z "$ans_upgrade" ]]; then
       sudo apt-get upgrade -y && echo -e "${GREEN}Upgrade completed successfully.${NC}" || { echo -e "${RED}Upgrade failed.${NC}"; return; }
    else
       echo -e "${YELLOW}Upgrade skipped.${NC}"
    fi
    print_border
    read -rp "Press Enter to return to the menu..." dummy
}

###############################################################################
# NEW Function: system_dist_upgrade
# Description: Esegue "apt-get update" seguito da "apt-get dist-upgrade" previa conferma.
###############################################################################
system_dist_upgrade() {
    clear
    print_border
    print_title "${YELLOW}SYSTEM DIST UPGRADE${NC}"
    print_border
    echo -e "${CYAN}This function will update the package list and perform a distribution upgrade (apt-get dist-upgrade).${NC}\n"
    
    read -rp "Proceed with 'apt-get update'? [Y/n]: " ans_update
    if [[ "$ans_update" =~ ^[Yy] || -z "$ans_update" ]]; then
       sudo apt-get update && echo -e "${GREEN}Update completed successfully.${NC}" || { echo -e "${RED}Update failed.${NC}"; return; }
    else
       echo -e "${YELLOW}Update skipped.${NC}"
    fi

    echo ""
    read -rp "Proceed with 'apt-get dist-upgrade'? [Y/n]: " ans_dist_upgrade
    if [[ "$ans_dist_upgrade" =~ ^[Yy] || -z "$ans_dist_upgrade" ]]; then
       sudo apt-get dist-upgrade -y && echo -e "${GREEN}Distribution upgrade completed successfully.${NC}" || { echo -e "${RED}Distribution upgrade failed.${NC}"; return; }
    else
       echo -e "${YELLOW}Distribution upgrade skipped.${NC}"
    fi
    
    print_border
    read -rp "Press Enter to return to the menu..." dummy
}

###############################################################################
# NEW Function: self_update
# Description: Tenta di aggiornare lo script eseguendo "git pull" dal repository.
###############################################################################
self_update() {
    clear
    print_border
    print_title "${YELLOW}SELF UPDATE${NC}"
    print_border
    echo -e "${CYAN}Attempting to update Super Info via git pull.${NC}\n"
    if command -v git &>/dev/null && [ -d ".git" ]; then
        git pull origin main || { echo -e "${RED}Self-update failed. Please update manually.${NC}"; sleep 2; return; }
        echo -e "${GREEN}Super Info has been updated successfully.${NC}"
    else
        echo -e "${RED}Git is not available or this is not a git repository. Cannot perform self-update.${NC}"
    fi
    print_border
    read -rp "Press Enter to return to the menu..." dummy
}

###############################################################################
# Main Menu: Mostra il menu principale e gestisce le scelte dell'utente.
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
         echo -e "9) Suspicious Process Check"
         echo -e "10) System Update & Upgrade"
         echo -e "11) System Dist Upgrade"
         echo -e "12) Self Update${NC}"
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
              10) system_update_upgrade ;;
              11) system_dist_upgrade ;;
              12) self_update ;;
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
