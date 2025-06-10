# Super Info | BASH Script

**Author:** Bocaletto Luca

## Overview

**Super Info** is a comprehensive, command-line utility designed for system administrators working on Ubuntu and Debian-based distributions. Developed entirely in Bash, it provides essential functionality for security monitoring and system checks without relying on an external GUI library. Instead, the tool "draws" its text-based interfaces using ASCII borders and colorized output (if your terminal supports colors) to improve readability.

This tool helps you quickly obtain critical system information and monitor various services. Its modular design includes the following features:

- **System Info:**  
  Displays basic system information such as the OS name, kernel version, architecture, hostname, date/time, and locale.
  
- **Machine Info:**  
  Shows detailed hardware specifications, including CPU details, memory usage, disk space, and network interfaces.
  
- **User Info:**  
  Provides details about the current user—username, UID, groups, home directory, and recent login history.
  
- **Login & Service Monitoring:**  
  Runs a loop that refreshes every 5 seconds to display current login sessions and the status of critical services (e.g., sshd, apache2/nginx, mysqld/mariadb, postgresql). You can press **m** during the update wait time to exit this monitoring loop and return to the main menu.
  
- **Authentication Log Monitoring:**  
  Continuously displays the latest 20 events from `/var/log/auth.log` to help you track authentication-related incidents. Press **m** to break the loop and return to the menu.
  
- **Network & Ports Analysis:**  
  Uses the `ss` command to scan and display all open ports on the system.
  
- **File Integrity Check:**  
  Runs an integrity check via `debsums`, comparing the current file checksums with the expected ones from the installed packages. It explains the process and displays any discrepancies (or a "system is intact" message if no errors are found).
  
- **Advanced Dashboard:**  
  Launches the real-time dashboard provided by Glances (if installed) for advanced system monitoring. Exit Glances by pressing **q** or **Ctrl+C** to return to the menu.
  
- **Audit & Log Correlation:**  
  Searches through the authentication logs for suspicious keywords (such as "failed," "invalid," or "error") and displays the last 30 matching entries.
  
- **Suspicious Process Check:**  
  Inspects the top 30 CPU-consuming processes and flags any processes that are not part of a predefined whitelist.
  
- **Exit:**  
  Terminates the utility.

## Features

- **Clear, Text-Driven Interface:**  
  Each area of the tool is rendered in a visually organized manner using ASCII borders and centered titles. Color codes (using `tput setaf` for universal compatibility) are applied if your terminal supports at least 8 colors.

- **Universal Compatibility:**  
  The tool uses only standard commands available on Ubuntu and all Debian-based systems, ensuring it runs on all these environments.

- **Modular Design:**  
  Each function—whether providing system info, hardware info, or live monitoring—is self-contained, making the tool easy to maintain and extend.

- **Real-Time Monitoring:**  
  Certain functions (like monitoring login sessions and authentication logs) update every 5 seconds and allow you to exit by pressing **m**.

- **Automatic Dependency Checking:**  
  At startup, the tool checks for required packages (Glances and Debsums) and prompts you to install any missing dependencies automatically via `apt-get`.

## Installation

1. **Requirements:**  
   - Ubuntu or another Debian-based system  
   - Bash shell  
   - `sudo` privileges (to install missing dependencies)

2. **Clone the Repository:**

   ```bash
   git clone https://github.com/bocaletto-luca/super-info.git
   cd super-info
