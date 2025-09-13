# Chapter 5: Linux Terminal and Basic Commands

## Overview

The Linux terminal is the command-line interface that provides direct access to the operating system's functionality. For ethical hackers, mastering the terminal is essential as most penetration testing tools and security operations are performed through command-line interfaces.

## Why Linux Terminal for Ethical Hacking?

### Key Advantages
- **Direct System Control**: Access to system functions and configurations
- **Automation Capabilities**: Scripting and batch operations
- **Tool Integration**: Most security tools are command-line based
- **Remote Access**: SSH and remote terminal sessions
- **Efficiency**: Faster than GUI for many operations
- **Scriptability**: Automate complex security workflows

## Terminal Basics

### Opening the Terminal
```bash
# Keyboard shortcuts:
Ctrl + Alt + T          # Most Linux distributions
Ctrl + Shift + T        # Additional terminal tab
Alt + F2, type "terminal" # Run dialog

# GUI Methods:
Applications > Terminal
Right-click desktop > Open Terminal
```

### Understanding the Prompt
```bash
# Standard prompt format:
username@hostname:current_directory$ command

# Examples:
kali@kali:~$ ls
root@kali:/home/kali# whoami
user@ubuntu:/etc$ pwd

# Prompt symbols:
$ = regular user
# = root user
~ = home directory
/ = root directory
```

## Essential File and Directory Commands

### Navigation Commands
```bash
# Present Working Directory
pwd                     # Show current directory path

# List Directory Contents  
ls                      # Basic listing
ls -l                   # Long format (detailed)
ls -la                  # Include hidden files
ls -lh                  # Human readable file sizes
ls -lt                  # Sort by modification time
ls -lS                  # Sort by file size

# Change Directory
cd /path/to/directory   # Absolute path
cd ../                  # Parent directory
cd ../../               # Two levels up
cd ~                    # Home directory
cd -                    # Previous directory
cd                      # Home directory (shortcut)

# Examples for security testing:
cd /var/log             # System logs
cd /etc                 # Configuration files
cd /usr/bin             # System binaries
cd /tmp                 # Temporary files
```

### File Operations
```bash
# Create Files
touch filename.txt      # Create empty file
touch file1 file2 file3 # Multiple files
nano filename.txt       # Create and edit with nano
vim filename.txt        # Create and edit with vim

# Copy Files and Directories
cp source destination   # Copy file
cp -r source dest      # Copy directory recursively
cp -p source dest      # Preserve permissions
cp *.txt backup/       # Copy all .txt files

# Move and Rename
mv oldname newname     # Rename file/directory
mv file /new/location  # Move to new location
mv *.log logs/         # Move all .log files

# Remove Files and Directories
rm filename            # Delete file
rm -f filename         # Force delete (no prompt)
rm -r directory        # Delete directory recursively
rm -rf directory       # Force delete directory
rm *.tmp              # Delete all .tmp files

# Security Examples:
rm -f /var/log/*.log   # Clear log files (authorized systems only)
cp /etc/passwd backup/ # Backup critical files
```

### File Content Operations
```bash
# View File Contents
cat filename           # Display entire file
less filename          # Page through file
more filename          # Page through file (older)
head filename          # First 10 lines
head -n 20 filename    # First 20 lines
tail filename          # Last 10 lines
tail -n 50 filename    # Last 50 lines
tail -f filename       # Follow file changes (real-time)

# Search File Contents
grep "pattern" filename        # Search for pattern
grep -i "pattern" filename     # Case insensitive
grep -r "pattern" directory    # Recursive search
grep -n "pattern" filename     # Show line numbers
grep -v "pattern" filename     # Invert match (exclude)

# Security Examples:
tail -f /var/log/auth.log     # Monitor authentication attempts
grep "Failed password" /var/log/auth.log  # Find failed logins
grep -i "error" /var/log/syslog          # Find errors in system log
```

## File Permissions and Security

### Understanding Permissions
```bash
# Permission format: rwxrwxrwx (owner, group, others)
# r = read (4), w = write (2), x = execute (1)

# View Permissions
ls -l filename         # Show detailed permissions
ls -la                # Show all files with permissions

# Permission Examples:
-rwxrwxrwx  # 777: Full permissions for all
-rwx------  # 700: Full permissions for owner only
-rw-r--r--  # 644: Owner read/write, others read only
-rwxr-xr-x  # 755: Owner full, others read/execute

# Change Permissions
chmod 755 filename     # Set permissions using numbers
chmod u+x filename     # Add execute for user
chmod g-w filename     # Remove write for group
chmod o=r filename     # Set others to read only
chmod +x script.sh     # Make script executable

# Change Ownership
sudo chown user:group filename    # Change owner and group
sudo chown user filename          # Change owner only
sudo chgrp group filename         # Change group only

# Security Applications:
chmod 600 ~/.ssh/id_rsa          # Secure SSH private key
chmod 644 /etc/passwd             # Standard passwd permissions
sudo chown root:root /etc/shadow  # Secure shadow file
```

## Process Management

### Viewing Processes
```bash
# Process Status
ps                     # Current user processes
ps aux                 # All processes (detailed)
ps aux | grep process  # Find specific process
pgrep process_name     # Find process by name
pstree                 # Show process tree

# Real-time Process Monitor
top                    # Interactive process monitor
htop                   # Enhanced process monitor (if installed)
iotop                  # I/O monitor
nethogs                # Network usage by process

# Process Information
pidof process_name     # Get Process ID
lsof                   # List open files
lsof -p PID           # Files opened by specific process
lsof -i :PORT         # Processes using specific port
```

### Managing Processes
```bash
# Job Control
command &              # Run in background
jobs                   # List background jobs
fg %1                  # Bring job to foreground
bg %1                  # Send job to background
nohup command &        # Run command immune to hangups

# Kill Processes
kill PID               # Terminate process by ID
kill -9 PID           # Force kill process
killall process_name   # Kill all instances of process
pkill pattern         # Kill processes matching pattern

# Security Examples:
ps aux | grep suspicious_process   # Look for malicious processes
sudo kill -9 $(pidof malware)     # Force kill malware process
lsof -i                           # Check network connections
```

## Network Commands

### Network Information
```bash
# Network Configuration
ifconfig              # Network interface configuration (older)
ip addr show         # Show IP addresses (newer)
ip route show        # Show routing table
hostname             # Display hostname
hostname -I          # Display IP addresses

# Network Connectivity
ping hostname        # Test connectivity
ping -c 4 8.8.8.8   # Ping 4 times
traceroute hostname  # Trace route to destination
nslookup domain     # DNS lookup
dig domain          # DNS information (detailed)

# Network Statistics
netstat -tuln       # Show listening ports
netstat -tuln | grep :80  # Check if port 80 is listening
ss -tuln            # Modern replacement for netstat
ss -p               # Show process using each socket
```

### Network Scanning (Authorized Systems Only)
```bash
# Port Scanning
nmap target_ip              # Basic port scan
nmap -sS target_ip          # SYN scan
nmap -sU target_ip          # UDP scan
nmap -A target_ip           # Aggressive scan
nmap -p 1-1000 target_ip    # Scan specific port range
nmap 192.168.1.0/24        # Scan entire subnet

# Service Detection
nmap -sV target_ip          # Version detection
nmap -sC target_ip          # Default scripts
nmap -O target_ip           # OS detection

# Network Discovery
nmap -sn 192.168.1.0/24    # Ping scan (host discovery)
arp-scan 192.168.1.0/24    # ARP scan for local network
```

## System Information Commands

### System Status
```bash
# System Information
uname -a                # System information
cat /etc/os-release     # OS version information
uptime                  # System uptime and load
whoami                  # Current username
id                      # User and group IDs
w                       # Who is logged in
last                    # Last login history

# Hardware Information
lscpu                   # CPU information
lsmem                   # Memory information
lsblk                   # Block devices
lsusb                   # USB devices
lspci                   # PCI devices
dmesg                   # Kernel messages
```

### Disk Usage
```bash
# Disk Space
df -h                   # Disk free space (human readable)
du -h directory         # Directory usage
du -sh directory        # Summary of directory size
du -h --max-depth=1     # One level deep

# Find Large Files
find / -size +100M 2>/dev/null  # Files larger than 100MB
find . -type f -exec ls -lh {} + | sort -k5 -hr  # Sort by size
```

## Log Analysis and Monitoring

### System Logs
```bash
# Important Log Files
/var/log/syslog         # System messages
/var/log/auth.log       # Authentication attempts
/var/log/kern.log       # Kernel messages
/var/log/apache2/access.log  # Web server access
/var/log/apache2/error.log   # Web server errors

# Log Analysis Commands
tail -f /var/log/auth.log           # Real-time auth monitoring
grep "Failed password" /var/log/auth.log  # Find failed login attempts
awk '/Failed password/ {print $1, $2, $3, $9, $11}' /var/log/auth.log  # Extract specific fields
```

### Security Monitoring
```bash
# Monitor Failed Login Attempts
grep "Failed password" /var/log/auth.log | tail -10

# Check for Suspicious Activity
grep -i "error\|fail\|warn" /var/log/syslog | tail -20

# Monitor Network Connections
netstat -tuln | grep LISTEN
ss -tuln | grep ":22"  # Check SSH connections

# Process Monitoring
ps aux --sort=-%cpu | head -10  # Top CPU users
ps aux --sort=-%mem | head -10  # Top memory users
```

## Text Processing and Filtering

### Advanced Grep Usage
```bash
# Regular Expressions with Grep
grep "^root" /etc/passwd        # Lines starting with "root"
grep "bash$" /etc/passwd        # Lines ending with "bash"
grep "[0-9]" filename           # Lines containing numbers
grep -E "(error|fail|warn)" logfile  # Multiple patterns

# Context Searching
grep -A 5 -B 5 "pattern" file  # 5 lines before and after match
grep -C 3 "pattern" file       # 3 lines of context around match
```

### Text Processing Tools
```bash
# Sort and Unique
sort filename              # Sort lines
sort -u filename          # Sort and remove duplicates
sort -n filename          # Numeric sort
uniq filename             # Remove adjacent duplicates

# Cut and AWK
cut -d: -f1 /etc/passwd   # Extract first field (username)
cut -d: -f1,3 /etc/passwd # Extract username and UID
awk '{print $1}' filename # Print first column
awk -F: '{print $1}' /etc/passwd  # Use colon as field separator

# Word Count
wc filename               # Lines, words, characters
wc -l filename           # Count lines only
wc -w filename           # Count words only
```

## File Search and Location

### Find Command
```bash
# Find Files by Name
find /path -name "filename"     # Exact name match
find /path -name "*.txt"        # Wildcard search
find /path -iname "*.PDF"       # Case insensitive

# Find by Properties
find /path -type f              # Files only
find /path -type d              # Directories only
find /path -size +10M           # Files larger than 10MB
find /path -mtime -7            # Modified in last 7 days
find /path -perm 777            # Files with specific permissions

# Security Examples
find /home -name "*.ssh"        # Find SSH directories
find /var/log -name "*.log" -mtime -1  # Recent log files
find /tmp -type f -atime +7 -delete    # Delete old temp files
```

### Locate Command
```bash
# Fast File Location (requires updatedb)
sudo updatedb              # Update locate database
locate filename            # Find files by name
locate "*.conf" | head -10 # Find config files
```

## Archive and Compression

### Tar Archives
```bash
# Create Archives
tar -czf archive.tar.gz directory/    # Create gzipped archive
tar -cjf archive.tar.bz2 directory/   # Create bzip2 archive
tar -cf archive.tar files/            # Create uncompressed archive

# Extract Archives
tar -xzf archive.tar.gz               # Extract gzipped archive
tar -xjf archive.tar.bz2              # Extract bzip2 archive
tar -tf archive.tar                   # List archive contents
tar -xzf archive.tar.gz -C /destination/  # Extract to specific directory

# Security Examples
tar -czf backup-$(date +%Y%m%d).tar.gz /etc/  # Backup configuration
tar -czf evidence.tar.gz suspicious_files/     # Archive evidence
```

### Other Compression Tools
```bash
# Zip/Unzip
zip -r archive.zip directory/     # Create zip archive
unzip archive.zip                 # Extract zip archive
unzip -l archive.zip             # List zip contents

# Gzip/Gunzip
gzip filename                    # Compress file
gunzip filename.gz              # Decompress file
zcat filename.gz               # View compressed file
```

## Environment and Variables

### Environment Variables
```bash
# View Environment
env                        # All environment variables
echo $PATH                # Display PATH variable
echo $HOME                # Display home directory
echo $USER                # Display username

# Set Variables
export VARIABLE=value     # Set environment variable
unset VARIABLE           # Remove variable
PATH=$PATH:/new/path     # Add to PATH

# Shell Configuration
~/.bashrc                # Bash configuration file
~/.profile              # Shell profile
source ~/.bashrc        # Reload configuration
```

## Practical Security Commands

### System Hardening Checks
```bash
# Check User Accounts
cat /etc/passwd | grep -v nologin    # Active user accounts
cat /etc/shadow | grep -v "*\|!"     # Accounts with passwords
last | head -20                      # Recent logins

# Check Services
systemctl list-units --type=service --state=running  # Running services
netstat -tuln | grep LISTEN         # Listening services
ps aux | grep -v "^\["              # Running processes

# File Permission Audits
find /etc -type f -perm -002         # World-writable files in /etc
find /home -type f -perm -004        # World-readable files
find / -perm -4000 2>/dev/null       # SUID files
find / -perm -2000 2>/dev/null       # SGID files
```

### Log Analysis for Security
```bash
# Authentication Monitoring
grep "authentication failure" /var/log/auth.log
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c
lastb                                # Failed login attempts

# System Monitoring
dmesg | grep -i error               # Hardware/driver errors
journalctl -xe                      # Recent journal entries
journalctl -f                       # Follow journal in real-time
```

## Command Shortcuts and Tips

### Keyboard Shortcuts
```bash
# Navigation
Ctrl + A        # Beginning of line
Ctrl + E        # End of line
Ctrl + U        # Clear line before cursor
Ctrl + K        # Clear line after cursor
Ctrl + R        # Reverse search history

# Process Control
Ctrl + C        # Interrupt current command
Ctrl + Z        # Suspend current command
Ctrl + D        # End of file/logout
```

### Command History
```bash
# History Commands
history                    # Show command history
history | grep command    # Search history
!!                        # Repeat last command
!n                        # Repeat command number n
!pattern                  # Repeat last command starting with pattern

# History Configuration
export HISTSIZE=1000      # Number of commands in memory
export HISTFILESIZE=2000  # Number of commands in history file
```

## Summary

**Essential Skills for Ethical Hackers:**
- File system navigation and manipulation
- Process and service management
- Network configuration and monitoring
- Log analysis and system monitoring
- Text processing and pattern matching
- System information gathering

**Security Applications:**
- System reconnaissance and enumeration
- Log analysis for threat detection
- Service and process monitoring
- File system auditing and hardening
- Network connectivity testing
- Evidence collection and analysis

**Best Practices:**
- Always get proper authorization before testing
- Use appropriate permissions (avoid unnecessary root)
- Document all activities for audit trails
- Practice in isolated lab environments
- Keep backups of critical system files
- Monitor system resources during operations

**Key Command Categories:**
- Navigation: `pwd`, `cd`, `ls`
- File Operations: `cp`, `mv`, `rm`, `chmod`
- Text Processing: `grep`, `awk`, `sort`, `cut`
- System Info: `ps`, `netstat`, `df`, `who`
- Network: `ping`, `netstat`, `nmap`, `ss`

Mastering these Linux terminal commands provides the foundation for advanced ethical hacking techniques and system administration skills essential for cybersecurity professionals.