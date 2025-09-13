# Chapter 2: Hacking Environment Setup

## Overview

Setting up a proper ethical hacking environment is crucial for safe, legal, and effective penetration testing. This chapter provides a comprehensive guide to building your own penetration testing laboratory using industry-standard tools and best practices.

## Core Components

### 1. Kali Linux (Primary Attack Platform)
- **Latest Version**: Kali 2025.2 (July 2025 release)
- **New Features**: GNOME 48, KDE 6.3, BloodHound Community Edition, 13 new tools
- **Menu Organization**: Now follows MITRE ATT&CK framework structure
- **System Requirements**: Minimum 2GB RAM (4GB+ recommended), 20GB disk space

### 2. Virtual Machine Platforms

| Platform | Best For | Cost | Performance |
|----------|----------|------|-------------|
| **VirtualBox** | Beginners, learning | Free | Good |
| **VMware Workstation Pro** | Professional use | Paid | Excellent |
| **VMware Workstation Player** | Personal use | Free | Good |

### 3. Vulnerable Target Machines

| Target | Type | Difficulty | Use Case |
|--------|------|-----------|----------|
| **Metasploitable 2** | Linux VM | Beginner | Service exploitation, Metasploit practice |
| **DVWA** | Web App | Beginner | Web vulnerability testing (SQLi, XSS) |
| **OWASP Juice Shop** | Modern Web | Intermediate | JavaScript/Node.js vulnerabilities |
| **Mutillidae** | Web App | Beginner-Intermediate | OWASP Top 10 + additional vulns |
| **VulnHub VMs** | Various | All levels | CTF-style challenges |

## Step-by-Step Setup Guide

### Phase 1: Hypervisor Installation

#### VirtualBox Setup (Recommended for Beginners)
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install virtualbox virtualbox-ext-pack

# CentOS/RHEL/Fedora
sudo dnf install VirtualBox

# Windows: Download from virtualbox.org
```

**Important**: Enable virtualization in BIOS/UEFI:
- Intel processors: Enable VT-x
- AMD processors: Enable AMD-V

### Phase 2: Kali Linux Deployment

#### Option A: Pre-built VM (Fastest)
1. **Download** Kali Linux VM from official site (kali.org)
2. **Import** OVA file into VirtualBox/VMware
3. **Default credentials**: `kali/kali`
4. **First boot**: Update system with `sudo apt update && sudo apt upgrade`

#### Option B: Docker Container (Lightweight)
```bash
# Quick access without full VM overhead
docker run --rm -it kalilinux/kali-rolling

# Persistent container with tools
docker run -it --name kali-container kalilinux/kali-rolling
docker exec -it kali-container /bin/bash
```

#### Option C: WSL (Windows Users)
```bash
# Windows Subsystem for Linux
wsl --install -d kali-linux
# Configure GUI: sudo apt install kali-win-kex
```

### Phase 3: Network Configuration

#### Recommended Setup: NAT Network
- **Isolates lab** from host network for safety
- **Allows internet access** for updates and tool downloads
- **Enables VM-to-VM communication** within the lab

**VirtualBox NAT Network Configuration:**
```bash
# Create NAT network
VBoxManage natnetwork add --netname "EthicalHackingLab" --network "192.168.100.0/24" --enable

# Configure DHCP
VBoxManage natnetwork modify --netname "EthicalHackingLab" --dhcp on
```

### Phase 4: Target Machine Deployment

#### Metasploitable 2 Setup
1. **Download** from VulnHub or SourceForge
2. **Import** VM and configure network as NAT
3. **Default credentials**: `msfadmin/msfadmin`
4. **Test connectivity**: Ping from Kali Linux

#### DVWA Setup (Multiple Options)
```bash
# Option 1: Docker (Recommended)
docker run --rm -it -p 80:80 vulnerables/web-dvwa
# Access: http://localhost/login.php (admin/password)

# Option 2: Manual Installation on LAMP stack
wget https://github.com/digininja/DVWA/archive/master.zip
unzip master.zip && cd DVWA-master
# Configure database and web server
```

## Essential Tools Pre-installed in Kali

### Network Reconnaissance & Scanning
```bash
# Nmap - Network discovery and port scanning
nmap -sn 192.168.100.0/24          # Host discovery
nmap -sS -sV -O 192.168.100.50     # Stealth SYN scan with version detection

# Masscan - High-speed port scanner
masscan -p1-65535 192.168.100.0/24 --rate=1000

# Nikto - Web server scanner
nikto -h http://192.168.100.50
```

### Web Application Testing
```bash
# Burp Suite - Web proxy and scanner
# Launch: Applications > Web Application Analysis > Burp Suite

# OWASP ZAP - Free web application scanner
zap.sh -daemon -host 127.0.0.1 -port 8080

# SQLMap - SQL injection testing
sqlmap -u "http://target.com/page.php?id=1" --dbs
```

### Exploitation Frameworks
```bash
# Metasploit - Primary exploitation framework
msfconsole
search cve:2024
use exploit/multi/handler

# Social Engineer Toolkit (SET)
setoolkit
# Menu-driven social engineering attacks
```

### Password Attacks
```bash
# John the Ripper - Password cracking
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Hydra - Network login brute forcer
hydra -l admin -P passwords.txt http-get://target.com

# Hashcat - Advanced password recovery
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

## Lab Architecture Examples

### Beginner Lab (3 VMs)
```
┌─────────────────────┐
│   Host Machine     │
│                     │
│  ┌───────────────┐  │
│  │ VirtualBox/   │  │
│  │ VMware        │  │
│  │               │  │
│  │ ┌──────────┐  │  │
│  │ │ Kali     │  │  │
│  │ │ Linux    │  │  │
│  │ └─────┬────┘  │  │
│  │       │       │  │
│  │ ┌─────┴────┐  │  │
│  │ │ NAT Net  │  │  │
│  │ │ 192.168. │  │  │
│  │ │ 100.0/24 │  │  │
│  │ └─────┬────┘  │  │
│  │   ┌───┴───┐   │  │
│  │   │ Meta- │   │  │
│  │   │ sploit│   │  │
│  │   │ able2 │   │  │
│  │   └───────┘   │  │
│  └───────────────┘  │
└─────────────────────┘
```

### Advanced Lab (5+ VMs)
```
Host Machine
├── Kali Linux (Attacker)
├── pfSense (Network Security)
├── Windows Server 2016 (Domain Controller)
├── Windows 10 (Client Machine)
├── Metasploitable 2 (Linux Target)
├── DVWA (Web Application Target)
└── Additional VulnHub VMs
```

## Hardware Requirements

### Minimum Specifications
- **CPU**: Dual-core with virtualization support (VT-x/AMD-V)
- **RAM**: 8GB (4GB for host + 4GB for VMs)
- **Storage**: 100GB available space
- **Network**: Dedicated lab environment

### Recommended Specifications
- **CPU**: Quad-core Intel i5/AMD Ryzen 5 or better
- **RAM**: 16GB+ (allows 3-4 VMs simultaneously)
- **Storage**: 512GB+ SSD for better VM performance
- **Graphics**: Dedicated GPU helps with resource allocation

## Security Best Practices

### Network Isolation
```bash
# Always use isolated networks
# Never expose vulnerable VMs to the internet
# Take VM snapshots before testing

# Example: VirtualBox host-only network
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1
```

### VM Snapshot Management
```bash
# Take snapshots before testing
VBoxManage snapshot "Kali Linux" take "Clean State"

# Restore to clean state after testing
VBoxManage snapshot "Kali Linux" restore "Clean State"
```

### Resource Optimization
```bash
# Optimize Kali for lab use
sudo apt update && sudo apt upgrade -y
sudo apt autoremove -y

# Install useful utilities
sudo apt install -y tmux htop git curl wget vim

# Update tool databases
sudo updatedb
sudo locate metasploit
```

## Lab Maintenance

### Regular Updates
```bash
# Update Kali Linux
sudo apt update && sudo apt full-upgrade -y

# Update Metasploit
sudo msfupdate

# Update wordlists
sudo apt install seclists

# Update exploit database
sudo searchsploit -u
```

### Backup Strategies
1. **VM Snapshots**: Clean states before testing
2. **Configuration Backups**: Save custom tool configurations
3. **Documentation**: Log successful exploits and methodologies
4. **Regular Exports**: Export VMs for disaster recovery

## Quick Start Commands

### Initial Network Discovery
```bash
# Discover live hosts
nmap -sn 192.168.100.0/24

# Quick port scan
nmap -F 192.168.100.50

# Service enumeration
nmap -sV -sC 192.168.100.50
```

### Web Application Testing Setup
```bash
# Start Burp Suite proxy
burpsuite &

# Configure browser proxy (127.0.0.1:8080)
# Install Burp certificate for HTTPS

# Directory enumeration
dirb http://192.168.100.50
gobuster dir -u http://192.168.100.50 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

### Metasploit Quick Setup
```bash
# Initialize Metasploit database
sudo msfdb init

# Start Metasploit
msfconsole

# Basic commands
help
search apache
use exploit/multi/handler
show options
set PAYLOAD windows/meterpreter/reverse_tcp
```

## Learning Resources

### Practice Platforms
- **VulnHub**: Free vulnerable VMs for download
- **Hack The Box**: Online penetration testing labs
- **OverTheWire**: Command-line security challenges
- **TryHackMe**: Guided learning paths and challenges

### Documentation & References
- **Kali Linux Documentation**: docs.kali.org
- **Metasploit Unleashed**: metasploitunleashed.com
- **OWASP Testing Guide**: owasp.org/www-project-web-security-testing-guide
- **NIST Cybersecurity Framework**: nist.gov/cybersecurity

## Troubleshooting Common Issues

### VM Performance Problems
```bash
# Increase VM memory allocation
# Enable hardware acceleration
# Disable unnecessary services
sudo systemctl disable bluetooth
sudo systemctl disable cups
```

### Network Connectivity Issues
```bash
# Reset network configuration
sudo dhclient -r
sudo dhclient

# Check routing table
route -n
ip route show
```

### Tool Installation Problems
```bash
# Fix broken packages
sudo apt --fix-broken install

# Reinstall Kali metapackage
sudo apt install kali-linux-large
```

## Summary

A well-configured ethical hacking environment provides the foundation for effective security testing while maintaining safety and legal compliance. The combination of Kali Linux, vulnerable targets, and proper network isolation creates an ideal learning and testing platform.

**Key Environment Components:**
- Kali Linux as primary attack platform
- Vulnerable target machines for practice
- Isolated network configuration for safety
- Regular updates and maintenance
- Comprehensive documentation and backups

This environment setup ensures you have access to industry-standard tools while maintaining complete control over your testing scope and activities.