# Chapter 6: Python 3 and Ethical Hacking

## Overview

Python has become the go-to language for cybersecurity professionals and ethical hackers due to its simplicity, extensive libraries, and powerful automation capabilities. This chapter provides a comprehensive guide to using Python for ethical hacking and cybersecurity in 2024.

## Why Python for Cybersecurity?

### Key Advantages
- **Simple & Readable**: Clear syntax makes complex security scripts easier to write and maintain
- **Cross-Platform**: Works seamlessly across Windows, Linux, and macOS
- **Extensive Libraries**: Vast ecosystem of cybersecurity-focused libraries
- **Automation-Friendly**: Perfect for repetitive security tasks
- **Community Support**: Large active community with continuous updates
- **Integration**: Easy integration with existing security tools and frameworks

### Python vs Other Languages in Security

| Language | Use Case | Pros | Cons |
|----------|----------|------|------|
| **Python** | General security, automation | Easy to learn, extensive libraries | Slower execution |
| **C/C++** | Exploit development, systems | Fast execution, low-level access | Complex syntax |
| **JavaScript** | Web security, XSS | Client-side testing, widespread | Limited to web |
| **PowerShell** | Windows penetration | Windows integration | Platform-specific |

## Essential Python Libraries for Ethical Hacking (2024)

### 1. Scapy - Network Packet Manipulation
**Purpose**: Create, send, receive, and analyze network packets  
**Installation**: `pip install scapy`

```python
from scapy.all import *

# Send ICMP ping
packet = IP(dst="8.8.8.8")/ICMP()
response = sr1(packet, timeout=2)
if response:
    print("Host is alive:", response.summary())

# ARP scan for network discovery
def arp_scan(network):
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    clients_list = []
    for element in answered_list:
        client_dict = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc
        }
        clients_list.append(client_dict)
    return clients_list

# Usage
devices = arp_scan("192.168.1.0/24")
for device in devices:
    print(f"IP: {device['ip']} - MAC: {device['mac']}")
```

### 2. Python-Nmap - Network Discovery & Scanning
**Purpose**: Automate network scanning and vulnerability assessment  
**Installation**: `pip install python-nmap`

```python
import nmap

# Basic port scanner
def scan_ports(target, port_range):
    nm = nmap.PortScanner()
    nm.scan(target, port_range)
    
    for host in nm.all_hosts():
        print(f'Host: {host} - State: {nm[host].state()}')
        
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            
            for port in ports:
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port].get('name', 'unknown')
                print(f'Port: {port} - State: {state} - Service: {service}')

# Advanced scanning with service detection
def advanced_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, '22-443', '-sV -sC')
    
    for host in nm.all_hosts():
        print(f'Host: {host}')
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                port_info = nm[host][proto][port]
                print(f'  Port {port}: {port_info}')

# Usage
scan_ports("192.168.1.1", "22-80")
```

### 3. Requests - HTTP Library
**Purpose**: Make HTTP requests for web application testing  
**Installation**: `pip install requests`

```python
import requests
from bs4 import BeautifulSoup
import urllib.parse

# Basic web reconnaissance
def web_recon(url):
    try:
        response = requests.get(url, timeout=5)
        print(f"Status Code: {response.status_code}")
        print(f"Server: {response.headers.get('Server', 'Unknown')}")
        print(f"Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
        
        # Look for interesting headers
        security_headers = ['X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options']
        for header in security_headers:
            value = response.headers.get(header, 'Missing')
            print(f"{header}: {value}")
            
    except requests.RequestException as e:
        print(f"Error: {e}")

# Directory enumeration
def directory_enum(base_url, wordlist):
    common_dirs = ['admin', 'login', 'test', 'backup', 'config', 'data']
    
    for directory in common_dirs:
        url = f"{base_url.rstrip('/')}/{directory}"
        try:
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                print(f"Found: {url} - Status: {response.status_code}")
        except:
            continue

# Simple SQL injection tester
def basic_sqli_test(url, params):
    sqli_payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "' UNION SELECT NULL --"
    ]
    
    for payload in sqli_payloads:
        test_params = params.copy()
        for param in test_params:
            test_params[param] = payload
            
        try:
            response = requests.get(url, params=test_params, timeout=5)
            if "error" in response.text.lower() or "mysql" in response.text.lower():
                print(f"Potential SQLi vulnerability with payload: {payload}")
        except:
            continue

# Usage
web_recon("https://example.com")
directory_enum("https://example.com", [])
```

### 4. Paramiko - SSH Operations
**Purpose**: SSH connectivity and automation  
**Installation**: `pip install paramiko`

```python
import paramiko
import time

# SSH brute force (for authorized testing only)
def ssh_bruteforce(hostname, username, passwords):
    for password in passwords:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, password=password, timeout=3)
            
            print(f"[+] Success: {username}:{password}")
            client.close()
            return True
            
        except paramiko.AuthenticationException:
            print(f"[-] Failed: {username}:{password}")
        except:
            print(f"[!] Connection error with {hostname}")
        
        time.sleep(1)  # Rate limiting
    
    return False

# SSH command execution
def ssh_execute(hostname, username, password, command):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, username=username, password=password)
        
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        
        client.close()
        
        return output, error
    
    except Exception as e:
        return None, str(e)

# Usage (only on authorized systems)
# passwords = ['password123', 'admin', '123456', 'password']
# ssh_bruteforce('192.168.1.100', 'admin', passwords)
```

### 5. Cryptography - Encryption & Decryption
**Purpose**: Implement cryptographic operations  
**Installation**: `pip install cryptography`

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import hashlib

# Password hashing and verification
def hash_password(password):
    # Create salt
    salt = b'salt_1234567890'
    
    # Hash password with SHA-256
    password_hash = hashlib.pbkdf2_hmac('sha256', 
                                      password.encode('utf-8'), 
                                      salt, 
                                      100000)
    return base64.b64encode(password_hash).decode('utf-8')

def verify_password(stored_password, provided_password):
    return hash_password(provided_password) == stored_password

# File encryption/decryption
class FileEncryptor:
    def __init__(self, password):
        self.password = password.encode()
        salt = b'salt_1234567890'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        self.cipher = Fernet(key)
    
    def encrypt_file(self, file_path):
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        encrypted_data = self.cipher.encrypt(file_data)
        
        with open(file_path + '.encrypted', 'wb') as file:
            file.write(encrypted_data)
        
        print(f"File encrypted: {file_path}.encrypted")
    
    def decrypt_file(self, encrypted_file_path):
        with open(encrypted_file_path, 'rb') as file:
            encrypted_data = file.read()
        
        decrypted_data = self.cipher.decrypt(encrypted_data)
        
        output_file = encrypted_file_path.replace('.encrypted', '_decrypted')
        with open(output_file, 'wb') as file:
            file.write(decrypted_data)
        
        print(f"File decrypted: {output_file}")

# Usage
# encryptor = FileEncryptor("mypassword123")
# encryptor.encrypt_file("sensitive_data.txt")
```

## Top Cybersecurity Use Cases

### Network Security Scripts
```python
# Port scanner with threading
import threading
import socket
from datetime import datetime

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"Port {port}: Open")
        sock.close()
    except socket.gaierror:
        print("Hostname could not be resolved")

def threaded_scan(target, ports):
    print(f"Starting scan on {target}")
    print(f"Time started: {datetime.now()}")
    
    threads = []
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(target, port))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()

# Usage
# common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995]
# threaded_scan("scanme.nmap.org", common_ports)
```

### Web Application Security Testing
```python
# XSS vulnerability scanner
def xss_scanner(url, forms):
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')"
    ]
    
    for payload in xss_payloads:
        for form in forms:
            form_data = {}
            for input_field in form.find_all('input'):
                input_name = input_field.get('name')
                if input_name:
                    form_data[input_name] = payload
            
            try:
                response = requests.post(url, data=form_data)
                if payload in response.text:
                    print(f"Potential XSS vulnerability found with payload: {payload}")
            except:
                continue

# Password strength checker
import re

def check_password_strength(password):
    score = 0
    feedback = []
    
    # Length check
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long")
    
    # Uppercase check
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Password should contain uppercase letters")
    
    # Lowercase check
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Password should contain lowercase letters")
    
    # Number check
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Password should contain numbers")
    
    # Special character check
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Password should contain special characters")
    
    strength_levels = {
        0: "Very Weak",
        1: "Weak", 
        2: "Fair",
        3: "Good",
        4: "Strong",
        5: "Very Strong"
    }
    
    return {
        "score": score,
        "strength": strength_levels[score],
        "feedback": feedback
    }

# Usage
# result = check_password_strength("MyPassword123!")
# print(f"Strength: {result['strength']}")
```

## Learning Path for 2024

### Beginner Level (3-6 months)
1. **Python Fundamentals**
   - Variables, data types, control structures
   - Functions, classes, and modules
   - File handling and exception management
   - Regular expressions

2. **Basic Security Scripts**
   - Simple port scanner
   - Password generator
   - Log file analyzer
   - Network ping utility

### Intermediate Level (6-12 months)
1. **Advanced Libraries**
   - Scapy for packet manipulation
   - Requests for web testing
   - Paramiko for SSH automation
   - Socket programming

2. **Security Tools Development**
   - Multi-threaded scanners
   - Web vulnerability scanners
   - Network traffic analyzers
   - Automated reporting tools

### Advanced Level (12+ months)
1. **Machine Learning & AI**
   - Anomaly detection systems
   - Behavioral analysis
   - Threat intelligence automation
   - Predictive security models

2. **Advanced Frameworks**
   - Custom exploit development
   - Metasploit integration
   - API security testing
   - Cloud security automation

## Best Practices for Ethical Hacking with Python

### Code Security & Quality
```python
# Always validate input
def validate_ip(ip_address):
    try:
        socket.inet_aton(ip_address)
        return True
    except socket.error:
        return False

# Use proper error handling
def safe_request(url):
    try:
        response = requests.get(url, timeout=5)
        return response
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return None

# Implement rate limiting
import time
def rate_limited_scan(targets, delay=1):
    for target in targets:
        # Perform scan operation
        scan_target(target)
        time.sleep(delay)  # Respect target resources
```

### Legal & Ethical Guidelines
- **Always get written permission** before testing
- **Stay within authorized scope** at all times
- **Rate limit your scripts** to avoid DoS conditions
- **Document all activities** for reporting
- **Handle sensitive data** securely

## Tools and Frameworks Integration

### Metasploit Integration
```python
# Example: Interfacing with Metasploit RPC
import requests
import json

class MetasploitRPC:
    def __init__(self, host='127.0.0.1', port=55553):
        self.host = host
        self.port = port
        self.url = f"http://{host}:{port}/api/"
        self.token = None
    
    def login(self, username, password):
        data = {
            'method': 'auth.login',
            'params': [username, password]
        }
        response = requests.post(self.url, json=data)
        if response.status_code == 200:
            self.token = response.json()['result']['token']
            return True
        return False
    
    def execute_module(self, module_type, module_name, options):
        data = {
            'method': f'{module_type}.execute',
            'params': [self.token, module_name, options]
        }
        response = requests.post(self.url, json=data)
        return response.json()
```

## Summary

Python's simplicity and extensive library ecosystem make it the ideal choice for cybersecurity professionals and ethical hackers. Whether you're automating security tasks, building custom tools, or conducting penetration tests, Python provides the flexibility and power needed for modern cybersecurity challenges.

**Key Python Advantages for Security:**
- Rapid prototyping and development
- Extensive library ecosystem
- Cross-platform compatibility
- Strong community support
- Integration with existing tools

**Essential Libraries to Master:**
- Scapy for network analysis
- Requests for web testing
- Paramiko for SSH operations
- Cryptography for secure operations
- Python-nmap for network scanning

Remember: With great power comes great responsibility. Always ensure you have proper authorization before conducting any security testing, and use these tools ethically and legally.