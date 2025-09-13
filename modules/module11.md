# Chapter 11: Python Loops for Ethical Hacking

## Overview

Loops are fundamental programming constructs that enable automation and repetitive tasks essential in ethical hacking and cybersecurity. This chapter covers how to effectively use Python loops for security testing, network scanning, log analysis, and penetration testing automation.

## For Loops

### Basic Port Scanner
```python
import socket
from datetime import datetime

def basic_port_scan(target, ports):
    open_ports = []
    
    print(f"Starting port scan on {target}")
    print(f"Time started: {datetime.now()}")
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                open_ports.append(port)
                print(f"Port {port}: OPEN")
            
            sock.close()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    
    return open_ports

# Usage
target_host = "scanme.nmap.org"
ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995]
open_ports = basic_port_scan(target_host, ports_to_scan)
print(f"Open ports found: {open_ports}")
```

### Subnet Scanning
```python
import subprocess

def subnet_scan(base_ip, start_host=1, end_host=254):
    """Scan a subnet for active hosts"""
    active_hosts = []
    base = '.'.join(base_ip.split('.')[:-1])
    
    for host_num in range(start_host, end_host + 1):
        target_ip = f"{base}.{host_num}"
        
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1000', target_ip],
                capture_output=True, timeout=2
            )
            
            if result.returncode == 0:
                active_hosts.append(target_ip)
                print(f"Host {target_ip}: ACTIVE")
        
        except subprocess.TimeoutExpired:
            continue
        except Exception as e:
            print(f"Error pinging {target_ip}: {e}")
    
    return active_hosts

# Usage
active_devices = subnet_scan("192.168.1.0", 1, 50)
print(f"Found {len(active_devices)} active hosts")
```

## While Loops for Monitoring

### Continuous Service Monitoring
```python
import time
import requests
from datetime import datetime

def monitor_website(url, check_interval=60, max_failures=5):
    """Continuously monitor website availability"""
    consecutive_failures = 0
    total_checks = 0
    
    print(f"Monitoring {url} every {check_interval} seconds")
    
    while consecutive_failures < max_failures:
        total_checks += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            response = requests.get(url, timeout=10)
            response_time = response.elapsed.total_seconds()
            
            if response.status_code == 200:
                print(f"[{timestamp}] ✓ {url} - Status: {response.status_code} - Time: {response_time:.2f}s")
                consecutive_failures = 0
            else:
                consecutive_failures += 1
                print(f"[{timestamp}] ✗ {url} - Status: {response.status_code}")
        
        except requests.RequestException as e:
            consecutive_failures += 1
            print(f"[{timestamp}] ✗ {url} - Error: {e}")
        
        time.sleep(check_interval)
    
    print(f"🚨 ALERT: {url} failed {max_failures} times!")
    return False
```

## Nested Loops for Complex Scanning

### Multi-target Port Scanner
```python
def comprehensive_scan(targets, ports):
    """Scan multiple targets and ports"""
    results = {}
    
    for target in targets:
        results[target] = {'status': 'scanning', 'open_ports': []}
        print(f"Scanning {target}...")
        
        # Check if host is alive
        if ping_host(target):
            results[target]['status'] = 'online'
            
            for port in ports:
                if scan_port(target, port):
                    results[target]['open_ports'].append(port)
                    print(f"  {target}:{port} - OPEN")
        else:
            results[target]['status'] = 'offline'
    
    return results

def ping_host(ip):
    try:
        result = subprocess.run(['ping', '-c', '1', '-W', '1000', ip],
                              capture_output=True, timeout=2)
        return result.returncode == 0
    except:
        return False

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False
```

## Real-World Applications

### Log Analysis with Pattern Detection
```python
import re
from collections import defaultdict

def analyze_security_logs(log_entries):
    """Analyze security logs for threats using loops"""
    threat_patterns = {
        'sql_injection': [r'union select', r'or 1=1', r'drop table'],
        'xss_attempts': [r'<script.*?>', r'javascript:', r'onerror='],
        'brute_force': [r'failed.*login', r'authentication.*failed'],
        'directory_traversal': [r'\.\./', r'/etc/passwd']
    }
    
    threat_summary = defaultdict(list)
    ip_threat_count = defaultdict(int)
    
    for line_num, log_line in enumerate(log_entries, 1):
        log_lower = log_line.lower()
        
        # Extract IP address
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', log_line)
        source_ip = ip_match.group(1) if ip_match else 'unknown'
        
        # Check each threat category
        for threat_type, patterns in threat_patterns.items():
            for pattern in patterns:
                if re.search(pattern, log_lower):
                    threat_summary[threat_type].append({
                        'line': line_num,
                        'ip': source_ip,
                        'content': log_line.strip()
                    })
                    ip_threat_count[source_ip] += 1
                    print(f"THREAT: {threat_type} from {source_ip} at line {line_num}")
                    break
    
    return dict(threat_summary), dict(ip_threat_count)

# Example usage
sample_logs = [
    "192.168.1.100 - GET /login.php?user=admin' OR 1=1--",
    "10.0.0.50 - GET /search.php?q=<script>alert('XSS')</script>",
    "192.168.1.100 - POST /login failed login attempt"
]

threats, ip_counts = analyze_security_logs(sample_logs)
print("Top attacking IPs:")
for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
    print(f"  {ip}: {count} threats")
```

### Threaded Network Scanner
```python
import threading
import queue
from concurrent.futures import ThreadPoolExecutor

class ThreadedScanner:
    def __init__(self, max_threads=50):
        self.max_threads = max_threads
        self.results = queue.Queue()
        self.scan_stats = {'scanned': 0, 'open': 0, 'closed': 0}
    
    def scan_port(self, target, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            
            self.scan_stats['scanned'] += 1
            
            if result == 0:
                self.scan_stats['open'] += 1
                service = self.identify_service(port)
                self.results.put({
                    'host': target,
                    'port': port,
                    'service': service
                })
            else:
                self.scan_stats['closed'] += 1
            
            sock.close()
        except Exception:
            pass
    
    def identify_service(self, port):
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 443: 'HTTPS'
        }
        return services.get(port, 'UNKNOWN')
    
    def threaded_scan(self, targets, ports):
        # Create all scan tasks
        tasks = [(target, port) for target in targets for port in ports]
        
        print(f"Scanning {len(tasks)} host:port combinations with {self.max_threads} threads")
        
        # Execute with thread pool
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            for target, port in tasks:
                executor.submit(self.scan_port, target, port)
        
        # Collect results
        results = []
        while not self.results.empty():
            result = self.results.get()
            results.append(result)
            print(f"OPEN: {result['host']}:{result['port']} ({result['service']})")
        
        print(f"\nScan complete: {self.scan_stats['open']} open, {self.scan_stats['closed']} closed")
        return results

# Usage
scanner = ThreadedScanner(max_threads=20)
targets = ["scanme.nmap.org"]
ports = [21, 22, 23, 25, 53, 80, 110, 443]
# results = scanner.threaded_scan(targets, ports)
```

## List Comprehensions for Efficiency

### Fast Network Operations
```python
# Efficient host discovery
def fast_ping_sweep(network_base, host_range):
    import subprocess
    
    ip_list = [f"{network_base}.{i}" for i in range(host_range[0], host_range[1] + 1)]
    
    active_hosts = [
        ip for ip in ip_list
        if subprocess.run(['ping', '-c', '1', '-W', '500', ip],
                         capture_output=True).returncode == 0
    ]
    
    return active_hosts

# Vulnerability filtering
def filter_critical_vulns(vuln_list):
    """Filter vulnerabilities by severity"""
    return [
        vuln for vuln in vuln_list
        if vuln.get('cvss_score', 0) > 7.0 and vuln.get('exploit_available', False)
    ]

# Port service mapping
def map_services_to_ports(open_ports):
    service_map = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 443: 'HTTPS'
    }
    
    return [
        {'port': port, 'service': service_map.get(port, 'UNKNOWN')}
        for port in open_ports
    ]
```

## Advanced Loop Control

### Smart Scanning with Break/Continue
```python
def smart_port_scanner(target, max_ports=1000):
    """Advanced scanner with intelligent stopping"""
    open_ports = []
    consecutive_timeouts = 0
    
    for port in range(1, max_ports + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                open_ports.append(port)
                print(f"Port {port}: OPEN")
                consecutive_timeouts = 0
            else:
                consecutive_timeouts = 0
            
            sock.close()
            
        except socket.timeout:
            consecutive_timeouts += 1
            print(f"Port {port}: TIMEOUT")
            
            # Stop if firewall detected (too many timeouts)
            if consecutive_timeouts >= 10:
                print("⚠️ Firewall detected - stopping scan")
                break
                
        except Exception as e:
            print(f"Error on port {port}: {e}")
            continue  # Skip to next port
    
    return open_ports
```

### Loop with Else Clause
```python
def find_vulnerable_service(target, service_ports, exploit_db):
    """Find exploitable services on target"""
    
    for port in service_ports:
        if scan_port(target, port):
            print(f"Found service on port {port}")
            
            # Check for known exploits
            for exploit in exploit_db:
                if port in exploit['affected_ports']:
                    print(f"🚨 VULNERABLE: {exploit['name']} on port {port}")
                    return True
    else:
        # Executes only if no vulnerabilities found
        print("✓ No vulnerable services found")
        return False
```

## Generator Functions for Memory Efficiency

### Large Log File Processing
```python
def memory_efficient_log_analysis(log_file_path):
    """Process large files without loading into memory"""
    
    def log_line_generator(file_path):
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                yield line_num, line.strip()
    
    def filter_threats(log_generator):
        threat_keywords = ['error', 'failed', 'attack', 'unauthorized']
        
        for line_num, line in log_generator:
            if any(keyword in line.lower() for keyword in threat_keywords):
                yield line_num, line
    
    # Process efficiently
    log_gen = log_line_generator(log_file_path)
    threat_gen = filter_threats(log_gen)
    
    threat_count = 0
    for line_num, line in threat_gen:
        threat_count += 1
        print(f"Line {line_num}: {line}")
        
        # Process in batches to manage memory
        if threat_count >= 100:
            print("Processed 100 threats. Use more specific filters for larger logs.")
            break
    
    return threat_count
```

## Best Practices

### Error Handling in Loops
```python
def robust_network_scan(targets, ports):
    """Scanner with comprehensive error handling"""
    results = {}
    
    for target in targets:
        results[target] = {'status': 'scanning', 'ports': [], 'errors': []}
        
        try:
            # Validate target format
            socket.inet_aton(target)
            
            for port in ports:
                try:
                    if scan_port_with_timeout(target, port, timeout=2):
                        results[target]['ports'].append(port)
                
                except socket.timeout:
                    results[target]['errors'].append(f"Timeout on port {port}")
                except ConnectionRefusedError:
                    pass  # Port closed, normal behavior
                except Exception as e:
                    results[target]['errors'].append(f"Port {port}: {str(e)}")
            
            results[target]['status'] = 'completed'
            
        except socket.error:
            results[target]['status'] = 'invalid_target'
            results[target]['errors'].append("Invalid IP address")
        except Exception as e:
            results[target]['status'] = 'error'
            results[target]['errors'].append(f"Scan failed: {str(e)}")
    
    return results
```

### Rate Limiting
```python
import time

def rate_limited_operations(targets, operation, rate_limit=1.0):
    """Perform operations with rate limiting"""
    results = []
    
    for i, target in enumerate(targets):
        # Perform operation
        try:
            result = operation(target)
            results.append(result)
            print(f"Processed {target}: {result}")
        except Exception as e:
            print(f"Error processing {target}: {e}")
            results.append(None)
        
        # Rate limiting (except for last item)
        if i < len(targets) - 1:
            time.sleep(rate_limit)
    
    return results

# Usage with dynamic rate adjustment
def adaptive_rate_scan(targets):
    current_delay = 1.0
    
    for target in targets:
        start_time = time.time()
        
        try:
            result = scan_target(target)
            response_time = time.time() - start_time
            
            # Adjust rate based on response time
            if response_time > 5:  # Slow response
                current_delay *= 1.5
            elif response_time < 1:  # Fast response
                current_delay = max(0.1, current_delay * 0.8)
                
        except Exception:
            current_delay *= 2  # Slow down on errors
        
        time.sleep(current_delay)
```

## Summary

**Key Loop Applications in Ethical Hacking:**
- Network scanning and service enumeration
- Log analysis and threat hunting
- Continuous security monitoring
- Vulnerability assessment automation  
- Brute force testing (authorized systems only)

**Performance Optimization:**
- Use list comprehensions for simple operations
- Implement threading for I/O-bound tasks
- Use generators for memory-efficient processing
- Apply rate limiting to avoid detection

**Security Best Practices:**
- Always obtain proper authorization
- Implement comprehensive error handling
- Add timeouts to prevent hanging operations
- Use rate limiting to respect target resources
- Log all activities for audit purposes

**Advanced Techniques:**
- Nested loops for complex multi-target scanning
- Generator functions for large dataset processing
- Threaded execution for parallel operations
- Adaptive rate limiting based on target response

Mastering Python loops enables the creation of sophisticated, automated security tools that are essential for modern ethical hacking and penetration testing workflows.