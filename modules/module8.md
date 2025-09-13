# Chapter 8: Python General Syntax for Ethical Hacking

## Overview

Python's clean and readable syntax makes it an ideal language for security professionals and ethical hackers. This chapter covers essential Python syntax elements with a focus on security applications, providing practical examples for penetration testing and cybersecurity automation.

## Python Syntax Fundamentals

### Code Structure and Indentation
```python
# Python uses indentation to define code blocks
# Consistent indentation is critical (use 4 spaces)

def scan_network(network_range):
    """Network scanning function with proper indentation"""
    active_hosts = []
    
    for ip in network_range:
        if ping_host(ip):                    # 4 spaces indentation
            active_hosts.append(ip)          # 4 spaces indentation
            print(f"Host {ip} is active")    # 4 spaces indentation
    
    return active_hosts

# Nested structures require additional indentation
def analyze_vulnerability(target, vulnerabilities):
    for vuln in vulnerabilities:             # 4 spaces
        if vuln['severity'] == 'critical':   # 8 spaces (nested)
            print(f"CRITICAL: {vuln['name']} found on {target}")
            if vuln['exploitable']:          # 12 spaces (double nested)
                print("Exploitation possible!")
```

### Comments and Documentation
```python
# Single-line comments for quick explanations
import socket  # For network operations

"""
Multi-line comments (docstrings) for detailed documentation
This function performs a TCP port scan on a target host
Returns a list of open ports
"""

def port_scan(host, ports):
    """
    Perform TCP port scan on target host
    
    Args:
        host (str): Target IP address or hostname
        ports (list): List of ports to scan
    
    Returns:
        list: List of open ports
        
    Example:
        >>> open_ports = port_scan("192.168.1.100", [22, 80, 443])
        >>> print(open_ports)
        [22, 80, 443]
    """
    open_ports = []
    
    for port in ports:
        # Try to connect to each port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # 1 second timeout
        
        result = sock.connect_ex((host, port))
        if result == 0:  # Port is open
            open_ports.append(port)
        
        sock.close()
    
    return open_ports
```

### Variables and Naming Conventions
```python
# Naming conventions for security scripts
target_ip = "192.168.1.100"              # Snake_case for variables
TARGET_PORT = 443                         # UPPER_CASE for constants
is_vulnerable = False                     # Boolean variables
vulnerability_count = 0                   # Counter variables

# Security-specific variable examples
COMMON_PASSWORDS = ["password", "123456", "admin"]
failed_login_attempts = []
exploit_payload = "'; DROP TABLE users; --"
authorized_users = {"admin", "security_team", "pentester"}

# Class names use PascalCase
class VulnerabilityScanner:
    """Base class for vulnerability scanning tools"""
    pass

class SqlInjectionTester:
    """Specialized class for SQL injection testing"""
    pass

# Function names use snake_case
def check_sql_injection(url, parameter, payload):
    """Test for SQL injection vulnerability"""
    pass

def generate_wordlist(length, charset):
    """Generate wordlist for password attacks"""
    pass
```

## Data Types for Security Applications

### Strings and Text Processing
```python
# String operations common in security work
target_url = "https://example.com/login"
malicious_payload = "<script>alert('XSS')</script>"
sql_injection = "' OR '1'='1"

# String formatting for security tools
def log_security_event(event_type, source_ip, details):
    """Log security events with proper formatting"""
    timestamp = "2024-01-15 10:30:45"
    
    # Modern f-string formatting (Python 3.6+)
    log_entry = f"[{timestamp}] {event_type}: {source_ip} - {details}"
    
    # Alternative .format() method
    log_entry_alt = "[{}] {}: {} - {}".format(timestamp, event_type, source_ip, details)
    
    # Old-style % formatting (still useful for logging)
    log_entry_old = "[%s] %s: %s - %s" % (timestamp, event_type, source_ip, details)
    
    return log_entry

# String methods for security analysis
suspicious_user_agent = "Mozilla/5.0 (compatible; sqlmap/1.0; http://sqlmap.org/)"

# Check for security tools in user agent
if "sqlmap" in suspicious_user_agent.lower():
    print("Potential SQL injection tool detected")

# Extract information from strings
log_line = "192.168.1.100 - Failed login attempt for user: admin"
ip_address = log_line.split(" - ")[0]
username = log_line.split("user: ")[1]

# String validation for input sanitization
def is_valid_ip(ip_string):
    """Basic IP address format validation"""
    parts = ip_string.split('.')
    if len(parts) != 4:
        return False
    
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
    
    return True

# Test the validation
test_ip = "192.168.1.100"
if is_valid_ip(test_ip):
    print(f"{test_ip} is a valid IP address")
```

### Lists and Arrays for Security Data
```python
# Lists for storing security-related data
discovered_hosts = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
open_ports = [22, 80, 443, 8080]
vulnerability_types = ["SQLi", "XSS", "CSRF", "Directory Traversal"]

# Common security wordlists
common_passwords = [
    "password", "123456", "admin", "root", "guest", 
    "user", "test", "password123", "qwerty", "letmein"
]

# Web directories for enumeration
common_directories = [
    "admin", "login", "panel", "config", "backup",
    "test", "dev", "staging", "api", "uploads"
]

# List operations for security tasks
def filter_high_ports(port_list):
    """Filter ports above 1024 (user ports)"""
    return [port for port in port_list if port > 1024]

def find_critical_vulnerabilities(vulnerability_list):
    """Find vulnerabilities with critical severity"""
    critical_vulns = []
    for vuln in vulnerability_list:
        if isinstance(vuln, dict) and vuln.get('severity') == 'critical':
            critical_vulns.append(vuln)
    return critical_vulns

# List comprehensions for efficient processing
# Extract IPs from log entries
log_entries = [
    "192.168.1.100 - Login successful",
    "10.0.0.50 - Failed login attempt", 
    "192.168.1.200 - Connection established"
]

ip_addresses = [entry.split(" - ")[0] for entry in log_entries]
print(f"IP addresses found: {ip_addresses}")

# Filter failed login attempts
failed_logins = [entry for entry in log_entries if "Failed" in entry]
```

### Dictionaries for Security Configurations
```python
# Dictionaries for security configurations and mappings
port_services = {
    21: "FTP",
    22: "SSH", 
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S"
}

# Vulnerability database structure
vulnerabilities = {
    "CVE-2024-1234": {
        "name": "Remote Code Execution in WebApp",
        "severity": "critical",
        "cvss_score": 9.8,
        "affected_ports": [80, 443, 8080],
        "description": "Remote code execution via unsanitized input",
        "exploit_available": True,
        "patch_available": False
    },
    "CVE-2024-5678": {
        "name": "SQL Injection in Login Form",
        "severity": "high", 
        "cvss_score": 7.5,
        "affected_ports": [80, 443],
        "description": "SQL injection via login parameters",
        "exploit_available": True,
        "patch_available": True
    }
}

# Security tool configurations
nmap_configs = {
    "stealth_scan": "-sS -T2 -f",
    "aggressive_scan": "-A -T4",
    "udp_scan": "-sU --top-ports 1000",
    "version_detection": "-sV -sC",
    "os_detection": "-O"
}

# Dictionary methods for security analysis
def get_service_info(port):
    """Get service information for a given port"""
    return port_services.get(port, "Unknown")

def check_vulnerability(cve_id):
    """Check if vulnerability exists in database"""
    if cve_id in vulnerabilities:
        vuln = vulnerabilities[cve_id]
        return f"Vulnerability: {vuln['name']}, Severity: {vuln['severity']}"
    return "Vulnerability not found"

# Iterate through dictionary for analysis
def analyze_discovered_services(service_dict):
    """Analyze discovered services for security risks"""
    risky_services = []
    
    for port, service in service_dict.items():
        if service in ["FTP", "Telnet", "HTTP"]:  # Unencrypted services
            risky_services.append({
                "port": port,
                "service": service, 
                "risk": "Unencrypted protocol"
            })
    
    return risky_services
```

### Sets for Unique Security Data
```python
# Sets for storing unique values (no duplicates)
scanned_hosts = {"192.168.1.100", "192.168.1.101", "192.168.1.102"}
authorized_users = {"admin", "security_team", "pentester", "auditor"}
blocked_ips = {"10.0.0.1", "172.16.0.1", "192.168.1.1"}

# Set operations for security analysis
compromised_hosts = {"192.168.1.100", "192.168.1.105", "192.168.1.110"}
all_monitored_hosts = {"192.168.1.100", "192.168.1.101", "192.168.1.102", 
                       "192.168.1.103", "192.168.1.104", "192.168.1.105"}

# Find which monitored hosts are compromised
affected_hosts = compromised_hosts.intersection(all_monitored_hosts)
print(f"Compromised monitored hosts: {affected_hosts}")

# Find uncompromised hosts
safe_hosts = all_monitored_hosts.difference(compromised_hosts)
print(f"Safe hosts: {safe_hosts}")

# Check if specific host is in set
target_host = "192.168.1.100"
if target_host in compromised_hosts:
    print(f"Warning: {target_host} is compromised!")

# Add/remove from sets
newly_discovered_threats = {"192.168.1.200", "192.168.1.201"}
compromised_hosts.update(newly_discovered_threats)

# Remove false positives
false_positive = "192.168.1.101"
if false_positive in compromised_hosts:
    compromised_hosts.remove(false_positive)
```

## Operators and Expressions

### Comparison Operators in Security Context
```python
# Comparison operators for security conditions
def assess_vulnerability_severity(cvss_score):
    """Assess vulnerability severity based on CVSS score"""
    if cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    elif cvss_score > 0.0:
        return "Low"
    else:
        return "Informational"

# Port range checking
def is_well_known_port(port):
    """Check if port is in well-known range (0-1023)"""
    return 0 <= port <= 1023

def is_registered_port(port):
    """Check if port is in registered range (1024-49151)"""
    return 1024 <= port <= 49151

def is_dynamic_port(port):
    """Check if port is in dynamic/private range (49152-65535)"""
    return 49152 <= port <= 65535

# String comparison for security validation
def validate_user_input(user_input):
    """Validate user input against malicious patterns"""
    malicious_patterns = [
        "script", "onload", "onerror", "javascript:",
        "union select", "drop table", "../", "cmd.exe"
    ]
    
    user_input_lower = user_input.lower()
    for pattern in malicious_patterns:
        if pattern in user_input_lower:
            return False, f"Suspicious pattern detected: {pattern}"
    
    return True, "Input appears safe"
```

### Logical Operators for Security Logic
```python
# Logical operators for complex security conditions
def should_block_ip(ip, failed_attempts, is_blacklisted, is_whitelisted):
    """Determine if IP should be blocked based on multiple criteria"""
    
    # Block if blacklisted AND not whitelisted
    if is_blacklisted and not is_whitelisted:
        return True, "IP is blacklisted"
    
    # Block if too many failed attempts AND not whitelisted
    if failed_attempts > 5 and not is_whitelisted:
        return True, f"Too many failed attempts: {failed_attempts}"
    
    # Allow if whitelisted
    if is_whitelisted:
        return False, "IP is whitelisted"
    
    return False, "No blocking criteria met"

def is_suspicious_activity(time_range, request_count, error_rate, user_agent):
    """Detect suspicious activity based on multiple indicators"""
    
    # High request rate in short time
    high_volume = request_count > 1000 and time_range < 60
    
    # High error rate indicates scanning/probing
    high_errors = error_rate > 0.5
    
    # Suspicious user agent patterns
    suspicious_ua = any(pattern in user_agent.lower() for pattern in 
                       ['scan', 'bot', 'crawler', 'sqlmap', 'nikto'])
    
    # Suspicious if any two conditions are true
    conditions_met = sum([high_volume, high_errors, suspicious_ua])
    
    return conditions_met >= 2, {
        "high_volume": high_volume,
        "high_errors": high_errors, 
        "suspicious_ua": suspicious_ua,
        "conditions_met": conditions_met
    }
```

### Arithmetic Operators for Security Calculations
```python
# Arithmetic operators for security calculations
def calculate_attack_success_rate(successful_attempts, total_attempts):
    """Calculate attack success rate percentage"""
    if total_attempts == 0:
        return 0
    return (successful_attempts / total_attempts) * 100

def calculate_entropy(password):
    """Calculate password entropy (simplified)"""
    import math
    
    # Character set sizes
    lowercase = sum(1 for c in password if c.islower())
    uppercase = sum(1 for c in password if c.isupper())
    digits = sum(1 for c in password if c.isdigit())
    special = len(password) - lowercase - uppercase - digits
    
    # Calculate charset size
    charset_size = 0
    if lowercase > 0:
        charset_size += 26
    if uppercase > 0:
        charset_size += 26
    if digits > 0:
        charset_size += 10
    if special > 0:
        charset_size += 32
    
    # Entropy = log2(charset_size^length)
    if charset_size > 0:
        entropy = len(password) * math.log2(charset_size)
        return entropy
    return 0

def estimate_crack_time(entropy):
    """Estimate time to crack password based on entropy"""
    # Assuming 1 billion guesses per second
    guesses_per_second = 1_000_000_000
    
    # Half the keyspace on average
    average_guesses = (2 ** entropy) / 2
    
    seconds = average_guesses / guesses_per_second
    
    # Convert to human-readable format
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.1f} days"
    else:
        return f"{seconds/31536000:.1f} years"

# Example usage
password = "MySecureP@ssw0rd!"
entropy = calculate_entropy(password)
crack_time = estimate_crack_time(entropy)
print(f"Password: {password}")
print(f"Entropy: {entropy:.1f} bits")
print(f"Estimated crack time: {crack_time}")
```

## Control Flow Structures

### If Statements for Security Decisions
```python
def security_response(threat_level, user_role, system_criticality):
    """Determine security response based on multiple factors"""
    
    if threat_level == "critical":
        if system_criticality == "high":
            action = "immediate_lockdown"
            notification = "emergency_alert"
        else:
            action = "isolate_system"
            notification = "urgent_alert"
    
    elif threat_level == "high":
        if user_role == "admin":
            action = "investigate_and_monitor"
            notification = "standard_alert"
        else:
            action = "block_user_access"
            notification = "security_alert"
    
    elif threat_level == "medium":
        action = "log_and_monitor"
        notification = "info_alert"
    
    else:  # low or informational
        action = "log_only"
        notification = None
    
    return {
        "action": action,
        "notification": notification,
        "threat_level": threat_level
    }

def validate_authentication(username, password, ip_address):
    """Validate authentication with security checks"""
    
    # Check for empty credentials
    if not username or not password:
        return False, "Empty credentials provided"
    
    # Check for suspicious characters
    if any(char in username for char in ['<', '>', ';', '\'', '"']):
        return False, "Invalid characters in username"
    
    # Check password length
    if len(password) < 8:
        return False, "Password too short"
    
    # Check IP blacklist (simplified)
    blacklisted_ips = ["10.0.0.1", "192.168.1.666"]  # Example IPs
    if ip_address in blacklisted_ips:
        return False, "IP address is blacklisted"
    
    # If all checks pass
    return True, "Authentication criteria met"
```

### Exception Handling for Robust Security Tools
```python
import socket
import requests
from time import sleep

def safe_port_scan(host, port, timeout=3):
    """Port scan with comprehensive error handling"""
    try:
        # Attempt to connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        
        if result == 0:
            return {"status": "open", "error": None}
        else:
            return {"status": "closed", "error": None}
            
    except socket.gaierror as e:
        return {"status": "error", "error": f"DNS resolution failed: {e}"}
    
    except socket.timeout:
        return {"status": "filtered", "error": "Connection timeout"}
    
    except PermissionError:
        return {"status": "error", "error": "Permission denied (try as root)"}
    
    except Exception as e:
        return {"status": "error", "error": f"Unexpected error: {e}"}
    
    finally:
        try:
            sock.close()
        except:
            pass

def safe_web_request(url, method="GET", **kwargs):
    """Make HTTP request with error handling and security measures"""
    
    # Security headers for requests
    default_headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Security Scanner",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    
    # Merge with provided headers
    headers = kwargs.get('headers', {})
    headers.update(default_headers)
    kwargs['headers'] = headers
    
    # Set reasonable timeout
    kwargs.setdefault('timeout', 10)
    
    try:
        if method.upper() == "GET":
            response = requests.get(url, **kwargs)
        elif method.upper() == "POST":
            response = requests.post(url, **kwargs)
        else:
            return {"success": False, "error": f"Unsupported method: {method}"}
        
        return {
            "success": True,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content": response.text,
            "error": None
        }
        
    except requests.exceptions.Timeout:
        return {"success": False, "error": "Request timeout"}
    
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": "Connection failed"}
    
    except requests.exceptions.HTTPError as e:
        return {"success": False, "error": f"HTTP error: {e}"}
    
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Request failed: {e}"}
    
    except Exception as e:
        return {"success": False, "error": f"Unexpected error: {e}"}

# Example usage with rate limiting
def scan_multiple_hosts(host_list, port_list, delay=0.1):
    """Scan multiple hosts with rate limiting and error handling"""
    results = {}
    
    for host in host_list:
        results[host] = {}
        print(f"Scanning {host}...")
        
        for port in port_list:
            result = safe_port_scan(host, port)
            results[host][port] = result
            
            if result["status"] == "error":
                print(f"  Port {port}: ERROR - {result['error']}")
            else:
                print(f"  Port {port}: {result['status'].upper()}")
            
            # Rate limiting to be respectful
            sleep(delay)
    
    return results
```

## Functions and Modular Security Code

### Function Definition and Documentation
```python
def brute_force_login(url, username_list, password_list, delay=1):
    """
    Perform brute force login attempt (for authorized testing only)
    
    Args:
        url (str): Target login URL
        username_list (list): List of usernames to try
        password_list (list): List of passwords to try  
        delay (float): Delay between attempts in seconds
        
    Returns:
        dict: Results of brute force attempt with successful credentials
        
    Raises:
        ValueError: If URL is invalid
        ConnectionError: If unable to connect to target
        
    Warning:
        Only use on systems you own or have explicit permission to test!
    """
    
    if not url.startswith(('http://', 'https://')):
        raise ValueError("Invalid URL format")
    
    successful_credentials = []
    total_attempts = len(username_list) * len(password_list)
    current_attempt = 0
    
    for username in username_list:
        for password in password_list:
            current_attempt += 1
            
            # Progress indicator
            progress = (current_attempt / total_attempts) * 100
            print(f"Progress: {progress:.1f}% - Testing {username}:{password}")
            
            try:
                # Simulate login attempt
                success = attempt_login(url, username, password)
                
                if success:
                    successful_credentials.append({
                        "username": username,
                        "password": password,
                        "attempt_number": current_attempt
                    })
                    print(f"SUCCESS: {username}:{password}")
                
            except Exception as e:
                print(f"Error testing {username}:{password} - {e}")
                continue
            
            # Rate limiting
            sleep(delay)
    
    return {
        "total_attempts": total_attempts,
        "successful_logins": successful_credentials,
        "success_rate": len(successful_credentials) / total_attempts
    }

def attempt_login(url, username, password):
    """
    Attempt single login (simplified implementation)
    
    Returns:
        bool: True if login successful, False otherwise
    """
    # This would contain actual HTTP request logic
    # Simplified for example
    session = requests.Session()
    
    login_data = {
        "username": username,
        "password": password
    }
    
    response = session.post(url, data=login_data)
    
    # Check for success indicators
    success_indicators = [
        "welcome", "dashboard", "logout", "profile"
    ]
    
    failure_indicators = [
        "invalid", "incorrect", "failed", "error"
    ]
    
    response_text = response.text.lower()
    
    # Check for success
    if any(indicator in response_text for indicator in success_indicators):
        return True
    
    # Check for explicit failure
    if any(indicator in response_text for indicator in failure_indicators):
        return False
    
    # Check status code
    return response.status_code == 200
```

### Lambda Functions for Security Operations
```python
# Lambda functions for quick security operations
is_private_ip = lambda ip: any(ip.startswith(prefix) for prefix in ['192.168.', '10.', '172.16.'])

is_high_port = lambda port: port > 1024

severity_score = lambda cvss: "Critical" if cvss >= 9 else "High" if cvss >= 7 else "Medium" if cvss >= 4 else "Low"

# Using lambdas with filter/map for data processing
ip_list = ["192.168.1.100", "8.8.8.8", "10.0.0.1", "1.1.1.1", "172.16.0.1"]
private_ips = list(filter(is_private_ip, ip_list))
print(f"Private IPs: {private_ips}")

port_list = [22, 80, 443, 8080, 3389]
high_ports = list(filter(is_high_port, port_list))
print(f"High ports: {high_ports}")

cvss_scores = [9.8, 7.5, 4.2, 2.1, 8.9]
severities = list(map(severity_score, cvss_scores))
print(f"Severities: {severities}")
```

## Summary

**Essential Python Syntax for Ethical Hacking:**
- **Clean Indentation**: Proper code structure for maintainable security tools
- **Comprehensive Comments**: Document security logic and configurations
- **Appropriate Data Types**: Lists, dictionaries, and sets for security data
- **Robust Error Handling**: Critical for network operations and user input
- **Modular Functions**: Reusable security components and tools

**Security-Specific Applications:**
- **Input Validation**: Prevent injection attacks and malicious input
- **Configuration Management**: Store security settings and tool configurations
- **Data Processing**: Analyze logs, vulnerabilities, and scan results
- **Network Operations**: Handle connections, timeouts, and failures gracefully
- **Authentication Logic**: Implement secure login and access controls

**Best Practices:**
- Always validate and sanitize user input
- Use appropriate error handling for network operations
- Implement rate limiting for scanning and brute force operations
- Document security functions with clear warnings about authorization
- Use descriptive variable names for security contexts

**Performance Considerations:**
- Use appropriate data structures for specific operations
- Implement proper exception handling to prevent crashes
- Add rate limiting to respect target systems
- Use lambda functions for simple filtering operations
- Structure code for maintainability and debugging

This comprehensive syntax foundation enables the development of robust, maintainable security tools and automation scripts essential for professional ethical hacking activities.