# Chapter 10: Python Conditionals for Ethical Hacking

## Overview

Conditional statements are fundamental building blocks in Python programming and essential for creating intelligent security tools and ethical hacking scripts. This chapter covers how to use conditionals effectively in cybersecurity contexts.

## Basic Conditional Statements

### If Statement
```python
# Basic security check
def check_port_status(port, open_ports):
    if port in open_ports:
        print(f"Port {port} is OPEN - Potential security risk")
        return True
    else:
        print(f"Port {port} is CLOSED - Secure")
        return False

# Usage in port scanning
open_ports = [22, 80, 443]
check_port_status(22, open_ports)  # Output: Port 22 is OPEN - Potential security risk
```

### If-Elif-Else Chains
```python
# Vulnerability severity assessment
def assess_vulnerability_severity(cvss_score):
    if cvss_score >= 9.0:
        severity = "CRITICAL"
        action = "Immediate patch required"
    elif cvss_score >= 7.0:
        severity = "HIGH"
        action = "Patch within 24 hours"
    elif cvss_score >= 4.0:
        severity = "MEDIUM"
        action = "Patch within 1 week"
    elif cvss_score > 0:
        severity = "LOW"
        action = "Patch during next maintenance window"
    else:
        severity = "INFO"
        action = "No immediate action required"
    
    return severity, action

# Usage
severity, action = assess_vulnerability_severity(8.5)
print(f"Severity: {severity}, Action: {action}")
```

## Advanced Conditional Patterns

### Multiple Conditions with Logical Operators
```python
# Network security validation
def validate_network_security(has_firewall, updated_os, strong_passwords):
    if has_firewall and updated_os and strong_passwords:
        security_level = "SECURE"
        recommendations = "All security measures in place"
    elif has_firewall and updated_os:
        security_level = "MODERATE"
        recommendations = "Implement strong password policy"
    elif has_firewall or updated_os:
        security_level = "WEAK"
        recommendations = "Enable missing security measures immediately"
    else:
        security_level = "VULNERABLE"
        recommendations = "Critical: Implement all security measures now"
    
    return security_level, recommendations

# Usage
security_status = validate_network_security(True, False, True)
print(f"Security Level: {security_status[0]}")
print(f"Recommendations: {security_status[1]}")
```

### Nested Conditionals
```python
# Advanced malware detection logic
def analyze_file_behavior(file_extension, file_size, network_activity, registry_modifications):
    suspicious_score = 0
    
    # File type analysis
    if file_extension in ['.exe', '.scr', '.bat', '.com']:
        suspicious_score += 2
        if file_size < 100000:  # Very small executable
            suspicious_score += 3
            if network_activity:
                suspicious_score += 2
                if registry_modifications:
                    suspicious_score += 3
                    classification = "HIGHLY SUSPICIOUS - Potential Malware"
                else:
                    classification = "SUSPICIOUS - Monitor Closely"
            else:
                classification = "POTENTIALLY UNWANTED"
        else:
            classification = "NORMAL EXECUTABLE"
    else:
        if network_activity and registry_modifications:
            suspicious_score += 4
            classification = "SUSPICIOUS ACTIVITY"
        else:
            classification = "NORMAL FILE"
    
    return classification, suspicious_score

# Usage
result = analyze_file_behavior('.exe', 50000, True, True)
print(f"Classification: {result[0]}, Score: {result[1]}")
```

## Conditional Expressions (Ternary Operator)

### Basic Ternary Operations
```python
# Quick security status checks
def quick_security_check(port_open):
    status = "VULNERABLE" if port_open else "SECURE"
    return status

# Password strength validation
def password_strength_indicator(length):
    strength = "STRONG" if length >= 12 else "WEAK"
    return strength

# Service availability check
def service_status(response_code):
    status = "UP" if response_code == 200 else "DOWN"
    return status

# Usage examples
print(quick_security_check(True))   # Output: VULNERABLE
print(password_strength_indicator(8))  # Output: WEAK
print(service_status(200))  # Output: UP
```

### Complex Ternary Chains
```python
# Multi-level security assessment
def security_rating(vulnerabilities):
    rating = ("CRITICAL" if vulnerabilities > 10 else
              "HIGH" if vulnerabilities > 5 else
              "MEDIUM" if vulnerabilities > 2 else
              "LOW" if vulnerabilities > 0 else
              "EXCELLENT")
    return rating

# Usage
print(security_rating(12))  # Output: CRITICAL
print(security_rating(3))   # Output: MEDIUM
print(security_rating(0))   # Output: EXCELLENT
```

## Practical Cybersecurity Applications

### 1. Port Scanner with Intelligent Analysis
```python
import socket
from datetime import datetime

def intelligent_port_scan(target, ports):
    open_ports = []
    scan_results = {}
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                open_ports.append(port)
                
                # Intelligent service identification
                if port == 22:
                    service = "SSH"
                    risk_level = "HIGH" if port in open_ports else "LOW"
                    recommendation = "Ensure key-based authentication" if port == 22 else "Monitor access"
                elif port == 80:
                    service = "HTTP"
                    risk_level = "MEDIUM"
                    recommendation = "Consider HTTPS redirection"
                elif port == 443:
                    service = "HTTPS"
                    risk_level = "LOW"
                    recommendation = "Verify SSL certificate validity"
                elif port == 21:
                    service = "FTP"
                    risk_level = "HIGH"
                    recommendation = "Replace with SFTP if possible"
                elif port == 23:
                    service = "Telnet"
                    risk_level = "CRITICAL"
                    recommendation = "Disable immediately - Use SSH instead"
                else:
                    service = "UNKNOWN"
                    risk_level = "MEDIUM"
                    recommendation = "Investigate service purpose"
                
                scan_results[port] = {
                    'service': service,
                    'risk_level': risk_level,
                    'recommendation': recommendation
                }
            
            sock.close()
            
        except socket.gaierror:
            print(f"Could not resolve {target}")
            break
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    
    return scan_results

# Usage
target_host = "scanme.nmap.org"
common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995]
results = intelligent_port_scan(target_host, common_ports)

for port, info in results.items():
    print(f"Port {port}: {info['service']} - Risk: {info['risk_level']}")
    print(f"  Recommendation: {info['recommendation']}")
```

### 2. Vulnerability Assessment Tool
```python
import re
import requests

def assess_web_security(url):
    security_issues = []
    
    try:
        response = requests.get(url, timeout=5)
        
        # Check for missing security headers
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-XSS-Protection': 'XSS filtering',
            'X-Content-Type-Options': 'MIME type sniffing protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'Content injection protection'
        }
        
        for header, description in security_headers.items():
            if header not in response.headers:
                security_issues.append(f"Missing {header} header - {description}")
        
        # Check for sensitive information disclosure
        if 'server' in response.headers:
            server_info = response.headers['server']
            if any(keyword in server_info.lower() for keyword in ['apache', 'nginx', 'iis']):
                security_issues.append(f"Server information disclosure: {server_info}")
        
        # Check for common vulnerabilities in response
        response_text = response.text.lower()
        
        if 'error' in response_text and 'mysql' in response_text:
            security_issues.append("Potential SQL error disclosure")
        
        if 'stacktrace' in response_text or 'exception' in response_text:
            security_issues.append("Potential error message disclosure")
        
        # Assess overall security posture
        if len(security_issues) == 0:
            security_rating = "EXCELLENT"
            priority = "LOW"
        elif len(security_issues) <= 2:
            security_rating = "GOOD"
            priority = "MEDIUM"
        elif len(security_issues) <= 4:
            security_rating = "FAIR"
            priority = "HIGH"
        else:
            security_rating = "POOR"
            priority = "CRITICAL"
        
        return {
            'url': url,
            'security_rating': security_rating,
            'priority': priority,
            'issues': security_issues,
            'status_code': response.status_code
        }
        
    except requests.RequestException as e:
        return {
            'url': url,
            'error': f"Connection error: {e}",
            'security_rating': 'UNKNOWN',
            'priority': 'UNKNOWN'
        }

# Usage
assessment = assess_web_security("https://example.com")
print(f"URL: {assessment['url']}")
print(f"Security Rating: {assessment['security_rating']}")
print(f"Priority: {assessment['priority']}")

if 'issues' in assessment:
    print("Security Issues Found:")
    for issue in assessment['issues']:
        print(f"  - {issue}")
```

### 3. Log Analysis and Threat Detection
```python
import re
from collections import defaultdict
from datetime import datetime, timedelta

def analyze_security_logs(log_entries):
    threat_indicators = {
        'failed_logins': 0,
        'suspicious_ips': set(),
        'potential_attacks': [],
        'high_risk_activities': []
    }
    
    ip_activity = defaultdict(int)
    
    for log_entry in log_entries:
        # Parse log entry (simplified example)
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', log_entry)
        
        if ip_match:
            ip_address = ip_match.group(1)
            ip_activity[ip_address] += 1
            
            # Check for failed login attempts
            if 'failed login' in log_entry.lower() or 'authentication failure' in log_entry.lower():
                threat_indicators['failed_logins'] += 1
                
                # Multiple failed attempts from same IP
                if ip_activity[ip_address] > 5:
                    threat_indicators['suspicious_ips'].add(ip_address)
            
            # Check for potential SQL injection attempts
            if any(pattern in log_entry.lower() for pattern in ['union select', 'or 1=1', 'drop table']):
                threat_indicators['potential_attacks'].append(f"SQL Injection attempt from {ip_address}")
            
            # Check for potential XSS attempts
            if any(pattern in log_entry.lower() for pattern in ['<script>', 'javascript:', 'onerror=']):
                threat_indicators['potential_attacks'].append(f"XSS attempt from {ip_address}")
            
            # Check for suspicious user agents
            if 'user-agent' in log_entry.lower():
                if any(bot in log_entry.lower() for bot in ['sqlmap', 'nikto', 'nmap', 'masscan']):
                    threat_indicators['high_risk_activities'].append(f"Security tool detected from {ip_address}")
    
    # Determine threat level
    total_threats = (threat_indicators['failed_logins'] + 
                    len(threat_indicators['suspicious_ips']) + 
                    len(threat_indicators['potential_attacks']) + 
                    len(threat_indicators['high_risk_activities']))
    
    if total_threats >= 10:
        threat_level = "CRITICAL"
        response_action = "Immediate investigation required"
    elif total_threats >= 5:
        threat_level = "HIGH"
        response_action = "Monitor closely and prepare defensive measures"
    elif total_threats >= 2:
        threat_level = "MEDIUM"
        response_action = "Continue monitoring"
    elif total_threats > 0:
        threat_level = "LOW"
        response_action = "Routine monitoring sufficient"
    else:
        threat_level = "NONE"
        response_action = "No immediate threats detected"
    
    return {
        'threat_level': threat_level,
        'response_action': response_action,
        'indicators': threat_indicators,
        'total_threat_count': total_threats
    }

# Usage example
sample_logs = [
    "192.168.1.100 - - [13/Sep/2024:10:30:45] 'GET /admin' failed login attempt",
    "192.168.1.100 - - [13/Sep/2024:10:31:12] 'POST /login' failed login attempt",
    "192.168.1.100 - - [13/Sep/2024:10:31:45] 'POST /login' failed login attempt",
    "10.0.0.50 - - [13/Sep/2024:11:15:22] 'GET /search.php?q=' union select * from users",
    "203.45.67.89 - - [13/Sep/2024:12:00:11] User-Agent: sqlmap/1.0"
]

analysis = analyze_security_logs(sample_logs)
print(f"Threat Level: {analysis['threat_level']}")
print(f"Response Action: {analysis['response_action']}")
print(f"Total Threats: {analysis['total_threat_count']}")
```

## Error Handling with Conditionals

### Robust Error Checking
```python
import socket
import requests

def secure_connection_test(hostname, port, protocol='tcp'):
    result = {
        'hostname': hostname,
        'port': port,
        'protocol': protocol,
        'status': None,
        'error': None,
        'security_notes': []
    }
    
    try:
        if protocol.lower() == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            connection_result = sock.connect_ex((hostname, port))
            
            if connection_result == 0:
                result['status'] = 'OPEN'
                
                # Security analysis based on port
                if port == 23:
                    result['security_notes'].append('CRITICAL: Telnet is unencrypted')
                elif port == 21:
                    result['security_notes'].append('WARNING: FTP may be unencrypted')
                elif port == 22:
                    result['security_notes'].append('INFO: SSH connection available')
                elif port == 443:
                    result['security_notes'].append('GOOD: HTTPS enabled')
                
            else:
                result['status'] = 'CLOSED'
            
            sock.close()
            
        elif protocol.lower() == 'http':
            url = f"http://{hostname}:{port}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                result['status'] = 'ACCESSIBLE'
                if not url.startswith('https'):
                    result['security_notes'].append('WARNING: Unencrypted HTTP connection')
            else:
                result['status'] = f'HTTP_ERROR_{response.status_code}'
        
    except socket.gaierror as e:
        result['status'] = 'DNS_ERROR'
        result['error'] = str(e)
    except socket.timeout as e:
        result['status'] = 'TIMEOUT'
        result['error'] = 'Connection timed out'
    except ConnectionRefusedError as e:
        result['status'] = 'REFUSED'
        result['error'] = 'Connection refused by target'
    except requests.RequestException as e:
        result['status'] = 'REQUEST_ERROR'
        result['error'] = str(e)
    except Exception as e:
        result['status'] = 'UNKNOWN_ERROR'
        result['error'] = str(e)
    
    return result

# Usage
test_results = [
    secure_connection_test('scanme.nmap.org', 22),
    secure_connection_test('example.com', 443),
    secure_connection_test('nonexistent.domain', 80)
]

for result in test_results:
    print(f"{result['hostname']}:{result['port']} - Status: {result['status']}")
    if result['error']:
        print(f"  Error: {result['error']}")
    for note in result['security_notes']:
        print(f"  Security: {note}")
```

## Best Practices for Conditionals in Security Code

### 1. Input Validation
```python
def validate_input(user_input, input_type):
    if not user_input:
        return False, "Input cannot be empty"
    
    if input_type == 'ip':
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', user_input):
            return False, "Invalid IP address format"
        
        octets = user_input.split('.')
        if any(int(octet) > 255 for octet in octets):
            return False, "IP address octets must be between 0-255"
    
    elif input_type == 'port':
        if not user_input.isdigit():
            return False, "Port must be numeric"
        
        port = int(user_input)
        if not (1 <= port <= 65535):
            return False, "Port must be between 1-65535"
    
    elif input_type == 'url':
        if not (user_input.startswith('http://') or user_input.startswith('https://')):
            return False, "URL must start with http:// or https://"
    
    return True, "Valid input"

# Usage
is_valid, message = validate_input("192.168.1.1", "ip")
print(f"Valid: {is_valid}, Message: {message}")
```

### 2. Defensive Programming
```python
def safe_exploit_attempt(target, payload):
    # Always check authorization first
    if not check_authorization(target):
        return {"status": "ERROR", "message": "Unauthorized target"}
    
    # Validate payload safety
    if contains_dangerous_commands(payload):
        return {"status": "ERROR", "message": "Payload contains dangerous commands"}
    
    # Rate limiting
    if exceeded_rate_limit(target):
        return {"status": "ERROR", "message": "Rate limit exceeded"}
    
    # Proceed with safe testing
    try:
        result = execute_test(target, payload)
        return {"status": "SUCCESS", "result": result}
    except Exception as e:
        return {"status": "ERROR", "message": f"Test failed: {e}"}

def check_authorization(target):
    # Implementation would check authorization database
    return True  # Placeholder

def contains_dangerous_commands(payload):
    dangerous_patterns = ['rm -rf', 'format c:', 'DROP DATABASE']
    return any(pattern in payload for pattern in dangerous_patterns)

def exceeded_rate_limit(target):
    # Implementation would check request frequency
    return False  # Placeholder

def execute_test(target, payload):
    # Actual testing implementation
    return "Test completed safely"
```

## Summary

Conditional statements are essential for creating intelligent, secure, and robust ethical hacking tools. They enable:

**Key Applications:**
- Dynamic security assessments based on scan results
- Intelligent threat detection and classification
- Automated response to security events
- Input validation and error handling
- Risk assessment and prioritization

**Best Practices:**
- Always validate inputs before processing
- Use defensive programming techniques
- Implement proper error handling
- Consider security implications of each condition
- Document decision logic clearly

**Security Considerations:**
- Never trust user input without validation
- Implement rate limiting to prevent abuse
- Always check authorization before performing actions
- Log security-relevant decisions for audit trails
- Use fail-safe defaults (deny by default)