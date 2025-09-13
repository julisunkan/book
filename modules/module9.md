# Chapter 9: Variables, Objects, and Values in Python Security

## Overview

Understanding Python's variable system, object model, and value types is fundamental for developing effective security tools and ethical hacking scripts. This chapter explores these concepts with practical security applications and real-world examples.

## Python Variable Fundamentals

### Variable Assignment and Security Context
```python
# Basic variable assignment in security contexts
target_ip = "192.168.1.100"
scan_port = 80
is_vulnerable = True
vulnerability_count = 0

# Multiple assignment for security operations
attacker_ip, target_ip, target_port = "10.0.0.1", "192.168.1.100", 443

# Parallel assignment for network ranges
start_ip, end_ip = "192.168.1.1", "192.168.1.254"
min_port, max_port = 1, 65535

# Security configuration variables
ALLOWED_SCAN_RATE = 10  # requests per second
MAX_THREADS = 50
TIMEOUT_SECONDS = 5
DEFAULT_USER_AGENT = "Mozilla/5.0 (Security Scanner)"

# Dynamic variable assignment from user input (with validation)
def configure_scan_from_input():
    """Configure scan parameters from user input with validation"""
    
    # Get target from user
    target = input("Enter target IP: ").strip()
    
    # Validate IP format
    if not validate_ip_format(target):
        print("Invalid IP format")
        return None
    
    # Get port range
    port_input = input("Enter port range (e.g., 80-443): ").strip()
    
    try:
        if '-' in port_input:
            start_port, end_port = map(int, port_input.split('-'))
        else:
            start_port = end_port = int(port_input)
            
        # Validate port range
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
            print("Invalid port range")
            return None
            
    except ValueError:
        print("Invalid port format")
        return None
    
    # Return configuration dictionary
    return {
        'target': target,
        'start_port': start_port,
        'end_port': end_port,
        'timestamp': time.time()
    }

def validate_ip_format(ip):
    """Validate IP address format"""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False
```

### Variable Scope in Security Functions
```python
# Global variables for security configuration
GLOBAL_TIMEOUT = 5
AUTHORIZED_USERS = ["admin", "security_team", "pentester"]
SCAN_RESULTS = {}  # Global results storage

def port_scanner(target, ports):
    """Port scanner demonstrating variable scope"""
    
    # Local variables
    open_ports = []
    scan_start_time = time.time()
    
    # Access global configuration
    timeout = GLOBAL_TIMEOUT
    
    for port in ports:
        # Local variable in loop
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)  # Using global variable
        
        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
                
                # Modify global results
                if target not in SCAN_RESULTS:
                    SCAN_RESULTS[target] = []
                SCAN_RESULTS[target].append(port)
                
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()
    
    # Local calculation
    scan_duration = time.time() - scan_start_time
    
    return {
        'target': target,
        'open_ports': open_ports,
        'scan_time': scan_duration,
        'total_scanned': len(ports)
    }

def user_authorization_check(username):
    """Check user authorization using global variables"""
    global AUTHORIZED_USERS  # Explicit global access
    
    if username in AUTHORIZED_USERS:
        return True, f"User {username} is authorized"
    else:
        # Log unauthorized access attempt
        log_security_event("unauthorized_access", username)
        return False, f"User {username} is not authorized"

# Nonlocal variables for nested functions
def create_vulnerability_scanner():
    """Factory function creating vulnerability scanner with closure"""
    
    # Enclosing scope variables
    scan_count = 0
    discovered_vulnerabilities = []
    
    def scan_for_vulnerability(target, vulnerability_type):
        """Nested function accessing enclosing scope"""
        nonlocal scan_count, discovered_vulnerabilities
        
        scan_count += 1
        print(f"Scan #{scan_count}: Checking {target} for {vulnerability_type}")
        
        # Simulate vulnerability check
        if simulate_vulnerability_check(target, vulnerability_type):
            vulnerability_info = {
                'target': target,
                'type': vulnerability_type,
                'discovered_at': time.time(),
                'scan_number': scan_count
            }
            discovered_vulnerabilities.append(vulnerability_info)
            return True
        
        return False
    
    def get_scan_statistics():
        """Get scanner statistics"""
        return {
            'total_scans': scan_count,
            'vulnerabilities_found': len(discovered_vulnerabilities),
            'vulnerability_details': discovered_vulnerabilities
        }
    
    # Return functions as a tuple
    return scan_for_vulnerability, get_scan_statistics

# Usage example
scanner, get_stats = create_vulnerability_scanner()
scanner("192.168.1.100", "SQL Injection")
scanner("192.168.1.101", "XSS")
stats = get_stats()
print(f"Scanner statistics: {stats}")
```

## Python Object Model and Security

### Everything is an Object
```python
import inspect

# Demonstrating that everything in Python is an object
target_ip = "192.168.1.100"
port_number = 443

# Check object types and properties
print(f"target_ip type: {type(target_ip)}")
print(f"target_ip id: {id(target_ip)}")
print(f"port_number type: {type(port_number)}")
print(f"port_number id: {id(port_number)}")

# Functions are also objects
def vulnerability_check():
    return "Checking for vulnerabilities..."

print(f"Function type: {type(vulnerability_check)}")
print(f"Function attributes: {dir(vulnerability_check)}")

# Object attributes and methods for security data
class SecurityAlert:
    """Security alert object with metadata"""
    
    def __init__(self, alert_type, severity, source_ip, message):
        # Instance attributes
        self.alert_type = alert_type
        self.severity = severity
        self.source_ip = source_ip
        self.message = message
        self.timestamp = time.time()
        self.acknowledged = False
    
    def acknowledge(self, user):
        """Acknowledge the alert"""
        self.acknowledged = True
        self.acknowledged_by = user
        self.acknowledged_at = time.time()
    
    def get_alert_info(self):
        """Get comprehensive alert information"""
        return {
            'type': self.alert_type,
            'severity': self.severity,
            'source': self.source_ip,
            'message': self.message,
            'timestamp': self.timestamp,
            'acknowledged': self.acknowledged
        }

# Create security alert object
alert = SecurityAlert("intrusion_attempt", "high", "192.168.1.200", "Multiple failed login attempts")

# Inspect object attributes
print(f"Alert object type: {type(alert)}")
print(f"Alert attributes: {[attr for attr in dir(alert) if not attr.startswith('_')]}")
print(f"Alert info: {alert.get_alert_info()}")

# Object introspection for security analysis
def analyze_object_security(obj):
    """Analyze object for security-relevant information"""
    
    analysis = {
        'object_type': type(obj).__name__,
        'object_id': id(obj),
        'is_callable': callable(obj),
        'has_dict': hasattr(obj, '__dict__'),
        'memory_size': sys.getsizeof(obj)
    }
    
    # Check for potentially dangerous attributes
    dangerous_methods = ['exec', 'eval', 'compile', 'open', '__import__']
    available_methods = dir(obj)
    
    analysis['dangerous_methods'] = [method for method in dangerous_methods if method in available_methods]
    
    # Check if object has custom attributes
    if hasattr(obj, '__dict__'):
        analysis['custom_attributes'] = list(obj.__dict__.keys())
    
    return analysis
```

### Mutable vs Immutable Objects in Security
```python
# Immutable objects (strings, numbers, tuples)
original_ip = "192.168.1.100"
modified_ip = original_ip.replace("100", "101")

print(f"Original IP: {original_ip}")  # Unchanged
print(f"Modified IP: {modified_ip}")  # New string object
print(f"Same object: {id(original_ip) == id(modified_ip)}")  # False

# Security implications of immutable objects
def secure_log_entry(event_type, details):
    """Create secure log entry using immutable data"""
    
    # Tuple is immutable - cannot be modified after creation
    log_entry = (
        time.time(),        # timestamp
        event_type,         # event type
        details,           # event details
        "unprocessed"      # status
    )
    
    # This would raise an error - tuples are immutable
    # log_entry[3] = "processed"  # TypeError
    
    return log_entry

# Mutable objects (lists, dictionaries, sets)
vulnerability_list = ["SQL Injection", "XSS"]
vulnerability_list.append("CSRF")  # Modifies the same object

print(f"Vulnerability list: {vulnerability_list}")

# Security implications of mutable objects
def update_security_config(config_dict, new_settings):
    """Update security configuration (modifies original)"""
    
    # This modifies the original dictionary
    config_dict.update(new_settings)
    
    return config_dict

# Safe approach: create copy to avoid unintended modifications
def safe_update_security_config(config_dict, new_settings):
    """Safely update security configuration (creates copy)"""
    
    import copy
    
    # Create deep copy to avoid modifying original
    new_config = copy.deepcopy(config_dict)
    new_config.update(new_settings)
    
    return new_config

# Example usage
original_config = {
    "max_scan_rate": 10,
    "timeout": 5,
    "allowed_protocols": ["http", "https"]
}

# Unsafe update - modifies original
update_security_config(original_config, {"timeout": 10})
print(f"Original config modified: {original_config}")

# Safe update - preserves original
safe_config = safe_update_security_config(original_config, {"max_scan_rate": 20})
print(f"Original config preserved: {original_config}")
print(f"New config created: {safe_config}")
```

### Reference vs Value Semantics
```python
# Reference semantics with mutable objects
scan_results_1 = {"target": "192.168.1.100", "open_ports": [22, 80]}
scan_results_2 = scan_results_1  # Same object reference

# Modifying through one reference affects both
scan_results_2["open_ports"].append(443)

print(f"scan_results_1: {scan_results_1}")  # Shows [22, 80, 443]
print(f"scan_results_2: {scan_results_2}")  # Shows [22, 80, 443]
print(f"Same object: {scan_results_1 is scan_results_2}")  # True

# Creating independent copies for security isolation
import copy

def create_isolated_scan_result(template_result):
    """Create isolated copy of scan result"""
    
    # Shallow copy - copies container but not nested objects
    shallow_copy = copy.copy(template_result)
    
    # Deep copy - copies everything recursively
    deep_copy = copy.deepcopy(template_result)
    
    return shallow_copy, deep_copy

# Security application: isolating user sessions
class UserSession:
    """Secure user session management"""
    
    def __init__(self, username, permissions):
        self.username = username
        self.permissions = copy.deepcopy(permissions)  # Isolate permissions
        self.session_start = time.time()
        self.last_activity = time.time()
        self.actions_log = []
    
    def update_permissions(self, new_permissions):
        """Update permissions without affecting other sessions"""
        # Create new permission set, don't modify original
        self.permissions = copy.deepcopy(new_permissions)
    
    def log_action(self, action):
        """Log user action"""
        self.actions_log.append({
            'action': action,
            'timestamp': time.time()
        })
        self.last_activity = time.time()
    
    def get_session_copy(self):
        """Get safe copy of session data"""
        return {
            'username': self.username,
            'permissions': copy.deepcopy(self.permissions),
            'session_duration': time.time() - self.session_start,
            'actions_count': len(self.actions_log)
        }

# Example: managing multiple user sessions
base_permissions = ["read_logs", "scan_network"]

user1_session = UserSession("alice", base_permissions)
user2_session = UserSession("bob", base_permissions)

# Modify one user's permissions
user1_session.update_permissions(["read_logs", "scan_network", "modify_config"])

print(f"User1 permissions: {user1_session.permissions}")
print(f"User2 permissions: {user2_session.permissions}")  # Unchanged
```

## Data Types for Security Applications

### Numbers in Security Calculations
```python
# Integer operations for security metrics
total_hosts = 254
scanned_hosts = 200
completion_percentage = (scanned_hosts / total_hosts) * 100

print(f"Scan completion: {completion_percentage:.1f}%")

# Port calculations
port_range_start = 1
port_range_end = 65535
total_ports = port_range_end - port_range_start + 1

print(f"Total possible ports: {total_ports}")

# Binary operations for network calculations
def calculate_network_info(ip, subnet_mask):
    """Calculate network information using binary operations"""
    
    # Convert IP to integer
    def ip_to_int(ip_str):
        parts = ip_str.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    
    # Convert integer back to IP
    def int_to_ip(ip_int):
        return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"
    
    ip_int = ip_to_int(ip)
    mask_int = ip_to_int(subnet_mask)
    
    # Calculate network address using bitwise AND
    network_int = ip_int & mask_int
    
    # Calculate broadcast address
    broadcast_int = network_int | (~mask_int & 0xFFFFFFFF)
    
    # Calculate number of hosts
    host_bits = 32 - bin(mask_int).count('1')
    total_hosts = (2 ** host_bits) - 2  # Exclude network and broadcast
    
    return {
        'network_address': int_to_ip(network_int),
        'broadcast_address': int_to_ip(broadcast_int),
        'first_host': int_to_ip(network_int + 1),
        'last_host': int_to_ip(broadcast_int - 1),
        'total_hosts': total_hosts
    }

# Example network calculation
network_info = calculate_network_info("192.168.1.100", "255.255.255.0")
print(f"Network info: {network_info}")

# Floating-point for security metrics
vulnerability_scores = [9.8, 7.5, 4.2, 2.1, 8.9]
average_score = sum(vulnerability_scores) / len(vulnerability_scores)
max_score = max(vulnerability_scores)
critical_count = sum(1 for score in vulnerability_scores if score >= 9.0)

print(f"Average CVSS score: {average_score:.2f}")
print(f"Maximum score: {max_score}")
print(f"Critical vulnerabilities: {critical_count}")
```

### Strings for Security Data Processing
```python
# String operations for log analysis
log_entry = "2024-01-15 10:30:45 [ERROR] Failed login attempt from 192.168.1.200 for user admin"

# String parsing for security analysis
def parse_security_log(log_line):
    """Parse security log entry"""
    
    # Extract timestamp
    timestamp = log_line[:19]  # First 19 characters
    
    # Extract log level
    level_start = log_line.find('[') + 1
    level_end = log_line.find(']')
    log_level = log_line[level_start:level_end] if level_start > 0 and level_end > 0 else "UNKNOWN"
    
    # Extract IP address using string operations
    words = log_line.split()
    ip_address = None
    for word in words:
        if word.count('.') == 3:  # Simple IP detection
            try:
                parts = word.split('.')
                if all(0 <= int(part) <= 255 for part in parts):
                    ip_address = word
                    break
            except ValueError:
                continue
    
    # Extract username
    username = None
    if "user " in log_line:
        user_index = log_line.find("user ") + 5
        username = log_line[user_index:].split()[0]
    
    return {
        'timestamp': timestamp,
        'level': log_level,
        'ip_address': ip_address,
        'username': username,
        'full_message': log_line
    }

parsed_log = parse_security_log(log_entry)
print(f"Parsed log: {parsed_log}")

# String formatting for security reports
def generate_security_report(scan_results):
    """Generate formatted security report"""
    
    report_lines = []
    report_lines.append("="*60)
    report_lines.append("SECURITY SCAN REPORT")
    report_lines.append("="*60)
    
    for target, results in scan_results.items():
        report_lines.append(f"\nTarget: {target}")
        report_lines.append("-" * 40)
        
        if results['open_ports']:
            report_lines.append(f"Open Ports ({len(results['open_ports'])}):")
            for port in results['open_ports']:
                service = get_service_name(port)
                report_lines.append(f"  Port {port:>5} - {service}")
        else:
            report_lines.append("No open ports found")
        
        if results.get('vulnerabilities'):
            report_lines.append(f"\nVulnerabilities ({len(results['vulnerabilities'])}):")
            for vuln in results['vulnerabilities']:
                severity_color = get_severity_indicator(vuln['severity'])
                report_lines.append(f"  {severity_color} {vuln['name']} (CVSS: {vuln['score']})")
    
    return '\n'.join(report_lines)

def get_service_name(port):
    """Get service name for port"""
    services = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 3389: "RDP"}
    return services.get(port, "Unknown")

def get_severity_indicator(severity):
    """Get visual indicator for severity"""
    indicators = {
        "critical": "[CRIT]",
        "high": "[HIGH]", 
        "medium": "[MED ]",
        "low": "[LOW ]"
    }
    return indicators.get(severity.lower(), "[INFO]")

# String validation for security inputs
def validate_security_input(user_input, input_type):
    """Validate user input for security applications"""
    
    # Remove leading/trailing whitespace
    cleaned_input = user_input.strip()
    
    if input_type == "ip_address":
        # IP address validation
        if not cleaned_input.count('.') == 3:
            return False, "Invalid IP format"
        
        try:
            parts = cleaned_input.split('.')
            if not all(0 <= int(part) <= 255 for part in parts):
                return False, "Invalid IP range"
        except ValueError:
            return False, "Non-numeric IP components"
    
    elif input_type == "port":
        # Port validation
        try:
            port = int(cleaned_input)
            if not 1 <= port <= 65535:
                return False, "Port out of valid range (1-65535)"
        except ValueError:
            return False, "Port must be numeric"
    
    elif input_type == "username":
        # Username validation
        if len(cleaned_input) < 3:
            return False, "Username too short"
        
        if not cleaned_input.replace('_', '').replace('-', '').isalnum():
            return False, "Username contains invalid characters"
    
    # Check for potential injection attacks
    dangerous_patterns = ['<script', 'javascript:', 'onerror=', 'onload=', 
                         'union select', 'drop table', '../', '..\\']
    
    lower_input = cleaned_input.lower()
    for pattern in dangerous_patterns:
        if pattern in lower_input:
            return False, f"Potentially malicious pattern detected: {pattern}"
    
    return True, "Input validation passed"
```

### Collections for Security Data Management
```python
# Lists for ordered security data
discovered_vulnerabilities = [
    {"name": "SQL Injection", "severity": "high", "cvss": 8.5},
    {"name": "XSS", "severity": "medium", "cvss": 6.1},
    {"name": "CSRF", "severity": "medium", "cvss": 5.4}
]

# Sort vulnerabilities by severity score
sorted_vulnerabilities = sorted(discovered_vulnerabilities, 
                              key=lambda x: x['cvss'], 
                              reverse=True)

print("Vulnerabilities by severity:")
for vuln in sorted_vulnerabilities:
    print(f"  {vuln['name']}: CVSS {vuln['cvss']}")

# Dictionaries for security mappings
security_headers = {
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block", 
    "X-Content-Type-Options": "nosniff",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'"
}

# Check for missing security headers
def audit_security_headers(response_headers):
    """Audit HTTP response headers for security"""
    
    missing_headers = []
    present_headers = []
    
    for header, recommended_value in security_headers.items():
        if header in response_headers:
            present_headers.append({
                "header": header,
                "value": response_headers[header],
                "recommended": recommended_value,
                "status": "present"
            })
        else:
            missing_headers.append({
                "header": header,
                "recommended": recommended_value,
                "status": "missing"
            })
    
    return {
        "present": present_headers,
        "missing": missing_headers,
        "security_score": len(present_headers) / len(security_headers) * 100
    }

# Sets for unique security data
compromised_ips = {"192.168.1.100", "10.0.0.50", "172.16.0.25"}
authorized_ips = {"192.168.1.1", "192.168.1.10", "192.168.1.100"}

# Find intersection (IPs that are both compromised and authorized)
critical_compromises = compromised_ips.intersection(authorized_ips)
print(f"Critical compromises (authorized IPs): {critical_compromises}")

# Find IPs that are compromised but not authorized
external_compromises = compromised_ips.difference(authorized_ips)
print(f"External compromises: {external_compromises}")

# Complex data structures for security analysis
security_events = {
    "2024-01-15": {
        "failed_logins": [
            {"ip": "192.168.1.200", "username": "admin", "time": "10:30"},
            {"ip": "10.0.0.50", "username": "root", "time": "11:45"}
        ],
        "successful_logins": [
            {"ip": "192.168.1.10", "username": "alice", "time": "09:15"}
        ],
        "port_scans": [
            {"source": "203.45.67.89", "target_ports": [22, 80, 443], "time": "14:20"}
        ]
    }
}

def analyze_daily_security_events(events_dict, date):
    """Analyze security events for a specific date"""
    
    if date not in events_dict:
        return {"error": f"No data for {date}"}
    
    day_events = events_dict[date]
    
    analysis = {
        "date": date,
        "failed_logins": len(day_events.get("failed_logins", [])),
        "successful_logins": len(day_events.get("successful_logins", [])),
        "port_scans": len(day_events.get("port_scans", [])),
        "unique_attacker_ips": set()
    }
    
    # Extract unique attacker IPs
    for failed_login in day_events.get("failed_logins", []):
        analysis["unique_attacker_ips"].add(failed_login["ip"])
    
    for port_scan in day_events.get("port_scans", []):
        analysis["unique_attacker_ips"].add(port_scan["source"])
    
    analysis["unique_attacker_count"] = len(analysis["unique_attacker_ips"])
    analysis["unique_attacker_ips"] = list(analysis["unique_attacker_ips"])  # Convert set to list for JSON
    
    # Calculate risk score
    risk_score = (analysis["failed_logins"] * 2 + 
                  analysis["port_scans"] * 3 + 
                  analysis["unique_attacker_count"] * 5)
    
    analysis["risk_score"] = risk_score
    
    if risk_score > 20:
        analysis["risk_level"] = "high"
    elif risk_score > 10:
        analysis["risk_level"] = "medium"
    else:
        analysis["risk_level"] = "low"
    
    return analysis

# Analyze security events
daily_analysis = analyze_daily_security_events(security_events, "2024-01-15")
print(f"Daily security analysis: {daily_analysis}")
```

## Memory Management and Security

### Object Lifecycle and Cleanup
```python
import gc
import weakref

class SecuritySession:
    """Security session with proper cleanup"""
    
    def __init__(self, user_id, session_token):
        self.user_id = user_id
        self.session_token = session_token
        self.created_at = time.time()
        self.active = True
        
        # Register for cleanup tracking
        self._cleanup_callbacks = []
    
    def add_cleanup_callback(self, callback):
        """Add callback for session cleanup"""
        self._cleanup_callbacks.append(callback)
    
    def invalidate(self):
        """Invalidate session and clean up resources"""
        self.active = False
        self.session_token = None  # Clear sensitive data
        
        # Execute cleanup callbacks
        for callback in self._cleanup_callbacks:
            try:
                callback(self.user_id)
            except Exception as e:
                print(f"Cleanup callback failed: {e}")
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        if self.active:
            print(f"Warning: Session {self.user_id} not properly invalidated")
            self.invalidate()

# Weak references for security monitoring
class SecurityMonitor:
    """Monitor security objects without preventing garbage collection"""
    
    def __init__(self):
        self._tracked_objects = []
    
    def track_object(self, obj, description):
        """Track object using weak reference"""
        def cleanup_callback(ref):
            print(f"Tracked object cleaned up: {description}")
            self._tracked_objects.remove(ref)
        
        weak_ref = weakref.ref(obj, cleanup_callback)
        self._tracked_objects.append(weak_ref)
        
        return weak_ref
    
    def get_tracked_count(self):
        """Get number of still-alive tracked objects"""
        alive_count = sum(1 for ref in self._tracked_objects if ref() is not None)
        return alive_count
    
    def force_cleanup(self):
        """Force garbage collection and report"""
        before_count = self.get_tracked_count()
        gc.collect()
        after_count = self.get_tracked_count()
        
        print(f"Garbage collection: {before_count} -> {after_count} objects")

# Memory-efficient security data processing
def process_large_log_file(filename):
    """Process large log file with memory efficiency"""
    
    threat_count = 0
    processed_lines = 0
    
    # Use generator to avoid loading entire file into memory
    def log_line_generator():
        with open(filename, 'r') as file:
            for line in file:
                yield line.strip()
    
    # Process one line at a time
    for line in log_line_generator():
        processed_lines += 1
        
        if is_threat_indicator(line):
            threat_count += 1
        
        # Periodically report progress and force cleanup
        if processed_lines % 10000 == 0:
            gc.collect()  # Force garbage collection
            print(f"Processed {processed_lines} lines, found {threat_count} threats")
    
    return {
        "total_lines": processed_lines,
        "threats_found": threat_count,
        "memory_usage": get_memory_usage()
    }

def is_threat_indicator(log_line):
    """Check if log line indicates a security threat"""
    threat_keywords = ["failed", "error", "attack", "intrusion", "malware"]
    return any(keyword in log_line.lower() for keyword in threat_keywords)

def get_memory_usage():
    """Get current memory usage information"""
    import psutil
    import os
    
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()
    
    return {
        "rss_mb": memory_info.rss / 1024 / 1024,  # Resident Set Size
        "vms_mb": memory_info.vms / 1024 / 1024   # Virtual Memory Size
    }
```

## Summary

**Key Variable and Object Concepts:**
- **Variable Scope**: Understanding global, local, and nonlocal variables in security contexts
- **Object Mutability**: Proper handling of mutable vs immutable objects for security data
- **Reference Semantics**: Managing object references to prevent unintended data modifications
- **Memory Management**: Efficient memory usage for large-scale security data processing

**Security Applications:**
- **Session Management**: Secure handling of user sessions and authentication data
- **Data Isolation**: Preventing cross-contamination between security assessments
- **Configuration Management**: Safe handling of security configurations and settings
- **Log Processing**: Memory-efficient processing of large security log files

**Best Practices:**
- Use appropriate data types for specific security tasks
- Implement proper object lifecycle management
- Validate and sanitize all input data
- Use weak references for monitoring without memory leaks
- Create defensive copies when sharing security data
- Implement proper cleanup for sensitive information

**Performance Considerations:**
- Use generators for large data processing
- Implement proper garbage collection strategies
- Monitor memory usage for long-running security tools
- Use appropriate data structures for specific operations
- Consider object pooling for frequently created objects

Understanding Python's variable and object model is essential for developing robust, secure, and efficient ethical hacking tools that can handle sensitive data safely while maintaining optimal performance.