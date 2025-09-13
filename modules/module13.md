# Chapter 13: Python Functions and Security Automation

## Overview

Functions are the building blocks of modular, reusable code in Python security applications. This chapter explores advanced function concepts, security-focused function design, and automation techniques essential for ethical hacking and cybersecurity operations.

## Function Fundamentals in Security Context

### Basic Function Structure for Security Tools
```python
def port_scanner(target, start_port, end_port, timeout=3):
    """
    Comprehensive port scanner with security best practices
    
    Args:
        target (str): Target IP address or hostname
        start_port (int): Starting port number
        end_port (int): Ending port number
        timeout (int): Connection timeout in seconds
        
    Returns:
        dict: Scan results with open ports and metadata
        
    Raises:
        ValueError: Invalid target or port range
        ConnectionError: Network connectivity issues
    """
    
    import socket
    import time
    from concurrent.futures import ThreadPoolExecutor
    
    # Input validation
    if not isinstance(target, str) or not target.strip():
        raise ValueError("Target must be a non-empty string")
    
    if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
        raise ValueError("Port range must be between 1 and 65535")
    
    if start_port > end_port:
        raise ValueError("Start port must be less than or equal to end port")
    
    # Initialize results structure
    scan_results = {
        'target': target,
        'scan_start': time.time(),
        'ports_scanned': 0,
        'open_ports': [],
        'closed_ports': [],
        'filtered_ports': [],
        'errors': []
    }
    
    def scan_single_port(port):
        """Scan individual port with error handling"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                return port, 'open'
            else:
                return port, 'closed'
                
        except socket.timeout:
            return port, 'filtered'
        except Exception as e:
            return port, f'error: {str(e)}'
    
    # Scan ports with threading for efficiency
    ports_to_scan = range(start_port, end_port + 1)
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(scan_single_port, ports_to_scan)
    
    # Process results
    for port, status in results:
        scan_results['ports_scanned'] += 1
        
        if status == 'open':
            scan_results['open_ports'].append(port)
        elif status == 'closed':
            scan_results['closed_ports'].append(port)
        elif status == 'filtered':
            scan_results['filtered_ports'].append(port)
        else:  # Error case
            scan_results['errors'].append({'port': port, 'error': status})
    
    # Calculate scan duration
    scan_results['scan_duration'] = time.time() - scan_results['scan_start']
    scan_results['scan_rate'] = scan_results['ports_scanned'] / scan_results['scan_duration']
    
    return scan_results

# Example usage
# results = port_scanner("scanme.nmap.org", 20, 100)
# print(f"Found {len(results['open_ports'])} open ports: {results['open_ports']}")
```

### Advanced Function Features

#### Default Arguments and Security Configuration
```python
def vulnerability_scanner(target, scan_types=None, severity_threshold='medium', 
                         output_format='json', timeout=30, max_threads=10):
    """
    Advanced vulnerability scanner with flexible configuration
    """
    
    # Handle mutable default arguments safely
    if scan_types is None:
        scan_types = ['sql_injection', 'xss', 'csrf', 'directory_traversal']
    
    # Severity mapping
    severity_levels = {
        'low': 1, 'medium': 2, 'high': 3, 'critical': 4
    }
    
    min_severity = severity_levels.get(severity_threshold, 2)
    
    # Configuration validation
    valid_formats = ['json', 'xml', 'csv', 'html']
    if output_format not in valid_formats:
        raise ValueError(f"Output format must be one of: {valid_formats}")
    
    scan_results = {
        'target': target,
        'scan_configuration': {
            'scan_types': scan_types,
            'severity_threshold': severity_threshold,
            'timeout': timeout,
            'max_threads': max_threads
        },
        'vulnerabilities': []
    }
    
    # Simulate vulnerability scanning
    for scan_type in scan_types:
        vulnerabilities = perform_vulnerability_check(target, scan_type, timeout)
        
        # Filter by severity threshold
        filtered_vulns = [
            vuln for vuln in vulnerabilities 
            if severity_levels.get(vuln.get('severity', 'low'), 1) >= min_severity
        ]
        
        scan_results['vulnerabilities'].extend(filtered_vulns)
    
    # Format output according to specification
    if output_format == 'json':
        return format_json_output(scan_results)
    elif output_format == 'xml':
        return format_xml_output(scan_results)
    elif output_format == 'csv':
        return format_csv_output(scan_results)
    else:
        return format_html_output(scan_results)

def perform_vulnerability_check(target, scan_type, timeout):
    """Perform specific vulnerability check"""
    # This would contain actual vulnerability detection logic
    # Returning mock data for demonstration
    
    mock_vulnerabilities = {
        'sql_injection': [
            {'name': 'SQL Injection in login', 'severity': 'high', 'confidence': 'high'},
            {'name': 'Blind SQL Injection', 'severity': 'medium', 'confidence': 'medium'}
        ],
        'xss': [
            {'name': 'Reflected XSS', 'severity': 'medium', 'confidence': 'high'},
            {'name': 'Stored XSS', 'severity': 'high', 'confidence': 'high'}
        ],
        'csrf': [
            {'name': 'CSRF in user settings', 'severity': 'medium', 'confidence': 'medium'}
        ],
        'directory_traversal': [
            {'name': 'Directory traversal vulnerability', 'severity': 'high', 'confidence': 'low'}
        ]
    }
    
    return mock_vulnerabilities.get(scan_type, [])
```

#### Variable-Length Arguments for Flexible Security Functions
```python
def log_security_event(event_type, severity, *details, **metadata):
    """
    Flexible security event logging function
    
    Args:
        event_type (str): Type of security event
        severity (str): Event severity level
        *details: Variable number of detail strings
        **metadata: Additional event metadata
    """
    
    import json
    from datetime import datetime
    
    # Create base event structure
    event = {
        'timestamp': datetime.now().isoformat(),
        'event_type': event_type,
        'severity': severity,
        'details': list(details),
        'metadata': metadata
    }
    
    # Add system information if not provided
    if 'hostname' not in metadata:
        import socket
        event['metadata']['hostname'] = socket.gethostname()
    
    if 'process_id' not in metadata:
        import os
        event['metadata']['process_id'] = os.getpid()
    
    # Log to different outputs based on severity
    if severity in ['critical', 'high']:
        log_to_security_system(event)
        send_alert_notification(event)
    
    log_to_file(event)
    
    return event

def aggregate_scan_results(*scan_results, merge_duplicates=True, sort_by='severity'):
    """
    Aggregate multiple scan results with flexible options
    
    Args:
        *scan_results: Variable number of scan result dictionaries
        merge_duplicates (bool): Whether to merge duplicate findings
        sort_by (str): Field to sort results by
    """
    
    aggregated = {
        'scan_count': len(scan_results),
        'total_vulnerabilities': 0,
        'vulnerabilities': [],
        'targets_scanned': set(),
        'scan_summary': {}
    }
    
    # Process each scan result
    for scan_result in scan_results:
        if not isinstance(scan_result, dict):
            continue
        
        target = scan_result.get('target', 'unknown')
        aggregated['targets_scanned'].add(target)
        
        vulnerabilities = scan_result.get('vulnerabilities', [])
        aggregated['total_vulnerabilities'] += len(vulnerabilities)
        
        # Add vulnerabilities with source information
        for vuln in vulnerabilities:
            vuln_copy = vuln.copy()
            vuln_copy['source_scan'] = target
            aggregated['vulnerabilities'].append(vuln_copy)
    
    # Remove duplicates if requested
    if merge_duplicates:
        aggregated['vulnerabilities'] = remove_duplicate_vulnerabilities(
            aggregated['vulnerabilities']
        )
    
    # Sort results
    if sort_by == 'severity':
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        aggregated['vulnerabilities'].sort(
            key=lambda x: severity_order.get(x.get('severity', 'low'), 1),
            reverse=True
        )
    elif sort_by == 'target':
        aggregated['vulnerabilities'].sort(key=lambda x: x.get('source_scan', ''))
    
    # Generate summary statistics
    aggregated['scan_summary'] = generate_scan_summary(aggregated['vulnerabilities'])
    aggregated['targets_scanned'] = list(aggregated['targets_scanned'])
    
    return aggregated

def remove_duplicate_vulnerabilities(vulnerabilities):
    """Remove duplicate vulnerability entries"""
    
    seen_vulns = set()
    unique_vulns = []
    
    for vuln in vulnerabilities:
        # Create unique identifier for vulnerability
        identifier = (
            vuln.get('name', ''),
            vuln.get('target', ''),
            vuln.get('parameter', '')
        )
        
        if identifier not in seen_vulns:
            seen_vulns.add(identifier)
            unique_vulns.append(vuln)
        else:
            # Merge confidence levels if duplicate found
            existing_vuln = next(v for v in unique_vulns 
                               if (v.get('name', ''), v.get('target', ''), v.get('parameter', '')) == identifier)
            
            # Keep higher confidence level
            confidence_levels = {'low': 1, 'medium': 2, 'high': 3}
            current_conf = confidence_levels.get(existing_vuln.get('confidence', 'low'), 1)
            new_conf = confidence_levels.get(vuln.get('confidence', 'low'), 1)
            
            if new_conf > current_conf:
                existing_vuln['confidence'] = vuln.get('confidence', 'low')
    
    return unique_vulns

# Example usage
event1 = log_security_event(
    "failed_login", 
    "medium", 
    "Multiple failed attempts", 
    "Brute force suspected",
    source_ip="192.168.1.200",
    username="admin",
    attempt_count=5
)

# Multiple scan aggregation
scan1 = {'target': '192.168.1.100', 'vulnerabilities': [{'name': 'XSS', 'severity': 'high'}]}
scan2 = {'target': '192.168.1.101', 'vulnerabilities': [{'name': 'SQLi', 'severity': 'critical'}]}
aggregated = aggregate_scan_results(scan1, scan2, sort_by='severity')
```

## Lambda Functions and Functional Programming

### Lambda Functions for Security Data Processing
```python
# Lambda functions for quick security operations
is_critical_port = lambda port: port in [22, 23, 25, 53, 80, 110, 143, 443, 993, 995]

is_high_severity = lambda vuln: vuln.get('severity', '').lower() in ['high', 'critical']

extract_ip = lambda log_line: log_line.split()[0] if log_line.split() else None

calculate_cvss_level = lambda score: (
    'Critical' if score >= 9.0 else
    'High' if score >= 7.0 else
    'Medium' if score >= 4.0 else
    'Low'
)

# Using lambdas with built-in functions for security analysis
scan_results = [
    {'port': 22, 'service': 'ssh', 'status': 'open'},
    {'port': 80, 'service': 'http', 'status': 'open'},
    {'port': 443, 'service': 'https', 'status': 'open'},
    {'port': 8080, 'service': 'http-alt', 'status': 'open'},
    {'port': 9999, 'service': 'unknown', 'status': 'open'}
]

# Filter critical ports
critical_ports = list(filter(lambda x: is_critical_port(x['port']), scan_results))
print(f"Critical ports found: {[p['port'] for p in critical_ports]}")

# Transform port data
port_summary = list(map(lambda x: f"{x['port']}/{x['service']}", scan_results))
print(f"Port summary: {port_summary}")

# Vulnerability severity analysis
vulnerabilities = [
    {'name': 'SQL Injection', 'cvss_score': 8.5},
    {'name': 'XSS', 'cvss_score': 6.1},
    {'name': 'Buffer Overflow', 'cvss_score': 9.8},
    {'name': 'Info Disclosure', 'cvss_score': 3.2}
]

# Categorize vulnerabilities by CVSS score
vuln_levels = list(map(lambda v: {
    'name': v['name'],
    'score': v['cvss_score'],
    'level': calculate_cvss_level(v['cvss_score'])
}, vulnerabilities))

print("Vulnerability severity levels:")
for vuln in vuln_levels:
    print(f"  {vuln['name']}: {vuln['level']} ({vuln['score']})")
```

### Higher-Order Functions for Security Automation
```python
def create_scanner_factory(base_config):
    """
    Factory function that creates customized scanner functions
    
    Args:
        base_config (dict): Base configuration for scanners
        
    Returns:
        function: Customized scanner function
    """
    
    def scanner_factory(scan_type, additional_config=None):
        """Create specific scanner with base configuration"""
        
        config = base_config.copy()
        if additional_config:
            config.update(additional_config)
        
        def actual_scanner(target, **kwargs):
            """The actual scanner function with embedded configuration"""
            
            final_config = config.copy()
            final_config.update(kwargs)
            
            print(f"Scanning {target} for {scan_type} with config: {final_config}")
            
            # Simulate scanning based on type
            if scan_type == 'port_scan':
                return perform_port_scan(target, final_config)
            elif scan_type == 'vuln_scan':
                return perform_vulnerability_scan(target, final_config)
            elif scan_type == 'web_scan':
                return perform_web_scan(target, final_config)
            else:
                return {'error': f'Unknown scan type: {scan_type}'}
        
        return actual_scanner
    
    return scanner_factory

def rate_limiter(max_calls, time_window):
    """
    Decorator factory for rate limiting security operations
    
    Args:
        max_calls (int): Maximum number of calls allowed
        time_window (int): Time window in seconds
    """
    
    import time
    from functools import wraps
    
    def decorator(func):
        call_times = []
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            current_time = time.time()
            
            # Remove old calls outside time window
            call_times[:] = [t for t in call_times if current_time - t < time_window]
            
            # Check if we've exceeded rate limit
            if len(call_times) >= max_calls:
                oldest_call = min(call_times)
                wait_time = time_window - (current_time - oldest_call)
                print(f"Rate limit exceeded. Waiting {wait_time:.2f} seconds...")
                time.sleep(wait_time)
                
                # Update current time after waiting
                current_time = time.time()
                call_times[:] = [t for t in call_times if current_time - t < time_window]
            
            # Record this call
            call_times.append(current_time)
            
            # Execute the actual function
            return func(*args, **kwargs)
        
        return wrapper
    return decorator

# Usage examples
base_security_config = {
    'timeout': 10,
    'threads': 5,
    'user_agent': 'Security Scanner v2.0',
    'retry_count': 3
}

# Create scanner factory
create_scanner = create_scanner_factory(base_security_config)

# Create specific scanners
port_scanner = create_scanner('port_scan', {'timeout': 5})
web_scanner = create_scanner('web_scan', {'follow_redirects': True})

# Apply rate limiting decorator
@rate_limiter(max_calls=10, time_window=60)
def scan_target(target, scan_type='port_scan'):
    """Rate-limited target scanning"""
    print(f"Scanning {target} - Type: {scan_type}")
    # Simulate scan operation
    import time
    time.sleep(0.1)  # Simulate work
    return {'target': target, 'status': 'completed'}

# Test rate limiting
print("Testing rate limiting:")
for i in range(15):
    result = scan_target(f"192.168.1.{i+100}")
```

## Recursion in Security Applications

### Recursive Functions for Security Analysis
```python
def analyze_network_structure(ip_range, max_depth=3, current_depth=0, visited=None):
    """
    Recursively analyze network structure and connectivity
    
    Args:
        ip_range (str): Network range to analyze (e.g., "192.168.1.0/24")
        max_depth (int): Maximum recursion depth
        current_depth (int): Current recursion depth
        visited (set): Set of already visited networks
        
    Returns:
        dict: Hierarchical network structure analysis
    """
    
    if visited is None:
        visited = set()
    
    # Base case: maximum depth reached or network already visited
    if current_depth >= max_depth or ip_range in visited:
        return None
    
    visited.add(ip_range)
    
    print(f"{'  ' * current_depth}Analyzing network: {ip_range}")
    
    # Analyze current network
    network_info = {
        'network': ip_range,
        'depth': current_depth,
        'active_hosts': [],
        'connected_networks': [],
        'services_discovered': {}
    }
    
    # Discover active hosts (simplified)
    active_hosts = discover_active_hosts(ip_range)
    network_info['active_hosts'] = active_hosts
    
    # For each active host, discover services
    for host in active_hosts[:5]:  # Limit to first 5 hosts for demo
        services = discover_services(host)
        network_info['services_discovered'][host] = services
        
        # Recursively analyze connected networks found through routing
        connected_networks = discover_connected_networks(host)
        
        for connected_net in connected_networks:
            if connected_net not in visited:
                sub_analysis = analyze_network_structure(
                    connected_net, 
                    max_depth, 
                    current_depth + 1, 
                    visited
                )
                
                if sub_analysis:
                    network_info['connected_networks'].append(sub_analysis)
    
    return network_info

def directory_traversal_scanner(base_url, max_depth=5, current_depth=0, 
                              discovered_dirs=None, wordlist=None):
    """
    Recursively scan web directories for security assessment
    
    Args:
        base_url (str): Base URL to scan
        max_depth (int): Maximum directory depth to scan
        current_depth (int): Current scanning depth
        discovered_dirs (set): Already discovered directories
        wordlist (list): Directory wordlist for scanning
    """
    
    if discovered_dirs is None:
        discovered_dirs = set()
    
    if wordlist is None:
        wordlist = ['admin', 'config', 'backup', 'test', 'dev', 'api', 'uploads']
    
    # Base case: maximum depth reached
    if current_depth >= max_depth:
        return []
    
    discovered_paths = []
    
    for directory in wordlist:
        test_url = f"{base_url.rstrip('/')}/{directory}"
        
        if test_url in discovered_dirs:
            continue
        
        print(f"{'  ' * current_depth}Testing: {test_url}")
        
        # Test if directory exists (simplified check)
        if test_directory_exists(test_url):
            discovered_dirs.add(test_url)
            discovered_paths.append({
                'url': test_url,
                'depth': current_depth,
                'method': 'directory_enum'
            })
            
            # Recursively scan subdirectories
            sub_discoveries = directory_traversal_scanner(
                test_url,
                max_depth,
                current_depth + 1,
                discovered_dirs,
                wordlist
            )
            
            discovered_paths.extend(sub_discoveries)
    
    return discovered_paths

def parse_nested_log_structure(log_data, level=0):
    """
    Recursively parse nested log structures for security analysis
    
    Args:
        log_data: Log data (can be dict, list, or string)
        level (int): Current nesting level
        
    Returns:
        dict: Parsed security events and anomalies
    """
    
    security_events = {
        'level': level,
        'anomalies': [],
        'security_indicators': [],
        'nested_structures': []
    }
    
    if isinstance(log_data, dict):
        for key, value in log_data.items():
            # Check for security-relevant keys
            if any(indicator in key.lower() for indicator in ['error', 'fail', 'attack', 'intrusion']):
                security_events['security_indicators'].append({
                    'key': key,
                    'value': str(value)[:100],  # Truncate long values
                    'level': level
                })
            
            # Recursively parse nested structures
            if isinstance(value, (dict, list)):
                nested_analysis = parse_nested_log_structure(value, level + 1)
                security_events['nested_structures'].append({
                    'parent_key': key,
                    'analysis': nested_analysis
                })
    
    elif isinstance(log_data, list):
        for i, item in enumerate(log_data):
            if isinstance(item, (dict, list)):
                nested_analysis = parse_nested_log_structure(item, level + 1)
                security_events['nested_structures'].append({
                    'parent_index': i,
                    'analysis': nested_analysis
                })
            elif isinstance(item, str):
                # Check string items for security indicators
                if any(indicator in item.lower() for indicator in ['failed', 'denied', 'unauthorized']):
                    security_events['anomalies'].append({
                        'content': item,
                        'index': i,
                        'level': level
                    })
    
    return security_events

# Helper functions (simplified implementations)
def discover_active_hosts(ip_range):
    """Discover active hosts in IP range"""
    # Simplified - would use actual network scanning
    return ['192.168.1.10', '192.168.1.20', '192.168.1.30']

def discover_services(host):
    """Discover services running on host"""
    # Simplified - would use actual port scanning
    return [22, 80, 443]

def discover_connected_networks(host):
    """Discover networks connected to host"""
    # Simplified - would analyze routing tables
    return ['10.0.0.0/24', '172.16.0.0/16']

def test_directory_exists(url):
    """Test if web directory exists"""
    # Simplified - would make actual HTTP request
    import random
    return random.choice([True, False])  # Random for demo

# Example usage
print("Recursive network analysis:")
# network_analysis = analyze_network_structure("192.168.1.0/24", max_depth=2)

print("\nRecursive directory scanning:")
# discovered_dirs = directory_traversal_scanner("https://example.com", max_depth=3)

# Complex nested log data
complex_log = {
    "system_events": [
        {"timestamp": "2024-01-15T10:30:00", "event": "failed_login", "user": "admin"},
        {"timestamp": "2024-01-15T10:31:00", "event": "unauthorized_access", "source": "192.168.1.200"}
    ],
    "network_data": {
        "connections": [
            {"src": "192.168.1.100", "dst": "suspicious.domain.com", "status": "denied"}
        ]
    }
}

security_analysis = parse_nested_log_structure(complex_log)
print(f"Security analysis: {security_analysis}")
```

## Error Handling in Security Functions

### Comprehensive Error Handling Strategies
```python
import logging
from functools import wraps
from typing import Optional, Tuple, Any

# Configure security logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_operations.log'),
        logging.StreamHandler()
    ]
)

security_logger = logging.getLogger('security_operations')

def security_error_handler(max_retries=3, backoff_factor=1.5):
    """
    Decorator for handling errors in security operations
    
    Args:
        max_retries (int): Maximum number of retry attempts
        backoff_factor (float): Exponential backoff factor
    """
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                
                except ConnectionError as e:
                    last_exception = e
                    security_logger.warning(
                        f"Connection error in {func.__name__} (attempt {attempt + 1}): {e}"
                    )
                    
                    if attempt < max_retries:
                        wait_time = backoff_factor ** attempt
                        security_logger.info(f"Retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                    
                except ValueError as e:
                    security_logger.error(f"Invalid input to {func.__name__}: {e}")
                    raise  # Don't retry for invalid input
                
                except PermissionError as e:
                    security_logger.error(f"Permission denied in {func.__name__}: {e}")
                    raise  # Don't retry for permission errors
                
                except Exception as e:
                    last_exception = e
                    security_logger.error(f"Unexpected error in {func.__name__}: {e}")
                    
                    if attempt < max_retries:
                        security_logger.info(f"Attempting retry {attempt + 1}/{max_retries}")
                    
            # If all retries failed, raise the last exception
            security_logger.error(f"All retry attempts failed for {func.__name__}")
            raise last_exception
        
        return wrapper
    return decorator

@security_error_handler(max_retries=3, backoff_factor=2.0)
def secure_network_request(url: str, timeout: int = 10) -> dict:
    """
    Make secure network request with comprehensive error handling
    
    Args:
        url (str): Target URL for request
        timeout (int): Request timeout in seconds
        
    Returns:
        dict: Response data and metadata
        
    Raises:
        ConnectionError: Network connectivity issues
        ValueError: Invalid URL format
        PermissionError: Authorization issues
    """
    
    import requests
    from urllib.parse import urlparse
    
    # Input validation
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")
    
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        raise ValueError("Invalid URL format")
    
    # Security headers
    headers = {
        'User-Agent': 'Security Analysis Tool',
        'Accept': 'application/json, text/html',
        'Connection': 'close'
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        
        # Check for authentication issues
        if response.status_code == 401:
            raise PermissionError("Authentication required")
        elif response.status_code == 403:
            raise PermissionError("Access forbidden")
        
        # Check for connection issues
        if response.status_code >= 500:
            raise ConnectionError(f"Server error: {response.status_code}")
        
        return {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content': response.text,
            'url': response.url,
            'request_successful': True
        }
        
    except requests.exceptions.Timeout:
        raise ConnectionError(f"Request timeout after {timeout} seconds")
    
    except requests.exceptions.ConnectionError as e:
        raise ConnectionError(f"Failed to connect to {url}: {e}")

def safe_vulnerability_scan(target: str, scan_config: dict) -> Tuple[bool, Optional[dict], Optional[str]]:
    """
    Safely perform vulnerability scan with comprehensive error handling
    
    Args:
        target (str): Target to scan
        scan_config (dict): Scan configuration
        
    Returns:
        Tuple[bool, Optional[dict], Optional[str]]: 
            (success, results, error_message)
    """
    
    try:
        # Validate inputs
        if not target or not isinstance(target, str):
            return False, None, "Invalid target specified"
        
        if not scan_config or not isinstance(scan_config, dict):
            return False, None, "Invalid scan configuration"
        
        # Required configuration keys
        required_keys = ['scan_type', 'timeout']
        missing_keys = [key for key in required_keys if key not in scan_config]
        
        if missing_keys:
            return False, None, f"Missing required config keys: {missing_keys}"
        
        # Perform actual scan
        scan_results = perform_actual_scan(target, scan_config)
        
        return True, scan_results, None
        
    except ValueError as e:
        error_msg = f"Validation error: {str(e)}"
        security_logger.error(error_msg)
        return False, None, error_msg
    
    except ConnectionError as e:
        error_msg = f"Network error: {str(e)}"
        security_logger.error(error_msg)
        return False, None, error_msg
    
    except Exception as e:
        error_msg = f"Unexpected error during scan: {str(e)}"
        security_logger.error(error_msg)
        return False, None, error_msg

def perform_actual_scan(target: str, config: dict) -> dict:
    """Mock scan implementation"""
    
    # Simulate various potential errors
    import random
    
    error_chance = random.random()
    
    if error_chance < 0.1:  # 10% chance of connection error
        raise ConnectionError("Target unreachable")
    elif error_chance < 0.15:  # 5% chance of timeout
        raise TimeoutError("Scan timeout")
    
    # Return mock results
    return {
        'target': target,
        'scan_type': config['scan_type'],
        'vulnerabilities_found': random.randint(0, 5),
        'scan_duration': random.uniform(1.0, 10.0)
    }

# Context manager for secure operations
class SecurityOperationContext:
    """Context manager for secure operations with resource cleanup"""
    
    def __init__(self, operation_name: str, log_activities: bool = True):
        self.operation_name = operation_name
        self.log_activities = log_activities
        self.start_time = None
        self.resources = []
    
    def __enter__(self):
        self.start_time = time.time()
        if self.log_activities:
            security_logger.info(f"Starting security operation: {self.operation_name}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Clean up resources
        for resource in self.resources:
            try:
                if hasattr(resource, 'close'):
                    resource.close()
                elif hasattr(resource, 'cleanup'):
                    resource.cleanup()
            except Exception as e:
                security_logger.warning(f"Error cleaning up resource: {e}")
        
        # Log completion or error
        duration = time.time() - self.start_time if self.start_time else 0
        
        if exc_type is None:
            if self.log_activities:
                security_logger.info(
                    f"Security operation completed: {self.operation_name} "
                    f"(Duration: {duration:.2f}s)"
                )
        else:
            security_logger.error(
                f"Security operation failed: {self.operation_name} "
                f"(Duration: {duration:.2f}s, Error: {exc_val})"
            )
        
        # Return False to propagate exceptions
        return False
    
    def add_resource(self, resource):
        """Add resource for cleanup"""
        self.resources.append(resource)

# Example usage with context manager
def comprehensive_security_scan(targets: list) -> dict:
    """Perform comprehensive security scan with proper resource management"""
    
    results = {
        'targets_scanned': 0,
        'successful_scans': 0,
        'failed_scans': 0,
        'total_vulnerabilities': 0,
        'scan_errors': []
    }
    
    with SecurityOperationContext("Comprehensive Security Scan") as ctx:
        for target in targets:
            try:
                with SecurityOperationContext(f"Scanning {target}", log_activities=False) as scan_ctx:
                    # Perform scan
                    success, scan_results, error_msg = safe_vulnerability_scan(
                        target, 
                        {'scan_type': 'full', 'timeout': 30}
                    )
                    
                    results['targets_scanned'] += 1
                    
                    if success:
                        results['successful_scans'] += 1
                        results['total_vulnerabilities'] += scan_results.get('vulnerabilities_found', 0)
                    else:
                        results['failed_scans'] += 1
                        results['scan_errors'].append({
                            'target': target,
                            'error': error_msg
                        })
            
            except Exception as e:
                results['scan_errors'].append({
                    'target': target,
                    'error': f"Unexpected error: {str(e)}"
                })
    
    return results

# Example usage
# test_targets = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
# scan_summary = comprehensive_security_scan(test_targets)
# print(f"Scan summary: {scan_summary}")
```

## Summary

**Advanced Function Concepts for Security:**
- **Modular Design**: Creating reusable security function components
- **Error Handling**: Comprehensive error management for network operations
- **Configuration Management**: Flexible function parameters for security tools
- **Resource Management**: Proper cleanup and resource allocation

**Security-Specific Applications:**
- **Scanner Factories**: Dynamic creation of specialized security scanners  
- **Rate Limiting**: Decorators for responsible security testing
- **Recursive Analysis**: Deep network and directory structure exploration
- **Automation Pipelines**: Chaining security operations with error recovery

**Best Practices:**
- Always validate input parameters for security functions
- Implement comprehensive error handling with appropriate retry logic
- Use context managers for resource management and cleanup
- Apply rate limiting to respect target system resources
- Log all security operations for audit and debugging purposes

**Performance and Security Considerations:**
- Use threading carefully in security tools to avoid overwhelming targets
- Implement exponential backoff for failed network operations  
- Clean up sensitive data and network connections properly
- Monitor resource usage in long-running security operations
- Provide clear error messages while avoiding information disclosure

Mastering these advanced function concepts enables the development of professional-grade security tools that are reliable, maintainable, and respectful of target systems while providing comprehensive security assessment capabilities.