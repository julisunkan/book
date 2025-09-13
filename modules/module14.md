# Chapter 14: Python Classes and Object-Oriented Security Programming

## Overview

Object-oriented programming (OOP) provides powerful abstraction and organization capabilities essential for building complex security tools and frameworks. This chapter explores Python classes, inheritance, and OOP principles applied to ethical hacking and cybersecurity applications.

## Class Fundamentals for Security Applications

### Basic Class Structure for Security Tools
```python
import time
import hashlib
import json
from datetime import datetime
from typing import List, Dict, Optional, Any

class SecurityEvent:
    """
    Base class for security events with comprehensive logging and analysis
    """
    
    # Class variables for event classification
    SEVERITY_LEVELS = {
        'low': 1, 'medium': 2, 'high': 3, 'critical': 4
    }
    
    EVENT_TYPES = {
        'authentication', 'authorization', 'network', 'system', 
        'application', 'data', 'malware', 'intrusion'
    }
    
    def __init__(self, event_type: str, severity: str, message: str, 
                 source_ip: Optional[str] = None, user: Optional[str] = None):
        """
        Initialize security event
        
        Args:
            event_type (str): Type of security event
            severity (str): Event severity level
            message (str): Event description
            source_ip (str, optional): Source IP address
            user (str, optional): Associated user
        """
        
        # Validate inputs
        if event_type not in self.EVENT_TYPES:
            raise ValueError(f"Invalid event type. Must be one of: {self.EVENT_TYPES}")
        
        if severity not in self.SEVERITY_LEVELS:
            raise ValueError(f"Invalid severity. Must be one of: {list(self.SEVERITY_LEVELS.keys())}")
        
        # Instance attributes
        self.event_id = self._generate_event_id()
        self.event_type = event_type
        self.severity = severity
        self.message = message
        self.source_ip = source_ip
        self.user = user
        self.timestamp = time.time()
        self.acknowledged = False
        self.metadata = {}
        
        # Log event creation
        self._log_event_creation()
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        timestamp_str = str(time.time())
        return hashlib.md5(timestamp_str.encode()).hexdigest()[:12]
    
    def _log_event_creation(self) -> None:
        """Log event creation for audit trail"""
        print(f"SecurityEvent created: {self.event_id} - {self.event_type}/{self.severity}")
    
    def acknowledge(self, user: str, notes: str = "") -> None:
        """
        Acknowledge the security event
        
        Args:
            user (str): User acknowledging the event
            notes (str): Optional acknowledgment notes
        """
        self.acknowledged = True
        self.metadata['acknowledged_by'] = user
        self.metadata['acknowledged_at'] = time.time()
        self.metadata['acknowledgment_notes'] = notes
        
        print(f"Event {self.event_id} acknowledged by {user}")
    
    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to the event"""
        self.metadata[key] = value
    
    def get_severity_score(self) -> int:
        """Get numeric severity score"""
        return self.SEVERITY_LEVELS[self.severity]
    
    def get_age_seconds(self) -> float:
        """Get event age in seconds"""
        return time.time() - self.timestamp
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary representation"""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'severity': self.severity,
            'severity_score': self.get_severity_score(),
            'message': self.message,
            'source_ip': self.source_ip,
            'user': self.user,
            'timestamp': self.timestamp,
            'acknowledged': self.acknowledged,
            'metadata': self.metadata,
            'age_seconds': self.get_age_seconds()
        }
    
    def __str__(self) -> str:
        """String representation of the event"""
        return f"SecurityEvent[{self.event_id}]: {self.severity.upper()} {self.event_type} - {self.message}"
    
    def __repr__(self) -> str:
        """Developer-friendly representation"""
        return (f"SecurityEvent(event_type='{self.event_type}', "
                f"severity='{self.severity}', message='{self.message[:50]}...')")

class VulnerabilityReport:
    """
    Class for managing vulnerability reports with detailed analysis
    """
    
    def __init__(self, target: str, scan_type: str):
        """
        Initialize vulnerability report
        
        Args:
            target (str): Target system or application
            scan_type (str): Type of vulnerability scan performed
        """
        self.target = target
        self.scan_type = scan_type
        self.report_id = self._generate_report_id()
        self.scan_start = time.time()
        self.scan_end = None
        self.vulnerabilities = []
        self.scan_metadata = {}
        self.recommendations = []
    
    def _generate_report_id(self) -> str:
        """Generate unique report ID"""
        data = f"{self.target}_{self.scan_type}_{time.time()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def add_vulnerability(self, vuln_type: str, severity: str, description: str,
                         cvss_score: Optional[float] = None, 
                         affected_component: Optional[str] = None) -> None:
        """
        Add vulnerability to the report
        
        Args:
            vuln_type (str): Type of vulnerability
            severity (str): Vulnerability severity
            description (str): Detailed description
            cvss_score (float, optional): CVSS score if available
            affected_component (str, optional): Affected system component
        """
        
        vulnerability = {
            'id': len(self.vulnerabilities) + 1,
            'type': vuln_type,
            'severity': severity,
            'description': description,
            'cvss_score': cvss_score,
            'affected_component': affected_component,
            'discovered_at': time.time(),
            'status': 'open'
        }
        
        self.vulnerabilities.append(vulnerability)
        print(f"Added vulnerability: {vuln_type} ({severity}) to report {self.report_id}")
    
    def complete_scan(self) -> None:
        """Mark scan as completed"""
        self.scan_end = time.time()
        self.scan_metadata['duration'] = self.scan_end - self.scan_start
        self.scan_metadata['total_vulnerabilities'] = len(self.vulnerabilities)
        
        # Generate recommendations based on findings
        self._generate_recommendations()
    
    def _generate_recommendations(self) -> None:
        """Generate security recommendations based on vulnerabilities"""
        
        # Count vulnerabilities by severity
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Generate recommendations
        if severity_counts.get('critical', 0) > 0:
            self.recommendations.append({
                'priority': 'immediate',
                'action': 'Address all critical vulnerabilities immediately',
                'timeline': '24 hours'
            })
        
        if severity_counts.get('high', 0) > 0:
            self.recommendations.append({
                'priority': 'high',
                'action': 'Remediate high-severity vulnerabilities',
                'timeline': '1 week'
            })
        
        if severity_counts.get('medium', 0) >= 5:
            self.recommendations.append({
                'priority': 'medium',
                'action': 'Review and address medium-severity issues',
                'timeline': '1 month'
            })
    
    def get_vulnerability_summary(self) -> Dict[str, Any]:
        """Get summary of vulnerabilities found"""
        
        summary = {
            'total_vulnerabilities': len(self.vulnerabilities),
            'by_severity': {},
            'by_type': {},
            'highest_cvss': 0.0,
            'scan_duration': self.scan_metadata.get('duration', 0)
        }
        
        for vuln in self.vulnerabilities:
            # Count by severity
            severity = vuln['severity']
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Count by type
            vuln_type = vuln['type']
            summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1
            
            # Track highest CVSS score
            if vuln['cvss_score'] and vuln['cvss_score'] > summary['highest_cvss']:
                summary['highest_cvss'] = vuln['cvss_score']
        
        return summary
    
    def export_to_json(self) -> str:
        """Export report to JSON format"""
        
        report_data = {
            'report_id': self.report_id,
            'target': self.target,
            'scan_type': self.scan_type,
            'scan_start': self.scan_start,
            'scan_end': self.scan_end,
            'vulnerabilities': self.vulnerabilities,
            'recommendations': self.recommendations,
            'metadata': self.scan_metadata,
            'summary': self.get_vulnerability_summary()
        }
        
        return json.dumps(report_data, indent=2, default=str)

# Example usage of basic classes
def demo_basic_classes():
    """Demonstrate basic class usage"""
    
    # Create security events
    auth_event = SecurityEvent(
        event_type="authentication",
        severity="high", 
        message="Multiple failed login attempts detected",
        source_ip="192.168.1.200",
        user="admin"
    )
    
    auth_event.add_metadata("attempt_count", 5)
    auth_event.add_metadata("time_window", "5 minutes")
    
    # Acknowledge event
    auth_event.acknowledge("security_analyst", "Investigating brute force attempt")
    
    print(f"Event details: {auth_event}")
    print(f"Event dict: {auth_event.to_dict()}")
    
    # Create vulnerability report
    vuln_report = VulnerabilityReport("192.168.1.100", "web_application_scan")
    
    # Add vulnerabilities
    vuln_report.add_vulnerability(
        "SQL Injection", 
        "high", 
        "SQL injection in login form parameter 'username'",
        cvss_score=8.5,
        affected_component="login.php"
    )
    
    vuln_report.add_vulnerability(
        "Cross-Site Scripting",
        "medium",
        "Reflected XSS in search functionality", 
        cvss_score=6.1,
        affected_component="search.php"
    )
    
    vuln_report.complete_scan()
    
    print(f"Vulnerability summary: {vuln_report.get_vulnerability_summary()}")
    
    # Export report
    json_report = vuln_report.export_to_json()
    print(f"JSON report length: {len(json_report)} characters")

# Run basic class demonstration
demo_basic_classes()
```

## Inheritance for Security Tool Hierarchies

### Base Scanner Class with Specialized Implementations
```python
from abc import ABC, abstractmethod
import socket
import requests
import subprocess
from typing import Union, List, Dict

class BaseSecurityScanner(ABC):
    """
    Abstract base class for all security scanners
    """
    
    def __init__(self, target: str, timeout: int = 30):
        """
        Initialize base scanner
        
        Args:
            target (str): Target for scanning
            timeout (int): Operation timeout in seconds
        """
        self.target = target
        self.timeout = timeout
        self.scan_results = {
            'target': target,
            'scanner_type': self.__class__.__name__,
            'scan_start': time.time(),
            'scan_end': None,
            'findings': [],
            'errors': [],
            'metadata': {}
        }
    
    @abstractmethod
    def scan(self) -> Dict[str, Any]:
        """
        Abstract method that must be implemented by subclasses
        
        Returns:
            Dict containing scan results
        """
        pass
    
    @abstractmethod
    def validate_target(self) -> bool:
        """
        Abstract method to validate target for specific scanner type
        
        Returns:
            bool: True if target is valid for this scanner type
        """
        pass
    
    def start_scan(self) -> Dict[str, Any]:
        """
        Common scan orchestration method
        
        Returns:
            Dict containing complete scan results
        """
        print(f"Starting {self.__class__.__name__} scan of {self.target}")
        
        # Validate target before scanning
        if not self.validate_target():
            error_msg = f"Invalid target for {self.__class__.__name__}: {self.target}"
            self.scan_results['errors'].append(error_msg)
            return self.scan_results
        
        try:
            # Perform actual scan (implemented by subclass)
            scan_findings = self.scan()
            self.scan_results['findings'] = scan_findings
            
        except Exception as e:
            error_msg = f"Scan error: {str(e)}"
            self.scan_results['errors'].append(error_msg)
            print(f"Error during scan: {error_msg}")
        
        finally:
            # Mark scan completion
            self.scan_results['scan_end'] = time.time()
            duration = self.scan_results['scan_end'] - self.scan_results['scan_start']
            self.scan_results['metadata']['scan_duration'] = duration
            
            print(f"Scan completed in {duration:.2f} seconds")
        
        return self.scan_results
    
    def add_finding(self, finding_type: str, severity: str, description: str, 
                   evidence: Optional[str] = None) -> None:
        """
        Add finding to scan results
        
        Args:
            finding_type (str): Type of finding
            severity (str): Finding severity
            description (str): Detailed description
            evidence (str, optional): Supporting evidence
        """
        finding = {
            'type': finding_type,
            'severity': severity,
            'description': description,
            'evidence': evidence,
            'timestamp': time.time()
        }
        
        self.scan_results['findings'].append(finding)

class PortScanner(BaseSecurityScanner):
    """
    Specialized port scanner implementation
    """
    
    def __init__(self, target: str, port_range: tuple = (1, 1000), timeout: int = 3):
        """
        Initialize port scanner
        
        Args:
            target (str): Target IP or hostname
            port_range (tuple): Port range to scan (start, end)
            timeout (int): Connection timeout per port
        """
        super().__init__(target, timeout)
        self.port_range = port_range
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
    
    def validate_target(self) -> bool:
        """Validate target is a valid IP or hostname"""
        try:
            socket.gethostbyname(self.target)
            return True
        except socket.gaierror:
            return False
    
    def scan(self) -> List[Dict[str, Any]]:
        """
        Perform port scan
        
        Returns:
            List of port scan findings
        """
        findings = []
        start_port, end_port = self.port_range
        
        print(f"Scanning ports {start_port}-{end_port} on {self.target}")
        
        for port in range(start_port, end_port + 1):
            port_status = self._scan_port(port)
            
            if port_status == 'open':
                self.open_ports.append(port)
                service = self._identify_service(port)
                
                finding = {
                    'type': 'open_port',
                    'port': port,
                    'status': 'open',
                    'service': service,
                    'risk_level': self._assess_port_risk(port, service)
                }
                findings.append(finding)
                
                # Add high-risk service findings
                if self._is_high_risk_service(service):
                    self.add_finding(
                        'high_risk_service',
                        'high',
                        f"High-risk service {service} detected on port {port}",
                        f"Port {port} is running {service} service"
                    )
            
            elif port_status == 'closed':
                self.closed_ports.append(port)
            else:
                self.filtered_ports.append(port)
        
        # Update metadata
        self.scan_results['metadata'].update({
            'ports_scanned': end_port - start_port + 1,
            'open_ports': len(self.open_ports),
            'closed_ports': len(self.closed_ports),
            'filtered_ports': len(self.filtered_ports)
        })
        
        return findings
    
    def _scan_port(self, port: int) -> str:
        """Scan individual port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            return 'open' if result == 0 else 'closed'
            
        except socket.timeout:
            return 'filtered'
        except Exception:
            return 'error'
    
    def _identify_service(self, port: int) -> str:
        """Identify service running on port"""
        service_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S', 3389: 'RDP'
        }
        return service_map.get(port, 'Unknown')
    
    def _assess_port_risk(self, port: int, service: str) -> str:
        """Assess risk level of open port"""
        high_risk_ports = [21, 23, 25, 135, 139, 445, 1433, 3389]
        medium_risk_ports = [53, 110, 143, 993, 995]
        
        if port in high_risk_ports:
            return 'high'
        elif port in medium_risk_ports:
            return 'medium'
        elif service in ['HTTP', 'HTTPS']:
            return 'low'
        else:
            return 'informational'
    
    def _is_high_risk_service(self, service: str) -> bool:
        """Check if service is considered high-risk"""
        high_risk_services = ['Telnet', 'FTP', 'RDP', 'SMB']
        return service in high_risk_services

class WebApplicationScanner(BaseSecurityScanner):
    """
    Specialized web application vulnerability scanner
    """
    
    def __init__(self, target: str, timeout: int = 30):
        """
        Initialize web application scanner
        
        Args:
            target (str): Target URL
            timeout (int): Request timeout
        """
        super().__init__(target, timeout)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebAppSecurityScanner/1.0'
        })
    
    def validate_target(self) -> bool:
        """Validate target is a valid URL"""
        return self.target.startswith(('http://', 'https://'))
    
    def scan(self) -> List[Dict[str, Any]]:
        """
        Perform web application security scan
        
        Returns:
            List of web application findings
        """
        findings = []
        
        # Check for common vulnerabilities
        findings.extend(self._check_sql_injection())
        findings.extend(self._check_xss())
        findings.extend(self._check_security_headers())
        findings.extend(self._check_directory_traversal())
        
        return findings
    
    def _make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with error handling"""
        try:
            if method.upper() == 'GET':
                return self.session.get(url, timeout=self.timeout, **kwargs)
            elif method.upper() == 'POST':
                return self.session.post(url, timeout=self.timeout, **kwargs)
        except requests.RequestException as e:
            self.scan_results['errors'].append(f"Request error: {str(e)}")
            return None
    
    def _check_sql_injection(self) -> List[Dict[str, Any]]:
        """Check for SQL injection vulnerabilities"""
        findings = []
        
        # Common SQL injection payloads
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users; --"
        ]
        
        for payload in payloads:
            test_url = f"{self.target}?id={payload}"
            response = self._make_request(test_url)
            
            if response and self._detect_sql_error(response.text):
                findings.append({
                    'type': 'sql_injection',
                    'severity': 'high',
                    'description': 'Potential SQL injection vulnerability detected',
                    'evidence': f'Error response with payload: {payload}',
                    'affected_url': test_url
                })
                break  # Don't test all payloads if one works
        
        return findings
    
    def _check_xss(self) -> List[Dict[str, Any]]:
        """Check for XSS vulnerabilities"""
        findings = []
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        for payload in xss_payloads:
            test_url = f"{self.target}?search={payload}"
            response = self._make_request(test_url)
            
            if response and payload in response.text:
                findings.append({
                    'type': 'xss',
                    'severity': 'medium',
                    'description': 'Potential XSS vulnerability detected',
                    'evidence': f'Payload reflected in response: {payload}',
                    'affected_url': test_url
                })
        
        return findings
    
    def _check_security_headers(self) -> List[Dict[str, Any]]:
        """Check for missing security headers"""
        findings = []
        
        response = self._make_request(self.target)
        if not response:
            return findings
        
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-XSS-Protection': 'XSS protection disabled',
            'X-Content-Type-Options': 'MIME type sniffing protection missing',
            'Strict-Transport-Security': 'HTTPS enforcement missing'
        }
        
        for header, description in security_headers.items():
            if header not in response.headers:
                findings.append({
                    'type': 'missing_security_header',
                    'severity': 'low',
                    'description': description,
                    'evidence': f'Header {header} not present in response',
                    'recommendation': f'Add {header} header to responses'
                })
        
        return findings
    
    def _check_directory_traversal(self) -> List[Dict[str, Any]]:
        """Check for directory traversal vulnerabilities"""
        findings = []
        
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc//passwd"
        ]
        
        for payload in traversal_payloads:
            test_url = f"{self.target}?file={payload}"
            response = self._make_request(test_url)
            
            if response and self._detect_file_contents(response.text):
                findings.append({
                    'type': 'directory_traversal',
                    'severity': 'high',
                    'description': 'Directory traversal vulnerability detected',
                    'evidence': f'System file contents accessed with: {payload}',
                    'affected_url': test_url
                })
        
        return findings
    
    def _detect_sql_error(self, response_text: str) -> bool:
        """Detect SQL error messages in response"""
        error_indicators = [
            'mysql_fetch', 'ORA-', 'Microsoft OLE DB', 'ODBC Driver',
            'SQLServer JDBC Driver', 'PostgreSQL query failed'
        ]
        return any(indicator.lower() in response_text.lower() for indicator in error_indicators)
    
    def _detect_file_contents(self, response_text: str) -> bool:
        """Detect system file contents in response"""
        file_indicators = [
            'root:x:', 'bin/bash', '127.0.0.1', 'localhost'
        ]
        return any(indicator in response_text for indicator in file_indicators)

class NetworkScanner(BaseSecurityScanner):
    """
    Network-level security scanner
    """
    
    def __init__(self, network_range: str, timeout: int = 30):
        """
        Initialize network scanner
        
        Args:
            network_range (str): Network range to scan (e.g., "192.168.1.0/24")
            timeout (int): Operation timeout
        """
        super().__init__(network_range, timeout)
        self.active_hosts = []
    
    def validate_target(self) -> bool:
        """Validate network range format"""
        # Simple validation - would be more comprehensive in production
        return '/' in self.target and '.' in self.target
    
    def scan(self) -> List[Dict[str, Any]]:
        """
        Perform network-level security scan
        
        Returns:
            List of network security findings
        """
        findings = []
        
        # Discover active hosts
        self.active_hosts = self._discover_hosts()
        
        # Analyze each active host
        for host in self.active_hosts:
            host_findings = self._analyze_host(host)
            findings.extend(host_findings)
        
        return findings
    
    def _discover_hosts(self) -> List[str]:
        """Discover active hosts in network range"""
        # Simplified implementation - would use proper network scanning
        active_hosts = []
        
        # For demonstration, simulate discovering hosts
        base_ip = self.target.split('/')[0]
        base_parts = base_ip.split('.')
        base = '.'.join(base_parts[:3])
        
        for i in range(1, 11):  # Scan first 10 IPs for demo
            test_ip = f"{base}.{i}"
            if self._ping_host(test_ip):
                active_hosts.append(test_ip)
        
        return active_hosts
    
    def _ping_host(self, host: str) -> bool:
        """Ping host to check if active"""
        try:
            # Use ping command (simplified)
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1000', host],
                capture_output=True, timeout=2
            )
            return result.returncode == 0
        except:
            return False
    
    def _analyze_host(self, host: str) -> List[Dict[str, Any]]:
        """Analyze individual host for security issues"""
        findings = []
        
        # Simple port scan on common ports
        common_ports = [22, 23, 80, 135, 139, 443, 445, 3389]
        open_ports = []
        
        for port in common_ports:
            if self._check_port(host, port):
                open_ports.append(port)
        
        # Analyze open ports for security implications
        if 23 in open_ports:  # Telnet
            findings.append({
                'type': 'insecure_service',
                'severity': 'high',
                'description': f'Telnet service detected on {host}',
                'evidence': 'Port 23 is open - unencrypted protocol',
                'recommendation': 'Disable Telnet and use SSH instead'
            })
        
        if 135 in open_ports and 139 in open_ports and 445 in open_ports:  # SMB
            findings.append({
                'type': 'smb_exposure',
                'severity': 'medium',
                'description': f'SMB services exposed on {host}',
                'evidence': 'Ports 135, 139, and 445 are open',
                'recommendation': 'Restrict SMB access or disable if not needed'
            })
        
        return findings
    
    def _check_port(self, host: str, port: int) -> bool:
        """Check if specific port is open on host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False

# Example usage of inheritance hierarchy
def demo_scanner_inheritance():
    """Demonstrate scanner inheritance and polymorphism"""
    
    # Create different scanner instances
    scanners = [
        PortScanner("scanme.nmap.org", port_range=(20, 100)),
        WebApplicationScanner("https://httpbin.org"),
        NetworkScanner("192.168.1.0/24")
    ]
    
    # Demonstrate polymorphism - all scanners have same interface
    for scanner in scanners:
        print(f"\n{'='*50}")
        print(f"Running {scanner.__class__.__name__}")
        print(f"Target: {scanner.target}")
        
        # All scanners implement the same interface
        results = scanner.start_scan()
        
        print(f"Findings: {len(results['findings'])}")
        print(f"Errors: {len(results['errors'])}")
        
        if results['findings']:
            print("Sample findings:")
            for finding in results['findings'][:3]:  # Show first 3
                print(f"  - {finding.get('type', 'unknown')}: {finding.get('description', 'No description')}")

# Run inheritance demonstration
demo_scanner_inheritance()
```

## Advanced OOP Concepts for Security

### Multiple Inheritance and Mixins
```python
class LoggingMixin:
    """Mixin class for adding logging capabilities to security tools"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logs = []
        self.log_enabled = True
    
    def log(self, level: str, message: str, **metadata) -> None:
        """Add log entry"""
        if not self.log_enabled:
            return
        
        log_entry = {
            'timestamp': time.time(),
            'level': level.upper(),
            'message': message,
            'source': self.__class__.__name__,
            'metadata': metadata
        }
        
        self.logs.append(log_entry)
        
        # Also print to console for immediate feedback
        timestamp_str = datetime.fromtimestamp(log_entry['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp_str}] {level.upper()}: {message}")
    
    def get_logs(self, level: Optional[str] = None) -> List[Dict]:
        """Get filtered logs"""
        if level:
            return [log for log in self.logs if log['level'] == level.upper()]
        return self.logs
    
    def clear_logs(self) -> None:
        """Clear all logs"""
        self.logs.clear()

class CachingMixin:
    """Mixin class for adding caching capabilities"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cache = {}
        self.cache_enabled = True
        self.cache_ttl = 300  # 5 minutes default
    
    def _cache_key(self, *args, **kwargs) -> str:
        """Generate cache key from arguments"""
        import hashlib
        key_data = str(args) + str(sorted(kwargs.items()))
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def get_cached(self, key: str) -> Optional[Any]:
        """Get cached value if valid"""
        if not self.cache_enabled or key not in self._cache:
            return None
        
        cache_entry = self._cache[key]
        if time.time() - cache_entry['timestamp'] > self.cache_ttl:
            del self._cache[key]
            return None
        
        return cache_entry['value']
    
    def set_cache(self, key: str, value: Any) -> None:
        """Set cached value"""
        if not self.cache_enabled:
            return
        
        self._cache[key] = {
            'value': value,
            'timestamp': time.time()
        }
    
    def clear_cache(self) -> None:
        """Clear all cached values"""
        self._cache.clear()

class RateLimitingMixin:
    """Mixin class for adding rate limiting capabilities"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rate_limit = 10  # requests per second
        self.request_times = []
    
    def check_rate_limit(self) -> bool:
        """Check if request is within rate limit"""
        current_time = time.time()
        
        # Remove old requests outside the 1-second window
        self.request_times = [
            req_time for req_time in self.request_times 
            if current_time - req_time < 1.0
        ]
        
        # Check if we're within rate limit
        if len(self.request_times) >= self.rate_limit:
            return False
        
        # Record this request
        self.request_times.append(current_time)
        return True
    
    def wait_for_rate_limit(self) -> None:
        """Wait until rate limit allows next request"""
        while not self.check_rate_limit():
            time.sleep(0.1)

class AdvancedPortScanner(BaseSecurityScanner, LoggingMixin, 
                         CachingMixin, RateLimitingMixin):
    """
    Advanced port scanner with logging, caching, and rate limiting
    """
    
    def __init__(self, target: str, port_range: tuple = (1, 1000), 
                 timeout: int = 3, rate_limit: int = 50):
        # Initialize all parent classes
        super().__init__(target, timeout)
        
        # Set specific configurations
        self.port_range = port_range
        self.rate_limit = rate_limit
        self.cache_ttl = 600  # 10 minutes for port scan results
        
        self.log('info', f'Initialized AdvancedPortScanner for {target}')
    
    def validate_target(self) -> bool:
        """Validate target with logging"""
        try:
            socket.gethostbyname(self.target)
            self.log('info', f'Target {self.target} validated successfully')
            return True
        except socket.gaierror as e:
            self.log('error', f'Target validation failed: {e}')
            return False
    
    def scan(self) -> List[Dict[str, Any]]:
        """Perform advanced port scan with all mixins"""
        findings = []
        start_port, end_port = self.port_range
        
        self.log('info', f'Starting port scan: {start_port}-{end_port}')
        
        for port in range(start_port, end_port + 1):
            # Check cache first
            cache_key = self._cache_key(self.target, port)
            cached_result = self.get_cached(cache_key)
            
            if cached_result:
                self.log('debug', f'Using cached result for port {port}')
                if cached_result['status'] == 'open':
                    findings.append(cached_result)
                continue
            
            # Apply rate limiting
            self.wait_for_rate_limit()
            
            # Scan port
            port_result = self._scan_port_advanced(port)
            
            # Cache result
            self.set_cache(cache_key, port_result)
            
            if port_result['status'] == 'open':
                findings.append(port_result)
                self.log('info', f'Open port found: {port} ({port_result.get("service", "unknown")})')
        
        self.log('info', f'Port scan completed. Found {len(findings)} open ports')
        return findings
    
    def _scan_port_advanced(self, port: int) -> Dict[str, Any]:
        """Advanced port scanning with detailed analysis"""
        result = {
            'type': 'port_scan',
            'port': port,
            'status': 'closed',
            'service': 'unknown',
            'version': None,
            'response_time': None
        }
        
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            connect_result = sock.connect_ex((self.target, port))
            
            if connect_result == 0:
                result['status'] = 'open'
                result['response_time'] = time.time() - start_time
                result['service'] = self._identify_service_advanced(sock, port)
                
                # Attempt banner grabbing for version information
                try:
                    sock.settimeout(2)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        result['banner'] = banner
                        result['version'] = self._extract_version_from_banner(banner)
                except:
                    pass
            
            sock.close()
            
        except socket.timeout:
            result['status'] = 'filtered'
            self.log('debug', f'Port {port} filtered (timeout)')
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
            self.log('warning', f'Error scanning port {port}: {e}')
        
        return result
    
    def _identify_service_advanced(self, sock: socket.socket, port: int) -> str:
        """Advanced service identification"""
        # Try to get service information
        try:
            service_name = socket.getservbyport(port)
            return service_name
        except:
            # Fallback to common port mapping
            common_services = {
                21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
                53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
                443: 'https', 993: 'imaps', 995: 'pop3s', 3389: 'rdp'
            }
            return common_services.get(port, 'unknown')
    
    def _extract_version_from_banner(self, banner: str) -> Optional[str]:
        """Extract version information from service banner"""
        # Simple version extraction patterns
        version_patterns = [
            r'OpenSSH_(\d+\.\d+)',
            r'Apache/(\d+\.\d+\.\d+)',
            r'nginx/(\d+\.\d+\.\d+)',
            r'Microsoft-IIS/(\d+\.\d+)'
        ]
        
        import re
        for pattern in version_patterns:
            match = re.search(pattern, banner)
            if match:
                return match.group(1)
        
        return None
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive scan report"""
        
        # Get scan results and logs
        scan_results = self.scan_results.copy()
        logs = self.get_logs()
        
        # Add performance metrics
        performance_metrics = {
            'cache_hit_rate': self._calculate_cache_hit_rate(),
            'average_response_time': self._calculate_average_response_time(),
            'rate_limit_violations': self._count_rate_limit_violations()
        }
        
        # Compile comprehensive report
        report = {
            'scan_results': scan_results,
            'performance_metrics': performance_metrics,
            'logs_summary': {
                'total_logs': len(logs),
                'error_count': len(self.get_logs('error')),
                'warning_count': len(self.get_logs('warning')),
                'info_count': len(self.get_logs('info'))
            },
            'cache_statistics': {
                'cached_entries': len(self._cache),
                'cache_enabled': self.cache_enabled
            }
        }
        
        return report
    
    def _calculate_cache_hit_rate(self) -> float:
        """Calculate cache hit rate"""
        # Simplified calculation
        return 0.75  # Would track actual hits/misses
    
    def _calculate_average_response_time(self) -> float:
        """Calculate average response time"""
        response_times = []
        for finding in self.scan_results.get('findings', []):
            if finding.get('response_time'):
                response_times.append(finding['response_time'])
        
        return sum(response_times) / len(response_times) if response_times else 0.0
    
    def _count_rate_limit_violations(self) -> int:
        """Count rate limit violations"""
        # Would track actual violations
        return 0

# Example usage of multiple inheritance
def demo_multiple_inheritance():
    """Demonstrate multiple inheritance and mixins"""
    
    print("=== Advanced Port Scanner with Mixins ===")
    
    scanner = AdvancedPortScanner(
        target="scanme.nmap.org",
        port_range=(20, 30),
        rate_limit=5
    )
    
    # Start scan
    results = scanner.start_scan()
    
    # Generate comprehensive report
    report = scanner.generate_report()
    
    print(f"\nScan Results Summary:")
    print(f"- Findings: {len(results['findings'])}")
    print(f"- Errors: {len(results['errors'])}")
    print(f"- Total logs: {report['logs_summary']['total_logs']}")
    print(f"- Cache entries: {report['cache_statistics']['cached_entries']}")
    
    # Show some logs
    print(f"\nRecent logs:")
    for log in scanner.get_logs()[-5:]:  # Last 5 logs
        timestamp_str = datetime.fromtimestamp(log['timestamp']).strftime('%H:%M:%S')
        print(f"  [{timestamp_str}] {log['level']}: {log['message']}")

# Run multiple inheritance demonstration
demo_multiple_inheritance()
```

## Summary

**Object-Oriented Programming Benefits for Security:**
- **Code Organization**: Logical grouping of related security functionality
- **Reusability**: Common security patterns can be inherited and extended
- **Maintainability**: Easier to modify and extend security tools
- **Polymorphism**: Consistent interfaces across different scanner types

**Key OOP Concepts Applied:**
- **Inheritance**: Specialized scanners inheriting from base security scanner
- **Encapsulation**: Internal methods and data protection in security classes  
- **Polymorphism**: Different scanners with same interface for flexibility
- **Multiple Inheritance/Mixins**: Combining functionality like logging, caching, rate limiting

**Security-Specific Applications:**
- **Scanner Hierarchies**: Port, web, and network scanners with common base
- **Event Management**: Security event classes with metadata and tracking
- **Report Generation**: Vulnerability reports with structured data
- **Tool Integration**: Consistent interfaces for security tool integration

**Best Practices:**
- Use abstract base classes to define interfaces for security tools
- Implement proper error handling and logging in all security classes
- Apply rate limiting and caching mixins to respect target systems
- Design classes with security and audit requirements in mind
- Use composition and mixins to add cross-cutting concerns

**Advanced Features:**
- Abstract methods ensure proper implementation of security interfaces
- Multiple inheritance enables flexible combination of capabilities
- Context managers provide proper resource cleanup for security operations
- Comprehensive logging and caching improve tool performance and debugging

Object-oriented design principles enable the creation of sophisticated, maintainable, and extensible security tools that can handle complex real-world penetration testing and vulnerability assessment requirements.