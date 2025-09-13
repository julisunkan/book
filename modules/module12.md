# Chapter 12: Regular Expressions for Ethical Hacking

## Overview

Regular expressions (regex) are powerful pattern-matching tools essential for ethical hackers and cybersecurity professionals. They enable efficient text processing, log analysis, vulnerability detection, and data extraction from various sources during security assessments.

## Why Regular Expressions for Security?

### Key Applications
- **Log Analysis**: Extract security events from massive log files
- **Vulnerability Detection**: Pattern matching for common attack signatures
- **Data Validation**: Input sanitization and format verification
- **Threat Hunting**: Search for indicators of compromise (IoCs)
- **Report Generation**: Extract and format security assessment data
- **Web Scraping**: Extract information from web applications

## Basic Regex Syntax

### Literal Characters
```python
import re

# Exact string matching
pattern = "admin"
text = "User admin logged in"
match = re.search(pattern, text)
if match:
    print(f"Found: {match.group()}")  # Output: Found: admin

# Case sensitivity
pattern_case = "ADMIN"
if not re.search(pattern_case, text):
    print("Case sensitive - no match")
```

### Metacharacters
```python
# . (dot) - matches any character except newline
pattern = "a.c"
texts = ["abc", "axc", "a5c", "ac"]
for text in texts:
    if re.search(pattern, text):
        print(f"'{text}' matches 'a.c'")
# Output: 'abc', 'axc', 'a5c' match

# ^ - matches start of string
pattern = "^Error"
log_entries = [
    "Error: Connection failed",
    "Warning: Error detected",
    "Error in processing"
]
for entry in log_entries:
    if re.search(pattern, entry):
        print(f"Starts with Error: {entry}")

# $ - matches end of string
pattern = "failed$"
for entry in log_entries:
    if re.search(pattern, entry):
        print(f"Ends with 'failed': {entry}")
```

## Character Classes and Quantifiers

### Character Classes
```python
# [abc] - matches any character in the set
pattern = "[aeiou]"
text = "security"
matches = re.findall(pattern, text)
print(f"Vowels found: {matches}")  # ['e', 'u', 'i']

# [a-z] - character ranges
ip_pattern = "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
log_line = "192.168.1.100 - Failed login attempt"
ip = re.search(ip_pattern, log_line)
if ip:
    print(f"IP found: {ip.group()}")

# [^abc] - negated character class (anything except a, b, or c)
pattern = "[^0-9]"  # Non-digits
text = "abc123xyz"
non_digits = re.findall(pattern, text)
print(f"Non-digits: {non_digits}")  # ['a', 'b', 'c', 'x', 'y', 'z']

# Predefined character classes
# \d - digits [0-9]
# \w - word characters [a-zA-Z0-9_]
# \s - whitespace characters
# \D - non-digits
# \W - non-word characters
# \S - non-whitespace characters
```

### Quantifiers
```python
# * - zero or more
pattern = "ab*c"  # 'a' followed by zero or more 'b's, then 'c'
texts = ["ac", "abc", "abbc", "abbbc", "axc"]
for text in texts:
    if re.search(pattern, text):
        print(f"'{text}' matches 'ab*c'")

# + - one or more
pattern = "ab+c"  # 'a' followed by one or more 'b's, then 'c'
for text in texts:
    if re.search(pattern, text):
        print(f"'{text}' matches 'ab+c'")

# ? - zero or one (optional)
pattern = "colou?r"  # Matches both 'color' and 'colour'
texts = ["color", "colour", "colouur"]
for text in texts:
    if re.search(pattern, text):
        print(f"'{text}' matches 'colou?r'")

# {n,m} - between n and m occurrences
pattern = "\d{3,4}"  # 3 or 4 digits
text = "Port 80, 443, 8080"
ports = re.findall(pattern, text)
print(f"Ports found: {ports}")  # ['443', '8080']
```

## Practical Security Applications

### IP Address Validation
```python
def validate_ip_address(ip):
    """Validate IPv4 address format"""
    # More precise IP validation
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    
    if re.match(ip_pattern, ip):
        return True
    return False

# Test IP validation
test_ips = [
    "192.168.1.1",      # Valid
    "10.0.0.255",       # Valid
    "256.1.1.1",        # Invalid (256 > 255)
    "192.168.1",        # Invalid (incomplete)
    "192.168.1.1.1"     # Invalid (too many octets)
]

for ip in test_ips:
    valid = validate_ip_address(ip)
    print(f"{ip}: {'Valid' if valid else 'Invalid'}")
```

### Log Analysis for Security Events
```python
def analyze_security_logs(log_file_path):
    """Analyze logs for security events using regex"""
    
    # Define security event patterns
    patterns = {
        'failed_login': r'Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)',
        'sql_injection': r'(?i)(union.*select|or\s+1\s*=\s*1|drop\s+table)',
        'xss_attempt': r'(?i)(<script|javascript:|onerror=|onload=)',
        'directory_traversal': r'(?i)(\.\.\/|\.\.\\|\/etc\/passwd|\\windows\\system32)',
        'port_scan': r'(\d+\.\d+\.\d+\.\d+).*connection.*port (\d+)',
        'brute_force': r'(\d+\.\d+\.\d+\.\d+).*(?:authentication failure|invalid user|failed login).*(\w+)'
    }
    
    security_events = {key: [] for key in patterns.keys()}
    
    try:
        with open(log_file_path, 'r') as file:
            for line_num, line in enumerate(file, 1):
                for event_type, pattern in patterns.items():
                    matches = re.findall(pattern, line)
                    if matches:
                        security_events[event_type].extend([{
                            'line_number': line_num,
                            'matches': matches,
                            'full_line': line.strip()
                        }])
    
    except FileNotFoundError:
        print(f"Log file not found: {log_file_path}")
        return None
    
    return security_events

# Example usage
def print_security_summary(events):
    """Print summary of security events"""
    if not events:
        return
    
    print("SECURITY EVENT SUMMARY")
    print("=" * 50)
    
    for event_type, event_list in events.items():
        if event_list:
            print(f"\n{event_type.upper()}: {len(event_list)} events")
            for event in event_list[:5]:  # Show first 5 events
                print(f"  Line {event['line_number']}: {event['matches']}")
            if len(event_list) > 5:
                print(f"  ... and {len(event_list) - 5} more")

# Create sample log for demonstration
sample_log = """
Jan 15 10:30:45 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22
Jan 15 10:31:15 server apache2: GET /search.php?q=' UNION SELECT * FROM users-- 
Jan 15 10:32:22 server sshd[1235]: Failed password for root from 10.0.0.50 port 22
Jan 15 10:33:01 server nginx: <script>alert('xss')</script> in request
Jan 15 10:34:12 server app: Access attempt to ../../etc/passwd blocked
"""

with open('sample_security.log', 'w') as f:
    f.write(sample_log)

# Analyze the sample log
events = analyze_security_logs('sample_security.log')
print_security_summary(events)
```

### Email Address Extraction and Validation
```python
def extract_emails_from_text(text):
    """Extract email addresses from text"""
    # Comprehensive email regex
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    emails = re.findall(email_pattern, text)
    return emails

def validate_email_security(email):
    """Validate email and check for security issues"""
    # Basic email validation
    email_pattern = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$'
    
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    
    # Check for suspicious patterns
    suspicious_patterns = [
        (r'\.{2,}', "Multiple consecutive dots"),
        (r'^\.', "Starts with dot"),
        (r'\.$', "Ends with dot"),
        (r'[<>"\']', "Contains suspicious characters"),
        (r'javascript:', "Contains JavaScript"),
        (r'@.*@', "Multiple @ symbols")
    ]
    
    for pattern, description in suspicious_patterns:
        if re.search(pattern, email, re.IGNORECASE):
            return False, f"Security issue: {description}"
    
    return True, "Email appears secure"

# Test email extraction and validation
sample_text = """
Contact us at support@company.com or admin@test.org
Suspicious emails: hacker@evil..com, test@fake@domain.com
Valid emails: user.name+tag@domain.co.uk, info@secure-site.net
"""

emails = extract_emails_from_text(sample_text)
print("Extracted emails:")
for email in emails:
    is_valid, message = validate_email_security(email)
    print(f"  {email}: {message}")
```

## Advanced Regex Techniques

### Groups and Capturing
```python
# Named groups for better readability
def parse_log_entry(log_line):
    """Parse log entry with named groups"""
    log_pattern = r'(?P<timestamp>\w+ \d+ \d+:\d+:\d+) (?P<host>\S+) (?P<process>\S+): (?P<message>.*)'
    
    match = re.match(log_pattern, log_line)
    if match:
        return match.groupdict()
    return None

# Non-capturing groups for efficiency
def extract_attack_ips(text):
    """Extract IPs from attack patterns without capturing unnecessary groups"""
    # Non-capturing group: (?:pattern)
    pattern = r'(?:attack|intrusion|breach).*?(\d+\.\d+\.\d+\.\d+)'
    
    ips = re.findall(pattern, text, re.IGNORECASE)
    return ips

# Example usage
log_line = "Jan 15 10:30:45 server sshd[1234]: Authentication failure from 192.168.1.100"
parsed = parse_log_entry(log_line)
if parsed:
    print(f"Timestamp: {parsed['timestamp']}")
    print(f"Host: {parsed['host']}")
    print(f"Message: {parsed['message']}")

attack_text = "Detected intrusion from 10.0.0.50 and attack from 192.168.1.200"
attack_ips = extract_attack_ips(attack_text)
print(f"Attack IPs: {attack_ips}")
```

### Lookahead and Lookbehind
```python
# Positive lookahead (?=...)
def find_passwords_with_requirements(passwords):
    """Find passwords meeting complexity requirements"""
    # Password must contain at least one digit, one lowercase, one uppercase
    pattern = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$'
    
    valid_passwords = []
    for password in passwords:
        if re.match(pattern, password):
            valid_passwords.append(password)
    
    return valid_passwords

# Negative lookahead (?!...)
def find_usernames_not_admin(usernames):
    """Find usernames that don't start with 'admin'"""
    pattern = r'^(?!admin).*'
    
    non_admin_users = []
    for username in usernames:
        if re.match(pattern, username, re.IGNORECASE):
            non_admin_users.append(username)
    
    return non_admin_users

# Example usage
test_passwords = [
    "Password123",      # Valid
    "password123",      # Missing uppercase
    "PASSWORD123",      # Missing lowercase
    "Password",         # Missing digit
    "Pass123"          # Too short
]

valid_passwords = find_passwords_with_requirements(test_passwords)
print(f"Valid passwords: {valid_passwords}")

test_usernames = ["admin1", "administrator", "user1", "guest", "Admin_User"]
non_admin = find_usernames_not_admin(test_usernames)
print(f"Non-admin usernames: {non_admin}")
```

## Web Application Security Testing

### SQL Injection Detection
```python
def detect_sqli_patterns(request_data):
    """Detect potential SQL injection patterns"""
    sqli_patterns = [
        r"(?i)'.*(?:or|and).*'.*=.*'",          # Basic OR/AND injection
        r"(?i)union.*select",                    # UNION-based injection
        r"(?i)(?:drop|delete|insert|update).*(?:table|from|into)", # Destructive operations
        r"(?i)(?:exec|execute).*(?:\(|\s)",      # Stored procedure execution
        r"(?i)(?:script|javascript|vbscript):",  # Script injection
        r"(?:'.*\||.*\|.*')",                   # Boolean-based blind injection
        r"(?i)(?:waitfor|delay|sleep)\s*\(",     # Time-based injection
        r"(?i)(?:benchmark|pg_sleep|sleep)\s*\(" # Database-specific time delays
    ]
    
    detections = []
    for i, pattern in enumerate(sqli_patterns):
        matches = re.findall(pattern, request_data)
        if matches:
            detections.append({
                'pattern_id': i,
                'pattern_type': [
                    'Basic OR/AND', 'UNION-based', 'Destructive', 'Stored Procedure',
                    'Script Injection', 'Boolean Blind', 'Time-based', 'DB Time Delay'
                ][i],
                'matches': matches
            })
    
    return detections

# Test SQL injection detection
test_requests = [
    "username=admin&password=pass' OR '1'='1",
    "id=1 UNION SELECT username,password FROM users",
    "search=test'; DROP TABLE users; --",
    "user=admin'; EXEC sp_configure 'show advanced options', 1 --",
    "input=<script>alert('xss')</script>",
    "param=1' AND SLEEP(5) --"
]

for request in test_requests:
    detections = detect_sqli_patterns(request)
    if detections:
        print(f"\nRequest: {request}")
        for detection in detections:
            print(f"  Detected {detection['pattern_type']}: {detection['matches']}")
```

### XSS (Cross-Site Scripting) Detection
```python
def detect_xss_patterns(input_data):
    """Detect potential XSS attack patterns"""
    xss_patterns = [
        r'(?i)<script.*?>.*?</script>',              # Script tags
        r'(?i)javascript:',                          # JavaScript protocol
        r'(?i)on\w+\s*=',                          # Event handlers
        r'(?i)<iframe.*?src=',                      # Iframe injection
        r'(?i)alert\s*\(',                         # Alert function
        r'(?i)document\.(cookie|location|domain)',   # Document object access
        r'(?i)<img.*?src=.*?onerror=',              # Image with onerror
        r'(?i)<svg.*?onload=',                      # SVG with onload
        r'(?i)eval\s*\(',                          # Eval function
        r'(?i)string\.fromcharcode',                # Character code conversion
    ]
    
    pattern_names = [
        'Script Tags', 'JavaScript Protocol', 'Event Handlers',
        'Iframe Injection', 'Alert Function', 'Document Access',
        'Image Error Handler', 'SVG Onload', 'Eval Function',
        'Character Encoding'
    ]
    
    detections = []
    for pattern, name in zip(xss_patterns, pattern_names):
        matches = re.findall(pattern, input_data)
        if matches:
            detections.append({
                'type': name,
                'matches': matches,
                'severity': 'HIGH' if name in ['Script Tags', 'JavaScript Protocol'] else 'MEDIUM'
            })
    
    return detections

# Test XSS detection
test_inputs = [
    "<script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))",
    "<iframe src='javascript:alert(`XSS`)'>",
    "onclick=\"alert('XSS')\""
]

for test_input in test_inputs:
    detections = detect_xss_patterns(test_input)
    if detections:
        print(f"\nInput: {test_input}")
        for detection in detections:
            print(f"  {detection['severity']}: {detection['type']}")
            print(f"  Matches: {detection['matches']}")
```

## Network Security Applications

### URL and Domain Analysis
```python
def analyze_urls_for_security(urls):
    """Analyze URLs for security issues"""
    security_checks = {
        'suspicious_tld': r'\.(?:tk|ml|ga|cf|bit|su|ru)$',  # Suspicious TLDs
        'ip_address': r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP instead of domain
        'url_shortener': r'(?:bit\.ly|tinyurl|t\.co|goo\.gl|short\.link)',  # URL shorteners
        'suspicious_keywords': r'(?i)(?:phishing|malware|virus|hack|crack|warez)',
        'homograph_attack': r'[а-я]',  # Cyrillic characters (homograph)
        'excessive_subdomain': r'(?:[a-zA-Z0-9-]+\.){4,}',  # Too many subdomains
        'suspicious_ports': r':(?:22|23|135|139|445|1433|3389|5432|6379)\b'  # Suspicious ports
    }
    
    results = {}
    for url in urls:
        url_analysis = {'url': url, 'issues': []}
        
        for check_name, pattern in security_checks.items():
            if re.search(pattern, url):
                url_analysis['issues'].append(check_name)
        
        # Risk assessment
        risk_score = len(url_analysis['issues'])
        if risk_score >= 3:
            risk_level = 'HIGH'
        elif risk_score >= 1:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        url_analysis['risk_level'] = risk_level
        url_analysis['risk_score'] = risk_score
        results[url] = url_analysis
    
    return results

# Test URL analysis
test_urls = [
    "https://legitimate-site.com/page",
    "http://192.168.1.100:8080/admin",
    "https://bit.ly/suspicious",
    "https://banking-phishing.tk/login",
    "https://sub1.sub2.sub3.sub4.example.com/path",
    "https://аррӏе.com/login",  # Homograph attack (fake Apple)
    "ftp://server.com:21/files"
]

url_analysis = analyze_urls_for_security(test_urls)
for url, analysis in url_analysis.items():
    print(f"\nURL: {url}")
    print(f"Risk Level: {analysis['risk_level']}")
    if analysis['issues']:
        print(f"Issues: {', '.join(analysis['issues'])}")
```

### MAC Address and Network Identifier Extraction
```python
def extract_network_identifiers(text):
    """Extract various network identifiers from text"""
    patterns = {
        'mac_address': r'(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}',
        'ipv4_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'ipv6_address': r'(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}',
        'domain_name': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        'url': r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:\w+=\w+&?)*)?)?',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    }
    
    identifiers = {}
    for identifier_type, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            identifiers[identifier_type] = list(set(matches))  # Remove duplicates
    
    return identifiers

# Example network log analysis
network_log = """
2024-01-15 10:30:45 Device MAC 00:1B:44:11:3A:B7 connected to network
Source IP: 192.168.1.100, Destination: 10.0.0.50:443
DNS query for malicious-domain.com from user@company.com
IPv6 address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
Suspicious URL accessed: https://phishing-site.tk/login?user=victim&pass=123
Contact administrator at admin@company.org for assistance
"""

identifiers = extract_network_identifiers(network_log)
print("NETWORK IDENTIFIERS FOUND:")
print("=" * 40)
for id_type, id_list in identifiers.items():
    print(f"\n{id_type.upper()}:")
    for identifier in id_list:
        print(f"  - {identifier}")
```

## Performance Optimization

### Compiled Regex for Repeated Use
```python
import re
import time

def optimized_log_analysis(log_file_path):
    """Optimized log analysis using compiled regex"""
    
    # Compile regex patterns once for better performance
    compiled_patterns = {
        'failed_login': re.compile(r'Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)', re.IGNORECASE),
        'sqli_attempt': re.compile(r'(?i)(union.*select|or\s+1\s*=\s*1)', re.IGNORECASE),
        'ip_address': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
        'error_level': re.compile(r'\b(?:ERROR|CRITICAL|FATAL)\b', re.IGNORECASE)
    }
    
    results = {key: [] for key in compiled_patterns.keys()}
    
    with open(log_file_path, 'r') as file:
        for line_num, line in enumerate(file, 1):
            for pattern_name, compiled_pattern in compiled_patterns.items():
                matches = compiled_pattern.findall(line)
                if matches:
                    results[pattern_name].append({
                        'line': line_num,
                        'matches': matches,
                        'text': line.strip()
                    })
    
    return results

# Performance comparison function
def compare_regex_performance(text, pattern, iterations=1000):
    """Compare compiled vs non-compiled regex performance"""
    
    # Non-compiled regex
    start_time = time.time()
    for _ in range(iterations):
        re.findall(pattern, text)
    non_compiled_time = time.time() - start_time
    
    # Compiled regex
    compiled_pattern = re.compile(pattern)
    start_time = time.time()
    for _ in range(iterations):
        compiled_pattern.findall(text)
    compiled_time = time.time() - start_time
    
    print(f"Non-compiled: {non_compiled_time:.4f} seconds")
    print(f"Compiled: {compiled_time:.4f} seconds")
    print(f"Speedup: {non_compiled_time/compiled_time:.2f}x")

# Example performance comparison
sample_text = "User admin failed login from 192.168.1.100 multiple times"
ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
compare_regex_performance(sample_text, ip_pattern)
```

## Summary

**Key Regex Applications in Ethical Hacking:**
- Log file analysis for security events
- Input validation and sanitization
- Vulnerability pattern detection
- Network identifier extraction
- Data parsing and report generation
- Threat hunting and IoC detection

**Essential Regex Components:**
- **Literals**: Exact character matching
- **Metacharacters**: Special pattern characters (^, $, ., *, +, ?, etc.)
- **Character Classes**: [abc], [a-z], \d, \w, \s
- **Quantifiers**: *, +, ?, {n,m}
- **Groups**: (pattern), (?:pattern), (?P<name>pattern)

**Security Pattern Categories:**
- **Network**: IP addresses, MAC addresses, URLs, domains
- **Authentication**: Failed logins, privilege escalation
- **Attacks**: SQL injection, XSS, directory traversal
- **System**: Error messages, process names, file paths

**Best Practices:**
- Use compiled regex for repeated operations
- Test patterns thoroughly with various inputs
- Use non-capturing groups when possible
- Validate extracted data for security
- Consider performance implications for large datasets
- Document complex regex patterns

**Performance Tips:**
- Compile frequently used patterns
- Use specific character classes instead of broad ones
- Avoid excessive backtracking with careful quantifier use
- Test regex performance with realistic data volumes

Regular expressions are powerful tools that, when mastered, significantly enhance the efficiency and effectiveness of security analysis, threat detection, and data processing tasks in ethical hacking and cybersecurity operations.