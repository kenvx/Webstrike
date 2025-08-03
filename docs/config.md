# ⚙️ WebStrike Configuration Guide

## Overview

WebStrike provides extensive configuration options to customize scanning behavior, authentication settings, performance parameters, and output formats. This guide covers all configuration methods and options available.

## Configuration Methods

### 1. Configuration File (config.ini)

The primary configuration method uses a standard INI file format:

```ini
# config.ini - WebStrike Configuration File

[scanning]
# Basic scanning parameters
max_depth = 3
max_urls = 100
threads = 5
delay = 1.0
timeout = 30

# Advanced scanning options
follow_redirects = true
verify_ssl = true
user_agent = WebStrike/1.0.0
max_retries = 3

[authentication]
# Authentication settings
timeout = 30
max_login_attempts = 3
session_timeout = 3600
cookie_jar_size = 1000

[modules]
# Module-specific settings
enabled_modules = sqli,xss,csrf,headers,file_upload
sqli_timeout = 45
xss_timeout = 30
csrf_timeout = 20
headers_timeout = 15
file_upload_timeout = 60

[reporting]
# Report generation settings
include_evidence = true
max_evidence_length = 1000
risk_scoring = true
include_recommendations = true
template_dir = reports/templates
output_dir = reports/output

[logging]
# Logging configuration
level = INFO
format = %(asctime)s - %(name)s - %(levelname)s - %(message)s
file = logs/webstrike.log
max_size = 10485760
backup_count = 5

[performance]
# Performance optimization
connection_pool_size = 100
connection_pool_maxsize = 200
read_timeout = 30
connect_timeout = 10
pool_timeout = 10

[proxy]
# Proxy configuration
http_proxy = 
https_proxy = 
no_proxy = localhost,127.0.0.1

[waf]
# WAF detection and evasion
enable_detection = true
evasion_techniques = true
random_user_agents = true
request_randomization = true
```

### 2. Environment Variables

Override configuration using environment variables:

```bash
# Basic settings
export WEBSTRIKE_MAX_DEPTH=5
export WEBSTRIKE_MAX_URLS=200
export WEBSTRIKE_THREADS=10
export WEBSTRIKE_DELAY=0.5

# Authentication
export WEBSTRIKE_AUTH_TIMEOUT=60
export WEBSTRIKE_SESSION_TIMEOUT=7200

# Logging
export WEBSTRIKE_LOG_LEVEL=DEBUG
export WEBSTRIKE_LOG_FILE=logs/debug.log

# Performance
export WEBSTRIKE_CONNECTION_POOL=150
export WEBSTRIKE_READ_TIMEOUT=45

# Proxy settings
export WEBSTRIKE_HTTP_PROXY=http://proxy.company.com:8080
export WEBSTRIKE_HTTPS_PROXY=https://proxy.company.com:8080
```

### 3. Command Line Arguments

CLI arguments override both config file and environment variables:

```bash
# Scanning configuration
python -m cli.webstrike_cli scan \
  -u https://example.com \
  --depth 4 \
  --max-urls 150 \
  --threads 8 \
  --delay 0.8 \
  --timeout 45

# Module selection
python -m cli.webstrike_cli scan \
  -u https://example.com \
  -m sqli,xss,headers

# Authentication
python -m cli.webstrike_cli scan \
  -u https://example.com \
  --auth-type form \
  --login-url /login \
  --username admin \
  --password secret

# Output configuration
python -m cli.webstrike_cli scan \
  -u https://example.com \
  -f html \
  -o custom_report_name \
  --verbose
```

### 4. Programmatic Configuration

Configure settings programmatically in Python:

```python
from engine.scanner import WebStrikeScanner
from engine.config import Config

# Load configuration
config = Config()
config.load_from_file('custom_config.ini')
config.set('scanning', 'max_depth', '5')
config.set('scanning', 'threads', '10')

# Create scanner with custom config
scanner = WebStrikeScanner(
    target_url="https://example.com",
    config=config
)

# Or configure directly
scanner = WebStrikeScanner("https://example.com")
scanner.configure(
    max_depth=5,
    max_urls=200,
    threads=10,
    delay=0.5
)
```

## Configuration Sections

### Scanning Configuration

Controls core scanning behavior:

```ini
[scanning]
# Crawling parameters
max_depth = 3              # Maximum link depth to follow
max_urls = 100             # Maximum URLs to discover
threads = 5                # Concurrent scanning threads
delay = 1.0                # Delay between requests (seconds)
timeout = 30               # Request timeout (seconds)

# Request settings
follow_redirects = true    # Follow HTTP redirects
verify_ssl = true          # Verify SSL certificates
user_agent = WebStrike/1.0.0  # Custom User-Agent string
max_retries = 3            # Maximum retry attempts

# Scope control
include_subdomains = false # Include subdomains in scope
exclude_extensions = jpg,png,gif,pdf  # Skip these file types
exclude_patterns = /logout,/signout   # Skip URLs matching patterns

# Discovery settings
enable_hidden_discovery = true  # Search for hidden endpoints
wordlist_file = wordlists/common.txt  # Custom wordlist path
discovery_threads = 3      # Threads for hidden discovery
```

### Authentication Configuration

Manages authentication and session handling:

```ini
[authentication]
# Session management
timeout = 30               # Authentication timeout
max_login_attempts = 3     # Maximum login retry attempts
session_timeout = 3600     # Session lifetime (seconds)
cookie_jar_size = 1000     # Maximum cookies to store

# Form authentication
form_timeout = 45          # Form submission timeout
auto_csrf = true           # Automatically handle CSRF tokens
username_fields = username,email,login  # Username field names
password_fields = password,passwd,pass  # Password field names

# Token authentication
token_refresh = true       # Auto-refresh expired tokens
token_header = Authorization  # Default token header
bearer_prefix = Bearer     # Bearer token prefix

# Cookie settings
persistent_cookies = true # Maintain cookies across requests
secure_cookies_only = false  # Only accept secure cookies
```

### Module Configuration

Configure individual vulnerability scanner modules:

```ini
[modules]
# Global module settings
enabled_modules = sqli,xss,csrf,headers,file_upload
parallel_execution = true  # Run modules in parallel
stop_on_first = false     # Stop scanning after first vulnerability

# SQL Injection module
[module_sqli]
timeout = 45               # SQLi-specific timeout
max_payloads = 100         # Maximum payloads to test
error_patterns = error,exception,mysql  # Additional error patterns
time_threshold = 5         # Time-based detection threshold
blind_techniques = true    # Enable blind injection testing

# XSS module
[module_xss]
timeout = 30               # XSS-specific timeout
max_payloads = 50          # Maximum XSS payloads
context_analysis = true    # Analyze injection context
dom_analysis = true        # Enable DOM XSS detection
reflected_only = false     # Test reflected XSS only

# CSRF module
[module_csrf]
timeout = 20               # CSRF-specific timeout
token_analysis = true      # Analyze token strength
bypass_techniques = true   # Test CSRF bypass methods
referrer_check = true      # Check referrer validation

# Headers module
[module_headers]
timeout = 15               # Headers-specific timeout
strict_checks = true       # Enable strict header validation
custom_headers = X-Custom-Security  # Additional headers to check

# File Upload module
[module_file_upload]
timeout = 60               # File upload timeout
max_file_size = 10485760   # Maximum test file size (10MB)
test_extensions = php,asp,jsp  # Extensions to test
malicious_content = true   # Test malicious file content
```

### Reporting Configuration

Control report generation and output:

```ini
[reporting]
# Report content
include_evidence = true    # Include vulnerability evidence
max_evidence_length = 1000 # Maximum evidence text length
risk_scoring = true        # Calculate risk scores
include_recommendations = true  # Include fix recommendations
include_references = true  # Include vulnerability references

# Report formatting
template_dir = reports/templates  # Custom template directory
output_dir = reports/output      # Report output directory
timestamp_format = %Y%m%d_%H%M%S  # Timestamp format for filenames

# HTML reports
html_theme = default       # HTML report theme
include_charts = true      # Include vulnerability charts
responsive_design = true   # Mobile-friendly reports
syntax_highlighting = true # Code syntax highlighting

# PDF reports
pdf_engine = pdfkit        # PDF generation engine
pdf_options = {"page-size": "A4", "orientation": "Portrait"}
include_cover_page = true  # Include PDF cover page
include_toc = true         # Include table of contents

# JSON reports
pretty_json = true         # Format JSON output
include_raw_responses = false  # Include raw HTTP responses
compress_output = false    # Compress JSON output
```

### Logging Configuration

Configure logging behavior:

```ini
[logging]
# Basic logging
level = INFO               # Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
format = %(asctime)s - %(name)s - %(levelname)s - %(message)s
file = logs/webstrike.log  # Log file path
console_output = true      # Also log to console

# Log rotation
max_size = 10485760        # Maximum log file size (10MB)
backup_count = 5           # Number of backup files to keep
rotation_interval = midnight  # Rotation interval

# Module-specific logging
[logging_modules]
engine.scanner = DEBUG     # Scanner module log level
engine.crawler = INFO      # Crawler module log level
engine.modules.sqli = DEBUG  # SQLi module log level
reports.generator = WARNING   # Report generator log level
```

### Performance Configuration

Optimize performance settings:

```ini
[performance]
# Connection pooling
connection_pool_size = 100    # Connection pool size
connection_pool_maxsize = 200 # Maximum pool size
pool_timeout = 10            # Pool connection timeout
pool_recycle = 3600          # Pool connection recycling

# Timeouts
read_timeout = 30            # Read timeout
connect_timeout = 10         # Connection timeout
total_timeout = 60           # Total request timeout

# Memory management
max_memory_usage = 1073741824  # Maximum memory usage (1GB)
garbage_collection = true      # Enable garbage collection
cache_size = 10000            # Response cache size

# Concurrency
max_workers = 10             # Maximum worker threads
semaphore_limit = 50         # Concurrent request limit
async_batch_size = 20        # Async operation batch size
```

### Proxy Configuration

Configure proxy settings:

```ini
[proxy]
# HTTP/HTTPS proxies
http_proxy = http://proxy.example.com:8080
https_proxy = https://proxy.example.com:8080
socks_proxy = socks5://proxy.example.com:1080

# Proxy authentication
proxy_username = proxyuser
proxy_password = proxypass

# Proxy bypass
no_proxy = localhost,127.0.0.1,*.internal.com

# Proxy validation
verify_proxy = true          # Verify proxy connectivity
proxy_timeout = 15          # Proxy connection timeout
```

### WAF Detection and Evasion

Configure WAF handling:

```ini
[waf]
# Detection settings
enable_detection = true      # Enable WAF detection
detection_payloads = <script>,SELECT,UNION  # WAF detection payloads
confidence_threshold = 0.7   # Detection confidence threshold

# Evasion techniques
evasion_techniques = true    # Enable evasion methods
random_user_agents = true    # Randomize User-Agent headers
request_randomization = true # Randomize request patterns
header_injection = false     # Inject bypass headers

# User agent rotation
user_agent_list = Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36,Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36
rotate_interval = 10         # Rotate every N requests

# Rate limiting evasion
adaptive_delay = true        # Adapt delay based on responses
jitter_factor = 0.2         # Add randomness to delays
backoff_multiplier = 2       # Exponential backoff multiplier
```

## Advanced Configuration

### Custom Configuration Classes

Create custom configuration managers:

```python
# config/custom_config.py

import configparser
import os
from typing import Dict, Any

class WebStrikeConfig:
    def __init__(self, config_file: str = 'config.ini'):
        self.config = configparser.ConfigParser()
        self.config_file = config_file
        self.load_defaults()
        self.load_from_file()
        self.load_from_env()
    
    def load_defaults(self):
        """Load default configuration values"""
        defaults = {
            'scanning': {
                'max_depth': '3',
                'max_urls': '100',
                'threads': '5',
                'delay': '1.0',
                'timeout': '30'
            },
            'authentication': {
                'timeout': '30',
                'max_login_attempts': '3',
                'session_timeout': '3600'
            },
            'reporting': {
                'include_evidence': 'true',
                'risk_scoring': 'true',
                'output_dir': 'reports/output'
            }
        }
        
        for section, options in defaults.items():
            if not self.config.has_section(section):
                self.config.add_section(section)
            for key, value in options.items():
                self.config.set(section, key, value)
    
    def load_from_file(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
    
    def load_from_env(self):
        """Load configuration from environment variables"""
        env_mapping = {
            'WEBSTRIKE_MAX_DEPTH': ('scanning', 'max_depth'),
            'WEBSTRIKE_MAX_URLS': ('scanning', 'max_urls'),
            'WEBSTRIKE_THREADS': ('scanning', 'threads'),
            'WEBSTRIKE_DELAY': ('scanning', 'delay'),
            'WEBSTRIKE_LOG_LEVEL': ('logging', 'level'),
            'WEBSTRIKE_OUTPUT_DIR': ('reporting', 'output_dir')
        }
        
        for env_var, (section, option) in env_mapping.items():
            if env_var in os.environ:
                if not self.config.has_section(section):
                    self.config.add_section(section)
                self.config.set(section, option, os.environ[env_var])
    
    def get(self, section: str, option: str, fallback: str = None) -> str:
        """Get configuration value"""
        return self.config.get(section, option, fallback=fallback)
    
    def getint(self, section: str, option: str, fallback: int = None) -> int:
        """Get integer configuration value"""
        return self.config.getint(section, option, fallback=fallback)
    
    def getfloat(self, section: str, option: str, fallback: float = None) -> float:
        """Get float configuration value"""
        return self.config.getfloat(section, option, fallback=fallback)
    
    def getboolean(self, section: str, option: str, fallback: bool = None) -> bool:
        """Get boolean configuration value"""
        return self.config.getboolean(section, option, fallback=fallback)
    
    def set(self, section: str, option: str, value: str):
        """Set configuration value"""
        if not self.config.has_section(section):
            self.config.add_section(section)
        self.config.set(section, option, value)
    
    def save(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            self.config.write(f)
    
    def to_dict(self) -> Dict[str, Dict[str, Any]]:
        """Convert configuration to dictionary"""
        result = {}
        for section in self.config.sections():
            result[section] = dict(self.config.items(section))
        return result
```

### Environment-Specific Configurations

Create different configurations for different environments:

```ini
# config/development.ini
[scanning]
max_depth = 2
max_urls = 50
threads = 3
delay = 0.5

[logging]
level = DEBUG
console_output = true

[modules]
enabled_modules = sqli,xss
```

```ini
# config/production.ini
[scanning]
max_depth = 5
max_urls = 1000
threads = 10
delay = 2.0

[logging]
level = WARNING
console_output = false
file = /var/log/webstrike/production.log

[modules]
enabled_modules = sqli,xss,csrf,headers,file_upload
```

```ini
# config/testing.ini
[scanning]
max_depth = 1
max_urls = 10
threads = 1
delay = 0.1

[logging]
level = DEBUG
console_output = true

[modules]
enabled_modules = headers
```

### Configuration Validation

Implement configuration validation:

```python
# config/validator.py

import re
from typing import List, Dict, Any

class ConfigValidator:
    def __init__(self):
        self.validation_rules = {
            'scanning': {
                'max_depth': {'type': int, 'min': 1, 'max': 10},
                'max_urls': {'type': int, 'min': 1, 'max': 10000},
                'threads': {'type': int, 'min': 1, 'max': 50},
                'delay': {'type': float, 'min': 0.0, 'max': 10.0},
                'timeout': {'type': int, 'min': 5, 'max': 300}
            },
            'authentication': {
                'timeout': {'type': int, 'min': 10, 'max': 300},
                'max_login_attempts': {'type': int, 'min': 1, 'max': 10},
                'session_timeout': {'type': int, 'min': 300, 'max': 86400}
            },
            'reporting': {
                'max_evidence_length': {'type': int, 'min': 100, 'max': 10000},
                'output_dir': {'type': str, 'pattern': r'^[a-zA-Z0-9_/.-]+$'}
            }
        }
    
    def validate_config(self, config: Dict[str, Dict[str, Any]]) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []
        
        for section, options in config.items():
            if section in self.validation_rules:
                section_rules = self.validation_rules[section]
                
                for option, value in options.items():
                    if option in section_rules:
                        rule = section_rules[option]
                        error = self._validate_option(section, option, value, rule)
                        if error:
                            errors.append(error)
        
        return errors
    
    def _validate_option(self, section: str, option: str, value: Any, rule: Dict) -> str:
        """Validate single configuration option"""
        # Type validation
        expected_type = rule.get('type')
        if expected_type:
            try:
                if expected_type == int:
                    value = int(value)
                elif expected_type == float:
                    value = float(value)
                elif expected_type == bool:
                    value = str(value).lower() in ['true', '1', 'yes', 'on']
            except ValueError:
                return f"[{section}] {option}: Invalid type, expected {expected_type.__name__}"
        
        # Range validation
        if 'min' in rule and value < rule['min']:
            return f"[{section}] {option}: Value {value} below minimum {rule['min']}"
        
        if 'max' in rule and value > rule['max']:
            return f"[{section}] {option}: Value {value} above maximum {rule['max']}"
        
        # Pattern validation
        if 'pattern' in rule and expected_type == str:
            if not re.match(rule['pattern'], str(value)):
                return f"[{section}] {option}: Value doesn't match required pattern"
        
        return None
```

## Configuration Examples

### Enterprise Configuration

```ini
# Enterprise production configuration
[scanning]
max_depth = 5
max_urls = 5000
threads = 20
delay = 1.0
timeout = 60
verify_ssl = true
follow_redirects = true
user_agent = EnterpriseScan/1.0

[authentication]
timeout = 60
max_login_attempts = 5
session_timeout = 7200
persistent_cookies = true

[modules]
enabled_modules = sqli,xss,csrf,headers,file_upload
parallel_execution = true

[module_sqli]
timeout = 90
max_payloads = 200
time_threshold = 10

[reporting]
include_evidence = true
max_evidence_length = 2000
risk_scoring = true
include_recommendations = true
output_dir = /opt/webstrike/reports

[logging]
level = INFO
file = /var/log/webstrike/enterprise.log
max_size = 52428800
backup_count = 10

[performance]
connection_pool_size = 200
max_workers = 25
max_memory_usage = 2147483648

[proxy]
http_proxy = http://corporate-proxy:8080
https_proxy = http://corporate-proxy:8080
proxy_username = scanuser
proxy_password = ${PROXY_PASSWORD}
```

### Quick Testing Configuration

```ini
# Quick testing configuration
[scanning]
max_depth = 1
max_urls = 20
threads = 3
delay = 0.2
timeout = 15

[modules]
enabled_modules = headers,csrf

[reporting]
include_evidence = false
output_dir = temp_reports

[logging]
level = WARNING
console_output = true
```

### Stealth Scanning Configuration

```ini
# Stealth scanning configuration
[scanning]
max_depth = 3
max_urls = 100
threads = 2
delay = 3.0
timeout = 45
user_agent = Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36

[waf]
enable_detection = true
evasion_techniques = true
random_user_agents = true
request_randomization = true
adaptive_delay = true
jitter_factor = 0.3

[performance]
connection_pool_size = 10
max_workers = 2
```

## Configuration Best Practices

### 1. Security Considerations

- Store sensitive values in environment variables
- Use encrypted configuration files for production
- Implement configuration validation
- Regular security reviews of settings

### 2. Performance Optimization

- Adjust thread counts based on target capacity
- Configure appropriate timeouts
- Monitor memory usage and adjust limits
- Use connection pooling efficiently

### 3. Environment Management

- Separate configurations for dev/test/prod
- Use configuration inheritance
- Implement configuration version control
- Document configuration changes

### 4. Monitoring and Logging

- Configure appropriate log levels
- Implement log rotation
- Monitor configuration changes
- Set up alerting for configuration errors

This comprehensive configuration guide should help you optimize WebStrike for your specific use cases and environments!
