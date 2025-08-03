# 📚 WebStrike API Documentation

## Overview

WebStrike provides a comprehensive Python API for integrating vulnerability scanning capabilities into your applications. This document covers the core classes, methods, and interfaces.

## Core Classes

### WebStrikeScanner

The main orchestrator class that coordinates all scanning operations.

```python
from engine.scanner import WebStrikeScanner

# Initialize scanner
scanner = WebStrikeScanner(target_url="https://example.com")

# Configure authentication
scanner.setup_authentication(
    auth_type="form",
    login_url="/login",
    username="admin",
    password="password"
)

# Run full scan
results = await scanner.scan()
```

#### Constructor Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `target_url` | str | Target URL to scan | Required |
| `max_depth` | int | Maximum crawling depth | 3 |
| `max_urls` | int | Maximum URLs to crawl | 100 |
| `threads` | int | Number of scanning threads | 5 |
| `delay` | float | Delay between requests (seconds) | 1.0 |

#### Methods

##### `setup_authentication(auth_type, **kwargs)`
Configure authentication for the target application.

**Parameters:**
- `auth_type` (str): Authentication type ("form", "bearer", "api_key", "cookies")
- `**kwargs`: Authentication-specific parameters

**Form Authentication:**
```python
scanner.setup_authentication(
    auth_type="form",
    login_url="/login",
    username="admin",
    password="password"
)
```

**Bearer Token:**
```python
scanner.setup_authentication(
    auth_type="bearer",
    token="eyJhbGciOiJIUzI1NiIs..."
)
```

##### `set_custom_headers(headers)`
Set custom HTTP headers for all requests.

```python
scanner.set_custom_headers({
    "User-Agent": "WebStrike Scanner",
    "X-Custom-Header": "value"
})
```

##### `set_proxy(proxy_url)`
Configure proxy for all requests.

```python
scanner.set_proxy("http://proxy.company.com:8080")
```

##### `async scan(modules=None)`
Execute vulnerability scan with specified modules.

**Parameters:**
- `modules` (list): List of module names to run. If None, runs all modules.

**Returns:** Dictionary containing scan results

```python
# Scan with specific modules
results = await scanner.scan(modules=["sqli", "xss"])

# Scan with all modules
results = await scanner.scan()
```

##### `export_results(results, format, output_file)`
Export scan results to specified format.

```python
scanner.export_results(results, "html", "scan_report.html")
```

---

### WebCrawler

Asynchronous web crawler for URL discovery and form extraction.

```python
from engine.crawler import WebCrawler

# Initialize crawler
crawler = WebCrawler(max_depth=3, max_urls=100, delay=1.0)

# Crawl target
crawl_results = await crawler.crawl(target_url)
```

#### Methods

##### `async crawl(start_url)`
Crawl website starting from the given URL.

**Returns:** Dictionary containing:
- `urls`: List of discovered URLs
- `forms`: List of extracted forms
- `parameters`: Dictionary of URL parameters

##### `extract_parameters(url)`
Extract parameters from URL query string and fragments.

##### `get_forms_by_method(method)`
Filter forms by HTTP method (GET/POST).

##### `get_urls_with_parameters()`
Get URLs that contain parameters for testing.

---

### Vulnerability Scanner Modules

All vulnerability scanner modules inherit from a base interface and provide consistent methods.

#### Base Scanner Interface

```python
class BaseScanner:
    def __init__(self, session_manager):
        self.session = session_manager
        
    async def scan_url(self, url, method="GET", data=None):
        """Scan a single URL for vulnerabilities"""
        pass
        
    async def scan_form(self, form_data):
        """Scan a form for vulnerabilities"""
        pass
```

#### SQL Injection Scanner

```python
from engine.modules.sqli import SQLiScanner

scanner = SQLiScanner(session_manager)

# Scan URL for SQLi
vulnerabilities = await scanner.scan_url(
    url="https://example.com/search",
    method="POST",
    data={"q": "test"}
)
```

**Detection Methods:**
- Error-based injection
- Boolean-based blind injection
- Time-based blind injection

#### XSS Scanner

```python
from engine.modules.xss import XSSScanner

scanner = XSSScanner(session_manager)

# Scan for XSS vulnerabilities
vulnerabilities = await scanner.scan_url(
    url="https://example.com/search",
    method="GET",
    data={"q": "test"}
)
```

**Detection Methods:**
- Reflected XSS
- DOM-based XSS
- Stored XSS detection

#### CSRF Scanner

```python
from engine.modules.csrf import CSRFScanner

scanner = CSRFScanner(session_manager)

# Analyze CSRF protections
vulnerabilities = await scanner.scan_form({
    "action": "/transfer",
    "method": "POST",
    "inputs": [{"name": "amount", "type": "text"}]
})
```

#### Headers Scanner

```python
from engine.modules.headers import HeadersScanner

scanner = HeadersScanner(session_manager)

# Analyze security headers
vulnerabilities = await scanner.scan_url("https://example.com")
```

**Analyzed Headers:**
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection

---

### Session Manager

Handles authentication and session management across requests.

```python
from engine.session_manager import SessionManager

# Initialize session manager
session_manager = SessionManager()

# Form authentication
await session_manager.authenticate_form(
    login_url="https://example.com/login",
    username="admin",
    password="password"
)

# Make authenticated request
response = await session_manager.get("https://example.com/dashboard")
```

#### Methods

##### `authenticate_form(login_url, username, password)`
Perform form-based authentication.

##### `authenticate_bearer(token)`
Set Bearer token for API authentication.

##### `authenticate_api_key(key, header_name)`
Set API key authentication.

##### `authenticate_cookies(cookies)`
Set authentication cookies.

##### `async get(url, **kwargs)`
Make authenticated GET request.

##### `async post(url, data=None, **kwargs)`
Make authenticated POST request.

---

### Report Generator

Generate reports in multiple formats from scan results.

```python
from reports.report_generator import ReportGenerator

generator = ReportGenerator()

# Generate HTML report
generator.generate_html_report(results, "scan_report.html")

# Generate PDF report
generator.generate_pdf_report(results, "scan_report.pdf")

# Generate JSON report
generator.generate_json_report(results, "scan_report.json")
```

---

## Usage Examples

### Basic Scanning

```python
import asyncio
from engine.scanner import WebStrikeScanner

async def basic_scan():
    scanner = WebStrikeScanner("https://example.com")
    results = await scanner.scan()
    scanner.export_results(results, "json", "results.json")
    await scanner.close()

asyncio.run(basic_scan())
```

### Authenticated Scanning

```python
import asyncio
from engine.scanner import WebStrikeScanner

async def authenticated_scan():
    scanner = WebStrikeScanner("https://app.example.com")
    
    # Setup form authentication
    scanner.setup_authentication(
        auth_type="form",
        login_url="/login",
        username="testuser",
        password="testpass"
    )
    
    # Run specific modules
    results = await scanner.scan(modules=["sqli", "xss", "csrf"])
    
    # Generate HTML report
    scanner.export_results(results, "html", "authenticated_scan.html")
    
    await scanner.close()

asyncio.run(authenticated_scan())
```

### Custom Module Integration

```python
from engine.scanner import WebStrikeScanner
from engine.modules.sqli import SQLiScanner

async def custom_scanning():
    scanner = WebStrikeScanner("https://api.example.com")
    
    # Use individual modules
    sqli_scanner = SQLiScanner(scanner.session_manager)
    
    # Scan specific endpoint
    vulnerabilities = await sqli_scanner.scan_url(
        "https://api.example.com/users",
        method="GET",
        data={"id": "1"}
    )
    
    print(f"Found {len(vulnerabilities)} SQL injection vulnerabilities")
    
    await scanner.close()
```

---

## Error Handling

```python
import asyncio
from engine.scanner import WebStrikeScanner
from engine.exceptions import WebStrikeException

async def safe_scanning():
    scanner = None
    try:
        scanner = WebStrikeScanner("https://example.com")
        results = await scanner.scan()
        
    except WebStrikeException as e:
        print(f"WebStrike error: {e}")
        
    except Exception as e:
        print(f"Unexpected error: {e}")
        
    finally:
        if scanner:
            await scanner.close()
```

---

## Configuration

### Environment Variables

- `WEBSTRIKE_USER_AGENT`: Custom User-Agent string
- `WEBSTRIKE_TIMEOUT`: Request timeout in seconds
- `WEBSTRIKE_MAX_RETRIES`: Maximum retry attempts
- `WEBSTRIKE_LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)

### Configuration File

Create `config.ini` in your project root:

```ini
[scanning]
max_depth = 3
max_urls = 100
threads = 5
delay = 1.0

[authentication]
timeout = 30
max_retries = 3

[reporting]
include_evidence = true
risk_scoring = true
```

---

## Thread Safety

WebStrike is designed to be thread-safe when used properly:

- Each `WebStrikeScanner` instance should be used in a single thread
- Session managers maintain their own connection pools
- Multiple scanner instances can run concurrently

```python
import asyncio
from engine.scanner import WebStrikeScanner

async def concurrent_scanning():
    targets = [
        "https://site1.example.com",
        "https://site2.example.com",
        "https://site3.example.com"
    ]
    
    # Create tasks for concurrent scanning
    tasks = []
    for target in targets:
        scanner = WebStrikeScanner(target)
        task = asyncio.create_task(scanner.scan())
        tasks.append(task)
    
    # Wait for all scans to complete
    results = await asyncio.gather(*tasks)
    
    # Process results
    for i, result in enumerate(results):
        print(f"Target {targets[i]}: {len(result.get('vulnerabilities', []))} vulnerabilities")
```

---

## Performance Optimization

### Memory Management

- Use context managers for scanner instances
- Close sessions properly after use
- Configure appropriate connection limits

### Request Optimization

- Adjust delay between requests based on target capacity
- Use connection pooling for better performance
- Implement proper timeout configurations

### Monitoring

```python
import time
from engine.scanner import WebStrikeScanner

async def monitored_scan():
    start_time = time.time()
    
    scanner = WebStrikeScanner("https://example.com")
    results = await scanner.scan()
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"Scan completed in {duration:.2f} seconds")
    print(f"URLs scanned: {results.get('urls_scanned', 0)}")
    print(f"Vulnerabilities found: {len(results.get('vulnerabilities', []))}")
    
    await scanner.close()
```
