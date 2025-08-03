# 🔧 WebStrike Module Development Guide

## Overview

WebStrike's modular architecture allows developers to easily extend the scanner with custom vulnerability detection modules. This guide covers everything you need to know about creating, testing, and integrating new modules.

## Module Architecture

### Base Module Interface

All vulnerability scanner modules inherit from the base scanner interface:

```python
from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseScanner(ABC):
    def __init__(self, session_manager):
        self.session = session_manager
        self.name = self.__class__.__name__
        self.description = ""
        
    @abstractmethod
    async def scan_url(self, url: str, method: str = "GET", data: Dict = None) -> List[Dict]:
        """Scan a URL for vulnerabilities"""
        pass
        
    @abstractmethod
    async def scan_form(self, form_data: Dict) -> List[Dict]:
        """Scan a form for vulnerabilities"""
        pass
        
    def _create_vulnerability(self, vuln_type: str, severity: str, **kwargs) -> Dict:
        """Helper method to create standardized vulnerability objects"""
        return {
            "type": vuln_type,
            "severity": severity,
            "confidence": kwargs.get("confidence", "Medium"),
            "description": kwargs.get("description", ""),
            "evidence": kwargs.get("evidence", ""),
            "recommendation": kwargs.get("recommendation", ""),
            "url": kwargs.get("url", ""),
            "parameter": kwargs.get("parameter", ""),
            "payload": kwargs.get("payload", ""),
            "module": self.name
        }
```

## Creating a New Module

### Step 1: Module Structure

Create a new file in `engine/modules/` directory:

```python
# engine/modules/my_custom_scanner.py

import asyncio
import re
from typing import List, Dict, Any
from ..utils import setup_logging

logger = setup_logging(__name__)

class MyCustomScanner:
    """Custom vulnerability scanner for detecting specific security issues"""
    
    def __init__(self, session_manager):
        self.session = session_manager
        self.name = "my_custom_scanner"
        self.description = "Custom scanner for detecting XYZ vulnerabilities"
        self.payloads = self._load_payloads()
        
    def _load_payloads(self) -> List[str]:
        """Load testing payloads"""
        try:
            with open('engine/payloads/custom.txt', 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.warning("Custom payload file not found, using default payloads")
            return [
                "test_payload_1",
                "test_payload_2",
                "test_payload_3"
            ]
    
    async def scan_url(self, url: str, method: str = "GET", data: Dict = None) -> List[Dict]:
        """Scan URL for custom vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test each payload
            for payload in self.payloads:
                vuln = await self._test_payload(url, method, data, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            logger.error(f"Error scanning URL {url}: {e}")
            
        return vulnerabilities
    
    async def scan_form(self, form_data: Dict) -> List[Dict]:
        """Scan form for custom vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Extract form details
            action = form_data.get('action', '')
            method = form_data.get('method', 'GET').upper()
            inputs = form_data.get('inputs', [])
            
            # Test each form input
            for input_field in inputs:
                vulns = await self._test_form_input(action, method, input_field)
                vulnerabilities.extend(vulns)
                
        except Exception as e:
            logger.error(f"Error scanning form: {e}")
            
        return vulnerabilities
    
    async def _test_payload(self, url: str, method: str, data: Dict, payload: str) -> Dict:
        """Test a specific payload against the URL"""
        try:
            # Modify data with payload
            test_data = data.copy() if data else {}
            
            # Add payload to all parameters
            for key in test_data:
                test_data[key] = payload
                
            # Make request
            if method.upper() == "POST":
                response = await self.session.post(url, data=test_data)
            else:
                response = await self.session.get(url, params=test_data)
                
            # Analyze response for vulnerability
            if await self._analyze_response(response, payload):
                return self._create_vulnerability(
                    vuln_type="Custom Vulnerability",
                    severity="Medium",
                    url=url,
                    payload=payload,
                    evidence=response.text[:200] + "..." if len(response.text) > 200 else response.text,
                    description="Custom vulnerability detected in response",
                    recommendation="Review and validate input handling"
                )
                
        except Exception as e:
            logger.error(f"Error testing payload {payload}: {e}")
            
        return None
    
    async def _test_form_input(self, action: str, method: str, input_field: Dict) -> List[Dict]:
        """Test form input for vulnerabilities"""
        vulnerabilities = []
        input_name = input_field.get('name', '')
        input_type = input_field.get('type', 'text')
        
        # Skip non-testable inputs
        if input_type in ['submit', 'button', 'hidden']:
            return vulnerabilities
            
        try:
            for payload in self.payloads:
                data = {input_name: payload}
                
                # Make request to form action
                if method == "POST":
                    response = await self.session.post(action, data=data)
                else:
                    response = await self.session.get(action, params=data)
                    
                # Check for vulnerability
                if await self._analyze_response(response, payload):
                    vuln = self._create_vulnerability(
                        vuln_type="Form Input Vulnerability",
                        severity="Medium",
                        url=action,
                        parameter=input_name,
                        payload=payload,
                        evidence=f"Vulnerable parameter: {input_name}",
                        description=f"Form input '{input_name}' is vulnerable to custom attack",
                        recommendation="Implement proper input validation and sanitization"
                    )
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            logger.error(f"Error testing form input {input_name}: {e}")
            
        return vulnerabilities
    
    async def _analyze_response(self, response, payload: str) -> bool:
        """Analyze response to determine if vulnerability exists"""
        try:
            # Custom detection logic here
            response_text = response.text.lower()
            
            # Example: Check if payload is reflected in response
            if payload.lower() in response_text:
                return True
                
            # Example: Check for error patterns
            error_patterns = [
                r"error",
                r"exception",
                r"warning",
                r"debug"
            ]
            
            for pattern in error_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
                    
            # Example: Check status codes
            if response.status_code in [500, 502, 503]:
                return True
                
        except Exception as e:
            logger.error(f"Error analyzing response: {e}")
            
        return False
    
    def _create_vulnerability(self, vuln_type: str, severity: str, **kwargs) -> Dict:
        """Create standardized vulnerability object"""
        return {
            "type": vuln_type,
            "severity": severity,
            "confidence": kwargs.get("confidence", "Medium"),
            "description": kwargs.get("description", ""),
            "evidence": kwargs.get("evidence", ""),
            "recommendation": kwargs.get("recommendation", ""),
            "url": kwargs.get("url", ""),
            "parameter": kwargs.get("parameter", ""),
            "payload": kwargs.get("payload", ""),
            "module": self.name,
            "timestamp": kwargs.get("timestamp", ""),
            "risk_score": self._calculate_risk_score(severity)
        }
    
    def _calculate_risk_score(self, severity: str) -> float:
        """Calculate numerical risk score based on severity"""
        severity_scores = {
            "Critical": 10.0,
            "High": 7.5,
            "Medium": 5.0,
            "Low": 2.5,
            "Info": 1.0
        }
        return severity_scores.get(severity, 5.0)
```

### Step 2: Integration with Scanner

Register your module in the main scanner (`engine/scanner.py`):

```python
# Add import
from .modules.my_custom_scanner import MyCustomScanner

# In WebStrikeScanner.__init__()
self.modules = {
    'sqli': SQLiScanner(self.session_manager),
    'xss': XSSScanner(self.session_manager),
    'csrf': CSRFScanner(self.session_manager),
    'headers': HeadersScanner(self.session_manager),
    'file_upload': FileUploadScanner(self.session_manager),
    'my_custom': MyCustomScanner(self.session_manager),  # Add your module
}
```

### Step 3: CLI Integration

Update the CLI to include your module (`cli/webstrike_cli.py`):

```python
# Update module choices in click options
@click.option(
    '-m', '--modules',
    default='all',
    help='Modules to run (comma-separated): sqli,xss,csrf,headers,file_upload,my_custom or "all"'
)
```

## Advanced Module Features

### Payload Management

Create custom payload files for your module:

```python
class PayloadManager:
    def __init__(self, payload_file: str):
        self.payload_file = payload_file
        
    def load_payloads(self) -> List[str]:
        """Load payloads from file with fallback"""
        try:
            with open(self.payload_file, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return payloads
        except FileNotFoundError:
            return self.get_default_payloads()
    
    def get_default_payloads(self) -> List[str]:
        """Return default payloads if file not found"""
        return [
            "default_payload_1",
            "default_payload_2"
        ]
    
    def add_custom_payload(self, payload: str):
        """Add custom payload at runtime"""
        with open(self.payload_file, 'a') as f:
            f.write(f"\n{payload}")
```

### Response Analysis

Implement sophisticated response analysis:

```python
class ResponseAnalyzer:
    def __init__(self):
        self.vulnerability_patterns = {
            'sql_error': [
                r'mysql_fetch_array',
                r'ORA-\d+',
                r'Microsoft.*ODBC.*SQL Server',
                r'PostgreSQL.*ERROR'
            ],
            'xss_reflection': [
                r'<script[^>]*>.*?</script>',
                r'javascript:',
                r'on\w+\s*='
            ],
            'path_traversal': [
                r'root:x:0:0',
                r'\[boot loader\]',
                r'<Directory'
            ]
        }
    
    def analyze_for_patterns(self, response_text: str, pattern_category: str) -> bool:
        """Check response against known vulnerability patterns"""
        patterns = self.vulnerability_patterns.get(pattern_category, [])
        
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False
    
    def calculate_confidence(self, indicators: List[str]) -> str:
        """Calculate confidence based on multiple indicators"""
        confidence_score = len(indicators) * 25  # 25% per indicator
        
        if confidence_score >= 75:
            return "High"
        elif confidence_score >= 50:
            return "Medium"
        else:
            return "Low"
```

### Configuration Management

Support module-specific configuration:

```python
import configparser

class ModuleConfig:
    def __init__(self, config_file: str = 'config.ini'):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        
    def get_module_config(self, module_name: str) -> Dict:
        """Get configuration for specific module"""
        section_name = f'module_{module_name}'
        if self.config.has_section(section_name):
            return dict(self.config.items(section_name))
        return {}
    
    def get_timeout(self, module_name: str, default: int = 30) -> int:
        """Get module-specific timeout"""
        config = self.get_module_config(module_name)
        return int(config.get('timeout', default))
    
    def get_max_payloads(self, module_name: str, default: int = 100) -> int:
        """Get maximum payloads for module"""
        config = self.get_module_config(module_name)
        return int(config.get('max_payloads', default))
```

## Testing Your Module

### Unit Tests

Create comprehensive unit tests for your module:

```python
# tests/test_my_custom_scanner.py

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock
from engine.modules.my_custom_scanner import MyCustomScanner

class TestMyCustomScanner:
    
    @pytest.fixture
    def mock_session(self):
        session = Mock()
        session.get = AsyncMock()
        session.post = AsyncMock()
        return session
    
    @pytest.fixture
    def scanner(self, mock_session):
        return MyCustomScanner(mock_session)
    
    @pytest.mark.asyncio
    async def test_scan_url_with_vulnerability(self, scanner, mock_session):
        """Test URL scanning when vulnerability is present"""
        # Mock response with vulnerability
        mock_response = Mock()
        mock_response.text = "error: test_payload_1 caused an exception"
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response
        
        result = await scanner.scan_url("https://example.com/test")
        
        assert len(result) > 0
        assert result[0]['type'] == "Custom Vulnerability"
        assert result[0]['severity'] == "Medium"
    
    @pytest.mark.asyncio
    async def test_scan_url_no_vulnerability(self, scanner, mock_session):
        """Test URL scanning when no vulnerability is present"""
        # Mock clean response
        mock_response = Mock()
        mock_response.text = "Normal response"
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response
        
        result = await scanner.scan_url("https://example.com/test")
        
        assert len(result) == 0
    
    @pytest.mark.asyncio
    async def test_scan_form(self, scanner, mock_session):
        """Test form scanning functionality"""
        form_data = {
            'action': '/submit',
            'method': 'POST',
            'inputs': [
                {'name': 'username', 'type': 'text'},
                {'name': 'password', 'type': 'password'}
            ]
        }
        
        # Mock vulnerable response
        mock_response = Mock()
        mock_response.text = "test_payload_1 reflected in response"
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response
        
        result = await scanner.scan_form(form_data)
        
        assert len(result) > 0
        assert any(vuln['parameter'] in ['username', 'password'] for vuln in result)
    
    def test_payload_loading(self, scanner):
        """Test payload loading functionality"""
        assert len(scanner.payloads) > 0
        assert all(isinstance(payload, str) for payload in scanner.payloads)
    
    def test_vulnerability_creation(self, scanner):
        """Test vulnerability object creation"""
        vuln = scanner._create_vulnerability(
            vuln_type="Test Vulnerability",
            severity="High",
            url="https://example.com",
            payload="test_payload"
        )
        
        assert vuln['type'] == "Test Vulnerability"
        assert vuln['severity'] == "High"
        assert vuln['url'] == "https://example.com"
        assert vuln['payload'] == "test_payload"
        assert vuln['module'] == scanner.name
```

### Integration Tests

Test module integration with the main scanner:

```python
# tests/test_integration_my_custom.py

import pytest
import asyncio
from engine.scanner import WebStrikeScanner

@pytest.mark.asyncio
async def test_custom_module_integration():
    """Test custom module integration with main scanner"""
    scanner = WebStrikeScanner("https://httpbin.org/get")
    
    # Run scan with custom module
    results = await scanner.scan(modules=['my_custom'])
    
    assert 'vulnerabilities' in results
    assert 'summary' in results
    assert 'my_custom' in results['summary']['modules_used']
    
    await scanner.close()
```

## Best Practices

### 1. Error Handling

Always implement comprehensive error handling:

```python
async def scan_url(self, url: str, method: str = "GET", data: Dict = None) -> List[Dict]:
    vulnerabilities = []
    
    try:
        # Scanning logic here
        pass
    except asyncio.TimeoutError:
        logger.warning(f"Timeout scanning {url}")
    except ConnectionError:
        logger.error(f"Connection error for {url}")
    except Exception as e:
        logger.error(f"Unexpected error scanning {url}: {e}")
    
    return vulnerabilities
```

### 2. Rate Limiting

Respect target server limits:

```python
import asyncio

class RateLimiter:
    def __init__(self, delay: float = 1.0):
        self.delay = delay
        self.last_request = 0
    
    async def wait(self):
        """Wait appropriate time before next request"""
        now = asyncio.get_event_loop().time()
        time_since_last = now - self.last_request
        
        if time_since_last < self.delay:
            await asyncio.sleep(self.delay - time_since_last)
        
        self.last_request = asyncio.get_event_loop().time()
```

### 3. Memory Management

Handle large responses efficiently:

```python
async def _analyze_large_response(self, response) -> bool:
    """Analyze response without loading entire content into memory"""
    # Read response in chunks
    chunk_size = 8192
    pattern = re.compile(r'vulnerability_pattern', re.IGNORECASE)
    
    async for chunk in response.content.iter_chunked(chunk_size):
        chunk_text = chunk.decode('utf-8', errors='ignore')
        if pattern.search(chunk_text):
            return True
    
    return False
```

### 4. Performance Optimization

Implement efficient scanning algorithms:

```python
async def scan_multiple_urls(self, urls: List[str]) -> List[Dict]:
    """Scan multiple URLs concurrently"""
    semaphore = asyncio.Semaphore(5)  # Limit concurrent requests
    
    async def scan_single(url):
        async with semaphore:
            return await self.scan_url(url)
    
    tasks = [scan_single(url) for url in urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Filter out exceptions and flatten results
    vulnerabilities = []
    for result in results:
        if not isinstance(result, Exception) and result:
            vulnerabilities.extend(result)
    
    return vulnerabilities
```

## Module Deployment

### 1. Documentation

Document your module thoroughly:

```python
class MyCustomScanner:
    """
    Custom vulnerability scanner for detecting XYZ vulnerabilities.
    
    This module tests for:
    - Custom vulnerability type A
    - Custom vulnerability type B
    - Custom configuration issues
    
    Configuration:
    - timeout: Request timeout in seconds (default: 30)
    - max_payloads: Maximum payloads to test (default: 100)
    - custom_patterns: Additional detection patterns
    
    Example usage:
        scanner = MyCustomScanner(session_manager)
        vulnerabilities = await scanner.scan_url("https://example.com")
    """
```

### 2. Configuration

Create configuration template:

```ini
# config.ini
[module_my_custom]
timeout = 30
max_payloads = 100
enable_deep_scan = true
custom_patterns = pattern1,pattern2,pattern3
```

### 3. Payload Files

Provide comprehensive payload files:

```text
# engine/payloads/my_custom.txt
# Custom payloads for XYZ vulnerability detection
# Format: one payload per line, # for comments

payload_1
payload_2
payload_3
```

## Contribution Guidelines

When contributing a new module to WebStrike:

1. **Follow naming conventions**: `engine/modules/vulnerability_type.py`
2. **Implement full interface**: Both `scan_url` and `scan_form` methods
3. **Add comprehensive tests**: Unit tests and integration tests
4. **Document thoroughly**: Code comments and usage examples
5. **Include payload files**: Comprehensive test cases
6. **Update CLI**: Add module to available options
7. **Performance test**: Ensure module doesn't impact overall performance

## Example: Complete Module Implementation

Here's a complete example of a Directory Traversal scanner module:

```python
# engine/modules/directory_traversal.py

import asyncio
import re
from typing import List, Dict, Any
from urllib.parse import quote, unquote
from ..utils import setup_logging

logger = setup_logging(__name__)

class DirectoryTraversalScanner:
    """Scanner for detecting directory traversal vulnerabilities"""
    
    def __init__(self, session_manager):
        self.session = session_manager
        self.name = "directory_traversal"
        self.description = "Directory traversal and path manipulation scanner"
        self.payloads = self._load_payloads()
        
    def _load_payloads(self) -> List[str]:
        """Load directory traversal payloads"""
        try:
            with open('engine/payloads/directory_traversal.txt', 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "....//....//....//etc/passwd",
                "../../../etc/passwd%00",
                "..%252f..%252f..%252fetc%252fpasswd"
            ]
    
    async def scan_url(self, url: str, method: str = "GET", data: Dict = None) -> List[Dict]:
        """Scan URL for directory traversal vulnerabilities"""
        vulnerabilities = []
        
        try:
            for payload in self.payloads:
                vuln = await self._test_directory_traversal(url, method, data, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            logger.error(f"Error in directory traversal scan: {e}")
            
        return vulnerabilities
    
    async def scan_form(self, form_data: Dict) -> List[Dict]:
        """Scan form inputs for directory traversal"""
        vulnerabilities = []
        action = form_data.get('action', '')
        method = form_data.get('method', 'GET').upper()
        inputs = form_data.get('inputs', [])
        
        for input_field in inputs:
            if input_field.get('type') in ['file', 'text', 'hidden']:
                vulns = await self._test_form_input(action, method, input_field)
                vulnerabilities.extend(vulns)
                
        return vulnerabilities
    
    async def _test_directory_traversal(self, url: str, method: str, data: Dict, payload: str) -> Dict:
        """Test for directory traversal with specific payload"""
        try:
            test_data = data.copy() if data else {}
            
            # Test payload in all parameters
            for key in test_data:
                original_value = test_data[key]
                test_data[key] = payload
                
                response = await self._make_request(url, method, test_data)
                
                if await self._check_traversal_success(response, payload):
                    return self._create_vulnerability(
                        vuln_type="Directory Traversal",
                        severity="High",
                        url=url,
                        parameter=key,
                        payload=payload,
                        evidence=self._extract_evidence(response.text),
                        description=f"Directory traversal vulnerability in parameter '{key}'",
                        recommendation="Implement proper input validation and path sanitization"
                    )
                
                # Restore original value
                test_data[key] = original_value
                
        except Exception as e:
            logger.error(f"Error testing directory traversal: {e}")
            
        return None
    
    async def _make_request(self, url: str, method: str, data: Dict):
        """Make HTTP request with error handling"""
        if method.upper() == "POST":
            return await self.session.post(url, data=data)
        else:
            return await self.session.get(url, params=data)
    
    async def _check_traversal_success(self, response, payload: str) -> bool:
        """Check if directory traversal was successful"""
        response_text = response.text.lower()
        
        # Unix/Linux indicators
        unix_indicators = [
            "root:x:0:0:",
            "daemon:x:1:1:",
            "bin:x:2:2:",
            "/bin/bash",
            "/bin/sh"
        ]
        
        # Windows indicators
        windows_indicators = [
            "# copyright (c) 1993-2009 microsoft corp.",
            "[boot loader]",
            "c:\\windows",
            "127.0.0.1       localhost"
        ]
        
        # Check for indicators
        all_indicators = unix_indicators + windows_indicators
        for indicator in all_indicators:
            if indicator.lower() in response_text:
                return True
                
        return False
    
    def _extract_evidence(self, response_text: str) -> str:
        """Extract relevant evidence from response"""
        # Look for system file content
        lines = response_text.split('\n')[:10]  # First 10 lines
        evidence_lines = []
        
        for line in lines:
            line = line.strip()
            if any(indicator in line.lower() for indicator in ['root:', 'daemon:', 'copyright', 'localhost']):
                evidence_lines.append(line)
                
        return '\n'.join(evidence_lines) if evidence_lines else response_text[:200]
    
    async def _test_form_input(self, action: str, method: str, input_field: Dict) -> List[Dict]:
        """Test specific form input for directory traversal"""
        vulnerabilities = []
        input_name = input_field.get('name', '')
        
        for payload in self.payloads:
            try:
                data = {input_name: payload}
                response = await self._make_request(action, method, data)
                
                if await self._check_traversal_success(response, payload):
                    vuln = self._create_vulnerability(
                        vuln_type="Directory Traversal",
                        severity="High",
                        url=action,
                        parameter=input_name,
                        payload=payload,
                        evidence=self._extract_evidence(response.text),
                        description=f"Directory traversal in form field '{input_name}'",
                        recommendation="Validate and sanitize file paths"
                    )
                    vulnerabilities.append(vuln)
                    
            except Exception as e:
                logger.error(f"Error testing form input {input_name}: {e}")
                
        return vulnerabilities
    
    def _create_vulnerability(self, vuln_type: str, severity: str, **kwargs) -> Dict:
        """Create standardized vulnerability object"""
        return {
            "type": vuln_type,
            "severity": severity,
            "confidence": kwargs.get("confidence", "High"),
            "description": kwargs.get("description", ""),
            "evidence": kwargs.get("evidence", ""),
            "recommendation": kwargs.get("recommendation", ""),
            "url": kwargs.get("url", ""),
            "parameter": kwargs.get("parameter", ""),
            "payload": kwargs.get("payload", ""),
            "module": self.name,
            "cwe": "CWE-22",  # Directory traversal CWE
            "risk_score": self._calculate_risk_score(severity)
        }
    
    def _calculate_risk_score(self, severity: str) -> float:
        """Calculate risk score based on severity"""
        scores = {"Critical": 10.0, "High": 7.5, "Medium": 5.0, "Low": 2.5}
        return scores.get(severity, 5.0)
```

This comprehensive guide should help you create robust, well-tested vulnerability scanner modules for WebStrike!
