"""
Test cases for vulnerability detection modules
"""
import pytest
from unittest.mock import Mock, MagicMock, patch
import requests
from engine.modules.sqli import SQLiScanner
from engine.modules.xss import XSSScanner
from engine.modules.csrf import CSRFScanner

class TestSQLiScanner:
    """Test cases for SQL Injection scanner"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mock_session = Mock(spec=requests.Session)
        self.scanner = SQLiScanner(self.mock_session)
    
    def test_load_payloads_from_file(self):
        """Test loading payloads from file"""
        with patch('builtins.open', mock_open_payloads()):
            scanner = SQLiScanner(Mock())
            assert len(scanner.payloads) > 0
            assert "' OR '1'='1" in scanner.payloads
    
    def test_load_payloads_fallback(self):
        """Test fallback payloads when file not found"""
        with patch('builtins.open', side_effect=FileNotFoundError):
            scanner = SQLiScanner(Mock())
            assert len(scanner.payloads) > 0
            assert "' OR '1'='1" in scanner.payloads
    
    def test_error_based_detection(self):
        """Test error-based SQL injection detection"""
        # Mock response with SQL error
        mock_response = Mock()
        mock_response.text = "MySQL syntax error near '1'='1'"
        mock_response.status_code = 200
        self.mock_session.post.return_value = mock_response
        
        result = self.scanner._test_error_based(
            "https://example.com/test", "id", "1", "' OR '1'='1"
        )
        
        assert result is not None
        assert result['type'] == 'Error-based SQL Injection'
        assert result['severity'] == 'High'
        assert result['confidence'] == 'High'
    
    def test_time_based_detection(self):
        """Test time-based SQL injection detection"""
        # Mock responses with different timing
        def mock_post(*args, **kwargs):
            response = Mock()
            response.status_code = 200
            if 'SLEEP' in str(kwargs.get('data', {})):
                # Simulate delay for payload
                import time
                time.sleep(0.01)  # Small delay for testing
            return response
        
        self.mock_session.post.side_effect = mock_post
        
        with patch('time.time') as mock_time:
            # Simulate timing difference
            mock_time.side_effect = [0, 1, 2, 6]  # Normal: 1s, Payload: 4s difference
            
            result = self.scanner._test_time_based(
                "https://example.com/test", "id", "1", "'; SELECT SLEEP(5)--"
            )
            
            assert result is not None
            assert result['type'] == 'Time-based SQL Injection'
    
    def test_boolean_based_detection(self):
        """Test boolean-based SQL injection detection"""
        def mock_post(*args, **kwargs):
            response = Mock()
            response.status_code = 200
            data = kwargs.get('data', {})
            
            # Different responses for true/false conditions
            if "'1'='1" in str(data):
                response.text = "Welcome! You have 5 messages."
            else:
                response.text = "Welcome! You have 0 messages."
            
            return response
        
        self.mock_session.post.side_effect = mock_post
        
        result = self.scanner._test_boolean_based(
            "https://example.com/test", "id", "1", "' OR '1'='1"
        )
        
        assert result is not None
        assert result['type'] == 'Boolean-based SQL Injection'
    
    def test_scan_form(self):
        """Test scanning a form for SQL injection"""
        form_data = {
            'url': 'https://example.com/login',
            'action': '/authenticate',
            'method': 'post',
            'inputs': [
                {'name': 'username', 'type': 'text', 'value': ''},
                {'name': 'password', 'type': 'password', 'value': ''},
                {'name': 'submit', 'type': 'submit', 'value': 'Login'}
            ]
        }
        
        # Mock scan_parameter method
        with patch.object(self.scanner, 'scan_parameter') as mock_scan:
            mock_scan.return_value = {
                'vulnerabilities': [
                    {'type': 'Error-based SQL Injection', 'severity': 'High'}
                ]
            }
            
            result = self.scanner.scan_form(form_data)
            
            assert result['form_url'] == 'https://example.com/login'
            assert result['method'] == 'post'
            assert len(result['vulnerabilities']) > 0
            assert mock_scan.call_count == 2  # username and password fields

class TestXSSScanner:
    """Test cases for XSS scanner"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mock_session = Mock(spec=requests.Session)
        self.scanner = XSSScanner(self.mock_session)
    
    def test_load_payloads_from_file(self):
        """Test loading XSS payloads from file"""
        with patch('builtins.open', mock_open_xss_payloads()):
            scanner = XSSScanner(Mock())
            assert len(scanner.payloads) > 0
            assert "<script>alert('XSS')</script>" in scanner.payloads
    
    def test_reflected_xss_detection(self):
        """Test reflected XSS detection"""
        payload = "<script>alert('XSSTEST1234')</script>"
        
        mock_response = Mock()
        mock_response.text = f"<html><body>Hello {payload}</body></html>"
        self.mock_session.get.return_value = mock_response
        
        result = self.scanner._test_reflected_xss(
            "https://example.com/search", "q", "test", payload
        )
        
        assert result is not None
        assert result['type'] == 'Reflected XSS'
        assert result['severity'] == 'High'
    
    def test_check_dangerous_context(self):
        """Test checking dangerous reflection contexts"""
        response_text = '<script>var x = "XSSTEST1234"; alert(x);</script>'
        
        context = self.scanner._check_dangerous_context(
            response_text, "<script>alert('XSSTEST1234')</script>", "XSSTEST1234"
        )
        
        assert context is not None
        assert "Script tag context" in context
    
    def test_dom_xss_detection(self):
        """Test DOM-based XSS pattern detection"""
        mock_response = Mock()
        mock_response.text = """
        <script>
            var userInput = location.search.split('q=')[1];
            document.write(userInput);
        </script>
        """
        self.mock_session.get.return_value = mock_response
        
        result = self.scanner._test_dom_xss(
            "https://example.com/search", "q", "test", "<script>alert('XSS')</script>"
        )
        
        assert result is not None
        assert result['type'] == 'Potential DOM-based XSS'
    
    def test_scan_form(self):
        """Test scanning a form for XSS"""
        form_data = {
            'url': 'https://example.com/comment',
            'action': '/submit',
            'method': 'post',
            'inputs': [
                {'name': 'comment', 'type': 'textarea', 'value': ''},
                {'name': 'name', 'type': 'text', 'value': ''},
                {'name': 'submit', 'type': 'submit', 'value': 'Submit'}
            ]
        }
        
        with patch.object(self.scanner, 'scan_parameter') as mock_scan:
            mock_scan.return_value = {
                'vulnerabilities': [
                    {'type': 'Reflected XSS', 'severity': 'High'}
                ]
            }
            
            result = self.scanner.scan_form(form_data)
            
            assert result['form_url'] == 'https://example.com/comment'
            assert len(result['vulnerabilities']) > 0
            assert mock_scan.call_count == 2  # comment and name fields

class TestCSRFScanner:
    """Test cases for CSRF scanner"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mock_session = Mock(spec=requests.Session)
        self.scanner = CSRFScanner(self.mock_session)
    
    def test_check_csrf_tokens_present(self):
        """Test CSRF token detection when present"""
        inputs = [
            {'name': 'username', 'type': 'text', 'value': ''},
            {'name': 'csrf_token', 'type': 'hidden', 'value': 'abc123'},
            {'name': 'submit', 'type': 'submit', 'value': 'Login'}
        ]
        
        result = self.scanner._check_csrf_tokens(inputs)
        
        assert result['has_token'] == True
        assert result['token_count'] == 1
        assert len(result['tokens']) == 1
        assert result['tokens'][0]['name'] == 'csrf_token'
    
    def test_check_csrf_tokens_missing(self):
        """Test CSRF token detection when missing"""
        inputs = [
            {'name': 'username', 'type': 'text', 'value': ''},
            {'name': 'password', 'type': 'password', 'value': ''},
            {'name': 'submit', 'type': 'submit', 'value': 'Login'}
        ]
        
        result = self.scanner._check_csrf_tokens(inputs)
        
        assert result['has_token'] == False
        assert result['token_count'] == 0
        assert len(result['tokens']) == 0
    
    def test_analyze_token_quality_weak(self):
        """Test analysis of weak CSRF tokens"""
        tokens = [
            {'name': 'csrf', 'value': '123', 'hidden': False},  # Too short, not hidden
            {'name': 'token', 'value': 'aaaaaaaaaaaaaaaa', 'hidden': True}  # Predictable
        ]
        
        result = self.scanner._analyze_token_quality(tokens)
        
        assert result['weak'] == True
        assert len(result['issues']) > 0
    
    def test_analyze_token_quality_strong(self):
        """Test analysis of strong CSRF tokens"""
        tokens = [
            {'name': 'csrf_token', 'value': 'a8f7d9e2b1c4f6h9j3k8l7m2n5p9q1r4', 'hidden': True}
        ]
        
        result = self.scanner._analyze_token_quality(tokens)
        
        assert result['weak'] == False
        assert len(result['issues']) == 0
    
    def test_is_predictable_token(self):
        """Test predictable token detection"""
        # Test predictable patterns
        assert self.scanner._is_predictable_token('12345678') == True
        assert self.scanner._is_predictable_token('aaaaaaaa') == True
        assert self.scanner._is_predictable_token('test123') == True
        
        # Test strong token
        assert self.scanner._is_predictable_token('a8f7d9e2b1c4f6h9j3k8l7m2n5p9q1r4') == False
    
    def test_scan_form_post_no_csrf(self):
        """Test scanning POST form without CSRF protection"""
        form_data = {
            'url': 'https://example.com/transfer',
            'method': 'post',
            'inputs': [
                {'name': 'amount', 'type': 'text', 'value': ''},
                {'name': 'to_account', 'type': 'text', 'value': ''},
                {'name': 'submit', 'type': 'submit', 'value': 'Transfer'}
            ]
        }
        
        with patch.object(self.scanner, '_test_csrf_bypass') as mock_test:
            mock_test.return_value = {
                'type': 'CSRF Vulnerability',
                'severity': 'High'
            }
            
            result = self.scanner.scan_form(form_data)
            
            assert len(result['vulnerabilities']) > 0
            assert result['vulnerabilities'][0]['type'] == 'CSRF Vulnerability'
    
    def test_scan_form_get_method(self):
        """Test scanning GET form (should be skipped)"""
        form_data = {
            'url': 'https://example.com/search',
            'method': 'get',
            'inputs': [
                {'name': 'q', 'type': 'text', 'value': ''},
                {'name': 'submit', 'type': 'submit', 'value': 'Search'}
            ]
        }
        
        result = self.scanner.scan_form(form_data)
        
        assert len(result['vulnerabilities']) == 0
        assert 'Only POST forms are checked' in result['reason']

# Helper functions for mocking file operations
def mock_open_payloads():
    """Mock open for SQLi payloads file"""
    content = """' OR '1'='1
' OR '1'='1' --
" OR "1"="1
'; WAITFOR DELAY '00:00:05'--
'; SELECT SLEEP(5)--"""
    return patch('builtins.open', mock_open(read_data=content))

def mock_open_xss_payloads():
    """Mock open for XSS payloads file"""
    content = """<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
javascript:alert('XSS')"""
    return patch('builtins.open', mock_open(read_data=content))

def mock_open(read_data=''):
    """Helper function to create mock open"""
    m = MagicMock()
    m.return_value.__enter__.return_value.read.return_value = read_data
    m.return_value.__enter__.return_value.__iter__ = lambda self: iter(read_data.splitlines())
    return m

if __name__ == '__main__':
    pytest.main([__file__])
