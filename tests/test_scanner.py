"""
Test cases for WebStrike Scanner
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from engine.scanner import WebStrikeScanner
from engine.session_manager import SessionManager

class TestWebStrikeScanner:
    """Test cases for WebStrikeScanner class"""
    
    def test_scanner_initialization(self):
        """Test scanner initialization"""
        scanner = WebStrikeScanner("https://example.com")
        
        assert scanner.target_url == "https://example.com"
        assert scanner.max_depth == 3
        assert scanner.max_urls == 100
        assert scanner.delay == 1.0
        assert scanner.threads == 5
        assert set(scanner.modules) == {'sqli', 'xss', 'csrf', 'headers', 'file_upload'}
        
        # Check scanners are initialized
        assert 'sqli' in scanner.scanners
        assert 'xss' in scanner.scanners
        assert 'csrf' in scanner.scanners
        assert 'headers' in scanner.scanners
        assert 'file_upload' in scanner.scanners
    
    def test_scanner_custom_config(self):
        """Test scanner with custom configuration"""
        config = {
            'max_depth': 5,
            'max_urls': 200,
            'delay': 0.5,
            'threads': 10,
            'modules': ['sqli', 'xss']
        }
        
        scanner = WebStrikeScanner("https://example.com", config)
        
        assert scanner.max_depth == 5
        assert scanner.max_urls == 200
        assert scanner.delay == 0.5
        assert scanner.threads == 10
        assert scanner.modules == ['sqli', 'xss']
    
    def test_setup_authentication_form(self):
        """Test form-based authentication setup"""
        scanner = WebStrikeScanner("https://example.com")
        
        auth_config = {
            'type': 'form',
            'login_url': 'https://example.com/login',
            'username': 'admin',
            'password': 'password'
        }
        
        with patch.object(scanner.session_manager, 'login_form') as mock_login:
            mock_login.return_value = True
            scanner.setup_authentication(auth_config)
            mock_login.assert_called_once_with(
                'https://example.com/login', 'admin', 'password', 'username', 'password'
            )
    
    def test_setup_authentication_bearer(self):
        """Test bearer token authentication setup"""
        scanner = WebStrikeScanner("https://example.com")
        
        auth_config = {
            'type': 'bearer',
            'token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...'
        }
        
        with patch.object(scanner.session_manager, 'set_bearer_token') as mock_token:
            scanner.setup_authentication(auth_config)
            mock_token.assert_called_once_with('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...')
    
    def test_setup_authentication_api_key(self):
        """Test API key authentication setup"""
        scanner = WebStrikeScanner("https://example.com")
        
        auth_config = {
            'type': 'api_key',
            'api_key': 'secret-api-key-123',
            'header_name': 'X-API-Key'
        }
        
        with patch.object(scanner.session_manager, 'set_api_key') as mock_api_key:
            scanner.setup_authentication(auth_config)
            mock_api_key.assert_called_once_with('secret-api-key-123', 'X-API-Key')
    
    def test_setup_authentication_cookies(self):
        """Test cookie-based authentication setup"""
        scanner = WebStrikeScanner("https://example.com")
        
        auth_config = {
            'type': 'cookies',
            'cookies': {'session_id': '12345', 'user_token': 'abcdef'}
        }
        
        with patch.object(scanner.session_manager, 'set_cookies') as mock_cookies:
            scanner.setup_authentication(auth_config)
            mock_cookies.assert_called_once_with({'session_id': '12345', 'user_token': 'abcdef'})
    
    def test_set_custom_headers(self):
        """Test setting custom headers"""
        scanner = WebStrikeScanner("https://example.com")
        
        headers = {'User-Agent': 'Custom Agent', 'X-Test': 'value'}
        
        with patch.object(scanner.session_manager, 'set_custom_headers') as mock_headers:
            scanner.set_custom_headers(headers)
            mock_headers.assert_called_once_with(headers)
    
    def test_set_proxy(self):
        """Test setting proxy"""
        scanner = WebStrikeScanner("https://example.com")
        
        proxy_url = "http://proxy.example.com:8080"
        
        with patch.object(scanner.session_manager, 'set_proxy') as mock_proxy:
            scanner.set_proxy(proxy_url)
            mock_proxy.assert_called_once_with(proxy_url)
    
    def test_export_results_json(self):
        """Test exporting results in JSON format"""
        scanner = WebStrikeScanner("https://example.com")
        
        # Set up some test results
        scanner.scan_results = {
            'target': 'https://example.com',
            'vulnerabilities': [
                {'type': 'XSS', 'severity': 'High'},
                {'type': 'SQLi', 'severity': 'Critical'}
            ],
            'summary': {'total_vulnerabilities': 2}
        }
        
        json_output = scanner.export_results('json')
        
        assert '"target": "https://example.com"' in json_output
        assert '"type": "XSS"' in json_output
        assert '"type": "SQLi"' in json_output
    
    def test_export_results_invalid_format(self):
        """Test exporting results with invalid format"""
        scanner = WebStrikeScanner("https://example.com")
        
        with pytest.raises(ValueError, match="Unsupported export format"):
            scanner.export_results('xml')
    
    def test_generate_summary(self):
        """Test summary generation"""
        scanner = WebStrikeScanner("https://example.com")
        
        # Set up test data
        scanner.scan_results = {
            'vulnerabilities': [
                {'type': 'XSS', 'severity': 'High'},
                {'type': 'SQLi', 'severity': 'Critical'},
                {'type': 'CSRF', 'severity': 'Medium'},
                {'type': 'XSS', 'severity': 'Low'}
            ],
            'crawl_results': {
                'all_urls': ['url1', 'url2', 'url3'],
                'forms': [{'form1': 'data'}, {'form2': 'data'}]
            }
        }
        scanner.modules = ['sqli', 'xss', 'csrf']
        
        scanner._generate_summary()
        
        summary = scanner.scan_results['summary']
        
        assert summary['total_vulnerabilities'] == 4
        assert summary['severity_distribution'] == {
            'Critical': 1, 'High': 1, 'Medium': 1, 'Low': 1
        }
        assert summary['vulnerability_types'] == {
            'XSS': 2, 'SQLi': 1, 'CSRF': 1
        }
        assert summary['urls_scanned'] == 3
        assert summary['forms_scanned'] == 2
        assert summary['modules_used'] == ['sqli', 'xss', 'csrf']
    
    @patch('engine.scanner.detect_waf')
    @patch('requests.Session.get')
    async def test_detect_waf(self, mock_get, mock_detect_waf):
        """Test WAF detection"""
        scanner = WebStrikeScanner("https://example.com")
        
        # Mock response
        mock_response = Mock()
        mock_response.headers = {'Server': 'cloudflare'}
        mock_response.text = 'CloudFlare protection'
        mock_get.return_value = mock_response
        
        # Mock WAF detection
        mock_detect_waf.return_value = 'cloudflare'
        
        result = await scanner._detect_waf()
        
        assert result['detected'] == True
        assert result['waf_type'] == 'cloudflare'
        assert result['confidence'] == 'High'
    
    def test_close(self):
        """Test scanner cleanup"""
        scanner = WebStrikeScanner("https://example.com")
        
        with patch.object(scanner.session_manager, 'close') as mock_close:
            scanner.close()
            mock_close.assert_called_once()

class TestScannerIntegration:
    """Integration tests for scanner components"""
    
    def test_scanner_with_session_manager(self):
        """Test scanner integration with session manager"""
        scanner = WebStrikeScanner("https://example.com")
        
        assert isinstance(scanner.session_manager, SessionManager)
        assert scanner.session_manager.session is not None
    
    @patch('engine.modules.sqli.SQLiScanner')
    @patch('engine.modules.xss.XSSScanner')
    def test_scanner_module_initialization(self, mock_xss, mock_sqli):
        """Test that all scanner modules are properly initialized"""
        scanner = WebStrikeScanner("https://example.com")
        
        # Verify modules are created with session
        session = scanner.session_manager.get_session()
        
        assert 'sqli' in scanner.scanners
        assert 'xss' in scanner.scanners
        assert 'csrf' in scanner.scanners
        assert 'headers' in scanner.scanners
        assert 'file_upload' in scanner.scanners

if __name__ == '__main__':
    pytest.main([__file__])
