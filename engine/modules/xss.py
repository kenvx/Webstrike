"""
Cross-Site Scripting (XSS) Detection Module
"""
import re
from typing import List, Dict, Optional
import requests
from urllib.parse import urljoin, quote
from ..utils import setup_logging, generate_payloads_variations

logger = setup_logging()

class XSSScanner:
    """Cross-Site Scripting vulnerability scanner"""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.payloads = self._load_payloads()
        self.reflection_patterns = [
            r'<script[^>]*>.*?alert.*?</script>',
            r'javascript:.*?alert',
            r'on\w+\s*=.*?alert',
            r'<img[^>]*onerror.*?alert',
            r'<svg[^>]*onload.*?alert',
            r'<iframe[^>]*src.*?javascript',
            r'<input[^>]*onfocus.*?alert'
        ]
    
    def _load_payloads(self) -> List[str]:
        """Load XSS payloads"""
        try:
            with open('engine/payloads/xss.txt', 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            logger.warning("XSS payloads file not found, using default payloads")
            return [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "'><script>alert('XSS')</script>",
                "\"><script>alert('XSS')</script>"
            ]
    
    def scan_parameter(self, url: str, param_name: str, param_value: str) -> Dict:
        """Scan a specific parameter for XSS"""
        vulnerabilities = []
        
        for payload in self.payloads[:15]:  # Limit for performance
            try:
                # Test reflected XSS
                vuln = self._test_reflected_xss(url, param_name, param_value, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                
                # Test DOM-based XSS patterns
                vuln = self._test_dom_xss(url, param_name, param_value, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                    
            except Exception as e:
                logger.error(f"Error testing XSS payload {payload}: {str(e)}")
                continue
        
        return {
            'parameter': param_name,
            'url': url,
            'vulnerabilities': vulnerabilities,
            'total_tests': len(self.payloads[:15]),
            'vulnerability_count': len(vulnerabilities)
        }
    
    def _test_reflected_xss(self, url: str, param_name: str, param_value: str, payload: str) -> Optional[Dict]:
        """Test for reflected XSS"""
        try:
            # Generate unique identifier for this test
            unique_id = f"XSSTEST{hash(payload) % 10000}"
            test_payload = payload.replace("XSS", unique_id).replace("alert('XSS')", f"alert('{unique_id}')")
            
            # Test with GET method
            params = {param_name: test_payload}
            response = self.session.get(url, params=params)
            
            # Check if payload is reflected in response
            if unique_id in response.text:
                # Check if it's within dangerous context
                dangerous_context = self._check_dangerous_context(response.text, test_payload, unique_id)
                if dangerous_context:
                    return {
                        'type': 'Reflected XSS',
                        'payload': test_payload,
                        'parameter': param_name,
                        'evidence': dangerous_context,
                        'severity': 'High',
                        'confidence': 'High',
                        'method': 'GET'
                    }
            
            # Test with POST method
            post_data = {param_name: test_payload}
            response = self.session.post(url, data=post_data)
            
            if unique_id in response.text:
                dangerous_context = self._check_dangerous_context(response.text, test_payload, unique_id)
                if dangerous_context:
                    return {
                        'type': 'Reflected XSS',
                        'payload': test_payload,
                        'parameter': param_name,
                        'evidence': dangerous_context,
                        'severity': 'High',
                        'confidence': 'High',
                        'method': 'POST'
                    }
                    
        except Exception as e:
            logger.error(f"Error in reflected XSS test: {str(e)}")
        
        return None
    
    def _test_dom_xss(self, url: str, param_name: str, param_value: str, payload: str) -> Optional[Dict]:
        """Test for DOM-based XSS patterns"""
        try:
            # Look for dangerous JavaScript patterns that could lead to DOM XSS
            response = self.session.get(url)
            
            dom_patterns = [
                r'document\.write\s*\(',
                r'innerHTML\s*=',
                r'outerHTML\s*=',
                r'document\.location',
                r'window\.location',
                r'eval\s*\(',
                r'setTimeout\s*\(',
                r'setInterval\s*\('
            ]
            
            dangerous_patterns_found = []
            for pattern in dom_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    dangerous_patterns_found.append(pattern)
            
            # Check if URL parameters are used in JavaScript
            if param_name in response.text and dangerous_patterns_found:
                return {
                    'type': 'Potential DOM-based XSS',
                    'payload': payload,
                    'parameter': param_name,
                    'evidence': f'Parameter used in JavaScript with patterns: {", ".join(dangerous_patterns_found)}',
                    'severity': 'Medium',
                    'confidence': 'Low',
                    'method': 'Analysis'
                }
                
        except Exception as e:
            logger.error(f"Error in DOM XSS test: {str(e)}")
        
        return None
    
    def _check_dangerous_context(self, response_text: str, payload: str, unique_id: str) -> Optional[str]:
        """Check if reflected content is in a dangerous context"""
        # Find the position of our unique identifier
        id_position = response_text.find(unique_id)
        if id_position == -1:
            return None
        
        # Get context around the reflection
        start = max(0, id_position - 100)
        end = min(len(response_text), id_position + 100)
        context = response_text[start:end]
        
        # Check for dangerous contexts
        dangerous_contexts = [
            # Direct script execution
            (r'<script[^>]*>.*?' + re.escape(unique_id), 'Script tag context'),
            # Event handlers
            (r'on\w+\s*=\s*["\']?[^"\']*' + re.escape(unique_id), 'Event handler context'),
            # JavaScript URI
            (r'javascript:[^"\']*' + re.escape(unique_id), 'JavaScript URI context'),
            # Unquoted attribute
            (r'<\w+[^>]*\s+\w+=' + re.escape(unique_id), 'Unquoted attribute context'),
            # Style context
            (r'style\s*=\s*["\']?[^"\']*' + re.escape(unique_id), 'CSS context')
        ]
        
        for pattern, description in dangerous_contexts:
            if re.search(pattern, context, re.IGNORECASE):
                return f"{description}: {context.strip()}"
        
        # Check if it's just reflected in HTML content (less dangerous)
        if unique_id in context:
            return f"HTML content reflection: {context.strip()}"
        
        return None
    
    def scan_form(self, form_data: Dict) -> Dict:
        """Scan a form for XSS vulnerabilities"""
        form_url = form_data['url']
        action = form_data.get('action', '')
        method = form_data.get('method', 'post').lower()
        
        if action:
            target_url = urljoin(form_url, action)
        else:
            target_url = form_url
        
        vulnerabilities = []
        
        for input_field in form_data.get('inputs', []):
            field_name = input_field.get('name', '')
            field_value = input_field.get('value', 'test')
            field_type = input_field.get('type', 'text')
            
            # Skip non-text inputs and submit buttons
            if field_name and field_type not in ['submit', 'button', 'hidden']:
                logger.info(f"Testing XSS in form field: {field_name} at {target_url}")
                result = self.scan_parameter(target_url, field_name, field_value)
                if result['vulnerabilities']:
                    vulnerabilities.extend(result['vulnerabilities'])
        
        return {
            'form_url': form_url,
            'target_url': target_url,
            'method': method,
            'vulnerabilities': vulnerabilities,
            'fields_tested': len([f for f in form_data.get('inputs', []) 
                                if f.get('type', '') not in ['submit', 'button', 'hidden']]),
            'vulnerability_count': len(vulnerabilities)
        }
    
    def test_stored_xss(self, url: str, form_data: Dict, check_urls: List[str]) -> Dict:
        """Test for stored XSS by submitting payload and checking reflection on other pages"""
        vulnerabilities = []
        
        # Generate unique payload for stored XSS testing
        unique_payload = f"<script>alert('STORED_XSS_{hash(url) % 10000}')</script>"
        
        try:
            # Submit payload through form
            target_url = urljoin(form_data['url'], form_data.get('action', ''))
            
            submit_data = {}
            for input_field in form_data.get('inputs', []):
                field_name = input_field.get('name', '')
                field_type = input_field.get('type', 'text')
                
                if field_type == 'submit':
                    continue
                elif field_type in ['text', 'textarea', 'email']:
                    submit_data[field_name] = unique_payload
                else:
                    submit_data[field_name] = input_field.get('value', '')
            
            # Submit the form
            self.session.post(target_url, data=submit_data)
            
            # Check for reflection on specified URLs
            for check_url in check_urls:
                response = self.session.get(check_url)
                if unique_payload in response.text:
                    vulnerabilities.append({
                        'type': 'Stored XSS',
                        'payload': unique_payload,
                        'submission_url': target_url,
                        'reflection_url': check_url,
                        'evidence': f'Payload reflected on {check_url}',
                        'severity': 'Critical',
                        'confidence': 'High'
                    })
        
        except Exception as e:
            logger.error(f"Error testing stored XSS: {str(e)}")
        
        return {
            'form_url': form_data['url'],
            'vulnerabilities': vulnerabilities,
            'vulnerability_count': len(vulnerabilities)
        }
