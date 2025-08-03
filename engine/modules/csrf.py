"""
CSRF (Cross-Site Request Forgery) Detection Module
"""
import re
from typing import Dict, List, Optional
import requests
from bs4 import BeautifulSoup
from ..utils import setup_logging

logger = setup_logging()

class CSRFScanner:
    """CSRF vulnerability scanner"""
    
    def __init__(self, session: requests.Session):
        self.session = session
    
    def scan_form(self, form_data: Dict) -> Dict:
        """Scan a form for CSRF vulnerabilities"""
        vulnerabilities = []
        
        form_url = form_data['url']
        method = form_data.get('method', 'get').lower()
        inputs = form_data.get('inputs', [])
        
        # Only check POST forms for CSRF
        if method != 'post':
            return {
                'form_url': form_url,
                'method': method,
                'vulnerabilities': [],
                'vulnerability_count': 0,
                'reason': 'Only POST forms are checked for CSRF'
            }
        
        # Check for CSRF tokens
        csrf_protection = self._check_csrf_tokens(inputs)
        
        if not csrf_protection['has_token']:
            # Test if form can be submitted without CSRF token
            vuln = self._test_csrf_bypass(form_data)
            if vuln:
                vulnerabilities.append(vuln)
        else:
            # Check token quality
            token_quality = self._analyze_token_quality(csrf_protection['tokens'])
            if token_quality['weak']:
                vulnerabilities.append({
                    'type': 'Weak CSRF Token',
                    'evidence': token_quality['issues'],
                    'severity': 'Medium',
                    'confidence': 'Medium',
                    'tokens_found': csrf_protection['tokens']
                })
        
        # Check for SameSite cookie attribute
        samesite_issues = self._check_samesite_cookies(form_url)
        if samesite_issues:
            vulnerabilities.extend(samesite_issues)
        
        return {
            'form_url': form_url,
            'method': method,
            'csrf_protection': csrf_protection,
            'vulnerabilities': vulnerabilities,
            'vulnerability_count': len(vulnerabilities)
        }
    
    def _check_csrf_tokens(self, inputs: List[Dict]) -> Dict:
        """Check for CSRF tokens in form inputs"""
        csrf_patterns = [
            r'csrf',
            r'xsrf',
            r'token',
            r'authenticity',
            r'_token',
            r'csrfmiddlewaretoken',
            r'__requestverificationtoken'
        ]
        
        tokens_found = []
        
        for input_field in inputs:
            field_name = input_field.get('name', '').lower()
            field_type = input_field.get('type', '').lower()
            field_value = input_field.get('value', '')
            
            # Check if field name matches CSRF patterns
            for pattern in csrf_patterns:
                if re.search(pattern, field_name, re.IGNORECASE):
                    tokens_found.append({
                        'name': input_field.get('name', ''),
                        'type': field_type,
                        'value': field_value,
                        'hidden': field_type == 'hidden'
                    })
                    break
        
        return {
            'has_token': len(tokens_found) > 0,
            'token_count': len(tokens_found),
            'tokens': tokens_found
        }
    
    def _analyze_token_quality(self, tokens: List[Dict]) -> Dict:
        """Analyze the quality of CSRF tokens"""
        issues = []
        weak = False
        
        for token in tokens:
            token_value = token.get('value', '')
            
            # Check token length
            if len(token_value) < 16:
                issues.append(f"Token '{token['name']}' is too short ({len(token_value)} chars)")
                weak = True
            
            # Check if token is predictable
            if self._is_predictable_token(token_value):
                issues.append(f"Token '{token['name']}' appears to be predictable")
                weak = True
            
            # Check if token is not hidden
            if not token.get('hidden', False):
                issues.append(f"Token '{token['name']}' is not a hidden field")
                weak = True
        
        return {
            'weak': weak,
            'issues': issues
        }
    
    def _is_predictable_token(self, token_value: str) -> bool:
        """Check if token appears to be predictable"""
        if not token_value:
            return True
        
        # Check for simple patterns
        predictable_patterns = [
            r'^[0-9]+$',  # Only numbers
            r'^[a-f0-9]{8,}$',  # Simple hex (might be timestamp)
            r'^(test|admin|user)',  # Starts with common words
            r'^(.)\1{5,}',  # Repeated characters
        ]
        
        for pattern in predictable_patterns:
            if re.match(pattern, token_value, re.IGNORECASE):
                return True
        
        # Check for low entropy (too many repeated chars)
        unique_chars = len(set(token_value.lower()))
        if len(token_value) > 10 and unique_chars < len(token_value) * 0.3:
            return True
        
        return False
    
    def _test_csrf_bypass(self, form_data: Dict) -> Optional[Dict]:
        """Test if form can be submitted without CSRF protection"""
        try:
            form_url = form_data['url']
            action = form_data.get('action', '')
            method = form_data.get('method', 'post')
            
            # Determine target URL
            if action:
                if action.startswith('http'):
                    target_url = action
                else:
                    from urllib.parse import urljoin
                    target_url = urljoin(form_url, action)
            else:
                target_url = form_url
            
            # Prepare form data
            submit_data = {}
            for input_field in form_data.get('inputs', []):
                field_name = input_field.get('name', '')
                field_type = input_field.get('type', '')
                field_value = input_field.get('value', '')
                
                if field_type != 'submit' and field_name:
                    if field_type in ['text', 'email', 'password']:
                        submit_data[field_name] = 'test_value'
                    else:
                        submit_data[field_name] = field_value
            
            # Submit form without referrer (simulate CSRF attack)
            headers = {
                'Referer': 'http://evil-site.com',
                'Origin': 'http://evil-site.com'
            }
            
            response = self.session.post(target_url, data=submit_data, headers=headers)
            
            # Check if submission was successful
            if response.status_code in [200, 201, 302]:
                # Look for success indicators
                success_indicators = [
                    'success', 'saved', 'updated', 'created', 'submitted',
                    'thank you', 'confirmation', 'redirect'
                ]
                
                response_text = response.text.lower()
                for indicator in success_indicators:
                    if indicator in response_text:
                        return {
                            'type': 'CSRF Vulnerability',
                            'evidence': f'Form submitted successfully without CSRF token (status: {response.status_code})',
                            'severity': 'High',
                            'confidence': 'High',
                            'target_url': target_url,
                            'method': method
                        }
        
        except Exception as e:
            logger.error(f"Error testing CSRF bypass: {str(e)}")
        
        return None
    
    def _check_samesite_cookies(self, url: str) -> List[Dict]:
        """Check for missing SameSite cookie attributes"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url)
            
            # Check Set-Cookie headers
            for cookie_header in response.headers.get_list('Set-Cookie') or []:
                cookie_name = cookie_header.split('=')[0]
                
                # Check if SameSite attribute is missing
                if 'samesite' not in cookie_header.lower():
                    vulnerabilities.append({
                        'type': 'Missing SameSite Cookie Attribute',
                        'evidence': f'Cookie "{cookie_name}" lacks SameSite attribute',
                        'severity': 'Medium',
                        'confidence': 'High',
                        'cookie_header': cookie_header,
                        'recommendation': 'Add SameSite=Strict or SameSite=Lax attribute'
                    })
                
                # Check for SameSite=None without Secure
                elif 'samesite=none' in cookie_header.lower() and 'secure' not in cookie_header.lower():
                    vulnerabilities.append({
                        'type': 'Insecure SameSite=None Cookie',
                        'evidence': f'Cookie "{cookie_name}" uses SameSite=None without Secure flag',
                        'severity': 'Medium',
                        'confidence': 'High',
                        'cookie_header': cookie_header,
                        'recommendation': 'Add Secure flag when using SameSite=None'
                    })
        
        except Exception as e:
            logger.error(f"Error checking SameSite cookies: {str(e)}")
        
        return vulnerabilities
    
    def generate_csrf_poc(self, form_data: Dict, vulnerability: Dict) -> str:
        """Generate a CSRF proof-of-concept HTML"""
        form_url = form_data['url']
        action = form_data.get('action', '')
        method = form_data.get('method', 'post')
        
        if action:
            if action.startswith('http'):
                target_url = action
            else:
                from urllib.parse import urljoin
                target_url = urljoin(form_url, action)
        else:
            target_url = form_url
        
        # Generate form fields
        form_fields = []
        for input_field in form_data.get('inputs', []):
            field_name = input_field.get('name', '')
            field_type = input_field.get('type', '')
            field_value = input_field.get('value', '')
            
            if field_type != 'submit' and field_name:
                if field_type in ['text', 'email', 'password']:
                    form_fields.append(f'    <input type="{field_type}" name="{field_name}" value="malicious_value">')
                else:
                    form_fields.append(f'    <input type="{field_type}" name="{field_name}" value="{field_value}">')
        
        poc_html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>CSRF Proof of Concept</title>
</head>
<body>
    <h1>CSRF Attack Demonstration</h1>
    <p>This form will be auto-submitted when the page loads.</p>
    
    <form id="csrfForm" action="{target_url}" method="{method}">
{chr(10).join(form_fields)}
        <input type="submit" value="Submit">
    </form>
    
    <script>
        // Auto-submit the form
        document.getElementById('csrfForm').submit();
    </script>
</body>
</html>
"""
        
        return poc_html
