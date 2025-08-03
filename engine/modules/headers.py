"""
HTTP Security Headers Analysis Module
"""
from typing import Dict, List
import requests
from ..utils import setup_logging

logger = setup_logging()

class HeadersScanner:
    """HTTP Security Headers vulnerability scanner"""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.security_headers = {
            'strict-transport-security': {
                'required': True,
                'severity': 'High',
                'description': 'HTTP Strict Transport Security (HSTS)',
                'recommendation': 'Add Strict-Transport-Security header to enforce HTTPS'
            },
            'x-frame-options': {
                'required': True,
                'severity': 'Medium',
                'description': 'X-Frame-Options protection against clickjacking',
                'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN'
            },
            'x-content-type-options': {
                'required': True,
                'severity': 'Medium',
                'description': 'X-Content-Type-Options prevents MIME sniffing',
                'recommendation': 'Add X-Content-Type-Options: nosniff'
            },
            'x-xss-protection': {
                'required': True,
                'severity': 'Low',
                'description': 'X-XSS-Protection enables browser XSS filter',
                'recommendation': 'Add X-XSS-Protection: 1; mode=block'
            },
            'content-security-policy': {
                'required': True,
                'severity': 'High',
                'description': 'Content Security Policy prevents XSS and injection attacks',
                'recommendation': 'Add Content-Security-Policy with appropriate directives'
            },
            'referrer-policy': {
                'required': False,
                'severity': 'Low',
                'description': 'Referrer Policy controls referrer information',
                'recommendation': 'Add Referrer-Policy: strict-origin-when-cross-origin'
            },
            'permissions-policy': {
                'required': False,
                'severity': 'Low',
                'description': 'Permissions Policy controls browser features',
                'recommendation': 'Add Permissions-Policy to restrict unnecessary features'
            }
        }
    
    def scan_headers(self, url: str) -> Dict:
        """Scan HTTP headers for security misconfigurations"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Check for missing security headers
            for header_name, header_info in self.security_headers.items():
                if header_name not in headers:
                    if header_info['required']:
                        vulnerabilities.append({
                            'type': 'Missing Security Header',
                            'header': header_name,
                            'description': header_info['description'],
                            'severity': header_info['severity'],
                            'confidence': 'High',
                            'recommendation': header_info['recommendation']
                        })
                else:
                    # Analyze header values
                    header_value = headers[header_name]
                    analysis = self._analyze_header_value(header_name, header_value)
                    if analysis:
                        vulnerabilities.extend(analysis)
            
            # Check for information disclosure headers
            info_disclosure = self._check_information_disclosure(headers)
            vulnerabilities.extend(info_disclosure)
            
            # Check for insecure header values
            insecure_headers = self._check_insecure_headers(headers)
            vulnerabilities.extend(insecure_headers)
            
        except Exception as e:
            logger.error(f"Error scanning headers for {url}: {str(e)}")
            return {
                'url': url,
                'error': str(e),
                'vulnerabilities': [],
                'vulnerability_count': 0
            }
        
        return {
            'url': url,
            'headers_analyzed': len(headers),
            'vulnerabilities': vulnerabilities,
            'vulnerability_count': len(vulnerabilities),
            'headers': dict(response.headers)
        }
    
    def _analyze_header_value(self, header_name: str, header_value: str) -> List[Dict]:
        """Analyze specific header values for issues"""
        issues = []
        
        if header_name == 'strict-transport-security':
            issues.extend(self._analyze_hsts(header_value))
        elif header_name == 'content-security-policy':
            issues.extend(self._analyze_csp(header_value))
        elif header_name == 'x-frame-options':
            issues.extend(self._analyze_frame_options(header_value))
        elif header_name == 'set-cookie':
            issues.extend(self._analyze_cookies(header_value))
        
        return issues
    
    def _analyze_hsts(self, hsts_value: str) -> List[Dict]:
        """Analyze HSTS header value"""
        issues = []
        
        # Check max-age
        if 'max-age=' not in hsts_value.lower():
            issues.append({
                'type': 'Incomplete HSTS Header',
                'header': 'strict-transport-security',
                'evidence': 'Missing max-age directive',
                'severity': 'Medium',
                'confidence': 'High',
                'recommendation': 'Add max-age directive with appropriate value (e.g., max-age=31536000)'
            })
        else:
            # Extract max-age value
            try:
                max_age_part = [part for part in hsts_value.split(';') if 'max-age=' in part.lower()][0]
                max_age = int(max_age_part.split('=')[1].strip())
                
                # Check if max-age is too short (less than 6 months)
                if max_age < 15768000:  # 6 months in seconds
                    issues.append({
                        'type': 'Weak HSTS Configuration',
                        'header': 'strict-transport-security',
                        'evidence': f'max-age too short: {max_age} seconds',
                        'severity': 'Low',
                        'confidence': 'High',
                        'recommendation': 'Use longer max-age value (at least 15768000 for 6 months)'
                    })
            except (IndexError, ValueError):
                issues.append({
                    'type': 'Invalid HSTS Header',
                    'header': 'strict-transport-security',
                    'evidence': 'Invalid max-age value',
                    'severity': 'Medium',
                    'confidence': 'High',
                    'recommendation': 'Fix max-age directive format'
                })
        
        # Check for includeSubDomains
        if 'includesubdomains' not in hsts_value.lower():
            issues.append({
                'type': 'Incomplete HSTS Header',
                'header': 'strict-transport-security',
                'evidence': 'Missing includeSubDomains directive',
                'severity': 'Low',
                'confidence': 'Medium',
                'recommendation': 'Consider adding includeSubDomains directive'
            })
        
        return issues
    
    def _analyze_csp(self, csp_value: str) -> List[Dict]:
        """Analyze Content Security Policy header"""
        issues = []
        
        # Check for unsafe directives
        unsafe_patterns = [
            ('unsafe-inline', 'Allows inline JavaScript/CSS'),
            ('unsafe-eval', 'Allows eval() function'),
            ('data:', 'Allows data: URIs'),
            ('*', 'Allows any source (wildcard)')
        ]
        
        for pattern, description in unsafe_patterns:
            if pattern in csp_value.lower():
                issues.append({
                    'type': 'Weak CSP Configuration',
                    'header': 'content-security-policy',
                    'evidence': f'Contains {pattern} - {description}',
                    'severity': 'Medium',
                    'confidence': 'High',
                    'recommendation': f'Remove or restrict {pattern} directive'
                })
        
        # Check for missing important directives
        important_directives = ['default-src', 'script-src', 'object-src']
        for directive in important_directives:
            if directive not in csp_value.lower():
                issues.append({
                    'type': 'Incomplete CSP Header',
                    'header': 'content-security-policy',
                    'evidence': f'Missing {directive} directive',
                    'severity': 'Medium',
                    'confidence': 'High',
                    'recommendation': f'Add {directive} directive'
                })
        
        return issues
    
    def _analyze_frame_options(self, frame_options_value: str) -> List[Dict]:
        """Analyze X-Frame-Options header"""
        issues = []
        
        valid_values = ['deny', 'sameorigin']
        if frame_options_value.lower() not in valid_values:
            if frame_options_value.lower().startswith('allow-from'):
                issues.append({
                    'type': 'Deprecated Frame Options',
                    'header': 'x-frame-options',
                    'evidence': 'ALLOW-FROM is deprecated',
                    'severity': 'Low',
                    'confidence': 'High',
                    'recommendation': 'Use CSP frame-ancestors directive instead'
                })
            else:
                issues.append({
                    'type': 'Invalid Frame Options',
                    'header': 'x-frame-options',
                    'evidence': f'Invalid value: {frame_options_value}',
                    'severity': 'Medium',
                    'confidence': 'High',
                    'recommendation': 'Use DENY or SAMEORIGIN'
                })
        
        return issues
    
    def _check_information_disclosure(self, headers: Dict[str, str]) -> List[Dict]:
        """Check for information disclosure in headers"""
        issues = []
        
        disclosure_headers = {
            'server': 'Server information disclosure',
            'x-powered-by': 'Technology stack disclosure',
            'x-aspnet-version': 'ASP.NET version disclosure',
            'x-aspnetmvc-version': 'ASP.NET MVC version disclosure',
            'x-generator': 'Generator information disclosure'
        }
        
        for header, description in disclosure_headers.items():
            if header in headers:
                issues.append({
                    'type': 'Information Disclosure',
                    'header': header,
                    'evidence': f'{header}: {headers[header]}',
                    'description': description,
                    'severity': 'Low',
                    'confidence': 'High',
                    'recommendation': f'Remove or modify {header} header'
                })
        
        return issues
    
    def _check_insecure_headers(self, headers: Dict[str, str]) -> List[Dict]:
        """Check for insecure header configurations"""
        issues = []
        
        # Check for insecure cookies in Set-Cookie headers
        if 'set-cookie' in headers:
            cookie_issues = self._analyze_cookies(headers['set-cookie'])
            issues.extend(cookie_issues)
        
        # Check for CORS misconfigurations
        if 'access-control-allow-origin' in headers:
            cors_value = headers['access-control-allow-origin']
            if cors_value == '*':
                issues.append({
                    'type': 'Insecure CORS Configuration',
                    'header': 'access-control-allow-origin',
                    'evidence': 'Wildcard (*) allows any origin',
                    'severity': 'Medium',
                    'confidence': 'High',
                    'recommendation': 'Specify allowed origins explicitly'
                })
        
        return issues
    
    def _analyze_cookies(self, cookie_header: str) -> List[Dict]:
        """Analyze cookie security attributes"""
        issues = []
        
        # Parse cookie name
        cookie_name = cookie_header.split('=')[0] if '=' in cookie_header else 'unknown'
        
        # Check for missing security flags
        if 'secure' not in cookie_header.lower():
            issues.append({
                'type': 'Insecure Cookie',
                'header': 'set-cookie',
                'evidence': f'Cookie "{cookie_name}" missing Secure flag',
                'severity': 'Medium',
                'confidence': 'High',
                'recommendation': 'Add Secure flag to cookies'
            })
        
        if 'httponly' not in cookie_header.lower():
            issues.append({
                'type': 'Insecure Cookie',
                'header': 'set-cookie',
                'evidence': f'Cookie "{cookie_name}" missing HttpOnly flag',
                'severity': 'Medium',
                'confidence': 'High',
                'recommendation': 'Add HttpOnly flag to cookies'
            })
        
        if 'samesite' not in cookie_header.lower():
            issues.append({
                'type': 'Insecure Cookie',
                'header': 'set-cookie',
                'evidence': f'Cookie "{cookie_name}" missing SameSite attribute',
                'severity': 'Medium',
                'confidence': 'High',
                'recommendation': 'Add SameSite attribute to cookies'
            })
        
        return issues
