"""
Utility functions for WebStrike scanner
"""
import re
import urllib.parse
from typing import List, Dict, Optional
import logging

def setup_logging(level: str = "INFO") -> logging.Logger:
    """Setup logging configuration"""
    logger = logging.getLogger("webstrike")
    logger.setLevel(getattr(logging, level.upper()))
    
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger

def normalize_url(url: str) -> str:
    """Normalize URL format"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.rstrip('/')

def is_valid_url(url: str) -> bool:
    """Validate URL format"""
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc
    except Exception:
        return ""

def is_same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs belong to the same domain"""
    return extract_domain(url1) == extract_domain(url2)

def clean_html(html_content: str) -> str:
    """Remove HTML tags and return clean text"""
    clean = re.compile('<.*?>')
    return re.sub(clean, '', html_content)

def extract_forms(soup) -> List[Dict]:
    """Extract forms from BeautifulSoup object"""
    forms = []
    for form in soup.find_all('form'):
        form_data = {
            'action': form.get('action', ''),
            'method': form.get('method', 'get').lower(),
            'inputs': []
        }
        
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_data = {
                'name': input_tag.get('name', ''),
                'type': input_tag.get('type', 'text'),
                'value': input_tag.get('value', '')
            }
            form_data['inputs'].append(input_data)
        
        forms.append(form_data)
    
    return forms

def extract_links(soup, base_url: str) -> List[str]:
    """Extract all links from BeautifulSoup object"""
    links = set()
    
    for link in soup.find_all(['a', 'link']):
        href = link.get('href')
        if href:
            absolute_url = urllib.parse.urljoin(base_url, href)
            if is_valid_url(absolute_url) and is_same_domain(base_url, absolute_url):
                links.add(absolute_url)
    
    return list(links)

def generate_payloads_variations(payload: str, url: str) -> List[str]:
    """Generate payload variations for testing"""
    variations = [payload]
    
    # URL encoded version
    variations.append(urllib.parse.quote(payload))
    
    # Double URL encoded
    variations.append(urllib.parse.quote(urllib.parse.quote(payload)))
    
    # HTML entity encoded
    html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
    variations.append(html_encoded)
    
    return variations

def parse_response_time(response) -> float:
    """Extract response time from request response"""
    try:
        return response.elapsed.total_seconds()
    except AttributeError:
        return 0.0

def detect_waf(response_headers: Dict[str, str], response_text: str) -> Optional[str]:
    """Detect Web Application Firewall"""
    waf_signatures = {
        'cloudflare': ['cf-ray', 'cloudflare'],
        'akamai': ['akamai'],
        'incapsula': ['incap_ses', 'visid_incap'],
        'sucuri': ['sucuri'],
        'aws': ['awselb', 'awsalb']
    }
    
    headers_str = ' '.join(response_headers.keys()).lower()
    response_lower = response_text.lower()
    
    for waf_name, signatures in waf_signatures.items():
        for signature in signatures:
            if signature in headers_str or signature in response_lower:
                return waf_name
    
    return None
