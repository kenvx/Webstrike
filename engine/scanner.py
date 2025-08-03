"""
Main Scanner Engine - Orchestrates all vulnerability scanning modules
"""
import asyncio
import json
import time
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse
import threading
from concurrent.futures import ThreadPoolExecutor

from .crawler import WebCrawler
from .session_manager import SessionManager
from .modules.sqli import SQLiScanner
from .modules.xss import XSSScanner
from .modules.csrf import CSRFScanner
from .modules.headers import HeadersScanner
from .modules.file_upload import FileUploadScanner
from .utils import setup_logging, normalize_url, is_valid_url, detect_waf

logger = setup_logging()

class WebStrikeScanner:
    """Main vulnerability scanner engine"""
    
    def __init__(self, target_url: str, config: Dict = None):
        self.target_url = normalize_url(target_url)
        self.config = config or {}
        self.session_manager = SessionManager()
        self.scan_results = {
            'target': self.target_url,
            'start_time': None,
            'end_time': None,
            'duration': 0,
            'scan_config': self.config,
            'crawl_results': {},
            'vulnerabilities': [],
            'summary': {}
        }
        
        # Scanner modules
        self.scanners = {}
        self._initialize_scanners()
        
        # Configuration
        self.max_depth = self.config.get('max_depth', 3)
        self.max_urls = self.config.get('max_urls', 100)
        self.delay = self.config.get('delay', 1.0)
        self.threads = self.config.get('threads', 5)
        self.modules = self.config.get('modules', ['sqli', 'xss', 'csrf', 'headers', 'file_upload'])
        
    def _initialize_scanners(self):
        """Initialize all scanner modules"""
        session = self.session_manager.get_session()
        self.scanners = {
            'sqli': SQLiScanner(session),
            'xss': XSSScanner(session),
            'csrf': CSRFScanner(session),
            'headers': HeadersScanner(session),
            'file_upload': FileUploadScanner(session)
        }
        logger.info("Scanner modules initialized")
    
    async def run_full_scan(self) -> Dict:
        """Run complete vulnerability scan"""
        logger.info(f"Starting full scan of {self.target_url}")
        self.scan_results['start_time'] = datetime.now().isoformat()
        start_time = time.time()
        
        try:
            # Phase 1: Crawling
            logger.info("Phase 1: Web crawling")
            crawl_results = await self._crawl_target()
            self.scan_results['crawl_results'] = crawl_results
            
            # Phase 2: WAF Detection
            logger.info("Phase 2: WAF detection")
            waf_info = await self._detect_waf()
            self.scan_results['waf_detection'] = waf_info
            
            # Phase 3: Vulnerability scanning
            logger.info("Phase 3: Vulnerability scanning")
            vulnerabilities = await self._scan_vulnerabilities(crawl_results)
            self.scan_results['vulnerabilities'] = vulnerabilities
            
            # Phase 4: Generate summary
            self._generate_summary()
            
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            self.scan_results['error'] = str(e)
        
        finally:
            self.scan_results['end_time'] = datetime.now().isoformat()
            self.scan_results['duration'] = time.time() - start_time
            logger.info(f"Scan completed in {self.scan_results['duration']:.2f} seconds")
        
        return self.scan_results
    
    async def _crawl_target(self) -> Dict:
        """Crawl the target website"""
        async with WebCrawler(
            max_depth=self.max_depth,
            max_urls=self.max_urls,
            delay=self.delay
        ) as crawler:
            results = await crawler.crawl_website(self.target_url)
            logger.info(f"Crawling complete: {results['total_urls']} URLs discovered")
            return results
    
    async def _detect_waf(self) -> Dict:
        """Detect Web Application Firewall"""
        try:
            session = self.session_manager.get_session()
            response = session.get(self.target_url)
            
            waf_detected = detect_waf(dict(response.headers), response.text)
            
            return {
                'detected': waf_detected is not None,
                'waf_type': waf_detected,
                'confidence': 'High' if waf_detected else 'N/A'
            }
        except Exception as e:
            logger.error(f"Error detecting WAF: {str(e)}")
            return {'detected': False, 'error': str(e)}
    
    async def _scan_vulnerabilities(self, crawl_results: Dict) -> List[Dict]:
        """Scan for vulnerabilities using enabled modules"""
        all_vulnerabilities = []
        
        # Get URLs and forms from crawl results
        urls = crawl_results.get('all_urls', [self.target_url])
        forms = crawl_results.get('forms', [])
        
        # Run scans with thread pool for better performance
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            tasks = []
            
            # URL-based scans
            for url in urls[:20]:  # Limit URLs for performance
                if 'headers' in self.modules:
                    tasks.append(executor.submit(self._scan_headers, url))
            
            # Form-based scans
            for form in forms:
                if 'sqli' in self.modules:
                    tasks.append(executor.submit(self._scan_sqli_form, form))
                if 'xss' in self.modules:
                    tasks.append(executor.submit(self._scan_xss_form, form))
                if 'csrf' in self.modules:
                    tasks.append(executor.submit(self._scan_csrf_form, form))
                if 'file_upload' in self.modules:
                    tasks.append(executor.submit(self._scan_file_upload_form, form))
            
            # Parameter-based scans
            param_urls = [url for url in urls if '?' in url]
            for url in param_urls[:10]:  # Limit parameter URLs
                if 'sqli' in self.modules:
                    tasks.append(executor.submit(self._scan_sqli_params, url))
                if 'xss' in self.modules:
                    tasks.append(executor.submit(self._scan_xss_params, url))
            
            # Collect results
            for task in tasks:
                try:
                    result = task.result(timeout=30)  # 30 second timeout per task
                    if result and result.get('vulnerabilities'):
                        all_vulnerabilities.extend(result['vulnerabilities'])
                except Exception as e:
                    logger.error(f"Task failed: {str(e)}")
        
        logger.info(f"Found {len(all_vulnerabilities)} vulnerabilities")
        return all_vulnerabilities
    
    def _scan_headers(self, url: str) -> Dict:
        """Scan HTTP headers for security issues"""
        try:
            return self.scanners['headers'].scan_headers(url)
        except Exception as e:
            logger.error(f"Error scanning headers for {url}: {str(e)}")
            return {'vulnerabilities': []}
    
    def _scan_sqli_form(self, form: Dict) -> Dict:
        """Scan form for SQL injection"""
        try:
            return self.scanners['sqli'].scan_form(form)
        except Exception as e:
            logger.error(f"Error scanning SQLi in form: {str(e)}")
            return {'vulnerabilities': []}
    
    def _scan_xss_form(self, form: Dict) -> Dict:
        """Scan form for XSS"""
        try:
            return self.scanners['xss'].scan_form(form)
        except Exception as e:
            logger.error(f"Error scanning XSS in form: {str(e)}")
            return {'vulnerabilities': []}
    
    def _scan_csrf_form(self, form: Dict) -> Dict:
        """Scan form for CSRF"""
        try:
            return self.scanners['csrf'].scan_form(form)
        except Exception as e:
            logger.error(f"Error scanning CSRF in form: {str(e)}")
            return {'vulnerabilities': []}
    
    def _scan_file_upload_form(self, form: Dict) -> Dict:
        """Scan form for file upload vulnerabilities"""
        try:
            return self.scanners['file_upload'].scan_upload_form(form)
        except Exception as e:
            logger.error(f"Error scanning file upload in form: {str(e)}")
            return {'vulnerabilities': []}
    
    def _scan_sqli_params(self, url: str) -> Dict:
        """Scan URL parameters for SQL injection"""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            vulnerabilities = []
            for param_name, param_values in params.items():
                if param_values:
                    result = self.scanners['sqli'].scan_parameter(
                        url, param_name, param_values[0]
                    )
                    vulnerabilities.extend(result.get('vulnerabilities', []))
            
            return {'vulnerabilities': vulnerabilities}
        except Exception as e:
            logger.error(f"Error scanning SQLi params for {url}: {str(e)}")
            return {'vulnerabilities': []}
    
    def _scan_xss_params(self, url: str) -> Dict:
        """Scan URL parameters for XSS"""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            vulnerabilities = []
            for param_name, param_values in params.items():
                if param_values:
                    result = self.scanners['xss'].scan_parameter(
                        url, param_name, param_values[0]
                    )
                    vulnerabilities.extend(result.get('vulnerabilities', []))
            
            return {'vulnerabilities': vulnerabilities}
        except Exception as e:
            logger.error(f"Error scanning XSS params for {url}: {str(e)}")
            return {'vulnerabilities': []}
    
    def _generate_summary(self):
        """Generate scan summary"""
        vulnerabilities = self.scan_results.get('vulnerabilities', [])
        
        # Count by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Count by type
        type_counts = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        self.scan_results['summary'] = {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_distribution': severity_counts,
            'vulnerability_types': type_counts,
            'urls_scanned': len(self.scan_results.get('crawl_results', {}).get('all_urls', [])),
            'forms_scanned': len(self.scan_results.get('crawl_results', {}).get('forms', [])),
            'modules_used': self.modules
        }
    
    def setup_authentication(self, auth_config: Dict):
        """Setup authentication for scanning"""
        auth_type = auth_config.get('type', 'none')
        
        if auth_type == 'form':
            success = self.session_manager.login_form(
                auth_config['login_url'],
                auth_config['username'],
                auth_config['password'],
                auth_config.get('username_field', 'username'),
                auth_config.get('password_field', 'password')
            )
            if success:
                logger.info("Form-based authentication successful")
            else:
                logger.warning("Form-based authentication failed")
        
        elif auth_type == 'bearer':
            self.session_manager.set_bearer_token(auth_config['token'])
            logger.info("Bearer token authentication set")
        
        elif auth_type == 'api_key':
            self.session_manager.set_api_key(
                auth_config['api_key'],
                auth_config.get('header_name', 'X-API-Key')
            )
            logger.info("API key authentication set")
        
        elif auth_type == 'cookies':
            self.session_manager.set_cookies(auth_config['cookies'])
            logger.info("Cookie authentication set")
    
    def set_custom_headers(self, headers: Dict[str, str]):
        """Set custom headers for requests"""
        self.session_manager.set_custom_headers(headers)
    
    def set_proxy(self, proxy_url: str):
        """Set proxy for requests"""
        self.session_manager.set_proxy(proxy_url)
    
    def export_results(self, format: str = 'json') -> str:
        """Export scan results in specified format"""
        if format.lower() == 'json':
            return json.dumps(self.scan_results, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def close(self):
        """Close session and cleanup"""
        self.session_manager.close()
        logger.info("Scanner session closed")
