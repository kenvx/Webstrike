"""
Web Crawler for discovering URLs and endpoints
"""
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Set, List, Dict, Optional
import re
import time
from .utils import setup_logging, is_same_domain, extract_forms, extract_links

logger = setup_logging()

class WebCrawler:
    """Asynchronous web crawler for discovering URLs and endpoints"""
    
    def __init__(self, max_depth: int = 3, max_urls: int = 100, delay: float = 1.0):
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.delay = delay
        self.discovered_urls = set()
        self.crawled_urls = set()
        self.forms = []
        self.session = None
        
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=20, limit_per_host=10)
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'WebStrike/1.0 Security Scanner'}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def crawl_url(self, url: str, depth: int = 0) -> Dict:
        """Crawl a single URL and extract information"""
        if depth > self.max_depth or len(self.discovered_urls) >= self.max_urls:
            return {}
        
        if url in self.crawled_urls:
            return {}
        
        try:
            await asyncio.sleep(self.delay)  # Rate limiting
            
            async with self.session.get(url) as response:
                if response.status != 200:
                    return {}
                
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                
                self.crawled_urls.add(url)
                
                # Extract links
                links = extract_links(soup, url)
                for link in links:
                    if link not in self.discovered_urls and is_same_domain(url, link):
                        self.discovered_urls.add(link)
                
                # Extract forms
                forms = extract_forms(soup)
                for form in forms:
                    form['url'] = url
                    self.forms.append(form)
                
                # Extract parameters from current URL
                params = self._extract_parameters(url)
                
                result = {
                    'url': url,
                    'status_code': response.status,
                    'title': soup.title.string if soup.title else '',
                    'forms': forms,
                    'links': links,
                    'parameters': params,
                    'depth': depth
                }
                
                logger.info(f"Crawled: {url} (depth: {depth}, links: {len(links)}, forms: {len(forms)})")
                
                return result
                
        except Exception as e:
            logger.error(f"Error crawling {url}: {str(e)}")
            return {}
    
    async def crawl_website(self, start_url: str) -> Dict:
        """Crawl entire website starting from a URL"""
        self.discovered_urls.add(start_url)
        crawl_results = []
        
        # BFS crawling
        queue = [(start_url, 0)]
        
        while queue and len(self.crawled_urls) < self.max_urls:
            current_url, depth = queue.pop(0)
            
            if depth > self.max_depth:
                continue
            
            result = await self.crawl_url(current_url, depth)
            if result:
                crawl_results.append(result)
                
                # Add new links to queue
                for link in result.get('links', []):
                    if link not in self.crawled_urls and (link, depth + 1) not in queue:
                        queue.append((link, depth + 1))
        
        # Discover hidden endpoints using wordlist
        await self._discover_hidden_endpoints(start_url)
        
        return {
            'start_url': start_url,
            'total_urls': len(self.discovered_urls),
            'crawled_urls': len(self.crawled_urls),
            'forms_found': len(self.forms),
            'results': crawl_results,
            'all_urls': list(self.discovered_urls),
            'forms': self.forms
        }
    
    async def _discover_hidden_endpoints(self, base_url: str):
        """Discover hidden endpoints using common paths"""
        common_paths = [
            '/admin', '/login', '/dashboard', '/api', '/upload',
            '/config', '/backup', '/test', '/dev', '/debug',
            '/phpmyadmin', '/wp-admin', '/cpanel', '/webmail',
            '/api/v1', '/api/v2', '/rest', '/graphql',
            '/robots.txt', '/sitemap.xml', '/.well-known',
            '/swagger', '/docs', '/documentation'
        ]
        
        tasks = []
        for path in common_paths:
            if len(self.discovered_urls) >= self.max_urls:
                break
            test_url = urljoin(base_url, path)
            tasks.append(self._test_endpoint(test_url))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for url, exists in results:
            if exists and isinstance(exists, bool):
                self.discovered_urls.add(url)
                logger.info(f"Hidden endpoint found: {url}")
    
    async def _test_endpoint(self, url: str) -> tuple:
        """Test if an endpoint exists"""
        try:
            await asyncio.sleep(self.delay)
            async with self.session.head(url) as response:
                return url, response.status in [200, 301, 302, 403]
        except Exception:
            return url, False
    
    def _extract_parameters(self, url: str) -> List[str]:
        """Extract parameters from URL"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            return list(params.keys())
        except Exception:
            return []
    
    def get_forms_by_method(self, method: str = 'post') -> List[Dict]:
        """Get forms filtered by HTTP method"""
        return [form for form in self.forms if form.get('method', '').lower() == method.lower()]
    
    def get_urls_with_parameters(self) -> List[str]:
        """Get URLs that contain parameters"""
        return [url for url in self.discovered_urls if '?' in url]
    
    def get_crawl_summary(self) -> Dict:
        """Get summary of crawling results"""
        return {
            'total_discovered': len(self.discovered_urls),
            'total_crawled': len(self.crawled_urls),
            'forms_found': len(self.forms),
            'post_forms': len(self.get_forms_by_method('post')),
            'get_forms': len(self.get_forms_by_method('get')),
            'urls_with_params': len(self.get_urls_with_parameters())
        }
