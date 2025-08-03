"""
Test cases for WebStrike Crawler
"""
import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
import aiohttp
from engine.crawler import WebCrawler

class TestWebCrawler:
    """Test cases for WebCrawler class"""
    
    @pytest.mark.asyncio
    async def test_crawler_initialization(self):
        """Test crawler initialization with default parameters"""
        async with WebCrawler() as crawler:
            assert crawler.max_depth == 3
            assert crawler.max_urls == 100
            assert crawler.delay == 1.0
            assert len(crawler.discovered_urls) == 0
            assert len(crawler.crawled_urls) == 0
            assert len(crawler.forms) == 0
    
    @pytest.mark.asyncio
    async def test_crawler_custom_config(self):
        """Test crawler initialization with custom parameters"""
        async with WebCrawler(max_depth=5, max_urls=200, delay=0.5) as crawler:
            assert crawler.max_depth == 5
            assert crawler.max_urls == 200
            assert crawler.delay == 0.5
    
    @pytest.mark.asyncio
    @patch('aiohttp.ClientSession.get')
    async def test_crawl_url_success(self, mock_get):
        """Test successful URL crawling"""
        # Mock response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="""
            <html>
                <head><title>Test Page</title></head>
                <body>
                    <a href="/page1">Page 1</a>
                    <a href="/page2">Page 2</a>
                    <form action="/submit" method="post">
                        <input type="text" name="username">
                        <input type="password" name="password">
                        <input type="submit" value="Submit">
                    </form>
                </body>
            </html>
        """)
        
        mock_get.return_value.__aenter__.return_value = mock_response
        
        async with WebCrawler() as crawler:
            result = await crawler.crawl_url("https://example.com")
            
            assert result['url'] == "https://example.com"
            assert result['status_code'] == 200
            assert result['title'] == "Test Page"
            assert len(result['forms']) == 1
            assert result['forms'][0]['method'] == 'post'
            assert len(result['forms'][0]['inputs']) == 3
    
    @pytest.mark.asyncio
    @patch('aiohttp.ClientSession.get')
    async def test_crawl_url_404(self, mock_get):
        """Test crawling URL that returns 404"""
        mock_response = AsyncMock()
        mock_response.status = 404
        
        mock_get.return_value.__aenter__.return_value = mock_response
        
        async with WebCrawler() as crawler:
            result = await crawler.crawl_url("https://example.com/notfound")
            
            assert result == {}
    
    @pytest.mark.asyncio
    @patch('aiohttp.ClientSession.get')
    async def test_crawl_url_exception(self, mock_get):
        """Test crawling URL that raises exception"""
        mock_get.side_effect = aiohttp.ClientError("Connection failed")
        
        async with WebCrawler() as crawler:
            result = await crawler.crawl_url("https://example.com")
            
            assert result == {}
    
    def test_extract_parameters(self):
        """Test parameter extraction from URLs"""
        crawler = WebCrawler()
        
        # Test URL with parameters
        params = crawler._extract_parameters("https://example.com/search?q=test&category=web&page=1")
        assert set(params) == {"q", "category", "page"}
        
        # Test URL without parameters
        params = crawler._extract_parameters("https://example.com/")
        assert params == []
        
        # Test invalid URL
        params = crawler._extract_parameters("invalid-url")
        assert params == []
    
    def test_get_forms_by_method(self):
        """Test filtering forms by HTTP method"""
        crawler = WebCrawler()
        
        # Add test forms
        crawler.forms = [
            {'method': 'post', 'action': '/submit'},
            {'method': 'get', 'action': '/search'},
            {'method': 'post', 'action': '/login'},
            {'method': 'get', 'action': '/filter'}
        ]
        
        post_forms = crawler.get_forms_by_method('post')
        assert len(post_forms) == 2
        
        get_forms = crawler.get_forms_by_method('get')
        assert len(get_forms) == 2
    
    def test_get_urls_with_parameters(self):
        """Test filtering URLs with parameters"""
        crawler = WebCrawler()
        
        # Add test URLs
        crawler.discovered_urls = {
            "https://example.com/",
            "https://example.com/search?q=test",
            "https://example.com/page",
            "https://example.com/filter?category=web&sort=date"
        }
        
        param_urls = crawler.get_urls_with_parameters()
        assert len(param_urls) == 2
        assert "https://example.com/search?q=test" in param_urls
        assert "https://example.com/filter?category=web&sort=date" in param_urls
    
    def test_get_crawl_summary(self):
        """Test crawl summary generation"""
        crawler = WebCrawler()
        
        # Set up test data
        crawler.discovered_urls = {
            "https://example.com/",
            "https://example.com/search?q=test",
            "https://example.com/page"
        }
        crawler.crawled_urls = {
            "https://example.com/",
            "https://example.com/page"
        }
        crawler.forms = [
            {'method': 'post', 'action': '/submit'},
            {'method': 'get', 'action': '/search'}
        ]
        
        summary = crawler.get_crawl_summary()
        
        assert summary['total_discovered'] == 3
        assert summary['total_crawled'] == 2
        assert summary['forms_found'] == 2
        assert summary['post_forms'] == 1
        assert summary['get_forms'] == 1
        assert summary['urls_with_params'] == 1

if __name__ == '__main__':
    pytest.main([__file__])
