"""
Session Manager for handling authentication and cookies
"""
import requests
from typing import Dict, Optional
import json
import os
from .utils import setup_logging

logger = setup_logging()

class SessionManager:
    """Manages HTTP sessions, cookies, and authentication"""
    
    def __init__(self):
        self.session = requests.Session()
        self.cookies = {}
        self.headers = {
            'User-Agent': 'WebStrike/1.0 Security Scanner'
        }
        self.session.headers.update(self.headers)
    
    def set_custom_headers(self, headers: Dict[str, str]):
        """Set custom headers for requests"""
        self.headers.update(headers)
        self.session.headers.update(headers)
        logger.info(f"Updated headers: {headers}")
    
    def set_proxy(self, proxy_url: str):
        """Set proxy for requests"""
        proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
        self.session.proxies.update(proxies)
        logger.info(f"Proxy set: {proxy_url}")
    
    def login_form(self, login_url: str, username: str, password: str, 
                   username_field: str = 'username', password_field: str = 'password') -> bool:
        """Attempt form-based login"""
        try:
            # Get login page to extract CSRF tokens if any
            response = self.session.get(login_url)
            
            login_data = {
                username_field: username,
                password_field: password
            }
            
            # Attempt login
            login_response = self.session.post(login_url, data=login_data)
            
            # Check if login was successful (basic heuristic)
            if login_response.status_code == 200:
                if 'dashboard' in login_response.url.lower() or 'welcome' in login_response.text.lower():
                    logger.info("Login successful")
                    return True
                elif 'error' in login_response.text.lower() or 'invalid' in login_response.text.lower():
                    logger.warning("Login failed - invalid credentials")
                    return False
            
            logger.info("Login status uncertain, proceeding with session")
            return True
            
        except Exception as e:
            logger.error(f"Login failed: {str(e)}")
            return False
    
    def set_bearer_token(self, token: str):
        """Set Bearer token for API authentication"""
        self.session.headers.update({
            'Authorization': f'Bearer {token}'
        })
        logger.info("Bearer token set")
    
    def set_api_key(self, api_key: str, header_name: str = 'X-API-Key'):
        """Set API key header"""
        self.session.headers.update({
            header_name: api_key
        })
        logger.info(f"API key set in header: {header_name}")
    
    def load_cookies_from_file(self, cookie_file: str):
        """Load cookies from JSON file"""
        try:
            if os.path.exists(cookie_file):
                with open(cookie_file, 'r') as f:
                    cookies = json.load(f)
                    self.session.cookies.update(cookies)
                    logger.info(f"Cookies loaded from: {cookie_file}")
                    return True
        except Exception as e:
            logger.error(f"Failed to load cookies: {str(e)}")
        return False
    
    def save_cookies_to_file(self, cookie_file: str):
        """Save current cookies to JSON file"""
        try:
            cookies_dict = dict(self.session.cookies)
            with open(cookie_file, 'w') as f:
                json.dump(cookies_dict, f, indent=2)
            logger.info(f"Cookies saved to: {cookie_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save cookies: {str(e)}")
            return False
    
    def set_cookies(self, cookies: Dict[str, str]):
        """Manually set cookies"""
        self.session.cookies.update(cookies)
        logger.info(f"Cookies updated: {list(cookies.keys())}")
    
    def get_session(self) -> requests.Session:
        """Get the current session object"""
        return self.session
    
    def test_authentication(self, test_url: str) -> bool:
        """Test if current authentication is working"""
        try:
            response = self.session.get(test_url)
            if response.status_code == 200:
                if 'login' not in response.url.lower() and 'unauthorized' not in response.text.lower():
                    logger.info("Authentication test passed")
                    return True
            logger.warning("Authentication test failed")
            return False
        except Exception as e:
            logger.error(f"Authentication test error: {str(e)}")
            return False
    
    def close(self):
        """Close the session"""
        self.session.close()
        logger.info("Session closed")
