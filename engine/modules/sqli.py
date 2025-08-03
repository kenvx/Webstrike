"""
SQL Injection Detection Module
"""
import re
import time
from typing import List, Dict, Optional
import requests
from urllib.parse import urljoin
from ..utils import setup_logging, generate_payloads_variations, parse_response_time

logger = setup_logging()

class SQLiScanner:
    """SQL Injection vulnerability scanner"""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.payloads = self._load_payloads()
        self.error_patterns = [
            # MySQL errors
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            
            # PostgreSQL errors
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            
            # MSSQL errors
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"Microsoft SQL Native Client error",
            r"SqlServer",
            
            # Oracle errors
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_.*",
            
            # SQLite errors
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            
            # Generic SQL errors
            r"SQL command not properly ended",
            r"Unclosed quotation mark after the character string",
            r"quoted string not properly terminated"
        ]
    
    def _load_payloads(self) -> List[str]:
        """Load SQL injection payloads"""
        try:
            with open('engine/payloads/sqli.txt', 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            logger.warning("SQLi payloads file not found, using default payloads")
            return [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "\" OR \"1\"=\"1",
                "\" OR \"1\"=\"1\" --",
                "'; WAITFOR DELAY '00:00:05'--",
                "'; SELECT SLEEP(5)--"
            ]
    
    def scan_parameter(self, url: str, param_name: str, param_value: str) -> Dict:
        """Scan a specific parameter for SQL injection"""
        vulnerabilities = []
        
        for payload in self.payloads[:20]:  # Limit payloads for performance
            try:
                # Test error-based SQLi
                vuln = self._test_error_based(url, param_name, param_value, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                
                # Test time-based SQLi
                if 'SLEEP' in payload or 'WAITFOR' in payload or 'pg_sleep' in payload:
                    vuln = self._test_time_based(url, param_name, param_value, payload)
                    if vuln:
                        vulnerabilities.append(vuln)
                
                # Test boolean-based SQLi
                vuln = self._test_boolean_based(url, param_name, param_value, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                    
            except Exception as e:
                logger.error(f"Error testing payload {payload}: {str(e)}")
                continue
        
        return {
            'parameter': param_name,
            'url': url,
            'vulnerabilities': vulnerabilities,
            'total_tests': len(self.payloads[:20]),
            'vulnerability_count': len(vulnerabilities)
        }
    
    def _test_error_based(self, url: str, param_name: str, param_value: str, payload: str) -> Optional[Dict]:
        """Test for error-based SQL injection"""
        try:
            # Create request with payload
            data = {param_name: payload}
            response = self.session.post(url, data=data)
            
            # Check for SQL error patterns
            for pattern in self.error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return {
                        'type': 'Error-based SQL Injection',
                        'payload': payload,
                        'parameter': param_name,
                        'evidence': pattern,
                        'severity': 'High',
                        'confidence': 'High'
                    }
        except Exception as e:
            logger.error(f"Error in error-based test: {str(e)}")
        
        return None
    
    def _test_time_based(self, url: str, param_name: str, param_value: str, payload: str) -> Optional[Dict]:
        """Test for time-based SQL injection"""
        try:
            # Normal request time
            normal_data = {param_name: param_value}
            start_time = time.time()
            normal_response = self.session.post(url, data=normal_data)
            normal_time = time.time() - start_time
            
            # Payload request time
            payload_data = {param_name: payload}
            start_time = time.time()
            payload_response = self.session.post(url, data=payload_data)
            payload_time = time.time() - start_time
            
            # Check if payload caused significant delay (>3 seconds difference)
            if payload_time - normal_time > 3:
                return {
                    'type': 'Time-based SQL Injection',
                    'payload': payload,
                    'parameter': param_name,
                    'evidence': f'Response time increased by {payload_time - normal_time:.2f} seconds',
                    'severity': 'High',
                    'confidence': 'Medium'
                }
        except Exception as e:
            logger.error(f"Error in time-based test: {str(e)}")
        
        return None
    
    def _test_boolean_based(self, url: str, param_name: str, param_value: str, payload: str) -> Optional[Dict]:
        """Test for boolean-based SQL injection"""
        try:
            # True condition payload
            true_payload = payload.replace("'1'='1", "'1'='1")
            true_data = {param_name: true_payload}
            true_response = self.session.post(url, data=true_data)
            
            # False condition payload
            false_payload = payload.replace("'1'='1", "'1'='2")
            false_data = {param_name: false_payload}
            false_response = self.session.post(url, data=false_data)
            
            # Compare response lengths and content
            if (len(true_response.text) != len(false_response.text) or 
                true_response.status_code != false_response.status_code):
                return {
                    'type': 'Boolean-based SQL Injection',
                    'payload': payload,
                    'parameter': param_name,
                    'evidence': f'Different responses for true/false conditions',
                    'severity': 'High',
                    'confidence': 'Medium'
                }
        except Exception as e:
            logger.error(f"Error in boolean-based test: {str(e)}")
        
        return None
    
    def scan_form(self, form_data: Dict) -> Dict:
        """Scan a form for SQL injection vulnerabilities"""
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
            
            if field_name and input_field.get('type', '') != 'submit':
                logger.info(f"Testing form field: {field_name} at {target_url}")
                result = self.scan_parameter(target_url, field_name, field_value)
                if result['vulnerabilities']:
                    vulnerabilities.extend(result['vulnerabilities'])
        
        return {
            'form_url': form_url,
            'target_url': target_url,
            'method': method,
            'vulnerabilities': vulnerabilities,
            'fields_tested': len(form_data.get('inputs', [])),
            'vulnerability_count': len(vulnerabilities)
        }
