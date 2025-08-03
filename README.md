
# 🛡️ WebStrike - Advanced Web Vulnerability Scanner

**WebStrike** is a powerful, modular web vulnerability scanner designed for penetration testers and security engineers. Built with Python, it provides comprehensive security testing capabilities without relying on AI/ML, instead using proven security testing methodologies.

## 🎯 Project Overview

WebStrike is a **production-ready** web vulnerability scanner that offers:
- **Modular Architecture**: Easy to extend with new vulnerability modules
- **CLI-First Design**: Complete command-line interface for automation
- **Multi-Format Reporting**: JSON, HTML, and PDF report generation
- **Authentication Support**: Form, Bearer token, API key, and cookie-based auth
- **Performance Optimized**: Asynchronous crawling and multi-threaded scanning

---

## ✅ Core Features

### **🕷️ Advanced Web Crawler**
- Asynchronous URL discovery and enumeration
- Form and parameter extraction
- Hidden endpoint discovery using wordlists
- Configurable depth and scope control

### **🔍 Vulnerability Detection Modules**
- **SQL Injection**: Error-based, Boolean-based, and Time-based detection
- **XSS**: Reflected, DOM-based, and stored XSS detection  
- **CSRF**: Token validation and bypass testing
- **Security Headers**: HSTS, CSP, X-Frame-Options analysis
- **File Upload**: Extension bypass and MIME type testing

### **🔐 Authentication & Session Management**
- Form-based login automation
- JWT Bearer token support
- API key authentication
- Custom cookie handling
- Session persistence

### **📊 Comprehensive Reporting**
- **JSON**: Machine-readable results for automation
- **HTML**: Interactive web-based reports with executive summary
- **PDF**: Professional documents for compliance reporting
- Risk scoring and vulnerability prioritization

### **⚡ Performance & Reliability**
- Multi-threaded scanning architecture
- Configurable rate limiting and delays
- WAF detection and evasion techniques
- Proxy support for testing through tools

---

## 🏗️ Project Structure
```
webstrike/
│
├── engine/                          # Core scanning engine
│   ├── __init__.py                 # Package initialization
│   ├── crawler.py                  # Asynchronous web crawler
│   ├── scanner.py                  # Main scanner orchestrator
│   ├── utils.py                    # Utility functions
│   ├── session_manager.py          # Authentication & session handling
│   ├── payloads/                   # Vulnerability payloads
│   │   ├── sqli.txt               # SQL injection payloads
│   │   ├── xss.txt                # XSS attack vectors
│   │   └── custom.txt             # Custom payloads
│   └── modules/                    # Vulnerability detection modules
│       ├── sqli.py                # SQL injection scanner
│       ├── xss.py                 # XSS vulnerability scanner
│       ├── csrf.py                # CSRF detection module
│       ├── headers.py             # Security headers analyzer
│       └── file_upload.py         # File upload security tester
│
├── reports/                        # Report generation system
│   ├── report_generator.py        # Multi-format report generator
│   ├── templates/                 # Report templates
│   └── output/                    # Generated reports
│
├── cli/                           # Command-line interface
│   └── webstrike_cli.py          # Main CLI application
│
├── tests/                         # Test suite
│   ├── test_crawler.py           # Crawler tests
│   ├── test_scanner.py           # Scanner tests
│   └── test_modules.py           # Module-specific tests
│
├── config.ini                     # Configuration file
├── requirements.txt               # Python dependencies
├── setup.py                      # Package setup
├── README.md                     # Project documentation
└── USAGE.md                      # Detailed usage guide
```

---

## 🚀 Quick Start

### **Installation**

1. **Clone the repository:**
   ```bash
   git clone https://github.com/kenvx/Webstrike
   cd webstrike
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation:**
   ```bash
   python -m cli.webstrike_cli info
   ```

### **Basic Usage**

**Run a basic vulnerability scan:**
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
python -m cli.webstrike_cli scan -u https://example.com \
  --auth-type form \
  --login-url /login \
  --username admin \
  --password password
```

---

## 🔧 Advanced Configuration

### **Command Line Options**

```bash
Options:
  -u, --url TEXT              Target URL to scan [required]
  -m, --modules TEXT          Modules: sqli,xss,csrf,headers,file_upload
  -d, --depth INTEGER         Maximum crawling depth (default: 3)
  --max-urls INTEGER          Maximum URLs to crawl (default: 100)
  -t, --threads INTEGER       Number of threads (default: 5)
  --delay FLOAT               Request delay in seconds (default: 1.0)
  -f, --format [json|html|pdf] Output format (default: json)
  --auth-type [form|bearer|api_key|cookies] Authentication method
  --proxy TEXT                Proxy URL for testing
  -v, --verbose               Enable verbose logging
```

### **Authentication Examples**

**Bearer Token:**
```bash
python -m cli.webstrike_cli scan -u https://api.example.com \
  --auth-type bearer \
  --token "eyJhbGciOiJIUzI1NiIs..."
```

**API Key:**
```bash
python -m cli.webstrike_cli scan -u https://api.example.com \
  --auth-type api_key \
  --token "your-api-key" \
  --header-name "X-API-Key"
```

---

## 📊 Sample Output

### **Console Output**
```
🎯 Starting WebStrike scan of https://example.com
📋 Modules: sqli, xss, csrf, headers, file_upload
⚙️  Config: depth=3, max_urls=100, threads=5
🔍 Starting scan...

📊 Scan Summary:
   Target: https://example.com
   Duration: 45.32 seconds
   URLs Scanned: 23
   Forms Scanned: 5

🔍 Vulnerabilities Found: 7
   🔴 Critical: 1
   🟠 High: 2
   🟡 Medium: 3
   🟢 Low: 1

✅ Scan complete! Report saved to: webstrike_report_example.com_20250803_143022.html
```

### **HTML Report Features**
- 📈 Executive summary with risk scoring
- 📋 Detailed vulnerability listings with evidence
- 🛠️ Remediation recommendations
- 📊 Visual charts and statistics
- 🔍 Technical details for each finding

---

## 🧪 Testing & Quality Assurance

### **Run Test Suite**
```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run all tests
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=engine
```

### **Test Categories**
- **Unit Tests**: Individual component testing
- **Integration Tests**: Module interaction testing
- **Async Tests**: Crawler and async functionality
- **Mock Tests**: External dependency simulation

---

## 🔒 Security & Legal Notice

### **⚠️ Legal Usage Only**
- **Only test systems you own or have explicit written permission to test**
- Unauthorized vulnerability scanning is illegal in most jurisdictions
- Follow responsible disclosure practices for any findings
- Respect rate limits and terms of service

### **🛡️ Safe Testing Practices**
- Use appropriate delays between requests
- Monitor target system performance
- Implement proper session management
- Store scan results securely

---

## 🤝 Contributing

### **Adding New Modules**
1. Create new scanner in `engine/modules/`
2. Implement required interface methods
3. Add comprehensive test coverage
4. Update CLI integration
5. Document usage and examples

### **Development Setup**
```bash
# Install development dependencies
pip install -r requirements.txt
pip install pytest pytest-asyncio black flake8

# Run code formatting
black engine/ cli/ tests/

# Run linting
flake8 engine/ cli/ tests/
```

---

## 📚 Documentation

- **[USAGE.md](USAGE.md)**: Comprehensive usage guide
- **[API Documentation](docs/api.md)**: Developer API reference
- **[Module Development](docs/modules.md)**: Creating custom modules
- **[Configuration](docs/config.md)**: Advanced configuration options

---

## 🏆 Project Status

✅ **COMPLETED FEATURES:**
- ✅ Asynchronous web crawler with form extraction
- ✅ SQL Injection detection (Error, Boolean, Time-based)
- ✅ XSS vulnerability scanning (Reflected, DOM-based)
- ✅ CSRF token validation and bypass testing
- ✅ Security headers analysis (HSTS, CSP, etc.)
- ✅ File upload vulnerability testing
- ✅ Multi-format reporting (JSON, HTML, PDF)
- ✅ Authentication support (Form, Bearer, API key)
- ✅ Command-line interface with full options
- ✅ Comprehensive test suite
- ✅ WAF detection capabilities
- ✅ Session management and proxy support

🚀 **READY FOR PRODUCTION USE**

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- OWASP for security testing methodologies
- Security community for vulnerability research
- Open source contributors and maintainers

---

**Built with ❤️ for the security community**
