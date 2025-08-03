#!/usr/bin/env python3
"""
Example WebStrike Usage Script
Demonstrates various scanning configurations and authentication methods
"""

import asyncio
import json
import sys
import os

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.scanner import WebStrikeScanner
from reports.report_generator import ReportGenerator

async def basic_scan_example():
    """Example: Basic vulnerability scan"""
    print("🔍 Running basic scan example...")
    
    # Initialize scanner with basic configuration
    config = {
        'max_depth': 2,
        'max_urls': 50,
        'modules': ['sqli', 'xss', 'headers'],
        'threads': 3,
        'delay': 0.5
    }
    
    scanner = WebStrikeScanner("https://httpbin.org", config)
    
    try:
        # Run the scan
        results = await scanner.run_full_scan()
        
        # Generate JSON report
        report_gen = ReportGenerator()
        json_report = report_gen.generate_json_report(results, "example_basic_scan.json")
        
        print(f"✅ Basic scan complete. Report: {json_report}")
        print(f"📊 Found {len(results.get('vulnerabilities', []))} vulnerabilities")
        
    finally:
        scanner.close()

async def authenticated_scan_example():
    """Example: Scan with form-based authentication"""
    print("🔐 Running authenticated scan example...")
    
    config = {
        'max_depth': 3,
        'max_urls': 100,
        'modules': ['sqli', 'xss', 'csrf'],
        'threads': 5
    }
    
    scanner = WebStrikeScanner("https://example.com", config)
    
    # Setup form-based authentication
    auth_config = {
        'type': 'form',
        'login_url': 'https://example.com/login',
        'username': 'testuser',
        'password': 'testpass'
    }
    
    try:
        scanner.setup_authentication(auth_config)
        
        # Custom headers for testing
        custom_headers = {
            'User-Agent': 'WebStrike-Example/1.0',
            'X-Test-Header': 'Security-Scan'
        }
        scanner.set_custom_headers(custom_headers)
        
        results = await scanner.run_full_scan()
        
        # Generate HTML report
        report_gen = ReportGenerator()
        html_report = report_gen.generate_html_report(results, "example_auth_scan.html")
        
        print(f"✅ Authenticated scan complete. Report: {html_report}")
        
    finally:
        scanner.close()

async def api_scan_example():
    """Example: API scanning with Bearer token"""
    print("🌐 Running API scan example...")
    
    config = {
        'max_depth': 1,  # APIs typically don't need deep crawling
        'max_urls': 30,
        'modules': ['headers', 'sqli'],  # Focus on relevant modules for APIs
        'threads': 3
    }
    
    scanner = WebStrikeScanner("https://jsonplaceholder.typicode.com", config)
    
    # Setup Bearer token authentication
    auth_config = {
        'type': 'bearer',
        'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example.token'
    }
    
    try:
        scanner.setup_authentication(auth_config)
        
        results = await scanner.run_full_scan()
        
        # Show scan summary
        summary = results.get('summary', {})
        print(f"📈 API Scan Summary:")
        print(f"   - URLs scanned: {summary.get('urls_scanned', 0)}")
        print(f"   - Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        print(f"   - Duration: {results.get('duration', 0):.2f} seconds")
        
        # Generate both JSON and HTML reports
        report_gen = ReportGenerator()
        json_report = report_gen.generate_json_report(results, "example_api_scan.json")
        html_report = report_gen.generate_html_report(results, "example_api_scan.html")
        
        print(f"✅ API scan complete.")
        print(f"📄 JSON Report: {json_report}")
        print(f"🌐 HTML Report: {html_report}")
        
    finally:
        scanner.close()

async def custom_module_scan():
    """Example: Scan with specific modules and custom configuration"""
    print("⚙️ Running custom module scan example...")
    
    # Highly customized configuration
    config = {
        'max_depth': 4,
        'max_urls': 200,
        'modules': ['sqli', 'xss', 'csrf', 'headers', 'file_upload'],  # All modules
        'threads': 8,
        'delay': 0.3
    }
    
    scanner = WebStrikeScanner("https://testphp.vulnweb.com", config)
    
    try:
        # Set up proxy for testing (comment out if no proxy)
        # scanner.set_proxy("http://127.0.0.1:8080")
        
        results = await scanner.run_full_scan()
        
        # Detailed analysis of results
        vulnerabilities = results.get('vulnerabilities', [])
        
        print(f"\n📊 Detailed Scan Results:")
        print(f"   Target: {results.get('target', 'Unknown')}")
        print(f"   Duration: {results.get('duration', 0):.2f} seconds")
        
        # Group by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print(f"\n🔍 Vulnerabilities by Severity:")
        for severity, count in severity_counts.items():
            emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(severity, '⚪')
            print(f"   {emoji} {severity}: {count}")
        
        # Show sample vulnerabilities
        if vulnerabilities:
            print(f"\n📋 Sample Findings:")
            for vuln in vulnerabilities[:3]:  # Show first 3
                print(f"   • {vuln.get('type', 'Unknown')}: {vuln.get('evidence', 'No evidence')[:50]}...")
        
        # Generate comprehensive report
        report_gen = ReportGenerator()
        html_report = report_gen.generate_html_report(results, "example_comprehensive_scan.html")
        
        print(f"\n✅ Comprehensive scan complete. Report: {html_report}")
        
    finally:
        scanner.close()

def demonstrate_report_generation():
    """Example: Generate reports from existing scan data"""
    print("📊 Demonstrating report generation...")
    
    # Sample scan results for demonstration
    sample_results = {
        'target': 'https://example.com',
        'start_time': '2025-08-03T14:30:22',
        'end_time': '2025-08-03T14:32:45',
        'duration': 143.2,
        'vulnerabilities': [
            {
                'type': 'Reflected XSS',
                'severity': 'High',
                'confidence': 'High',
                'evidence': 'Script tag reflected in search parameter',
                'payload': '<script>alert("XSS")</script>',
                'parameter': 'q',
                'recommendation': 'Implement proper input validation and output encoding'
            },
            {
                'type': 'SQL Injection',
                'severity': 'Critical',
                'confidence': 'High',
                'evidence': 'MySQL error: syntax error near "1=1"',
                'payload': "' OR '1'='1",
                'parameter': 'id',
                'recommendation': 'Use parameterized queries and input validation'
            },
            {
                'type': 'Missing Security Headers',
                'severity': 'Medium',
                'confidence': 'High',
                'evidence': 'X-Frame-Options header not present',
                'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN header'
            }
        ],
        'summary': {
            'total_vulnerabilities': 3,
            'severity_distribution': {
                'Critical': 1,
                'High': 1,
                'Medium': 1,
                'Low': 0
            },
            'urls_scanned': 25,
            'forms_scanned': 3
        },
        'crawl_results': {
            'total_urls': 25,
            'forms_found': 3
        }
    }
    
    try:
        report_gen = ReportGenerator()
        
        # Generate all report formats
        json_report = report_gen.generate_json_report(sample_results, "demo_scan_results.json")
        html_report = report_gen.generate_html_report(sample_results, "demo_scan_report.html")
        
        print(f"✅ Demo reports generated:")
        print(f"📄 JSON: {json_report}")
        print(f"🌐 HTML: {html_report}")
        
        # Try PDF generation (may fail if wkhtmltopdf not installed)
        try:
            pdf_report = report_gen.generate_pdf_report(sample_results, "demo_scan_report.pdf")
            print(f"📑 PDF: {pdf_report}")
        except Exception as e:
            print(f"⚠️  PDF generation failed (install wkhtmltopdf): {str(e)}")
        
    except Exception as e:
        print(f"❌ Report generation error: {str(e)}")

async def main():
    """Run all examples"""
    print("🛡️ WebStrike Usage Examples")
    print("=" * 50)
    
    examples = [
        ("Basic Scan", basic_scan_example()),
        ("Authenticated Scan", authenticated_scan_example()),
        ("API Scan", api_scan_example()),
        ("Custom Module Scan", custom_module_scan())
    ]
    
    for name, example in examples:
        try:
            print(f"\n🎯 {name}")
            print("-" * 30)
            await example
        except KeyboardInterrupt:
            print(f"\n⏹️  {name} interrupted by user")
            break
        except Exception as e:
            print(f"❌ {name} failed: {str(e)}")
            continue
    
    # Non-async example
    print(f"\n🎯 Report Generation Demo")
    print("-" * 30)
    demonstrate_report_generation()
    
    print(f"\n✅ All examples completed!")
    print(f"\n📚 Check the generated reports in the 'reports/output/' directory")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⏹️  Examples interrupted by user")
    except Exception as e:
        print(f"❌ Fatal error: {str(e)}")
        sys.exit(1)
