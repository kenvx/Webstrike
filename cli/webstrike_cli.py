"""
WebStrike Command Line Interface
"""
import click
import asyncio
import json
import os
import sys
from typing import Dict, List

# Add the parent directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.scanner import WebStrikeScanner
from engine.utils import setup_logging, is_valid_url
from reports.report_generator import ReportGenerator

logger = setup_logging()

@click.group()
@click.version_option(version='1.0.0')
def cli():
    """
    🛡️ WebStrike - Advanced Web Vulnerability Scanner
    
    A modular, extensible web security testing tool designed for
    penetration testers and security engineers.
    """
    pass

@cli.command()
@click.option('--url', '-u', required=True, help='Target URL to scan')
@click.option('--modules', '-m', default='all', 
              help='Modules to run (comma-separated): sqli,xss,csrf,headers,file_upload or "all"')
@click.option('--depth', '-d', default=3, type=int, help='Maximum crawling depth')
@click.option('--max-urls', default=100, type=int, help='Maximum URLs to crawl')
@click.option('--threads', '-t', default=5, type=int, help='Number of threads for scanning')
@click.option('--delay', default=1.0, type=float, help='Delay between requests (seconds)')
@click.option('--output', '-o', help='Output file prefix (without extension)')
@click.option('--format', '-f', default='json', type=click.Choice(['json', 'html', 'pdf']),
              help='Output format')
@click.option('--auth-type', type=click.Choice(['none', 'form', 'bearer', 'api_key', 'cookies']),
              default='none', help='Authentication type')
@click.option('--login-url', help='Login URL for form authentication')
@click.option('--username', help='Username for form authentication')
@click.option('--password', help='Password for form authentication')
@click.option('--token', help='Bearer token or API key')
@click.option('--header-name', default='Authorization', help='Header name for API key')
@click.option('--cookies', help='Cookies as JSON string')
@click.option('--proxy', help='Proxy URL (http://proxy:port)')
@click.option('--headers', help='Custom headers as JSON string')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(url, modules, depth, max_urls, threads, delay, output, format, 
         auth_type, login_url, username, password, token, header_name, 
         cookies, proxy, headers, verbose):
    """
    Run a vulnerability scan against the target URL
    
    Examples:
        webstrike scan -u https://example.com
        webstrike scan -u https://example.com -m sqli,xss -f html
        webstrike scan -u https://example.com --auth-type form --login-url /login --username admin --password password
    """
    try:
        # Setup logging level
        if verbose:
            logger.setLevel('DEBUG')
        
        # Validate URL
        if not is_valid_url(url):
            click.echo(f"❌ Invalid URL: {url}", err=True)
            return
        
        # Parse modules
        if modules.lower() == 'all':
            selected_modules = ['sqli', 'xss', 'csrf', 'headers', 'file_upload']
        else:
            selected_modules = [m.strip() for m in modules.split(',')]
            valid_modules = ['sqli', 'xss', 'csrf', 'headers', 'file_upload']
            invalid_modules = [m for m in selected_modules if m not in valid_modules]
            if invalid_modules:
                click.echo(f"❌ Invalid modules: {', '.join(invalid_modules)}", err=True)
                click.echo(f"Valid modules: {', '.join(valid_modules)}")
                return
        
        # Configuration
        config = {
            'max_depth': depth,
            'max_urls': max_urls,
            'threads': threads,
            'delay': delay,
            'modules': selected_modules
        }
        
        click.echo(f"🎯 Starting WebStrike scan of {url}")
        click.echo(f"📋 Modules: {', '.join(selected_modules)}")
        click.echo(f"⚙️  Config: depth={depth}, max_urls={max_urls}, threads={threads}")
        
        # Initialize scanner
        scanner = WebStrikeScanner(url, config)
        
        # Setup authentication
        if auth_type != 'none':
            auth_config = _build_auth_config(auth_type, login_url, username, password, 
                                           token, header_name, cookies)
            scanner.setup_authentication(auth_config)
            click.echo(f"🔐 Authentication configured: {auth_type}")
        
        # Setup proxy
        if proxy:
            scanner.set_proxy(proxy)
            click.echo(f"🌐 Proxy configured: {proxy}")
        
        # Setup custom headers
        if headers:
            try:
                custom_headers = json.loads(headers)
                scanner.set_custom_headers(custom_headers)
                click.echo(f"📝 Custom headers configured")
            except json.JSONDecodeError:
                click.echo("❌ Invalid JSON format for headers", err=True)
                return
        
        # Run scan
        click.echo("🔍 Starting scan...")
        scan_results = asyncio.run(scanner.run_full_scan())
        
        # Generate report
        click.echo("📊 Generating report...")
        report_generator = ReportGenerator()
        
        if format == 'json':
            report_path = report_generator.generate_json_report(scan_results, output)
        elif format == 'html':
            report_path = report_generator.generate_html_report(scan_results, output)
        elif format == 'pdf':
            report_path = report_generator.generate_pdf_report(scan_results, output)
        
        # Display summary
        _display_scan_summary(scan_results)
        click.echo(f"✅ Scan complete! Report saved to: {report_path}")
        
        # Close scanner
        scanner.close()
        
    except KeyboardInterrupt:
        click.echo("\n⏹️  Scan interrupted by user")
    except Exception as e:
        click.echo(f"❌ Error during scan: {str(e)}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()

@cli.command()
@click.option('--input', '-i', required=True, help='Input JSON report file')
@click.option('--format', '-f', required=True, type=click.Choice(['html', 'pdf']),
              help='Output format')
@click.option('--output', '-o', help='Output file name')
def report(input, format, output):
    """
    Generate a report from existing scan results
    
    Examples:
        webstrike report -i scan_results.json -f html
        webstrike report -i scan_results.json -f pdf -o custom_report.pdf
    """
    try:
        # Load scan results
        if not os.path.exists(input):
            click.echo(f"❌ Input file not found: {input}", err=True)
            return
        
        with open(input, 'r', encoding='utf-8') as f:
            scan_results = json.load(f)
        
        click.echo(f"📊 Generating {format.upper()} report from {input}")
        
        # Generate report
        report_generator = ReportGenerator()
        
        if format == 'html':
            report_path = report_generator.generate_html_report(scan_results, output)
        elif format == 'pdf':
            report_path = report_generator.generate_pdf_report(scan_results, output)
        
        click.echo(f"✅ Report generated: {report_path}")
        
    except Exception as e:
        click.echo(f"❌ Error generating report: {str(e)}", err=True)

@cli.command()
@click.option('--url', '-u', required=True, help='Target URL to test')
@click.option('--auth-type', type=click.Choice(['form', 'bearer', 'api_key']),
              required=True, help='Authentication type to test')
@click.option('--login-url', help='Login URL (for form auth)')
@click.option('--username', help='Username (for form auth)')
@click.option('--password', help='Password (for form auth)')
@click.option('--token', help='Token (for bearer/api_key auth)')
@click.option('--test-url', help='URL to test authentication against')
def test_auth(url, auth_type, login_url, username, password, token, test_url):
    """
    Test authentication configuration
    
    Examples:
        webstrike test-auth -u https://example.com --auth-type form --login-url /login --username admin --password secret
        webstrike test-auth -u https://api.example.com --auth-type bearer --token eyJ...
    """
    try:
        from engine.session_manager import SessionManager
        
        session_manager = SessionManager()
        
        if auth_type == 'form':
            if not all([login_url, username, password]):
                click.echo("❌ Form authentication requires --login-url, --username, and --password")
                return
            
            full_login_url = login_url if login_url.startswith('http') else url.rstrip('/') + '/' + login_url.lstrip('/')
            success = session_manager.login_form(full_login_url, username, password)
            
            if success:
                click.echo("✅ Form authentication successful")
                if test_url:
                    test_result = session_manager.test_authentication(test_url)
                    click.echo(f"🔍 Authentication test: {'✅ PASSED' if test_result else '❌ FAILED'}")
            else:
                click.echo("❌ Form authentication failed")
        
        elif auth_type == 'bearer':
            if not token:
                click.echo("❌ Bearer authentication requires --token")
                return
            
            session_manager.set_bearer_token(token)
            click.echo("✅ Bearer token configured")
            
            if test_url:
                test_result = session_manager.test_authentication(test_url)
                click.echo(f"🔍 Authentication test: {'✅ PASSED' if test_result else '❌ FAILED'}")
        
        elif auth_type == 'api_key':
            if not token:
                click.echo("❌ API key authentication requires --token")
                return
            
            session_manager.set_api_key(token)
            click.echo("✅ API key configured")
            
            if test_url:
                test_result = session_manager.test_authentication(test_url)
                click.echo(f"🔍 Authentication test: {'✅ PASSED' if test_result else '❌ FAILED'}")
        
        session_manager.close()
        
    except Exception as e:
        click.echo(f"❌ Error testing authentication: {str(e)}", err=True)

@cli.command()
def info():
    """Display information about WebStrike and available modules"""
    click.echo("""
🛡️  WebStrike - Advanced Web Vulnerability Scanner v1.0.0

📋 Available Modules:
  • sqli        - SQL Injection detection (Error, Boolean, Time-based)
  • xss         - Cross-Site Scripting detection (Reflected, DOM-based)
  • csrf        - Cross-Site Request Forgery detection
  • headers     - HTTP Security Headers analysis
  • file_upload - File Upload vulnerability detection

🔧 Key Features:
  • Asynchronous web crawling
  • Multi-threaded vulnerability scanning
  • Session management and authentication support
  • Multiple output formats (JSON, HTML, PDF)
  • WAF detection
  • Customizable payloads

📚 Usage Examples:
  webstrike scan -u https://example.com
  webstrike scan -u https://example.com -m sqli,xss -f html
  webstrike scan -u https://example.com --auth-type form --login-url /login --username admin --password secret
  webstrike report -i results.json -f pdf

⚠️  Legal Notice:
Only use this tool against systems you own or have explicit permission to test.
Unauthorized testing is illegal and unethical.
""")

def _build_auth_config(auth_type: str, login_url: str, username: str, 
                      password: str, token: str, header_name: str, cookies: str) -> Dict:
    """Build authentication configuration"""
    if auth_type == 'form':
        return {
            'type': 'form',
            'login_url': login_url,
            'username': username,
            'password': password
        }
    elif auth_type == 'bearer':
        return {
            'type': 'bearer',
            'token': token
        }
    elif auth_type == 'api_key':
        return {
            'type': 'api_key',
            'api_key': token,
            'header_name': header_name
        }
    elif auth_type == 'cookies':
        return {
            'type': 'cookies',
            'cookies': json.loads(cookies) if cookies else {}
        }
    else:
        return {'type': 'none'}

def _display_scan_summary(scan_results: Dict):
    """Display scan summary"""
    summary = scan_results.get('summary', {})
    vulnerabilities = scan_results.get('vulnerabilities', [])
    
    click.echo("\n📊 Scan Summary:")
    click.echo(f"   Target: {scan_results.get('target', 'Unknown')}")
    click.echo(f"   Duration: {scan_results.get('duration', 0):.2f} seconds")
    click.echo(f"   URLs Scanned: {summary.get('urls_scanned', 0)}")
    click.echo(f"   Forms Scanned: {summary.get('forms_scanned', 0)}")
    
    # Vulnerability counts
    severity_dist = summary.get('severity_distribution', {})
    click.echo(f"\n🔍 Vulnerabilities Found: {summary.get('total_vulnerabilities', 0)}")
    for severity, count in severity_dist.items():
        if count > 0:
            emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(severity, '⚪')
            click.echo(f"   {emoji} {severity}: {count}")
    
    # WAF detection
    waf_detection = scan_results.get('waf_detection', {})
    if waf_detection.get('detected'):
        click.echo(f"\n🛡️  WAF Detected: {waf_detection.get('waf_type', 'Unknown')}")

def main():
    """Main entry point"""
    try:
        cli()
    except Exception as e:
        click.echo(f"❌ Fatal error: {str(e)}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
