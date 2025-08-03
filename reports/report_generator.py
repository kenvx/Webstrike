"""
Report Generator for WebStrike Scanner Results
"""
import json
import os
from datetime import datetime
from typing import Dict, List
from jinja2 import Environment, FileSystemLoader, Template
from engine.utils import setup_logging

logger = setup_logging()

class ReportGenerator:
    """Generate reports from scan results in various formats"""
    
    def __init__(self, template_dir: str = None):
        self.template_dir = template_dir or os.path.join(os.path.dirname(__file__), '..', 'reports', 'templates')
        self.output_dir = os.path.join(os.path.dirname(__file__), '..', 'reports', 'output')
        
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Setup Jinja2 environment
        try:
            self.jinja_env = Environment(loader=FileSystemLoader(self.template_dir))
        except Exception as e:
            logger.warning(f"Could not load templates from {self.template_dir}: {str(e)}")
            self.jinja_env = None
    
    def generate_json_report(self, scan_results: Dict, output_file: str = None) -> str:
        """Generate JSON report"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_domain = scan_results.get('target', 'unknown').replace('://', '_').replace('/', '_')
            output_file = f"webstrike_report_{target_domain}_{timestamp}.json"
        
        output_path = os.path.join(self.output_dir, output_file)
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(scan_results, f, indent=2, default=str)
            
            logger.info(f"JSON report generated: {output_path}")
            return output_path
        
        except Exception as e:
            logger.error(f"Error generating JSON report: {str(e)}")
            raise
    
    def generate_html_report(self, scan_results: Dict, output_file: str = None) -> str:
        """Generate HTML report"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_domain = scan_results.get('target', 'unknown').replace('://', '_').replace('/', '_')
            output_file = f"webstrike_report_{target_domain}_{timestamp}.html"
        
        output_path = os.path.join(self.output_dir, output_file)
        
        try:
            # Prepare data for template
            template_data = self._prepare_template_data(scan_results)
            
            # Generate HTML using template or fallback
            if self.jinja_env:
                try:
                    template = self.jinja_env.get_template('html_report.html')
                    html_content = template.render(**template_data)
                except Exception as e:
                    logger.warning(f"Could not use template, using fallback: {str(e)}")
                    html_content = self._generate_fallback_html(template_data)
            else:
                html_content = self._generate_fallback_html(template_data)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML report generated: {output_path}")
            return output_path
        
        except Exception as e:
            logger.error(f"Error generating HTML report: {str(e)}")
            raise
    
    def generate_pdf_report(self, scan_results: Dict, output_file: str = None) -> str:
        """Generate PDF report"""
        try:
            import pdfkit
        except ImportError:
            logger.error("pdfkit not available. Please install: pip install pdfkit")
            raise ImportError("pdfkit required for PDF generation")
        
        # First generate HTML
        html_path = self.generate_html_report(scan_results, 
                                            output_file.replace('.pdf', '.html') if output_file else None)
        
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_domain = scan_results.get('target', 'unknown').replace('://', '_').replace('/', '_')
            output_file = f"webstrike_report_{target_domain}_{timestamp}.pdf"
        
        output_path = os.path.join(self.output_dir, output_file)
        
        try:
            # Configure PDF options
            options = {
                'page-size': 'A4',
                'margin-top': '0.75in',
                'margin-right': '0.75in',
                'margin-bottom': '0.75in',
                'margin-left': '0.75in',
                'encoding': "UTF-8",
                'no-outline': None,
                'enable-local-file-access': None
            }
            
            # Generate PDF from HTML
            pdfkit.from_file(html_path, output_path, options=options)
            
            logger.info(f"PDF report generated: {output_path}")
            return output_path
        
        except Exception as e:
            logger.error(f"Error generating PDF report: {str(e)}")
            raise
    
    def _prepare_template_data(self, scan_results: Dict) -> Dict:
        """Prepare data for template rendering"""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        summary = scan_results.get('summary', {})
        
        # Group vulnerabilities by severity
        vuln_by_severity = {
            'Critical': [v for v in vulnerabilities if v.get('severity') == 'Critical'],
            'High': [v for v in vulnerabilities if v.get('severity') == 'High'],
            'Medium': [v for v in vulnerabilities if v.get('severity') == 'Medium'],
            'Low': [v for v in vulnerabilities if v.get('severity') == 'Low']
        }
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(vulnerabilities)
        
        return {
            'scan_results': scan_results,
            'target': scan_results.get('target', 'Unknown'),
            'start_time': scan_results.get('start_time', 'Unknown'),
            'end_time': scan_results.get('end_time', 'Unknown'),
            'duration': scan_results.get('duration', 0),
            'summary': summary,
            'vulnerabilities': vulnerabilities,
            'vuln_by_severity': vuln_by_severity,
            'total_vulns': len(vulnerabilities),
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score),
            'crawl_summary': scan_results.get('crawl_results', {}).get('crawl_summary', {}),
            'waf_detection': scan_results.get('waf_detection', {}),
            'report_generated': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate overall risk score based on vulnerabilities"""
        severity_weights = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 1
        }
        
        total_score = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            weight = severity_weights.get(severity, 1)
            confidence = vuln.get('confidence', 'Medium')
            
            # Adjust score based on confidence
            confidence_multiplier = {
                'High': 1.0,
                'Medium': 0.8,
                'Low': 0.5
            }.get(confidence, 0.5)
            
            total_score += weight * confidence_multiplier
        
        # Normalize to 0-100 scale
        max_possible = len(vulnerabilities) * 10 if vulnerabilities else 1
        normalized_score = (total_score / max_possible) * 100
        
        return min(normalized_score, 100)
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Get risk level based on score"""
        if risk_score >= 80:
            return 'Critical'
        elif risk_score >= 60:
            return 'High'
        elif risk_score >= 30:
            return 'Medium'
        elif risk_score > 0:
            return 'Low'
        else:
            return 'Minimal'
    
    def _generate_fallback_html(self, data: Dict) -> str:
        """Generate HTML report without template"""
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebStrike Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .vulnerability {{ margin: 15px 0; padding: 15px; border-left: 4px solid #e74c3c; background: #fff; }}
        .critical {{ border-left-color: #e74c3c; }}
        .high {{ border-left-color: #f39c12; }}
        .medium {{ border-left-color: #f1c40f; }}
        .low {{ border-left-color: #27ae60; }}
        .severity {{ font-weight: bold; padding: 3px 8px; border-radius: 3px; color: white; }}
        .severity.critical {{ background: #e74c3c; }}
        .severity.high {{ background: #f39c12; }}
        .severity.medium {{ background: #f1c40f; color: #333; }}
        .severity.low {{ background: #27ae60; }}
        .code {{ background: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #34495e; color: white; }}
        .risk-score {{ font-size: 24px; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ WebStrike Security Report</h1>
        <p><strong>Target:</strong> {data['target']}</p>
        <p><strong>Scan Date:</strong> {data['start_time']}</p>
        <p><strong>Duration:</strong> {data['duration']:.2f} seconds</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Risk Level:</strong> <span class="risk-score">{data['risk_level']}</span></p>
        <p><strong>Risk Score:</strong> {data['risk_score']:.1f}/100</p>
        <p><strong>Total Vulnerabilities:</strong> {data['total_vulns']}</p>
        
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
            </tr>
            <tr><td>Critical</td><td>{len(data['vuln_by_severity']['Critical'])}</td></tr>
            <tr><td>High</td><td>{len(data['vuln_by_severity']['High'])}</td></tr>
            <tr><td>Medium</td><td>{len(data['vuln_by_severity']['Medium'])}</td></tr>
            <tr><td>Low</td><td>{len(data['vuln_by_severity']['Low'])}</td></tr>
        </table>
    </div>
    
    <h2>Detailed Findings</h2>
"""
        
        # Add vulnerabilities
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            vulns = data['vuln_by_severity'][severity]
            if vulns:
                html += f"<h3>{severity} Severity ({len(vulns)} findings)</h3>"
                for i, vuln in enumerate(vulns, 1):
                    html += f"""
    <div class="vulnerability {severity.lower()}">
        <h4>{i}. {vuln.get('type', 'Unknown Vulnerability')}</h4>
        <p><span class="severity {severity.lower()}">{severity}</span></p>
        <p><strong>Evidence:</strong> {vuln.get('evidence', 'No evidence provided')}</p>
        <p><strong>Recommendation:</strong> {vuln.get('recommendation', 'No recommendation provided')}</p>
        {f'<div class="code">{vuln["payload"]}</div>' if vuln.get('payload') else ''}
    </div>
"""
        
        html += """
    <div class="summary">
        <h2>Scan Statistics</h2>
        <ul>
            <li><strong>URLs Scanned:</strong> """ + str(data['summary'].get('urls_scanned', 0)) + """</li>
            <li><strong>Forms Scanned:</strong> """ + str(data['summary'].get('forms_scanned', 0)) + """</li>
            <li><strong>Modules Used:</strong> """ + ', '.join(data['summary'].get('modules_used', [])) + """</li>
        </ul>
    </div>
    
    <footer style="margin-top: 40px; padding: 20px; background: #ecf0f1; text-align: center;">
        <p><strong>WebStrike Security Scanner</strong> - Generated on """ + data['report_generated'] + """</p>
        <p>This report contains confidential security information and should be handled accordingly.</p>
    </footer>
</body>
</html>
"""
        return html
    
    def create_template_files(self):
        """Create template files if they don't exist"""
        template_files = {
            'html_report.html': self._get_html_template(),
            'pdf_report.html': self._get_pdf_template()
        }
        
        os.makedirs(self.template_dir, exist_ok=True)
        
        for filename, content in template_files.items():
            template_path = os.path.join(self.template_dir, filename)
            if not os.path.exists(template_path):
                with open(template_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                logger.info(f"Created template: {template_path}")
    
    def _get_html_template(self) -> str:
        """Get HTML template content"""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebStrike Security Report - {{ target }}</title>
    <style>
        /* Add your custom CSS styles here */
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .vulnerability { margin: 15px 0; padding: 15px; border-left: 4px solid #e74c3c; }
        /* Add more styles as needed */
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ WebStrike Security Report</h1>
        <p><strong>Target:</strong> {{ target }}</p>
        <p><strong>Scan Date:</strong> {{ start_time }}</p>
    </div>
    
    <!-- Add your template content here -->
    
    {% for vuln in vulnerabilities %}
    <div class="vulnerability">
        <h4>{{ vuln.type }}</h4>
        <p>{{ vuln.evidence }}</p>
    </div>
    {% endfor %}
</body>
</html>"""
    
    def _get_pdf_template(self) -> str:
        """Get PDF template content (similar to HTML but optimized for PDF)"""
        return self._get_html_template()  # For now, use same template
