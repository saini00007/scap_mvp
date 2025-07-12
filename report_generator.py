#!/usr/bin/env python3
"""
Report Generator for SCAP MVP
Creates compliance reports in various formats
"""

import os
import json
import logging
import datetime
from typing import Dict, List, Any, Optional
from tabulate import tabulate

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generator for compliance reports in various formats"""
    
    def __init__(self, results: Dict[str, Any], summary: Dict[str, Any], system_info: Dict[str, Any], 
                 output_dir: str = "reports", include_evidence: bool = True, include_remediation: bool = True):
        """
        Initialize the report generator
        
        Args:
            results: Dictionary of check results
            summary: Summary statistics
            system_info: Target system information
            output_dir: Directory to save reports
            include_evidence: Whether to include evidence in reports
            include_remediation: Whether to include remediation advice
        """
        self.results = results
        self.summary = summary
        self.system_info = system_info
        self.output_dir = output_dir
        self.include_evidence = include_evidence
        self.include_remediation = include_remediation
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                logger.info(f"Created output directory: {output_dir}")
            except Exception as e:
                logger.error(f"Failed to create output directory: {e}")
    
    def generate_console_report(self) -> str:
        """
        Generate a text report for console output
        
        Returns:
            str: Formatted text report
        """
        report = []
        
        # Add header
        report.append("=" * 80)
        report.append("SCAP COMPLIANCE SCAN REPORT")
        report.append("=" * 80)
        report.append("")
        
        # Add system information
        report.append("SYSTEM INFORMATION")
        report.append("-" * 80)
        if self.system_info:
            for key, value in self.system_info.items():
                report.append(f"{key}: {value}")
        else:
            report.append("No system information available")
        report.append("")
        
        # Add scan summary
        report.append("SCAN SUMMARY")
        report.append("-" * 80)
        report.append(f"Scan Time: {self.timestamp}")
        report.append(f"Total Rules: {self.summary['total']}")
        report.append(f"Passed: {self.summary['pass']}")
        report.append(f"Failed: {self.summary['fail']}")
        report.append(f"Errors: {self.summary['error']}")
        report.append(f"Compliance: {self.summary['compliance_percentage']:.2f}%")
        report.append("")
        
        # Add severity breakdown
        report.append("SEVERITY BREAKDOWN")
        report.append("-" * 80)
        headers = ["Severity", "Total", "Pass", "Fail", "Error", "Compliance %"]
        rows = []
        
        for severity, counts in self.summary['by_severity'].items():
            if counts['total'] > 0:
                compliance = (counts['pass'] / (counts['pass'] + counts['fail'])) * 100 if (counts['pass'] + counts['fail']) > 0 else 0
                rows.append([
                    severity.upper(),
                    counts['total'],
                    counts['pass'],
                    counts['fail'],
                    counts['error'],
                    f"{compliance:.2f}%"
                ])
                
        report.append(tabulate(rows, headers=headers, tablefmt="simple"))
        report.append("")
        
        # Add failed checks
        failed_checks = [r for r in self.results.values() if r.get('status') == 'fail']
        if failed_checks:
            report.append("FAILED CHECKS")
            report.append("-" * 80)
            
            for check in failed_checks:
                report.append(f"Rule: {check.get('title', 'Unknown')}")
                report.append(f"Severity: {check.get('severity', 'unknown').upper()}")
                report.append(f"Description: {check.get('description', '')}")
                report.append(f"Expected: {check.get('expected')}")
                report.append(f"Actual: {check.get('actual')}")
                
                if self.include_evidence and 'evidence' in check:
                    report.append(f"Evidence: {check.get('evidence')}")
                    
                if self.include_remediation:
                    remediation = self._get_remediation_advice(check)
                    if remediation:
                        report.append(f"Remediation: {remediation}")
                        
                report.append("")
        else:
            report.append("No failed checks!")
            report.append("")
            
        # Add error checks
        error_checks = [r for r in self.results.values() if r.get('status') == 'error']
        if error_checks:
            report.append("CHECKS WITH ERRORS")
            report.append("-" * 80)
            
            for check in error_checks:
                report.append(f"Rule: {check.get('title', 'Unknown')}")
                report.append(f"Error: {check.get('message', 'Unknown error')}")
                report.append("")
                
        return "\n".join(report)
    
    def generate_json_report(self, output_file: Optional[str] = None) -> str:
        """
        Generate a JSON report
        
        Args:
            output_file: File to save the report to (optional)
            
        Returns:
            str: Path to the saved report file
        """
        # Prepare report data
        report_data = {
            'scan_info': {
                'timestamp': self.timestamp,
                'system_info': self.system_info
            },
            'summary': self.summary,
            'results': self.results
        }
        
        # Generate JSON
        json_report = json.dumps(report_data, indent=2)
        
        # Save to file if requested
        if output_file:
            file_path = output_file
        else:
            file_path = os.path.join(self.output_dir, f"scap_report_{self.timestamp}.json")
            
        try:
            with open(file_path, 'w') as f:
                f.write(json_report)
            logger.info(f"JSON report saved to {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Failed to save JSON report: {e}")
            return ""
    
    def generate_html_report(self, output_file: Optional[str] = None) -> str:
        """
        Generate an HTML report
        
        Args:
            output_file: File to save the report to (optional)
            
        Returns:
            str: Path to the saved report file
        """
        # Prepare HTML content
        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html>")
        html.append("<head>")
        html.append("  <title>SCAP Compliance Report</title>")
        html.append("  <style>")
        html.append("    body { font-family: Arial, sans-serif; margin: 20px; }")
        html.append("    h1 { color: #2c3e50; }")
        html.append("    h2 { color: #34495e; margin-top: 20px; }")
        html.append("    .summary { margin: 20px 0; }")
        html.append("    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }")
        html.append("    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }")
        html.append("    th { background-color: #f2f2f2; }")
        html.append("    tr:nth-child(even) { background-color: #f9f9f9; }")
        html.append("    .pass { color: green; }")
        html.append("    .fail { color: red; }")
        html.append("    .error { color: orange; }")
        html.append("    .critical { background-color: #ffdddd; }")
        html.append("    .high { background-color: #ffe6e6; }")
        html.append("    .medium { background-color: #ffffcc; }")
        html.append("    .low { background-color: #e6ffe6; }")
        html.append("    .progress-container { width: 100%; background-color: #f1f1f1; border-radius: 5px; }")
        html.append("    .progress-bar { height: 30px; border-radius: 5px; text-align: center; line-height: 30px; color: white; }")
        html.append("  </style>")
        html.append("</head>")
        html.append("<body>")
        
        # Header
        html.append("  <h1>SCAP Compliance Report</h1>")
        
        # System Information
        html.append("  <h2>System Information</h2>")
        html.append("  <table>")
        html.append("    <tr><th>Property</th><th>Value</th></tr>")
        if self.system_info:
            for key, value in self.system_info.items():
                html.append(f"    <tr><td>{key}</td><td>{value}</td></tr>")
        else:
            html.append("    <tr><td colspan='2'>No system information available</td></tr>")
        html.append("  </table>")
        
        # Scan Summary
        html.append("  <h2>Scan Summary</h2>")
        html.append("  <div class='summary'>")
        html.append(f"    <p><strong>Scan Time:</strong> {self.timestamp}</p>")
        html.append(f"    <p><strong>Total Rules:</strong> {self.summary['total']}</p>")
        
        # Compliance Progress Bar
        compliance = self.summary['compliance_percentage']
        bar_color = "#4CAF50"  # Green
        if compliance < 50:
            bar_color = "#f44336"  # Red
        elif compliance < 80:
            bar_color = "#ff9800"  # Orange
            
        html.append("    <div class='progress-container'>")
        html.append(f"      <div class='progress-bar' style='width: {compliance}%; background-color: {bar_color};'>")
        html.append(f"        {compliance:.2f}% Compliant")
        html.append("      </div>")
        html.append("    </div>")
        
        html.append("  </div>")
        
        # Results by Severity
        html.append("  <h2>Results by Severity</h2>")
        html.append("  <table>")
        html.append("    <tr><th>Severity</th><th>Total</th><th>Pass</th><th>Fail</th><th>Error</th><th>Compliance %</th></tr>")
        
        for severity, counts in self.summary['by_severity'].items():
            if counts['total'] > 0:
                compliance = (counts['pass'] / (counts['pass'] + counts['fail'])) * 100 if (counts['pass'] + counts['fail']) > 0 else 0
                html.append(f"    <tr class='{severity}'>")
                html.append(f"      <td>{severity.upper()}</td>")
                html.append(f"      <td>{counts['total']}</td>")
                html.append(f"      <td class='pass'>{counts['pass']}</td>")
                html.append(f"      <td class='fail'>{counts['fail']}</td>")
                html.append(f"      <td class='error'>{counts['error']}</td>")
                html.append(f"      <td>{compliance:.2f}%</td>")
                html.append("    </tr>")
                
        html.append("  </table>")
        
        # Failed Checks
        html.append("  <h2>Failed Checks</h2>")
        failed_checks = [r for r in self.results.values() if r.get('status') == 'fail']
        if failed_checks:
            html.append("  <table>")
            html.append("    <tr><th>Rule</th><th>Severity</th><th>Expected</th><th>Actual</th>")
            if self.include_evidence:
                html.append("<th>Evidence</th>")
            html.append("</tr>")
            
            for check in failed_checks:
                severity = check.get('severity', 'unknown')
                html.append(f"    <tr class='{severity}'>")
                html.append(f"      <td>{check.get('title', 'Unknown')}</td>")
                html.append(f"      <td>{severity.upper()}</td>")
                html.append(f"      <td>{check.get('expected')}</td>")
                html.append(f"      <td>{check.get('actual')}</td>")
                if self.include_evidence:
                    html.append(f"      <td>{check.get('evidence', '')}</td>")
                html.append("    </tr>")
                
            html.append("  </table>")
        else:
            html.append("  <p>No failed checks!</p>")
            
        # Error Checks
        error_checks = [r for r in self.results.values() if r.get('status') == 'error']
        if error_checks:
            html.append("  <h2>Checks with Errors</h2>")
            html.append("  <table>")
            html.append("    <tr><th>Rule</th><th>Error</th></tr>")
            
            for check in error_checks:
                html.append("    <tr>")
                html.append(f"      <td>{check.get('title', 'Unknown')}</td>")
                html.append(f"      <td>{check.get('message', 'Unknown error')}</td>")
                html.append("    </tr>")
                
            html.append("  </table>")
            
        # All Checks
        html.append("  <h2>All Checks</h2>")
        html.append("  <table>")
        html.append("    <tr><th>Rule</th><th>Severity</th><th>Status</th><th>Description</th></tr>")
        
        for check in self.results.values():
            status = check.get('status', 'error')
            status_class = 'pass' if status == 'pass' else ('fail' if status == 'fail' else 'error')
            severity = check.get('severity', 'unknown')
            
            html.append(f"    <tr class='{severity}'>")
            html.append(f"      <td>{check.get('title', 'Unknown')}</td>")
            html.append(f"      <td>{severity.upper()}</td>")
            html.append(f"      <td class='{status_class}'>{status.upper()}</td>")
            html.append(f"      <td>{check.get('description', '')}</td>")
            html.append("    </tr>")
            
        html.append("  </table>")
        
        # Footer
        html.append("  <div style='margin-top: 30px; text-align: center; color: #777;'>")
        html.append("    <p>Generated by SCAP MVP Scanner</p>")
        html.append(f"    <p>Report Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
        html.append("  </div>")
        
        html.append("</body>")
        html.append("</html>")
        
        # Save to file if requested
        if output_file:
            file_path = output_file
        else:
            file_path = os.path.join(self.output_dir, f"scap_report_{self.timestamp}.html")
            
        try:
            with open(file_path, 'w') as f:
                f.write("\n".join(html))
            logger.info(f"HTML report saved to {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Failed to save HTML report: {e}")
            return ""
    
    def _get_remediation_advice(self, check: Dict[str, Any]) -> str:
        """
        Get remediation advice for a failed check
        
        Args:
            check: The failed check
            
        Returns:
            str: Remediation advice
        """
        rule_id = check.get('rule_id', '')
        title = check.get('title', '')
        
        # Simple remediation advice based on rule ID or title
        if 'password_length' in rule_id or 'Password' in title:
            return "Update the minimum password length policy in Group Policy: Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy"
            
        elif 'firewall' in rule_id or 'Firewall' in title:
            return "Enable Windows Firewall service: Open Services.msc, find 'Windows Defender Firewall' service, set to Automatic and Start the service"
            
        elif 'auto_updates' in rule_id or 'Automatic Updates' in title:
            return "Enable Windows automatic updates: Control Panel > System and Security > Windows Update > Change settings"
            
        elif 'guest' in rule_id or 'Guest Account' in title:
            return "Disable the Guest account: Computer Management > Local Users and Groups > Users > Guest > Right-click > Properties > Check 'Account is disabled'"
            
        elif 'log_size' in rule_id or 'Log Size' in title:
            return "Increase the security log size: Event Viewer > Windows Logs > Security > Right-click > Properties > Maximum log size"
            
        # Default remediation advice
        return "Review the security policy and ensure the system is configured according to security requirements"


def main():
    """Test function for the report generator"""
    # Sample data
    results = {
        'rule1': {
            'rule_id': 'rule1',
            'title': 'Password Minimum Length',
            'description': 'Passwords must be at least 8 characters long',
            'severity': 'high',
            'status': 'fail',
            'message': 'Password minimum length is too short',
            'expected': '8 or greater',
            'actual': '6',
            'evidence': 'HKLM\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\MinimumPasswordLength = 6'
        },
        'rule2': {
            'rule_id': 'rule2',
            'title': 'Windows Firewall Enabled',
            'description': 'Windows Firewall service must be running',
            'severity': 'high',
            'status': 'pass',
            'message': 'Windows Firewall service is running',
            'expected': 'running',
            'actual': 'running',
            'evidence': 'Service MpsSvc (Status: Running, Start Type: Automatic)'
        }
    }
    
    summary = {
        'total': 2,
        'pass': 1,
        'fail': 1,
        'error': 0,
        'compliance_percentage': 50.0,
        'by_severity': {
            'high': {'total': 2, 'pass': 1, 'fail': 1, 'error': 0},
            'medium': {'total': 0, 'pass': 0, 'fail': 0, 'error': 0},
            'low': {'total': 0, 'pass': 0, 'fail': 0, 'error': 0},
            'unknown': {'total': 0, 'pass': 0, 'fail': 0, 'error': 0}
        }
    }
    
    system_info = {
        'ComputerName': 'DESKTOP-TEST',
        'OSVersion': 'Microsoft Windows 10 Pro',
        'LastBootTime': '2023-01-01T12:00:00Z'
    }
    
    # Generate reports
    generator = ReportGenerator(results, summary, system_info)
    
    # Console report
    console_report = generator.generate_console_report()
    print(console_report)
    
    # JSON report
    json_path = generator.generate_json_report()
    print(f"JSON report saved to: {json_path}")
    
    # HTML report
    html_path = generator.generate_html_report()
    print(f"HTML report saved to: {html_path}")


if __name__ == "__main__":
    main() 