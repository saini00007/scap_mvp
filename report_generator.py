#!/usr/bin/env python3
"""
Advanced Report Generator for SCAP MVP
Generates modern, minimalistic, and interactive compliance reports
"""

import os
import json
import logging
import datetime
from typing import Dict, Any, Optional
from tabulate import tabulate

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, results: Dict[str, Any], summary: Dict[str, Any], system_info: Dict[str, Any],
                 output_dir: str = "reports", include_evidence: bool = True, include_remediation: bool = True):
        self.results = results
        self.summary = summary
        self.system_info = system_info
        self.output_dir = output_dir
        self.include_evidence = include_evidence
        self.include_remediation = include_remediation
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                logger.info(f"Created output directory: {output_dir}")
            except Exception as e:
                logger.error(f"Failed to create output directory: {e}")

    def generate_html_report(self, output_file: Optional[str] = None) -> str:
        html = []
        html.append("<!DOCTYPE html><html lang='en'>")
        html.append("<head><meta charset='UTF-8'>")
        html.append("<meta name='viewport' content='width=device-width, initial-scale=1.0'>")
        html.append("<title>Security Compliance Report</title>")
        html.append("<link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css'>")
        html.append("<script src='https://cdn.jsdelivr.net/npm/chart.js'></script>")
        html.append("<script src='https://cdn.jsdelivr.net/npm/chartjs-plugin-datalabels@2.0.0'></script>")
        html.append("<style>")
        html.append("""
        :root {
            --primary: #2563eb;
            --primary-light: #3b82f6;
            --secondary: #64748b;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --dark: #1e293b;
            --light: #f1f5f9;
            --white: #ffffff;
            --gray-100: #f1f5f9;
            --gray-200: #e2e8f0;
            --gray-300: #cbd5e1;
            --gray-400: #94a3b8;
            --gray-500: #64748b;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            font-size: 16px;
            line-height: 1.5;
            color: var(--dark);
            background-color: var(--gray-100);
            padding: 0;
            margin: 0;
        }
        
        .container {
            max-width: 1280px;
            margin: 0 auto;
            padding: 0 1rem;
        }
        
        .header {
            background-color: var(--white);
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            position: sticky;
            top: 0;
            z-index: 10;
            padding: 1.5rem 0;
        }
        
        .header .container {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            font-weight: 700;
            font-size: 1.5rem;
            color: var(--primary);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .logo i {
            font-size: 1.75rem;
        }
        
        .timestamp {
            color: var(--gray-500);
            font-size: 0.875rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .card {
            background-color: var(--white);
            border-radius: 0.5rem;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        
        .section-title {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--dark);
            margin-bottom: 1.25rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .section-title i {
            color: var(--primary);
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .summary-card {
            background-color: var(--white);
            border-radius: 0.5rem;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }
        
        .summary-card .title {
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--gray-500);
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .summary-card .value {
            font-size: 2rem;
            font-weight: 700;
            line-height: 1;
        }
        
        .primary {
            color: var(--primary);
        }
        
        .success {
            color: var(--success);
        }
        
        .danger {
            color: var(--danger);
        }
        
        .warning {
            color: var(--warning);
        }
        
        .flex-row {
            display: flex;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
        }
        
        .flex-between {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .chart-container {
            position: relative;
            height: 300px;
            max-width: 100%;
            margin-bottom: 2rem;
        }
        
        .chart-container.small {
            height: 220px;
        }
        
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.75rem;
            border-radius: 2rem;
            font-size: 0.75rem;
            font-weight: 600;
            white-space: nowrap;
        }
        
        .badge.primary {
            background-color: rgba(37, 99, 235, 0.1);
            color: var(--primary);
        }
        
        .badge.success {
            background-color: rgba(16, 185, 129, 0.1);
            color: var(--success);
        }
        
        .badge.danger {
            background-color: rgba(239, 68, 68, 0.1);
            color: var(--danger);
        }
        
        .badge.warning {
            background-color: rgba(245, 158, 11, 0.1);
            color: var(--warning);
        }
        
        .badge i {
            margin-right: 0.25rem;
        }
        
        .progress-container {
            width: 100%;
            height: 10px;
            background-color: var(--gray-200);
            border-radius: 1rem;
            overflow: hidden;
            margin: 0.75rem 0;
        }
        
        .progress-bar {
            height: 100%;
            transition: width 0.4s ease;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0 2rem;
            font-size: 0.875rem;
        }
        
        th {
            text-align: left;
            padding: 1rem;
            background-color: var(--gray-100);
            font-weight: 600;
            color: var(--gray-500);
            border-bottom: 2px solid var(--gray-200);
            position: sticky;
            top: 71px;
        }
        
        td {
            padding: 1rem;
            border-bottom: 1px solid var(--gray-200);
            vertical-align: middle;
        }
        
        tr:last-child td {
            border-bottom: none;
        }
        
        tr:hover {
            background-color: var(--gray-100);
        }
        
        .status-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 24px;
            height: 24px;
            border-radius: 50%;
            font-size: 12px;
            margin-right: 0.5rem;
        }
        
        .pass .status-icon {
            background-color: rgba(16, 185, 129, 0.2);
            color: var(--success);
        }
        
        .fail .status-icon {
            background-color: rgba(239, 68, 68, 0.2);
            color: var(--danger);
        }
        
        .error .status-icon {
            background-color: rgba(245, 158, 11, 0.2);
            color: var(--warning);
        }
        
        .severity-high {
            border-left: 4px solid var(--danger);
        }
        
        .severity-medium {
            border-left: 4px solid var(--warning);
        }
        
        .severity-low {
            border-left: 4px solid var(--success);
        }
        
        .expandable-row {
            cursor: pointer;
        }
        
        .detail-row {
            background-color: var(--gray-100);
            display: none;
        }
        
        .detail-row.active {
            display: table-row;
        }
        
        .detail-content {
            padding: 1.5rem;
        }
        
        .detail-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .detail-item {
            background-color: var(--white);
            border-radius: 0.5rem;
            padding: 1rem;
        }
        
        .detail-label {
            font-size: 0.75rem;
            color: var(--gray-500);
            margin-bottom: 0.25rem;
        }
        
        .detail-value {
            font-weight: 500;
        }
        
        .tabs {
            display: flex;
            border-bottom: 1px solid var(--gray-300);
            margin-bottom: 1.5rem;
        }
        
        .tab {
            padding: 0.75rem 1.5rem;
            cursor: pointer;
            font-weight: 500;
            border-bottom: 2px solid transparent;
        }
        
        .tab.active {
            border-bottom: 2px solid var(--primary);
            color: var(--primary);
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .action-btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 0.75rem 1.5rem;
            font-weight: 500;
            background-color: var(--primary);
            color: var(--white);
            border: none;
            border-radius: 0.5rem;
            cursor: pointer;
            transition: background-color 0.2s;
        }
        
        .action-btn:hover {
            background-color: var(--primary-light);
        }
        
        .action-btn i {
            margin-right: 0.5rem;
        }
        
        .footer {
            background-color: var(--dark);
            color: var(--white);
            padding: 2rem 0;
            margin-top: 2rem;
            font-size: 0.875rem;
        }
        
        .footer .container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .info-item {
            display: flex;
            flex-direction: column;
        }
        
        .info-label {
            font-size: 0.75rem;
            color: var(--gray-500);
            margin-bottom: 0.25rem;
        }
        
        .info-value {
            font-weight: 500;
        }
        
        @media print {
            .header {
                position: static;
            }
            
            .card, .summary-card {
                break-inside: avoid;
                page-break-inside: avoid;
            }
            
            .action-btn {
                display: none;
            }
            
            th {
                position: static;
            }
        }
        
        @media (max-width: 768px) {
            .header .container {
                flex-direction: column;
                gap: 0.5rem;
                align-items: flex-start;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
            }
            
            table {
                font-size: 0.75rem;
            }
            
            th, td {
                padding: 0.75rem;
            }
        }
        """)
        html.append("</style></head><body>")

        # Header
        html.append("<header class='header'>")
        html.append("<div class='container'>")
        html.append("<div class='logo'><i class='fas fa-shield-alt'></i>Security Compliance Report</div>")
        html.append(f"<div class='timestamp'><i class='fas fa-calendar-alt'></i>Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>")
        html.append("</div>")
        html.append("</header>")

        # Main content
        html.append("<main class='container' style='padding-top: 1.5rem;'>")
        
        # System Information
        html.append("<div class='card'>")
        html.append("<h2 class='section-title'><i class='fas fa-server'></i>System Information</h2>")
        html.append("<div class='info-grid'>")
        for key, value in self.system_info.items():
            html.append(f"<div class='info-item'>")
            html.append(f"<div class='info-label'>{key}</div>")
            html.append(f"<div class='info-value'>{value}</div>")
            html.append(f"</div>")
        html.append("</div>")
        html.append("</div>")
        
        # Compliance Summary
        compliance = self.summary.get('compliance_percentage', 0)
        compliance_color = "success" if compliance >= 80 else ("warning" if compliance >= 50 else "danger")
        
        html.append("<div class='card'>")
        html.append("<h2 class='section-title'><i class='fas fa-chart-pie'></i>Compliance Overview</h2>")
        
        html.append("<div class='summary-grid'>")
        
        # Overall compliance
        html.append("<div class='summary-card'>")
        html.append("<div class='title'><i class='fas fa-percentage'></i>Overall Compliance</div>")
        html.append(f"<div class='value {compliance_color}'>{compliance:.1f}%</div>")
        html.append("<div class='progress-container'>")
        html.append(f"<div class='progress-bar {compliance_color}' style='width: {compliance}%;'></div>")
        html.append("</div>")
        html.append("</div>")
        
        # Total checks
        html.append("<div class='summary-card'>")
        html.append("<div class='title'><i class='fas fa-list-check'></i>Total Checks</div>")
        html.append(f"<div class='value primary'>{self.summary.get('total', 0)}</div>")
        html.append("</div>")
        
        # Pass rate
        html.append("<div class='summary-card'>")
        html.append("<div class='title'><i class='fas fa-check'></i>Passed</div>")
        html.append(f"<div class='value success'>{self.summary.get('pass', 0)}</div>")
        html.append("</div>")
        
        # Fail rate
        html.append("<div class='summary-card'>")
        html.append("<div class='title'><i class='fas fa-xmark'></i>Failed</div>")
        html.append(f"<div class='value danger'>{self.summary.get('fail', 0)}</div>")
        html.append("</div>")
        
        html.append("</div>") # End of summary grid
        
        # Charts
        html.append("<div class='flex-row'>")
        html.append("<div class='chart-container' style='flex: 1;'><canvas id='summaryChart'></canvas></div>")
        html.append("<div class='chart-container' style='flex: 1;'><canvas id='severityChart'></canvas></div>")
        html.append("</div>")
        html.append("</div>") # End of compliance overview card
        
        # Severity Breakdown
        html.append("<div class='card'>")
        html.append("<h2 class='section-title'><i class='fas fa-layer-group'></i>Severity Analysis</h2>")
        
        html.append("<table>")
        html.append("<thead><tr>")
        html.append("<th>Severity</th><th>Total</th><th>Pass</th><th>Fail</th><th>Error</th><th>Compliance %</th>")
        html.append("</tr></thead><tbody>")
        
        severity_order = ['high', 'medium', 'low']
        for severity in severity_order:
            if severity in self.summary['by_severity']:
                counts = self.summary['by_severity'][severity]
                total = counts['total']
                passed = counts['pass']
                failed = counts['fail']
                error = counts['error']
                compliance_pct = (passed / (passed + failed)) * 100 if (passed + failed) > 0 else 0
                
                severity_class = "danger" if severity == "high" else ("warning" if severity == "medium" else "success")
                
                html.append(f"<tr>")
                html.append(f"<td><span class='badge {severity_class}'><i class='fas fa-exclamation-triangle'></i>{severity.upper()}</span></td>")
                html.append(f"<td>{total}</td>")
                html.append(f"<td class='success'>{passed}</td>")
                html.append(f"<td class='danger'>{failed}</td>")
                html.append(f"<td class='warning'>{error}</td>")
                html.append(f"<td>")
                html.append(f"<div class='flex-between'>")
                html.append(f"<span>{compliance_pct:.1f}%</span>")
                html.append(f"<div class='progress-container' style='width: 100px; margin: 0 0 0 10px;'>")
                html.append(f"<div class='progress-bar {severity_class}' style='width: {compliance_pct}%;'></div>")
                html.append(f"</div>")
                html.append(f"</div>")
                html.append(f"</td>")
                html.append(f"</tr>")
                
        html.append("</tbody></table>")
        html.append("</div>") # End of severity breakdown card
        
        # Failed Checks with Interactive Details
        html.append("<div class='card'>")
        html.append("<h2 class='section-title'><i class='fas fa-triangle-exclamation'></i>Failed Controls</h2>")
        
        html.append("<table id='failedChecksTable'>")
        html.append("<thead><tr>")
        html.append("<th>Status</th><th>Rule</th><th>Severity</th><th>Expected</th><th>Actual</th><th>Actions</th>")
        html.append("</tr></thead><tbody>")
        
        # Sort by severity (high to low)
        severity_order = {"high": 3, "medium": 2, "low": 1, "": 0}
        failed_checks = [check for check in self.results.values() if check.get('status') == 'fail']
        failed_checks.sort(key=lambda x: severity_order.get(x.get('severity', '').lower(), 0), reverse=True)
        
        for i, check in enumerate(failed_checks):
            severity = check.get('severity', '').lower()
            severity_class = "danger" if severity == "high" else ("warning" if severity == "medium" else "success")
            
            html.append(f"<tr class='expandable-row severity-{severity}' data-row='{i}'>")
            
            # Status
            html.append(f"<td class='fail'><span class='status-icon'><i class='fas fa-xmark'></i></span></td>")
            
            # Rule
            html.append(f"<td>{check.get('title', 'Unknown')}</td>")
            
            # Severity
            html.append(f"<td><span class='badge {severity_class}'>{severity.upper()}</span></td>")
            
            # Expected
            html.append(f"<td>{check.get('expected', '')}</td>")
            
            # Actual
            html.append(f"<td>{check.get('actual', '')}</td>")
            
            # Actions
            html.append(f"<td><button class='badge primary' onclick='toggleDetails({i})'><i class='fas fa-eye'></i>Details</button></td>")
            
            html.append("</tr>")
            
            # Detail row (hidden by default)
            html.append(f"<tr id='detail-row-{i}' class='detail-row'>")
            html.append("<td colspan='6'>")
            html.append("<div class='detail-content'>")
            
            # Description
            html.append("<div class='detail-item'>")
            html.append("<div class='detail-label'>Description</div>")
            html.append(f"<div class='detail-value'>{check.get('description', '')}</div>")
            html.append("</div>")
            
            if self.include_evidence:
                html.append("<div class='detail-item'>")
                html.append("<div class='detail-label'>Evidence</div>")
                html.append(f"<div class='detail-value'>{check.get('evidence', '')}</div>")
                html.append("</div>")
                
            if self.include_remediation:
                html.append("<div class='detail-item'>")
                html.append("<div class='detail-label'>Remediation</div>")
                html.append(f"<div class='detail-value'>{self._get_remediation_advice(check)}</div>")
                html.append("</div>")
            
            html.append("</div>") # End of detail content
            html.append("</td>")
            html.append("</tr>")
            
        html.append("</tbody></table>")
        html.append("</div>") # End of failed checks card
        
        # Export Actions
        html.append("<div class='flex-between' style='margin-top: 2rem;'>")
        html.append("<button class='action-btn' onclick='window.print()'><i class='fas fa-download'></i>Export PDF</button>")
        html.append("</div>")
        
        html.append("</main>") # End of main content
        
        # Footer
        html.append("<footer class='footer'>")
        html.append("<div class='container'>")
        html.append("<div>SCAP MVP Security Compliance Scanner</div>")
        html.append(f"<div>Report ID: {self.timestamp}</div>")
        html.append("</div>")
        html.append("</footer>")
        
        # Scripts
        html.append("<script>")
        
        # Chart for Summary
        html.append("document.addEventListener('DOMContentLoaded', function() {")
        html.append("  const ctx = document.getElementById('summaryChart').getContext('2d');")
        html.append("  const summaryChart = new Chart(ctx, {")
        html.append("    type: 'bar',")
        html.append("    data: {")
        html.append("      labels: ['Pass', 'Fail', 'Error'],")
        html.append("      datasets: [{")
        html.append(f"        data: [{self.summary.get('pass', 0)}, {self.summary.get('fail', 0)}, {self.summary.get('error', 0)}],")
        html.append("        backgroundColor: ['#10b981', '#ef4444', '#f59e0b'],")
        html.append("        borderRadius: 8,")
        html.append("        borderWidth: 0")
        html.append("      }]")
        html.append("    },")
        html.append("    options: {")
        html.append("      responsive: true,")
        html.append("      maintainAspectRatio: false,")
        html.append("      plugins: {")
        html.append("        legend: { display: false },")
        html.append("        title: {")
        html.append("          display: true,")
        html.append("          text: 'Check Results',")
        html.append("          font: { size: 16, weight: 'bold' }")
        html.append("        },")
        html.append("        datalabels: {")
        html.append("          color: '#fff',")
        html.append("          font: { weight: 'bold' },")
        html.append("          formatter: (value) => value > 0 ? value : ''")
        html.append("        }")
        html.append("      },")
        html.append("      scales: {")
        html.append("        y: {")
        html.append("          beginAtZero: true,")
        html.append("          grid: { display: false }")
        html.append("        },")
        html.append("        x: {")
        html.append("          grid: { display: false }")
        html.append("        }")
        html.append("      }")
        html.append("    }")
        html.append("  });")
        
        # Chart for Severity Breakdown
        severity_labels = [s.title() for s in self.summary['by_severity'].keys()]
        severity_values_total = [self.summary['by_severity'][s]['total'] for s in self.summary['by_severity']]
        severity_values_pass = [self.summary['by_severity'][s]['pass'] for s in self.summary['by_severity']]
        severity_values_fail = [self.summary['by_severity'][s]['fail'] for s in self.summary['by_severity']]

        html.append("  const severityCtx = document.getElementById('severityChart').getContext('2d');")
        html.append("  const severityChart = new Chart(severityCtx, {")
        html.append("    type: 'bar',")
        html.append("    data: {")
        html.append(f"      labels: {json.dumps(severity_labels)},")
        html.append("      datasets: [")
        html.append("        {")
        html.append("          label: 'Pass',")
        html.append(f"          data: {json.dumps(severity_values_pass)},")
        html.append("          backgroundColor: '#10b981',")
        html.append("          borderRadius: 8,")
        html.append("          borderWidth: 0")
        html.append("        },")
        html.append("        {")
        html.append("          label: 'Fail',")
        html.append(f"          data: {json.dumps(severity_values_fail)},")
        html.append("          backgroundColor: '#ef4444',")
        html.append("          borderRadius: 8,")
        html.append("          borderWidth: 0")
        html.append("        }")
        html.append("      ]")
        html.append("    },")
        html.append("    options: {")
        html.append("      responsive: true,")
        html.append("      maintainAspectRatio: false,")
        html.append("      plugins: {")
        html.append("        legend: { position: 'bottom' },")
        html.append("        title: {")
        html.append("          display: true,")
        html.append("          text: 'Results by Severity',")
        html.append("          font: { size: 16, weight: 'bold' }")
        html.append("        },")
        html.append("        datalabels: {")
        html.append("          color: '#fff',")
        html.append("          font: { weight: 'bold' },")
        html.append("          formatter: (value) => value > 0 ? value : ''")
        html.append("        }")
        html.append("      },")
        html.append("      scales: {")
        html.append("        y: {")
        html.append("          beginAtZero: true,")
        html.append("          grid: { display: false },")
        html.append("          stacked: true")
        html.append("        },")
        html.append("        x: {")
        html.append("          grid: { display: false },")
        html.append("          stacked: true")
        html.append("        }")
        html.append("      }")
        html.append("    }")
        html.append("  });")
        
        # Toggle details function
        html.append("""
        });
        
        function toggleDetails(rowId) {
            const detailRow = document.getElementById(`detail-row-${rowId}`);
            detailRow.classList.toggle('active');
        }
        """)
        html.append("</script>")
        
        html.append("</body></html>")

        file_path = output_file or os.path.join(self.output_dir, f"scap_report_{self.timestamp}.html")
        try:
            with open(file_path, 'w') as f:
                f.write("\n".join(html))
            logger.info(f"Modern HTML report saved to {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Failed to save HTML report: {e}")
            return ""

    def _get_remediation_advice(self, check: Dict[str, Any]) -> str:
        """
        Generate remediation advice based on the check details.
        Enhanced to provide more specific guidance.
        """
        title = check.get('title', '').lower()
        severity = check.get('severity', '').lower()
        
        # More detailed remediation advice based on check patterns
        if 'password' in title:
            return "Update password policy settings in Group Policy or local security policy. Navigate to Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy and set the minimum password length according to your organization's requirements."
        elif 'firewall' in title:
            return "Enable Windows Defender Firewall for all network profiles (Domain, Private, Public) via Group Policy or PowerShell using Set-NetFirewallProfile -Enabled True."
        elif 'bitlocker' in title:
            return "Enable BitLocker encryption via the Control Panel or using manage-bde.exe command-line tool. Ensure proper key management and backup of recovery keys to Active Directory or other secure storage."
        elif 'updates' in title:
            return "Configure automatic updates through Group Policy (Computer Configuration > Administrative Templates > Windows Components > Windows Update) or Settings app. Set appropriate active hours and restart policies."
        elif 'account lockout' in title:
            return "Configure account lockout policy via Group Policy. Set appropriate threshold, duration and reset time based on your organization's security requirements."
        elif 'audit' in title:
            return "Configure audit policies via Group Policy (Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration)."
        
        # Default remediation advice with severity consideration
        if severity == 'high':
            return "Critical security issue that requires immediate attention. Review security documentation and apply the recommended hardening configurations as soon as possible."
        elif severity == 'medium':
            return "Important security setting that should be addressed according to your organization's security policies and risk management framework."
        else:
            return "Review security best practices and consider implementing this control based on your organization's security requirements."

    def generate_console_report(self) -> str:
        """
        Generate a simple console report for CLI output
        
        Returns:
            str: Formatted console report as a string
        """
        lines = []
        lines.append("=" * 60)
        lines.append("SECURITY COMPLIANCE REPORT")
        lines.append("=" * 60)
        
        # System Information
        lines.append("\nSYSTEM INFORMATION:")
        for key, value in self.system_info.items():
            lines.append(f"{key}: {value}")
            
        # Compliance Summary
        lines.append("\nCOMPLIANCE SUMMARY:")
        compliance = self.summary.get('compliance_percentage', 0)
        total = self.summary.get('total', 0)
        passed = self.summary.get('pass', 0)
        failed = self.summary.get('fail', 0)
        error = self.summary.get('error', 0)
        
        lines.append(f"Overall Compliance: {compliance:.2f}%")
        lines.append(f"Total Checks: {total}")
        lines.append(f"Passed: {passed}")
        lines.append(f"Failed: {failed}")
        lines.append(f"Error: {error}")
        
        # Severity Breakdown
        lines.append("\nSEVERITY BREAKDOWN:")
        headers = ["Severity", "Total", "Pass", "Fail", "Error", "Compliance %"]
        rows = []
        
        for severity, counts in self.summary['by_severity'].items():
            sev_total = counts['total']
            sev_pass = counts['pass']
            sev_fail = counts['fail']
            sev_error = counts['error']
            sev_compliance = (sev_pass / (sev_pass + sev_fail)) * 100 if (sev_pass + sev_fail) > 0 else 0
            rows.append([
                severity.upper(),
                sev_total,
                sev_pass,
                sev_fail, 
                sev_error,
                f"{sev_compliance:.2f}%"
            ])
        
        lines.append(tabulate(rows, headers=headers, tablefmt="grid"))
        
        # Failed Checks
        lines.append("\nFAILED CHECKS:")
        
        if not any(check.get('status') == 'fail' for check in self.results.values()):
            lines.append("No failed checks found.")
        else:
            fail_headers = ["Rule", "Severity", "Expected", "Actual"]
            fail_rows = []
            
            for check in self.results.values():
                if check.get('status') == 'fail':
                    fail_rows.append([
                        check.get('title', 'Unknown'),
                        check.get('severity', '').upper(),
                        check.get('expected', ''),
                        check.get('actual', '')
                    ])
                    
            lines.append(tabulate(fail_rows, headers=fail_headers, tablefmt="grid"))
        
        # Footer
        lines.append("\n" + "=" * 60)
        lines.append(f"Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 60)
        
        return "\n".join(lines)


def main():
    results = {
        'rule1': {
            'rule_id': 'rule1',
            'title': 'Password Minimum Length',
            'description': 'Ensure passwords are at least 8 characters',
            'severity': 'high',
            'status': 'fail',
            'expected': '>=8',
            'actual': '6',
            'evidence': 'Registry value shows 6'
        },
        'rule2': {
            'rule_id': 'rule2',
            'title': 'Firewall Enabled',
            'description': 'Firewall must be enabled',
            'severity': 'high',
            'status': 'pass',
            'expected': 'enabled',
            'actual': 'enabled',
            'evidence': 'Firewall service is running'
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
            'low': {'total': 0, 'pass': 0, 'fail': 0, 'error': 0}
        }
    }

    system_info = {
        'Hostname': 'TEST-PC',
        'OS': 'Windows 10 Pro',
        'Uptime': '5 days'
    }

    generator = ReportGenerator(results, summary, system_info)
    generator.generate_html_report()

if __name__ == '__main__':
    main()
