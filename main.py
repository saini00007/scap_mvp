#!/usr/bin/env python3
"""
SCAP MVP Scanner - Improved for NIST SCAP compatibility
Main program for scanning Windows computers for security compliance
"""

import os
import sys
import logging
import yaml
import click
from typing import Dict, List, Any, Optional
import glob
import time

from xml_parser import XmlParser
from windows_scanner import WindowsScanner
from rule_engine import RuleEngine
from report_generator import ReportGenerator

# Set up logging with better formatting
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Default config file
DEFAULT_CONFIG_FILE = "config.yaml"

def load_config(config_file: str = DEFAULT_CONFIG_FILE) -> Dict[str, Any]:
    """
    Load configuration from YAML file with better error handling
    
    Args:
        config_file: Path to the configuration file
        
    Returns:
        Dict: Configuration dictionary
    """
    try:
        if not os.path.exists(config_file):
            logger.info(f"Config file not found: {config_file}, using defaults")
            return {
                'scan': {'timeout': 60, 'parallel': 4},
                'report': {'default_format': 'console', 'output_dir': 'reports', 'include_evidence': True, 'include_remediation': True},
                'logging': {'level': 'INFO'}
            }
            
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
            
        logger.info(f"Loaded configuration from {config_file}")
        return config
    except Exception as e:
        logger.warning(f"Error loading configuration: {e}, using defaults")
        return {
            'scan': {'timeout': 60, 'parallel': 4},
            'report': {'default_format': 'console', 'output_dir': 'reports', 'include_evidence': True, 'include_remediation': True},
            'logging': {'level': 'INFO'}
        }

def find_scap_files(directory=".") -> Dict[str, str]:
    """
    Find SCAP rule files in the given directory with improved detection
    
    Args:
        directory: Directory to search in
        
    Returns:
        Dict: Dictionary with rule file paths
    """
    rule_files = {}
    
    logger.info(f"Searching for SCAP files in: {directory}")
    
    # Look for SCAP datastreams (priority order)
    scap_patterns = [
        "*STIG*SCAP*.xml",
        "*stig*scap*.xml", 
        "*datastream*.xml",
        "*SCAP*.xml",
        "*scap*.xml"
    ]
    
    for pattern in scap_patterns:
        datastreams = glob.glob(os.path.join(directory, pattern))
        if datastreams:
            # Sort by size (larger files are likely more complete)
            datastreams.sort(key=lambda x: os.path.getsize(x), reverse=True)
            rule_files["scap_datastream"] = datastreams[0]
            logger.info(f"Found SCAP datastream: {datastreams[0]} ({os.path.getsize(datastreams[0])} bytes)")
            break
    
    # Look for XCCDF files if no datastream found
    if "scap_datastream" not in rule_files:
        xccdf_patterns = ["*xccdf*.xml", "*XCCDF*.xml", "*benchmark*.xml", "*Benchmark*.xml"]
        for pattern in xccdf_patterns:
            xccdf_files = glob.glob(os.path.join(directory, pattern))
            if xccdf_files:
                rule_files["xccdf"] = xccdf_files[0]
                logger.info(f"Found XCCDF file: {xccdf_files[0]}")
                break
    
    # Look for OVAL files
    oval_patterns = ["*oval*.xml", "*OVAL*.xml"]
    for pattern in oval_patterns:
        oval_files = glob.glob(os.path.join(directory, pattern))
        if oval_files:
            rule_files["oval"] = oval_files[0]
            logger.info(f"Found OVAL file: {oval_files[0]}")
            break
    
    return rule_files

def validate_scap_file(file_path: str) -> bool:
    """
    Validate that a file appears to be a valid SCAP file
    
    Args:
        file_path: Path to the file to validate
        
    Returns:
        bool: True if file appears valid, False otherwise
    """
    try:
        if not os.path.exists(file_path):
            return False
            
        # Check file size (too small files are likely not valid SCAP content)
        file_size = os.path.getsize(file_path)
        if file_size < 1024:  # Less than 1KB
            logger.warning(f"File {file_path} is very small ({file_size} bytes), may not be valid SCAP content")
            return False
        
        # Quick check for XML content
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            first_line = f.readline().strip()
            if not first_line.startswith('<?xml'):
                logger.warning(f"File {file_path} does not appear to be XML")
                return False
        
        logger.info(f"File {file_path} appears to be valid ({file_size} bytes)")
        return True
        
    except Exception as e:
        logger.error(f"Error validating file {file_path}: {e}")
        return False

@click.group()
@click.version_option(version="0.2.0")
def cli():
    """SCAP MVP Scanner - Windows security compliance scanner (Enhanced for NIST SCAP)"""
    pass

@cli.command()
@click.option('--target', default='localhost', help='Target Windows computer (hostname or IP, defaults to localhost)')
@click.option('--username', help='Username for authentication (optional for localhost)')
@click.option('--password', help='Password for authentication (optional for localhost)')
@click.option('--scap-file', help='Path to SCAP datastream or XCCDF file')
@click.option('--oval-file', help='Path to OVAL definitions file (optional if using datastream)')
@click.option('--config', default=DEFAULT_CONFIG_FILE, help='Path to configuration file')
@click.option('--report-format', type=click.Choice(['console', 'json', 'html', 'all']), default='console', 
              help='Report format')
@click.option('--output-dir', help='Directory to save reports')
@click.option('--timeout', type=int, help='Connection timeout in seconds')
@click.option('--use-ssl', is_flag=True, help='Use HTTPS for WinRM connection')
@click.option('--test-mode', is_flag=True, help='Run in test mode with mock data (no actual connection)')
@click.option('--auto-detect', is_flag=True, default=True, help='Auto-detect SCAP files in current directory')
@click.option('--limit', type=int, help='Limit the number of rules to scan (for testing)')
@click.option('--parallel', type=int, help='Number of parallel checks (default: 4, use 1 for debugging)')
@click.option('--debug', is_flag=True, help='Enable debug logging')
def scan(target, username, password, scap_file, oval_file, config, report_format, output_dir, 
         timeout, use_ssl, test_mode, auto_detect, limit, parallel, debug):
    """Scan a Windows computer for security compliance using NIST SCAP content"""
    
    # Set debug logging if requested
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    try:
        start_time = time.time()
        
        # Load configuration
        cfg = load_config(config)
        
        # Auto-detect SCAP files if requested or if no files specified
        if auto_detect or (not scap_file and not oval_file):
            logger.info("Auto-detecting SCAP files...")
            rule_files = find_scap_files()
            
            if "scap_datastream" in rule_files:
                scap_file = scap_file or rule_files["scap_datastream"]
                logger.info(f"Using SCAP datastream: {scap_file}")
            elif "xccdf" in rule_files:
                scap_file = scap_file or rule_files["xccdf"]
                logger.info(f"Using XCCDF file: {scap_file}")
                
                if "oval" in rule_files:
                    oval_file = oval_file or rule_files["oval"]
                    logger.info(f"Using OVAL file: {oval_file}")
        
        # Validate SCAP file
        if not scap_file:
            logger.error("No SCAP file specified and none found. Please provide --scap-file or place SCAP files in current directory.")
            return 1
            
        if not validate_scap_file(scap_file):
            logger.error(f"Invalid or missing SCAP file: {scap_file}")
            return 1
        
        # Set defaults from config if not provided
        output_dir = output_dir or cfg.get('report', {}).get('output_dir', 'reports')
        timeout = timeout or cfg.get('scan', {}).get('timeout', 60)
        parallel = parallel if parallel is not None else cfg.get('scan', {}).get('parallel', 4)
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Log scan parameters
        logger.info("=" * 60)
        logger.info("SCAP MVP SCANNER - Starting Scan")
        logger.info("=" * 60)
        logger.info(f"Target: {target}")
        logger.info(f"SCAP File: {scap_file}")
        if oval_file:
            logger.info(f"OVAL File: {oval_file}")
        logger.info(f"Test Mode: {test_mode}")
        logger.info(f"Parallel Checks: {parallel}")
        logger.info(f"Output Directory: {output_dir}")
        
        # Parse XML files
        logger.info("Loading and parsing SCAP content...")
        parser = XmlParser(scap_file, oval_file, test_mode=test_mode)
        
        if not parser.load_files():
            logger.error("Failed to load SCAP files")
            return 1
            
        parsed_rules = parser.extract_rules()
        if not parsed_rules:
            logger.error("No rules found in SCAP files")
            return 1
        
        # Limit rules if requested
        if limit and limit > 0 and limit < len(parsed_rules):
            logger.info(f"Limiting scan to {limit} rules (out of {len(parsed_rules)})")
            rule_ids = list(parsed_rules.keys())[:limit]
            limited_rules = {rule_id: parsed_rules[rule_id] for rule_id in rule_ids}
            parsed_rules = limited_rules
            
        logger.info(f"Loaded {len(parsed_rules)} rules for scanning")
        
        # Show rule breakdown by severity
        severity_counts = {}
        for rule in parsed_rules.values():
            severity = rule.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
        logger.info("Rule breakdown by severity:")
        for severity, count in sorted(severity_counts.items()):
            logger.info(f"  {severity.upper()}: {count} rules")
        
        # Set up scanner
        if test_mode:
            logger.info("=" * 60)
            logger.info("RUNNING IN TEST MODE - No actual connections will be made")
            logger.info("=" * 60)
            scanner = WindowsScanner(target, username, password, timeout, use_ssl)
            system_info = {
                'ComputerName': 'TEST-MACHINE',
                'OSVersion': 'Microsoft Windows 11 Pro (Test Mode)',
                'LastBootTime': '2023-01-01T12:00:00Z',
                'InstallDate': '2022-01-01T00:00:00Z'
            }
        else:
            # Connect to target
            logger.info(f"Connecting to target: {target}")
            scanner = WindowsScanner(target, username, password, timeout, use_ssl)
            if not scanner.connect():
                logger.error(f"Failed to connect to {target}")
                logger.error("Please check:")
                logger.error("  - Target is reachable")
                logger.error("  - WinRM is enabled on target")
                logger.error("  - Credentials are correct (if required)")
                logger.error("  - Firewall allows WinRM connections")
                return 1
                
            # Get system information
            system_info = scanner.get_system_info()
            logger.info(f"Connected to: {system_info.get('ComputerName', 'Unknown')}")
            logger.info(f"OS Version: {system_info.get('OSVersion', 'Unknown')}")
        
        # Execute checks
        logger.info("=" * 60)
        logger.info("EXECUTING SECURITY CHECKS")
        logger.info("=" * 60)
        
        engine = RuleEngine(scanner, parsed_rules, parallel)
        results = engine.execute_all_checks()
        
        if not results:
            logger.error("No results returned from rule engine")
            return 1
        
        # Get summary
        summary = engine.get_summary()
        
        scan_time = time.time() - start_time
        
        # Generate reports
        logger.info("=" * 60)
        logger.info("GENERATING REPORTS")
        logger.info("=" * 60)
        
        generator = ReportGenerator(
            results, 
            summary, 
            system_info,
            output_dir=output_dir,
            include_evidence=cfg.get('report', {}).get('include_evidence', True),
            include_remediation=cfg.get('report', {}).get('include_remediation', True)
        )
        
        if report_format in ['console', 'all']:
            console_report = generator.generate_console_report()
            print("\n" + console_report)
            
        if report_format in ['json', 'all']:
            json_path = generator.generate_json_report()
            logger.info(f"JSON report saved to: {json_path}")
            
        if report_format in ['html', 'all']:
            html_path = generator.generate_html_report()
            logger.info(f"HTML report saved to: {html_path}")
            
        # Display final summary
        logger.info("=" * 60)
        logger.info("SCAN COMPLETE")
        logger.info("=" * 60)
        logger.info(f"Scan Duration: {scan_time:.2f} seconds")
        logger.info(f"Total Rules Checked: {summary['total']}")
        logger.info(f"Passed: {summary['pass']} ({summary['pass']/summary['total']*100:.1f}%)")
        logger.info(f"Failed: {summary['fail']} ({summary['fail']/summary['total']*100:.1f}%)")
        logger.info(f"Errors: {summary['error']} ({summary['error']/summary['total']*100:.1f}%)")
        logger.info(f"Overall Compliance: {summary['compliance_percentage']:.2f}%")
        
        # Show severity breakdown
        logger.info("\nCompliance by Severity:")
        for severity, counts in summary['by_severity'].items():
            if counts['total'] > 0:
                compliance = (counts['pass'] / (counts['pass'] + counts['fail'])) * 100 if (counts['pass'] + counts['fail']) > 0 else 0
                logger.info(f"  {severity.upper()}: {compliance:.1f}% ({counts['pass']}/{counts['pass'] + counts['fail']} passing)")
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        if debug:
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
        return 1

@cli.command()
@click.option('--scap-file', help='Path to SCAP datastream or XCCDF file')
@click.option('--oval-file', help='Path to OVAL definitions file (optional if using datastream)')
@click.option('--auto-detect', is_flag=True, default=True, help='Auto-detect SCAP files in current directory')
@click.option('--show-details', is_flag=True, help='Show detailed information about each rule')
@click.option('--limit', type=int, default=10, help='Limit the number of rules to display (default: 10, use 0 for all)')
def list_rules(scap_file, oval_file, auto_detect, show_details, limit):
    """List available rules in the specified SCAP content"""
    try:
        # Auto-detect SCAP files if requested
        if auto_detect or not scap_file:
            logger.info("Auto-detecting SCAP files...")
            rule_files = find_scap_files()
            
            if "scap_datastream" in rule_files:
                scap_file = scap_file or rule_files["scap_datastream"]
                logger.info(f"Using SCAP datastream: {scap_file}")
            elif "xccdf" in rule_files:
                scap_file = scap_file or rule_files["xccdf"]
                logger.info(f"Using XCCDF file: {scap_file}")
                
                if "oval" in rule_files:
                    oval_file = oval_file or rule_files["oval"]
                    logger.info(f"Using OVAL file: {oval_file}")
        
        if not scap_file:
            logger.error("No SCAP file found. Please specify --scap-file or place SCAP files in current directory.")
            return 1
        
        if not validate_scap_file(scap_file):
            logger.error(f"Invalid SCAP file: {scap_file}")
            return 1
        
        # Parse XML files
        logger.info("Parsing SCAP content...")
        parser = XmlParser(scap_file, oval_file)
        if not parser.load_files():
            logger.error("Failed to load SCAP files")
            return 1
            
        # Get rules
        rules = parser.extract_rules()
        
        if not rules:
            logger.error("No rules found in SCAP files")
            return 1
        
        # Count rules by severity
        severity_counts = {}
        for rule in rules.values():
            severity = rule.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Display summary
        print(f"\n{'='*80}")
        print(f"SCAP CONTENT SUMMARY")
        print(f"{'='*80}")
        print(f"File: {scap_file}")
        print(f"Total Rules: {len(rules)}")
        print(f"\nRules by Severity:")
        for severity, count in sorted(severity_counts.items()):
            print(f"  {severity.upper()}: {count}")
        
        # Display rules
        print(f"\n{'='*80}")
        print(f"RULES LISTING")
        print(f"{'='*80}")
        
        display_count = len(rules) if limit == 0 else min(limit, len(rules))
        count = 0
        
        for rule_id, rule in rules.items():
            if count >= display_count:
                break
                
            print(f"\n{count + 1}. {rule['title']}")
            print(f"   ID: {rule_id}")
            print(f"   Severity: {rule['severity'].upper()}")
            
            if show_details:
                print(f"   Version: {rule.get('version', 'N/A')}")
                print(f"   Test Type: {rule['test_type']}")
                print(f"   OVAL Reference: {rule.get('oval_ref', 'N/A')}")
                if rule.get('description'):
                    desc = rule['description'][:200] + "..." if len(rule['description']) > 200 else rule['description']
                    print(f"   Description: {desc}")
                print(f"   Object Info: {rule['object_info']}")
                print(f"   State Info: {rule['state_info']}")
            
            print(f"   {'-'*70}")
            count += 1
        
        if limit > 0 and len(rules) > limit:
            print(f"\n... and {len(rules) - limit} more rules")
            print(f"Use --limit 0 to show all rules, or --show-details for more information")
        
        return 0
        
    except Exception as e:
        logger.error(f"Error listing rules: {e}")
        return 1

@cli.command()
@click.option('--target', default='localhost', help='Target Windows computer (hostname or IP)')
@click.option('--username', help='Username for authentication')
@click.option('--password', help='Password for authentication')
@click.option('--timeout', type=int, default=60, help='Connection timeout in seconds')
@click.option('--use-ssl', is_flag=True, help='Use HTTPS for WinRM connection')
def test_connection(target, username, password, timeout, use_ssl):
    """Test connection to a Windows computer"""
    try:
        logger.info(f"Testing connection to {target}...")
        scanner = WindowsScanner(target, username, password, timeout, use_ssl)
        
        if scanner.connect():
            logger.info(f"✓ Connection to {target} successful!")
            
            # Get system information
            system_info = scanner.get_system_info()
            
            print("\n" + "="*50)
            print("SYSTEM INFORMATION")
            print("="*50)
            print(f"Computer Name: {system_info.get('ComputerName', 'Unknown')}")
            print(f"OS Version: {system_info.get('OSVersion', 'Unknown')}")
            print(f"Last Boot Time: {system_info.get('LastBootTime', 'Unknown')}")
            print(f"Install Date: {system_info.get('InstallDate', 'Unknown')}")
            
            # Test basic functionality
            print(f"\n{'='*50}")
            print("FUNCTIONALITY TEST")
            print("="*50)
            
            # Test registry access
            reg_result = scanner.check_registry("HKEY_LOCAL_MACHINE", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName")
            if reg_result.get('exists'):
                print(f"✓ Registry access: {reg_result.get('value', 'N/A')}")
            else:
                print(f"⚠ Registry access: {reg_result.get('error', 'Failed')}")
            
            # Test service access
            service_result = scanner.check_service("Winmgmt")
            if service_result.get('exists'):
                print(f"✓ Service access: Winmgmt is {service_result.get('status', 'unknown')}")
            else:
                print(f"⚠ Service access: {service_result.get('error', 'Failed')}")
            
            print(f"\n✓ All tests completed successfully!")
            return 0
        else:
            logger.error(f"✗ Failed to connect to {target}")
            print(f"\nTroubleshooting tips:")
            print(f"1. Ensure WinRM is enabled: winrm quickconfig")
            print(f"2. Check firewall: netsh advfirewall firewall add rule name='WinRM-HTTP' dir=in localport=5985 protocol=TCP action=allow")
            print(f"3. For remote connections, configure WinRM: winrm set winrm/config/service '@{{AllowUnencrypted=\"true\"}}'")
            print(f"4. Verify credentials and network connectivity")
            return 1
            
    except Exception as e:
        logger.error(f"Error testing connection: {e}")
        return 1

@cli.command()
@click.option('--input', required=True, help='Path to scan results JSON file')
@click.option('--format', type=click.Choice(['console', 'json', 'html', 'all']), default='html', 
              help='Report format')
@click.option('--output-dir', help='Directory to save reports')
def report(input, format, output_dir):
    """Generate a report from existing scan results"""
    try:
        # Load configuration
        cfg = load_config()
        
        # Set defaults from config if not provided
        output_dir = output_dir or cfg.get('report', {}).get('output_dir', 'reports')
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Load scan results
        logger.info(f"Loading scan results from {input}...")
        try:
            with open(input, 'r') as f:
                import json
                data = json.load(f)
                
            results = data.get('results', {})
            summary = data.get('summary', {})
            system_info = data.get('scan_info', {}).get('system_info', {})
            
            if not results or not summary:
                logger.error("Invalid scan results file - missing results or summary")
                return 1
                
        except Exception as e:
            logger.error(f"Error loading scan results: {e}")
            return 1
        
        # Generate reports
        logger.info("Generating reports...")
        generator = ReportGenerator(
            results, 
            summary, 
            system_info,
            output_dir=output_dir,
            include_evidence=cfg.get('report', {}).get('include_evidence', True),
            include_remediation=cfg.get('report', {}).get('include_remediation', True)
        )
        
        if format in ['console', 'all']:
            console_report = generator.generate_console_report()
            print("\n" + console_report)
            
        if format in ['json', 'all']:
            json_path = generator.generate_json_report()
            logger.info(f"JSON report saved to: {json_path}")
            
        if format in ['html', 'all']:
            html_path = generator.generate_html_report()
            logger.info(f"HTML report saved to: {html_path}")
            
        return 0
        
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return 1

@cli.command()
@click.option('--directory', default='.', help='Directory to search for SCAP files')
def detect_files(directory):
    """Detect and validate SCAP files in a directory"""
    try:
        logger.info(f"Scanning directory: {directory}")
        
        # Find all XML files
        xml_files = glob.glob(os.path.join(directory, "*.xml"))
        
        if not xml_files:
            print(f"No XML files found in {directory}")
            return 1
        
        print(f"\nFound {len(xml_files)} XML files:")
        print("="*80)
        
        scap_files = []
        other_files = []
        
        for xml_file in xml_files:
            file_size = os.path.getsize(xml_file)
            file_name = os.path.basename(xml_file)
            
            # Check if this looks like a SCAP file
            is_scap = any(keyword in file_name.lower() for keyword in 
                         ['scap', 'stig', 'xccdf', 'oval', 'benchmark', 'datastream'])
            
            if is_scap and validate_scap_file(xml_file):
                scap_files.append((xml_file, file_size))
            else:
                other_files.append((xml_file, file_size))
        
        # Display SCAP files
        if scap_files:
            print(f"\nSCAP Files Found ({len(scap_files)}):")
            print("-" * 80)
            for file_path, size in sorted(scap_files, key=lambda x: x[1], reverse=True):
                file_name = os.path.basename(file_path)
                size_mb = size / (1024 * 1024)
                print(f"  {file_name:<50} ({size_mb:.2f} MB)")
                
                # Try to identify file type
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(2048)  # Read first 2KB
                        if 'data-stream-collection' in content:
                            print(f"    → SCAP Datastream")
                        elif 'Benchmark' in content:
                            print(f"    → XCCDF Benchmark")
                        elif 'oval_definitions' in content:
                            print(f"    → OVAL Definitions")
                        else:
                            print(f"    → Unknown SCAP format")
                except:
                    print(f"    → Could not analyze content")
        
        # Display other XML files
        if other_files:
            print(f"\nOther XML Files ({len(other_files)}):")
            print("-" * 80)
            for file_path, size in other_files:
                file_name = os.path.basename(file_path)
                size_kb = size / 1024
                print(f"  {file_name:<50} ({size_kb:.1f} KB)")
        
        # Provide recommendations
        print(f"\n{'='*80}")
        print("RECOMMENDATIONS")
        print("="*80)
        
        if scap_files:
            largest_scap = max(scap_files, key=lambda x: x[1])
            print(f"Recommended file to use: {os.path.basename(largest_scap[0])}")
            print(f"  (Largest SCAP file, likely most complete)")
            print(f"\nTo scan with this file:")
            print(f"  python main.py scan --scap-file \"{largest_scap[0]}\"")
        else:
            print("No valid SCAP files found.")
            print("Please ensure you have downloaded SCAP content from:")
            print("  - NIST NVD: https://nvd.nist.gov/scap")
            print("  - DISA STIG: https://public.cyber.mil/stigs/")
        
        return 0
        
    except Exception as e:
        logger.error(f"Error detecting files: {e}")
        return 1

if __name__ == "__main__":
    cli()