#!/usr/bin/env python3
"""
SCAP MVP Scanner
Main program for scanning Windows computers for security compliance
"""

import os
import sys
import logging
import yaml
import click
from typing import Dict, List, Any, Optional
import glob

from xml_parser import XmlParser
from windows_scanner import WindowsScanner
from rule_engine import RuleEngine
from report_generator import ReportGenerator

# Set up logging
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
    Load configuration from YAML file
    
    Args:
        config_file: Path to the configuration file
        
    Returns:
        Dict: Configuration dictionary
    """
    try:
        if not os.path.exists(config_file):
            logger.warning(f"Config file not found: {config_file}")
            return {}
            
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
            
        logger.info(f"Loaded configuration from {config_file}")
        return config
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return {}

def find_rule_files(directory=".") -> Dict[str, str]:
    """
    Find SCAP rule files in the given directory
    
    Args:
        directory: Directory to search in
        
    Returns:
        Dict: Dictionary with rule file paths
    """
    rule_files = {}
    
    # Look for SCAP datastreams
    datastreams = glob.glob(os.path.join(directory, "*.xml"))
    for ds_file in datastreams:
        if any(x in os.path.basename(ds_file).lower() for x in ["scap", "xccdf", "stig", "benchmark"]):
            rule_files["scap_datastream"] = ds_file
            break
    
    # Look for XCCDF files
    xccdf_files = glob.glob(os.path.join(directory, "*xccdf*.xml"))
    if xccdf_files:
        rule_files["xccdf"] = xccdf_files[0]
    
    # Look for OVAL files
    oval_files = glob.glob(os.path.join(directory, "*oval*.xml"))
    if oval_files:
        rule_files["oval"] = oval_files[0]
    
    return rule_files

@click.group()
@click.version_option(version="0.1.0")
def cli():
    """SCAP MVP Scanner - Windows security compliance scanner"""
    pass

@cli.command()
@click.option('--target', required=True, help='Target Windows computer (hostname or IP)')
@click.option('--username', help='Username for authentication')
@click.option('--password', help='Password for authentication')
@click.option('--rules', help='Path to XCCDF rules file or SCAP datastream')
@click.option('--oval', help='Path to OVAL definitions file (optional if using datastream)')
@click.option('--config', default=DEFAULT_CONFIG_FILE, help='Path to configuration file')
@click.option('--report-format', type=click.Choice(['console', 'json', 'html', 'all']), default='console', 
              help='Report format')
@click.option('--output-dir', help='Directory to save reports')
@click.option('--timeout', type=int, help='Connection timeout in seconds')
@click.option('--use-ssl', is_flag=True, help='Use HTTPS for WinRM connection')
@click.option('--test-mode', is_flag=True, help='Run in test mode with mock data (no actual connection)')
@click.option('--auto-detect', is_flag=True, help='Auto-detect rule files in current directory')
@click.option('--limit', type=int, help='Limit the number of rules to scan (for testing)')
def scan(target, username, password, rules, oval, config, report_format, output_dir, timeout, use_ssl, test_mode, auto_detect, limit):
    """Scan a Windows computer for security compliance"""
    try:
        # Load configuration
        cfg = load_config(config)
        
        # Auto-detect rule files if requested
        if auto_detect:
            logger.info("Auto-detecting rule files...")
            rule_files = find_rule_files()
            
            if "scap_datastream" in rule_files:
                logger.info(f"Found SCAP datastream: {rule_files['scap_datastream']}")
                rules = rules or rule_files["scap_datastream"]
            elif "xccdf" in rule_files:
                logger.info(f"Found XCCDF file: {rule_files['xccdf']}")
                rules = rules or rule_files["xccdf"]
                
                if "oval" in rule_files:
                    logger.info(f"Found OVAL file: {rule_files['oval']}")
                    oval = oval or rule_files["oval"]
        
        # Set defaults from config if not provided
        rules = rules or cfg.get('rules', {}).get('default_xccdf', 'sample_rules.xml')
        oval = oval or cfg.get('rules', {}).get('default_oval', 'sample_oval.xml')
        output_dir = output_dir or cfg.get('report', {}).get('output_dir', 'reports')
        timeout = timeout or cfg.get('scan', {}).get('timeout', 60)
        parallel = cfg.get('scan', {}).get('parallel', 4)
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Log scan parameters
        logger.info(f"Starting scan of {target}")
        logger.info(f"Using rules file: {rules}")
        if oval:
            logger.info(f"Using OVAL file: {oval}")
        
        # Parse XML files
        logger.info("Parsing XML files...")
        parser = XmlParser(rules, oval, test_mode=test_mode)
        if not parser.load_files():
            logger.error("Failed to load XML files")
            return 1
            
        parsed_rules = parser.extract_rules()
        if not parsed_rules:
            logger.error("No rules found in XML files")
            return 1
        
        # Limit rules if requested
        if limit and limit > 0 and limit < len(parsed_rules):
            logger.info(f"Limiting scan to {limit} rules (out of {len(parsed_rules)})")
            # Take a subset of rules
            rule_ids = list(parsed_rules.keys())[:limit]
            limited_rules = {rule_id: parsed_rules[rule_id] for rule_id in rule_ids}
            parsed_rules = limited_rules
            
        logger.info(f"Parsed {len(parsed_rules)} rules")
        
        if test_mode:
            # Skip actual connection and use mock data
            logger.info("Running in TEST MODE with mock data (no actual connection)")
            scanner = WindowsScanner(target, username, password, timeout, use_ssl)
            system_info = {
                'ComputerName': 'TEST-MACHINE',
                'OSVersion': 'Microsoft Windows 10 Pro',
                'LastBootTime': '2023-01-01T12:00:00Z',
                'InstallDate': '2022-01-01T00:00:00Z'
            }
            
            # Create rule engine with test mode
            engine = RuleEngine(scanner, parsed_rules, parallel)
            results = engine.execute_all_checks()
            
            # Get summary
            summary = engine.get_summary()
        else:
            # Connect to target
            logger.info(f"Connecting to {target}...")
            scanner = WindowsScanner(target, username, password, timeout, use_ssl)
            if not scanner.connect():
                logger.error(f"Failed to connect to {target}")
                return 1
                
            # Get system information
            system_info = scanner.get_system_info()
            
            # Execute checks
            logger.info("Executing security checks...")
            engine = RuleEngine(scanner, parsed_rules, parallel)
            results = engine.execute_all_checks()
            
            # Get summary
            summary = engine.get_summary()
        
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
        
        if report_format in ['console', 'all']:
            console_report = generator.generate_console_report()
            print("\n" + console_report)
            
        if report_format in ['json', 'all']:
            json_path = generator.generate_json_report()
            logger.info(f"JSON report saved to: {json_path}")
            
        if report_format in ['html', 'all']:
            html_path = generator.generate_html_report()
            logger.info(f"HTML report saved to: {html_path}")
            
        # Display summary
        logger.info(f"Scan completed: {summary['pass']} passed, {summary['fail']} failed, {summary['error']} errors")
        logger.info(f"Compliance: {summary['compliance_percentage']:.2f}%")
        
        return 0
        
    except Exception as e:
        logger.error(f"Error during scan: {e}", exc_info=True)
        return 1

@cli.command()
@click.option('--input', required=True, help='Path to scan results JSON file')
@click.option('--format', type=click.Choice(['console', 'json', 'html', 'all']), default='html', 
              help='Report format')
@click.option('--output-dir', help='Directory to save reports')
def report(input, format, output_dir):
    """Generate a report from scan results"""
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
                logger.error("Invalid scan results file")
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
@click.option('--target', required=True, help='Target Windows computer (hostname or IP)')
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
            logger.info(f"Connection to {target} successful!")
            
            # Get system information
            system_info = scanner.get_system_info()
            
            print("\nSystem Information:")
            print(f"  Computer Name: {system_info.get('ComputerName', 'Unknown')}")
            print(f"  OS Version: {system_info.get('OSVersion', 'Unknown')}")
            print(f"  Last Boot Time: {system_info.get('LastBootTime', 'Unknown')}")
            print(f"  Install Date: {system_info.get('InstallDate', 'Unknown')}")
            
            return 0
        else:
            logger.error(f"Failed to connect to {target}")
            return 1
            
    except Exception as e:
        logger.error(f"Error testing connection: {e}")
        return 1

@cli.command()
@click.option('--rules', help='Path to XCCDF rules file or SCAP datastream')
@click.option('--oval', help='Path to OVAL definitions file (optional if using datastream)')
@click.option('--auto-detect', is_flag=True, help='Auto-detect rule files in current directory')
def list_rules(rules, oval, auto_detect):
    """List available rules in the specified SCAP content"""
    try:
        # Auto-detect rule files if requested
        if auto_detect:
            logger.info("Auto-detecting rule files...")
            rule_files = find_rule_files()
            
            if "scap_datastream" in rule_files:
                logger.info(f"Found SCAP datastream: {rule_files['scap_datastream']}")
                rules = rules or rule_files["scap_datastream"]
            elif "xccdf" in rule_files:
                logger.info(f"Found XCCDF file: {rule_files['xccdf']}")
                rules = rules or rule_files["xccdf"]
                
                if "oval" in rule_files:
                    logger.info(f"Found OVAL file: {rule_files['oval']}")
                    oval = oval or rule_files["oval"]
        
        # Load configuration to get defaults
        cfg = load_config()
        rules = rules or cfg.get('rules', {}).get('default_xccdf', 'sample_rules.xml')
        oval = oval or cfg.get('rules', {}).get('default_oval', 'sample_oval.xml')
        
        logger.info(f"Using rules file: {rules}")
        if oval:
            logger.info(f"Using OVAL file: {oval}")
        
        # Parse XML files
        logger.info("Parsing XML files...")
        parser = XmlParser(rules, oval)
        if not parser.load_files():
            logger.error("Failed to load XML files")
            return 1
            
        # Get rules
        xccdf_rules = parser.parse_xccdf()
        
        if not xccdf_rules:
            logger.error("No rules found in XML files")
            return 1
        
        # Display rules
        print(f"\nFound {len(xccdf_rules)} rules:")
        print("=" * 80)
        
        for i, (rule_id, rule) in enumerate(xccdf_rules.items(), 1):
            print(f"{i}. {rule['title']} ({rule['severity']})")
            print(f"   ID: {rule_id}")
            print(f"   OVAL Reference: {rule['oval_ref']}")
            print("-" * 80)
        
        return 0
        
    except Exception as e:
        logger.error(f"Error listing rules: {e}")
        return 1

if __name__ == "__main__":
    cli() 