#!/usr/bin/env python3
"""
Rule Engine for SCAP MVP
Executes security checks based on parsed rules
"""

import logging
import concurrent.futures
import time
from typing import Dict, List, Any, Optional, Tuple

from windows_scanner import WindowsScanner

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RuleEngine:
    """Engine for executing security checks"""
    
    def __init__(self, scanner: WindowsScanner, rules: Dict[str, Any], parallel: int = 4):
        """
        Initialize the rule engine
        
        Args:
            scanner: WindowsScanner instance for checking settings
            rules: Dictionary of rules to check
            parallel: Number of checks to run in parallel
        """
        self.scanner = scanner
        self.rules = rules
        self.parallel = parallel
        self.results = {}
        self.progress = {'total': len(rules), 'completed': 0, 'passed': 0, 'failed': 0, 'error': 0}
        # Detect test mode (no actual connection)
        self.test_mode = not hasattr(self.scanner, 'session') and not getattr(self.scanner, 'use_direct_powershell', False)
        
    def execute_all_checks(self) -> Dict[str, Any]:
        """
        Execute all rules in the ruleset
        
        Returns:
            Dict: Dictionary of check results
        """
        if not self.scanner:
            logger.error("Scanner not initialized")
            return {}
            
        # Verify scanner connection
        if not hasattr(self.scanner, 'use_direct_powershell') and not hasattr(self.scanner, 'session'):
            logger.error("Scanner is not connected to target")
            # Create dummy results for all rules
            results = {}
            for rule_id, rule in self.rules.items():
                results[rule_id] = {
                    'rule_id': rule_id,
                    'title': rule.get('title', ''),
                    'description': rule.get('description', ''),
                    'severity': rule.get('severity', 'unknown'),
                    'status': 'error',
                    'message': 'Scanner is not connected to target',
                    'expected': None,
                    'actual': None,
                    'evidence': None
                }
            return results
            
        if not self.rules:
            logger.error("No rules to execute")
            return {}
            
        start_time = time.time()
        logger.info(f"Starting scan with {len(self.rules)} rules")
        
        # Reset progress
        self.progress = {'total': len(self.rules), 'completed': 0, 'passed': 0, 'failed': 0, 'error': 0}
        
        # Test connection before starting parallel execution
        test_cmd = "Write-Output 'Connection Test'"
        test_result = self.scanner.run_powershell(test_cmd)
        if not test_result['success']:
            logger.error(f"Scanner connection test failed: {test_result['stderr']}")
            # Create dummy results for all rules
            results = {}
            for rule_id, rule in self.rules.items():
                results[rule_id] = {
                    'rule_id': rule_id,
                    'title': rule.get('title', ''),
                    'description': rule.get('description', ''),
                    'severity': rule.get('severity', 'unknown'),
                    'status': 'error',
                    'message': f"Scanner connection failed: {test_result['stderr']}",
                    'expected': None,
                    'actual': None,
                    'evidence': None
                }
            self.results = results
            return results
        
        # Execute checks in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.parallel) as executor:
            future_to_rule = {executor.submit(self.execute_check, rule_id, rule): rule_id 
                             for rule_id, rule in self.rules.items()}
            
            for future in concurrent.futures.as_completed(future_to_rule):
                rule_id = future_to_rule[future]
                try:
                    result = future.result()
                    self.results[rule_id] = result
                    self.progress['completed'] += 1
                    
                    if result['status'] == 'pass':
                        self.progress['passed'] += 1
                    elif result['status'] == 'fail':
                        self.progress['failed'] += 1
                    else:
                        self.progress['error'] += 1
                        
                    # Log progress
                    if self.progress['completed'] % 5 == 0 or self.progress['completed'] == self.progress['total']:
                        logger.info(f"Progress: {self.progress['completed']}/{self.progress['total']} "
                                   f"(Pass: {self.progress['passed']}, Fail: {self.progress['failed']}, "
                                   f"Error: {self.progress['error']})")
                        
                except Exception as e:
                    logger.error(f"Error executing rule {rule_id}: {e}")
                    self.results[rule_id] = {
                        'rule_id': rule_id,
                        'title': self.rules[rule_id].get('title', ''),
                        'description': self.rules[rule_id].get('description', ''),
                        'severity': self.rules[rule_id].get('severity', 'unknown'),
                        'status': 'error',
                        'message': f"Exception: {str(e)}",
                        'expected': None,
                        'actual': None,
                        'evidence': None
                    }
                    self.progress['completed'] += 1
                    self.progress['error'] += 1
        
        end_time = time.time()
        duration = end_time - start_time
        logger.info(f"Scan completed in {duration:.2f} seconds")
        logger.info(f"Results: {self.progress['passed']} passed, {self.progress['failed']} failed, "
                   f"{self.progress['error']} errors")
        
        return self.results
    
    def execute_check(self, rule_id: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a single security check
        
        Args:
            rule_id: ID of the rule to check
            rule: Rule definition
            
        Returns:
            Dict: Check result
        """
        logger.debug(f"Executing check for rule: {rule_id}")
        
        result = {
            'rule_id': rule_id,
            'title': rule.get('title', ''),
            'description': rule.get('description', ''),
            'severity': rule.get('severity', 'unknown'),
            'status': 'error',
            'message': '',
            'expected': None,
            'actual': None,
            'evidence': None
        }
        
        try:
            test_type = rule.get('test_type', '')
            object_info = rule.get('object_info', {})
            state_info = rule.get('state_info', {})
            
            if not test_type or not object_info or not state_info:
                result['message'] = "Missing test information"
                return result
            
            # If in test mode, generate mock results
            if hasattr(self, 'test_mode') and self.test_mode:
                return self._generate_mock_result(rule_id, rule)
                
            # Execute check based on test type
            if test_type == 'registry':
                check_result = self._check_registry(object_info, state_info)
            elif test_type == 'service':
                check_result = self._check_service(object_info, state_info)
            elif test_type == 'cmdlet':
                check_result = self._check_cmdlet(object_info, state_info)
            else:
                result['message'] = f"Unsupported test type: {test_type}"
                return result
                
            # Update result with check details
            result.update(check_result)
            
            return result
            
        except Exception as e:
            logger.error(f"Error executing check for rule {rule_id}: {e}")
            result['message'] = f"Exception: {str(e)}"
            return result
    
    def _generate_mock_result(self, rule_id: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a mock result for testing
        
        Args:
            rule_id: ID of the rule
            rule: Rule definition
            
        Returns:
            Dict: Mock check result
        """
        # Determine pass/fail based on rule ID
        # Make some rules pass and some fail for testing
        status = 'pass' if rule_id.endswith('0') or rule_id.endswith('5') else 'fail'
        
        test_type = rule.get('test_type', '')
        object_info = rule.get('object_info', {})
        state_info = rule.get('state_info', {})
        
        expected_value = state_info.get('value', 'Expected Value')
        
        if test_type == 'registry':
            hive = object_info.get('hive', 'HKEY_LOCAL_MACHINE')
            key = object_info.get('key', 'SOFTWARE\\Policies\\Microsoft\\Windows')
            name = object_info.get('name', 'Setting')
            
            if status == 'pass':
                actual_value = expected_value
                message = f"Registry value matches expected value"
                evidence = f"{hive}\\{key}\\{name} = {actual_value}"
            else:
                actual_value = "Incorrect Value"
                message = f"Registry value does not match expected value"
                evidence = f"{hive}\\{key}\\{name} = {actual_value}"
                
        elif test_type == 'service':
            service_name = object_info.get('service_name', 'TestService')
            expected_state = state_info.get('current_state', 'running')
            
            if status == 'pass':
                actual_value = expected_state
                message = f"Service state matches expected state"
                evidence = f"Service {service_name} is {actual_value}"
            else:
                actual_value = "stopped" if expected_state == "running" else "running"
                message = f"Service state does not match expected state"
                evidence = f"Service {service_name} is {actual_value}"
                
        else:
            if status == 'pass':
                actual_value = expected_value
                message = f"Check passed"
                evidence = f"Expected: {expected_value}, Actual: {actual_value}"
            else:
                actual_value = "Incorrect Value"
                message = f"Check failed"
                evidence = f"Expected: {expected_value}, Actual: {actual_value}"
        
        return {
            'status': status,
            'message': message,
            'expected': expected_value,
            'actual': actual_value,
            'evidence': evidence
        }
    
    def _check_registry(self, object_info: Dict[str, Any], state_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check a registry value
        
        Args:
            object_info: Registry object information
            state_info: Expected state information
            
        Returns:
            Dict: Check result
        """
        result = {
            'status': 'error',
            'message': '',
            'expected': None,
            'actual': None,
            'evidence': None
        }
        
        try:
            # Get registry parameters
            hive = object_info.get('hive', '')
            key = object_info.get('key', '')
            name = object_info.get('name', '')
            
            expected_value = state_info.get('value')
            datatype = state_info.get('datatype', 'string')
            operation = state_info.get('operation', 'equals')
            
            # Fix common issues with registry paths
            if hive.startswith('HKLM'):
                hive = 'HKEY_LOCAL_MACHINE'
            elif hive.startswith('HKCU'):
                hive = 'HKEY_CURRENT_USER'
            
            # For empty registry values, use default
            if not name:
                name = '(Default)'
                
            # Log the registry check
            logger.debug(f"Checking registry: {hive}\\{key}\\{name}, expected: {expected_value}, operation: {operation}")
                
            # For STIG checks, we often need to check if a key exists
            # rather than a specific value
            if name == '(Default)' and not expected_value:
                # Just check if the key exists
                command = f"""
                $exists = Test-Path -Path "Registry::{hive}\\{key}"
                if ($exists) {{
                    Write-Output "Key exists"
                    exit 0
                }} else {{
                    Write-Output "Key does not exist"
                    exit 1
                }}
                """
                cmd_result = self.scanner.run_powershell(command)
                
                if cmd_result['success']:
                    result['status'] = 'pass'
                    result['message'] = "Registry key exists"
                    result['expected'] = "Key exists"
                    result['actual'] = "Key exists"
                    result['evidence'] = f"{hive}\\{key} exists"
                else:
                    result['status'] = 'fail'
                    result['message'] = "Registry key does not exist"
                    result['expected'] = "Key exists"
                    result['actual'] = "Key does not exist"
                    result['evidence'] = f"{hive}\\{key} does not exist"
                    
                return result
            
            # Check registry value
            reg_result = self.scanner.check_registry(hive, key, name)
            
            # Build evidence string
            evidence = f"{hive}\\{key}\\{name}"
            if reg_result.get('exists', False):
                actual_value = reg_result.get('value')
                evidence += f" = {actual_value}"
            else:
                error = reg_result.get('error', 'Value not found')
                evidence += f" ({error})"
                
            result['evidence'] = evidence
            
            # Handle non-existent registry value
            if not reg_result.get('exists', False):
                # If the operation is 'not exists', this is actually a pass
                if operation == 'not exists':
                    result['status'] = 'pass'
                    result['message'] = f"Registry value correctly does not exist"
                    result['expected'] = "Value should not exist"
                    result['actual'] = "Value does not exist"
                else:
                    # For SCAP/STIG checks, we often want to fail gracefully if the registry doesn't exist
                    # This is because many settings are only applicable if a feature is installed
                    result['status'] = 'fail'
                    result['message'] = f"Registry value not found: {evidence}"
                    result['expected'] = expected_value
                    result['actual'] = None
                return result
                
            # Get actual value and convert to correct type
            actual_value = reg_result.get('value')
            result['actual'] = actual_value
            result['expected'] = expected_value
            
            # If operation is 'not exists', this is a fail because the value exists
            if operation == 'not exists':
                result['status'] = 'fail'
                result['message'] = f"Registry value exists but should not: {evidence}"
                result['expected'] = "Value should not exist"
                result['actual'] = actual_value
                return result
            
            # Convert values to correct type for comparison
            if datatype == 'int':
                try:
                    actual_value = int(actual_value)
                    expected_value = int(expected_value)
                except (ValueError, TypeError):
                    result['status'] = 'error'
                    result['message'] = f"Failed to convert values to integers: actual={actual_value}, expected={expected_value}"
                    return result
            elif datatype == 'boolean':
                if isinstance(actual_value, str):
                    actual_value = actual_value.lower() in ('true', 'yes', '1')
                if isinstance(expected_value, str):
                    expected_value = expected_value.lower() in ('true', 'yes', '1')
                    
            # Compare values based on operation
            comparison_result = self._compare_values(actual_value, expected_value, operation)
            
            if comparison_result:
                result['status'] = 'pass'
                result['message'] = f"Registry value matches expected value"
            else:
                result['status'] = 'fail'
                result['message'] = f"Registry value does not match expected value"
                
            return result
            
        except Exception as e:
            logger.error(f"Error in registry check: {e}")
            result['message'] = f"Exception: {str(e)}"
            return result
    
    def _check_service(self, object_info: Dict[str, Any], state_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check a service status
        
        Args:
            object_info: Service object information
            state_info: Expected state information
            
        Returns:
            Dict: Check result
        """
        result = {
            'status': 'error',
            'message': '',
            'expected': None,
            'actual': None,
            'evidence': None
        }
        
        try:
            # Get service parameters
            service_name = object_info.get('service_name', '')
            expected_state = state_info.get('current_state', '')
            expected_start_type = state_info.get('start_type', '')
            
            # Check service status
            service_result = self.scanner.check_service(service_name)
            
            # Build evidence string
            evidence = f"Service {service_name}"
            if service_result.get('exists', False):
                status = service_result.get('status')
                start_type = service_result.get('start_type')
                evidence += f" (Status: {status}, Start Type: {start_type})"
            else:
                error = service_result.get('error', 'Service not found')
                evidence += f" ({error})"
                
            result['evidence'] = evidence
            
            # Handle non-existent service
            if not service_result.get('exists', False):
                result['status'] = 'fail'
                result['message'] = f"Service not found: {service_name}"
                result['expected'] = f"Service {expected_state}, Start Type: {expected_start_type}"
                result['actual'] = "Service does not exist"
                return result
                
            # Get actual values
            actual_state = service_result.get('status')
            actual_start_type = service_result.get('start_type')
            
            result['expected'] = f"Status: {expected_state}, Start Type: {expected_start_type}"
            result['actual'] = f"Status: {actual_state}, Start Type: {actual_start_type}"
            
            # Compare service state
            state_match = True
            if expected_state and actual_state:
                state_match = expected_state.lower() == actual_state.lower()
                
            # Compare start type
            start_type_match = True
            if expected_start_type and actual_start_type:
                start_type_match = expected_start_type.lower() == actual_start_type.lower()
                
            # Determine overall result
            if state_match and start_type_match:
                result['status'] = 'pass'
                result['message'] = f"Service status and start type match expected values"
            else:
                result['status'] = 'fail'
                result['message'] = f"Service status or start type does not match expected values"
                
            return result
            
        except Exception as e:
            logger.error(f"Error in service check: {e}")
            result['message'] = f"Exception: {str(e)}"
            return result
    
    def _check_cmdlet(self, object_info: Dict[str, Any], state_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check using PowerShell cmdlet (e.g., for user accounts)
        
        Args:
            object_info: Cmdlet object information
            state_info: Expected state information
            
        Returns:
            Dict: Check result
        """
        result = {
            'status': 'error',
            'message': '',
            'expected': None,
            'actual': None,
            'evidence': None
        }
        
        try:
            # Get cmdlet parameters
            module_name = object_info.get('module_name', '')
            cmdlet = object_info.get('cmdlet', '')
            parameters = object_info.get('parameters', '')
            select_property = object_info.get('select', '')
            
            expected_value = state_info.get('value')
            datatype = state_info.get('datatype', 'string')
            operation = state_info.get('operation', 'equals')
            
            # For user account check
            if cmdlet == 'Get-LocalUser' and 'Guest' in parameters:
                user_result = self.scanner.check_user_account('Guest')
                
                # Build evidence string
                evidence = "Guest account"
                if user_result.get('exists', False):
                    enabled = user_result.get('enabled')
                    evidence += f" (Enabled: {enabled})"
                else:
                    error = user_result.get('error', 'Account not found')
                    evidence += f" ({error})"
                    
                result['evidence'] = evidence
                
                # Handle non-existent account
                if not user_result.get('exists', False):
                    result['status'] = 'error'
                    result['message'] = "Guest account not found"
                    result['expected'] = f"Enabled: {expected_value}"
                    result['actual'] = "Account does not exist"
                    return result
                    
                # Compare account status
                actual_value = user_result.get('enabled')
                result['expected'] = expected_value
                result['actual'] = actual_value
                
                # Convert to boolean if needed
                if datatype == 'boolean':
                    if isinstance(actual_value, str):
                        actual_value = actual_value.lower() in ('true', 'yes', '1')
                    if isinstance(expected_value, str):
                        expected_value = expected_value.lower() in ('true', 'yes', '1')
                        
                # Compare values
                comparison_result = self._compare_values(actual_value, expected_value, operation)
                
                if comparison_result:
                    result['status'] = 'pass'
                    result['message'] = "Guest account status matches expected value"
                else:
                    result['status'] = 'fail'
                    result['message'] = "Guest account status does not match expected value"
                    
                return result
            else:
                # Generic cmdlet handling (not implemented for MVP)
                result['status'] = 'error'
                result['message'] = f"Unsupported cmdlet: {cmdlet}"
                return result
                
        except Exception as e:
            logger.error(f"Error in cmdlet check: {e}")
            result['message'] = f"Exception: {str(e)}"
            return result
    
    def _check_event_log(self, object_info: Dict[str, Any], state_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check event log configuration
        
        Args:
            object_info: Event log object information
            state_info: Expected state information
            
        Returns:
            Dict: Check result
        """
        result = {
            'status': 'error',
            'message': '',
            'expected': None,
            'actual': None,
            'evidence': None
        }
        
        try:
            # Get log parameters
            log_name = object_info.get('log_name', 'Security')
            expected_size = state_info.get('value')
            datatype = state_info.get('datatype', 'int')
            operation = state_info.get('operation', 'greater_than_or_equal')
            
            # Check event log
            log_result = self.scanner.check_event_log(log_name)
            
            # Build evidence string
            evidence = f"Event Log {log_name}"
            if log_result.get('exists', False):
                file_size = log_result.get('FileSize')
                evidence += f" (Size: {file_size} bytes)"
            else:
                error = log_result.get('error', 'Log not found')
                evidence += f" ({error})"
                
            result['evidence'] = evidence
            
            # Handle non-existent log
            if not log_result.get('exists', False):
                result['status'] = 'fail'
                result['message'] = f"Event log not found: {log_name}"
                result['expected'] = f"Size: {expected_size} bytes or larger"
                result['actual'] = "Log does not exist"
                return result
                
            # Get actual size
            actual_size = log_result.get('FileSize')
            result['expected'] = expected_size
            result['actual'] = actual_size
            
            # Convert to integers for comparison
            if datatype == 'int':
                try:
                    actual_size = int(actual_size)
                    expected_size = int(expected_size)
                except (ValueError, TypeError):
                    result['status'] = 'error'
                    result['message'] = f"Failed to convert sizes to integers: actual={actual_size}, expected={expected_size}"
                    return result
                    
            # Compare values
            comparison_result = self._compare_values(actual_size, expected_size, operation)
            
            if comparison_result:
                result['status'] = 'pass'
                result['message'] = f"Event log size meets requirements"
            else:
                result['status'] = 'fail'
                result['message'] = f"Event log size does not meet requirements"
                
            return result
            
        except Exception as e:
            logger.error(f"Error in event log check: {e}")
            result['message'] = f"Exception: {str(e)}"
            return result
    
    def _compare_values(self, actual_value: Any, expected_value: Any, operation: str) -> bool:
        """
        Compare values based on operation
        
        Args:
            actual_value: The actual value found
            expected_value: The expected value
            operation: Comparison operation
            
        Returns:
            bool: True if comparison passes, False otherwise
        """
        try:
            if operation == 'equals':
                return actual_value == expected_value
            elif operation == 'not_equal':
                return actual_value != expected_value
            elif operation == 'greater_than':
                return actual_value > expected_value
            elif operation == 'less_than':
                return actual_value < expected_value
            elif operation == 'greater_than_or_equal':
                return actual_value >= expected_value
            elif operation == 'less_than_or_equal':
                return actual_value <= expected_value
            elif operation == 'pattern_match':
                import re
                pattern = re.compile(str(expected_value))
                return bool(pattern.match(str(actual_value)))
            elif operation == 'contains':
                return str(expected_value) in str(actual_value)
            else:
                logger.error(f"Unsupported operation: {operation}")
                return False
        except Exception as e:
            logger.error(f"Error comparing values: {e}")
            return False
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of check results
        
        Returns:
            Dict: Summary statistics
        """
        summary = {
            'total': len(self.results),
            'pass': 0,
            'fail': 0,
            'error': 0,
            'by_severity': {
                'critical': {'total': 0, 'pass': 0, 'fail': 0, 'error': 0},
                'high': {'total': 0, 'pass': 0, 'fail': 0, 'error': 0},
                'medium': {'total': 0, 'pass': 0, 'fail': 0, 'error': 0},
                'low': {'total': 0, 'pass': 0, 'fail': 0, 'error': 0},
                'unknown': {'total': 0, 'pass': 0, 'fail': 0, 'error': 0}
            }
        }
        
        for rule_id, result in self.results.items():
            status = result.get('status', 'error')
            severity = result.get('severity', 'unknown').lower()
            
            # Update overall counts
            if status == 'pass':
                summary['pass'] += 1
            elif status == 'fail':
                summary['fail'] += 1
            else:
                summary['error'] += 1
                
            # Update severity counts
            if severity not in summary['by_severity']:
                severity = 'unknown'
                
            summary['by_severity'][severity]['total'] += 1
            
            if status == 'pass':
                summary['by_severity'][severity]['pass'] += 1
            elif status == 'fail':
                summary['by_severity'][severity]['fail'] += 1
            else:
                summary['by_severity'][severity]['error'] += 1
                
        # Calculate compliance percentage
        total_checks = summary['pass'] + summary['fail']
        summary['compliance_percentage'] = (summary['pass'] / total_checks * 100) if total_checks > 0 else 0
        
        return summary


def main():
    """Test function for the rule engine"""
    from windows_scanner import WindowsScanner
    from xml_parser import XmlParser
    
    # Set up scanner
    scanner = WindowsScanner("localhost", "username", "password")
    if not scanner.connect():
        logger.error("Failed to connect to scanner")
        return
        
    # Parse rules
    parser = XmlParser("sample_rules.xml", "sample_oval.xml")
    if not parser.load_files():
        logger.error("Failed to load XML files")
        return
        
    rules = parser.extract_rules()
    
    # Execute checks
    engine = RuleEngine(scanner, rules)
    results = engine.execute_all_checks()
    
    # Print summary
    summary = engine.get_summary()
    print(f"Scan Summary:")
    print(f"  Total Rules: {summary['total']}")
    print(f"  Passed: {summary['pass']}")
    print(f"  Failed: {summary['fail']}")
    print(f"  Errors: {summary['error']}")
    print(f"  Compliance: {summary['compliance_percentage']:.2f}%")


if __name__ == "__main__":
    main() 