#!/usr/bin/env python3
"""
Rule Engine for SCAP MVP - Improved for NIST SCAP compatibility
Executes security checks based on parsed rules with better error handling
"""

import logging
import concurrent.futures
import time
import re
from typing import Dict, List, Any, Optional, Tuple

from windows_scanner import WindowsScanner

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RuleEngine:
    """Engine for executing security checks with improved NIST SCAP support"""
    
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
        Execute all rules in the ruleset with improved error handling
        
        Returns:
            Dict: Dictionary of check results
        """
        if not self.scanner:
            logger.error("Scanner not initialized")
            return self._create_error_results("Scanner not initialized")
            
        if not self.rules:
            logger.error("No rules to execute")
            return {}
            
        start_time = time.time()
        logger.info(f"Starting scan with {len(self.rules)} rules")
        
        # Reset progress
        self.progress = {'total': len(self.rules), 'completed': 0, 'passed': 0, 'failed': 0, 'error': 0}
        
        # Test connection before starting if not in test mode
        if not self.test_mode:
            if not self._test_scanner_connection():
                logger.error("Scanner connection test failed")
                return self._create_error_results("Scanner connection failed")
        
        # Execute checks in parallel (or sequentially for better debugging)
        if self.parallel > 1 and not self.test_mode:
            results = self._execute_parallel()
        else:
            results = self._execute_sequential()
        
        end_time = time.time()
        duration = end_time - start_time
        logger.info(f"Scan completed in {duration:.2f} seconds")
        logger.info(f"Results: {self.progress['passed']} passed, {self.progress['failed']} failed, "
                   f"{self.progress['error']} errors")
        
        self.results = results
        return results
    
    def _test_scanner_connection(self) -> bool:
        """Test scanner connection"""
        try:
            test_cmd = "Write-Output 'Connection Test'"
            test_result = self.scanner.run_powershell(test_cmd)
            return test_result['success']
        except Exception as e:
            logger.error(f"Scanner connection test error: {e}")
            return False
    
    def _create_error_results(self, error_message: str) -> Dict[str, Any]:
        """Create error results for all rules"""
        results = {}
        for rule_id, rule in self.rules.items():
            results[rule_id] = {
                'rule_id': rule_id,
                'title': rule.get('title', ''),
                'description': rule.get('description', ''),
                'severity': rule.get('severity', 'unknown'),
                'status': 'error',
                'message': error_message,
                'expected': None,
                'actual': None,
                'evidence': None
            }
        return results
    
    def _execute_sequential(self) -> Dict[str, Any]:
      
        results = {}
        
        for rule_id, rule in self.rules.items():
            try:
                result = self.execute_check(rule_id, rule)
                results[rule_id] = result
                self._update_progress(result)
                
                # Log progress every 10 rules
                if self.progress['completed'] % 10 == 0:
                    self._log_progress()
                    
            except Exception as e:
                logger.error(f"Error executing rule {rule_id}: {e}")
                results[rule_id] = self._create_error_result(rule_id, rule, str(e))
                self.progress['completed'] += 1
                self.progress['error'] += 1
        
        return results
    
    def _execute_parallel(self) -> Dict[str, Any]:
        """Execute checks in parallel"""
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.parallel) as executor:
            future_to_rule = {executor.submit(self.execute_check, rule_id, rule): rule_id 
                             for rule_id, rule in self.rules.items()}
            
            for future in concurrent.futures.as_completed(future_to_rule):
                rule_id = future_to_rule[future]
                try:
                    result = future.result()
                    results[rule_id] = result
                    self._update_progress(result)
                    
                    # Log progress
                    if self.progress['completed'] % 5 == 0 or self.progress['completed'] == self.progress['total']:
                        self._log_progress()
                        
                except Exception as e:
                    logger.error(f"Error executing rule {rule_id}: {e}")
                    results[rule_id] = self._create_error_result(rule_id, self.rules[rule_id], str(e))
                    self.progress['completed'] += 1
                    self.progress['error'] += 1
        
        return results
    
    def _update_progress(self, result: Dict[str, Any]):
        """Update progress counters"""
        self.progress['completed'] += 1
        
        if result['status'] == 'pass':
            self.progress['passed'] += 1
        elif result['status'] == 'fail':
            self.progress['failed'] += 1
        else:
            self.progress['error'] += 1
    
    def _log_progress(self):
        """Log current progress"""
        logger.info(f"Progress: {self.progress['completed']}/{self.progress['total']} "
                   f"(Pass: {self.progress['passed']}, Fail: {self.progress['failed']}, "
                   f"Error: {self.progress['error']})")
    
    def _create_error_result(self, rule_id: str, rule: Dict[str, Any], error_message: str) -> Dict[str, Any]:
        """Create an error result for a single rule"""
        return {
            'rule_id': rule_id,
            'title': rule.get('title', ''),
            'description': rule.get('description', ''),
            'severity': rule.get('severity', 'unknown'),
            'status': 'error',
            'message': f"Exception: {error_message}",
            'expected': None,
            'actual': None,
            'evidence': None
        }
    
    def execute_check(self, rule_id: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a single security check with improved error handling
        
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
            'version': rule.get('version', ''),
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
            
            if not test_type:
                result['message'] = "Missing test type"
                return result
            
            # If in test mode, generate mock results
            if self.test_mode:
                return self._generate_mock_result(rule_id, rule)
                
            # Execute check based on test type
            if test_type == 'registry':
                check_result = self._check_registry(object_info, state_info)
            elif test_type == 'service':
                check_result = self._check_service(object_info, state_info)
            elif test_type in ['cmdlet', 'powershell']:
                check_result = self._check_cmdlet(object_info, state_info)
            elif test_type == 'file':
                check_result = self._check_file(object_info, state_info)
            elif test_type == 'eventlog':
                check_result = self._check_event_log(object_info, state_info)
            else:
                # For unsupported test types, try to infer from object info
                check_result = self._infer_and_execute_check(object_info, state_info)
                if not check_result:
                    result['message'] = f"Unsupported test type: {test_type}"
                    return result
                
            # Update result with check details
            result.update(check_result)
            
            return result
            
        except Exception as e:
            logger.error(f"Error executing check for rule {rule_id}: {e}")
            result['message'] = f"Exception: {str(e)}"
            return result
    
    def _infer_and_execute_check(self, object_info: Dict[str, Any], state_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Try to infer the check type from object info and execute it
        
        Args:
            object_info: Object information
            state_info: State information
            
        Returns:
            Dict: Check result or None if cannot infer
        """
        try:
            # Check if this looks like a registry check
            if any(key in object_info for key in ['hive', 'key', 'name']):
                logger.debug("Inferred registry check from object info")
                return self._check_registry(object_info, state_info)
            
            # Check if this looks like a service check
            if 'service_name' in object_info or 'service' in str(object_info):
                logger.debug("Inferred service check from object info")
                return self._check_service(object_info, state_info)
            
            # Check if this looks like a file check
            if any(key in object_info for key in ['path', 'file_path', 'filename']):
                logger.debug("Inferred file check from object info")
                return self._check_file(object_info, state_info)
            
            # Default to registry check for unknown types
            logger.debug("Defaulting to registry check for unknown type")
            return self._check_registry(object_info, state_info)
            
        except Exception as e:
            logger.error(f"Error in inferred check: {e}")
            return None
    
    def _generate_mock_result(self, rule_id: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a mock result for testing with more realistic data
        
        Args:
            rule_id: ID of the rule
            rule: Rule definition
            
        Returns:
            Dict: Mock check result
        """
        # Determine pass/fail based on rule characteristics
        title = rule.get('title', '').lower()
        severity = rule.get('severity', 'unknown').lower()
        
        # Make high severity rules more likely to fail for testing
        if severity == 'high':
            status = 'fail' if hash(rule_id) % 3 == 0 else 'pass'
        elif severity == 'medium':
            status = 'fail' if hash(rule_id) % 4 == 0 else 'pass'
        else:
            status = 'fail' if hash(rule_id) % 5 == 0 else 'pass'
        
        test_type = rule.get('test_type', 'registry')
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
                actual_value = "Incorrect Value" if expected_value != "Incorrect Value" else "Wrong Value"
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
        Check a registry value with improved error handling
        
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
            # Get registry parameters with better defaults
            hive = object_info.get('hive', 'HKEY_LOCAL_MACHINE')
            key = object_info.get('key', '')
            name = object_info.get('name', '')
            
            expected_value = state_info.get('value')
            datatype = state_info.get('datatype', 'string')
            operation = state_info.get('operation', 'equals')
            
            # Validate required parameters
            if not key:
                result['message'] = "Missing registry key"
                return result
            
            # Normalize hive name
            if hive.startswith('HKLM'):
                hive = 'HKEY_LOCAL_MACHINE'
            elif hive.startswith('HKCU'):
                hive = 'HKEY_CURRENT_USER'
            elif hive.startswith('HKCR'):
                hive = 'HKEY_CLASSES_ROOT'
            elif hive.startswith('HKU'):
                hive = 'HKEY_USERS'
            elif hive.startswith('HKCC'):
                hive = 'HKEY_CURRENT_CONFIG'
            
            # Handle default value
            if not name or name.lower() in ['(default)', 'default']:
                name = '(Default)'
                
            logger.debug(f"Checking registry: {hive}\\{key}\\{name}")
                
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
                if operation == 'not exists':
                    result['status'] = 'pass'
                    result['message'] = f"Registry value correctly does not exist"
                    result['expected'] = "Value should not exist"
                    result['actual'] = "Value does not exist"
                else:
                    result['status'] = 'fail'
                    result['message'] = f"Registry value not found"
                    result['expected'] = expected_value
                    result['actual'] = None
                return result
                
            # Get actual value and set up for comparison
            actual_value = reg_result.get('value')
            result['actual'] = actual_value
            result['expected'] = expected_value
            
            # Handle 'not exists' operation when value does exist
            if operation == 'not exists':
                result['status'] = 'fail'
                result['message'] = f"Registry value exists but should not"
                return result
            
            # Convert values for comparison
            try:
                if datatype == 'int':
                    actual_value = int(actual_value)
                    expected_value = int(expected_value) if expected_value is not None else None
                elif datatype == 'boolean':
                    if isinstance(actual_value, str):
                        actual_value = actual_value.lower() in ('true', 'yes', '1')
                    if isinstance(expected_value, str):
                        expected_value = expected_value.lower() in ('true', 'yes', '1')
            except (ValueError, TypeError) as e:
                result['status'] = 'error'
                result['message'] = f"Type conversion error: {e}"
                return result
                    
            # Compare values
            comparison_result = self._compare_values(actual_value, expected_value, operation)
            
            if comparison_result:
                result['status'] = 'pass'
                result['message'] = f"Registry value matches expected criteria"
            else:
                result['status'] = 'fail'
                result['message'] = f"Registry value does not match expected criteria"
                
            return result
            
        except Exception as e:
            logger.error(f"Error in registry check: {e}")
            result['message'] = f"Exception: {str(e)}"
            return result
    
    def _check_service(self, object_info: Dict[str, Any], state_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check a service status with improved handling
        
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
            
            if not service_name:
                result['message'] = "Missing service name"
                return result
            
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
                result['expected'] = f"Service exists"
                result['actual'] = "Service does not exist"
                return result
                
            # Get actual values
            actual_state = service_result.get('status', '').lower()
            actual_start_type = service_result.get('start_type', '').lower()
            
            # Normalize expected values
            expected_state = expected_state.lower() if expected_state else ''
            expected_start_type = expected_start_type.lower() if expected_start_type else ''
            
            # Map start type variations
            start_type_map = {
                'auto': 'automatic',
                'manual': 'manual',
                'disabled': 'disabled',
                'automatic': 'automatic'
            }
            
            if expected_start_type in start_type_map:
                expected_start_type = start_type_map[expected_start_type]
            if actual_start_type in start_type_map:
                actual_start_type = start_type_map[actual_start_type]
            
            result['expected'] = f"Status: {expected_state}, Start Type: {expected_start_type}"
            result['actual'] = f"Status: {actual_state}, Start Type: {actual_start_type}"
            
            # Compare service state and start type
            state_match = True
            start_type_match = True
            
            if expected_state:
                state_match = expected_state == actual_state
                
            if expected_start_type:
                start_type_match = expected_start_type == actual_start_type
                
            # Determine overall result
            if state_match and start_type_match:
                result['status'] = 'pass'
                result['message'] = f"Service configuration matches expected values"
            else:
                result['status'] = 'fail'
                mismatches = []
                if not state_match:
                    mismatches.append(f"state (expected: {expected_state}, actual: {actual_state})")
                if not start_type_match:
                    mismatches.append(f"start type (expected: {expected_start_type}, actual: {actual_start_type})")
                result['message'] = f"Service configuration mismatch: {', '.join(mismatches)}"
                
            return result
            
        except Exception as e:
            logger.error(f"Error in service check: {e}")
            result['message'] = f"Exception: {str(e)}"
            return result
    
    def _check_cmdlet(self, object_info: Dict[str, Any], state_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check using PowerShell cmdlet with improved support
        
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
            cmdlet = object_info.get('cmdlet', '')
            parameters = object_info.get('parameters', '')
            select_property = object_info.get('select', '')
            
            expected_value = state_info.get('value')
            datatype = state_info.get('datatype', 'string')
            operation = state_info.get('operation', 'equals')
            
            if not cmdlet:
                result['message'] = "Missing cmdlet name"
                return result
            
            # Handle specific cmdlets
            if cmdlet == 'Get-LocalUser':
                # Extract username from parameters
                username_match = re.search(r'-Name\s+["\']?(\w+)["\']?', parameters)
                if username_match:
                    username = username_match.group(1)
                else:
                    username = 'Guest'  # Default
                
                user_result = self.scanner.check_user_account(username)
                
                # Build evidence string
                evidence = f"{username} account"
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
                    result['message'] = f"User account not found: {username}"
                    result['expected'] = f"Account exists"
                    result['actual'] = "Account does not exist"
                    return result
                    
                # Get actual value based on select property
                if select_property.lower() == 'enabled':
                    actual_value = user_result.get('enabled')
                else:
                    actual_value = user_result.get('enabled')  # Default to enabled
                
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
                    result['message'] = f"User account status matches expected value"
                else:
                    result['status'] = 'fail'
                    result['message'] = f"User account status does not match expected value"
                    
                return result
            else:
                # Generic cmdlet handling (basic implementation)
                result['status'] = 'error'
                result['message'] = f"Unsupported cmdlet: {cmdlet}"
                return result
                
        except Exception as e:
            logger.error(f"Error in cmdlet check: {e}")
            result['message'] = f"Exception: {str(e)}"
            return result
    
    def _check_file(self, object_info: Dict[str, Any], state_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check file existence and properties
        
        Args:
            object_info: File object information
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
            # Get file parameters
            file_path = object_info.get('path', object_info.get('file_path', ''))
            
            if not file_path:
                result['message'] = "Missing file path"
                return result
            
            expected_exists = state_info.get('exists', True)
            
            # Check file
            file_result = self.scanner.check_file(file_path)
            
            # Build evidence string
            evidence = f"File {file_path}"
            if file_result.get('exists', False):
                length = file_result.get('length', 0)
                evidence += f" (Size: {length} bytes)"
            else:
                error = file_result.get('error', 'File not found')
                evidence += f" ({error})"
                
            result['evidence'] = evidence
            
            # Check file existence
            actual_exists = file_result.get('exists', False)
            result['expected'] = f"File exists: {expected_exists}"
            result['actual'] = f"File exists: {actual_exists}"
            
            if expected_exists == actual_exists:
                result['status'] = 'pass'
                result['message'] = f"File existence matches expected state"
            else:
                result['status'] = 'fail'
                result['message'] = f"File existence does not match expected state"
                
            return result
            
        except Exception as e:
            logger.error(f"Error in file check: {e}")
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
                result['expected'] = f"Log exists with appropriate size"
                result['actual'] = "Log does not exist"
                return result
                
            # Get actual size
            actual_size = log_result.get('FileSize')
            result['expected'] = expected_size
            result['actual'] = actual_size
            
            # Convert to integers for comparison
            if datatype == 'int' and expected_size is not None:
                try:
                    actual_size = int(actual_size)
                    expected_size = int(expected_size)
                except (ValueError, TypeError):
                    result['status'] = 'error'
                    result['message'] = f"Failed to convert sizes to integers"
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
        Compare values based on operation with improved handling
        
        Args:
            actual_value: The actual value found
            expected_value: The expected value
            operation: Comparison operation
            
        Returns:
            bool: True if comparison passes, False otherwise
        """
        try:
            # Handle None values
            if expected_value is None:
                return True  # No comparison needed
                
            if actual_value is None:
                return operation in ['not_equal', 'not exists']
            
            # Normalize operation names
            operation = operation.replace(' ', '_').lower()
            operation_map = {
                'equals': 'equals',
                'equal': 'equals',
                'not_equal': 'not_equal',
                'not_equals': 'not_equal',
                'greater_than': 'greater_than',
                'greater_than_or_equal': 'greater_than_or_equal',
                'less_than': 'less_than',
                'less_than_or_equal': 'less_than_or_equal',
                'pattern_match': 'pattern_match',
                'contains': 'contains'
            }
            
            operation = operation_map.get(operation, operation)
            
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
                logger.warning(f"Unsupported operation: {operation}, defaulting to equals")
                return actual_value == expected_value
                
        except Exception as e:
            logger.error(f"Error comparing values: {e}")
            return False
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of check results with improved statistics
        
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
    scanner = WindowsScanner("localhost")
    
    # Parse rules
    parser = XmlParser("paste.txt", test_mode=True)
    if not parser.load_files():
        logger.error("Failed to load XML files")
        return
        
    rules = parser.extract_rules()
    if not rules:
        logger.error("No rules extracted") 
        return
    
    # Execute checks
    engine = RuleEngine(scanner, rules)
    results = engine.execute_all_checks()
    
    # Print summary
    summary = engine.get_summary()
    print(f"Scan Summary: {summary}")


if __name__ == "__main__":
    main()