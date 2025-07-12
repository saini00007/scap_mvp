#!/usr/bin/env python3
"""
Windows Scanner for SCAP MVP
Connects to Windows systems and retrieves security settings
"""

import logging
import winrm
import json
import re
from typing import Dict, List, Any, Optional, Tuple
import subprocess
import tempfile
import os

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WindowsScanner:
    """Scanner for Windows systems using WinRM"""
    
    def __init__(self, target: str, username: Optional[str] = None, password: Optional[str] = None, 
                 timeout: int = 60, use_ssl: bool = False):
        """
        Initialize the Windows scanner
        
        Args:
            target: The target Windows computer (hostname or IP)
            username: Username for authentication
            password: Password for authentication
            timeout: Connection timeout in seconds
            use_ssl: Whether to use HTTPS for WinRM
        """
        self.target = target
        self.username = username
        self.password = password
        self.timeout = timeout
        self.use_ssl = use_ssl
        self.session = None
        self.system_info = {}
        self.use_direct_powershell = False
        
    def connect(self) -> bool:
        """
        Establish a WinRM connection to the target
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            # For localhost, try direct PowerShell execution first
            if self.target.lower() in ('localhost', '127.0.0.1'):
                logger.info(f"Target is localhost, attempting direct PowerShell execution")
                try:
                    # Test if we can run PowerShell directly
                    result = self._run_local_powershell("Write-Output 'PowerShell Test'")
                    if result['success']:
                        logger.info("Successfully connected to localhost via direct PowerShell")
                        self.use_direct_powershell = True
                        return True
                    else:
                        logger.warning("Direct PowerShell execution failed, falling back to WinRM")
                        self.use_direct_powershell = False
                except Exception as local_e:
                    logger.warning(f"Direct PowerShell execution failed: {local_e}, falling back to WinRM")
                    self.use_direct_powershell = False
            else:
                self.use_direct_powershell = False
            
            # Determine protocol
            protocol = 'https' if self.use_ssl else 'http'
            endpoint = f"{protocol}://{self.target}:{'5986' if self.use_ssl else '5985'}/wsman"
            
            # Create session
            logger.info(f"Connecting to {self.target} via WinRM...")
            logger.info(f"Using endpoint: {endpoint}")
            logger.info(f"Authentication: {'Yes' if self.username and self.password else 'No'}")
            
            # For localhost connections without credentials, we need to provide empty strings
            # instead of None because the winrm library tries to unpack None
            if self.target.lower() in ('localhost', '127.0.0.1') and not (self.username and self.password):
                logger.info("Using NTLM authentication for localhost with empty credentials")
                self.session = winrm.Session(
                    endpoint,
                    auth=('', ''),  # Empty strings instead of None
                    transport='ntlm',
                    read_timeout_sec=self.timeout,
                    operation_timeout_sec=self.timeout
                )
            else:
                self.session = winrm.Session(
                    endpoint,
                    auth=(self.username, self.password) if self.username and self.password else ('', ''),
                    transport='ssl' if self.use_ssl else 'ntlm',
                    read_timeout_sec=self.timeout,
                    operation_timeout_sec=self.timeout
                )
            
            # Test connection
            result = self.run_powershell("Get-ComputerInfo -Property CsName | Select-Object -ExpandProperty CsName")
            if result['status_code'] != 0:
                logger.error(f"Failed to connect to {self.target}: {result['stderr']}")
                return False
                
            logger.info(f"Successfully connected to {self.target}")
            return True
            
        except Exception as e:
            logger.error(f"Error connecting to {self.target}: {e}")
            logger.error(f"Exception type: {type(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False
            
    def _run_local_powershell(self, command: str) -> Dict[str, Any]:
        """
        Run a PowerShell command directly on the local machine
        
        Args:
            command: The PowerShell command to run
            
        Returns:
            Dict: Dictionary with command results
        """
        try:
            # Create a temporary file for the PowerShell script
            with tempfile.NamedTemporaryFile(suffix='.ps1', delete=False) as temp:
                temp_path = temp.name
                # Write the command to the temporary file
                with open(temp_path, 'w') as f:
                    f.write(command)
                    
            # Execute the PowerShell script
            process = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-File', temp_path],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # Clean up the temporary file
            try:
                os.unlink(temp_path)
            except:
                pass
                
            return {
                'status_code': process.returncode,
                'stdout': process.stdout,
                'stderr': process.stderr,
                'success': process.returncode == 0
            }
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {self.timeout} seconds")
            return {
                'status_code': -1,
                'stdout': '',
                'stderr': f"Command timed out after {self.timeout} seconds",
                'success': False
            }
        except Exception as e:
            logger.error(f"Error running local PowerShell command: {e}")
            return {
                'status_code': -1,
                'stdout': '',
                'stderr': str(e),
                'success': False
            }
            
    def run_powershell(self, command: str) -> Dict[str, Any]:
        """
        Run a PowerShell command on the target
        
        Args:
            command: The PowerShell command to run
            
        Returns:
            Dict: Dictionary with command results
        """
        # If we're using direct PowerShell execution for localhost
        if hasattr(self, 'use_direct_powershell') and self.use_direct_powershell:
            return self._run_local_powershell(command)
            
        if not hasattr(self, 'session') or self.session is None:
            logger.error("Not connected to target")
            return {
                'status_code': -1,
                'stdout': '',
                'stderr': 'Not connected to target',
                'success': False
            }
            
        try:
            result = self.session.run_ps(command)
            return {
                'status_code': result.status_code,
                'stdout': result.std_out.decode('utf-8', errors='replace').strip(),
                'stderr': result.std_err.decode('utf-8', errors='replace').strip(),
                'success': result.status_code == 0
            }
        except Exception as e:
            logger.error(f"Error running command: {e}")
            return {
                'status_code': -1,
                'stdout': '',
                'stderr': str(e),
                'success': False
            }
    
    def get_system_info(self) -> Dict[str, Any]:
        """
        Get basic system information
        
        Returns:
            Dict: System information
        """
        if (not hasattr(self, 'session') or self.session is None) and not self.use_direct_powershell:
            logger.error("Not connected to target")
            return {}
            
        try:
            # Get computer info
            command = """
            $info = New-Object PSObject
            $info | Add-Member -MemberType NoteProperty -Name ComputerName -Value $env:COMPUTERNAME
            $info | Add-Member -MemberType NoteProperty -Name OSVersion -Value (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
            $info | Add-Member -MemberType NoteProperty -Name LastBootTime -Value (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
            $info | Add-Member -MemberType NoteProperty -Name InstallDate -Value (Get-CimInstance -ClassName Win32_OperatingSystem).InstallDate
            $info | ConvertTo-Json
            """
            
            result = self.run_powershell(command)
            if result['success']:
                try:
                    self.system_info = json.loads(result['stdout'])
                    logger.info(f"Retrieved system info for {self.target}")
                    return self.system_info
                except json.JSONDecodeError:
                    logger.error("Failed to parse system info JSON")
            else:
                logger.error(f"Failed to get system info: {result['stderr']}")
                
            return {}
            
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            return {}
    
    def check_registry(self, hive: str, key: str, name: str) -> Dict[str, Any]:
        """
        Check a registry value
        
        Args:
            hive: Registry hive (e.g., HKEY_LOCAL_MACHINE)
            key: Registry key path
            name: Registry value name
            
        Returns:
            Dict: Registry check results
        """
        if (not hasattr(self, 'session') or self.session is None) and not self.use_direct_powershell:
            logger.error("Not connected to target")
            return {'exists': False, 'error': 'Not connected'}
            
        try:
            logger.debug(f"Checking registry: {hive}\\{key}\\{name}")
            
            # Build PowerShell command to check registry
            command = f"""
            try {{
                # First check if the key exists
                $keyExists = Test-Path -Path "Registry::{hive}\\{key}"
                if (-not $keyExists) {{
                    $result = @{{
                        "exists" = $false
                        "error" = "Registry key does not exist"
                    }}
                    $result | ConvertTo-Json
                    exit
                }}
                
                # Then try to get the value
                $regKey = Get-ItemProperty -Path "Registry::{hive}\\{key}" -Name {name} -ErrorAction Stop
                $value = $regKey.{name}
                $result = @{{
                    "exists" = $true
                    "value" = "$value"
                    "type" = $value.GetType().Name
                }}
                $result | ConvertTo-Json
            }} catch [System.Management.Automation.ItemNotFoundException] {{
                # Key exists but value doesn't
                $result = @{{
                    "exists" = $false
                    "error" = "Registry value does not exist"
                }}
                $result | ConvertTo-Json
            }} catch {{
                # Other errors
                $result = @{{
                    "exists" = $false
                    "error" = $_.Exception.Message
                }}
                $result | ConvertTo-Json
            }}
            """
            
            # Execute command
            result = self.run_powershell(command)
            
            # Parse result
            if result['success']:
                try:
                    data = json.loads(result['stdout'])
                    logger.debug(f"Registry check result: {data}")
                    return data
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse registry check JSON: {result['stdout']}")
            else:
                logger.error(f"Failed to check registry: {result['stderr']}")
                
            return {'exists': False, 'error': result['stderr'] or "Failed to check registry"}
            
        except Exception as e:
            logger.error(f"Error checking registry: {e}")
            return {'exists': False, 'error': str(e)}
    
    def check_service(self, service_name: str) -> Dict[str, Any]:
        """
        Check a service status
        
        Args:
            service_name: Name of the service
            
        Returns:
            Dict: Service check results
        """
        if not self.session:
            logger.error("Not connected to target")
            return {'exists': False, 'status': None, 'start_type': None, 'error': 'Not connected'}
            
        try:
            command = f"""
            try {{
                $service = Get-Service -Name '{service_name}' -ErrorAction Stop
                $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='{service_name}'" -ErrorAction Stop
                
                $result = New-Object PSObject
                $result | Add-Member -MemberType NoteProperty -Name Exists -Value $true
                $result | Add-Member -MemberType NoteProperty -Name Status -Value $service.Status
                $result | Add-Member -MemberType NoteProperty -Name StartType -Value $wmiService.StartMode
                $result | ConvertTo-Json
            }} catch {{
                $result = New-Object PSObject
                $result | Add-Member -MemberType NoteProperty -Name Exists -Value $false
                $result | Add-Member -MemberType NoteProperty -Name Status -Value $null
                $result | Add-Member -MemberType NoteProperty -Name StartType -Value $null
                $result | Add-Member -MemberType NoteProperty -Name Error -Value "Service does not exist"
                $result | ConvertTo-Json
            }}
            """
            
            result = self.run_powershell(command)
            if result['success']:
                try:
                    service_result = json.loads(result['stdout'])
                    logger.debug(f"Service check result: {service_result}")
                    return service_result
                except json.JSONDecodeError:
                    logger.error("Failed to parse service check JSON")
            else:
                logger.error(f"Failed to check service: {result['stderr']}")
                
            return {'exists': False, 'status': None, 'start_type': None, 'error': result['stderr']}
            
        except Exception as e:
            logger.error(f"Error checking service: {e}")
            return {'exists': False, 'status': None, 'start_type': None, 'error': str(e)}
    
    def check_user_account(self, username: str) -> Dict[str, Any]:
        """
        Check a user account
        
        Args:
            username: Name of the user account
            
        Returns:
            Dict: User account check results
        """
        if not self.session:
            logger.error("Not connected to target")
            return {'exists': False, 'enabled': None, 'error': 'Not connected'}
            
        try:
            command = f"""
            try {{
                $user = Get-LocalUser -Name '{username}' -ErrorAction Stop
                
                $result = New-Object PSObject
                $result | Add-Member -MemberType NoteProperty -Name Exists -Value $true
                $result | Add-Member -MemberType NoteProperty -Name Enabled -Value $user.Enabled
                $result | Add-Member -MemberType NoteProperty -Name PasswordRequired -Value $user.PasswordRequired
                $result | Add-Member -MemberType NoteProperty -Name PasswordLastSet -Value $user.PasswordLastSet
                $result | ConvertTo-Json
            }} catch {{
                $result = New-Object PSObject
                $result | Add-Member -MemberType NoteProperty -Name Exists -Value $false
                $result | Add-Member -MemberType NoteProperty -Name Enabled -Value $null
                $result | Add-Member -MemberType NoteProperty -Name Error -Value "User account does not exist"
                $result | ConvertTo-Json
            }}
            """
            
            result = self.run_powershell(command)
            if result['success']:
                try:
                    user_result = json.loads(result['stdout'])
                    logger.debug(f"User account check result: {user_result}")
                    return user_result
                except json.JSONDecodeError:
                    logger.error("Failed to parse user account check JSON")
            else:
                logger.error(f"Failed to check user account: {result['stderr']}")
                
            return {'exists': False, 'enabled': None, 'error': result['stderr']}
            
        except Exception as e:
            logger.error(f"Error checking user account: {e}")
            return {'exists': False, 'enabled': None, 'error': str(e)}
    
    def check_file(self, file_path: str) -> Dict[str, Any]:
        """
        Check if a file exists
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dict: File check results
        """
        if not self.session:
            logger.error("Not connected to target")
            return {'exists': False, 'error': 'Not connected'}
            
        try:
            command = f"""
            try {{
                $file = Get-Item -Path '{file_path}' -ErrorAction Stop
                
                $result = New-Object PSObject
                $result | Add-Member -MemberType NoteProperty -Name Exists -Value $true
                $result | Add-Member -MemberType NoteProperty -Name Length -Value $file.Length
                $result | Add-Member -MemberType NoteProperty -Name LastWriteTime -Value $file.LastWriteTime
                $result | ConvertTo-Json
            }} catch {{
                $result = New-Object PSObject
                $result | Add-Member -MemberType NoteProperty -Name Exists -Value $false
                $result | Add-Member -MemberType NoteProperty -Name Error -Value "File does not exist"
                $result | ConvertTo-Json
            }}
            """
            
            result = self.run_powershell(command)
            if result['success']:
                try:
                    file_result = json.loads(result['stdout'])
                    logger.debug(f"File check result: {file_result}")
                    return file_result
                except json.JSONDecodeError:
                    logger.error("Failed to parse file check JSON")
            else:
                logger.error(f"Failed to check file: {result['stderr']}")
                
            return {'exists': False, 'error': result['stderr']}
            
        except Exception as e:
            logger.error(f"Error checking file: {e}")
            return {'exists': False, 'error': str(e)}
    
    def check_event_log(self, log_name: str) -> Dict[str, Any]:
        """
        Check event log configuration
        
        Args:
            log_name: Name of the event log
            
        Returns:
            Dict: Event log check results
        """
        if not self.session:
            logger.error("Not connected to target")
            return {'exists': False, 'error': 'Not connected'}
            
        try:
            command = f"""
            try {{
                $log = Get-WinEvent -ListLog '{log_name}' -ErrorAction Stop
                
                $result = New-Object PSObject
                $result | Add-Member -MemberType NoteProperty -Name Exists -Value $true
                $result | Add-Member -MemberType NoteProperty -Name LogName -Value $log.LogName
                $result | Add-Member -MemberType NoteProperty -Name FileSize -Value $log.MaximumSizeInBytes
                $result | Add-Member -MemberType NoteProperty -Name IsEnabled -Value $log.IsEnabled
                $result | Add-Member -MemberType NoteProperty -Name LogMode -Value $log.LogMode
                $result | Add-Member -MemberType NoteProperty -Name RecordCount -Value $log.RecordCount
                $result | ConvertTo-Json
            }} catch {{
                $result = New-Object PSObject
                $result | Add-Member -MemberType NoteProperty -Name Exists -Value $false
                $result | Add-Member -MemberType NoteProperty -Name Error -Value "Event log does not exist"
                $result | ConvertTo-Json
            }}
            """
            
            result = self.run_powershell(command)
            if result['success']:
                try:
                    log_result = json.loads(result['stdout'])
                    logger.debug(f"Event log check result: {log_result}")
                    return log_result
                except json.JSONDecodeError:
                    logger.error("Failed to parse event log check JSON")
            else:
                logger.error(f"Failed to check event log: {result['stderr']}")
                
            return {'exists': False, 'error': result['stderr']}
            
        except Exception as e:
            logger.error(f"Error checking event log: {e}")
            return {'exists': False, 'error': str(e)}


def main():
    """Test function for the scanner"""
    scanner = WindowsScanner("localhost")
    if scanner.connect():
        print("Connected to localhost")
        
        # Get system info
        system_info = scanner.get_system_info()
        print(f"System Info: {system_info}")
        
        # Check registry
        reg_result = scanner.check_registry("HKEY_LOCAL_MACHINE", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName")
        print(f"Registry Check: {reg_result}")
        
        # Check service
        service_result = scanner.check_service("wuauserv")
        print(f"Service Check: {service_result}")
        
        # Check user account
        user_result = scanner.check_user_account("Administrator")
        print(f"User Account Check: {user_result}")
        
        # Check file
        file_result = scanner.check_file("C:\\Windows\\System32\\notepad.exe")
        print(f"File Check: {file_result}")
        
        # Check event log
        log_result = scanner.check_event_log("Security")
        print(f"Event Log Check: {log_result}")


if __name__ == "__main__":
    main() 