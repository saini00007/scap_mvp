#!/usr/bin/env python3
"""
XML Parser for SCAP MVP - Updated for NIST SCAP datastreams
Reads XCCDF and OVAL files and converts them to Python dictionaries
"""

import os
import logging
from lxml import etree
from typing import Dict, List, Any, Optional, Tuple

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Updated XML Namespaces for NIST SCAP
NS = {
    'xccdf': 'http://checklists.nist.gov/xccdf/1.2',
    'oval': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
    'oval-common': 'http://oval.mitre.org/XMLSchema/oval-common-5',
    'win-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#windows',
    'ind-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#independent',
    'ds': 'http://scap.nist.gov/schema/scap/source/1.2',
    'xlink': 'http://www.w3.org/1999/xlink',
    'cpe-dict': 'http://cpe.mitre.org/dictionary/2.0',
    'cat': 'urn:oasis:names:tc:entity:xmlns:xml:catalog',
    'dc': 'http://purl.org/dc/elements/1.1/'
}

class XmlParser:
    """Parser for XCCDF and OVAL XML files with improved NIST SCAP support"""
    
    def __init__(self, xccdf_path: str, oval_path: str = None, test_mode: bool = False):
        """
        Initialize the parser with paths to XCCDF and OVAL files
        
        Args:
            xccdf_path: Path to the XCCDF XML file or SCAP datastream
            oval_path: Path to the OVAL XML file (optional for datastreams)
            test_mode: If True, will create mock rules for testing
        """
        self.xccdf_path = xccdf_path
        self.oval_path = oval_path
        self.xccdf_tree = None
        self.oval_tree = None
        self.rules = {}
        self.test_mode = test_mode
        self.is_datastream = False
        self.xccdf_benchmark = None
        self.oval_definitions = None
        
    def load_files(self) -> bool:
        """
        Load the XML files into memory with improved error handling
        
        Returns:
            bool: True if files were loaded successfully, False otherwise
        """
        try:
            if not os.path.exists(self.xccdf_path):
                logger.error(f"SCAP file not found: {self.xccdf_path}")
                return False
            
            logger.info(f"Loading SCAP file: {self.xccdf_path}")
            
            # Parse the main XML file
            try:
                self.xccdf_tree = etree.parse(self.xccdf_path)
            except etree.XMLSyntaxError as e:
                logger.error(f"XML syntax error in {self.xccdf_path}: {e}")
                return False
            
            root = self.xccdf_tree.getroot()
            logger.info(f"Root element: {root.tag}")
            
            # Check if this is a SCAP datastream
            self.is_datastream = (
                root.tag.endswith('data-stream-collection') or 
                'data-stream-collection' in root.tag
            )
            
            if self.is_datastream:
                logger.info("Detected SCAP datastream format")
                # Extract XCCDF benchmark and OVAL definitions from datastream
                success = self._extract_from_datastream()
                if not success and not self.test_mode:
                    logger.warning("Failed to extract from datastream, attempting fallback")
                    # Try to find benchmark directly
                    benchmark = self.xccdf_tree.find(".//xccdf:Benchmark", namespaces=NS)
                    if benchmark is not None:
                        self.xccdf_benchmark = benchmark
                        logger.info("Found benchmark using fallback method")
                    else:
                        return False
            else:
                # Regular XCCDF file
                self.xccdf_benchmark = root
                
                # Try to load OVAL file if provided
                if not self.test_mode and self.oval_path:
                    if not os.path.exists(self.oval_path):
                        logger.error(f"OVAL file not found: {self.oval_path}")
                        return False
                    self.oval_tree = etree.parse(self.oval_path)
                    self.oval_definitions = self.oval_tree.getroot()
            
            return True
            
        except Exception as e:
            logger.error(f"Error loading XML files: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False
    
    def _extract_from_datastream(self) -> bool:
        """
        Extract XCCDF benchmark and OVAL definitions from a SCAP datastream
        Improved to handle NIST SCAP format
        
        Returns:
            bool: True if extraction was successful, False otherwise
        """
        try:
            # First, find the data-stream element
            data_streams = self.xccdf_tree.xpath("//ds:data-stream", namespaces=NS)
            if not data_streams:
                logger.warning("No data-stream elements found")
                return False
            
            # Use the first data stream
            data_stream = data_streams[0]
            logger.info(f"Found data stream: {data_stream.get('id', 'unknown')}")
            
            # Look for checklists section
            checklists = data_stream.xpath(".//ds:checklists", namespaces=NS)
            if checklists:
                # Find component references in checklists
                xccdf_refs = checklists[0].xpath(".//ds:component-ref", namespaces=NS)
                for ref in xccdf_refs:
                    ref_id = ref.get('id', '')
                    href = ref.get('{http://www.w3.org/1999/xlink}href', '')
                    
                    # Remove the # prefix from href
                    if href.startswith('#'):
                        component_id = href[1:]
                    else:
                        component_id = ref_id
                    
                    # Find the actual component
                    component_xpath = f"//ds:component[@id='{component_id}']"
                    components = self.xccdf_tree.xpath(component_xpath, namespaces=NS)
                    
                    for component in components:
                        # Look for Benchmark inside component
                        benchmark = component.find(".//xccdf:Benchmark", namespaces=NS)
                        if benchmark is not None:
                            self.xccdf_benchmark = benchmark
                            logger.info(f"Found XCCDF Benchmark in component: {component_id}")
                            break
                    
                    if self.xccdf_benchmark is not None:
                        break
            
            # Look for checks section to find OVAL
            checks = data_stream.xpath(".//ds:checks", namespaces=NS)
            if checks:
                oval_refs = checks[0].xpath(".//ds:component-ref", namespaces=NS)
                for ref in oval_refs:
                    ref_id = ref.get('id', '')
                    href = ref.get('{http://www.w3.org/1999/xlink}href', '')
                    
                    # Remove the # prefix from href
                    if href.startswith('#'):
                        component_id = href[1:]
                    else:
                        component_id = ref_id
                    
                    # Find the actual component
                    component_xpath = f"//ds:component[@id='{component_id}']"
                    components = self.xccdf_tree.xpath(component_xpath, namespaces=NS)
                    
                    for component in components:
                        
                        oval_defs = component.find(".//oval:oval_definitions", namespaces=NS)
                        if oval_defs is not None:
                            self.oval_definitions = oval_defs
                            logger.info(f"Found OVAL definitions in component: {component_id}")
                            break
                    
                    if self.oval_definitions is not None:
                        break
            
            
            if self.xccdf_benchmark is None:
                benchmark = self.xccdf_tree.find(".//xccdf:Benchmark", namespaces=NS)
                if benchmark is not None:
                    self.xccdf_benchmark = benchmark
                    logger.info("Found XCCDF Benchmark using direct search")
            
            if self.oval_definitions is None:
                oval_defs = self.xccdf_tree.find(".//oval:oval_definitions", namespaces=NS)
                if oval_defs is not None:
                    self.oval_definitions = oval_defs
                    logger.info("Found OVAL definitions using direct search")
            
           
            if self.oval_definitions is None and self.oval_path and os.path.exists(self.oval_path):
                self.oval_tree = etree.parse(self.oval_path)
                self.oval_definitions = self.oval_tree.getroot()
                logger.info(f"Loaded OVAL definitions from separate file: {self.oval_path}")
            
            success = self.xccdf_benchmark is not None
            if not success:
                logger.error("Could not extract XCCDF Benchmark from datastream")
            
            return success
            
        except Exception as e:
            logger.error(f"Error extracting components from datastream: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False
    
    def parse_xccdf(self) -> Dict[str, Any]:
        """
        Parse the XCCDF file to extract rules with improved handling
        
        Returns:
            Dict: Dictionary of rules with their metadata
        """
        if self.xccdf_benchmark is None:
            logger.error("XCCDF Benchmark not loaded")
            return {}
            
        rules_dict = {}
        
        try:
            # Find all Rule elements, including nested ones in Groups
            rules = self.xccdf_benchmark.xpath(".//xccdf:Rule", namespaces=NS)
            logger.info(f"Found {len(rules)} rules in XCCDF")
            
            for rule in rules:
                rule_id = rule.get("id")
                if not rule_id:
                    continue
                    
                # Get rule metadata
                title = self._get_element_text(rule, "./xccdf:title", "")
                description = self._get_element_text(rule, "./xccdf:description", "")
                severity = rule.get("severity", "unknown")
                
                # Get version for STIG compatibility
                version = self._get_element_text(rule, "./xccdf:version", "")
                
                # Get check reference
                checks = rule.xpath(".//xccdf:check", namespaces=NS)
                oval_ref = ""
                
                for check in checks:
                    # Look for check-content-ref
                    check_refs = check.xpath(".//xccdf:check-content-ref", namespaces=NS)
                    for check_ref in check_refs:
                        name = check_ref.get("name", "")
                        if name and "oval:" in name:
                            oval_ref = name
                            break
                    
                    if oval_ref:
                        break
                
                # Store rule info
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "title": title,
                    "description": description,
                    "severity": severity,
                    "version": version,
                    "oval_ref": oval_ref
                }
                
            logger.info(f"Parsed {len(rules_dict)} rules from XCCDF")
            return rules_dict
            
        except Exception as e:
            logger.error(f"Error parsing XCCDF: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return {}
    
    def parse_oval(self) -> Dict[str, Any]:
        """
        Parse the OVAL file to extract tests, objects, and states with improved handling
        
        Returns:
            Dict: Dictionary of OVAL definitions with their tests
        """
        if self.test_mode:
            # In test mode, create mock OVAL definitions
            return self._create_mock_oval_defs()
            
        if self.oval_definitions is None:
            logger.warning("OVAL definitions not loaded, attempting to continue without them")
            return {}
            
        oval_dict = {}
        
        try:
            # Find all definitions
            definitions = self.oval_definitions.xpath(".//oval:definition", namespaces=NS)
            logger.info(f"Found {len(definitions)} OVAL definitions")
            
            for definition in definitions:
                def_id = definition.get("id")
                if not def_id:
                    continue
                    
                # Get definition metadata
                title = self._get_element_text(definition, "./oval:metadata/oval:title", "")
                description = self._get_element_text(definition, "./oval:metadata/oval:description", "")
                
                # Get criteria and test references
                criteria = definition.find(".//oval:criteria", namespaces=NS)
                if criteria is None:
                    continue
                
                # Look for criterion elements
                criterions = criteria.xpath(".//oval:criterion", namespaces=NS)
                if not criterions:
                    continue
                
                # Use the first criterion for now
                criterion = criterions[0]
                test_ref = criterion.get("test_ref", "")
                
                # Get test details
                test_info = self._get_test_info(test_ref)
                
                # Store definition info
                oval_dict[def_id] = {
                    "id": def_id,
                    "title": title,
                    "description": description,
                    "test_ref": test_ref,
                    "test_info": test_info
                }
                
            logger.info(f"Parsed {len(oval_dict)} definitions from OVAL")
            return oval_dict
            
        except Exception as e:
            logger.error(f"Error parsing OVAL: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return {}
    
    def _get_test_info(self, test_ref: str) -> Dict[str, Any]:
        """
        Get detailed information about a test with improved parsing
        
        Args:
            test_ref: The test reference ID
            
        Returns:
            Dict: Dictionary with test details
        """
        test_info = {
            "type": "",
            "object_ref": "",
            "state_ref": "",
            "object_info": {},
            "state_info": {}
        }
        
        if self.oval_definitions is None:
            return test_info
            
        try:
            # Find the test element
            test_xpath = f".//*[@id='{test_ref}']"
            tests = self.oval_definitions.xpath(test_xpath)
            
            if not tests or len(tests) == 0:
                logger.debug(f"Test not found: {test_ref}")
                return test_info
                
            test = tests[0]
            test_tag = etree.QName(test).localname
            
            # Determine test type
            if "_test" in test_tag:
                test_type = test_tag.replace("_test", "")
            else:
                test_type = test_tag
            
            test_info["type"] = test_type
            
            # Get object and state references
            object_elem = test.find(".//*[@object_ref]")
            state_elem = test.find(".//*[@state_ref]")
            
            if object_elem is not None:
                object_ref = object_elem.get("object_ref", "")
                test_info["object_ref"] = object_ref
                test_info["object_info"] = self._get_object_info(object_ref)
                
            if state_elem is not None:
                state_ref = state_elem.get("state_ref", "")
                test_info["state_ref"] = state_ref
                test_info["state_info"] = self._get_state_info(state_ref)
                
            return test_info
            
        except Exception as e:
            logger.debug(f"Error getting test info for {test_ref}: {e}")
            return test_info
    
    def _get_object_info(self, object_ref: str) -> Dict[str, Any]:
        """
        Get detailed information about an object with improved parsing
        
        Args:
            object_ref: The object reference ID
            
        Returns:
            Dict: Dictionary with object details
        """
        object_info = {}
        
        if self.oval_definitions is None:
            return object_info
            
        try:
            # Find the object element
            object_xpath = f".//*[@id='{object_ref}']"
            objects = self.oval_definitions.xpath(object_xpath)
            
            if not objects or len(objects) == 0:
                logger.debug(f"Object not found: {object_ref}")
                return object_info
                
            obj = objects[0]
            obj_tag = etree.QName(obj).localname
            
            # Determine object type
            if "_object" in obj_tag:
                obj_type = obj_tag.replace("_object", "")
            else:
                obj_type = obj_tag
                
            object_info["type"] = obj_type
            
            # Handle different object types
            if "registry" in obj_tag:
                # Registry object fields
                fields = ["hive", "key", "name"]
                for field in fields:
                    # Try multiple xpath patterns
                    for pattern in [f".//{field}", f".//win-def:{field}", f".//*[local-name()='{field}']"]:
                        elements = obj.xpath(pattern, namespaces=NS)
                        if elements and elements[0].text:
                            object_info[field] = elements[0].text.strip()
                            break
                
            elif "service" in obj_tag:
                # Service object fields
                for pattern in ["service_name", "service"]:
                    for xpath_pattern in [f".//{pattern}", f".//win-def:{pattern}", f".//*[local-name()='{pattern}']"]:
                        elements = obj.xpath(xpath_pattern, namespaces=NS)
                        if elements and elements[0].text:
                            object_info["service_name"] = elements[0].text.strip()
                            break
                    if "service_name" in object_info:
                        break
                
            elif "cmdlet" in obj_tag or "powershell" in obj_tag:
                # PowerShell/cmdlet object fields
                fields = ["module_name", "cmdlet", "parameters", "select"]
                for field in fields:
                    for pattern in [f".//{field}", f".//win-def:{field}", f".//*[local-name()='{field}']"]:
                        elements = obj.xpath(pattern, namespaces=NS)
                        if elements and elements[0].text:
                            object_info[field] = elements[0].text.strip()
                            break
                
            return object_info
            
        except Exception as e:
            logger.debug(f"Error getting object info for {object_ref}: {e}")
            return object_info
    
    def _get_state_info(self, state_ref: str) -> Dict[str, Any]:
        """
        Get detailed information about a state with improved parsing
        
        Args:
            state_ref: The state reference ID
            
        Returns:
            Dict: Dictionary with state details
        """
        state_info = {}
        
        if self.oval_definitions is None:
            return state_info
            
        try:
            # Find the state element
            state_xpath = f".//*[@id='{state_ref}']"
            states = self.oval_definitions.xpath(state_xpath)
            
            if not states or len(states) == 0:
                logger.debug(f"State not found: {state_ref}")
                return state_info
                
            state = states[0]
            state_tag = etree.QName(state).localname
            
            # Determine state type
            if "_state" in state_tag:
                state_type = state_tag.replace("_state", "")
            else:
                state_type = state_tag
                
            state_info["type"] = state_type
            
            # Handle different state types
            if "registry" in state_tag:
                # Look for value element
                for pattern in ["value", "win-def:value", "*[local-name()='value']"]:
                    value_elements = state.xpath(f".//{pattern}", namespaces=NS)
                    if value_elements:
                        value_elem = value_elements[0]
                        state_info["value"] = value_elem.text or ""
                        state_info["datatype"] = value_elem.get("datatype", "string")
                        state_info["operation"] = value_elem.get("operation", "equals")
                        break
                    
            elif "service" in state_tag:
                # Service state fields
                fields = ["start_type", "current_state", "start_mode"]
                for field in fields:
                    for pattern in [f".//{field}", f".//win-def:{field}", f".//*[local-name()='{field}']"]:
                        elements = state.xpath(pattern, namespaces=NS)
                        if elements and elements[0].text:
                            if field == "start_mode":
                                state_info["start_type"] = elements[0].text.strip()
                            else:
                                state_info[field] = elements[0].text.strip()
                            break
                
            elif "cmdlet" in state_tag or "powershell" in state_tag:
                # PowerShell/cmdlet state
                for pattern in ["value_of", "value", "win-def:value_of", "*[local-name()='value_of']"]:
                    value_elements = state.xpath(f".//{pattern}", namespaces=NS)
                    if value_elements:
                        value_elem = value_elements[0]
                        state_info["value"] = value_elem.text or ""
                        state_info["datatype"] = value_elem.get("datatype", "string")
                        state_info["operation"] = value_elem.get("operation", "equals")
                        break
                    
            return state_info
            
        except Exception as e:
            logger.debug(f"Error getting state info for {state_ref}: {e}")
            return state_info
    
    def extract_rules(self) -> Dict[str, Any]:
        """
        Extract all rules from XCCDF and link them to OVAL definitions
        Improved to handle cases where OVAL definitions are missing
        
        Returns:
            Dict: Dictionary of rules with their complete information
        """
        xccdf_rules = self.parse_xccdf()
        
        if self.test_mode:
            oval_defs = self._create_mock_oval_defs()
        else:
            oval_defs = self.parse_oval()
        
        if not xccdf_rules:
            logger.error("No XCCDF rules found")
            return {}
        
        logger.info(f"Found {len(xccdf_rules)} XCCDF rules and {len(oval_defs)} OVAL definitions")
        
        # Link XCCDF rules to OVAL definitions
        rules = {}
        rules_without_oval = 0
        
        for rule_id, rule_info in xccdf_rules.items():
            oval_ref = rule_info.get("oval_ref", "")
            
            # Try to find matching OVAL definition
            oval_def = None
            if oval_ref and oval_defs:
                oval_def = oval_defs.get(oval_ref)
                
                # If exact match fails, try pattern matching
                if not oval_def:
                    import re
                    match = re.search(r'(\d+)$', oval_ref)
                    if match:
                        oval_id_num = match.group(1)
                        for def_id, def_info in oval_defs.items():
                            if def_id.endswith(oval_id_num):
                                oval_def = def_info
                                logger.debug(f"Matched rule {rule_id} to OVAL definition {def_id} by pattern")
                                break
            
            # Create rule with available information
            if oval_def:
                test_info = oval_def.get("test_info", {})
                test_type = test_info.get("type", "registry")
                object_info = test_info.get("object_info", {})
                state_info = test_info.get("state_info", {})
            else:
                # Create a default test configuration for rules without OVAL
                rules_without_oval += 1
                test_type = "registry"  # Default to registry test
                object_info = {
                    "type": "registry",
                    "hive": "HKEY_LOCAL_MACHINE",
                    "key": "SOFTWARE\\Policies\\Microsoft\\Windows",
                    "name": "DefaultSetting"
                }
                state_info = {
                    "type": "registry",
                    "value": "1",
                    "datatype": "int",
                    "operation": "equals"
                }
            
            rules[rule_id] = {
                "id": rule_id,
                "title": rule_info.get("title", ""),
                "description": rule_info.get("description", ""),
                "severity": rule_info.get("severity", "unknown"),
                "version": rule_info.get("version", ""),
                "test_type": test_type,
                "object_info": object_info,
                "state_info": state_info,
                "oval_ref": oval_ref
            }
        
        if rules_without_oval > 0:
            logger.warning(f"{rules_without_oval} rules do not have matching OVAL definitions")
        
        self.rules = rules
        logger.info(f"Extracted {len(rules)} complete rules")
        return rules
    
    def _create_mock_oval_defs(self) -> Dict[str, Any]:
        """
        Create mock OVAL definitions for testing
        
        Returns:
            Dict: Dictionary of mock OVAL definitions
        """
        logger.info("Creating mock OVAL definitions for testing")
        
        oval_dict = {}
        
        # Create a few mock OVAL definitions
        for i in range(10):
            oval_id = f"oval:mil.disa.stig.windows11:def:{253254 + i}"
            oval_dict[oval_id] = {
                "id": oval_id,
                "title": f"Mock OVAL Definition {i+1}",
                "description": f"Mock OVAL definition for testing ({i+1})",
                "test_ref": f"oval:mil.disa.stig.windows11:tst:{253254 + i}",
                "test_info": {
                    "type": "registry",
                    "object_ref": f"oval:mil.disa.stig.windows11:obj:{253254 + i}",
                    "state_ref": f"oval:mil.disa.stig.windows11:ste:{253254 + i}",
                    "object_info": {
                        "type": "registry",
                        "hive": "HKEY_LOCAL_MACHINE",
                        "key": "SOFTWARE\\Policies\\Microsoft\\Windows",
                        "name": f"MockSetting{i+1}"
                    },
                    "state_info": {
                        "type": "registry",
                        "value": str(i % 2),  # Alternate between 0 and 1
                        "datatype": "int",
                        "operation": "equals"
                    }
                }
            }
        
        logger.info(f"Created {len(oval_dict)} mock OVAL definitions")
        return oval_dict
    
    def _get_element_text(self, element, xpath, default="") -> str:
        """
        Helper method to get text from an XML element with improved handling
        
        Args:
            element: The XML element to search in
            xpath: XPath expression to find the target element
            default: Default value if element not found
            
        Returns:
            str: Text content of the element
        """
        try:
            # Try with namespaces first
            result = element.xpath(xpath, namespaces=NS)
            if result and len(result) > 0 and result[0].text:
                return result[0].text.strip()
                
            # Try without namespaces
            simple_xpath = xpath.replace("./xccdf:", "./").replace("./win-def:", "./").replace("./oval:", "./")
            if simple_xpath != xpath:
                result = element.xpath(simple_xpath)
                if result and len(result) > 0 and result[0].text:
                    return result[0].text.strip()
            
            # Try with local-name
            local_name_xpath = xpath.replace("xccdf:", "*[local-name()='").replace("/", "']//")
            if "local-name" not in xpath:
                parts = xpath.split("/")
                local_parts = []
                for part in parts:
                    if ":" in part and not part.startswith("."):
                        tag_name = part.split(":")[-1]
                        local_parts.append(f"*[local-name()='{tag_name}']")
                    else:
                        local_parts.append(part)
                local_name_xpath = "/".join(local_parts)
                
                result = element.xpath(local_name_xpath)
                if result and len(result) > 0 and result[0].text:
                    return result[0].text.strip()
                    
            return default
            
        except Exception as e:
            logger.debug(f"Error getting element text with xpath {xpath}: {e}")
            return default


def main():
    """Test function for the XML parser"""
    import sys
    
    if len(sys.argv) > 1:
        scap_file = sys.argv[1]
    else:
        scap_file = "paste.txt"  # Use the provided NIST SCAP file
    
    parser = XmlParser(scap_file, test_mode=False)
    
    if parser.load_files():
        print("✓ Successfully loaded SCAP files")
        
        rules = parser.extract_rules()
        
        if rules:
            print(f"✓ Extracted {len(rules)} rules")
            
            # Show first 5 rules as examples
            count = 0
            for rule_id, rule in rules.items():
                if count >= 5:
                    break
                    
                print(f"\nRule {count + 1}: {rule['title']}")
                print(f"  ID: {rule_id}")
                print(f"  Severity: {rule['severity']}")
                print(f"  Version: {rule['version']}")
                print(f"  Test Type: {rule['test_type']}")
                print(f"  OVAL Ref: {rule['oval_ref']}")
                print(f"  Object: {rule['object_info']}")
                print(f"  State: {rule['state_info']}")
                count += 1
        else:
            print("✗ No rules extracted")
    else:
        print("✗ Failed to load SCAP files")


if __name__ == "__main__":
    main()