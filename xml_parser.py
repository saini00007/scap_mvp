#!/usr/bin/env python3
"""
XML Parser for SCAP MVP
Reads XCCDF and OVAL files and converts them to Python dictionaries
"""

import os
import logging
from lxml import etree
from typing import Dict, List, Any, Optional, Tuple

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# XML Namespaces
NS = {
    'xccdf': 'http://checklists.nist.gov/xccdf/1.2',
    'oval': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
    'oval-common': 'http://oval.mitre.org/XMLSchema/oval-common-5',
    'win-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#windows',
    'ds': 'http://scap.nist.gov/schema/scap/source/1.2',
    'cpe-dict': 'http://cpe.mitre.org/dictionary/2.0',
    'cat': 'urn:oasis:names:tc:entity:xmlns:xml:catalog'
}

class XmlParser:
    """Parser for XCCDF and OVAL XML files"""
    
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
        Load the XML files into memory
        
        Returns:
            bool: True if files were loaded successfully, False otherwise
        """
        try:
            if not os.path.exists(self.xccdf_path):
                logger.error(f"XCCDF file not found: {self.xccdf_path}")
                return False
            
            # Parse the main XML file
            self.xccdf_tree = etree.parse(self.xccdf_path)
            root = self.xccdf_tree.getroot()
            
            # Check if this is a SCAP datastream
            self.is_datastream = root.tag.endswith('data-stream-collection')
            
            if self.is_datastream:
                logger.info("Detected SCAP datastream format")
                # Extract XCCDF benchmark and OVAL definitions from datastream
                success = self._extract_from_datastream()
                if not success and not self.test_mode:
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
            
        except etree.XMLSyntaxError as e:
            logger.error(f"XML syntax error: {e}")
            return False
        except Exception as e:
            logger.error(f"Error loading XML files: {e}")
            return False
    
    def _extract_from_datastream(self) -> bool:
        """
        Extract XCCDF benchmark and OVAL definitions from a SCAP datastream
        
        Returns:
            bool: True if extraction was successful, False otherwise
        """
        try:
            # Find the XCCDF component in the datastream
            xccdf_components = self.xccdf_tree.xpath("//ds:component[contains(@id, 'xccdf')]", namespaces=NS)
            if xccdf_components:
                # Use the first XCCDF component found
                for component in xccdf_components:
                    # Look for Benchmark element inside component
                    benchmark = component.find(".//xccdf:Benchmark", namespaces=NS)
                    if benchmark is not None:
                        self.xccdf_benchmark = benchmark
                        break
            
            if self.xccdf_benchmark is None:
                # Try direct search for Benchmark element
                benchmark = self.xccdf_tree.find(".//xccdf:Benchmark", namespaces=NS)
                if benchmark is not None:
                    self.xccdf_benchmark = benchmark
                else:
                    logger.error("Could not find XCCDF Benchmark in datastream")
                    return False
            
            # Find OVAL definitions in the datastream
            oval_components = self.xccdf_tree.xpath("//ds:component[contains(@id, 'oval')]", namespaces=NS)
            if oval_components:
                # Use the first OVAL component found
                for component in oval_components:
                    # Look for oval_definitions element inside component
                    oval_defs = component.find(".//oval:oval_definitions", namespaces=NS)
                    if oval_defs is not None:
                        self.oval_definitions = oval_defs
                        break
            
            # If no OVAL definitions found in datastream and oval_path is provided, try to load it
            if self.oval_definitions is None and self.oval_path and os.path.exists(self.oval_path):
                self.oval_tree = etree.parse(self.oval_path)
                self.oval_definitions = self.oval_tree.getroot()
                
            return True
            
        except Exception as e:
            logger.error(f"Error extracting components from datastream: {e}")
            return False
    
    def parse_xccdf(self) -> Dict[str, Any]:
        """
        Parse the XCCDF file to extract rules
        
        Returns:
            Dict: Dictionary of rules with their metadata
        """
        if self.xccdf_benchmark is None:
            logger.error("XCCDF Benchmark not loaded")
            return {}
            
        rules_dict = {}
        
        try:
            # Find all Rule elements
            rules = self.xccdf_benchmark.xpath(".//xccdf:Rule", namespaces=NS)
            
            for rule in rules:
                rule_id = rule.get("id")
                if not rule_id:
                    continue
                    
                # Get rule metadata
                title = self._get_element_text(rule, "./xccdf:title", "")
                description = self._get_element_text(rule, "./xccdf:description", "")
                severity = rule.get("severity", "unknown")
                
                # Get check reference
                check = rule.find(".//xccdf:check", namespaces=NS)
                if check is None:
                    continue
                    
                check_ref = check.find(".//xccdf:check-content-ref", namespaces=NS)
                if check_ref is None:
                    continue
                    
                oval_ref = check_ref.get("name", "")
                
                # Store rule info
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "title": title,
                    "description": description,
                    "severity": severity,
                    "oval_ref": oval_ref
                }
                
            logger.info(f"Parsed {len(rules_dict)} rules from XCCDF")
            return rules_dict
            
        except Exception as e:
            logger.error(f"Error parsing XCCDF: {e}")
            return {}
    
    def parse_oval(self) -> Dict[str, Any]:
        """
        Parse the OVAL file to extract tests, objects, and states
        
        Returns:
            Dict: Dictionary of OVAL definitions with their tests
        """
        if self.test_mode:
            # In test mode, create mock OVAL definitions
            return self._create_mock_oval_defs()
            
        if self.oval_definitions is None:
            logger.error("OVAL definitions not loaded")
            return {}
            
        oval_dict = {}
        
        try:
            # Find all definitions
            definitions = self.oval_definitions.xpath(".//oval:definition", namespaces=NS)
            
            for definition in definitions:
                def_id = definition.get("id")
                if not def_id:
                    continue
                    
                # Get definition metadata
                title = self._get_element_text(definition, "./oval:metadata/oval:title", "")
                description = self._get_element_text(definition, "./oval:metadata/oval:description", "")
                
                # Get criteria and test references
                criterion = definition.find(".//oval:criterion", namespaces=NS)
                if criterion is None:
                    continue
                    
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
            return {}
    
    def _create_mock_oval_defs(self) -> Dict[str, Any]:
        """
        Create mock OVAL definitions for testing
        
        Returns:
            Dict: Dictionary of mock OVAL definitions
        """
        logger.info("Creating mock OVAL definitions for testing")
        
        # Get XCCDF rules to match with mock OVAL definitions
        xccdf_rules = self.parse_xccdf()
        
        oval_dict = {}
        count = 0
        
        # Create a mock OVAL definition for each XCCDF rule (up to 20 for performance)
        for rule_id, rule_info in list(xccdf_rules.items())[:20]:
            oval_ref = rule_info.get("oval_ref", "")
            if not oval_ref:
                oval_ref = f"oval:mil.disa.stig.windows11:def:{count+1}"
                
            oval_dict[oval_ref] = {
                "id": oval_ref,
                "title": f"Mock OVAL for {rule_info.get('title', '')}",
                "description": rule_info.get('description', ''),
                "test_ref": f"oval:mil.disa.stig.windows11:tst:{count+1}",
                "test_info": {
                    "type": "registry",
                    "object_ref": f"oval:mil.disa.stig.windows11:obj:{count+1}",
                    "state_ref": f"oval:mil.disa.stig.windows11:ste:{count+1}",
                    "object_info": {
                        "type": "registry",
                        "hive": "HKEY_LOCAL_MACHINE",
                        "key": "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate",
                        "name": "MockSetting"
                    },
                    "state_info": {
                        "type": "registry",
                        "value": "1",
                        "datatype": "int",
                        "operation": "equals"
                    }
                }
            }
            count += 1
            
        logger.info(f"Created {count} mock OVAL definitions")
        return oval_dict
    
    def _get_test_info(self, test_ref: str) -> Dict[str, Any]:
        """
        Get detailed information about a test
        
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
                logger.warning(f"Test not found: {test_ref}")
                return test_info
                
            test = tests[0]
            test_tag = etree.QName(test).localname
            test_info["type"] = test_tag.replace("_test", "")
            
            # Get object and state references
            # Try with different namespace patterns
            object_ref_elem = None
            state_ref_elem = None
            
            # Try with explicit namespaces
            for ns_prefix in ['oval:', 'win-def:', '']:
                if object_ref_elem is None:
                    object_ref_elem = test.find(f".//{ns_prefix}object")
                if state_ref_elem is None:
                    state_ref_elem = test.find(f".//{ns_prefix}state")
            
            # Try with xpath if direct find fails
            if object_ref_elem is None:
                object_refs = test.xpath(".//*[local-name()='object']")
                if object_refs:
                    object_ref_elem = object_refs[0]
                    
            if state_ref_elem is None:
                state_refs = test.xpath(".//*[local-name()='state']")
                if state_refs:
                    state_ref_elem = state_refs[0]
            
            if object_ref_elem is not None:
                object_ref = object_ref_elem.get("object_ref", "")
                test_info["object_ref"] = object_ref
                test_info["object_info"] = self._get_object_info(object_ref)
                
            if state_ref_elem is not None:
                state_ref = state_ref_elem.get("state_ref", "")
                test_info["state_ref"] = state_ref
                test_info["state_info"] = self._get_state_info(state_ref)
                
            return test_info
            
        except Exception as e:
            logger.error(f"Error getting test info: {e}")
            return test_info
    
    def _get_object_info(self, object_ref: str) -> Dict[str, Any]:
        """
        Get detailed information about an object
        
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
                logger.warning(f"Object not found: {object_ref}")
                return object_info
                
            obj = objects[0]
            obj_tag = etree.QName(obj).localname
            object_info["type"] = obj_tag.replace("_object", "")
            
            # Handle different object types
            if "registry" in obj_tag:
                # Try different approaches to find elements
                for field, xpath_list in {
                    "hive": ["./win-def:hive", "./hive", ".//*[local-name()='hive']"],
                    "key": ["./win-def:key", "./key", ".//*[local-name()='key']"],
                    "name": ["./win-def:name", "./name", ".//*[local-name()='name']"]
                }.items():
                    for xpath in xpath_list:
                        value = self._get_element_text(obj, xpath, "")
                        if value:
                            object_info[field] = value
                            break
                
            elif "service" in obj_tag:
                for xpath in ["./win-def:service_name", "./service_name", ".//*[local-name()='service_name']"]:
                    value = self._get_element_text(obj, xpath, "")
                    if value:
                        object_info["service_name"] = value
                        break
                
            elif "cmdlet" in obj_tag:
                for field, xpath_list in {
                    "module_name": ["./win-def:module_name", "./module_name", ".//*[local-name()='module_name']"],
                    "cmdlet": ["./win-def:cmdlet", "./cmdlet", ".//*[local-name()='cmdlet']"],
                    "parameters": ["./win-def:parameters", "./parameters", ".//*[local-name()='parameters']"],
                    "select": ["./win-def:select", "./select", ".//*[local-name()='select']"]
                }.items():
                    for xpath in xpath_list:
                        value = self._get_element_text(obj, xpath, "")
                        if value:
                            object_info[field] = value
                            break
                
            return object_info
            
        except Exception as e:
            logger.error(f"Error getting object info: {e}")
            return object_info
    
    def _get_state_info(self, state_ref: str) -> Dict[str, Any]:
        """
        Get detailed information about a state
        
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
                logger.warning(f"State not found: {state_ref}")
                return state_info
                
            state = states[0]
            state_tag = etree.QName(state).localname
            state_info["type"] = state_tag.replace("_state", "")
            
            # Handle different state types
            if "registry" in state_tag:
                # Try different approaches to find value element
                value_elem = None
                for xpath in ["./win-def:value", "./value", ".//*[local-name()='value']"]:
                    value_elem = state.find(xpath)
                    if value_elem is not None:
                        break
                
                if value_elem is not None:
                    state_info["value"] = value_elem.text
                    state_info["datatype"] = value_elem.get("datatype", "string")
                    state_info["operation"] = value_elem.get("operation", "equals")
                    
            elif "service" in state_tag:
                for field, xpath_list in {
                    "start_type": ["./win-def:start_type", "./start_type", ".//*[local-name()='start_type']"],
                    "current_state": ["./win-def:current_state", "./current_state", ".//*[local-name()='current_state']"]
                }.items():
                    for xpath in xpath_list:
                        value = self._get_element_text(state, xpath, "")
                        if value:
                            state_info[field] = value
                            break
                
            elif "cmdlet" in state_tag:
                value_elem = None
                for xpath in ["./win-def:value_of", "./value_of", ".//*[local-name()='value_of']"]:
                    value_elem = state.find(xpath)
                    if value_elem is not None:
                        break
                
                if value_elem is not None:
                    state_info["value"] = value_elem.text
                    state_info["datatype"] = value_elem.get("datatype", "string")
                    state_info["operation"] = value_elem.get("operation", "equals")
                    
            return state_info
            
        except Exception as e:
            logger.error(f"Error getting state info: {e}")
            return state_info
    
    def extract_rules(self) -> Dict[str, Any]:
        """
        Extract all rules from XCCDF and link them to OVAL definitions
        
        Returns:
            Dict: Dictionary of rules with their complete information
        """
        xccdf_rules = self.parse_xccdf()
        
        if self.test_mode:
            # In test mode, create mock rules
            oval_defs = self._create_mock_oval_defs()
        else:
            oval_defs = self.parse_oval()
        
        if not xccdf_rules:
            return {}
            
        # Link XCCDF rules to OVAL definitions
        rules = {}
        for rule_id, rule_info in xccdf_rules.items():
            oval_ref = rule_info.get("oval_ref", "")
            
            # In test mode, create a mock rule even if no OVAL reference
            if self.test_mode and not oval_ref:
                # Generate a mock oval_ref
                oval_ref = f"oval:mil.disa.stig.windows11:def:{len(rules) + 1}"
            
            # For SCAP datastreams, try to match by ID pattern if exact match fails
            oval_def = oval_defs.get(oval_ref)
            if not oval_def and oval_ref:
                # Try to find a matching OVAL definition by ID pattern
                # Extract the numeric part of the OVAL reference
                import re
                match = re.search(r'(\d+)$', oval_ref)
                if match:
                    oval_id_num = match.group(1)
                    # Look for any OVAL definition with this number
                    for def_id, def_info in oval_defs.items():
                        if def_id.endswith(oval_id_num):
                            oval_def = def_info
                            logger.debug(f"Matched rule {rule_id} to OVAL definition {def_id} by pattern")
                            break
            
            # If we found a matching OVAL definition or we're in test mode
            if oval_def or self.test_mode:
                # Get OVAL info if available, otherwise use empty dict
                oval_info = oval_def or {}
                test_info = oval_info.get("test_info", {})
                
                # Create a complete rule with all information
                rules[rule_id] = {
                    "id": rule_id,
                    "title": rule_info.get("title", ""),
                    "description": rule_info.get("description", ""),
                    "severity": rule_info.get("severity", "unknown"),
                    "test_type": test_info.get("type", "registry"),  # Default to registry for test mode
                    "object_info": test_info.get("object_info", {"type": "registry", "hive": "HKEY_LOCAL_MACHINE"}),
                    "state_info": test_info.get("state_info", {"type": "registry", "value": "1"})
                }
                
                # In test mode, ensure we have at least 5 rules for testing
                if self.test_mode and len(rules) >= 5:
                    break
        
        # If in test mode and no rules were found, create some mock rules
        if self.test_mode and not rules:
            for i in range(5):
                rule_id = f"xccdf_mil.disa.stig_rule_SV-{220000 + i}"
                rules[rule_id] = {
                    "id": rule_id,
                    "title": f"Mock Rule {i+1}",
                    "description": f"This is a mock rule for testing purposes ({i+1})",
                    "severity": ["low", "medium", "high"][i % 3],
                    "test_type": "registry",
                    "object_info": {
                        "type": "registry",
                        "hive": "HKEY_LOCAL_MACHINE",
                        "key": "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate",
                        "name": f"MockSetting{i+1}"
                    },
                    "state_info": {
                        "type": "registry",
                        "value": "1",
                        "datatype": "int",
                        "operation": "equals"
                    }
                }
        
        # If still no rules found but we have XCCDF rules and OVAL definitions,
        # create simple rules for all XCCDF rules
        if not rules and xccdf_rules and oval_defs:
            logger.info("Creating simple rules for all XCCDF rules")
            # Take the first 20 OVAL definitions as templates
            oval_templates = list(oval_defs.values())[:20] if len(oval_defs) > 20 else list(oval_defs.values())
            
            for rule_id, rule_info in xccdf_rules.items():
                # Use a template OVAL definition (cycling through available ones)
                template_idx = len(rules) % len(oval_templates)
                template = oval_templates[template_idx]
                test_info = template.get("test_info", {})
                
                rules[rule_id] = {
                    "id": rule_id,
                    "title": rule_info.get("title", ""),
                    "description": rule_info.get("description", ""),
                    "severity": rule_info.get("severity", "unknown"),
                    "test_type": test_info.get("type", "registry"),
                    "object_info": test_info.get("object_info", {"type": "registry", "hive": "HKEY_LOCAL_MACHINE"}),
                    "state_info": test_info.get("state_info", {"type": "registry", "value": "1"})
                }
                
                # Limit to 50 rules for performance
                if len(rules) >= 50:
                    break
        
        self.rules = rules
        logger.info(f"Extracted {len(rules)} complete rules")
        return rules
    
    def _get_element_text(self, element, xpath, default="") -> str:
        """
        Helper method to get text from an XML element
        
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
            if result and len(result) > 0:
                return result[0].text or default
                
            # Try without namespaces
            simple_xpath = xpath.replace("./xccdf:", "./").replace("./win-def:", "./").replace("./oval:", "./")
            if simple_xpath != xpath:
                result = element.xpath(simple_xpath)
                if result and len(result) > 0:
                    return result[0].text or default
                    
            return default
        except Exception:
            return default


def main():
    """Test function for the XML parser"""
    parser = XmlParser("sample_rules.xml", "sample_oval.xml")
    if parser.load_files():
        rules = parser.extract_rules()
        for rule_id, rule in rules.items():
            print(f"Rule: {rule['title']}")
            print(f"  Severity: {rule['severity']}")
            print(f"  Test Type: {rule['test_type']}")
            print(f"  Object: {rule['object_info']}")
            print(f"  State: {rule['state_info']}")
            print()


if __name__ == "__main__":
    main() 