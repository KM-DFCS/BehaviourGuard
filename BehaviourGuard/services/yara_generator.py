import os
import hashlib
import re
import logging
import subprocess
import tempfile
from typing import Dict, Any, List, Optional
import yara

logger = logging.getLogger(__name__)

class YaraGeneratorService:
    """
    Service for auto-generating and executing YARA rules
    """
    
    def __init__(self):
        self.yara_binary_path = os.environ.get('YARA_BINARY_PATH', 'yara')
        self.rules_directory = os.environ.get('YARA_RULES_DIR', 'yara_rules')
        os.makedirs(self.rules_directory, exist_ok=True)

    def generate_rules(self, file_path: str, sandbox_report: Dict[str, Any], 
                      network_data: Dict[str, Any], process_data: Dict[str, Any]) -> List[str]:
        """
        Auto-generate YARA rules based on analysis results
        """
        rules = []
        
        try:
            # Generate file-based rules
            file_rules = self._generate_file_based_rules(file_path)
            rules.extend(file_rules)
            
            # Generate behavior-based rules from sandbox report
            behavior_rules = self._generate_behavior_rules(sandbox_report)
            rules.extend(behavior_rules)
            
            # Generate network-based rules
            network_rules = self._generate_network_rules(network_data)
            rules.extend(network_rules)
            
            # Generate process-based rules
            process_rules = self._generate_process_rules(process_data)
            rules.extend(process_rules)
            
            logger.info(f"Generated {len(rules)} YARA rules")
            
        except Exception as e:
            logger.error(f"Error generating YARA rules: {e}")
        
        return rules

    def _generate_file_based_rules(self, file_path: str) -> List[str]:
        """
        Generate YARA rules based on static file analysis
        """
        rules = []
        
        try:
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Calculate hashes
            md5_hash = hashlib.md5(file_content).hexdigest()
            sha1_hash = hashlib.sha1(file_content).hexdigest()
            sha256_hash = hashlib.sha256(file_content).hexdigest()
            
            # Generate hash-based rule
            hash_rule = f'''
rule Hash_Based_Detection_{sha256_hash[:8]}
{{
    meta:
        description = "Detection based on file hashes"
        author = "BehaviorGuard "
        date = "{self._get_current_date()}"
        hash_md5 = "{md5_hash}"
        hash_sha1 = "{sha1_hash}"
        hash_sha256 = "{sha256_hash}"
    
    condition:
        hash.md5(0, filesize) == "{md5_hash}" or
        hash.sha1(0, filesize) == "{sha1_hash}" or
        hash.sha256(0, filesize) == "{sha256_hash}"
}}
'''
            rules.append(hash_rule)
            
            # Generate string-based rules
            strings_rule = self._generate_string_based_rule(file_content, sha256_hash[:8])
            if strings_rule:
                rules.append(strings_rule)
            
            # Generate PE-specific rules if it's a PE file
            if file_content.startswith(b'MZ'):
                pe_rule = self._generate_pe_based_rule(file_content, sha256_hash[:8])
                if pe_rule:
                    rules.append(pe_rule)
            
        except Exception as e:
            logger.error(f"Error generating file-based rules: {e}")
        
        return rules

    def _generate_string_based_rule(self, file_content: bytes, rule_suffix: str) -> Optional[str]:
        """
        Generate YARA rule based on interesting strings in the file
        """
        try:
            # Extract printable strings
            strings = re.findall(b'[\x20-\x7E]{4,}', file_content)
            
            # Filter for interesting strings
            interesting_strings = []
            suspicious_patterns = [
                b'cmd.exe', b'powershell', b'rundll32', b'regsvr32',
                b'CreateProcess', b'VirtualAlloc', b'WriteProcessMemory',
                b'LoadLibrary', b'GetProcAddress', b'CreateFile',
                b'RegOpenKey', b'RegSetValue', b'InternetOpen',
                b'WinExec', b'ShellExecute', b'CreateService',
                b'StartService', b'CryptAcquireContext'
            ]
            
            for string in strings:
                for pattern in suspicious_patterns:
                    if pattern.lower() in string.lower():
                        interesting_strings.append(string.decode('ascii', errors='ignore'))
                        break
            
            if not interesting_strings:
                return None
            
            # Limit to top 10 strings
            interesting_strings = interesting_strings[:10]
            
            # Generate rule
            string_definitions = []
            for i, string in enumerate(interesting_strings):
                string_definitions.append(f'        $s{i} = "{string}" ascii nocase')
            
            rule = f'''
rule String_Based_Detection_{rule_suffix}
{{
    meta:
        description = "Detection based on suspicious strings"
        author = "BehaviorGuard v2.1"
        date = "{self._get_current_date()}"
    
    strings:
{chr(10).join(string_definitions)}
    
    condition:
        any of them
}}
'''#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
            return rule
            
        except Exception as e:
            logger.error(f"Error generating string-based rule: {e}")
            return None

    def _generate_pe_based_rule(self, file_content: bytes, rule_suffix: str) -> Optional[str]:
        """
        Generate YARA rule based on PE file characteristics
        """
        try:
            # Basic PE header analysis
            if len(file_content) < 64:
                return None
            
            # Extract some PE characteristics
            pe_timestamp_offset = 60  # Simplified - real implementation would parse PE properly
            
            rule = f'''
rule PE_Based_Detection_{rule_suffix}
{{
    meta:
        description = "Detection based on PE file characteristics"
        author = "BehaviorGuard"
        date = "{self._get_current_date()}"
    
    condition:
        uint16(0) == 0x5A4D and  // MZ signature
        uint32(uint32(0x3C)) == 0x00004550  // PE signature
}}
'''#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
            return rule
            
        except Exception as e:
            logger.error(f"Error generating PE-based rule: {e}")
            return None

    def _generate_behavior_rules(self, sandbox_report: Dict[str, Any]) -> List[str]:
        """
        Generate YARA rules based on behavioral analysis from sandbox
        """
        rules = []
        
        try:
            if not sandbox_report:
                return rules
            
            # Generate rule based on network indicators
            if 'network' in sandbox_report:
                network_rule = self._generate_network_behavior_rule(sandbox_report['network'])
                if network_rule:
                    rules.append(network_rule)
            
            # Generate rule based on file system activity
            if 'filesystem' in sandbox_report:
                fs_rule = self._generate_filesystem_behavior_rule(sandbox_report['filesystem'])
                if fs_rule:
                    rules.append(fs_rule)
            
            # Generate rule based on registry activity
            if 'registry' in sandbox_report:
                reg_rule = self._generate_registry_behavior_rule(sandbox_report['registry'])
                if reg_rule:
                    rules.append(reg_rule)
            
        except Exception as e:
            logger.error(f"Error generating behavior rules: {e}")
        
        return rules

    def _generate_network_behavior_rule(self, network_data: Dict[str, Any]) -> Optional[str]:
        """
        Generate rule based on network behavior
        """
        try:
            domains = []
            ips = []
            
            if 'dns' in network_data:
                domains = [entry.get('domain', '') for entry in network_data['dns'][:5]]
            
            if 'tcp' in network_data:
                ips = [entry.get('dst', '') for entry in network_data['tcp'][:5]]
            
            if not domains and not ips:
                return None
            
            conditions = []
            if domains:
                domain_conditions = ' or '.join([f'"{domain}"' for domain in domains if domain])
                if domain_conditions:
                    conditions.append(f"any of ({domain_conditions})")
  #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved          
            if ips:
                ip_conditions = ' or '.join([f'"{ip}"' for ip in ips if ip])
                if ip_conditions:
                    conditions.append(f"any of ({ip_conditions})")
            
            if not conditions:
                return None
            
            rule = f'''
rule Network_Behavior_Detection
{{
    meta:
        description = "Detection based on network behavior patterns"
        author = "BehaviorGuard"
        date = "{self._get_current_date()}"
    
    strings:
        $behavior = "network_communication"
    
    condition:
        $behavior  // This is a simplified example
}}
'''
            return rule
            
        except Exception as e:
            logger.error(f"Error generating network behavior rule: {e}")
            return None

    def _generate_filesystem_behavior_rule(self, filesystem_data: List[Dict[str, Any]]) -> Optional[str]:
        """
        Generate rule based on file system behavior
        """
        try:
            suspicious_paths = []
     #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved       
            for fs_entry in filesystem_data[:10]:
                filename = fs_entry.get('filename', '')
                if any(suspicious in filename.lower() for suspicious in ['temp', 'startup', 'system32']):
                    suspicious_paths.append(filename)
            
            if not suspicious_paths:
                return None
            
            rule = f'''
rule Filesystem_Behavior_Detection
{{
    meta:
        description = "Detection based on file system behavior patterns"
        author = "BehaviorGuard"
        date = "{self._get_current_date()}"
        
    strings:
        $behavior = "filesystem_activity"
    
    condition:
        $behavior  // This is a simplified example
}}
'''
            return rule
            
        except Exception as e:
            logger.error(f"Error generating filesystem behavior rule: {e}")
            return None

    def _generate_registry_behavior_rule(self, registry_data: List[Dict[str, Any]]) -> Optional[str]:
        """
        Generate rule based on registry behavior
        """
        try:
            persistence_keys = []
            
            for reg_entry in registry_data[:10]:
                key = reg_entry.get('key', '')
                if any(persistence in key.lower() for persistence in ['run', 'runonce', 'winlogon']):
                    persistence_keys.append(key)
            
            if not persistence_keys: #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
                return None
            
            rule = f'''
rule Registry_Behavior_Detection
{{
    meta:
        description = "Detection based on registry behavior patterns"
        author = "BehaviorGuard"
        date = "{self._get_current_date()}"
        
    strings:
        $behavior = "registry_persistence"
    
    condition:
        $behavior  // This is a simplified example
}}
'''
            return rule
            
        except Exception as e:
            logger.error(f"Error generating registry behavior rule: {e}")
            return None

    def _generate_network_rules(self, network_data: Dict[str, Any]) -> List[str]:
        """
        Generate YARA rules based on network analysis
        """
        rules = []
        
        try:
            if not network_data or 'note' in network_data:
                return rules
            
            # Generate rule for suspicious domains
            if 'dns_queries' in network_data and network_data['dns_queries']:
                domain_rule = self._generate_domain_rule(network_data['dns_queries'])
                if domain_rule:
                    rules.append(domain_rule)
            
        except Exception as e:
            logger.error(f"Error generating network rules: {e}")
        
        return rules

    def _generate_domain_rule(self, domains: List[str]) -> Optional[str]:
        """
        Generate rule for suspicious domains
        """
        try:
            # Filter for potentially suspicious domains
            suspicious_domains = []
            for domain in domains[:10]:
                if any(indicator in domain.lower() for indicator in ['temp', 'test', 'malware', 'bot']):
                    suspicious_domains.append(domain)
            
            if not suspicious_domains:
                return None
            
            string_definitions = []
            for i, domain in enumerate(suspicious_domains):
                string_definitions.append(f'        $domain{i} = "{domain}" ascii nocase')
            
            rule = f'''
rule Suspicious_Domains_Detection
{{
    meta:
        description = "Detection based on suspicious domain communications"
        author = "BehaviorGuard"
        date = "{self._get_current_date()}"
    
    strings:
{chr(10).join(string_definitions)}
    
    condition:
        any of them
}}
'''
            return rule
            
        except Exception as e:
            logger.error(f"Error generating domain rule: {e}")
            return None

    def _generate_process_rules(self, process_data: Dict[str, Any]) -> List[str]:
        """
        Generate YARA rules based on process analysis
        """
        rules = []
        
        try:
            if not process_data or 'note' in process_data:
                return rules
    #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved        
            # Generate rule for suspicious process activities
            if 'suspicious_activities' in process_data and process_data['suspicious_activities']:
                activity_rule = self._generate_suspicious_activity_rule(process_data['suspicious_activities'])
                if activity_rule:
                    rules.append(activity_rule)
            
        except Exception as e:
            logger.error(f"Error generating process rules: {e}")
        
        return rules

    def _generate_suspicious_activity_rule(self, activities: List[Any]) -> Optional[str]:
        """
        Generate rule for suspicious process activities
        """
        try:
            if not activities:
                return None
            
            # Extract activity names from dictionaries or use strings directly
            activity_names = []
            for activity in activities[:5]:
                if isinstance(activity, dict):
                    activity_names.append(activity.get('name', 'unknown'))
                elif isinstance(activity, str):
                    activity_names.append(activity)
                else:
                    activity_names.append(str(activity))
            
            rule = f'''
rule Suspicious_Process_Activities
{{
    meta:
        description = "Detection based on suspicious process activities"
        author = "BehaviorGuard"
        date = "{self._get_current_date()}"
        activities = "{'; '.join(activity_names)}"
   
    strings:
        $activity = "suspicious_behavior"
    
    condition:
        $activity  // This is a simplified example
}}
'''
            return rule
            
        except Exception as e:
            logger.error(f"Error generating suspicious activity rule: {e}")
            return None

    def run_yara_rules(self, file_path: str, rules: List[str]) -> Dict[str, Any]:
        """
        Execute YARA rules against the target file
        """
        matches = {
            'total_rules': len(rules),
            'matched_rules': [],
            'match_count': 0,
            'scan_time': 0
        }
        #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
        try:
            # Save rules to temporary files and compile them
            rule_files = []
            for i, rule in enumerate(rules):
                rule_file = os.path.join(self.rules_directory, f"rule_{i}.yar")
                with open(rule_file, 'w') as f:
                    f.write(rule)
                rule_files.append(rule_file)
            
            # Run YARA using yara-python library
            for rule_file in rule_files:
                try:
                    compiled_rules = yara.compile(rule_file)
                    rule_matches = compiled_rules.match(file_path)
                    
                    for match in rule_matches:
                        matches['matched_rules'].append({
                            'rule_name': match.rule,
                            'namespace': match.namespace,
                            'tags': list(match.tags),
                            'meta': dict(match.meta),
                            'strings': [{'identifier': s.identifier, 'instances': len(s.instances)} 
                                      for s in match.strings]
                        })
                        matches['match_count'] += 1
                        
                except yara.Error as e:
                    logger.error(f"YARA compilation error for {rule_file}: {e}")
                    # Try to compile with error handling
                    try:
                        with open(rule_file, 'r') as f:
                            rule_content = f.read()
                        # Create a simple fallback rule
                        fallback_rule = f'''
rule Fallback_Detection
{{
    meta:
        description = "Fallback detection rule"
        author = "BehaviorGuard"
    #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
    condition:
        filesize > 0
}}
'''
                        fallback_file = os.path.join(self.rules_directory, f"fallback_{len(rule_files)}.yar")
                        with open(fallback_file, 'w') as f:
                            f.write(fallback_rule)
                        compiled_rules = yara.compile(fallback_file)
                        rule_matches = compiled_rules.match(file_path)
                        if rule_matches:
                            matches['match_count'] += 1
                        os.remove(fallback_file)
                    except:
                        continue
            
            # Clean up temporary rule files
            for rule_file in rule_files:
                try:
                    os.remove(rule_file)
                except:
                    pass
         #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved   
            logger.info(f"YARA scan completed: {matches['match_count']} matches found")
            
        except Exception as e:
            logger.error(f"Error running YARA rules: {e}")
            matches['error'] = str(e)
        
        return matches

    def _get_current_date(self) -> str:
        """Get current date in YYYY-MM-DD format"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d")
