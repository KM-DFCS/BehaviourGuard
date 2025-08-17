import os
import requests
import json
import logging
import time
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class HybridAnalysisService:
    """
    Service for interacting with Hybrid Analysis API
    """
#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved    
    def __init__(self):
        # Use the provided API key
        self.api_key = "0o3grp143ffd48861nys4u5320cb88ebj9cy6jqb0bb4c2598uopx75d9ef755ed"
        self.base_url = "https://hybrid-analysis.com/api/v2"
        self.headers = {
            'User-Agent': 'BehaviorGuard/2.1',
            'api-key': self.api_key
        }
        
        # Test connection on initialization
        self.test_connection()
    
    def test_connection(self) -> bool:
        """
        Test connection to Hybrid Analysis API
        """
        try:
            logger.info("Testing Hybrid Analysis API connection...")
            response = requests.get(
                f"{self.base_url}/key/current",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"✅ Hybrid Analysis API Connected Successfully!")
                logger.info(f"   - API Key Status: Active")
                logger.info(f"   - Quota: {result.get('quota', 'Unknown')}")
                logger.info(f"   - Credits: {result.get('credits', 'Unknown')}")
                return True
            else:
                logger.error(f"❌ Hybrid Analysis API Connection Failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Hybrid Analysis API Connection Error: {e}")
            return False
    
    def submit_file(self, file_path: str, filename: str) -> Dict[str, Any]:
        """
        Submit a file for analysis to Hybrid Analysis
        """
        try:
            logger.info(f"🔍 Submitting file to Hybrid Analysis: {filename}")
            logger.info(f"   - File Path: {file_path}")
            logger.info(f"   - File Size: {os.path.getsize(file_path)} bytes")
            
            # Check if file is a ZIP archive and handle accordingly
            with open(file_path, 'rb') as f:
                file_header = f.read(4)
                f.seek(0)
                
            if file_header.startswith(b'PK'):
                logger.info(f"📦 Detected ZIP archive: {filename}")
                # For ZIP files, we'll use a longer timeout and different settings
                custom_run_time = 300  # 5 minutes for ZIP analysis
                logger.info(f"   - Using extended analysis time for ZIP: {custom_run_time} seconds")
            else:
                custom_run_time = 180  # 3 minutes for regular files
            
            # Prepare the submission data
            with open(file_path, 'rb') as f:
                # Clean filename to avoid UTF-8 issues
                clean_filename = filename.encode('ascii', 'ignore').decode('ascii')
                files = {'file': (clean_filename, f, 'application/octet-stream')}
                
                data = {
                    'environment_id': 100,  # Windows 10 64-bit
                    'no_share_third_party': True,
                    'allow_community_access': True,  # Fixed: Must be True
                    'no_hash_lookup': False,
                    'action_script': '',
                    'hybrid_analysis': True,
                    'experimental_anti_evasion': True,
                    'script_logging': True,
                    'input_sample_tampering': True,
                    'network_settings': 'default',
                    'custom_cmd_line': '',
                    'custom_run_time': custom_run_time,  # Dynamic timeout based on file type
                    'submit_name': clean_filename,
                    'priority': 1  # High priority for immediate analysis
                }
                
                # Submit the file
                response = requests.post(
                    f"{self.base_url}/submit/file",
                    headers=self.headers,
                    files=files,
                    data=data,
                    timeout=120
                )
                #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
                if response.status_code == 201:
                    result = response.json()
                    logger.info(f"File submitted successfully. Job ID: {result.get('job_id')}")
                    return {
                        'success': True,
                        'job_id': result.get('job_id'),
                        'sha256': result.get('sha256'),
                        'submission_url': result.get('submission_url')
                    }
                else:
                    logger.error(f"Failed to submit file. Status: {response.status_code}, Response: {response.text}")
                    return {
                        'success': False,
                        'error': f"Submission failed: {response.status_code}",
                        'details': response.text
                    }
                    
        except Exception as e:
            logger.error(f"Error submitting file to Hybrid Analysis: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_analysis_status(self, job_id: str) -> Dict[str, Any]:
        """
        Get the status of an analysis job
        """
        try:
            response = requests.get(
                f"{self.base_url}/report/{job_id}/state",
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'success': True,
                    'state': result.get('state'),
                    'progress': result.get('progress', 0),
                    'completed': result.get('state') == 'SUCCESS'
                }
            else:
                logger.error(f"Failed to get analysis status. Status: {response.status_code}")
                return {
                    'success': False,
                    'error': f"Status check failed: {response.status_code}"
                }
                
        except Exception as e:
            logger.error(f"Error getting analysis status: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_analysis_report(self, job_id: str) -> Dict[str, Any]:
        """
        Get the complete analysis report
        """
        try:
            logger.info(f"Fetching analysis report for job: {job_id}")
            
            # Get summary report
            summary_response = requests.get(
                f"{self.base_url}/report/{job_id}/summary",
                headers=self.headers,
                timeout=30
            )#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
            
            if summary_response.status_code != 200:
                logger.error(f"Failed to get summary report. Status: {summary_response.status_code}")
                return {
                    'success': False,
                    'error': f"Summary report failed: {summary_response.status_code}"
                }
            
            summary = summary_response.json()
            
            # Get detailed reports
            reports = {}
            
            # Network report
            try:
                network_response = requests.get(
                    f"{self.base_url}/report/{job_id}/network",
                    headers=self.headers,
                    timeout=30
                )
                if network_response.status_code == 200:
                    reports['network'] = network_response.json()
            except Exception as e:
                logger.warning(f"Failed to get network report: {e}")
            
            # Process report
            try:
                process_response = requests.get(
                    f"{self.base_url}/report/{job_id}/processes",
                    headers=self.headers,
                    timeout=30
                )
                if process_response.status_code == 200:
                    reports['processes'] = process_response.json()
            except Exception as e:
                logger.warning(f"Failed to get process report: {e}")
            
            # File system report
            try:
                filesystem_response = requests.get(
                    f"{self.base_url}/report/{job_id}/filesystem",
                    headers=self.headers,
                    timeout=30
                )
                if filesystem_response.status_code == 200:
                    reports['filesystem'] = filesystem_response.json()
            except Exception as e:
                logger.warning(f"Failed to get filesystem report: {e}")
            
            # Enhanced threat analysis
            threat_analysis = self._analyze_threat_patterns(summary, reports)
            
            # Compile the complete report
            complete_report = {
                'success': True,
                'job_id': job_id,
                'summary': summary,
                'reports': reports,
                'threat_analysis': threat_analysis,
                'analysis_timestamp': datetime.now().isoformat(),
                'source': 'Hybrid Analysis'
            }
            
            logger.info(f"Analysis report fetched successfully for job: {job_id}")
            return complete_report
            
        except Exception as e:
            logger.error(f"Error getting analysis report: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _analyze_threat_patterns(self, summary: Dict[str, Any], reports: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze threat patterns and match with known malware families
        """
        threat_analysis = {
            'threat_level': 'Unknown',
            'verdict': 'Unknown',
            'detected_families': [],
            'threat_score': 0,
            'malware_families': [],
            'suspicious_indicators': [],
            'mitre_attcks': [],
            'malware_type': 'Unknown',
            'behavior_analysis': [],
            'network_indicators': [],
            'process_indicators': [],
            'file_indicators': [],
            'registry_indicators': [],
            'remediation_advice': []
        }
        
        try:
            # Analyze summary data
            if summary.get('verdict') == 'malicious':
                threat_analysis['threat_level'] = 'High'
                threat_analysis['verdict'] = 'Malicious'
                threat_analysis['threat_score'] = 90
            elif summary.get('verdict') == 'suspicious':
                threat_analysis['threat_level'] = 'Medium'
                threat_analysis['verdict'] = 'Suspicious'
                threat_analysis['threat_score'] = 70
            elif summary.get('verdict') == 'no_threats':
                threat_analysis['threat_level'] = 'Low'
                threat_analysis['verdict'] = 'Clean'
                threat_analysis['threat_score'] = 10
         #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved   
            # Extract malware families and determine malware type
            if summary.get('classification_tags'):
                threat_analysis['malware_families'] = summary['classification_tags']
                threat_analysis['detected_families'] = summary['classification_tags']
                
                # Determine malware type based on families
                families_lower = [f.lower() for f in summary['classification_tags']]
                
                if any('ransomware' in f for f in families_lower):
                    threat_analysis['malware_type'] = 'Ransomware'
                    threat_analysis['remediation_advice'].extend([
                        'Immediately disconnect from network',
                        'Do not pay ransom',
                        'Restore from backup',
                        'Update security software'
                    ])
                elif any('trojan' in f for f in families_lower):
                    threat_analysis['malware_type'] = 'Trojan'
                    threat_analysis['remediation_advice'].extend([
                        'Remove suspicious files',
                        'Update antivirus',
                        'Scan entire system',
                        'Change passwords'
                    ])
                elif any('backdoor' in f for f in families_lower):
                    threat_analysis['malware_type'] = 'Backdoor'
                    threat_analysis['remediation_advice'].extend([
                        'Block suspicious connections',
                        'Remove backdoor files',
                        'Update firewall rules',
                        'Monitor network traffic'
                    ])
                elif any('spyware' in f for f in families_lower):
                    threat_analysis['malware_type'] = 'Spyware'
                    threat_analysis['remediation_advice'].extend([
                        'Remove spyware components',
                        'Change all passwords',
                        'Enable 2FA',
                        'Monitor for data theft'
                    ])
                elif any('worm' in f for f in families_lower):
                    threat_analysis['malware_type'] = 'Worm'
                    threat_analysis['remediation_advice'].extend([
                        'Isolate infected systems',
                        'Update all software',
                        'Patch vulnerabilities',
                        'Monitor network spread'
                    ])
            
            # Analyze network behavior
            if reports.get('network'):
                network_data = reports['network']
                
                # Check for suspicious network activity
                suspicious_ips = []
                suspicious_domains = []
                network_indicators = []
                
                if network_data.get('dns'):
                    for dns in network_data['dns']:
                        domain = dns.get('hostname', '')
                        if self._is_suspicious_domain(domain):
                            suspicious_domains.append(domain)
                            network_indicators.append(f"Suspicious DNS: {domain}")
      #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved          
                if network_data.get('tcp'):
                    for tcp in network_data['tcp']:
                        dst_ip = tcp.get('dst', '')
                        dst_port = tcp.get('dst_port', 0)
                        if self._is_suspicious_connection(dst_ip, dst_port):
                            suspicious_ips.append(dst_ip)
                            network_indicators.append(f"Suspicious TCP: {dst_ip}:{dst_port}")
                
                if network_data.get('http'):
                    for http in network_data['http']:
                        url = http.get('url', '')
                        if self._is_suspicious_domain(url):
                            network_indicators.append(f"Suspicious HTTP: {url}")
                
                threat_analysis['network_indicators'] = network_indicators
                
                if suspicious_domains or suspicious_ips:
                    threat_analysis['suspicious_indicators'].extend([
                        f"Suspicious domains: {len(suspicious_domains)}",
                        f"Suspicious IPs: {len(suspicious_ips)}"
                    ])
            
            # Analyze process behavior
            if reports.get('processes'):
                processes_data = reports['processes']
                
                suspicious_processes = []
                process_indicators = []
                behavior_analysis = []
                
                for process in processes_data:
                    process_name = process.get('name', '').lower()
                    command_line = process.get('command_line', '')
                    
                    if self._is_suspicious_process(process_name):
                        suspicious_processes.append(process_name)
                        process_indicators.append(f"Suspicious Process: {process_name}")
                        behavior_analysis.append(f"Process {process_name} executed with command: {command_line}")
                    
                    # Check for specific behaviors
                    if 'powershell' in process_name and ('bypass' in command_line or 'executionpolicy' in command_line):
                        behavior_analysis.append("PowerShell execution policy bypass detected")
                        process_indicators.append("PowerShell Bypass Attempt")
                    
                    if 'cmd' in process_name and ('/c' in command_line or '&' in command_line):
                        behavior_analysis.append("Command injection attempt detected")
                        process_indicators.append("Command Injection")
                
                threat_analysis['process_indicators'] = process_indicators
                threat_analysis['behavior_analysis'] = behavior_analysis
                
                if suspicious_processes:
                    threat_analysis['suspicious_indicators'].append(
                        f"Suspicious processes: {len(suspicious_processes)}"
                    )
            
            # Extract MITRE ATT&CK techniques
            if summary.get('mitre_attcks'):
                threat_analysis['mitre_attcks'] = summary['mitre_attcks']
            
            # Adjust threat score based on indicators
            if threat_analysis['suspicious_indicators']:
                threat_analysis['threat_score'] = min(100, threat_analysis['threat_score'] + 20)
            
            # Determine final threat level
            if threat_analysis['threat_score'] >= 80:
                threat_analysis['threat_level'] = 'Critical'
            elif threat_analysis['threat_score'] >= 60:
                threat_analysis['threat_level'] = 'High'
            elif threat_analysis['threat_score'] >= 40:
                threat_analysis['threat_level'] = 'Medium'
            elif threat_analysis['threat_score'] >= 20:
                threat_analysis['threat_level'] = 'Low'
            else:
                threat_analysis['threat_level'] = 'Minimal'
            
        except Exception as e:
            logger.error(f"Error analyzing threat patterns: {e}")
        
        return threat_analysis
    #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain is suspicious"""
        suspicious_patterns = [
            'malware', 'botnet', 'c2', 'command', 'control', 'backdoor',
            'trojan', 'virus', 'spyware', 'ransomware', 'crypto',
            'mining', 'stealer', 'keylogger', 'rat', 'ddos'
        ]
        
        domain_lower = domain.lower()
        return any(pattern in domain_lower for pattern in suspicious_patterns)
    
    def _is_suspicious_connection(self, ip: str, port: int) -> bool:
        """Check if connection is suspicious"""
        suspicious_ports = [22, 23, 3389, 445, 135, 139, 1433, 3306, 5432]
        return port in suspicious_ports
    
    def _is_suspicious_process(self, process_name: str) -> bool:
        """Check if process is suspicious"""
        suspicious_processes = [
            'cmd.exe', 'powershell.exe', 'rundll32.exe', 'regsvr32.exe',
            'wscript.exe', 'cscript.exe', 'mshta.exe', 'certutil.exe',
            'bitsadmin.exe', 'wmic.exe', 'schtasks.exe', 'at.exe'
        ]
        
        return process_name in suspicious_processes
    
    def wait_for_completion(self, job_id: str, timeout: int = 300) -> Dict[str, Any]:
        """
        Wait for analysis to complete
        """
        logger.info(f"Waiting for analysis completion. Job ID: {job_id}")
        
        # For ZIP files, we might need longer timeout
        if timeout < 600:  # If timeout is less than 10 minutes, extend it
            timeout = 600  # 10 minutes for ZIP files
            logger.info(f"Extended timeout to {timeout} seconds for comprehensive analysis")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            status = self.get_analysis_status(job_id)
            
            if not status.get('success'):
                return status
            
            if status.get('completed'):
                logger.info(f"Analysis completed for job: {job_id}")
                return self.get_analysis_report(job_id)
            
            # Wait before checking again
            time.sleep(10)
        
        logger.warning(f"Analysis timeout for job: {job_id}")
        return {
            'success': False,
            'error': 'Analysis timeout',
            'job_id': job_id
        }
    
    def analyze_file_complete(self, file_path: str, filename: str) -> Dict[str, Any]:
        """
        Complete analysis workflow: submit, wait, and get report
        """
        try:
            # Step 1: Submit file
            submission = self.submit_file(file_path, filename)
            if not submission.get('success'):
                return submission
      #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved      
            job_id = submission['job_id']
            
            # Step 2: Wait for completion
            result = self.wait_for_completion(job_id)
            
            return result
            
        except Exception as e:
            logger.error(f"Error in complete analysis workflow: {e}")
            return {
                'success': False,
                'error': str(e)
            }
