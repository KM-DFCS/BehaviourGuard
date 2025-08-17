import os
import hashlib
import struct
import logging
import re
import json
import math
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class StaticAnalysisService:
    """
    Service for performing static analysis on malware files
    """
    #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
    def __init__(self):
        self.suspicious_strings = [
            b'cmd.exe', b'powershell', b'rundll32', b'regsvr32',
            b'CreateProcess', b'VirtualAlloc', b'WriteProcessMemory',
            b'LoadLibrary', b'GetProcAddress', b'CreateFile',
            b'RegOpenKey', b'RegSetValue', b'InternetOpen',
            b'WinExec', b'ShellExecute', b'CreateService',
            b'StartService', b'CryptAcquireContext', b'URLDownloadToFile',
            b'WinHttpOpen', b'WinHttpConnect', b'WinHttpSendRequest',
            b'HttpOpenRequest', b'InternetConnect', b'HttpSendRequest',
            b'CreateRemoteThread', b'SetWindowsHookEx', b'SetTimer',
            b'CreateThread', b'ResumeThread', b'SuspendThread'
        ]
        
        self.suspicious_apis = [
            'CreateProcess', 'VirtualAlloc', 'WriteProcessMemory',
            'LoadLibrary', 'GetProcAddress', 'CreateFile',
            'RegOpenKey', 'RegSetValue', 'InternetOpen',
            'WinExec', 'ShellExecute', 'CreateService',
            'StartService', 'CryptAcquireContext', 'URLDownloadToFile'
        ]
   #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved     
        self.malware_families = {
            'ransomware': [
                b'encrypt', b'decrypt', b'ransom', b'bitcoin', b'wallet', b'crypto', 
                b'locker', b'cryptolocker', b'wannacry', b'petya', b'cerber',
                b'payment', b'extortion', b'victim', b'files', b'documents',
                b'encrypted', b'decryption', b'key', b'payment', b'bitcoin'
            ],
            'trojan': [
                b'backdoor', b'trojan', b'stealer', b'keylogger', b'remote',
                b'access', b'control', b'rat', b'botnet', b'command',
                b'execute', b'shell', b'cmd', b'powershell', b'rundll32',
                b'regsvr32', b'wscript', b'cscript', b'mshta', b'certutil'
            ],
            'worm': [
                b'worm', b'spread', b'network', b'infection', b'propagate',
                b'replicate', b'copy', b'share', b'network', b'lan', b'wan',
                b'email', b'smtp', b'outlook', b'exchange', b'contacts'
            ],
            'spyware': [
                b'spy', b'keylog', b'screen', b'capture', b'monitor',
                b'watch', b'log', b'record', b'webcam', b'microphone',
                b'audio', b'video', b'clipboard', b'keystroke', b'password'
            ],
            'downloader': [
                b'download', b'url', b'http', b'ftp', b'get', b'fetch',
                b'wget', b'curl', b'urlmon', b'wininet', b'http', b'https',
                b'ftp', b'sftp', b'file', b'save', b'write', b'create'
            ],
            'banker': [
                b'bank', b'credit', b'card', b'payment', b'online',
                b'banking', b'financial', b'money', b'account', b'login',
                b'password', b'secure', b'ssl', b'https', b'form'
            ],
            'adware': [
                b'ad', b'advertisement', b'popup', b'banner', b'click',
                b'install', b'offer', b'deal', b'discount', b'free',
                b'bonus', b'reward', b'prize', b'win', b'winner'
            ]
        }

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive static analysis on a file
        """
        try:
            logger.info(f"Starting static analysis for: {file_path}")
            
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Basic file analysis
            file_info = self._analyze_file_basic(file_content, file_path)
            
            # PE file analysis (if applicable)
            pe_analysis = {}
            if file_content.startswith(b'MZ'):
                pe_analysis = self._analyze_pe_file(file_content)
            
            # String analysis
            string_analysis = self._analyze_strings(file_content)
            
            # Entropy analysis
            entropy_analysis = self._analyze_entropy(file_content)
            
            # Malware family detection
            family_analysis = self._detect_malware_family(file_content)
            
            # Threat assessment
            threat_assessment = self._assess_threat_level(
                file_info, pe_analysis, string_analysis, 
                entropy_analysis, family_analysis
            )
      #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved      
            # Compile results
            analysis_result = {
                'file_info': file_info,
                'pe_analysis': pe_analysis,
                'string_analysis': string_analysis,
                'entropy_analysis': entropy_analysis,
                'family_analysis': family_analysis,
                'threat_assessment': threat_assessment,
                'analysis_timestamp': datetime.now().isoformat(),
                'analysis_type': 'static'
            }
            
            logger.info(f"Static analysis completed for: {file_path}")
            return analysis_result
            
        except Exception as e:
            logger.error(f"Error in static analysis: {e}")
            return {
                'error': str(e),
                'analysis_timestamp': datetime.now().isoformat(),
                'analysis_type': 'static'
            }
#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
    def _analyze_file_basic(self, file_content: bytes, file_path: str) -> Dict[str, Any]:
        """Basic file information analysis"""
        file_size = len(file_content)
        
        # Calculate hashes
        md5_hash = hashlib.md5(file_content).hexdigest()
        sha1_hash = hashlib.sha1(file_content).hexdigest()
        sha256_hash = hashlib.sha256(file_content).hexdigest()
        
        # File type detection
        file_type = "Unknown"
        if file_content.startswith(b'MZ'):
            file_type = "PE Executable (.exe/.dll/.sys/.scr/.com)"
        elif file_content.startswith(b'\x7fELF'):
            file_type = "ELF Executable"
        elif file_content.startswith(b'PK'):
            file_type = "ZIP Archive (.zip/.jar/.apk)"
        elif file_content.startswith(b'%PDF'):
            file_type = "PDF Document"
        elif file_content.startswith(b'Rar!'):
            file_type = "RAR Archive"
        elif file_content.startswith(b'7z\xbc\xaf\x27\x1c'):
            file_type = "7-Zip Archive"
        elif file_content.startswith(b'ustar'):
            file_type = "TAR Archive"
        elif file_content.startswith(b'\x1f\x8b'):
            file_type = "GZIP Archive"
  #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved      
        # Additional analysis for ZIP files
        zip_analysis = {}
        if file_content.startswith(b'PK'):
            zip_analysis = self._analyze_zip_content(file_content)
        
        return {
            'file_size': file_size,
            'md5_hash': md5_hash,
            'sha1_hash': sha1_hash,
            'sha256_hash': sha256_hash,
            'file_type': file_type,
            'filename': os.path.basename(file_path),
            'zip_analysis': zip_analysis
        }

    def _analyze_pe_file(self, file_content: bytes) -> Dict[str, Any]:
        """Analyze PE file structure"""
        try:
            # Basic PE header analysis
            if len(file_content) < 64:
                return {'error': 'File too small for PE analysis'}
    #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved        
            # MZ header
            mz_signature = file_content[:2]
            pe_offset = struct.unpack('<I', file_content[60:64])[0]
            
            if pe_offset >= len(file_content) - 4:
                return {'error': 'Invalid PE offset'}
            
            # PE signature
            pe_signature = file_content[pe_offset:pe_offset+4]
            
            if pe_signature != b'PE\x00\x00':
                return {'error': 'Invalid PE signature'}
            
            # File header
            file_header_offset = pe_offset + 4
            if file_header_offset + 20 > len(file_content):
                return {'error': 'File header out of bounds'}
            
            machine = struct.unpack('<H', file_content[file_header_offset+4:file_header_offset+6])[0]
            number_of_sections = struct.unpack('<H', file_content[file_header_offset+6:file_header_offset+8])[0]
            
            # Optional header
            optional_header_offset = file_header_offset + 20
            if optional_header_offset + 24 > len(file_content):
                return {'error': 'Optional header out of bounds'}
            
            magic = struct.unpack('<H', file_content[optional_header_offset:optional_header_offset+2])[0]
            is_64bit = magic == 0x20b
            
            # Extract imports (simplified)
            imports = self._extract_pe_imports(file_content, optional_header_offset, is_64bit)
            
            return {
                'is_valid_pe': True,
                'is_64bit': is_64bit,
                'machine': machine,
                'number_of_sections': number_of_sections,
                'imports': imports,
                'suspicious_imports': [imp for imp in imports if any(api in imp for api in self.suspicious_apis)]
            }
            
        except Exception as e:
            return {'error': f'PE analysis failed: {str(e)}'}
#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
    def _extract_pe_imports(self, file_content: bytes, optional_header_offset: int, is_64bit: bool) -> List[str]:
        """Extract imported functions from PE file"""
        imports = []
        try:
            # This is a simplified import extraction
            # In a real implementation, you'd parse the import directory properly
            
            # Look for common DLL names and API functions
            dll_patterns = [b'kernel32.dll', b'user32.dll', b'advapi32.dll', 
                           b'ws2_32.dll', b'wininet.dll', b'urlmon.dll']
            
            for pattern in dll_patterns:
                if pattern in file_content:
                    imports.append(pattern.decode('ascii', errors='ignore'))
            
            # Look for API function names
            api_patterns = [b'CreateProcess', b'VirtualAlloc', b'WriteProcessMemory',
                           b'LoadLibrary', b'GetProcAddress', b'CreateFile']
            
            for pattern in api_patterns:
                if pattern in file_content:
                    imports.append(pattern.decode('ascii', errors='ignore'))
                    
        except Exception as e:
            logger.warning(f"Error extracting PE imports: {e}")
        
        return imports

    def _analyze_strings(self, file_content: bytes) -> Dict[str, Any]:
        """Analyze strings in the file"""
        try:
            # Extract printable strings
            strings = re.findall(b'[\x20-\x7E]{4,}', file_content)
            string_list = [s.decode('ascii', errors='ignore') for s in strings]
            
            # Find suspicious strings
            suspicious_strings = []
            for string in string_list:
                for pattern in self.suspicious_strings:
                    if pattern.decode('ascii', errors='ignore').lower() in string.lower():
                        suspicious_strings.append(string)
                        break
       #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved     
            # Find URLs
            url_pattern = re.compile(b'https?://[^\s\x00]+')
            urls = [url.decode('ascii', errors='ignore') for url in url_pattern.findall(file_content)]
            
            # Find IP addresses
            ip_pattern = re.compile(b'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            ips = [ip.decode('ascii', errors='ignore') for ip in ip_pattern.findall(file_content)]
            
            # Find file paths
            path_pattern = re.compile(b'[A-Za-z]:\\[^\x00]+')
            paths = [path.decode('ascii', errors='ignore') for path in path_pattern.findall(file_content)]
            
            return {
                'total_strings': len(string_list),
                'suspicious_strings': suspicious_strings[:20],  # Limit to 20
                'urls': urls[:10],  # Limit to 10
                'ip_addresses': ips[:10],  # Limit to 10
                'file_paths': paths[:10],  # Limit to 10
                'string_sample': string_list[:50]  # Sample of strings
            }
            
        except Exception as e:
            logger.error(f"Error in string analysis: {e}")
            return {'error': str(e)}

    def _analyze_entropy(self, file_content: bytes) -> Dict[str, Any]:
        """Analyze file entropy"""
        try:
            # Calculate byte frequency
            byte_freq = [0] * 256
            for byte in file_content:
                byte_freq[byte] += 1
            
            # Calculate entropy
            total_bytes = len(file_content)
            entropy = 0.0
            
            for freq in byte_freq:
                if freq > 0:
                    probability = freq / total_bytes
                    entropy -= probability * math.log2(probability)
            
            # Normalize entropy (0-8 scale)
            normalized_entropy = entropy / 8.0
            
            # Determine if file is likely encrypted/packed
            is_likely_encrypted = normalized_entropy > 0.7
            
            return {
                'entropy': round(entropy, 4),
                'normalized_entropy': round(normalized_entropy, 4),
                'is_likely_encrypted': is_likely_encrypted,
                'entropy_interpretation': 'High entropy suggests encryption or packing' if is_likely_encrypted else 'Normal entropy'
            }
            
        except Exception as e:
            logger.error(f"Error in entropy analysis: {e}")
            return {'error': str(e)}

    def _detect_malware_family(self, file_content: bytes) -> Dict[str, Any]:
        """Detect potential malware family"""
        try:
            detected_families = []
            family_indicators = {}
            
            for family, indicators in self.malware_families.items():
                matches = []
                for indicator in indicators:
                    if indicator in file_content:
                        matches.append(indicator.decode('ascii', errors='ignore'))
                
                if matches:
                    detected_families.append(family)
                    family_indicators[family] = matches
            
            # Additional heuristics
            if b'cmd.exe' in file_content and b'powershell' in file_content:
                detected_families.append('script_based')
            
            if b'CreateProcess' in file_content and b'VirtualAlloc' in file_content:
                detected_families.append('process_injection')
            
            if b'RegOpenKey' in file_content and b'Run' in file_content:
                detected_families.append('persistence')
            
            return {
                'detected_families': list(set(detected_families)),
                'family_indicators': family_indicators,
                'confidence': 'medium' if detected_families else 'low'
            }
            
        except Exception as e:
            logger.error(f"Error in family detection: {e}")
            return {'error': str(e)}

    def _assess_threat_level(self, file_info: Dict, pe_analysis: Dict, 
                           string_analysis: Dict, entropy_analysis: Dict, 
                           family_analysis: Dict) -> Dict[str, Any]:
        """Assess overall threat level"""
        try:
            threat_score = 0
            threat_indicators = []
            
            # PE file indicators
            if pe_analysis.get('is_valid_pe'):
                threat_score += 10
                threat_indicators.append('Valid PE executable')
                
                if pe_analysis.get('suspicious_imports'):
                    suspicious_imports = pe_analysis['suspicious_imports'] or []
                    threat_score += len(suspicious_imports) * 5
                    threat_indicators.append(f"Suspicious imports: {len(suspicious_imports)}")
            
            # String analysis indicators
            if string_analysis.get('suspicious_strings'):
                suspicious_strings = string_analysis['suspicious_strings'] or []
                threat_score += len(suspicious_strings) * 2
                threat_indicators.append(f"Suspicious strings: {len(suspicious_strings)}")
            
            if string_analysis.get('urls'):
                urls = string_analysis['urls'] or []
                threat_score += len(urls) * 3
                threat_indicators.append(f"Network URLs: {len(urls)}")
            
            # Entropy indicators
            if entropy_analysis.get('is_likely_encrypted'):
                threat_score += 15
                threat_indicators.append('High entropy (possible encryption/packing)')
            
            # Family detection with weighted scoring
            if family_analysis.get('detected_families'):
                family_weights = {
                    'ransomware': 25,
                    'trojan': 20,
                    'banker': 18,
                    'spyware': 15,
                    'worm': 12,
                    'downloader': 10,
                    'adware': 8,
                    'script_based': 15,
                    'process_injection': 20,
                    'persistence': 12
                }
     #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved           
                for family in family_analysis['detected_families']:
                    weight = family_weights.get(family, 10)
                    threat_score += weight
                
                threat_indicators.append(f"Detected families: {', '.join(family_analysis['detected_families'])}")
                
                # Set verdict based on most dangerous family
                if 'ransomware' in family_analysis['detected_families']:
                    verdict = 'Malicious (Ransomware)'
                elif 'trojan' in family_analysis['detected_families']:
                    verdict = 'Malicious (Trojan)'
                elif 'banker' in family_analysis['detected_families']:
                    verdict = 'Malicious (Banker)'
                elif 'spyware' in family_analysis['detected_families']:
                    verdict = 'Malicious (Spyware)'
            
            # ZIP file specific threat assessment
            if file_info.get('zip_analysis') and not file_info['zip_analysis'].get('error'):
                zip_analysis = file_info['zip_analysis']
                if zip_analysis.get('suspicious_files'):
                    suspicious_files = zip_analysis['suspicious_files'] or []
                    threat_score += len(suspicious_files) * 10
                    threat_indicators.append(f"Suspicious files in ZIP: {len(suspicious_files)}")
                
                if zip_analysis.get('executable_files'):
                    executable_files = zip_analysis['executable_files'] or []
                    threat_score += len(executable_files) * 15
                    threat_indicators.append(f"Executable files in ZIP: {len(executable_files)}")
                
                if zip_analysis.get('script_files'):
                    script_files = zip_analysis['script_files'] or []
                    threat_score += len(script_files) * 8
                    threat_indicators.append(f"Script files in ZIP: {len(script_files)}")
            
            # Determine threat level
            if threat_score >= 50:
                threat_level = 'High'
                verdict = 'Malicious'
            elif threat_score >= 30:
                threat_level = 'Medium'
                verdict = 'Suspicious'
            elif threat_score >= 15:
                threat_level = 'Low'
                verdict = 'Suspicious'
            else:
                threat_level = 'Very Low'
                verdict = 'Benign'
            
            return {
                'threat_score': threat_score,
                'threat_level': threat_level,
                'verdict': verdict,
                'threat_indicators': threat_indicators,
                'analysis_confidence': 'High' if threat_score > 30 else 'Medium' if threat_score > 15 else 'Low'
            }
            
        except Exception as e:
            logger.error(f"Error in threat assessment: {e}")
            return {
                'threat_score': 0,
                'threat_level': 'Unknown',
                'verdict': 'Unknown',
                'threat_indicators': ['Analysis error'],
                'analysis_confidence': 'Low'
            }

    def _analyze_zip_content(self, file_content: bytes) -> Dict[str, Any]:
        """
        Analyze ZIP file content and extract information about contained files
        """
        try:
            import zipfile
            import io
            
            zip_info = {
                'total_files': 0,
                'total_size': 0,
                'file_list': [],
                'suspicious_files': [],
                'executable_files': [],
                'script_files': [],
                'archive_files': []
            }
            
            # Try to read ZIP file
            try:
                with zipfile.ZipFile(io.BytesIO(file_content), 'r') as zip_file:
                    zip_info['total_files'] = len(zip_file.namelist())
                    
                    for file_info in zip_file.filelist:
                        filename = file_info.filename
                        file_size = file_info.file_size
                        
                        zip_info['total_size'] += file_size
                        zip_info['file_list'].append({
                            'name': filename,
                            'size': file_size,
                            'compressed_size': file_info.compress_size
                        })
                        
                        # Check for suspicious file types
                        lower_filename = filename.lower()
                        
                        if any(ext in lower_filename for ext in ['.exe', '.dll', '.sys', '.scr', '.com']):
                            zip_info['executable_files'].append(filename)
                            zip_info['suspicious_files'].append(filename)
                        elif any(ext in lower_filename for ext in ['.bat', '.cmd', '.ps1', '.vbs', '.js']):
                            zip_info['script_files'].append(filename)
                            zip_info['suspicious_files'].append(filename)
                        elif any(ext in lower_filename for ext in ['.zip', '.rar', '.7z', '.tar']):
                            zip_info['archive_files'].append(filename)
                            zip_info['suspicious_files'].append(filename)
    #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved                    
                        # Check for suspicious filenames
                        suspicious_patterns = [
                            'malware', 'trojan', 'virus', 'backdoor', 'keylogger',
                            'stealer', 'ransomware', 'spyware', 'bot', 'rat'
                        ]
                        
                        if any(pattern in lower_filename for pattern in suspicious_patterns):
                            zip_info['suspicious_files'].append(filename)
                    
                    # Limit file list to prevent memory issues
                    zip_info['file_list'] = zip_info['file_list'][:50]
                    
            except zipfile.BadZipFile:
                zip_info['error'] = 'Invalid ZIP file format'
            except Exception as e:
                zip_info['error'] = f'Error reading ZIP file: {str(e)}'
            
            return zip_info
            
        except Exception as e:
            logger.error(f"Error analyzing ZIP content: {e}")
            return {'error': str(e)}
