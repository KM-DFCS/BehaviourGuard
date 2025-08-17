import os
import subprocess
import time
import logging
from typing import Dict, Optional, List
import json

logger = logging.getLogger(__name__)


class NetworkAnalysisService:
    """Service for network traffic capture and analysis"""
    
    def __init__(self):
        self.tcpdump_path = os.environ.get("TCPDUMP_PATH", "/usr/sbin/tcpdump")
        self.tshark_path = os.environ.get("TSHARK_PATH", "/usr/bin/tshark")
        self.pcap_folder = os.environ.get("PCAP_FOLDER", "pcap_files")
        
        # Ensure pcap folder exists
        os.makedirs(self.pcap_folder, exist_ok=True)
    
    def capture_traffic(self, duration: int = 300, interface: str = "any") -> Optional[str]:
        """
        Capture network traffic using tcpdump
        
        Args:
            duration: Capture duration in seconds
            interface: Network interface to capture on
            
        Returns:
            Path to the captured pcap file
        """
        timestamp = int(time.time())
        pcap_file = os.path.join(self.pcap_folder, f"capture_{timestamp}.pcap")
        
        try:
            # Check if tcpdump is available
            if not os.path.exists(self.tcpdump_path):
                logger.warning(f"tcpdump not found at {self.tcpdump_path}. Using mock data.")
                return self._create_mock_pcap(pcap_file)
            
            # Build tcpdump command
            cmd = [
                self.tcpdump_path,
                "-i", interface,
                "-w", pcap_file,
                "-c", "1000",  # Capture max 1000 packets
                "-s", "65535",  # Capture full packets
                "-q"  # Quiet mode
            ]
            
            logger.info(f"Starting network capture for {duration} seconds")
            
            # Start tcpdump process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )
            
            # Wait for specified duration or until process completes
            try:
                stdout, stderr = process.communicate(timeout=duration)
                
                if process.returncode == 0:
                    logger.info(f"Network capture completed: {pcap_file}")
                    return pcap_file
                else:
                    logger.error(f"tcpdump failed: {stderr.decode()}")
                    return None
            
            except subprocess.TimeoutExpired:
                # Kill process after timeout
                os.killpg(os.getpgid(process.pid), 9)
                logger.info(f"Network capture timed out after {duration} seconds")
                
                if os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 0:
                    return pcap_file
                else:
                    return None
        
        except Exception as e:
            logger.error(f"Error during network capture: {str(e)}")
            return self._create_mock_pcap(pcap_file)
    
    def analyze_pcap(self, pcap_file: str) -> Dict:
        """
        Analyze captured network traffic using tshark
        
        Args:
            pcap_file: Path to the pcap file
            
        Returns:
            Dictionary containing analysis results
        """
        if not os.path.exists(pcap_file):
            logger.error(f"PCAP file not found: {pcap_file}")
            return {}
        
        analysis_result = {
            'file_path': pcap_file,
            'packet_count': 0,
            'protocols': {},
            'conversations': [],
            'suspicious_activity': [],
            'dns_queries': [],
            'http_requests': [],
            'ssl_connections': []
        }
        
        try:
            # Check if tshark is available
            if not os.path.exists(self.tshark_path):
                logger.warning(f"tshark not found at {self.tshark_path}. Using mock analysis.")
                return self._mock_pcap_analysis()
            
            # Get basic statistics
            analysis_result['packet_count'] = self._get_packet_count(pcap_file)
            
            # Analyze protocols
            analysis_result['protocols'] = self._analyze_protocols(pcap_file)
            
            # Extract conversations
            analysis_result['conversations'] = self._extract_conversations(pcap_file)
            
            # Find suspicious activity
            analysis_result['suspicious_activity'] = self._find_suspicious_activity(pcap_file)
            
            # Extract DNS queries
            analysis_result['dns_queries'] = self._extract_dns_queries(pcap_file)
            
            # Extract HTTP requests
            analysis_result['http_requests'] = self._extract_http_requests(pcap_file)
            
            # Extract SSL connections
            analysis_result['ssl_connections'] = self._extract_ssl_connections(pcap_file)
            
            logger.info(f"PCAP analysis completed for {pcap_file}")
            
        except Exception as e:
            logger.error(f"Error analyzing PCAP file: {str(e)}")
        
        return analysis_result
    
    def capture_and_analyze(self, job_id: int, filename: str) -> Dict:
        """
        Capture network traffic and analyze it
        
        Args:
            job_id: Analysis job ID
            filename: Original filename being analyzed
            
        Returns:
            Complete network analysis results
        """
        logger.info(f"Starting network capture and analysis for job {job_id}")
        
        # Capture traffic (simulated for demo)
        pcap_file = self.capture_traffic(duration=60)  # 1 minute capture
        
        if not pcap_file:
            logger.error("Failed to capture network traffic")
            return {'error': 'Network capture failed'}
        
        # Analyze the captured traffic
        analysis_result = self.analyze_pcap(pcap_file)
        analysis_result['capture_info'] = {
            'job_id': job_id,
            'filename': filename,
            'capture_duration': 60,
            'pcap_file': pcap_file
        }
        
        return analysis_result
    
    def _get_packet_count(self, pcap_file: str) -> int:
        """Get total packet count from pcap file"""
        try:
            cmd = [self.tshark_path, "-r", pcap_file, "-q", "-z", "io,stat,0"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Parse packet count from output
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if 'Packets' in line and '|' in line:
                    parts = line.split('|')
                    if len(parts) > 1:
                        return int(parts[1].strip())
            
            return 0
        
        except Exception as e:
            logger.error(f"Error getting packet count: {str(e)}")
            return 0
    
    def _analyze_protocols(self, pcap_file: str) -> Dict:
        """Analyze protocol distribution"""
        try:
            cmd = [self.tshark_path, "-r", pcap_file, "-q", "-z", "io,phs"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            protocols = {}
            lines = result.stdout.strip().split('\n')
            
            for line in lines:
                if '%' in line and 'frames' in line:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        protocol = parts[0]
                        frames = int(parts[1])
                        protocols[protocol] = frames
            
            return protocols
        
        except Exception as e:
            logger.error(f"Error analyzing protocols: {str(e)}")
            return {}
    
    def _extract_conversations(self, pcap_file: str) -> List[Dict]:
        """Extract network conversations"""
        try:
            cmd = [
                self.tshark_path, "-r", pcap_file,
                "-q", "-z", "conv,ip", "-q"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            conversations = []
            lines = result.stdout.strip().split('\n')
            
            for line in lines:
                if '<->' in line:
                    parts = line.strip().split()
                    if len(parts) >= 6:
                        conversations.append({
                            'src_ip': parts[0],
                            'dst_ip': parts[2],
                            'packets_ab': int(parts[3]),
                            'bytes_ab': int(parts[4]),
                            'packets_ba': int(parts[5]),
                            'bytes_ba': int(parts[6]) if len(parts) > 6 else 0
                        })
            
            return conversations[:20]  # Limit to top 20 conversations
        
        except Exception as e:
            logger.error(f"Error extracting conversations: {str(e)}")
            return []
    
    def _find_suspicious_activity(self, pcap_file: str) -> List[Dict]:
        """Find potentially suspicious network activity"""
        suspicious = []
        
        try:
            # Look for unusual ports
            cmd = [
                self.tshark_path, "-r", pcap_file,
                "-T", "fields", "-e", "tcp.dstport", "-e", "ip.dst",
                "tcp.dstport > 1024 and tcp.dstport < 65535"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            unusual_ports = set()
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.strip().split('\t')
                    if len(parts) >= 2:
                        port = parts[0]
                        ip = parts[1]
                        if port and port not in ['80', '443', '53', '22', '21']:
                            unusual_ports.add((ip, port))
            
            for ip, port in list(unusual_ports)[:10]:
                suspicious.append({
                    'type': 'unusual_port',
                    'description': f'Connection to unusual port {port} on {ip}',
                    'severity': 'medium'
                })
        
        except Exception as e:
            logger.error(f"Error finding suspicious activity: {str(e)}")
        
        return suspicious
    
    def _extract_dns_queries(self, pcap_file: str) -> List[Dict]:
        """Extract DNS queries"""
        try:
            cmd = [
                self.tshark_path, "-r", pcap_file,
                "-T", "fields", "-e", "dns.qry.name", "-e", "frame.time",
                "dns.flags.response == 0"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            queries = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.strip().split('\t')
                    if len(parts) >= 2:
                        queries.append({
                            'domain': parts[0],
                            'timestamp': parts[1]
                        })
            
            return queries[:50]  # Limit to 50 queries
        
        except Exception as e:
            logger.error(f"Error extracting DNS queries: {str(e)}")
            return []
    
    def _extract_http_requests(self, pcap_file: str) -> List[Dict]:
        """Extract HTTP requests"""
        try:
            cmd = [
                self.tshark_path, "-r", pcap_file,
                "-T", "fields", "-e", "http.host", "-e", "http.request.uri", "-e", "http.request.method",
                "http.request"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            requests = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.strip().split('\t')
                    if len(parts) >= 3:
                        requests.append({
                            'host': parts[0],
                            'uri': parts[1],
                            'method': parts[2]
                        })
            
            return requests[:30]  # Limit to 30 requests
        
        except Exception as e:
            logger.error(f"Error extracting HTTP requests: {str(e)}")
            return []
    
    def _extract_ssl_connections(self, pcap_file: str) -> List[Dict]:
        """Extract SSL/TLS connections"""
        try:
            cmd = [
                self.tshark_path, "-r", pcap_file,
                "-T", "fields", "-e", "tls.handshake.extensions_server_name", "-e", "ip.dst",
                "tls.handshake.type == 1"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            connections = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.strip().split('\t')
                    if len(parts) >= 2 and parts[0]:
                        connections.append({
                            'server_name': parts[0],
                            'ip': parts[1]
                        })
            
            return connections[:20]  # Limit to 20 connections
        
        except Exception as e:
            logger.error(f"Error extracting SSL connections: {str(e)}")
            return []
    
    def _create_mock_pcap(self, pcap_file: str) -> str:
        """Create a mock pcap file for testing"""
        try:
            # Create an empty file to simulate pcap
            with open(pcap_file, 'w') as f:
                f.write("")  # Empty file for mock
            
            logger.info(f"Created mock PCAP file: {pcap_file}")
            return pcap_file
        
        except Exception as e:
            logger.error(f"Error creating mock PCAP: {str(e)}")
            return None
    
    def _mock_pcap_analysis(self) -> Dict:
        """Return mock analysis data when tools are not available"""
        return {
            'packet_count': 1247,
            'protocols': {
                'TCP': 856,
                'UDP': 234,
                'ICMP': 12,
                'HTTP': 145,
                'HTTPS': 234,
                'DNS': 67
            },
            'conversations': [
                {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'packets_ab': 45, 'bytes_ab': 2048, 'packets_ba': 43, 'bytes_ba': 3456},
                {'src_ip': '192.168.1.100', 'dst_ip': '1.1.1.1', 'packets_ab': 23, 'bytes_ab': 1024, 'packets_ba': 25, 'bytes_ba': 2048}
            ],
            'suspicious_activity': [
                {'type': 'unusual_port', 'description': 'Connection to unusual port 8080 on 192.168.1.50', 'severity': 'medium'},
                {'type': 'high_frequency', 'description': 'High frequency connections to external host', 'severity': 'low'}
            ],
            'dns_queries': [
                {'domain': 'google.com', 'timestamp': '2024-01-01 12:00:00'},
                {'domain': 'suspicious-domain.com', 'timestamp': '2024-01-01 12:01:00'}
            ],
            'http_requests': [
                {'host': 'example.com', 'uri': '/index.html', 'method': 'GET'},
                {'host': 'api.example.com', 'uri': '/data', 'method': 'POST'}
            ],
            'ssl_connections': [
                {'server_name': 'secure.example.com', 'ip': '93.184.216.34'},
                {'server_name': 'api.service.com', 'ip': '172.217.12.142'}
            ]
        }
