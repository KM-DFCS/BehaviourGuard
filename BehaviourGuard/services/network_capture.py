import socket
import struct
import time
import json
import logging#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
from datetime import datetime
from typing import Dict, List, Any
import threading
import subprocess
import platform

logger = logging.getLogger(__name__)

class NetworkCaptureService:
    """
    Service for capturing and analyzing network traffic
    """
    
    def __init__(self):
        self.capturing = False
        self.packets = []
        self.connections = []
        self.suspicious_traffic = []
        
        # Suspicious patterns
        self.suspicious_ips = [
            '192.168.1.100', '10.0.0.1', '172.16.0.1'  # Example suspicious IPs
        ]
        
        self.suspicious_ports = [22, 23, 3389, 445, 135, 139]  # Common attack ports
        self.suspicious_domains = ['malware.com', 'evil.com', 'backdoor.net']
    
    def start_capture(self, duration: int = 60) -> Dict[str, Any]:
        """
        Start network traffic capture
        """
        try:
            logger.info(f"Starting network capture for {duration} seconds")
            self.capturing = True
            self.packets = []
            self.connections = []
            self.suspicious_traffic = []
            
            # Start capture thread
            capture_thread = threading.Thread(target=self._capture_traffic, args=(duration,))
            capture_thread.start()
            capture_thread.join()
            
            return self._generate_network_report()
            
        except Exception as e:
            logger.error(f"Error in network capture: {e}")
            return {'error': str(e)}
    
    def _capture_traffic(self, duration: int):
        """Capture network traffic (simulated)"""
        start_time = time.time()
        
        while time.time() - start_time < duration and self.capturing:
            try:
                # Simulate network packet capture
                # In a real implementation, you'd use pcap or similar libraries
                
                # Simulate some network activity
                simulated_packets = self._simulate_network_packets()
                
                for packet in simulated_packets:
                    self.packets.append(packet)
                    
                    # Check for suspicious traffic
                    if self._is_suspicious_packet(packet):
                        self.suspicious_traffic.append(packet)
                    
                    # Track connections
                    conn_key = f"{packet['src_ip']}:{packet['src_port']}-{packet['dst_ip']}:{packet['dst_port']}"
                    if conn_key not in [c['connection'] for c in self.connections]:
                        self.connections.append({
                            'connection': conn_key,
                            'src_ip': packet['src_ip'],
                            'src_port': packet['src_port'],
                            'dst_ip': packet['dst_ip'],
                            'dst_port': packet['dst_port'],
                            'protocol': packet['protocol'],
                            'first_seen': packet['timestamp'],
                            'last_seen': packet['timestamp'],
                            'packet_count': 1
                        })
                    else:
                        # Update existing connection
                        for conn in self.connections:
                            if conn['connection'] == conn_key:
                                conn['last_seen'] = packet['timestamp']
                                conn['packet_count'] += 1
                                break
          #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved      
                time.sleep(1)  # Capture every second
                
            except Exception as e:
                logger.error(f"Error capturing traffic: {e}")
                time.sleep(1)
    
    def _simulate_network_packets(self) -> List[Dict]:
        """Simulate network packets for demonstration"""
        import random
        
        packets = [] #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
        
        # Common protocols and ports
        protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'FTP']
        common_ports = [80, 443, 53, 21, 22, 25, 110, 143, 993, 995]
        
        # Generate more realistic malware-like network activity
        for _ in range(random.randint(10, 25)):
            # Simulate different types of network activity
            activity_type = random.choice(['normal', 'suspicious', 'malware'])
            
            if activity_type == 'normal':
                src_ip = f"192.168.1.{random.randint(1, 254)}"
                dst_ip = f"8.8.8.8"  # Google DNS
                dst_port = 53  # DNS
                protocol = 'DNS'
            elif activity_type == 'suspicious':
                src_ip = f"192.168.1.{random.randint(1, 254)}"
                dst_ip = f"10.0.0.{random.randint(1, 254)}"
                dst_port = random.choice([22, 23, 3389, 445])  # Suspicious ports
                protocol = 'TCP'
            else:  # malware
                src_ip = f"192.168.1.{random.randint(1, 254)}"
                dst_ip = f"185.220.101.{random.randint(1, 254)}"  # Suspicious IP range
                dst_port = random.choice([4444, 6667, 8080, 12345])  # Malware ports
                protocol = 'TCP'
            
            packet = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': random.randint(1024, 65535),
                'dst_port': dst_port,
                'protocol': protocol,
                'length': random.randint(64, 1500),
                'flags': random.choice(['SYN', 'ACK', 'FIN', 'RST', 'PSH']),
                'payload': f"Sample payload {random.randint(1000, 9999)}"
            }
            
            packets.append(packet)
        
        return packets
    
    def _is_suspicious_packet(self, packet: Dict) -> bool:
        """Check if packet is suspicious"""
        # Check suspicious IPs
        if packet['src_ip'] in self.suspicious_ips or packet['dst_ip'] in self.suspicious_ips:
            return True
        
        # Check suspicious ports
        if packet['src_port'] in self.suspicious_ports or packet['dst_port'] in self.suspicious_ports:
            return True
     #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved   
        # Check for unusual protocols
        if packet['protocol'] in ['FTP', 'TELNET']:
            return True
        
        return False
    
    def _generate_network_report(self) -> Dict[str, Any]:
        """Generate network analysis report"""
        try:
            # Analyze captured data
            total_packets = len(self.packets)
            unique_connections = len(self.connections)
            suspicious_count = len(self.suspicious_traffic)
            
            # Protocol distribution
            protocol_stats = {}
            for packet in self.packets:
                protocol = packet['protocol']
                protocol_stats[protocol] = protocol_stats.get(protocol, 0) + 1
            
            # Top source and destination IPs
            src_ips = {}
            dst_ips = {}
            for packet in self.packets:
                src_ips[packet['src_ip']] = src_ips.get(packet['src_ip'], 0) + 1
                dst_ips[packet['dst_ip']] = dst_ips.get(packet['dst_ip'], 0) + 1
            
            top_src_ips = sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:5]
            top_dst_ips = sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:5]
            
            # Calculate risk score #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
            risk_score = 0
            risk_indicators = []
            
            if suspicious_count > 0:
                risk_score += suspicious_count * 10
                risk_indicators.append(f"Suspicious packets detected: {suspicious_count}")
            
            if unique_connections > 20:
                risk_score += 20
                risk_indicators.append(f"High connection count: {unique_connections}")
            
            # Check for unusual protocols
            if 'FTP' in protocol_stats or 'TELNET' in protocol_stats:
                risk_score += 15
                risk_indicators.append("Unusual protocols detected")
            
            # Determine threat level
            if risk_score >= 50:
                threat_level = 'High'
                verdict = 'Suspicious Network Activity'
            elif risk_score >= 30:
                threat_level = 'Medium'
                verdict = 'Moderate Network Activity'
            else:
                threat_level = 'Low'
                verdict = 'Normal Network Activity'
            
            return {
                'capture_summary': {
                    'total_packets_captured': total_packets,
                    'unique_connections': unique_connections,
                    'suspicious_packets': suspicious_count,
                    'capture_duration': '60 seconds'
                },
                'protocol_distribution': protocol_stats,
                'top_source_ips': top_src_ips, #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
                'top_destination_ips': top_dst_ips,
                'suspicious_traffic': self.suspicious_traffic[:20],  # Limit to 20
                'connection_details': self.connections[:20],  # Limit to 20
                'packet_sample': self.packets[:50],  # Sample of packets
                'risk_assessment': {
                    'risk_score': risk_score,
                    'threat_level': threat_level,
                    'verdict': verdict,
                    'risk_indicators': risk_indicators
                },
                'capture_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating network report: {e}")
            return {'error': str(e)}
    
    def stop_capture(self):
        """Stop network capture"""
        self.capturing = False
        logger.info("Network capture stopped")
#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved