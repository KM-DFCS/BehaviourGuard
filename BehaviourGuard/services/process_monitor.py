import os
import psutil
import time#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
import json
import logging
import threading
from datetime import datetime
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class ProcessMonitorService:
    """
    Service for monitoring system processes and activities
    """
    
    def __init__(self):
        self.monitoring = False
        self.process_data = []
        self.network_connections = []
        self.file_activities = []
        self.registry_activities = []
        self.suspicious_processes = []
        
        # Suspicious process patterns
        self.suspicious_patterns = [
            'cmd.exe', 'powershell.exe', 'rundll32.exe', 'regsvr32.exe',
            'wscript.exe', 'cscript.exe', 'mshta.exe', 'certutil.exe',
            'bitsadmin.exe', 'wmic.exe', 'schtasks.exe', 'at.exe'
        ]
        
        # Suspicious activities
        self.suspicious_activities = [
            'CreateProcess', 'VirtualAlloc', 'WriteProcessMemory',
            'LoadLibrary', 'GetProcAddress', 'CreateRemoteThread',
            'SetWindowsHookEx', 'RegCreateKey', 'RegSetValue'
        ]
    
    def start_monitoring(self, duration: int = 60) -> Dict[str, Any]:
        """
        Start process monitoring for specified duration
        """#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
        try:
            logger.info(f"Starting process monitoring for {duration} seconds")
            self.monitoring = True
            self.process_data = []
            self.network_connections = []
            self.file_activities = []
            self.registry_activities = []
            self.suspicious_processes = []
            
            # Start monitoring threads
            process_thread = threading.Thread(target=self._monitor_processes, args=(duration,))
            network_thread = threading.Thread(target=self._monitor_network, args=(duration,))
            file_thread = threading.Thread(target=self._monitor_file_activities, args=(duration,))
            
            process_thread.start()
            network_thread.start()
            file_thread.start()
            
            # Wait for monitoring to complete
            process_thread.join()
            network_thread.join()
            file_thread.join()
            
            return self._generate_monitoring_report()
            
        except Exception as e:
            logger.error(f"Error in process monitoring: {e}")
            return {'error': str(e)}
    
    def generate_simulated_process_data(self) -> Dict[str, Any]:
        """Generate simulated process data for demonstration"""
        import random
        
        simulated_processes = []
        suspicious_processes = []
        
        # Common Windows processes
        common_processes = [
            'explorer.exe', 'svchost.exe', 'winlogon.exe', 'services.exe',
            'lsass.exe', 'wininit.exe', 'csrss.exe', 'smss.exe',
            'cmd.exe', 'powershell.exe', 'rundll32.exe', 'regsvr32.exe',
            'wscript.exe', 'cscript.exe', 'mshta.exe', 'certutil.exe'
        ]
        #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
        # Generate simulated process data
        for i in range(random.randint(15, 30)):
            process_name = random.choice(common_processes)
            is_suspicious = process_name in ['cmd.exe', 'powershell.exe', 'rundll32.exe', 'regsvr32.exe']
            
            process_data = {
                'pid': random.randint(1000, 8000),
                'name': process_name,
                'cmdline': f'"{process_name}" {"--arg" if random.choice([True, False]) else ""}',
                'cpu_percent': random.uniform(0.1, 5.0),
                'memory_percent': random.uniform(0.1, 10.0),
                'create_time': time.time() - random.randint(0, 3600),
                'timestamp': datetime.now().isoformat()
            }
            
            simulated_processes.append(process_data)
            
            if is_suspicious:
                suspicious_processes.append({
                    'pid': process_data['pid'],
                    'name': process_data['name'],
                    'cmdline': process_data['cmdline'],
                    'timestamp': process_data['timestamp'],
                    'suspicious_reason': 'Known suspicious process'
                })
        
        return {
            'process_data': simulated_processes,
            'suspicious_processes': suspicious_processes,
            'total_processes': len(simulated_processes),
            'suspicious_count': len(suspicious_processes)
        }
    
    def _monitor_processes(self, duration: int):
        """Monitor system processes"""
        start_time = time.time()
        #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
        while time.time() - start_time < duration and self.monitoring:
            try:
                # Get all running processes
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent', 'create_time']):
                    try:
                        proc_info = proc.info
                        
                        # Check for suspicious processes
                        if any(pattern in proc_info['name'].lower() for pattern in self.suspicious_patterns):
                            self.suspicious_processes.append({
                                'pid': proc_info['pid'],
                                'name': proc_info['name'],
                                'cmdline': proc_info['cmdline'],
                                'timestamp': datetime.now().isoformat(),
                                'suspicious_reason': 'Known suspicious process'
                            })
                        
                        # Record process data
                        self.process_data.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cmdline': proc_info['cmdline'],
                            'cpu_percent': proc_info['cpu_percent'],
                            'memory_percent': proc_info['memory_percent'],
                            'create_time': proc_info['create_time'],
                            'timestamp': datetime.now().isoformat()
                        })
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                time.sleep(2)  # Monitor every 2 seconds
                
            except Exception as e:
                logger.error(f"Error monitoring processes: {e}")
                time.sleep(2)
    
    def _monitor_network(self, duration: int):
        """Monitor network connections"""
        start_time = time.time()
        
        while time.time() - start_time < duration and self.monitoring:
            try:
                # Get network connections
                connections = psutil.net_connections()
                
                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        self.network_connections.append({
                            'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                            'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                            'status': conn.status,
                            'pid': conn.pid,
                            'timestamp': datetime.now().isoformat()
                        })
                #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
                time.sleep(5)  # Monitor every 5 seconds
                
            except Exception as e:
                logger.error(f"Error monitoring network: {e}")
                time.sleep(5)
    
    def _monitor_file_activities(self, duration: int):
        """Monitor file system activities (simulated)"""
        start_time = time.time()
        
        while time.time() - start_time < duration and self.monitoring:
            try:
                # Simulate file activity monitoring
                # In a real implementation, you'd use Windows API or tools like Process Monitor
                
                # Check for recent file modifications in temp directories
                temp_dirs = ['C:\\Windows\\Temp', 'C:\\Users\\Public\\Temp']
                
                for temp_dir in temp_dirs:
                    if os.path.exists(temp_dir):
                        try:
                            for file in os.listdir(temp_dir):
                                file_path = os.path.join(temp_dir, file)
                                if os.path.isfile(file_path):
                                    stat = os.stat(file_path)
                                    if time.time() - stat.st_mtime < 60:  # Modified in last minute
                                        self.file_activities.append({
                                            'file_path': file_path,
                                            'action': 'modified',
                                            'timestamp': datetime.now().isoformat(),
                                            'size': stat.st_size
                                        })
                        except PermissionError:
                            continue
                
                time.sleep(10)  # Monitor every 10 seconds
                
            except Exception as e:
                logger.error(f"Error monitoring file activities: {e}")
                time.sleep(10)
    
    def _generate_monitoring_report(self) -> Dict[str, Any]:
        """Generate comprehensive monitoring report"""
        try:
            # Analyze process data
            total_processes = len(self.process_data)
            unique_processes = len(set(p['name'] for p in self.process_data))
            
            # Analyze network data
            unique_connections = len(set(f"{c['local_address']}-{c['remote_address']}" for c in self.network_connections))
            
            # Analyze suspicious activities
            suspicious_count = len(self.suspicious_processes)
            
            # Calculate risk score
            risk_score = 0
            risk_indicators = []
         #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved   
            if suspicious_count > 0:
                risk_score += suspicious_count * 10
                risk_indicators.append(f"Suspicious processes detected: {suspicious_count}")
            
            if unique_connections > 10:
                risk_score += 20
                risk_indicators.append(f"High network activity: {unique_connections} connections")
            
            if len(self.file_activities) > 5:
                risk_score += 15
                risk_indicators.append(f"High file activity: {len(self.file_activities)} operations")
            
            # Determine threat level
            if risk_score >= 50:
                threat_level = 'High'
                verdict = 'Suspicious Activity Detected'
            elif risk_score >= 30:
                threat_level = 'Medium'
                verdict = 'Moderate Activity'
            else:
                threat_level = 'Low'
                verdict = 'Normal Activity'
            
            return {
                'monitoring_summary': {
                    'total_processes_monitored': total_processes,
                    'unique_processes': unique_processes,
                    'network_connections': unique_connections,
                    'file_activities': len(self.file_activities),
                    'suspicious_processes': suspicious_count,
                    'monitoring_duration': '60 seconds'
                },
                'suspicious_activities': self.suspicious_processes,
                'network_connections': self.network_connections[:20],  # Limit to 20
                'file_activities': self.file_activities[:20],  # Limit to 20
                'process_sample': self.process_data[:50],  # Sample of processes
                'risk_assessment': {
                    'risk_score': risk_score,
                    'threat_level': threat_level,
                    'verdict': verdict,
                    'risk_indicators': risk_indicators
                },
                'monitoring_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating monitoring report: {e}")
            return {'error': str(e)}
    
    def stop_monitoring(self):
        """Stop process monitoring"""
        self.monitoring = False
        logger.info("Process monitoring stopped")
#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved