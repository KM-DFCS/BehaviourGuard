import os
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class Config:
    """
    Configuration management for the malware analysis system
    """
    #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
    def __init__(self):
        self._config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """
        Load configuration from environment variables with defaults
        """
        config = {
            # Flask settings
            'SECRET_KEY': os.environ.get('SESSION_SECRET', 'dev-secret-change-in-production'),
            'DATABASE_URL': os.environ.get('DATABASE_URL', 'sqlite:///malware_analysis.db'),
            'UPLOAD_FOLDER': os.environ.get('UPLOAD_FOLDER', 'uploads'),
            'REPORTS_DIR': os.environ.get('REPORTS_DIR', 'reports'),
            #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
            # Redis/Celery settings
            'REDIS_URL': os.environ.get('REDIS_URL', 'redis://localhost:6379/0'),
            'CELERY_BROKER_URL': os.environ.get('REDIS_URL', 'redis://localhost:6379/0'),
            'CELERY_RESULT_BACKEND': os.environ.get('REDIS_URL', 'redis://localhost:6379/0'),
            
            # Analysis settings
            'MAX_FILE_SIZE': int(os.environ.get('MAX_FILE_SIZE', 100 * 1024 * 1024)),  # 100MB
            'ANALYSIS_TIMEOUT': int(os.environ.get('ANALYSIS_TIMEOUT', 600)),  # 10 minutes
            
            # Hybrid Analysis API
            'HYBRID_ANALYSIS_API_KEY': os.environ.get('HYBRID_ANALYSIS_API_KEY'),
            
            # Analysis VM settings
            'ANALYSIS_VM_IP': os.environ.get('ANALYSIS_VM_IP'),
            'ANALYSIS_VM_USER': os.environ.get('ANALYSIS_VM_USER', 'analyst'),
            'ANALYSIS_VM_SSH_KEY': os.environ.get('ANALYSIS_VM_SSH_KEY'),
            'CAPTURE_INTERFACE': os.environ.get('CAPTURE_INTERFACE', 'eth0'),
            'CAPTURE_DURATION': int(os.environ.get('CAPTURE_DURATION', 300)),  # 5 minutes
            
            # Windows VM settings
            'WINDOWS_VM_IP': os.environ.get('WINDOWS_VM_IP'),
            'WINDOWS_VM_USER': os.environ.get('WINDOWS_VM_USER', 'Administrator'),
            'WINDOWS_VM_PASSWORD': os.environ.get('WINDOWS_VM_PASSWORD'),
            'PROCMON_PATH': os.environ.get('PROCMON_PATH', 'C:\\Tools\\Procmon.exe'),
            'MONITOR_DURATION': int(os.environ.get('MONITOR_DURATION', 300)),  # 5 minutes
            
            # YARA settings
            'YARA_BINARY_PATH': os.environ.get('YARA_BINARY_PATH', 'yara'),
            'YARA_RULES_DIR': os.environ.get('YARA_RULES_DIR', 'yara_rules'),
            
            # Security settings
            'ALLOWED_FILE_EXTENSIONS': [
                'exe',
                'zip', 'rar', '7z', 'tar', 'gz', 'jar', 'msi', 'deb', 'rpm',
                'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
                'js', 'vbs', 'ps1', 'sh', 'py', 'pl', 'rb'
            ],
            #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
            # Logging settings
            'LOG_LEVEL': os.environ.get('LOG_LEVEL', 'INFO'),
        }
        
        return config

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value
        """
        return self._config.get(key, default)

    def get_required(self, key: str) -> Any:
        """
        Get required configuration value, raise exception if not found
        """
        value = self._config.get(key)
        if value is None:
            raise ValueError(f"Required configuration '{key}' not found")
        return value

    def validate_config(self) -> Dict[str, list]:
        """
        Validate configuration and return warnings/errors
        """
        warnings = []
        errors = []
        
        # Check required API keys
        if not self.get('HYBRID_ANALYSIS_API_KEY'):
            warnings.append("HYBRID_ANALYSIS_API_KEY not set - sandbox analysis will not work")
        #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
        # Check VM configurations
        if not self.get('ANALYSIS_VM_IP'):
            warnings.append("ANALYSIS_VM_IP not set - network capture will use mock data")
        
        if not self.get('WINDOWS_VM_IP'):
            warnings.append("WINDOWS_VM_IP not set - process monitoring will use mock data")
        
        # Check directories
        upload_folder = self.get('UPLOAD_FOLDER')
        if upload_folder and not os.path.exists(upload_folder):
            try:
                os.makedirs(upload_folder, exist_ok=True)
            except Exception as e:
                errors.append(f"Cannot create upload folder {upload_folder}: {e}")
        
        reports_dir = self.get('REPORTS_DIR')
        if reports_dir and not os.path.exists(reports_dir):
            try:
                os.makedirs(reports_dir, exist_ok=True)
            except Exception as e:
                errors.append(f"Cannot create reports directory {reports_dir}: {e}")
        
        # Check file size limits
        max_file_size = self.get('MAX_FILE_SIZE')
        if max_file_size and max_file_size > 1024 * 1024 * 1024:  # 1GB
            warnings.append(f"MAX_FILE_SIZE is very large: {max_file_size} bytes")
        
        return {'warnings': warnings, 'errors': errors}

    def print_config_status(self):
        """
        Print configuration status to logs
        """
        validation = self.validate_config()
       #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved 
        logger.info("=== Configuration Status ===")
        
        # Print configuration (excluding secrets)
        safe_config = {k: v for k, v in self._config.items() 
                      if 'password' not in k.lower() and 'key' not in k.lower() and 'secret' not in k.lower()}
        
        for key, value in safe_config.items():
            logger.info(f"{key}: {value}")
        
        # Print warnings
        if validation['warnings']:
            logger.warning("Configuration warnings:")
            for warning in validation['warnings']:
                logger.warning(f"  - {warning}")
        
        # Print errors
        if validation['errors']:
            logger.error("Configuration errors:")
            for error in validation['errors']:
                logger.error(f"  - {error}")
        
        logger.info("=== End Configuration Status ===")

# Global config instance
config = Config()
#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved