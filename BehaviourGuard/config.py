import os
from pathlib import Path
#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved.
class Config:
    """Configuration class for the malware analysis system"""
    
    # Basic Flask config
    SECRET_KEY = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///malware_analysis.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File upload settings
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "uploads")
    REPORTS_FOLDER = os.environ.get("REPORTS_FOLDER", "reports")
    PCAP_FOLDER = os.environ.get("PCAP_FOLDER", "pcap_files")
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    
    # Celery configuration
    CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
    CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
    
    # Hybrid Analysis API
    HYBRID_ANALYSIS_API_KEY = os.environ.get("HYBRID_ANALYSIS_API_KEY", "your-api-key-here")
    HYBRID_ANALYSIS_BASE_URL = "https://www.hybrid-analysis.com/api/v2"
    
    # Analysis VM settings (for network capture and procmon)
    ANALYSIS_VM_HOST = os.environ.get("ANALYSIS_VM_HOST", "192.168.1.100")
    ANALYSIS_VM_USER = os.environ.get("ANALYSIS_VM_USER", "analyst")
    ANALYSIS_VM_PASSWORD = os.environ.get("ANALYSIS_VM_PASSWORD", "")
    
    # YARA settings
    YARA_BINARY_PATH = os.environ.get("YARA_BINARY_PATH", "/usr/bin/yara")
    YARA_RULES_DIR = os.environ.get("YARA_RULES_DIR", "yara_rules")
    
    # Network analysis settings
    TCPDUMP_PATH = os.environ.get("TCPDUMP_PATH", "/usr/sbin/tcpdump")
    TSHARK_PATH = os.environ.get("TSHARK_PATH", "/usr/bin/tshark")
    
    # Procmon settings for Windows VM
    PROCMON_PATH = os.environ.get("PROCMON_PATH", "C:\\SysinternalsSuite\\Procmon.exe")
    PROCDOT_PATH = os.environ.get("PROCDOT_PATH", "C:\\ProcDOT\\ProcDOT.exe")
    
    # Report settings
    WKHTMLTOPDF_PATH = os.environ.get("WKHTMLTOPDF_PATH", "/usr/bin/wkhtmltopdf")
    #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved.

    @staticmethod
    def init_app(app):
        """Initialize application with config"""
        # Create necessary directories
        for folder in [Config.UPLOAD_FOLDER, Config.REPORTS_FOLDER, 
                      Config.PCAP_FOLDER, Config.YARA_RULES_DIR]:
            Path(folder).mkdir(parents=True, exist_ok=True)


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False


class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved.


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
