from datetime import datetime
from enum import Enum
from flask_sqlalchemy import SQLAlchemy

# Create a separate db instance to avoid circular imports
db = SQLAlchemy()

class AnalysisStatus(Enum):
    PENDING = "pending"
    UPLOADING = "uploading"
    SANDBOX_SUBMITTED = "sandbox_submitted"
    ANALYZING = "analyzing"
    GENERATING_REPORT = "generating_report"
    COMPLETED = "completed"
    FAILED = "failed"

class AnalysisJob(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    status = db.Column(db.Enum(AnalysisStatus), default=AnalysisStatus.PENDING)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Hybrid Analysis
    hybrid_job_id = db.Column(db.String(100))
    hybrid_status = db.Column(db.String(50))
    
    # Results storage
    sandbox_report = db.Column(db.Text)  # JSON string
    network_analysis = db.Column(db.Text)  # JSON string
    process_analysis = db.Column(db.Text)  # JSON string
    yara_matches = db.Column(db.Text)  # JSON string
    iocs = db.Column(db.Text)  # JSON string
    
    # Report generation
    report_path = db.Column(db.String(500))
    error_message = db.Column(db.Text)
    
    # Celery task tracking (optional)
    # celery_task_id = db.Column(db.String(100))

    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'file_hash': self.file_hash,
            'file_size': self.file_size,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'hybrid_job_id': self.hybrid_job_id,
            'hybrid_status': self.hybrid_status,
            'report_path': self.report_path,
            'error_message': self.error_message
        }
#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved