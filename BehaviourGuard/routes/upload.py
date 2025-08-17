import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from models import AnalysisJob, AnalysisStatus, db
from utils.file_handler import FileHandler
from utils.config2 import config
from tasks import analyze_malware

logger = logging.getLogger(__name__)

upload_bp = Blueprint('upload', __name__)
#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
@upload_bp.route('/')
def index():
    """
    Main page with upload form and recent jobs
    """
    try:
        # Get job statistics
        total_jobs = AnalysisJob.query.count()
        completed_jobs = AnalysisJob.query.filter(AnalysisJob.status == AnalysisStatus.COMPLETED).count()
        failed_jobs = AnalysisJob.query.filter(AnalysisJob.status == AnalysisStatus.FAILED).count()
        pending_jobs = AnalysisJob.query.filter(AnalysisJob.status.in_([
            AnalysisStatus.PENDING, 
            AnalysisStatus.UPLOADING, 
            AnalysisStatus.SANDBOX_SUBMITTED, 
            AnalysisStatus.ANALYZING, 
            AnalysisStatus.GENERATING_REPORT
        ])).count()
        
        # Get recent analysis jobs
        recent_jobs = AnalysisJob.query.order_by(AnalysisJob.created_at.desc()).limit(10).all()
        
        stats = {
            'total': total_jobs,
            'completed': completed_jobs,
            'failed': failed_jobs,
            'pending': pending_jobs
        }
        
        return render_template('index.html', recent_jobs=recent_jobs, stats=stats)
        
    except Exception as e:
        logger.error(f"Error loading index page: {e}")
        # Don't show error flash message, just return empty data
        return render_template('index.html', recent_jobs=[], stats={'total': 0, 'completed': 0, 'failed': 0, 'pending': 0})

@upload_bp.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """
    Handle file upload and start analysis
    """
    if request.method == 'GET':
        return render_template('upload.html')
    
    try:
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        # Initialize file handler
        file_handler = FileHandler(config.get('UPLOAD_FOLDER'))
        
        # Save uploaded file
        try:
            file_info = file_handler.save_uploaded_file(file)
        except ValueError as e:
            flash(str(e), 'error')
            return redirect(request.url)
        
        # Create analysis job
        job = AnalysisJob()
        job.filename = file_info['original_filename']
        job.file_path = file_info['file_path']
        job.file_hash = file_info['sha256_hash']
        job.file_size = file_info['file_size']
        job.status = AnalysisStatus.PENDING
    #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved    
        db.session.add(job)
        db.session.commit()
        
        # Start analysis task immediately
        try:
            from tasks import analyze_malware_sync
            # Run analysis synchronously
            analyze_malware_sync(job.id)
            flash(f'File uploaded and analyzed successfully. Analysis job #{job.id} completed.', 'success')
            
            logger.info(f"Analysis job {job.id} completed for file: {file_info['original_filename']}")
            
        except Exception as e:
            logger.error(f"Error during analysis: {e}")
            job.status = AnalysisStatus.FAILED
            job.error_message = f"Analysis failed: {str(e)}"
            db.session.commit()
            flash('File uploaded but analysis failed', 'error')
        
        return redirect(url_for('analysis.view_job', job_id=job.id))
        
    except Exception as e:
        logger.error(f"Error handling file upload: {e}")
        flash('Upload failed due to server error', 'error')
        return redirect(request.url)

@upload_bp.route('/api/upload', methods=['POST'])
def api_upload():
    """
    API endpoint for file upload
    """
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Initialize file handler
        file_handler = FileHandler(config.get('UPLOAD_FOLDER'))
        
        # Save uploaded file
        try:
            file_info = file_handler.save_uploaded_file(file)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        
        # Create analysis job
        job = AnalysisJob()
        job.filename = file_info['original_filename']
        job.file_path = file_info['file_path']
        job.file_hash = file_info['sha256_hash']
        job.file_size = file_info['file_size']
        job.status = AnalysisStatus.PENDING
        
        db.session.add(job)
        db.session.commit()
        
        # Start analysis task immediately
        try:
            from tasks import analyze_malware_sync
            # Run analysis synchronously
            analyze_malware_sync(job.id)
            
            return jsonify({
                'success': True,
                'job_id': job.id,
                'message': 'File uploaded and analyzed successfully',
                'file_info': {
                    'filename': file_info['original_filename'],
                    'size': file_info['file_size'],
                    'hash': file_info['sha256_hash']
                }
            })
     #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved       
        except Exception as e:
            logger.error(f"Error during analysis: {e}")
            job.status = AnalysisStatus.FAILED
            job.error_message = f"Analysis failed: {str(e)}"
            db.session.commit()
            
            return jsonify({
                'success': False,
                'job_id': job.id,
                'error': 'Analysis failed'
            }), 500
        
    except Exception as e:
        logger.error(f"Error in API upload: {e}")
        return jsonify({'error': 'Server error during upload'}), 500

@upload_bp.route('/guidelines')
def upload_guidelines():
    """
    Display upload guidelines and safety information
    """
    return render_template('guidelines.html')
#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved