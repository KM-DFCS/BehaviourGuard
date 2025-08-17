#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved.
import os
import logging
import requests
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file, abort
from models import AnalysisJob, AnalysisStatus, db
from utils.config2 import config

logger = logging.getLogger(__name__)

analysis_bp = Blueprint('analysis', __name__, url_prefix='/analysis')

@analysis_bp.route('/job/<int:job_id>')
def view_job(job_id):
    """
    View analysis job details
    """
    try:
        job = AnalysisJob.query.get_or_404(job_id)
        
        # Parse JSON fields for display
        context = {
            'job': job,
            'sandbox_report': None,
            'network_analysis': None,
            'process_analysis': None,
            'yara_matches': None,
            'iocs': None
        }
        
        # Parse JSON data if available with proper defaults
        if job.sandbox_report and job.sandbox_report.strip():
            try:
                import json
                sandbox_data = json.loads(job.sandbox_report)
                # Ensure all required keys exist with defaults
                if isinstance(sandbox_data, dict):
                    context['sandbox_report'] = {
                        'threat_assessment': sandbox_data.get('threat_assessment', {
                            'verdict': 'Unknown',
                            'threat_level': 'Unknown',
                            'threat_score': 0,
                            'analysis_confidence': 'Unknown',
                            'threat_indicators': []
                        }),
                        'file_info': sandbox_data.get('file_info', {
                            'file_type': 'Unknown',
                            'md5_hash': 'N/A',
                            'sha1_hash': 'N/A',
                            'sha256_hash': 'N/A'
                        }),
                        'pe_analysis': sandbox_data.get('pe_analysis', {
                            'is_valid_pe': False,
                            'is_64bit': False,
                            'number_of_sections': 0,
                            'suspicious_imports': []
                        }),
                        'string_analysis': sandbox_data.get('string_analysis', {
                            'total_strings': 0,
                            'suspicious_strings': [],
                            'urls': [],
                            'ip_addresses': []
                        }),
                        'entropy_analysis': sandbox_data.get('entropy_analysis', {
                            'entropy': 0,
                            'normalized_entropy': 0,
                            'is_likely_encrypted': False,
                            'entropy_interpretation': 'No entropy data available'
                        })
                    }
                else:
                    context['sandbox_report'] = {}
            except Exception as e:
                logger.warning(f"Error parsing sandbox_report for job {job_id}: {e}")
                context['sandbox_report'] = {}
        else:
            context['sandbox_report'] = {}
        
        if job.network_analysis and job.network_analysis.strip():
            try:
                import json
                network_data = json.loads(job.network_analysis)
                context['network_analysis'] = {
                    'capture_summary': network_data.get('capture_summary', {
                        'total_packets_captured': 0,
                        'unique_connections': 0,
                        'suspicious_packets': 0,
                        'capture_duration': '0 seconds'
                    }),
                    'protocol_distribution': network_data.get('protocol_distribution', {}),
                    'suspicious_traffic': network_data.get('suspicious_traffic', []),
                    'connection_details': network_data.get('connection_details', [])
                }
            except Exception as e:
                logger.warning(f"Error parsing network_analysis for job {job_id}: {e}")
                context['network_analysis'] = {}
        else:
            context['network_analysis'] = {}
        
        if job.process_analysis and job.process_analysis.strip():
            try:
                import json
                process_data = json.loads(job.process_analysis)
                context['process_analysis'] = {
                    'monitoring_summary': process_data.get('monitoring_summary', {
                        'total_processes_monitored': 0,
                        'unique_processes': 0,
                        'suspicious_processes': 0,
                        'monitoring_duration': '0 seconds'
                    }),
                    'suspicious_activities': process_data.get('suspicious_activities', []),
                    'file_activities': process_data.get('file_activities', [])
                }
            except Exception as e:
                logger.warning(f"Error parsing process_analysis for job {job_id}: {e}")
                context['process_analysis'] = {}
        else:
            context['process_analysis'] = {}
        
        if job.yara_matches and job.yara_matches.strip():
            try:
                import json
                yara_data = json.loads(job.yara_matches)
                context['yara_matches'] = {
                    'total_rules': yara_data.get('total_rules', 0),
                    'matched_rules': yara_data.get('matched_rules', []),
                    'match_count': yara_data.get('match_count', 0),
                    'scan_time': yara_data.get('scan_time', 0)
                }
            except Exception as e:
                logger.warning(f"Error parsing yara_matches for job {job_id}: {e}")
                context['yara_matches'] = {}
        else:
            context['yara_matches'] = {}
        
        if job.iocs and job.iocs.strip():
            try:
                import json
                iocs_data = json.loads(job.iocs)
                context['iocs'] = {
                    'urls': iocs_data.get('urls', []),
                    'ip_addresses': iocs_data.get('ip_addresses', []),
                    'domains': iocs_data.get('domains', []),
                    'file_hashes': iocs_data.get('file_hashes', []),
                    'registry_keys': iocs_data.get('registry_keys', [])
                }
            except Exception as e:
                logger.warning(f"Error parsing iocs for job {job_id}: {e}")
                context['iocs'] = {}
        else:
            context['iocs'] = {}
        
        return render_template('analysis.html', **context)
        
    except Exception as e:
        logger.error(f"Error viewing job {job_id}: {e}")
        flash('Error loading analysis job', 'error')
        return redirect(url_for('upload.index'))

@analysis_bp.route('/api/job/<int:job_id>/status')
def api_job_status(job_id):
    """
    API endpoint for job status
    """
    try:
        job = AnalysisJob.query.get_or_404(job_id)
        
        return jsonify({
            'job_id': job.id,
            'status': job.status.value,
            'filename': job.filename,
            'created_at': job.created_at.isoformat(),
            'updated_at': job.updated_at.isoformat(),
            'hybrid_status': job.hybrid_status,
            'error_message': job.error_message,
            'report_available': bool(job.report_path and os.path.exists(job.report_path))
        })
        
    except Exception as e:
        logger.error(f"Error getting job status {job_id}: {e}")
        return jsonify({'error': 'Job not found'}), 404

@analysis_bp.route('/jobs')
def list_jobs():
    """
    List all analysis jobs
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        jobs = AnalysisJob.query.order_by(
            AnalysisJob.created_at.desc()
        ).paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        return render_template('job_list.html', jobs=jobs)
        
    except Exception as e:
        logger.error(f"Error listing jobs: {e}")
        flash('Error loading jobs list', 'error')
        return redirect(url_for('upload.index'))

@analysis_bp.route('/api/jobs')
def api_list_jobs():
    """
    API endpoint for listing jobs
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        status_filter = request.args.get('status')
        #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
        query = AnalysisJob.query
        
        if status_filter:
            try:
                status_enum = AnalysisStatus(status_filter)
                query = query.filter(AnalysisJob.status == status_enum)
            except ValueError:
                return jsonify({'error': 'Invalid status filter'}), 400
        
        jobs = query.order_by(
            AnalysisJob.created_at.desc()
        ).paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        return jsonify({
            'jobs': [job.to_dict() for job in jobs.items],
            'total': jobs.total,
            'pages': jobs.pages,
            'current_page': jobs.page,
            'per_page': jobs.per_page,
            'has_next': jobs.has_next,
            'has_prev': jobs.has_prev
        })
        
    except Exception as e:
        logger.error(f"Error in API list jobs: {e}")
        return jsonify({'error': 'Server error'}), 500

@analysis_bp.route('/job/<int:job_id>/report')
def download_report(job_id):
    """
    Download analysis report
    """
    try:
        job = AnalysisJob.query.get_or_404(job_id)
        
        if not job.report_path:
            flash('Report not available yet', 'warning')
            return redirect(url_for('analysis.view_job', job_id=job_id))
        
        if not os.path.exists(job.report_path):
            flash('Report file not found', 'error')
            return redirect(url_for('analysis.view_job', job_id=job_id))
        
        return send_file(
            job.report_path,
            as_attachment=True,
            download_name=f"malware_analysis_report_{job.id}_{job.filename}.pdf"
        )
        
    except Exception as e:
        logger.error(f"Error downloading report for job {job_id}: {e}")
        flash('Error downloading report', 'error')
        return redirect(url_for('analysis.view_job', job_id=job_id))

@analysis_bp.route('/job/<int:job_id>/delete', methods=['POST'])
def delete_job(job_id):
    """
    Delete analysis job and associated files
    """
    try:
        job = AnalysisJob.query.get_or_404(job_id)
        
        # Delete associated files
        if job.file_path and os.path.exists(job.file_path):
            try:
                os.remove(job.file_path)
                logger.info(f"Deleted file: {job.file_path}")
            except Exception as e:
                logger.warning(f"Could not delete file {job.file_path}: {e}")
    #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved    
        if job.report_path and os.path.exists(job.report_path):
            try:
                os.remove(job.report_path)
                logger.info(f"Deleted report: {job.report_path}")
            except Exception as e:
                logger.warning(f"Could not delete report {job.report_path}: {e}")
        
        # Delete job from database
        filename = job.filename
        db.session.delete(job)
        db.session.commit()
        
        flash(f'Analysis job for "{filename}" deleted successfully', 'success')
        logger.info(f"Deleted analysis job {job_id}")
        
        return redirect(url_for('analysis.list_jobs'))
        
    except Exception as e:
        logger.error(f"Error deleting job {job_id}: {e}")
        flash('Error deleting analysis job', 'error')
        return redirect(url_for('analysis.view_job', job_id=job_id))

@analysis_bp.route('/stats')
def analysis_stats():
    """
    Display analysis statistics
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
        
        # Get recent activity
        recent_jobs = AnalysisJob.query.order_by(
            AnalysisJob.created_at.desc()
        ).limit(5).all()
        
        stats = {
            'total_jobs': total_jobs,
            'completed_jobs': completed_jobs,
            'failed_jobs': failed_jobs,
            'pending_jobs': pending_jobs,
            'success_rate': (completed_jobs / total_jobs * 100) if total_jobs > 0 else 0,
            'recent_jobs': recent_jobs
        }
        
        return render_template('stats.html', stats=stats)
        
    except Exception as e:
        logger.error(f"Error loading stats: {e}")
        flash('Error loading statistics', 'error')
        return redirect(url_for('upload.index'))

@analysis_bp.route('/api/stats')
def api_stats():
    """
    API endpoint for analysis statistics
    """
    try:
        # Get job statistics - handle missing column gracefully
        try:
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
        except Exception as db_error:
            logger.warning(f"Database error in stats API: {db_error}")
            total_jobs = completed_jobs = failed_jobs = pending_jobs = 0
        
        return jsonify({
            'total_jobs': total_jobs,
            'completed_jobs': completed_jobs,
            'failed_jobs': failed_jobs,
            'pending_jobs': pending_jobs,
            'success_rate': (completed_jobs / total_jobs * 100) if total_jobs > 0 else 0
        })
        
    except Exception as e:
        logger.error(f"Error in API stats: {e}")
        return jsonify({'error': 'Server error'}), 500

@analysis_bp.route('/api/connection-status')
def api_connection_status():
    """Get Hybrid Analysis API connection status"""
    try:
        from services.hybrid_analysis import HybridAnalysisService
        hybrid_service = HybridAnalysisService()
        connected = hybrid_service.test_connection()
   #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved     
        if connected:
            # Get API key info
            response = requests.get(
                f"{hybrid_service.base_url}/key/current",
                headers=hybrid_service.headers,
                timeout=10
            )
            if response.status_code == 200:
                result = response.json()
                return jsonify({
                    'connected': True,
                    'quota': result.get('quota', 'Unknown'),
                    'credits': result.get('credits', 'Unknown')
                })
        
        return jsonify({
            'connected': False,
            'error': 'API connection failed'
        })
    except Exception as e:
        logger.error(f"Error checking connection status: {e}")
        return jsonify({
            'connected': False,
            'error': str(e)
        })

@analysis_bp.route('/api/active-jobs')
def api_active_jobs():
    """Get active analysis jobs"""
    try:
        active_jobs = AnalysisJob.query.filter(AnalysisJob.status.in_([
            AnalysisStatus.PENDING, 
            AnalysisStatus.UPLOADING, 
            AnalysisStatus.SANDBOX_SUBMITTED, 
            AnalysisStatus.ANALYZING, 
            AnalysisStatus.GENERATING_REPORT
        ])).order_by(AnalysisJob.created_at.desc()).limit(10).all()
        
        jobs = []
        for job in active_jobs:
            # Calculate progress based on status
            progress_map = {
                AnalysisStatus.PENDING: 10,
                AnalysisStatus.UPLOADING: 20,
                AnalysisStatus.SANDBOX_SUBMITTED: 40,
                AnalysisStatus.ANALYZING: 70,
                AnalysisStatus.GENERATING_REPORT: 90
            }
            progress = progress_map.get(job.status, 0)
            
            jobs.append({
                'id': job.id,
                'filename': job.filename,
                'status': job.status.value,
                'progress': progress,
                'created_at': job.created_at.isoformat()
            })
        
        return jsonify({'jobs': jobs})
    except Exception as e:
        logger.error(f"Error getting active jobs: {e}")
        return jsonify({'error': str(e)}), 500

@analysis_bp.route('/api/network-capture')
def api_network_capture():
    """Get live network capture data"""
    try:
        from datetime import datetime
        # This would be populated from real network capture
        # For now, return sample data
        packets = [
            {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'source': '192.168.1.100:12345',
                'destination': '8.8.8.8:53',
                'protocol': 'DNS',
                'size': 64,
                'suspicious': False
            }
        ]
        
        return jsonify({'packets': packets})
    except Exception as e:
        logger.error(f"Error getting network capture: {e}")
        return jsonify({'error': str(e)}), 500

@analysis_bp.route('/api/process-monitoring')
def api_process_monitoring():
    """Get live process monitoring data"""
    try:
        # This would be populated from real process monitoring
        # For now, return sample data
        processes = [
            {
                'pid': 1234,
                'name': 'explorer.exe',
                'command': 'C:\\Windows\\explorer.exe',
                'suspicious': False
            }
        ]
        
        return jsonify({'processes': processes})
    except Exception as e:
        logger.error(f"Error getting process monitoring: {e}")
        return jsonify({'error': str(e)}), 500

@analysis_bp.route('/api/threat-alerts')
def api_threat_alerts():
    """Get threat detection alerts"""
    try:
        # This would be populated from real threat detection
        # For now, return empty alerts
        alerts = []
  #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved      
        return jsonify({'alerts': alerts})
    except Exception as e:
        logger.error(f"Error getting threat alerts: {e}")
        return jsonify({'error': str(e)}), 500

@analysis_bp.route('/activity-logs')
def activity_logs():
    """Activity logs dashboard"""
    try:
        return render_template('activity_logs.html')
    except Exception as e:
        logger.error(f"Error in activity logs dashboard: {e}")
        flash('Error loading activity logs dashboard', 'error')
        return redirect(url_for('upload.index'))

@analysis_bp.route('/api/activity-logs')
def api_activity_logs():
    """API endpoint for activity logs"""
    try:
        # Get recent analysis jobs as activity logs
        jobs = AnalysisJob.query.order_by(AnalysisJob.created_at.desc()).limit(50).all()
        
        logs = []
        for job in jobs:
            # Create activity log entries for each job
            logs.append({
                'id': f"job_{job.id}",
                'timestamp': job.created_at.isoformat(),
                'job_id': job.id,
                'activity': 'File Analysis Started',
                'status': job.status.value,
                'details': f"File: {job.filename} | Size: {job.file_size} bytes",
                'duration': None
            })
            
            if job.updated_at and job.updated_at != job.created_at:
                logs.append({
                    'id': f"job_{job.id}_updated",
                    'timestamp': job.updated_at.isoformat(),
                    'job_id': job.id,
                    'activity': 'Analysis Status Updated',
                    'status': job.status.value,
                    'details': f"Status changed to: {job.status.value}",
                    'duration': None
                })
        
        return jsonify({'logs': logs})
        
    except Exception as e:
        logger.error(f"Error in activity logs API: {e}")
        return jsonify({'error': str(e)}), 500

@analysis_bp.route('/api/system-events')
def api_system_events():
    """API endpoint for system events"""
    try:
        # Create system events based on recent activity
        events = []
        
        # Get recent jobs for system events
        recent_jobs = AnalysisJob.query.order_by(AnalysisJob.created_at.desc()).limit(10).all()
        
        for job in recent_jobs:
            if job.status == AnalysisStatus.COMPLETED:
                events.append({
                    'timestamp': job.updated_at.isoformat(),
                    'type': 'Analysis Completed',
                    'message': f"Job #{job.id} completed successfully",
                    'level': 'success'
                })
            elif job.status == AnalysisStatus.FAILED:
                events.append({
                    'timestamp': job.updated_at.isoformat(),
                    'type': 'Analysis Failed',
                    'message': f"Job #{job.id} failed during analysis",
                    'level': 'error'
                })
            elif job.status == AnalysisStatus.ANALYZING:
                events.append({
                    'timestamp': job.created_at.isoformat(),
                    'type': 'Analysis Started',
                    'message': f"Job #{job.id} started analysis",
                    'level': 'info'
                })
        
        return jsonify({'events': events})
        
    except Exception as e:
        logger.error(f"Error in system events API: {e}")
        return jsonify({'error': str(e)}), 500

@analysis_bp.route('/api/recent-jobs')
def api_recent_jobs():
    """API endpoint for recent jobs"""
    try:
        jobs = AnalysisJob.query.order_by(AnalysisJob.created_at.desc()).limit(20).all()
        
        jobs_data = []
        for job in jobs:
            jobs_data.append({
                'id': job.id,
                'filename': job.filename,
                'status': job.status.value,
                'created_at': job.created_at.isoformat(),
                'updated_at': job.updated_at.isoformat() if job.updated_at else job.created_at.isoformat()
            })
        
        return jsonify({'jobs': jobs_data})
        
    except Exception as e:
        logger.error(f"Error in recent jobs API: {e}")
        return jsonify({'error': str(e)}), 500

@analysis_bp.route('/api/activity-stats')
def api_activity_stats():
    """API endpoint for activity statistics"""
    try:
        total_jobs = AnalysisJob.query.count()
        completed_jobs = AnalysisJob.query.filter_by(status=AnalysisStatus.COMPLETED).count()
        active_jobs = AnalysisJob.query.filter(
            AnalysisJob.status.in_([AnalysisStatus.ANALYZING, AnalysisStatus.PENDING])
        ).count()
        failed_jobs = AnalysisJob.query.filter_by(status=AnalysisStatus.FAILED).count()
    #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved    
        return jsonify({
            'total_jobs': total_jobs,
            'completed_jobs': completed_jobs,
            'active_jobs': active_jobs,
            'failed_jobs': failed_jobs
        })
    #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved    
    except Exception as e:
        logger.error(f"Error in activity stats API: {e}")
        return jsonify({'error': str(e)}), 500
