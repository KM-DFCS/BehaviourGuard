/**
 * BehaviorGuard  - Frontend JavaScript
 * Handles UI interactions, real-time updates, and enhanced user experience
 */

// Global application state
const MalwareAnalysisApp = {
    currentJobId: null,
    refreshInterval: null,
    uploadProgress: null,
    statusPolling: new Set(),
    
    // Initialize application
    init() {
        console.log('Initializing BehaviorGuard');
        
        // Initialize components
        this.initializeEventListeners();
        this.initializeFileUpload();
        this.initializeStatusPolling();
        this.initializeTooltips();
        this.initializeCharts();
        
        // Auto-refresh functionality
        this.startGlobalRefresh();
        
        console.log('Application initialized successfully');
    },
    // Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ. All rights reserved.
    // Event listeners setup
    initializeEventListeners() {
        // Global error handler
        window.addEventListener('error', (event) => {
            console.error('JavaScript error:', event.error);
            this.showNotification('An unexpected error occurred', 'error');
        });
        
        // Handle navigation
        document.addEventListener('click', (event) => {
            if (event.target.matches('[data-action]')) {
                event.preventDefault();
                this.handleAction(event.target);
            }
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (event) => {
            if (event.ctrlKey || event.metaKey) {
                switch(event.key) {
                    case 'u':
                        event.preventDefault();
                        window.location.href = '/upload';
                        break;
                    case 'h':
                        event.preventDefault();
                        window.location.href = '/';
                        break;
                }
            }
        });
        
        // Handle form submissions
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', (event) => {
                this.handleFormSubmit(event);
            });
        });
    },
    
    // File upload enhancement
    initializeFileUpload() {
        const uploadArea = document.getElementById('file-upload-area');
        const fileInput = document.getElementById('file');
        
        if (!uploadArea || !fileInput) return;
        
        // Drag and drop functionality
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            uploadArea.addEventListener(eventName, this.preventDefaults, false);
            document.body.addEventListener(eventName, this.preventDefaults, false);
        });
        
        ['dragenter', 'dragover'].forEach(eventName => {
            uploadArea.addEventListener(eventName, () => {
                uploadArea.classList.add('dragover');
            }, false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            uploadArea.addEventListener(eventName, () => {
                uploadArea.classList.remove('dragover');
            }, false);
        });
        
        uploadArea.addEventListener('drop', (event) => {
            const files = event.dataTransfer.files;
            if (files.length > 0) {
                this.handleFileSelection(files[0]);
            }
        }, false);
        
        // File input change
        fileInput.addEventListener('change', (event) => {
            if (event.target.files.length > 0) {
                this.handleFileSelection(event.target.files[0]);
            }
        });
        
        // Click to upload
        uploadArea.addEventListener('click', () => {
            fileInput.click();
        });
    },
    
    // Handle file selection
    handleFileSelection(file) {
        // Validate file size (100MB)
        if (file.size > 100 * 1024 * 1024) {
            this.showNotification('File too large. Maximum size is 100MB.', 'error');
            return;
        }
        
        // Update file info display
        this.updateFileInfo(file);
        
        // Enable upload button
        const uploadBtn = document.getElementById('upload-btn');
        if (uploadBtn) {
            uploadBtn.disabled = false;
            uploadBtn.classList.remove('btn-secondary');
            uploadBtn.classList.add('btn-primary');
        }
    },
    
    // Update file information display
    updateFileInfo(file) {
        const fileInfo = document.getElementById('file-info');
        if (!fileInfo) return;
        
        document.getElementById('info-filename').textContent = file.name;
        document.getElementById('info-size').textContent = this.formatBytes(file.size);
        document.getElementById('info-type').textContent = file.type || 'Unknown';
        
        fileInfo.classList.remove('d-none');
    },
    
    // Status polling for active jobs
    initializeStatusPolling() {
        // Poll status for jobs in progress
        const jobStatusElements = document.querySelectorAll('[data-job-id][data-status]');
        
        jobStatusElements.forEach(element => {
            const jobId = element.getAttribute('data-job-id');
            const status = element.getAttribute('data-status');
            
            if (this.isActiveStatus(status)) {
                this.startStatusPolling(jobId);
            }
        });
    },
    // Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ. All rights reserved.
    // Start polling for specific job
    startStatusPolling(jobId) {
        if (this.statusPolling.has(jobId)) return;
        
        this.statusPolling.add(jobId);
        
        const pollInterval = setInterval(() => {
            this.checkJobStatus(jobId).then(status => {
                if (!this.isActiveStatus(status)) {
                    clearInterval(pollInterval);
                    this.statusPolling.delete(jobId);
                    
                    // Reload page if we're viewing this specific job
                    if (window.location.pathname.includes(`/job/${jobId}`)) {
                        setTimeout(() => window.location.reload(), 2000);
                    }
                }
            });
        }, 10000); // Poll every 10 seconds
    },
    
    // Check if status is active (in progress)
    isActiveStatus(status) {
        return ['pending', 'uploading', 'sandbox_submitted', 'analyzing', 'generating_report'].includes(status);
    },
    
    // Check job status via API
    async checkJobStatus(jobId) {
        try {
            const response = await fetch(`/analysis/api/job/${jobId}/status`);
            const data = await response.json();
            
            if (response.ok) {
                this.updateJobStatusDisplay(jobId, data);
                return data.status;
            }
        } catch (error) {
            console.error('Error checking job status:', error);
        }
        return null;
    },
    
    // Update job status in UI
    updateJobStatusDisplay(jobId, data) {
        const statusElements = document.querySelectorAll(`[data-job-id="${jobId}"]`);
        
        statusElements.forEach(element => {
            const statusBadge = element.querySelector('.badge, .status-badge');
            if (statusBadge) {
                statusBadge.textContent = this.formatStatus(data.status);
                statusBadge.className = `badge fs-6 bg-${this.getStatusColor(data.status)}`;
            }
            
            // Update data attribute
            element.setAttribute('data-status', data.status);
        });
        
        // Add download button if report is available
        if (data.report_available) {
            this.addDownloadButton(jobId);
        }
    },
    
    // Add download button to job row
    addDownloadButton(jobId) {
        const jobRow = document.querySelector(`[data-job-id="${jobId}"]`);
        if (!jobRow) return;
        
        const actionsDiv = jobRow.querySelector('.btn-group');
        if (!actionsDiv || actionsDiv.querySelector('.btn-outline-success')) return;
        
        const downloadBtn = document.createElement('a');
        downloadBtn.href = `/analysis/job/${jobId}/report`;
        downloadBtn.className = 'btn btn-outline-success btn-sm';
        downloadBtn.title = 'Download Report';
        downloadBtn.innerHTML = '<i data-feather="download" width="14" height="14"></i>';
        
        actionsDiv.insertBefore(downloadBtn, actionsDiv.lastElementChild);
        feather.replace();
    },
    
    // Format status text
    formatStatus(status) {
        return status.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    },
    
    // Get status color class
    getStatusColor(status) {
        const colorMap = {
            'completed': 'success',
            'failed': 'danger',
            'pending': 'warning',
            'uploading': 'warning',
            'sandbox_submitted': 'info',
            'analyzing': 'warning',
            'generating_report': 'warning'
        };
        return colorMap[status] || 'secondary';
    },
    
    // Initialize Bootstrap tooltips
    initializeTooltips() {
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(tooltipTriggerEl => {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    },
    
    // Initialize charts if Chart.js is available
    initializeCharts() {
        if (typeof Chart === 'undefined') return;
        
        // Set default chart colors for dark theme
        Chart.defaults.color = '#6c757d';
        Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.1)';
    },
    
    // Start global refresh for dashboard stats
    startGlobalRefresh() {
        // Refresh dashboard stats every 30 seconds
        setInterval(() => {
            this.refreshDashboardStats();
        }, 30000);
        
        // Refresh job list every 15 seconds if on jobs page
        if (window.location.pathname.includes('/jobs')) {
            setInterval(() => {
                this.refreshJobStatuses();
            }, 15000);
        }
    },
    
    // Refresh dashboard statistics
    async refreshDashboardStats() {
        if (!document.getElementById('total-jobs')) return;
        
        try {
            const response = await fetch('/analysis/api/stats');
            const data = await response.json();
            
            if (response.ok) {
                document.getElementById('total-jobs').textContent = data.total_jobs;
                document.getElementById('completed-jobs').textContent = data.completed_jobs;
                document.getElementById('pending-jobs').textContent = data.pending_jobs;
                document.getElementById('failed-jobs').textContent = data.failed_jobs;
            }
        } catch (error) {
            console.error('Error refreshing dashboard stats:', error);
        }
    },
    
    // Refresh job statuses in job list
    refreshJobStatuses() {
        const pendingBadges = document.querySelectorAll('.badge.bg-warning, .badge.bg-info');
        
        pendingBadges.forEach(badge => {
            const jobRow = badge.closest('[data-job-id]');
            if (!jobRow) return;
            
            const jobId = jobRow.getAttribute('data-job-id');
            this.checkJobStatus(jobId);
        });
    },
    
    // Handle action buttons
    handleAction(element) {
        const action = element.getAttribute('data-action');
        const jobId = element.getAttribute('data-job-id');
        
        switch (action) {
            case 'delete-job':
                this.confirmDeleteJob(jobId, element.getAttribute('data-filename'));
                break;
            case 'refresh-status':
                this.checkJobStatus(jobId);
                break;
            case 'copy-hash':
                this.copyToClipboard(element.getAttribute('data-hash'));
                break;
            default:
                console.warn('Unknown action:', action);
        }
    },
    // Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ. All rights reserved.
    // Confirm job deletion
    confirmDeleteJob(jobId, filename) {
        if (confirm(`Are you sure you want to delete the analysis job for "${filename}"? This action cannot be undone.`)) {
            this.deleteJob(jobId);
        }
    },
    
    // Delete job
    async deleteJob(jobId) {
        try {
            const response = await fetch(`/analysis/job/${jobId}/delete`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });
            
            if (response.ok) {
                this.showNotification('Job deleted successfully', 'success');
                
                // Redirect if on job detail page
                if (window.location.pathname.includes(`/job/${jobId}`)) {
                    window.location.href = '/analysis/jobs';
                } else {
                    // Remove job row from list
                    const jobRow = document.querySelector(`[data-job-id="${jobId}"]`);
                    if (jobRow) {
                        jobRow.remove();
                    }
                }
            } else {
                this.showNotification('Failed to delete job', 'error');
            }
        } catch (error) {
            console.error('Error deleting job:', error);
            this.showNotification('An error occurred while deleting the job', 'error');
        }
    },
    
    // Copy text to clipboard
    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            this.showNotification('Copied to clipboard', 'success');
        } catch (error) {
            console.error('Failed to copy to clipboard:', error);
            this.showNotification('Failed to copy to clipboard', 'error');
        }
    },
    
    // Handle form submissions
    handleFormSubmit(event) {
        const form = event.target;
        const submitBtn = form.querySelector('button[type="submit"]');
        
        if (submitBtn) {
            // Disable button and show loading state
            const originalText = submitBtn.innerHTML;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Processing...';
            
            // Re-enable after 5 seconds as fallback
            setTimeout(() => {
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalText;
            }, 5000);
        }
    },
    // Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ. All rights reserved.
    // Show notification
    showNotification(message, type = 'info') {
        const alertClass = type === 'error' ? 'alert-danger' : `alert-${type}`;
        const icon = type === 'error' ? 'alert-circle' : type === 'success' ? 'check-circle' : 'info';
        
        const alertHTML = `
            <div class="alert ${alertClass} alert-dismissible fade show" role="alert">
                <i data-feather="${icon}" class="me-2"></i>
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;
        
        // Find or create alerts container
        let alertsContainer = document.getElementById('alerts-container');
        if (!alertsContainer) {
            alertsContainer = document.createElement('div');
            alertsContainer.id = 'alerts-container';
            alertsContainer.className = 'container mt-3';
            document.querySelector('main').insertBefore(alertsContainer, document.querySelector('main').firstChild);
        }
        
        alertsContainer.insertAdjacentHTML('afterbegin', alertHTML);
        
        // Replace feather icons
        feather.replace();
        
        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            const alert = alertsContainer.querySelector('.alert');
            if (alert) {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }
        }, 5000);
    },
    
    // Utility: Prevent default behavior
    preventDefaults(event) {
        event.preventDefault();
        event.stopPropagation();
    },
    
    // Utility: Format bytes
    formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    },
    // Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ. All rights reserved.
    // Utility: Format time duration
    formatDuration(seconds) {
        if (seconds < 60) return `${Math.round(seconds)}s`;
        if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
        return `${(seconds / 3600).toFixed(1)}h`;
    },
    
    // Utility: Get relative time
    getRelativeTime(timestamp) {
        const now = new Date();
        const time = new Date(timestamp);
        const diff = (now - time) / 1000; // seconds
        
        if (diff < 60) return 'just now';
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return `${Math.floor(diff / 86400)}d ago`;
    }
};
// Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ. All rights reserved.
// File upload specific functionality
const FileUpload = {
    // Enhanced file validation
    validateFile(file) {
        const allowedExtensions = [
            'exe',
            'zip', 'rar', '7z', 'tar', 'gz', 'jar', 'msi', 'deb', 'rpm',
            'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
            'js', 'vbs', 'ps1', 'sh', 'py', 'pl', 'rb'
        ];
        
        const extension = file.name.split('.').pop().toLowerCase();
        
        if (!allowedExtensions.includes(extension)) {
            throw new Error(`File type .${extension} is not supported for analysis.`);
        }
        
        if (file.size > 100 * 1024 * 1024) {
            throw new Error('File size exceeds 100MB limit.');
        }
        
        if (file.size === 0) {
            throw new Error('Cannot upload empty file.');
        }
        
        return true;
    },
    
    // Upload with progress tracking
    async uploadWithProgress(file, onProgress) {
        return new Promise((resolve, reject) => {
            const formData = new FormData();
            formData.append('file', file);
            
            const xhr = new XMLHttpRequest();
            
            xhr.upload.addEventListener('progress', (event) => {
                if (event.lengthComputable) {
                    const percentComplete = (event.loaded / event.total) * 100;
                    onProgress(percentComplete);
                }
            });
            
            xhr.addEventListener('load', () => {
                if (xhr.status === 200 || xhr.status === 302) {
                    resolve(xhr.responseURL || window.location.href);
                } else {
                    reject(new Error(`Upload failed with status ${xhr.status}`));
                }
            });
            
            xhr.addEventListener('error', () => {
                reject(new Error('Network error during upload'));
            });
            
            xhr.open('POST', '/upload');
            xhr.send(formData);
        });
    }
};

// Job management functionality
const JobManager = {
    // Batch operations
    deleteSelectedJobs() {
        const selectedJobs = document.querySelectorAll('input[name="job-select"]:checked');
        
        if (selectedJobs.length === 0) {
            MalwareAnalysisApp.showNotification('Please select jobs to delete', 'warning');
            return;
        }
        // Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ. All rights reserved.
        if (confirm(`Delete ${selectedJobs.length} selected job(s)? This action cannot be undone.`)) {
            selectedJobs.forEach(checkbox => {
                const jobId = checkbox.value;
                MalwareAnalysisApp.deleteJob(jobId); // Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ. All rights reserved.
            });
        }
    },
    
    // Export job data
    exportJobData(jobId, format = 'json') {
        const url = `/analysis/api/job/${jobId}/export?format=${format}`;
        window.open(url, '_blank');
    },
    
    // Refresh all job statuses
    refreshAllStatuses() {
        const jobRows = document.querySelectorAll('[data-job-id]');
        const promises = Array.from(jobRows).map(row => {
            const jobId = row.getAttribute('data-job-id');
            return MalwareAnalysisApp.checkJobStatus(jobId);
        });
        
        Promise.all(promises).then(() => {
            MalwareAnalysisApp.showNotification('All job statuses updated', 'success');
        }).catch(() => {
            MalwareAnalysisApp.showNotification('Some job statuses could not be updated', 'warning');
        });
    }
};

// Dark mode management
const ThemeManager = {
    init() {
        // Dark mode is default, but allow toggle if needed
        const themeToggle = document.getElementById('theme-toggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', this.toggleTheme.bind(this));
        }
    },
    
    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-bs-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        document.documentElement.setAttribute('data-bs-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        
        // Update charts if they exist
        if (typeof Chart !== 'undefined') {
            Chart.defaults.color = newTheme === 'dark' ? '#6c757d' : '#212529';
            Chart.defaults.borderColor = newTheme === 'dark' ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
        }
    }
};

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    MalwareAnalysisApp.init();
    ThemeManager.init();
});

// Export for global access
window.MalwareAnalysisApp = MalwareAnalysisApp;
window.FileUpload = FileUpload;
window.JobManager = JobManager;
window.ThemeManager = ThemeManager;

// Service worker registration for PWA features (optional)
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/static/sw.js').then(registration => {
            console.log('SW registered: ', registration);
        }).catch(registrationError => {
            console.log('SW registration failed: ', registrationError);
        });
    });
}