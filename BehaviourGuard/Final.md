# BEHAVIOURGUARD
# Behavioral Malware Analysis System
## License  
Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ. All rights reserved
## Overview

This is a comprehensive behavioral-based malware classification system designed for safe analysis of potentially malicious files. The system provides a web interface for file uploads and orchestrates automated analysis through multiple security tools including Hybrid Analysis API sandbox execution, network traffic capture, process monitoring, YARA rule generation, and comprehensive PDF report generation. All analysis is performed in isolated environments to ensure security.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Web Framework
The application uses Flask as the primary web framework with a modular blueprint structure separating upload and analysis functionality. The application factory pattern is implemented in `app.py` with proper database initialization and blueprint registration.

### Database Layer
SQLAlchemy ORM is used with a declarative base model for database operations. The system supports both SQLite (default for development) and PostgreSQL (via DATABASE_URL environment variable). The main entity is `AnalysisJob` which tracks file analysis through various states including pending, analyzing, completed, and failed.

### Asynchronous Task Processing
Celery with Redis backend handles long-running analysis tasks to prevent blocking the web interface. Tasks include coordinating multiple analysis services, polling external APIs, and generating comprehensive reports.

### Service-Oriented Architecture
The system is built around specialized services:
- **HybridAnalysisService**: Integrates with Hybrid Analysis API for sandbox execution
- **NetworkCaptureService**: Handles automated network traffic capture using tcpdump/tshark
- **ProcessMonitorService**: Manages Windows VM process monitoring via Procmon
- **YaraGeneratorService**: Auto-generates YARA rules from analysis results
- **ReportGeneratorService**: Creates comprehensive PDF reports using ReportLab

### Security Design
File uploads are validated for type and size with secure filename handling. All analysis is designed to run in isolated VMs with configurable remote execution capabilities. The system includes proper error handling and logging throughout.

### Frontend Architecture
Bootstrap-based responsive web interface with dark theme support. JavaScript handles real-time status updates, file upload progress, and interactive dashboard elements. The template system uses Jinja2 with a base template pattern for consistent UI.

## External Dependencies

### Third-Party APIs
- **Hybrid Analysis API**: Primary sandbox execution service requiring API key authentication
- **Redis**: Message broker and result backend for Celery task queue

### Analysis Tools
- **tcpdump/tshark**: Network traffic capture tools (configurable paths)
- **Procmon**: Windows process monitoring (requires Windows analysis VM)
- **ProcDOT**: Process visualization tool integration
- **YARA**: Rule engine for malware detection patterns

### System Dependencies
- **wkhtmltopdf**: PDF generation from HTML reports
- **Python libraries**: Flask, SQLAlchemy, Celery, ReportLab, matplotlib, python-magic
- **SSH connectivity**: For remote analysis VM management

### Analysis Infrastructure
- **Linux Analysis VM**: For network capture and general analysis tasks
- **Windows Analysis VM**: For Procmon-based process monitoring
- **File storage**: Local filesystem for uploads, reports, and capture files

The system is designed to gracefully handle missing dependencies by providing mock implementations and detailed error logging when external services are unavailable.