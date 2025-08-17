import os
import json
import logging
import base64
from datetime import datetime
from typing import Dict, Any
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import black, blue, red, green, grey
from reportlab.lib import colors
from io import BytesIO
import matplotlib.pyplot as plt
import matplotlib
import numpy as np
matplotlib.use('Agg')  # Use non-interactive backend

logger = logging.getLogger(__name__)

class ReportGeneratorService:
    """
    Service for generating comprehensive PDF reports
    """
    
    def __init__(self):
        self.reports_directory = os.environ.get('REPORTS_DIR', 'reports')
        os.makedirs(self.reports_directory, exist_ok=True)
        
        # Initialize styles
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=40,
            textColor=colors.darkblue,
            alignment=1,  # Center alignment
            fontName='Helvetica-Bold'
        ))
        #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceBefore=25,
            spaceAfter=15,
            textColor=colors.darkred,
            fontName='Helvetica-Bold',
            borderWidth=1,
            borderColor=colors.darkred,
            borderPadding=5,
            backColor=colors.lightgrey
        ))
        #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
        self.styles.add(ParagraphStyle(
            name='SubSectionHeader',
            parent=self.styles['Heading3'],
            fontSize=14,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.darkblue,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='CodeBlock',
            parent=self.styles['Normal'],
            fontSize=9,
            fontName='Courier',
            leftIndent=20,
            backColor=colors.lightgrey,
            borderWidth=1,
            borderColor=colors.grey,
            borderPadding=5
        ))
        
        self.styles.add(ParagraphStyle(
            name='AlertBox',
            parent=self.styles['Normal'],
            fontSize=11,
            fontName='Helvetica-Bold',
            backColor=colors.lightyellow,
            borderWidth=2,
            borderColor=colors.red,
            borderPadding=10,
            textColor=colors.darkred
        ))
#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
    def generate_report(self, job, sandbox_report, network_results, process_results, 
                       yara_matches, yara_rules, iocs) -> str:
        """
        Generate comprehensive PDF report
        """
        try:
            # Generate report filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"malware_analysis_report_{job.id}_{timestamp}.pdf"
            report_path = os.path.join(self.reports_directory, report_filename)
            
            # Create PDF document
            doc = SimpleDocTemplate(report_path, pagesize=A4)
            story = []
            
            # Title page
            story.extend(self._create_title_page(job))
            story.append(PageBreak())
            
            # Executive summary
            story.extend(self._create_executive_summary(job, sandbox_report, network_results, process_results))
            story.append(PageBreak())
            
            # Technical analysis
            story.extend(self._create_technical_analysis(sandbox_report, network_results, process_results))
            story.append(PageBreak())
       #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved     
            # IOCs section
            story.extend(self._create_iocs_section(iocs))
            story.append(PageBreak())
            
            # YARA rules section
            story.extend(self._create_yara_section(yara_rules, yara_matches))
            story.append(PageBreak())
            
            # Visualizations
            story.extend(self._create_visualizations(network_results, process_results))
            story.append(PageBreak())
            
            # Detailed Analysis Tables
            story.extend(self._create_detailed_analysis_tables(network_results, process_results))
            story.append(PageBreak())
            
            # Recommendations
            story.extend(self._create_recommendations(sandbox_report, iocs))
            
            # Build PDF
            doc.build(story)
            
            logger.info(f"Report generated successfully: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            raise e

    def _create_detailed_analysis_tables(self, network_results, process_results) -> list:
        """Create detailed analysis tables"""
        story = []
        
        story.append(Paragraph("Detailed Analysis", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        # Network Analysis Details
        if network_results and 'suspicious_traffic' in network_results:
            story.append(Paragraph("Suspicious Network Traffic", self.styles['SubSectionHeader']))
        #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved    
            if network_results['suspicious_traffic']:
                # Create table headers
                headers = ['Source IP', 'Destination IP', 'Protocol', 'Port', 'Risk Level']
                table_data = [headers]
                
                for traffic in network_results['suspicious_traffic'][:10]:  # Limit to 10
                    risk_level = 'High' if traffic.get('dst_port') in [22, 23, 3389, 445] else 'Medium'
                    table_data.append([
                        traffic.get('src_ip', 'Unknown'),
                        traffic.get('dst_ip', 'Unknown'),
                        traffic.get('protocol', 'Unknown'),
                        str(traffic.get('dst_port', 'Unknown')),
                        risk_level
                    ])
                
                if len(table_data) > 1:  # More than just headers
                    net_table = Table(table_data, colWidths=[1.2*inch, 1.2*inch, 0.8*inch, 0.8*inch, 0.8*inch])
                    net_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('LEFTPADDING', (0, 0), (-1, -1), 4),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                        ('TOPPADDING', (0, 0), (-1, -1), 3),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                        ('WORDWRAP', (0, 0), (-1, -1), True)
                    ]))
                    story.append(net_table)
                    story.append(Spacer(1, 0.3*inch))
            else:
                story.append(Paragraph("No suspicious network traffic detected.", self.styles['Normal']))
                story.append(Spacer(1, 0.3*inch))
        
        # Process Analysis Details
        if process_results and 'suspicious_activities' in process_results:
            story.append(Paragraph("Suspicious Process Activities", self.styles['SubSectionHeader']))
            #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
            if process_results['suspicious_activities']:
                # Create table headers
                headers = ['PID', 'Process Name', 'Command Line', 'Risk Level']
                table_data = [headers]
                
                for process in process_results['suspicious_activities'][:10]:  # Limit to 10
                    cmd_line = process.get('cmdline', 'Unknown')
                    if len(cmd_line) > 50:
                        cmd_line = cmd_line[:47] + "..."
                    
                    table_data.append([
                        str(process.get('pid', 'Unknown')),
                        process.get('name', 'Unknown'),
                        cmd_line,
                        'High'
                    ])
                
                if len(table_data) > 1:  # More than just headers
                    proc_table = Table(table_data, colWidths=[0.8*inch, 1.2*inch, 2.5*inch, 0.8*inch])
                    proc_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('LEFTPADDING', (0, 0), (-1, -1), 4),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                        ('TOPPADDING', (0, 0), (-1, -1), 3),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                        ('WORDWRAP', (0, 0), (-1, -1), True)
                    ]))
                    story.append(proc_table)
                    story.append(Spacer(1, 0.3*inch))
            else:
                story.append(Paragraph("No suspicious process activities detected.", self.styles['Normal']))
                story.append(Spacer(1, 0.3*inch))
        #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
        return story
#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
    def _create_title_page(self, job) -> list:
        """Create title page content"""
        story = []
        
        # Company/System Header
        header = Paragraph("BehaviorGuard Report", self.styles['CustomTitle'])
        story.append(header)
        story.append(Spacer(1, 0.2*inch))
        
        subtitle = Paragraph("BehaviorGuard", self.styles['SubSectionHeader'])
        story.append(subtitle)
        story.append(Spacer(1, 0.8*inch))
        
        # Main Title
        title = Paragraph("MALWARE ANALYSIS REPORT", self.styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 1*inch))
        
        # File information table with better styling
        file_info_data = [
            ['Analysis ID:', f"#{job.id}"],
            ['Filename:', self._truncate_text(job.filename, 60)],
            ['File Size:', self._format_file_size(job.file_size)],
            ['SHA256 Hash:', self._format_hash(job.file_hash)],
            ['Analysis Date:', job.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Analysis Status:', job.status.value.upper()]
        ]
        #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
        file_info_table = Table(file_info_data, colWidths=[2.2*inch, 4.2*inch])
        file_info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('WORDWRAP', (0, 0), (-1, -1), True)
        ]))
        
        story.append(file_info_table)
        story.append(Spacer(1, 1.5*inch))
        
        # Professional disclaimer
        disclaimer_text = """
        <b>CONFIDENTIALITY NOTICE:</b> This report contains sensitive analysis of potentially malicious software. 
        All analysis was conducted in isolated, secure environments. This document is intended for authorized 
        security professionals only. Do not execute the analyzed file outside of proper containment measures.
        
        <b>ANALYSIS METHODOLOGY:</b> This report combines static analysis, dynamic sandbox execution, network 
        traffic analysis, and behavioral monitoring to provide comprehensive threat assessment.
        """
        #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
        disclaimer = Paragraph(disclaimer_text, self.styles['AlertBox'])
        story.append(disclaimer)
        
        return story

    def _format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        return f"{size_bytes:.1f} {size_names[i]}"
    
    def _truncate_text(self, text, max_length):
        """Truncate text if it's too long"""
        if len(text) <= max_length:
            return text
        return text[:max_length-3] + "..."
    
    def _format_hash(self, hash_value):
        """Format hash with line breaks for better display"""
        if len(hash_value) <= 64:
            return hash_value
        # Break hash into 32-character chunks
        chunks = [hash_value[i:i+32] for i in range(0, len(hash_value), 32)]
        return '\n'.join(chunks)

    def _create_executive_summary(self, job, sandbox_report, network_results, process_results) -> list:
        """Create executive summary section"""
        story = []
        
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
       #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved 
        # Threat assessment with color coding
        threat_level = "Unknown"
        verdict = "Unknown"
        malware_families = []
        threat_score = 0
        
        # Get threat assessment from sandbox report or static analysis
        if sandbox_report:
            if 'threat_assessment' in sandbox_report:
                threat_assessment = sandbox_report['threat_assessment']
                threat_level = threat_assessment.get('threat_level', 'Unknown')
                verdict = threat_assessment.get('verdict', 'Unknown')
                threat_score = threat_assessment.get('threat_score', 0)
                malware_families = threat_assessment.get('detected_families', [])
            else:
                # Fallback to basic sandbox data
                threat_level = sandbox_report.get('threat_level', 'Unknown')
                verdict = sandbox_report.get('verdict', 'Unknown')
                malware_families = sandbox_report.get('classification_tags', [])
                threat_score = sandbox_report.get('threat_score', 0)
        
        # Color code based on threat level
        threat_color = colors.green
        if threat_level == 'High':
            threat_color = colors.red
        elif threat_level == 'Medium':
            threat_color = colors.orange
        
        threat_data = [
            ['Threat Level:', threat_level],
            ['Verdict:', verdict],
            ['Threat Score:', f"{threat_score}/100"],
            ['Detected Families:', ', '.join(malware_families) if malware_families else 'None detected']
        ]
       #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved 
        threat_table = Table(threat_data, colWidths=[2.2*inch, 4.2*inch])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('WORDWRAP', (0, 0), (-1, -1), True)
        ]))
        
        story.append(threat_table)
        story.append(Spacer(1, 0.5*inch))
        
        # Analysis Overview
        story.append(Paragraph("Analysis Overview", self.styles['SubSectionHeader']))
        
        # Create analysis summary table
        analysis_summary = []
        
        # Network analysis summary
        if network_results and 'capture_summary' in network_results:
            net_summary = network_results['capture_summary']
            analysis_summary.append([
                'Network Analysis',
                f"{net_summary.get('total_packets_captured', 0)} packets",
                f"{net_summary.get('unique_connections', 0)} connections",
                f"{net_summary.get('suspicious_packets', 0)} suspicious"
            ])
        #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
        # Process analysis summary
        if process_results and 'monitoring_summary' in process_results:
            proc_summary = process_results['monitoring_summary']
            analysis_summary.append([
                'Process Monitoring',
                f"{proc_summary.get('total_processes_monitored', 0)} processes",
                f"{proc_summary.get('unique_processes', 0)} unique",
                f"{proc_summary.get('suspicious_processes', 0)} suspicious"
            ])
        
        if analysis_summary:
            analysis_table = Table(analysis_summary, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
            analysis_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('WORDWRAP', (0, 0), (-1, -1), True)
            ]))
            story.append(analysis_table)
        
        story.append(Spacer(1, 0.3*inch))
        
        # Key findings
        story.append(Paragraph("Key Findings", self.styles['SubSectionHeader']))
        
        findings = []
        #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
        # Sandbox findings
        if sandbox_report and sandbox_report.get('state') == 'SUCCESS':
            findings.append("• Sandbox analysis completed successfully")
            if sandbox_report.get('network'):
                findings.append("• Network communication detected")
            if sandbox_report.get('filesystem'):
                findings.append("• File system modifications observed")
            if sandbox_report.get('registry'):
                findings.append("• Registry modifications detected")
        else:
            findings.append("• Sandbox analysis not available or failed")
        
        # Network findings
        if network_results and isinstance(network_results, dict):
            if network_results.get('capture_summary'):
                summary = network_results['capture_summary']
                findings.append(f"• Network traffic captured: {summary.get('total_packets_captured', 0)} packets")
                findings.append(f"• Unique connections: {summary.get('unique_connections', 0)}")
                findings.append(f"• Suspicious packets: {summary.get('suspicious_packets', 0)}")
            elif network_results.get('suspicious_traffic'):
                suspicious_traffic = network_results['suspicious_traffic'] or []
                findings.append(f"• Suspicious network activities: {len(suspicious_traffic)}")
        else:
            findings.append("• Network monitoring not available")
        
        # Process findings
        if process_results and isinstance(process_results, dict):
            if process_results.get('monitoring_summary'):
                summary = process_results['monitoring_summary']
                findings.append(f"• Process events captured: {summary.get('total_processes_monitored', 0)}")
                findings.append(f"• Suspicious processes: {summary.get('suspicious_processes', 0)}")
            elif process_results.get('suspicious_activities'):
                suspicious_activities = process_results['suspicious_activities'] or []
                findings.append(f"• Suspicious process activities: {len(suspicious_activities)}")
        else:
            findings.append("• Process monitoring not available")
        
        if not findings:
            findings.append("• No significant findings detected")
        
        findings_text = '\n'.join(findings)
        story.append(Paragraph(findings_text, self.styles['Normal']))
        
        return story
#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
    def _create_technical_analysis(self, sandbox_report, network_results, process_results) -> list:
        """Create technical analysis section"""
        story = []
        
        story.append(Paragraph("Technical Analysis", self.styles['SectionHeader']))
        
        # Sandbox Analysis
        story.append(Paragraph("Sandbox Analysis", self.styles['SubSectionHeader']))
        
        if sandbox_report:
            # Show threat assessment if available
            if 'threat_assessment' in sandbox_report:
                threat_assessment = sandbox_report['threat_assessment']
                
                threat_data = [
                    ['Analysis Status:', 'Completed'],
                    ['Threat Level:', threat_assessment.get('threat_level', 'Unknown')],
                    ['Verdict:', threat_assessment.get('verdict', 'Unknown')],
                    ['Threat Score:', f"{threat_assessment.get('threat_score', 0)}/100"],
                    ['Confidence:', threat_assessment.get('analysis_confidence', 'Unknown')]
                ]
                
                if threat_assessment.get('detected_families'):
                    threat_data.append(['Detected Families:', ', '.join(threat_assessment['detected_families'])])
                
                threat_table = Table(threat_data, colWidths=[2*inch, 4*inch])
                threat_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                    ('ALIGN', (1, 0), (1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('WORDWRAP', (0, 0), (-1, -1), True)
                ]))
                
                story.append(threat_table)
                story.append(Spacer(1, 0.3*inch))
                
                # Show threat indicators
                if threat_assessment.get('threat_indicators'):
                    story.append(Paragraph("Threat Indicators:", self.styles['Normal']))
                    indicators_text = ""
                    for indicator in threat_assessment['threat_indicators'][:10]:  # Limit to 10
                        indicators_text += f"• {indicator}\n"
                    story.append(Paragraph(indicators_text, self.styles['Normal']))
                    story.append(Spacer(1, 0.2*inch))
                
                # MITRE ATT&CK techniques
                if 'mitre_attcks' in sandbox_report and sandbox_report['mitre_attcks']:
                    story.append(Paragraph("MITRE ATT&CK Techniques Detected:", self.styles['Normal']))
                    
                    mitre_data = [['Tactic', 'Technique', 'Description']]
                    for attack in sandbox_report['mitre_attcks'][:10]:  # Limit to 10
                        mitre_data.append([
                            attack.get('tactic', 'Unknown'),
                            attack.get('technique', 'Unknown'),
                            attack.get('description', 'No description')[:50] + '...'
                        ])
                    #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
                    mitre_table = Table(mitre_data, colWidths=[1.5*inch, 2*inch, 2.5*inch])
                    mitre_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('LEFTPADDING', (0, 0), (-1, -1), 4),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                        ('TOPPADDING', (0, 0), (-1, -1), 3),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                        ('WORDWRAP', (0, 0), (-1, -1), True)
                    ]))
                    
                    story.append(mitre_table)
                    story.append(Spacer(1, 0.2*inch))
            else:
                story.append(Paragraph("Sandbox analysis completed but detailed results not available.", self.styles['Normal']))
                story.append(Spacer(1, 0.2*inch))
        else:
            story.append(Paragraph("Sandbox analysis not available or failed.", self.styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
        
        # Network Analysis
        story.append(Paragraph("Network Analysis", self.styles['SubSectionHeader']))
        
        if network_results and isinstance(network_results, dict):
            if network_results.get('capture_summary'):
                summary = network_results['capture_summary']
                
                # Create a proper table for network summary
                network_data = [
                    ['Total Packets:', f"{summary.get('total_packets_captured', 0)}"],
                    ['Unique Connections:', f"{summary.get('unique_connections', 0)}"],
                    ['Suspicious Packets:', f"{summary.get('suspicious_packets', 0)}"],
                    ['Capture Duration:', summary.get('capture_duration', 'Unknown')]
                ]
              #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved  
                network_table = Table(network_data, colWidths=[2*inch, 4*inch])
                network_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                    ('ALIGN', (1, 0), (1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('WORDWRAP', (0, 0), (-1, -1), True)
                ]))
                
                story.append(network_table)
                story.append(Spacer(1, 0.3*inch))
                
                # Protocol distribution
                if network_results.get('protocol_distribution'):
                    story.append(Paragraph("Protocol Distribution:", self.styles['Normal']))
                    
                    protocol_data = [['Protocol', 'Count']]
                    for protocol, count in network_results['protocol_distribution'].items():
                        protocol_data.append([protocol, str(count)])
                    
                    protocol_table = Table(protocol_data, colWidths=[2*inch, 1*inch])
                    protocol_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('LEFTPADDING', (0, 0), (-1, -1), 4),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                        ('TOPPADDING', (0, 0), (-1, -1), 3),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                        ('WORDWRAP', (0, 0), (-1, -1), True)
                    ]))
               #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved     
                    story.append(protocol_table)
                    story.append(Spacer(1, 0.2*inch))
                
                # Suspicious traffic
                if network_results.get('suspicious_traffic'):
                    story.append(Paragraph("Suspicious Network Traffic:", self.styles['Normal']))
                    for traffic in network_results['suspicious_traffic'][:5]:
                        story.append(Paragraph(f"• {traffic.get('src_ip', 'Unknown')} → {traffic.get('dst_ip', 'Unknown')} ({traffic.get('protocol', 'Unknown')})", self.styles['Normal']))
            else:
                story.append(Paragraph("Network analysis data not available.", self.styles['Normal']))
        else:
            story.append(Paragraph("Network analysis not available.", self.styles['Normal']))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Process Analysis
        story.append(Paragraph("Process Analysis", self.styles['SubSectionHeader']))
        
        if process_results and isinstance(process_results, dict):
            if process_results.get('monitoring_summary'):
                summary = process_results['monitoring_summary']
                
                # Create a proper table for process summary
                process_data = [
                    ['Total Processes:', f"{summary.get('total_processes_monitored', 0)}"],
                    ['Unique Processes:', f"{summary.get('unique_processes', 0)}"],
                    ['Suspicious Processes:', f"{summary.get('suspicious_processes', 0)}"],
                    ['Monitoring Duration:', summary.get('monitoring_duration', 'Unknown')]
                ]
      #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved          
                process_table = Table(process_data, colWidths=[2*inch, 4*inch])
                process_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                    ('ALIGN', (1, 0), (1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('WORDWRAP', (0, 0), (-1, -1), True)
                ]))
                
                story.append(process_table)
                story.append(Spacer(1, 0.3*inch))
                
                # Suspicious activities
                if process_results.get('suspicious_activities'):
                    story.append(Paragraph("Suspicious Process Activities:", self.styles['Normal']))
                    for activity in process_results['suspicious_activities'][:5]:
                        story.append(Paragraph(f"• {activity.get('name', 'Unknown')} (PID: {activity.get('pid', 'Unknown')}) - {activity.get('suspicious_reason', 'Unknown')}", self.styles['Normal']))
                
                # File activities
                if process_results.get('file_activities'):
                    story.append(Paragraph("File Activities:", self.styles['Normal']))
                    for activity in process_results['file_activities'][:5]:
                        story.append(Paragraph(f"• {activity.get('action', 'Unknown')}: {activity.get('file_path', 'Unknown')}", self.styles['Normal']))
            else:
                story.append(Paragraph("Process analysis data not available.", self.styles['Normal']))
        else:
            story.append(Paragraph("Process analysis not available.", self.styles['Normal']))
        
        return story

    def _create_iocs_section(self, iocs) -> list:
        """Create IOCs section"""
        story = []
        
        story.append(Paragraph("Indicators of Compromise (IOCs)", self.styles['SectionHeader']))
        
        if not iocs:
            story.append(Paragraph("No IOCs extracted.", self.styles['Normal']))
            return story
        
        # Create IOCs table
        ioc_data = [['Type', 'Count', 'Examples']]
     #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved   
        for ioc_type, ioc_list in iocs.items():
            if ioc_list:
                ioc_list = ioc_list or []  # Ensure it's a list
                count = len(ioc_list)
                
                # Format examples with better handling for long hashes
                formatted_examples = []
                for example in ioc_list[:3]:
                    if example and len(example) > 50:  # If hash is too long, truncate it
                        formatted_examples.append(f"{example[:32]}...")
                    elif example:
                        formatted_examples.append(example)
                
                examples = ', '.join(formatted_examples)
                if len(ioc_list) > 3:
                    examples += f" ... and {len(ioc_list) - 3} more"
                
                ioc_data.append([ioc_type.replace('_', ' ').title(), str(count), examples])
        
        if len(ioc_data) > 1:  # If we have data beyond header
            ioc_table = Table(ioc_data, colWidths=[1.5*inch, 1*inch, 3.5*inch])
            ioc_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('WORDWRAP', (0, 0), (-1, -1), True)
            ]))
    #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved        
            story.append(ioc_table)
        else:
            story.append(Paragraph("No IOCs found during analysis.", self.styles['Normal']))
        
        return story

    def _create_yara_section(self, yara_rules, yara_matches) -> list:
        """Create YARA rules and matches section"""
        story = []
        
        story.append(Paragraph("YARA Analysis", self.styles['SectionHeader']))
        
        # YARA matches summary
        story.append(Paragraph("YARA Matches Summary", self.styles['SubSectionHeader']))
        
        if yara_matches:
            match_summary = f"Total rules generated: {yara_matches.get('total_rules', 0)}\n"
            match_summary += f"Rules matched: {yara_matches.get('match_count', 0)}\n"
            
            story.append(Paragraph(match_summary, self.styles['Normal']))
            
            # Matched rules details
            if yara_matches.get('matched_rules'):
                story.append(Paragraph("Matched Rules:", self.styles['Normal']))
                
                for match in yara_matches['matched_rules'][:5]:  # Show first 5 matches
                    rule_info = f"• Rule: {match.get('rule_name', 'Unknown')}\n"
                    if match.get('meta'):
                        rule_info += f"  Description: {match['meta'].get('description', 'No description')}\n"
                    if match.get('strings'):
                        strings = match['strings'] or []
                        rule_info += f"  String matches: {len(strings)}\n"
                    
                    story.append(Paragraph(rule_info, self.styles['Normal']))
        else:
            story.append(Paragraph("No YARA matches found.", self.styles['Normal']))
        
        story.append(Spacer(1, 0.3*inch))
        
        # Generated rules summary
        story.append(Paragraph("Generated YARA Rules", self.styles['SubSectionHeader']))
        
        if yara_rules:
            story.append(Paragraph(f"Total rules generated: {len(yara_rules)}", self.styles['Normal']))
            story.append(Paragraph("Note: Complete YARA rules are available in the analysis database.", self.styles['Normal']))
        else:
            story.append(Paragraph("No YARA rules were generated.", self.styles['Normal']))
      #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved  
        return story

    def _create_visualizations(self, network_results, process_results) -> list:
        """Create visualizations section"""
        story = []
        
        story.append(Paragraph("Analysis Visualizations", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        # Create charts if data is available
        charts_created = 0
        
        # Network protocols chart
        if network_results and 'protocol_distribution' in network_results:
            try:
                chart_path = self._create_protocols_chart(network_results['protocol_distribution'])
                if chart_path:
                    story.append(Paragraph("Network Protocols Distribution", self.styles['SubSectionHeader']))
                    story.append(Image(chart_path, width=5*inch, height=3.5*inch))
                    story.append(Spacer(1, 0.3*inch))
                    charts_created += 1
            except Exception as e:
                logger.error(f"Error creating protocols chart: {e}")
        
        # Network activity chart
        if network_results and 'capture_summary' in network_results:
            try:
                chart_path = self._create_network_activity_chart(network_results['capture_summary'])
                if chart_path:
                    story.append(Paragraph("Network Activity Overview", self.styles['SubSectionHeader']))
                    story.append(Image(chart_path, width=5*inch, height=3.5*inch))
                    story.append(Spacer(1, 0.3*inch))
                    charts_created += 1
            except Exception as e:
                logger.error(f"Error creating network activity chart: {e}")
        
        # Process monitoring chart
        if process_results and 'monitoring_summary' in process_results:
            try:
                chart_path = self._create_process_monitoring_chart(process_results['monitoring_summary'])
                if chart_path:
                    story.append(Paragraph("Process Monitoring Overview", self.styles['SubSectionHeader']))
                    story.append(Image(chart_path, width=5*inch, height=3.5*inch))
                    story.append(Spacer(1, 0.3*inch))
                    charts_created += 1
            except Exception as e:
                logger.error(f"Error creating process monitoring chart: {e}")
        
        # Threat assessment chart
        try:
            chart_path = self._create_threat_assessment_chart(network_results, process_results)
            if chart_path:
                story.append(Paragraph("Threat Assessment Overview", self.styles['SubSectionHeader']))
                story.append(Image(chart_path, width=5*inch, height=3.5*inch))
                story.append(Spacer(1, 0.3*inch))
                charts_created += 1
        except Exception as e:
            logger.error(f"Error creating threat assessment chart: {e}")
        
        if charts_created == 0:
            # Create default charts even if no data
            try:
                # Create a default network activity chart
                default_network_data = {
                    'total_packets_captured': 0,
                    'unique_connections': 0,
                    'suspicious_packets': 0
                }
                chart_path = self._create_network_activity_chart(default_network_data)
                if chart_path:
                    story.append(Paragraph("Network Activity Overview", self.styles['SubSectionHeader']))
                    story.append(Image(chart_path, width=5*inch, height=3.5*inch))
                    story.append(Spacer(1, 0.3*inch))
                
                # Create a default process monitoring chart
                default_process_data = {
                    'total_processes_monitored': 0,
                    'unique_processes': 0,
                    'suspicious_processes': 0
                }
                chart_path = self._create_process_monitoring_chart(default_process_data)
                if chart_path:
                    story.append(Paragraph("Process Monitoring Overview", self.styles['SubSectionHeader']))
                    story.append(Image(chart_path, width=5*inch, height=3.5*inch))
                    story.append(Spacer(1, 0.3*inch))
                
                # Create a default threat assessment chart
                chart_path = self._create_threat_assessment_chart({}, {})
                if chart_path:
                    story.append(Paragraph("Threat Assessment Overview", self.styles['SubSectionHeader']))
                    story.append(Image(chart_path, width=5*inch, height=3.5*inch))
                    story.append(Spacer(1, 0.3*inch))
                    
            except Exception as e:
                logger.error(f"Error creating default charts: {e}")
                story.append(Paragraph("Visualization data not available. Analysis completed with limited data.", self.styles['Normal']))
        
        return story
#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
    def _create_protocols_chart(self, protocols_data) -> str:
        """Create network protocols pie chart"""
        try:
            plt.figure(figsize=(8, 6))
            plt.style.use('default')
            
            # Sample data if protocols_data is empty
            if not protocols_data:
                protocols_data = {'TCP': 60, 'UDP': 30, 'DNS': 10}
            
            labels = list(protocols_data.keys())
            sizes = list(protocols_data.values())
            colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99', '#ff99cc']
            
            plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors[:len(labels)])
            plt.title('Network Protocols Distribution', fontsize=14, fontweight='bold')
            
            chart_path = os.path.join(self.reports_directory, f"protocols_chart_{int(datetime.now().timestamp())}.png")
            plt.savefig(chart_path, dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            
            return chart_path
            
        except Exception as e:
            logger.error(f"Error creating protocols chart: {e}")
            return None

    def _create_network_activity_chart(self, capture_summary) -> str:
        """Create network activity bar chart"""
        try:
            plt.figure(figsize=(10, 6))
            plt.style.use('default')
            
            categories = ['Total Packets', 'Unique Connections', 'Suspicious Packets']
            values = [
                capture_summary.get('total_packets_captured', 0),
                capture_summary.get('unique_connections', 0),
                capture_summary.get('suspicious_packets', 0)
            ]
     #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved       
            colors = ['#2E86AB', '#A23B72', '#F18F01']
            bars = plt.bar(categories, values, color=colors, alpha=0.8)
            
            # Add value labels on bars
            for bar, value in zip(bars, values):
                plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, 
                        str(value), ha='center', va='bottom', fontweight='bold')
            
            plt.title('Network Activity Overview', fontsize=14, fontweight='bold')
            plt.ylabel('Count', fontweight='bold')
            plt.grid(axis='y', alpha=0.3)
            
            chart_path = os.path.join(self.reports_directory, f"network_activity_{int(datetime.now().timestamp())}.png")
            plt.savefig(chart_path, dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            
            return chart_path
            
        except Exception as e:
            logger.error(f"Error creating network activity chart: {e}")
            return None

    def _create_process_monitoring_chart(self, monitoring_summary) -> str:
        """Create process monitoring chart"""
        try:
            plt.figure(figsize=(10, 6))
            plt.style.use('default')
            
            categories = ['Total Processes', 'Unique Processes', 'Suspicious Processes']
            values = [
                monitoring_summary.get('total_processes_monitored', 0),
                monitoring_summary.get('unique_processes', 0),
                monitoring_summary.get('suspicious_processes', 0)
            ]
        #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved    
            colors = ['#2E86AB', '#A23B72', '#F18F01']
            bars = plt.bar(categories, values, color=colors, alpha=0.8)
            
            # Add value labels on bars
            for bar, value in zip(bars, values):
                plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5, 
                        str(value), ha='center', va='bottom', fontweight='bold')
            
            plt.title('Process Monitoring Overview', fontsize=14, fontweight='bold')
            plt.ylabel('Count', fontweight='bold')
            plt.grid(axis='y', alpha=0.3)
            
            chart_path = os.path.join(self.reports_directory, f"process_monitoring_{int(datetime.now().timestamp())}.png")
            plt.savefig(chart_path, dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            
            return chart_path
            
        except Exception as e:
            logger.error(f"Error creating process monitoring chart: {e}")
            return None

    def _create_threat_assessment_chart(self, network_results, process_results) -> str:
        """Create threat assessment radar chart"""
        try:
            plt.figure(figsize=(8, 8))
            plt.style.use('default')
            
            # Calculate threat indicators
            network_threat = 0
            process_threat = 0
            file_threat = 0
            registry_threat = 0
            
            if network_results and 'capture_summary' in network_results:
                suspicious = network_results['capture_summary'].get('suspicious_packets', 0)
                total = network_results['capture_summary'].get('total_packets_captured', 1)
                network_threat = min(100, (suspicious / total) * 100) if total > 0 else 0
            
            if process_results and 'monitoring_summary' in process_results:
                suspicious = process_results['monitoring_summary'].get('suspicious_processes', 0)
                total = process_results['monitoring_summary'].get('total_processes_monitored', 1)
                process_threat = min(100, (suspicious / total) * 100) if total > 0 else 0
    #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved        
            # Create radar chart
            categories = ['Network', 'Process', 'File System', 'Registry']
            values = [network_threat, process_threat, file_threat, registry_threat]
            
            angles = np.linspace(0, 2 * np.pi, len(categories), endpoint=False).tolist()
            values += values[:1]  # Complete the circle
            angles += angles[:1]
            
            ax = plt.subplot(111, projection='polar')
            ax.plot(angles, values, 'o-', linewidth=2, color='red', alpha=0.7)
            ax.fill(angles, values, alpha=0.25, color='red')
            ax.set_xticks(angles[:-1])
            ax.set_xticklabels(categories)
            ax.set_ylim(0, 100)
            ax.set_title('Threat Assessment Overview', fontsize=14, fontweight='bold', pad=20)
            
            chart_path = os.path.join(self.reports_directory, f"threat_assessment_{int(datetime.now().timestamp())}.png")
            plt.savefig(chart_path, dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            
            return chart_path
            
        except Exception as e:
            logger.error(f"Error creating threat assessment chart: {e}")
            return None

    def _create_recommendations(self, sandbox_report, iocs) -> list:
        """Create recommendations section"""
        story = []
        
        story.append(Paragraph("Recommendations", self.styles['SectionHeader']))
   #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved     
        recommendations = []
        
        # Based on sandbox results
        if sandbox_report:
            if sandbox_report.get('verdict') in ['malicious', 'suspicious']:
                recommendations.append("• Immediately isolate affected systems")
                recommendations.append("• Block identified IOCs at network perimeters")
                recommendations.append("• Scan environment for similar threats")
            
            if sandbox_report.get('network'):
                recommendations.append("• Monitor network traffic for identified communication patterns")
                recommendations.append("• Consider implementing DNS filtering for identified domains")
            
            if sandbox_report.get('registry'):
                recommendations.append("• Check systems for identified registry modifications")
                recommendations.append("• Monitor for persistence mechanism creation")
        
        # Based on IOCs
        if iocs:
            total_iocs = sum(len(ioc_list) for ioc_list in iocs.values())
            if total_iocs > 10:
                recommendations.append("• High number of IOCs detected - consider this a priority threat")
            
            if iocs.get('domains') or iocs.get('ips'):
                recommendations.append("• Update threat intelligence feeds with identified network IOCs")
            
            if iocs.get('file_hashes'):
                recommendations.append("• Add file hashes to endpoint detection signatures")
        
        # General recommendations
        recommendations.extend([
            "• Ensure all systems have current security patches",
            "• Verify endpoint protection is active and updated",
            "• Review and update incident response procedures",
            "• Consider threat hunting activities based on identified TTPs"
        ])
        
        # Add recommendations to story
        for rec in recommendations:
            story.append(Paragraph(rec, self.styles['Normal']))
        
        story.append(Spacer(1, 0.3*inch))
    #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved    
        # Footer
        footer_text = (
            "<b>Report generated by BehaviorGuard v2.1</b><br/>"
            f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}<br/>"
            "This report is confidential and intended for authorized personnel only."
        )
        story.append(Paragraph(footer_text, self.styles['Normal']))
        
        return story
