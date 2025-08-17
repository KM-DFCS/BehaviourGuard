"""

Security utilities for file validation and safety checks
"""
#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
import os
import re
from typing import Set

# Allowed file extensions for analysis
ALLOWED_EXTENSIONS: Set[str] = {
    # Executables
    '.exe', '.dll', '.sys', '.msi', '.scr', '.bat', '.cmd', '.com', '.pif',
    # Scripts
    '.ps1', '.vbs', '.js', '.jar', '.py', '.pl', '.rb', '.sh',
    # Office documents
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
    # Archives
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
    # Other suspicious files
    '.apk', '.dmg', '.pkg', '.deb', '.rpm',
    # Binary files
    '.bin', '.dat', '.tmp'
}

# Dangerous filename patterns
DANGEROUS_PATTERNS = [
    r'^\.', r'\.\.', r'\\', r'/', r':', r'\*', r'\?', r'"', r'<', r'>', r'\|'
]
#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
def is_safe_filename(filename: str) -> bool:
    """
    Check if filename is safe for processing
    
    Args:
        filename: The filename to validate
        
    Returns:
        bool: True if filename is safe, False otherwise
    """
    if not filename or not isinstance(filename, str):
        return False
    
    # Check for dangerous patterns
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, filename):
            return False
    
    # Check length
    if len(filename) > 255:
        return False
    
    # Must have an extension
    if '.' not in filename:
        return False
    
    return True

def validate_file_type(filename: str) -> bool:
    """
    Validate that the file type is allowed for analysis
 #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved   
    Args:
        filename: The filename to validate
        
    Returns:
        bool: True if file type is allowed, False otherwise
    """
    if not filename or not isinstance(filename, str):
        return False
    
    # Get file extension
    _, ext = os.path.splitext(filename.lower())
    
    return ext in ALLOWED_EXTENSIONS

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename by removing dangerous characters
    
    Args:
        filename: The filename to sanitize
        
    Returns:
        str: Sanitized filename
    """
    if not filename:
        return "unknown_file"
    
    # Remove dangerous characters
    sanitized = re.sub(r'[^\w\-_\.]', '_', filename)
    
    # Limit length
    if len(sanitized) > 255:
        name, ext = os.path.splitext(sanitized)
        sanitized = name[:255 - len(ext)] + ext
    
    return sanitized

def is_allowed_file_size(file_size: int, max_size: int = 100 * 1024 * 1024) -> bool:
    """
    Check if file size is within allowed limits
    
    Args:
        file_size: Size of the file in bytes
        max_size: Maximum allowed size in bytes (default: 100MB)
      
    Returns:
        bool: True if file size is allowed, False otherwise
    """
    return 0 < file_size <= max_size #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved