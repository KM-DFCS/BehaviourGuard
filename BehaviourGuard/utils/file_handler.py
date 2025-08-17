import os #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
import hashlib
import logging
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage

logger = logging.getLogger(__name__)

class FileHandler:
    """
    Secure file handling utilities
    """
    #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
    def __init__(self, upload_folder: str):
        self.upload_folder = upload_folder
        self.allowed_extensions = {
            # Executables
            'exe',
            # Archives
            'zip', 'rar', '7z', 'tar', 'gz',
            # Documents
            'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
            # Scripts
            'js', 'vbs', 'ps1', 'sh', 'py',
            # Installers
            'msi', 'deb', 'rpm', 'jar',
            # Commands
            'bat', 'cmd'
        }
        self.max_file_size = 100 * 1024 * 1024  # 100MB
        
        # Ensure upload folder exists
        os.makedirs(upload_folder, exist_ok=True)

    def is_allowed_file(self, filename: str) -> bool:
        """
        Check if file extension is allowed
        """
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in self.allowed_extensions

    def save_uploaded_file(self, file: FileStorage) -> dict:
        """
        Safely save uploaded file and return file information
        """
        try:
            if not file or file.filename == '':
                raise ValueError("No file provided")
            
            # Validate file
            if not self.is_allowed_file(file.filename):
                raise ValueError(f"File type not allowed: {file.filename}")
            
            # Check file size
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)
            
            if file_size > self.max_file_size:
                raise ValueError(f"File too large: {file_size} bytes (max: {self.max_file_size})")
            
            if file_size == 0:
                raise ValueError("Empty file")
            #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
            # Read file content
            file_content = file.read()
            file.seek(0)  # Reset for potential re-reading
            
            # Calculate hashes
            md5_hash = hashlib.md5(file_content).hexdigest()
            sha1_hash = hashlib.sha1(file_content).hexdigest()
            sha256_hash = hashlib.sha256(file_content).hexdigest()
            
            # Generate secure filename
            original_filename = secure_filename(file.filename)
            stored_filename = f"{sha256_hash}_{original_filename}"
            file_path = os.path.join(self.upload_folder, stored_filename)
            
            # Check if file already exists
            if os.path.exists(file_path):
                logger.info(f"File already exists: {file_path}")
            else:
                # Save file
                with open(file_path, 'wb') as f:
                    f.write(file_content)
                logger.info(f"File saved: {file_path}")
            
            # Get file type
            file_type = self._get_file_type(file_content)
            
            return {
                'original_filename': original_filename,
                'stored_filename': stored_filename,
                'file_path': file_path,
                'file_size': file_size,
                'md5_hash': md5_hash,
                'sha1_hash': sha1_hash,
                'sha256_hash': sha256_hash,
                'file_type': file_type
            }
         #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved   
        except Exception as e:
            logger.error(f"Error saving uploaded file: {e}")
            raise e

    def _get_file_type(self, file_content: bytes) -> str:
        """
        Determine file type using python-magic or fallback
        """
        try:
            if MAGIC_AVAILABLE:
                file_type = magic.from_buffer(file_content, mime=True)
                return file_type
            else:
                # Fallback: check file extension or return default
                return "application/octet-stream"
        except Exception as e:
            logger.warning(f"Could not determine file type: {e}")
            return "application/octet-stream"

    def delete_file(self, file_path: str) -> bool:
        """
        Safely delete a file
        """
        try:
            if os.path.exists(file_path):
                # Ensure file is within upload folder for security
                abs_file_path = os.path.abspath(file_path)
                abs_upload_folder = os.path.abspath(self.upload_folder)
                
                if not abs_file_path.startswith(abs_upload_folder):
                    raise ValueError("File is outside upload folder")
                
                os.remove(file_path)
                logger.info(f"File deleted: {file_path}")
                return True
            else:
                logger.warning(f"File not found for deletion: {file_path}")
                return False
         #Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved       
        except Exception as e:
            logger.error(f"Error deleting file: {e}")
            return False

    def get_file_info(self, file_path: str) -> dict:
        """
        Get information about a stored file
        """
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            stat = os.stat(file_path)
            
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            return {
                'file_path': file_path,
                'file_size': stat.st_size,
                'created_time': stat.st_ctime,
                'modified_time': stat.st_mtime,
                'md5_hash': hashlib.md5(file_content).hexdigest(),
                'sha1_hash': hashlib.sha1(file_content).hexdigest(),
                'sha256_hash': hashlib.sha256(file_content).hexdigest(),
                'file_type': self._get_file_type(file_content)
            }
            
        except Exception as e:
            logger.error(f"Error getting file info: {e}")
            raise e

    def validate_file_integrity(self, file_path: str, expected_hash: str) -> bool:
        """
        Validate file integrity using SHA256 hash
        """
        try:
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            actual_hash = hashlib.sha256(file_content).hexdigest()
            return actual_hash == expected_hash
            
        except Exception as e:
            logger.error(f"Error validating file integrity: {e}")
            return False


# Helper functions for backward compatibility with existing routes
def save_uploaded_file(file: FileStorage, filename: str, upload_folder: str) -> tuple:
    """
    Save uploaded file and return file path and size
    """
    handler = FileHandler(upload_folder)
    result = handler.save_uploaded_file(file)
    return result['file_path'], result['file_size']


def calculate_file_hash(file_path: str) -> str:
    """
    Calculate SHA256 hash of a file
    """#Copyright (c) 2025 KOMAL MAZHAR MUSHTAQ All rights reserved
    try:
        with open(file_path, 'rb') as f:
            file_content = f.read()
        return hashlib.sha256(file_content).hexdigest()
    except Exception as e:
        logger.error(f"Error calculating file hash: {e}")
        raise e
