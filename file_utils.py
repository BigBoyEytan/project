import os
import hashlib
import mimetypes


def get_file_extension(file_path):
    """Get the file extension from a path"""
    return os.path.splitext(file_path)[1].lower()


def get_file_size(file_path):
    """Get file size in bytes"""
    try:
        return os.path.getsize(file_path)
    except:
        return 0


def format_size(size_bytes):
    """Format file size in human-readable format"""
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def calculate_file_hash(file_path, hash_type='sha256'):
    """Calculate hash for file"""
    try:
        hasher = getattr(hashlib, hash_type)()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except:
        return None


def get_mime_type(file_path):
    """Get MIME type of file"""
    mime_type, _ = mimetypes.guess_type(file_path)
    return mime_type or "application/octet-stream"


def is_executable(file_path):
    """Check if file is executable"""
    return get_file_extension(file_path) in ['.exe', '.bat', '.cmd', '.msi']


def is_document(file_path):
    """Check if file is a document"""
    return get_file_extension(file_path) in ['.doc', '.docx', '.pdf', '.txt', '.rtf', '.odt']