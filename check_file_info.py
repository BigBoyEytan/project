import magic
import hashlib
import os
from typing import Dict, Optional
import mimetypes


class FileInformationEngine:
    """Enhanced engine to gather file information with better type detection and error handling."""

    def __init__(self):
        self.mime_detector = magic.Magic(mime=True)
        self.file_type_detector = magic.Magic()
        # Initialize mimetypes database
        mimetypes.init()

    def get_file_info(self, file_path: str) -> Dict[str, str]:
        """Get detailed file information with multiple detection methods."""
        try:
            result = {
                'mime_type': 'unknown',
                'file_type': 'unknown',
                'extension': os.path.splitext(file_path)[1].lower(),
                'size': os.path.getsize(file_path)
            }

            # Try multiple methods for type detection
            try:
                # Method 1: python-magic
                with open(file_path, 'rb') as f:
                    content = f.read(4096)  # Read only first 4KB for type detection
                    result['mime_type'] = self.mime_detector.from_buffer(content)
                    result['file_type'] = self.file_type_detector.from_buffer(content)
            except Exception as e:
                print(f"Magic detection failed: {e}")

                # Method 2: mimetypes module as fallback
                mime_type, _ = mimetypes.guess_type(file_path)
                if mime_type:
                    result['mime_type'] = mime_type

            return result
        except Exception as e:
            print(f"Error getting file info for {file_path}: {e}")
            return {
                'mime_type': 'error',
                'file_type': str(e),
                'extension': os.path.splitext(file_path)[1].lower(),
                'size': -1
            }

    def calculate_file_hashes(self, file_path: str) -> Dict[str, Optional[str]]:
        """Calculate file hashes with chunked reading for large files."""
        hashers = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }

        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):  # 8KB chunks
                    for hasher in hashers.values():
                        hasher.update(chunk)

            return {name: hasher.hexdigest() for name, hasher in hashers.items()}
        except Exception as e:
            print(f"Error calculating hashes for {file_path}: {e}")
            return {name: None for name in hashers}