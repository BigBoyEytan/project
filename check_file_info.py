import magic
import hashlib

class FileInformationEngine:
    """Engine to gather file information like MIME type, file type, and file hashes."""

    def __init__(self):
        self.mime_detector = magic.Magic(mime=True)
        self.file_type_detector = magic.Magic()

    def get_file_info(self, file_path):
        """Get detailed file information."""
        content = self._read_file_content(file_path)
        if not content:
            return {'mime_type': 'unknown', 'file_type': 'unknown'}

        return {
            'mime_type': self.mime_detector.from_buffer(content),
            'file_type': self.file_type_detector.from_buffer(content)
        }

    def calculate_file_hashes(self, file_path):
        """Calculate MD5, SHA1, and SHA256 file hashes."""
        hashers = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }

        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    for hasher in hashers.values():
                        hasher.update(chunk)

            return {name: hasher.hexdigest() for name, hasher in hashers.items()}
        except Exception as e:
            print(f"Error calculating hashes for {file_path}: {e}")
            return {name: None for name in hashers}

    @staticmethod
    def _read_file_content(file_path):
        """Safely read file content."""
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return None