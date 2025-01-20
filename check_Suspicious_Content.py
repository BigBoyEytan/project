import re

class SuspiciousContentEngine:
    """Engine to detect suspicious content and patterns in files."""

    SUSPICIOUS_FILE_EXTENSIONS = {
        # Executable files
        '.exe', '.dll', '.sys', '.drv', '.bin', '.scr', '.bat', '.cmd',
        # Script files
        '.ps1', '.vbs', '.js', '.py', '.sh', '.bash', '.php',
        # Document files with macro capabilities
        '.docm', '.xlsm', '.pptm',
        # Archive files
        '.zip', '.rar', '.7z', '.tar.gz'
    }

    SUSPICIOUS_PATTERNS = [
        r'cmd\.exe', r'powershell\.exe',
        r'eval\(', r'exec\(',
        r'system\(', r'shell_exec',
        r'base64_decode', r'base64_encode',
        r'http[s]?://'
    ]

    def __init__(self):
        pass

    def detect_suspicious_content(self, file_path):
        """Detect suspicious content in file based on file extension and content."""
        suspicious_items = {
            'file_extensions': [],
            'code_patterns': [],
            'security_risks': []
        }

        # Check file extension
        if file_path.suffix.lower() in self.SUSPICIOUS_FILE_EXTENSIONS:
            suspicious_items['file_extensions'].append(file_path.suffix.lower())

        # Check file content
        content = self._read_file_content(file_path)
        if content:
            suspicious_items['security_risks'].extend(self._analyze_file_content(content))

        return suspicious_items

    def _analyze_file_content(self, content):
        """Analyze file content for suspicious patterns."""
        findings = []

        # Check file headers
        if content.startswith(b'MZ'):
            findings.append('Windows executable detected')
        elif content.startswith(b'\x7fELF'):
            findings.append('Linux executable detected')
        elif content.startswith(b'#!'):
            findings.append('Shell script detected')

        # Check for suspicious patterns in text content
        try:
            text_content = content.decode('utf-8', errors='ignore')
            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, text_content, re.IGNORECASE):
                    findings.append(f'Suspicious pattern found: {pattern}')
        except UnicodeDecodeError:
            pass

        return findings

    @staticmethod
    def _read_file_content(file_path):
        """Safely read file content."""
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return None